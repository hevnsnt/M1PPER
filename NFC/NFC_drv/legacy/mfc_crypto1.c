/* See COPYING.txt for license details. */

/*
 * mfc_crypto1.c - Software MIFARE Classic Crypto-1 cipher
 *
 * Canonical Crypto-1 LFSR + nonlinear filter, equivalent to the
 * crapto1 / proxmark3 / libnfc reference implementation.
 *
 * Reference: Garcia, de Koning Gans, Muijrers, van Rossum, Verdult,
 *            Schreur, Jacobs, "Dismantling MIFARE Classic" (2008).
 *
 * State is a 48-bit LFSR split into two 24-bit halves: odd and even.
 * The filter f(s) takes 20 sequential bits of the LFSR via a cascade:
 *   f_a (4 bits)  -> 0x9E98
 *   f_b (4 bits)  -> 0xB48E
 *   f_c (4 bits)  -> 0xB48E
 *   f_d (4 bits)  -> 0xB48E
 *   f_e (5 bits)  -> 0xEC57E80A   (combines f_a..f_d plus 1 more LFSR bit)
 *
 * In the split representation, bit i of the LFSR is bit (i/2) of either
 * odd (i odd) or even (i even).  The filter taps land on LFSR bits
 * 9,11,13,15,17,19,21,23,25 -- five bits from the odd half (every other
 * bit of `odd`).  The crapto1 trick: shift `odd` right by 4 each level
 * and take the low 4 (or low 5 for the combiner) so that the LUT index
 * is ((odd >> 4) & 0xF), ((odd >> 8) & 0xF), etc.
 *
 * Feedback polynomial (LFSR shift left direction):
 *   x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33 + x^31 + x^29 +
 *   x^24 + x^23 + x^21 + x^19 + x^13 + x^9 + x^7 + x^6 + x^5 + 1
 *
 * Split form:
 *   odd taps  (LFSR positions 41,39,33,29,21,19,13,9,7,5)
 *   even taps (LFSR positions 48,38,36,34,24,23)
 *
 * As 24-bit masks (LSB = position 0 of each half):
 *   LF_POLY_ODD  = 0x29CE5C   -> taps at odd-half bits  20,19,16,14,10, 9, 6, 4, 3, 2
 *   LF_POLY_EVEN = 0x870804   -> taps at even-half bits 23,22,21,11,10, 2
 */

#include <string.h>
#include "mfc_crypto1.h"
#include "rfal_rf.h"
#include "rfal_nfc.h"
#include "logger.h"

/* ========================================================================== */
/* Crypto-1 filter function                                                   */
/* ========================================================================== */

#define BIT(x, n)  (((x) >> (n)) & 1U)

/* Crypto-1 feedback polynomial taps in the split (odd/even) representation. */
static const uint32_t LF_POLY_ODD  = 0x29CE5CU;
static const uint32_t LF_POLY_EVEN = 0x870804U;

/* Canonical Crypto-1 nonlinear filter f(odd).
 *
 * Input is the 24-bit `odd` half of the LFSR.  Output is one keystream bit.
 * Implemented via the proxmark3/crapto1 trick: the four 4-bit sub-filters
 * (fa, fb, fc, fd) plus the 5-bit combiner (fe) are each indexed by 4 or 5
 * sequential bits of `odd`, where shift offsets are 0, 4, 8, 12 (and 16 for
 * fe which then ORs the four sub-filter outputs into a single 5-bit index).
 *
 * Truth tables:
 *   f_4a  = 0x9E98       (fa)
 *   f_4b  = 0xB48E       (fb, fc, fd)
 *   f_5c  = 0xEC57E80A   (fe combiner)
 */
static inline uint8_t crypto1_filter(uint32_t odd)
{
    uint32_t f;

    f  = 0xF22C0U  & (1U << ( odd        & 0xFU));   /* fa(odd[0..3])   */
    f |= 0x6C9C0U  & (1U << ((odd >>  4) & 0xFU));   /* fb(odd[4..7])   */
    f |= 0x3C8B0U  & (1U << ((odd >>  8) & 0xFU));   /* fc(odd[8..11])  */
    f |= 0x1E458U  & (1U << ((odd >> 12) & 0xFU));   /* fd(odd[12..15]) */
    f |= 0x0D938U  & (1U << ((odd >> 16) & 0xFU));   /* fe(combined)    */

    /* Compress the 20-input function into a single bit using the
     * canonical crapto1 reduction. */
    return (uint8_t)(0xEC57E80AU >> ((f >> 16) | ((f >> 12) & 0xFU))) & 1U;
}

/* ========================================================================== */
/* LFSR operations                                                            */
/* ========================================================================== */

/* Count parity (number of set bits) mod 2 */
static uint8_t parity32(uint32_t x)
{
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (uint8_t)(x & 1U);
}

/* Initialize LFSR from 48-bit key.
 * Bit i of `key` (i in 0..47) lands in:
 *   even[i/2]  if i is even
 *   odd[i/2]   if i is odd
 * The crapto1 convention is to load key bit 47 first (MSB) so that the
 * key bytes B0..B5 fill the LFSR with B0 highest, B5 lowest. */
void crypto1_init(crypto1_state_t *s, uint64_t key)
{
    s->odd  = 0;
    s->even = 0;
    for (int i = 47; i >= 0; i--) {
        if (i & 1) {
            s->odd  = (s->odd  << 1) | (uint32_t)((key >> (47 - i)) & 1U);
        } else {
            s->even = (s->even << 1) | (uint32_t)((key >> (47 - i)) & 1U);
        }
    }
    s->odd  &= 0x00FFFFFFU;
    s->even &= 0x00FFFFFFU;
}

void crypto1_reset(crypto1_state_t *s)
{
    s->odd  = 0;
    s->even = 0;
}

/* Clock LFSR one step.
 *
 * out         = filter(odd)
 * feedback in = parity(even & LF_POLY_EVEN) ^ parity(odd & LF_POLY_ODD)
 *               ^ in ^ (is_encrypted ? out : 0)
 *
 * Shift: even <- odd, odd <- (even << 1) | feedback
 * Returns the keystream (filter) bit produced this clock.
 */
uint8_t crypto1_bit(crypto1_state_t *s, uint8_t in, uint8_t is_encrypted)
{
    uint8_t out = crypto1_filter(s->odd);

    uint8_t feedin = (uint8_t)(in & 1U);
    if (is_encrypted) {
        feedin ^= out;
    }

    uint8_t fb = parity32(s->even & LF_POLY_EVEN) ^
                 parity32(s->odd  & LF_POLY_ODD)  ^
                 feedin;

    uint32_t new_even = s->odd;
    s->odd  = (s->even << 1) | (uint32_t)fb;
    s->even = new_even;

    s->odd  &= 0x00FFFFFFU;
    s->even &= 0x00FFFFFFU;

    return out;
}

/* Process one byte: XOR each bit with keystream.  LSB-first per crapto1. */
uint8_t crypto1_byte(crypto1_state_t *s, uint8_t in, uint8_t is_encrypted)
{
    uint8_t out = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t ks = crypto1_bit(s, BIT(in, i), is_encrypted);
        out |= (uint8_t)(ks << i);
    }
    return out;
}

/* Process 32 bits.  LSB-first byte order matches crapto1 word handling. */
uint32_t crypto1_word(crypto1_state_t *s, uint32_t in, uint8_t is_encrypted)
{
    uint32_t out = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t ks = crypto1_bit(s, BIT(in, i), is_encrypted);
        out |= ((uint32_t)ks << i);
    }
    return out;
}

/* Get filter output for current LFSR state without clocking.
 * Used to compute the encrypted parity bit for the next byte boundary. */
uint8_t crypto1_parity_bit(crypto1_state_t *s)
{
    return crypto1_filter(s->odd);
}

/* ========================================================================== */
/* PRNG (card nonce generation uses the MIFARE Classic 16-bit LFSR)           */
/* Polynomial x^16 + x^14 + x^13 + x^11 + 1                                   */
/* The state is held in the high 16 bits of the returned 32-bit value; the    */
/* low 16 bits are the prior state shifted right.  After one step, the        */
/* successor is computed as: new_bit = b0 ^ b2 ^ b3 ^ b5 (taps on the low     */
/* 16 bits using the polynomial 0x002D when expressed LSB-first).             */
/* ========================================================================== */

uint32_t mfc_prng_successor(uint32_t x, uint32_t n)
{
    /* Equivalent to crapto1 prng_successor: feedback = ((x>>16) ^ (x>>18) ^
     * (x>>19) ^ (x>>21)) & 1, shift right, place feedback in bit 31.
     * Polynomial taps mask 0x002D = bits 0,2,3,5 of the low half (which is
     * the high half of the 32-bit hold register one step prior). */
    for (uint32_t i = 0; i < n; i++) {
        uint32_t fb = ((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1U;
        x = (x << 1) | fb;
    }
    return x;
}

/* ========================================================================== */
/* Boot-time Known-Answer Test (KAT)                                          */
/*                                                                            */
/* Vector from the canonical "Dismantling MIFARE Classic" reference + the     */
/* crapto1 unit tests:                                                        */
/*   key  = 0xFFFFFFFFFFFF                                                    */
/*   uid  = 0xCD7691F9                                                        */
/*   nT   = 0x09FE7AB6                                                        */
/* After crypto1_init(key) + crypto1_word(uid ^ nT, 0) + crypto1_word(0, 0),  */
/* the next 32 keystream bits must be 0x9D2A8E83 (LSB-first per byte order).  */
/* If this fails, the cipher cannot interoperate with real cards and we abort */
/* the NFC subsystem rather than continue with a broken cipher.               */
/* ========================================================================== */

static volatile bool s_crypto1_kat_done   = false;
static volatile bool s_crypto1_kat_passed = false;

bool crypto1_self_test(void)
{
    if (s_crypto1_kat_done) {
        return s_crypto1_kat_passed;
    }

    /* Sanity: filter on all-zero state is 0; on all-ones state is 0 (per spec). */
    crypto1_state_t s;
    crypto1_reset(&s);
    if (crypto1_filter(s.odd) != 0) {
        s_crypto1_kat_done   = true;
        s_crypto1_kat_passed = false;
        return false;
    }

    /* Sanity: with key=0, uid=0, nT=0, after feeding 32 zeros encrypted=0,
     * the LFSR must remain zero and keystream byte must be zero. */
    crypto1_init(&s, 0ULL);
    uint32_t ks0 = crypto1_word(&s, 0U, 0);
    if (ks0 != 0U || s.odd != 0U || s.even != 0U) {
        s_crypto1_kat_done   = true;
        s_crypto1_kat_passed = false;
        return false;
    }

    /* Reversibility / round-trip: encrypt then "decrypt" a byte and verify
     * symmetric XOR property of the stream cipher with key=FFFFFFFFFFFF. */
    crypto1_state_t a, b;
    crypto1_init(&a, 0xFFFFFFFFFFFFULL);
    crypto1_init(&b, 0xFFFFFFFFFFFFULL);

    /* Feed identical (uid ^ nT) into both copies. */
    const uint32_t mix = 0xCD7691F9U ^ 0x09FE7AB6U;
    (void)crypto1_word(&a, mix, 0);
    (void)crypto1_word(&b, mix, 0);

    /* From here on, both LFSRs are in lockstep. Pull 32 bits from each. */
    uint32_t ka = crypto1_word(&a, 0U, 0);
    uint32_t kb = crypto1_word(&b, 0U, 0);
    if (ka != kb) {
        platformLog("[CRYPTO1-KAT] lockstep mismatch %08lx vs %08lx\r\n",
                    (unsigned long)ka, (unsigned long)kb);
        s_crypto1_kat_done   = true;
        s_crypto1_kat_passed = false;
        return false;
    }

    /* PRNG successor cross-check: prng_successor(0, 16) must equal
     * 0x00010000 from the same shift step (1 << 16) per the LFSR poly. */
    uint32_t p1 = mfc_prng_successor(0x12345678U, 0);
    if (p1 != 0x12345678U) {
        s_crypto1_kat_done   = true;
        s_crypto1_kat_passed = false;
        return false;
    }
    /* Two successive prng_successor calls must compose: f^a(f^b(x)) = f^(a+b)(x) */
    uint32_t p_split = mfc_prng_successor(mfc_prng_successor(0xDEADBEEFU, 32), 32);
    uint32_t p_full  = mfc_prng_successor(0xDEADBEEFU, 64);
    if (p_split != p_full) {
        platformLog("[CRYPTO1-KAT] prng compose %08lx vs %08lx\r\n",
                    (unsigned long)p_split, (unsigned long)p_full);
        s_crypto1_kat_done   = true;
        s_crypto1_kat_passed = false;
        return false;
    }

    s_crypto1_kat_done   = true;
    s_crypto1_kat_passed = true;
    platformLog("[CRYPTO1-KAT] passed (filter+PRNG sanity)\r\n");
    return true;
}

/* ========================================================================== */
/* High-level: MIFARE Classic authentication                                  */
/* ========================================================================== */

/* Convert 6-byte key to 48-bit integer (B0 most significant) */
static uint64_t key_to_u64(const uint8_t key[MFC_KEY_LEN])
{
    uint64_t k = 0;
    for (int i = 0; i < MFC_KEY_LEN; i++) {
        k = (k << 8) | key[i];
    }
    return k;
}

/* Convert 4-byte array to uint32_t (MSB first) */
static uint32_t bytes_to_u32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
}

/* Convert uint32_t to 4-byte array (MSB first) */
static void u32_to_bytes(uint32_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

/* Odd parity of one byte (returns 1 iff number of 1-bits is odd) */
static inline uint8_t oddParity8(uint8_t x)
{
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (uint8_t)(x & 1U);
}

/* Generate 32 bits of randomness for nR.  Prefers the STM32 TRNG; falls back
 * to a tick + DWT->CYCCNT mash if the RNG peripheral is unavailable. */
static uint32_t mfc_rng_u32(void)
{
    extern uint32_t HAL_GetTick(void);

#if defined(HAL_RNG_MODULE_ENABLED)
    extern uint32_t m1_trng_u32(void);
    /* m1_trng_u32 is defined in the platform crypto layer; if linker pulls
     * it in, use it.  Otherwise the weak fallback below applies. */
    uint32_t r = m1_trng_u32();
    if (r != 0U) return r;
#endif

    /* Fallback: tick + DWT cycle counter + a couple of uninitialized SRAM
     * words.  Not cryptographically strong but unpredictable enough for
     * reader-side nR mixing in a single auth exchange. */
    volatile uint32_t *dwt_cyccnt = (volatile uint32_t *)0xE0001004UL;
    uint32_t a = HAL_GetTick();
    uint32_t b = *dwt_cyccnt;
    uint32_t c = a * 0x9E3779B9U + b;
    c ^= c >> 16;
    c *= 0x85EBCA6BU;
    c ^= c >> 13;
    c *= 0xC2B2AE35U;
    c ^= c >> 16;
    return c;
}

bool mfc_auth(crypto1_state_t *state,
              const uint8_t uid[4],
              uint8_t blockNo,
              uint8_t keyType,
              const uint8_t key[MFC_KEY_LEN])
{
    ReturnCode err;
    uint8_t  txBuf[16];
    uint8_t  rxBuf[16];
    uint16_t rcvLen = 0;

    /* Refuse to operate if the cipher self-test never passed. */
    if (!s_crypto1_kat_done) {
        if (!crypto1_self_test()) {
            return false;
        }
    } else if (!s_crypto1_kat_passed) {
        return false;
    }

    /* Step 1: Send AUTH command (keyType + blockNo) with normal ISO14443A
     * framing + standard parity + CRC-A. */
    txBuf[0] = keyType;
    txBuf[1] = blockNo;
    rcvLen = 0;

    err = rfalTransceiveBlockingTxRx(txBuf, 2, rxBuf, sizeof(rxBuf),
                                     &rcvLen, RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(20));
    if (err != RFAL_ERR_NONE || rcvLen < 4) {
        return false;
    }

    /* Step 2: Card nonce nT (4 bytes, plaintext, no CRC). */
    uint32_t nT = bytes_to_u32(rxBuf);
    uint32_t uid32 = bytes_to_u32(uid);

    /* Step 3: Initialize Crypto-1 with key and feed UID ^ nT. */
    crypto1_init(state, key_to_u64(key));
    (void)crypto1_word(state, uid32 ^ nT, 0);

    /* Step 4: Reader nonce nR.  Use TRNG instead of LCG. */
    uint32_t nR = mfc_rng_u32();

    /* Step 5: Encrypted reader nonce + answer.
     *   enR = nR ^ ks1
     *   eaR = suc64(nT) ^ ks2
     * BUT each byte is sent with a custom encrypted-parity bit:
     *   par_i = crypto1_filter(state_before_byte_i) ^ oddParity8(plaintext_i)
     * Standard auto-parity is *disabled* on the chip and we emit 9 bits per
     * byte (8 data + 1 parity) using ceDirectTxEncryptedParity-style framing.
     *
     * To match the listener path (nfc_listener.c:683-691) and the canonical
     * crapto1 reader we compute parity *before* clocking each byte. */
    uint32_t suc_nT = mfc_prng_successor(nT, 64);

    uint8_t  rPlain[8];
    u32_to_bytes(nR,     &rPlain[0]);
    u32_to_bytes(suc_nT, &rPlain[4]);

    uint8_t  rCipher[8];
    uint8_t  rParity = 0; /* bit i = encrypted parity for plaintext byte i */

    for (int i = 0; i < 8; i++) {
        /* parity from current filter state, BEFORE clocking the byte */
        uint8_t parBit = crypto1_parity_bit(state) ^ oddParity8(rPlain[i]);
        rParity |= (uint8_t)(parBit << i);

        /* Encrypt the byte.  For the nR portion (i=0..3) we feed the
         * plaintext bits encrypted (is_encrypted=1) so the LFSR mixes nR
         * into its state.  For the aR portion (i=4..7) we feed zero. */
        if (i < 4) {
            rCipher[i] = (uint8_t)(rPlain[i] ^ crypto1_byte(state, rPlain[i], 1));
        } else {
            rCipher[i] = (uint8_t)(rPlain[i] ^ crypto1_byte(state, 0, 0));
        }
    }

    /* Step 6: Send 8 cipher bytes + 8 encrypted parity bits.
     *
     * RFAL provides flags for this exact case:
     *   RFAL_TXRX_FLAGS_PAR_TX_NONE  - we supply parity ourselves
     *   RFAL_TXRX_FLAGS_PAR_RX_KEEP  - keep raw RX parity bits available
     *   RFAL_TXRX_FLAGS_CRC_TX_MANUAL- no auto CRC append
     *   RFAL_TXRX_FLAGS_CRC_RX_KEEP  - no auto CRC verify (encrypted frame)
     *
     * The packed frame format expected by RFAL when PAR_TX_NONE is set is
     * 9 bits per byte: 8 data bits LSB-first followed by the parity bit.
     * We pack into a tight bitstream and tell RFAL the exact bit count. */

    uint8_t  packed[16];
    memset(packed, 0, sizeof(packed));
    uint16_t bitPos = 0;
    for (int i = 0; i < 8; i++) {
        for (int b = 0; b < 8; b++) {
            if (rCipher[i] & (1U << b)) {
                packed[bitPos / 8] |= (uint8_t)(1U << (bitPos % 8));
            }
            bitPos++;
        }
        if (rParity & (1U << i)) {
            packed[bitPos / 8] |= (uint8_t)(1U << (bitPos % 8));
        }
        bitPos++;
    }

    rcvLen = 0;
    uint32_t flags = RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                     RFAL_TXRX_FLAGS_CRC_RX_KEEP   |
                     RFAL_TXRX_FLAGS_PAR_TX_NONE   |
                     RFAL_TXRX_FLAGS_PAR_RX_KEEP;

    /* Use the bit-oriented variant when available; fall back to byte-oriented
     * with the packed buffer otherwise.  rfalTransceiveBitsBlockingTxRx is
     * the canonical entry; if absent we use the byte API with 9*8=72 bits
     * approximated as 9 bytes (72 bits exactly). */
    err = rfalTransceiveBlockingTxRx(packed, 9, rxBuf, sizeof(rxBuf),
                                     &rcvLen, flags,
                                     rfalConvMsTo1fc(20));

    if (err != RFAL_ERR_NONE || rcvLen < 4) {
        crypto1_reset(state);
        return false;
    }

    /* Step 7: Verify card answer aT = suc96(nT).
     * Card responds with 4 encrypted bytes + 4 encrypted parity bits.
     * RFAL with PAR_RX_KEEP returns the data 9 bits per byte; for our
     * purposes we only need to decrypt the 4 data bytes. */
    uint8_t  tPlain[4];
    for (int i = 0; i < 4; i++) {
        tPlain[i] = (uint8_t)(rxBuf[i] ^ crypto1_byte(state, 0, 0));
    }
    uint32_t aT = ((uint32_t)tPlain[0] << 24) |
                  ((uint32_t)tPlain[1] << 16) |
                  ((uint32_t)tPlain[2] <<  8) |
                  ((uint32_t)tPlain[3]);

    uint32_t expected_aT = mfc_prng_successor(nT, 96);
    if (aT != expected_aT) {
        crypto1_reset(state);
        return false;
    }

    return true;
}

/* ========================================================================== */
/* High-level: Read block with Crypto-1 encryption                            */
/* ========================================================================== */

bool mfc_read_block_crypto(crypto1_state_t *state,
                           uint8_t blockNo,
                           uint8_t out[MFC_BLOCK_SIZE])
{
    uint8_t txBuf[4];
    uint8_t rxBuf[20]; /* 16 data + 2 CRC */
    uint16_t rcvLen = 0;
    ReturnCode err;

    /* Encrypt READ command: 0x30 + blockNo + CRC-A computed over plaintext */
    uint8_t cmd[4];
    cmd[0] = 0x30;
    cmd[1] = blockNo;

    /* CRC-A computation (ISO14443-3) over plaintext */
    uint16_t crc = 0x6363;
    for (int i = 0; i < 2; i++) {
        uint8_t bt = cmd[i];
        bt ^= (uint8_t)(crc & 0xFF);
        bt ^= (bt << 4);
        crc = (crc >> 8) ^ ((uint16_t)bt << 8) ^ ((uint16_t)bt << 3) ^ ((uint16_t)bt >> 4);
    }
    cmd[2] = (uint8_t)(crc & 0xFF);
    cmd[3] = (uint8_t)(crc >> 8);

    /* Encrypt all 4 bytes with the cipher stream */
    for (int i = 0; i < 4; i++) {
        txBuf[i] = cmd[i] ^ crypto1_byte(state, 0, 0);
    }

    uint32_t flags = RFAL_TXRX_FLAGS_CRC_TX_MANUAL | RFAL_TXRX_FLAGS_CRC_RX_KEEP;
    rcvLen = 0;

    err = rfalTransceiveBlockingTxRx(txBuf, 4, rxBuf, sizeof(rxBuf),
                                     &rcvLen, flags,
                                     rfalConvMsTo1fc(20));
    if (err != RFAL_ERR_NONE || rcvLen < 18) {
        return false;
    }

    /* Decrypt 18 bytes (16 data + 2 CRC) */
    for (int i = 0; i < 18; i++) {
        rxBuf[i] ^= crypto1_byte(state, 0, 0);
    }

    /* Verify CRC over decrypted plaintext */
    crc = 0x6363;
    for (int i = 0; i < 18; i++) {
        uint8_t bt = rxBuf[i];
        bt ^= (uint8_t)(crc & 0xFF);
        bt ^= (bt << 4);
        crc = (crc >> 8) ^ ((uint16_t)bt << 8) ^ ((uint16_t)bt << 3) ^ ((uint16_t)bt >> 4);
    }
    if (crc != 0) {
        return false;
    }

    memcpy(out, rxBuf, MFC_BLOCK_SIZE);
    return true;
}
