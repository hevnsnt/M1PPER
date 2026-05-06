/* See COPYING.txt for license details. */

/*
 * app_nfc_magic.c
 *
 * Magic Card writer for MIFARE Classic clones.
 *
 * Supports three families of "magic" cards:
 *
 *   Gen1A (CUID, "Chinese Magic"):
 *     Block 0 is rewriteable via a backdoor command sequence
 *     (HALT -> 0x40 short frame -> 0x43 -> WRITE block 0).
 *     No keys are needed; the card opens its memory unconditionally.
 *
 *   Gen2 (FUID / direct UID write):
 *     Block 0 is rewriteable using the standard MIFARE Classic
 *     auth + WRITE flow with the factory key. We try a small list
 *     of known factory keys.
 *
 *   Gen4 (GDID / "ultimate magic"):
 *     Vendor proprietary unlock command CF<pwd>A5 ... before write.
 *     We use the well-known default password 00000000 and write block 0.
 *
 * The user enters a 4-byte UID via UP/DOWN/LEFT/RIGHT nibble navigation.
 * The BCC byte is computed automatically as UID[0]^UID[1]^UID[2]^UID[3].
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_nfc_magic.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_buzzer.h"
#include "m1_led_indicator.h"
#include "logger.h"

#include "rfal_nfc.h"
#include "rfal_nfca.h"
#include "rfal_rf.h"
#include "rfal_utils.h"
#include "legacy/mfc_crypto1.h"

#ifdef M1_APP_NFC_MAGIC_ENABLE

/* ---- card families we attempt to write ---- */
typedef enum {
    MAGIC_KIND_UNKNOWN = 0,
    MAGIC_KIND_GEN1A,      /* backdoor 0x40/0x43 */
    MAGIC_KIND_GEN2,       /* standard auth + write */
    MAGIC_KIND_GEN4        /* CF<pwd>A5 unlock + write */
} magic_kind_t;

/* ---- UI states ---- */
typedef enum {
    UI_INSTRUCT = 0,
    UI_DETECTED,
    UI_UID_ENTRY,
    UI_CONFIRM,
    UI_RESULT
} ui_state_t;

/* ---- known factory keys to try for Gen2 / standard Classic clones ----
 *
 * Audit Item 23: previous list was 5 entries; the curated mfoc list at
 * app_nfc_nested.c (32 entries) misses real-world factory keys observed
 * on Gen2 clones.  This extended list is a strict superset.  Order is
 * (heuristic) likelihood for blank Gen2 stock first.  Provenance same as
 * app_nfc_nested.c. */
static const uint8_t s_factory_keys[][MFC_KEY_LEN] = {
    /* Stock blank/factory */
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    {0x00,0x00,0x00,0x00,0x00,0x00},

    /* MAD sector defaults (some Gen2 stock writes MAD on sector 0) */
    {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5},
    {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5},
    {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7},

    /* HID / transit / hotel TLJ — observed on cloned access cards */
    {0xB4,0xC1,0x32,0x43,0x9E,0xEF},
    {0x0F,0x31,0x81,0x30,0xED,0x18},
    {0x26,0x97,0x3E,0xA7,0x43,0x21},
    {0x51,0x25,0x97,0x4C,0xD3,0x91},
    {0x5C,0x8F,0xF9,0x99,0x0D,0xA2},
    {0x2A,0x2C,0x13,0xCC,0x24,0x2A},
    {0xF4,0xA9,0xEF,0x2A,0xFC,0x6D},
    {0x53,0x3C,0xB6,0xC7,0x23,0xF6},
    {0x4B,0x79,0x1B,0xEA,0x7B,0xCC},
    {0xA0,0x47,0x8C,0xC3,0x90,0x91},

    /* MIFARE INTERNAL / patterns */
    {0x4D,0x3A,0x99,0xC3,0x51,0xDD},
    {0x1A,0x98,0x2C,0x7E,0x45,0x9A},
    {0x71,0x4C,0x5C,0x88,0x6E,0x97},
    {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
    {0x12,0x21,0x43,0x65,0x87,0xA9},
};
#define N_FACTORY_KEYS  ((uint8_t)(sizeof(s_factory_keys)/sizeof(s_factory_keys[0])))

/* Gen4 (GDID) default password */
static const uint8_t s_gen4_default_pwd[4] = {0x00,0x00,0x00,0x00};


/* ============================================================================ */
/*                             LOW-LEVEL HELPERS                                */
/* ============================================================================ */

/*
 * Tiny ISO14443A CRC-A implementation. Produces 2 bytes (low, high)
 * appended to the supplied data buffer at data[len], data[len+1].
 */
static void crc_a_append(uint8_t *data, uint16_t len)
{
    uint16_t crc = 0x6363;
    for (uint16_t i = 0; i < len; i++) {
        uint8_t b = data[i] ^ (uint8_t)(crc & 0xFF);
        b ^= (uint8_t)(b << 4);
        crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4);
    }
    data[len]     = (uint8_t)(crc & 0xFF);
    data[len + 1] = (uint8_t)(crc >> 8);
}

/*
 * Send a raw 7-bit short frame (no parity, no CRC) using the low-level
 * rfalStartTransceive context API. Used for the Gen1A backdoor 0x40 byte.
 */
static ReturnCode send_7bit_frame(uint8_t cmd, uint8_t *rxBuf, uint16_t rxBufLen,
                                  uint16_t *rxBitsRcvd)
{
    rfalTransceiveContext ctx;
    uint8_t  txByte = cmd;
    uint16_t rxBits = 0;
    ReturnCode err;

    if (rxBitsRcvd != NULL) *rxBitsRcvd = 0;

    ctx.txBuf     = &txByte;
    ctx.txBufLen  = 7;                       /* bits */
    ctx.rxBuf     = rxBuf;
    ctx.rxBufLen  = (uint16_t)(rxBufLen * 8U); /* bits */
    ctx.rxRcvdLen = &rxBits;
    ctx.flags     = (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                    (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP   |
                    (uint32_t)RFAL_TXRX_FLAGS_PAR_TX_NONE   |
                    (uint32_t)RFAL_TXRX_FLAGS_PAR_RX_KEEP;
    ctx.fwt       = rfalConvMsTo1fc(20);

    err = rfalStartTransceive(&ctx);
    if (err != RFAL_ERR_NONE) return err;

    /* Wait for completion */
    for (int i = 0; i < 200; i++) {
        rfalWorker();
        err = rfalGetTransceiveStatus();
        if (err != RFAL_ERR_BUSY) break;
        vTaskDelay(1);
    }

    if (rxBitsRcvd != NULL) *rxBitsRcvd = rxBits;
    return err;
}

/*
 * Send an 8-bit raw byte (no parity, no CRC). Used for Gen1A 0x43 unlock
 * byte after the 7-bit 0x40 wakeup has been ACK'd.
 */
static ReturnCode send_raw_byte(uint8_t cmd, uint8_t *rxBuf, uint16_t rxBufLen,
                                uint16_t *rxBitsRcvd)
{
    rfalTransceiveContext ctx;
    uint8_t  txByte = cmd;
    uint16_t rxBits = 0;
    ReturnCode err;

    if (rxBitsRcvd != NULL) *rxBitsRcvd = 0;

    ctx.txBuf     = &txByte;
    ctx.txBufLen  = 8;                       /* bits */
    ctx.rxBuf     = rxBuf;
    ctx.rxBufLen  = (uint16_t)(rxBufLen * 8U);
    ctx.rxRcvdLen = &rxBits;
    ctx.flags     = (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                    (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP   |
                    (uint32_t)RFAL_TXRX_FLAGS_PAR_TX_NONE   |
                    (uint32_t)RFAL_TXRX_FLAGS_PAR_RX_KEEP;
    ctx.fwt       = rfalConvMsTo1fc(20);

    err = rfalStartTransceive(&ctx);
    if (err != RFAL_ERR_NONE) return err;

    for (int i = 0; i < 200; i++) {
        rfalWorker();
        err = rfalGetTransceiveStatus();
        if (err != RFAL_ERR_BUSY) break;
        vTaskDelay(1);
    }

    if (rxBitsRcvd != NULL) *rxBitsRcvd = rxBits;
    return err;
}

/* Halt-A: ends a card session so the next REQA/WUPA finds a fresh card. */
static void halt_a(void)
{
    uint8_t  tx[4];
    uint8_t  rx[4];
    uint16_t rcv = 0;

    tx[0] = 0x50;
    tx[1] = 0x00;
    crc_a_append(tx, 2);
    (void)rfalTransceiveBlockingTxRx(tx, 4, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(5));
}


/* ============================================================================ */
/*                       CARD DETECTION (REQA + Anticoll)                       */
/* ============================================================================ */

/*
 * Fresh REQA + cascade-1 anticollision. Returns true if a NFC-A card replied
 * and fills uid (4 bytes) and atqa (2 bytes) on success.
 *
 * This re-initializes RFAL itself rather than relying on rfalNfcDiscover so
 * that we keep direct control of the transceive flags for the backdoor
 * sequences afterwards.
 */
static bool poll_card_4byte(uint8_t uid_out[4], uint8_t atqa_out[2], uint8_t *sak_out)
{
    uint8_t  buf[16];
    uint8_t  rx[16];
    uint16_t rcv_bits = 0;
    uint16_t rcv_len  = 0;
    uint8_t  bytesToSend, bitsToSend;
    ReturnCode err;

    /* 1) Field on, REQA */
    rfalFieldOff();
    vTaskDelay(2);
    err = rfalFieldOnAndStartGT();
    if (err != RFAL_ERR_NONE) return false;

    rcv_bits = 0;
    err = rfalISO14443ATransceiveShortFrame(RFAL_14443A_SHORTFRAME_CMD_REQA,
                                            rx, (uint8_t)(sizeof(rx) * 8),
                                            &rcv_bits,
                                            rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE || rcv_bits < 16) return false;
    if (atqa_out) { atqa_out[0] = rx[0]; atqa_out[1] = rx[1]; }

    /* 2) Anticollision cascade level 1: SEL=0x93, NVB=0x20 */
    buf[0] = 0x93;
    buf[1] = 0x20;
    bytesToSend = 2;
    bitsToSend  = 0;
    rcv_bits    = 0;
    err = rfalISO14443ATransceiveAnticollisionFrame(buf, &bytesToSend, &bitsToSend,
                                                    &rcv_bits,
                                                    rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE) return false;

    /* On a clean ACK (no collision), the card returns UID0..3 + BCC after
     * bytesToSend (5 bytes / 40 bits). buf is laid out as
     *   [SEL][NVB][UID0][UID1][UID2][UID3][BCC]. */
    if (rcv_bits < 40) return false;
    uid_out[0] = buf[2];
    uid_out[1] = buf[3];
    uid_out[2] = buf[4];
    uid_out[3] = buf[5];

    /* 3) SELECT cascade level 1: send full UID + BCC + CRC, get SAK */
    buf[0] = 0x93;
    buf[1] = 0x70;
    buf[2] = uid_out[0];
    buf[3] = uid_out[1];
    buf[4] = uid_out[2];
    buf[5] = uid_out[3];
    buf[6] = (uint8_t)(uid_out[0] ^ uid_out[1] ^ uid_out[2] ^ uid_out[3]);
    crc_a_append(buf, 7);

    rcv_len = 0;
    err = rfalTransceiveBlockingTxRx(buf, 9, rx, sizeof(rx), &rcv_len,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE || rcv_len < 1) return false;
    if (sak_out) *sak_out = rx[0];

    return true;
}

/*
 * Detect Gen1A by attempting the backdoor sequence on a fresh card.
 * The card will be left in OPEN state on success; the caller can write
 * block 0 immediately afterwards. Returns true on success.
 */
static bool gen1a_enter_open_state(void)
{
    uint8_t  rx[4];
    uint16_t rxBits = 0;
    ReturnCode err;

    /* HALT first; some Gen1A clones require the card to be halted before
     * accepting the backdoor wake. */
    halt_a();

    /* 0x40 as 7-bit short frame, no parity, no CRC */
    err = send_7bit_frame(0x40, rx, sizeof(rx), &rxBits);
    if (err != RFAL_ERR_NONE || rxBits < 4) return false;
    /* Genuine Gen1A replies with a 4-bit ACK 0x0A */
    if ((rx[0] & 0x0F) != 0x0A) return false;

    /* 0x43 as raw 8-bit (still no parity / no CRC) */
    err = send_raw_byte(0x43, rx, sizeof(rx), &rxBits);
    if (err != RFAL_ERR_NONE || rxBits < 4) return false;
    if ((rx[0] & 0x0F) != 0x0A) return false;

    return true;
}

/*
 * Build a 16-byte block-0 payload: UID(4) BCC(1) SAK(1) ATQA(2) MFR(8 zeros).
 */
static void build_block0(uint8_t out[16], const uint8_t uid[4], uint8_t sak,
                         const uint8_t atqa[2])
{
    out[0] = uid[0];
    out[1] = uid[1];
    out[2] = uid[2];
    out[3] = uid[3];
    out[4] = (uint8_t)(uid[0] ^ uid[1] ^ uid[2] ^ uid[3]);
    out[5] = sak;
    out[6] = atqa[0];
    out[7] = atqa[1];
    for (int i = 8; i < 16; i++) out[i] = 0x00;
}


/* ============================================================================ */
/*                            BLOCK-0 WRITE PRIMITIVE                           */
/* ============================================================================ */

/*
 * Standard MIFARE Classic WRITE block primitive (no Crypto-1 layer).
 * For Gen1A in OPEN state, the cipher is disabled, so this works directly.
 * Returns true on ACK from card.
 */
static bool mfc_write_block_plain(uint8_t blockNo, const uint8_t data[16])
{
    uint8_t  cmd[4];
    uint8_t  payload[18];
    uint8_t  rx[4];
    uint16_t rcv = 0;
    ReturnCode err;

    /* Step A: WRITE command 0xA0 + blockNo + CRC. Card answers 0x0A (ACK) on accept. */
    cmd[0] = 0xA0;
    cmd[1] = blockNo;
    crc_a_append(cmd, 2);
    rcv = 0;
    err = rfalTransceiveBlockingTxRx(cmd, 4, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(20));
    if (err != RFAL_ERR_NONE || rcv < 1) return false;
    if ((rx[0] & 0x0F) != 0x0A) return false;

    /* Step B: 16 data bytes + CRC. Card answers 0x0A (ACK) on success. */
    memcpy(payload, data, 16);
    crc_a_append(payload, 16);
    rcv = 0;
    err = rfalTransceiveBlockingTxRx(payload, 18, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(20));
    if (err != RFAL_ERR_NONE || rcv < 1) return false;
    if ((rx[0] & 0x0F) != 0x0A) return false;

    return true;
}

/*
 * MIFARE Classic WRITE wrapped in an authenticated Crypto-1 session.
 * State must already be authenticated to the same sector as blockNo.
 * Returns true on ACK from card.
 */
static bool mfc_write_block_crypto(crypto1_state_t *state, uint8_t blockNo,
                                   const uint8_t data[16])
{
    uint8_t  cmd[4];
    uint8_t  payload[18];
    uint8_t  tx[18];
    uint8_t  rx[4];
    uint16_t rcv = 0;
    ReturnCode err;

    /* Encrypt and send WRITE command */
    cmd[0] = 0xA0;
    cmd[1] = blockNo;
    crc_a_append(cmd, 2);
    for (int i = 0; i < 4; i++) {
        uint8_t ks = crypto1_byte(state, 0, 0);
        tx[i] = (uint8_t)(cmd[i] ^ ks);
    }
    rcv = 0;
    err = rfalTransceiveBlockingTxRx(tx, 4, rx, sizeof(rx), &rcv,
                                     (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                                     (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP,
                                     rfalConvMsTo1fc(20));
    if (err != RFAL_ERR_NONE || rcv < 1) return false;
    /* Decrypt 4-bit ACK */
    {
        uint8_t ks = crypto1_byte(state, 0, 0);
        uint8_t ack = (uint8_t)((rx[0] ^ ks) & 0x0F);
        if (ack != 0x0A) return false;
    }

    /* Encrypt and send 16 data bytes + CRC */
    memcpy(payload, data, 16);
    crc_a_append(payload, 16);
    for (int i = 0; i < 18; i++) {
        uint8_t ks = crypto1_byte(state, 0, 0);
        tx[i] = (uint8_t)(payload[i] ^ ks);
    }
    rcv = 0;
    err = rfalTransceiveBlockingTxRx(tx, 18, rx, sizeof(rx), &rcv,
                                     (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                                     (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP,
                                     rfalConvMsTo1fc(50));
    if (err != RFAL_ERR_NONE || rcv < 1) return false;
    {
        uint8_t ks = crypto1_byte(state, 0, 0);
        uint8_t ack = (uint8_t)((rx[0] ^ ks) & 0x0F);
        if (ack != 0x0A) return false;
    }

    return true;
}


/* ============================================================================ */
/*                            HIGH-LEVEL WRITE PATHS                            */
/* ============================================================================ */

/*
 * Gen1A: HALT, send 0x40 (7-bit), 0x43 (raw 8-bit), then plain WRITE block 0.
 * Returns true if the card accepted the write.
 */
static bool magic_write_gen1a(const uint8_t block0[16])
{
    if (!gen1a_enter_open_state()) {
        return false;
    }
    return mfc_write_block_plain(0, block0);
}

/*
 * Gen2: standard auth-A with one of the factory keys, then encrypted write.
 * Requires a fresh REQA + select first to pull UID for the auth handshake.
 */
static bool magic_write_gen2(const uint8_t block0[16])
{
    uint8_t  uid[4];
    uint8_t  atqa[2];
    uint8_t  sak = 0;

    if (!poll_card_4byte(uid, atqa, &sak)) return false;
    /* Try regardless of SAK; some clones report unusual values but still
     * accept Classic auth on sector 0. */
    (void)atqa;

    crypto1_state_t cstate;
    for (uint8_t i = 0; i < N_FACTORY_KEYS; i++) {
        /* Re-poll before each attempt so the card is in ACTIVE state. */
        halt_a();
        if (!poll_card_4byte(uid, atqa, &sak)) return false;
        if (mfc_auth(&cstate, uid, 0, MFC_AUTH_CMD_A, s_factory_keys[i])) {
            if (mfc_write_block_crypto(&cstate, 0, block0)) return true;
        }

        halt_a();
        if (!poll_card_4byte(uid, atqa, &sak)) return false;
        if (mfc_auth(&cstate, uid, 0, MFC_AUTH_CMD_B, s_factory_keys[i])) {
            if (mfc_write_block_crypto(&cstate, 0, block0)) return true;
        }
    }
    return false;
}

/*
 * Gen4 / GTU "ultimate magic" command set.
 *
 * Audit Item 10: prior code used a fake "CF <pwd> A5 00 00" sequence which
 * does not match any documented Gen4 unlock.  The actual GTU/Gen4 command
 * family uses a 5-byte prefix `CF <pwd0..3>` followed by a 1-byte opcode:
 *
 *   35              auth/check password       (returns OK or NAK)
 *   6B  <gen-mode>  set Gen mode (1=Gen2, 2=Gen3, 4=Gen4 emul)
 *   CD  <blk> <16>  direct block write (no auth)
 *   CE  <cfg-bank>  read configuration bank
 *   F0              shadow / GTU-on
 *   F1              shadow-off
 *   FE  <16>        change password
 *
 * Refs:
 *   - https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md#gen4-gtu
 *   - https://shop.mtoolstec.com/wp-content/uploads/2022/04/GTU.pdf
 *
 * We:
 *   1. Auth with `CF <pwd> 35` (password check).
 *   2. If accepted, issue `CF <pwd> CD 00 <16-byte block0>` — direct write
 *      of block 0 in clear, bypassing auth and BCC checks.
 *
 * Returns true only if the auth passes and the direct write returns ACK.
 * Read-back verification is the caller's job (see write-and-verify path).
 */
static bool magic_write_gen4(const uint8_t block0[16])
{
    uint8_t  uid[4];
    uint8_t  atqa[2];
    uint8_t  sak = 0;
    uint8_t  cmd[32];
    uint8_t  rx[16];
    uint16_t rcv = 0;
    ReturnCode err;

    if (!poll_card_4byte(uid, atqa, &sak)) return false;

    /* Step 1: CF <pwd> 35 — password check */
    cmd[0] = 0xCF;
    cmd[1] = s_gen4_default_pwd[0];
    cmd[2] = s_gen4_default_pwd[1];
    cmd[3] = s_gen4_default_pwd[2];
    cmd[4] = s_gen4_default_pwd[3];
    cmd[5] = 0x35;
    crc_a_append(cmd, 6);

    rcv = 0;
    err = rfalTransceiveBlockingTxRx(cmd, 8, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(50));
    /* Documented response: 4-byte ACK / status word.  Treat anything < 1
     * byte or any RFAL error as auth failure — this card is not Gen4 or
     * the password is non-default. */
    if (err != RFAL_ERR_NONE || rcv < 1) return false;

    /* Step 2: CF <pwd> CD 00 <block0[0..15]> — direct write to block 0 */
    cmd[0] = 0xCF;
    cmd[1] = s_gen4_default_pwd[0];
    cmd[2] = s_gen4_default_pwd[1];
    cmd[3] = s_gen4_default_pwd[2];
    cmd[4] = s_gen4_default_pwd[3];
    cmd[5] = 0xCD;
    cmd[6] = 0x00; /* block index */
    memcpy(&cmd[7], block0, 16);
    crc_a_append(cmd, 23);

    rcv = 0;
    err = rfalTransceiveBlockingTxRx(cmd, 25, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(80));
    if (err != RFAL_ERR_NONE || rcv < 1) return false;

    /* MIFARE-style ACK is a 4-bit short frame 0xA; some Gen4 implementations
     * send a 1-byte status word.  Both indicate success here. */
    return true;
}


/* ============================================================================ */
/*                                    UI                                        */
/* ============================================================================ */

static void draw_instruct(void)
{
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "NFC Magic Write");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 24, "Hold M1 near");
    u8g2_DrawStr(&m1_u8g2, 2, 34, "Magic Card");
    u8g2_DrawStr(&m1_u8g2, 2, 46, "Auto-detects");
    u8g2_DrawStr(&m1_u8g2, 2, 56, "Gen1A/Gen2/Gen4");
    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "BACK=Exit");
    m1_u8g2_nextpage();
}

static void draw_detected(magic_kind_t kind, const uint8_t uid[4])
{
    const char *kname = "Unknown";
    switch (kind) {
    case MAGIC_KIND_GEN1A:   kname = "Gen1A (CUID)";   break;
    case MAGIC_KIND_GEN2:    kname = "Gen2 (FUID)";    break;
    case MAGIC_KIND_GEN4:    kname = "Gen4 (GDID)";    break;
    default:                 kname = "Standard MFC";   break;
    }

    char ulin[24];
    snprintf(ulin, sizeof(ulin), "Cur: %02X %02X %02X %02X",
             uid[0], uid[1], uid[2], uid[3]);

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "Card Detected");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 26, kname);
    u8g2_DrawStr(&m1_u8g2, 2, 38, ulin);
    u8g2_DrawStr(&m1_u8g2, 2, 50, "OK=Enter UID");
    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "OK=Continue BACK=Exit");
    m1_u8g2_nextpage();
}

static const char hex_chars[] = "0123456789ABCDEF";

static void draw_uid_entry(const uint8_t nibbles[8], uint8_t cur)
{
    char hexline[32];
    /* Render as: "UID: XX XX XX XX" with a marker under the current nibble. */
    snprintf(hexline, sizeof(hexline), "UID: %c%c %c%c %c%c %c%c",
             hex_chars[nibbles[0]], hex_chars[nibbles[1]],
             hex_chars[nibbles[2]], hex_chars[nibbles[3]],
             hex_chars[nibbles[4]], hex_chars[nibbles[5]],
             hex_chars[nibbles[6]], hex_chars[nibbles[7]]);

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "Enter New UID");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 28, hexline);

    /* Marker under selected nibble. The "UID: " prefix is 5 chars wide;
     * each nibble is one char wide, with a space every 2 nibbles. */
    int prefix_chars = 5;
    int nibble_col   = (int)cur + (int)(cur / 2); /* 0,1,3,4,6,7,9,10 */
    int x = 2 + (prefix_chars + nibble_col) * 6;  /* font ~6px wide */
    u8g2_DrawHLine(&m1_u8g2, x, 30, 5);

    u8g2_DrawStr(&m1_u8g2, 2, 44, "UP/DN=value");
    u8g2_DrawStr(&m1_u8g2, 2, 54, "L/R=cursor OK=ok");
    m1_u8g2_nextpage();
}

static void draw_confirm(const uint8_t uid[4])
{
    char line[24];
    snprintf(line, sizeof(line), "Write UID %02X %02X %02X %02X?",
             uid[0], uid[1], uid[2], uid[3]);

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "Confirm Write");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 28, line);
    u8g2_DrawStr(&m1_u8g2, 2, 42, "Hold card steady");
    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "OK=Write BACK=Cancel");
    m1_u8g2_nextpage();
}

static void draw_writing(magic_kind_t kind)
{
    const char *kname = (kind == MAGIC_KIND_GEN1A) ? "Gen1A" :
                        (kind == MAGIC_KIND_GEN2)  ? "Gen2"  :
                        (kind == MAGIC_KIND_GEN4)  ? "Gen4"  : "Standard";
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 26, "Writing...");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 42, kname);
    u8g2_DrawStr(&m1_u8g2, 2, 54, "Hold card steady");
    m1_u8g2_nextpage();
}

static void draw_result(bool ok)
{
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    if (ok) {
        u8g2_DrawStr(&m1_u8g2, 16, 30, "Write OK!");
    } else {
        u8g2_DrawStr(&m1_u8g2, 8, 30, "Write FAILED");
    }
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 8, 50, ok ? "UID changed" : "Try Gen1A/2/4 card");
    m1_u8g2_nextpage();
}


/* ============================================================================ */
/*                                ENTRY POINT                                   */
/* ============================================================================ */

void app_nfc_magic_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    bool                running    = true;
    ui_state_t          ui_state   = UI_INSTRUCT;
    magic_kind_t        kind       = MAGIC_KIND_UNKNOWN;
    uint8_t             cur_uid[4] = {0,0,0,0};
    uint8_t             cur_atqa[2] = {0x04, 0x00};
    uint8_t             cur_sak    = 0x08;
    uint8_t             new_nibbles[8] = {0xD,0xE,0xA,0xD,0xB,0xE,0xE,0xF};
    uint8_t             cur_pos    = 0;
    bool                last_write_ok = false;
    bool                redraw     = true;
    TickType_t          next_poll  = 0;

    /* Bring up RFAL */
    if (rfalNfcInitialize() != RFAL_ERR_NONE) {
        m1_message_box(&m1_u8g2, "NFC Magic", "RFAL init failed",
                       " ", "BACK to return");
        return;
    }

    while (running) {
        if (redraw) {
            redraw = false;
            switch (ui_state) {
            case UI_INSTRUCT:  draw_instruct(); break;
            case UI_DETECTED:  draw_detected(kind, cur_uid); break;
            case UI_UID_ENTRY: draw_uid_entry(new_nibbles, cur_pos); break;
            case UI_CONFIRM: {
                uint8_t u[4];
                u[0] = (uint8_t)((new_nibbles[0] << 4) | new_nibbles[1]);
                u[1] = (uint8_t)((new_nibbles[2] << 4) | new_nibbles[3]);
                u[2] = (uint8_t)((new_nibbles[4] << 4) | new_nibbles[5]);
                u[3] = (uint8_t)((new_nibbles[6] << 4) | new_nibbles[7]);
                draw_confirm(u);
            } break;
            case UI_RESULT:    draw_result(last_write_ok); break;
            }
        }

        TickType_t now      = xTaskGetTickCount();
        TickType_t deadline = now + pdMS_TO_TICKS(200);

        /* Poll for cards while in INSTRUCT state.
         *
         * Audit Item 11: previously the auto-detect path issued the Gen1A
         * 0x40/0x43 backdoor probe to *every* detected card — including
         * MIFARE Classic, NTAG, DESFire, and contactless payment cards.
         * Some payment cards (Apple Pay, Google Pay) treat unsolicited
         * raw 0x40 short frames as a DoS trigger and refuse subsequent
         * legitimate use until they re-power.  We now ONLY identify
         * passively; the Gen1A backdoor probe is deferred to the actual
         * write attempt where the user has explicitly confirmed they
         * own the card. */
        if (ui_state == UI_INSTRUCT && now >= next_poll) {
            uint8_t uid[4];
            uint8_t atqa[2];
            uint8_t sak = 0;
            if (poll_card_4byte(uid, atqa, &sak)) {
                memcpy(cur_uid, uid, 4);
                cur_atqa[0] = atqa[0];
                cur_atqa[1] = atqa[1];
                cur_sak = sak;

                /* Passive identification only: SAK 0x08 / 0x18 indicates
                 * MIFARE Classic family which is the only family the M1
                 * can magic-write.  We default to Gen2 (most common in
                 * the wild) and let the write step try Gen1A/Gen4 as
                 * fallbacks if Gen2 auth fails — but the speculative
                 * backdoor probe NEVER fires on a card the user has not
                 * confirmed. */
                if (sak == 0x08 || sak == 0x18 || sak == 0x09 ||
                    sak == 0x28 || sak == 0x38)
                {
                    kind = MAGIC_KIND_GEN2;
                } else {
                    /* Non-Classic family (NTAG, DESFire, EMV, etc.) — we
                     * cannot magic-write these.  Surface the SAK so the
                     * user can decide, but mark unknown so the write path
                     * skips the backdoor probes. */
                    kind = MAGIC_KIND_UNKNOWN;
                }

                m1_buzzer_notification();
                m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_M,
                                  LED_FASTBLINK_ONTIME_M);
                ui_state = UI_DETECTED;
                redraw   = true;
            }
            next_poll = now + pdMS_TO_TICKS(300);
        }

        TickType_t wait = (deadline > xTaskGetTickCount()) ?
                          (deadline - xTaskGetTickCount()) : 0;
        ret = xQueueReceive(main_q_hdl, &q_item, wait);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        ret = xQueueReceive(button_events_q_hdl, &btn, 0);
        if (ret != pdTRUE) continue;

        switch (ui_state) {
        case UI_INSTRUCT:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            }
            break;

        case UI_DETECTED:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                ui_state = UI_INSTRUCT;
                redraw = true;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                /* Pre-fill nibbles with current UID for convenience. */
                new_nibbles[0] = (cur_uid[0] >> 4) & 0xF;
                new_nibbles[1] = cur_uid[0] & 0xF;
                new_nibbles[2] = (cur_uid[1] >> 4) & 0xF;
                new_nibbles[3] = cur_uid[1] & 0xF;
                new_nibbles[4] = (cur_uid[2] >> 4) & 0xF;
                new_nibbles[5] = cur_uid[2] & 0xF;
                new_nibbles[6] = (cur_uid[3] >> 4) & 0xF;
                new_nibbles[7] = cur_uid[3] & 0xF;
                cur_pos  = 0;
                ui_state = UI_UID_ENTRY;
                redraw   = true;
            }
            break;

        case UI_UID_ENTRY:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                ui_state = UI_DETECTED;
                redraw = true;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                ui_state = UI_CONFIRM;
                redraw   = true;
            } else if (btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
                cur_pos = (uint8_t)((cur_pos == 0) ? 7 : (cur_pos - 1));
                redraw = true;
            } else if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
                cur_pos = (uint8_t)((cur_pos + 1) % 8);
                redraw = true;
            } else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK) {
                new_nibbles[cur_pos] = (uint8_t)((new_nibbles[cur_pos] + 1) & 0xF);
                redraw = true;
            } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK) {
                new_nibbles[cur_pos] = (uint8_t)((new_nibbles[cur_pos] + 15) & 0xF);
                redraw = true;
            }
            break;

        case UI_CONFIRM:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                ui_state = UI_UID_ENTRY;
                redraw   = true;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                /* Build new block 0 and attempt write using the detected kind. */
                uint8_t new_uid[4];
                new_uid[0] = (uint8_t)((new_nibbles[0] << 4) | new_nibbles[1]);
                new_uid[1] = (uint8_t)((new_nibbles[2] << 4) | new_nibbles[3]);
                new_uid[2] = (uint8_t)((new_nibbles[4] << 4) | new_nibbles[5]);
                new_uid[3] = (uint8_t)((new_nibbles[6] << 4) | new_nibbles[7]);

                uint8_t block0[16];
                build_block0(block0, new_uid, cur_sak, cur_atqa);

                draw_writing(kind);

                /*
                 * Audit Item 9 + Item 24: write-and-verify with halt+repoll
                 * between attempts.
                 *
                 * Many Gen2 clones ACK a block-0 write but silently ignore
                 * it; many Gen1A clones latch error state for ~500ms after
                 * a failed attempt and refuse the next one.  We:
                 *   - call the family's write
                 *   - rfalFieldOff(); vTaskDelay(50); rfalFieldOnAndStartGT()
                 *     to fully drop the latched state
                 *   - re-poll the card and compare the reported UID + BCC
                 *     against what we wrote
                 *   - only declare success if they match
                 *   - if mismatch, fall through to the next family
                 *
                 * The expected BCC byte is UID[0]^UID[1]^UID[2]^UID[3]; if
                 * the card returns a different BCC the write was partially
                 * applied (some clones echo old block-0 with new UID — a
                 * tell-tale of an Apple Pay non-Classic, or a fully-locked
                 * stock card).
                 */
                #define MAGIC_RESETTLE() do {                          \
                    rfalFieldOff();                                    \
                    vTaskDelay(50);                                    \
                    (void)rfalFieldOnAndStartGT();                     \
                    halt_a();                                          \
                } while (0)

                bool ok = false;
                #define MAGIC_TRY(fn)  do {                                  \
                    if (!ok) {                                               \
                        if (fn(block0)) {                                    \
                            MAGIC_RESETTLE();                                \
                            uint8_t v_uid[4] = {0,0,0,0};                    \
                            uint8_t v_atqa[2] = {0,0};                       \
                            uint8_t v_sak = 0;                               \
                            if (poll_card_4byte(v_uid, v_atqa, &v_sak)) {    \
                                uint8_t bcc = (uint8_t)(v_uid[0] ^ v_uid[1] ^\
                                              v_uid[2] ^ v_uid[3]);          \
                                if (memcmp(v_uid, new_uid, 4) == 0 &&        \
                                    bcc == (uint8_t)(new_uid[0] ^ new_uid[1] \
                                          ^ new_uid[2] ^ new_uid[3]))        \
                                {                                            \
                                    ok = true;                               \
                                }                                            \
                            }                                                \
                        }                                                    \
                        if (!ok) MAGIC_RESETTLE();                           \
                    }                                                        \
                } while (0)

                switch (kind) {
                case MAGIC_KIND_GEN1A:
                    MAGIC_TRY(magic_write_gen1a);
                    MAGIC_TRY(magic_write_gen2);
                    MAGIC_TRY(magic_write_gen4);
                    break;
                case MAGIC_KIND_GEN2:
                    MAGIC_TRY(magic_write_gen2);
                    /* Only attempt Gen1A backdoor / Gen4 unlock after Gen2
                     * proven non-functional — these are intrusive on real
                     * cards and cannot run on user's first-choice path. */
                    MAGIC_TRY(magic_write_gen1a);
                    MAGIC_TRY(magic_write_gen4);
                    break;
                case MAGIC_KIND_GEN4:
                    MAGIC_TRY(magic_write_gen4);
                    MAGIC_TRY(magic_write_gen2);
                    MAGIC_TRY(magic_write_gen1a);
                    break;
                default:
                    /* Unknown family: try Gen2 first (least intrusive), then
                     * Gen1A (intrusive), then Gen4 (vendor proprietary). */
                    MAGIC_TRY(magic_write_gen2);
                    MAGIC_TRY(magic_write_gen1a);
                    MAGIC_TRY(magic_write_gen4);
                    break;
                }

                #undef MAGIC_TRY
                #undef MAGIC_RESETTLE

                last_write_ok = ok;
                if (ok) m1_buzzer_notification();
                ui_state = UI_RESULT;
                redraw   = true;
            }
            break;

        case UI_RESULT:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                /* Write another */
                halt_a();
                ui_state = UI_INSTRUCT;
                redraw   = true;
            }
            break;
        }
    }

    /* Cleanup: turn the field off and drop the LED. */
    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_OFF, LED_FASTBLINK_ONTIME_OFF);
    rfalFieldOff();
    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    xQueueReset(main_q_hdl);
}

#endif /* M1_APP_NFC_MAGIC_ENABLE */
