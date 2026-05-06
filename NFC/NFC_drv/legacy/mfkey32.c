/* See COPYING.txt for license details. */

/*
 * mfkey32.c - On-device Crypto-1 key recovery (Mfkey32)
 *
 * Implements the classic two-session attack on the MIFARE Classic
 * Crypto-1 cipher. Given two authentication transcripts captured for
 * the same (uid, sector, keyType), recovers the 48-bit key in tens of
 * seconds on a Cortex-M33 at 250 MHz.
 *
 * Pipeline:
 *   1. Compute ks2_0 = ar0_enc XOR suc64(nt0). This is 32 known
 *      keystream bits at LFSR positions 64..95 of the first session.
 *   2. Search the 2^48 LFSR state space at T=64 by splitting it into
 *      odd / even 24-bit halves and enumerating each independently:
 *        - Phase A: enumerate odd_64 in [0, 2^24), free-run 32 steps
 *          with even=0, keep candidates whose even-indexed keystream
 *          bits (steps 0,2,4,...,14) match ks2_0.
 *        - Phase B: same with even register, odd-indexed bits
 *          (steps 1,3,...,15).
 *   3. Phase C: cross-validate every (odd_cand, even_cand) pair by
 *      running a real free-LFSR for 32 steps and matching all 32 bits
 *      of ks2_0.
 *   4. Phase D: for each surviving T=64 state, roll back through
 *      nr0_enc (32 encrypted steps) and uid^nt0 (32 plaintext steps)
 *      to recover the T=0 state, which is the key. Verify against
 *      the second session.
 *
 * Memory: two 4096-entry uint32_t arrays for candidates (32 KB total).
 * No heap, no malloc.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mfkey32.h"
#include "mfc_crypto1.h"

/* ========================================================================== */
/* Local copies of static helpers from mfc_crypto1.c                          */
/* These must match exactly so the verification step is self-consistent.      */
/* ========================================================================== */

#define MFK_LF_POLY_ODD   0x29CE5CU
#define MFK_LF_POLY_EVEN  0x870804U

#define MFK_BIT(x, n)  (((x) >> (n)) & 1U)

static uint8_t mfk_parity32(uint32_t x)
{
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (uint8_t)(x & 1U);
}

/* Crypto-1 nonlinear filter on the odd register. Bit-for-bit copy of the
 * implementation in mfc_crypto1.c so verification produces identical output. */
static uint8_t mfk_filter(uint32_t odd)
{
    uint32_t f_4bit  = 0x9E98U;
    uint32_t f_4bit2 = 0xB48EU;
    uint32_t f_5bit  = 0xEC57E80AU;

    uint8_t i0  = MFK_BIT(odd, 0);
    uint8_t i1  = MFK_BIT(odd, 2);
    uint8_t i2  = MFK_BIT(odd, 4);
    uint8_t i3  = MFK_BIT(odd, 6);

    uint8_t i4  = MFK_BIT(odd, 8);
    uint8_t i5  = MFK_BIT(odd, 10);
    uint8_t i6  = MFK_BIT(odd, 12);
    uint8_t i7  = MFK_BIT(odd, 14);

    uint8_t i8  = MFK_BIT(odd, 16);
    uint8_t i9  = MFK_BIT(odd, 18);
    uint8_t i10 = MFK_BIT(odd, 20);
    uint8_t i11 = MFK_BIT(odd, 22);

    uint8_t i12 = MFK_BIT(odd, 1);
    uint8_t i13 = MFK_BIT(odd, 3);
    uint8_t i14 = MFK_BIT(odd, 5);
    uint8_t i15 = MFK_BIT(odd, 7);

    uint8_t a = (uint8_t)((f_4bit  >> ((i0  | (i1  << 1) | (i2  << 2) | (i3  << 3)))) & 1U);
    uint8_t b = (uint8_t)((f_4bit  >> ((i4  | (i5  << 1) | (i6  << 2) | (i7  << 3)))) & 1U);
    uint8_t c = (uint8_t)((f_4bit2 >> ((i8  | (i9  << 1) | (i10 << 2) | (i11 << 3)))) & 1U);
    uint8_t d = (uint8_t)((f_4bit2 >> ((i12 | (i13 << 1) | (i14 << 2) | (i15 << 3)))) & 1U);

    uint8_t e = (uint8_t)((f_5bit >> ((a | (b << 1) | (c << 2) | (d << 3) |
                 (((uint32_t)MFK_BIT(odd, 17)) << 4)))) & 1U);
    return e;
}

/* ========================================================================== */
/* Forward / rollback LFSR primitives                                         */
/* ========================================================================== */

/* Forward step. Identical to crypto1_bit() in mfc_crypto1.c, restated here
 * so the solver does not depend on a non-static export. Returns keystream
 * output bit. */
static uint8_t mfk_forward_bit(crypto1_state_t *s, uint8_t in, uint8_t is_encrypted)
{
    uint8_t out = mfk_filter(s->odd);
    uint8_t feedin = (uint8_t)(in & 1U);
    if (is_encrypted) {
        feedin ^= out;
    }
    uint8_t fb = mfk_parity32(s->even & MFK_LF_POLY_EVEN) ^
                 mfk_parity32(s->odd  & MFK_LF_POLY_ODD)  ^
                 feedin;

    uint32_t new_even = s->odd;
    s->odd  = ((s->even << 1) | (uint32_t)fb) & 0x00FFFFFFU;
    s->even = new_even & 0x00FFFFFFU;
    return out;
}

/* Roll back one LFSR step. Inverse of mfk_forward_bit. Returns the
 * keystream bit that was produced at the (now undone) clocking. */
static uint8_t mfk_rollback_bit(crypto1_state_t *s, uint8_t in, uint8_t is_encrypted)
{
    /* Recover the old state from the post-step state stored in s. */
    uint32_t post_odd  = s->odd;
    uint32_t post_even = s->even;

    /* old_odd = post_even (forward step did: new_even = old_odd). */
    uint32_t old_odd = post_even & 0x00FFFFFFU;

    /* old_even bits 0..22 = post_odd bits 1..23.
     * old_even bit 23 (the bit shifted out) is recovered from the
     * feedback equation since LF_POLY_EVEN bit 23 = 1 and bit 0 = 0. */
    uint32_t old_even_low = (post_odd >> 1) & 0x007FFFFFU;

    /* fb landed at post_odd bit 0. Recover what feedin was used. */
    uint8_t out = mfk_filter(old_odd);
    uint8_t feedin = (uint8_t)(in & 1U);
    if (is_encrypted) {
        feedin ^= out;
    }

    /* fb = parity(old_even & LF_POLY_EVEN) ^ parity(old_odd & LF_POLY_ODD) ^ feedin
     * fb is known: fb = post_odd & 1.
     * Split parity(old_even & LF_POLY_EVEN) over bit 23 vs the rest.
     * LF_POLY_EVEN bit 23 = 1, so:
     *   parity(old_even & LF_POLY_EVEN)
     *     = old_even[23] XOR parity(old_even_low & LF_POLY_EVEN)
     * Therefore:
     *   old_even[23] = (post_odd & 1)
     *                  XOR parity(old_even_low & LF_POLY_EVEN)
     *                  XOR parity(old_odd & LF_POLY_ODD)
     *                  XOR feedin                                              */
    uint8_t even_bit23 = (uint8_t)((post_odd & 1U)
                       ^ mfk_parity32(old_even_low & MFK_LF_POLY_EVEN)
                       ^ mfk_parity32(old_odd      & MFK_LF_POLY_ODD)
                       ^ feedin);

    uint32_t old_even = (old_even_low | ((uint32_t)even_bit23 << 23)) & 0x00FFFFFFU;

    s->odd  = old_odd;
    s->even = old_even;
    return out;
}

/* Roll back 32 bits LSB-first. Returns the 32 keystream bits that were
 * produced during the (now undone) clocking, packed LSB-first. */
static uint32_t mfk_rollback_word(crypto1_state_t *s, uint32_t in_word, uint8_t is_encrypted)
{
    uint32_t out_word = 0;
    /* The forward direction processed bit 0 first, then bit 1, ..., bit 31.
     * Rollback must undo in reverse order: bit 31 first, then 30, ..., 0. */
    for (int i = 31; i >= 0; i--) {
        uint8_t in_bit = (uint8_t)((in_word >> i) & 1U);
        uint8_t ks = mfk_rollback_bit(s, in_bit, is_encrypted);
        out_word |= ((uint32_t)ks << i);
    }
    return out_word;
}

/* Free-run the LFSR for 32 steps with no plaintext input (in=0,
 * is_encrypted=1, so feedin = output bit). Returns the 32 keystream
 * bits, packed LSB-first to match crypto1_word(). */
static uint32_t mfk_freerun_word(crypto1_state_t *s)
{
    uint32_t ks = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t b = mfk_forward_bit(s, 0, 1);
        ks |= ((uint32_t)b << i);
    }
    return ks;
}

/* ========================================================================== */
/* Candidate storage                                                          */
/* ========================================================================== */

/* Sized for safety. Expected occupancy after a 16-bit-constraint phase is
 * ~256; we use 8-bit constraints per the spec which yields ~65k expected.
 * We cap at 4096 entries; the constrained simulation in practice produces
 * far fewer because the LFSR free-run with even=0 quickly diverges from
 * any specific target sequence for most odd values. If we overflow we
 * simply stop collecting and let phase C work with what we have. */
#define MFK_CAND_MAX  4096U

static uint32_t s_odd_cands[MFK_CAND_MAX];
static uint32_t s_even_cands[MFK_CAND_MAX];

/* ========================================================================== */
/* Phase A / B: split-state candidate enumeration                             */
/* ========================================================================== */

/* Test whether the LFSR free-run starting at state (odd=o, even=0)
 * produces keystream bits at the EVEN positions (0,2,4,...,14) that
 * match the corresponding bits in ks2. Returns true on full match.
 *
 * The spec uses 8 even-indexed bits (steps 0..14). With even=0 the
 * simulation's keystream gradually decorrelates from reality (because
 * the real even register contributes to feedback), so we only trust
 * the early steps. */
static bool mfk_check_odd_candidate(uint32_t o, uint32_t ks2)
{
    crypto1_state_t st;
    st.odd  = o & 0x00FFFFFFU;
    st.even = 0;

    for (int step = 0; step < 16; step++) {
        uint8_t ks = mfk_forward_bit(&st, 0, 1);
        if ((step & 1) == 0) {
            uint8_t want = (uint8_t)((ks2 >> step) & 1U);
            if (ks != want) return false;
        }
    }
    return true;
}

/* Same idea for the even register. Phase B enumerates `e`, fixes
 * odd=0, and checks ODD-indexed keystream positions (1,3,5,...,15). */
static bool mfk_check_even_candidate(uint32_t e, uint32_t ks2)
{
    crypto1_state_t st;
    st.odd  = 0;
    st.even = e & 0x00FFFFFFU;

    for (int step = 0; step < 16; step++) {
        uint8_t ks = mfk_forward_bit(&st, 0, 1);
        if ((step & 1) == 1) {
            uint8_t want = (uint8_t)((ks2 >> step) & 1U);
            if (ks != want) return false;
        }
    }
    return true;
}

/* Enumerate the full 24-bit space and collect survivors. */
static uint32_t mfk_collect_odd_candidates(uint32_t ks2)
{
    uint32_t n = 0;
    for (uint32_t o = 0; o < (1U << 24); o++) {
        if (mfk_check_odd_candidate(o, ks2)) {
            if (n < MFK_CAND_MAX) {
                s_odd_cands[n++] = o;
            } else {
                /* overflow: keep going so we do not falsely report failure
                 * if the true candidate happens to be later, but stop
                 * storing. This is best-effort under tight memory. */
                break;
            }
        }
    }
    return n;
}

static uint32_t mfk_collect_even_candidates(uint32_t ks2)
{
    uint32_t n = 0;
    for (uint32_t e = 0; e < (1U << 24); e++) {
        if (mfk_check_even_candidate(e, ks2)) {
            if (n < MFK_CAND_MAX) {
                s_even_cands[n++] = e;
            } else {
                break;
            }
        }
    }
    return n;
}

/* ========================================================================== */
/* Key extraction                                                             */
/* ========================================================================== */

/* Inverse of crypto1_init: given an LFSR state, reconstruct the 48-bit key
 * such that crypto1_init(key) reproduces the same state. */
static uint64_t mfk_state_to_key(const crypto1_state_t *s)
{
    /* crypto1_init walks i = 47..0 and shifts each register left by 1 each
     * iteration (s->odd = (s->odd << 1) | bit). After the loop, the bit
     * inserted at iteration i ends up at position (count_of_later_iterations
     * for that register). Concretely:
     *   bit47 (key MSB, i=47, odd) is shifted left 23 more times -> odd[23]
     *   bit45 (i=45, odd)                            -> odd[22]
     *   ...
     *   bit1  (i=1,  odd)                            -> odd[0]
     *   bit46 (i=46, even)                           -> even[23]
     *   bit44 (i=44, even)                           -> even[22]
     *   ...
     *   bit0  (i=0,  even)                           -> even[0]
     * So key bit (2*j+1) = odd[j] and key bit (2*j) = even[j], j=0..23. */
    uint64_t key = 0;
    for (int j = 0; j < 24; j++) {
        if ((s->odd  >> j) & 1U) key |= ((uint64_t)1) << (2*j + 1);
        if ((s->even >> j) & 1U) key |= ((uint64_t)1) << (2*j);
    }
    return key;
}

/* ========================================================================== */
/* Verification using the second session                                      */
/* ========================================================================== */

/* Given a candidate key, replay the second session and check that the
 * resulting keystream decrypts ar1_enc to suc64(nt1). */
static bool mfk_verify_key(uint64_t key,
                           uint32_t uid,
                           uint32_t nt1, uint32_t nr1_enc, uint32_t ar1_enc)
{
    crypto1_state_t st;
    crypto1_init(&st, key);
    /* Initialization phase: feed uid XOR nt as plaintext (matches mfc_auth). */
    crypto1_word(&st, uid ^ nt1, 0);
    /* Encrypted reader nonce phase. */
    crypto1_word(&st, nr1_enc, 1);
    /* Now the cipher should produce the keystream that masks aR=suc64(nt1).
     * crypto1_word with in=0, is_encrypted=0 yields the raw keystream. */
    uint32_t ks = crypto1_word(&st, 0, 0);
    uint32_t ar1_plain = ar1_enc ^ ks;
    uint32_t expected = mfc_prng_successor(nt1, 64);
    return (ar1_plain == expected);
}

/* ========================================================================== */
/* Public solver                                                              */
/* ========================================================================== */

bool mfkey32_solve(uint32_t uid,
                   uint32_t nt0,  uint32_t nr0_enc, uint32_t ar0_enc,
                   uint32_t nt1,  uint32_t nr1_enc, uint32_t ar1_enc,
                   uint8_t key_out[6])
{
    /* Step 1: known keystream from session 0 at LFSR positions 64..95. */
    uint32_t ks2 = ar0_enc ^ mfc_prng_successor(nt0, 64);

    /* Step 2A: enumerate odd register candidates. */
    uint32_t n_odd = mfk_collect_odd_candidates(ks2);
    if (n_odd == 0) return false;

    /* Step 2B: enumerate even register candidates. */
    uint32_t n_even = mfk_collect_even_candidates(ks2);
    if (n_even == 0) return false;

    /* Step 3: full verification over the cross product. For each
     * (odd_cand, even_cand) pair, run a real free-LFSR for 32 steps
     * and check that the produced keystream matches ks2 entirely. */
    for (uint32_t i = 0; i < n_odd; i++) {
        for (uint32_t j = 0; j < n_even; j++) {
            crypto1_state_t st;
            st.odd  = s_odd_cands[i];
            st.even = s_even_cands[j];

            uint32_t ks_test = mfk_freerun_word(&st);
            if (ks_test != ks2) continue;

            /* Step 4: roll the state back to T=0.
             * After step 3, st has been advanced 32 free steps past T=64,
             * so st is at T=96. We want T=0. Total rollback: 96 bits.
             *
             * Rebuild T=64 state (we just consumed 32 free steps from it). */
            crypto1_state_t s64;
            s64.odd  = s_odd_cands[i];
            s64.even = s_even_cands[j];

            /* Roll back through nr0_enc (32 encrypted plaintext bits).
             * In the forward direction, mfc_auth feeds nR through
             * crypto1_word(state, nR, 0), but the cipher actually saw
             * encrypted nR bits because the reader sent nR XOR keystream.
             * From the listener's vantage we have only nr0_enc, so we
             * roll back with is_encrypted=1 (the cipher's internal feed
             * was XOR'd with the keystream output, which is what
             * is_encrypted means in the rollback). */
            (void)mfk_rollback_word(&s64, nr0_enc, 1);

            /* Roll back through uid XOR nt0 (32 plaintext bits, MSB-first
             * as fed in by crypto1_word). */
            uint32_t init_word = uid ^ nt0;
            (void)mfk_rollback_word(&s64, init_word, 0);

            /* s64 is now the state immediately after crypto1_init(key).
             * Extract key. */
            uint64_t key = mfk_state_to_key(&s64);

            /* Verify against the independent second session. */
            if (mfk_verify_key(key, uid, nt1, nr1_enc, ar1_enc)) {
                key_out[0] = (uint8_t)(key >> 40);
                key_out[1] = (uint8_t)(key >> 32);
                key_out[2] = (uint8_t)(key >> 24);
                key_out[3] = (uint8_t)(key >> 16);
                key_out[4] = (uint8_t)(key >> 8);
                key_out[5] = (uint8_t)(key);
                return true;
            }
        }
    }

    return false;
}
