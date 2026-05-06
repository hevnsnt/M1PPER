/* See COPYING.txt for license details. */

/*
 * app_nfc_emv.c
 *
 * EMV (contactless) payment card reader.
 *
 * Implements the public-data subset of the EMV/PSE Book 1 transaction
 * flow that is reachable without keys:
 *
 *   1.  RFAL discovery activates the card as ISO-DEP.
 *   2.  SELECT 2PAY.SYS.DDF01 (PPSE) returns an FCI containing a list
 *       of supported AIDs.
 *   3.  SELECT first AID -> FCI may contain PDOL.
 *   4.  GET PROCESSING OPTIONS with empty PDOL.
 *   5.  READ RECORD walks SFI 1..10, record 1..16 until SW=9000 stops.
 *   6.  TLV is searched for PAN (5A), Track2 Equivalent (57),
 *       expiry (5F24), cardholder name (5F20).
 *
 * Result is masked PAN + expiry + name on screen and saved to
 * /NFC/emv_data.txt for off-device review.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_nfc_emv.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_buzzer.h"
#include "m1_led_indicator.h"
#include "m1_file_browser.h"

#include "rfal_nfc.h"
#include "rfal_isoDep.h"
#include "rfal_rf.h"
#include "rfal_utils.h"

#ifdef M1_APP_NFC_EMV_ENABLE

/* ---- limits ---- */
#define EMV_MAX_AIDS         4
#define EMV_AID_MAX_LEN      16
#define EMV_PAN_DIGITS_MAX   19
#define EMV_NAME_MAX         26


/* ---- parsed result struct ---- */
typedef struct {
    bool     have_pan;
    char     pan[EMV_PAN_DIGITS_MAX + 1];
    bool     have_exp;
    char     exp_mmyy[6];      /* "MM/YY" */
    bool     have_name;
    char     name[EMV_NAME_MAX + 1];
    char     scheme[16];       /* "Visa" | "Mastercard" | "Amex" | "Unknown" */
    uint8_t  aid[EMV_AID_MAX_LEN];
    uint8_t  aid_len;
} emv_card_t;


/* ---- well-known AID prefixes for scheme labelling ---- */
static const struct {
    uint8_t        prefix[5];
    uint8_t        prefix_len;
    const char    *name;
} s_aid_schemes[] = {
    {{0xA0,0x00,0x00,0x00,0x03}, 5, "Visa"},
    {{0xA0,0x00,0x00,0x00,0x04}, 5, "Mastercard"},
    {{0xA0,0x00,0x00,0x00,0x05}, 5, "Mastercard"},
    {{0xA0,0x00,0x00,0x00,0x25}, 5, "Amex"},
    {{0xA0,0x00,0x00,0x01,0x52}, 5, "Discover"},
    {{0xA0,0x00,0x00,0x06,0x51}, 5, "Interac"},
    {{0xA0,0x00,0x00,0x03,0x33}, 5, "UnionPay"},
};
#define N_AID_SCHEMES ((uint8_t)(sizeof(s_aid_schemes) / sizeof(s_aid_schemes[0])))


/* APDU buffers must be static. RFAL keeps pointers across calls. */
static rfalIsoDepApduBufFormat s_txApdu;
static rfalIsoDepApduBufFormat s_rxApdu;
static rfalIsoDepBufFormat     s_tmpBuf;


/* ============================================================================ */
/*                                APDU EXCHANGE                                 */
/* ============================================================================ */

/*
 * Send one APDU, wait for response. Returns true on RFAL_ERR_NONE.
 * tx points to a complete APDU (CLA INS P1 P2 [Lc data] [Le]).
 */
static bool send_apdu(const rfalIsoDepDevice *isoDep,
                      const uint8_t *tx, uint16_t tx_len,
                      uint8_t *rx_out, uint16_t rx_out_max,
                      uint16_t *rx_len_out)
{
    uint16_t rxLen = 0;
    ReturnCode err;

    if (tx_len > sizeof(s_txApdu.apdu)) return false;
    memcpy(s_txApdu.apdu, tx, tx_len);

    rfalIsoDepApduTxRxParam param;
    const rfalIsoDepInfo *info = &isoDep->info;
    param.txBuf    = &s_txApdu;
    param.txBufLen = tx_len;
    param.rxBuf    = &s_rxApdu;
    param.rxLen    = &rxLen;
    param.tmpBuf   = &s_tmpBuf;
    param.FWT      = info->FWT;
    param.dFWT     = info->dFWT;
    param.FSx      = info->FSx;
    param.ourFSx   = RFAL_ISODEP_DEFAULT_FSC;
    param.DID      = info->supDID ? info->DID : RFAL_ISODEP_NO_DID;

    err = rfalIsoDepStartApduTransceive(param);
    if (err != RFAL_ERR_NONE) return false;

    /*
     * Audit Item 12: deadline-based wait off the card's reported FWT.
     *
     * The previous fixed 1500*2ms = ~3s budget caused premature timeouts on
     * EMV chips that legitimately need 5-10s for cryptographic operations
     * (PDOL evaluation, GENERATE AC offline data authentication, etc.).
     *
     * RFAL reports per-card timing via info->FWT (Frame Waiting Time, in
     * 1/fc units) and info->dFWT (max additional accumulated wait).  We
     * convert that to milliseconds and add a generous safety margin
     * (3x dFWT + 100ms slack) so cards near the upper FWT bound still
     * complete.  Cap at 10s to avoid wedging the UI on a stuck card.
     */
    uint32_t fwt_ms      = rfalConv1fcToMs(info->FWT);
    uint32_t dfwt_ms     = rfalConv1fcToMs(info->dFWT);
    uint32_t deadline_ms = fwt_ms + 3U * dfwt_ms + 100U;
    if (deadline_ms > 10000U) deadline_ms = 10000U;
    if (deadline_ms <   500U) deadline_ms =   500U;

    TickType_t start = xTaskGetTickCount();
    for (;;) {
        rfalNfcWorker();
        err = rfalIsoDepGetApduTransceiveStatus();
        if (err != RFAL_ERR_BUSY) break;
        if ((uint32_t)(xTaskGetTickCount() - start) >= pdMS_TO_TICKS(deadline_ms)) {
            err = RFAL_ERR_TIMEOUT;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    if (err != RFAL_ERR_NONE) return false;

    if (rxLen == 0 || rxLen > rx_out_max) return false;
    memcpy(rx_out, s_rxApdu.apdu, rxLen);
    *rx_len_out = rxLen;
    return true;
}


/* ============================================================================ */
/*                                  TLV PARSING                                 */
/* ============================================================================ */

/*
 * Parse one BER-TLV header at *p. Returns false on malformed TLV.
 * On success, sets *tag (1- or 2-byte tag, big-endian), *len, *vbeg
 * and advances *p to the start of the next TLV (after the value).
 */
static bool tlv_parse_one(const uint8_t **pp, const uint8_t *end,
                          uint16_t *tag_out, uint16_t *len_out,
                          const uint8_t **val_out)
{
    const uint8_t *p = *pp;
    if (p >= end) return false;

    /* skip leading 00 padding */
    while (p < end && *p == 0x00) p++;
    if (p >= end) return false;

    /* tag: 1 or 2 bytes */
    uint16_t tag = *p++;
    if ((tag & 0x1F) == 0x1F) {
        if (p >= end) return false;
        tag = (uint16_t)((tag << 8) | *p++);
    }

    /* length.
     *
     * Audit Item 20: previous code rejected lengths encoded with > 2
     * length-of-length bytes.  EMV PSE FCI responses legitimately use
     * 3-byte lengths for fielded transit/long records.  We now accept
     * 1..4 length-of-length bytes (covering up to 4-byte payload length,
     * far beyond any single TLV envelope an EMV card returns).  We track
     * the length in 32-bit, then narrow to uint16_t after a sanity check
     * because the rest of the parser uses uint16_t bounds. */
    if (p >= end) return false;
    uint32_t len32 = *p++;
    if (len32 & 0x80) {
        uint8_t lol = (uint8_t)(len32 & 0x7F);
        if (lol == 0 || lol > 4) return false;
        len32 = 0;
        while (lol--) {
            if (p >= end) return false;
            len32 = (len32 << 8) | (uint32_t)(*p++);
        }
    }
    if (len32 > 0xFFFFU) return false;
    uint16_t len = (uint16_t)len32;

    if ((p + len) > end) return false;

    *tag_out = tag;
    *len_out = len;
    *val_out = p;
    *pp = p + len;
    return true;
}

/* Constructed tags whose values are themselves TLV. */
static bool tag_is_constructed(uint16_t tag)
{
    /* Tag is constructed when bit 6 of the first tag byte is set. */
    if (tag <= 0xFF) return (tag & 0x20) != 0;
    return ((tag >> 8) & 0x20) != 0;
}

/*
 * Recursively search a TLV stream for a tag. Returns true on first match
 * and outputs (val, len). Callers should not rely on uniqueness; we take
 * the first occurrence.
 */
static bool tlv_find(const uint8_t *buf, uint16_t buf_len, uint16_t want_tag,
                     const uint8_t **val_out, uint16_t *len_out)
{
    const uint8_t *p   = buf;
    const uint8_t *end = buf + buf_len;
    while (p < end) {
        uint16_t tag, len;
        const uint8_t *val;
        if (!tlv_parse_one(&p, end, &tag, &len, &val)) return false;
        if (tag == want_tag) {
            *val_out = val;
            *len_out = len;
            return true;
        }
        if (tag_is_constructed(tag)) {
            if (tlv_find(val, len, want_tag, val_out, len_out)) return true;
        }
    }
    return false;
}


/* ============================================================================ */
/*                                FIELD DECODING                                */
/* ============================================================================ */

/*
 * Decode a packed-BCD PAN tag (5A) into ASCII digits, dropping the
 * trailing nibble 0xF padding. Returns digit count.
 */
static uint8_t decode_pan(const uint8_t *val, uint16_t len, char *out, uint8_t out_max)
{
    uint8_t n = 0;
    for (uint16_t i = 0; i < len && n + 2 <= out_max; i++) {
        uint8_t hi = (uint8_t)(val[i] >> 4);
        uint8_t lo = (uint8_t)(val[i] & 0x0F);
        if (hi > 9) break;
        out[n++] = (char)('0' + hi);
        if (lo > 9) break;
        out[n++] = (char)('0' + lo);
    }
    if (n < out_max) out[n] = '\0';
    return n;
}

/*
 * Track 2 Equivalent (tag 57): packed-BCD PAN, then 0xD separator,
 * then expiry YYMM, then service code, then discretionary data, padded
 * with 0xF nibbles. We extract PAN and expiry.
 */
static void decode_track2(const uint8_t *val, uint16_t len, emv_card_t *card)
{
    /* unpack BCD into a digit string up to the 'D' separator (0xD nibble) */
    char digits[64];
    uint8_t n = 0;
    bool seen_d = false;
    char yymm[5] = {0};
    uint8_t e = 0;

    for (uint16_t i = 0; i < len && n < (uint8_t)(sizeof(digits) - 1); i++) {
        uint8_t hi = (uint8_t)(val[i] >> 4);
        uint8_t lo = (uint8_t)(val[i] & 0x0F);
        for (int half = 0; half < 2; half++) {
            uint8_t nib = (half == 0) ? hi : lo;
            if (nib == 0x0D) { seen_d = true; e = 0; continue; }
            if (nib == 0x0F) { return; }
            if (!seen_d) {
                if (nib > 9) return;
                digits[n++] = (char)('0' + nib);
            } else if (e < 4) {
                if (nib > 9) return;
                yymm[e++] = (char)('0' + nib);
            }
        }
    }

    if (!card->have_pan && n > 0) {
        digits[n] = '\0';
        size_t copy = (n < EMV_PAN_DIGITS_MAX) ? n : EMV_PAN_DIGITS_MAX;
        memcpy(card->pan, digits, copy);
        card->pan[copy] = '\0';
        card->have_pan = true;
    }
    if (!card->have_exp && e == 4) {
        card->exp_mmyy[0] = yymm[2];
        card->exp_mmyy[1] = yymm[3];
        card->exp_mmyy[2] = '/';
        card->exp_mmyy[3] = yymm[0];
        card->exp_mmyy[4] = yymm[1];
        card->exp_mmyy[5] = '\0';
        card->have_exp = true;
    }
}

/* Tag 5F24: expiry as packed BCD YY MM DD. */
static void decode_expiry(const uint8_t *val, uint16_t len, emv_card_t *card)
{
    if (len < 2 || card->have_exp) return;
    uint8_t yy_h = (uint8_t)(val[0] >> 4);
    uint8_t yy_l = (uint8_t)(val[0] & 0x0F);
    uint8_t mm_h = (uint8_t)(val[1] >> 4);
    uint8_t mm_l = (uint8_t)(val[1] & 0x0F);
    if (yy_h > 9 || yy_l > 9 || mm_h > 9 || mm_l > 9) return;

    card->exp_mmyy[0] = (char)('0' + mm_h);
    card->exp_mmyy[1] = (char)('0' + mm_l);
    card->exp_mmyy[2] = '/';
    card->exp_mmyy[3] = (char)('0' + yy_h);
    card->exp_mmyy[4] = (char)('0' + yy_l);
    card->exp_mmyy[5] = '\0';
    card->have_exp = true;
}

/* Tag 5F20: cardholder name in ASCII, space-padded. */
static void decode_name(const uint8_t *val, uint16_t len, emv_card_t *card)
{
    if (card->have_name) return;
    uint8_t n = 0;
    for (uint16_t i = 0; i < len && n < EMV_NAME_MAX; i++) {
        uint8_t c = val[i];
        if (c < 0x20 || c > 0x7E) c = ' ';
        card->name[n++] = (char)c;
    }
    /* trim trailing spaces */
    while (n > 0 && card->name[n - 1] == ' ') n--;
    card->name[n] = '\0';
    if (n > 0) card->have_name = true;
}

/* Pick a scheme label by AID prefix match. */
static void label_scheme(emv_card_t *card)
{
    snprintf(card->scheme, sizeof(card->scheme), "Unknown");
    for (uint8_t i = 0; i < N_AID_SCHEMES; i++) {
        if (card->aid_len < s_aid_schemes[i].prefix_len) continue;
        if (memcmp(card->aid, s_aid_schemes[i].prefix,
                   s_aid_schemes[i].prefix_len) == 0) {
            snprintf(card->scheme, sizeof(card->scheme), "%s",
                     s_aid_schemes[i].name);
            return;
        }
    }
}


/* ============================================================================ */
/*                              EMV TRANSACTION                                 */
/* ============================================================================ */

static const uint8_t s_apdu_select_ppse[] = {
    0x00, 0xA4, 0x04, 0x00, 0x0E,
    '2','P','A','Y','.','S','Y','S','.','D','D','F','0','1',
    0x00
};

static const uint8_t s_apdu_gpo_empty[] = {
    0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00
};

static bool sw_ok(const uint8_t *resp, uint16_t resp_len)
{
    return resp_len >= 2 &&
           resp[resp_len - 2] == 0x90 &&
           resp[resp_len - 1] == 0x00;
}

/*
 * Walk a PPSE FCI and pull up to EMV_MAX_AIDS AIDs out of it.
 * Each "Application Template" 0x61 contains an AID 0x4F.
 */
static uint8_t parse_ppse_aids(const uint8_t *resp, uint16_t resp_len,
                               uint8_t aids[][EMV_AID_MAX_LEN],
                               uint8_t aid_lens[],
                               uint8_t max_aids)
{
    /* The body is the response without the trailing SW1/SW2. */
    if (resp_len < 2) return 0;
    uint16_t body_len = (uint16_t)(resp_len - 2);

    /* PPSE response is wrapped in 6F (FCI Template) -> A5 (FCI Proprietary)
     * -> BF0C (FCI Issuer Discretionary) -> 61 (Application Template). */
    const uint8_t *fci_val;
    uint16_t       fci_len;
    if (!tlv_find(resp, body_len, 0x6F, &fci_val, &fci_len)) return 0;

    uint8_t found = 0;
    const uint8_t *p = fci_val;
    const uint8_t *end = fci_val + fci_len;

    /* Iterate everything inside FCI; recurse into constructed tags. */
    /* Manual stack-free recursion: scan top level, then descend into A5
     * and BF0C if present. */
    const uint8_t *scan_starts[4];
    uint16_t       scan_lens  [4];
    uint8_t        scan_n     = 0;
    scan_starts[scan_n] = p;
    scan_lens  [scan_n] = (uint16_t)(end - p);
    scan_n++;

    while (scan_n > 0 && found < max_aids) {
        scan_n--;
        const uint8_t *sp = scan_starts[scan_n];
        const uint8_t *se = sp + scan_lens[scan_n];

        while (sp < se && found < max_aids) {
            uint16_t tag, len;
            const uint8_t *val;
            if (!tlv_parse_one(&sp, se, &tag, &len, &val)) break;

            if (tag == 0x61) {
                /* Application Template: search for 4F (AID) inside */
                const uint8_t *aid_val;
                uint16_t       aid_len;
                if (tlv_find(val, len, 0x4F, &aid_val, &aid_len)) {
                    if (aid_len > 0 && aid_len <= EMV_AID_MAX_LEN) {
                        memcpy(aids[found], aid_val, aid_len);
                        aid_lens[found] = (uint8_t)aid_len;
                        found++;
                    }
                }
            } else if (tag_is_constructed(tag) && scan_n < 4) {
                scan_starts[scan_n] = val;
                scan_lens  [scan_n] = len;
                scan_n++;
            }
        }
    }
    return found;
}

/*
 * Process one record body's TLV stream and merge fields into the card.
 * Factor of the read_records walk so both the AFL-driven and fallback
 * paths can call it.
 */
static void merge_record_tlv(const uint8_t *body, uint16_t body_len,
                             emv_card_t *card)
{
    const uint8_t *inner     = body;
    uint16_t       inner_len = body_len;
    const uint8_t *t70_val;
    uint16_t       t70_len;
    if (tlv_find(body, body_len, 0x70, &t70_val, &t70_len)) {
        inner     = t70_val;
        inner_len = t70_len;
    }

    const uint8_t *v;
    uint16_t       l;
    if (tlv_find(inner, inner_len, 0x5A, &v, &l) && !card->have_pan) {
        decode_pan(v, l, card->pan, sizeof(card->pan));
        if (card->pan[0] != '\0') card->have_pan = true;
    }
    if (tlv_find(inner, inner_len, 0x57, &v, &l)) {
        decode_track2(v, l, card);
    }
    if (tlv_find(inner, inner_len, 0x5F24, &v, &l)) {
        decode_expiry(v, l, card);
    }
    if (tlv_find(inner, inner_len, 0x5F20, &v, &l)) {
        decode_name(v, l, card);
    }
}

/*
 * Audit Item 19: AFL-driven READ RECORD.
 *
 * The AFL (Application File Locator, tag 94) is returned inside the GPO
 * response and tells us EXACTLY which (SFI, first_rec, last_rec) ranges
 * the issuer wants us to read.  Walking it instead of the fixed
 * 1..10 x 1..16 = 160-APDU sweep:
 *   - cuts ~1.5 s/card
 *   - avoids consecutive 6A83 responses that some chips treat as a card
 *     misuse heuristic and lock out
 *
 * AFL format: groups of 4 bytes
 *   byte 0: SFI (high 5 bits) | 0x04
 *   byte 1: first record
 *   byte 2: last record
 *   byte 3: number of records involved in offline data authentication
 *           (we don't care for read purposes)
 */
static bool read_records_via_afl(const rfalIsoDepDevice *isoDep,
                                 const uint8_t *afl, uint16_t afl_len,
                                 emv_card_t *card)
{
    if ((afl_len % 4U) != 0U || afl_len == 0U) return false;

    uint8_t  apdu[5];
    uint8_t  resp[300];
    uint16_t resp_len = 0;

    for (uint16_t i = 0; i + 4U <= afl_len; i += 4U) {
        uint8_t sfi_byte = afl[i];
        uint8_t sfi      = (uint8_t)(sfi_byte >> 3);
        uint8_t first    = afl[i + 1];
        uint8_t last     = afl[i + 2];
        if (sfi == 0 || sfi > 30 || first == 0 || last < first) continue;
        if (last - first > 16) continue; /* guard against malformed AFL */

        for (uint8_t rec = first; rec <= last; rec++) {
            apdu[0] = 0x00;
            apdu[1] = 0xB2;
            apdu[2] = rec;
            apdu[3] = (uint8_t)((sfi << 3) | 0x04);
            apdu[4] = 0x00;
            if (!send_apdu(isoDep, apdu, 5, resp, sizeof(resp), &resp_len)) break;
            if (!sw_ok(resp, resp_len)) break;
            merge_record_tlv(resp, (uint16_t)(resp_len - 2), card);
            if (card->have_pan && card->have_exp && card->have_name) return true;
        }
    }
    return card->have_pan;
}

/*
 * Fallback fixed walk used when no AFL is present in the GPO response.
 * Keep it conservative to bound APDU count.
 */
static void read_records(const rfalIsoDepDevice *isoDep, emv_card_t *card)
{
    uint8_t  apdu[5];
    uint8_t  resp[300];
    uint16_t resp_len = 0;

    for (uint8_t sfi = 1; sfi <= 10; sfi++) {
        for (uint8_t rec = 1; rec <= 16; rec++) {
            apdu[0] = 0x00;
            apdu[1] = 0xB2;
            apdu[2] = rec;
            apdu[3] = (uint8_t)((sfi << 3) | 0x04);
            apdu[4] = 0x00;
            if (!send_apdu(isoDep, apdu, 5, resp, sizeof(resp), &resp_len)) break;
            if (!sw_ok(resp, resp_len)) break;
            merge_record_tlv(resp, (uint16_t)(resp_len - 2), card);

            if (card->have_pan && card->have_exp && card->have_name) return;
        }
    }
}

/*
 * Run the full EMV public-data flow against the active ISO-DEP device.
 * Returns true if at least the PAN was extracted.
 */
static bool run_emv_flow(rfalNfcDevice *dev, emv_card_t *card)
{
    if (!dev || dev->rfInterface != RFAL_NFC_INTERFACE_ISODEP) return false;
    const rfalIsoDepDevice *isoDep = &dev->proto.isoDep;

    uint8_t  resp[300];
    uint16_t resp_len = 0;

    memset(card, 0, sizeof(*card));

    /* 1) SELECT PPSE */
    if (!send_apdu(isoDep, s_apdu_select_ppse, sizeof(s_apdu_select_ppse),
                   resp, sizeof(resp), &resp_len)) return false;
    if (!sw_ok(resp, resp_len)) return false;

    /* 2) Pull AIDs */
    uint8_t aids    [EMV_MAX_AIDS][EMV_AID_MAX_LEN];
    uint8_t aid_lens[EMV_MAX_AIDS];
    memset(aid_lens, 0, sizeof(aid_lens));
    uint8_t n_aids = parse_ppse_aids(resp, resp_len, aids, aid_lens,
                                     EMV_MAX_AIDS);
    if (n_aids == 0) return false;

    /* 3) SELECT first AID (Apps in priority order from the card) */
    memcpy(card->aid, aids[0], aid_lens[0]);
    card->aid_len = aid_lens[0];
    label_scheme(card);

    uint8_t sel_aid[5 + EMV_AID_MAX_LEN + 1];
    sel_aid[0] = 0x00;
    sel_aid[1] = 0xA4;
    sel_aid[2] = 0x04;
    sel_aid[3] = 0x00;
    sel_aid[4] = aid_lens[0];
    memcpy(&sel_aid[5], aids[0], aid_lens[0]);
    sel_aid[5 + aid_lens[0]] = 0x00;
    if (!send_apdu(isoDep, sel_aid, (uint16_t)(5 + aid_lens[0] + 1),
                   resp, sizeof(resp), &resp_len)) return false;
    if (!sw_ok(resp, resp_len)) return false;

    /* 4) GET PROCESSING OPTIONS with empty PDOL.
     *    On success, the response carries either:
     *      - format 1: 80 <len> <AIP[2]> <AFL[...]>
     *      - format 2: 77 ... 82(AIP) ... 94(AFL) ...
     *    We parse out tag 94 (AFL) when present so the READ RECORD walk
     *    visits ONLY the issuer-specified records (Item 19). */
    bool used_afl = false;
    if (send_apdu(isoDep, s_apdu_gpo_empty, sizeof(s_apdu_gpo_empty),
                  resp, sizeof(resp), &resp_len) &&
        sw_ok(resp, resp_len))
    {
        uint16_t body_len = (uint16_t)(resp_len - 2);
        const uint8_t *afl_val = NULL;
        uint16_t       afl_len = 0;

        /* Format 2 — search for tag 94 anywhere */
        if (tlv_find(resp, body_len, 0x94, &afl_val, &afl_len)) {
            used_afl = read_records_via_afl(isoDep, afl_val, afl_len, card);
        } else if (body_len >= 4 && resp[0] == 0x80) {
            /* Format 1 — AIP[2] then AFL[len-2] */
            uint16_t fmt1_len = resp[1];
            if (fmt1_len >= 2 && (uint16_t)(2 + fmt1_len) <= body_len) {
                afl_val = &resp[4];           /* skip AIP */
                afl_len = (uint16_t)(fmt1_len - 2U);
                used_afl = read_records_via_afl(isoDep, afl_val, afl_len, card);
            }
        }
    }

    /* 5) Fallback wide READ RECORD walk if no AFL or AFL gave nothing */
    if (!used_afl) {
        read_records(isoDep, card);
    }

    return card->have_pan;
}


/* ============================================================================ */
/*                                  DISCOVERY                                   */
/* ============================================================================ */

static bool discover_iso_dep(rfalNfcDevice **dev_out)
{
    rfalNfcDiscoverParam dp;
    rfalNfcDefaultDiscParams(&dp);
    dp.devLimit      = 1;
    dp.totalDuration = 500;
    /* Audit Item 18: extend discovery to NFC-F so JCB QUICPay (FeliCa-based)
     * and Suica-linked credit instruments enumerate.  POLL_TECH_F is
     * essentially free here — RFAL polls it after A/B and only adds a few
     * ms when no NFC-F card is present.  NFC-F devices that respond to the
     * SystemCode 0xFE00 (EMV) will activate ISO-DEP-equivalent transport
     * via the FeliCa Read Without Encryption command set; cards that do
     * not are filtered out by the "rfInterface == ISODEP" check below. */
    dp.techs2Find    = RFAL_NFC_POLL_TECH_A
                     | RFAL_NFC_POLL_TECH_B
                     | RFAL_NFC_POLL_TECH_F;
    dp.compMode      = RFAL_COMPLIANCE_MODE_NFC;

    if (rfalNfcDiscover(&dp) != RFAL_ERR_NONE) return false;

    /* Pump the worker until activated or timed out */
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(800);
    while (xTaskGetTickCount() < deadline) {
        rfalNfcWorker();
        if (rfalNfcIsDevActivated(rfalNfcGetState())) {
            rfalNfcDevice *dev = NULL;
            rfalNfcGetActiveDevice(&dev);
            if (dev && dev->rfInterface == RFAL_NFC_INTERFACE_ISODEP) {
                *dev_out = dev;
                return true;
            }
            return false;
        }
        vTaskDelay(2);
    }
    return false;
}


/* ============================================================================ */
/*                                    UI                                        */
/* ============================================================================ */

static void draw_intro(void)
{
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "EMV Card Reader");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 26, "Hold contactless");
    u8g2_DrawStr(&m1_u8g2, 2, 36, "card on M1");
    u8g2_DrawStr(&m1_u8g2, 2, 48, "Reads PAN/exp/name");
    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "BACK=Exit");
    m1_u8g2_nextpage();
}

static void draw_reading(void)
{
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 26, "Reading EMV...");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 42, "Hold card steady");
    m1_u8g2_nextpage();
}

static void mask_pan(const char *pan, char *out, size_t out_max)
{
    size_t n = strlen(pan);
    if (n == 0) {
        snprintf(out, out_max, "----");
        return;
    }
    if (n <= 4) {
        snprintf(out, out_max, "**** %s", pan);
        return;
    }
    /* "**** **** **** 1234" style truncated to fit */
    const char *last4 = pan + (n - 4);
    snprintf(out, out_max, "**** **** **** %s", last4);
}

static void draw_result(const emv_card_t *card)
{
    char pan_disp[24];
    mask_pan(card->pan, pan_disp, sizeof(pan_disp));

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 10, "EMV Read OK");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    char l[40];
    snprintf(l, sizeof(l), "%s", card->scheme);
    u8g2_DrawStr(&m1_u8g2, 2, 22, l);

    snprintf(l, sizeof(l), "Card:");
    u8g2_DrawStr(&m1_u8g2, 2, 32, l);
    u8g2_DrawStr(&m1_u8g2, 2, 42, pan_disp);

    if (card->have_exp) {
        snprintf(l, sizeof(l), "Exp: %s  %s",
                 card->exp_mmyy,
                 card->have_name ? card->name : "");
    } else {
        snprintf(l, sizeof(l), "%s",
                 card->have_name ? card->name : "");
    }
    u8g2_DrawStr(&m1_u8g2, 2, 52, l);

    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "OK=Again BACK=Exit");
    m1_u8g2_nextpage();
}


/* ============================================================================ */
/*                              SAVE TO SD CARD                                 */
/* ============================================================================ */

/* PCI-DSS Requirement 3.3 / 3.4:
 *
 * Storing the full primary account number, expiry date, and cardholder
 * name together in clear on persistent removable media (SD card) makes
 * this device a contactless skimmer with persistent storage.  This is
 * forbidden whether or not the operator owns the card.
 *
 * We therefore:
 *   - Write only the masked PAN (last 4 digits) to SD.
 *   - NEVER write the cardholder name or expiry date to SD.  The operator
 *     can still see them on the device display during the active session.
 *   - Tag the file with a clear notice so it is obvious to anyone reading
 *     the SD what was (and was not) captured.
 */
static void save_emv(const emv_card_t *card)
{
    FIL fk;
    if (m1_fb_open_new_file(&fk, "0:/NFC/emv_data.txt") != 0) return;

    char line[96];
    snprintf(line, sizeof(line),
             "# EMV public data - masked per PCI-DSS\r\n"
             "# PAN last-4 only; expiry/name NEVER written to SD\r\n");
    m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));

    snprintf(line, sizeof(line), "Scheme: %s\r\n", card->scheme);
    m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));

    /* AID hex */
    char aid_hex[2 * EMV_AID_MAX_LEN + 1] = {0};
    for (uint8_t i = 0; i < card->aid_len; i++) {
        snprintf(&aid_hex[i * 2], 3, "%02X", card->aid[i]);
    }
    snprintf(line, sizeof(line), "AID: %s\r\n", aid_hex);
    m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));

    if (card->have_pan) {
        char masked[24];
        mask_pan(card->pan, masked, sizeof(masked));
        snprintf(line, sizeof(line), "PAN: %s\r\n", masked);
        m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));
    }
    /* Expiry and cardholder name intentionally not persisted.
     * Either field, combined with the masked PAN's last 4 + BIN exposure
     * via the AID, is enough to enable card-not-present fraud. */
    m1_fb_close_file(&fk);
}


/* ============================================================================ */
/*                                ENTRY POINT                                   */
/* ============================================================================ */

void app_nfc_emv_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    bool                running = true;
    bool                redraw  = true;
    enum { ST_INTRO, ST_RESULT, ST_FAIL } state = ST_INTRO;
    emv_card_t          card;
    TickType_t          next_poll = 0;

    if (rfalNfcInitialize() != RFAL_ERR_NONE) {
        m1_message_box(&m1_u8g2, "EMV Reader", "RFAL init failed",
                       " ", "BACK to return");
        return;
    }
    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_M, LED_FASTBLINK_ONTIME_M);

    memset(&card, 0, sizeof(card));

    while (running) {
        if (redraw) {
            redraw = false;
            switch (state) {
            case ST_INTRO:  draw_intro(); break;
            case ST_RESULT: draw_result(&card); break;
            case ST_FAIL:
                m1_message_box(&m1_u8g2, "EMV Reader",
                               "Read failed",
                               "Not an EMV card?",
                               "OK=Retry BACK=Exit");
                break;
            }
        }

        TickType_t now = xTaskGetTickCount();

        if (state == ST_INTRO && now >= next_poll) {
            draw_reading();
            rfalNfcDevice *dev = NULL;
            if (discover_iso_dep(&dev)) {
                if (run_emv_flow(dev, &card)) {
                    save_emv(&card);
                    m1_buzzer_notification();
                    state = ST_RESULT;
                } else {
                    state = ST_FAIL;
                }
                rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
                redraw = true;
                continue;
            }
            rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
            draw_intro();
            next_poll = now + pdMS_TO_TICKS(400);
        }

        TickType_t deadline = now + pdMS_TO_TICKS(200);
        TickType_t wait = (deadline > xTaskGetTickCount()) ?
                          (deadline - xTaskGetTickCount()) : 0;
        ret = xQueueReceive(main_q_hdl, &q_item, wait);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        ret = xQueueReceive(button_events_q_hdl, &btn, 0);
        if (ret != pdTRUE) continue;

        switch (state) {
        case ST_INTRO:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            }
            break;
        case ST_RESULT:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                state = ST_INTRO;
                redraw = true;
                next_poll = 0;
            }
            break;
        case ST_FAIL:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                state = ST_INTRO;
                redraw = true;
                next_poll = 0;
            }
            break;
        }
    }

    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_OFF, LED_FASTBLINK_ONTIME_OFF);
    rfalFieldOff();
    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    xQueueReset(main_q_hdl);
}

#endif /* M1_APP_NFC_EMV_ENABLE */
