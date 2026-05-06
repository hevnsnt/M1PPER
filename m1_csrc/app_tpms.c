/* See COPYING.txt for license details. */

/*
 * app_tpms.c
 *
 * Tire-Pressure Monitoring System (TPMS) sensor decoder.
 *
 * Pipeline:
 *   1) User picks 315 MHz (US) or 433.92 MHz (EU).
 *   2) SI4463 is brought up in OOK direct-mode RX. (Most TPMS sensors are
 *      FSK but their bursts produce useful envelope edges in the SI4463
 *      OOK/peak-detector path; this is the same trick the existing
 *      Sub-GHz read / repeater / POCSAG paths use.)
 *   3) The TIM1 input-capture pipeline drains run-length timings, in
 *      microseconds, into the existing uint16_t ring buffer.
 *   4) Each run is converted into one or two Manchester chips using a
 *      bit period of 50 us (Schrader / generic, ~20 kbps) and fed into
 *      a sliding shift register.
 *   5) When a known preamble + sync pattern matches, the next N data
 *      bits are unpacked into bytes and dispatched to the matching
 *      protocol decoder. If nothing matches, the raw bytes are shown.
 *   6) Decoded sensors are kept in a small table; user can assign
 *      readings to FL/FR/RL/RR with OK and view a 4-wheel summary.
 *
 * Static memory only: no heap.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

#include "m1_compile_cfg.h"

#ifdef M1_APP_TPMS_ENABLE

#include "ff.h"

#include "app_tpms.h"
#include "m1_lcd.h"
#include "m1_display.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_lib.h"
#include "m1_buzzer.h"
#include "m1_sub_ghz.h"
#include "m1_sub_ghz_api.h"
#include "m1_ring_buffer.h"

/* ============================================================================
 * Tuning
 * ============================================================================ */

#define TPMS_RING_SLOTS          1024U
#define TPMS_BIT_BUF_LEN         512U     /* sliding chip / bit window */
#define TPMS_SCAN_TIMEOUT_S      30U
#define TPMS_MAX_SENSORS         8U

/* Default Manchester chip period in microseconds. Most TPMS protocols
 * sit in the 9.6..20 kbps range.  Schrader encodes around 10 kbps -> bit
 * period ~100 us -> Manchester chip ~50 us.  Citroen sits near 19.2 kbps
 * -> chip ~26 us.  We try a small set of chip periods with a +-30 %
 * tolerance window. */
typedef struct {
    uint16_t chip_us;          /* one Manchester half-bit, microseconds */
    uint16_t tol_us;           /* +- tolerance for "1 chip" classification */
    uint16_t double_us;        /* two chips                                */
    uint16_t double_tol_us;
    const char *label;
} tpms_rate_t;

static const tpms_rate_t s_tpms_rates[] = {
    { 50,  20,  100, 35, "10 kbps" },   /* Schrader / generic           */
    { 26,  10,   52, 18, "19.2 kbps" }, /* Citroen / Peugeot 64-bit FSK */
    { 100, 35,  200, 70, "5 kbps"  }    /* Some old generic OOK sensors */
};

#define TPMS_RATE_COUNT  (sizeof(s_tpms_rates) / sizeof(s_tpms_rates[0]))

/* ============================================================================
 * Frequency presets
 * ============================================================================ */

typedef struct {
    uint32_t   freq_hz;
    const char *label;
} tpms_freq_preset_t;

static const tpms_freq_preset_t s_tpms_freq_presets[] = {
    { 315000000UL, "315 MHz (US)" },
    { 433920000UL, "433 MHz (EU)" }
};

#define TPMS_FREQ_PRESET_COUNT \
    (sizeof(s_tpms_freq_presets) / sizeof(s_tpms_freq_presets[0]))

/* ============================================================================
 * Decoder state
 * ============================================================================ */

typedef enum {
    TPMS_PROTO_UNKNOWN = 0,
    TPMS_PROTO_SCHRADER,
    TPMS_PROTO_CITROEN,
    TPMS_PROTO_GENERIC
} tpms_proto_t;

typedef struct {
    bool       used;
    uint32_t   sensor_id;       /* 32-bit ID */
    int16_t    pressure_x10_psi;/* PSI * 10 (e.g. 325 = 32.5 PSI) */
    int8_t     temp_c;          /* Celsius */
    uint8_t    flags;           /* status byte if available */
    tpms_proto_t proto;
    uint8_t    raw[8];          /* up to 8 bytes of payload preview */
    uint8_t    raw_len;
    uint32_t   last_seen_ms;
    uint8_t    wheel;           /* 0=unassigned 1=FL 2=FR 3=RL 4=RR */
} tpms_sensor_t;

typedef struct {
    /* Sliding chip window: each entry is 0 or 1. */
    uint8_t    chips[TPMS_BIT_BUF_LEN];
    uint16_t   chip_count;

    /* Edge state for "current level" while consuming runs. */
    uint8_t    cur_level;

    /* Stats. */
    uint32_t   packets_seen;
    uint32_t   packets_decoded;
    uint8_t    rate_idx;

    /* Sensor table. */
    tpms_sensor_t sensors[TPMS_MAX_SENSORS];
    uint8_t       sensor_count;
    int8_t        last_decoded_idx;   /* -1 if none */
} tpms_ctx_t;

static tpms_ctx_t s_ctx;

/* Static buffers. */
static uint16_t s_ring_storage[TPMS_RING_SLOTS];
static uint16_t s_consume[256];

/* ============================================================================
 * Bit / chip helpers
 * ============================================================================ */

static void tpms_chip_buf_reset(void)
{
    s_ctx.chip_count = 0;
    s_ctx.cur_level = 0;
}

static void tpms_chip_push(uint8_t chip)
{
    if (s_ctx.chip_count < TPMS_BIT_BUF_LEN)
    {
        s_ctx.chips[s_ctx.chip_count++] = (uint8_t)(chip & 1U);
    }
    else
    {
        /* Slide window left by 1 to keep recent chips. */
        memmove(&s_ctx.chips[0], &s_ctx.chips[1], TPMS_BIT_BUF_LEN - 1U);
        s_ctx.chips[TPMS_BIT_BUF_LEN - 1U] = (uint8_t)(chip & 1U);
    }
}

/* Convert a level run-length in microseconds into an integer number of
 * Manchester chips, with tolerance. Returns 0 if the run looks like
 * noise / cannot be quantised. */
static uint8_t tpms_run_to_chips(uint32_t dur_us, const tpms_rate_t *rate)
{
    if (dur_us + rate->tol_us < rate->chip_us) return 0;     /* glitch */

    /* Try the most common counts first (1 chip, 2 chips, 3, 4). */
    if (dur_us >= (uint32_t)rate->chip_us - rate->tol_us &&
        dur_us <= (uint32_t)rate->chip_us + rate->tol_us)
        return 1;

    if (dur_us >= (uint32_t)rate->double_us - rate->double_tol_us &&
        dur_us <= (uint32_t)rate->double_us + rate->double_tol_us)
        return 2;

    /* Long carrier-on or carrier-off (preamble runs or end-of-burst).
     * Round to nearest integer chip count, capped at 8 so the shift
     * register cannot be flooded. */
    uint32_t n = (dur_us + (rate->chip_us / 2U)) / rate->chip_us;
    if (n == 0U) return 0;
    if (n > 8U)  n = 8U;
    return (uint8_t)n;
}

/* Push a level run to the chip buffer. */
static void tpms_consume_run(uint32_t dur_us, uint8_t level,
                             const tpms_rate_t *rate)
{
    uint8_t n = tpms_run_to_chips(dur_us, rate);
    while (n--)
    {
        tpms_chip_push(level);
    }
}

/* Decode a contiguous Manchester chip run into bits.
 * Return number of bits decoded, write into out[0..*pn-1]. */
static uint16_t tpms_manchester_decode(const uint8_t *chips, uint16_t nchips,
                                       uint8_t *out, uint16_t out_max,
                                       bool invert)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i + 1U < nchips; i += 2U)
    {
        uint8_t a = chips[i];
        uint8_t b = chips[i + 1U];
        if (a == b)
        {
            /* Two chips at the same level = encoding violation. Stop. */
            break;
        }
        uint8_t bit;
        if (!invert)
        {
            /* IEEE 802.3 / G.E. Thomas: 10 = 0, 01 = 1.
             * a=1 b=0 -> 0, a=0 b=1 -> 1 */
            bit = (a == 0U) ? 1U : 0U;
        }
        else
        {
            /* Differential / inverted Manchester. */
            bit = (a == 0U) ? 0U : 1U;
        }
        if (n >= out_max) break;
        out[n++] = bit;
    }
    return n;
}

/* ============================================================================
 * Sliding sync detector
 * ============================================================================ */

/* Try to find a known preamble + sync inside the chip buffer.
 * Each protocol provides:
 *   - a chip-level expected pattern length (for fast scan), OR
 *   - a Manchester-decoded sync byte sequence at known bit offset.
 *
 * For simplicity we Manchester-decode the whole window and search for
 * sync bytes inside the resulting bit stream. */

#define TPMS_DECODED_BIT_MAX  (TPMS_BIT_BUF_LEN / 2U)
static uint8_t s_decoded_bits[TPMS_DECODED_BIT_MAX];

static uint16_t tpms_decode_window(bool invert)
{
    return tpms_manchester_decode(s_ctx.chips, s_ctx.chip_count,
                                  s_decoded_bits, TPMS_DECODED_BIT_MAX,
                                  invert);
}

/* Pack 8 bits MSB-first starting at bit_offset into a byte. */
static uint8_t tpms_pack_byte(const uint8_t *bits, uint16_t bit_offset)
{
    uint8_t v = 0;
    for (uint8_t i = 0; i < 8U; i++)
    {
        v = (uint8_t)((v << 1) | (bits[bit_offset + i] & 1U));
    }
    return v;
}

/* Find the first occurrence of a sync pattern (in bits) inside the
 * decoded bit stream. Returns bit offset or -1. */
static int32_t tpms_find_sync(const uint8_t *bits, uint16_t nbits,
                              const uint8_t *sync_bytes, uint8_t sync_len)
{
    uint16_t total_sync_bits = (uint16_t)sync_len * 8U;
    if (nbits < total_sync_bits) return -1;

    for (uint16_t off = 0; off + total_sync_bits <= nbits; off++)
    {
        bool match = true;
        for (uint8_t b = 0; b < sync_len; b++)
        {
            uint8_t v = tpms_pack_byte(bits, (uint16_t)(off + b * 8U));
            if (v != sync_bytes[b])
            {
                match = false;
                break;
            }
        }
        if (match) return (int32_t)off;
    }
    return -1;
}

/* ============================================================================
 * Sensor table
 * ============================================================================ */

static int8_t tpms_find_or_add_sensor(uint32_t sensor_id, tpms_proto_t proto)
{
    for (uint8_t i = 0; i < s_ctx.sensor_count; i++)
    {
        if (s_ctx.sensors[i].used &&
            s_ctx.sensors[i].sensor_id == sensor_id &&
            s_ctx.sensors[i].proto == proto)
        {
            return (int8_t)i;
        }
    }
    if (s_ctx.sensor_count < TPMS_MAX_SENSORS)
    {
        uint8_t idx = s_ctx.sensor_count++;
        memset(&s_ctx.sensors[idx], 0, sizeof(s_ctx.sensors[idx]));
        s_ctx.sensors[idx].used = true;
        s_ctx.sensors[idx].sensor_id = sensor_id;
        s_ctx.sensors[idx].proto = proto;
        return (int8_t)idx;
    }
    /* Replace the oldest. */
    int8_t oldest = 0;
    uint32_t oldest_ms = s_ctx.sensors[0].last_seen_ms;
    for (uint8_t i = 1; i < s_ctx.sensor_count; i++)
    {
        if (s_ctx.sensors[i].last_seen_ms < oldest_ms)
        {
            oldest = (int8_t)i;
            oldest_ms = s_ctx.sensors[i].last_seen_ms;
        }
    }
    memset(&s_ctx.sensors[oldest], 0, sizeof(s_ctx.sensors[oldest]));
    s_ctx.sensors[oldest].used = true;
    s_ctx.sensors[oldest].sensor_id = sensor_id;
    s_ctx.sensors[oldest].proto = proto;
    return oldest;
}

/* ============================================================================
 * Persistence (SD card)
 * ============================================================================ */

static const char *tpms_proto_name(tpms_proto_t p)
{
    switch (p)
    {
        case TPMS_PROTO_SCHRADER: return "Schrader";
        case TPMS_PROTO_CITROEN:  return "Citroen";
        case TPMS_PROTO_GENERIC:  return "Generic";
        default:                  return "Unknown";
    }
}

static void tpms_log_to_sd(const tpms_sensor_t *s)
{
    FIL    file;
    UINT   bw;
    FRESULT fr;
    m1_time_t now;
    char   line[160];
    const char *flag_str = (s->flags == 0) ? "OK" : "FLAG";

    f_mkdir("/SubGHz");

    fr = f_open(&file, "/SubGHz/tpms_log.txt", FA_WRITE | FA_OPEN_APPEND);
    if (fr != FR_OK)
    {
        fr = f_open(&file, "/SubGHz/tpms_log.txt",
                    FA_WRITE | FA_CREATE_ALWAYS);
        if (fr != FR_OK) return;
    }

    m1_get_localtime(&now);
    snprintf(line, sizeof(line),
             "%04u-%02u-%02u,%02u:%02u,%s,%08lX,%d.%d,%d,%s\r\n",
             (unsigned)now.year, (unsigned)now.month, (unsigned)now.day,
             (unsigned)now.hour, (unsigned)now.minute,
             tpms_proto_name(s->proto),
             (unsigned long)s->sensor_id,
             (int)(s->pressure_x10_psi / 10),
             (int)((s->pressure_x10_psi < 0
                    ? -s->pressure_x10_psi : s->pressure_x10_psi) % 10),
             (int)s->temp_c,
             flag_str);

    (void)f_write(&file, line, (UINT)strlen(line), &bw);
    f_sync(&file);
    f_close(&file);
}

/* ============================================================================
 * Protocol decoders
 * ============================================================================ */

/* Generic 8-bit CRC with arbitrary polynomial.  Used to validate decoded
 * TPMS frames before accepting them; without this any 16-bit sync match in
 * a 256-chip noise window populates tpms_log.txt with hallucinated sensors. */
static uint8_t tpms_crc8(const uint8_t *data, uint8_t len, uint8_t poly,
                         uint8_t init)
{
    uint8_t crc = init;
    for (uint8_t i = 0; i < len; i++)
    {
        crc ^= data[i];
        for (uint8_t b = 0; b < 8U; b++)
        {
            crc = (crc & 0x80U) ? (uint8_t)((crc << 1) ^ poly) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

/* Reject decoded frames whose pressure or temperature falls outside any
 * physically plausible tire range.  Pressures are in PSI*10, temps in C. */
static bool tpms_values_plausible(int16_t psi_x10, int8_t temp_c)
{
    /* Pressure 10..80 PSI, temperature -40..+90 C. */
    if (psi_x10 < 100 || psi_x10 > 800) return false;
    if (temp_c  < -40 || temp_c  > 90)  return false;
    return true;
}

/* Schrader (legacy US TPMS):
 *   preamble: 0xFF 0xFF
 *   sync    : 0x0F
 *   payload : ID (3-4 bytes) + pressure (1) + temperature (1) + flags(1)
 * Pressure unit: 0.25 PSI per LSB.
 * Temperature : signed Celsius, offset 40 (so byte = degC + 40).
 *
 * We accept the simplified 4-byte payload variant described in the spec. */
static const uint8_t s_sync_schrader[] = { 0xFF, 0x0F };

static bool tpms_decode_schrader(const uint8_t *bits, uint16_t nbits,
                                 int32_t sync_off, tpms_sensor_t *out)
{
    /* Need 4 payload bytes + 1 CRC byte after the 2-byte sync. */
    uint16_t want = (uint16_t)sync_off + 2U * 8U + 5U * 8U;
    if (want > nbits) return false;

    uint8_t pl[4];
    for (uint8_t i = 0; i < 4U; i++)
    {
        pl[i] = tpms_pack_byte(bits, (uint16_t)(sync_off + 16 + i * 8));
    }
    uint8_t crc_rx = tpms_pack_byte(bits, (uint16_t)(sync_off + 16 + 4 * 8));

    /* Schrader / generic CRC8 polynomial 0x07, init 0x00, over the 4
     * payload bytes.  Reject if the trailing byte doesn't match. */
    if (tpms_crc8(pl, 4U, 0x07U, 0x00U) != crc_rx) return false;

    int16_t psi_x10 = (int16_t)((uint16_t)pl[1] * 25U / 10U);
    int8_t  temp_c  = (int8_t)((int16_t)pl[2] - 40);
    if (!tpms_values_plausible(psi_x10, temp_c)) return false;

    /* byte[0] is also part of the ID in some real Schrader frames; the
     * spec told us to use byte[1] for pressure / byte[2] for temperature
     * / byte[3] for status. */
    out->proto = TPMS_PROTO_SCHRADER;
    out->sensor_id = (uint32_t)pl[0] << 24;   /* 8-bit shown left-padded */
    out->pressure_x10_psi = psi_x10;
    out->temp_c = temp_c;
    out->flags = pl[3];
    out->raw_len = 4;
    memcpy(out->raw, pl, 4);
    return true;
}

/* Citroen / Peugeot:
 *   64-bit Manchester payload, sync looks like 0xAAAAA9AB or similar.
 *   ID = bits[63:32], pressure = bits[31:24] in kPa * 0.75, temp = bits[23:16] - 40.
 * We use a coarse sync of 0xAA 0xA9 (16 bits) then read 8 bytes. */
static const uint8_t s_sync_citroen[] = { 0xAA, 0xA9 };

static bool tpms_decode_citroen(const uint8_t *bits, uint16_t nbits,
                                int32_t sync_off, tpms_sensor_t *out)
{
    uint16_t want = (uint16_t)sync_off + 2U * 8U + 8U * 8U;
    if (want > nbits) return false;

    uint8_t pl[8];
    for (uint8_t i = 0; i < 8U; i++)
    {
        pl[i] = tpms_pack_byte(bits, (uint16_t)(sync_off + 16 + i * 8));
    }

    /* Citroen frame: pl[7] is the trailing CRC over pl[0..6] using
     * polynomial 0x07, init 0x00 (same family as Schrader / SAE J2602). */
    if (tpms_crc8(pl, 7U, 0x07U, 0x00U) != pl[7]) return false;

    /* pressure in kPa * 0.75, convert to PSI*10 (1 kPa ~= 0.145 PSI). */
    uint16_t kpa_x4 = (uint16_t)pl[4] * 3U;     /* kPa = pl[4]*0.75 -> *4 = pl[4]*3 */
    int32_t  psi_x10 = (int32_t)kpa_x4 * 145 / 400;  /* (kPa*4)*0.145/4 = PSI */
    int8_t   temp_c  = (int8_t)((int16_t)pl[5] - 40);
    if (!tpms_values_plausible((int16_t)psi_x10, temp_c)) return false;

    out->proto = TPMS_PROTO_CITROEN;
    out->sensor_id = ((uint32_t)pl[0] << 24) |
                     ((uint32_t)pl[1] << 16) |
                     ((uint32_t)pl[2] << 8)  |
                      (uint32_t)pl[3];
    out->pressure_x10_psi = (int16_t)psi_x10;
    out->temp_c = temp_c;
    out->flags = pl[6];
    out->raw_len = 8;
    memcpy(out->raw, pl, 8);
    return true;
}

/* Generic decoder: assume 4 bytes ID + 1 byte pressure + 1 byte temp +
 * 1 byte flags, after a permissive 0xAA 0xAA preamble. */
static const uint8_t s_sync_generic[] = { 0xAA, 0xAA };

static bool tpms_decode_generic(const uint8_t *bits, uint16_t nbits,
                                int32_t sync_off, tpms_sensor_t *out)
{
    uint16_t want = (uint16_t)sync_off + 2U * 8U + 7U * 8U;
    if (want > nbits) return false;

    uint8_t pl[7];
    for (uint8_t i = 0; i < 7U; i++)
    {
        pl[i] = tpms_pack_byte(bits, (uint16_t)(sync_off + 16 + i * 8));
    }

    /* Reject obvious all-zero or all-FF payloads to avoid bogus reports. */
    bool all_zero = true, all_ff = true;
    for (uint8_t i = 0; i < 7U; i++)
    {
        if (pl[i] != 0x00U) all_zero = false;
        if (pl[i] != 0xFFU) all_ff = false;
    }
    if (all_zero || all_ff) return false;

    int16_t psi_x10 = (int16_t)((uint16_t)pl[4] * 25U / 10U);
    int8_t  temp_c  = (int8_t)((int16_t)pl[5] - 40);

    /* Without a known CRC scheme for the generic decoder, fall back to a
     * physical-plausibility check on the decoded values.  This still rejects
     * the great majority of random 433 MHz noise that previously populated
     * tpms_log.txt with hallucinated sensors. */
    if (!tpms_values_plausible(psi_x10, temp_c)) return false;

    out->proto = TPMS_PROTO_GENERIC;
    out->sensor_id = ((uint32_t)pl[0] << 24) |
                     ((uint32_t)pl[1] << 16) |
                     ((uint32_t)pl[2] << 8)  |
                      (uint32_t)pl[3];
    out->pressure_x10_psi = psi_x10;
    out->temp_c = temp_c;
    out->flags = pl[6];
    out->raw_len = 7;
    memcpy(out->raw, pl, 7);
    return true;
}

/* Try every known protocol on the current chip window. */
static bool tpms_try_decode_all(void)
{
    bool any = false;

    /* Try both Manchester polarities. */
    for (uint8_t inv = 0; inv < 2U; inv++)
    {
        uint16_t nbits = tpms_decode_window(inv != 0U);
        if (nbits < 32U) continue;

        tpms_sensor_t found;
        memset(&found, 0, sizeof(found));
        bool ok = false;

        int32_t off = tpms_find_sync(s_decoded_bits, nbits,
                                     s_sync_schrader,
                                     (uint8_t)sizeof(s_sync_schrader));
        if (off >= 0)
        {
            ok = tpms_decode_schrader(s_decoded_bits, nbits, off, &found);
        }
        if (!ok)
        {
            off = tpms_find_sync(s_decoded_bits, nbits,
                                 s_sync_citroen,
                                 (uint8_t)sizeof(s_sync_citroen));
            if (off >= 0)
            {
                ok = tpms_decode_citroen(s_decoded_bits, nbits, off, &found);
            }
        }
        if (!ok)
        {
            off = tpms_find_sync(s_decoded_bits, nbits,
                                 s_sync_generic,
                                 (uint8_t)sizeof(s_sync_generic));
            if (off >= 0)
            {
                ok = tpms_decode_generic(s_decoded_bits, nbits, off, &found);
            }
        }

        if (ok)
        {
            int8_t idx = tpms_find_or_add_sensor(found.sensor_id,
                                                 found.proto);
            if (idx >= 0)
            {
                /* Preserve wheel assignment if any. */
                uint8_t prev_wheel = s_ctx.sensors[idx].wheel;
                s_ctx.sensors[idx].pressure_x10_psi = found.pressure_x10_psi;
                s_ctx.sensors[idx].temp_c = found.temp_c;
                s_ctx.sensors[idx].flags = found.flags;
                s_ctx.sensors[idx].proto = found.proto;
                s_ctx.sensors[idx].raw_len = found.raw_len;
                memcpy(s_ctx.sensors[idx].raw, found.raw, found.raw_len);
                s_ctx.sensors[idx].last_seen_ms =
                    (uint32_t)xTaskGetTickCount();
                s_ctx.sensors[idx].wheel = prev_wheel;
                s_ctx.last_decoded_idx = idx;
                s_ctx.packets_decoded++;
                tpms_log_to_sd(&s_ctx.sensors[idx]);
                m1_buzzer_notification();
                any = true;
            }
            /* Clear chip buffer to avoid double-decoding the same frame. */
            tpms_chip_buf_reset();
            break;
        }
    }
    return any;
}

/* ============================================================================
 * Capture / drain
 * ============================================================================ */

static void tpms_drain(void)
{
    const tpms_rate_t *rate = &s_tpms_rates[s_ctx.rate_idx];
    uint32_t avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);

    while (avail > 0U)
    {
        uint16_t want = (avail > (uint16_t)(sizeof(s_consume) /
                                            sizeof(s_consume[0])))
                        ? (uint16_t)(sizeof(s_consume) / sizeof(s_consume[0]))
                        : (uint16_t)avail;
        uint16_t got = m1_ringbuffer_read(&subghz_rx_rawdata_rb,
                                          (uint8_t *)s_consume, want);
        if (got == 0U) break;

        for (uint16_t i = 0; i < got; i++)
        {
            uint32_t dur = s_consume[i];
            if (dur == 0U) dur = 1U;
            tpms_consume_run(dur, s_ctx.cur_level, rate);
            s_ctx.cur_level ^= 1U;

            /* Try a decode every time we have at least one full short
             * frame's worth of chips available. */
            if (s_ctx.chip_count >= 96U)   /* ~48 bits payload candidate */
            {
                if (tpms_try_decode_all())
                {
                    /* Buffer was reset inside try_decode_all; skip more. */
                }
            }
        }
        avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);
    }
}

/* ============================================================================
 * Radio bring-up / tear-down
 * ============================================================================ */

static void tpms_radio_start(uint32_t freq_hz)
{
    radio_init_rx_tx(SUB_GHZ_BAND_433_92, MODEM_MOD_TYPE_OOK, true);
    SI446x_Change_State(
        SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_READY);
    SI446x_Set_Frequency(freq_hz);
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_RX);
    SI446x_Start_Rx(0);
    /* TPMS bursts are short (~1 ms), 9.6-19.2 kbps, with sharp envelope
     * edges from the FSK modulation that the SI4463 OOK peak detector still
     * resolves at high enough SNR.  Use a faster PDTC and a tighter
     * averaging window than the slow-baud POCSAG profile. */
    SI446x_Apply_OOK_RX_Profile(/*pdtc*/    0x2A,
                                /*cnt1*/    0x40,
                                /*raw_ctrl*/0x82,
                                /*raw_eye*/ 0x4F);

    m1_ringbuffer_init(&subghz_rx_rawdata_rb,
                       (uint8_t *)s_ring_storage,
                       (uint16_t)TPMS_RING_SLOTS,
                       (uint8_t)sizeof(uint16_t));
    m1_ringbuffer_reset(&subghz_rx_rawdata_rb);

    sub_ghz_pulse_capture_arm();
}

static void tpms_radio_stop(void)
{
    sub_ghz_pulse_capture_disarm();
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_ISOLATED);
    SI446x_Change_State(
        SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_SLEEP);
    subghz_rx_rawdata_rb.pdata = NULL;
}

/* ============================================================================
 * UI: frequency picker
 * ============================================================================ */

static uint32_t tpms_pick_frequency(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint8_t             sel = 1;     /* default 433 MHz */
    bool                done = false;
    uint32_t            chosen = 0UL;

    while (!done)
    {
        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
            u8g2_DrawStr(&m1_u8g2, 0, 10, "TPMS Decoder");
            u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

            u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
            for (uint8_t i = 0; i < TPMS_FREQ_PRESET_COUNT; i++)
            {
                uint8_t y = (uint8_t)(26 + i * 12);
                if (i == sel)
                {
                    u8g2_DrawBox(&m1_u8g2, 0, (uint8_t)(y - 9), 128, 12);
                    u8g2_SetDrawColor(&m1_u8g2, 0);
                    u8g2_DrawStr(&m1_u8g2, 4, y,
                                 s_tpms_freq_presets[i].label);
                    u8g2_SetDrawColor(&m1_u8g2, 1);
                }
                else
                {
                    u8g2_DrawStr(&m1_u8g2, 4, y,
                                 s_tpms_freq_presets[i].label);
                }
            }

            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 0, 56, "\x18\x19:Pick OK:Scan");
            u8g2_DrawStr(&m1_u8g2, 0, 64, "BACK:Exit");
        } while (u8g2_NextPage(&m1_u8g2));

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &bs, 0);

        if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            done = true;
        }
        else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel == 0)
                            ? (TPMS_FREQ_PRESET_COUNT - 1U)
                            : (sel - 1U));
        }
        else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel + 1U) % TPMS_FREQ_PRESET_COUNT);
        }
        else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            chosen = s_tpms_freq_presets[sel].freq_hz;
            done = true;
        }
    }

    xQueueReset(main_q_hdl);
    return chosen;
}

/* ============================================================================
 * UI: scanning / results screens
 * ============================================================================ */

static void tpms_format_pressure(int16_t psi_x10, char *buf, size_t buflen)
{
    int sign = (psi_x10 < 0) ? -1 : 1;
    int abs_x10 = (psi_x10 < 0) ? -psi_x10 : psi_x10;
    snprintf(buf, buflen, "%s%d.%d", (sign < 0) ? "-" : "",
             abs_x10 / 10, abs_x10 % 10);
}

static void tpms_draw_scanning(uint32_t freq_hz, uint32_t elapsed_s)
{
    char l_top[28];
    char l_count[28];
    char l_time[28];

    snprintf(l_top, sizeof(l_top), "TPMS | %lu.%02lu MHz",
             (unsigned long)(freq_hz / 1000000UL),
             (unsigned long)((freq_hz % 1000000UL) / 10000UL));
    snprintf(l_count, sizeof(l_count), "Sensors: %u",
             (unsigned)s_ctx.sensor_count);
    snprintf(l_time, sizeof(l_time), "Listening %lus",
             (unsigned long)elapsed_s);

    u8g2_FirstPage(&m1_u8g2);
    do {
        u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 0, 10, l_top);
        u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 24, l_time);
        u8g2_DrawStr(&m1_u8g2, 0, 34, l_count);

        /* Show last decoded sensor mini-line. */
        if (s_ctx.last_decoded_idx >= 0)
        {
            const tpms_sensor_t *s =
                &s_ctx.sensors[s_ctx.last_decoded_idx];
            char line[28];
            char psi[8];
            tpms_format_pressure(s->pressure_x10_psi, psi, sizeof(psi));
            snprintf(line, sizeof(line), "%08lX %sp %dC",
                     (unsigned long)s->sensor_id, psi, (int)s->temp_c);
            u8g2_DrawStr(&m1_u8g2, 0, 46, line);
        }
        else
        {
            u8g2_DrawStr(&m1_u8g2, 0, 46, "No packets yet");
        }

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 64,
                     "OK:Assign LFT:Sum BACK:Exit");
    } while (u8g2_NextPage(&m1_u8g2));
}

static const char *tpms_wheel_label(uint8_t wheel)
{
    switch (wheel)
    {
        case 1: return "FL";
        case 2: return "FR";
        case 3: return "RL";
        case 4: return "RR";
        default: return "--";
    }
}

static void tpms_draw_summary(void)
{
    char l_top[28];
    char l[4][28];

    snprintf(l_top, sizeof(l_top), "TPMS Summary");

    /* Initialise four lines to "[---]" by default. */
    for (uint8_t i = 0; i < 4U; i++)
    {
        snprintf(l[i], sizeof(l[i]), "%s: [---]",
                 tpms_wheel_label((uint8_t)(i + 1U)));
    }

    /* Fill in any sensor with a wheel assignment. */
    for (uint8_t i = 0; i < s_ctx.sensor_count; i++)
    {
        const tpms_sensor_t *s = &s_ctx.sensors[i];
        if (!s->used) continue;
        if (s->wheel < 1U || s->wheel > 4U) continue;
        char psi[8];
        tpms_format_pressure(s->pressure_x10_psi, psi, sizeof(psi));
        snprintf(l[s->wheel - 1U], sizeof(l[0]), "%s: %sp %dC",
                 tpms_wheel_label(s->wheel), psi, (int)s->temp_c);
    }

    u8g2_FirstPage(&m1_u8g2);
    do {
        u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 0, 10, l_top);
        u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 24, l[0]);
        u8g2_DrawStr(&m1_u8g2, 0, 34, l[1]);
        u8g2_DrawStr(&m1_u8g2, 0, 44, l[2]);
        u8g2_DrawStr(&m1_u8g2, 0, 54, l[3]);

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 64, "OK:Refresh BACK:Exit");
    } while (u8g2_NextPage(&m1_u8g2));
}

/* Dialog: assign the most-recently-decoded sensor to a wheel. */
static void tpms_assign_dialog(void)
{
    if (s_ctx.last_decoded_idx < 0) return;

    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint8_t             sel = 0;     /* 0=FL 1=FR 2=RL 3=RR 4=cancel */
    static const char  *opts[5] = { "FL", "FR", "RL", "RR", "Cancel" };
    bool                done = false;

    tpms_sensor_t *s = &s_ctx.sensors[s_ctx.last_decoded_idx];

    while (!done)
    {
        char title[28];
        snprintf(title, sizeof(title), "Assign %08lX",
                 (unsigned long)s->sensor_id);

        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
            u8g2_DrawStr(&m1_u8g2, 0, 10, title);
            u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

            u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
            for (uint8_t i = 0; i < 5U; i++)
            {
                uint8_t y = (uint8_t)(22 + i * 8);
                if (i == sel)
                {
                    u8g2_DrawBox(&m1_u8g2, 0, (uint8_t)(y - 7), 128, 9);
                    u8g2_SetDrawColor(&m1_u8g2, 0);
                    u8g2_DrawStr(&m1_u8g2, 4, y, opts[i]);
                    u8g2_SetDrawColor(&m1_u8g2, 1);
                }
                else
                {
                    u8g2_DrawStr(&m1_u8g2, 4, y, opts[i]);
                }
            }

            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 0, 64, "\x18\x19:Pick OK:Set");
        } while (u8g2_NextPage(&m1_u8g2));

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &bs, 0);

        if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            done = true;
        }
        else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel == 0) ? 4U : (sel - 1U));
        }
        else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel + 1U) % 5U);
        }
        else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (sel < 4U)
            {
                /* Clear any other sensor previously assigned to this wheel.
                 * Use the static cap (TPMS_MAX_SENSORS) as the loop bound so
                 * the compiler can prove the array access stays in-bounds;
                 * relying solely on s_ctx.sensor_count (uint8_t with no
                 * static upper bound visible to GCC) trips
                 * -Wstringop-overflow on -O2. */
                uint8_t cap = s_ctx.sensor_count;
                if (cap > TPMS_MAX_SENSORS) cap = TPMS_MAX_SENSORS;
                for (uint8_t i = 0; i < cap; i++)
                {
                    if (i != (uint8_t)s_ctx.last_decoded_idx &&
                        s_ctx.sensors[i].wheel == (uint8_t)(sel + 1U))
                    {
                        s_ctx.sensors[i].wheel = 0;
                    }
                }
                s->wheel = (uint8_t)(sel + 1U);
            }
            done = true;
        }
    }

    xQueueReset(main_q_hdl);
}

/* ============================================================================
 * Public entry point
 * ============================================================================ */

void app_tpms_run(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint32_t            freq_hz;

    /* 0) Reset full context. */
    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.last_decoded_idx = -1;
    s_ctx.rate_idx = 0;       /* default 10 kbps */

    /* 1) Pick frequency. */
    freq_hz = tpms_pick_frequency();
    if (freq_hz == 0UL)
    {
        m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
        return;
    }

    /* 2) Bring up radio. */
    menu_sub_ghz_init();
    tpms_radio_start(freq_hz);

    bool       running = true;
    bool       show_summary = false;
    TickType_t scan_started = xTaskGetTickCount();
    TickType_t last_redraw  = 0;
    TickType_t last_progress = scan_started;
    bool       any_decoded = false;

    tpms_draw_scanning(freq_hz, 0);

    while (running)
    {
        /* Drain pulses + try to decode. */
        tpms_drain();
        if (s_ctx.packets_decoded > 0)
        {
            any_decoded = true;
            last_progress = xTaskGetTickCount();
        }

        /* 30-second no-result watchdog. */
        TickType_t now = xTaskGetTickCount();
        uint32_t elapsed_ms = (uint32_t)((now - scan_started) * portTICK_PERIOD_MS);
        uint32_t since_progress_ms =
            (uint32_t)((now - last_progress) * portTICK_PERIOD_MS);

        if (!any_decoded && elapsed_ms > TPMS_SCAN_TIMEOUT_S * 1000UL &&
            since_progress_ms > TPMS_SCAN_TIMEOUT_S * 1000UL)
        {
            /* No sensors after 30 s. Show a blocking notice once. */
            m1_message_box(&m1_u8g2, "TPMS",
                           "No sensors found",
                           "in 30s.", "OK to keep listening");
            scan_started = xTaskGetTickCount();
            last_progress = scan_started;
            last_redraw = 0;
        }

        /* Periodic redraw. */
        if ((now - last_redraw) > pdMS_TO_TICKS(150))
        {
            if (show_summary)
                tpms_draw_summary();
            else
                tpms_draw_scanning(freq_hz, elapsed_ms / 1000UL);
            last_redraw = now;
        }

        /* Non-blocking key check. */
        ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(20));
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &bs, 0);
            if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (show_summary)
                {
                    show_summary = false;
                    last_redraw = 0;
                }
                else
                {
                    running = false;
                }
            }
            else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (show_summary)
                {
                    last_redraw = 0;
                }
                else if (s_ctx.last_decoded_idx >= 0)
                {
                    /* Pause radio while user interacts. */
                    sub_ghz_pulse_capture_disarm();
                    tpms_assign_dialog();
                    /* Re-arm and refresh. */
                    m1_ringbuffer_reset(&subghz_rx_rawdata_rb);
                    tpms_chip_buf_reset();
                    sub_ghz_pulse_capture_arm();
                    last_redraw = 0;
                }
            }
            else if (bs.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK ||
                     bs.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                show_summary = !show_summary;
                last_redraw = 0;
            }
            else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK ||
                     bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Cycle decoder rate. */
                s_ctx.rate_idx = (uint8_t)((s_ctx.rate_idx + 1U)
                                            % TPMS_RATE_COUNT);
                tpms_chip_buf_reset();
                m1_ringbuffer_reset(&subghz_rx_rawdata_rb);
                last_redraw = 0;
            }
        }
        else
        {
            /* No event waiting: brief yield so we never busy-loop. */
            osDelay(2);
        }
    }

    /* Tear down. */
    tpms_radio_stop();
    menu_sub_ghz_exit();

    xQueueReset(main_q_hdl);
    m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
}

#endif /* M1_APP_TPMS_ENABLE */
