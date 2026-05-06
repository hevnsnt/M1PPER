/* See COPYING.txt for license details. */

/*
 * app_bleptd.c
 *
 * BLEPTD: BLE Privacy Threat Detector.
 *
 * Continuously scans BLE (via ESP32-C6 over SPI AT commands), classifies
 * advertising packets against a 50+ entry signature database, and identifies
 * tracking devices, wearables, audio gear, phones, medical devices and smart
 * home BLE peripherals. Threat-level scored 0..3.
 *
 * Capable of impersonating non-medical signatures (TX tab) to confuse trackers
 * and stalkerware. Medical devices are explicitly non-transmittable.
 *
 * UI: 4 tabs (SCAN, FILTER, TX, SETUP) navigated via LEFT/RIGHT.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "ff.h"
#include "app_bleptd.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "app_freertos.h"
#include "cmsis_os.h"

#ifdef M1_APP_BLEPTD_ENABLE

/* ---- tuning ---- */
#define BLEPTD_MAX_DEVICES         64
#define BLEPTD_AT_RESP_SIZE       512
#define BLEPTD_DEFAULT_SCAN_SEC     5
#define BLEPTD_TX_CYCLE_MS       3000
#define BLEPTD_AT_TIMEOUT_S         3

/* ---- BLE company IDs ---- */
#define CID_APPLE      0x004C
#define CID_SAMSUNG    0x0075
#define CID_GOOGLE     0x00E0
#define CID_MICROSOFT  0x0006
#define CID_FITBIT     0x00CA
#define CID_GARMIN     0x0087
#define CID_PEBBLEBEE  0x06FF
#define CID_NUTFIND    0x0041
#define CID_MEDTRONIC  0x0046
#define CID_BOSE       0x002D
#define CID_BEATS      0x0233
#define CID_AMAZON     0x0171

/* ---- Service UUIDs ---- */
#define SVC_TILE       0xFEED
#define SVC_CHIPOLO    0xFE65
#define SVC_GLUCOSE    0x1808
#define SVC_HRSERVICE  0x180D

/* ---- Categories ---- */
#define CATEGORY_TRACKER   0
#define CATEGORY_WEARABLE  1
#define CATEGORY_AUDIO     2
#define CATEGORY_PHONE     3
#define CATEGORY_MEDICAL   4
#define CATEGORY_SMART     5
#define CATEGORY_COUNT     6

/* ---- Threat levels ---- */
#define THREAT_BENIGN  0
#define THREAT_LOW     1
#define THREAT_MED     2
#define THREAT_HIGH    3

/* ---- Display geometry ---- */
#define BLEPTD_ROW_H             10
#define BLEPTD_LIST_START_Y      24
#define BLEPTD_LIST_VISIBLE       4

/* ---- Tab indices ---- */
#define TAB_SCAN    0
#define TAB_FILTER  1
#define TAB_TX      2
#define TAB_SETUP   3
#define TAB_COUNT   4

/* --------------------------------------------------------------------------
 * Signature table
 * -------------------------------------------------------------------------- */

typedef struct {
    uint16_t    company_id;     /* 0 = don't match on company_id    */
    uint8_t     payload_byte0;  /* 0xFF = wildcard                  */
    uint8_t     payload_byte1;  /* 0xFF = wildcard                  */
    uint16_t    service_uuid;   /* 0 = don't match on service uuid  */
    uint8_t     category;       /* CATEGORY_* enum                  */
    uint8_t     threat;         /* 0..3                             */
    bool        transmittable;  /* false = NEVER TX (medical)       */
    const char *name;
    const char *tx_hex;         /* NULL if not transmittable        */
} bleptd_sig_t;

/* TX hex strings: full ADV_IND payloads ready for AT+BLEADVDATA.
 * Format is the same as app_ble_spam.c.                              */

static const char TX_AIRTAG[] =
    "02011A"
    "1AFF4C00"
    "1219" "0000000000000000000000000000000000000000000000";

static const char TX_AIRPODS[] =
    "02011A"
    "1AFF4C00"
    "0713" "010020AA20000000002C55000000000000000000";

static const char TX_AIRPODS_PRO[] =
    "02011A"
    "1AFF4C00"
    "0713" "010020E02000000000002C550000000000000000";

static const char TX_FINDMY[] =
    "02011A"
    "1AFF4C00"
    "1225" "00" "0000000000000000000000000000000000000000000000";

static const char TX_IPHONE_NEAR[] =
    "02011A"
    "0EFF4C00"
    "0F05" "C1010000000000";

static const char TX_APPLE_WATCH[] =
    "02011A"
    "0AFF4C00"
    "0B05" "01180000000000";

static const char TX_HANDOFF[] =
    "02011A"
    "0AFF4C00"
    "0C0E" "0102030405060708";

static const char TX_AIRDROP[] =
    "02011A"
    "1AFF4C00"
    "0518" "0001020304050607080900010203040506070809";

static const char TX_GALAXY_TAG[] =
    "02011A"
    "1BFF7500"
    "42040180" "66B099D7B2B4EBB299D7B2B4EA01000000000000";

static const char TX_GALAXY_PHONE[] =
    "02011A"
    "1BFF7500"
    "42098102" "141503210149E217012D06BCB09700000000A300";

static const char TX_SMARTTAG2[] =
    "02011A"
    "1BFF7500"
    "42040180" "667C0A3F9BD5CD7E0A3F9BD5CC01000000000000";

static const char TX_TILE[] =
    "020106"
    "03022CFE"
    "0716EDFE" "01020304";

static const char TX_TILE_PRO[] =
    "020106"
    "03022CFE"
    "0916EDFE" "0102030405060708";

static const char TX_TILE_SLIM[] =
    "020106"
    "03022CFE"
    "0716EDFE" "11223344";

static const char TX_TILE_STICKER[] =
    "020106"
    "03022CFE"
    "0716EDFE" "AABBCCDD";

static const char TX_TILE_MATE[] =
    "020106"
    "03022CFE"
    "0716EDFE" "DEADBEEF";

static const char TX_CHIPOLO[] =
    "020106"
    "030265FE"
    "0716FE65" "F00DCAFE";

static const char TX_FITBIT[] =
    "02011A"
    "0BFFCA00"
    "01020304050607";

static const char TX_GARMIN[] =
    "02011A"
    "0BFF8700"
    "AA01020304050607";

static const char TX_PEBBLEBEE[] =
    "02011A"
    "0BFFFF06"
    "10203040506070";

static const char TX_NUTFIND[] =
    "02011A"
    "0BFF4100"
    "01020304050607";

static const char TX_GOOGLE_NEAR[] =
    "020106"
    "030320FE"
    "0616FE2C" "44C8D1";

static const char TX_MICROSOFT[] =
    "02011A"
    "0AFF0600" "0301010203040506";

static const char TX_BOSE[] =
    "02011A"
    "07FF2D00" "01020304";

static const char TX_BEATS[] =
    "02011A"
    "07FF3302" "01020304";

static const char TX_AMAZON[] =
    "02011A"
    "0BFF7101" "AA01020304050607";

/* Signature database (most specific entries listed first).
 * The matcher walks top-to-bottom and stops at first match.        */
static const bleptd_sig_t s_sigs[] = {
    /* ---------- Trackers ---------- */
    { CID_APPLE,    0x12, 0xFF, 0,           CATEGORY_TRACKER,   THREAT_HIGH, true,  "AirTag",         TX_AIRTAG     },
    { CID_APPLE,    0x12, 0x25, 0,           CATEGORY_TRACKER,   THREAT_MED,  true,  "Find My",        TX_FINDMY     },
    { CID_SAMSUNG,  0x42, 0x04, 0,           CATEGORY_TRACKER,   THREAT_HIGH, true,  "Galaxy Tag",     TX_GALAXY_TAG },
    { CID_SAMSUNG,  0x42, 0x55, 0,           CATEGORY_TRACKER,   THREAT_HIGH, true,  "SmartTag2",      TX_SMARTTAG2  },
    { 0,            0xFF, 0xFF, SVC_TILE,    CATEGORY_TRACKER,   THREAT_MED,  true,  "Tile",           TX_TILE       },
    { 0,            0xFF, 0xFF, 0xFEEC,      CATEGORY_TRACKER,   THREAT_MED,  true,  "Tile Pro",       TX_TILE_PRO   },
    { 0,            0xFF, 0xFF, 0xFEEB,      CATEGORY_TRACKER,   THREAT_MED,  true,  "Tile Slim",      TX_TILE_SLIM  },
    { 0,            0xFF, 0xFF, 0xFEEA,      CATEGORY_TRACKER,   THREAT_HIGH, true,  "Tile Sticker",   TX_TILE_STICKER },
    { 0,            0xFF, 0xFF, 0xFEE9,      CATEGORY_TRACKER,   THREAT_MED,  true,  "Tile Mate",      TX_TILE_MATE  },
    { 0,            0xFF, 0xFF, SVC_CHIPOLO, CATEGORY_TRACKER,   THREAT_MED,  true,  "Chipolo",        TX_CHIPOLO    },
    { CID_PEBBLEBEE,0xFF, 0xFF, 0,           CATEGORY_TRACKER,   THREAT_MED,  true,  "PebbleBee",      TX_PEBBLEBEE  },
    { CID_NUTFIND,  0xFF, 0xFF, 0,           CATEGORY_TRACKER,   THREAT_MED,  true,  "Nut Find",       TX_NUTFIND    },

    /* ---------- Audio ---------- */
    { CID_APPLE,    0x07, 0x13, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "AirPods",      TX_AIRPODS    },
    { CID_APPLE,    0x07, 0x19, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "AirPods Pro",  TX_AIRPODS_PRO},
    { CID_APPLE,    0x07, 0xFF, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "AirPods Gen",  TX_AIRPODS    },
    { CID_BOSE,     0xFF, 0xFF, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "Bose Audio",   TX_BOSE       },
    { CID_BEATS,    0xFF, 0xFF, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "Beats",        TX_BEATS      },
    { CID_SAMSUNG,  0x42, 0x09, 0,           CATEGORY_AUDIO,     THREAT_BENIGN, true,  "Galaxy Buds",  NULL          },

    /* ---------- Phones ---------- */
    { CID_APPLE,    0x0F, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "iPhone",         TX_IPHONE_NEAR },
    { CID_APPLE,    0x0E, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "iPhone/Mac",     TX_IPHONE_NEAR },
    { CID_APPLE,    0x10, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Apple Nearby",   TX_IPHONE_NEAR },
    { CID_APPLE,    0x05, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "AirDrop",        TX_AIRDROP     },
    { CID_APPLE,    0x0C, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Handoff",        TX_HANDOFF     },
    { CID_SAMSUNG,  0x42, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Galaxy Phone",   TX_GALAXY_PHONE},
    { CID_SAMSUNG,  0x81, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Samsung Phone",  TX_GALAXY_PHONE},
    { CID_GOOGLE,   0xFF, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Google Dev",     TX_GOOGLE_NEAR },
    { 0,            0xFF, 0xFF, 0xFE2C,      CATEGORY_PHONE,     THREAT_LOW,  true,  "Nearby Share",   TX_GOOGLE_NEAR },

    /* ---------- Wearables ---------- */
    { CID_APPLE,    0x0B, 0xFF, 0,           CATEGORY_WEARABLE,  THREAT_LOW,  true,  "Apple Watch",    TX_APPLE_WATCH },
    { CID_FITBIT,   0xFF, 0xFF, 0,           CATEGORY_WEARABLE,  THREAT_LOW,  true,  "Fitbit",         TX_FITBIT      },
    { CID_GARMIN,   0xFF, 0xFF, 0,           CATEGORY_WEARABLE,  THREAT_LOW,  true,  "Garmin",         TX_GARMIN      },

    /* ---------- Smart home ---------- */
    { CID_MICROSOFT,0xFF, 0xFF, 0,           CATEGORY_SMART,     THREAT_LOW,  true,  "MS Device",      TX_MICROSOFT   },
    { CID_AMAZON,   0xFF, 0xFF, 0,           CATEGORY_SMART,     THREAT_LOW,  true,  "Alexa Dev",      TX_AMAZON      },
    { 0,            0xFF, 0xFF, 0xFE9F,      CATEGORY_SMART,     THREAT_LOW,  true,  "Smart Lock",     NULL           },
    { 0,            0xFF, 0xFF, 0xFE61,      CATEGORY_SMART,     THREAT_LOW,  true,  "Logitech",       NULL           },
    { 0,            0xFF, 0xFF, 0xFE40,      CATEGORY_SMART,     THREAT_LOW,  true,  "Anhui Huami",    NULL           },
    { 0,            0xFF, 0xFF, 0xFD3D,      CATEGORY_SMART,     THREAT_LOW,  true,  "Smart Sensor",   NULL           },

    /* ---------- Medical (NEVER TX) ---------- */
    { CID_MEDTRONIC,0xFF, 0xFF, 0,           CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Medtronic",     NULL          },
    { 0,            0xFF, 0xFF, SVC_GLUCOSE, CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Glucose Mon",   NULL          },
    { 0,            0xFF, 0xFF, SVC_HRSERVICE,CATEGORY_MEDICAL,  THREAT_BENIGN, false, "HR / Pacer",    NULL          },
    { 0,            0xFF, 0xFF, 0x1810,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "BloodPressure", NULL          },
    { 0,            0xFF, 0xFF, 0x181A,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Env Sensor",    NULL          },
    { 0,            0xFF, 0xFF, 0x181B,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Body Comp",     NULL          },
    { 0,            0xFF, 0xFF, 0x181D,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Weight Scale",  NULL          },
    { 0,            0xFF, 0xFF, 0x1822,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Pulse Oximeter",NULL          },
    { 0,            0xFF, 0xFF, 0x1814,      CATEGORY_MEDICAL,   THREAT_BENIGN, false, "Run/Walk Sens", NULL          },

    /* ---------- Catch-alls ---------- */
    { CID_APPLE,    0xFF, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Apple Dev",      TX_IPHONE_NEAR },
    { CID_SAMSUNG,  0xFF, 0xFF, 0,           CATEGORY_PHONE,     THREAT_LOW,  true,  "Samsung Dev",    TX_GALAXY_PHONE},
};
#define N_SIGS  ((uint16_t)(sizeof(s_sigs) / sizeof(s_sigs[0])))

/* --------------------------------------------------------------------------
 * Tracked device list
 * -------------------------------------------------------------------------- */

typedef struct {
    char        addr[18];        /* "AA:BB:CC:DD:EE:FF" */
    char        name[20];
    uint8_t     category;
    uint8_t     threat;
    int8_t      rssi;
    uint32_t    first_seen;
    uint32_t    last_seen;
    uint8_t     seen_count;
    bool        transmittable;
    bool        active;
    const char *tx_hex;
} bleptd_device_t;

static bleptd_device_t s_devices[BLEPTD_MAX_DEVICES];
static uint8_t         s_device_count;

/* --------------------------------------------------------------------------
 * UI / settings state
 * -------------------------------------------------------------------------- */

static bool     s_filter_enabled[CATEGORY_COUNT] = { true, true, true, true, true, true };
static uint16_t s_scan_seconds   = BLEPTD_DEFAULT_SCAN_SEC;
static uint8_t  s_alert_thresh   = THREAT_MED;

static uint8_t  s_tab            = TAB_SCAN;

/* per-tab cursors */
static uint8_t  s_scan_sel       = 0;
static uint8_t  s_scan_scroll    = 0;
static uint8_t  s_filter_sel     = 0;
static uint8_t  s_tx_sel         = 0;
static uint8_t  s_tx_scroll      = 0;
static uint8_t  s_setup_sel      = 0;

/* TX state */
static bool     s_tx_active      = false;
static int16_t  s_tx_active_idx  = -1;     /* -1 == none, -2 == confusion mode */
static uint32_t s_tx_count       = 0;
static uint32_t s_tx_last_switch = 0;
static char     s_tx_mac[18]     = {0};

/* Build a dynamic list of transmittable signature indices.        *
 * The +1 slot at the end is the "Confusion Mode" pseudo-entry.    */
static uint16_t s_tx_list[N_SIGS + 1];
static uint16_t s_tx_list_n;

/* AT response scratch buffer */
static char s_at_buf[BLEPTD_AT_RESP_SIZE];

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static const char *s_category_names[CATEGORY_COUNT] = {
    "Trackers", "Wearables", "Audio", "Phones", "Medical", "Smart"
};

static const char *s_tab_names[TAB_COUNT] = { "SCAN", "FILTR", "TX", "SETUP" };

static inline void at_send(const char *cmd)
{
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf), BLEPTD_AT_TIMEOUT_S);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string into bytes.  Returns number of bytes decoded. */
static uint16_t hex_decode(const char *hex, uint8_t *out, uint16_t out_max)
{
    uint16_t n = 0;
    while (hex[0] && hex[1] && n < out_max) {
        int hi = hex_nibble(hex[0]);
        int lo = hex_nibble(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* Generate a random MAC string "XX:XX:XX:XX:XX:XX" */
static void random_mac(char *out)
{
    uint8_t b[6];
    for (uint8_t i = 0; i < 6; i++) b[i] = (uint8_t)(rand() & 0xFF);
    /* Set as random static address: top two bits = 11 */
    b[0] |= 0xC0;
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

/* --------------------------------------------------------------------------
 * AD parser: walks AD structures, extracts company id, payload bytes 0/1,
 * service UUID (if present).
 * -------------------------------------------------------------------------- */

typedef struct {
    bool     have_company_id;
    uint16_t company_id;
    uint8_t  payload_byte0;
    uint8_t  payload_byte1;
    uint8_t  payload_len;
    bool     have_service_uuid;
    uint16_t service_uuid;
} adv_parsed_t;

static void parse_adv_bytes(const uint8_t *adv, uint16_t len, adv_parsed_t *out)
{
    memset(out, 0, sizeof(*out));
    out->payload_byte0 = 0xFF;
    out->payload_byte1 = 0xFF;

    uint16_t i = 0;
    while (i < len) {
        uint8_t l = adv[i];
        /* AD layout: [length=l][type][data x (l-1)]   *
         * Total bytes consumed = l + 1                 *
         * Need i + l + 1 <= len, i.e., i + l < len     */
        if (l == 0) break;
        if (i + l >= len) break;
        uint8_t t = adv[i + 1];
        const uint8_t *d = &adv[i + 2];
        uint8_t dl = (uint8_t)(l - 1);

        switch (t) {
            case 0xFF: /* Manufacturer Specific Data */
                if (dl >= 2 && !out->have_company_id) {
                    out->company_id      = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
                    out->have_company_id = true;
                    out->payload_len     = (uint8_t)(dl - 2);
                    if (out->payload_len > 0) out->payload_byte0 = d[2];
                    if (out->payload_len > 1) out->payload_byte1 = d[3];
                }
                break;
            case 0x02: /* Incomplete 16-bit UUIDs */
            case 0x03: /* Complete 16-bit UUIDs   */
                if (dl >= 2 && !out->have_service_uuid) {
                    out->service_uuid      = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
                    out->have_service_uuid = true;
                }
                break;
            case 0x16: /* Service Data 16-bit UUID */
                if (dl >= 2 && !out->have_service_uuid) {
                    out->service_uuid      = (uint16_t)d[0] | ((uint16_t)d[1] << 8);
                    out->have_service_uuid = true;
                }
                break;
            default:
                break;
        }

        i += (uint16_t)(l + 1);
    }
}

/* --------------------------------------------------------------------------
 * Classification
 * -------------------------------------------------------------------------- */

static int16_t classify(const adv_parsed_t *a, int8_t rssi)
{
    for (uint16_t i = 0; i < N_SIGS; i++) {
        const bleptd_sig_t *s = &s_sigs[i];

        if (s->company_id) {
            if (!a->have_company_id || a->company_id != s->company_id) continue;
            if (s->payload_byte0 != 0xFF && a->payload_byte0 != s->payload_byte0) continue;
            if (s->payload_byte1 != 0xFF && a->payload_byte1 != s->payload_byte1) continue;
            return (int16_t)i;
        } else if (s->service_uuid) {
            if (!a->have_service_uuid || a->service_uuid != s->service_uuid) continue;
            return (int16_t)i;
        }
    }

    /* Long-range unknown rule */
    if (rssi > -60) return -2; /* synthetic "Unknown long-range" */
    return -1;
}

/* --------------------------------------------------------------------------
 * Device list management
 * -------------------------------------------------------------------------- */

static bleptd_device_t *find_or_alloc(const char *addr)
{
    for (uint8_t i = 0; i < s_device_count; i++) {
        if (strncmp(s_devices[i].addr, addr, sizeof(s_devices[i].addr)) == 0)
            return &s_devices[i];
    }

    if (s_device_count < BLEPTD_MAX_DEVICES) {
        bleptd_device_t *d = &s_devices[s_device_count++];
        memset(d, 0, sizeof(*d));
        strncpy(d->addr, addr, sizeof(d->addr) - 1);
        d->first_seen = HAL_GetTick();
        return d;
    }

    /* Ring-buffer overflow: replace oldest (smallest last_seen) */
    uint8_t oldest = 0;
    for (uint8_t i = 1; i < BLEPTD_MAX_DEVICES; i++)
        if (s_devices[i].last_seen < s_devices[oldest].last_seen) oldest = i;
    bleptd_device_t *d = &s_devices[oldest];
    memset(d, 0, sizeof(*d));
    strncpy(d->addr, addr, sizeof(d->addr) - 1);
    d->first_seen = HAL_GetTick();
    return d;
}

static void update_device(const char *addr, int8_t rssi,
                          const adv_parsed_t *a)
{
    int16_t sig_idx = classify(a, rssi);

    bleptd_device_t *d = find_or_alloc(addr);
    if (!d) return;

    d->rssi        = rssi;
    d->last_seen   = HAL_GetTick();
    if (d->seen_count < 0xFF) d->seen_count++;
    d->active      = true;

    if (sig_idx >= 0) {
        const bleptd_sig_t *s = &s_sigs[sig_idx];
        snprintf(d->name, sizeof(d->name), "%s", s->name);
        d->category      = s->category;
        d->threat        = s->threat;
        d->transmittable = s->transmittable;
        d->tx_hex        = s->tx_hex;
    } else if (sig_idx == -2) {
        if (d->name[0] == '\0') {
            snprintf(d->name, sizeof(d->name), "Unknown Strong");
            d->category      = CATEGORY_SMART;
            d->threat        = THREAT_MED;
            d->transmittable = false;
            d->tx_hex        = NULL;
        }
    } else {
        if (d->name[0] == '\0') {
            snprintf(d->name, sizeof(d->name), "Unknown");
            d->category      = CATEGORY_SMART;
            d->threat        = THREAT_BENIGN;
            d->transmittable = false;
            d->tx_hex        = NULL;
        }
    }
}

/* --------------------------------------------------------------------------
 * AT scan + parse pipeline
 * -------------------------------------------------------------------------- */

/* Parse one +BLESCAN line in s_at_buf starting at line_start.
 * Returns pointer to the NEXT line, or NULL when no more lines.
 * Fills addr[18], rssi, adv_hex pointer (NULL terminated within buf).
 *
 * We mutate s_at_buf in place by writing terminating NULs at delimiters.   */
static bool parse_blescan_line(char *line, char addr[18], int8_t *rssi,
                               char **adv_hex, char **scan_rsp_hex)
{
    /* Expected format:                                                     *
     * +BLESCAN:"aa:bb:cc:dd:ee:ff",-XX,<adv_hex>,<scan_rsp_hex>,<at>,<et>  */
    if (strncmp(line, "+BLESCAN:", 9) != 0) return false;
    char *p = line + 9;
    if (*p != '"') return false;
    p++;

    /* Address up to next quote */
    char *q = strchr(p, '"');
    if (!q) return false;
    if ((uint16_t)(q - p) != 17) return false;
    memcpy(addr, p, 17);
    addr[17] = '\0';
    /* Normalize uppercase                                              */
    for (uint8_t i = 0; i < 17; i++)
        if (addr[i] >= 'a' && addr[i] <= 'f') addr[i] = (char)(addr[i] - 32);

    p = q + 1;
    if (*p != ',') return false;
    p++;

    /* RSSI: signed integer */
    int rssi_val = atoi(p);
    *rssi = (int8_t)rssi_val;
    /* skip past rssi field */
    while (*p && *p != ',') p++;
    if (*p != ',') return false;
    p++;

    /* adv_data_hex: up to next comma */
    *adv_hex = p;
    while (*p && *p != ',') p++;
    if (*p != ',') return false;
    *p = '\0';
    p++;

    /* scan_rsp_hex: up to next comma */
    *scan_rsp_hex = p;
    while (*p && *p != ',') p++;
    if (*p == ',') *p = '\0';

    return true;
}

static void scan_pass(uint16_t seconds)
{
    /* If the slave rebooted between scans, the on-chip NimBLE
     * stack is back to BLEINIT=0 and adv config is gone. We need
     * to re-issue the init sequence before scanning. */
    if (esp_consume_slave_restart_event()) {
        at_send("AT+BLEINIT=0\r\n");
        vTaskDelay(pdMS_TO_TICKS(80));
    }
    at_send("AT+BLEINIT=1\r\n");
    vTaskDelay(pdMS_TO_TICKS(50));
    at_send("AT+BLESCANPARAM=0,0,0,80,40\r\n");
    vTaskDelay(pdMS_TO_TICKS(20));

    char cmd[40];
    snprintf(cmd, sizeof(cmd), "AT+BLESCAN=1,%u\r\n", (unsigned)seconds);
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf),
                     (int)(seconds + BLEPTD_AT_TIMEOUT_S));

    /* Walk the buffer line by line.                                       */
    char *line = s_at_buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Trim trailing CR */
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\r') line[llen - 1] = '\0';

        char     addr[18];
        int8_t   rssi   = -127;
        char    *adv    = NULL;
        char    *rsp    = NULL;

        if (parse_blescan_line(line, addr, &rssi, &adv, &rsp)) {
            uint8_t adv_bytes[64];
            uint16_t n = 0;
            if (adv && *adv) n = hex_decode(adv, adv_bytes, sizeof(adv_bytes));

            adv_parsed_t parsed;
            parse_adv_bytes(adv_bytes, n, &parsed);

            /* If primary advert is empty, try scan response */
            if (!parsed.have_company_id && !parsed.have_service_uuid &&
                rsp && *rsp) {
                uint8_t  rsp_bytes[64];
                uint16_t rn = hex_decode(rsp, rsp_bytes, sizeof(rsp_bytes));
                parse_adv_bytes(rsp_bytes, rn, &parsed);
            }

            update_device(addr, rssi, &parsed);
        }

        if (!nl) break;
        line = nl + 1;
    }

    /* Stop scan to free the radio. */
    at_send("AT+BLESCAN=0\r\n");
    vTaskDelay(pdMS_TO_TICKS(20));
}

/* --------------------------------------------------------------------------
 * TX engine
 * -------------------------------------------------------------------------- */

static void tx_init(void)
{
    at_send("AT+BLEINIT=0\r\n");
    vTaskDelay(pdMS_TO_TICKS(50));
    at_send("AT+BLEINIT=2\r\n");
    vTaskDelay(pdMS_TO_TICKS(50));
}

static void tx_set_random_mac(void)
{
    char mac[18];
    random_mac(mac);
    memcpy(s_tx_mac, mac, sizeof(s_tx_mac));

    /* Strip colons for the AT MAC format: 12 hex chars */
    char hexmac[13];
    uint8_t k = 0;
    for (uint8_t i = 0; i < 17 && k < 12; i++) {
        if (mac[i] != ':') hexmac[k++] = mac[i];
    }
    hexmac[12] = '\0';

    /* CRITICAL: actually rotate the on-air BD_ADDR. AT+BLEADVPARAM
     * with own_addr_type=1 alone does NOT change the broadcaster's
     * source MAC; ESP32-AT continues to advertise from the chip's
     * factory MAC. AT+BLEADDR=1,"<hexmac>" rewrites the random
     * static device address used by NimBLE before each new advert.
     * Without this command, "Confusion Mode" rotates only the
     * payload while the on-air MAC stays constant -- iOS Find-My
     * filters dedup on (MAC, payload) so the feature was a no-op. */
    char addr_cmd[48];
    snprintf(addr_cmd, sizeof(addr_cmd),
             "AT+BLEADDR=1,\"%s\"\r\n", hexmac);
    at_send(addr_cmd);
    vTaskDelay(pdMS_TO_TICKS(20));

    char cmd[64];
    /* min=32, max=64, type=3 (non-conn), own_addr_type=1 (random),
     * channel_map=7 (37,38,39), filter=0, peer_addr=hexmac          */
    snprintf(cmd, sizeof(cmd),
             "AT+BLEADVPARAM=32,64,3,1,7,0,0,\"%s\"\r\n", hexmac);
    at_send(cmd);
    vTaskDelay(pdMS_TO_TICKS(20));
}

static void tx_payload(const char *hex)
{
    if (!hex) return;
    if (s_tx_active) at_send("AT+BLEADVSTOP\r\n");
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "AT+BLEADVDATA=\"%s\"\r\n", hex);
    at_send(cmd);
    vTaskDelay(pdMS_TO_TICKS(20));
    at_send("AT+BLEADVSTART\r\n");
    s_tx_active = true;
    s_tx_count++;
}

static void tx_stop(void)
{
    if (s_tx_active) {
        at_send("AT+BLEADVSTOP\r\n");
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    at_send("AT+BLEINIT=0\r\n");
    s_tx_active     = false;
    s_tx_active_idx = -1;
    s_tx_count      = 0;
}

/* --------------------------------------------------------------------------
 * Drawing
 * -------------------------------------------------------------------------- */

static void draw_tab_bar(void)
{
    /* Top bar: "BLEPTD" + active tab name on the right */
    char hdr_r[16];
    snprintf(hdr_r, sizeof(hdr_r), "%s", s_tab_names[s_tab]);
    m1_draw_header_bar(&m1_u8g2, "BLEPTD", hdr_r);
}

/* Map threat -> single-char prefix */
static char threat_prefix(uint8_t t)
{
    switch (t) {
        case THREAT_HIGH: return '!';
        case THREAT_MED:  return '*';
        case THREAT_LOW:  return '.';
        default:          return ' ';
    }
}

static int8_t cmp_devices(const bleptd_device_t *a, const bleptd_device_t *b)
{
    if (a->threat != b->threat) return (a->threat > b->threat) ? -1 : 1;
    if (a->seen_count != b->seen_count)
        return (a->seen_count > b->seen_count) ? -1 : 1;
    if (a->rssi != b->rssi) return (a->rssi > b->rssi) ? -1 : 1;
    return 0;
}

/* Build display list of devices honoring filters. Returns count.
 * Output: list of indices into s_devices (sorted highest threat first). */
static uint8_t build_scan_view(uint8_t *out, uint8_t out_max)
{
    uint8_t n = 0;
    for (uint8_t i = 0; i < s_device_count && n < out_max; i++) {
        bleptd_device_t *d = &s_devices[i];
        if (!d->active) continue;
        if (d->category < CATEGORY_COUNT && !s_filter_enabled[d->category])
            continue;
        out[n++] = i;
    }

    /* Selection sort */
    for (uint8_t i = 0; i < n; i++) {
        uint8_t best = i;
        for (uint8_t j = i + 1; j < n; j++) {
            if (cmp_devices(&s_devices[out[j]], &s_devices[out[best]]) < 0)
                best = j;
        }
        if (best != i) {
            uint8_t t = out[i]; out[i] = out[best]; out[best] = t;
        }
    }
    return n;
}

static void draw_scan_tab(void)
{
    uint8_t view[BLEPTD_MAX_DEVICES];
    uint8_t n = build_scan_view(view, BLEPTD_MAX_DEVICES);

    if (s_scan_sel >= n) s_scan_sel = (n > 0) ? (n - 1) : 0;
    if (s_scan_sel < s_scan_scroll) s_scan_scroll = s_scan_sel;
    if (s_scan_sel >= s_scan_scroll + BLEPTD_LIST_VISIBLE)
        s_scan_scroll = (uint8_t)(s_scan_sel - BLEPTD_LIST_VISIBLE + 1);

    if (n == 0) {
        u8g2_DrawStr(&m1_u8g2, 4, 30, "Scanning...");
        u8g2_DrawStr(&m1_u8g2, 4, 42, "No devices yet");
        return;
    }

    for (uint8_t i = 0; i < BLEPTD_LIST_VISIBLE && (s_scan_scroll + i) < n; i++) {
        uint8_t          idx = s_scan_scroll + i;
        bleptd_device_t *d   = &s_devices[view[idx]];
        uint8_t          y   = (uint8_t)(BLEPTD_LIST_START_Y + i * BLEPTD_ROW_H);
        bool             sel_row = (idx == s_scan_sel);

        if (sel_row || d->threat >= THREAT_HIGH) {
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 8), 128, BLEPTD_ROW_H);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        }

        char row[36];
        snprintf(row, sizeof(row), "%c%-14.14s %4d",
                 threat_prefix(d->threat), d->name, (int)d->rssi);
        u8g2_DrawStr(&m1_u8g2, 2, y, row);

        if (sel_row || d->threat >= THREAT_HIGH)
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }

    char bot[24];
    snprintf(bot, sizeof(bot), "%u/%u dev",
             (unsigned)(s_scan_sel + 1), (unsigned)n);
    m1_draw_bottom_bar(&m1_u8g2, NULL, bot, NULL, NULL);
}

static void draw_filter_tab(void)
{
    for (uint8_t i = 0; i < CATEGORY_COUNT; i++) {
        uint8_t y = (uint8_t)(BLEPTD_LIST_START_Y + i * 7);
        if (i == s_filter_sel) {
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 6), 128, 8);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        }
        char row[28];
        const char *state;
        if (i == CATEGORY_MEDICAL) state = "[PROT]";
        else                       state = s_filter_enabled[i] ? "[ON ]" : "[OFF]";
        snprintf(row, sizeof(row), "%-10s%s", s_category_names[i], state);
        u8g2_DrawStr(&m1_u8g2, 2, y, row);
        if (i == s_filter_sel)
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }
}

/* Build the TX list (transmittable signatures only) */
static void build_tx_list(void)
{
    s_tx_list_n = 0;
    for (uint16_t i = 0; i < N_SIGS; i++) {
        if (s_sigs[i].transmittable && s_sigs[i].tx_hex != NULL) {
            s_tx_list[s_tx_list_n++] = i;
        }
    }
    /* Add Confusion Mode pseudo-entry as 0xFFFF */
    s_tx_list[s_tx_list_n++] = 0xFFFF;
}

static void draw_tx_tab(void)
{
    if (s_tx_list_n == 0) build_tx_list();

    if (s_tx_active) {
        char l1[32], l2[32], l3[32];
        if (s_tx_active_idx == -2) {
            snprintf(l1, sizeof(l1), "Confusion: cycling");
        } else if (s_tx_active_idx >= 0 &&
                   s_tx_active_idx < (int16_t)s_tx_list_n) {
            uint16_t s_i = s_tx_list[s_tx_active_idx];
            if (s_i != 0xFFFF) {
                snprintf(l1, sizeof(l1), "TX: %s", s_sigs[s_i].name);
            } else {
                snprintf(l1, sizeof(l1), "TX: Confusion");
            }
        } else {
            snprintf(l1, sizeof(l1), "TX active");
        }
        snprintf(l2, sizeof(l2), "MAC %s", s_tx_mac);
        snprintf(l3, sizeof(l3), "burst #%lu  OK=stop",
                 (unsigned long)s_tx_count);
        u8g2_DrawStr(&m1_u8g2, 2, 26, l1);
        u8g2_DrawStr(&m1_u8g2, 2, 38, l2);
        u8g2_DrawStr(&m1_u8g2, 2, 50, l3);
        return;
    }

    if (s_tx_sel >= s_tx_list_n) s_tx_sel = 0;
    if (s_tx_sel < s_tx_scroll) s_tx_scroll = s_tx_sel;
    if (s_tx_sel >= s_tx_scroll + BLEPTD_LIST_VISIBLE)
        s_tx_scroll = (uint8_t)(s_tx_sel - BLEPTD_LIST_VISIBLE + 1);

    for (uint8_t i = 0; i < BLEPTD_LIST_VISIBLE &&
                       (s_tx_scroll + i) < s_tx_list_n; i++) {
        uint8_t idx = (uint8_t)(s_tx_scroll + i);
        uint8_t y   = (uint8_t)(BLEPTD_LIST_START_Y + i * BLEPTD_ROW_H);
        bool    selrow = (idx == s_tx_sel);

        if (selrow) {
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 8), 128, BLEPTD_ROW_H);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        }
        char row[28];
        uint16_t s_i = s_tx_list[idx];
        if (s_i == 0xFFFF) {
            snprintf(row, sizeof(row), "%-16s [>]", "Confusion Mode");
        } else {
            snprintf(row, sizeof(row), "%-16s",
                     s_sigs[s_i].name);
        }
        u8g2_DrawStr(&m1_u8g2, 2, y, row);
        if (selrow)
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }

    char bot[24];
    snprintf(bot, sizeof(bot), "%u/%u OK=tx",
             (unsigned)(s_tx_sel + 1), (unsigned)s_tx_list_n);
    m1_draw_bottom_bar(&m1_u8g2, NULL, bot, NULL, NULL);
}

static void draw_setup_tab(void)
{
    char line[32];
    for (uint8_t i = 0; i < 3; i++) {
        uint8_t y = (uint8_t)(BLEPTD_LIST_START_Y + i * BLEPTD_ROW_H);
        if (i == s_setup_sel) {
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 8), 128, BLEPTD_ROW_H);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        }
        switch (i) {
            case 0:
                snprintf(line, sizeof(line), "Scan %us", (unsigned)s_scan_seconds);
                break;
            case 1:
                snprintf(line, sizeof(line), "Alert %s",
                         (s_alert_thresh == THREAT_HIGH) ? "HIGH" : "MED");
                break;
            case 2:
                snprintf(line, sizeof(line), "Export Log");
                break;
            default:
                line[0] = '\0';
                break;
        }
        u8g2_DrawStr(&m1_u8g2, 2, y, line);
        if (i == s_setup_sel)
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }

    snprintf(line, sizeof(line), "%u devices", (unsigned)s_device_count);
    m1_draw_bottom_bar(&m1_u8g2, NULL, line, NULL, NULL);
}

static void draw_all(void)
{
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_u8g2_firstpage();
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    draw_tab_bar();
    switch (s_tab) {
        case TAB_SCAN:   draw_scan_tab();   break;
        case TAB_FILTER: draw_filter_tab(); break;
        case TAB_TX:     draw_tx_tab();     break;
        case TAB_SETUP:  draw_setup_tab();  break;
        default: break;
    }
    m1_u8g2_nextpage();
}

/* --------------------------------------------------------------------------
 * Export log to /BLE/bleptd_log.txt
 * -------------------------------------------------------------------------- */

static const char *category_name(uint8_t c)
{
    if (c >= CATEGORY_COUNT) return "?";
    return s_category_names[c];
}

static void export_log(void)
{
    FIL  fp;
    FRESULT res;

    f_mkdir("/BLE");
    res = f_open(&fp, "/BLE/bleptd_log.txt", FA_WRITE | FA_CREATE_ALWAYS);
    if (res != FR_OK) return;

    char line[128];
    UINT bw;
    int len;

    len = snprintf(line, sizeof(line),
                   "BLEPTD log - %u devices\r\n",
                   (unsigned)s_device_count);
    f_write(&fp, line, (UINT)len, &bw);
    len = snprintf(line, sizeof(line),
                   "addr,name,category,threat,rssi,seen\r\n");
    f_write(&fp, line, (UINT)len, &bw);

    for (uint8_t i = 0; i < s_device_count; i++) {
        bleptd_device_t *d = &s_devices[i];
        len = snprintf(line, sizeof(line),
                       "%s,%s,%s,%u,%d,%u\r\n",
                       d->addr, d->name,
                       category_name(d->category),
                       (unsigned)d->threat,
                       (int)d->rssi,
                       (unsigned)d->seen_count);
        if (len < 0) continue;
        f_write(&fp, line, (UINT)len, &bw);
    }
    f_close(&fp);
}

/* --------------------------------------------------------------------------
 * Setup tab actions
 * -------------------------------------------------------------------------- */

static void setup_action(void)
{
    switch (s_setup_sel) {
        case 0: /* scan interval */
            if      (s_scan_seconds == 5)  s_scan_seconds = 10;
            else if (s_scan_seconds == 10) s_scan_seconds = 30;
            else                           s_scan_seconds = 5;
            break;
        case 1: /* alert threshold */
            if (s_alert_thresh == THREAT_MED) s_alert_thresh = THREAT_HIGH;
            else                              s_alert_thresh = THREAT_MED;
            break;
        case 2: /* export log */
            export_log();
            break;
        default: break;
    }
}

/* --------------------------------------------------------------------------
 * TX selection action
 * -------------------------------------------------------------------------- */

static void tx_select_action(void)
{
    if (s_tx_active) {
        tx_stop();
        return;
    }

    if (s_tx_list_n == 0) build_tx_list();
    if (s_tx_sel >= s_tx_list_n) return;

    uint16_t s_i = s_tx_list[s_tx_sel];
    tx_init();
    if (s_i == 0xFFFF) {
        /* Confusion mode */
        s_tx_active_idx  = -2;
        s_tx_count       = 0;
        s_tx_last_switch = 0;
    } else {
        if (!s_sigs[s_i].transmittable || !s_sigs[s_i].tx_hex) return;
        s_tx_active_idx = (int16_t)s_tx_sel;
        s_tx_count      = 0;
        tx_set_random_mac();
        tx_payload(s_sigs[s_i].tx_hex);
    }
}

/* --------------------------------------------------------------------------
 * TX cycling for confusion mode (called periodically)
 * -------------------------------------------------------------------------- */

static void tx_tick(void)
{
    if (!s_tx_active) return;
    if (s_tx_active_idx != -2) return; /* only confusion mode rotates */

    uint32_t now = HAL_GetTick();
    if ((now - s_tx_last_switch) < BLEPTD_TX_CYCLE_MS) return;
    s_tx_last_switch = now;

    /* Pick a random transmittable signature */
    uint16_t pool_max = (uint16_t)(s_tx_list_n > 0 ? s_tx_list_n - 1 : 0);
    if (pool_max == 0) return;
    uint16_t pick = (uint16_t)(rand() % pool_max);
    uint16_t s_i  = s_tx_list[pick];
    if (s_i == 0xFFFF || !s_sigs[s_i].transmittable || !s_sigs[s_i].tx_hex)
        return;

    tx_set_random_mac();
    tx_payload(s_sigs[s_i].tx_hex);
}

/* --------------------------------------------------------------------------
 * Button handling
 * -------------------------------------------------------------------------- */

static bool handle_button(const S_M1_Buttons_Status *btn)
{
    /* Universal: BACK exits */
    if (btn->event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) return true;

    /* LEFT/RIGHT navigate tabs (unless TX is broadcasting) */
    if (!s_tx_active) {
        if (btn->event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
            s_tab = (uint8_t)((s_tab + TAB_COUNT - 1) % TAB_COUNT);
            return false;
        }
        if (btn->event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
            s_tab = (uint8_t)((s_tab + 1) % TAB_COUNT);
            return false;
        }
    }

    switch (s_tab) {
        case TAB_SCAN: {
            uint8_t view[BLEPTD_MAX_DEVICES];
            uint8_t n = build_scan_view(view, BLEPTD_MAX_DEVICES);
            if (btn->event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK && n > 0)
                s_scan_sel = (uint8_t)((s_scan_sel > 0) ? (s_scan_sel - 1)
                                                        : (n - 1));
            else if (btn->event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK && n > 0)
                s_scan_sel = (uint8_t)((s_scan_sel + 1 < n) ? (s_scan_sel + 1) : 0);
        } break;

        case TAB_FILTER:
            if (btn->event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
                s_filter_sel = (uint8_t)((s_filter_sel > 0)
                                          ? (s_filter_sel - 1)
                                          : (CATEGORY_COUNT - 1));
            else if (btn->event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
                s_filter_sel = (uint8_t)((s_filter_sel + 1) % CATEGORY_COUNT);
            else if (btn->event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                if (s_filter_sel != CATEGORY_MEDICAL)
                    s_filter_enabled[s_filter_sel] =
                        !s_filter_enabled[s_filter_sel];
            }
            break;

        case TAB_TX:
            if (s_tx_active) {
                if (btn->event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
                    tx_stop();
                break;
            }
            if (s_tx_list_n == 0) build_tx_list();
            if (btn->event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK &&
                s_tx_list_n > 0)
                s_tx_sel = (uint8_t)((s_tx_sel > 0)
                                      ? (s_tx_sel - 1)
                                      : (s_tx_list_n - 1));
            else if (btn->event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK &&
                     s_tx_list_n > 0)
                s_tx_sel = (uint8_t)((s_tx_sel + 1 < s_tx_list_n)
                                      ? (s_tx_sel + 1) : 0);
            else if (btn->event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
                tx_select_action();
            break;

        case TAB_SETUP:
            if (btn->event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
                s_setup_sel = (uint8_t)((s_setup_sel > 0) ? (s_setup_sel - 1) : 2);
            else if (btn->event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
                s_setup_sel = (uint8_t)((s_setup_sel + 1) % 3);
            else if (btn->event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
                setup_action();
            break;

        default: break;
    }

    return false;
}

/* --------------------------------------------------------------------------
 * Reset state on entry
 * -------------------------------------------------------------------------- */

static void state_reset(void)
{
    memset(s_devices, 0, sizeof(s_devices));
    s_device_count    = 0;
    s_tab             = TAB_SCAN;
    s_scan_sel        = 0;
    s_scan_scroll     = 0;
    s_filter_sel      = 0;
    s_tx_sel          = 0;
    s_tx_scroll       = 0;
    s_setup_sel       = 0;
    s_tx_active       = false;
    s_tx_active_idx   = -1;
    s_tx_count        = 0;
    s_tx_last_switch  = 0;
    s_tx_mac[0]       = '\0';
    for (uint8_t i = 0; i < CATEGORY_COUNT; i++) s_filter_enabled[i] = true;
    s_scan_seconds    = BLEPTD_DEFAULT_SCAN_SEC;
    s_alert_thresh    = THREAT_MED;
    build_tx_list();
    srand((unsigned)HAL_GetTick());
}

/* --------------------------------------------------------------------------
 * Main entry point
 * -------------------------------------------------------------------------- */

void app_bleptd_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    bool                running = true;

    state_reset();

    /* Bring up ESP32 if needed */
    if (!m1_esp32_get_init_status())   m1_esp32_init();
    if (!get_esp32_main_init_status()) {
        m1_u8g2_firstpage();
        m1_draw_status_panel(&m1_u8g2, "BLEPTD", NULL,
                             hourglass_18x32, 18, 32,
                             "Initializing", "ESP32-C6", "Please wait...");
        m1_u8g2_nextpage();
        esp32_main_init();
    }
    if (!get_esp32_main_init_status()) {
        m1_message_box(&m1_u8g2, "BLEPTD", "ESP32 not", "ready", " OK ");
        m1_esp32_deinit();
        return;
    }

    /* Initial draw */
    draw_all();

    while (running) {
        /* Run a scan when on SCAN tab and not transmitting.        *
         * scan_pass() blocks for s_scan_seconds. After the scan we *
         * give the user a results-window where buttons are read    *
         * before the next scan starts. This matches the cadence in *
         * app_omni_sniffer.c.                                      */
        if (s_tab == TAB_SCAN && !s_tx_active) {
            scan_pass(s_scan_seconds);
            draw_all();
        } else {
            draw_all();
        }

        /* Decide a deadline for the input-collection window:       *
         * - on SCAN tab: 2.5s before next scan                     *
         * - confusion TX: BLEPTD_TX_CYCLE_MS                       *
         * - otherwise: block on input                              */
        bool block_forever = (s_tab != TAB_SCAN) && !s_tx_active;
        TickType_t deadline = xTaskGetTickCount();
        if (s_tx_active && s_tx_active_idx == -2) {
            deadline += pdMS_TO_TICKS(BLEPTD_TX_CYCLE_MS);
        } else if (s_tab == TAB_SCAN) {
            deadline += pdMS_TO_TICKS(2500);
        } else if (s_tx_active) {
            deadline += pdMS_TO_TICKS(500);
        }

        bool stay_in_window = true;
        while (stay_in_window) {
            TickType_t now = xTaskGetTickCount();
            TickType_t wait;
            if (block_forever) {
                wait = portMAX_DELAY;
            } else {
                wait = (deadline > now) ? (deadline - now) : 0;
            }

            BaseType_t r = xQueueReceive(main_q_hdl, &q_item, wait);
            if (r == pdTRUE) {
                if (q_item.q_evt_type == Q_EVENT_KEYPAD &&
                    xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE) {
                    if (handle_button(&btn)) {
                        running        = false;
                        stay_in_window = false;
                        break;
                    }
                    draw_all();
                    /* If the user changed the tab, exit the window  *
                     * immediately so the new tab can do its work.   */
                    if (s_tab == TAB_SCAN) {
                        stay_in_window = false;
                        break;
                    }
                    /* Otherwise stay collecting input until deadline */
                    if (block_forever) continue;
                }
            } else {
                /* Timeout */
                stay_in_window = false;
            }
        }

        /* Confusion-mode rotation tick (fires when window timed out) */
        if (s_tx_active && s_tx_active_idx == -2) {
            tx_tick();
            draw_all();
        }
    }

    /* Cleanup */
    if (s_tx_active) tx_stop();
    xQueueReset(main_q_hdl);
    m1_esp32_deinit();
}

#endif /* M1_APP_BLEPTD_ENABLE */
