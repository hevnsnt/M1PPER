/* See COPYING.txt for license details. */

/*
 * app_omni_sniffer.c
 *
 * Omni-Sniffer v3: Unified BLE + Sub-GHz RF passive scanner.
 *
 * Continuously scans BLE (via ESP32-C6) and sweeps ISM RF bands (via SI4463).
 * Identifies ALL visible devices by type: iPhones, AirTags, Galaxy phones,
 * garage door remotes, key fobs, IoT sensors, trackers, and more.
 * Uses a multi-feature confidence classifier instead of binary threat detection.
 * Press BACK to exit.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_omni_sniffer.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "ctrl_api.h"
#include "m1_sub_ghz.h"
#include "m1_sub_ghz_api.h"

#ifdef M1_APP_OMNI_SNIFFER_ENABLE

/* ---- tuning ---- */
#define OMNI_SCAN_SEC         5
#define OMNI_RESULTS_MS    2500
#define OMNI_MAX_BLE         96
#define OMNI_MAX_RF           8
#define OMNI_MAX_DB         104   /* BLE slots + RF slots */
#define RF_DETECT_THRESH    -88   /* dBm: energy threshold for RF detection */
#define RF_DWELL_MS         150   /* ms to listen per RF frequency */

/* ---- display geometry ---- */
#define OMNI_ROW_H           10
#define OMNI_LIST_START_Y    14
#define OMNI_LIST_VISIBLE     4

/* ---- BLE company IDs ---- */
#define CID_APPLE        0x004C
#define CID_SAMSUNG      0x0075
#define CID_GOOGLE       0x00E0
#define CID_MICROSOFT    0x0006
#define CID_AMAZON       0x0171
#define CID_GARMIN       0x0087
#define CID_BOSE         0x002D
#define CID_FITBIT       0x00CA
#define CID_META         0x01AB
#define CID_FLIPPER      0x0499
#define CID_NORDIC       0x0059
#define CID_TI           0x000D
#define CID_PEBBLEBEE    0x06FF

/* ---- BLE signature table ---- */
typedef struct {
    uint16_t   cid;      /* company id; 0 = don't match on cid */
    uint8_t    s0;       /* mfr_sub[0]; 0 = wildcard */
    uint8_t    s1;       /* mfr_sub[1]; 0 = wildcard */
    uint16_t   svc;      /* service UUID; 0 = don't match on svc */
    uint8_t    conf;     /* confidence 1-5 */
    bool       tracker;
    const char *lbl;
} ble_sig_t;

static const ble_sig_t s_sigs[] = {
    /* Apple sub-type specific */
    { CID_APPLE, 0x12, 0, 0,      5, true,  "AirTag"      },
    { CID_APPLE, 0x07, 0, 0,      5, true,  "Find My"     },
    { CID_APPLE, 0x10, 0, 0,      5, false, "AirPods"     },
    { CID_APPLE, 0x0F, 0, 0,      5, false, "iPhone"      },
    { CID_APPLE, 0x0E, 0, 0,      5, false, "iPhone/Mac"  },
    { CID_APPLE, 0x0B, 0, 0,      5, false, "Apple Watch" },
    { CID_APPLE, 0x09, 0, 0,      4, false, "AirPlay"     },
    { CID_APPLE, 0x0C, 0, 0,      4, false, "Handoff"     },
    { CID_APPLE, 0x05, 0, 0,      4, false, "AirDrop"     },
    { CID_APPLE, 0,    0, 0,      3, false, "Apple Dev"   },
    /* Samsung */
    { CID_SAMSUNG, 0x42, 0x09, 0, 5, true,  "Galaxy Tag"  },
    { CID_SAMSUNG, 0x81, 0,    0, 4, false, "Galaxy Phone"},
    { CID_SAMSUNG, 0,    0,    0, 3, false, "Samsung Dev" },
    /* Trackers by service UUID */
    { 0, 0, 0, 0xFEEC,            5, true,  "Tile"        },
    { 0, 0, 0, 0xFE65,            5, true,  "Chipolo"     },
    /* Google */
    { CID_GOOGLE, 0, 0, 0,        3, false, "Google Dev"  },
    { 0,          0, 0, 0xFE2C,   4, false, "Nearby Share"},
    /* Microsoft */
    { CID_MICROSOFT, 0, 0, 0,     3, false, "Microsoft"   },
    /* Amazon */
    { CID_AMAZON, 0, 0, 0,        4, false, "Amazon Alexa"},
    /* Garmin */
    { CID_GARMIN, 0, 0, 0,        4, false, "Garmin"      },
    /* Bose */
    { CID_BOSE, 0, 0, 0,          4, false, "Bose Audio"  },
    /* Fitbit/Google */
    { CID_FITBIT, 0, 0, 0,        4, false, "Fitbit"      },
    /* Meta */
    { CID_META, 0, 0, 0,          4, false, "Meta Device" },
    /* Flipper Zero */
    { CID_FLIPPER, 0, 0, 0xFE60,  4, false, "Flipper Zero"},
    /* Nordic Semi (dev kits, custom IoT) */
    { CID_NORDIC, 0, 0, 0,        3, false, "Nordic IoT"  },
    /* Texas Instruments (Sensortag, etc.) */
    { CID_TI, 0, 0, 0,            3, false, "TI IoT"      },
    /* Pebblebee tracker */
    { CID_PEBBLEBEE, 0, 0, 0,     4, true,  "Pebblebee"   },
};
#define N_SIGS ((uint16_t)(sizeof(s_sigs) / sizeof(ble_sig_t)))

/* ---- RF bands to sweep ---- */
/* Covers US and EU ISM bands + pager/TPMS ranges.
 * Ordered by typical US prevalence. Keep N_RF_BANDS <= 8 to fit display. */
static const struct {
    S_M1_SubGHz_Band band;
    const char      *lbl;
} s_rf_bands[] = {
    { SUB_GHZ_BAND_315,    "315MHz Garage" },  /* US Chamberlain, Linear     */
    { SUB_GHZ_BAND_345,    "345MHz Honwl."  },  /* US Honeywell, 2GIG alarm    */
    { SUB_GHZ_BAND_433_92, "433MHz Keyfob" },  /* EU/AU keyfobs, sensors      */
    { SUB_GHZ_BAND_433,    "433MHz Sensor" },  /* 433.075 EU temperature       */
    { SUB_GHZ_BAND_390,    "390MHz KeyF2"  },  /* US Skylink / 390MHz gates   */
    { SUB_GHZ_BAND_915,    "915MHz IoT"    },  /* US LoRa, Z-Wave, ZigBee     */
};
#define N_RF_BANDS ((uint8_t)(sizeof(s_rf_bands) / sizeof(s_rf_bands[0])))

/* ---- persistent device record ---- */
typedef struct {
    bool     is_rf;
    uint8_t  addr[BSSID_STR_SIZE];
    uint16_t company_id;
    uint16_t service_uuid;
    uint8_t  mfr_sub[2];
    char     lbl[18];
    int      rssi;
    int      rssi_best;
    uint8_t  times_seen;
    uint8_t  conf;
    bool     is_tracker;
    bool     active;
} omni_dev_t;

static omni_dev_t s_db[OMNI_MAX_DB];
static uint16_t   s_db_n;

/* ---- helpers ---- */

static void db_reset(void)
{
    memset(s_db, 0, sizeof(s_db));
    s_db_n = 0;
}

/*
 * Classify a BLE device.
 * Returns confidence (1-5), sets *lbl_out and *tracker_out.
 * Returns 0 for completely anonymous devices (skip).
 */
static uint8_t ble_classify(const ble_scanlist_t *d,
                             const char **lbl_out, bool *tracker_out)
{
    *tracker_out = false;

    /* Match against signature table (most specific entries are listed first) */
    for (uint16_t i = 0; i < N_SIGS; i++) {
        const ble_sig_t *s = &s_sigs[i];
        if (s->cid) {
            if (d->company_id != s->cid) continue;
            if (s->s0 && d->mfr_sub[0] != s->s0) continue;
            if (s->s1 && d->mfr_sub[1] != s->s1) continue;
            *lbl_out     = s->lbl;
            *tracker_out = s->tracker;
            return s->conf;
        } else if (s->svc) {
            if (d->service_uuid != s->svc) continue;
            *lbl_out     = s->lbl;
            *tracker_out = s->tracker;
            return s->conf;
        }
    }

    /* Named device (BLE local name from advertisement) */
    if (d->name[0] != '\0') {
        *lbl_out = (const char *)d->name;
        return 4;
    }

    /* Unknown company ID - low confidence */
    if (d->company_id) {
        *lbl_out = "Unknown Mfr";
        return 2;
    }

    return 0; /* completely anonymous */
}

/* Merge BLE scan results into the persistent device DB. */
static void db_merge_ble(const ble_scanlist_t *scan, int16_t count)
{
    for (int16_t i = 0; i < count; i++) {
        const ble_scanlist_t *d = &scan[i];

        const char *lbl;
        bool        is_tracker;
        uint8_t     conf = ble_classify(d, &lbl, &is_tracker);
        if (conf == 0) continue;

        omni_dev_t *slot = NULL;
        for (uint16_t j = 0; j < s_db_n; j++) {
            if (!s_db[j].is_rf &&
                memcmp(s_db[j].addr, d->addr, sizeof(s_db[j].addr)) == 0) {
                slot = &s_db[j];
                break;
            }
        }
        if (!slot) {
            if (s_db_n >= OMNI_MAX_DB) continue;
            slot = &s_db[s_db_n++];
            memset(slot, 0, sizeof(*slot));
            memcpy(slot->addr, d->addr, sizeof(slot->addr));
            slot->rssi_best = d->rssi;
        }

        slot->active       = true;
        slot->rssi         = d->rssi;
        if (d->rssi > slot->rssi_best) slot->rssi_best = d->rssi;
        slot->times_seen++;
        slot->company_id   = d->company_id;
        slot->service_uuid = d->service_uuid;
        slot->mfr_sub[0]   = d->mfr_sub[0];
        slot->mfr_sub[1]   = d->mfr_sub[1];
        slot->is_tracker   = is_tracker;

        /* Update label if this classification is better than what we had */
        if (conf >= slot->conf || slot->lbl[0] == '\0') {
            slot->conf = conf;
            snprintf(slot->lbl, sizeof(slot->lbl), "%s", lbl);
        }
    }
}

/* Add or update an RF detection entry. Uses band_idx as unique key. */
static void db_merge_rf(uint8_t band_idx, const char *lbl, int rssi)
{
    omni_dev_t *slot = NULL;
    for (uint16_t j = 0; j < s_db_n; j++) {
        if (s_db[j].is_rf && s_db[j].addr[1] == band_idx) {
            slot = &s_db[j];
            break;
        }
    }
    if (!slot) {
        if (s_db_n >= OMNI_MAX_DB) return;
        slot = &s_db[s_db_n++];
        memset(slot, 0, sizeof(*slot));
        slot->is_rf   = true;
        slot->addr[0] = 0xAA;
        slot->addr[1] = band_idx;
        slot->rssi_best = rssi;
        snprintf(slot->lbl, sizeof(slot->lbl), "%s", lbl);
        slot->conf = 3;
    }
    slot->active = true;
    slot->rssi   = rssi;
    if (rssi > slot->rssi_best) slot->rssi_best = rssi;
    slot->times_seen++;
}

/*
 * Sweep key ISM RF bands using the SI4463 in passive OOK-RX mode.
 * Listens briefly on each band and records any detected RF energy.
 * RSSI formula: dBm = (CURR_RSSI / 2) - MODEM_RSSI_COMP - 70
 */
static void rf_scan_pass(void)
{
    for (uint8_t i = 0; i < N_RF_BANDS; i++) {
        radio_init_rx_tx(s_rf_bands[i].band, MODULATION_OOK, (i == 0));
        SI446x_Start_Rx(0);
        vTaskDelay(pdMS_TO_TICKS(RF_DWELL_MS));
        struct si446x_reply_GET_MODEM_STATUS_map *pstat = SI446x_Get_ModemStatus(0xFF);
        if (!pstat) continue;
        int8_t rssi_dbm = (int8_t)(pstat->CURR_RSSI / 2) - MODEM_RSSI_COMP - 70;
        if (rssi_dbm > RF_DETECT_THRESH)
            db_merge_rf(i, s_rf_bands[i].lbl, rssi_dbm);
    }
}

/* ---- display ---- */

static void draw_scanning(uint16_t cycle, uint16_t n_known)
{
    char line1[24], line2[24];
    snprintf(line1, sizeof(line1), "Scan #%u", (unsigned)cycle);
    snprintf(line2, sizeof(line2), "%u tracked", (unsigned)n_known);
    m1_u8g2_firstpage();
    m1_draw_status_panel(&m1_u8g2, "OMNI-SNIFFER", NULL,
                         hourglass_18x32, 18, 32,
                         line1, "BLE + RF scan...", line2);
    m1_u8g2_nextpage();
}

static void draw_results(uint16_t cycle, uint8_t sel, uint8_t scroll,
                         omni_dev_t **list, uint8_t list_n)
{
    char hdr_r[8];
    snprintf(hdr_r, sizeof(hdr_r), "#%u", (unsigned)cycle);

    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_u8g2_firstpage();
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    m1_draw_header_bar(&m1_u8g2, "OMNI-SNIFFER", hdr_r);

    if (list_n == 0) {
        u8g2_DrawStr(&m1_u8g2, 4, 28, "All Clear");
        u8g2_DrawStr(&m1_u8g2, 4, 40, "Rescanning...");
    } else {
        for (uint8_t i = 0; i < OMNI_LIST_VISIBLE && (scroll + i) < list_n; i++) {
            uint8_t       idx = scroll + i;
            const omni_dev_t *dev = list[idx];
            uint8_t       y   = OMNI_LIST_START_Y + i * OMNI_ROW_H;
            bool          sel_row = (idx == sel);

            if (sel_row) {
                u8g2_SetDrawColor(&m1_u8g2, 1);
                u8g2_DrawBox(&m1_u8g2, 2, y, 124, OMNI_ROW_H - 1);
                u8g2_SetDrawColor(&m1_u8g2, 0);
            }

            /* prefix: '!' tracker, '~' RF signal, ' ' normal BLE */
            char pfx = dev->is_rf ? '~' : (dev->is_tracker ? '!' : ' ');
            char row[26];
            snprintf(row, sizeof(row), "%c%-14.14s%4d",
                     pfx, dev->lbl, dev->rssi_best);
            u8g2_DrawStr(&m1_u8g2, 2, y + 7, row);

            if (sel_row)
                u8g2_SetDrawColor(&m1_u8g2, 1);
        }

        char bot[24];
        snprintf(bot, sizeof(bot), "%u/%u devices",
                 (unsigned)(sel + 1), (unsigned)list_n);
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, bot, NULL, NULL);
    }
    m1_u8g2_nextpage();
}

/* Priority comparison: trackers > confidence > times_seen > rssi */
static bool dev_before(const omni_dev_t *a, const omni_dev_t *b)
{
    if (a->is_tracker != b->is_tracker) return a->is_tracker;
    if (a->conf       != b->conf)       return a->conf > b->conf;
    if (a->times_seen != b->times_seen) return a->times_seen > b->times_seen;
    return a->rssi_best > b->rssi_best;
}

/* ---- entry point ---- */

void app_omni_sniffer_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    uint16_t  cycle    = 0;
    bool      running  = true;
    bool      rf_ready = false;
    BaseType_t ret;

    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);

    /* Initialize ESP32-C6 for BLE scanning */
    if (!m1_esp32_get_init_status())
        m1_esp32_init();

    if (!get_esp32_main_init_status()) {
        m1_u8g2_firstpage();
        m1_draw_status_panel(&m1_u8g2, "OMNI-SNIFFER", NULL,
                             hourglass_18x32, 18, 32,
                             "Initializing", "Preparing ESP32-C6", "Please wait...");
        m1_u8g2_nextpage();
        esp32_main_init();
    }
    if (!get_esp32_main_init_status()) {
        m1_u8g2_firstpage();
        m1_draw_status_panel(&m1_u8g2, "OMNI-SNIFFER", NULL, NULL, 0, 0,
                             "ESP32 not ready", "Press Back", NULL);
        m1_u8g2_nextpage();
        goto cleanup;
    }

    /* Initialize SI4463 sub-GHz radio for RF scanning */
    sub_ghz_init();
    rf_ready = true;

    db_reset();

    omni_dev_t *show[OMNI_MAX_DB];
    uint8_t     show_n = 0;
    uint8_t     sel = 0, scroll = 0;

    while (running) {
        cycle++;
        draw_scanning(cycle, s_db_n);

        /* BLE scan: blocks for OMNI_SCAN_SEC seconds */
        ctrl_cmd_t req = CTRL_CMD_DEFAULT_REQ();
        req.cmd_timeout_sec = OMNI_SCAN_SEC;
        req.msg_id = CTRL_RESP_GET_BLE_SCAN_LIST;
        ret = ble_scan_list_ex(&req);
        if (ret == SUCCESS && req.msg_type == CTRL_RESP &&
            req.resp_event_status == SUCCESS &&
            req.u.ble_scan.count > 0) {
            db_merge_ble(req.u.ble_scan.out_list, req.u.ble_scan.count);
            if (req.u.ble_scan.out_list)
                free(req.u.ble_scan.out_list);
        }

        /* RF sweep: ~3 bands x 150ms = ~500ms */
        if (rf_ready)
            rf_scan_pass();

        /* Rebuild sorted display list (confidence >= 2 and active) */
        show_n = 0;
        for (uint16_t j = 0; j < s_db_n && show_n < OMNI_MAX_DB; j++) {
            if (s_db[j].active && s_db[j].conf >= 2)
                show[show_n++] = &s_db[j];
        }

        /* Selection sort by priority (O(n^2) fine for n<=104) */
        for (uint8_t a = 0; a < show_n; a++) {
            uint8_t best = a;
            for (uint8_t b = a + 1; b < show_n; b++) {
                if (dev_before(show[b], show[best]))
                    best = b;
            }
            if (best != a) {
                omni_dev_t *t = show[a]; show[a] = show[best]; show[best] = t;
            }
        }

        if (sel >= show_n) sel = 0;
        scroll = 0;

        /* Display results, handle buttons, auto-advance after timeout */
        bool redraw = true;
        TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(OMNI_RESULTS_MS);

        while (running) {
            if (redraw) {
                redraw = false;
                if (sel < scroll) scroll = sel;
                if (sel >= scroll + OMNI_LIST_VISIBLE)
                    scroll = sel - OMNI_LIST_VISIBLE + 1;
                draw_results(cycle, sel, scroll, show, show_n);
            }

            TickType_t now  = xTaskGetTickCount();
            TickType_t wait = (deadline > now) ? (deadline - now) : 0;
            ret = xQueueReceive(main_q_hdl, &q_item, wait);

            if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD) {
                xQueueReceive(button_events_q_hdl, &btn, 0);
                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
                    running = false;
                } else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK &&
                           show_n > 0) {
                    sel    = (sel > 0) ? sel - 1 : show_n - 1;
                    redraw = true;
                } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK &&
                           show_n > 0) {
                    sel    = (sel < show_n - 1) ? sel + 1 : 0;
                    redraw = true;
                }
            } else {
                break; /* timeout: start next scan cycle */
            }
        }
    }

cleanup:
    xQueueReset(main_q_hdl);
    if (rf_ready)
        menu_sub_ghz_exit();
    m1_esp32_deinit();
}

#endif /* M1_APP_OMNI_SNIFFER_ENABLE */
