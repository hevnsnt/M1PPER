/* See COPYING.txt for license details. */

/*
 * app_ble_gatt.c
 *
 * BLE GATT Browser.
 *
 * Scans for nearby BLE devices, lets the user pick one, connects to it via
 * the ESP32-C6 in BLE central role (AT+BLEINIT=1) and enumerates all primary
 * services and their characteristics.  A read action on a selected
 * characteristic shows the raw value as hex.
 *
 * Pure SPI-AT command driven, no heap allocations.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_ble_gatt.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "app_freertos.h"
#include "cmsis_os.h"

#ifdef M1_APP_BLE_GATT_ENABLE

/* ---- tuning ---- */
#define GATT_MAX_DEVICES        16
#define GATT_MAX_SERVICES       16
#define GATT_MAX_CHARS          48
#define GATT_AT_BUF_SIZE       512
#define GATT_SCAN_SECONDS        5
#define GATT_AT_TIMEOUT_S        3
#define GATT_CONN_TIMEOUT_S      8
#define GATT_VAL_LEN            48

/* Display geometry */
#define GATT_ROW_H              10
#define GATT_LIST_START_Y       24
#define GATT_LIST_VISIBLE        4

/* GATT properties (BLE Core 4.0 char declaration) */
#define CHAR_PROP_BCAST       0x01
#define CHAR_PROP_READ        0x02
#define CHAR_PROP_WRITE_NR    0x04
#define CHAR_PROP_WRITE       0x08
#define CHAR_PROP_NOTIFY      0x10
#define CHAR_PROP_INDICATE    0x20

/* App states */
typedef enum {
    GATT_STATE_SCAN_BUSY = 0,
    GATT_STATE_SCAN_LIST,
    GATT_STATE_CONNECTING,
    GATT_STATE_CONN_FAILED,
    GATT_STATE_BROWSE,
    GATT_STATE_READ_VALUE,
} gatt_state_t;

typedef struct {
    char    addr[18];   /* "AA:BB:CC:DD:EE:FF" */
    int8_t  rssi;
    uint8_t addr_type;
} gatt_dev_t;

typedef struct {
    uint8_t  srv_idx;
    uint16_t uuid16;       /* 0 if non-16-bit */
    bool     uuid_is_16;
    char     uuid_str[40]; /* full UUID as reported */
    uint16_t start_handle; /* unused (ESP-AT does not surface) but reserved */
    uint16_t end_handle;
} gatt_srv_t;

typedef struct {
    uint8_t  srv_idx;
    uint8_t  char_idx;
    uint16_t uuid16;
    bool     uuid_is_16;
    char     uuid_str[40];
    uint8_t  prop;
} gatt_char_t;

/* --------------------------------------------------------------------------
 * State (static, no heap)
 * -------------------------------------------------------------------------- */

static gatt_dev_t   s_devs[GATT_MAX_DEVICES];
static uint8_t      s_dev_n;
static uint8_t      s_dev_sel;
static uint8_t      s_dev_scroll;

static gatt_srv_t   s_srvs[GATT_MAX_SERVICES];
static uint8_t      s_srv_n;

static gatt_char_t  s_chars[GATT_MAX_CHARS];
static uint8_t      s_char_n;

/* The browse view interleaves services and their characteristics into one
 * scrollable list. Each row points to either an SVC (kind=0) or CHR (kind=1).*/
typedef struct {
    uint8_t kind;   /* 0=SVC, 1=CHR */
    uint8_t idx;    /* index into s_srvs[] or s_chars[] */
} gatt_row_t;

static gatt_row_t   s_rows[GATT_MAX_SERVICES + GATT_MAX_CHARS];
static uint8_t      s_rows_n;
static uint8_t      s_rows_sel;
static uint8_t      s_rows_scroll;

static uint8_t      s_read_value[GATT_VAL_LEN];
static uint8_t      s_read_value_len;
static char         s_read_uuid_label[24];

static char         s_at_buf[GATT_AT_BUF_SIZE];

/* --------------------------------------------------------------------------
 * Well-known UUID lookup
 * -------------------------------------------------------------------------- */

typedef struct {
    uint16_t    uuid;
    const char *name;
} uuid_name_t;

static const uuid_name_t s_uuid_names[] = {
    /* services */
    { 0x1800, "GenAccess"   },
    { 0x1801, "GenAttrib"   },
    { 0x1802, "ImmedAlert"  },
    { 0x1803, "LinkLoss"    },
    { 0x1804, "TxPower"     },
    { 0x1805, "CurrTime"    },
    { 0x1808, "Glucose"     },
    { 0x180A, "DevInfo"     },
    { 0x180D, "HeartRate"   },
    { 0x180F, "Battery"     },
    { 0x1810, "BloodPress"  },
    { 0x1812, "HID"         },
    { 0x1816, "CycSpeed"    },
    { 0x181A, "EnvSense"    },
    { 0x181C, "UserData"    },
    { 0x181D, "WeightScale" },
    { 0x1822, "PulseOx"     },
    { 0xFEED, "Tile"        },
    { 0xFE2C, "GoogFastPair"},
    /* characteristics */
    { 0x2A00, "DevName"     },
    { 0x2A01, "Appearance"  },
    { 0x2A19, "BatteryLvl"  },
    { 0x2A24, "ModelNum"    },
    { 0x2A25, "SerialNum"   },
    { 0x2A26, "FwRev"       },
    { 0x2A27, "HwRev"       },
    { 0x2A28, "SwRev"       },
    { 0x2A29, "Manufact"    },
    { 0x2A2B, "CurrTime"    },
    { 0x2A37, "HRMeasure"   },
    { 0x2A38, "BodySensor"  },
    { 0x2A50, "PnP"         },
    { 0x2A6E, "Temperature" },
    { 0x2A6F, "Humidity"    },
};
#define N_UUID_NAMES ((uint16_t)(sizeof(s_uuid_names) / sizeof(s_uuid_names[0])))

static const char *uuid_lookup(uint16_t u)
{
    for (uint16_t i = 0; i < N_UUID_NAMES; i++)
        if (s_uuid_names[i].uuid == u) return s_uuid_names[i].name;
    return NULL;
}

/* --------------------------------------------------------------------------
 * AT helpers
 * -------------------------------------------------------------------------- */

static void at_send(const char *cmd, int timeout_s)
{
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf), timeout_s);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

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

/* Parse "0xNNNN" or "NNNN" into uint16_t. Returns -1 on failure. */
static int32_t parse_uuid16(const char *s)
{
    if (!s || !*s) return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    /* Quick check: 4 hex digits, then end-of-token */
    uint16_t v = 0;
    uint8_t  n = 0;
    while (s[n] && n < 4) {
        int d = hex_nibble(s[n]);
        if (d < 0) break;
        v = (uint16_t)((v << 4) | (uint16_t)d);
        n++;
    }
    if (n == 0 || n > 4) return -1;
    return (int32_t)v;
}

/* Extract a quoted token starting at *pp into out (up to out_max-1 chars).
 * Advances *pp past closing quote and following comma if any.            */
static bool parse_quoted(char **pp, char *out, uint16_t out_max)
{
    char *p = *pp;
    if (*p != '"') return false;
    p++;
    uint16_t n = 0;
    while (*p && *p != '"' && n + 1 < out_max) out[n++] = *p++;
    out[n] = '\0';
    if (*p != '"') return false;
    p++;
    if (*p == ',') p++;
    *pp = p;
    return true;
}

/* Trim whitespace (in-place) and return length. */
static size_t trim_inplace(char *s)
{
    size_t l = strlen(s);
    while (l > 0 && (s[l-1] == ' ' || s[l-1] == '\r' || s[l-1] == '\t')) {
        s[--l] = '\0';
    }
    return l;
}

/* --------------------------------------------------------------------------
 * Scanning
 * -------------------------------------------------------------------------- */

static void scan_devices(void)
{
    s_dev_n = 0;
    s_dev_sel = 0;
    s_dev_scroll = 0;

    at_send("AT+BLEINIT=1\r\n", GATT_AT_TIMEOUT_S);
    vTaskDelay(pdMS_TO_TICKS(50));
    at_send("AT+BLESCANPARAM=0,0,0,80,40\r\n", GATT_AT_TIMEOUT_S);
    vTaskDelay(pdMS_TO_TICKS(20));

    char cmd[40];
    snprintf(cmd, sizeof(cmd), "AT+BLESCAN=1,%u\r\n", (unsigned)GATT_SCAN_SECONDS);
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf),
                     (int)(GATT_SCAN_SECONDS + GATT_AT_TIMEOUT_S));

    char *line = s_at_buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        trim_inplace(line);

        if (strncmp(line, "+BLESCAN:", 9) == 0) {
            char *p = line + 9;
            char addr[18];
            if (parse_quoted(&p, addr, sizeof(addr)) && strlen(addr) == 17) {
                int rssi = atoi(p);
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                /* skip adv_data */
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                /* skip scan_rsp */
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                /* addr_type */
                int addr_type = atoi(p);

                /* Normalize uppercase */
                for (uint8_t i = 0; i < 17; i++)
                    if (addr[i] >= 'a' && addr[i] <= 'f') addr[i] = (char)(addr[i] - 32);

                /* Update or insert */
                bool found = false;
                for (uint8_t i = 0; i < s_dev_n; i++) {
                    if (memcmp(s_devs[i].addr, addr, 17) == 0) {
                        if ((int8_t)rssi > s_devs[i].rssi) s_devs[i].rssi = (int8_t)rssi;
                        found = true;
                        break;
                    }
                }
                if (!found && s_dev_n < GATT_MAX_DEVICES) {
                    memset(&s_devs[s_dev_n], 0, sizeof(s_devs[s_dev_n]));
                    memcpy(s_devs[s_dev_n].addr, addr, 17);
                    s_devs[s_dev_n].addr[17]   = '\0';
                    s_devs[s_dev_n].rssi       = (int8_t)rssi;
                    s_devs[s_dev_n].addr_type  = (uint8_t)addr_type;
                    s_dev_n++;
                }
            }
        }

        if (!nl) break;
        line = nl + 1;
    }

    at_send("AT+BLESCAN=0\r\n", GATT_AT_TIMEOUT_S);
}

/* --------------------------------------------------------------------------
 * Connect + service discovery
 * -------------------------------------------------------------------------- */

static bool gatt_connect(const gatt_dev_t *d)
{
    /* Lowercase address for AT  */
    char addr_lc[18];
    memcpy(addr_lc, d->addr, 18);
    for (uint8_t i = 0; i < 17; i++)
        if (addr_lc[i] >= 'A' && addr_lc[i] <= 'F')
            addr_lc[i] = (char)(addr_lc[i] + 32);

    char cmd[64];
    snprintf(cmd, sizeof(cmd),
             "AT+BLECONN=0,\"%s\",%u,%u\r\n",
             addr_lc, (unsigned)d->addr_type, (unsigned)GATT_CONN_TIMEOUT_S);
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf), GATT_CONN_TIMEOUT_S + 2);

    if (strstr(s_at_buf, "+BLECONN:0")) return true;
    if (strstr(s_at_buf, "OK"))         return true;
    return false;
}

static void gatt_disconnect(void)
{
    at_send("AT+BLEDISCONN=0\r\n", GATT_AT_TIMEOUT_S);
    vTaskDelay(pdMS_TO_TICKS(100));
}

/* Parse +BLEGATTCPRIMSRV:0,<srv_idx>,<srv_uuid>,<srv_type>
 * srv_uuid is "0xNNNN" for 16-bit or full string for 128-bit.            */
static void parse_primsrv_lines(void)
{
    s_srv_n = 0;
    char *line = s_at_buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        trim_inplace(line);

        if (strncmp(line, "+BLEGATTCPRIMSRV:", 17) == 0) {
            char *p = line + 17;
            /* conn_index */
            int conn = atoi(p);
            (void)conn;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
            /* srv_idx */
            int srv_idx = atoi(p);
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
            /* srv_uuid (may be quoted, may be naked 0xNNNN) */
            char uuid_str[40] = {0};
            if (*p == '"') {
                parse_quoted(&p, uuid_str, sizeof(uuid_str));
            } else {
                uint16_t k = 0;
                while (*p && *p != ',' && k + 1 < sizeof(uuid_str))
                    uuid_str[k++] = *p++;
                uuid_str[k] = '\0';
                if (*p == ',') p++;
            }

            if (s_srv_n < GATT_MAX_SERVICES) {
                gatt_srv_t *s = &s_srvs[s_srv_n];
                memset(s, 0, sizeof(*s));
                s->srv_idx = (uint8_t)srv_idx;
                strncpy(s->uuid_str, uuid_str, sizeof(s->uuid_str) - 1);
                int32_t u16 = parse_uuid16(uuid_str);
                if (u16 >= 0 && strlen(uuid_str) <= 6) {
                    s->uuid16     = (uint16_t)u16;
                    s->uuid_is_16 = true;
                } else {
                    s->uuid_is_16 = false;
                }
                s_srv_n++;
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
}

static void parse_char_lines(uint8_t srv_idx)
{
    /* Look for +BLEGATTCCHAR:"char",<conn>,<srv>,<char>,<uuid>,<prop>     */
    char *line = s_at_buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        trim_inplace(line);

        if (strncmp(line, "+BLEGATTCCHAR:", 14) == 0) {
            char *p = line + 14;
            char tag[8] = {0};
            if (parse_quoted(&p, tag, sizeof(tag)) && strcmp(tag, "char") == 0) {
                int conn = atoi(p);
                (void)conn;
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                int srv = atoi(p);
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                int chx = atoi(p);
                while (*p && *p != ',') p++;
                if (*p == ',') p++;
                char uuid_str[40] = {0};
                if (*p == '"') {
                    parse_quoted(&p, uuid_str, sizeof(uuid_str));
                } else {
                    uint16_t k = 0;
                    while (*p && *p != ',' && k + 1 < sizeof(uuid_str))
                        uuid_str[k++] = *p++;
                    uuid_str[k] = '\0';
                    if (*p == ',') p++;
                }
                int prop = atoi(p);

                if ((uint8_t)srv == srv_idx && s_char_n < GATT_MAX_CHARS) {
                    gatt_char_t *c = &s_chars[s_char_n];
                    memset(c, 0, sizeof(*c));
                    c->srv_idx  = (uint8_t)srv;
                    c->char_idx = (uint8_t)chx;
                    strncpy(c->uuid_str, uuid_str, sizeof(c->uuid_str) - 1);
                    int32_t u16 = parse_uuid16(uuid_str);
                    if (u16 >= 0 && strlen(uuid_str) <= 6) {
                        c->uuid16     = (uint16_t)u16;
                        c->uuid_is_16 = true;
                    } else {
                        c->uuid_is_16 = false;
                    }
                    c->prop = (uint8_t)prop;
                    s_char_n++;
                }
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
}

static void enumerate_services(void)
{
    s_srv_n  = 0;
    s_char_n = 0;

    /* Discover primary services */
    at_send("AT+BLEGATTCPRIMSRV=0\r\n", GATT_CONN_TIMEOUT_S);
    parse_primsrv_lines();

    /* For each service, discover characteristics */
    for (uint8_t i = 0; i < s_srv_n; i++) {
        char cmd[40];
        snprintf(cmd, sizeof(cmd), "AT+BLEGATTCCHAR=0,%u\r\n",
                 (unsigned)s_srvs[i].srv_idx);
        at_send(cmd, GATT_CONN_TIMEOUT_S);
        parse_char_lines(s_srvs[i].srv_idx);
    }

    /* Build interleaved row list */
    s_rows_n = 0;
    for (uint8_t i = 0; i < s_srv_n; i++) {
        if (s_rows_n >= sizeof(s_rows) / sizeof(s_rows[0])) break;
        s_rows[s_rows_n].kind = 0;
        s_rows[s_rows_n].idx  = i;
        s_rows_n++;
        for (uint8_t j = 0; j < s_char_n; j++) {
            if (s_chars[j].srv_idx != s_srvs[i].srv_idx) continue;
            if (s_rows_n >= sizeof(s_rows) / sizeof(s_rows[0])) break;
            s_rows[s_rows_n].kind = 1;
            s_rows[s_rows_n].idx  = j;
            s_rows_n++;
        }
    }
    s_rows_sel    = 0;
    s_rows_scroll = 0;
}

/* --------------------------------------------------------------------------
 * Read characteristic
 * -------------------------------------------------------------------------- */

static bool read_char_value(uint8_t srv_idx, uint8_t char_idx,
                            uint16_t uuid16, bool uuid_is_16,
                            const char *uuid_str)
{
    char cmd[48];
    snprintf(cmd, sizeof(cmd),
             "AT+BLEGATTCRD=0,%u,%u,0\r\n",
             (unsigned)srv_idx, (unsigned)char_idx);
    spi_AT_send_recv(cmd, s_at_buf, sizeof(s_at_buf), GATT_AT_TIMEOUT_S);

    s_read_value_len = 0;
    if (uuid_is_16) {
        const char *nm = uuid_lookup(uuid16);
        if (nm) snprintf(s_read_uuid_label, sizeof(s_read_uuid_label),
                         "%04X %s", uuid16, nm);
        else    snprintf(s_read_uuid_label, sizeof(s_read_uuid_label),
                         "%04X", uuid16);
    } else {
        snprintf(s_read_uuid_label, sizeof(s_read_uuid_label), "%s",
                 uuid_str ? uuid_str : "?");
    }

    /* Look for "+BLEGATTCRD:0,<len>,<hex>" */
    char *line = s_at_buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        trim_inplace(line);

        if (strncmp(line, "+BLEGATTCRD:", 12) == 0) {
            char *p = line + 12;
            int conn = atoi(p);
            (void)conn;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
            int len = atoi(p);
            (void)len;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
            /* The remainder is hex */
            char *hex = p;
            /* Trim quotes if any */
            if (*hex == '"') {
                hex++;
                char *q = strchr(hex, '"');
                if (q) *q = '\0';
            }
            s_read_value_len = (uint8_t)hex_decode(hex, s_read_value, GATT_VAL_LEN);
            return true;
        }

        if (!nl) break;
        line = nl + 1;
    }
    return false;
}

/* --------------------------------------------------------------------------
 * Drawing
 * -------------------------------------------------------------------------- */

static void draw_header(const char *r)
{
    m1_draw_header_bar(&m1_u8g2, "BLE GATT", r);
}

static void draw_busy(const char *l1, const char *l2)
{
    m1_u8g2_firstpage();
    m1_draw_status_panel(&m1_u8g2, "BLE GATT", NULL,
                         hourglass_18x32, 18, 32,
                         l1, l2, NULL);
    m1_u8g2_nextpage();
}

static void draw_msg(const char *l1, const char *l2, const char *l3)
{
    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    draw_header(NULL);
    if (l1) u8g2_DrawStr(&m1_u8g2, 4, 28, l1);
    if (l2) u8g2_DrawStr(&m1_u8g2, 4, 40, l2);
    if (l3) u8g2_DrawStr(&m1_u8g2, 4, 52, l3);
    m1_u8g2_nextpage();
}

static void draw_dev_list(void)
{
    if (s_dev_sel >= s_dev_n) s_dev_sel = (s_dev_n > 0) ? (uint8_t)(s_dev_n - 1) : 0;
    if (s_dev_sel < s_dev_scroll) s_dev_scroll = s_dev_sel;
    if (s_dev_sel >= s_dev_scroll + GATT_LIST_VISIBLE)
        s_dev_scroll = (uint8_t)(s_dev_sel - GATT_LIST_VISIBLE + 1);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    {
        char r[8];
        snprintf(r, sizeof(r), "%u", (unsigned)s_dev_n);
        draw_header(r);
    }

    if (s_dev_n == 0) {
        u8g2_DrawStr(&m1_u8g2, 4, 30, "No BLE devices");
        u8g2_DrawStr(&m1_u8g2, 4, 42, "Press OK rescan");
    } else {
        for (uint8_t i = 0; i < GATT_LIST_VISIBLE && (s_dev_scroll + i) < s_dev_n; i++) {
            uint8_t      idx = (uint8_t)(s_dev_scroll + i);
            gatt_dev_t  *d   = &s_devs[idx];
            uint8_t      y   = (uint8_t)(GATT_LIST_START_Y + i * GATT_ROW_H);
            bool         sel = (idx == s_dev_sel);

            if (sel) {
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
                u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 8), 128, GATT_ROW_H);
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
            }
            char row[32];
            /* Compact addr: drop the colons -> 12 hex chars */
            char compact[13]; uint8_t k = 0;
            for (uint8_t j = 0; j < 17 && k < 12; j++)
                if (d->addr[j] != ':') compact[k++] = d->addr[j];
            compact[12] = '\0';
            snprintf(row, sizeof(row), "%c %s %4d",
                     sel ? '>' : ' ', compact, (int)d->rssi);
            u8g2_DrawStr(&m1_u8g2, 2, y, row);
            if (sel)
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        }
        char bot[24];
        snprintf(bot, sizeof(bot), "%u/%u OK=conn",
                 (unsigned)(s_dev_sel + 1), (unsigned)s_dev_n);
        m1_draw_bottom_bar(&m1_u8g2, NULL, bot, NULL, NULL);
    }
    m1_u8g2_nextpage();
}

static void prop_str(uint8_t prop, char out[8])
{
    uint8_t p = 0;
    out[p++] = '[';
    if (prop & CHAR_PROP_READ)     out[p++] = 'R';
    if (prop & (CHAR_PROP_WRITE | CHAR_PROP_WRITE_NR)) out[p++] = 'W';
    if (prop & CHAR_PROP_NOTIFY)   out[p++] = 'N';
    if (prop & CHAR_PROP_INDICATE) out[p++] = 'I';
    out[p++] = ']';
    out[p]   = '\0';
}

static void draw_browse(void)
{
    if (s_rows_n == 0) {
        draw_msg("No services", "found", "BACK to exit");
        return;
    }
    if (s_rows_sel >= s_rows_n) s_rows_sel = (uint8_t)(s_rows_n - 1);
    if (s_rows_sel < s_rows_scroll) s_rows_scroll = s_rows_sel;
    if (s_rows_sel >= s_rows_scroll + GATT_LIST_VISIBLE)
        s_rows_scroll = (uint8_t)(s_rows_sel - GATT_LIST_VISIBLE + 1);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    {
        char r[10];
        snprintf(r, sizeof(r), "%us %uc", (unsigned)s_srv_n, (unsigned)s_char_n);
        draw_header(r);
    }

    for (uint8_t i = 0; i < GATT_LIST_VISIBLE && (s_rows_scroll + i) < s_rows_n; i++) {
            uint8_t     idx = (uint8_t)(s_rows_scroll + i);
            gatt_row_t *r2  = &s_rows[idx];
            uint8_t     y   = (uint8_t)(GATT_LIST_START_Y + i * GATT_ROW_H);
            bool        sel = (idx == s_rows_sel);

            if (sel) {
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
                u8g2_DrawBox(&m1_u8g2, 0, (u8g2_uint_t)(y - 8), 128, GATT_ROW_H);
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
            }

            char row[36];
            if (r2->kind == 0) {
                gatt_srv_t *s = &s_srvs[r2->idx];
                const char *nm = s->uuid_is_16 ? uuid_lookup(s->uuid16) : NULL;
                if (s->uuid_is_16) {
                    snprintf(row, sizeof(row), "S %04X %-12.12s",
                             s->uuid16, nm ? nm : "");
                } else {
                    snprintf(row, sizeof(row), "S %-16.16s", s->uuid_str);
                }
            } else {
                gatt_char_t *c = &s_chars[r2->idx];
                const char  *nm = c->uuid_is_16 ? uuid_lookup(c->uuid16) : NULL;
                char props[8];
                prop_str(c->prop, props);
                if (c->uuid_is_16) {
                    snprintf(row, sizeof(row), " c %04X %-7.7s%s",
                             c->uuid16, nm ? nm : "", props);
                } else {
                    snprintf(row, sizeof(row), " c %-12.12s%s", c->uuid_str, props);
                }
            }
            u8g2_DrawStr(&m1_u8g2, 2, y, row);
            if (sel)
                u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        }

    char bot[24];
    snprintf(bot, sizeof(bot), "%u/%u OK=read",
             (unsigned)(s_rows_sel + 1), (unsigned)s_rows_n);
    m1_draw_bottom_bar(&m1_u8g2, NULL, bot, NULL, NULL);
    m1_u8g2_nextpage();
}

static void draw_value(void)
{
    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    draw_header("READ");
    u8g2_DrawStr(&m1_u8g2, 2, 22, s_read_uuid_label);

    /* Hex line(s) */
    char l1[40], l2[40];
    l1[0] = '\0'; l2[0] = '\0';
    for (uint8_t i = 0; i < s_read_value_len && i < 12; i++) {
        char tmp[4];
        snprintf(tmp, sizeof(tmp), "%02X ", s_read_value[i]);
        strncat(l1, tmp, sizeof(l1) - strlen(l1) - 1);
    }
    for (uint8_t i = 12; i < s_read_value_len && i < 24; i++) {
        char tmp[4];
        snprintf(tmp, sizeof(tmp), "%02X ", s_read_value[i]);
        strncat(l2, tmp, sizeof(l2) - strlen(l2) - 1);
    }
    u8g2_DrawStr(&m1_u8g2, 2, 36, l1);
    if (l2[0]) u8g2_DrawStr(&m1_u8g2, 2, 48, l2);

    /* ASCII row */
    char ascii[16];
    uint8_t a = 0;
    for (uint8_t i = 0; i < s_read_value_len && a + 1 < sizeof(ascii); i++) {
        uint8_t b = s_read_value[i];
        ascii[a++] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
    }
    ascii[a] = '\0';
    u8g2_DrawStr(&m1_u8g2, 2, 60, ascii);
    m1_u8g2_nextpage();
}

/* --------------------------------------------------------------------------
 * Main entry
 * -------------------------------------------------------------------------- */

void app_ble_gatt_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    bool                running = true;
    gatt_state_t        state;

    /* Bring up ESP32 if needed */
    if (!m1_esp32_get_init_status())   m1_esp32_init();
    if (!get_esp32_main_init_status()) {
        draw_busy("Initializing", "ESP32-C6...");
        esp32_main_init();
    }
    if (!get_esp32_main_init_status()) {
        m1_message_box(&m1_u8g2, "BLE GATT", "ESP32 not", "ready", " OK ");
        m1_esp32_deinit();
        return;
    }

    state = GATT_STATE_SCAN_BUSY;

    while (running) {
        switch (state) {
            case GATT_STATE_SCAN_BUSY:
                draw_busy("Scanning BLE", "5 seconds...");
                scan_devices();
                state = GATT_STATE_SCAN_LIST;
                draw_dev_list();
                break;

            case GATT_STATE_SCAN_LIST:
                if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) break;
                if (q_item.q_evt_type != Q_EVENT_KEYPAD) break;
                if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) break;

                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                    running = false;
                } else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK && s_dev_n > 0) {
                    s_dev_sel = (uint8_t)((s_dev_sel > 0) ? (s_dev_sel - 1) : (s_dev_n - 1));
                    draw_dev_list();
                } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK && s_dev_n > 0) {
                    s_dev_sel = (uint8_t)((s_dev_sel + 1 < s_dev_n) ? (s_dev_sel + 1) : 0);
                    draw_dev_list();
                } else if (btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
                    /* rescan */
                    state = GATT_STATE_SCAN_BUSY;
                } else if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK ||
                           btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
                    if (s_dev_n > 0) state = GATT_STATE_CONNECTING;
                }
                break;

            case GATT_STATE_CONNECTING: {
                char busy_l2[24];
                /* Show abbreviated address */
                snprintf(busy_l2, sizeof(busy_l2),
                         "%s", s_devs[s_dev_sel].addr);
                draw_busy("Connecting to", busy_l2);
                if (gatt_connect(&s_devs[s_dev_sel])) {
                    draw_busy("Discovering", "services...");
                    enumerate_services();
                    state = GATT_STATE_BROWSE;
                    draw_browse();
                } else {
                    state = GATT_STATE_CONN_FAILED;
                    draw_msg("Connect failed", "Try again", "BACK to list");
                }
            } break;

            case GATT_STATE_CONN_FAILED:
                if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) break;
                if (q_item.q_evt_type != Q_EVENT_KEYPAD) break;
                if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) break;
                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_OK_KP_ID]   == BUTTON_EVENT_CLICK) {
                    state = GATT_STATE_SCAN_LIST;
                    draw_dev_list();
                }
                break;

            case GATT_STATE_BROWSE:
                if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) break;
                if (q_item.q_evt_type != Q_EVENT_KEYPAD) break;
                if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) break;

                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
                    gatt_disconnect();
                    state = GATT_STATE_SCAN_LIST;
                    draw_dev_list();
                } else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK && s_rows_n > 0) {
                    s_rows_sel = (uint8_t)((s_rows_sel > 0) ? (s_rows_sel - 1) : (s_rows_n - 1));
                    draw_browse();
                } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK && s_rows_n > 0) {
                    s_rows_sel = (uint8_t)((s_rows_sel + 1 < s_rows_n) ? (s_rows_sel + 1) : 0);
                    draw_browse();
                } else if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK ||
                           btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
                    if (s_rows_n > 0 && s_rows[s_rows_sel].kind == 1) {
                        gatt_char_t *c = &s_chars[s_rows[s_rows_sel].idx];
                        if (c->prop & CHAR_PROP_READ) {
                            draw_busy("Reading", "characteristic");
                            if (read_char_value(c->srv_idx, c->char_idx,
                                                c->uuid16, c->uuid_is_16,
                                                c->uuid_str)) {
                                state = GATT_STATE_READ_VALUE;
                                draw_value();
                            } else {
                                draw_msg("Read failed", "or empty", "OK to return");
                                state = GATT_STATE_READ_VALUE;
                            }
                        }
                    }
                }
                break;

            case GATT_STATE_READ_VALUE:
                if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) break;
                if (q_item.q_evt_type != Q_EVENT_KEYPAD) break;
                if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) break;
                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK ||
                    btn.event[BUTTON_OK_KP_ID]   == BUTTON_EVENT_CLICK) {
                    state = GATT_STATE_BROWSE;
                    draw_browse();
                }
                break;

            default:
                running = false;
                break;
        }
    }

    gatt_disconnect();
    at_send("AT+BLEINIT=0\r\n", GATT_AT_TIMEOUT_S);
    xQueueReset(main_q_hdl);
    m1_esp32_deinit();
}

#endif /* M1_APP_BLE_GATT_ENABLE */
