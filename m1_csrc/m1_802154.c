/*
 * m1_802154.c
 *
 * IEEE 802.15.4 (Zigbee/Thread) scanning for M1
 *
 * Sends AT+ZIGSNIFF commands to ESP32-C6 and parses +ZIGFRAME responses.
 * Builds a deduplicated device list and displays it on the LCD.
 * Two entry points: zigbee_scan() and thread_scan() - same logic,
 * different protocol filter ('Z' vs 'T').
 *
 * AT+ZIGSNIFF SUPPORT STATUS
 * --------------------------
 * As of factory_ESP32C6-SPI-XIAO.bin (build dated 2026-04), the
 * ESP-AT command list (esp_at_list.h) declares only WiFi/BLE custom
 * commands -- AT+ZIGSNIFF is NOT registered. This sniff feature
 * therefore returns ERROR on every channel and surfaces "No devices
 * found" regardless of nearby Zigbee/Thread traffic.
 *
 * TODO (ESP32 firmware change required):
 *   1. Add AT+ZIGSNIFF=<enable>[,<channel>] to esp_at_list.h.
 *   2. In esp_at_custom_cmd implementation, call:
 *        esp_ieee802154_enable() then
 *        esp_ieee802154_set_promiscuous(true) and
 *        esp_ieee802154_receive() per channel.
 *   3. Forward each frame as "+ZIGFRAME:<proto>,<ftype>,<len>,<ch>,
 *      <rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex>".
 *   4. Run a 50ms drain loop in the AT firmware so unsolicited frames
 *      arrive at the master before being flushed by the next AT poll.
 *
 * Until that lands, the runtime ieee802154_start_sniffer call below
 * recognizes the ERROR response and surfaces a clear "AT firmware
 * does not support 802.15.4 sniff - flash new factory_ESP32C6-SPI"
 * message instead of "No devices found".
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "m1_802154.h"
#include "m1_esp32_hal.h"
#include "esp_app_main.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"

/*************************** D E F I N E S ************************************/

#define SCAN_DWELL_TIME_MS      2000   /* Time per channel in ms */
#define SCAN_POLL_INTERVAL_MS   50     /* How often to poll SPI for frames */
#define AT_RESP_BUF_SIZE        512    /* Buffer for AT responses */
#define IEEE802154_SCAN_ATTEMPTS 2
#define IEEE802154_RECOVERY_DELAY_MS 400

#define LIST_ITEM_HEIGHT        9
#define LIST_START_Y            13
#define LIST_VISIBLE            4


/************************** S T A T I C S ************************************/

static ieee802154_device_t s_devices[IEEE802154_MAX_DEVICES];
static int s_device_count = 0;

/********************* H E L P E R S ****************************************/

static void draw_title_bar(const char *title)
{
    u8g2_DrawXBMP(&m1_u8g2, 0, 0, 128, 14, m1_frame_128_14);
    u8g2_DrawStr(&m1_u8g2, 2, 1 + 10, title);
}

static bool ieee802154_ensure_esp32_ready(void)
{
    if (!m1_esp32_get_init_status())
        m1_esp32_init();

    if (!get_esp32_main_init_status())
        esp32_main_init();

    return get_esp32_main_init_status();
}

static void ieee802154_display_panel(const char *title,
                                     const char *line1,
                                     const char *line2,
                                     const char *line3)
{
    m1_u8g2_firstpage();
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    draw_title_bar(title);
    u8g2_DrawFrame(&m1_u8g2, 2, 16, 124, 34);
    if (line1)
        u8g2_DrawStr(&m1_u8g2, 6, 26, line1);
    if (line2)
        u8g2_DrawStr(&m1_u8g2, 6, 36, line2);
    if (line3)
        u8g2_DrawStr(&m1_u8g2, 6, 46, line3);
    m1_u8g2_nextpage();
}

static void ieee802154_recover_module(void)
{
    m1_esp32_deinit();
    esp32_disable();
    m1_hard_delay(100);
    esp32_enable();
    m1_hard_delay(IEEE802154_RECOVERY_DELAY_MS);
    ieee802154_ensure_esp32_ready();
}

static void ieee802154_stop_sniffer(char *resp_buf, size_t resp_buf_size)
{
    if (resp_buf && resp_buf_size > 0)
        resp_buf[0] = '\0';

    spi_AT_send_recv("AT+ZIGSNIFF=0\r\n", resp_buf, (int)resp_buf_size, 2);
}

static bool ieee802154_start_sniffer(uint8_t ch, char *resp_buf, size_t resp_buf_size)
{
    char cmd[24];

    if (resp_buf == NULL || resp_buf_size == 0)
        return false;

    snprintf(cmd, sizeof(cmd), "AT+ZIGSNIFF=1,%u\r\n", ch);

    for (uint8_t attempt = 0; attempt < IEEE802154_SCAN_ATTEMPTS; attempt++)
    {
        resp_buf[0] = '\0';
        spi_AT_send_recv(cmd, resp_buf, (int)resp_buf_size, 2);

        if (strstr(resp_buf, "ERROR") == NULL && strstr(resp_buf, "SEND_ERR") == NULL)
            return true;

        if ((attempt + 1U) < IEEE802154_SCAN_ATTEMPTS)
        {
            ieee802154_display_panel("802.15.4 Scan",
                                     "Sniffer start failed",
                                     "Recovering ESP32...",
                                     "Retrying now");
            ieee802154_recover_module();
        }
    }

    return false;
}

static void draw_list_item(uint8_t vis_idx, const char *text, bool selected)
{
    uint8_t y = LIST_START_Y + vis_idx * LIST_ITEM_HEIGHT;

    if (selected)
    {
        u8g2_SetDrawColor(&m1_u8g2, 1);
        u8g2_DrawBox(&m1_u8g2, 0, y, 128, LIST_ITEM_HEIGHT);
        u8g2_SetDrawColor(&m1_u8g2, 0);
    }

    char buf[22];
    strncpy(buf, text, 21);
    buf[21] = '\0';
    u8g2_DrawStr(&m1_u8g2, 2, y + 8, buf);

    if (selected)
        u8g2_SetDrawColor(&m1_u8g2, 1);
}

static void show_message(const char *title, const char *line1, const char *line2, uint16_t delay_ms)
{
    ieee802154_display_panel(title, line1, line2, NULL);
    if (delay_ms)
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
}

/*
 * Parse a +ZIGFRAME line and add/update device list.
 * Format: +ZIGFRAME:<proto>,<ftype>,<len>,<ch>,<rssi>,<lqi>,<dst_pan>,<dst_addr>,<src_pan>,<src_addr>,<hex>
 */
static void parse_zigframe(const char *line, char filter_proto)
{
    const char *p = strstr(line, "+ZIGFRAME:");
    if (!p) return;
    p += 10; /* skip "+ZIGFRAME:" */

    /* Parse proto (single char) */
    char proto = *p;
    /* Accept target protocol + unknown ('U') — many encrypted frames can't be classified */
    if (proto != filter_proto && proto != 'U') return;
    if (*++p != ',') return;
    p++;

    /* Parse ftype (up to comma) */
    char ftype[8] = {0};
    const char *comma = strchr(p, ',');
    if (!comma || (comma - p) >= (int)sizeof(ftype)) return;
    memcpy(ftype, p, comma - p);
    ftype[comma - p] = '\0';
    p = comma + 1;

    /* Parse len */
    /* uint8_t frame_len = (uint8_t)strtol(p, NULL, 10); */ /* unused */
    comma = strchr(p, ',');
    if (!comma) return;
    p = comma + 1;

    /* Parse channel */
    uint8_t channel = (uint8_t)strtol(p, NULL, 10);
    comma = strchr(p, ',');
    if (!comma) return;
    p = comma + 1;

    /* Parse RSSI */
    int8_t rssi = (int8_t)strtol(p, NULL, 10);
    comma = strchr(p, ',');
    if (!comma) return;
    p = comma + 1;

    /* Parse LQI */
    uint8_t lqi = (uint8_t)strtol(p, NULL, 10);
    comma = strchr(p, ',');
    if (!comma) return;
    p = comma + 1;

    /* Parse dst_pan */
    char dst_pan[IEEE802154_PAN_STR_SIZE] = {0};
    comma = strchr(p, ',');
    if (!comma) return;
    int len = (comma - p < (int)sizeof(dst_pan) - 1) ? (int)(comma - p) : (int)sizeof(dst_pan) - 1;
    memcpy(dst_pan, p, len);
    dst_pan[len] = '\0';
    p = comma + 1;

    /* Parse dst_addr */
    comma = strchr(p, ',');
    if (!comma) return;
    /* skip dst_addr — we dedup on src_addr */
    p = comma + 1;

    /* Parse src_pan */
    char src_pan[IEEE802154_PAN_STR_SIZE] = {0};
    comma = strchr(p, ',');
    if (!comma) return;
    len = (comma - p < (int)sizeof(src_pan) - 1) ? (int)(comma - p) : (int)sizeof(src_pan) - 1;
    memcpy(src_pan, p, len);
    src_pan[len] = '\0';
    p = comma + 1;

    /* Parse src_addr */
    char src_addr[IEEE802154_ADDR_STR_SIZE] = {0};
    comma = strchr(p, ',');
    if (!comma) return;
    len = (comma - p < (int)sizeof(src_addr) - 1) ? (int)(comma - p) : (int)sizeof(src_addr) - 1;
    memcpy(src_addr, p, len);
    src_addr[len] = '\0';

    /* Skip frames with no source address (ACKs) */
    if (src_addr[0] == '\0')
        return;

    /* Dedup: find existing device by (src_pan, src_addr) */
    for (int i = 0; i < s_device_count; i++)
    {
        if (strcmp(s_devices[i].src_pan, src_pan) == 0 &&
            strcmp(s_devices[i].src_addr, src_addr) == 0)
        {
            /* Update existing entry */
            s_devices[i].frame_count++;
            if (rssi > s_devices[i].rssi) s_devices[i].rssi = rssi;
            if (lqi > s_devices[i].lqi) s_devices[i].lqi = lqi;
            s_devices[i].channel = channel;
            /* Append frame type if not already present */
            if (!strstr(s_devices[i].frame_types, ftype))
            {
                if (s_devices[i].frame_types[0])
                    strncat(s_devices[i].frame_types, ",", sizeof(s_devices[i].frame_types) - strlen(s_devices[i].frame_types) - 1);
                strncat(s_devices[i].frame_types, ftype, sizeof(s_devices[i].frame_types) - strlen(s_devices[i].frame_types) - 1);
            }
            return;
        }
    }

    /* Add new device */
    if (s_device_count >= IEEE802154_MAX_DEVICES) return;

    ieee802154_device_t *dev = &s_devices[s_device_count];
    memset(dev, 0, sizeof(*dev));
    dev->proto = proto;
    strncpy(dev->src_pan, src_pan, sizeof(dev->src_pan) - 1);
    strncpy(dev->src_addr, src_addr, sizeof(dev->src_addr) - 1);
    strncpy(dev->dst_pan, dst_pan, sizeof(dev->dst_pan) - 1);
    dev->rssi = rssi;
    dev->lqi = lqi;
    dev->channel = channel;
    dev->frame_count = 1;
    strncpy(dev->frame_types, ftype, sizeof(dev->frame_types) - 1);
    s_device_count++;
}

/*
 * Process a buffer that may contain multiple +ZIGFRAME lines.
 */
static void process_response_buffer(const char *buf, char filter_proto)
{
    const char *p = buf;
    while ((p = strstr(p, "+ZIGFRAME:")) != NULL)
    {
        /* Find end of this line */
        const char *eol = strchr(p, '\n');
        if (!eol) eol = p + strlen(p);

        /* Copy line for parsing */
        char line[400];
        int llen = (eol - p < (int)sizeof(line) - 1) ? (int)(eol - p) : (int)sizeof(line) - 1;
        memcpy(line, p, llen);
        line[llen] = '\0';

        parse_zigframe(line, filter_proto);
        p = eol;
    }
}

/********************* D E T A I L   S C R E E N *****************************/

static void device_detail_screen(const char *title, ieee802154_device_t *dev)
{
    S_M1_Buttons_Status this_button_status;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    char prn_msg[25];
    bool redraw = true;

    while (1)
    {
        if (redraw)
        {
            redraw = false;
            m1_u8g2_firstpage();
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
            draw_title_bar(title);

            uint8_t y = 22;

            /* Source address */
            u8g2_DrawStr(&m1_u8g2, 2, y, dev->src_addr);
            y += 9;

            /* PAN ID + Channel */
            snprintf(prn_msg, sizeof(prn_msg), "PAN:%s Ch:%u", dev->src_pan, dev->channel);
            u8g2_DrawStr(&m1_u8g2, 2, y, prn_msg);
            y += 9;

            /* RSSI + LQI */
            snprintf(prn_msg, sizeof(prn_msg), "RSSI:%ddBm LQI:%u", dev->rssi, dev->lqi);
            u8g2_DrawStr(&m1_u8g2, 2, y, prn_msg);
            y += 9;

            /* Frame types + count */
            snprintf(prn_msg, sizeof(prn_msg), "%s (%u)", dev->frame_types, dev->frame_count);
            u8g2_DrawStr(&m1_u8g2, 2, y, prn_msg);

            m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "", NULL);
            m1_u8g2_nextpage();
        }

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &this_button_status, 0);
            if (this_button_status.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
             || this_button_status.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                break;
            }
        }
    }
}

/********************* M A I N   S C A N   L O G I C *************************/

/*
 * Core scan function. filter_proto = 'Z' for Zigbee, 'T' for Thread.
 */
static void ieee802154_scan(char filter_proto)
{
    S_M1_Buttons_Status this_button_status;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    int16_t selection = 0;
    int16_t scroll_offset = 0;
    bool redraw = true;
    bool scan_done = false;
    char page_info[20];
    char resp_buf[AT_RESP_BUF_SIZE];
    const char *title = (filter_proto == 'Z') ? "Zigbee Scan" : "Thread Scan";

    s_device_count = 0;
    memset(s_devices, 0, sizeof(s_devices));
    xQueueReset(main_q_hdl);

    /* Init ESP32 if needed */
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    ieee802154_display_panel(title, "Initializing...", "Preparing ESP32-C6", NULL);
    if (!ieee802154_ensure_esp32_ready())
    {
        ieee802154_display_panel(title, "ESP32 not ready", "Press BACK to exit", NULL);
        goto wait_exit;
    }

    int total_poll_bytes = 0;  /* diagnostic: total bytes received from polls */

    /* Scan all 16 channels (11-26) */
    for (uint8_t ch = 11; ch <= 26; ch++)
    {
        /* Show scanning progress */
        m1_u8g2_firstpage();
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        draw_title_bar(title);
        snprintf(page_info, sizeof(page_info), "Channel %u (%u/16)", ch, ch - 10);
        u8g2_DrawStr(&m1_u8g2, 2, 26, page_info);
        snprintf(page_info, sizeof(page_info), "Found: %d", s_device_count);
        u8g2_DrawStr(&m1_u8g2, 2, 38, page_info);
        /* Progress bar: channels 11-26 = 16 steps */
        {
            uint8_t bar_x = 2, bar_y = 44, bar_w = 124, bar_h = 6;
            uint8_t fill = (uint8_t)((uint16_t)(ch - 11 + 1) * (bar_w - 2) / 16);
            u8g2_DrawFrame(&m1_u8g2, bar_x, bar_y, bar_w, bar_h);
            u8g2_DrawBox(&m1_u8g2, bar_x + 1, bar_y + 1, fill, bar_h - 2);
        }
        m1_u8g2_nextpage();

        /* Start/switch channel */
        if (!ieee802154_start_sniffer(ch, resp_buf, sizeof(resp_buf)))
        {
            /* Most likely cause on stock ESP-AT: AT+ZIGSNIFF is not
             * a registered custom command (see file header for
             * required ESP-side change). Surface that explicitly. */
            if (ch == 11) {
                ieee802154_display_panel(title,
                    "AT firmware lacks",
                    "802.15.4 sniff support",
                    "Flash newer ESP-AT");
            } else {
                char err_msg[44];
                strncpy(err_msg, resp_buf, 40);
                err_msg[40] = '\0';
                for (int i = 0; err_msg[i]; i++)
                    if (err_msg[i] == '\r' || err_msg[i] == '\n') err_msg[i] = ' ';
                ieee802154_display_panel(title, "Sniffer start failed", err_msg, "BACK to exit");
            }
            goto wait_exit;
        }

        /* Dwell on this channel and collect frames */
        uint32_t dwell_start = HAL_GetTick();
        while ((HAL_GetTick() - dwell_start) < SCAN_DWELL_TIME_MS)
        {
            /* Poll for unsolicited +ZIGFRAME responses */
            resp_buf[0] = '\0';
            spi_AT_send_recv("AT\r\n", resp_buf, sizeof(resp_buf), 1);
            if (resp_buf[0])
            {
                total_poll_bytes += strlen(resp_buf);
                process_response_buffer(resp_buf, filter_proto);
            }
            vTaskDelay(pdMS_TO_TICKS(SCAN_POLL_INTERVAL_MS));

            /* Check for BACK press to abort scan */
            if (xQueueReceive(main_q_hdl, &q_item, 0) == pdTRUE)
            {
                if (q_item.q_evt_type == Q_EVENT_KEYPAD)
                {
                    xQueueReceive(button_events_q_hdl, &this_button_status, 0);
                    if (this_button_status.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
                     || this_button_status.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
                    {
                        /* Stop sniffer and exit */
                        ieee802154_stop_sniffer(resp_buf, sizeof(resp_buf));
                        xQueueReset(main_q_hdl);
                        m1_esp32_deinit();
                        return;
                    }
                }
            }
        }
    }

    /* Stop sniffer */
    ieee802154_stop_sniffer(resp_buf, sizeof(resp_buf));
    scan_done = true;

    if (!scan_done || s_device_count == 0)
    {
        char diag[32];
        snprintf(diag, sizeof(diag), "SPI data: %d bytes", total_poll_bytes);
        ieee802154_display_panel(title, "No devices found", diag, "OK retry BACK exit");
        goto wait_exit;
    }

    /* Display scrollable device list */
    selection = 0;
    scroll_offset = 0;
    redraw = true;

    while (1)
    {
        if (redraw)
        {
            redraw = false;
            m1_u8g2_firstpage();
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);

            snprintf(page_info, sizeof(page_info), "%s (%d)", title, s_device_count);
            draw_title_bar(page_info);

            /* Adjust scroll offset */
            if (selection < scroll_offset) scroll_offset = selection;
            if (selection >= scroll_offset + LIST_VISIBLE)
                scroll_offset = selection - LIST_VISIBLE + 1;

            /* Draw visible items */
            for (int i = 0; i < LIST_VISIBLE && scroll_offset + i < s_device_count; i++)
            {
                int idx = scroll_offset + i;
                char item_text[22];
                /* Show short addr + PAN + RSSI */
                snprintf(item_text, sizeof(item_text), "%s %sdB",
                    s_devices[idx].src_addr,
                    /* Format RSSI without snprintf sign issues */
                    "");
                /* Simpler: just show addr and RSSI */
                snprintf(item_text, sizeof(item_text), "%.12s %ddB",
                    s_devices[idx].src_addr, s_devices[idx].rssi);

                draw_list_item(i, item_text, (idx == selection));
            }

            snprintf(page_info, sizeof(page_info), "%d/%d", selection + 1, s_device_count);
            m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, page_info, "Info", arrowright_8x8);
            m1_u8g2_nextpage();
        }

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &this_button_status, 0);
            if (this_button_status.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
             || this_button_status.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                break;
            }
            else if (this_button_status.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (selection > 0) selection--;
                else selection = s_device_count - 1;
                redraw = true;
            }
            else if (this_button_status.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (selection < s_device_count - 1) selection++;
                else selection = 0;
                redraw = true;
            }
            else if (this_button_status.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK
                  || this_button_status.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                device_detail_screen(title, &s_devices[selection]);
                redraw = true;
            }
        }
    }

    xQueueReset(main_q_hdl);
    m1_esp32_deinit();
    return;

wait_exit:
    while (1)
    {
        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &this_button_status, 0);
            if (this_button_status.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
             || this_button_status.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
                break;
            if (this_button_status.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                ieee802154_stop_sniffer(resp_buf, sizeof(resp_buf));
                xQueueReset(main_q_hdl);
                m1_esp32_deinit();
                ieee802154_scan(filter_proto);
                return;
            }
        }
    }
    /* Stop sniffer just in case */
    ieee802154_stop_sniffer(resp_buf, sizeof(resp_buf));
    xQueueReset(main_q_hdl);
    m1_esp32_deinit();
}

/********************* P U B L I C   E N T R Y   P O I N T S *****************/

void zigbee_scan(void)
{
    ieee802154_scan(IEEE802154_PROTO_ZIGBEE);
}

void thread_scan(void)
{
    ieee802154_scan(IEEE802154_PROTO_THREAD);
}
