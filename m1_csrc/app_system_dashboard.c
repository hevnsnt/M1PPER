/* See COPYING.txt for license details. */

/*
*
* app_system_dashboard.c
*
* System dashboard utility app
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "m1_builtin_apps.h"
#include "m1_games.h"
#include "m1_sdcard.h"
#include "m1_esp32_hal.h"
#include "m1_usb_cdc_msc.h"
#include "m1_t1000_version.h"
#include "battery.h"
#include "esp_app_main.h"

/*************************** D E F I N E S ************************************/

#define DASHBOARD_PAGE_COUNT   3U
#define DASHBOARD_POLL_MS      200U

//************************** S T R U C T U R E S *******************************/

typedef enum
{
    DASHBOARD_PAGE_OVERVIEW = 0,
    DASHBOARD_PAGE_IO,
    DASHBOARD_PAGE_SYSTEM
} dashboard_page_t;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static const char *dashboard_orientation_text(void);
static const char *dashboard_sd_status_text(S_M1_SDCard_Access_Status status);
static void dashboard_format_uptime(uint32_t uptime_ms, char *out, size_t out_len);
static void dashboard_draw_page(dashboard_page_t page);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

static const char *dashboard_orientation_text(void)
{
    switch (m1_screen_orientation)
    {
        case M1_ORIENT_SOUTHPAW:
            return "Southpaw";
        case M1_ORIENT_REMOTE:
            return "Remote";
        case M1_ORIENT_NORMAL:
        default:
            return "Normal";
    }
}


static const char *dashboard_sd_status_text(S_M1_SDCard_Access_Status status)
{
    switch (status)
    {
        case SD_access_OK:
            return "Ready";
        case SD_access_NoFS:
            return "No FS";
        case SD_access_UnMounted:
            return "Unmounted";
        case SD_access_NotReady:
            return "No Card";
        case SD_access_NotOK:
        default:
            return "Error";
    }
}


static void dashboard_format_uptime(uint32_t uptime_ms, char *out, size_t out_len)
{
    uint32_t total_sec = uptime_ms / 1000U;
    uint32_t hours = total_sec / 3600U;
    uint32_t minutes = (total_sec / 60U) % 60U;
    uint32_t seconds = total_sec % 60U;

    if (hours >= 100U)
    {
        snprintf(out, out_len, "%luh %lum", (unsigned long)hours, (unsigned long)minutes);
    }
    else
    {
        snprintf(out, out_len, "%02lu:%02lu:%02lu",
                 (unsigned long)hours,
                 (unsigned long)minutes,
                 (unsigned long)seconds);
    }
}


static void dashboard_draw_page(dashboard_page_t page)
{
    char badge[8];
    char line1[32];
    char line2[32];
    char line3[32];
    char line4[32];
    S_M1_Power_Status_t pwr;
    S_M1_SDCard_Access_Status sd_status;
    S_M1_SDCard_Info *sd_info;
    m1_time_t now;
    const char *usb_mode;
    const char *usb_link;

    battery_power_status_get(&pwr);
    m1_get_localtime(&now);
    sd_status = m1_sdcard_get_status();
    sd_info = (sd_status == SD_access_OK) ? m1_sdcard_get_info() : NULL;

    if (m1_USB_CDC_ready == M1_USB_MODE_HID)
    {
        usb_mode = "HID";
    }
    else
    {
        usb_mode = (m1_usbcdc_mode == CDC_MODE_VCP) ? "VCP" : "CLI";
    }
    usb_link = (hUsbDeviceFS.dev_state == USBD_STATE_CONFIGURED) ? "Linked" : "Idle";

    snprintf(badge, sizeof(badge), "%u/%u", (unsigned)page + 1U, (unsigned)DASHBOARD_PAGE_COUNT);

    line1[0] = '\0';
    line2[0] = '\0';
    line3[0] = '\0';
    line4[0] = '\0';

    if (page == DASHBOARD_PAGE_OVERVIEW)
    {
        char uptime[20];
        dashboard_format_uptime(HAL_GetTick(), uptime, sizeof(uptime));
        snprintf(line1, sizeof(line1), "%02u:%02u:%02u  %02u/%02u/%02u",
                 now.hour, now.minute, now.second,
                 now.month, now.day, now.year % 100U);
        snprintf(line2, sizeof(line2), "Battery %u%%  %uC",
                 pwr.battery_level, pwr.battery_temp);
        snprintf(line3, sizeof(line3), "VBAT %.1fV  %dmA",
                 pwr.battery_voltage / 1000.0f, pwr.consumption_current);
        snprintf(line4, sizeof(line4), "Uptime %s", uptime);
    }
    else if (page == DASHBOARD_PAGE_IO)
    {
        if (sd_info != NULL)
        {
            snprintf(line1, sizeof(line1), "SD %s  %luG free",
                     dashboard_sd_status_text(sd_status),
                     (unsigned long)(sd_info->free_cap_kb / 1024UL / 1024UL));
            snprintf(line2, sizeof(line2), "Card %s", sd_info->vol_label[0] ? sd_info->vol_label : "No label");
        }
        else
        {
            snprintf(line1, sizeof(line1), "SD %s", dashboard_sd_status_text(sd_status));
            snprintf(line2, sizeof(line2), "Use Mount or check card");
        }
        snprintf(line3, sizeof(line3), "USB %s  %s", usb_mode, usb_link);
        snprintf(line4, sizeof(line4), "ESP32 %s / %s",
                 m1_esp32_get_init_status() ? "HAL" : "Off",
                 get_esp32_main_init_status() ? "AT Ready" : "AT Idle");
    }
    else
    {
        snprintf(line1, sizeof(line1), "%s", T1000_VERSION_STRING);
        snprintf(line2, sizeof(line2), "Compat %d.%d.%d.%d",
                 FW_VERSION_MAJOR, FW_VERSION_MINOR, FW_VERSION_BUILD, FW_VERSION_RC);
        snprintf(line3, sizeof(line3), "Bank %d  %s",
                 (m1_device_stat.active_bank == BANK1_ACTIVE) ? 1 : 2,
                 dashboard_orientation_text());
        snprintf(line4, sizeof(line4), "Buzz %s  LED %s",
                 m1_buzzer_on ? "On" : "Off",
                 m1_led_notify_on ? "On" : "Off");
    }

    m1_u8g2_firstpage();
    m1_draw_header_bar(&m1_u8g2, "Dashboard", badge);
    m1_draw_content_frame(&m1_u8g2, 2, 14, 124, 37);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 23, 114, line1, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 8, 32, 114, line2, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 8, 41, 114, line3, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 8, 50, 114, line4, TEXT_ALIGN_LEFT);
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Next", arrowright_8x8);
    m1_u8g2_nextpage();
}


void app_system_dashboard_run(void)
{
    dashboard_page_t page = DASHBOARD_PAGE_OVERVIEW;
    game_button_t btn;

    for (;;)
    {
        dashboard_draw_page(page);
        btn = game_poll_button(DASHBOARD_POLL_MS);

        if (btn == GAME_BTN_BACK)
        {
            return;
        }
        if (btn == GAME_BTN_LEFT || btn == GAME_BTN_UP)
        {
            page = (page == DASHBOARD_PAGE_OVERVIEW) ?
                (dashboard_page_t)(DASHBOARD_PAGE_COUNT - 1U) :
                (dashboard_page_t)(page - 1U);
        }
        else if (btn == GAME_BTN_RIGHT || btn == GAME_BTN_DOWN || btn == GAME_BTN_OK)
        {
            page = (dashboard_page_t)((page + 1U) % DASHBOARD_PAGE_COUNT);
        }
    }
}
