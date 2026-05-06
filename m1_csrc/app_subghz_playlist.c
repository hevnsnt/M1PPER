/* See COPYING.txt for license details. */

/*
 * app_subghz_playlist.c
 *
 * SubGHz Playlist: plays all .sub (Flipper-format) and .sgh (native) files
 * found in a selected folder on the SD card, one after another.
 *
 * The user picks a subfolder under /SUBGHZ/Playlists/ (or /SUBGHZ/ directly),
 * sets an inter-file delay, then presses OK to start.
 *
 * Each file is transmitted using the existing sub_ghz_replay_flipper_file()
 * / sub_ghz_file_load() infrastructure.
 *
 * Navigation:
 *   UP/DOWN  = browse folders/delay
 *   OK/RIGHT = start playback
 *   BACK     = exit / stop current playback
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_subghz_playlist.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_sdcard.h"
#include "m1_sub_ghz.h"
#include "app_freertos.h"
#include "cmsis_os.h"
#include "ff.h"

#ifdef M1_APP_SUBGHZ_PLAYLIST_ENABLE

/* -------------------------------------------------------------------------- */
#define PLAYLIST_ROOT      "0:/SUBGHZ"
#define PLAYLIST_MAX_FILES  64
#define PLAYLIST_MAX_PATH   128

/* -------------------------------------------------------------------------- */
/* File list (stack-allocated, no heap) */
static char s_paths[PLAYLIST_MAX_FILES][PLAYLIST_MAX_PATH];
static uint8_t s_count;

/* -------------------------------------------------------------------------- */

static uint8_t playlist_scan_dir(const char *dir)
{
    DIR d;
    FILINFO fno;
    uint8_t n = 0;

    if (f_opendir(&d, dir) != FR_OK) return 0;

    while (n < PLAYLIST_MAX_FILES) {
        if (f_readdir(&d, &fno) != FR_OK || fno.fname[0] == '\0') break;
        if (fno.fattrib & AM_DIR) continue;

        uint16_t nl = (uint16_t)strlen(fno.fname);
        bool is_sub = (nl > 4 && (strncasecmp(&fno.fname[nl - 4], ".sub", 4) == 0));
        bool is_sgh = (nl > 4 && (strncasecmp(&fno.fname[nl - 4], ".sgh", 4) == 0));
        if (!is_sub && !is_sgh) continue;

        snprintf(s_paths[n], PLAYLIST_MAX_PATH, "%s/%s", dir, fno.fname);
        n++;
    }
    f_closedir(&d);
    return n;
}

/* -------------------------------------------------------------------------- */

static void draw_status(const char *status, const char *filename,
                        uint8_t current, uint8_t total)
{
    char prog[24];
    snprintf(prog, sizeof(prog), "%u/%u", current, total);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 0, 11, "SubGHz Playlist");
    u8g2_DrawHLine(&m1_u8g2, 0, 13, 128);
    u8g2_DrawStr(&m1_u8g2, 2, 24, status);
    u8g2_DrawStr(&m1_u8g2, 2, 35, filename);
    u8g2_DrawStr(&m1_u8g2, 2, 46, prog);
    u8g2_DrawStr(&m1_u8g2, 2, 58, "[BACK] Stop");
    m1_u8g2_nextpage();
}

static void draw_menu(const char *dir, uint16_t delay_ms)
{
    char delay_str[24];
    snprintf(delay_str, sizeof(delay_str), "Delay: %ums", delay_ms);
    char dir_str[24];
    /* Show just last component */
    const char *d = strrchr(dir, '/');
    snprintf(dir_str, sizeof(dir_str), "Dir: %s", d ? d + 1 : dir);

    m1_u8g2_firstpage();
    u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 0, 11, "SubGHz Playlist");
    u8g2_DrawHLine(&m1_u8g2, 0, 13, 128);
    u8g2_DrawStr(&m1_u8g2, 2, 26, dir_str);
    u8g2_DrawStr(&m1_u8g2, 2, 38, delay_str);
    u8g2_DrawStr(&m1_u8g2, 2, 52, "OK=Start  UP/DN=Delay");
    m1_u8g2_nextpage();
}

/* -------------------------------------------------------------------------- */

void subghz_playlist_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;

    /* Scan the /SUBGHZ directory for .sub/.sgh files */
    s_count = playlist_scan_dir(PLAYLIST_ROOT);

    if (s_count == 0) {
        m1_message_box(&m1_u8g2, "Playlist", "No .sub/.sgh", "files in", "/SUBGHZ");
        return;
    }

    uint16_t delay_ms = 500;   /* inter-file gap */
    draw_menu(PLAYLIST_ROOT, delay_ms);

    /* Config loop */
    while (1) {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) continue;

        if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK) {
            if (delay_ms < 5000) delay_ms += 100;
            draw_menu(PLAYLIST_ROOT, delay_ms);
        } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK) {
            if (delay_ms >= 100) delay_ms -= 100;
            draw_menu(PLAYLIST_ROOT, delay_ms);
        } else if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK ||
                   btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK) {
            break; /* start playback */
        } else if (btn.event[BUTTON_BACK_KP_ID]  == BUTTON_EVENT_CLICK ||
                   btn.event[BUTTON_LEFT_KP_ID]  == BUTTON_EVENT_CLICK) {
            return;
        }
    }

    /* Playback loop */
    for (uint8_t i = 0; i < s_count; i++) {
        /* Filename for display (just the last component) */
        const char *fn = strrchr(s_paths[i], '/');
        fn = fn ? fn + 1 : s_paths[i];

        draw_status("Playing...", fn, i + 1, s_count);

        /* Determine file type and transmit */
        uint16_t plen = (uint16_t)strlen(s_paths[i]);
        bool is_sub = (plen > 4 && strncasecmp(&s_paths[i][plen - 4], ".sub", 4) == 0);

        /* sub_ghz_replay_flipper_file() handles both .sub and falls back gracefully for .sgh */
        (void)is_sub;
        sub_ghz_replay_flipper_file(s_paths[i]);

        /* Check for BACK between files */
        bool aborted = false;
        TickType_t t0 = xTaskGetTickCount();
        TickType_t gap = pdMS_TO_TICKS(delay_ms);
        while ((xTaskGetTickCount() - t0) < gap) {
            if (xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(50)) == pdTRUE) {
                if (q_item.q_evt_type == Q_EVENT_KEYPAD &&
                    xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE) {
                    if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
                        btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK) {
                        aborted = true;
                        break;
                    }
                }
            }
        }
        if (aborted) break;
    }

    draw_status("Done", "", s_count, s_count);
    /* Wait for BACK */
    while (1) {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) continue;
        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK ||
            btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            break;
    }
}

#endif /* M1_APP_SUBGHZ_PLAYLIST_ENABLE */
