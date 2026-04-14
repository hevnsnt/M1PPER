/* See COPYING.txt for license details. */

/*
*
* app_file_tools.c
*
* File tools utility app
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "m1_builtin_apps.h"
#include "m1_games.h"
#include "m1_storage.h"
#include "m1_sdcard.h"

/*************************** D E F I N E S ************************************/

#define FILE_TOOLS_ITEM_COUNT  4U
#define FILE_TOOLS_POLL_MS     120U
#define FILE_TOOLS_ROW_HEIGHT  6U
#define FILE_TOOLS_LIST_Y      27U

//************************** S T R U C T U R E S *******************************/

typedef enum
{
    FILE_TOOLS_MANAGE = 0,
    FILE_TOOLS_INFO,
    FILE_TOOLS_MOUNT,
    FILE_TOOLS_UNMOUNT
} file_tools_item_t;

/***************************** V A R I A B L E S ******************************/

static const char *file_tools_labels[FILE_TOOLS_ITEM_COUNT] = {
    "Manage Files",
    "Card Info",
    "Mount SD",
    "Unmount SD"
};

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static void file_tools_draw(uint8_t sel);
static void file_tools_status_text(char *status_text, size_t status_len, char *capacity_text, size_t capacity_len);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

static void file_tools_draw(uint8_t sel)
{
    char badge[12];
    char status_text[24];
    char capacity_text[20];
    uint8_t y = FILE_TOOLS_LIST_Y;

    snprintf(badge, sizeof(badge), "%u/%u", (unsigned)(sel + 1U), (unsigned)FILE_TOOLS_ITEM_COUNT);
    file_tools_status_text(status_text, sizeof(status_text), capacity_text, sizeof(capacity_text));

    m1_u8g2_firstpage();
    m1_draw_header_bar(&m1_u8g2, "File Tools", badge);
    m1_draw_content_frame(&m1_u8g2, 2, 14, 124, 36);

    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 7, 22, 74, status_text, TEXT_ALIGN_LEFT);
    m1_draw_text(&m1_u8g2, 83, 22, 36, capacity_text, TEXT_ALIGN_RIGHT);
    u8g2_DrawHLine(&m1_u8g2, 6, 24, 114);

    u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
    for (uint8_t i = 0; i < FILE_TOOLS_ITEM_COUNT; i++)
    {
        if (i == sel)
        {
            u8g2_DrawBox(&m1_u8g2, 6, (u8g2_uint_t)(y - 5U), 114, 7);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
            m1_draw_text(&m1_u8g2, 10, y, 108, file_tools_labels[i], TEXT_ALIGN_LEFT);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        }
        else
        {
            u8g2_DrawFrame(&m1_u8g2, 6, (u8g2_uint_t)(y - 5U), 114, 7);
            m1_draw_text(&m1_u8g2, 10, y, 108, file_tools_labels[i], TEXT_ALIGN_LEFT);
        }
        y = (uint8_t)(y + FILE_TOOLS_ROW_HEIGHT);
    }

    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Open", arrowright_8x8);
    m1_u8g2_nextpage();
}


static void file_tools_status_text(char *status_text, size_t status_len, char *capacity_text, size_t capacity_len)
{
    S_M1_SDCard_Access_Status sd_status = m1_sdcard_get_status();
    S_M1_SDCard_Info *info;
    unsigned long free_gb;
    unsigned long free_mb;

    snprintf(capacity_text, capacity_len, " ");

    if (sd_status == SD_access_OK)
    {
        info = m1_sdcard_get_info();
        snprintf(status_text, status_len, "SD card mounted");

        if (info != NULL)
        {
            free_gb = (unsigned long)(info->free_cap_kb / 1024UL / 1024UL);
            free_mb = (unsigned long)(info->free_cap_kb / 1024UL);

            if (free_gb > 0UL)
            {
                snprintf(capacity_text, capacity_len, "%luG free", free_gb);
            }
            else
            {
                snprintf(capacity_text, capacity_len, "%luM free", free_mb);
            }
        }
        else
        {
            snprintf(capacity_text, capacity_len, "Mounted");
        }
    }
    else if (sd_status == SD_access_NotReady)
    {
        snprintf(status_text, status_len, "No SD card detected");
        snprintf(capacity_text, capacity_len, "No card");
    }
    else if (sd_status == SD_access_NoFS)
    {
        snprintf(status_text, status_len, "Card needs formatting");
        snprintf(capacity_text, capacity_len, "No FS");
    }
    else if (sd_status == SD_access_UnMounted)
    {
        snprintf(status_text, status_len, "Card is unmounted");
        snprintf(capacity_text, capacity_len, "Offline");
    }
    else
    {
        snprintf(status_text, status_len, "Card access error");
        snprintf(capacity_text, capacity_len, "Error");
    }
}


void app_file_tools_run(void)
{
    uint8_t sel = 0;
    game_button_t btn;

    for (;;)
    {
        file_tools_draw(sel);
        btn = game_poll_button(FILE_TOOLS_POLL_MS);

        if (btn == GAME_BTN_BACK)
        {
            return;
        }
        if (btn == GAME_BTN_UP)
        {
            sel = (sel == 0U) ? (FILE_TOOLS_ITEM_COUNT - 1U) : (uint8_t)(sel - 1U);
        }
        else if (btn == GAME_BTN_DOWN)
        {
            sel = (uint8_t)((sel + 1U) % FILE_TOOLS_ITEM_COUNT);
        }
        else if (btn == GAME_BTN_OK || btn == GAME_BTN_RIGHT)
        {
            switch ((file_tools_item_t)sel)
            {
                case FILE_TOOLS_MANAGE:
                    storage_explore();
                    break;
                case FILE_TOOLS_INFO:
                    storage_about();
                    break;
                case FILE_TOOLS_MOUNT:
                    storage_mount();
                    break;
                case FILE_TOOLS_UNMOUNT:
                    storage_unmount();
                    break;
                default:
                    break;
            }
        }
    }
}
