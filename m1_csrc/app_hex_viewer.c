/* See COPYING.txt for license details. */

/*
*
* app_hex_viewer.c
*
* Hex viewer utility app — pick a file from SD, then page through 24-byte
* windows of its content with U/D/L/R. Built on m1_app_runtime.
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "ff.h"
#include "m1_builtin_apps.h"
#include "m1_app_runtime.h"
#include "m1_layout.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_storage.h"
#include "m1_log_debug.h"

/*************************** D E F I N E S ************************************/

#define HEX_VIEWER_TAG          "HEXVW"
#define HEX_VIEWER_PAGE_BYTES  24U
#define HEX_VIEWER_ROW_BYTES    6U
#define HEX_VIEWER_ROW_COUNT    4U
#define HEX_VIEWER_TICK_MS    120U

//************************** S T R U C T U R E S *******************************/

typedef struct
{
    FIL      file;
    char     path[192];
    char     name[32];
    uint32_t file_size;
    uint32_t offset;
    bool     file_open;
} app_hex_viewer_state_t;

/***************************** V A R I A B L E S ******************************/

static app_hex_viewer_state_t s_hex_viewer;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static void hex_viewer_close(app_hex_viewer_state_t *st);
static bool hex_viewer_pick_file(app_hex_viewer_state_t *st);
static void hex_viewer_ascii_preview(const uint8_t *buf, uint16_t len,
                                     char *out, size_t out_len);
static void hex_viewer_format_row(const uint8_t *buf, uint16_t len,
                                  uint32_t row_offset,
                                  char *out, size_t out_len);
static void hex_viewer_init(m1_app_ctx_t *ctx);
static void hex_viewer_render(m1_app_ctx_t *ctx);
static bool hex_viewer_button(m1_app_ctx_t *ctx, m1_button_t btn);
static void hex_viewer_exit(m1_app_ctx_t *ctx);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

static void hex_viewer_close(app_hex_viewer_state_t *st)
{
    if (st->file_open)
    {
        f_close(&st->file);
        st->file_open = false;
    }
}


static bool hex_viewer_pick_file(app_hex_viewer_state_t *st)
{
    S_M1_file_info *f_info;
    FRESULT         res;

    hex_viewer_close(st);
    f_info = storage_browse(NULL);
    if (f_info == NULL || !f_info->file_is_selected)
    {
        return false;
    }

    snprintf(st->path, sizeof(st->path), "%s/%s",
             f_info->dir_name, f_info->file_name);
    strncpy(st->name, f_info->file_name, sizeof(st->name) - 1U);
    st->name[sizeof(st->name) - 1U] = '\0';

    res = f_open(&st->file, st->path, FA_READ | FA_OPEN_EXISTING);
    if (res != FR_OK)
    {
        st->file_open = false;
        st->file_size = 0U;
        st->offset    = 0U;
        return false;
    }

    st->file_size = f_size(&st->file);
    st->offset    = 0U;
    st->file_open = true;
    return true;
}


static void hex_viewer_ascii_preview(const uint8_t *buf, uint16_t len,
                                     char *out, size_t out_len)
{
    uint16_t count;

    if (out_len == 0U)
    {
        return;
    }

    count = (len < (uint16_t)(out_len - 1U)) ? len : (uint16_t)(out_len - 1U);
    for (uint16_t i = 0U; i < count; i++)
    {
        out[i] = isprint((int)buf[i]) ? (char)buf[i] : '.';
    }
    out[count] = '\0';
}


static void hex_viewer_format_row(const uint8_t *buf, uint16_t len,
                                  uint32_t row_offset,
                                  char *out, size_t out_len)
{
    uint16_t pos = 0U;

    if (out_len == 0U)
    {
        return;
    }

    pos += (uint16_t)snprintf(out + pos, out_len - pos, "%04lX ",
                              (unsigned long)(row_offset & 0xFFFFUL));
    for (uint16_t i = 0U; i < len && pos < (out_len - 3U); i++)
    {
        pos += (uint16_t)snprintf(out + pos, out_len - pos, "%02X", buf[i]);
    }

    out[out_len - 1U] = '\0';
}


static void hex_viewer_init(m1_app_ctx_t *ctx)
{
    app_hex_viewer_state_t *st = (app_hex_viewer_state_t *)ctx->user_state;

    if (!hex_viewer_pick_file(st))
    {
        ctx->should_exit = true;
    }
}


static void hex_viewer_render(m1_app_ctx_t *ctx)
{
    const app_hex_viewer_state_t *st =
        (const app_hex_viewer_state_t *)ctx->user_state;
    uint8_t  page_buf[HEX_VIEWER_PAGE_BYTES];
    UINT     br = 0U;
    char     badge[14];
    char     row_buf[24];
    char     ascii_buf[20];
    char     status_buf[24];
    uint32_t row_offset;
    uint8_t  row_y;
    uint16_t row_len;

    memset(page_buf, 0, sizeof(page_buf));
    memset(ascii_buf, 0, sizeof(ascii_buf));

    if (st->file_open)
    {
        FRESULT res = f_lseek((FIL *)&st->file, st->offset);
        if (res != FR_OK)
        {
            M1_LOG_W(HEX_VIEWER_TAG, "f_lseek -> %d\r\n", res);
        }
        else
        {
            res = f_read((FIL *)&st->file, page_buf, sizeof(page_buf), &br);
            if (res != FR_OK)
            {
                M1_LOG_W(HEX_VIEWER_TAG, "f_read -> %d\r\n", res);
                br = 0U;
            }
        }
    }

    snprintf(badge, sizeof(badge), "%04lX/%04lX",
             (unsigned long)(st->offset & 0xFFFFUL),
             (unsigned long)(st->file_size & 0xFFFFUL));
    if (st->file_open)
    {
        strncpy(status_buf, st->name, sizeof(status_buf) - 1U);
    }
    else
    {
        strncpy(status_buf, "No file selected", sizeof(status_buf) - 1U);
    }
    status_buf[sizeof(status_buf) - 1U] = '\0';
    hex_viewer_ascii_preview(page_buf, (uint16_t)br, ascii_buf, sizeof(ascii_buf));

    m1_u8g2_firstpage();
    m1_draw_header_bar(&m1_u8g2, "Hex Viewer", badge);
    m1_draw_content_frame(&m1_u8g2,
                          M1_LAYOUT_CONTENT_LEFT_X, M1_LAYOUT_CONTENT_TOP_Y,
                          M1_LAYOUT_CONTENT_W,      M1_LAYOUT_CONTENT_H);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 22, 114, status_buf, TEXT_ALIGN_LEFT);

    row_y = 30U;
    for (uint8_t row = 0U; row < HEX_VIEWER_ROW_COUNT; row++)
    {
        row_offset = st->offset + ((uint32_t)row * HEX_VIEWER_ROW_BYTES);
        if (row_offset >= st->file_size || row_offset >= (st->offset + br))
        {
            break;
        }

        row_len = (uint16_t)(br - (row * HEX_VIEWER_ROW_BYTES));
        if (row_len > HEX_VIEWER_ROW_BYTES)
        {
            row_len = HEX_VIEWER_ROW_BYTES;
        }

        hex_viewer_format_row(&page_buf[row * HEX_VIEWER_ROW_BYTES], row_len,
                              row_offset, row_buf, sizeof(row_buf));
        m1_draw_text(&m1_u8g2, 8, row_y, 114, row_buf, TEXT_ALIGN_LEFT);
        row_y = (uint8_t)(row_y + 8U);
    }

    m1_draw_text(&m1_u8g2, 8, 50, 114,
                 ascii_buf[0] ? ascii_buf : "ASCII preview", TEXT_ALIGN_LEFT);
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Browse", arrowright_8x8);
    m1_u8g2_nextpage();
}


static bool hex_viewer_button(m1_app_ctx_t *ctx, m1_button_t btn)
{
    app_hex_viewer_state_t *st = (app_hex_viewer_state_t *)ctx->user_state;

    switch (btn)
    {
        case M1_BTN_UP:
            if (st->offset >= HEX_VIEWER_ROW_BYTES)
            {
                st->offset -= HEX_VIEWER_ROW_BYTES;
            }
            else
            {
                st->offset = 0U;
            }
            return true;

        case M1_BTN_DOWN:
            if ((st->offset + HEX_VIEWER_ROW_BYTES) < st->file_size)
            {
                st->offset += HEX_VIEWER_ROW_BYTES;
            }
            return true;

        case M1_BTN_LEFT:
            if (st->offset >= HEX_VIEWER_PAGE_BYTES)
            {
                st->offset -= HEX_VIEWER_PAGE_BYTES;
            }
            else
            {
                st->offset = 0U;
            }
            return true;

        case M1_BTN_RIGHT:
            if ((st->offset + HEX_VIEWER_PAGE_BYTES) < st->file_size)
            {
                st->offset += HEX_VIEWER_PAGE_BYTES;
            }
            return true;

        case M1_BTN_OK:
            if (!hex_viewer_pick_file(st))
            {
                ctx->should_exit = true;
            }
            return true;

        default:
            return false;
    }
}


static void hex_viewer_exit(m1_app_ctx_t *ctx)
{
    app_hex_viewer_state_t *st = (app_hex_viewer_state_t *)ctx->user_state;
    hex_viewer_close(st);
}


void app_hex_viewer_run(void)
{
    static const m1_app_def_t def = {
        .title           = "Hex Viewer",
        .on_init         = hex_viewer_init,
        .on_render       = hex_viewer_render,
        .on_button       = hex_viewer_button,
        .on_tick         = NULL,
        .on_exit         = hex_viewer_exit,
        .tick_period_ms  = HEX_VIEWER_TICK_MS,
        .user_state      = &s_hex_viewer,
        .user_state_size = sizeof(s_hex_viewer),
    };

    m1_app_run(&def);
}
