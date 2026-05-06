/* See COPYING.txt for license details. */

/*
 *
 * app_rgb_backlight.c
 *
 * Unified Backlight settings menu for M1. Auto-detects whether the RGB
 * mod (LP5814 / SK6805) is fitted and shows the matching control set:
 *   - RGB hardware fitted -> RGB mode / animation / brightness controls
 *   - Bare LP5814 only    -> simple monochrome on/off + brightness
 *
 * Settings (mode / effect / brightness) are persisted to
 * `0:/System/settings.cfg` via `settings_save_to_sd`. The save call is
 * debounced 5 seconds after the last user input so we do not wear the
 * SD card with a write on every D-pad tick.
 *
 * The legacy `app_stock_backlight_run` and `app_rgb_backlight_run` entry
 * points are both kept and route here.
 *
 * M1 Project
 *
 */

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "m1_builtin_apps.h"
#include "m1_app_runtime.h"
#include "m1_layout.h"
#include "m1_rgb_backlight.h"
#include "m1_lp5814.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_settings.h"

/*************************** D E F I N E S ************************************/

#define BL_TICK_MS              120U
#define BL_VISIBLE_ITEMS        2U

/* Debounce window for SD-card persistence — wait this long after the
 * last user input before flushing settings. */
#define BL_SETTINGS_FLUSH_MS  5000U

/* Brightness presets for the combined app. RGB mode advertises the same
 * 6-step ladder as the legacy app; stock mode collapses to 5 steps. */
#define BL_RGB_LEVELS    6U
#define BL_STOCK_LEVELS  5U

//************************** S T R U C T U R E S *******************************/

typedef enum
{
    BL_MENU_ONOFF = 0,
    BL_MENU_COLOR,        /* RGB only */
    BL_MENU_EFFECT,       /* RGB only */
    BL_MENU_BRIGHT,
    BL_MENU_ITEMS_RGB     = 4U,
    BL_MENU_ITEMS_STOCK   = 2U
} bl_menu_item_t;

typedef struct
{
    bool      rgb_available;     /* sticky once detected at on_init */
    uint8_t   sel;               /* selected menu row */
    uint8_t   bright_idx;        /* current index into the level table */
    uint32_t  last_change_ms;    /* tick of last user input */
    bool      dirty;             /* something changed since last flush */
} app_backlight_state_t;

/***************************** V A R I A B L E S ******************************/

static app_backlight_state_t s_backlight;

static const char *s_rgb_brightness_labels[BL_RGB_LEVELS] = {
    "Off", "10%", "25%", "50%", "75%", "100%"
};
static const uint8_t s_rgb_brightness_values[BL_RGB_LEVELS] = {
    0, 26, 64, 128, 192, 255
};

static const char *s_stock_brightness_labels[BL_STOCK_LEVELS] = {
    "Off", "Low", "Med", "High", "Max"
};
static const uint8_t s_stock_brightness_values[BL_STOCK_LEVELS] = {
    0, 64, 128, 192, 255
};

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static uint8_t      bl_menu_items(const app_backlight_state_t *st);
static const char  *bl_label(const app_backlight_state_t *st, uint8_t row);
static const char  *bl_value(const app_backlight_state_t *st, uint8_t row);
static uint8_t      bl_brightness_index(uint8_t brightness,
                                        const uint8_t *table, uint8_t n);
static void         bl_mark_dirty(app_backlight_state_t *st);
static void         bl_flush_if_due(app_backlight_state_t *st, uint32_t now_ms);

static void  backlight_on_init(m1_app_ctx_t *ctx);
static void  backlight_on_render(m1_app_ctx_t *ctx);
static bool  backlight_on_button(m1_app_ctx_t *ctx, m1_button_t btn);
static void  backlight_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms);
static void  backlight_on_exit(m1_app_ctx_t *ctx);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

static uint8_t bl_menu_items(const app_backlight_state_t *st)
{
    return st->rgb_available ? BL_MENU_ITEMS_RGB : BL_MENU_ITEMS_STOCK;
}


static uint8_t bl_brightness_index(uint8_t brightness,
                                   const uint8_t *table, uint8_t n)
{
    uint8_t  best     = 0U;
    uint16_t best_diff = 255U;

    for (uint8_t i = 0U; i < n; i++)
    {
        uint16_t diff = (brightness > table[i])
            ? (uint16_t)(brightness - table[i])
            : (uint16_t)(table[i] - brightness);
        if (diff < best_diff)
        {
            best      = i;
            best_diff = diff;
        }
    }
    return best;
}


static const char *bl_label(const app_backlight_state_t *st, uint8_t row)
{
    if (st->rgb_available)
    {
        switch ((bl_menu_item_t)row)
        {
            case BL_MENU_ONOFF:  return "RGB Mod";
            case BL_MENU_COLOR:  return "LCD Color";
            case BL_MENU_EFFECT: return "Animation";
            case BL_MENU_BRIGHT: return "Brightness";
            default:             return "";
        }
    }

    /* Stock mode collapses to 2 rows: ONOFF then BRIGHT. */
    if (row == 0U) return "Backlight";
    if (row == 1U) return "Brightness";
    return "";
}


static const char *bl_value(const app_backlight_state_t *st, uint8_t row)
{
    static char val_buf[12];

    if (st->rgb_available)
    {
        switch ((bl_menu_item_t)row)
        {
            case BL_MENU_ONOFF:  return rgb_bl_is_on() ? "On" : "Off";
            case BL_MENU_COLOR:  return rgb_bl_mode_name(rgb_bl_get_mode());
            case BL_MENU_EFFECT: return rgb_bl_effect_name(rgb_bl_get_effect());
            case BL_MENU_BRIGHT:
            {
                uint8_t b = rgb_bl_get_brightness();
                for (uint8_t i = 0U; i < BL_RGB_LEVELS; i++)
                {
                    if (b <= s_rgb_brightness_values[i])
                    {
                        snprintf(val_buf, sizeof(val_buf), "%s",
                                 s_rgb_brightness_labels[i]);
                        return val_buf;
                    }
                }
                return "100%";
            }
            default: return "";
        }
    }

    if (row == 0U)
    {
        return (m1_brightness_level > 0U) ? "On" : "Off";
    }
    if (row == 1U)
    {
        uint8_t idx = (m1_brightness_level < BL_STOCK_LEVELS)
            ? m1_brightness_level
            : (uint8_t)(BL_STOCK_LEVELS - 1U);
        return s_stock_brightness_labels[idx];
    }
    return "";
}


static void bl_mark_dirty(app_backlight_state_t *st)
{
    st->dirty          = true;
    st->last_change_ms = HAL_GetTick();
}


static void bl_flush_if_due(app_backlight_state_t *st, uint32_t now_ms)
{
    if (st->dirty && (now_ms - st->last_change_ms) >= BL_SETTINGS_FLUSH_MS)
    {
        settings_save_to_sd();
        st->dirty = false;
    }
}


static void backlight_on_init(m1_app_ctx_t *ctx)
{
    app_backlight_state_t *st = (app_backlight_state_t *)ctx->user_state;

    /* `rgb_bl_init()` is safe to call repeatedly; it only sets up PD3 and
     * marks the chain available. We let auto-detect drive the menu shape:
     * if the system already knows RGB is fitted, use the RGB layout. */
    rgb_bl_init();
    st->rgb_available = (rgb_bl_is_available() != 0U);

    if (st->rgb_available)
    {
        st->bright_idx = bl_brightness_index(rgb_bl_get_brightness(),
                                             s_rgb_brightness_values,
                                             BL_RGB_LEVELS);
    }
    else
    {
        uint8_t lvl = (m1_brightness_level < BL_STOCK_LEVELS)
            ? m1_brightness_level
            : (uint8_t)(BL_STOCK_LEVELS - 1U);
        st->bright_idx = lvl;
    }
}


static void backlight_on_render(m1_app_ctx_t *ctx)
{
    const app_backlight_state_t *st =
        (const app_backlight_state_t *)ctx->user_state;
    char    badge[8];
    uint8_t menu_items   = bl_menu_items(st);
    uint8_t visible_start = 0U;

    if (st->sel >= BL_VISIBLE_ITEMS && menu_items > BL_VISIBLE_ITEMS)
    {
        visible_start = (uint8_t)(st->sel - BL_VISIBLE_ITEMS + 1U);
    }

    snprintf(badge, sizeof(badge), "%u/%u",
             (unsigned)(st->sel + 1U), (unsigned)menu_items);

    m1_u8g2_firstpage();
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    m1_draw_header_bar(&m1_u8g2, "Backlight", badge);
    m1_draw_content_frame(&m1_u8g2,
                          M1_LAYOUT_CONTENT_LEFT_X, M1_LAYOUT_CONTENT_TOP_Y,
                          M1_LAYOUT_CONTENT_W,      M1_LAYOUT_CONTENT_H - 2);
    u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);

    for (uint8_t vi = 0U;
         vi < BL_VISIBLE_ITEMS && (visible_start + vi) < menu_items;
         vi++)
    {
        uint8_t row = visible_start + vi;
        uint8_t y   = (uint8_t)(30U + (vi * 12U));

        if (row == st->sel)
        {
            u8g2_DrawBox(&m1_u8g2, 6, y - 7, 114, 11);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
            m1_draw_text(&m1_u8g2, 10, y, 64, bl_label(st, row), TEXT_ALIGN_LEFT);
            m1_draw_text(&m1_u8g2, 78, y, 38, bl_value(st, row), TEXT_ALIGN_RIGHT);
            u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        }
        else
        {
            u8g2_DrawFrame(&m1_u8g2, 6, y - 7, 114, 11);
            m1_draw_text(&m1_u8g2, 10, y, 64, bl_label(st, row), TEXT_ALIGN_LEFT);
            m1_draw_text(&m1_u8g2, 78, y, 38, bl_value(st, row), TEXT_ALIGN_RIGHT);
        }
    }

    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Change", arrowright_8x8);
    m1_u8g2_nextpage();
}


/* RGB-mode L/R changes a single setting; OK does the same as RIGHT. */
static void rgb_change(app_backlight_state_t *st, int8_t direction)
{
    switch ((bl_menu_item_t)st->sel)
    {
        case BL_MENU_ONOFF:
            if (rgb_bl_is_on()) rgb_bl_off();
            else                rgb_bl_on();
            break;

        case BL_MENU_COLOR:
        {
            rgb_bl_mode_t m = rgb_bl_get_mode();
            if (direction < 0)
            {
                rgb_bl_set_mode((m == 0U)
                    ? (rgb_bl_mode_t)(RGB_MODE_COUNT - 1U)
                    : (rgb_bl_mode_t)(m - 1U));
            }
            else
            {
                rgb_bl_set_mode((rgb_bl_mode_t)((m + 1U) % RGB_MODE_COUNT));
            }
            break;
        }

        case BL_MENU_EFFECT:
        {
            rgb_bl_effect_t e = rgb_bl_get_effect();
            if (direction < 0)
            {
                rgb_bl_set_effect((e == 0U)
                    ? (rgb_bl_effect_t)(RGB_EFFECT_COUNT - 1U)
                    : (rgb_bl_effect_t)(e - 1U));
            }
            else
            {
                rgb_bl_set_effect((rgb_bl_effect_t)((e + 1U) % RGB_EFFECT_COUNT));
            }
            break;
        }

        case BL_MENU_BRIGHT:
            if (direction < 0)
            {
                st->bright_idx = (st->bright_idx == 0U)
                    ? (uint8_t)(BL_RGB_LEVELS - 1U)
                    : (uint8_t)(st->bright_idx - 1U);
            }
            else
            {
                st->bright_idx = (uint8_t)((st->bright_idx + 1U) % BL_RGB_LEVELS);
            }
            rgb_bl_set_brightness(s_rgb_brightness_values[st->bright_idx]);
            break;

        default:
            return;
    }
    bl_mark_dirty(st);
}


/* Stock mode: row 0 is on/off (any direction toggles), row 1 is the
 * brightness ladder. */
static void stock_change(app_backlight_state_t *st, int8_t direction)
{
    if (st->sel == 0U)
    {
        if (m1_brightness_level > 0U)
        {
            m1_brightness_level = 0U;
            m1_backlight_on(0);
            st->bright_idx = 0U;
        }
        else
        {
            const uint8_t default_idx = 3U;   /* "High" */
            m1_brightness_level = default_idx;
            m1_backlight_on(s_stock_brightness_values[default_idx]);
            st->bright_idx = default_idx;
        }
    }
    else if (st->sel == 1U)
    {
        if (direction < 0)
        {
            st->bright_idx = (st->bright_idx == 0U)
                ? (uint8_t)(BL_STOCK_LEVELS - 1U)
                : (uint8_t)(st->bright_idx - 1U);
        }
        else
        {
            st->bright_idx = (uint8_t)((st->bright_idx + 1U) % BL_STOCK_LEVELS);
        }
        m1_brightness_level = st->bright_idx;
        m1_backlight_on(s_stock_brightness_values[st->bright_idx]);
    }
    bl_mark_dirty(st);
}


static bool backlight_on_button(m1_app_ctx_t *ctx, m1_button_t btn)
{
    app_backlight_state_t *st = (app_backlight_state_t *)ctx->user_state;
    uint8_t menu_items = bl_menu_items(st);

    switch (btn)
    {
        case M1_BTN_UP:
            st->sel = (st->sel == 0U)
                ? (uint8_t)(menu_items - 1U)
                : (uint8_t)(st->sel - 1U);
            return true;

        case M1_BTN_DOWN:
            st->sel = (uint8_t)((st->sel + 1U) % menu_items);
            return true;

        case M1_BTN_LEFT:
            if (st->rgb_available) rgb_change(st, -1);
            else                   stock_change(st, -1);
            return true;

        case M1_BTN_RIGHT:
        case M1_BTN_OK:
            if (st->rgb_available) rgb_change(st, +1);
            else                   stock_change(st, +1);
            return true;

        default:
            return false;
    }
}


static void backlight_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms)
{
    app_backlight_state_t *st = (app_backlight_state_t *)ctx->user_state;

    if (st->rgb_available)
    {
        rgb_bl_update();    /* keeps breathe / cycle effects animated */
    }
    bl_flush_if_due(st, now_ms);
}


static void backlight_on_exit(m1_app_ctx_t *ctx)
{
    app_backlight_state_t *st = (app_backlight_state_t *)ctx->user_state;
    /* Always flush on exit even if the debounce timer has not elapsed. */
    if (st->dirty)
    {
        settings_save_to_sd();
        st->dirty = false;
    }
}


static const m1_app_def_t s_backlight_def = {
    .title           = "Backlight",
    .on_init         = backlight_on_init,
    .on_render       = backlight_on_render,
    .on_button       = backlight_on_button,
    .on_tick         = backlight_on_tick,
    .on_exit         = backlight_on_exit,
    .tick_period_ms  = BL_TICK_MS,
    .user_state      = &s_backlight,
    .user_state_size = sizeof(s_backlight),
};


void app_rgb_backlight_run(void)
{
    m1_app_run(&s_backlight_def);
}
