/* See COPYING.txt for license details. */

/*
*
* app_dvd_logo.c
*
* Bouncing DVD logo app. Built on the m1_app_runtime so the file only
* contains the actual physics + rendering — the event loop, frame timing
* and BACK handling are all done by the runtime.
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
#include "m1_compile_cfg.h"
#include "m1_app_runtime.h"
#include "m1_layout.h"
#include "m1_buzzer.h"
#include "m1_display.h"
#include "m1_lcd.h"

/*************************** D E F I N E S ************************************/

#define DVD_LOGO_W              40
#define DVD_LOGO_H              32
#define DVD_AREA_X              0
#define DVD_AREA_Y              M1_LAYOUT_HEADER_HLINE_Y    /* below header */
#define DVD_AREA_W              M1_LAYOUT_SCREEN_W
#define DVD_AREA_H              (M1_LAYOUT_SCREEN_H - DVD_AREA_Y)
#define DVD_FRAME_MS            35U
#define DVD_SPEED_MIN           1
#define DVD_SPEED_MAX           3
#define DVD_CORNER_BUZZ_GAP_MS  500U

//************************** S T R U C T U R E S *******************************/

typedef struct
{
    int16_t  x;
    int16_t  y;
    int8_t   dx;
    int8_t   dy;
    uint8_t  speed;
    uint16_t bounces;
    uint16_t corners;
    uint32_t last_corner_ms;
    bool     paused;
    bool     show_trail;
} app_dvd_logo_state_t;

/***************************** V A R I A B L E S ******************************/

static app_dvd_logo_state_t s_dvd_logo;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static void dvd_logo_on_init(m1_app_ctx_t *ctx);
static void dvd_logo_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms);
static void dvd_logo_on_render(m1_app_ctx_t *ctx);
static bool dvd_logo_on_button(m1_app_ctx_t *ctx, m1_button_t btn);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

static void dvd_logo_on_init(m1_app_ctx_t *ctx)
{
    app_dvd_logo_state_t *st = (app_dvd_logo_state_t *)ctx->user_state;

    st->x          = (DVD_AREA_W - DVD_LOGO_W) / 2;
    st->y          = DVD_AREA_Y + ((DVD_AREA_H - DVD_LOGO_H) / 2);
    st->dx         = 1;
    st->dy         = 1;
    st->speed      = 2;
}


static void dvd_logo_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms)
{
    app_dvd_logo_state_t *st = (app_dvd_logo_state_t *)ctx->user_state;
    bool    hit_x = false;
    bool    hit_y = false;
    int16_t next_x;
    int16_t next_y;

    if (st->paused)
    {
        return;
    }

    next_x = st->x + (st->dx * (int8_t)st->speed);
    next_y = st->y + (st->dy * (int8_t)st->speed);

    if (next_x <= DVD_AREA_X)
    {
        next_x = DVD_AREA_X;
        st->dx = 1;
        hit_x  = true;
    }
    else if (next_x >= (DVD_AREA_X + DVD_AREA_W - DVD_LOGO_W))
    {
        next_x = DVD_AREA_X + DVD_AREA_W - DVD_LOGO_W;
        st->dx = -1;
        hit_x  = true;
    }

    if (next_y <= DVD_AREA_Y)
    {
        next_y = DVD_AREA_Y;
        st->dy = 1;
        hit_y  = true;
    }
    else if (next_y >= (DVD_AREA_Y + DVD_AREA_H - DVD_LOGO_H))
    {
        next_y = DVD_AREA_Y + DVD_AREA_H - DVD_LOGO_H;
        st->dy = -1;
        hit_y  = true;
    }

    st->x = next_x;
    st->y = next_y;

    if (hit_x || hit_y)
    {
        st->bounces++;
        if (hit_x && hit_y)
        {
            st->corners++;
            /* Debounce the buzzer — back-to-back corner hits at high speed
             * would otherwise sound like a continuous tone. */
            if ((uint32_t)(now_ms - st->last_corner_ms) >= DVD_CORNER_BUZZ_GAP_MS)
            {
                m1_buzzer_notification();
                st->last_corner_ms = now_ms;
            }
        }
    }
}


static void dvd_logo_on_render(m1_app_ctx_t *ctx)
{
    const app_dvd_logo_state_t *st = (const app_dvd_logo_state_t *)ctx->user_state;
    char status_buf[24];

    m1_u8g2_firstpage();
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);

    u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
    snprintf(status_buf, sizeof(status_buf), "DVD S%u B%u C%u",
             st->speed, st->bounces, st->corners);
    u8g2_DrawStr(&m1_u8g2, 0, M1_LAYOUT_HEADER_BASELINE_Y - 1, status_buf);

    if (st->show_trail)
    {
        u8g2_DrawFrame(&m1_u8g2, st->x + 3, st->y + 3, DVD_LOGO_W, DVD_LOGO_H);
    }

    u8g2_DrawBox(&m1_u8g2, st->x, st->y, DVD_LOGO_W, DVD_LOGO_H);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawXBMP(&m1_u8g2, st->x, st->y, DVD_LOGO_W, DVD_LOGO_H, m1_logo_40x32);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);

    if (st->paused)
    {
        u8g2_DrawBox(&m1_u8g2, 88, 0, 40, 9);
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
        u8g2_DrawStr(&m1_u8g2, 93, 8, "PAUSED");
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    }

    u8g2_DrawStr(&m1_u8g2, 0, M1_LAYOUT_BOTTOM_BAR_Y, "OK speed U trail");
    u8g2_DrawStr(&m1_u8g2, 83, M1_LAYOUT_BOTTOM_BAR_Y, "D pause");

    m1_u8g2_nextpage();
}


static bool dvd_logo_on_button(m1_app_ctx_t *ctx, m1_button_t btn)
{
    app_dvd_logo_state_t *st = (app_dvd_logo_state_t *)ctx->user_state;

    switch (btn)
    {
        case M1_BTN_OK:
            st->speed = (st->speed < DVD_SPEED_MAX) ? (uint8_t)(st->speed + 1U)
                                                   : (uint8_t)DVD_SPEED_MIN;
            return true;

        case M1_BTN_UP:
            st->show_trail = !st->show_trail;
            return true;

        case M1_BTN_DOWN:
            st->paused = !st->paused;
            return true;

        default:
            return false;
    }
}


void app_dvd_logo_run(void)
{
    static const m1_app_def_t def = {
        .title           = "DVD Logo",
        .on_init         = dvd_logo_on_init,
        .on_render       = dvd_logo_on_render,
        .on_button       = dvd_logo_on_button,
        .on_tick         = dvd_logo_on_tick,
        .on_exit         = NULL,
        .tick_period_ms  = DVD_FRAME_MS,
        .user_state      = &s_dvd_logo,
        .user_state_size = sizeof(s_dvd_logo),
    };

    m1_app_run(&def);
}
