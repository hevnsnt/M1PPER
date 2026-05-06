/* See COPYING.txt for license details. */

/*
*
* app_clock.c
*
* Unified clock utility — Local time, World zones, Stopwatch and Timer
* (the old "Dab Timer" merged in as the Timer page). Built on
* m1_app_runtime so the file only contains state, rendering and per-page
* button handling.
*
* World zones cover the western hemisphere too: UTC-10, UTC-8, UTC-6,
* UTC-5, UTC-3 alongside the original UTC, UTC+1, UTC+5, UTC+9.
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
#include "m1_buzzer.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"

/*************************** D E F I N E S ************************************/

#define CLOCK_TICK_MS                100U

/* Timer (formerly Dab Timer) */
#define CLOCK_TIMER_DEFAULT_SEC      45U
#define CLOCK_TIMER_MIN_SEC          10U
#define CLOCK_TIMER_MAX_SEC          180U
#define CLOCK_TIMER_STEP_SMALL_SEC   5U
#define CLOCK_TIMER_STEP_LARGE_SEC   15U
#define CLOCK_TIMER_ALERT_GAP_MS     300U
#define CLOCK_TIMER_ALERT_BEEPS      4U

//************************** S T R U C T U R E S *******************************/

typedef enum
{
    CLOCK_PAGE_LOCAL = 0,
    CLOCK_PAGE_ZONES,
    CLOCK_PAGE_STOPWATCH,
    CLOCK_PAGE_TIMER,
    CLOCK_PAGE_COUNT
} clock_page_t;

typedef struct
{
    const char *label;
    int8_t      offset_hours;
} world_zone_t;

typedef enum
{
    TIMER_IDLE = 0,
    TIMER_RUNNING,
    TIMER_PAUSED,
    TIMER_ALERT
} timer_mode_t;

typedef struct
{
    /* Stopwatch */
    bool     sw_running;
    uint32_t sw_started_ms;     /* HAL_GetTick() when started */
    uint32_t sw_accum_ms;       /* accumulated paused-time */

    /* Timer (formerly Dab Timer) */
    uint16_t     tm_duration_sec;
    uint32_t     tm_remaining_ms;
    uint32_t     tm_deadline_ms;
    uint32_t     tm_last_alert_ms;
    uint8_t      tm_alert_count;
    timer_mode_t tm_mode;

    /* Page state */
    clock_page_t page;
    uint8_t      zone_idx;
} app_clock_state_t;

/***************************** V A R I A B L E S ******************************/

static app_clock_state_t s_clock;

static const char *clock_weekdays[] = {
    "---",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat",
    "Sun"
};

static const world_zone_t clock_zones[] = {
    { "UTC-10 HST", -10 },   /* Hawaii */
    { "UTC-8  PST",  -8 },   /* US Pacific */
    { "UTC-6  CST",  -6 },   /* US Central */
    { "UTC-5  EST",  -5 },   /* US Eastern */
    { "UTC-3  ART",  -3 },   /* Argentina / Brasilia */
    { "UTC",          0 },
    { "UTC+1  CET",   1 },
    { "UTC+5  PKT",   5 },
    { "UTC+9  JST",   9 }
};
#define CLOCK_ZONE_COUNT  ((uint8_t)(sizeof(clock_zones)/sizeof(clock_zones[0])))

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static bool    clock_is_leap_year(uint16_t year);
static uint8_t clock_days_in_month(uint16_t year, uint8_t month);
static void    clock_adjust_days(m1_time_t *dt, int8_t delta_days);
static void    clock_apply_offset(const m1_time_t *src, int8_t offset_hours,
                                  m1_time_t *dst);

static void    clock_render_local(void);
static void    clock_render_zones(const app_clock_state_t *st);
static void    clock_render_stopwatch(const app_clock_state_t *st);
static void    clock_render_timer(const app_clock_state_t *st);

static void    clock_timer_reset_countdown(app_clock_state_t *st);
static void    clock_timer_adjust(app_clock_state_t *st, int16_t delta_sec);
static void    clock_timer_advance(app_clock_state_t *st, uint32_t now_ms);

static void    clock_on_init(m1_app_ctx_t *ctx);
static void    clock_on_render(m1_app_ctx_t *ctx);
static void    clock_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms);
static bool    clock_on_button(m1_app_ctx_t *ctx, m1_button_t btn);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

/*-------------------------------- date math ---------------------------------*/

static bool clock_is_leap_year(uint16_t year)
{
    return ((year % 4U) == 0U && ((year % 100U) != 0U || (year % 400U) == 0U));
}


static uint8_t clock_days_in_month(uint16_t year, uint8_t month)
{
    static const uint8_t month_days[] = {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U
    };

    if (month == 2U && clock_is_leap_year(year))
    {
        return 29U;
    }
    if (month >= 1U && month <= 12U)
    {
        return month_days[month - 1U];
    }
    return 30U;
}


static void clock_adjust_days(m1_time_t *dt, int8_t delta_days)
{
    if (dt == NULL || delta_days == 0)
    {
        return;
    }

    while (delta_days > 0)
    {
        uint8_t dim = clock_days_in_month(dt->year, dt->month);
        if (dt->day < dim)
        {
            dt->day++;
        }
        else
        {
            dt->day = 1U;
            if (dt->month < 12U)
            {
                dt->month++;
            }
            else
            {
                dt->month = 1U;
                dt->year++;
            }
        }

        if (dt->weekday >= 1U && dt->weekday <= 7U)
        {
            dt->weekday = (dt->weekday == 7U) ? 1U : (uint8_t)(dt->weekday + 1U);
        }
        delta_days--;
    }

    while (delta_days < 0)
    {
        if (dt->day > 1U)
        {
            dt->day--;
        }
        else
        {
            if (dt->month > 1U)
            {
                dt->month--;
            }
            else
            {
                dt->month = 12U;
                if (dt->year > 2000U)
                {
                    dt->year--;
                }
            }
            dt->day = clock_days_in_month(dt->year, dt->month);
        }

        if (dt->weekday >= 1U && dt->weekday <= 7U)
        {
            dt->weekday = (dt->weekday == 1U) ? 7U : (uint8_t)(dt->weekday - 1U);
        }
        delta_days++;
    }
}


static void clock_apply_offset(const m1_time_t *src, int8_t offset_hours,
                               m1_time_t *dst)
{
    int16_t hour;

    if (src == NULL || dst == NULL)
    {
        return;
    }

    *dst = *src;
    hour = (int16_t)src->hour + (int16_t)offset_hours;

    while (hour < 0)
    {
        hour += 24;
        clock_adjust_days(dst, -1);
    }

    while (hour >= 24)
    {
        hour -= 24;
        clock_adjust_days(dst, 1);
    }

    dst->hour = (uint8_t)hour;
}


/*------------------------------- page renders -------------------------------*/

static void clock_draw_page_chrome(const char *title, uint8_t page_idx)
{
    char badge[8];
    snprintf(badge, sizeof(badge), "%u/%u",
             (unsigned)(page_idx + 1U), (unsigned)CLOCK_PAGE_COUNT);
    m1_draw_header_bar(&m1_u8g2, title, badge);
    m1_draw_content_frame(&m1_u8g2,
                          M1_LAYOUT_CONTENT_LEFT_X, M1_LAYOUT_CONTENT_TOP_Y,
                          M1_LAYOUT_CONTENT_W,      M1_LAYOUT_CONTENT_H);
}


static void clock_render_local(void)
{
    m1_time_t   now;
    char        date_line[24];
    char        time_line[12];
    const char *weekday;

    m1_get_localtime(&now);
    weekday = (now.weekday <= 7U) ? clock_weekdays[now.weekday] : clock_weekdays[0];

    snprintf(time_line, sizeof(time_line), "%02u:%02u:%02u",
             now.hour, now.minute, now.second);
    snprintf(date_line, sizeof(date_line), "%s %02u/%02u/%04u",
             weekday, now.month, now.day, now.year);

    clock_draw_page_chrome("Clock", (uint8_t)CLOCK_PAGE_LOCAL);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 22, 114, date_line, TEXT_ALIGN_LEFT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_LARGE_FONT_2B);
    m1_draw_text(&m1_u8g2, 10, 40, 108, time_line, TEXT_ALIGN_CENTER);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 50, 114, "Local time", TEXT_ALIGN_LEFT);
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Next", arrowright_8x8);
}


static void clock_render_zones(const app_clock_state_t *st)
{
    m1_time_t            now, zone_time;
    const world_zone_t  *zone = &clock_zones[st->zone_idx];
    char                 time_line[12];
    char                 date_line[24];
    char                 idx_line[16];

    m1_get_localtime(&now);
    clock_apply_offset(&now, zone->offset_hours, &zone_time);

    snprintf(time_line, sizeof(time_line), "%02u:%02u:%02u",
             zone_time.hour, zone_time.minute, zone_time.second);
    snprintf(date_line, sizeof(date_line), "%02u/%02u/%04u",
             zone_time.month, zone_time.day, zone_time.year);
    snprintf(idx_line, sizeof(idx_line), "%u/%u  L/R", st->zone_idx + 1U, CLOCK_ZONE_COUNT);

    clock_draw_page_chrome(zone->label, (uint8_t)CLOCK_PAGE_ZONES);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 22, 114, date_line, TEXT_ALIGN_LEFT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_LARGE_FONT_2B);
    m1_draw_text(&m1_u8g2, 10, 40, 108, time_line, TEXT_ALIGN_CENTER);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 50, 114, idx_line, TEXT_ALIGN_LEFT);
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Next", arrowright_8x8);
}


static uint32_t clock_stopwatch_elapsed_ms(const app_clock_state_t *st)
{
    if (st->sw_running)
    {
        return st->sw_accum_ms + (HAL_GetTick() - st->sw_started_ms);
    }
    return st->sw_accum_ms;
}


static void clock_render_stopwatch(const app_clock_state_t *st)
{
    uint32_t ms       = clock_stopwatch_elapsed_ms(st);
    uint32_t total_s  = ms / 1000U;
    uint32_t hundreds = (ms / 10U) % 100U;
    uint32_t minutes  = (total_s / 60U) % 60U;
    uint32_t hours    = total_s / 3600U;
    uint32_t seconds  = total_s % 60U;
    char     time_buf[16];
    char     status_buf[20];

    snprintf(time_buf, sizeof(time_buf), "%02lu:%02lu:%02lu",
             (unsigned long)hours, (unsigned long)minutes,
             (unsigned long)seconds);
    snprintf(status_buf, sizeof(status_buf), "%s  .%02lu",
             st->sw_running ? "Running" : "Stopped",
             (unsigned long)hundreds);

    clock_draw_page_chrome("Stopwatch", (uint8_t)CLOCK_PAGE_STOPWATCH);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 22, 114, status_buf, TEXT_ALIGN_LEFT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_LARGE_FONT_2B);
    m1_draw_text(&m1_u8g2, 10, 40, 108, time_buf, TEXT_ALIGN_CENTER);
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    m1_draw_text(&m1_u8g2, 8, 50, 114,
                 st->sw_running ? "OK Pause   U Reset" : "OK Start   U Reset",
                 TEXT_ALIGN_LEFT);
    m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Prev", "Next", arrowright_8x8);
}


static void clock_render_timer(const app_clock_state_t *st)
{
    char        time_buf[8];
    char        status_buf[20];
    uint32_t    seconds_left;
    uint8_t     minutes;
    uint8_t     seconds;
    uint32_t    total_ms;
    uint16_t    fill_w = 0U;
    bool        flash  = false;
    uint8_t     text_color = M1_DISP_DRAW_COLOR_TXT;

    seconds_left = (st->tm_remaining_ms + 999U) / 1000U;
    minutes      = (uint8_t)(seconds_left / 60U);
    seconds      = (uint8_t)(seconds_left % 60U);
    snprintf(time_buf, sizeof(time_buf), "%02u:%02u", minutes, seconds);

    switch (st->tm_mode)
    {
        case TIMER_RUNNING:
            snprintf(status_buf, sizeof(status_buf), "Running %us",
                     st->tm_duration_sec);
            break;
        case TIMER_PAUSED:
            snprintf(status_buf, sizeof(status_buf), "Paused %us",
                     st->tm_duration_sec);
            break;
        case TIMER_ALERT:
            snprintf(status_buf, sizeof(status_buf), "READY!");
            flash = ((HAL_GetTick() / 250U) & 1U) != 0U;
            break;
        case TIMER_IDLE:
        default:
            snprintf(status_buf, sizeof(status_buf), "Set %us",
                     st->tm_duration_sec);
            break;
    }

    /* Use uint32_t multiplication to avoid the uint16-overflow that bit
     * the legacy DAB timer for durations > 65 s. */
    total_ms = (uint32_t)st->tm_duration_sec * 1000U;
    if (total_ms > 0U && st->tm_remaining_ms <= total_ms)
    {
        fill_w = (uint16_t)((96U * (total_ms - st->tm_remaining_ms)) / total_ms);
    }

    m1_u8g2_firstpage();   /* note: caller already wrapped firstpage but we
                              redo so the flash-inversion looks right */

    if (flash)
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_DrawBox(&m1_u8g2, 0, 0, M1_LAYOUT_SCREEN_W, M1_LAYOUT_SCREEN_H);
        text_color = M1_DISP_DRAW_COLOR_BG;
    }

    u8g2_SetDrawColor(&m1_u8g2, text_color);
    clock_draw_page_chrome("Timer", (uint8_t)CLOCK_PAGE_TIMER);
    u8g2_SetDrawColor(&m1_u8g2, text_color);

    u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2,
                 (M1_LAYOUT_SCREEN_W - u8g2_GetStrWidth(&m1_u8g2, status_buf)) / 2,
                 22, status_buf);

    u8g2_SetFont(&m1_u8g2, M1_DISP_LARGE_FONT_2B);
    u8g2_DrawStr(&m1_u8g2,
                 (M1_LAYOUT_SCREEN_W - u8g2_GetStrWidth(&m1_u8g2, time_buf)) / 2,
                 44, time_buf);

    u8g2_DrawFrame(&m1_u8g2, 16, 48, 96, 8);
    if (fill_w > 0U)
    {
        u8g2_DrawBox(&m1_u8g2, 18, 50, (fill_w > 92U) ? 92U : fill_w, 4);
    }

    u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
    if (st->tm_mode == TIMER_RUNNING)
    {
        u8g2_DrawStr(&m1_u8g2, 0, M1_LAYOUT_BOTTOM_BAR_Y, "OK Pause");
        u8g2_DrawStr(&m1_u8g2, 70, M1_LAYOUT_BOTTOM_BAR_Y, "BACK Exit");
    }
    else if (st->tm_mode == TIMER_ALERT)
    {
        u8g2_DrawStr(&m1_u8g2, 0, M1_LAYOUT_BOTTOM_BAR_Y, "OK Reset");
        u8g2_DrawStr(&m1_u8g2, 68, M1_LAYOUT_BOTTOM_BAR_Y, "BACK Exit");
    }
    else
    {
        u8g2_DrawStr(&m1_u8g2, 0, 55, "L/R -/+5");
        u8g2_DrawStr(&m1_u8g2, 72, 55, "U/D 15");
        u8g2_DrawStr(&m1_u8g2, 0, M1_LAYOUT_BOTTOM_BAR_Y, "OK Start");
        u8g2_DrawStr(&m1_u8g2, 68, M1_LAYOUT_BOTTOM_BAR_Y, "BACK Exit");
    }

    m1_u8g2_nextpage();
}


/*-------------------------------- timer logic -------------------------------*/

static void clock_timer_reset_countdown(app_clock_state_t *st)
{
    st->tm_remaining_ms  = (uint32_t)st->tm_duration_sec * 1000U;
    st->tm_alert_count   = 0U;
    st->tm_last_alert_ms = 0U;
}


static void clock_timer_adjust(app_clock_state_t *st, int16_t delta_sec)
{
    int32_t v = (int32_t)st->tm_duration_sec + delta_sec;
    if (v < (int32_t)CLOCK_TIMER_MIN_SEC)  v = CLOCK_TIMER_MIN_SEC;
    if (v > (int32_t)CLOCK_TIMER_MAX_SEC)  v = CLOCK_TIMER_MAX_SEC;
    st->tm_duration_sec = (uint16_t)v;
    st->tm_mode         = TIMER_IDLE;
    clock_timer_reset_countdown(st);
}


static void clock_timer_advance(app_clock_state_t *st, uint32_t now_ms)
{
    if (st->tm_mode == TIMER_RUNNING)
    {
        if (now_ms >= st->tm_deadline_ms)
        {
            st->tm_remaining_ms  = 0U;
            st->tm_mode          = TIMER_ALERT;
            st->tm_alert_count   = 1U;
            st->tm_last_alert_ms = now_ms;
            m1_buzzer_set(BUZZER_FREQ_02_KHZ, 120);
        }
        else
        {
            st->tm_remaining_ms = st->tm_deadline_ms - now_ms;
        }
    }
    else if (st->tm_mode == TIMER_ALERT &&
             st->tm_alert_count < CLOCK_TIMER_ALERT_BEEPS)
    {
        if (st->tm_last_alert_ms == 0U ||
            (now_ms - st->tm_last_alert_ms) >= CLOCK_TIMER_ALERT_GAP_MS)
        {
            m1_buzzer_set((st->tm_alert_count & 1U) ? BUZZER_FREQ_04_KHZ
                                                    : BUZZER_FREQ_02_KHZ, 90);
            st->tm_last_alert_ms = now_ms;
            st->tm_alert_count++;
        }
    }
}


/*--------------------------- runtime callbacks ------------------------------*/

static void clock_on_init(m1_app_ctx_t *ctx)
{
    app_clock_state_t *st = (app_clock_state_t *)ctx->user_state;

    st->tm_duration_sec = CLOCK_TIMER_DEFAULT_SEC;
    st->tm_mode         = TIMER_IDLE;
    clock_timer_reset_countdown(st);
}


static void clock_on_render(m1_app_ctx_t *ctx)
{
    const app_clock_state_t *st = (const app_clock_state_t *)ctx->user_state;

    /* clock_render_timer paints its own page-loop because of the
     * full-screen flash inversion. The other pages share one. */
    if (st->page == CLOCK_PAGE_TIMER)
    {
        clock_render_timer(st);
        return;
    }

    m1_u8g2_firstpage();
    switch (st->page)
    {
        case CLOCK_PAGE_LOCAL:     clock_render_local();       break;
        case CLOCK_PAGE_ZONES:     clock_render_zones(st);     break;
        case CLOCK_PAGE_STOPWATCH: clock_render_stopwatch(st); break;
        default: break;
    }
    m1_u8g2_nextpage();
}


static void clock_on_tick(m1_app_ctx_t *ctx, uint32_t now_ms)
{
    app_clock_state_t *st = (app_clock_state_t *)ctx->user_state;

    clock_timer_advance(st, now_ms);
    /* All four pages need a periodic redraw so seconds / progress bars
     * update. */
    ctx->redraw_pending = true;
}


static bool clock_on_button(m1_app_ctx_t *ctx, m1_button_t btn)
{
    app_clock_state_t *st = (app_clock_state_t *)ctx->user_state;

    /* Timer page intercepts L/R/U/D for duration changes. Stopwatch
     * intercepts UP for reset. Other pages defer L/R navigation to the
     * default page-cycle handler below. */
    if (st->page == CLOCK_PAGE_TIMER)
    {
        switch (btn)
        {
            case M1_BTN_OK:
                if (st->tm_mode == TIMER_RUNNING)
                {
                    /* sample-then-pause so remaining_ms is current */
                    clock_timer_advance(st, HAL_GetTick());
                    st->tm_mode = TIMER_PAUSED;
                }
                else if (st->tm_mode == TIMER_ALERT)
                {
                    st->tm_mode = TIMER_IDLE;
                    clock_timer_reset_countdown(st);
                }
                else
                {
                    if (st->tm_remaining_ms == 0U)
                    {
                        clock_timer_reset_countdown(st);
                    }
                    st->tm_mode         = TIMER_RUNNING;
                    st->tm_deadline_ms  = HAL_GetTick() + st->tm_remaining_ms;
                }
                return true;

            case M1_BTN_LEFT:
                if (st->tm_mode != TIMER_RUNNING)
                {
                    clock_timer_adjust(st, -(int16_t)CLOCK_TIMER_STEP_SMALL_SEC);
                }
                return true;

            case M1_BTN_RIGHT:
                if (st->tm_mode != TIMER_RUNNING)
                {
                    clock_timer_adjust(st, (int16_t)CLOCK_TIMER_STEP_SMALL_SEC);
                }
                return true;

            case M1_BTN_UP:
                if (st->tm_mode != TIMER_RUNNING)
                {
                    clock_timer_adjust(st, (int16_t)CLOCK_TIMER_STEP_LARGE_SEC);
                }
                return true;

            case M1_BTN_DOWN:
                if (st->tm_mode != TIMER_RUNNING)
                {
                    clock_timer_adjust(st, -(int16_t)CLOCK_TIMER_STEP_LARGE_SEC);
                }
                return true;

            default:
                break;
        }
    }
    else if (st->page == CLOCK_PAGE_STOPWATCH)
    {
        if (btn == M1_BTN_OK)
        {
            uint32_t now = HAL_GetTick();
            if (st->sw_running)
            {
                st->sw_accum_ms  += (now - st->sw_started_ms);
                st->sw_running    = false;
            }
            else
            {
                st->sw_started_ms = now;
                st->sw_running    = true;
            }
            return true;
        }
        if (btn == M1_BTN_UP)
        {
            st->sw_accum_ms  = 0U;
            st->sw_started_ms = HAL_GetTick();
            return true;
        }
    }
    else if (st->page == CLOCK_PAGE_ZONES)
    {
        /* L/R cycles zones first; only when at the boundary should we
         * cross to a different page. We model this as: L/R always cycles
         * zones, U/D advances pages. */
        if (btn == M1_BTN_LEFT)
        {
            st->zone_idx = (st->zone_idx == 0U)
                ? (uint8_t)(CLOCK_ZONE_COUNT - 1U)
                : (uint8_t)(st->zone_idx - 1U);
            return true;
        }
        if (btn == M1_BTN_RIGHT)
        {
            st->zone_idx = (uint8_t)((st->zone_idx + 1U) % CLOCK_ZONE_COUNT);
            return true;
        }
    }

    /* Default page navigation (UP / DOWN always; LEFT / RIGHT for pages
     * that did not consume them above). */
    if (btn == M1_BTN_UP)
    {
        st->page = (st->page == CLOCK_PAGE_LOCAL)
            ? (clock_page_t)(CLOCK_PAGE_COUNT - 1U)
            : (clock_page_t)(st->page - 1U);
        return true;
    }
    if (btn == M1_BTN_DOWN)
    {
        st->page = (clock_page_t)((st->page + 1U) % CLOCK_PAGE_COUNT);
        return true;
    }
    if (btn == M1_BTN_LEFT)
    {
        st->page = (st->page == CLOCK_PAGE_LOCAL)
            ? (clock_page_t)(CLOCK_PAGE_COUNT - 1U)
            : (clock_page_t)(st->page - 1U);
        return true;
    }
    if (btn == M1_BTN_RIGHT)
    {
        st->page = (clock_page_t)((st->page + 1U) % CLOCK_PAGE_COUNT);
        return true;
    }

    return false;
}


/*-------------------------------- public api --------------------------------*/

void app_clock_run(void)
{
    static const m1_app_def_t def = {
        .title           = "Clock",
        .on_init         = clock_on_init,
        .on_render       = clock_on_render,
        .on_button       = clock_on_button,
        .on_tick         = clock_on_tick,
        .on_exit         = NULL,
        .tick_period_ms  = CLOCK_TICK_MS,
        .user_state      = &s_clock,
        .user_state_size = sizeof(s_clock),
    };

    m1_app_run(&def);
}


/* The "Dab Timer" menu entry is preserved as an alias that lands directly
 * on the Timer page. This keeps existing menu wiring working while users
 * discover the merged Clock app. */
void app_dab_timer_run(void)
{
    /* Pre-seed the page index so the user lands on the Timer page even
     * though clock_on_init resets state. We do it after init via a
     * dedicated def so the static state is still owned by us. */
    s_clock.page = CLOCK_PAGE_TIMER;

    static const m1_app_def_t def = {
        .title           = "Timer",
        .on_init         = clock_on_init,
        .on_render       = clock_on_render,
        .on_button       = clock_on_button,
        .on_tick         = clock_on_tick,
        .on_exit         = NULL,
        .tick_period_ms  = CLOCK_TICK_MS,
        .user_state      = &s_clock,
        .user_state_size = 0U,    /* don't zero — we just set page above */
    };

    m1_app_run(&def);
}
