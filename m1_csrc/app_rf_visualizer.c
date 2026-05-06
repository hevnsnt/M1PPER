/* See COPYING.txt for license details. */

/*
 * app_rf_visualizer.c
 *
 * ProtoView-style RF signal visualizer.
 *
 * Pipeline:
 *   1) User picks a frequency from a small preset table or enters a custom
 *      one digit-by-digit.
 *   2) The SI4463 is brought up in OOK direct-mode RX. The existing TIM1
 *      input-capture pipeline (the same one used by sub_ghz_repeater() and
 *      app_pocsag.c) drains pulse-edge timings, in microseconds, into a
 *      uint16_t ring buffer.
 *   3) Each pulse alternates HIGH / LOW. We store them in a flat capture
 *      array (s_pulses[]) and treat the first pulse as a LOW gap.
 *   4) When a >20 ms silence is observed the burst is considered finished
 *      and we run a tiny histogram to suggest a likely modulation
 *      (PWM if there are two distinct pulse widths, Manchester if three).
 *   5) The waveform is rendered onto the 128x64 OLED as a stack of bars
 *      around a centre line at y=32. Up to ~80 bars fit on screen at any
 *      one time; LEFT/RIGHT scrolls and UP/DOWN zooms in/out.
 *
 * Static memory only: no heap is used.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

#include "m1_compile_cfg.h"

#ifdef M1_APP_RF_VISUALIZER_ENABLE

#include "app_rf_visualizer.h"
#include "m1_lcd.h"
#include "m1_display.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_lib.h"
#include "m1_sub_ghz.h"
#include "m1_sub_ghz_api.h"
#include "m1_ring_buffer.h"

/* ============================================================================
 * Tuning
 * ============================================================================ */

#define RF_VIZ_MAX_PULSES        512U     /* edge timings stored per burst */
#define RF_VIZ_RING_SLOTS        1024U    /* uint16_t ring slots */
#define RF_VIZ_BURST_END_MS      20U      /* silence that closes a burst */
#define RF_VIZ_MIN_BURST_PULSES  8U
#define RF_VIZ_MIN_FREQ_HZ       142000000UL
#define RF_VIZ_MAX_FREQ_HZ       1050000000UL

/* Display geometry: HIGH bars from y=24..40, LOW bars from y=40..56. */
#define RF_VIZ_CENTRE_Y          40
#define RF_VIZ_BAR_HALF_H        16
#define RF_VIZ_VIS_WIDTH         128
#define RF_VIZ_BARS_TARGET       80      /* bars we like to fit on-screen */

/* Default scale (microseconds per on-screen pixel). */
#define RF_VIZ_DEFAULT_SCALE_US  100U

/* ============================================================================
 * Frequency picker
 * ============================================================================ */

typedef struct {
    uint32_t   freq_hz;     /* 0 = "Custom..." */
    const char *label;
} rf_viz_preset_t;

static const rf_viz_preset_t s_freq_presets[] = {
    { 315000000UL, "315.000 (US)"  },
    { 433920000UL, "433.920 (EU)"  },
    { 868350000UL, "868.350 (EU)"  },
    { 915000000UL, "915.000 (US)"  },
    {         0UL, "Custom..."     }
};

#define RF_VIZ_PRESET_COUNT \
    (sizeof(s_freq_presets) / sizeof(s_freq_presets[0]))

/* ============================================================================
 * Static state
 * ============================================================================ */

static uint32_t s_pulses[RF_VIZ_MAX_PULSES];   /* alternating durations us  */
static uint16_t s_ring_storage[RF_VIZ_RING_SLOTS];
static uint16_t s_consume[256];                /* drain scratch buffer       */

static uint32_t s_pulse_count = 0;
static uint32_t s_burst_pulse_count = 0;       /* sealed after burst end     */
static uint32_t s_total_us = 0;                /* sum of all pulses in burst */
static uint32_t s_high_us_last = 0;
static uint32_t s_low_us_last  = 0;
static uint32_t s_scale_us_per_px = RF_VIZ_DEFAULT_SCALE_US;
static int32_t  s_scroll_pulse_idx = 0;        /* leftmost pulse on screen   */
static bool     s_have_burst = false;          /* true once a burst sealed   */
static const char *s_mod_hint = "";            /* PWM/Manchester guess       */
/* Polarity of the GPIO0 line at the moment the capture pipeline was armed.
 * The hardware ISR records EDGE durations only, so without sampling the
 * starting level here, half the captures display upside-down. */
static uint8_t  s_initial_level = 0;

/* ============================================================================
 * Frequency entry helpers
 * ============================================================================ */

static bool rf_viz_custom_freq(uint32_t *out_freq_hz)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    char                freq_str[12];
    uint8_t             digits[7];
    uint8_t             cursor = 0;
    bool                done = false;
    bool                accepted = false;
    uint32_t            cur = (out_freq_hz && *out_freq_hz)
                              ? *out_freq_hz : 433920000UL;
    uint32_t            mhz = cur / 1000000UL;
    uint32_t            khz = (cur % 1000000UL) / 1000UL;

    digits[0] = (uint8_t)((mhz / 1000U) % 10U);
    digits[1] = (uint8_t)((mhz / 100U)  % 10U);
    digits[2] = (uint8_t)((mhz / 10U)   % 10U);
    digits[3] = (uint8_t)( mhz % 10U);
    digits[4] = (uint8_t)((khz / 100U)  % 10U);
    digits[5] = (uint8_t)((khz / 10U)   % 10U);
    digits[6] = (uint8_t)( khz % 10U);

    while (!done)
    {
        snprintf(freq_str, sizeof(freq_str), "%d%d%d%d.%d%d%d",
                 digits[0], digits[1], digits[2], digits[3],
                 digits[4], digits[5], digits[6]);

        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
            u8g2_DrawStr(&m1_u8g2, 0, 10, "RF Viz: Freq (MHz)");
            u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

            u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 8, 38, freq_str);

            uint8_t cursor_x = 8;
            for (uint8_t c = 0; c < cursor; c++)
            {
                if (c == 4) cursor_x += 5;
                cursor_x += 10;
            }
            if (cursor >= 4) cursor_x += 5;
            u8g2_DrawHLine(&m1_u8g2, cursor_x, 40, 8);

            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 0, 56, "\x18\x19:Digit L/R:Move");
            u8g2_DrawStr(&m1_u8g2, 0, 64, "OK:Set BACK:Cancel");
        } while (u8g2_NextPage(&m1_u8g2));

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &bs, 0);

        if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            digits[cursor] = (uint8_t)((digits[cursor] + 1U) % 10U);
        }
        else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            digits[cursor] = (uint8_t)((digits[cursor] + 9U) % 10U);
        }
        else if (bs.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (cursor < 6) cursor++;
        }
        else if (bs.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (cursor > 0) cursor--;
        }
        else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            uint32_t new_mhz = (uint32_t)digits[0] * 1000U
                             + (uint32_t)digits[1] * 100U
                             + (uint32_t)digits[2] * 10U
                             + (uint32_t)digits[3];
            uint32_t new_khz = (uint32_t)digits[4] * 100U
                             + (uint32_t)digits[5] * 10U
                             + (uint32_t)digits[6];
            uint32_t new_freq = new_mhz * 1000000UL + new_khz * 1000UL;
            if (new_freq >= RF_VIZ_MIN_FREQ_HZ &&
                new_freq <= RF_VIZ_MAX_FREQ_HZ)
            {
                *out_freq_hz = new_freq;
                accepted = true;
                done = true;
            }
            else
            {
                m1_message_box(&m1_u8g2, "Out of range!",
                               "142.000 - 1050.000",
                               "MHz", "BACK to retry");
            }
        }
        else if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            done = true;
        }
    }

    xQueueReset(main_q_hdl);
    return accepted;
}

static uint32_t rf_viz_pick_frequency(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint8_t             sel = 1;        /* default: 433.920 */
    bool                done = false;
    uint32_t            freq_out = 0;
    static uint32_t     custom_cache_hz = 433920000UL;

    while (!done)
    {
        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
            u8g2_DrawStr(&m1_u8g2, 0, 10, "RF Visualizer");
            u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);

            u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
            for (uint8_t i = 0; i < RF_VIZ_PRESET_COUNT; i++)
            {
                uint8_t y = (uint8_t)(22 + i * 9);
                if (i == sel)
                {
                    u8g2_DrawBox(&m1_u8g2, 0, (uint8_t)(y - 7), 128, 9);
                    u8g2_SetDrawColor(&m1_u8g2, 0);
                    u8g2_DrawStr(&m1_u8g2, 2, y, s_freq_presets[i].label);
                    u8g2_SetDrawColor(&m1_u8g2, 1);
                }
                else
                {
                    u8g2_DrawStr(&m1_u8g2, 2, y, s_freq_presets[i].label);
                }
            }

            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 0, 64, "\x18\x19:Move OK:Pick BACK:Exit");
        } while (u8g2_NextPage(&m1_u8g2));

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        xQueueReceive(button_events_q_hdl, &bs, 0);

        if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            done = true;
        }
        else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel == 0) ? (RF_VIZ_PRESET_COUNT - 1U)
                                       : (sel - 1U));
        }
        else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel + 1U) % RF_VIZ_PRESET_COUNT);
        }
        else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (s_freq_presets[sel].freq_hz != 0UL)
            {
                freq_out = s_freq_presets[sel].freq_hz;
                done = true;
            }
            else
            {
                if (rf_viz_custom_freq(&custom_cache_hz))
                {
                    freq_out = custom_cache_hz;
                    done = true;
                }
            }
        }
    }

    xQueueReset(main_q_hdl);
    return freq_out;
}

/* ============================================================================
 * Burst analysis: simple histogram of pulse widths
 * ============================================================================ */

/* Cluster pulse widths into up to 4 buckets using a tolerance window.
 * Returns the number of distinct clusters detected. */
static uint8_t rf_viz_count_clusters(void)
{
    if (s_burst_pulse_count == 0) return 0;

    uint32_t centres[4] = { 0, 0, 0, 0 };
    uint32_t counts[4]  = { 0, 0, 0, 0 };
    uint8_t  n = 0;

    for (uint32_t i = 0; i < s_burst_pulse_count; i++)
    {
        uint32_t w = s_pulses[i];
        if (w == 0) continue;
        bool placed = false;
        for (uint8_t k = 0; k < n; k++)
        {
            uint32_t c = centres[k];
            uint32_t lo = (c * 7U) / 10U;       /* 70 % */
            uint32_t hi = (c * 13U) / 10U;      /* 130 % */
            if (w >= lo && w <= hi)
            {
                /* Running average. */
                centres[k] = (uint32_t)(((uint64_t)c * counts[k] + w)
                                         / (counts[k] + 1U));
                counts[k]++;
                placed = true;
                break;
            }
        }
        if (!placed && n < 4)
        {
            centres[n] = w;
            counts[n]  = 1;
            n++;
        }
    }

    /* Drop clusters that are statistical noise (<5 %). */
    uint32_t total = 0;
    for (uint8_t k = 0; k < n; k++) total += counts[k];
    uint8_t  effective = 0;
    if (total > 0)
    {
        for (uint8_t k = 0; k < n; k++)
        {
            if ((counts[k] * 100U) / total >= 5U) effective++;
        }
    }
    return effective;
}

static void rf_viz_classify(void)
{
    uint8_t clusters = rf_viz_count_clusters();
    if (s_burst_pulse_count < RF_VIZ_MIN_BURST_PULSES)
    {
        s_mod_hint = "noise?";
    }
    else if (clusters <= 1)
    {
        s_mod_hint = "single";
    }
    else if (clusters == 2)
    {
        s_mod_hint = "PWM/OOK";
    }
    else if (clusters == 3)
    {
        s_mod_hint = "Manchester";
    }
    else
    {
        s_mod_hint = "complex";
    }
}

/* ============================================================================
 * Capture: drain ring buffer into s_pulses[]
 * ============================================================================ */

static void rf_viz_capture_reset(void)
{
    s_pulse_count = 0;
    s_burst_pulse_count = 0;
    s_total_us = 0;
    s_high_us_last = 0;
    s_low_us_last  = 0;
    s_scroll_pulse_idx = 0;
    s_have_burst = false;
    s_mod_hint = "";
    /* Re-sample the current GPIO0 line level so a clear-buffer keypress
     * before any RF arrives still labels bars with the correct polarity. */
    s_initial_level = (uint8_t)(
        (SUBGHZ_RX_GPIO_PORT->IDR & SUBGHZ_RX_GPIO_PIN) ? 1U : 0U);
    m1_ringbuffer_reset(&subghz_rx_rawdata_rb);
}

/* Pulse polarity convention: index 0 takes the GPIO0 level captured at
 * arm time; subsequent indices alternate.  Without seeding from the actual
 * line level the visualiser inverts the displayed waveform on roughly half
 * of all captures (whichever polarity the line happened to be on at arm).
 *
 * Truth table:
 *   initial=HIGH(1): idx=0 HIGH, idx=1 LOW, idx=2 HIGH, ...
 *   initial=LOW (0): idx=0 LOW,  idx=1 HIGH, idx=2 LOW, ...
 *
 * Both collapse to: is_high <=> (idx & 1) XOR initial != 0.
 */
static inline bool rf_viz_pulse_is_high(uint32_t idx)
{
    return (((idx & 1U) ^ (uint32_t)s_initial_level) != 0U);
}

/* Returns true if at least one new pulse was appended. */
static bool rf_viz_drain_ring(TickType_t *p_last_sample_tick)
{
    uint32_t avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);
    bool got_any = false;

    while (avail > 0 && s_pulse_count < RF_VIZ_MAX_PULSES)
    {
        uint32_t room = RF_VIZ_MAX_PULSES - s_pulse_count;
        uint32_t want = (avail > room) ? room : avail;
        if (want > (uint32_t)(sizeof(s_consume) / sizeof(s_consume[0])))
            want = (uint32_t)(sizeof(s_consume) / sizeof(s_consume[0]));

        uint16_t got = m1_ringbuffer_read(&subghz_rx_rawdata_rb,
                                          (uint8_t *)s_consume,
                                          (uint16_t)want);
        if (got == 0) break;

        for (uint16_t i = 0; i < got; i++)
        {
            uint32_t dur = s_consume[i];
            if (dur == 0) dur = 1;
            s_pulses[s_pulse_count] = dur;
            s_total_us += dur;
            if (rf_viz_pulse_is_high(s_pulse_count))
                s_high_us_last = dur;
            else
                s_low_us_last = dur;
            s_pulse_count++;
            if (s_pulse_count >= RF_VIZ_MAX_PULSES) break;
        }
        got_any = true;
        if (p_last_sample_tick) *p_last_sample_tick = xTaskGetTickCount();
        avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);
    }

    return got_any;
}

/* ============================================================================
 * Auto-scale and rendering
 * ============================================================================ */

static void rf_viz_autoscale(void)
{
    if (s_burst_pulse_count == 0)
    {
        s_scale_us_per_px = RF_VIZ_DEFAULT_SCALE_US;
        return;
    }

    /* Pick a scale so that ~80 typical pulses fit on screen. We use the
     * median-ish duration (mean is good enough for OOK). */
    uint64_t mean_us = s_total_us / s_burst_pulse_count;
    if (mean_us == 0) mean_us = 1;

    /* Bars target = RF_VIZ_BARS_TARGET; pixel/bar = WIDTH/BARS = 1.6 -> 2.
     * scale = mean_us / 2 keeps the average pulse 2 px wide. */
    uint32_t scale = (uint32_t)(mean_us / 2U);
    if (scale < 1U) scale = 1U;
    s_scale_us_per_px = scale;
}

/* Draw the waveform area (y=20..56) using current scroll/scale. */
static void rf_viz_draw_waveform(void)
{
    if (s_pulse_count == 0)
    {
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 16, 42, "Waiting for signal...");
        u8g2_DrawHLine(&m1_u8g2, 0, RF_VIZ_CENTRE_Y, 128);
        return;
    }

    /* Centre line. */
    u8g2_DrawHLine(&m1_u8g2, 0, RF_VIZ_CENTRE_Y, 128);

    int32_t  x = 0;
    uint32_t i = (uint32_t)((s_scroll_pulse_idx < 0) ? 0 : s_scroll_pulse_idx);

    while (i < s_pulse_count && x < RF_VIZ_VIS_WIDTH)
    {
        uint32_t dur = s_pulses[i];
        uint32_t w_px = dur / s_scale_us_per_px;
        if (w_px == 0) w_px = 1;
        if ((int32_t)w_px > (RF_VIZ_VIS_WIDTH - x))
            w_px = (uint32_t)(RF_VIZ_VIS_WIDTH - x);

        if (rf_viz_pulse_is_high(i))
        {
            /* HIGH bar: filled rectangle above the centre line. */
            u8g2_DrawBox(&m1_u8g2, (u8g2_uint_t)x,
                         (u8g2_uint_t)(RF_VIZ_CENTRE_Y - RF_VIZ_BAR_HALF_H),
                         (u8g2_uint_t)w_px,
                         (u8g2_uint_t)RF_VIZ_BAR_HALF_H);
            /* Vertical edge at start to make sharp transitions visible. */
            u8g2_DrawVLine(&m1_u8g2, (u8g2_uint_t)x,
                           (u8g2_uint_t)(RF_VIZ_CENTRE_Y - RF_VIZ_BAR_HALF_H),
                           (u8g2_uint_t)RF_VIZ_BAR_HALF_H);
        }
        else
        {
            /* LOW bar: filled rectangle below the centre line. */
            u8g2_DrawBox(&m1_u8g2, (u8g2_uint_t)x,
                         (u8g2_uint_t)RF_VIZ_CENTRE_Y,
                         (u8g2_uint_t)w_px,
                         (u8g2_uint_t)RF_VIZ_BAR_HALF_H);
            u8g2_DrawVLine(&m1_u8g2, (u8g2_uint_t)x,
                           (u8g2_uint_t)RF_VIZ_CENTRE_Y,
                           (u8g2_uint_t)RF_VIZ_BAR_HALF_H);
        }

        x += (int32_t)w_px;
        i++;
    }
}

/* Compose the full 128x64 frame. */
static void rf_viz_draw(uint32_t freq_hz, bool capturing)
{
    char l_top[28];
    char l_pulse[28];
    char l_bot[28];

    snprintf(l_top, sizeof(l_top), "%lu.%03lu MHz OOK",
             (unsigned long)(freq_hz / 1000000UL),
             (unsigned long)((freq_hz % 1000000UL) / 1000UL));

    snprintf(l_pulse, sizeof(l_pulse), "H:%luus L:%luus",
             (unsigned long)s_high_us_last,
             (unsigned long)s_low_us_last);

    if (s_have_burst)
    {
        snprintf(l_bot, sizeof(l_bot), "N=%lu %luus %s",
                 (unsigned long)s_burst_pulse_count,
                 (unsigned long)s_total_us,
                 s_mod_hint);
    }
    else if (capturing)
    {
        snprintf(l_bot, sizeof(l_bot), "Capturing... %lu",
                 (unsigned long)s_pulse_count);
    }
    else
    {
        uint32_t end_idx = s_scroll_pulse_idx + (uint32_t)RF_VIZ_BARS_TARGET;
        if (end_idx > s_burst_pulse_count) end_idx = s_burst_pulse_count;
        snprintf(l_bot, sizeof(l_bot), "%ld-%lu/%lu %luus/px",
                 (long)s_scroll_pulse_idx,
                 (unsigned long)end_idx,
                 (unsigned long)s_burst_pulse_count,
                 (unsigned long)s_scale_us_per_px);
    }

    u8g2_FirstPage(&m1_u8g2);
    do {
        u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 0, 9, l_top);
        u8g2_DrawHLine(&m1_u8g2, 0, 11, 128);

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 19, l_pulse);

        rf_viz_draw_waveform();

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 64, l_bot);
    } while (u8g2_NextPage(&m1_u8g2));
}

/* ============================================================================
 * Burst end detection
 * ============================================================================ */

static void rf_viz_seal_burst(void)
{
    s_burst_pulse_count = s_pulse_count;
    s_have_burst = (s_burst_pulse_count >= RF_VIZ_MIN_BURST_PULSES);
    if (s_have_burst)
    {
        rf_viz_classify();
        rf_viz_autoscale();
        s_scroll_pulse_idx = 0;
    }
}

/* ============================================================================
 * Radio bring-up / tear-down
 * ============================================================================ */

static void rf_viz_radio_start(uint32_t freq_hz)
{
    /* Use the same code path as POCSAG/Repeater: bring up SI4463 in OOK
     * direct-mode at a base band, then retune to the user frequency. */
    radio_init_rx_tx(SUB_GHZ_BAND_433_92, MODEM_MOD_TYPE_OOK, true);
    SI446x_Change_State(
        SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_READY);
    SI446x_Set_Frequency(freq_hz);
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_RX);
    SI446x_Start_Rx(0);
    SI446x_Change_Modem_OOK_PDTC(0x6C);

    m1_ringbuffer_init(&subghz_rx_rawdata_rb,
                       (uint8_t *)s_ring_storage,
                       (uint16_t)RF_VIZ_RING_SLOTS,
                       (uint8_t)sizeof(uint16_t));
    m1_ringbuffer_reset(&subghz_rx_rawdata_rb);

    /* Sample the GPIO0 level at arm time.  Pulses come in alternating, so
     * if the line was already HIGH when we armed, index 0 is a HIGH run; if
     * it was LOW, index 0 is a LOW run.  rf_viz_pulse_is_high() uses this
     * to label the bars correctly. */
    s_initial_level = (uint8_t)(
        (SUBGHZ_RX_GPIO_PORT->IDR & SUBGHZ_RX_GPIO_PIN) ? 1U : 0U);

    sub_ghz_pulse_capture_arm();
}

static void rf_viz_radio_stop(void)
{
    sub_ghz_pulse_capture_disarm();
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_ISOLATED);
    SI446x_Change_State(
        SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_SLEEP);
    /* The driver's ring-buffer pdata still points at our static storage;
     * null it out so future record/replay code paths re-initialise cleanly,
     * mirroring what sub_ghz_repeater() does. */
    subghz_rx_rawdata_rb.pdata = NULL;
}

/* ============================================================================
 * Public entry point
 * ============================================================================ */

void app_rf_visualizer_run(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint32_t            freq_hz;

    freq_hz = rf_viz_pick_frequency();
    if (freq_hz == 0UL)
    {
        m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
        return;
    }

    rf_viz_capture_reset();

    menu_sub_ghz_init();
    rf_viz_radio_start(freq_hz);

    bool       running = true;
    bool       capturing = false;
    TickType_t last_sample_tick = xTaskGetTickCount();
    TickType_t last_redraw      = 0;

    rf_viz_draw(freq_hz, capturing);

    while (running)
    {
        /* Drain new pulses. */
        if (!s_have_burst && s_pulse_count < RF_VIZ_MAX_PULSES)
        {
            if (rf_viz_drain_ring(&last_sample_tick))
            {
                if (!capturing)
                {
                    capturing = true;
                }
            }

            /* End-of-burst detection. */
            if (capturing && s_pulse_count >= RF_VIZ_MIN_BURST_PULSES)
            {
                TickType_t silence = xTaskGetTickCount() - last_sample_tick;
                if (silence > pdMS_TO_TICKS(RF_VIZ_BURST_END_MS))
                {
                    rf_viz_seal_burst();
                    capturing = false;
                    /* Stop accepting more pulses; user must press OK to rearm. */
                    sub_ghz_pulse_capture_disarm();
                }
            }
            else if (!capturing && s_pulse_count >= RF_VIZ_MAX_PULSES)
            {
                /* Buffer full without ever passing min count - seal anyway. */
                rf_viz_seal_burst();
                sub_ghz_pulse_capture_disarm();
            }

            if (capturing && s_pulse_count >= RF_VIZ_MAX_PULSES)
            {
                /* Edge case: hit the cap during a live burst. */
                rf_viz_seal_burst();
                capturing = false;
                sub_ghz_pulse_capture_disarm();
            }
        }

        /* Periodic redraw. */
        TickType_t now = xTaskGetTickCount();
        if ((now - last_redraw) > pdMS_TO_TICKS(120))
        {
            rf_viz_draw(freq_hz, capturing);
            last_redraw = now;
        }

        /* Non-blocking key check. */
        ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(20));
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &bs, 0);
            if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                running = false;
            }
            else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Rearm capture, dropping any sealed burst. */
                rf_viz_capture_reset();
                capturing = false;
                last_sample_tick = xTaskGetTickCount();
                sub_ghz_pulse_capture_arm();
                rf_viz_draw(freq_hz, capturing);
                last_redraw = xTaskGetTickCount();
            }
            else if (bs.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (s_have_burst && s_burst_pulse_count > 0)
                {
                    int32_t step = (int32_t)(RF_VIZ_BARS_TARGET / 2U);
                    s_scroll_pulse_idx -= step;
                    if (s_scroll_pulse_idx < 0) s_scroll_pulse_idx = 0;
                    rf_viz_draw(freq_hz, capturing);
                    last_redraw = xTaskGetTickCount();
                }
            }
            else if (bs.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            {
                if (s_have_burst && s_burst_pulse_count > 0)
                {
                    int32_t step = (int32_t)(RF_VIZ_BARS_TARGET / 2U);
                    int32_t max_start =
                        (int32_t)s_burst_pulse_count - 1;
                    if (max_start < 0) max_start = 0;
                    s_scroll_pulse_idx += step;
                    if (s_scroll_pulse_idx > max_start)
                        s_scroll_pulse_idx = max_start;
                    rf_viz_draw(freq_hz, capturing);
                    last_redraw = xTaskGetTickCount();
                }
            }
            else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Zoom in: smaller us/px -> bars look wider. */
                if (s_scale_us_per_px > 2U)
                {
                    s_scale_us_per_px = (s_scale_us_per_px * 2U) / 3U;
                    if (s_scale_us_per_px < 1U) s_scale_us_per_px = 1U;
                    rf_viz_draw(freq_hz, capturing);
                    last_redraw = xTaskGetTickCount();
                }
            }
            else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Zoom out: larger us/px. */
                if (s_scale_us_per_px < 100000UL)
                {
                    s_scale_us_per_px = (s_scale_us_per_px * 3U) / 2U;
                    if (s_scale_us_per_px == 0) s_scale_us_per_px = 1U;
                    rf_viz_draw(freq_hz, capturing);
                    last_redraw = xTaskGetTickCount();
                }
            }
        }
    }

    rf_viz_radio_stop();
    menu_sub_ghz_exit();

    xQueueReset(main_q_hdl);
    m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
}

#endif /* M1_APP_RF_VISUALIZER_ENABLE */
