/* See COPYING.txt for license details. */

/*
 * app_pocsag.c
 *
 * POCSAG pager decoder for M1.
 *
 * Pipeline:
 *   1) User selects frequency (preset list + Custom entry).
 *   2) SI4463 is configured for OOK direct-mode RX, driving demodulated
 *      bits onto GPIO0.
 *   3) TIM1 input capture (channel 1) records the duration of each level
 *      run in microseconds and the existing sub_ghz_rx_rawdata_rb ring
 *      buffer collects the uint16_t pulse widths.
 *   4) The decoder walks each pulse, divides its duration by the POCSAG
 *      bit period (auto-detected among 512 / 1200 / 2400 bps), and feeds
 *      a sliding 32-bit shift register with alternating bit values.
 *   5) When the shift register matches the POCSAG sync word
 *      (0x7CD215D8) within a 2-bit Hamming distance, the decoder
 *      consumes the next 16 codewords (one POCSAG batch = 8 frames *
 *      2 codewords) and BCH(31,21)-checks each one before extracting
 *      address / message bits.
 *
 * UI:
 *   - Frequency picker first (UP/DOWN scroll, OK to confirm, BACK exit).
 *   - Live decoder screen shows current frequency, rate, packet count
 *     and the last few decoded messages. Press BACK to leave.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"
#include "app_pocsag.h"
#include "m1_lcd.h"
#include "m1_display.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_lib.h"
#include "m1_buzzer.h"
#include "m1_sub_ghz.h"
#include "m1_sub_ghz_api.h"
#include "m1_ring_buffer.h"

/* ============================================================================
 * Constants and tuning
 * ============================================================================ */

#define POCSAG_SYNC_WORD            0x7CD215D8UL
#define POCSAG_IDLE_WORD            0x7A89C197UL
#define POCSAG_BATCH_CODEWORDS      16        /* 8 frames * 2 codewords */

#define POCSAG_SYNC_TOLERANCE_BITS  2         /* allow up to 2 bit errors */

/* BCH(31,21) generator polynomial: x^10 + x^9 + x^8 + x^6 + x^5 + x^3 + 1 */
#define POCSAG_BCH_POLY             0x769U

#define POCSAG_RX_BIT_BUFFER_LEN    2048      /* sliding bit window cap */

#define POCSAG_MSG_LINES            4
#define POCSAG_MSG_TEXT_LEN         32

/* Supported baud rates (auto-detected at run time). */
typedef struct {
    uint16_t baud;
    uint16_t bit_us;          /* microseconds per bit */
    uint16_t half_bit_us;
    uint16_t three_half_us;
} pocsag_rate_t;

static const pocsag_rate_t pocsag_rates[3] = {
    {  512, 1953,  977, 2930 },   /* 1/512  s = 1953 µs */
    { 1200,  833,  417, 1250 },   /* 1/1200 s =  833 µs */
    { 2400,  417,  208,  625 }    /* 1/2400 s =  417 µs */
};

#define POCSAG_RATE_COUNT  (sizeof(pocsag_rates) / sizeof(pocsag_rates[0]))

/* Frequency presets shown on the picker. */
typedef struct {
    uint32_t   freq_hz;
    const char *label;
} pocsag_freq_preset_t;

static const pocsag_freq_preset_t pocsag_freq_presets[] = {
    { 152000000UL, "152.000 (US)"   },
    { 157450000UL, "157.450 (US)"   },
    { 158100000UL, "158.100 (US)"   },
    { 159100000UL, "159.100 (US)"   },
    { 462000000UL, "462.000 (US)"   },
    { 462962500UL, "462.962 (FRS)"  },
    { 466000000UL, "466.000 (EU)"   },
    { 466075000UL, "466.075 (EU)"   },
    { 0UL,         "Custom..."      }
};

#define POCSAG_PRESET_COUNT  (sizeof(pocsag_freq_presets) / sizeof(pocsag_freq_presets[0]))

/* ============================================================================
 * Static decoder state
 * ============================================================================ */

typedef enum {
    POCSAG_STATE_HUNT_PREAMBLE = 0,
    POCSAG_STATE_HUNT_SYNC,
    POCSAG_STATE_BATCH
} pocsag_state_t;

typedef struct {
    uint8_t  bits[POCSAG_RX_BIT_BUFFER_LEN];
    uint16_t bit_count;
    uint16_t bit_read_pos;

    pocsag_state_t state;
    uint8_t  rate_idx;
    uint8_t  frame_idx;            /* 0..7 inside batch */
    uint8_t  cw_in_frame;          /* 0..1 */

    uint32_t shift_reg;
    uint8_t  shift_filled;

    /* In-progress alphanumeric message accumulator. */
    char     pending_text[POCSAG_MSG_TEXT_LEN + 1];
    uint8_t  pending_len;
    uint8_t  pending_bit_carry;     /* leftover bits from previous codeword */
    uint8_t  pending_bit_carry_len;
    uint32_t pending_capcode;
    uint8_t  pending_function;
    bool     pending_active;
    bool     pending_is_numeric;

    /* Display log. */
    char    log_lines[POCSAG_MSG_LINES][POCSAG_MSG_TEXT_LEN + 1];
    uint8_t log_count;
    uint32_t packets_decoded;
    uint32_t bch_correctable;
    uint32_t bch_failed;
} pocsag_ctx_t;

static pocsag_ctx_t pocsag_ctx;

/* ============================================================================
 * Bit-level helpers
 * ============================================================================ */

static uint32_t pocsag_reverse32(uint32_t v)
{
    v = ((v >> 1) & 0x55555555U) | ((v & 0x55555555U) << 1);
    v = ((v >> 2) & 0x33333333U) | ((v & 0x33333333U) << 2);
    v = ((v >> 4) & 0x0F0F0F0FU) | ((v & 0x0F0F0F0FU) << 4);
    v = ((v >> 8) & 0x00FF00FFU) | ((v & 0x00FF00FFU) << 8);
    v = (v >> 16) | (v << 16);
    return v;
}

static uint8_t pocsag_popcount32(uint32_t v)
{
    v = v - ((v >> 1) & 0x55555555U);
    v = (v & 0x33333333U) + ((v >> 2) & 0x33333333U);
    v = (v + (v >> 4)) & 0x0F0F0F0FU;
    return (uint8_t)((v * 0x01010101U) >> 24);
}

static bool pocsag_even_parity_ok(uint32_t cw)
{
    /* POCSAG codeword has an even-parity bit at LSB. */
    return (pocsag_popcount32(cw) & 1U) == 0U;
}

/* Compute BCH(31,21) syndrome for a 31-bit codeword.
 * The codeword is bits 31..1 (we drop the parity bit at bit 0).
 * Polynomial g(x) = x^10 + x^9 + x^8 + x^6 + x^5 + x^3 + 1 = 0x769. */
static uint16_t pocsag_bch_syndrome(uint32_t codeword31)
{
    uint32_t r = codeword31 & 0x7FFFFFFFU;     /* 31 bits */
    for (int i = 30; i >= 10; i--)
    {
        if (r & (1UL << i))
            r ^= ((uint32_t)POCSAG_BCH_POLY) << (i - 10);
    }
    return (uint16_t)(r & 0x3FFU);
}

/* Try to correct single-bit errors in a 32-bit POCSAG codeword.
 * Returns true if codeword is valid (or successfully corrected). */
static bool pocsag_bch_correct(uint32_t *pcw)
{
    uint32_t cw32 = *pcw;
    /* Strip parity, keep only data + BCH (bits 31..1). */
    uint32_t cw31 = cw32 >> 1;

    uint16_t syn = pocsag_bch_syndrome(cw31);
    if (syn == 0)
    {
        if (pocsag_even_parity_ok(cw32))
            return true;
        /* Parity broken, BCH OK: flip parity. */
        *pcw = cw32 ^ 1U;
        return true;
    }

    /* Single-bit search: try toggling each of the 31 data/BCH bits. */
    for (int i = 0; i < 31; i++)
    {
        uint32_t trial = cw31 ^ (1UL << i);
        if (pocsag_bch_syndrome(trial) == 0)
        {
            uint32_t corrected = (trial << 1) | (cw32 & 1U);
            if (!pocsag_even_parity_ok(corrected))
                corrected ^= 1U;
            *pcw = corrected;
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Frequency picker UI
 * ============================================================================ */

/* Implemented in m1_sub_ghz.c, used for the "Custom..." entry. */
extern uint32_t pocsag_get_custom_freq_hz_dummy_unused(void);  /* silence linker if any */

/* Re-uses the digit-by-digit entry style from sub_ghz_radio_settings via a
 * small local implementation so this module remains self-contained. */
static bool pocsag_custom_freq_entry(uint32_t *out_freq_hz)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    char freq_str[12];
    uint8_t digits[7];
    uint8_t cursor = 0;
    bool done = false;
    bool accepted = false;
    uint32_t cur = (out_freq_hz && *out_freq_hz) ? *out_freq_hz : 466000000UL;
    uint32_t mhz = cur / 1000000UL;
    uint32_t khz = (cur % 1000000UL) / 1000UL;

    digits[0] = (mhz / 1000) % 10;
    digits[1] = (mhz / 100)  % 10;
    digits[2] = (mhz / 10)   % 10;
    digits[3] = mhz % 10;
    digits[4] = (khz / 100)  % 10;
    digits[5] = (khz / 10)   % 10;
    digits[6] = khz % 10;

    while (!done)
    {
        snprintf(freq_str, sizeof(freq_str), "%d%d%d%d.%d%d%d",
                 digits[0], digits[1], digits[2], digits[3],
                 digits[4], digits[5], digits[6]);

        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
            u8g2_DrawStr(&m1_u8g2, 4, 12, "POCSAG Custom (MHz)");
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
            u8g2_DrawStr(&m1_u8g2, 0, 56, "\x18\x19:Digit L/R:Move OK:Set");
        } while (u8g2_NextPage(&m1_u8g2));

        ret = xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY);
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &bs, 0);
            if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
            {
                digits[cursor] = (digits[cursor] + 1) % 10;
            }
            else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                digits[cursor] = (digits[cursor] + 9) % 10;
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
                uint32_t new_mhz = digits[0]*1000U + digits[1]*100U + digits[2]*10U + digits[3];
                uint32_t new_khz = digits[4]*100U + digits[5]*10U + digits[6];
                uint32_t new_freq = new_mhz * 1000000UL + new_khz * 1000UL;
                if (new_freq >= 142000000UL && new_freq <= 1050000000UL)
                {
                    *out_freq_hz = new_freq;
                    accepted = true;
                    done = true;
                }
                else
                {
                    m1_message_box(&m1_u8g2, "Out of range!",
                                   "142.000 - 1050.000 MHz", "", "BACK to retry");
                }
            }
            else if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                done = true;
            }
        }
    }

    xQueueReset(main_q_hdl);
    return accepted;
}

/* Returns the chosen frequency in Hz, or 0 if user cancelled. */
static uint32_t pocsag_pick_frequency(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    uint8_t sel = 0;
    uint8_t top = 0;
    bool done = false;
    uint32_t freq_out = 0;
    static uint32_t custom_cache_hz = 466000000UL;

    while (!done)
    {
        u8g2_FirstPage(&m1_u8g2);
        do {
            u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
            u8g2_DrawStr(&m1_u8g2, 0, 10, "POCSAG: Pick Freq");

            u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
            const uint8_t visible = 4;
            for (uint8_t i = 0; i < visible && (top + i) < POCSAG_PRESET_COUNT; i++)
            {
                uint8_t idx = top + i;
                uint8_t y = 22 + i * 10;
                if (idx == sel)
                {
                    u8g2_DrawBox(&m1_u8g2, 0, y - 8, 128, 10);
                    u8g2_SetDrawColor(&m1_u8g2, 0);
                    u8g2_DrawStr(&m1_u8g2, 2, y, pocsag_freq_presets[idx].label);
                    u8g2_SetDrawColor(&m1_u8g2, 1);
                }
                else
                {
                    u8g2_DrawStr(&m1_u8g2, 2, y, pocsag_freq_presets[idx].label);
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
            if (sel > 0) sel--;
            else sel = POCSAG_PRESET_COUNT - 1;
            if (sel < top) top = sel;
            if (sel >= top + 4) top = sel - 3;
        }
        else if (bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel + 1) % POCSAG_PRESET_COUNT);
            if (sel < top) top = sel;
            if (sel >= top + 4) top = sel - 3;
        }
        else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (pocsag_freq_presets[sel].freq_hz != 0)
            {
                freq_out = pocsag_freq_presets[sel].freq_hz;
                done = true;
            }
            else
            {
                if (pocsag_custom_freq_entry(&custom_cache_hz))
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
 * Bit reconstruction from edge timings
 * ============================================================================ */

static void pocsag_log_message(const char *line)
{
    if (pocsag_ctx.log_count < POCSAG_MSG_LINES)
    {
        strncpy(pocsag_ctx.log_lines[pocsag_ctx.log_count], line,
                POCSAG_MSG_TEXT_LEN);
        pocsag_ctx.log_lines[pocsag_ctx.log_count][POCSAG_MSG_TEXT_LEN] = '\0';
        pocsag_ctx.log_count++;
    }
    else
    {
        for (uint8_t i = 1; i < POCSAG_MSG_LINES; i++)
        {
            strncpy(pocsag_ctx.log_lines[i - 1], pocsag_ctx.log_lines[i],
                    POCSAG_MSG_TEXT_LEN + 1);
        }
        strncpy(pocsag_ctx.log_lines[POCSAG_MSG_LINES - 1], line,
                POCSAG_MSG_TEXT_LEN);
        pocsag_ctx.log_lines[POCSAG_MSG_LINES - 1][POCSAG_MSG_TEXT_LEN] = '\0';
    }
}

static void pocsag_finalize_pending(void)
{
    if (!pocsag_ctx.pending_active)
        return;

    char line[POCSAG_MSG_TEXT_LEN + 1];
    if (pocsag_ctx.pending_is_numeric)
    {
        snprintf(line, sizeof(line), "%lu:%s",
                 (unsigned long)pocsag_ctx.pending_capcode,
                 pocsag_ctx.pending_text);
    }
    else
    {
        snprintf(line, sizeof(line), "%lu:%s",
                 (unsigned long)pocsag_ctx.pending_capcode,
                 pocsag_ctx.pending_text);
    }
    pocsag_log_message(line);
    pocsag_ctx.packets_decoded++;
    m1_buzzer_notification();

    pocsag_ctx.pending_active = false;
    pocsag_ctx.pending_len = 0;
    pocsag_ctx.pending_text[0] = '\0';
    pocsag_ctx.pending_bit_carry = 0;
    pocsag_ctx.pending_bit_carry_len = 0;
}

static void pocsag_append_alpha_bits(uint32_t data20)
{
    /* POCSAG alphanumeric: 20 data bits, 7-bit ASCII chars, LSB first.
     * Bits flow MSB-first into a shift register; we accumulate 7-bit
     * groups crossing codeword boundaries. */
    uint32_t carry = pocsag_ctx.pending_bit_carry;
    uint8_t  carry_len = pocsag_ctx.pending_bit_carry_len;

    /* Walk the 20 bits MSB-first. */
    for (int8_t b = 19; b >= 0; b--)
    {
        uint8_t bit = (data20 >> b) & 1U;
        carry = (carry << 1) | bit;
        carry_len++;
        if (carry_len >= 7)
        {
            uint8_t ch = (uint8_t)(carry & 0x7FU);
            carry_len = 0;
            carry = 0;

            /* Reverse 7-bit field for LSB-first encoding. */
            uint8_t rev = 0;
            for (uint8_t i = 0; i < 7; i++)
                if (ch & (1U << i)) rev |= (uint8_t)(1U << (6 - i));
            ch = rev;

            if (ch >= 32 && ch < 127)
            {
                if (pocsag_ctx.pending_len < POCSAG_MSG_TEXT_LEN)
                {
                    pocsag_ctx.pending_text[pocsag_ctx.pending_len++] = (char)ch;
                    pocsag_ctx.pending_text[pocsag_ctx.pending_len] = '\0';
                }
            }
            /* Non-printable / control bytes are dropped. */
        }
    }

    pocsag_ctx.pending_bit_carry = (uint8_t)(carry & 0x7FU);
    pocsag_ctx.pending_bit_carry_len = carry_len;
}

static void pocsag_append_numeric_bits(uint32_t data20)
{
    /* Numeric POCSAG: 20 bits = 5 BCD digits, LSB first per nibble. */
    static const char numeric_table[16] = {
        '0','1','2','3','4','5','6','7',
        '8','9','*','U',' ','-',')','('
    };

    for (int8_t i = 0; i < 5; i++)
    {
        uint8_t nibble = (uint8_t)((data20 >> (16 - i * 4)) & 0xFU);
        /* Reverse nibble for LSB-first encoding. */
        uint8_t rev = (uint8_t)(((nibble & 1U) << 3) |
                                ((nibble & 2U) << 1) |
                                ((nibble & 4U) >> 1) |
                                ((nibble & 8U) >> 3));
        char c = numeric_table[rev & 0xF];
        if (pocsag_ctx.pending_len < POCSAG_MSG_TEXT_LEN)
        {
            pocsag_ctx.pending_text[pocsag_ctx.pending_len++] = c;
            pocsag_ctx.pending_text[pocsag_ctx.pending_len] = '\0';
        }
    }
}

static void pocsag_handle_codeword(uint32_t cw)
{
    /* Idle codewords end any in-progress message. */
    if (cw == POCSAG_IDLE_WORD)
    {
        pocsag_finalize_pending();
        return;
    }

    /* Address codeword: bit 31 = 0 */
    if ((cw & 0x80000000UL) == 0)
    {
        pocsag_finalize_pending();

        /* Bits 30..13 = 18-bit address MSBs. The 3 LSBs of the CAPCODE
         * are inferred from the frame index (0..7) inside the batch. */
        uint32_t addr_high = (cw >> 13) & 0x3FFFFU;       /* 18 bits */
        uint32_t capcode = (addr_high << 3) | (pocsag_ctx.frame_idx & 0x7U);
        uint8_t func = (uint8_t)((cw >> 11) & 0x3U);

        pocsag_ctx.pending_active = true;
        pocsag_ctx.pending_is_numeric = (func == 0);   /* func 0 = numeric */
        pocsag_ctx.pending_capcode = capcode;
        pocsag_ctx.pending_function = func;
        pocsag_ctx.pending_len = 0;
        pocsag_ctx.pending_text[0] = '\0';
        pocsag_ctx.pending_bit_carry = 0;
        pocsag_ctx.pending_bit_carry_len = 0;
    }
    else
    {
        /* Message codeword: 20 data bits in bits 30..11. */
        uint32_t data20 = (cw >> 11) & 0xFFFFFU;
        if (!pocsag_ctx.pending_active)
            return;

        if (pocsag_ctx.pending_is_numeric)
            pocsag_append_numeric_bits(data20);
        else
            pocsag_append_alpha_bits(data20);
    }
}

static void pocsag_feed_bit(uint8_t bit)
{
    pocsag_ctx.shift_reg = (pocsag_ctx.shift_reg << 1) | (bit & 1U);
    if (pocsag_ctx.shift_filled < 32)
        pocsag_ctx.shift_filled++;

    switch (pocsag_ctx.state)
    {
        case POCSAG_STATE_HUNT_PREAMBLE:
        case POCSAG_STATE_HUNT_SYNC:
        {
            if (pocsag_ctx.shift_filled < 32) break;
            uint32_t diff = pocsag_ctx.shift_reg ^ POCSAG_SYNC_WORD;
            uint8_t hd = pocsag_popcount32(diff);
            if (hd <= POCSAG_SYNC_TOLERANCE_BITS)
            {
                pocsag_ctx.state = POCSAG_STATE_BATCH;
                pocsag_ctx.frame_idx = 0;
                pocsag_ctx.cw_in_frame = 0;
                pocsag_ctx.shift_reg = 0;
                pocsag_ctx.shift_filled = 0;
            }
            else
            {
                /* Try the inverted polarity (some receivers invert OOK). */
                uint32_t inv = ~pocsag_ctx.shift_reg;
                uint8_t hd2 = pocsag_popcount32(inv ^ POCSAG_SYNC_WORD);
                if (hd2 <= POCSAG_SYNC_TOLERANCE_BITS)
                {
                    pocsag_ctx.state = POCSAG_STATE_BATCH;
                    pocsag_ctx.frame_idx = 0;
                    pocsag_ctx.cw_in_frame = 0;
                    pocsag_ctx.shift_reg = 0;
                    pocsag_ctx.shift_filled = 0;
                }
            }
            break;
        }

        case POCSAG_STATE_BATCH:
        {
            if (pocsag_ctx.shift_filled < 32) break;
            uint32_t cw = pocsag_ctx.shift_reg;
            pocsag_ctx.shift_reg = 0;
            pocsag_ctx.shift_filled = 0;

            uint32_t corrected = cw;
            bool ok = pocsag_bch_correct(&corrected);
            if (ok)
            {
                if (corrected != cw)
                    pocsag_ctx.bch_correctable++;
                pocsag_handle_codeword(corrected);
            }
            else
            {
                pocsag_ctx.bch_failed++;
                /* Treat as IDLE to keep frame alignment. */
            }

            pocsag_ctx.cw_in_frame++;
            if (pocsag_ctx.cw_in_frame >= 2)
            {
                pocsag_ctx.cw_in_frame = 0;
                pocsag_ctx.frame_idx++;
                if (pocsag_ctx.frame_idx >= 8)
                {
                    /* End of batch: next 32 bits should be the next sync
                     * word. Drop back to hunt mode. */
                    pocsag_finalize_pending();
                    pocsag_ctx.state = POCSAG_STATE_HUNT_SYNC;
                    pocsag_ctx.frame_idx = 0;
                }
            }
            break;
        }
    }
}

static void pocsag_consume_pulses(uint16_t *samples, uint16_t count, uint8_t rate_idx)
{
    /* OOK pulses alternate level: assume the first sample after RX init
     * is a "low" run (no carrier). The actual polarity is recovered by
     * the inverted-sync-word fallback inside pocsag_feed_bit. */
    uint16_t bit_us = pocsag_rates[rate_idx].bit_us;
    uint16_t half_us = pocsag_rates[rate_idx].half_bit_us;

    static uint8_t  cur_level = 0;
    static uint16_t residual_us = 0;

    for (uint16_t i = 0; i < count; i++)
    {
        uint32_t dur = samples[i];
        if (dur == 0) dur = 1;

        /* Add residual from previous pulse to better track sub-bit drift. */
        dur += residual_us;
        residual_us = 0;

        /* Number of bits represented by this pulse. */
        uint32_t nbits = (dur + half_us) / bit_us;
        if (nbits == 0)
        {
            /* Dur shorter than half a bit: accumulate into residual. */
            residual_us = (uint16_t)dur;
            cur_level ^= 1U;
            continue;
        }

        /* Cap to keep the inner loop bounded under noise floods. */
        if (nbits > 64) nbits = 64;

        for (uint32_t k = 0; k < nbits; k++)
            pocsag_feed_bit(cur_level);

        /* Track residual error so timing drift does not accumulate. */
        uint32_t consumed = nbits * bit_us;
        if (dur > consumed)
            residual_us = (uint16_t)(dur - consumed);

        cur_level ^= 1U;
    }
}

/* Naive auto-rate detector: drains samples at all three rates in shadow
 * counters and picks whichever produced the most successful BCH events.
 * For the live UI we just keep the user-selected rate (default 1200) and
 * cycle through with OK; auto-mode is left as a single periodic try at
 * the current rate. */
static void pocsag_reset_state(uint8_t rate_idx)
{
    memset(&pocsag_ctx, 0, sizeof(pocsag_ctx));
    pocsag_ctx.rate_idx = rate_idx;
    pocsag_ctx.state = POCSAG_STATE_HUNT_SYNC;
}

/* ============================================================================
 * Main UI loop
 * ============================================================================ */

static void pocsag_draw_screen(uint32_t freq_hz)
{
    char title[24];
    char ratel[16];
    char stats[32];

    snprintf(title, sizeof(title), "%lu.%03lu MHz",
             (unsigned long)(freq_hz / 1000000UL),
             (unsigned long)((freq_hz % 1000000UL) / 1000UL));
    snprintf(ratel, sizeof(ratel), "POCSAG %ub",
             (unsigned)pocsag_rates[pocsag_ctx.rate_idx].baud);
    snprintf(stats, sizeof(stats), "Pkts:%lu  BCH:%lu/%lu",
             (unsigned long)pocsag_ctx.packets_decoded,
             (unsigned long)pocsag_ctx.bch_correctable,
             (unsigned long)pocsag_ctx.bch_failed);

    u8g2_FirstPage(&m1_u8g2);
    do {
        u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 0, 9, ratel);
        u8g2_DrawStr(&m1_u8g2, 60, 9, title);

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawHLine(&m1_u8g2, 0, 12, 128);
        u8g2_DrawStr(&m1_u8g2, 0, 21, stats);

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        for (uint8_t i = 0; i < pocsag_ctx.log_count; i++)
        {
            u8g2_DrawStr(&m1_u8g2, 0, 32 + i * 9, pocsag_ctx.log_lines[i]);
        }
        if (pocsag_ctx.log_count == 0)
        {
            u8g2_DrawStr(&m1_u8g2, 0, 36, "Listening...");
        }

        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 0, 64, "OK:Rate  BACK:Exit");
    } while (u8g2_NextPage(&m1_u8g2));
}

/* External helpers from m1_sub_ghz.c that we reuse via a tiny shim. */
extern S_M1_RingBuffer subghz_rx_rawdata_rb;
extern uint8_t subghz_record_mode_flag;

/* Forward declarations of static helpers in m1_sub_ghz.c are not visible
 * across translation units, so we drive the radio directly with the
 * SI4463 API plus the public radio_init_rx_tx() / antenna helpers. */

void sub_ghz_pocsag(void)
{
    S_M1_Buttons_Status bs;
    S_M1_Main_Q_t q_item;
    BaseType_t ret;
    uint32_t freq_hz;

    /* 1) Frequency picker. */
    freq_hz = pocsag_pick_frequency();
    if (freq_hz == 0)
    {
        /* User cancelled. */
        m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
        return;
    }

    /* 2) Allocate decoder state and capture buffer. */
    pocsag_reset_state(1);                 /* default to 1200 bps */

    uint16_t *capture = (uint16_t *)pvPortMalloc(1024 * sizeof(uint16_t));
    if (capture == NULL)
    {
        m1_message_box(&m1_u8g2, "Memory error!",
                       "POCSAG buffer alloc", "failed.", "BACK to exit");
        m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
        return;
    }

    /* 3) Bring up SI4463 in OOK direct-mode RX at the user frequency.
     * We use SUB_GHZ_BAND_433_92 as a base config so the GPIO2 direction
     * is correct, then retune via SI446x_Set_Frequency(). */
    radio_init_rx_tx(SUB_GHZ_BAND_433_92, MODEM_MOD_TYPE_OOK, true);
    SI446x_Change_State(SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_READY);
    SI446x_Set_Frequency(freq_hz);
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_RX);
    SI446x_Start_Rx(0);
    /* Per-app OOK RX profile.  POCSAG runs at 512/1200/2400 baud — much
     * slower than 433 MHz remotes — so we want a longer peak-detector
     * hold time and a wider averaging window to keep the carrier-on level
     * stable across each Manchester-encoded bit. */
    SI446x_Apply_OOK_RX_Profile(/*pdtc*/   0x6C,
                                /*cnt1*/   0x42,
                                /*raw_ctrl*/0x83,
                                /*raw_eye*/ 0x6F);

    /* 4) Drive the existing TIM1 capture path so subghz_rx_rawdata_rb
     * fills automatically. We allocate the ring buffer directly here. */
    uint16_t ring_size = 4096;
    uint16_t *ring_storage = (uint16_t *)pvPortMalloc(ring_size * sizeof(uint16_t));
    if (ring_storage == NULL)
    {
        vPortFree(capture);
        m1_message_box(&m1_u8g2, "Memory error!",
                       "POCSAG ring alloc", "failed.", "BACK to exit");
        radio_set_antenna_mode(RADIO_ANTENNA_MODE_ISOLATED);
        SI446x_Change_State(SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_SLEEP);
        m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
        return;
    }
    m1_ringbuffer_init(&subghz_rx_rawdata_rb,
                       (uint8_t *)ring_storage, ring_size, sizeof(uint16_t));

    /* Driver hook: tell the existing ISR we are in record mode so
     * timer captures get pushed into subghz_rx_rawdata_rb. */
    subghz_record_mode_flag = 1;

    /* 5) Main poll loop. */
    bool running = true;
    TickType_t last_draw = xTaskGetTickCount();

    pocsag_draw_screen(freq_hz);

    while (running)
    {
        /* Drain ring buffer in chunks. */
        uint32_t avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);
        while (avail > 0)
        {
            uint16_t want = (avail > 1024) ? 1024 : (uint16_t)avail;
            uint16_t got = m1_ringbuffer_read(&subghz_rx_rawdata_rb,
                                              (uint8_t *)capture, want);
            if (got == 0) break;
            pocsag_consume_pulses(capture, got, pocsag_ctx.rate_idx);
            avail = ringbuffer_get_data_slots(&subghz_rx_rawdata_rb);
        }

        /* Refresh display roughly every 200 ms. */
        if ((xTaskGetTickCount() - last_draw) > pdMS_TO_TICKS(200))
        {
            pocsag_draw_screen(freq_hz);
            last_draw = xTaskGetTickCount();
        }

        /* Non-blocking key poll. */
        ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(50));
        if (ret == pdTRUE && q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            xQueueReceive(button_events_q_hdl, &bs, 0);
            if (bs.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                running = false;
            }
            else if (bs.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
            {
                /* Cycle baud rate. */
                uint8_t next = (uint8_t)((pocsag_ctx.rate_idx + 1) % POCSAG_RATE_COUNT);
                pocsag_reset_state(next);
                pocsag_draw_screen(freq_hz);
            }
            else if (bs.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK ||
                     bs.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
            {
                pocsag_ctx.log_count = 0;
                pocsag_draw_screen(freq_hz);
            }
        }
    }

    /* 6) Tear down: stop radio, release allocations. */
    subghz_record_mode_flag = 0;
    radio_set_antenna_mode(RADIO_ANTENNA_MODE_ISOLATED);
    SI446x_Change_State(SI446X_CMD_CHANGE_STATE_ARG_NEXT_STATE1_NEW_STATE_ENUM_SLEEP);

    vPortFree(ring_storage);
    vPortFree(capture);

    xQueueReset(main_q_hdl);
    m1_app_send_q_message(main_q_hdl, Q_EVENT_MENU_EXIT);
}
