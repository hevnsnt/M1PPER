/* See COPYING.txt for license details. */

/*
 * app_ibutton.c
 *
 * Dallas / Maxim iButton 1-Wire ROM-code reader.
 *
 * Bit-bangs the 1-Wire protocol on a single GPIO and decodes the 8-byte ROM
 * code from any single device on the bus (DS1990A / DS1990R and friends).
 * No transactional read of memory pages — for a plain ID iButton just the
 * ROM code is the unique identifier.
 *
 * GPIO assignment:
 *   By default the bus runs on PE6 (the M1's exposed GP4 pin) — change the
 *   M1_IBUTTON_PORT / M1_IBUTTON_PIN macros below if your hardware wires the
 *   iButton probe elsewhere.  An external 4.7kΩ pull-up to 3V3 is required.
 *
 * Microsecond timing:
 *   The STM32H573 runs at 250 MHz with the DWT cycle counter enabled (see
 *   m1_rgb_backlight.c for the same trick).  We use DWT->CYCCNT directly so
 *   our delays are exact even with FreeRTOS interrupts left enabled at the
 *   process-level — for the read/write atoms we briefly mask interrupts to
 *   keep within the 1-Wire master timing windows.
 *
 * M1 Project
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "m1_compile_cfg.h"

#ifdef M1_APP_IBUTTON_ENABLE

#include "app_ibutton.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_buzzer.h"
#include "m1_system.h"
#include "ff.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

extern QueueHandle_t main_q_hdl;
extern QueueHandle_t button_events_q_hdl;

/*-----------------------------------------------------------------------------
 * GPIO assignment.  Configure here for your hardware revision if PE6 is
 * already taken.  PE6 is part of the M1's external GPIO header and is left
 * floating by default.
 *---------------------------------------------------------------------------*/
#ifndef M1_IBUTTON_PORT
#define M1_IBUTTON_PORT    GPIOE
#endif
#ifndef M1_IBUTTON_PIN
#define M1_IBUTTON_PIN     GPIO_PIN_6
#endif

/* Save destination */
#define IBUTTON_DIR        "0:/iButton"
#define IBUTTON_SAVE_PATH  "0:/iButton/saved.txt"

/* 1-Wire timing constants (microseconds), Dallas standard mode. */
#define OW_RESET_LOW_US        500U   /* master pulls low */
#define OW_RESET_RELEASE_US     70U   /* wait before sampling presence */
#define OW_RESET_RECOVER_US    410U   /* remainder of the reset slot     */
#define OW_WRITE0_LOW_US        65U
#define OW_WRITE0_REC_US        10U
#define OW_WRITE1_LOW_US         6U
#define OW_WRITE1_REC_US        64U
#define OW_READ_LOW_US           6U
#define OW_READ_SAMPLE_US        9U   /* total ~15us from start of slot */
#define OW_READ_REC_US          55U

/* DWT-based microsecond delay.  At 250MHz, 1us = 250 cycles.  We read
 * SystemCoreClock at runtime so this stays correct if the rate ever changes. */
static inline void ow_delay_us(uint32_t us)
{
    uint32_t start  = DWT->CYCCNT;
    uint32_t cycles = (SystemCoreClock / 1000000U) * us;
    while ((uint32_t)(DWT->CYCCNT - start) < cycles) { /* spin */ }
}

/*-----------------------------------------------------------------------------
 * GPIO direction helpers.  1-Wire is open-drain so we simulate by toggling
 * between push-pull-low and input-floating modes.  An external pull-up does
 * the rest.
 *---------------------------------------------------------------------------*/
static void ow_pin_low(void)
{
    GPIO_InitTypeDef io = {0};
    io.Pin   = M1_IBUTTON_PIN;
    io.Mode  = GPIO_MODE_OUTPUT_PP;
    io.Pull  = GPIO_NOPULL;
    io.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(M1_IBUTTON_PORT, &io);
    HAL_GPIO_WritePin(M1_IBUTTON_PORT, M1_IBUTTON_PIN, GPIO_PIN_RESET);
}

static void ow_pin_release(void)
{
    GPIO_InitTypeDef io = {0};
    io.Pin   = M1_IBUTTON_PIN;
    io.Mode  = GPIO_MODE_INPUT;
    io.Pull  = GPIO_PULLUP;          /* internal weak pull-up as a safety net */
    io.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(M1_IBUTTON_PORT, &io);
}

static uint8_t ow_pin_read(void)
{
    return (HAL_GPIO_ReadPin(M1_IBUTTON_PORT, M1_IBUTTON_PIN) == GPIO_PIN_SET) ? 1U : 0U;
}

/*-----------------------------------------------------------------------------
 * Reset pulse.  Returns true if a presence pulse is detected (a slave is
 * holding the bus low after our release).
 *---------------------------------------------------------------------------*/
static bool ow_reset(void)
{
    bool presence;

    ow_pin_release();
    ow_delay_us(5U);

    __disable_irq();
    ow_pin_low();
    ow_delay_us(OW_RESET_LOW_US);
    ow_pin_release();
    ow_delay_us(OW_RESET_RELEASE_US);
    presence = (ow_pin_read() == 0U);
    __enable_irq();

    ow_delay_us(OW_RESET_RECOVER_US);
    return presence;
}

static void ow_write_bit(uint8_t bit)
{
    __disable_irq();
    if (bit & 1U)
    {
        ow_pin_low();
        ow_delay_us(OW_WRITE1_LOW_US);
        ow_pin_release();
        ow_delay_us(OW_WRITE1_REC_US);
    }
    else
    {
        ow_pin_low();
        ow_delay_us(OW_WRITE0_LOW_US);
        ow_pin_release();
        ow_delay_us(OW_WRITE0_REC_US);
    }
    __enable_irq();
}

static uint8_t ow_read_bit(void)
{
    uint8_t bit;
    __disable_irq();
    ow_pin_low();
    ow_delay_us(OW_READ_LOW_US);
    ow_pin_release();
    ow_delay_us(OW_READ_SAMPLE_US);
    bit = ow_pin_read();
    __enable_irq();
    ow_delay_us(OW_READ_REC_US);
    return bit;
}

static void ow_write_byte(uint8_t b)
{
    for (uint8_t i = 0U; i < 8U; i++)
    {
        ow_write_bit(b & 0x01U);
        b >>= 1;
    }
}

static uint8_t ow_read_byte(void)
{
    uint8_t b = 0U;
    for (uint8_t i = 0U; i < 8U; i++)
    {
        b >>= 1;
        if (ow_read_bit())
            b |= 0x80U;
    }
    return b;
}

/*-----------------------------------------------------------------------------
 * Dallas/Maxim CRC-8 (polynomial x^8 + x^5 + x^4 + 1, init 0).
 *---------------------------------------------------------------------------*/
static uint8_t ow_crc8(const uint8_t *data, uint8_t len)
{
    uint8_t crc = 0U;
    for (uint8_t i = 0U; i < len; i++)
    {
        uint8_t byte = data[i];
        for (uint8_t j = 0U; j < 8U; j++)
        {
            uint8_t mix = (crc ^ byte) & 0x01U;
            crc >>= 1;
            if (mix) crc ^= 0x8CU;
            byte >>= 1;
        }
    }
    return crc;
}

/*-----------------------------------------------------------------------------
 * Family-code → human readable label.
 *---------------------------------------------------------------------------*/
static const char *ow_family_label(uint8_t family)
{
    switch (family)
    {
        case 0x01: return "DS1990A - ID";
        case 0x81: return "DS1990R - ID";
        case 0x02: return "DS1991 Multikey";
        case 0x04: return "DS1994 RTC+Mem";
        case 0x06: return "DS1993 Memory";
        case 0x08: return "DS1992 Memory";
        case 0x0A: return "DS1995 Memory";
        case 0x0C: return "DS1996 Memory";
        case 0x12: return "DS2406 Switch";
        default:   return "Unknown";
    }
}

/*-----------------------------------------------------------------------------
 * High-level: do a Read-ROM (0x33) and decode.  Returns true on success and
 * fills rom[8] with family-code, 6-byte serial, CRC.
 *---------------------------------------------------------------------------*/
static bool ow_read_rom(uint8_t rom[8])
{
    if (!ow_reset())
        return false;

    ow_write_byte(0x33U); /* READ ROM */
    for (uint8_t i = 0U; i < 8U; i++)
        rom[i] = ow_read_byte();

    /* 0x00 / 0xFF are bus-idle indicators (no device, or floating). */
    bool all_zero = true, all_one = true;
    for (uint8_t i = 0U; i < 8U; i++)
    {
        if (rom[i] != 0x00U) all_zero = false;
        if (rom[i] != 0xFFU) all_one  = false;
    }
    if (all_zero || all_one) return false;

    return true;
}

/*=============================================================================
 *  S A V E  T O  S D
 *===========================================================================*/
static bool ibutton_save_rom(const uint8_t rom[8])
{
    FIL  fp;
    UINT bw;
    char line[48];

    f_mkdir(IBUTTON_DIR);

    /* Open in append mode (create if missing). */
    FRESULT res = f_open(&fp, IBUTTON_SAVE_PATH, FA_OPEN_APPEND | FA_WRITE);
    if (res != FR_OK)
        res = f_open(&fp, IBUTTON_SAVE_PATH, FA_OPEN_ALWAYS | FA_WRITE);
    if (res != FR_OK)
        return false;
    /* Seek to end (FA_OPEN_APPEND should already, but belt + braces). */
    f_lseek(&fp, f_size(&fp));

    int n = snprintf(line, sizeof(line),
                     "%s:%02X%02X%02X%02X%02X%02X%02X%02X\n",
                     ow_family_label(rom[0]),
                     rom[0], rom[1], rom[2], rom[3],
                     rom[4], rom[5], rom[6], rom[7]);
    bool ok = false;
    if (n > 0)
    {
        if (f_write(&fp, line, (UINT)n, &bw) == FR_OK && bw == (UINT)n)
            ok = true;
    }
    f_close(&fp);
    return ok;
}

/*=============================================================================
 *  U I
 *===========================================================================*/
static void ibutton_draw_touch(void)
{
    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "iButton Reader");

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 24, "Touch iButton to M1");
        u8g2_DrawStr(&m1_u8g2, 2, 36, "(probe on GP4 pin)");

        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "", NULL);
    } while (m1_u8g2_nextpage());
}

static void ibutton_draw_reading(uint8_t dots)
{
    char buf[16];
    buf[0] = 'R'; buf[1] = 'e'; buf[2] = 'a'; buf[3] = 'd';
    buf[4] = 'i'; buf[5] = 'n'; buf[6] = 'g';
    uint8_t i;
    for (i = 0U; i < (dots % 4U); i++) buf[7U + i] = '.';
    buf[7U + i] = '\0';

    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "iButton Reader");
        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 2, 30, buf);
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "", NULL);
    } while (m1_u8g2_nextpage());
}

static void ibutton_draw_result(const uint8_t rom[8], bool crc_ok)
{
    char id_line[40];
    snprintf(id_line, sizeof(id_line),
             "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             rom[0], rom[1], rom[2], rom[3],
             rom[4], rom[5], rom[6], rom[7]);

    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "iButton ID");

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 22, id_line);
        u8g2_DrawStr(&m1_u8g2, 2, 34, ow_family_label(rom[0]));
        u8g2_DrawStr(&m1_u8g2, 2, 46, crc_ok ? "CRC: OK" : "CRC: BAD");

        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Save", arrowright_8x8);
    } while (m1_u8g2_nextpage());
}

static void ibutton_draw_saved(void)
{
    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "iButton Reader");
        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 2, 26, "Saved!");
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 38, "iButton/saved.txt");
        u8g2_DrawStr(&m1_u8g2, 2, 50, "OK=read another");
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Again", arrowright_8x8);
    } while (m1_u8g2_nextpage());
}

static void ibutton_draw_save_failed(void)
{
    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "iButton Reader");
        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 2, 26, "Save failed");
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 38, "Check SD card");
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Again", arrowright_8x8);
    } while (m1_u8g2_nextpage());
}

/*===========================================================================*/
/**
 * @brief  Drain the main queue and return whether BACK / OK were pressed.
 *         Returns:  -1 = back, +1 = ok/right, 0 = nothing.
 */
/*===========================================================================*/
static int ibutton_poll_buttons(uint32_t wait_ms)
{
    S_M1_Main_Q_t       q_item;
    S_M1_Buttons_Status btn;
    BaseType_t          ret;

    if (main_q_hdl == NULL) return 0;

    ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(wait_ms));
    if (ret != pdTRUE) return 0;
    if (q_item.q_evt_type != Q_EVENT_KEYPAD) return 0;
    if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) return 0;

    if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
     || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
        return -1;
    if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK
     || btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
        return +1;
    return 0;
}

/*===========================================================================*/
/**
 * @brief  Top-level entry point.
 */
/*===========================================================================*/
void app_ibutton_run(void)
{
    uint8_t rom[8];

    /* Make sure DWT cycle counter is running (set up once during init,
     * but enable defensively in case nobody else has touched it yet). */
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL        |= DWT_CTRL_CYCCNTENA_Msk;

    if (main_q_hdl != NULL) xQueueReset(main_q_hdl);

    /* The bus must idle high (released).  Configure pin and let it pull up. */
    ow_pin_release();
    vTaskDelay(pdMS_TO_TICKS(2));

    while (1)
    {
        /* ---- Touch screen: wait for a presence pulse OR back ------------ */
        ibutton_draw_touch();

        bool got_id    = false;
        bool crc_ok    = false;
        uint8_t dots   = 0U;
        bool exiting   = false;

        while (!got_id && !exiting)
        {
            /* Quick reset attempt; presence pulse means an iButton is
             * physically touching the contacts. */
            if (ow_reset())
            {
                /* Show "Reading..." then issue the actual read */
                ibutton_draw_reading(dots++);
                if (ow_read_rom(rom))
                {
                    crc_ok = (ow_crc8(rom, 7U) == rom[7]);
                    got_id = true;
                    break;
                }
            }

            /* Wait ~120ms between probes — enough for the user to reposition
             * the iButton without flooding the bus. */
            int b = ibutton_poll_buttons(120U);
            if (b == -1)
            {
                exiting = true;
                break;
            }
        }

        if (exiting) break;

        if (got_id)
        {
            m1_buzzer_notification();
            ibutton_draw_result(rom, crc_ok);

            /* Wait for OK (save) or BACK (cancel) */
            int choice = 0;
            while (choice == 0)
            {
                choice = ibutton_poll_buttons(portMAX_DELAY);
            }

            if (choice == +1)
            {
                if (ibutton_save_rom(rom))
                {
                    m1_buzzer_notification();
                    ibutton_draw_saved();
                }
                else
                {
                    ibutton_draw_save_failed();
                }
                /* Wait for choice to read another or exit */
                int next_choice = 0;
                while (next_choice == 0)
                {
                    next_choice = ibutton_poll_buttons(portMAX_DELAY);
                }
                if (next_choice == -1) break;
                /* +1 = read another -> loop back to touch screen */
            }
            else
            {
                /* BACK from result screen -> exit app */
                break;
            }
        }
    }

    /* Restore pin to safe-floating state */
    ow_pin_release();
    if (main_q_hdl != NULL) xQueueReset(main_q_hdl);
}

#endif /* M1_APP_IBUTTON_ENABLE */
