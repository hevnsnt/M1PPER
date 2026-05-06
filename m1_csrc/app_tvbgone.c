/* See COPYING.txt for license details. */

/*
 * app_tvbgone.c
 *
 * TV-B-Gone: blast a curated database of universal TV power-off IR codes
 * across the major brands (Samsung, LG, Sony, Panasonic, Philips, etc.)
 * using the M1's existing IR transmit hardware.
 *
 * Codes are sent through the IRMP/IRSND protocol stack already used by the
 * "Saved Remotes" replay path so all carrier and pulse timing is handled by
 * the firmware's hardware-timer state machine. We only need to populate an
 * IRMP_DATA structure and feed it to irsnd_generate_tx_data() /
 * infrared_transmit().
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

#ifdef M1_APP_TVBGONE_ENABLE

#include "app_tvbgone.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_buzzer.h"
#include "m1_infrared.h"
#include "irmp.h"
#include "irsnd.h"
#include "irmpprotocols.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include <stdlib.h>
#include "ff.h"

/* Externals owned by m1_infrared.c */
extern QueueHandle_t main_q_hdl;
extern QueueHandle_t button_events_q_hdl;

/*-----------------------------------------------------------------------------
 * Code database
 *
 * Each entry corresponds to a (protocol, address, command) tuple that decodes
 * to a "POWER" key for the named brand on the IRMP/IRSND stack.  Several of
 * the manufacturer-specified payloads are inverted by the wire encoding (NEC
 * sends address-low, ~address-low, command, ~command) — the IRMP API expects
 * the *logical* address/command, so we store those.
 *
 * The repeats field is for the auto-repeat logic of the IRSND state machine:
 * 2 means the frame is sent followed by a single repeat, which is what nearly
 * every real TV remote does for a single keypress.  Sony SIRC requires the
 * frame be sent three times back-to-back to be reliably accepted, so we use
 * 3 there.
 *---------------------------------------------------------------------------*/
typedef struct
{
    char        brand[24];   /* short label for UI; copied so SD path owns its own string */
    uint8_t     protocol;    /* IRMP_*_PROTOCOL */
    uint16_t    address;
    uint16_t    command;
    uint8_t     repeats;     /* 1 = single, >=2 = with auto-repeat */
} tvbgone_code_t;

static const tvbgone_code_t s_default_codes[] =
{
    /* NEC family --------------------------------------------------------- */
    { "Samsung",    IRMP_NEC_PROTOCOL,        0x0707, 0x02FD, 2 },
    { "Samsung 2",  IRMP_SAMSUNG32_PROTOCOL,  0x0707, 0x02FD, 2 },
    { "LG",         IRMP_NEC_PROTOCOL,        0x0400, 0x08F7, 2 },
    { "Toshiba",    IRMP_NEC_PROTOCOL,        0x02FD, 0x40BF, 2 },
    { "Hisense",    IRMP_NEC_PROTOCOL,        0x0000, 0xD02F, 2 },
    { "TCL/RCA",    IRMP_NEC_PROTOCOL,        0xFF00, 0x0CF3, 2 },
    { "Vizio",      IRMP_NEC_PROTOCOL,        0x0F0F, 0x09F6, 2 },
    { "Haier",      IRMP_NEC_PROTOCOL,        0x0000, 0xC23D, 2 },
    { "Insignia",   IRMP_NEC_PROTOCOL,        0xBB44, 0xDA25, 2 },
    { "Element",    IRMP_NEC_PROTOCOL,        0xFFFF, 0xA25D, 2 },
    { "Sansui",     IRMP_NEC_PROTOCOL,        0x0202, 0x01FE, 2 },
    { "Panasonic",  IRMP_KASEIKYO_PROTOCOL,   0x5AA5, 0x002D, 2 },
    { "Sharp",      IRMP_DENON_PROTOCOL,      0x0001, 0x00CB, 2 },
    { "Philips",    IRMP_RC5_PROTOCOL,        0x0000, 0x000C, 2 },
    { "Sony Bravia",IRMP_SIRCS_PROTOCOL,      0x0001, 0x0095, 3 },
    { "Sony older", IRMP_SIRCS_PROTOCOL,      0x0001, 0x0015, 3 },
};
#define TVBGONE_DEFAULT_COUNT  ((uint8_t)(sizeof(s_default_codes) / sizeof(s_default_codes[0])))

/* Runtime DB filled either from /IR/tvbgone.txt or the in-flash defaults.
 * audit 07 finding "TV-B-Gone code DB from SD".  Fallback path keeps
 * existing behavior intact when the SD file is missing or invalid. */
#define TVBGONE_RUNTIME_MAX    96U
static tvbgone_code_t s_runtime_codes[TVBGONE_RUNTIME_MAX];
static const tvbgone_code_t *s_codes        = s_default_codes;
static uint8_t               s_codes_count  = TVBGONE_DEFAULT_COUNT;
#define TVBGONE_CODE_COUNT  s_codes_count
#define TVBGONE_SD_DB_PATH  "0:/IR/tvbgone.txt"

static bool tvbgone_parse_line(const char *line, tvbgone_code_t *out)
{
    const char *p = line;
    const char *brand_start;
    size_t brand_len;
    char *endp;
    long protocol_l, address_l, command_l, repeats_l;

    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '#' || *p == '\r' || *p == '\n') return false;
    brand_start = p;
    while (*p && *p != ',') p++;
    if (*p != ',') return false;
    brand_len = (size_t)(p - brand_start);
    if (brand_len == 0U || brand_len >= sizeof(out->brand)) return false;
    p++;
    protocol_l = strtol(p, &endp, 0); if (endp == p || *endp != ',') return false; p = endp + 1;
    address_l  = strtol(p, &endp, 0); if (endp == p || *endp != ',') return false; p = endp + 1;
    command_l  = strtol(p, &endp, 0); if (endp == p || *endp != ',') return false; p = endp + 1;
    repeats_l  = strtol(p, &endp, 0); if (endp == p) return false;
    if (protocol_l < 0 || protocol_l > 0x7F)   return false;
    if (address_l  < 0 || address_l  > 0xFFFF) return false;
    if (command_l  < 0 || command_l  > 0xFFFF) return false;
    if (repeats_l  < 1) repeats_l = 1;
    if (repeats_l  > 8) repeats_l = 8;
    memcpy(out->brand, brand_start, brand_len);
    out->brand[brand_len] = '\0';
    out->protocol = (uint8_t)protocol_l;
    out->address  = (uint16_t)address_l;
    out->command  = (uint16_t)command_l;
    out->repeats  = (uint8_t)repeats_l;
    return true;
}

static void tvbgone_try_load_sd_db(void)
{
    static bool loaded_once = false;
    if (loaded_once) return;
    loaded_once = true;
    FIL fp;
    if (f_open(&fp, TVBGONE_SD_DB_PATH, FA_READ | FA_OPEN_EXISTING) != FR_OK) return;
    char line[96];
    uint8_t parsed = 0U;
    while (f_gets(line, sizeof(line), &fp) != NULL && parsed < TVBGONE_RUNTIME_MAX) {
        if (tvbgone_parse_line(line, &s_runtime_codes[parsed])) parsed++;
    }
    f_close(&fp);
    if (parsed > 0U) {
        s_codes = s_runtime_codes;
        s_codes_count = parsed;
    }
}

/* Inter-brand gap (ms).  The IRSND auto-repeat already inserts protocol
 * specific repeat-frame pauses (~108ms for NEC, ~45ms for SIRC) so we only
 * add a small extra gap so users can see the on-screen brand cycle.       */
#define TVBGONE_BRAND_GAP_MS    50U

/* Maximum time (ms) we wait for the IRSND TX state machine to drain a single
 * code before bailing out.  In practice every code completes well under this
 * threshold — it just guards against a stuck timer interrupt.             */
#define TVBGONE_TX_TIMEOUT_MS   1500U

/*===========================================================================*/
/**
 * @brief   Render the TV-B-Gone progress screen.
 *
 *           +--------------------------------+
 *           | TV-B-Gone                      |
 *           | Sending codes...               |
 *           | [████████░░] 7/15              |
 *           | Sony Bravia                    |
 *           | Press BACK to stop             |
 *           +--------------------------------+
 *
 * @param   index    Zero-based index of the code currently transmitting
 * @param   total    Total number of codes in the database
 * @param   brand    NULL-terminated brand string for the current code
 */
/*===========================================================================*/
static void tvbgone_draw(uint8_t index, uint8_t total, const char *brand)
{
    char counter[16];
    uint8_t fill_w;

    /* Progress bar geometry: 100 px wide bar at x=4..104, y=24..30 */
    if (total == 0U)
        fill_w = 0U;
    else
        fill_w = (uint8_t)(((uint16_t)index * 100U) / total);
    if (fill_w > 100U) fill_w = 100U;

    snprintf(counter, sizeof(counter), "%u/%u",
             (unsigned)(index + 1U > total ? total : index + 1U),
             (unsigned)total);

    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);

        /* Title */
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "TV-B-Gone");

        /* Status line */
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 20, "Sending codes...");

        /* Progress bar frame */
        u8g2_DrawFrame(&m1_u8g2, 2, 24, 102, 7);
        if (fill_w > 0U)
            u8g2_DrawBox(&m1_u8g2, 3, 25, fill_w, 5);

        /* Counter */
        u8g2_DrawStr(&m1_u8g2, 106, 30, counter);

        /* Brand currently transmitting */
        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
        if (brand != NULL)
            u8g2_DrawStr(&m1_u8g2, 2, 42, brand);

        /* Bottom hint bar */
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Stop", "", NULL);
    } while (m1_u8g2_nextpage());
}

/*===========================================================================*/
/**
 * @brief   Render the "all done" screen and wait for user acknowledge.
 */
/*===========================================================================*/
static void tvbgone_draw_done(uint8_t total)
{
    char counter[24];
    snprintf(counter, sizeof(counter), "%u codes sent", (unsigned)total);

    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "TV-B-Gone");
        u8g2_SetFont(&m1_u8g2, M1_DISP_SUB_MENU_FONT_B);
        u8g2_DrawStr(&m1_u8g2, 2, 26, "Done!");
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 40, counter);
        u8g2_DrawStr(&m1_u8g2, 2, 50, "BACK to exit, OK to repeat");
        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "Repeat", arrowright_8x8);
    } while (m1_u8g2_nextpage());
}

/*===========================================================================*/
/**
 * @brief   Drain any stale events that may already be in the main queue.
 */
/*===========================================================================*/
static void tvbgone_flush_queue(void)
{
    if (main_q_hdl != NULL)
        xQueueReset(main_q_hdl);
}

/*===========================================================================*/
/**
 * @brief   Check whether the user pressed BACK or LEFT.
 *
 * @return  true if user wants to abort.
 */
/*===========================================================================*/
static bool tvbgone_back_pressed(void)
{
    S_M1_Main_Q_t       q_item;
    S_M1_Buttons_Status btn;
    BaseType_t          ret;

    if (main_q_hdl == NULL)
        return false;

    ret = xQueueReceive(main_q_hdl, &q_item, 0);
    if (ret != pdTRUE)
        return false;

    if (q_item.q_evt_type != Q_EVENT_KEYPAD)
        return false;

    if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE)
        return false;

    if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
     || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return true;
    }
    return false;
}

/*===========================================================================*/
/**
 * @brief   Wait for either an OK press or BACK press on the "done" screen.
 *
 * @return  true if user pressed OK / RIGHT (repeat), false on BACK / LEFT.
 */
/*===========================================================================*/
static bool tvbgone_wait_done_choice(void)
{
    S_M1_Main_Q_t       q_item;
    S_M1_Buttons_Status btn;

    if (main_q_hdl == NULL)
        return false;

    while (1)
    {
        if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE)
            continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD)
            continue;
        if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE)
            continue;

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
         || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
            return false;
        if (btn.event[BUTTON_OK_KP_ID]   == BUTTON_EVENT_CLICK
         || btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
            return true;
    }
}

/*===========================================================================*/
/**
 * @brief   Send a single code and block until the IR transmit state machine
 *          reports completion (or the user aborts via BACK).
 *
 *          The TX flow mirrors infrared_saved_remotes() in m1_infrared.c:
 *          we generate the OTA bitstream, kick off infrared_transmit(1),
 *          then service the pump from the main queue waiting for either a
 *          Q_EVENT_IRRED_TX completion or BACK button.
 *
 * @return  true on completion, false if user aborted.
 */
/*===========================================================================*/
static bool tvbgone_send_one(const tvbgone_code_t *code, bool *abort_out)
{
    IRMP_DATA           ir;
    S_M1_Main_Q_t       q_item;
    S_M1_Buttons_Status btn;
    BaseType_t          ret;
    TickType_t          deadline;
    bool                done = false;

    *abort_out = false;

    memset(&ir, 0, sizeof(ir));
    ir.protocol = code->protocol;
    ir.address  = code->address;
    ir.command  = code->command;
    /* Bit 0 of irsnd 'flags' is the auto-repeat count.  Use 0 for a single
     * frame, otherwise (repeats - 1) auto-repetition frames will follow.   */
    ir.flags    = (uint8_t)((code->repeats > 0U) ? (code->repeats - 1U) : 0U);

    /* Re-initialise the IRSND back-end so it picks up the protocol-specific
     * carrier frequency and frame timing for this code. */
    irsnd_init(&Timerhdl_IrCarrier, IR_ENCODE_TIMER_TX_CHANNEL);
    /* Tiny settle delay required by the TX hardware after re-init.  20ms
     * matches the same pattern in infrared_saved_remotes().                */
    vTaskDelay(pdMS_TO_TICKS(20));

    if (!irsnd_generate_tx_data(ir))
    {
        /* Couldn't encode (shouldn't happen for known protocols) — skip.   */
        return false;
    }

    infrared_transmit(1); /* (re)initialise TX state machine */
    deadline = xTaskGetTickCount() + pdMS_TO_TICKS(TVBGONE_TX_TIMEOUT_MS);

    while (!done)
    {
        /* Pump the TX state machine — it self-clocks via timer ISR but the
         * state transitions are advanced from this caller. */
        infrared_transmit(0);

        TickType_t now = xTaskGetTickCount();
        TickType_t wait;
        if (deadline > now)
            wait = deadline - now;
        else
            break; /* timeout */

        ret = xQueueReceive(main_q_hdl, &q_item, wait);
        if (ret != pdTRUE)
            break; /* timeout — assume done */

        if (q_item.q_evt_type == Q_EVENT_KEYPAD)
        {
            if (xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE)
            {
                if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
                 || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
                {
                    *abort_out = true;
                    /* Cancel any in-flight TX so the next code can run if
                     * the user is just stepping past, but we still bail.  */
                    if (ir_ota_data_tx_active)
                        m1_ir_ota_frame_post_process(0xFF);
                    return false;
                }
            }
        }
        else if (q_item.q_evt_type == Q_EVENT_IRRED_TX)
        {
            done = true;
        }
    }

    /* If we fell through the loop without seeing the TX complete event but
     * the hardware is still busy, force a graceful reset so the next code
     * can start with a clean state. */
    if (ir_ota_data_tx_active)
        m1_ir_ota_frame_post_process(0xFF);

    return true;
}

/*===========================================================================*/
/**
 * @brief   Run a single full sweep of every code.
 *
 * @return  true if completed normally, false if user aborted.
 */
/*===========================================================================*/
static bool tvbgone_blast_all(void)
{
    bool abort_flag = false;

    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_M, LED_FASTBLINK_ONTIME_M);

    for (uint8_t i = 0U; i < TVBGONE_CODE_COUNT; i++)
    {
        tvbgone_draw(i, TVBGONE_CODE_COUNT, s_codes[i].brand);

        /* Quick check for early abort before we commit to this code. */
        if (tvbgone_back_pressed())
        {
            abort_flag = true;
            break;
        }

        (void)tvbgone_send_one(&s_codes[i], &abort_flag);
        if (abort_flag)
            break;

        /* Brand gap so the user can see the on-screen progress. */
        vTaskDelay(pdMS_TO_TICKS(TVBGONE_BRAND_GAP_MS));
    }

    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_OFF, LED_FASTBLINK_ONTIME_OFF);
    return !abort_flag;
}

/*===========================================================================*/
/**
 * @brief   Top-level entry point invoked from the menu.
 */
/*===========================================================================*/
void app_tvbgone_run(void)
{
    bool repeat;

    /* audit 07: try /IR/tvbgone.txt before falling back to in-flash list. */
    tvbgone_try_load_sd_db();

    tvbgone_flush_queue();
    infrared_encode_sys_init();

    do
    {
        repeat = false;
        if (tvbgone_blast_all())
        {
            m1_buzzer_notification();
            tvbgone_draw_done(TVBGONE_CODE_COUNT);
            repeat = tvbgone_wait_done_choice();
        }
    } while (repeat);

    infrared_encode_sys_deinit();
    tvbgone_flush_queue();
}

#endif /* M1_APP_TVBGONE_ENABLE */
