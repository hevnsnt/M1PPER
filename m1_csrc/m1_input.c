/* See COPYING.txt for license details. */

/*
 *
 * m1_input.c
 *
 * Implementation of `m1_app_poll_button`. Migrated from m1_games.c so that
 * non-game apps can share the helper without pulling in a "games" header.
 *
 * M1 Project
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include "stm32h5xx_hal.h"
#include "FreeRTOS.h"
#include "queue.h"
#include "main.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_input.h"

m1_button_t m1_app_poll_button(uint32_t timeout_ms)
{
    S_M1_Main_Q_t       q_item;
    S_M1_Buttons_Status btn_status;
    BaseType_t          ret;

    ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(timeout_ms));
    if (ret != pdTRUE)
    {
        return M1_BTN_NONE;
    }

    if (q_item.q_evt_type != Q_EVENT_KEYPAD)
    {
        return M1_BTN_NONE;
    }

    ret = xQueueReceive(button_events_q_hdl, &btn_status, 0);
    if (ret != pdTRUE)
    {
        return M1_BTN_NONE;
    }

    if (btn_status.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return M1_BTN_UP;
    }
    if (btn_status.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return M1_BTN_DOWN;
    }
    if (btn_status.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return M1_BTN_LEFT;
    }
    if (btn_status.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return M1_BTN_RIGHT;
    }
    if (btn_status.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK)
    {
        return M1_BTN_OK;
    }
    if (btn_status.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK)
    {
        /* Drain main queue when BACK is observed: matches the legacy
         * game_poll_button behavior so existing callers keep working. */
        xQueueReset(main_q_hdl);
        return M1_BTN_BACK;
    }

    return M1_BTN_NONE;
}
