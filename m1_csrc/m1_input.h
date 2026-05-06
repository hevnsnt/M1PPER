/* See COPYING.txt for license details. */

/*
 *
 * m1_input.h
 *
 * Project-wide button-polling helper. Apps drain a single button click off
 * the main FreeRTOS event queue with one call instead of reimplementing
 * the xQueueReceive(main_q_hdl) -> Q_EVENT_KEYPAD -> button_events_q_hdl
 * dance dozens of times.
 *
 * The legacy `game_poll_button` symbol in m1_games.h forwards to
 * `m1_app_poll_button` for backward compatibility.
 *
 * M1 Project
 *
 */

#ifndef M1_INPUT_H_
#define M1_INPUT_H_

#include <stdint.h>

/* Logical button identifiers exposed to apps. */
typedef enum
{
    M1_BTN_NONE = 0,
    M1_BTN_UP,
    M1_BTN_DOWN,
    M1_BTN_LEFT,
    M1_BTN_RIGHT,
    M1_BTN_OK,
    M1_BTN_BACK
} m1_button_t;

/*
 * Block on the main queue up to `timeout_ms` and return the first button
 * click. Returns M1_BTN_NONE on timeout or if a non-keypad event was
 * dequeued.
 */
m1_button_t m1_app_poll_button(uint32_t timeout_ms);

#endif /* M1_INPUT_H_ */
