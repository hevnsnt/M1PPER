/* See COPYING.txt for license details. */

/*
*
* m1_games.h
*
* Built-in games for M1
*
* The button-poll and rand helpers used to live here, named with a `game_`
* prefix. They have moved to project-level modules (m1_input.h, m1_rand.h)
* because non-game apps need them too. The legacy names below are
* preserved as forwarding macros so callers do not have to change.
*
* M1 Project
*
*/

#ifndef M1_GAMES_H_
#define M1_GAMES_H_

#include <stdint.h>
#include <stdbool.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "m1_system.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_tasks.h"
#include "m1_buzzer.h"
#include "m1_input.h"
#include "m1_rand.h"

/* Display dimensions — kept for legacy callers. New code should use the
 * M1_LAYOUT_* macros from m1_layout.h. */
#define GAME_SCREEN_W    128
#define GAME_SCREEN_H    64

/* Backward-compat aliases for the renamed input enum + helper. New code
 * should use m1_button_t / m1_app_poll_button directly. */
typedef m1_button_t game_button_t;

#define GAME_BTN_NONE   M1_BTN_NONE
#define GAME_BTN_UP     M1_BTN_UP
#define GAME_BTN_DOWN   M1_BTN_DOWN
#define GAME_BTN_LEFT   M1_BTN_LEFT
#define GAME_BTN_RIGHT  M1_BTN_RIGHT
#define GAME_BTN_OK     M1_BTN_OK
#define GAME_BTN_BACK   M1_BTN_BACK

static inline game_button_t game_poll_button(uint32_t timeout_ms)
{
    return m1_app_poll_button(timeout_ms);
}

static inline void game_rand_seed(void)
{
    m1_rand_seed();
}

static inline int game_rand_range(int min, int max)
{
    return m1_rand_range(min, max);
}

/* Game entry points */
void game_snake_run(void);
void game_tetris_run(void);
void game_trex_run(void);
void game_pong_run(void);
void game_dice_run(void);

#endif /* M1_GAMES_H_ */
