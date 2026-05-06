/* See COPYING.txt for license details. */

/*
 *
 * m1_app_runtime.c
 *
 * Implementation. See m1_app_runtime.h.
 *
 * Design notes:
 *   - The runtime calls on_render once on entry so apps see a frame even
 *     if no input arrives. After that, redraws are gated by the
 *     `redraw_pending` flag plus tick events.
 *   - The button-poll timeout is `tick_period_ms` if set, otherwise a
 *     conservative 200 ms. This keeps tick-driven apps responsive without
 *     hammering the queue when there is nothing to update.
 *   - on_init / on_exit run on the calling task — apps are free to use
 *     stack-allocated state via def->user_state, or a static, or skip
 *     state entirely.
 *
 * M1 Project
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "m1_app_runtime.h"
#include "m1_input.h"

#define APP_RUNTIME_DEFAULT_POLL_MS  200U

void m1_app_run(const m1_app_def_t *def)
{
    m1_app_ctx_t ctx;
    uint32_t     poll_ms;
    uint32_t     last_tick_ms;

    if (def == NULL || def->on_render == NULL)
    {
        return;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.user_state = def->user_state;
    if (def->user_state != NULL && def->user_state_size > 0U)
    {
        memset(def->user_state, 0, def->user_state_size);
    }

    ctx.now_ms        = HAL_GetTick();
    ctx.redraw_pending = true;

    if (def->on_init != NULL)
    {
        def->on_init(&ctx);
    }

    poll_ms      = (def->tick_period_ms != 0U) ? def->tick_period_ms
                                               : APP_RUNTIME_DEFAULT_POLL_MS;
    last_tick_ms = ctx.now_ms;

    /* Always paint the first frame so the user sees something while we
     * wait on the first input. */
    def->on_render(&ctx);
    ctx.redraw_pending = false;

    while (!ctx.should_exit)
    {
        m1_button_t btn = m1_app_poll_button(poll_ms);

        ctx.now_ms = HAL_GetTick();

        /* Periodic tick. */
        if (def->on_tick != NULL && def->tick_period_ms != 0U)
        {
            if ((uint32_t)(ctx.now_ms - last_tick_ms) >= def->tick_period_ms)
            {
                def->on_tick(&ctx, ctx.now_ms);
                last_tick_ms       = ctx.now_ms;
                ctx.redraw_pending = true;
            }
        }

        /* Button handling. */
        if (btn != M1_BTN_NONE)
        {
            bool consumed = false;
            if (def->on_button != NULL)
            {
                consumed = def->on_button(&ctx, btn);
            }
            if (!consumed && btn == M1_BTN_BACK)
            {
                ctx.should_exit = true;
            }
            ctx.redraw_pending = true;
        }

        if (ctx.should_exit)
        {
            break;
        }

        if (ctx.redraw_pending)
        {
            def->on_render(&ctx);
            ctx.redraw_pending = false;
        }
    }

    if (def->on_exit != NULL)
    {
        def->on_exit(&ctx);
    }
}
