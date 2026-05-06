/* See COPYING.txt for license details. */

/*
 *
 * m1_app_runtime.h
 *
 * Unified runtime for built-in apps. Each app describes itself with an
 * `m1_app_def_t` (lifecycle callbacks + tick period + opaque user state)
 * and calls `m1_app_run` once. The runtime then handles:
 *
 *   - Allocating / zeroing the user_state buffer
 *   - Calling on_init / on_render / on_tick / on_exit at the right times
 *   - The u8g2 page-loop on every frame
 *   - Polling buttons via m1_app_poll_button
 *   - Default BACK = exit (apps can intercept by consuming BACK in
 *     on_button)
 *
 * This eliminates the dozens of lines of identical event-loop boilerplate
 * that every legacy app currently carries.
 *
 * M1 Project
 *
 */

#ifndef M1_APP_RUNTIME_H_
#define M1_APP_RUNTIME_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "m1_input.h"

/* Opaque per-run context handed to every callback. */
typedef struct m1_app_ctx
{
    void    *user_state;
    uint32_t now_ms;
    bool     should_exit;     /* set true to request runtime exit */
    bool     redraw_pending;  /* hint to next frame; also set after on_button */
} m1_app_ctx_t;

typedef void (*m1_app_init_fn)   (m1_app_ctx_t *ctx);
typedef void (*m1_app_render_fn) (m1_app_ctx_t *ctx);
typedef bool (*m1_app_button_fn) (m1_app_ctx_t *ctx, m1_button_t btn);
typedef void (*m1_app_tick_fn)   (m1_app_ctx_t *ctx, uint32_t now_ms);
typedef void (*m1_app_exit_fn)   (m1_app_ctx_t *ctx);

typedef struct
{
    const char       *title;            /* informational; not drawn by runtime */
    m1_app_init_fn    on_init;          /* may be NULL */
    m1_app_render_fn  on_render;        /* required */
    m1_app_button_fn  on_button;        /* may be NULL; return true to consume,
                                           false to bubble (BACK exits) */
    m1_app_tick_fn    on_tick;          /* may be NULL */
    m1_app_exit_fn    on_exit;          /* may be NULL */
    uint32_t          tick_period_ms;   /* 0 = no periodic tick. Also doubles
                                           as the button poll timeout. */
    void             *user_state;       /* optional caller-provided buffer */
    size_t            user_state_size;  /* sizeof(*user_state) — runtime zeroes
                                           it at startup. 0 if unused. */
} m1_app_def_t;

/*
 * Run an app to completion. Returns when the app requests exit, the user
 * presses BACK and on_button does not consume it, or on_render is missing.
 */
void m1_app_run(const m1_app_def_t *def);

#endif /* M1_APP_RUNTIME_H_ */
