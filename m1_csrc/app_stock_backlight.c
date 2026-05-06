/* See COPYING.txt for license details. */

/*
 *
 * app_stock_backlight.c
 *
 * The stock-LP5814 backlight controls have been merged into
 * app_rgb_backlight.c. The unified app auto-detects whether the RGB mod
 * is fitted and shows the appropriate menu. This file stays as a small
 * forwarder so existing menu wiring (`app_stock_backlight_run`) keeps
 * working.
 *
 * M1 Project
 *
 */

#include "m1_builtin_apps.h"

void app_stock_backlight_run(void)
{
    /* Same code path as the RGB backlight entry — the runtime auto-detects
     * the hardware mode in on_init. */
    app_rgb_backlight_run();
}
