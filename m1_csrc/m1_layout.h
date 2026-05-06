/* See COPYING.txt for license details. */

/*
 *
 * m1_layout.h
 *
 * Shared screen geometry constants for M1 apps. Replaces magic numbers
 * scattered through every app_*.c file with named macros so that any future
 * display-format change only needs to be made in one place.
 *
 * The display is a 128x64 monochrome panel. The layout convention is:
 *
 *     0  +------------------------------+ <- y=0
 *        |  Title              [badge]  |   header text baseline at y=9
 *     12 +------------------------------+ <- horizontal divider
 *        |                              |   content area starts at y=14
 *        |          content             |
 *        |                              |
 *     54 +------------------------------+
 *        | < page    OK Action     > |  bottom-bar baseline at y=62
 *     63 +------------------------------+
 *
 * M1 Project
 *
 */

#ifndef M1_LAYOUT_H_
#define M1_LAYOUT_H_

/* Physical screen dimensions */
#define M1_LAYOUT_SCREEN_W              128
#define M1_LAYOUT_SCREEN_H              64

/* Header bar */
#define M1_LAYOUT_HEADER_BASELINE_Y     9
#define M1_LAYOUT_HEADER_HLINE_Y        12

/* Content area */
#define M1_LAYOUT_CONTENT_TOP_Y         14
#define M1_LAYOUT_CONTENT_LEFT_X        2
#define M1_LAYOUT_CONTENT_W             124
#define M1_LAYOUT_CONTENT_H             37

/* Bottom bar */
#define M1_LAYOUT_BOTTOM_BAR_Y          63
#define M1_LAYOUT_BOTTOM_BAR_BASELINE_Y 62

#endif /* M1_LAYOUT_H_ */
