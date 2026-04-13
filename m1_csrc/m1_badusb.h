/* See COPYING.txt for license details. */

/*
 * m1_badusb.h
 *
 * BadUSB — USB HID keyboard injection with DuckyScript parser
 */

#ifndef M1_BADUSB_H_
#define M1_BADUSB_H_

#include <stdint.h>
#include <stdbool.h>

/* BadUSB script max sizes */
#define BADUSB_MAX_SCRIPT_SIZE    4096
#define BADUSB_MAX_LINE_LEN       256
#define BADUSB_DIR                "0:/BadUSB"

/* BadUSB execution state */
typedef struct
{
    volatile uint8_t  running;
    uint16_t current_line;
    uint16_t total_lines;
    uint16_t default_delay_ms;
    char     last_line[BADUSB_MAX_LINE_LEN];
} badusb_state_t;

/* Main menu entry point (3-item submenu: Run Script, Payload Library, OS Detect) */
void badusb_main_menu(void);

/* File browser entry point (also called from main menu as "Run Script") */
void badusb_run(void);

/* Script execution API */
bool badusb_execute_file(const char *filepath);
void badusb_stop(void);

/* OS fingerprinting */
void badusb_os_detect(void);

/* Payload library browser */
void badusb_payload_library(void);

/* Keyboard emulation API for external apps */
void badusb_send_key(uint8_t modifier, uint8_t keycode);
void badusb_type_char(char c);
void badusb_type_string(const char *str);
void badusb_type_string_forced(const char *str);

#endif /* M1_BADUSB_H_ */
