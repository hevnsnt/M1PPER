/* See COPYING.txt for license details. */

/*
 * m1_badusb_fingerprint.h
 *
 * OS fingerprinting via USB HID enumeration behavior.
 * Records Setup request sequence/timing during HID enumeration
 * and classifies the host OS based on known patterns.
 */

#ifndef M1_BADUSB_FINGERPRINT_H_
#define M1_BADUSB_FINGERPRINT_H_

#include <stdint.h>
#include <stdbool.h>

/* Maximum Setup requests to record during enumeration */
#define HID_FP_MAX_EVENTS    16

/* Detected OS types */
typedef enum {
    BADUSB_OS_UNKNOWN = 0,
    BADUSB_OS_WINDOWS,
    BADUSB_OS_MACOS,
    BADUSB_OS_LINUX,
    BADUSB_OS_CHROMEOS
} badusb_os_t;

/* Single recorded HID Setup request */
typedef struct {
    uint8_t  bmRequest;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timestamp_ms;
} hid_fp_event_t;

/* Fingerprint capture state */
typedef struct {
    hid_fp_event_t events[HID_FP_MAX_EVENTS];
    uint8_t        count;
    uint32_t       enum_start_ms;
    bool           capture_active;
    badusb_os_t    detected_os;
} hid_fingerprint_t;

/* Global fingerprint state - written from USB IRQ, read from task context */
extern volatile hid_fingerprint_t g_hid_fingerprint;

/* Start capture (call from USBD_HID_Init) */
void hid_fp_start_capture(void);

/* Record a Setup request (call from USBD_HID_Setup - runs in IRQ context) */
void hid_fp_record_event(uint8_t bmRequest, uint8_t bRequest,
                         uint16_t wValue, uint16_t wIndex, uint16_t wLength);

/* Stop capture and analyze pattern - returns detected OS */
badusb_os_t hid_fp_analyze(void);

/* Get string name for OS */
const char *hid_fp_os_name(badusb_os_t os);

#endif /* M1_BADUSB_FINGERPRINT_H_ */
