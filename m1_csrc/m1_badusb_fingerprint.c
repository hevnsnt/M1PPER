/* See COPYING.txt for license details. */

/*
 * m1_badusb_fingerprint.c
 *
 * OS fingerprinting via USB HID enumeration behavior.
 * Records Setup request sequence/timing during HID enumeration
 * and classifies the host OS based on known patterns.
 *
 * Called from IRQ context (USBD_HID_Setup/Init) — must be fast,
 * no blocking, no FreeRTOS calls.
 */

#include "m1_badusb_fingerprint.h"
#include "m1_compile_cfg.h"
#include "main.h"

#ifdef M1_APP_BADUSB_ENABLE

/*************************** D E F I N E S ************************************/

/* USB HID class request codes (duplicated here to avoid pulling in usbd_hid.h
 * into IRQ-context code that shouldn't depend on the full USB stack) */
#define FP_SET_IDLE       0x0A
#define FP_SET_PROTOCOL   0x0B
#define FP_GET_IDLE       0x02
#define FP_SET_REPORT     0x09
#define FP_GET_REPORT     0x01
#define FP_GET_DESCRIPTOR 0x06

/* bmRequest type masks */
#define FP_REQ_TYPE_CLASS    0x21  /* Host-to-device, class, interface */
#define FP_REQ_TYPE_STD_IN   0x81  /* Device-to-host, standard, interface */

/* Scoring thresholds */
#define FP_SCORE_THRESHOLD   3

/***************************** V A R I A B L E S ******************************/

volatile hid_fingerprint_t g_hid_fingerprint;

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/

/*============================================================================*/
/**
 * @brief  Start fingerprint capture (call from USBD_HID_Init, runs in IRQ)
 */
/*============================================================================*/
void hid_fp_start_capture(void)
{
    g_hid_fingerprint.count = 0;
    g_hid_fingerprint.enum_start_ms = HAL_GetTick();
    g_hid_fingerprint.detected_os = BADUSB_OS_UNKNOWN;
    g_hid_fingerprint.capture_active = true;
}

/*============================================================================*/
/**
 * @brief  Record a Setup request during enumeration (runs in IRQ context)
 */
/*============================================================================*/
void hid_fp_record_event(uint8_t bmRequest, uint8_t bRequest,
                         uint16_t wValue, uint16_t wIndex, uint16_t wLength)
{
    if (!g_hid_fingerprint.capture_active)
        return;

    if (g_hid_fingerprint.count >= HID_FP_MAX_EVENTS)
        return;

    uint8_t idx = g_hid_fingerprint.count;
    g_hid_fingerprint.events[idx].bmRequest    = bmRequest;
    g_hid_fingerprint.events[idx].bRequest     = bRequest;
    g_hid_fingerprint.events[idx].wValue       = wValue;
    g_hid_fingerprint.events[idx].wIndex       = wIndex;
    g_hid_fingerprint.events[idx].wLength      = wLength;
    g_hid_fingerprint.events[idx].timestamp_ms = HAL_GetTick() - g_hid_fingerprint.enum_start_ms;
    g_hid_fingerprint.count++;
}

/*============================================================================*/
/**
 * @brief  Analyze captured events and classify host OS
 *
 * Scoring heuristics based on known USB HID enumeration patterns:
 *
 * Windows:
 *   - Sends SET_IDLE(0) early, then GET_REPORT or SET_REPORT
 *   - Typically 4-6 class requests during enumeration
 *   - Usually requests GET_IDLE
 *   - Enumeration completes in ~50-150ms
 *
 * macOS:
 *   - Sends SET_IDLE(0) then SET_PROTOCOL(0) (boot protocol)
 *   - Requests GET_REPORT with wLength=8
 *   - Enumeration is fast, ~30-80ms
 *   - Fewer class requests (2-4 typically)
 *
 * Linux:
 *   - Sends SET_IDLE(0) only, minimal class requests
 *   - Often just 1-2 class requests total
 *   - May send SET_PROTOCOL(1) (report protocol)
 *   - Enumeration ~40-120ms
 *
 * ChromeOS:
 *   - Similar to Linux but with SET_PROTOCOL(0) (boot protocol)
 *   - Tends to have slightly more requests than vanilla Linux
 *
 * @retval Detected OS type
 */
/*============================================================================*/
badusb_os_t hid_fp_analyze(void)
{
    g_hid_fingerprint.capture_active = false;

    uint8_t n = g_hid_fingerprint.count;
    if (n == 0)
    {
        g_hid_fingerprint.detected_os = BADUSB_OS_UNKNOWN;
        return BADUSB_OS_UNKNOWN;
    }

    int score_win   = 0;
    int score_mac   = 0;
    int score_linux = 0;
    int score_chrome = 0;

    bool has_set_idle      = false;
    bool has_set_protocol  = false;
    bool has_get_idle      = false;
    bool has_set_report    = false;
    bool has_get_report    = false;
    uint8_t set_protocol_val = 0xFF;
    uint8_t class_req_count  = 0;

    /* Pass 1: catalog what requests arrived */
    for (uint8_t i = 0; i < n; i++)
    {
        const volatile hid_fp_event_t *ev = &g_hid_fingerprint.events[i];

        if ((ev->bmRequest & 0x60) == 0x20)  /* Class request */
        {
            class_req_count++;

            switch (ev->bRequest)
            {
                case FP_SET_IDLE:
                    has_set_idle = true;
                    break;
                case FP_SET_PROTOCOL:
                    has_set_protocol = true;
                    set_protocol_val = (uint8_t)(ev->wValue & 0xFF);
                    break;
                case FP_GET_IDLE:
                    has_get_idle = true;
                    break;
                case FP_SET_REPORT:
                    has_set_report = true;
                    break;
                case FP_GET_REPORT:
                    has_get_report = true;
                    break;
                default:
                    break;
            }
        }
    }

    /* Total enumeration time */
    uint32_t enum_time = 0;
    if (n > 0)
        enum_time = g_hid_fingerprint.events[n - 1].timestamp_ms;

    /* Pass 2: score each OS */

    /* --- Windows --- */
    if (has_set_idle)          score_win += 1;
    if (has_get_idle)          score_win += 3;  /* Strong Windows signal */
    if (has_set_report)        score_win += 2;
    if (has_get_report)        score_win += 1;
    if (class_req_count >= 4)  score_win += 2;
    if (class_req_count >= 6)  score_win += 1;

    /* --- macOS --- */
    if (has_set_idle)          score_mac += 1;
    if (has_set_protocol && set_protocol_val == 0)
                               score_mac += 3;  /* Boot protocol = strong macOS */
    if (has_get_report)        score_mac += 1;
    if (!has_get_idle)         score_mac += 1;  /* macOS doesn't usually GET_IDLE */
    if (class_req_count >= 2 && class_req_count <= 4)
                               score_mac += 2;
    if (enum_time > 0 && enum_time < 100)
                               score_mac += 1;

    /* --- Linux --- */
    if (has_set_idle)          score_linux += 1;
    if (!has_get_idle)         score_linux += 1;
    if (!has_set_report)       score_linux += 1;
    if (!has_get_report)       score_linux += 1;
    if (class_req_count <= 2)  score_linux += 3;  /* Very few requests = Linux */
    if (has_set_protocol && set_protocol_val == 1)
                               score_linux += 2;  /* Report protocol */

    /* --- ChromeOS --- */
    if (has_set_idle)          score_chrome += 1;
    if (has_set_protocol && set_protocol_val == 0)
                               score_chrome += 2;
    if (!has_get_idle)         score_chrome += 1;
    if (class_req_count >= 2 && class_req_count <= 3)
                               score_chrome += 2;
    /* ChromeOS typically slightly more requests than Linux but fewer than macOS */
    if (class_req_count == 3)  score_chrome += 1;

    /* Resolve: pick highest score, with tie-breaking priority:
     * Windows > macOS > ChromeOS > Linux > Unknown */
    badusb_os_t result = BADUSB_OS_UNKNOWN;
    int best = FP_SCORE_THRESHOLD;

    if (score_win >= best)     { best = score_win;    result = BADUSB_OS_WINDOWS; }
    if (score_mac > best)      { best = score_mac;    result = BADUSB_OS_MACOS; }
    if (score_chrome > best)   { best = score_chrome; result = BADUSB_OS_CHROMEOS; }
    if (score_linux > best)    { best = score_linux;  result = BADUSB_OS_LINUX; }

    g_hid_fingerprint.detected_os = result;
    return result;
}

/*============================================================================*/
/**
 * @brief  Get human-readable OS name
 */
/*============================================================================*/
const char *hid_fp_os_name(badusb_os_t os)
{
    switch (os)
    {
        case BADUSB_OS_WINDOWS:  return "Windows";
        case BADUSB_OS_MACOS:    return "macOS";
        case BADUSB_OS_LINUX:    return "Linux";
        case BADUSB_OS_CHROMEOS: return "ChromeOS";
        default:                 return "Unknown";
    }
}

#endif /* M1_APP_BADUSB_ENABLE */
