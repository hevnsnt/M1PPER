/* See COPYING.txt for license details. */

/*
 * app_nfc_nested.c
 *
 * MIFARE Classic Default Key Survey.
 *
 * The full StaticNested attack requires a software Crypto-1 LFSR replay and
 * specific timing not available on this RFAL stack. The Default Key Survey
 * is the practical, fully-implementable equivalent: it tries every common
 * factory/transit key against every sector (Key A and Key B) and reports
 * which keys unlock which sectors.
 *
 * In practice this finds keys for the vast majority of MIFARE Classic
 * deployments in the wild (parking, gym, hotel, transit, access cards)
 * because operators rarely change all 32 keys from defaults.
 *
 * Output:
 *   - On-screen scrollable table:  S00 A:OK B:NO  FFFFFFFFFFFF
 *   - Saved to /NFC/recovered_keys.txt for later use with key dictionary
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "stm32h5xx_hal.h"
#include "main.h"
#include "app_nfc_nested.h"
#include "m1_compile_cfg.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "m1_tasks.h"
#include "m1_buzzer.h"
#include "m1_led_indicator.h"
#include "m1_file_browser.h"

#include "rfal_nfc.h"
#include "rfal_nfca.h"
#include "rfal_rf.h"
#include "rfal_utils.h"
#include "legacy/mfc_crypto1.h"

#ifdef M1_APP_NFC_NESTED_ENABLE

/* ---- common factory / transit / leaked keys ---- */
#define N_DEFAULT_KEYS  20

static const uint8_t s_default_keys[N_DEFAULT_KEYS][MFC_KEY_LEN] = {
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, /* factory */
    {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5}, /* MAD key A */
    {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5}, /* MAD key B */
    {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7}, /* well-known leaked */
    {0x00,0x00,0x00,0x00,0x00,0x00}, /* zeros */
    {0x4D,0x3A,0x99,0xC3,0x51,0xDD}, /* INTERNAL */
    {0x1A,0x98,0x2C,0x7E,0x45,0x9A},
    {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
    {0x71,0x4C,0x5C,0x88,0x6E,0x97},
    {0x58,0x7E,0xE5,0xF9,0x35,0x0F},
    {0xA0,0x47,0x8C,0xC3,0x90,0x91}, /* hotel TLJ */
    {0x53,0x3C,0xB6,0xC7,0x23,0xF6}, /* transit */
    {0x8F,0xD0,0xA4,0xF2,0x56,0xE9},
    {0x5C,0x83,0x8C,0xB1,0x06,0xCC},
    {0x6A,0x19,0x87,0xC4,0x0A,0x21},
    {0x3E,0x65,0xE4,0xFB,0x65,0xB3},
    {0xCA,0xFE,0xBA,0xBE,0xFE,0xED},
    {0xDE,0xAD,0xBE,0xEF,0x00,0x00},
    {0x12,0x34,0x56,0x78,0x9A,0xBC},
    {0x12,0x21,0x43,0x65,0x87,0xA9},
};

#define MAX_SECTORS  40   /* MIFARE Classic 4K worst case */

/* Per-sector recovery record */
typedef struct {
    bool     a_ok;
    bool     b_ok;
    uint8_t  a_key[6];
    uint8_t  b_key[6];
} sector_keys_t;

static sector_keys_t s_recovered[MAX_SECTORS];


/* ============================================================================ */
/*                         CARD POLL / SAK INTERPRETATION                       */
/* ============================================================================ */

static void crc_a_append(uint8_t *data, uint16_t len)
{
    uint16_t crc = 0x6363;
    for (uint16_t i = 0; i < len; i++) {
        uint8_t b = data[i] ^ (uint8_t)(crc & 0xFF);
        b ^= (uint8_t)(b << 4);
        crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4);
    }
    data[len]     = (uint8_t)(crc & 0xFF);
    data[len + 1] = (uint8_t)(crc >> 8);
}

static void halt_a(void)
{
    uint8_t  tx[4];
    uint8_t  rx[4];
    uint16_t rcv = 0;
    tx[0] = 0x50;
    tx[1] = 0x00;
    crc_a_append(tx, 2);
    (void)rfalTransceiveBlockingTxRx(tx, 4, rx, sizeof(rx), &rcv,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(5));
}

/* Polls a fresh card; returns UID (4 bytes for cascade-1 only) and SAK. */
static bool poll_card(uint8_t uid_out[4], uint8_t *sak_out, uint8_t atqa_out[2])
{
    uint8_t  buf[16];
    uint8_t  rx[16];
    uint16_t rcv_bits = 0;
    uint16_t rcv_len  = 0;
    uint8_t  bytesToSend, bitsToSend;
    ReturnCode err;

    rfalFieldOff();
    vTaskDelay(2);
    err = rfalFieldOnAndStartGT();
    if (err != RFAL_ERR_NONE) return false;

    rcv_bits = 0;
    err = rfalISO14443ATransceiveShortFrame(RFAL_14443A_SHORTFRAME_CMD_REQA,
                                            rx, (uint8_t)(sizeof(rx) * 8),
                                            &rcv_bits,
                                            rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE || rcv_bits < 16) return false;
    if (atqa_out) { atqa_out[0] = rx[0]; atqa_out[1] = rx[1]; }

    buf[0] = 0x93;
    buf[1] = 0x20;
    bytesToSend = 2;
    bitsToSend  = 0;
    rcv_bits    = 0;
    err = rfalISO14443ATransceiveAnticollisionFrame(buf, &bytesToSend, &bitsToSend,
                                                    &rcv_bits,
                                                    rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE || rcv_bits < 40) return false;

    uid_out[0] = buf[2];
    uid_out[1] = buf[3];
    uid_out[2] = buf[4];
    uid_out[3] = buf[5];

    buf[0] = 0x93;
    buf[1] = 0x70;
    buf[2] = uid_out[0];
    buf[3] = uid_out[1];
    buf[4] = uid_out[2];
    buf[5] = uid_out[3];
    buf[6] = (uint8_t)(uid_out[0] ^ uid_out[1] ^ uid_out[2] ^ uid_out[3]);
    crc_a_append(buf, 7);

    rcv_len = 0;
    err = rfalTransceiveBlockingTxRx(buf, 9, rx, sizeof(rx), &rcv_len,
                                     RFAL_TXRX_FLAGS_DEFAULT,
                                     rfalConvMsTo1fc(10));
    if (err != RFAL_ERR_NONE || rcv_len < 1) return false;
    if (sak_out) *sak_out = rx[0];
    return true;
}

/*
 * Map SAK to expected sector count. 0x08/0x28 = 1K (16 sectors).
 * 0x18/0x38 = 4K (40 sectors). Default to 16.
 */
static uint8_t sak_to_sectors(uint8_t sak)
{
    switch (sak) {
    case 0x09: return 5;          /* MIFARE Mini */
    case 0x08:
    case 0x28: return 16;         /* Classic 1K  */
    case 0x18:
    case 0x38: return 40;         /* Classic 4K  */
    case 0x19: return 32;         /* Classic 2K  */
    default:   return 16;
    }
}

/* First block index of a sector. Sectors 0..31 hold 4 blocks each;
 * sectors 32..39 (4K only) hold 16 blocks each. */
static uint8_t sector_first_block(uint8_t sector)
{
    if (sector < 32) return (uint8_t)(sector * 4);
    return (uint8_t)(128 + (sector - 32) * 16);
}


/* ============================================================================ */
/*                                    UI                                        */
/* ============================================================================ */

static void draw_intro(void)
{
    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "Default Key Attack");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 24, "Tries 20 common");
    u8g2_DrawStr(&m1_u8g2, 2, 34, "MFC keys per sector");
    u8g2_DrawStr(&m1_u8g2, 2, 46, "Hold MFC card on M1");
    u8g2_DrawBox(&m1_u8g2, 0, 56, 128, 8);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_BG);
    u8g2_DrawStr(&m1_u8g2, 2, 63, "BACK=Exit");
    m1_u8g2_nextpage();
}

static void draw_progress(uint8_t sector, uint8_t total, uint8_t found)
{
    char l1[24];
    char l2[24];
    snprintf(l1, sizeof(l1), "Sector %u/%u", (unsigned)sector, (unsigned)total);
    snprintf(l2, sizeof(l2), "Found keys: %u",  (unsigned)found);

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 12, "Surveying Keys");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 26, l1);
    u8g2_DrawStr(&m1_u8g2, 2, 38, l2);

    /* progress bar */
    uint8_t bar_w = (uint8_t)(((uint16_t)sector * 124U) / (total ? total : 1));
    u8g2_DrawFrame(&m1_u8g2, 2, 44, 124, 6);
    if (bar_w > 124) bar_w = 124;
    u8g2_DrawBox(&m1_u8g2, 2, 44, bar_w, 6);
    u8g2_DrawStr(&m1_u8g2, 2, 62, "BACK=Abort");
    m1_u8g2_nextpage();
}

#define RESULTS_LINES_PER_SCREEN  5

static void draw_results(uint8_t total_sectors, uint8_t scroll, uint8_t found)
{
    char hdr[24];
    snprintf(hdr, sizeof(hdr), "Keys: %u/%u",
             (unsigned)found, (unsigned)(total_sectors * 2));

    u8g2_FirstPage(&m1_u8g2);
    u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
    u8g2_SetFont(&m1_u8g2, M1_DISP_RUN_MENU_FONT_B);
    u8g2_DrawStr(&m1_u8g2, 2, 10, "Default Key Atk");
    u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
    u8g2_DrawStr(&m1_u8g2, 2, 20, hdr);

    for (uint8_t r = 0; r < RESULTS_LINES_PER_SCREEN; r++) {
        uint8_t s = (uint8_t)(scroll + r);
        if (s >= total_sectors) break;

        char line[40];
        char keystr[14] = "------------";
        const sector_keys_t *rec = &s_recovered[s];

        if (rec->a_ok) {
            snprintf(keystr, sizeof(keystr), "%02X%02X%02X%02X%02X%02X",
                     rec->a_key[0], rec->a_key[1], rec->a_key[2],
                     rec->a_key[3], rec->a_key[4], rec->a_key[5]);
        } else if (rec->b_ok) {
            snprintf(keystr, sizeof(keystr), "%02X%02X%02X%02X%02X%02X",
                     rec->b_key[0], rec->b_key[1], rec->b_key[2],
                     rec->b_key[3], rec->b_key[4], rec->b_key[5]);
        }

        snprintf(line, sizeof(line), "S%02u %c%c %s",
                 (unsigned)s,
                 rec->a_ok ? 'A' : '-',
                 rec->b_ok ? 'B' : '-',
                 keystr);
        u8g2_DrawStr(&m1_u8g2, 2, (u8g2_uint_t)(28 + r * 8), line);
    }

    u8g2_DrawStr(&m1_u8g2, 2, 63, "UP/DN scroll BACK exit");
    m1_u8g2_nextpage();
}


/* ============================================================================ */
/*                              SAVE TO SD CARD                                 */
/* ============================================================================ */

static void save_results(uint8_t total_sectors, const uint8_t uid[4])
{
    FIL fk;
    if (m1_fb_open_new_file(&fk, "0:/NFC/recovered_keys.txt") != 0) return;

    char line[80];
    snprintf(line, sizeof(line),
             "# Default Key Survey  UID=%02X%02X%02X%02X\r\n",
             uid[0], uid[1], uid[2], uid[3]);
    m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));

    snprintf(line, sizeof(line),
             "# sector,keyType,key (hex MSB first)\r\n");
    m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));

    for (uint8_t s = 0; s < total_sectors; s++) {
        const sector_keys_t *r = &s_recovered[s];
        if (r->a_ok) {
            snprintf(line, sizeof(line),
                     "%u,A,%02X%02X%02X%02X%02X%02X\r\n",
                     (unsigned)s,
                     r->a_key[0], r->a_key[1], r->a_key[2],
                     r->a_key[3], r->a_key[4], r->a_key[5]);
            m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));
        }
        if (r->b_ok) {
            snprintf(line, sizeof(line),
                     "%u,B,%02X%02X%02X%02X%02X%02X\r\n",
                     (unsigned)s,
                     r->b_key[0], r->b_key[1], r->b_key[2],
                     r->b_key[3], r->b_key[4], r->b_key[5]);
            m1_fb_write_to_file(&fk, line, (uint16_t)strlen(line));
        }
    }
    m1_fb_close_file(&fk);
}


/* ============================================================================ */
/*                                   ATTACK                                     */
/* ============================================================================ */

/*
 * Run the survey on a freshly polled card. Returns total sectors processed
 * and updates the global s_recovered table. Aborts early if BACK is held.
 */
static uint8_t run_survey(const uint8_t uid[4], uint8_t total_sectors,
                          uint8_t *found_out, bool *aborted_out)
{
    crypto1_state_t cstate;
    uint8_t  found = 0;
    bool     aborted = false;
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;

    memset(s_recovered, 0, sizeof(s_recovered));

    if (total_sectors > MAX_SECTORS) total_sectors = MAX_SECTORS;

    for (uint8_t s = 0; s < total_sectors; s++) {

        /* Allow user to abort between sectors */
        if (xQueueReceive(main_q_hdl, &q_item, 0) == pdTRUE &&
            q_item.q_evt_type == Q_EVENT_KEYPAD &&
            xQueueReceive(button_events_q_hdl, &btn, 0) == pdTRUE &&
            btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
            aborted = true;
            break;
        }

        draw_progress((uint8_t)(s + 1), total_sectors, found);

        uint8_t firstBlock = sector_first_block(s);

        for (uint8_t k = 0; k < N_DEFAULT_KEYS; k++) {

            /* Try Key A */
            if (!s_recovered[s].a_ok) {
                /* Each auth attempt may halt the card on failure; re-poll
                 * every key so we always start from a clean state. */
                halt_a();
                uint8_t poll_uid[4];
                uint8_t poll_sak;
                if (!poll_card(poll_uid, &poll_sak, NULL)) continue;
                if (memcmp(poll_uid, uid, 4) != 0) continue;

                if (mfc_auth(&cstate, uid, firstBlock,
                             MFC_AUTH_CMD_A, s_default_keys[k])) {
                    s_recovered[s].a_ok = true;
                    memcpy(s_recovered[s].a_key, s_default_keys[k], 6);
                    found++;
                }
            }

            /* Try Key B */
            if (!s_recovered[s].b_ok) {
                halt_a();
                uint8_t poll_uid[4];
                uint8_t poll_sak;
                if (!poll_card(poll_uid, &poll_sak, NULL)) continue;
                if (memcmp(poll_uid, uid, 4) != 0) continue;

                if (mfc_auth(&cstate, uid, firstBlock,
                             MFC_AUTH_CMD_B, s_default_keys[k])) {
                    s_recovered[s].b_ok = true;
                    memcpy(s_recovered[s].b_key, s_default_keys[k], 6);
                    found++;
                }
            }

            if (s_recovered[s].a_ok && s_recovered[s].b_ok) break;
        }
    }

    if (found_out)   *found_out = found;
    if (aborted_out) *aborted_out = aborted;
    return total_sectors;
}


/* ============================================================================ */
/*                                ENTRY POINT                                   */
/* ============================================================================ */

void app_nfc_nested_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    bool                running = true;
    bool                redraw  = true;
    enum { ST_INTRO, ST_RUNNING, ST_RESULTS, ST_NO_CARD } state = ST_INTRO;
    uint8_t             total_sectors = 0;
    uint8_t             found_keys    = 0;
    uint8_t             scroll        = 0;
    uint8_t             card_uid[4]   = {0};
    TickType_t          next_poll     = 0;

    if (rfalNfcInitialize() != RFAL_ERR_NONE) {
        m1_message_box(&m1_u8g2, "Default Key Atk", "RFAL init failed",
                       " ", "BACK to return");
        return;
    }

    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_M, LED_FASTBLINK_ONTIME_M);

    while (running) {

        if (redraw) {
            redraw = false;
            switch (state) {
            case ST_INTRO:    draw_intro(); break;
            case ST_RUNNING:  /* progress drawn inside run_survey */ break;
            case ST_RESULTS:  draw_results(total_sectors, scroll, found_keys); break;
            case ST_NO_CARD:
                m1_message_box(&m1_u8g2, "Default Key Atk",
                               "No MFC card found", " ", "BACK to return");
                break;
            }
        }

        TickType_t now = xTaskGetTickCount();

        if (state == ST_INTRO && now >= next_poll) {
            uint8_t uid[4];
            uint8_t sak = 0;
            uint8_t atqa[2];
            if (poll_card(uid, &sak, atqa)) {
                memcpy(card_uid, uid, 4);
                total_sectors = sak_to_sectors(sak);
                m1_buzzer_notification();

                state = ST_RUNNING;
                bool aborted = false;
                run_survey(card_uid, total_sectors, &found_keys, &aborted);

                if (found_keys > 0) {
                    save_results(total_sectors, card_uid);
                    m1_buzzer_notification();
                }
                state  = ST_RESULTS;
                scroll = 0;
                redraw = true;
                continue;
            }
            next_poll = now + pdMS_TO_TICKS(300);
        }

        TickType_t deadline = now + pdMS_TO_TICKS(150);
        TickType_t wait = (deadline > xTaskGetTickCount()) ?
                          (deadline - xTaskGetTickCount()) : 0;
        ret = xQueueReceive(main_q_hdl, &q_item, wait);
        if (ret != pdTRUE) continue;
        if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
        ret = xQueueReceive(button_events_q_hdl, &btn, 0);
        if (ret != pdTRUE) continue;

        switch (state) {
        case ST_INTRO:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            }
            break;

        case ST_RESULTS:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            } else if (btn.event[BUTTON_OK_KP_ID] == BUTTON_EVENT_CLICK) {
                /* Re-run on a new card */
                state = ST_INTRO;
                redraw = true;
                next_poll = 0;
            } else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK) {
                if (scroll > 0) { scroll--; redraw = true; }
            } else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK) {
                if (scroll + RESULTS_LINES_PER_SCREEN < total_sectors) {
                    scroll++; redraw = true;
                }
            }
            break;

        case ST_NO_CARD:
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK) {
                running = false;
            }
            break;

        case ST_RUNNING:
            /* Should not happen; survey is blocking */
            break;
        }
    }

    m1_led_fast_blink(LED_BLINK_ON_RGB, LED_FASTBLINK_PWM_OFF, LED_FASTBLINK_ONTIME_OFF);
    rfalFieldOff();
    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    xQueueReset(main_q_hdl);
}

#endif /* M1_APP_NFC_NESTED_ENABLE */
