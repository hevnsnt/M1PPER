/* See COPYING.txt for license details. */

/*
 * app_totp.c
 *
 * RFC 6238 TOTP / RFC 4226 HOTP authenticator.
 *
 * Reads Base32-encoded shared secrets from /TOTP/accounts.txt on the SD card
 * (or /TOTP/hotp_accounts.txt for HOTP mode).  Computes 6-digit one-time
 * codes using a from-scratch SHA-1 / HMAC-SHA-1 implementation — no external
 * crypto dependencies.
 *
 * File format (one entry per line):
 *
 *     AccountName:BASE32SECRETXXX
 *
 * Lines starting with '#' or empty lines are skipped.  Account names are
 * truncated to TOTP_NAME_MAX-1 chars; secrets are truncated to the maximum
 * 32-byte raw key size.
 *
 * For HOTP, an additional /TOTP/hotp_counters.txt holds per-account counter
 * values.  When the user presses OK we increment the counter and re-write
 * that file.
 *
 * M1 Project
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "stm32h5xx_hal.h"
#include "main.h"
#include "m1_compile_cfg.h"

#ifdef M1_APP_TOTP_ENABLE

#include "app_totp.h"
#include "m1_display.h"
#include "m1_lcd.h"
#include "m1_system.h"
#include "ff.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

extern QueueHandle_t main_q_hdl;
extern QueueHandle_t button_events_q_hdl;

/*-----------------------------------------------------------------------------
 * Configuration limits
 *---------------------------------------------------------------------------*/
#define TOTP_MAX_ACCOUNTS    16
#define TOTP_NAME_MAX        24
#define TOTP_KEY_MAX         32     /* SHA-1 block (64) > key, so >=20 covers everything */
#define TOTP_PERIOD_SEC      30U
#define TOTP_DIGITS          6U

#define TOTP_ACCOUNTS_PATH   "0:/TOTP/accounts.txt"
#define HOTP_ACCOUNTS_PATH   "0:/TOTP/hotp_accounts.txt"
#define HOTP_COUNTERS_PATH   "0:/TOTP/hotp_counters.txt"

typedef struct
{
    char     name[TOTP_NAME_MAX];
    uint8_t  key[TOTP_KEY_MAX];
    uint8_t  key_len;
    uint32_t counter;       /* HOTP only */
    bool     is_hotp;
} totp_account_t;

static totp_account_t s_accounts[TOTP_MAX_ACCOUNTS];
static uint8_t        s_account_count = 0U;

/* Default Unix epoch baseline (2024-01-01 00:00:00 UTC) used when the RTC
 * year is below 2024 — the firmware default is 2024, so this is just a sane
 * floor while the user has no real time set. */
#define UNIX_EPOCH_FALLBACK_YEAR    2024U

/*=============================================================================
 *  S H A - 1
 *
 *  Standard FIPS-180-1 implementation.  ~6 KB code, no allocations.
 *===========================================================================*/
typedef struct
{
    uint32_t state[5];
    uint64_t total_bits;
    uint8_t  buffer[64];
    uint8_t  buf_len;
} sha1_ctx_t;

static uint32_t sha1_rol(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32U - n));
}

static void sha1_compress(sha1_ctx_t *ctx, const uint8_t *block)
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, t;
    uint32_t i;

    for (i = 0U; i < 16U; i++)
    {
        w[i] = ((uint32_t)block[i * 4U]      << 24)
             | ((uint32_t)block[i * 4U + 1U] << 16)
             | ((uint32_t)block[i * 4U + 2U] << 8)
             | ((uint32_t)block[i * 4U + 3U]);
    }
    for (i = 16U; i < 80U; i++)
    {
        w[i] = sha1_rol(w[i - 3U] ^ w[i - 8U] ^ w[i - 14U] ^ w[i - 16U], 1U);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0U; i < 80U; i++)
    {
        if (i < 20U)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        }
        else if (i < 40U)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        }
        else if (i < 60U)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        t = sha1_rol(a, 5U) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rol(b, 30U);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->total_bits = 0U;
    ctx->buf_len = 0U;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    while (len > 0U)
    {
        size_t take = (size_t)(64U - ctx->buf_len);
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buf_len, data, take);
        ctx->buf_len += (uint8_t)take;
        data += take;
        len  -= take;
        if (ctx->buf_len == 64U)
        {
            sha1_compress(ctx, ctx->buffer);
            ctx->total_bits += 512U;
            ctx->buf_len = 0U;
        }
    }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t out[20])
{
    uint64_t total_bits = ctx->total_bits + (uint64_t)ctx->buf_len * 8U;
    uint8_t  pad = 0x80U;

    sha1_update(ctx, &pad, 1U);
    pad = 0x00U;
    while (ctx->buf_len != 56U)
    {
        sha1_update(ctx, &pad, 1U);
    }
    /* append length big-endian */
    uint8_t lenbuf[8];
    lenbuf[0] = (uint8_t)(total_bits >> 56);
    lenbuf[1] = (uint8_t)(total_bits >> 48);
    lenbuf[2] = (uint8_t)(total_bits >> 40);
    lenbuf[3] = (uint8_t)(total_bits >> 32);
    lenbuf[4] = (uint8_t)(total_bits >> 24);
    lenbuf[5] = (uint8_t)(total_bits >> 16);
    lenbuf[6] = (uint8_t)(total_bits >>  8);
    lenbuf[7] = (uint8_t)(total_bits);
    sha1_update(ctx, lenbuf, 8U);

    for (uint8_t i = 0U; i < 5U; i++)
    {
        out[i * 4U]      = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4U + 1U] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4U + 2U] = (uint8_t)(ctx->state[i] >>  8);
        out[i * 4U + 3U] = (uint8_t)(ctx->state[i]);
    }
}

/*=============================================================================
 *  H M A C - S H A - 1
 *
 *  Per RFC 2104.  Block size B = 64 bytes for SHA-1.
 *===========================================================================*/
static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t out[20])
{
    uint8_t  k_pad[64];
    uint8_t  o_key_pad[64];
    uint8_t  inner[20];
    sha1_ctx_t ctx;
    size_t   i;

    if (key_len > 64U)
    {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, k_pad);
        memset(k_pad + 20U, 0, 64U - 20U);
    }
    else
    {
        memcpy(k_pad, key, key_len);
        memset(k_pad + key_len, 0, 64U - key_len);
    }

    for (i = 0U; i < 64U; i++)
    {
        o_key_pad[i] = k_pad[i] ^ 0x5CU;
        k_pad[i]    ^= 0x36U;
    }

    /* inner = SHA1((K xor ipad) || msg) */
    sha1_init(&ctx);
    sha1_update(&ctx, k_pad, 64U);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, inner);

    /* out = SHA1((K xor opad) || inner) */
    sha1_init(&ctx);
    sha1_update(&ctx, o_key_pad, 64U);
    sha1_update(&ctx, inner, 20U);
    sha1_final(&ctx, out);
}

/*=============================================================================
 *  B A S E - 3 2   D E C O D E R   ( RFC 4648 )
 *===========================================================================*/
static int totp_base32_decode(const char *encoded, uint8_t *decoded, int max_len)
{
    int      out_idx = 0;
    uint32_t buf     = 0U;
    int      bits    = 0;
    char     c;

    while ((c = *encoded++) != '\0')
    {
        int v;
        if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a';
        else if (c >= '2' && c <= '7')
            v = (c - '2') + 26;
        else
            return -1; /* invalid character */

        buf = (buf << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            if (out_idx >= max_len)
                return -1; /* overflow */
            decoded[out_idx++] = (uint8_t)((buf >> bits) & 0xFFU);
        }
    }
    return out_idx;
}

/*=============================================================================
 *  H O T P  /  T O T P
 *===========================================================================*/
static uint32_t hotp_compute(const uint8_t *key, size_t key_len, uint64_t counter)
{
    uint8_t msg[8];
    uint8_t hash[20];

    msg[0] = (uint8_t)(counter >> 56);
    msg[1] = (uint8_t)(counter >> 48);
    msg[2] = (uint8_t)(counter >> 40);
    msg[3] = (uint8_t)(counter >> 32);
    msg[4] = (uint8_t)(counter >> 24);
    msg[5] = (uint8_t)(counter >> 16);
    msg[6] = (uint8_t)(counter >>  8);
    msg[7] = (uint8_t)(counter);

    hmac_sha1(key, key_len, msg, sizeof(msg), hash);

    uint8_t  off = hash[19] & 0x0FU;
    uint32_t bin = ((uint32_t)(hash[off]     & 0x7FU) << 24)
                 | ((uint32_t) hash[off + 1U]         << 16)
                 | ((uint32_t) hash[off + 2U]         <<  8)
                 | ((uint32_t) hash[off + 3U]);

    /* 10^TOTP_DIGITS */
    uint32_t mod = 1U;
    for (uint32_t i = 0U; i < TOTP_DIGITS; i++) mod *= 10U;
    return bin % mod;
}

/*=============================================================================
 *  R T C   -- > U N I X   T I M E
 *
 *  Convert m1_get_datetime() output to a Unix epoch (seconds since
 *  1970-01-01 00:00:00 UTC) using a Howard Hinnant style civil-from-days
 *  algorithm — branchless and overflow-safe for 1970..2099.
 *===========================================================================*/
static int64_t totp_civil_to_days(int32_t y, uint32_t m, uint32_t d)
{
    /* Days from Mar 1 of year 0; works for any year incl. before 1970 */
    y -= (m <= 2U) ? 1 : 0;
    int32_t  era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);                       /* 0..399 */
    uint32_t doy = (153U * (m + (m > 2U ? -3U : 9U)) + 2U) / 5U + d - 1U; /* 0..365 */
    uint32_t doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;        /* 0..146096 */
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static uint64_t totp_now_unix(void)
{
    m1_time_t dt;

    memset(&dt, 0, sizeof(dt));
    m1_get_datetime(&dt);

    if (dt.year < UNIX_EPOCH_FALLBACK_YEAR)
    {
        /* RTC not set — degrade to a tick-based pseudo-clock so the UI still
         * animates and codes still rotate, even though they will not match
         * a real authenticator's expectation.                                */
        return (uint64_t)(HAL_GetTick() / 1000U);
    }

    int64_t days = totp_civil_to_days((int32_t)dt.year, (uint32_t)dt.month, (uint32_t)dt.day);
    int64_t secs = days * 86400
                 + (int64_t)dt.hour   * 3600
                 + (int64_t)dt.minute * 60
                 + (int64_t)dt.second;
    if (secs < 0) secs = 0;
    return (uint64_t)secs;
}

/*=============================================================================
 *  S D - C A R D   I / O
 *===========================================================================*/
static void totp_strip_eol(char *line)
{
    size_t n = strlen(line);
    while (n > 0U && (line[n - 1U] == '\r' || line[n - 1U] == '\n'
                  ||  line[n - 1U] == ' '  || line[n - 1U] == '\t'))
    {
        line[--n] = '\0';
    }
}

static bool totp_read_line(FIL *fp, char *buf, int max)
{
    int  i = 0;
    UINT br;
    char ch;

    while (i < max - 1)
    {
        if (f_read(fp, &ch, 1U, &br) != FR_OK || br == 0U)
        {
            buf[i] = '\0';
            return i > 0;
        }
        if (ch == '\n')
        {
            buf[i] = '\0';
            return true;
        }
        if (ch != '\r')
        {
            buf[i++] = ch;
        }
    }
    buf[i] = '\0';
    return true;
}

/*===========================================================================*/
/**
 * @brief  Parse one "Name:BASE32" line into an account slot.
 */
/*===========================================================================*/
static bool totp_parse_account_line(const char *line, totp_account_t *acc, bool is_hotp)
{
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '\0' || *line == '#') return false;

    const char *colon = strchr(line, ':');
    if (colon == NULL || colon == line) return false;

    size_t name_len = (size_t)(colon - line);
    if (name_len >= TOTP_NAME_MAX) name_len = TOTP_NAME_MAX - 1U;
    memcpy(acc->name, line, name_len);
    acc->name[name_len] = '\0';
    /* trim trailing space from name */
    while (name_len > 0U && (acc->name[name_len - 1U] == ' '
                          || acc->name[name_len - 1U] == '\t'))
    {
        acc->name[--name_len] = '\0';
    }

    int dec = totp_base32_decode(colon + 1, acc->key, TOTP_KEY_MAX);
    if (dec <= 0) return false;
    acc->key_len = (uint8_t)dec;
    acc->counter = 0U;
    acc->is_hotp = is_hotp;
    return true;
}

/*===========================================================================*/
/**
 * @brief  Load all accounts.  Tries HOTP file first, then TOTP file.  Returns
 *         the number of accounts loaded (also stored in s_account_count).
 *         Both files may be present — TOTP entries are appended after HOTP.
 */
/*===========================================================================*/
static uint8_t totp_load_accounts(void)
{
    FIL  fp;
    char line[128];

    s_account_count = 0U;

    /* HOTP accounts */
    if (f_open(&fp, HOTP_ACCOUNTS_PATH, FA_READ) == FR_OK)
    {
        while (totp_read_line(&fp, line, sizeof(line))
            && s_account_count < TOTP_MAX_ACCOUNTS)
        {
            totp_strip_eol(line);
            if (line[0] == '\0') continue;
            if (totp_parse_account_line(line, &s_accounts[s_account_count], true))
                s_account_count++;
        }
        f_close(&fp);
    }

    /* TOTP accounts */
    if (f_open(&fp, TOTP_ACCOUNTS_PATH, FA_READ) == FR_OK)
    {
        while (totp_read_line(&fp, line, sizeof(line))
            && s_account_count < TOTP_MAX_ACCOUNTS)
        {
            totp_strip_eol(line);
            if (line[0] == '\0') continue;
            if (totp_parse_account_line(line, &s_accounts[s_account_count], false))
                s_account_count++;
        }
        f_close(&fp);
    }

    /* Load HOTP counters (if any HOTP accounts exist) */
    if (f_open(&fp, HOTP_COUNTERS_PATH, FA_READ) == FR_OK)
    {
        while (totp_read_line(&fp, line, sizeof(line)))
        {
            totp_strip_eol(line);
            if (line[0] == '\0' || line[0] == '#') continue;
            char *colon = strchr(line, ':');
            if (colon == NULL) continue;
            *colon = '\0';
            uint32_t cnt = 0U;
            for (const char *p = colon + 1; *p; p++)
            {
                if (*p < '0' || *p > '9') break;
                cnt = cnt * 10U + (uint32_t)(*p - '0');
            }
            for (uint8_t i = 0U; i < s_account_count; i++)
            {
                if (s_accounts[i].is_hotp
                 && strcmp(s_accounts[i].name, line) == 0)
                {
                    s_accounts[i].counter = cnt;
                    break;
                }
            }
        }
        f_close(&fp);
    }

    return s_account_count;
}

/*===========================================================================*/
/**
 * @brief  Persist HOTP counters back to SD card.
 */
/*===========================================================================*/
static void totp_save_hotp_counters(void)
{
    FIL  fp;
    UINT bw;
    char line[64];

    f_mkdir("0:/TOTP");
    if (f_open(&fp, HOTP_COUNTERS_PATH, FA_WRITE | FA_CREATE_ALWAYS) != FR_OK)
        return;

    for (uint8_t i = 0U; i < s_account_count; i++)
    {
        if (!s_accounts[i].is_hotp) continue;
        int n = snprintf(line, sizeof(line), "%s:%lu\n",
                         s_accounts[i].name,
                         (unsigned long)s_accounts[i].counter);
        if (n > 0)
            (void)f_write(&fp, line, (UINT)n, &bw);
    }
    f_close(&fp);
}

/*=============================================================================
 *  U I
 *===========================================================================*/
static void totp_draw_no_accounts(void)
{
    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 9, "TOTP Auth");

        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 2, 20, "No accounts found.");
        u8g2_DrawStr(&m1_u8g2, 2, 30, "Create on SD:");
        u8g2_DrawStr(&m1_u8g2, 2, 40, "/TOTP/accounts.txt");
        u8g2_DrawStr(&m1_u8g2, 2, 50, "Name:BASE32SECRET");

        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", "", NULL);
    } while (m1_u8g2_nextpage());
}

/*===========================================================================*/
/**
 * @brief  Main account display.  Big 6-digit code with countdown bar.
 */
/*===========================================================================*/
static void totp_draw_account(const totp_account_t *acc, uint32_t code,
                              uint32_t seconds_left, uint8_t idx, uint8_t total)
{
    char digits[16];
    char header[40];
    uint8_t bar_w;

    /* "123 456" formatting */
    snprintf(digits, sizeof(digits), "%03lu %03lu",
             (unsigned long)(code / 1000U),
             (unsigned long)(code % 1000U));

    snprintf(header, sizeof(header), "%s%u/%u",
             acc->is_hotp ? "[HOTP] " : "",
             (unsigned)(idx + 1U), (unsigned)total);

    if (acc->is_hotp)
    {
        bar_w = 100U;
    }
    else
    {
        bar_w = (uint8_t)((seconds_left * 100U) / TOTP_PERIOD_SEC);
        if (bar_w > 100U) bar_w = 100U;
    }

    m1_u8g2_firstpage();
    do
    {
        u8g2_SetDrawColor(&m1_u8g2, M1_DISP_DRAW_COLOR_TXT);

        /* Title bar: account name + index */
        u8g2_SetFont(&m1_u8g2, M1_DISP_MAIN_MENU_FONT_N);
        /* Truncate name visually to ~16 chars */
        char nbuf[20];
        size_t nlen = strlen(acc->name);
        if (nlen > 16U) nlen = 16U;
        memcpy(nbuf, acc->name, nlen);
        nbuf[nlen] = '\0';
        u8g2_DrawStr(&m1_u8g2, 2, 9, nbuf);
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        u8g2_DrawStr(&m1_u8g2, 92, 8, header);

        /* Big digits in middle band */
        u8g2_SetFont(&m1_u8g2, u8g2_font_inb16_mn);
        u8g2_DrawStr(&m1_u8g2, 8, 32, digits);

        /* Countdown bar */
        u8g2_DrawFrame(&m1_u8g2, 2, 38, 102, 7);
        if (bar_w > 0U)
            u8g2_DrawBox(&m1_u8g2, 3, 39, bar_w, 5);

        /* Hint text */
        u8g2_SetFont(&m1_u8g2, M1_DISP_FUNC_MENU_FONT_N);
        if (acc->is_hotp)
            u8g2_DrawStr(&m1_u8g2, 2, 54, "OK=next code  UP/DN=acct");
        else
            u8g2_DrawStr(&m1_u8g2, 2, 54, "UP/DN=acct  BACK=exit");

        m1_draw_bottom_bar(&m1_u8g2, arrowleft_8x8, "Back", acc->is_hotp ? "Next" : "", arrowright_8x8);
    } while (m1_u8g2_nextpage());
}

/*===========================================================================*/
/**
 * @brief  Top-level entry point.
 */
/*===========================================================================*/
void app_totp_run(void)
{
    S_M1_Buttons_Status btn;
    S_M1_Main_Q_t       q_item;
    BaseType_t          ret;
    uint8_t             sel = 0U;
    uint64_t            last_step  = 0xFFFFFFFFFFFFFFFFULL;
    uint32_t            last_secs  = 0xFFFFFFFFU;
    uint32_t            cur_code   = 0U;
    bool                redraw     = true;

    if (main_q_hdl != NULL)
        xQueueReset(main_q_hdl);

    if (totp_load_accounts() == 0U)
    {
        totp_draw_no_accounts();

        /* Wait for back */
        while (1)
        {
            if (xQueueReceive(main_q_hdl, &q_item, portMAX_DELAY) != pdTRUE)
                continue;
            if (q_item.q_evt_type != Q_EVENT_KEYPAD) continue;
            if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE) continue;
            if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
             || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
                break;
        }
        if (main_q_hdl != NULL) xQueueReset(main_q_hdl);
        return;
    }

    while (1)
    {
        totp_account_t *acc = &s_accounts[sel];

        uint64_t unix_now;
        uint64_t step;
        uint32_t secs_left;

        if (acc->is_hotp)
        {
            unix_now = 0U;
            step     = acc->counter;
            secs_left = 0U;
        }
        else
        {
            unix_now  = totp_now_unix();
            step      = unix_now / TOTP_PERIOD_SEC;
            secs_left = (uint32_t)(TOTP_PERIOD_SEC - (unix_now % TOTP_PERIOD_SEC));
        }

        if (redraw || step != last_step || secs_left != last_secs)
        {
            if (redraw || step != last_step)
            {
                cur_code = hotp_compute(acc->key, acc->key_len, step);
                last_step = step;
            }
            last_secs = secs_left;
            totp_draw_account(acc, cur_code, secs_left, sel, s_account_count);
            redraw = false;
        }

        /* Wait up to ~250ms to refresh countdown bar smoothly */
        ret = xQueueReceive(main_q_hdl, &q_item, pdMS_TO_TICKS(250));
        if (ret != pdTRUE)
            continue;

        if (q_item.q_evt_type != Q_EVENT_KEYPAD)
            continue;

        if (xQueueReceive(button_events_q_hdl, &btn, 0) != pdTRUE)
            continue;

        if (btn.event[BUTTON_BACK_KP_ID] == BUTTON_EVENT_CLICK
         || btn.event[BUTTON_LEFT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            break;
        }
        else if (btn.event[BUTTON_UP_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (sel == 0U) ? (uint8_t)(s_account_count - 1U) : (uint8_t)(sel - 1U);
            redraw = true;
        }
        else if (btn.event[BUTTON_DOWN_KP_ID] == BUTTON_EVENT_CLICK)
        {
            sel = (uint8_t)((sel + 1U) % s_account_count);
            redraw = true;
        }
        else if (btn.event[BUTTON_OK_KP_ID]    == BUTTON_EVENT_CLICK
              || btn.event[BUTTON_RIGHT_KP_ID] == BUTTON_EVENT_CLICK)
        {
            if (acc->is_hotp)
            {
                acc->counter++;
                totp_save_hotp_counters();
                redraw = true;
            }
            /* TOTP OK is reserved for "copy" but we have no clipboard, so
             * just visually flash by forcing a redraw. */
            redraw = true;
        }
    }

    if (main_q_hdl != NULL)
        xQueueReset(main_q_hdl);
}

#endif /* M1_APP_TOTP_ENABLE */
