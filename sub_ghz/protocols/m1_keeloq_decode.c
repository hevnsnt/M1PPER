/* See COPYING.txt for license details. */

/*
*  m1_keeloq_decode.c
*
*  M1 sub-ghz KeeLoq decoding (decode-only, no key cracking)
*  Encoding: PWM - short-high + long-low → bit 0; long-high + short-low → bit 1
*  te_short ~400μs, te_long ~800μs
*  Preamble: header pulse, then 66 bits (32-bit encrypted + 28-bit serial + 4-bit button + 2 status)
*  Used by: Chamberlain, LiftMaster, Craftsman, many car alarms
*
*  NOTE: This only captures the raw rolling code packet for display.
*        Decryption requires the manufacturer key which is not included.
*/

#include <string.h>
#include <stdlib.h>
#include "stm32h5xx_hal.h"
#include "bit_util.h"
#include "m1_sub_ghz_decenc.h"
#include "m1_log_debug.h"

#define M1_LOGDB_TAG	"SUBGHZ_KEELOQ"

uint8_t subghz_decode_keeloq(uint16_t p, uint16_t pulsecount)
{
    /* KeeLoq packets are 66 bits, which does not fit in a single uint64.
     * Track the low 64 bits ("low") and the trailing 2 status bits ("high")
     * separately so the upper bits do not get silently shifted off. */
    uint64_t low  = 0;
    uint8_t  high = 0;          /* holds bit64..bit65, max value 0x03 */
    uint16_t te_short, te_long, tol_s, tol_l;
    uint16_t i;
    uint8_t bits_count = 0;
    uint8_t max_bits;

    max_bits = subghz_protocols_list[p].data_bits;
    te_short = subghz_protocols_list[p].te_short;
    te_long  = subghz_protocols_list[p].te_long;
    tol_s = (te_short * subghz_protocols_list[p].te_tolerance) / 100;
    tol_l = (te_long  * subghz_protocols_list[p].te_tolerance) / 100;

    /* Skip preamble bits if defined */
    i = subghz_protocols_list[p].preamble_bits;
    if (i >= pulsecount) return 1;

    for (; i + 1 < pulsecount && bits_count < max_bits; i += 2)
    {
        uint16_t t_hi = subghz_decenc_ctl.pulse_times[i];
        uint16_t t_lo = subghz_decenc_ctl.pulse_times[i + 1];

        uint8_t this_bit;
        if (get_diff(t_hi, te_short) < tol_s && get_diff(t_lo, te_long) < tol_l)
        {
            this_bit = 0;
        }
        else if (get_diff(t_hi, te_long) < tol_l && get_diff(t_lo, te_short) < tol_s)
        {
            this_bit = 1;
        }
        else
        {
            break;
        }

        /* Shift the (high, low) pair left by one and OR in the new bit at
         * the bottom.  The bit shifted out of the low half goes into the
         * low bit of high. */
        uint8_t carry = (uint8_t)((low >> 63) & 1U);
        low  = (low << 1) | (uint64_t)this_bit;
        high = (uint8_t)(((high << 1) | carry) & 0x03U);

        bits_count++;
    }

    if (bits_count >= max_bits)
    {
        /* Bit layout (transmitted MSB first into our (high,low) buffer):
         *   bits 0..1   (top of high) = status (2 bits)
         *   bits 2..5                 = button id (4 bits)
         *   bits 6..33                = serial (28 bits)
         *   bits 34..65               = encrypted rolling code (32 bits)
         *
         * After 66 shifts:
         *   high[1:0]            -> the top 2 bits  (status, top-most)
         *   low[63:62]           -> next 2 bits
         *   ...
         *   low[31:0]            -> rolling code (least significant 32)
         */
        uint64_t serial64    = (low >> 32) & 0x0FFFFFFFULL;        /* 28 bits */
        uint64_t button64    = (low >> 60) & 0x0FULL;              /* 4 bits  */
        uint8_t  status_bits = high & 0x03U;                       /* 2 bits  */

        subghz_decenc_ctl.n64_decodedvalue   = low;
        subghz_decenc_ctl.ndecodedbitlength  = bits_count;
        subghz_decenc_ctl.ndecodeddelay      = 0;
        subghz_decenc_ctl.ndecodedprotocol   = p;
        subghz_decenc_ctl.n32_rollingcode    = (uint32_t)(low & 0xFFFFFFFFUL);
        subghz_decenc_ctl.n32_serialnumber   = (uint32_t)serial64;
        /* Pack button (low 4 bits) + status (next 2) into the buttonid byte
         * so the existing UI display still shows something useful without
         * extending the decoder struct. */
        subghz_decenc_ctl.n8_buttonid        =
            (uint8_t)(button64 | ((uint8_t)status_bits << 4));

        return 0;
    }

    return 1;
}
