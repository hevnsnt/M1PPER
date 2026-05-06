/* See COPYING.txt for license details. */

/*
 * app_pocsag.h
 *
 * POCSAG pager decoder for M1 (uses SI4463 OOK direct mode).
 *
 * Listens for POCSAG (Post Office Code Standardisation Advisory Group)
 * paging frames on a user-selected frequency, demodulates the OOK
 * bitstream from edge timings captured by TIM1 input capture, locks on
 * the 0x7CD215D8 sync word, performs BCH(31,21) error correction on each
 * codeword, and displays decoded address (CAPCODE) plus message text.
 *
 * Supports the three POCSAG baud rates: 512, 1200, 2400 bps.
 */

#ifndef APP_POCSAG_H_
#define APP_POCSAG_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Entry point invoked from the Sub-GHz menu. */
void sub_ghz_pocsag(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_POCSAG_H_ */
