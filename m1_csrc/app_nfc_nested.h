/* See COPYING.txt for license details. */

/*
 * app_nfc_nested.h
 *
 * MIFARE Classic Default Key Survey (a.k.a. Default Key Attack).
 * Tries the most common factory/default keys against every sector of a
 * MIFARE Classic 1K/4K card and reports which sector responds to which key.
 */

#ifndef APP_NFC_NESTED_H_
#define APP_NFC_NESTED_H_

void app_nfc_nested_run(void);

#endif /* APP_NFC_NESTED_H_ */
