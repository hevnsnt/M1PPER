/* See COPYING.txt for license details. */

/*
 * app_nfc_magic.h
 *
 * Magic Card writer entry point.
 * Supports MIFARE Classic Gen1A (CUID) backdoor write,
 * Gen2 (FUID) direct block-0 write, and Gen4 (GDID) password-unlock write.
 */

#ifndef APP_NFC_MAGIC_H_
#define APP_NFC_MAGIC_H_

void app_nfc_magic_run(void);

#endif /* APP_NFC_MAGIC_H_ */
