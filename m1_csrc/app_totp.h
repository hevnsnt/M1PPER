/* See COPYING.txt for license details. */

/*
 * app_totp.h
 *
 * RFC 6238 TOTP / RFC 4226 HOTP authenticator with SD-card seed storage.
 *
 * M1 Project
 */

#ifndef APP_TOTP_H_
#define APP_TOTP_H_

#include "m1_compile_cfg.h"

#ifdef M1_APP_TOTP_ENABLE

void app_totp_run(void);

#endif /* M1_APP_TOTP_ENABLE */

#endif /* APP_TOTP_H_ */
