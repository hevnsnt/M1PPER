/* See COPYING.txt for license details. */

/*
 * app_ibutton.h
 *
 * Dallas / Maxim iButton 1-Wire ROM-code reader (DS1990A / DS1990R etc.)
 *
 * M1 Project
 */

#ifndef APP_IBUTTON_H_
#define APP_IBUTTON_H_

#include "m1_compile_cfg.h"

#ifdef M1_APP_IBUTTON_ENABLE

void app_ibutton_run(void);

#endif /* M1_APP_IBUTTON_ENABLE */

#endif /* APP_IBUTTON_H_ */
