/* See COPYING.txt for license details. */

/*
*
* app_evil_portal.h
*
* Evil Portal: captive portal credential harvester (WiFi AP + HTTP server
* via ESP32-C6 AT commands).  Saves captured creds to /WiFi/portal_creds.txt.
*
* M1 Project
*
*/

#ifndef APP_EVIL_PORTAL_H_
#define APP_EVIL_PORTAL_H_

#include "m1_compile_cfg.h"

#ifdef M1_APP_EVIL_PORTAL_ENABLE

void app_evil_portal_run(void);

#endif /* M1_APP_EVIL_PORTAL_ENABLE */

#endif /* APP_EVIL_PORTAL_H_ */
