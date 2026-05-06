/* See COPYING.txt for license details. */

/*
*
* app_net_recon.h
*
* Net Recon: TCP/IP reconnaissance suite (ARP sweep, port scan, OUI
* lookup) over the ESP32-C6 AT command interface.
*
* M1 Project
*
*/

#ifndef APP_NET_RECON_H_
#define APP_NET_RECON_H_

#include "m1_compile_cfg.h"

#ifdef M1_APP_NET_RECON_ENABLE

void app_net_recon_run(void);

#endif /* M1_APP_NET_RECON_ENABLE */

#endif /* APP_NET_RECON_H_ */
