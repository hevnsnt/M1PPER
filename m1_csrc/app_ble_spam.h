/* See COPYING.txt for license details. */

#ifndef APP_BLE_SPAM_H_
#define APP_BLE_SPAM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef M1_APP_BLE_SPAM_ENABLE
void ble_spam_run(void);

/* Validate a raw BLE adv payload. Walks AD structures and asserts
 * sum(length + 1) <= 31 (BLE 5.0 legacy adv max). Returns true on
 * structurally valid payloads, false on malformed/over-length. */
bool ble_spam_validate_payload(const uint8_t *adv, size_t len);
#endif

#endif /* APP_BLE_SPAM_H_ */
