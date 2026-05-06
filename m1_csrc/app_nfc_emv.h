/* See COPYING.txt for license details. */

/*
 * app_nfc_emv.h
 *
 * EMV (contactless payment) card reader.
 * Walks PPSE -> SELECT AID -> GET PROCESSING OPTIONS -> READ RECORD,
 * then parses TLV for PAN, expiry, cardholder name.
 */

#ifndef APP_NFC_EMV_H_
#define APP_NFC_EMV_H_

void app_nfc_emv_run(void);

#endif /* APP_NFC_EMV_H_ */
