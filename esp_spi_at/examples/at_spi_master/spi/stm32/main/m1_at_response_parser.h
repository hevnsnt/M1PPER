/* See COPYING.txt for license details. */

/*
*
* m1_at_response_parser.h
*
* M1 parser for EPS32 module
*
* M1 Project
*
*/

#ifndef M1_AT_RESPONSE_PARSER_H_
#define M1_AT_RESPONSE_PARSER_H_

#include <stdbool.h>
#include <stddef.h>
#include "m1_compile_cfg.h"

char *m1_resp_string_strip(char *resp, const char *substr);
uint8_t m1_parse_spi_at_resp(char *resp, const char *resp_key, ctrl_cmd_t *app_resp);

/* Returns true if the buffer ends in a final response terminator
 * "\r\nOK\r\n" or "\r\nERROR\r\n" (or the bare "OK\r\n"/"ERROR\r\n"
 * prefix for first-chunk single-line responses). On true, *is_error
 * is set to true if the terminator was an ERROR. Substring matches
 * inside the buffer (e.g. inside SSID names, GATT values, or +IPD
 * blobs) do not trigger termination. */
bool at_response_is_terminated(const char *buf, size_t len, bool *is_error);

#ifdef M1_APP_BT_MANAGE_ENABLE
uint8_t m1_parse_ble_scan_resp(char *resp, const char *resp_key, ctrl_cmd_t *app_resp);
#endif

#endif /* M1_AT_RESPONSE_PARSER_H_ */
