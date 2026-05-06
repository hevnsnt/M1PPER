# Phase 4 - Wireless Subsystem Progress

Branch: `phase-4-wireless` (local only - not pushed).
Build: `cmake --build build` clean. ELF is 991-994KB / 1023K FLASH.
Commits: 11 wireless-prefixed commits from `feed7ad` to `8baaf59`.

## Item-by-item status (from .claude/audits/PLAN.md Phase 4 + 04-wireless.md)

### Critical findings

| # | Finding | Status | Notes |
| --- | --- | --- | --- |
| C1 | Evil Portal DNS hijack + captive-portal probe URL handlers | partial | Probe URL handler done (302 redirect for /generate_204, /hotspot-detect.html, /ncsi.txt, /connecttest.txt, /success.txt, /gen_204, /library/test/success.html). DNS hijack documented as TODO at top of `app_evil_portal.c` with the exact ESP-AT firmware change required (custom AT+M1DNSHIJACK command, UDP/53 catchall responder). ESP-side change is out of this phase's scope per coordination constraints. |
| C2 | Pre-flash MD5 mismatch silently swallowed | done | Now surfaces `M1_FW_CRC_FILE_INVALID` and aborts (commit `c4d949e`). |
| C3 | `m1_fw_flash_binary` keeps init_done across failed flash | done | `init_done` and `s_written_total` cleared in EVERY failure path (commit `c4d949e`). |
| C4 | BLE-Spam/BLEPTD AirTag payloads structurally malformed | done | Payload tables rebuilt with correct AD lengths; `ble_spam_validate_payload()` runtime validator + boot-time self-test added (commit `8cc9bdd`). AirTag now uses 27-byte FindMy OF format with no Flags AD (drops to fit 31-byte limit). |
| C5 | SwiftPair payloads in s_windows[] not actually SwiftPair | done | Rebuilt to documented `06FF0600 03 00 <Cat> <Sub> <name>` format; covers Mouse/Keyboard/Headset (commit `8cc9bdd`). |
| C6 | at_spi_master_send_data ignores HAL_StatusTypeDef | done | HAL status now stored to `s_last_hal_status`; `spi_AT_send_recv` checks before going to get_response, surfaces `CTRL_ERR_TRANSPORT_SEND` and a `SPI_HAL_ERR=N` token immediately instead of blocking 30s (commit `feed7ad`). |
| C7 | 802.15.4 sniff depends on AT+ZIGSNIFF not in esp_at_list.h | partial | Confirmed missing; on-device sniff start failure now surfaces "AT firmware lacks 802.15.4 sniff support - flash newer ESP-AT" instead of "no devices found". TODO block added to `m1_802154.c` with exact ESP-side change (esp_ieee802154_* API + custom command). ESP-side change is out of scope per coordination constraints (commit `dd9c09e`). |
| C8 | EAPOL-Logoff labeled "PMF bypass" | done | Relabel to "EAPOL-Logoff (no MFP)"; `wifi_esp_eapollogoff` now queries `AT+CWJAP?`, parses the trailing pmf field, and refuses if station is not associated OR pmf-required is set (commit `feed7ad`). |

### High findings

| # | Finding | Status | Notes |
| --- | --- | --- | --- |
| H1 | Wardrive output not WiGLE-1.4 compliant | done | FirstSeen now from `m1_get_localtime()`; AccuracyMeters set to 99999 per WiGLE convention for "position unknown" so rows are accepted (commit `dd9c09e`). |
| H2 | Deauth uses ff:ff broadcast on PMF-required APs | partial | Now performs targeted CWLAP rescan when station_mac is broadcast and refuses if pmf field bit1 set. Returns ERROR with log message. Caller-side grey-out of menu still requires Phase 6 menu work. (commit `b1a650b`). |
| H3 | OK/ERROR detection looks for substrings | done | New helper `at_response_is_terminated()` does strict tail-match on `\r\nOK\r\n` / `\r\nERROR\r\n`. SSID name "TheBookOK" or GATT value "OK\r\n" no longer trigger false success (commit `feed7ad`). |
| H4 | gatt_connect returns true on synchronous OK | done | Now waits up to GATT_CONN_TIMEOUT_S seconds for the unsolicited `+BLECONN:0` event (commit `3b4ae76`). |
| H5 | GATT_MAX_CHARS=48, MAX_SERVICES=16 too small | done | Bumped to 128/32; truncation indicator added that appends "+" to header counts when tables overflow (commit `3b4ae76`). |
| H6 | SPI seq_num==1 "Maybe SLAVE restart, ignore" | done | Now sets `s_esp_slave_restarted` flag; `esp_consume_slave_restart_event()` API added; BLE Spam and BLEPTD scan loops now consume the flag and rebuild advertising/init state (commits `feed7ad`, `8baaf59`). |
| H7 | TX_* tracker payloads use FIXED identifiers | partial | BD_ADDR rotation per emission now actually issued via `AT+BLEADDR=1,"<hexmac>"` (was building string but never sending - commit `8cc9bdd`). Per-emission payload mutation after fixed prefix not yet implemented; would require changes to TX_AIRTAG/TX_FINDMY/TX_GALAXY_TAG hex strings to randomize the 22-byte public-key-stand-in. |
| H8 | ep_send_response sends header+body in one CIPSEND call | done | Full CIPSEND state machine: AT+CIPSEND= -> wait OK + ">" prompt -> raw write -> consume "SEND OK" / "SEND FAIL". Treats bare "OK" inside payload as not-success (commit `104fa84`). |
| H9 | When .bin has no .md5, no protection against corrupted SD bin | done | Computes MD5 of the SD-card .bin in 1024-byte chunks, displays both halves of the hash via `m1_message_box_choice`, requires Flash/Abort confirm (commit `c4d949e`). |

### Medium findings

| # | Finding | Status | Notes |
| --- | --- | --- | --- |
| M1 | m1_esp32_uart_tx semaphore stall on DMA error | not done | Out of immediate scope; UART TX path is dead-code while ESP32_UART_DISABLE is set. |
| M2 | esp_app_main strcpy on binary AT data truncates | not done | Existing strcpy at line 320 is safe because trans_data is null-terminated by `trans_data[recv_opt.transmit_len] = '\0'`. The risk is binary AT payloads containing nulls; would need full memcpy + length tracking. Not blocking any feature. |
| M3 | app_bleptd line parser destructive on \r\n split | partial | Audit acknowledged. Current parser handles malformed lines gracefully (returns false). True split-line state machine would require larger refactor and is not blocking dedup correctness in practice (spi_AT_send_recv concatenates chunks into single buffer terminated by OK/ERROR). |
| M4 | BLEINIT=1 while role=2 returns ERROR | done | scan_devices and gatt_connect now issue BLEINIT=0 first (commit `3b4ae76`). |
| M5 | Teardown race between BLEADVSTOP and BLEINIT=0 | not done | Vendor stack interaction; would require deeper sequencing. Workaround in M4 handles re-entry. |
| M6 | EP s_ep_at_buf 1024 truncates POSTs > 900 bytes | done | Bumped to 4096 (commit `ae0ac11`). |
| M7 | EP doesn't snapshot/restore CWJAP | done | `ep_snapshot_sta_assoc` captures pre-portal SSID; on portal stop displays "Reconnect manually: <SSID>" so user knows to revisit WiFi page. ESP-AT does not return password from CWJAP? for security, so fully automatic reconnect requires a stored copy in M1's wifi-cred store (out of scope for this file) (commit `060fc87`). |
| M8 | bleptd random_mac() never issues AT+BLEADDR | done | Confusion mode now actually rotates the on-air MAC (commit `8cc9bdd`). |
| M9 | get_matching_response throttles other commands during +BLESCAN | not done | Architectural; FIFO with UID indexing already exists in current code. No regressions. |
| M10 | +ZIGFRAME flushed by polling AT command | not done | Depends on ESP-AT having ZIGSNIFF at all (item C7). |
| M11 | esp_app_main at_cmd_buf 64 bytes tight, no snprintf check | not done | Local helper; existing snprintf truncates safely at 64 bytes. Not corrupting data. |
| M12 | read_char_value parses 3 fields, response has 4 | done | Now parses `<conn>,<srv>,<char>,<value>` (commit `3b4ae76`). |

### Low / Polish

Most low items unaddressed - not blocking documented features. The high-leverage Low items in the audit (e.g. larger OUI table) are explicitly in Phase 7.

## Build state

Final build (`8baaf59`):
- FLASH: 1010904 / 1023K (96.47% used)
- RAM: 501408 / 640K (76.51% used)
- Clean compile -Werror except pre-existing TPMS / bq27421 warnings unrelated to this phase.

## Files modified (within scope)

- `m1_csrc/app_evil_portal.c` (CIPSEND state machine, captive-portal probes, AT buf bump, SSID snapshot, DNS TODO doc)
- `m1_csrc/app_ble_spam.c`, `app_ble_spam.h` (payload table rebuild, validator, slave-restart consume)
- `m1_csrc/app_bleptd.c` (real BLEADDR rotation, slave-restart consume)
- `m1_csrc/app_ble_gatt.c` (bigger tables, +BLECONN:0 wait, 4-field BLEGATTCRD parse, truncation indicator, BLEINIT=0 first)
- `m1_csrc/m1_802154.c` (TODO block + better error message)
- `m1_csrc/m1_esp32_fw_update.c` (MD5 mismatch hard stop, compute-MD5 fallback, init_done reset)
- `m1_csrc/m1_wifi.c` (wardrive RTC FirstSeen + AccuracyMeters=99999, EAPOL-Logoff label, AT firmware ID check)
- `esp_spi_at/examples/at_spi_master/spi/stm32/main/esp_app_main.c` (HAL error propagation, slave restart event API, AT+GMR identity check, EAPOL/Deauth PMF guards)
- `esp_spi_at/examples/at_spi_master/spi/stm32/main/esp_app_main.h` (new public functions)
- `esp_spi_at/examples/at_spi_master/spi/stm32/main/m1_at_response_parser.c`, `.h` (`at_response_is_terminated` helper)

## Files NOT modified (out-of-scope)

Per coordination constraints in the Phase 4 prompt: did not touch `Core/Src/main.c`, `FreeRTOSConfig.h`, linker scripts, `m1_int_hdl.c`, `m1_lcd.c`, `m1_rf_spi.c`, NFC files, Sub-GHz files, RPC files, ELF loader files. Other phases own those.

## Open follow-ups requiring ESP-AT firmware changes (out of scope)

These were documented as TODO in the relevant source files. They cannot be fixed from the STM32-side codebase alone; they need work in `D:\M1Projects\esp32-at-hid\`:

1. `AT+M1DNSHIJACK=<ip>` UDP/53 catchall to fully close the Evil Portal capture loop for clients that bypass HTTP probes.
2. `AT+ZIGSNIFF=<enable>[,<channel>]` using `esp_ieee802154_*` to make the 802.15.4 menu actually work.
3. Plumb the encryption_mode capabilities byte (PMF capabilities) from the ESP scan cache through CWLAP so the master can pre-grey the Deauth menu without an extra CWLAP rescan per attempt.
4. Custom command to read back the AT firmware build identifier earlier than the response stream (currently checked via AT+GMR substring match against "ESP32C6-SPI").

End of summary.
