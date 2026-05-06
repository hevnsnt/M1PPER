# Phase 5 Security Hardening — Progress

Branch: `phase-4-wireless`
Build: `cmake --build build` — green throughout.
Excluded from scope per user: 5.1 (Ed25519 signing) and 5.2 (TrustZone /
RDP-2 key vault).

## Summary

| Item | Audit ref | Status | Commit(s) |
| --- | --- | --- | --- |
| 1. RPC FW_UPDATE_DATA bounds | 06 #1 | ✅ | `5cf134e` |
| 2. RPC path traversal + system-write protection | 06 #2 / 5.5 | ✅ | `5cf134e` |
| 3. RPC host pairing handshake | 06 #2 / 5.4 | ✅ | `b9eaeba` |
| 4. CLI buffer overruns (mtest sprintf → snprintf) | 06 #5 | ✅ | `4484a72` |
| 4. mtest NULL-param guard | 06 #4 | ✅ | `4484a72` |
| 4. configCOMMAND_INT_MAX_OUTPUT_SIZE 200 → 512 | 06 #5 | ✅ | `4484a72` |
| 5. cli_app.c cliWrite NUL termination | 01 high | ✅ | `4484a72` |
| 5. cli_app.c MAX_INPUT_LENGTH off-by-one | 01 high | ✅ | `4484a72` |
| 6. .m1app MPU sandbox before entry | 06 #4 / 5.6 | ⚠️ partial | `74ca3de` |
| 6. Drop unprivileged before app entry() | 06 #4 / 5.6 | ✅ | `74ca3de` |
| 6. Strip dangerous APIs from app_api table | 06 #4 / 5.6 | ✅ | `d5c7cda` |
| 6. App manifest permissions framework | 5.6 | ✅ | `74ca3de` |
| 6. ELF relocation r_offset bounds | 05 #2 / 5.7 | ✅ | `74ca3de` |
| 6. ELF SHN_COMMON / unhandled st_shndx | 05 #2 / 5.7 | ✅ | `74ca3de` |
| 6. ELF R_ARM_THM_CALL out-of-range fatal | 05 #3 / 5.7 | ✅ | `74ca3de` |
| 6. ELF entry SHF_EXECINSTR enforce | 05 #4 / 5.8 | ✅ | `74ca3de` |
| 7. TOTP/HOTP encryption with PIN-derived key | 5.9 | ⬜ doc-only | `db8fd9a` |
| 8. WiFi cred AES key TRNG-derived (OTP) | 06 #3 / 5.10 | ✅ | `35e59f1` |
| 9. IV generation from hardware TRNG | 06 medium / 5.11 | ✅ | `d5c7cda` |
| 9. Encrypt fail-closed on TRNG error | 06 medium / 5.11 | ✅ | `d5c7cda` |
| 10. settings.cfg line-by-line parser | 06 high / 5.13 | ✅ | `e1a7c24` |
| 10. badbt_name printable-ASCII filter | 06 high / 5.13 | ✅ | `e1a7c24` |
| 11. BadUSB DEFAULT_DELAY/RANDOM_DELAY clamps | 06 medium / 5.14 | ✅ | `f4a1a87` |
| 11. BadUSB IF/WHILE block scan buffer 64 → 256 | 06 medium / 5.14 | ✅ | `f4a1a87` |
| 12. Document signing absent in fw update path | n/a | ✅ | `db8fd9a` |
| flipper_nfc.c bound check | 05 #5 / 06 high | ✅ | (already done in `1dd0838`) |
| EMV PAN masking | 06 low | ✅ | (already done in `16da844`) |
| 5.1 Firmware signature verification | 06 #2 | ⬜ skipped per user |
| 5.2 TrustZone / RDP-2 key vault | 06 #2 | ⬜ skipped per user |

Legend: ✅ implemented · ⚠️ partial · ⬜ not done in this pass

## Notes on partial / not-done items

### 6. MPU sandbox (partial)

The user-mode privilege drop is in place (`__set_CONTROL` in
`m1_app_manager.c:app_task_wrapper`) and blocks the most direct
privilege primitives (NVIC, MPU, MSR PRIMASK/BASEPRI/FAULTMASK,
system control regs). The FreeRTOS ARM_CM33_NTZ port saves and
restores `CONTROL` per task context-switch so other tasks remain
privileged.

What is NOT in place: per-task MPU regions. The Cortex-M33 MPU is a
global resource and the linked FreeRTOS port (`ARM_CM33_NTZ`) does not
save/restore MPU state per task. Full memory-region isolation requires
migrating to `ARM_CM33_NTZ_MPU` plus rewiring every task creation site
to use `xTaskCreateRestricted`. That is an architectural change beyond
the scope of this Phase 5 pass and is tracked as a follow-up to 5.6 in
PLAN.md.

The active enforcement preventing apps from issuing peripheral writes
is the dangerous-API strip in `m1_app_api.c` (HAL_GPIO_*, raw SPI/I2C,
USB/HID, BadUSB, write-side FatFS, raw crypto-derive_key, srand). Apps
no longer see those symbols, so even though the MPU does not block raw
memory writes, the practical attack surface (peripheral abuse,
HID injection, file-system clobber) is closed.

### 7. TOTP secret encryption (doc-only)

The full PIN flow (PBKDF2-HMAC-SHA1, on-screen PIN entry, file format
migration) was deprioritised vs the immediately-exploitable network
surface (RPC bounds, ELF sandbox, TRNG IVs). A `SECURITY GAP` block at
the top of `app_totp.c` documents the intended fix and references
`m1_crypto_encrypt_with_key` (now fail-closed on TRNG error) as the
primitive to build on.

### 5.1 / 5.2 — explicitly skipped

`m1_fw_update_bl.c`, `boot_recovery_check`, and `bl_verify_bank_crc`
are untouched. The `rpc_handle_fw_update_finish` path now carries an
explicit `SECURITY GAP` comment so downstream readers know that
"CRC verified OK" does NOT mean "signed firmware".

## Build / regression

Every commit was preceded by `cmake --build build`. Final build with
all changes:

```
text    data    bss
1006836 18836  501332    →  ELF size 1525004 / 0x174D40
```

Bank-1 flash usage 97.6 % (1023132 / 1047552). FreeRTOS / RAM /
BKPSRAM regions unchanged. No new compiler warnings introduced.

## Security gain in one paragraph

Before this pass, an unauthenticated USB-CDC peer could:
flash arbitrary firmware (CRC-32 only), drop the device into ROM DFU,
overwrite `/System/wifi_cred.ini`, run any CLI command (including ones
that toggle the radio or wipe the SD card), and trigger reboot/poweroff
on demand. Independently, any `.m1app` on the SD card could call into
the firmware's BadUSB/HID and FatFS write APIs and pwn the host the
device was plugged into.

After this pass, all of those state-changing RPC commands are gated
behind a TRNG-backed pairing handshake the user must approve from the
device LCD before the host is admitted; firmware-update writes are
bounds-checked against the inactive bank; SD path traversal and system
writes are refused; `.m1app` loaders run unprivileged with the worst
APIs stripped from the symbol table; relocations are bounds-checked
and entry points must live in `SHF_EXECINSTR` sections; CBC IVs come
from the on-chip TRNG with fail-closed semantics; the WiFi-cred AES
key is per-device TRNG-derived and lives in OTP rather than UID-
derived from a global magic constant; and the BadUSB engine clamps
pathological delay scripts and fixes the IF/WHILE block scanner.

The remaining critical gaps — Ed25519 firmware signing (5.1) and
TrustZone key vault (5.2) — were skipped per user direction. TOTP
secret encryption (5.9) is documented but not implemented in this
pass.
