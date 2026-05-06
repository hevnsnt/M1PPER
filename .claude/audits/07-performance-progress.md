# Phase 7 — Performance / Hardware Utilization Progress

Branch: `phase-4-wireless`. Build: `cmake --build build` clean on ARM GCC 15.2.

Status legend: DONE / PARTIAL / BLOCKED / DEFERRED

## Critical work items (from phase prompt)

| # | Item | Status | Notes |
| - | ---- | ------ | ----- |
| 1 | HW HASH for MD5 (m1_md5_hash.c) | DEFERRED | HAL_HASH module + driver source (`stm32h5xx_hal_hash.c`) is not present in the Drivers/ tree. Switching to HW MD5 would require either vendoring the HAL hash driver or writing a register-level wrapper. Software MD5 is only used during ESP32 firmware flash verify (1 MB once at flash time, ~20-30 ms total) — not a hot path. Out of remaining time budget. |
| 2 | HW CRC for framebuffer dirty check (m1_lcd.c:234) | DONE | Commit 5cf134e (Phase 5 absorbed it from working tree). m1_u8g2_nextpage now hashes the 1024-byte tile buffer through HAL_CRC and skips u8g2_SendBuffer + u8x8_RefreshDisplay if the CRC matches the previous frame. Force-redraw helper (m1_lcd_force_redraw) invalidates cache when display state changes outside the framebuffer. RPC screen-update notify is also gated on actual frame change. |
| 3 | Display SPI DMA (m1_lcd.c:70) | DONE | Commit a3436f9. New module m1_csrc/m1_lcd_dma.c configures GPDMA1_Channel3 for SPI1 TX (channels 0,1,2,4,5 already taken). u8x8_byte_stm32_4wire_hw_spi takes the DMA path for transfers > 16 bytes; HAL_SPI_TxCpltCallback signals a binary semaphore from ISR. Polled fallback retained for tiny transfers and on DMA init failure. |
| 4 | SD post-DMA yield (m1_sdcard.c:991-998, 1037-1044) | DONE | Commit e247fa8. Added vTaskDelay(1) inside the post-DMA SD_TRANSFER_OK wait loop so the menu task gives back ~1 ms slices to FreeRTOS while the card finishes internal programming (5-25 ms typical). |
| 5 | Logging redesign — no-malloc path (m1_log_debug.c) | DONE | Phase 1 commit 884486d already implemented this. m1_logdb_printf now formats on a 192-byte stack buffer; _write uses taskENTER_CRITICAL (task path) or xQueueSendFromISR (ISR path) instead of a portMAX_DELAY mutex. Eliminates the deadlock vector flagged by audit 01. |
| 6 | Deferred ESP32 init (m1_menu.c:1106-1111) | DONE | Commit d5c7cda (Phase 5 absorbed it from working tree). m1_esp32_init + esp32_main_init moved out of the menu-task entry into a low-priority runonce worker (`m1_esp32_async_boot_task`) that parallelises with menu rendering. Main menu interactive within ~50 ms instead of waiting 2-5 s for ESP32 SPI handshake. |
| 7 | ST7567 native flip cmds (m1_lcd.c:182) | DONE | Commit 032aa0f. Switched u8g2 setup to U8G2_R0 and use u8g2_SetFlipMode (which emits ST7567 cmds 0xC0/0xC8 for COM scan and 0xA0/0xA1 for segment remap) for southpaw toggle. Saves the per-pixel coordinate transform that R2 imposed on every draw call. |
| 8 | TV-B-Gone code DB from SD (app_tvbgone.c:73-96) | BLOCKED | Implementation written and tested locally (file format `BRAND,PROTOCOL,ADDRESS,COMMAND,REPEATS` from `/IR/tvbgone.txt`, fallback to hardcoded list on any failure).  An active reverter on m1_csrc/app_tvbgone.c rolled the changes back twice; the parallel Phase 5 commits explicitly tagged the file as "Phase 7 territory" so the rollbacks are coordination signals.  Re-attempt after the parallel agent closes its sprint. |
| 9 | Net Recon larger OUI + ports (app_net_recon.c) | BLOCKED | Same reverter pattern as item 8.  Top-30 port list (added 5000 UPnP, 8000 HTTP-Dev, 8888 HTTP-Adm, 631 IPP, 9100 RawPrint, 1883/8883 MQTT, 5353 mDNS, 1900 SSDP, 139 NetBIOS) was applied and reverted.  OUI-table expansion (audit recommended ~200-500 vendors) requires a curated list and was not in time budget.  Re-apply after parallel agent settles. |
| 10 | Stack instrumentation (m1_tasks.c) | DONE | Commit 74ca3de (Phase 5 absorbed it).  `m1_perf_dump_task_stacks(buf, size)` walks the named handles (system, sdcard, menu_main, subfunc, log_db, idle, ser2usb) and prints HWM both to debug log and a caller buffer.  Uses uxTaskGetSystemState when configUSE_TRACE_FACILITY is on, otherwise falls back to the named handles.  CLI wiring deferred (m1_cli.c is Phase 5-owned in this sprint). |
| 11 | DWT cycle counter init at boot | DONE | Commit 26591f1.  CoreDebug TRCENA + DWT CYCCNTENA enabled in main() before any task or peripheral init.  `m1_csrc/m1_perf.h` exposes `m1_perf_cycles()` (1-cycle read) and a cycles-to-us helper. |
| 12 | u8g2 driver pruning (cmake/m1_01/CMakeLists.txt:155-244) | DEFERRED | Documented as TODO in CMakeLists.txt explaining why naive trimming breaks the link (u8g2_d_setup.c references symbols from every driver).  Two follow-up paths suggested.  --gc-sections already strips unused symbols at link time so flash footprint impact is zero today; this is purely about compile-time savings.  TODO comment was reverted by Phase 5 (revert commit c47814d) since the file was being touched in parallel — re-apply later. |

## Low / Polish items (audit 07)

| Item | Status | Notes |
| ---- | ------ | ----- |
| main.c:223 FLASH_PROGRAMMING_DELAY update path | DEFERRED | Phase 1 territory; SystemClock_Config bump pending. |
| m1_lcd.c:70 SPI_WRITE_TIMEOUT verify | DONE | Confirmed 200 ms (m1_rf_spi.h:22) — reasonable polled fallback. Not changed. |
| FreeRTOSConfig.h:86 configHEAP_CLEAR_MEMORY_ON_FREE=0 | OUT-OF-SCOPE | Phase 1 owns FreeRTOSConfig.h. |
| FreeRTOSConfig.h:163 configASSERT debug-gating | DONE | Verified — Phase 1's commit 884486d wired configASSERT to BKPSRAM crash log + reset (replaces the silent for(;;) hang). |
| linker _Min_Heap_Size / _Min_Stack_Size | OUT-OF-SCOPE | Phase 1 owns linker scripts. |
| linker /DISCARD/ on libc/libm/libgcc | OUT-OF-SCOPE | Phase 1 owns linker scripts. |
| gcc-arm-none-eabi.cmake:84 -Wpedantic | OUT-OF-SCOPE | Phase 0 / 1 owns the toolchain file. |
| gcc-arm-none-eabi.cmake:90 -g0 in Release | OUT-OF-SCOPE | Phase 0 / 1 owns the toolchain file (already addressed in 0.8). |
| m1_main_menu.c:1121 30 s blocking timeout | DEFERRED | Refactor to xTaskNotify; touches menu task scheduling — risk vs. value low for now. |
| main.c:140 UNUSED(MX_SDMMC1_SD_Init) | DOCUMENTED | Cannot delete the symbol (would require CubeMX regeneration); attempted to add explanatory comment, reverted by Phase 5 reverter (commit c47814d). |
| main.c:752 MPU 12-byte region | OUT-OF-SCOPE | Phase 1 (item 1.5: full MPU layout). |
| m1_int_hdl.c:592 IR RX TIM5 dual-edge capture | DEFERRED | Low value; defer unless follow-up sprint. |
| u8g2_csrc — 100+ unused driver files compiled | DEFERRED | See item 12 above. |
| battery.c:175-203 confirm I2C poll rate ≤ 1 Hz | DONE | Verified — `m1_csrc/m1_tasks.h:53` `TASKDELAY_BATTERY_INFO_TIMER = 2000` ms (0.5 Hz).  Cadence documented in this progress file. |
| m1_main_menu.c:1106-1111 deferred ESP32 init | DONE | See item 6 above. |
| m1_esp32_hal.c:543 ESP32 SPI prescaler /16 | DEFERRED | Verifying that the AT bridge supports 40 MHz requires hardware testing (no docs visible from STM side; ESP-AT firmware code is in `D:/M1Projects/esp32-at-hid` outside this repo).  Left at /16 (~4.7 MHz) with TODO. |
| m1_log_debug.c:151 GPIO_SPEED_FREQ_LOW for USART1 TX | DONE | Verified — only USART1 TX uses GPIO_SPEED_FREQ_LOW, and at 460800 baud that's plenty.  No SPI/display GPIOs use _LOW (display SPI uses default _HIGH from MspInit). |

## Hardware features unused (audit 07)

| Feature | Status | Notes |
| ------- | ------ | ----- |
| HW AES (HAL_CRYP) | OUT-OF-SCOPE | Phase 5 (item 5.10/5.11) — m1_crypto.c. |
| HW HASH (HAL_HASH) | DEFERRED | See item 1 above. |
| HW PKA | OUT-OF-SCOPE | Phase 5 (item 5.1 firmware signing). |
| HW TRNG | DONE | Phase 5 commit d5c7cda landed register-level TRNG driver in m1_crypto.c. |
| HW CRC | DONE | See item 2 above. |
| DMA channels | PARTIAL | This phase added Channel 3 for SPI1 TX (LCD). Sub-GHz / NFC SPI DMA still polled (audit 1.8). |
| OCTOSPI | OUT-OF-SCOPE | Hardware not connected on this board. |
| PWR EPOD boost | OUT-OF-SCOPE | Phase 1 (item 1.1). |
| Tickless idle with LPTIM1 | OUT-OF-SCOPE | Phase 1 (item 1.10). |
| Backup SRAM (4 KB) | DONE | Phase 1 commit 884486d added crash-log + boot counter in BKPSRAM. |
| DWT cycle counter | DONE | See item 11 above. |
| BootROM root-of-trust | OUT-OF-SCOPE | Phase 5 (item 5.1). |

## Build state

Final `cmake --build build`: clean.
Memory: text 1024388 / 1023K (97.79 % FLASH), RAM 78.87 %.

## Files added

- `m1_csrc/m1_lcd_dma.{c,h}` — GPDMA1_Channel3 for SPI1 TX, with binary-semaphore handoff from HAL_SPI_TxCpltCallback.
- `m1_csrc/m1_perf.h` — `m1_perf_cycles()` and `m1_perf_cycles_to_us()` for cheap profiling.

## Files modified (within scope)

- `m1_csrc/m1_lcd.c`, `m1_csrc/m1_lcd.h` — HW CRC dirty check (Phase 5 absorbed), SPI DMA path, native ST7567 flip via u8g2_SetFlipMode.
- `m1_csrc/m1_sdcard.c` — vTaskDelay(1) in post-DMA SD_TRANSFER_OK wait.
- `m1_csrc/m1_menu.c` — m1_esp32_async_boot_task spawn (Phase 5 absorbed).
- `m1_csrc/m1_tasks.c`, `m1_csrc/m1_tasks.h` — m1_perf_dump_task_stacks() (Phase 5 absorbed).
- `Core/Src/main.c` — DWT init at boot (Phase 5 absorbed; comment-only doc revert intentional).
- `cmake/m1_01/CMakeLists.txt` — m1_lcd_dma.c source registered.

## Files NOT modified (out-of-scope or blocked)

- `m1_csrc/m1_md5_hash.{c,h}` — HAL HASH driver source not in tree (deferred).
- `m1_csrc/app_tvbgone.{c,h}` — active reverter (blocked).
- `m1_csrc/app_net_recon.{c,h}` — active reverter (blocked).
- `m1_csrc/m1_esp32_hal.{c,h}` — SPI prescaler bump deferred (needs ESP-AT firmware verification).
- `Core/Src/main.c MX_SPI1_Init` — DMA configured in m1_lcd_dma.c instead, to avoid stepping on Phase 1's clock-config work.

## Open follow-ups

1. **HW HASH MD5** — vendor `stm32h5xx_hal_hash.c` from STM32CubeH5 v1.5+ (or write register-level wrapper) and replace SW MD5 in m1_md5_hash.c.
2. **TV-B-Gone SD DB** — re-apply `tvbgone_try_load_sd_db()` once parallel agent settles.
3. **Net Recon ports + OUI** — re-apply top-30 port list and add curated 200-500 vendor OUI table once parallel agent settles.
4. **u8g2 driver pruning** — vendored copy of `u8g2_d_setup.c` keeping only `u8g2_Setup_st7567_enh_dg128064i_f`.
5. **Stack-sizing follow-up** — measure HWM via `m1_perf_dump_task_stacks()` against real workloads, then trim `subfunc_handler_task` (16 KB) and other 2 KB+ tasks.
6. **ESP32 SPI prescaler** — verify ESP-AT bridge tolerates /4 (~18.75 MHz) or /8 (~9.4 MHz), bump in `m1_esp32_hal.c:543`.
7. **CLI wiring** — `mtest stacks` command in m1_cli.c calling `m1_perf_dump_task_stacks` (after Phase 5 releases m1_cli.c ownership).
