# Phase 3 Sub-GHz Progress

Branch: phase-4-wireless. Build: clean (`cmake --build build`) on ARM GCC 15.2.

Status legend: completed, partial, deferred.

## Critical items

| # | Item | Status | Notes |
| --- | --- | --- | --- |
| 1 | SI446x_Set_Frequency outdiv branch <340 MHz | completed | Added outdiv=24 / clkgen_band=0x0D for 142-283 MHz so US POCSAG / low VHF retunes can lock the synthesizer. Out-of-range freq <142 MHz also routed to the same branch as a defensive fallback. |
| 2 | TIM1 RX ISR CCR1 + slave-mode reset | completed | sub_ghz_rx_init now configures `MasterSlaveMode = ENABLE`, `HAL_TIM_SlaveConfigSynchro` with `SlaveMode=TIM_SLAVEMODE_RESET`, `InputTrigger=TIM_TS_TI1FP1`, `TriggerPolarity=BOTHEDGE`. ISR reads `__HAL_TIM_GET_COMPARE(...,CHANNEL_1)`; the redundant `__HAL_TIM_SET_COUNTER(0)` is removed. Removes 1-5 us ISR-entry jitter. |
| 3 | TIM1 update IRQ routing | completed | TIM1_UP_IRQHandler now disambiguates RX vs TX by checking `hdma_subghz_tx.Instance->CCR & DMA_CCR_EN` and `timerhdl_subghz_rx.Instance->CCER & TIM_CCER_CC1E`. RX-timeout updates clear the RX flag and return without touching TX bookkeeping. |
| 4 | Brute force TX wiring | completed | sub_ghz_brute_force now calls `sub_ghz_tx_raw_init()` once + `sub_ghz_transmit_raw()` per encoded frame, gated on Q_EVENT_SUBGHZ_TX with a 250 ms watchdog. End-of-app cleanup tears down via `sub_ghz_raw_tx_stop` + `sub_ghz_tx_raw_deinit` + `sub_ghz_set_opmode(ISOLATED)`. |
| 5 | Repeater 868 MHz retune via CUSTOM | completed | sub_ghz_repeater_freqs[] now lists 868.350 MHz as `SUB_GHZ_BAND_CUSTOM`. set_opmode loads BAND_433_92 base config and retunes via `SI446x_Set_Frequency(868350000)`. Previous SUB_GHZ_BAND_915 mapping silently broadcast on 915 MHz (illegal in EU). |
| 6 | TPMS FSK + CRC + range + buffer overrun | partial | CRC8 (poly 0x07) validated for Schrader (5-byte payload incl. trailing CRC) and Citroen (8 bytes incl. CRC). Generic decoder uses physical-plausibility guard (10-80 PSI, -40..+90 C) since it has no fixed CRC scheme. tpms_assign_dialog wheel-overrun fixed by bounding the loop with `min(sensor_count, TPMS_MAX_SENSORS)` so -Wstringop-overflow is satisfied. **FSK packet-handler / RX_FIFO path is NOT yet wired** — that's the FSK-rework half of item 6 and is deferred to the Phase 7 SI4463-FIFO project (audit explicitly tracked separately). |
| 7 | POCSAG preamble lock + sync tolerance + ctx state | completed | Required POCSAG_PREAMBLE_MIN_BITS=32 alternating-bit run before HUNT_SYNC; sync tolerance tightened from 2 to 1 bit. cur_level / residual_us moved into pocsag_ctx and zeroed by pocsag_reset_state. End-of-batch returns to HUNT_PREAMBLE so each batch re-arms on a fresh 1010... run. |
| 8 | KeeLoq 66-bit code | completed | Replaced single uint64 with (uint64_t low, uint8_t high) pair carrying the trailing 2 status bits.  Serial extracted from bits 32..59 of low, button id from bits 60..63, status bits packed into the high nibble of n8_buttonid. |
| 9 | Per-app radio config | completed | Added `SI446x_Apply_OOK_RX_Profile(pdtc, cnt1, raw_ctrl, raw_eye)` writing MODEM_OOK_PDTC, OOK_CNT1, RAW_CONTROL, RAW_EYE_2_1.  POCSAG (slow baud, long PDTC) and TPMS (fast burst, tight PDTC) now select per-app params instead of all sharing the 433 MHz remote setting.  RF-Visualizer / repeater / brute force still use the default 0x6C PDTC since their OOK profiles are tuned to that. |
| 10 | Spectrum analyzer low-band branch | completed | `if (center_freq < 284 MHz) radio_init_rx_tx(BAND_315, OOK)` else 433/915 fallback. Per-band dwell time 1 / 2 / 3 ms scales with band. |
| 11 | Region-aware TX allow-list | completed | New `sub_ghz_freq_is_globally_restricted()` unconditionally rejects aircraft 118-137 MHz, US public-safety 138-144 / 148-149.9 MHz, NOAA 162.4-162.55, FCC 15.205 322-335.4 / 399.9-410 MHz even with region "Off". Existing region-positive-list path retained. |
| 12 | Repeater free order | completed | `subghz_rx_rawdata_rb.pdata = NULL; __DMB();` BEFORE `vPortFree(ring_storage)`. ISR write into freed heap is no longer possible. |

## High-priority items

| # | Item | Status | Notes |
| --- | --- | --- | --- |
| 13 | Pulse handler off-task / feature-vector pre-filter | deferred | Architecture refactor (worker task + queue + per-decoder feature vectors).  Per session brief: "Don't sprawl on 13, 17, 19 if time runs short."  Time budget ran out before this could land safely. |
| 14 | Princeton median pulse classification | completed | Added insertion-sort over min(pulsecount, 64) samples, median split into lo/hi sums, robust te_short / te_long means.  Front-of-packet noise pulses no longer poison every subsequent comparison. |
| 15 | RF Visualizer initial-polarity capture | completed | Sample SUBGHZ_RX_GPIO_PORT->IDR at arm + on capture reset; `rf_viz_pulse_is_high(idx)` is now `((idx & 1) ^ initial_level) != 0`. Visualiser stops inverting roughly half its captures. |
| 16 | Playlist .sub vs .sgh branch | partial | Playlist now branches explicitly on extension and surfaces a "Skipped .sgh" status for native files (was silently calling the Flipper-only parser). Native .sgh playback from playlist context needs `sub_ghz_file_load` refactored to take a path; deferred. |
| 17 | TIM kernel-clock derivation H5 | completed | Both RX and TX timer prescalers now derived from `HAL_RCC_GetPCLK2Freq()` and the APB2 prescaler bits in `RCC->CFGR2`.  Tick stays at 1 us across the planned 75 -> 250 MHz SYSCLK bump. |
| 18 | CTS recovery non-blocking | completed | Replaced HAL_Delay(50) with vTaskDelay(50ms) when the FreeRTOS scheduler is running.  Returns SI446X_CTS_FAILED (0x02) to the caller on terminal recovery failure instead of swallowing the error. |
| 19 | Frequency-change settling | partial | sub_ghz_set_opmode polls Request_DeviceState up to 8x with 1 ms backoff after `SI446x_Set_Frequency` to confirm the chip is in READY/RX/TX before continuing.  Spectrum analyzer also now uses per-band dwell (1-3 ms) instead of fixed HAL_Delay(1).  A more thorough per-band dwell table inside set_opmode itself is deferred. |
| 20 | Si4463 nIRQ unused | completed | Documented as a Phase 7 hook (FSK packet-handler / FIFO path); EXTI plumbing kept so future code can subscribe without touching the ISR. |

## Files touched

- `sub_ghz/m1_sub_ghz_api.c` — outdiv<340 MHz fix, OOK RX profile helper, CTS-recovery yield + error surface, FreeRTOS include, nIRQ doc.
- `sub_ghz/m1_sub_ghz_api.h` — public prototype for SI446x_Apply_OOK_RX_Profile.
- `sub_ghz/protocols/m1_keeloq_decode.c` — 66-bit shift register fix.
- `sub_ghz/protocols/m1_princeton_decode.c` — median-based te_short/te_long.
- `m1_csrc/m1_sub_ghz.c` — slave-mode reset config in rx_init, dynamic TIM kernel clock for both RX and TX, brute force TX wiring + cleanup, repeater CUSTOM-band entry for 868 MHz, repeater free order + __DMB, spectrum low-band branch + per-band dwell, retune state-poll, region restricted-band guard.
- `m1_csrc/m1_int_hdl.c` — TIM1_CC ISR reads CCR1 instead of CNT, TIM1_UP_IRQHandler RX/TX disambiguation, stdbool include.
- `m1_csrc/app_pocsag.c` — preamble lock, tolerance tighten, ctx state for pulse quantiser, per-app OOK profile.
- `m1_csrc/app_tpms.c` — CRC8, range guard, wheel-overrun bound, per-app OOK profile.
- `m1_csrc/app_rf_visualizer.c` — initial-polarity capture at arm + reset.
- `m1_csrc/app_subghz_playlist.c` — explicit .sub vs .sgh branch with status feedback.

## Build state

- Final `cmake --build build`: clean. Memory: text 994 KB, RAM 78.80%, FLASH 96.69-96.91% across the change series.
- All warnings from earlier audit (Wstringop-overflow on app_tpms wheel write) cleared.

## Deferred / not landed

- TPMS FSK packet-handler path (uses Si4463 RX_FIFO instead of TIM1 OOK envelope). Belongs to Phase 7 SI4463-FIFO project.
- Off-task pulse-handler refactor (item 13). Architectural; explicit "don't sprawl" guidance.
- Native .sgh playlist playback (item 16 second half). Requires `sub_ghz_file_load` path-arg refactor.
- Per-band dwell table inside sub_ghz_set_opmode (item 19 second half).
- KAT test for KeeLoq decode against a published vector (would catch any future regression of the 66-bit shift).
