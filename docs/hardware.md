# Hardware Reference

## Overview

The Monstatek M1 is a pocket-sized multi-protocol security research tool. Every component is on the same PCB — no devboards, no dongles required for any feature.

---

## Main MCU

| Attribute | Value                                           |
| --------- | ----------------------------------------------- |
| Part      | STM32H573VIT6                                   |
| Core      | ARM Cortex-M33                                  |
| Clock     | 250 MHz                                         |
| Flash     | 2 MB, dual-bank                                 |
| RAM       | 640 KB SRAM                                     |
| Security  | TrustZone, hardware crypto (AES, SHA, PKA, RNG) |
| USB       | USB 2.0 FS — CDC + MSC + HID composite          |
| Debugger  | SWD (CN2 header)                                |

**Dual-bank flash** means the M1 can receive an over-the-air update into bank B while running from bank A, then swap and verify atomically. The bootloader validates both banks with CRC32 on every power-on and falls back to the last known good image if a bank fails.

---

## Display

| Attribute  | Value               |
| ---------- | ------------------- |
| Controller | ST7586s             |
| Resolution | 128 x 64 monochrome |
| Interface  | SPI                 |
| Library    | u8g2                |

The display uses a page-rendering model. All UI code calls `m1_u8g2_firstpage()`, draws with standard u8g2 functions, then loops until `m1_u8g2_nextpage()` returns 0.

---

## Sub-GHz Radio

| Attribute       | Value                          |
| --------------- | ------------------------------ |
| Part            | Silicon Labs Si4463            |
| Frequency range | 142 MHz to 1050 MHz            |
| Modulations     | OOK, ASK, (G)FSK, 4(G)FSK      |
| Max TX power    | +20 dBm                        |
| Sensitivity     | -126 dBm (OOK), -110 dBm (FSK) |
| Interface       | SPI                            |

The Si4463 covers a wider frequency range than the CC1101 in the Flipper Zero (300-928 MHz). The extra low-end (142-300 MHz) covers older pager bands, VHF remote controls, and some TPMS sensors. The high-end (928-1050 MHz) reaches some DECT cordless bands and custom ISM allocations.

Raw edge-timing mode is used for signal capture: the Si4463 asserts a GPIO on each RF edge transition, and a hardware timer captures the timestamp. This gives microsecond-accurate pulse trains for any OOK/ASK signal without protocol-specific decoding in hardware.

---

## NFC

| Attribute      | Value                                                           |
| -------------- | --------------------------------------------------------------- |
| Part           | ST25R3916                                                       |
| Frequency      | 13.56 MHz                                                       |
| Standards      | ISO 14443A/B, ISO 15693, ISO 18092 (NFC-F), ISO 18092 (NFC-P2P) |
| Max modulation | 40% (hardware maximum for this IC)                              |
| Interface      | SPI                                                             |
| Library        | RFAL (ST RF Abstraction Layer)                                  |

The 40% modulation depth is the ST25R3916's hardware maximum and gives M1PPER better read range and emulation reliability against strict readers than devices using lower modulation.

The RFAL library handles ISO-DEP (T=CL) framing for EMV APDU transactions, MIFARE Classic Crypto-1 authentication, and raw transceive for Magic card backdoor sequences.

---

## 125 kHz RFID

| Attribute      | Value                                           |
| -------------- | ----------------------------------------------- |
| Implementation | Discrete analog front-end + STM32 timer capture |
| Protocols      | ASK/PSK demodulation                            |
| Write support  | T5577                                           |

Supported protocols: HID Generic, HID 26-bit, HID 35-bit, HID 37-bit, Indala, AWID, Pyramid, Paradox, IOProx, FDX-A, FDX-B, Viking, Electra, Gallagher, Jablotron, PAC/Stanley, Keri, EM4100, EM410x, and more.

---

## WiFi / Bluetooth / 802.15.4

| Attribute        | Value                                  |
| ---------------- | -------------------------------------- |
| Part             | Espressif ESP32-C6                     |
| WiFi             | 802.11ax (WiFi 6), 2.4 GHz             |
| Bluetooth        | BLE 5.3                                |
| 802.15.4         | IEEE 802.15.4 (Zigbee, Thread, Matter) |
| Interface to MCU | SPI (AT command protocol, SPI Mode 1)  |

The ESP32-C6 is the only coprocessor in the M1. It handles all three wireless protocols simultaneously. Runtime communication with the STM32H573 uses SPI-based AT commands — **not UART**. The stock Espressif AT firmware downloads are UART-only and will not work. M1PPER uses a custom ESP32 AT build compiled with `CONFIG_AT_BASE_ON_SPI=y`.

The 802.15.4 radio is native to the ESP32-C6 silicon. No Flipper Zero variant has native 802.15.4 capability. M1PPER uses this for Zigbee and Thread network scanning directly from the main menu.

---

## Infrared

| Attribute   | Value                          |
| ----------- | ------------------------------ |
| Receiver    | TSOP38238                      |
| Transmitter | IR LED                         |
| Carrier     | 30-56 kHz (protocol dependent) |

The transmitter supports all common IR carrier frequencies: 36 kHz (RC-5, Kaseikyo), 38 kHz (NEC), 40 kHz (Sony SIRC), 56 kHz (RCMM).

---

## USB

| Attribute | Value                                   |
| --------- | --------------------------------------- |
| Connector | USB-C                                   |
| Protocol  | USB 2.0 Full Speed                      |
| Composite | CDC (serial) + MSC (mass storage) + HID |

All three USB device classes are active simultaneously. CDC appears as a serial port for debug/CLI access. MSC exposes the microSD card as a removable drive when connected. HID is used for BadUSB keystroke injection.

The COM port number changes after a power cycle on Windows. Use qMonstatek which auto-detects the port.

---

## Storage

| Attribute  | Value           |
| ---------- | --------------- |
| Interface  | microSD via SPI |
| Filesystem | FAT32 (FatFS)   |
| Max tested | 32 GB           |

---

## Power

The M1 is USB-powered. Settings, signal files, and credentials are persisted to the microSD card. No internal battery in the base unit.

---

## Debug / Flash Headers

**SWD (CN2):** SWDIO, SWDCLK, GND, VCC — compatible with ST-Link V2, J-Link, and OpenOCD.

**DFU mode:** Hold UP + OK for 5 seconds while powered off, then connect USB-C. The M1 enumerates as a DFU device.

---

## Schematic Notes

- STM32H5 uses `FLASH->NSSR` (not `FLASH->SR`) for flash status. BSY bit is `FLASH_SR_BSY`.
- SPI Mode 1 (CPOL=0, CPHA=1) hardcoded in `m1_esp32_hal.c`.
- Si4463 CTS function is on a GPIO pin, not the SPI MISO line (`M1_APP_RADIO_POLL_CTS_ON_GPIO`).
