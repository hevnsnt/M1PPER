<!-- See COPYING.txt for license details. -->

<div align="center">

<img src="https://img.shields.io/badge/Hardware-Monstatek%20M1-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Firmware-C3.6-brightgreen?style=for-the-badge" />
<img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" />
<img src="https://img.shields.io/github/actions/workflow/status/hevnsnt/M1PPER/firmware-release.yml?style=for-the-badge&label=Build" />

<br /><br />

# M1PPER

**The most advanced community firmware for the Monstatek M1.**

_Not a Flipper port. Not a clone. Built from the ground up to use hardware the Flipper can't touch._

</div>

---

## The Hardware Gap

The Monstatek M1 is objectively better hardware than a Flipper Zero. M1PPER is the firmware that proves it.

|                          | Flipper Zero        | Monstatek M1                    |
| ------------------------ | ------------------- | ------------------------------- |
| CPU                      | Cortex-M4 @ 64 MHz  | **Cortex-M33 @ 250 MHz**        |
| RAM                      | 256 KB              | **640 KB**                      |
| Flash                    | 1 MB                | **2 MB dual-bank**              |
| Sub-GHz                  | CC1101, 300-928 MHz | **Si4463, 142-1050 MHz**        |
| WiFi                     | External devboard   | **ESP32-C6, WiFi 6, built-in**  |
| Bluetooth                | External devboard   | **BLE 5.3, built-in**           |
| 802.15.4                 | No                  | **Yes — ESP32-C6 native radio** |
| On-device Mfkey32        | No                  | **Yes**                         |
| POCSAG decoder           | No                  | **Yes**                         |
| Sub-GHz repeater         | No                  | **Yes**                         |
| BLEPTD tracker detection | No                  | **Yes**                         |
| TPMS decoder             | No                  | **Yes**                         |
| Evil Portal              | Plugin              | **Native**                      |
| TOTP authenticator       | No                  | **Yes**                         |

The 802.15.4 radio is the one that gets people. The ESP32-C6 has a native Zigbee/Thread radio built in. No Flipper variant can sniff Zigbee or Thread without external hardware. M1PPER does it from the main menu.

---

## What M1PPER Does

### Radio

**Sub-GHz (142-1050 MHz)** — Read, replay, repeat, brute-force, playlist, spectrum analyzer, frequency scanner, RSSI meter, jam detection. 30+ protocol decoders. POCSAG pager decoding with BCH error correction. RF Signal Visualizer (ProtoView-style waveform display). TPMS tire pressure sensor decoding.

**NFC (13.56 MHz)** — Full MIFARE Classic read with Crypto-1 auth. On-device Mfkey32 key recovery (no laptop, ~2s per sector). Magic card write (Gen1A/Gen2/Gen4). Default key survey (20 factory keys, all sectors). EMV payment card reader. Detect Reader with nonce capture. NFC fuzzer.

**125 kHz RFID** — Read, write, clone, fuzz. 20+ protocols including HID, Indala, EM4100, Gallagher, Keri, FDX.

**Infrared** — Learn, replay, universal remote database, TV-B-Gone (15 brands).

**IEEE 802.15.4** — Zigbee and Thread sniffing via the ESP32-C6's native 15.4 radio. No other portable device does this natively.

### WiFi (ESP32-C6, WiFi 6)

Passive: AP scan, channel survey, probe sniff, wardriving with WiGLE CSV output.

Offensive: deauth flood, beacon spam, PMKID capture, WPA2/WPA3 handshake capture with deauth assist, Karma, Evil Twin, Evil Portal (captive portal with credential harvesting), EAPOL-Logoff (PMF bypass).

Recon: ARP scan, port scan (top 20 services), OUI lookup.

### Bluetooth (BLE 5.3)

Scanner, GATT browser, BLE Spam (Apple Continuity, Google Fast Pair, Samsung EasySetup, Windows SwiftPair), Bad-BT (wireless keystroke injection over BLE HID), BLE advertisement sniffer (Omni-Sniffer).

**BLEPTD** — Port of haxorthematrix/BLEPTD. 55+ device signatures, detects AirTags, Tiles, Galaxy Tags, and 50+ other tracking devices. Confusion mode broadcasts random device profiles to make surveillance tracking impractical. Medical device signatures are permanently protected and never transmitted.

### Tools

**BadUSB** — DuckyScript 2.0 over USB HID. Same scripts over BLE HID (Bad-BT, no cable required).

**TOTP/HOTP** — On-device authenticator. Self-contained SHA-1/HMAC-SHA1. Seeds from SD card. No network needed.

**iButton** — Dallas/Maxim 1-Wire ROM read, CRC validation, family code identification.

**TOTP Auth** — RFC 6238 time-based codes, RFC 4226 counter-based codes, large display, 30-second countdown.

---

## No Stubs. No Coming Soon.

Every feature in M1PPER has a route from the main menu and uses real hardware. If it is in the menu, it runs. If it does not run yet, it is not in the menu.

---

## Quick Start

**Flash a pre-built binary:**

1. Download `M1_T-1000_vX.X.X_wCRC.bin` from [Releases](https://github.com/hevnsnt/M1PPER/releases)
2. Open [qMonstatek](https://github.com/bedge117/qMonstatek), connect via USB-C, go to Firmware Update
3. Done

**Build from source:**

```bash
# Windows
.\do_build.ps1

# Linux / macOS
./build.sh
```

Full build and flash instructions: [docs/installation.md](docs/installation.md)

---

## Documentation

|                                        |                                             |
| -------------------------------------- | ------------------------------------------- |
| [Hardware Reference](docs/hardware.md) | MCU, radio ICs, display, pinout, memory map |
| [Installation](docs/installation.md)   | Build from source, flash via DFU or SWD     |
| [Features](docs/features.md)           | Complete feature reference for every app    |
| [SD Card Layout](docs/sd-card.md)      | Directory structure, file formats           |

---

## Flipper File Compatibility

`.sub`, `.nfc`, `.rfid`, `.ir` files from Flipper Zero work directly. Drop them on the SD card and they appear in the saved signal library.

---

## Contributing

Pull requests are welcome. Open an issue for bugs or feature requests.

RPC protocol for tool integrations: `m1_csrc/m1_rpc.c` and `Core/Src/cli_app.c`.

This is a community project. Not affiliated with or endorsed by Monstatek.

---

## License

GNU General Public License v3.0. See [COPYING.txt](COPYING.txt).
