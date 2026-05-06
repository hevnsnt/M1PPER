<!-- See COPYING.txt for license details. -->

<div align="center">

<img src="https://img.shields.io/badge/Hardware-Monstatek%20M1-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Firmware-C3.6-brightgreen?style=for-the-badge" />
<img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" />
<img src="https://img.shields.io/github/actions/workflow/status/hevnsnt/M1PPER/firmware-release.yml?style=for-the-badge&label=Build" />

<br /><br />

# M1PPER

### Community firmware for the Monstatek M1.

### Not a Flipper port. Not a clone. Built to use hardware the Flipper can't touch.

<br />

[**Features Reference**](docs/features.md) &nbsp;|&nbsp; [**Installation**](docs/installation.md) &nbsp;|&nbsp; [**Hardware**](docs/hardware.md) &nbsp;|&nbsp; [**Releases**](https://github.com/hevnsnt/M1PPER/releases)

</div>

---

The Flipper Zero gets all the press. The Monstatek M1 has a CPU that runs at nearly 4x the clock speed, 2.5x the RAM, a Sub-GHz radio that reaches bands the CC1101 never could, and native WiFi 6, BLE 5.3, and IEEE 802.15.4 — all on the same board, no dongles, no expansion modules. The stock firmware barely scratches the surface of what the hardware can do.

M1PPER fixes that.

---

## The Gap

|               |    Flipper Zero     |          Monstatek M1          |
| ------------- | :-----------------: | :----------------------------: |
| CPU           | Cortex-M4 @ 64 MHz  |    **Cortex-M33 @ 250 MHz**    |
| RAM           |       256 KB        |           **640 KB**           |
| Flash         |        1 MB         |       **2 MB dual-bank**       |
| Sub-GHz range | CC1101, 300–928 MHz |    **Si4463, 142–1050 MHz**    |
| WiFi          |   External module   | **ESP32-C6, WiFi 6, built-in** |
| Bluetooth     |   External module   |     **BLE 5.3, built-in**      |
| IEEE 802.15.4 |         No          | **Native — ESP32-C6 silicon**  |

---

## What M1PPER Unlocks

The table below shows the full capability gap across Flipper Zero, Monstatek stock firmware, and M1PPER. For a detailed breakdown of every feature, see [**docs/features.md**](docs/features.md).

### Sub-GHz

| Capability                      | Flipper Zero | Monstatek Stock |    M1PPER    |
| ------------------------------- | :----------: | :-------------: | :----------: |
| Read / Replay                   |     Yes      |       Yes       |     Yes      |
| 30+ protocol decoders           |     Yes      |       Yes       |     Yes      |
| Frequency range                 | 300–928 MHz  |  142–1050 MHz   | 142–1050 MHz |
| Brute-force / Fuzzer            |     Yes      |       Yes       |     Yes      |
| Spectrum analyzer               |     Yes      |       No        |     Yes      |
| POCSAG pager decoder            |      No      |       No        |   **Yes**    |
| TPMS tire pressure decoder      |      No      |       No        |   **Yes**    |
| RF signal visualizer (waveform) |      No      |       No        |   **Yes**    |
| Sub-GHz repeater                |      No      |       No        |   **Yes**    |
| Signal playlist                 |      No      |       No        |   **Yes**    |

### NFC (13.56 MHz)

| Capability                             | Flipper Zero | Monstatek Stock |        M1PPER        |
| -------------------------------------- | :----------: | :-------------: | :------------------: |
| MIFARE Classic read                    |     Yes      |       Yes       |         Yes          |
| Crypto-1 authentication                |     Yes      |       Yes       |         Yes          |
| On-device Mfkey32 key recovery         |      No      |       No        | **Yes — ~2s/sector** |
| Default key survey (20 factory keys)   |      No      |       No        |       **Yes**        |
| Magic card write (Gen1A / Gen2 / Gen4) |   Partial    |       No        | **Yes — all three**  |
| EMV payment card reader                |      No      |       No        |       **Yes**        |
| Detect Reader + nonce capture          |     Yes      |       No        |       **Yes**        |
| NFC fuzzer                             |    Plugin    |       No        |       **Yes**        |

### 125 kHz RFID

| Capability                     | Flipper Zero | Monstatek Stock | M1PPER |
| ------------------------------ | :----------: | :-------------: | :----: |
| Read / Write / Clone           |     Yes      |       Yes       |  Yes   |
| HID, EM4100, Indala, Gallagher |     Yes      |       Yes       |  Yes   |
| 20+ protocols                  |     Yes      |       Yes       |  Yes   |
| T5577 write                    |     Yes      |       Yes       |  Yes   |

### Infrared

| Capability                        | Flipper Zero | Monstatek Stock |       M1PPER        |
| --------------------------------- | :----------: | :-------------: | :-----------------: |
| Learn / Replay                    |     Yes      |       Yes       |         Yes         |
| Universal remote database         |     Yes      |       Yes       |         Yes         |
| TV-B-Gone (multi-brand power-off) |    Plugin    |       No        | **Yes — 15 brands** |

### IEEE 802.15.4

| Capability               | Flipper Zero | Monstatek Stock |          M1PPER           |
| ------------------------ | :----------: | :-------------: | :-----------------------: |
| Zigbee sniffing          |      No      |       No        | **Yes — ESP32-C6 native** |
| Thread / Matter sniffing |      No      |       No        | **Yes — ESP32-C6 native** |

No Flipper variant — stock or modified — can sniff Zigbee or Thread without external hardware. The M1 does it from the main menu.

### WiFi

| Capability                        | Flipper Zero | Monstatek Stock |      M1PPER      |
| --------------------------------- | :----------: | :-------------: | :--------------: |
| AP scan / Channel survey          |    Plugin    |       Yes       |       Yes        |
| Probe sniff                       |    Plugin    |       No        |     **Yes**      |
| Wardriving (WiGLE CSV output)     |    Plugin    |       No        |     **Yes**      |
| Deauth flood                      |    Plugin    |       Yes       |       Yes        |
| PMKID capture                     |    Plugin    |       No        |     **Yes**      |
| WPA2/WPA3 handshake capture       |    Plugin    |       No        |     **Yes**      |
| Karma / Evil Twin                 |    Plugin    |       No        |     **Yes**      |
| Evil Portal (captive portal)      |    Plugin    |       No        | **Yes — native** |
| EAPOL-Logoff (PMF bypass)         |      No      |       No        |     **Yes**      |
| ARP scan / Port scan / OUI lookup |      No      |       No        |     **Yes**      |

### Bluetooth (BLE 5.3)

| Capability                                        | Flipper Zero | Monstatek Stock |      M1PPER      |
| ------------------------------------------------- | :----------: | :-------------: | :--------------: |
| BLE scanner                                       |    Plugin    |       Yes       |       Yes        |
| GATT browser                                      |      No      |       No        |     **Yes**      |
| BLE advertisement sniffer                         |      No      |       No        |     **Yes**      |
| BLE Spam (Apple / Google / Samsung / Microsoft)   |    Plugin    |       No        | **Yes — native** |
| Bad-BT (wireless keystroke injection via BLE HID) |      No      |       No        |     **Yes**      |
| BLEPTD tracker detection (55+ device signatures)  |      No      |       No        |     **Yes**      |
| BLEPTD Confusion Mode                             |      No      |       No        |     **Yes**      |

### Tools

| Capability                                | Flipper Zero | Monstatek Stock |          M1PPER          |
| ----------------------------------------- | :----------: | :-------------: | :----------------------: |
| BadUSB (DuckyScript 2.0 via USB HID)      |     Yes      |       Yes       |           Yes            |
| Bad-BT (same scripts, no cable, over BLE) |      No      |       No        |         **Yes**          |
| TOTP / HOTP authenticator                 |    Plugin    |       No        | **Yes — self-contained** |
| iButton (Dallas/Maxim 1-Wire)             |     Yes      |       No        |         **Yes**          |

---

## No Stubs. No Coming Soon.

If a feature is in the menu, it runs. Every entry in the table above uses real hardware on the M1. Nothing is stubbed. Nothing is placeholder. If it does not work yet, it is not in the menu.

---

## Flipper File Compatibility

`.sub`, `.nfc`, `.rfid`, and `.ir` files from Flipper Zero drop directly onto the SD card and appear in the saved signal library. No conversion needed.

---

## Quick Start

**Flash (recommended):**

1. Download `M1_T-1000_vX.X.X_wCRC.bin` from [Releases](https://github.com/hevnsnt/M1PPER/releases)
2. Open [qMonstatek](https://github.com/bedge117/qMonstatek), connect USB-C, go to Firmware Update, flash

**Build from source:**

```bash
# Windows
.\do_build.ps1

# Linux / macOS
./build.sh
```

Full build, DFU, and SWD instructions: [docs/installation.md](docs/installation.md)

---

## Documentation

|                                        |                                                      |
| -------------------------------------- | ---------------------------------------------------- |
| [Hardware Reference](docs/hardware.md) | MCU, radio ICs, display, memory map, SWD/DFU         |
| [Installation](docs/installation.md)   | Build from source, flash via qMonstatek, DFU, or SWD |
| [Features](docs/features.md)           | Complete reference for every app and mode in C3.6    |
| [SD Card Layout](docs/sd-card.md)      | Directory structure and all file formats             |

---

## Contributing

Pull requests are welcome. Open an issue for bugs or feature requests.

RPC protocol for tool integrations: `m1_csrc/m1_rpc.c` and `Core/Src/cli_app.c`.

This is a community project. Not affiliated with or endorsed by Monstatek.

---

## License

GNU General Public License v3.0. See [COPYING.txt](COPYING.txt) and [LICENSES.md](LICENSES.md) for third-party attributions.
