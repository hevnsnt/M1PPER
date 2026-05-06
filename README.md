<!-- See COPYING.txt for license details. -->

<div align="center">

# M1PPER

### The Most Advanced Firmware for the Monstatek M1

**Community firmware that outclasses every alternative on the market.**

[![Build Status](https://github.com/hevnsnt/M1PPER/actions/workflows/firmware-release.yml/badge.svg)](https://github.com/hevnsnt/M1PPER/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](COPYING.txt)
[![Hardware: M1](https://img.shields.io/badge/Hardware-Monstatek%20M1-red.svg)](https://monstatek.com)
[![Firmware: C3.5](https://img.shields.io/badge/Firmware-C3.5-brightgreen.svg)]()

</div>

---

> **This is a community project and is not affiliated with or endorsed by Monstatek.**

---

## Why M1PPER Wins

The Monstatek M1 runs hardware that is objectively superior to a Flipper Zero in every measurable category. M1PPER is the firmware that actually uses that hardware. Not a port. Not a clone. A ground-up implementation built to exploit every advantage the M1 has over the competition.

| Capability                    | Flipper Zero (Momentum)               | Monstatek M1 (M1PPER)              |
| ----------------------------- | ------------------------------------- | ---------------------------------- |
| **Processor**                 | STM32WB55, Cortex-M4, 64 MHz          | STM32H573, Cortex-M33, **250 MHz** |
| **Flash**                     | 1 MB                                  | **2 MB dual-bank**                 |
| **RAM**                       | 256 KB                                | **640 KB**                         |
| **Sub-GHz Radio**             | CC1101 (300-928 MHz)                  | **Si4463 (142-1050 MHz)**          |
| **NFC**                       | ST25R3916                             | ST25R3916 + **40% modulation**     |
| **WiFi**                      | Optional devboard (separate purchase) | **ESP32-C6 built-in, WiFi 6**      |
| **Bluetooth**                 | Optional devboard                     | **BLE 5.3 built-in**               |
| **USB**                       | CDC only                              | **CDC + MSC + HID composite**      |
| **On-device Crypto-1 solver** | External tool required                | **Built in (Mfkey32)**             |
| **POCSAG decoder**            | Not available                         | **Built in**                       |
| **Sub-GHz repeater**          | Not available                         | **Built in**                       |
| **Evil Twin AP**              | Plugin dependent                      | **Native**                         |
| **Wardriving**                | Plugin dependent                      | **Native with WiGLE CSV**          |
| **EAPOL-Logoff (PMF bypass)** | Not available                         | **Built in**                       |

The M1 has 4x the CPU speed, 2.5x the RAM, a wider-range Sub-GHz radio, and built-in WiFi 6 with no dongle required. M1PPER is the firmware that turns those specifications into real capabilities.

---

## What Is M1PPER

M1PPER (codename C3) is a community firmware for the [Monstatek M1](https://monstatek.com) that began as an enhancement of the stock firmware and has grown into the most feature-complete, most offensively capable, and most hardware-accurate firmware available for the device.

Every feature in M1PPER is fully implemented. No stubs. No "coming soon." Every app has a route from the main menu and uses the hardware it was designed to use.

---

## C3.6 Features (Latest Release)

### On-Device Mfkey32: NFC Key Recovery

The industry-standard mfkey32 attack recovers MIFARE Classic Crypto-1 keys from captured reader authentication nonces. Every other device sends you to a PC to run the solver. M1PPER runs it on the STM32H573 at 250 MHz.

Tap the M1 against a MIFARE Classic reader, capture nonce pairs in emulation mode, and watch the on-device LFSR rollback solver crack the key in under 2 seconds per sector. Results are displayed directly on screen and saved to SD card.

- Full Crypto-1 48-bit key recovery with two-phase LFSR state enumeration
- 2^24 odd-register and even-register candidate search, filtered by known keystream bits
- Rollback through encrypted nR and plaintext uid XOR nt phases
- Automatic key verification against second nonce pair before display
- Scrollable recovered key display: sector, key type, 6-byte hex value
- Saves to `/NFC/recovered_keys.txt` for use in subsequent attacks

### SubGHz Repeater

Real-time relay mode for Sub-GHz signals. No file saves, no manual replay steps. M1 listens, captures the signal frame into the ring buffer, detects the end of transmission via 100ms silence threshold, switches the Si4463 to TX, and retransmits. Then loops back to listen. Continuous relay until BACK is pressed.

- Full band and modulation picker (300 to 928 MHz, OOK/ASK/FSK)
- Live status: frequency, modulation, state (Listening/Capturing/Replaying), cycle count
- Clean radio teardown on exit

### POCSAG Pager Decoder

POCSAG is an old pager protocol that still carries real traffic. The Si4463 receives OOK at 512, 1200, or 2400 bps. M1PPER decodes the full frame: preamble detection, sync word search with Hamming tolerance and inverted-polarity fallback, BCH(31,21) single-bit error correction, address codeword parsing (CAPCODE + function), numeric BCD messages, and alphanumeric 7-bit ASCII spanning codeword boundaries.

- Frequency presets: 152.0, 157.45, 158.1, 159.1, 462.0, 462.9625 MHz and custom entry
- Auto-baud cycling between 512/1200/2400 bps with OK key toggle
- Scrolling 4-line message log on display
- BCH error correction with syndrome computation (poly 0x769)

### BLEPTD: BLE Privacy Threat Detector

Port of haxorthematrix/BLEPTD, fully integrated as a standalone M1PPER application. Continuously scans BLE advertisements and classifies detected devices against a 55+ signature database covering trackers, wearables, audio devices, phones, medical devices, and smart home hardware.

- 55+ device signatures matching company ID, manufacturer payload bytes, and service UUIDs
- Threat levels 0-3 with automatic alert highlighting for high-threat devices (AirTag, Galaxy Tag, Tile)
- Medical device protection: glucose monitors and pacemaker monitors marked `[PROT]`, never transmittable
- 4-tab UI: SCAN (live device list sorted by threat), FILTER (category toggles), TX (broadcast selected profile), SETUP
- Confusion mode: round-robin broadcast of all transmittable profiles with rotating random MACs
- Exports device log to `/BLE/bleptd_log.txt`

### BLE GATT Browser

Connect to any nearby BLE device and enumerate its full GATT service/characteristic tree.

- Scan, select, and connect to any BLE peripheral
- Hierarchical display: service UUID, characteristic UUID, property flags (R/W/N/I)
- 35-entry well-known UUID lookup table (Generic Access, Battery, Device Info, HID, Heart Rate, environmental, and more)
- Press OK on any readable characteristic to fetch and display the raw value as hex + ASCII

### NFC Magic Card Write

Write arbitrary UIDs to Magic cards (Gen1A, Gen2, Gen4) directly from the M1.

- Gen1A: 7-bit backdoor command sequence to bypass authentication, then write block 0
- Gen2: standard write path after dictionary auth unlock
- Nibble-by-nibble UID entry with live display, confirm before write
- BCC auto-calculated from entered UID bytes

### MIFARE Default Key Survey

Systematic factory-key sweep against all sectors of a MIFARE Classic card.

- Tests 20 common default keys (FFFFFFFFFFFF, A0A1A2A3A4A5, D3F7D3F7D3F7, and 17 more) against both Key A and Key B on all 16 sectors
- Progress display: sector/key counter with live results
- Saves recovered sector keys to `/NFC/recovered_keys.txt`

### EMV Payment Card Reader

Read public data from contactless Visa, Mastercard, and Amex cards.

- Full ISO 7816-4 APDU flow: SELECT PPSE, AID enumeration, SELECT AID, GET PROCESSING OPTIONS, READ RECORD
- Extracts PAN (masked to last 4 digits), expiry date, cardholder name
- BER-TLV parser for tags 5A, 57, 5F24, 5F20
- Saves to `/NFC/emv_data.txt`

### Evil Portal

Captive portal credential harvester. Spins up an open AP, intercepts HTTP, and serves a login page.

- SSID picker with presets (FreeWifi, Airport_WiFi, Hotel_Guest, Starbucks, xfinitywifi) and custom entry
- HTML harvest page served via ESP32-C6 TCP stack (AT command TCP server on port 80)
- Parses POST `email=` and `password=` fields with URL decoding
- Live screen: AP status, client count, captured credentials (scrollable)
- Credentials appended to `/WiFi/portal_creds.txt` with timestamp

### Network Recon Suite

Three-tab TCP/IP reconnaissance tool requiring an active WiFi connection.

- ARP Scan: ping-sweeps the /24 subnet, identifies live hosts and the gateway
- Port Scan: probes top-20 services (SSH, HTTP, SMB, RDP, MySQL, Redis, etc.) against a user-entered IP
- OUI Lookup: resolves the first 24 bits of any MAC against a 51-entry vendor table

### RF Signal Visualizer

ProtoView-style raw RF signal display. Captures OOK pulse trains from the Si4463 and renders them as a scrollable time-domain waveform.

- Frequency presets: 315, 433.92, 868.35, 915 MHz and custom entry
- Waveform displayed as high/low bars around a center line, auto-scaled to fit screen
- Pulse width statistics: min, max, median
- Modulation hint: single-width (carrier), two-width (PWM/OOK), three-width (Manchester), or complex
- LEFT/RIGHT scroll, UP/DOWN zoom, OK to re-arm capture

### TPMS Tire Pressure Decoder

Decodes TPMS sensor broadcasts from tire pressure monitoring systems.

- Supports 315 MHz and 433 MHz with selectable baud rate
- Protocol support: Schrader (0.25 PSI/LSB), Citroen/Peugeot (kPa\*0.75), and generic
- Manchester decoder with automatic polarity detection
- Tracks up to 8 sensors with FL/FR/RL/RR wheel assignment
- 4-wheel summary screen, saves to `/SubGHz/tpms_log.txt`

### TV-B-Gone

Universal IR power-off blaster. Cycles through power codes for 15 TV brands in sequence.

- Samsung (NEC + Samsung32), LG, Toshiba, Hisense, TCL/RCA, Vizio, Haier, Insignia, Element, Sansui, Panasonic (Kaseikyo), Sharp (Denon), Philips (RC-5), Sony SIRC (×2)
- Progress bar and brand label during transmission
- Also accessible from the Infrared menu

### TOTP/HOTP Authenticator

RFC 6238 TOTP and RFC 4226 HOTP codes, computed on-device with no network required.

- Self-contained SHA-1 and HMAC-SHA-1 implementation (no external crypto library)
- RFC 4648 Base32 seed decoder
- Reads accounts from `/TOTP/accounts.txt` (format: `Name:BASE32SECRET`)
- Large 6-digit code display with 30-second countdown bar
- HOTP counter persisted to `/TOTP/hotp_counters.txt` on each use

### iButton 1-Wire Reader

Reads Dallas/Maxim iButton ROM codes directly from the hardware GPIO.

- Bit-bang 1-Wire master with DWT microsecond timing
- Read ROM (0x33), Dallas CRC-8 validation
- Family code identification: DS1990A/R, DS1991-1996, DS2406
- Saves IDs to `/iButton/saved.txt`

### C3.5 Features

Mfkey32 on-device Crypto-1 key recovery, Sub-GHz Repeater, and POCSAG pager decoder shipped in C3.5 and remain in C3.6 unchanged.

---

## Full Feature Set

### WiFi (ESP32-C6, built-in)

**Passive / Recon:**

- AP Scan: discover nearby access points with SSID, BSSID, channel, RSSI, encryption
- 2.4G Survey: channel utilization, strongest AP, signal distribution
- Probe Sniff: capture and display client probe requests

**Offensive:**

- Deauth Flood: targeted 802.11 deauthentication frames
- PMKID Capture: WPA2/WPA3 PMKID hash extraction
- Handshake Capture: WPA2/WPA3 4-way handshake capture with deauth assist
- Beacon Spam: broadcast arbitrary SSID lists
- Karma Attack: rogue AP responding to all client probes
- Evil Twin: full rogue AP clone (beacon + karma + deauth flood combined)
- Wardriving: continuous AP scanning with WiGLE CSV output to SD card, BSSID deduplication
- EAPOL-Logoff: PMF-bypass attack using EAPOL frames against protected networks

**Management:**

- Connect to 2.4 GHz networks with password entry
- Saved Networks: store and manage credentials
- RTC Sync over SNTP
- Status: IP, signal, channel, mode

### Sub-GHz (Si4463, 142-1050 MHz)

**Tools:**

- Read: capture raw signals with edge-timing ring buffer
- Replay: retransmit saved signals from SD card
- Repeater: real-time relay (new in C3.5)
- Playlist: queue and replay multiple saved signals
- Add Manually: hand-enter signal parameters
- Saved: browse and manage signal library
- Brute Force: iterate through code spaces

**Analysis:**

- Spectrum Analyzer: visual RF spectrum display across configurable range
- Frequency Scanner: sweep for active transmitters
- RSSI Meter: real-time signal strength
- Frequency Reader: identify carrier frequency of incoming signal
- Jam Detector: detect and log RF jamming events
- Jam Log: review jam event history

**Decoding:**

- POCSAG: pager traffic decoder (new in C3.5)
- Weather Station: decode Oregon v2, Acurite, LaCrosse, Infactory sensor data
- 30+ protocol decoders: Princeton, CAME, Nice Flo, Keeloq, Security+ 2.0, Linear, Holtek, Hormann, Marantec, Somfy, and more

**Configuration:**

- Radio Settings: TX power, modulation, custom frequency
- Regional Information: ISM band reference by region
- Extended band support: 150, 200, 250, 300-928 MHz

### NFC (ST25R3916, 13.56 MHz)

**Read / Analyze:**

- Scan: detect and identify NFC tags
- Tag Info: manufacturer lookup, SAK decode, technology identification
- T2T Page Dump: read Type 2 Tag memory pages
- MIFARE Classic: full sector read with Crypto-1 authentication

**Attack / Emulate:**

- Clone and Emulate: copy and replay NFC tags
- Detect Reader: card emulation mode with nonce capture
- Mfkey32: on-device Crypto-1 key recovery from captured nonces (new in C3.5)
- NFC Fuzzer: protocol testing with configurable payloads
- Maximum Power Carrier: 40% modulation (ST25R3916 hardware maximum)

**Saved Tags:** browse and manage NFC tag library on SD card

### 125 kHz RFID

- Read: decode incoming RFID transmissions (20+ protocols)
- Write: clone to T5577 blank cards
- Erase: reset T5577 tags
- Tag Info: read and display T5577 configuration
- RFID Fuzzer: iterate through tag ID spaces
- Saved: browse and manage RFID tag library

Supported protocols: HID Generic, HID 26-bit, HID 35-bit, HID 37-bit, Indala, AWID, Pyramid, Paradox, IOProx, FDX-A, FDX-B, Viking, Electra, Gallagher, Jablotron, PAC/Stanley, Keri, EM4100, EM410x, and more.

### Infrared

- Learn: capture IR signals from any remote
- Replay: retransmit saved signals
- Universal Remote: built-in database of pre-coded remotes
- Import: use Flipper Zero `.ir` files directly

IR database includes: Samsung, LG, Sony, Philips, Panasonic, Vizio, TCL, Hisense, Toshiba, Sharp, Bose, Denon, universal power codes.

### BadUSB / Bad-BT

- DuckyScript 2.0 interpreter: full keystroke injection from SD card scripts
- `STRING`, `DELAY`, `GUI`, `CTRL`, `ALT`, `SHIFT`, key combos, `REPEAT`, `REM`
- Bad-BT: same scripting delivered over BLE HID (no cable, wireless injection)
- BLE Spam: advertisement flood with device type selection

### Bluetooth (ESP32-C6, BLE 5.3)

- BLE Scanner: scan and display nearby Bluetooth devices
- Omni-Sniffer: passive BLE advertisement capture and decode
- BLE Spam: flood advertisement packets across device type categories
- Bluetooth Device Manager: save, review, and connect to known devices

### Field Detection

- NFC Field Detector: detect 13.56 MHz reader fields
- RFID Field Detector: detect 125 kHz reader fields
- Useful for locating hidden readers and access control equipment

### System

- Dual Boot: two firmware banks, CRC-validated on every boot, safe fallback
- Settings: LCD brightness, southpaw mode, persisted to SD card
- Games: Snake, Tetris, T-Rex Runner, Pong, Dice
- External Apps: ELF app loader for `.m1app` files from SD card
- Flipper Zero file compatibility: `.sub`, `.rfid`, `.nfc`, `.ir` files

---

## Hardware Reference

| Component | Specification                                                        |
| --------- | -------------------------------------------------------------------- |
| MCU       | STM32H573VIT6, Cortex-M33, 250 MHz, 2 MB dual-bank flash, 640 KB RAM |
| Display   | 128x64 monochrome (ST7586s)                                          |
| Sub-GHz   | Si4463 transceiver, 142-1050 MHz, OOK/ASK/FSK/GFSK                   |
| NFC       | ST25R3916, 13.56 MHz, up to 40% modulation                           |
| RFID      | 125 kHz ASK/PSK, T5577 write                                         |
| WiFi / BT | ESP32-C6, WiFi 6 (802.11ax), BLE 5.3, 802.15.4                       |
| IR        | TSOP38238 receiver + IR LED                                          |
| USB       | USB-C, CDC + MSC + HID composite                                     |
| Storage   | microSD                                                              |

---

## Building

### Prerequisites

- ARM GCC 14.3 (via STM32CubeIDE 2.1.0 or standalone)
- CMake 3.22+
- Ninja
- Python 3 (for post-build CRC injection)

### Quick Build (Linux / macOS)

```bash
./build.sh
```

### CMake Manual Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
python tools/append_crc32.py build/M1_v0800_C3.4.bin \
    --output build/M1_v0800_C3.4_wCRC.bin \
    --c3-revision 4 --verbose
```

### Windows (PowerShell)

```powershell
.\do_build.ps1
```

Output binaries in `artifacts/`. Flash the `_wCRC.bin` file.

---

## Flashing

### Via qMonstatek (recommended)

[qMonstatek](https://github.com/bedge117/qMonstatek) is the desktop companion app for Windows. Connect via USB-C and use the Firmware Update page.

### Via DFU Mode

1. Power off (Settings > Power > Power Off > Right)
2. Hold **Up + OK** for 5 seconds to enter DFU mode
3. Connect USB-C
4. Flash via the DFU page in qMonstatek

### Via SWD

Use an ST-Link or J-Link with STM32CubeIDE or OpenOCD.

---

## SD Card Layout

```
0:/
├── BadUSB/          DuckyScript .txt payloads
├── IR/              Infrared remote .ir files
│   └── Learned/     Captured IR signals
├── NFC/             NFC tag .nfc files
│   ├── mfkey_nonces.txt    Captured auth nonces
│   └── recovered_keys.txt  Mfkey32 recovered keys
├── RFID/            RFID tag .rfid files
├── SubGHz/          Sub-GHz signal .sub files
├── WARDRIVE/        WiGLE CSV wardriving logs
├── apps/            External .m1app applications
├── settings.ini     Device settings
└── wifi_cred.ini    Saved WiFi credentials
```

---

## Companion App

[qMonstatek](https://github.com/bedge117/qMonstatek) connects over USB to mirror the M1 display, manage SD card files, flash firmware, update the ESP32 coprocessor, and control WiFi settings from a desktop interface.

---

## Contributing

Pull requests are welcome. Open an issue for bugs or feature requests.

The RPC protocol for tool integrations is implemented in `m1_csrc/m1_rpc.c` and `Core/Src/cli_app.c`.

---

## License

GNU General Public License v3.0. See [COPYING.txt](COPYING.txt).
