# Feature Reference

Complete reference for every application in M1PPER C3.6.

---

## Sub-GHz

The Si4463 transceiver covers 142-1050 MHz with OOK, ASK, FSK, and GFSK modulations.

### Read

Capture raw Sub-GHz signals. Displays modulation, frequency, and protocol if recognized. Saves to `/SubGHz/` as `.sub` files.

### Replay

Retransmit any saved `.sub` file. Supports Flipper Zero `.sub` format natively.

### Repeater

Real-time relay mode. Listens for a signal, captures it into a ring buffer, detects end-of-transmission via 100 ms silence threshold, switches to TX, retransmits, and loops. Continuous relay until BACK. No file saves, no manual steps.

- Frequency picker: 300-928 MHz in steps, plus custom entry
- Modulation picker: OOK / ASK / FSK
- Live status: state (Listening / Capturing / Replaying), cycle count

### Playlist

Queue multiple `.sub` files for sequential replay. Useful for testing multi-button remotes or replay sequences.

### Saved

Browse, preview, and manage saved signals on the SD card.

### Add Manually

Hand-enter signal parameters: frequency, modulation, protocol, bit pattern.

### Brute Force

Iterate through a code space. Configure start code, end code, bit count, and timing. Useful for fixed-code remotes.

### Spectrum Analyzer

Scrolling RF energy display across a configurable frequency range. Shows which channels are active.

### Frequency Scanner

Sweep a frequency range and report active transmitters with RSSI.

### RSSI Meter

Real-time signal strength at the current frequency. Useful for locating transmitters.

### Frequency Reader

Identify the carrier frequency of an incoming signal. Points the Si4463 at an unknown frequency and reports what it finds.

### Jam Detector

Monitor for RF jamming events (broadband noise bursts that disrupt communication). Logs events with timestamp.

### Jam Log

Review previously detected jamming events.

### Weather Station

Decode ISM-band wireless weather sensor broadcasts. Supports Oregon Scientific v2, Acurite, LaCrosse, Infactory protocols. Displays temperature, humidity, channel.

### POCSAG

Full POCSAG pager protocol decoder.

- Si4463 receives OOK at 512, 1200, or 2400 bps
- BCH(31,21) single-bit error correction (polynomial 0x769)
- Preamble detection, sync word search with inverted-polarity fallback
- Address codeword parsing: CAPCODE (18-bit) + function field
- Numeric BCD and 7-bit ASCII messages spanning codeword boundaries
- Frequency presets: 152.0, 157.45, 158.1, 159.1, 462.0, 462.9625 MHz, plus custom
- Auto-baud cycling between 512/1200/2400 bps (toggle with OK)
- Scrolling 4-line message log

### RF Signal Visualizer

ProtoView-style raw OOK signal waveform display.

- Captures pulse trains from the Si4463 edge-timing mode
- Renders HIGH/LOW bars around a center line, auto-scaled to ~80 bars on screen
- Pulse width statistics: min, max, median
- Modulation hint: single-width (carrier), two-width (PWM/OOK), three-width (Manchester)
- LEFT/RIGHT to scroll, UP/DOWN to zoom, OK to re-arm capture
- Frequency presets: 315, 433.92, 868.35, 915 MHz, plus custom

### TPMS Decoder

Tire Pressure Monitoring System sensor decoder.

- 315 MHz and 433 MHz, selectable baud rate
- Protocol support: Schrader (0.25 PSI per LSB), Citroen/Peugeot (kPa \* 0.75), generic
- Manchester decoding with automatic polarity detection
- Tracks up to 8 sensors simultaneously
- FL/FR/RL/RR wheel position assignment
- 4-wheel summary display
- Saves decoded packets to `/SubGHz/tpms_log.txt`

### Protocol Decoders

30+ fixed-code and rolling-code protocol decoders built into the Sub-GHz stack: Princeton, CAME, Nice Flo, Keeloq, Security+ 2.0, Linear, Holtek, Hormann, Marantec, Somfy, and more.

---

## NFC

The ST25R3916 operates at 13.56 MHz and supports ISO 14443A/B, ISO 15693, and NFC-F.

### Read (Scan)

Detect and identify NFC tags. Shows technology, UID, manufacturer (lookup table), SAK decode for MIFARE variants.

### Fast Read

Rapid UID capture mode. Minimal UI, maximum scan rate.

### Saved Tags

Browse and manage NFC tag files on the SD card.

### Add Manually

Hand-enter tag parameters to create a `.nfc` file.

### Advanced

Extra actions for detected tags: clone, emulate, edit UID, rename, delete.

### Tools

Protocol-level utilities: T2T page dump, MIFARE Classic full sector read.

### MFKey Detect (Detect Reader)

Card emulation mode. Emulate a MIFARE Classic card in front of a reader, capture authentication nonces (nt, nr_enc, ar_enc pairs). Saves nonce pairs to `/NFC/mfkey_nonces.txt` for use with Mfkey32.

### Mfkey32

On-device Crypto-1 key recovery from captured reader nonces.

- Full two-phase LFSR state enumeration (2^24 odd + 2^24 even candidate search)
- Filtered by 32 known keystream bits from the authentication exchange
- Rollback through encrypted nR and uid XOR nt phases
- Automatic key verification against second nonce pair before display
- Runs on the STM32H573 at 250 MHz — under 2 seconds per sector
- Results displayed as scrollable sector/key table
- Saves to `/NFC/recovered_keys.txt`

### Magic Write

Write arbitrary UIDs to Magic MIFARE cards.

- **Gen1A (CUID):** 7-bit backdoor command (0x40 / 0x43), then direct block 0 write without authentication
- **Gen2 (FUID):** dictionary auth unlock, then standard write
- **Gen4 (GDID):** proprietary vendor unlock, then write
- Nibble-by-nibble UID entry with live display, BCC auto-calculated
- Confirm screen before write, result displayed

### Default Key Survey

Systematic factory-key sweep against all sectors of a MIFARE Classic card.

- Tests 20 common default keys against both Key A and Key B on all 16 sectors
- Keys include: FFFFFFFFFFFF, A0A1A2A3A4A5, D3F7D3F7D3F7, 000000000000, B0B1B2B3B4B5, and 15 more transit/access control defaults
- Live progress display: sector number, key index
- Saves all found sector keys to `/NFC/recovered_keys.txt`

### EMV Card Reader

Read public data from contactless Visa, Mastercard, and Amex payment cards.

- Full ISO 7816-4 APDU flow: SELECT PPSE, AID enumeration, SELECT AID, GET PROCESSING OPTIONS, READ RECORD
- BER-TLV parser searches for: PAN (tag 5A), track 2 (tag 57), expiry (tag 5F24), cardholder name (tag 5F20)
- PAN displayed masked to last 4 digits
- Saves to `/NFC/emv_data.txt`

---

## 125 kHz RFID

Discrete analog front-end with STM32 timer capture. ASK/PSK demodulation in firmware.

Supported protocols: HID Generic, HID 26-bit, HID 35-bit, HID 37-bit, Indala, AWID, Pyramid, Paradox, IOProx, FDX-A, FDX-B, Viking, Electra, Gallagher, Jablotron, PAC/Stanley, Keri, EM4100, EM410x, and more.

### Read

Hold the M1 near a tag or card. Displays protocol, facility code, card number, and raw bit string. Save to `.rfid` file.

### Write

Write a captured or manually entered ID to a T5577 blank. Sets the T5577 configuration block to match the source protocol's modulation, bit rate, and carrier settings. Verify pass/fail displayed after write.

### Erase

Wipe a T5577: clears the configuration block and all data pages to default (all-zero config, 0xFF data). Useful before re-writing a card to a different protocol.

### Tag Info

Read and display the raw T5577 configuration block: modulation type, bit rate, RF divide ratio, and PSK carrier frequency settings. Useful for diagnosing read failures on unusual tags.

### RFID Fuzzer

Increment through an ID space for a selected protocol. Configure start ID, end ID, and inter-transmission delay. Useful for access control research on fixed-code systems.

### Saved

Browse, load, and delete `.rfid` files from the SD card.

---

## Infrared

TSOP38238 receiver for capture. IR LED transmitter supports all common carriers: 36 kHz (RC-5, Kaseikyo), 38 kHz (NEC), 40 kHz (Sony SIRC), 56 kHz (RCMM).

### Learn

Point any IR remote at the M1 and press a button. Captures the raw timing, identifies the protocol if recognized (NEC, Samsung32, RC-5, Kaseikyo, SIRC, RCMM), and saves to `/IR/Learned/`. Learn mode stays active for multi-button capture.

### Replay

Retransmit any saved `.ir` file. Supports both M1PPER-captured and Flipper Zero `.ir` format (RAW and protocol variants).

### Universal Remote

Pre-loaded IR database organized by device category: TV (LG, Samsung, Sony, Philips, Panasonic, Sharp, Toshiba, Hisense, TCL, Vizio), Audio (Bose, Denon, Samsung Soundbar), Projector, Fan. Power, volume, input, and mute codes included per device.

### TV-B-Gone

Universal TV power-off blaster. Cycles through 15 brand-specific power codes in sequence: Samsung (NEC + Samsung32), LG, Toshiba, Hisense, TCL/RCA, Vizio, Haier, Insignia, Element, Sansui, Panasonic (Kaseikyo), Sharp (Denon), Philips (RC-5), Sony SIRC x2. Progress bar and brand label during transmission.

---

## WiFi

All WiFi features use the ESP32-C6 via SPI AT commands. Requires the custom SPI AT firmware.

### AP Scan

Discover nearby access points. Displays SSID, BSSID, channel, RSSI, and encryption type.

### 2.4G Survey

Channel utilization overview. Shows which channels are congested and which APs are strongest per channel.

### Health Check

Connectivity diagnostics. Tests association, DHCP, and gateway reachability.

### Zigbee Scan

Scan for IEEE 802.15.4 Zigbee devices via the ESP32-C6's native 802.15.4 radio. No external hardware required.

### Thread Scan

Scan for IEEE 802.15.4 Thread/Matter devices.

### Connect / Saved Networks

Connect to a 2.4 GHz AP with password entry. Store and manage credentials (encrypted on SD card).

### RTC Sync

Synchronize the STM32H573 RTC to SNTP time servers over WiFi.

### Status / Mode / Stats

Live display of IP address, RSSI, channel, connection mode, and traffic counters.

---

## WiFi Offensive

### Deauth Flood

Broadcast 802.11 deauthentication frames against a target AP and/or client. Select target from scan list.

### Beacon Spam

Broadcast arbitrary SSID lists to flood nearby device probe responses and SSID history.

### Probe Sniff

Capture and display client probe request frames. Shows what SSIDs nearby clients are looking for.

### PMKID Capture

WPA2/WPA3 PMKID hash extraction from association frames. No clients required.

### Handshake Capture

WPA2/WPA3 4-way handshake capture. Optional deauth assist to force clients to re-authenticate. Saves PCAP-compatible output for offline cracking.

### Karma Attack

Rogue AP that responds to all client probe requests, luring clients to associate.

### Evil Twin

Combined beacon + karma + deauth flood. Clones a target AP's SSID and deauths its clients to force association with the rogue AP.

### Wardriving

Continuous AP scanning with WiGLE CSV output to `/WARDRIVE/`. BSSID deduplication across scans.

### EAPOL-Logoff

PMF bypass attack. Sends EAPOL-Logoff frames to forcibly disconnect clients from PMF-protected networks.

### Evil Portal

Captive portal credential harvester.

- Configurable SSID (presets: FreeWifi, Airport_WiFi, Hotel_Guest, Starbucks, xfinitywifi, plus custom)
- Open AP on configurable channel
- TCP server on port 80 via ESP32-C6 AT stack
- Serves styled HTML login page on all GET requests
- Parses POST `email` and `password` fields with URL decoding
- Live display: SSID, client count, captured credential count, scrollable credential log
- Saves to `/WiFi/portal_creds.txt` with timestamp

### Net Recon

TCP/IP network reconnaissance. Requires an active WiFi connection.

Three tabs navigated with LEFT/RIGHT:

**ARP Scan:** Reads M1's IP from `AT+CIPSTA?`, derives the /24 subnet, ping-sweeps .1 through .254, marks the gateway. Shows live host count.

**Port Scan:** Enter a target IPv4, probe top-20 services: FTP(21), SSH(22), Telnet(23), SMTP(25), DNS(53), HTTP(80), POP3(110), IMAP(143), HTTPS(443), SMB(445), MSSQL(1433), MySQL(3306), RDP(3389), Postgres(5432), VNC(5900), Redis(6379), HTTP-Alt(8080), HTTPS-Alt(8443), Elastic(9200), MongoDB(27017). Shows OPEN/closed per port.

**OUI Lookup:** Enter any 6-byte MAC, resolves first 3 bytes against a 51-entry vendor table (Apple variants, Google/Nest, Samsung, Cisco, TP-Link, VMware, Raspberry Pi, Sonos, and more).

---

## Bluetooth

### BLE Scanner

Scan and display nearby Bluetooth devices. Shows address, name, RSSI, and company ID where available.

### Saved Devices

Store and manage known device entries.

### Omni-Sniffer

Passive BLE advertisement capture and classification. Identifies device types: iPhones, AirTags, Galaxy phones, AirPods, Fitbit, Garmin, and more. Uses a multi-feature confidence classifier.

### BLE Spam

Flood BLE advertisement packets to trigger proximity-pairing popups on nearby phones.

- **Apple:** AirPods Gen1/Pro, AirPods Max, Apple Watch, Apple TV, iPhone Handoff — all Continuity types
- **Google:** Fast Pair with 3-byte model IDs
- **Samsung:** EasySetup device pairing popups
- **Windows:** SwiftPair pairing prompts
- Cycle mode rotates through all vendors continuously

### BLE GATT Browser

Connect to any BLE peripheral and enumerate its full GATT service/characteristic tree.

- Scan, select, and connect to nearby devices
- Hierarchical display: service UUID, characteristic UUID, property flags (R/W/N/I)
- 35-entry well-known UUID lookup: Generic Access, Battery, Device Info, HID, Heart Rate, Environmental Sensing, Tile, Fast Pair, and more
- Press OK on any readable characteristic to fetch and display the raw hex + ASCII value
- Clean disconnect on BACK

### Bad-BT

DuckyScript 2.0 keystroke injection delivered over BLE HID. Same script files as BadUSB, no cable required.

### BLE Device Manager

Connect to, save, and manage known BLE peripherals.

---

## BLEPTD

Standalone application. Port of [haxorthematrix/BLEPTD](https://github.com/haxorthematrix/BLEPTD).

BLE Privacy Threat Detector continuously scans BLE advertisements and classifies detected devices against a 55+ signature database.

**Categories:** Trackers, Wearables, Audio, Phones, Medical, Smart Home

**Threat levels:**

- 0 — Benign (headphones, smartwatches)
- 1 — Low (phone advertising nearby)
- 2 — Medium (unknown tracker or Tile)
- 3 — High (AirTag, Galaxy SmartTag, unknown follower)

**Covered devices include:** AirTag, Find My items, Apple AirPods, iPhone proximity, Samsung Galaxy Tag, Galaxy Phone, Tile Pro/Slim/Sticker/Mate, Chipolo, PebbleBee, Fitbit, Garmin, glucose monitors, and more.

**Medical protection:** Glucose monitors and pacemaker monitors are permanently flagged `[PROT]`. They can never be added to the TX list.

**4-tab UI:**

| Tab    | Function                                                                                 |
| ------ | ---------------------------------------------------------------------------------------- |
| SCAN   | Live device list sorted by threat level. High-threat devices highlighted.                |
| FILTER | Toggle which categories appear in the scan list. Medical always protected.               |
| TX     | Select and broadcast a transmittable device profile. Confusion mode cycles all profiles. |
| SETUP  | Scan interval, alert threshold, export log.                                              |

**Confusion mode:** Cycles through all transmittable signatures every 3 seconds using a different random MAC for each transmission. Makes it impractical for surveillance systems to track any single device type.

**Log export:** `/BLE/bleptd_log.txt`

---

## BadUSB

DuckyScript 2.0 interpreter over USB HID.

- Supported commands: `STRING`, `DELAY`, `GUI`, `CTRL`, `ALT`, `SHIFT`, all key names, `REPEAT`, `REM`
- Scripts loaded from `/BadUSB/` on the SD card (`.txt` files)
- USB VID/PID presents as a standard HID keyboard
- Also available over BLE as Bad-BT (no cable required)

---

## GPIO

Direct control of the M1's external GPIO header for hardware interfacing and debug.

### GPIO Manual Control

Toggle individual pins on the external header high or low. Useful for driving external circuits, triggering test equipment, or verifying pin assignments.

### 3.3V Power

Enable the 3.3V rail on the GPIO header. Use this to power low-current external sensors or modules without a separate supply.

---

## Field Detection

Passive carrier-sense modes. No transmission — the M1 listens for reader fields and reports signal strength. Useful for locating readers in walls or ceilings before attempting a read.

### NFC Field Detector

The ST25R3916 monitors for 13.56 MHz carrier energy and displays signal amplitude as a live bar graph. Hold near an access control reader, tap terminal, or POS device to confirm presence and range.

### RFID Field Detector

Monitors the 125 kHz analog front-end for carrier energy from LF RFID readers. Displays signal level. Useful for finding HID, EM4100, or Indala readers in field installations.

---

## TOTP Authenticator

RFC 6238 TOTP and RFC 4226 HOTP, computed entirely on-device.

- Self-contained SHA-1 and HMAC-SHA1 implementation (no external crypto library)
- RFC 4648 Base32 seed decoder with padding and case tolerance
- Reads accounts from `/TOTP/accounts.txt` — one per line, format: `AccountName:BASE32SECRET`
- HOTP accounts from `/TOTP/hotp_accounts.txt`, counters in `/TOTP/hotp_counters.txt`
- Large 6-digit code display with 30-second countdown bar (TOTP) or full bar (HOTP)
- UP/DOWN to switch accounts
- Uses STM32 RTC for accurate time; falls back to HAL_GetTick() if RTC not set

---

## iButton Reader

Dallas/Maxim iButton 1-Wire reader.

- Bit-banged 1-Wire master using DWT cycle counter for microsecond timing
- Read ROM (0x33) command
- Dallas CRC-8 validation (polynomial 0x8C reflected)
- Family code identification: DS1990A/R, DS1991, DS1992, DS1993, DS1994, DS1995, DS1996, DS2406
- Saves IDs to `/iButton/saved.txt`

---

## Apps

Built-in utility applications accessible from the Apps menu.

| App              | Description                                           |
| ---------------- | ----------------------------------------------------- |
| System Dashboard | CPU, RAM, flash usage, uptime, temperature            |
| File Tools       | SD card file manager: browse, rename, delete          |
| Hex Viewer       | View any file as hex dump on-screen                   |
| Clock            | RTC display with date and time                        |
| ESP32 Link       | Direct AT command terminal to the ESP32-C6            |
| TV-B-Gone        | Universal IR power-off (also in Infrared menu)        |
| TOTP Auth        | TOTP/HOTP authenticator (also standalone)             |
| iButton Read     | iButton 1-Wire reader (also standalone)               |
| Apps Browser     | Load and run external `.m1app` ELF files from SD card |
| Dab Timer        | Timer with display                                    |
| DVD Logo         | Bouncing DVD logo screensaver                         |

---

## Games

Five games: Snake, Tetris, T-Rex Runner, Pong, Dice Roll.

---

## System

### Backlight

Adjust LCD brightness 0–100%. Setting persisted to `[display] brightness` in `settings.ini` on the SD card.

### LCD & Notifications

Display options including southpaw mode (mirrors the button layout for left-handed use, persisted to `settings.ini`).

### Firmware Update

OTA-style update from the SD card. Place a `_wCRC.bin` file on the SD card and select it here. The bootloader verifies the embedded CRC32 before committing to the inactive flash bank. On success, switches boot bank and reboots.

### ESP32 Update

Flash new ESP32-C6 SPI-AT coprocessor firmware via the STM32's UART ROM bootloader passthrough. Requires `factory_ESP32C6-SPI.bin` and `factory_ESP32C6-SPI.md5` in the SD root. The MD5 must be exactly 32 bytes of uppercase hex with no newline.

### About

Displays firmware version string (`v0.8.0.0-C3.X`), build date, and C3 revision number.

### Dual Boot

Displays both flash bank versions with CRC32 validation status. On every boot, the bootloader validates both banks and falls back to the last verified good bank if the active bank fails its checksum.

---

## Flipper Zero File Compatibility

M1PPER reads Flipper Zero file formats directly:

| Extension | Format           | Notes                         |
| --------- | ---------------- | ----------------------------- |
| `.sub`    | Sub-GHz signal   | All Flipper protocol variants |
| `.nfc`    | NFC tag          | MIFARE Classic, NTAG, etc.    |
| `.rfid`   | 125 kHz RFID tag | All Flipper RFID protocols    |
| `.ir`     | Infrared signal  | RAW and protocol variants     |

Place files in the corresponding directory on the SD card.
