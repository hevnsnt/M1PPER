# Changelog

All notable changes to M1PPER are documented here.

---

## [1.0.0] - C3.6 - 2026-05-06

### Added

**NFC**

- MIFARE Classic Default Key Survey (20 factory keys, all 16 sectors, Key A+B)
- Magic Card Writer (Gen1A backdoor 0x40/0x43, Gen2, Gen4 direct write)
- EMV Payment Card Reader (SELECT PPSE, AID enumeration, GPO, READ RECORD, BER-TLV parse, masked PAN display)

**Bluetooth (BLE 5.3)**

- BLEPTD tracker detection (55+ device signatures: AirTag, Tile, Galaxy Tag, SmartTag, Find My, and 50+ others)
- BLEPTD Confusion Mode (random MAC/profile broadcast to defeat surveillance tracking)
- BLE GATT Browser (connect, enumerate services and characteristics, read values, 35-entry UUID table)

**WiFi**

- Evil Portal (captive portal AP, TCP server, credential harvesting page, timestamped log)
- Network Recon (ARP sweep, top-20 port scanner, 51-entry OUI lookup table)

**Sub-GHz**

- RF Signal Visualizer (ProtoView-style OOK pulse waveform display, 512-pulse buffer, scroll/zoom)
- TPMS Decoder (Manchester decode, Schrader/Citroen-Peugeot/generic protocols, 8-sensor table with FL/FR/RL/RR assignment)

**Tools**

- TV-B-Gone (15 brands: Samsung, LG, Sony, Philips, Panasonic, TCL, Vizio, Hisense, Sharp, Toshiba, Hitachi, Insignia, Sanyo, JVC, Magnavox)
- TOTP/HOTP Authenticator (RFC 6238/4226, self-contained SHA-1/HMAC-SHA1, Base32 seeds from SD card)
- iButton (Dallas/Maxim 1-Wire ROM read, CRC-8 validation, family code identification, save to SD)

**Documentation**

- Complete hardware reference (docs/hardware.md)
- Build and installation guide (docs/installation.md)
- Full feature reference for all C3.6 apps (docs/features.md)
- SD card directory tree and file format specifications (docs/sd-card.md)

---

## [0.1.1] - C3.5 - 2026-04-24

### Added

**NFC**

- On-device Mfkey32 key recovery (Crypto-1 nonce pair attack, no laptop required, ~2s per sector)
- Detect Reader with nonce capture to /NFC/mfkey_nonces.txt

**Sub-GHz**

- POCSAG pager decoder (BCH(31,21) error correction, numeric/alpha/sky pager formats)
- Sub-GHz Repeater (RX then re-transmit, configurable delay)
- Sub-GHz Signal Playlist (sequential playback of saved .sub files)

**WiFi (ESP32-C6)**

- Deauth Flood
- PMKID Capture
- WPA2/WPA3 Handshake Capture with deauth assist
- Beacon Spam
- Karma Attack
- Evil Twin
- EAPOL-Logoff (PMF bypass)
- Probe Sniff
- Wardriving with WiGLE CSV output

**Bluetooth**

- BLE Spam (Apple Continuity, Google Fast Pair, Samsung EasySetup, Windows SwiftPair)
- Omni-Sniffer (BLE advertisement capture)
- Bad-BT (wireless keystroke injection over BLE HID)

### Improved

- Virtual keyboard with MAC address formatting
- NFC carrier at ST25R3916 hardware maximum (40% modulation)
- SPI communication reliability with retry logic

---

## [0.1.0] - C3.4 - Initial Release

Base M1PPER firmware:

- Sub-GHz radio with 30+ protocol decoders (OOK/ASK/FSK, 142-1050 MHz)
- MIFARE Classic read with Crypto-1 authentication
- 125 kHz RFID read/write/clone (HID, Indala, EM4100, Gallagher, and 15+ more)
- Infrared learn, replay, and universal remote database
- BadUSB (DuckyScript 2.0 over USB HID)
- WiFi AP scan, channel survey, ARP scan
- External app loader (.m1app)
- TOTP authenticator (basic)
- Dual-bank firmware update with CRC32 validation
