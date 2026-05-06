# SD Card Layout

The M1 requires a FAT32-formatted microSD card. M1PPER creates directories automatically on first use. The full directory tree is documented here for reference.

---

## Directory Tree

```
0:/
├── BadUSB/
│   └── *.txt                     DuckyScript 2.0 payload files
│
├── BLE/
│   └── bleptd_log.txt            BLEPTD device detection log
│
├── IR/
│   ├── *.ir                      Saved infrared remotes (Flipper .ir format)
│   └── Learned/
│       └── *.ir                  Signals captured by Learn mode
│
├── iButton/
│   └── saved.txt                 Saved iButton ROM codes
│
├── NFC/
│   ├── *.nfc                     Saved NFC tags (Flipper .nfc format)
│   ├── mfkey_nonces.txt          Auth nonces captured in Detect Reader mode
│   ├── recovered_keys.txt        Keys recovered by Mfkey32 and Default Key Survey
│   └── emv_data.txt              Data read by EMV Card Reader
│
├── RFID/
│   └── *.rfid                    Saved 125 kHz RFID tags (Flipper .rfid format)
│
├── SubGHz/
│   ├── *.sub                     Saved Sub-GHz signals (Flipper .sub format)
│   └── tpms_log.txt              TPMS sensor decode log
│
├── TOTP/
│   ├── accounts.txt              TOTP account seeds
│   ├── hotp_accounts.txt         HOTP account seeds
│   └── hotp_counters.txt         HOTP counter state (auto-updated on each use)
│
├── WARDRIVE/
│   └── *.csv                     WiGLE-format wardriving logs
│
├── WiFi/
│   ├── portal_creds.txt          Evil Portal captured credentials
│   └── wifi_cred.ini             Saved WiFi network credentials (encrypted)
│
├── apps/
│   └── *.m1app                   External ELF applications
│
├── factory_ESP32C6-SPI.bin       ESP32-C6 firmware update image (optional)
├── factory_ESP32C6-SPI.md5       MD5 checksum for ESP32 update (32 bytes, uppercase hex, no newline)
├── settings.ini                  Device settings (brightness, southpaw mode, etc.)
└── wifi_cred.ini                 WiFi credentials (symlink target, see WiFi/wifi_cred.ini)
```

---

## File Formats

### BadUSB Scripts (`/BadUSB/*.txt`)

DuckyScript 2.0. UTF-8 text, one command per line.

```
REM Example payload
DELAY 1000
GUI r
DELAY 500
STRING notepad
ENTER
DELAY 500
STRING Hello from M1PPER
ENTER
```

Supported commands: `REM`, `DELAY`, `STRING`, `ENTER`, `GUI`, `CTRL`, `ALT`, `SHIFT`, `TAB`, `ESC`, `BACKSPACE`, `DELETE`, `HOME`, `END`, `INSERT`, `PAGEUP`, `PAGEDOWN`, `UP`, `DOWN`, `LEFT`, `RIGHT`, `F1`-`F12`, `REPEAT`.

---

### TOTP Accounts (`/TOTP/accounts.txt`)

One account per line: `AccountName:BASE32ENCODEDKEY`

```
GitHub:JBSWY3DPEHPK3PXP
Google:JBSWY3DPEHPK3PXP
Cloudflare:MFRA4Y3JPFXGG4TF
```

Base32 encoding as per RFC 4648. Case-insensitive. Padding optional. Whitespace ignored.

HOTP accounts use the same format in `/TOTP/hotp_accounts.txt`. Counter state is managed automatically in `/TOTP/hotp_counters.txt`.

---

### Mfkey32 Nonces (`/NFC/mfkey_nonces.txt`)

Written by Detect Reader mode. Read by Mfkey32.

```
uid: AABBCCDD
nt0: 12345678
nr0_enc: 87654321
ar0_enc: ABCDEF01
nt1: 23456789
nr1_enc: 98765432
ar1_enc: BCDEF012
sector: 0
key_type: A
```

Two nonce pairs per sector are required for Mfkey32 to recover the key.

---

### Recovered Keys (`/NFC/recovered_keys.txt`)

Written by Mfkey32 and Default Key Survey.

```
Sector 0 Key A: FFFFFFFFFFFF
Sector 0 Key B: FFFFFFFFFFFF
Sector 1 Key A: A0A1A2A3A4A5
Sector 3 Key A: D3F7D3F7D3F7
```

---

### EMV Data (`/NFC/emv_data.txt`)

```
[2026-05-06 14:32] AID: A0000000031010 (Visa)
PAN: **** **** **** 1234
Expiry: 12/27
Name: CARDHOLDER NAME
```

---

### TPMS Log (`/SubGHz/tpms_log.txt`)

CSV format: date, time, protocol, sensor ID, pressure (PSI), temperature (C), status.

```
2026-05-06,14:32,Schrader,A1B2C3D4,32.5,22,OK
2026-05-06,14:32,Schrader,E5F6A7B8,31.0,21,OK
```

---

### Evil Portal Credentials (`/WiFi/portal_creds.txt`)

```
[2026-05-06 14:32] user@example.com:password123
[2026-05-06 14:33] victim@company.com:hunter2
```

---

### BLEPTD Log (`/BLE/bleptd_log.txt`)

```
[2026-05-06 14:32] AirTag AA:BB:CC:DD:EE:FF RSSI:-65 THREAT:3
[2026-05-06 14:33] Tile FF:EE:DD:CC:BB:AA RSSI:-72 THREAT:2
```

---

### WiGLE CSV (`/WARDRIVE/wardrive_YYYYMMDD_HHMMSS.csv`)

Standard WiGLE upload format.

```
WigleWifi-1.4,appRelease=M1PPER-C3.6,model=M1,release=0.1.2,...
MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,...
AA:BB:CC:DD:EE:FF,NetworkName,[WPA2],2026-05-06 14:32:00,6,-65,-1.0,-1.0,...
```

---

### iButton Saved (`/iButton/saved.txt`)

```
DS1990A:01A2B3C4D5E6F708
DS1990A:01CAFEBABE001234
```

Format: `FamilyName:16HexChars` (8 bytes = family + 6-byte serial + CRC).

---

### Settings (`/settings.ini`)

Written and read by M1PPER on every boot. Manual edits are safe as long as keys and section names match exactly.

Known keys:

| Section     | Key          | Values | Description                                                       |
| ----------- | ------------ | ------ | ----------------------------------------------------------------- |
| `[display]` | `brightness` | 0–100  | LCD backlight level                                               |
| `[display]` | `southpaw`   | 0 or 1 | Mirror button layout for left-handed use                          |
| `[system]`  | `boot_bank`  | 0 or 1 | Active flash bank (managed by bootloader, do not change manually) |

```ini
[display]
brightness=80
southpaw=0

[system]
boot_bank=0
```

---

### WiFi Credentials (`/WiFi/wifi_cred.ini`)

AES-encrypted. The encryption key is derived from device-specific data — credentials saved on one M1 will not decrypt on another. Manage saved networks through System > Saved Networks. The raw file is not user-editable.

---

## ESP32 Firmware Update Files

To update the ESP32-C6 coprocessor firmware, place these two files in the SD root:

| File                      | Description                                                |
| ------------------------- | ---------------------------------------------------------- |
| `factory_ESP32C6-SPI.bin` | Full factory image (bootloader + partition table + app)    |
| `factory_ESP32C6-SPI.md5` | Exactly 32 bytes of uppercase hex MD5 checksum, no newline |

The MD5 must be uppercase. The M1 uses `mh_hexify()` which produces uppercase and will reject lowercase MD5 files.

Flash offset for the factory image is `0x000000`.

---

## SD Card Requirements

- Format: FAT32 (not exFAT, not NTFS)
- Max tested size: 32 GB SDHC
- Recommended: class 10 / A1 or faster
- Connection: SPI mode (the M1 does not use SDIO)

SDXC cards (>32 GB) formatted as exFAT will not work. If your card came formatted as exFAT, reformat it as FAT32 before use.
