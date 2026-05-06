# Installation

## Flashing Pre-Built Firmware

### Option 1: qMonstatek (Recommended)

[qMonstatek](https://github.com/bedge117/qMonstatek) is the official desktop companion for Windows.

1. Download the latest `M1_T-1000_vX.X.X_wCRC.bin` from [Releases](https://github.com/hevnsnt/M1PPER/releases)
2. Connect the M1 via USB-C
3. Open qMonstatek, go to **Firmware Update**
4. Select the `_wCRC.bin` file and click Flash

The `_wCRC.bin` file contains the firmware binary with an appended CRC32 checksum and C3 revision metadata. Always flash the `_wCRC` variant, not the bare `.bin`.

---

### Option 2: DFU Mode

Use this if qMonstatek is unavailable or for SWD flashing.

**Enter DFU mode:**

1. Power off: Settings > Power > Power Off > Right
2. Hold **Up + OK** for 5 seconds
3. Connect USB-C — the M1 enumerates as a USB DFU device

**Flash using qMonstatek:**
Navigate to the DFU page and flash the `_wCRC.bin` file.

**Flash using dfu-util (Linux/macOS):**

```bash
dfu-util -a 0 -s 0x08000000:leave -D M1_T-1000_vX.X.X_wCRC.bin
```

---

### Option 3: SWD

For developers with an ST-Link or J-Link.

**STM32CubeIDE:**
Import the project, connect the debugger to CN2, and use Run > Debug or Run > Flash.

**OpenOCD:**

```bash
openocd -f interface/stlink.cfg -f target/stm32h5x.cfg \
  -c "program M1_T-1000_vX.X.X_wCRC.bin 0x08000000 verify reset exit"
```

---

## Building from Source

### Prerequisites

| Tool     | Version | Source                           |
| -------- | ------- | -------------------------------- |
| ARM GCC  | 14.3    | STM32CubeIDE 2.1.0 or standalone |
| CMake    | 3.22+   | Bundled in STM32CubeIDE          |
| Ninja    | Any     | Bundled in STM32CubeIDE          |
| Python 3 | 3.8+    | System                           |

The CMake post-build step automatically runs `tools/append_crc32.py` to inject the CRC32 checksum and C3 revision into the output binary. Python must be on PATH or discoverable by CMake's `find_package(Python3)`.

---

### Windows

```powershell
.\do_build.ps1
```

This script configures CMake, builds with Ninja, and copies outputs to `artifacts/`. The `_wCRC.bin` in `artifacts/` is ready to flash.

The script uses the ARM GCC toolchain from `D:\tools\bin`. If your toolchain is elsewhere, update `$ARM_GCC` at the top of `do_build.ps1`.

---

### Linux / macOS

```bash
./build.sh
```

Or manually:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Output is in `build/`. The `_wCRC.bin` is generated automatically by the post-build step.

---

### Manual CMake (any platform)

```bash
# Configure (once)
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=arm-none-eabi-gcc \
  -DCMAKE_CXX_COMPILER=arm-none-eabi-g++

# Build
cmake --build build

# Output
ls build/M1_T-1000_v*.bin        # bare binary
ls build/M1_T-1000_v*_wCRC.bin   # CRC-injected, ready to flash
```

---

### Build Output

| File                              | Description                      |
| --------------------------------- | -------------------------------- |
| `build/M1_T-1000_vX.X.X.elf`      | Debug ELF with symbols           |
| `build/M1_T-1000_vX.X.X.bin`      | Raw binary                       |
| `build/M1_T-1000_vX.X.X_wCRC.bin` | CRC-injected binary — flash this |
| `build/M1_T-1000_vX.X.X.hex`      | Intel HEX format                 |
| `build/M1_T-1000_vX.X.X.list`     | Disassembly listing              |

---

## SD Card Setup

Most M1PPER features require a FAT32-formatted microSD card. SDHC cards up to 32 GB work reliably. SDXC cards (>32 GB) default to exFAT and must be reformatted — the M1 will not mount them otherwise.

**Format commands:**

```bash
# Windows (built-in, works up to 32 GB)
# Right-click the drive in Explorer > Format > FAT32

# Linux
mkfs.fat -F 32 /dev/sdX
```

M1PPER creates all necessary directories (`BadUSB/`, `NFC/`, `SubGHz/`, etc.) on first use. No manual setup required beyond formatting. Full directory tree and file format specs: [SD Card Layout](sd-card.md).

---

## Updating the ESP32 Coprocessor

The ESP32-C6 runs a custom SPI AT firmware. The M1 can update it from an SD card file.

1. Place `factory_ESP32C6-SPI.bin` and `factory_ESP32C6-SPI.md5` in the root of the SD card
2. Go to System > ESP32 Update
3. The M1 flashes the ESP32 via its UART ROM bootloader

The MD5 file must be exactly 32 bytes of uppercase hex with no trailing newline. The M1's MD5 verifier uses `mh_hexify()` which produces uppercase.

---

## Versioning

Three version numbers coexist in M1PPER, each tracking something different:

| Version          | Example            | What it tracks                                                    |
| ---------------- | ------------------ | ----------------------------------------------------------------- |
| Monstatek base   | `v0.8.0.0`         | Upstream Monstatek firmware compatibility. Fixed — do not change. |
| C3 revision      | `-C3.6`            | M1PPER community fork revision. Displayed after the base version. |
| Artifact version | `M1_T-1000_v1.0.0` | Repository release tag. Used in the binary filename.              |

The on-device display shows `v0.8.0.0-C3.6`. The binary you flash is named `M1_T-1000_v1.0.0_wCRC.bin`. These numbers are independent — a new artifact release does not imply a new C3 revision and vice versa.
