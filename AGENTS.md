# AGENTS.md — Standing Instructions for AI Assistants

## Project: M1 T-1000 Firmware (M1-os)
## Owner: dagnazty

---

## ABSOLUTE RULES (NEVER VIOLATE)

### 1. NO Co-Author Attribution
- **NEVER** add `Co-Authored-By` lines to git commits
- **NEVER** add any AI attribution to commits, code comments, or files
- Commits must appear as if written solely by the repository owner
- This applies to ALL commits — initial, amend, fixup, squash, etc.

### 2. NO Unauthorized Remote Operations
- **NEVER** push to any remote repository without explicit permission
- **NEVER** create pull requests without explicit permission
- **NEVER** create issues, releases, or any public GitHub artifacts without explicit permission
- Default assumption: all work is LOCAL ONLY

### 3. NO Public Exposure
- **NEVER** make code, binaries, or documentation public without explicit permission
- **NEVER** fork, share, or distribute any project files without explicit permission
- Treat all project content as private/confidential by default

---

## Git Commit Rules

- Keep commit messages concise and descriptive
- No AI attribution of any kind in commit messages or trailers
- Stage specific files by name (avoid `git add -A` or `git add .`)
- Do not commit build artifacts, .bat/.ps1 helper scripts, or IDE workspace files unless asked

---

## Workflow Rules

- **Always build after code changes** — if you edit source code, you must build it yourself. Do not tell the user to build; just do it.
- **Build command**: `./build.sh` or `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build`
- On macOS, Homebrew tools need: `eval "$(/opt/homebrew/bin/brew shellenv)"` before building

---

## Hardware Notes

- **MCU**: STM32H573VIT (Cortex-M33, 250MHz, 2MB flash dual-bank, 640KB RAM)
- **WiFi**: ESP32-C6 coprocessor via SPI AT commands (NOT UART)
- **USB**: CDC + MSC composite — COM port drops during power cycle
- **Debugger**: ST-Link / J-Link available for flashing
- **Flash registers**: STM32H5 uses `FLASH->NSSR` (not `FLASH->SR`), BSY bit is `FLASH_SR_BSY`

---

## ESP32-C6 Coprocessor

### Communication
- M1 <-> ESP32-C6 uses **SPI** for AT commands (NOT UART)
- SPI Mode 1 (CPOL=0, CPHA=1) — hardcoded in `m1_esp32_hal.c:529`
- Firmware flashing uses UART (ROM bootloader), but runtime AT uses SPI
- Espressif's stock AT firmware downloads are UART-only — they will NOT work with M1

### ESP32 Firmware Requirements
- Must be built with `CONFIG_AT_BASE_ON_SPI=y` (NOT UART)
- Must use `CONFIG_SPI_MODE=1` (matches M1's STM32 SPI master)
- Module config: `ESP32C6-SPI` (NOT `ESP32C6-4MB` which is UART)

### ESP32 Firmware Flashing via M1
- M1's flasher requires both `.bin` and `.md5` files on SD card
- **MD5 file must be UPPERCASE hex, exactly 32 bytes, no newline** — M1 uses uppercase in `mh_hexify()`
- Factory image at offset 0x000000 (contains bootloader + partition table + app)

---

## Versioning Scheme

- **T-1000 version**: `T1000_VERSION_MAJOR/MINOR/PATCH` in `m1_t1000_version.h` — this is our version
- **Monstatek compatibility version**: `FW_VERSION_*` fields in `m1_fw_update_bl.h` track compatibility with Monstatek's base firmware (currently `0.8.0.0`). Do not change these unless syncing with upstream.
- **C3 revision**: `M1_C3_REVISION` in `m1_fw_update_bl.h` — legacy fork revision counter, still used in RPC protocol and dual boot display
- **CMake project name** in `CMakeLists.txt` must match the build output name

---

## Architecture Rules

- **S_M1_FW_CONFIG_t** struct is EXACTLY 20 bytes — NEVER modify it
- CRC extension data lives at fixed offsets AFTER the struct (offset 20+)
- All Flipper file parsers use stack allocation (no heap/malloc)
- FreeRTOS headers must be included before stream_buffer.h / queue.h
- Flipper parser API: functions are named `flipper_*_load()` / `flipper_*_save()`, return `bool`
- Menu layout is defined in `m1_main_menu.c`; menu engine lives in `m1_menu.c`
- Branding strings in `m1_branding.h`; version strings in `m1_t1000_version.h`

---

## Remote Configuration

- `origin` = dagnazty/M1-os (our repo)
- `upstream` = bedge117/M1 (reference upstream)
