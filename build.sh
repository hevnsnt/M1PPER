#!/bin/sh
set -e

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

prepend_path_dir() {
    if [ -n "$1" ] && [ -d "$1" ]; then
        PATH="$1:$PATH"
    fi
}

compiler_has_standard_headers() {
    compiler="$1"
    tmp_c="$(mktemp /tmp/m1-build-check-XXXXXX.c)"
    tmp_out="$(mktemp /tmp/m1-build-check-XXXXXX.out)"
    cat >"$tmp_c" <<'EOF'
#include <stdint.h>
#include <string.h>
#include <math.h>
int main(void) { return 0; }
EOF

    if "$compiler" -E "$tmp_c" >"$tmp_out" 2>/dev/null; then
        rm -f "$tmp_c" "$tmp_out"
        return 0
    fi

    rm -f "$tmp_c" "$tmp_out"
    return 1
}

print_dir_if_exists() {
    if [ -n "$1" ] && [ -d "$1" ]; then
        printf '%s\n' "$1"
    fi
}

find_executable_in_dir() {
    tool_dir="$1"
    tool_name="$2"

    if [ -x "$tool_dir/$tool_name" ]; then
        printf '%s\n' "$tool_dir/$tool_name"
        return 0
    fi

    if [ -x "$tool_dir/$tool_name.exe" ]; then
        printf '%s\n' "$tool_dir/$tool_name.exe"
        return 0
    fi

    return 1
}

list_arm_toolchain_dirs() {
    print_dir_if_exists "${ARM_GCC_BIN:-}"
    print_dir_if_exists "${ARM_GCC_BIN:-}/bin"

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.*.macosaarch64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.*.macosx.cocoa.x86_64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    print_dir_if_exists "/c/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.win32_1.0.100.202602081740/tools/bin"
    print_dir_if_exists "C:/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.14.3.rel1.win32_1.0.100.202602081740/tools/bin"

    print_dir_if_exists "$HOME/.ufbt/toolchain/current/bin"
    print_dir_if_exists "$HOME/.ufbt/toolchain/arm64-darwin/bin"

    if command_exists arm-none-eabi-gcc; then
        dirname "$(command -v arm-none-eabi-gcc)"
    fi
}

resolve_arm_toolchain_dir() {
    for tool_dir in $(list_arm_toolchain_dirs); do
        compiler_path="$(find_executable_in_dir "$tool_dir" arm-none-eabi-gcc || true)"
        if [ -z "$compiler_path" ]; then
            continue
        fi

        if compiler_has_standard_headers "$compiler_path"; then
            printf '%s\n' "$tool_dir"
            return 0
        fi
    done

    return 1
}

list_cmake_dirs() {
    print_dir_if_exists "${CMAKE_BIN:-}"

    if command_exists cmake; then
        dirname "$(command -v cmake)"
    fi

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.cmake.*.macosaarch64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.cmake.*.macosx.cocoa.x86_64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    print_dir_if_exists "/c/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.cmake.win32_1.1.100.202601091506/tools/bin"
    print_dir_if_exists "C:/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.cmake.win32_1.1.100.202601091506/tools/bin"
}

list_ninja_dirs() {
    print_dir_if_exists "${NINJA_BIN:-}"

    if command_exists ninja; then
        dirname "$(command -v ninja)"
    fi

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.ninja.*.macosaarch64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    for dir in /Applications/STM32CubeIDE.app/Contents/Eclipse/plugins/com.st.stm32cube.ide.mcu.externaltools.ninja.*.macosx.cocoa.x86_64_*/tools/bin; do
        print_dir_if_exists "$dir"
    done

    print_dir_if_exists "/c/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.ninja.win32_1.1.100.202601091506/tools/bin"
    print_dir_if_exists "C:/ST/STM32CubeIDE_2.1.0/STM32CubeIDE/plugins/com.st.stm32cube.ide.mcu.externaltools.ninja.win32_1.1.100.202601091506/tools/bin"
}

resolve_tool_path() {
    tool_name="$1"
    for tool_dir in $2; do
        tool_path="$(find_executable_in_dir "$tool_dir" "$tool_name" || true)"
        if [ -n "$tool_path" ]; then
            printf '%s\n' "$tool_path"
            return 0
        fi
    done
    return 1
}

detect_cpu_count() {
    if command_exists nproc; then
        nproc
    elif command_exists getconf; then
        getconf _NPROCESSORS_ONLN
    elif command_exists sysctl; then
        sysctl -n hw.logicalcpu
    else
        echo 4
    fi
}

TOOLCHAIN_DIR="$(resolve_arm_toolchain_dir || true)"
if [ -n "$TOOLCHAIN_DIR" ]; then
    prepend_path_dir "$TOOLCHAIN_DIR"
    export PATH
fi

CMAKE_CMD="$(resolve_tool_path cmake "$(list_cmake_dirs)" || true)"
NINJA_CMD="$(resolve_tool_path ninja "$(list_ninja_dirs)" || true)"

if [ -z "$CMAKE_CMD" ]; then
    echo "Error: cmake was not found in PATH."
    exit 1
fi

if [ -z "$NINJA_CMD" ]; then
    echo "Error: ninja was not found in PATH."
    exit 1
fi

if [ -z "$TOOLCHAIN_DIR" ]; then
    echo "Error: arm-none-eabi-gcc was not found."
    echo "Install a complete ARM GCC toolchain, or set ARM_GCC_BIN to the directory containing arm-none-eabi-gcc."
    echo "If Homebrew's arm-none-eabi-gcc is installed without newlib/sysroot, this script will skip it."
    exit 1
fi

CMAKE_COMPILER_ARGS=""
if [ -n "$TOOLCHAIN_DIR" ]; then
    C_COMPILER="$TOOLCHAIN_DIR/arm-none-eabi-gcc"
    CXX_COMPILER="$TOOLCHAIN_DIR/arm-none-eabi-g++"
    if [ -x "$C_COMPILER" ] && [ -x "$CXX_COMPILER" ]; then
        CMAKE_COMPILER_ARGS="-DCMAKE_C_COMPILER=$C_COMPILER -DCMAKE_CXX_COMPILER=$CXX_COMPILER"
    fi
fi

echo "Using CMake: $CMAKE_CMD"
echo "Using Ninja: $NINJA_CMD"
echo "Using ARM GCC: $TOOLCHAIN_DIR/arm-none-eabi-gcc"

echo "Updating submodules..."
git submodule update --init --recursive

BUILD_DIR="build"
OUTPUT_DIR="artifacts"
mkdir -p $BUILD_DIR $OUTPUT_DIR
CPU_COUNT=$(detect_cpu_count)

if [ -f "$BUILD_DIR/CMakeCache.txt" ] && [ -n "$TOOLCHAIN_DIR" ]; then
    if ! grep -q "$TOOLCHAIN_DIR/arm-none-eabi-gcc" "$BUILD_DIR/CMakeCache.txt"; then
        echo "Toolchain changed; clearing stale CMake cache..."
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
    fi
fi

echo "Configuring CMake..."
"$CMAKE_CMD" -G Ninja -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_MAKE_PROGRAM="$NINJA_CMD" \
    $CMAKE_COMPILER_ARGS

echo "Compiling..."
"$CMAKE_CMD" --build "$BUILD_DIR" --parallel "$CPU_COUNT"

BUILD_ELF_FILE=$(ls -t "$BUILD_DIR"/*.elf 2>/dev/null | head -1)
if [ -z "$BUILD_ELF_FILE" ]; then
    echo "Error: No ELF file found in $BUILD_DIR"
    exit 1
fi

BUILD_BASENAME=$(basename "$BUILD_ELF_FILE" .elf)

echo "Collecting artifacts to ./$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.bin "$OUTPUT_DIR"/*.elf "$OUTPUT_DIR"/*.hex "$OUTPUT_DIR"/*.list 2>/dev/null || true
cp "$BUILD_ELF_FILE" "$OUTPUT_DIR/"
[ -f "$BUILD_DIR/$BUILD_BASENAME.bin" ] && cp "$BUILD_DIR/$BUILD_BASENAME.bin" "$OUTPUT_DIR/"
[ -f "$BUILD_DIR/$BUILD_BASENAME.hex" ] && cp "$BUILD_DIR/$BUILD_BASENAME.hex" "$OUTPUT_DIR/"
[ -f "$BUILD_DIR/$BUILD_BASENAME.list" ] && cp "$BUILD_DIR/$BUILD_BASENAME.list" "$OUTPUT_DIR/"
[ -f "$BUILD_DIR/${BUILD_BASENAME}_wCRC.bin" ] && cp "$BUILD_DIR/${BUILD_BASENAME}_wCRC.bin" "$OUTPUT_DIR/"

ELF_FILE="$OUTPUT_DIR/$BUILD_BASENAME.elf"

if [ ! -f "$ELF_FILE" ]; then
    echo "Error: No ELF file found in $OUTPUT_DIR"
    exit 1
fi

ARCH=$(arm-none-eabi-objdump -f "$ELF_FILE" 2>/dev/null | grep "architecture" | head -1)
if echo "$ARCH" | grep -q "armv8-m\|armv7-m"; then
    ELF_NAME=$(basename "$ELF_FILE")
    echo "Build verification: Valid ARM firmware ($ELF_NAME)"
    arm-none-eabi-size "$ELF_FILE"
else
    echo "Error: Unexpected architecture in ELF"
    exit 1
fi

echo "Success! Firmware is in $(pwd)/$OUTPUT_DIR"
