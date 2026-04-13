.PHONY: all setup build clean check_env

all: check_env build

# Check if the build dependencies are available.
check_env:
	@if ! command -v cmake >/dev/null 2>&1; then \
		echo "Error: Missing dependency (cmake)."; \
		exit 1; \
	fi
	@if ! command -v ninja >/dev/null 2>&1; then \
		echo "Error: Missing dependency (ninja)."; \
		exit 1; \
	fi
	@if ! command -v arm-none-eabi-gcc >/dev/null 2>&1 && [ -z "$$ARM_GCC_BIN" ]; then \
		echo "Error: Missing ARM GCC toolchain (arm-none-eabi-gcc)."; \
		echo "Add it to PATH or set ARM_GCC_BIN=/path/to/toolchain/bin."; \
		exit 1; \
	fi
	@if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then \
		echo "Error: Missing Python interpreter (python3 or python)."; \
		echo "Run 'make setup' first to install dependencies."; \
		exit 1; \
	fi
	@if command -v arm-none-eabi-gcc >/dev/null 2>&1; then \
		tmp_c=$$(mktemp /tmp/m1-check-XXXXXX.c); \
		printf '%s\n' '#include <stdint.h>' '#include <string.h>' '#include <math.h>' > "$$tmp_c"; \
		if ! arm-none-eabi-gcc -E "$$tmp_c" >/dev/null 2>&1; then \
			echo "Error: arm-none-eabi-gcc is present but missing standard C headers."; \
			echo "Install a complete Arm GNU toolchain/newlib, or point ARM_GCC_BIN at one."; \
			rm -f "$$tmp_c"; \
			exit 1; \
		fi; \
		rm -f "$$tmp_c"; \
	fi

# Distro-specific setup
setup:
	@if [ -f /etc/arch-release ]; then \
		./setup_arch.sh; \
	else \
		echo "Manual setup required: Ensure cmake, ninja, Python, and arm-none-eabi-gcc are installed."; \
	fi

build:
	./build.sh

clean:
	rm -rf build artifacts
