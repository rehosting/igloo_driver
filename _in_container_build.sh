#!/bin/bash

set -eu

# Input parameters
TARGETS="$1"         # Target architectures
VERSION="$2"       # Kernel version
BUILD_DIR="/tmp/build/${VERSION}"  # Directory for build artifacts (e.g., cache/ from linux_builder)
KERNEL_DIR="/kernel/${VERSION}"  # Directory containing the kernel source code:
MODULE_DIR="/app/src"  # Directory containing the module source code
OUTPUT_BASE="${5:-/output}"  # Output directory for built modules and symbols

# Function to get cross-compiler prefix
get_cc() {
    local arch=$1
    local abi=""

    # Clear CFLAGS and KCFLAGS if they are set
    unset CFLAGS
    unset KCFLAGS

    if [[ $arch == *"arm64"* ]]; then
        abi=""
        arch="aarch64"
    elif [[ $arch == *"arm"* ]]; then
        abi="eabi"
        if [[ $arch == *"eb"* ]]; then
            export CFLAGS="-mbig-endian"
            export KCFLAGS="-mbig-endian"
        fi
        arch="arm"
    fi

    if [[ $arch == *"loongarch"* ]]; then
        echo "/opt/cross/loongarch64-linux-gcc-cross/bin/loongarch64-unknown-linux-gnu-"
    elif [[ $arch == *"powerpc"* ]]; then
        echo "/opt/cross/powerpc64-linux-musl-cross/bin/powerpc64-linux-musl-"
    elif [[ $arch == "riscv64" ]]; then
        # riscv64 linux-musl seems to run out of memory on linking so we switched
        # to the glibc version
        echo "/usr/bin/riscv64-linux-gnu-"
    else
        echo "/opt/cross/${arch}-linux-musl${abi}/bin/${arch}-linux-musl${abi}-"
    fi
}

for TARGET in $TARGETS; do
    # Set short_arch based on TARGET
    short_arch=$(echo $TARGET | sed -E 's/(.*)(e[lb]|eb64)$/\1/')
    if [ "$short_arch" == "mips64" ]; then
        short_arch="mips"
    elif [ "$short_arch" == "loongarch64" ]; then
        short_arch="loongarch"
    elif [[ "$short_arch" == "powerpc64" || "$short_arch" == "powerpc64le" || "$short_arch" == "powerpcle" ]]; then
        short_arch="powerpc"
    elif [ "$short_arch" == "riscv64" ]; then
        short_arch="riscv"
    elif [ "$short_arch" == "riscv32" ]; then
        short_arch="riscv"
    fi

    TARGET_BUILD_DIR="${BUILD_DIR}/${TARGET}"

    # If you have a .config but missing other artifacts
    if [ ! -f "${TARGET_BUILD_DIR}/.config" ]; then
        echo "Kernel config not found at ${BUILD_DIR}/.config! Please ensure the kernel source and config are available."
        exit 1
    fi

    if [ ! -d "${TARGET_BUILD_DIR}/include/generated" ]; then
        echo "include/generated directory not found in ${TARGET_BUILD_DIR}!"
        echo "Found kernel config but missing generated headers."
        exit 1
    fi

    if [ ! -f "${TARGET_BUILD_DIR}/Module.symvers" ]; then
        echo "Module.symvers not found in ${TARGET_BUILD_DIR}!"
        exit 1
    fi

    echo "Building IGLOO module for $TARGET with kernel at ${KERNEL_DIR}"

    # Create output directory
    OUTPUT_DIR="${OUTPUT_BASE}/kernels/${VERSION}"
    mkdir -p "${OUTPUT_DIR}"

    # Clean and build the module
    make -C "${MODULE_DIR}" \
        KDIR="${KERNEL_DIR}" \
        ARCH="${short_arch}" \
        CROSS_COMPILE="$(get_cc $TARGET)" \
        all

    # Copy built module to output directory with new naming
    if [ -f "${MODULE_DIR}/igloo.ko" ]; then
        cp "${MODULE_DIR}/igloo.ko" "${OUTPUT_DIR}/igloo.ko.${TARGET}"
    fi
    
    # Clean and build the module
    make -C "${MODULE_DIR}" \
        KDIR="${KERNEL_DIR}" \
        ARCH="${short_arch}" \
        CROSS_COMPILE="$(get_cc $TARGET)" \
        clean

    # Generate symbols from the built kernel module using dwarf2json
    if [ -f "${OUTPUT_DIR}/igloo.ko.${TARGET}" ] && command -v dwarf2json >/dev/null 2>&1; then
        echo "Generating symbols with dwarf2json for $TARGET..."
        dwarf2json linux --elf "${OUTPUT_DIR}/igloo.ko.${TARGET}" | xz -c > "${OUTPUT_DIR}/igloo.ko.${TARGET}.json.xz"
    else
        echo "Warning: igloo.ko.${TARGET} or dwarf2json not found, skipping symbol generation for $TARGET."
    fi

    chmod -R o+rw "${OUTPUT_DIR}"
    echo "IGLOO module for $TARGET built successfully"
done
