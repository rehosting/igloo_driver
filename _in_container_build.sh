#!/bin/bash

set -eu

# Input parameters
TARGETS="$1"         # Target architectures
VERSION="$2"       # Kernel version
BUILD_DIR="/tmp/build/${VERSION}"  # Directory for build artifacts (e.g., cache/ from linux_builder)
KERNEL_DIR="/kernel/${VERSION}"  # Directory containing the kernel source code:
MODULE_DIR="/app"  # Directory containing the module source code

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
    echo "/opt/cross/${arch}-linux-musl${abi}/bin/${arch}-linux-musl${abi}-"
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

    if [ ! -d "${TARGET_BUILD_DIR}/include/generated" || ! -d "${TARGET_BUILD_DIR}/Module.symvers" ]; then
        echo "Found kernel config but missing build artifacts. Preparing build environment..."

        # Generate headers and scripts needed for module building
        make -C "${KERNEL_DIR}" O="${TARGET_BUILD_DIR}" ARCH="${short_arch}" CROSS_COMPILE="$(get_cc $TARGET)" modules_prepare scripts

        echo "Build environment prepared for module compilation"
    fi

    echo "Building IGLOO module for $TARGET with kernel at ${KERNEL_DIR}"

    # Create output directory
    OUTPUT_DIR="/tmp/build/${VERSION}/modules/${TARGET}"
    mkdir -p "${OUTPUT_DIR}"

    # Clean and build the module
    make -C "${MODULE_DIR}" \
        KDIR="${KERNEL_DIR}" \
        ARCH="${short_arch}" \
        CROSS_COMPILE="$(get_cc $TARGET)" \
        O=${TARGET_BUILD_DIR} \
        clean all

    chmod -R o+rw "${OUTPUT_DIR}"
    echo "IGLOO module for $TARGET built successfully"
done
