#!/bin/bash

set -eu

# Input parameters
TARGETS="$1"         # Target architectures (space-separated)
VERSIONS="$2"        # Kernel versions (space-separated)
KERNEL_DEVEL_BASE="$3"  # Base directory containing extracted kernel-devel files
MODULE_DIR="$4"         # Directory containing the module source code
OUTPUT_BASE="$5"        # Output directory for built modules and symbols

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

for VERSION in $VERSIONS; do
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

    # Use extracted kernel-devel directory structure
    TARGET_BUILD_DIR="${KERNEL_DEVEL_BASE}/${TARGET}.${VERSION}"

    # Check for .config file in kernel-devel
    if [ ! -f "${TARGET_BUILD_DIR}/.config" ]; then
        echo "Kernel config not found at ${TARGET_BUILD_DIR}/.config! Please ensure the kernel source and config are available."
        if [ "$(echo $VERSIONS | wc -w)" -eq 1 ]; then
            echo "Since only one version is being built, exiting."
            exit 1
        fi
        echo "Assuming this is fine in multi-version builds, skipping."
        continue
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

    echo "Building IGLOO module for $TARGET with kernel at ${TARGET_BUILD_DIR}"
    
    
    # Debug: Check if crtsavres.o exists in the expected location
    if [[ "$TARGET" == powerpc* ]]; then
        echo "Debug: Checking for crtsavres.o in ${TARGET_BUILD_DIR}"
        ls -la "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" || echo "crtsavres.o not found!"
        echo "Debug: Current working directory structure:"
        pwd
        ls -la "${TARGET_BUILD_DIR}/arch/powerpc/lib/" | head -5
    fi

    # Create output directory
    OUTPUT_DIR="${OUTPUT_BASE}/kernels/${VERSION}"
    mkdir -p "${OUTPUT_DIR}"

    # Clean and build the module using the target build directory which has all artifacts
    # For PowerPC, create symlinks to make crtsavres.o available where the linker expects it
    if [[ "$TARGET" == powerpc* ]]; then
        # Create symlinks in multiple possible locations where the linker might look
        CROSS_COMPILER_PREFIX="$(get_cc $TARGET)"
        CROSS_COMPILER_DIR=$(dirname "${CROSS_COMPILER_PREFIX}gcc")
        CROSS_LIB_BASE="${CROSS_COMPILER_DIR}/../lib/gcc/powerpc64-linux-musl"
        
        echo "Debug: Looking for GCC lib directories in ${CROSS_LIB_BASE}"
        # Find all possible gcc lib directories and create symlinks
        find "${CROSS_LIB_BASE}" -type d 2>/dev/null | while read lib_dir; do
            if [ -d "$lib_dir" ]; then
                echo "Debug: Creating symlink in $lib_dir"
                mkdir -p "$lib_dir/arch/powerpc/lib" 2>/dev/null || true
                ln -sf "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" "$lib_dir/arch/powerpc/lib/crtsavres.o" 2>/dev/null || true
                # Also try creating it in the 32-bit subdirectory
                if [ -d "$lib_dir/32" ]; then
                    mkdir -p "$lib_dir/32/arch/powerpc/lib" 2>/dev/null || true
                    ln -sf "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" "$lib_dir/32/arch/powerpc/lib/crtsavres.o" 2>/dev/null || true
                fi
            fi
        done
        
        # Also try creating symlinks in common relative paths from the build directory
        mkdir -p "${MODULE_DIR}/arch/powerpc/lib" 2>/dev/null || true
        ln -sf "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" "${MODULE_DIR}/arch/powerpc/lib/crtsavres.o" 2>/dev/null || true
        
        # Create in current working directory as well
        mkdir -p "arch/powerpc/lib" 2>/dev/null || true  
        ln -sf "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" "arch/powerpc/lib/crtsavres.o" 2>/dev/null || true
        
        # Build with additional library search path
        make -C "${MODULE_DIR}" \
            KDIR="${TARGET_BUILD_DIR}" \
            ARCH="${short_arch}" \
            CROSS_COMPILE="$(get_cc $TARGET)" \
            EXTRA_LDFLAGS="-L${TARGET_BUILD_DIR}/arch/powerpc/lib" \
            all
    else
        make -C "${MODULE_DIR}" \
            KDIR="${TARGET_BUILD_DIR}" \
            ARCH="${short_arch}" \
            CROSS_COMPILE="$(get_cc $TARGET)" \
            all
    fi

    # Copy built module to output directory with new naming
    if [ -f "${MODULE_DIR}/igloo.ko" ]; then
        cp "${MODULE_DIR}/igloo.ko" "${OUTPUT_DIR}/igloo.ko.${TARGET}"
    fi
    
    # Clean the module
    make -C "${MODULE_DIR}" \
        KDIR="${TARGET_BUILD_DIR}" \
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
done

# End of build loop
echo "Completed module build for all versions and targets"
echo "All builds completed successfully."

# Create the archive in the output directory
echo "Creating igloo_driver.tar.gz archive in output directory..."
tar --use-compress-program=pigz -cf "/app/igloo_driver.tar.gz" -C "${OUTPUT_BASE}" kernels
echo "Archive created at /app/igloo_driver.tar.gz"
