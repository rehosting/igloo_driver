#!/bin/bash
set -eu

# Input parameters
TARGETS="$1"         # Target architectures (space-separated)
VERSIONS="$2"        # Kernel versions (space-separated)
KERNEL_DEVEL_BASE="$3"  # Base directory containing extracted kernel-devel files
MODULE_DIR="$4"         # Directory containing the module source code
OUTPUT_BASE="$5"        # Output directory for built modules and symbols

# Calculate optimal thread distribution to avoid OOM killer
TOTAL_CORES=$(nproc 2>/dev/null || echo 4)
MAX_PARALLEL_BUILDS=4
if [ "$TOTAL_CORES" -lt 4 ]; then MAX_PARALLEL_BUILDS=$TOTAL_CORES; fi
export CORES_PER_BUILD=$(( TOTAL_CORES / MAX_PARALLEL_BUILDS ))
if [ "$CORES_PER_BUILD" -lt 1 ]; then export CORES_PER_BUILD=1; fi

export RELEASE="${RELEASE:-0}"

mkdir -p "${OUTPUT_BASE}/workspaces/scripts"
cp -a -u /app/scripts/. "${OUTPUT_BASE}/workspaces/scripts/"

get_cc() {
    local arch=$1
    local version=$2
    local abi=""

    # Clear CFLAGS and KCFLAGS if they are set
    unset CFLAGS
    unset KCFLAGS

    if [[ $arch == *"arm64"* ]]; then
        abi="";
        arch="aarch64"
    elif [[ $arch == *"arm"* ]]; then
        abi="eabi"
        if [[ $arch == *"eb"* ]]; then
            export CFLAGS="-mbig-endian"; 
            export KCFLAGS="-mbig-endian"
        fi
        arch="arm"
    fi

    if [[ $arch == *"loongarch"* ]]; then
        echo "/opt/cross/loongarch64-linux-gcc-cross/bin/loongarch64-unknown-linux-gnu-"
    elif [[ $arch == *"powerpc"* ]] && [ "$version" = "4.10" ]; then
        echo "powerpc64-linux-gnu-"
    elif [[ $arch == *"powerpc"* ]] && [ "$version" != "4.10" ]; then
        echo "/opt/cross/powerpc64-linux-musl-cross/bin/powerpc64-linux-musl-"
    elif [ "$arch" = "x86_64" ] && [ "$version" = "4.10" ]; then
        echo "/opt/cross/x86_64-legacy/bin/x86_64-linux-musl-"
    elif [[ $arch == "riscv64" ]]; then
        # riscv64 linux-musl seems to run out of memory on linking so we switched
        # to the glibc version
        echo "/usr/bin/riscv64-linux-gnu-"
    else
        echo "/opt/cross/${arch}-linux-musl${abi}/bin/${arch}-linux-musl${abi}-"
    fi
}
export -f get_cc

build_module() {
    local TARGET=$1
    local VERSION=$2
    local KERNEL_DEVEL_BASE=$3
    local MODULE_DIR=$4
    local OUTPUT_BASE=$5

    local short_arch=$(echo $TARGET | sed -E 's/(.*)(e[lb]|eb64)$/\1/')
    if [[ "$short_arch" == "mips64" ]]; then short_arch="mips"; fi
    if [[ "$short_arch" == "loongarch64" ]]; then short_arch="loongarch"; fi
    if [[ "$short_arch" == "powerpc64" || "$short_arch" == "powerpc64le" || "$short_arch" == "powerpcle" ]]; then short_arch="powerpc"; fi
    if [[ "$short_arch" == "riscv64" || "$short_arch" == "riscv32" ]]; then short_arch="riscv"; fi

    local TARGET_BUILD_DIR="${KERNEL_DEVEL_BASE}/${TARGET}.${VERSION}"
    local LOG_FILE="${OUTPUT_BASE}/logs/build_${TARGET}_${VERSION}.log"
    local OUTPUT_DIR="${OUTPUT_BASE}/kernels/${VERSION}"
    local WORK_DIR="${OUTPUT_BASE}/workspaces/${TARGET}_${VERSION}"

    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${WORK_DIR}"

    # Delete stale artifacts so a previously cached successful build
    # doesn't falsely signal success if the current compilation fails.
    rm -f "${WORK_DIR}/igloo.ko" "${OUTPUT_DIR}/igloo.ko.${TARGET}"

    echo ">>> Starting build for $TARGET ($VERSION). Logging to logs/build_${TARGET}_${VERSION}.log"
    
    local STATUS=0

    # Wrap the build logic in a strict subshell.
    # If any command fails, 'set -e' safely halts the subshell, and STATUS catches the failure.
    (
        set -e 

        if [ ! -f "${TARGET_BUILD_DIR}/.config" ]; then
            echo "SKIPPED_NO_CONFIG"
            exit 0
        fi

        cp -a -u "${MODULE_DIR}/." "${WORK_DIR}/"

        local CROSS_COMPILER_PREFIX="$(get_cc $TARGET $VERSION)"
        local EXTRA_LDFLAGS=""
        local PPC_KCFLAGS=""

        if [[ "$TARGET" == powerpc* ]]; then
            mkdir -p "${WORK_DIR}/arch/powerpc/lib"
            ln -sf "${TARGET_BUILD_DIR}/arch/powerpc/lib/crtsavres.o" "${WORK_DIR}/arch/powerpc/lib/crtsavres.o"
            
            EXTRA_LDFLAGS="-L${TARGET_BUILD_DIR}/arch/powerpc/lib"
            if [[ "$VERSION" == 4.* ]] && [[ "$TARGET" == "powerpc64"* ]]; then
                PPC_KCFLAGS="-mabi=elfv1 -mcall-aixdesc"
            fi
        fi
        # Build with additional library search path
        make -j${CORES_PER_BUILD} -C "${WORK_DIR}" \
            KDIR="${TARGET_BUILD_DIR}" \
            ARCH="${short_arch}" \
            CROSS_COMPILE="${CROSS_COMPILER_PREFIX}" \
            EXTRA_LDFLAGS="${EXTRA_LDFLAGS}" \
            KCFLAGS="${PPC_KCFLAGS}" \
            all

        if [ ! -f "${WORK_DIR}/igloo.ko" ]; then
            echo "ERROR: igloo.ko not produced for ${TARGET}."
            exit 1
        fi

        cp "${WORK_DIR}/igloo.ko" "${OUTPUT_DIR}/igloo.ko.${TARGET}"

        if command -v dwarf2json >/dev/null 2>&1; then
            dwarf2json linux --elf "${OUTPUT_DIR}/igloo.ko.${TARGET}" | xz -c > "${OUTPUT_DIR}/igloo.ko.${TARGET}.json.xz"
        fi

        if [ "$RELEASE" = "1" ]; then
            local STRIP_BIN="${CROSS_COMPILER_PREFIX}strip"
            local OBJCOPY_BIN="${CROSS_COMPILER_PREFIX}objcopy"
            if command -v "${STRIP_BIN}" >/dev/null 2>&1; then
                "${STRIP_BIN}" --strip-unneeded "${OUTPUT_DIR}/igloo.ko.${TARGET}" || true
            elif command -v "${OBJCOPY_BIN}" >/dev/null 2>&1; then
                "${OBJCOPY_BIN}" --strip-debug "${OUTPUT_DIR}/igloo.ko.${TARGET}" || true
            elif command -v strip >/dev/null 2>&1; then
                strip --strip-unneeded "${OUTPUT_DIR}/igloo.ko.${TARGET}" || true
            fi
        fi

    ) > "$LOG_FILE" 2>&1 || STATUS=$?

    # Outside the subshell, interpret the result
    if [ $STATUS -ne 0 ]; then
        echo "--- FAILED: $TARGET $VERSION (See logs/build_${TARGET}_${VERSION}.log for details)"
    elif grep -q "SKIPPED_NO_CONFIG" "$LOG_FILE"; then
        echo "--- SKIPPED: $TARGET $VERSION (No kernel config)"
    else
        echo "+++ SUCCESS: $TARGET $VERSION"
    fi

    # Always return 0 to xargs. This ensures a failure in one worker doesn't kill the whole queue
    return 0
}
export -f build_module

echo "Parallelizing with $MAX_PARALLEL_BUILDS concurrent workers ($CORES_PER_BUILD CPU threads per worker)."

for VERSION in $VERSIONS; do
    for TARGET in $TARGETS; do
        echo "$TARGET $VERSION $KERNEL_DEVEL_BASE $MODULE_DIR $OUTPUT_BASE"
    done
done | xargs -n 5 -P "$MAX_PARALLEL_BUILDS" bash -c 'build_module "$@"' _

echo "Completed module builds for all targets."

echo "Creating igloo_driver.tar.gz archive in output directory..."
cd "${OUTPUT_BASE}"
tar --use-compress-program=pigz -cf "/app/igloo_driver.tar.gz" kernels
echo "Archive created at /app/igloo_driver.tar.gz"
