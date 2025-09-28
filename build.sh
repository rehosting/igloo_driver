#!/bin/bash

set -eu
set -x

help() {
    cat >&2 <<EOF
USAGE ./build.sh [--help] [--versions VERSIONS] [--targets TARGETS] [--linux-builder LINUX_BUILDER_PATH] [--kernel-devel-path KERNEL_DEVEL_PATH] [--image IMAGE] [--release]

    --versions VERSIONS
        Build modules for the specified kernel versions. By default, version 4.10 is used.
    --targets TARGETS
        Build modules only for the specified targets. By default, all targets are built.
    --linux-builder LINUX_BUILDER_PATH
        Path to linux_builder directory. Kernel source and build artifacts will be derived from this path.
        Default: /home/user/linux_builder
    --kernel-devel-path KERNEL_DEVEL_PATH
        Path to extracted kernel-devel directory for the target/version. If not provided, will look for local_packages/kernel-devel-all.tar.gz and extract as needed.
    --image IMAGE
        Specify the Docker image to use for building. Default: rehosting/embedded-toolchains:latest
    --release
        Enable release mode: strip modules after build to reduce size.

EXAMPLES
    ./build.sh --versions "4.10 6.7" --targets "armel mipseb mipsel mips64eb"
    ./build.sh --versions 4.10 --kernel-devel-path /tmp/kernel-devel-x86_64-6.13
    ./build.sh --targets armel
    ./build.sh --image myrepo/myimage:latest
    ./build.sh --release
EOF
}

# Default options
VERSIONS="4.10 6.13"
TARGETS="armel arm64 mipseb mipsel mips64eb mips64el powerpc powerpcle powerpc64 powerpc64le loongarch64 riscv64 x86_64"
INTERACTIVE=
LINUX_BUILDER_PATH="${HOME}/github/linux_builder"
KERNEL_DEVEL_PATH=""

DOCKER_IMAGE=rehosting/embedded-toolchains:latest
RELEASE=0

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)
            help
            exit
            ;;
        --versions)
            VERSIONS="$2"
            shift; shift;;
        --targets)
            TARGETS="$2"
            shift; shift;;
        --linux-builder)
            LINUX_BUILDER_PATH="$2"
            shift; shift;;
        --kernel-devel-path)
            KERNEL_DEVEL_PATH="$2"
            shift; shift;;
        --image)
            DOCKER_IMAGE="$2"
            shift; shift;;
        --interactive)
            INTERACTIVE="-it"
            shift;;
        --release)
            RELEASE=1
            shift;;
        *)
            help
            exit 1;;
    esac
done

echo "Building modules for kernel versions: ${VERSIONS}, targets: ${TARGETS}..."

# Extract kernel-devel package if not using custom path
if [ -z "$KERNEL_DEVEL_PATH" ]; then
    PKG=local_packages/kernel-devel-all.tar.gz
    if [ -f "$PKG" ]; then
        mkdir -p cache/kernel-devel-extract

        # Compute package hash and compare with cached hash to skip extraction if unchanged
        HASHFILE="cache/kernel-devel-extract/.kernel_devel_pkg_hash"
        PKG_HASH="$(md5sum "$PKG" | awk '{print $1}')"
        OLD_HASH=""
        if [ -f "$HASHFILE" ]; then
            OLD_HASH="$(cat "$HASHFILE")" || OLD_HASH=""
        fi

        if [ "$PKG_HASH" = "$OLD_HASH" ] && [ -n "$(ls -A cache/kernel-devel-extract 2>/dev/null)" ]; then
            echo "Using cached kernel-devel-extract (hash unchanged)"
        else
            echo "Extracting kernel-devel package (hash changed or no cache)"
            rm -rf cache/kernel-devel-extract/*
            pigz -dc "$PKG" | tar -xf - -C cache/kernel-devel-extract
            # Update hash atomically
            printf '%s' "$PKG_HASH" > "${HASHFILE}.tmp" && mv "${HASHFILE}.tmp" "$HASHFILE"
        fi

        KERNEL_DEVEL_MOUNT_DIR="$(pwd)/cache/kernel-devel-extract"
    else
        echo "Error: --kernel-devel-path not provided and $PKG not found."
        exit 1
    fi
else
    KERNEL_DEVEL_MOUNT_DIR="$KERNEL_DEVEL_PATH"
fi

# Set build output directory in cache
BUILD_OUTPUT_DIR="$(pwd)/cache/build"
mkdir -p "$BUILD_OUTPUT_DIR"

# Run the container with proper environment variables and mounts
docker run ${INTERACTIVE} --rm \
    -e RELEASE="${RELEASE}" \
    -v $KERNEL_DEVEL_MOUNT_DIR:/kernel-devel:ro \
    -v $PWD:/app \
    -v $BUILD_OUTPUT_DIR:/output \
    $DOCKER_IMAGE \
    bash -c "/app/_in_container_build.sh \"${TARGETS}\" \"${VERSIONS}\" /kernel-devel /app/src /output"
