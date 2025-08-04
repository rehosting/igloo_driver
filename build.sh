#!/bin/bash

set -eu
set -x

help() {
    cat >&2 <<EOF
USAGE ./build.sh [--help] [--versions VERSIONS] [--targets TARGETS] [--linux-builder LINUX_BUILDER_PATH] [--kernel-devel-path KERNEL_DEVEL_PATH]

    --versions VERSIONS
        Build modules for the specified kernel versions. By default, version 4.10 is used.
    --targets TARGETS
        Build modules only for the specified targets. By default, all targets are built.
    --linux-builder LINUX_BUILDER_PATH
        Path to linux_builder directory. Kernel source and build artifacts will be derived from this path.
        Default: /home/user/linux_builder
    --kernel-devel-path KERNEL_DEVEL_PATH
        Path to extracted kernel-devel directory for the target/version. If not provided, will look for local_packages/kernel-devel-all.tar.gz and extract as needed.

EXAMPLES
    ./build.sh --versions "4.10 6.7" --targets "armel mipseb mipsel mips64eb"
    ./build.sh --versions 4.10 --kernel-devel-path /tmp/kernel-devel-x86_64-6.13
    ./build.sh --targets armel
    ./build.sh
EOF
}

# Default options
VERSIONS="4.10"
TARGETS="armel arm64 mipseb mipsel mips64eb mips64el powerpc powerpcle powerpc64 powerpc64le loongarch64 riscv64 x86_64"
INTERACTIVE=
LINUX_BUILDER_PATH="${HOME}/github/linux_builder"
KERNEL_DEVEL_PATH=""

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
        --interactive)
            INTERACTIVE="-it"
            shift;;
        *)
            help
            exit 1;;
    esac
done

DOCKER_IMAGE=igloo_driver_builder

echo "Building modules for kernel versions: ${VERSIONS}, targets: ${TARGETS}..."

# Extract kernel-devel package if not using custom path
if [ -z "$KERNEL_DEVEL_PATH" ]; then
    PKG=local_packages/kernel-devel-all.tar.gz
    if [ -f "$PKG" ]; then
        mkdir -p cache/kernel-devel-extract
        pigz -dc "$PKG" | tar -xf - -C cache/kernel-devel-extract
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
    -v $KERNEL_DEVEL_MOUNT_DIR:/kernel-devel:ro \
    -v $PWD:/app \
    -v $BUILD_OUTPUT_DIR:/output \
    $DOCKER_IMAGE \
    bash -c "/app/_in_container_build.sh \"${TARGETS}\" \"${VERSIONS}\" /kernel-devel /app/src /output"

echo "Completed module build for all versions and targets"

echo "All builds completed successfully."
echo "Creating igloo_driver.tar.gz archive in current directory..."
tar --use-compress-program=pigz -cf igloo_driver.tar.gz -C cache/build kernels
echo "Archive created at $(pwd)/igloo_driver.tar.gz"
