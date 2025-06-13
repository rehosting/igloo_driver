#!/bin/bash

set -eu

help() {
    cat >&2 <<EOF
USAGE ./build.sh [--help] [--versions VERSIONS] [--targets TARGETS] [--linux-builder LINUX_BUILDER_PATH]

    --versions VERSIONS
        Build modules for the specified kernel versions. By default, version 4.10 is used.
    --targets TARGETS
        Build modules only for the specified targets. By default, all targets are built.
    --linux-builder LINUX_BUILDER_PATH
        Path to linux_builder directory. Kernel source and build artifacts will be derived from this path.
        Default: /home/user/linux_builder

EXAMPLES
    ./build.sh --versions "4.10 6.7" --targets "armel mipseb mipsel mips64eb"
    ./build.sh --versions 4.10 --linux-builder /path/to/linux_builder
    ./build.sh --targets armel
    ./build.sh
EOF
}

# Default options
VERSIONS="4.10"
TARGETS="armel arm64 mipseb mipsel mips64eb mips64el powerpc powerpcle powerpc64 powerpc64le loongarch64 riscv64 x86_64"
INTERACTIVE=
LINUX_BUILDER_PATH="${HOME}/github/linux_builder"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)
            help
            exit
            ;;
        --versions)
            VERSIONS="$2"
            shift # past flag
            shift # past value
            ;;
        --targets)
            TARGETS="$2"
            shift # past flag
            shift # past value
            ;;
        --linux-builder)
            LINUX_BUILDER_PATH="$2"
            shift # past flag
            shift # past value
            ;;
        --interactive)
            INTERACTIVE="-it"
            shift # past flag
            ;;
        *)
            help
            exit 1
            ;;
    esac
done

for VERSION in $VERSIONS; do
    echo "Building modules for kernel version ${VERSION}..."

    # Derive paths from linux_builder directory
    KERNEL_DIR=$(realpath "${LINUX_BUILDER_PATH}/linux")
    BUILD_DIR=$(realpath "${LINUX_BUILDER_PATH}/cache")

    echo "Using kernel directory: ${KERNEL_DIR}"
    echo "Using build directory: ${BUILD_DIR}"

    # Run the container with proper environment variables and mounts
    docker run ${INTERACTIVE} --rm \
        -v ${BUILD_DIR}:/tmp/build \
        -v ${KERNEL_DIR}:/kernel \
        -v $PWD:/app \
        pandare/kernel_builder \
        bash -c "/app/_in_container_build.sh \"${TARGETS}\" \"${VERSION}\""

    echo "Completed module build for kernel version ${VERSION}"
done

echo "All builds completed successfully"
