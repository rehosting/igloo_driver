#!/bin/bash

set -eu

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

# Build the local Docker image if not present
DOCKER_IMAGE=igloo_driver_builder
docker build -t $DOCKER_IMAGE .

for VERSION in $VERSIONS; do
    for TARGET in $TARGETS; do
        echo "Building modules for kernel version ${VERSION}, target ${TARGET}..."

        # Determine kernel-devel path
        KERNEL_DEVEL_DIR="$KERNEL_DEVEL_PATH"
        if [ -z "$KERNEL_DEVEL_DIR" ]; then
            PKG=local_packages/kernel-devel-all.tar.gz
            if [ -f "$PKG" ]; then
                echo "Extracting kernel-devel-${TARGET}.${VERSION}.tar.gz from $PKG..."
                mkdir -p cache/kernel-devel-extract
                tar -xzf "$PKG" -C cache/kernel-devel-extract "kernel-devel-${TARGET}.${VERSION}.tar.gz"
                tar -xzf cache/kernel-devel-extract/kernel-devel-${TARGET}.${VERSION}.tar.gz -C cache/kernel-devel-extract/kernel-devel-${TARGET}.${VERSION}
                KERNEL_DEVEL_DIR="$(pwd)/cache/kernel-devel-extract/kernel-devel-${TARGET}.${VERSION}"
            else
                echo "Error: --kernel-devel-path not provided and $PKG not found."
                exit 1
            fi
        fi

        echo "Using kernel-devel directory: $KERNEL_DEVEL_DIR"

        # Run the container with proper environment variables and mounts
        docker run ${INTERACTIVE} --rm \
            -v $KERNEL_DEVEL_DIR:/kernel-devel:ro \
            -v $PWD:/app \
            $DOCKER_IMAGE \
            bash -c "/app/_in_container_build.sh \"${TARGET}\" \"${VERSION}\" /kernel-devel /app"

        echo "Completed module build for kernel version ${VERSION}, target ${TARGET}"
    done
done

echo "All builds completed successfully"
