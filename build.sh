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

kernel_devel_cache_complete() {
    local base_dir=$1
    local package=$2
    local target
    local version
    local manifest="${base_dir}/.kernel_devel_pkg_configs"

    [ -f "$base_dir/.kernel_devel_pkg_hash" ] || return 1
    if [ ! -f "$manifest" ]; then
        tar -tzf "$package" | sed -n 's#^\./\([^/]*\)/\.config$#\1#p' > "$manifest"
    fi

    for version in $VERSIONS; do
        for target in $TARGETS; do
            if grep -Fxq "${target}.${version}" "$manifest"; then
                [ -f "$base_dir/${target}.${version}/.config" ] || return 1
            fi
        done
    done

    return 0
}

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

        if [ "$PKG_HASH" = "$OLD_HASH" ] && kernel_devel_cache_complete cache/kernel-devel-extract "$PKG"; then
            echo "Using cached kernel-devel-extract (hash unchanged)"
        else
            echo "Extracting kernel-devel package (hash changed or no cache)"
            rm -rf cache/kernel-devel-extract/*
            rm -f cache/kernel-devel-extract/.kernel_devel_pkg_configs
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
    if [[ "$KERNEL_DEVEL_PATH" = /* ]]; then
        KERNEL_DEVEL_MOUNT_DIR="$KERNEL_DEVEL_PATH"
    else
        KERNEL_DEVEL_MOUNT_DIR="$(pwd)/$KERNEL_DEVEL_PATH"
    fi
fi

# Set build output directory in cache & initialize subfolders
BUILD_OUTPUT_DIR="$(pwd)/cache/build"
mkdir -p "$BUILD_OUTPUT_DIR/kernels"
mkdir -p "$BUILD_OUTPUT_DIR/logs"

# Normally dockerd shares this script's mount namespace, so a bind-mount source
# path means the same thing to the daemon as to us. Under a shared per-node
# daemon (e.g. rehosting CI's shared-docker runners) it does NOT: the daemon
# can't see this runner's per-pod workspace under /home/runner/_work, so
# "-v $PWD:/app" would mount an empty dir and the build would fail with
# "/app/_in_container_build.sh: No such file". The runner exports
# PENGUIN_HOST_MOUNT_FROM / PENGUIN_HOST_MOUNT_TO (the same mechanism penguin's
# wrapper uses) giving the daemon-visible location of that workspace.
#
# rewrite_mount() rewrites a bind source ONLY when BOTH env vars are set and the
# path is under _FROM. When they're unset — every local build and every
# GitHub-hosted runner — it returns the path unchanged, so behaviour is
# identical to before. All three mounts here (kernel-devel extract, $PWD, and
# the build output) live under this workspace, so all three are rewritten; an
# absolute --kernel-devel-path outside _FROM is left as-is.
rewrite_mount() {
    local path="$1"
    if [[ -n "$PENGUIN_HOST_MOUNT_FROM" && -n "$PENGUIN_HOST_MOUNT_TO" \
          && "$path" == "$PENGUIN_HOST_MOUNT_FROM"* ]]; then
        printf '%s' "${PENGUIN_HOST_MOUNT_TO}${path#"$PENGUIN_HOST_MOUNT_FROM"}"
    else
        printf '%s' "$path"
    fi
}

KERNEL_DEVEL_MOUNT_SRC="$(rewrite_mount "$KERNEL_DEVEL_MOUNT_DIR")"
APP_MOUNT_SRC="$(rewrite_mount "$PWD")"
BUILD_OUTPUT_MOUNT_SRC="$(rewrite_mount "$BUILD_OUTPUT_DIR")"

# Run the container with proper environment variables and mounts
docker run ${INTERACTIVE} --rm \
    -e RELEASE="${RELEASE}" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$KERNEL_DEVEL_MOUNT_SRC":/kernel-devel:ro \
    -v "$APP_MOUNT_SRC":/app \
    -v "$BUILD_OUTPUT_MOUNT_SRC":/output \
    $DOCKER_IMAGE \
    bash -c "/app/_in_container_build.sh \"${TARGETS}\" \"${VERSIONS}\" /kernel-devel /app/src /output"
