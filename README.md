# IGLOO Linux Kernel Module

The IGLOO module is a Linux kernel driver designed to provide hypervisor interactions and support for specific embedded environments. It includes features such as `hyperfs`, `portal`, hypercalls (`ehypercall`), network devices (`igloonet`), and various system call/ioctl hooks.

## Prerequisites

Building the IGLOO module relies on Docker for a consistent cross-compilation environment and extracting required kernel development packages.

- **Docker:** Ensure you have Docker installed and running.
- **Docker Image:** By default, the build script uses the `rehosting/embedded-toolchains:latest` image.
- **Kernel Devel:** You need the `kernel-devel` archives. The script looks for an archive at `local_packages/kernel-devel-all.tar.gz` by default. Alternatively, you can specify an extracted path using the `--kernel-devel-path` option.

## How to Build

A build script (`build.sh`) is provided to automate compiling the module for various kernel versions and target architectures. It uses a Docker container to invoke the cross-compilers.

### Usage

```bash
./build.sh [OPTIONS]
```

#### Options:

- `--versions VERSIONS`
  Space-separated list of kernel versions to build for. (Default: `"4.10 6.13"`)
- `--targets TARGETS`
  Space-separated list of target architectures. (Default: `"armel arm64 mipseb mipsel mips64eb mips64el powerpc powerpcle powerpc64 powerpc64le loongarch64 riscv64 x86_64"`)
- `--linux-builder LINUX_BUILDER_PATH`
  Path to the `linux_builder` directory. Kernel source and build artifacts are derived from this path. (Default: `/home/user/linux_builder`)
- `--kernel-devel-path KERNEL_DEVEL_PATH`
  Path to an extracted `kernel-devel` directory for the target/version. If omitted, the script extracts from `local_packages/kernel-devel-all.tar.gz`.
- `--image IMAGE`
  Specify the Docker image to use for building. (Default: `rehosting/embedded-toolchains:latest`)
- `--release`
  Enable release mode: strips built modules after compilation to reduce binary size.

### Examples

Build for default targets and versions:
```bash
./build.sh
```

Build for specific versions and architectures:
```bash
./build.sh --versions "4.10 6.7" --targets "armel mipseb mipsel mips64eb"
```

Build using a custom kernel-devel path:
```bash
./build.sh --versions 4.10 --kernel-devel-path /tmp/kernel-devel-x86_64-6.13
```

Build with release mode (stripped modules):
```bash
./build.sh --release
```

## Build Artifacts

Upon a successful build, the modules (`igloo.ko.<target>`) and optionally their symbols (generated via `dwarf2json`) are compiled and then archived into:

```
igloo_driver.tar.gz
```

This archive will be created in your current working directory and contains the built modules organized by kernel version.
