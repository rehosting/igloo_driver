# Building

igloo_driver is cross-compiled for ~13 architectures against multiple kernel
versions, so the build runs inside a Docker container that carries the
cross-compilation toolchains. The wrapper is [`build.sh`](https://github.com/rehosting/igloo_driver/blob/main/build.sh);
the work inside the container is done by `_in_container_build.sh`.

## Prerequisites

- **Docker**, installed and running.
- **A toolchain image** — by default `rehosting/embedded-toolchains:latest`,
  which carries the cross-compilers for every target.
- **Kernel headers** — an extracted `kernel-devel` tree per target/version.
  `build.sh` looks for `local_packages/kernel-devel-all.tar.gz` and extracts it,
  caching the result under `cache/`. These archives are produced by the kernel
  build ([`linux_builder`](https://github.com/rehosting/linux_builder)); its
  latest release publishes `kernel-devel-all.tar.gz`.

```bash
mkdir -p local_packages
curl -L -o local_packages/kernel-devel-all.tar.gz \
  https://github.com/rehosting/linux_builder/releases/latest/download/kernel-devel-all.tar.gz
```

## Quick start

Build every default target for the default kernel versions (`4.10 6.13`):

```bash
./build.sh
```

The result is a single archive in the current directory:

```
igloo_driver.tar.gz
```

containing the built modules (`igloo.ko.<target>`) organized by kernel version,
plus symbol information when available.

## Options

```
./build.sh [--help] [--versions VERSIONS] [--targets TARGETS]
           [--linux-builder PATH] [--kernel-devel-path PATH]
           [--image IMAGE] [--release]
```

| Option | Meaning |
|---|---|
| `--versions "V1 V2 …"` | Kernel versions to build for. Default: `"4.10 6.13"`. |
| `--targets "T1 T2 …"` | Target architectures. Default: all (see below). |
| `--kernel-devel-path PATH` | Use an already-extracted `kernel-devel` tree instead of extracting the archive. |
| `--linux-builder PATH` | Path to a `linux_builder` checkout (source of kernel artifacts). |
| `--image IMAGE` | Toolchain Docker image. Default: `rehosting/embedded-toolchains:latest`. |
| `--release` | Strip modules after build to reduce size. |
| `--interactive` | Run the build container with `-it` (for debugging). |

Default targets:

```
armel arm64 mipseb mipsel mips64eb mips64el
powerpc powerpcle powerpc64 powerpc64le
loongarch64 riscv64 x86_64
```

## Examples

```bash
# A couple of versions, a subset of architectures
./build.sh --versions "4.10 6.7" --targets "armel mipseb mipsel mips64eb"

# One version, using a pre-extracted kernel-devel tree
./build.sh --versions 4.10 --kernel-devel-path /tmp/kernel-devel-x86_64-6.13

# Stripped (release) modules
./build.sh --release
```

## How it works

`build.sh` prepares three bind mounts and invokes `_in_container_build.sh`
inside the toolchain image:

- `/kernel-devel` — the extracted kernel headers (read-only),
- `/app` — this repository (so the container sees `src/` and the build script),
- `/output` — the build output directory (`cache/build`).

The container compiles `src/` for each requested `target`/`version` pair and
assembles `igloo_driver.tar.gz`.

```{note}
`build.sh` transparently rewrites bind-mount source paths when the environment
variables `PENGUIN_HOST_MOUNT_FROM` / `PENGUIN_HOST_MOUNT_TO` are set — this is
only relevant when a shared per-node Docker daemon cannot see the caller's
workspace directly (the same mechanism Penguin's wrapper uses). For local
builds and standard CI runners these are unset and behavior is unchanged.
```

## Using the module with Penguin

The `igloo_driver.tar.gz` artifact is consumed by Penguin: drop it into
Penguin's `local_packages/` before a `./penguin --build` to test a local driver
build, or let Penguin download the pinned release. See Penguin's development
documentation for the local-package hand-off contract.

## Continuous integration

On pushes to `main` (and `dev_*` tags), CI builds all targets and publishes a
versioned GitHub release containing `igloo_driver.tar.gz`. Pull requests run the
same build as a check without releasing.
