# igloo_driver

**igloo_driver** is the in-guest half of the [IGLOO / Penguin](https://github.com/rehosting/penguin)
firmware rehosting stack — a small, built-in Linux kernel module that turns an
emulated guest kernel into a **programmable kernel debugger**. From a host-side
PANDA / QEMU analysis plugin (Penguin) you can, at runtime:

- **Read and write** kernel and user memory (bytes, strings, pointer arrays,
  whole process address spaces);
- **Introspect the OS** — walk processes and read their maps, `argv`, `environ`,
  open FDs, registers, and executable paths;
- **Install hooks** — kprobes, uprobes, syscall entry/return hooks, and signal
  delivery hooks, each reported back to the host (and optionally able to skip a
  syscall or drop a signal);
- **Call kernel functions** via an FFI, resolve symbols with `kallsyms`, and
  generate trampolines;
- **Synthesize pseudo-files and devices** — `/proc`, `/sys`, `/dev`, `sysctl`,
  anonymous inodes, sockets, and MTD flash — backed by host-side models.

All of this rides on a single cooperative shared-memory protocol, **Portal**,
carried over a tiny per-architecture **hypercall** ABI (~50 operations in all).
The module has no configuration of its own; it is orchestrated entirely from the
host by Penguin.

> **Guest side vs. host side.** igloo_driver runs *inside the guest*. The Python
> API that drives it (`plugins.portal.read_str(...)`, kprobe/uprobe
> registration, pseudo-file models) lives in Penguin. If you want the host API,
> see Penguin's [Portal](https://github.com/rehosting/penguin/blob/main/docs/portal.md),
> [kprobes](https://github.com/rehosting/penguin/blob/main/docs/kprobes.md), and
> [uprobes](https://github.com/rehosting/penguin/blob/main/docs/uprobes.md) docs.

## Documentation

Full documentation — architecture, the Portal operation catalog, the hypercall
ABI, hooks, hyperfs, pseudo-file synthesis, and an auto-extracted C API
reference — is published to **GitHub Pages** and mirrored to the **`docs`
branch** of this repository.

To build the docs locally:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r docs/requirements.txt
# Doxygen must also be on PATH (conf.py runs it to extract the C API):
sphinx-build -b html docs docs/_build/html
# open docs/_build/html/index.html
```

## Building the module

igloo_driver is cross-compiled for ~13 architectures against multiple kernel
versions inside a Docker toolchain container. The wrapper is `build.sh`.

**Prerequisites:** Docker; a toolchain image (default
`rehosting/embedded-toolchains:latest`); and kernel headers as
`local_packages/kernel-devel-all.tar.gz` (published by
[`linux_builder`](https://github.com/rehosting/linux_builder)):

```bash
mkdir -p local_packages
curl -L -o local_packages/kernel-devel-all.tar.gz \
  https://github.com/rehosting/linux_builder/releases/latest/download/kernel-devel-all.tar.gz
```

Then build:

```bash
./build.sh                                   # all default targets, versions 4.10 & 6.13
./build.sh --versions "4.10 6.7" \
           --targets "armel mipseb mipsel"   # a subset
./build.sh --release                         # stripped modules
./build.sh --help                            # all options
```

The output is a single archive, `igloo_driver.tar.gz`, containing
`igloo.ko.<target>` per target/version. See
[docs/building.md](docs/building.md) for the full reference.

## Using it with Penguin

Drop `igloo_driver.tar.gz` into Penguin's `local_packages/` before a
`./penguin --build` to test a local driver build, or let Penguin fetch the
pinned release. Pushes to `main` publish a versioned GitHub release of the
built modules.

## Repository layout

| Path | Contents |
|---|---|
| `src/igloo_hc.c` | Module entry point and subsystem init order. |
| `src/ehypercall.h`, `src/igloo_hypercall_consts.h` | The per-arch hypercall primitive and its numbers. |
| `src/portal/` | The Portal protocol: dispatch loop, op handlers, shared-memory types. |
| `src/hooks/` | Syscall / ioctl / signal / socket / uname / mount / open hooks. |
| `src/hyperfs/` | Host-backed pseudo-filesystem. |
| `src/netdevs/` | Synthetic network devices (`igloonet`). |
| `scripts/` | Build-time helpers (e.g. trampoline codegen). |
| `docs/` | Sphinx documentation sources. |

## License

The kernel module is GPL-licensed (`MODULE_LICENSE("GPL")`).
