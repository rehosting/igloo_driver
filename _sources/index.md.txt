# igloo_driver

**igloo_driver** is the in-guest half of the [IGLOO / Penguin][penguin] firmware
rehosting stack: a small, built-in Linux kernel module that turns the emulated
guest kernel into a **programmable kernel debugger**. From the host (a PANDA /
QEMU analysis plugin) you can, at runtime, reach into the running guest and:

- **Read and write kernel and user memory** — arbitrary addresses, strings,
  pointer arrays, whole process address spaces.
- **Introspect the OS** — walk the process list, read a process's maps, argv,
  environ, open file descriptors, register state, and executable path.
- **Install hooks** — kprobes, uprobes, syscall entry/return hooks, and signal
  delivery hooks, all dispatched back to the host.
- **Call kernel functions** — a foreign-function interface (`ffi_exec`) plus
  `kallsyms` lookup and generated trampolines.
- **Synthesize pseudo-files and devices** — create `/proc`, `/sys`, `/dev`,
  `sysctl`, anonymous-inode, socket and MTD nodes on demand, backed by
  host-side models via **hyperfs**.

All of this is driven over a single cooperative, shared-memory protocol called
**Portal**, carried on top of a tiny per-architecture **hypercall** ABI. The
module has no configuration of its own — it is orchestrated entirely from the
host by Penguin.

```{admonition} Where this fits
:class: tip
igloo_driver runs **inside the guest**. The host-side counterpart — the Python
API that issues these operations — lives in Penguin. If you are looking for the
*host* API (`plugins.portal.read_str(...)`, kprobe/uprobe registration from a
pyplugin, pseudo-file models), start with Penguin's
[Portal][penguin-portal], [kprobes][penguin-kprobes] and
[uprobes][penguin-uprobes] documentation. This site documents the guest-side
kernel module those APIs talk to.
```

## Start here

```{toctree}
:maxdepth: 2
:caption: Guide

architecture
portal
hypercall_abi
hooks
hyperfs
pseudofiles
building
```

```{toctree}
:maxdepth: 2
:caption: C API reference

api/index
```

## At a glance

| | |
|---|---|
| **What it is** | A built-in Linux kernel module (`igloo.ko`) |
| **Language** | C (kernel), plus a small trampoline codegen helper in Python |
| **Targets** | ~13 architectures (arm/arm64, mips/mips64 both endians, powerpc 32/64 both endians, x86_64, riscv64, loongarch64) |
| **Kernel versions** | Multiple; regularly built against 4.10 and 6.13 |
| **Host protocol** | Portal (shared-memory) over a per-arch hypercall instruction |
| **Configured by** | Penguin (the module itself is unconfigured) |
| **Build** | `./build.sh` (Docker cross-compile toolchain) → `igloo_driver.tar.gz` |

[penguin]: https://github.com/rehosting/penguin
[penguin-portal]: https://github.com/rehosting/penguin/blob/main/docs/portal.md
[penguin-kprobes]: https://github.com/rehosting/penguin/blob/main/docs/kprobes.md
[penguin-uprobes]: https://github.com/rehosting/penguin/blob/main/docs/uprobes.md
