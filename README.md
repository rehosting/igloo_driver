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

There are two build paths. They produce the same `igloo_driver.tar.gz` layout.

### With Nix (recommended)

```bash
nix build .#igloo_driver                                # the release tarball
nix build '.#packages.x86_64-linux."igloo-6.13-armel"'  # one module
nix build .#all                                         # every module
nix flake check                                         # shape + modversion checks
```

No Docker, no toolchain image, and no `local_packages/` download: the kernels
come from
[`linux_builder`](https://github.com/rehosting/linux_builder)'s flake as
**derivations**, and the cross compiler comes from the kernel each module is
built against.

That last point is the reason this path exists. A module is loadable only by
the exact kernel build it was compiled against — its modversion CRCs come from
that kernel's headers, and the kernel's `.config` itself contains options
Kconfig resolves *by probing the compiler* (`CONFIG_STACKPROTECTOR_PER_TASK`,
`CONFIG_INIT_STACK_*`, the `CC_HAS_*` family). So the ABI moves when the
toolchain moves, even with identical sources and identical config files.
Building against a kernel *derivation* makes a mismatched pair unrepresentable,
where building against an unpacked `kernel-devel` tree only made it unlikely.

`kernels/BUILT_AGAINST.txt` inside the archive names the exact kernel store
path each module belongs to, and `nix flake check` asserts that every module's
modversion CRCs actually agree with that kernel's `Module.symvers` — the check
that catches a `disagrees about version of symbol module_layout` panic before
it reaches a guest rather than after.

The matrix is not restated here: it is read out of `linux_builder`'s kernel
outputs, so this repo builds for exactly the kernels that exist.

To build `igloo.ko` against some other kernelsmith-built kernel — a stock
upstream one, say — use the `buildFor` seam rather than adding it to a matrix:

```nix
igloo-driver.lib.x86_64-linux.buildFor {
  kernel = kernelsmith.buildKernel { /* ... */ };
  version = "6.6"; target = "armel";
}
```

> Cell names contain a `.`, which Nix parses as an attribute-path separator —
> quote the attribute (`'.#packages.x86_64-linux."igloo-6.13-armel"'`) or it
> will not resolve.

To build against a different `linux_builder`:

```bash
nix build .#igloo_driver --override-input linux-builder github:rehosting/linux_builder/<ref>
```

### History: the Docker path

Until linux_builder v4.0.1 this repo also cross-compiled inside a Docker
toolchain container, driven by `build.sh`. That path is removed; it lives in
git history.

It did not rot — it became **unrunnable**. It fed on linux_builder's
`releases/latest/download/kernel-devel-all.tar.gz`, and as of v4.0.1 that asset
is Nix-built. A Nix-built kernel-devel tree ships prebuilt host tools linked
against the Nix store (`scripts/basic/fixdep` requests an interpreter under
`/nix/store`), which cannot execute inside an Ubuntu toolchain image; every
target fails within seconds of `make` starting. `build.sh` grew a guard that
detected exactly this and refused, rather than failing with an error naming
fixdep and nothing else.

That is not a bug in the tarball. It is what "prebuilt host tools" means, and
it is why a Nix linux_builder forces a Nix igloo_driver.

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
