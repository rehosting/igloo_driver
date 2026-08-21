# Building

`igloo.ko` is cross-compiled for ~13 architectures against multiple kernel
versions. The build is a Nix flake: the kernels come from
[`linux_builder`](https://github.com/rehosting/linux_builder)'s flake as
**derivations**, and the cross compiler for each module comes from the kernel
it is built against.

There is no Docker image, no toolchain container, and no `local_packages/`
download.

## Prerequisites

- **Nix**, with flakes enabled.

That is the whole list. Optionally add the shared binary cache so kernels are
substituted rather than cross-built:

```
extra-substituters = https://rehosting-tools.cachix.org
extra-trusted-public-keys = rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0=
```

## Build

```sh
nix build .#igloo_driver     # the release tarball, every cell
nix build .#all              # every module, as a tree
```

One cell at a time — note the quoting, since cell names contain a `.` which Nix
would otherwise read as an attribute-path separator:

```sh
nix build '.#packages.x86_64-linux."igloo-6.13-armel"'   # the module
nix build '.#packages.x86_64-linux."isf-6.13-armel"'     # its ISF
nix build '.#packages.x86_64-linux."ko-6.13-armel"'      # stripped .ko
```

The matrix is **not declared in this repo**. It is read out of `linux_builder`'s
kernel outputs, so this builds for exactly the kernels that exist — a target
cannot be silently missing from one side.

## Against a different linux_builder

```sh
nix build .#igloo_driver \
  --override-input linux-builder github:rehosting/linux_builder/<ref>
```

For a kernel that is not in linux_builder's matrix at all — a stock upstream
one, say — use the `buildFor` seam rather than adding a cell:

```nix
igloo-driver.lib.x86_64-linux.buildFor {
  kernel = kernelsmith.buildKernel { /* ... */ };
  version = "6.6";
  target = "armel";
}
```

## Checks

```sh
nix flake check                      # everything below
nix build .#modversions-check        # module CRCs vs each kernel's Module.symvers
nix build .#shape-check              # ELF class/endianness/machine per target
```

`modversions-check` is the one that matters. A module is loadable only by the
exact kernel build it was compiled against: its modversion CRCs come from that
kernel's headers, and the kernel's own `.config` contains options Kconfig
resolves *by probing the compiler* (`CONFIG_STACKPROTECTOR_PER_TASK`,
`CONFIG_INIT_STACK_*`, the `CC_HAS_*` family). The ABI therefore moves when the
toolchain moves, even with identical sources and identical config files.

Building against a kernel **derivation** makes a mismatched pair
unrepresentable, where building against an unpacked `kernel-devel` tree only
made it unlikely. For scale: driver `v0.0.96`, Docker-built against different
kernels, disagreed on **129 of 221** symbols when paired with Nix kernels —
which a guest reports as `igloo: disagrees about version of symbol
module_layout`, at load time, in a running rehost.

## Output

A single archive, `igloo_driver.tar.gz`:

```
kernels/<version>/igloo.ko.<target>
kernels/<version>/igloo.ko.<target>.json.xz    # Volatility ISF
kernels/BUILT_AGAINST.txt                      # kernel store path per cell
```

`BUILT_AGAINST.txt` records the exact kernel **store path** each module belongs
to, not a version string — so the pairing can be verified by content rather
than trusted by tag number.

## Releases

Cut automatically on merge to `main`, by the same job that builds the matrix —
so a release is only published if every module built, the shapes match, and the
CRCs agree. The version comes from `reecetech/version-increment` with
`use_api: true`, which reads git tags, takes the highest by `sort -V`, and bumps
the patch.

To move the version *line*, push a bare marker tag at main's tip and let the
patch increment continue from it. Do **not** set `increment: minor` in the
workflow: it is not self-clearing, so it silently bumps the release after it as
well.

`nixdev_*` tags publish **prereleases** instead, off the version line, for
handing a downstream repo an immutable driver to test against.

## History: the Docker path

Until linux_builder v4.0.1 this repo cross-compiled inside a Docker toolchain
container via `build.sh` and `_in_container_build.sh`. Both are removed and
live in git history.

That path did not merely fall out of favour — it became unrunnable. It consumed
linux_builder's `releases/latest/download/kernel-devel-all.tar.gz`, and from
v4.0.1 that asset is Nix-built. A Nix-built kernel-devel tree ships prebuilt
host tools linked against the Nix store (`scripts/basic/fixdep` requests an
interpreter under `/nix/store`), which cannot execute inside an Ubuntu image;
every target failed within seconds of `make` starting. `build.sh` ended up with
a guard that detected precisely that and refused, which is why the failure was
legible at all.

It is not a bug in the tarball — it is what "prebuilt host tools" means, and it
is why a Nix `linux_builder` forces a Nix `igloo_driver`.
