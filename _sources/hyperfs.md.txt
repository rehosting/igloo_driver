# hyperfs

**hyperfs** (`src/hyperfs/`) is a pseudo-filesystem whose file contents are
served by the *host*. When guest code opens, reads, writes, or `ioctl`s a
hyperfs-backed file, the operation is forwarded over a hypercall to a host-side
model, which computes the answer and returns it. This is how Penguin makes a
device node or a `/proc` entry "exist" and behave sensibly even though no real
hardware or kernel subsystem is behind it.

hyperfs is loaded last during module init and is declared as a soft dependency
(`MODULE_SOFTDEP("post: hyperfs")`) so it comes up after the rest of
igloo_driver.

## Protocol

hyperfs uses a compact operation set on top of the hypercall ABI, distinguished
by the `IGLOO_HYPERFS_MAGIC` value (`crc32("hyperfs")`):

```c
enum hyperfs_ops {
    HYP_FILE_OP,              /* perform a file operation */
    HYP_GET_NUM_HYPERFILES,   /* how many hyperfiles are registered? */
    HYP_GET_HYPERFILE_PATHS,  /* enumerate their paths */
};

enum hyperfs_file_ops {
    HYP_READ, HYP_WRITE, HYP_IOCTL, HYP_GETATTR,
};
```

- `HYP_FILE_OP` carries one of the four file operations (`HYP_READ`,
  `HYP_WRITE`, `HYP_IOCTL`, `HYP_GETATTR`) to the host model.
- `HYP_GET_NUM_HYPERFILES` / `HYP_GET_HYPERFILE_PATHS` let the host enumerate the
  registered hyperfiles (paths up to `HYPERFILE_PATH_MAX` = 1024 bytes).
- `HYP_RETRY` (`0xdeadbeef`) is a sentinel the host can return to ask the guest
  to retry an operation.

## Passthrough

A hyperfs mount can be given a `passthrough_path=` option. Paths not backed by a
registered hyperfile fall through to the real underlying filesystem, so a
hyperfs overlay can synthesize a handful of files while leaving everything else
untouched. Internally hyperfs resolves and caches `vfs_read`, `vfs_write`, and
`vfs_ioctl` via `kallsyms` to perform the passthrough.

## Relationship to the pseudo-file Portal ops

hyperfs is the delivery mechanism behind most of the [synthesized pseudo-files
and devices](pseudofiles.md). The `hyperfs_add_hyperfile` Portal op registers a
new host-backed file; the higher-level `procfs_create_file`,
`sysfs_create_file`, `devfs_create_device`, `sysctl_create_file`,
`anonfs_create_file`, and MTD operations build on the same foundation to place
those files at the right spot in the guest's namespace.
