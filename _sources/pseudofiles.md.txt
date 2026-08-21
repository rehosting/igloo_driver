# Pseudo-files & devices

A large fraction of firmware rehosting is making the guest believe that hardware
and kernel interfaces it expects are present. igloo_driver can **synthesize**
entries across every major kernel namespace on demand, driven by Portal
operations from the host and backed by [hyperfs](hyperfs.md) models.

## What can be synthesized

| Namespace | Portal ops | Backed by |
|---|---|---|
| `/proc` | `procfs_create_file`, `procfs_create_or_lookup_dir` | `portal_procfs.c` |
| `/sys` | `sysfs_create_file`, `sysfs_create_or_lookup_dir` | `portal_sysfs.c` |
| `/dev` | `devfs_create_device`, `devfs_create_or_lookup_dir` | `portal_devfs.c` |
| `sysctl` | `sysctl_create_file` | `portal_sysctl.c` |
| anonymous inodes | `anonfs_create_file` | `portal_anon.c` |
| sockets | `sockfs_create_socket` | `portal_net.c` |
| MTD (flash) | `mtd_create`, `mtd_nuke` | `portal_mtd.c` |

Each `*_create_file` / `*_create_device` op registers the node and wires its
read/write/ioctl operations back to a host model through hyperfs, so accessing
the file from guest userland produces host-controlled behavior. The
`*_create_or_lookup_dir` variants create intermediate directories idempotently,
so a deep path can be materialized one component at a time.

## MTD devices

MTD (Memory Technology Device) nodes model raw flash. `mtd_create` brings up a
synthetic MTD device — letting firmware that reads or writes flash partitions
run against a host-backed model — and `mtd_nuke` tears one down. This is how
NVRAM/flash-backed configuration can be emulated without real flash hardware.

## Synthetic network devices

Network interfaces are handled separately from files, in `src/netdevs/`
(`igloonet`), via `register_netdev`, `lookup_netdev`, `set_netdev_state`, and
`get_netdev_state`. Combined with the networking hypercalls
(`IGLOO_IPV4_SETUP`/`_BIND`/`_RELEASE` and IPv6 equivalents), this lets Penguin
present synthetic interfaces and track what the firmware binds to them.

## Who drives this

The guest module only implements the *mechanism*. Which pseudo-files exist,
what they contain, and how they respond is decided entirely by the host: Penguin
issues the `*_create_*` operations and answers the subsequent hyperfs reads and
writes. From a rehoster's point of view you configure these through Penguin's
pseudo-file / device models, not by editing the kernel module.
