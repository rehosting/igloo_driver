# Portal

**Portal** is the cooperative, shared-memory protocol between the guest kernel
(igloo_driver) and the host analysis engine (Penguin). It is what makes
igloo_driver a *programmable* kernel debugger: rather than the host reaching
blindly into guest physical memory, the guest kernel executes each request in
its own context — with full access to `current`, the page tables, the VFS, and
`kallsyms` — and hands back a well-formed result.

The host-side API (the Python `plugins.portal.*` calls you write in a Penguin
pyplugin) is documented in Penguin's
[Portal guide](https://github.com/rehosting/penguin/blob/main/docs/portal.md).
This page documents the *guest* side: the protocol and the catalog of
operations the kernel module implements.

## How Portal works

### The shared region

At module init, `igloo_portal_init()` registers a single page-sized region with
the host (`IGLOO_HYPER_REGISTER_MEM_REGION`) and enables an interrupt path
(`IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT`). Every operation is carried in a
`portal_region` — a union of a small fixed header and a raw data buffer that
fills the rest of the page:

```c
typedef struct {
    uint32_t op;    // operation type (HYPER_OP_* / HYPER_RESP_*)
    uint32_t pid;   // process ID, if the op targets a process (CURRENT_PID_NUM = current)
    uint64_t addr;  // address or primary parameter
    uint64_t size;  // size or secondary parameter
} region_header;

typedef union {
    region_header header;
    uint8_t raw[PAGE_SIZE - sizeof(region_header)];  // data payload
} portal_region;
```

The usable payload is `CHUNK_SIZE = PAGE_SIZE - sizeof(region_header)`; larger
transfers are chunked across multiple round trips.

### The dispatch loop

`igloo_portal()` (in `src/portal/portal.c`) is the guest-side engine:

1. Allocate a fresh region page and zero its header.
2. Issue `igloo_hypercall4(num, arg1, arg2, &region, region->header.op)` — this
   traps to the host, which fills the region with the next operation to perform
   (or a "no work" sentinel).
3. `handle_post_memregion()` looks up `region->header.op` in the handler table
   and dispatches to `handle_op_<name>()`. Each handler reads its parameters
   from the header/payload, performs the work, and writes a response code
   (`HYPER_RESP_*`) plus any result data back into the region.
4. Loop back to step 2 until the host signals there is no further work.

The handler table is built directly from the op list via an X-macro, so adding
an operation is a matter of adding one line to `portal_op_list.h` and
implementing its `handle_op_<name>()`:

```c
static const portal_op_handler op_handlers[] = {
    [HYPER_OP_NONE] = NULL,
#define X(lower, upper) [HYPER_OP_##upper] = handle_op_##lower,
    PORTAL_OP_LIST
#undef X
};
```

### The interrupt path

Between explicit Portal calls, the host may need the guest's attention (for
example, to service a pending operation). igloo_driver exposes a lightweight
`portal_interrupt` flag; `check_portal_interrupt()` notices when it is set and
re-enters the Portal loop via `IGLOO_HYPER_PORTAL_INTERRUPT`. A
**fast path** (`set_portalcall_fastpath`, `register_portalcall_magic`) lets the
host reduce the per-call overhead for hot operations.

## Operation catalog

The full set of operations is declared in
[`src/portal/portal_op_list.h`](https://github.com/rehosting/igloo_driver/blob/main/src/portal/portal_op_list.h)
as `PORTAL_OP_LIST`. Each `X(lower, UPPER)` entry generates an enum value
`HYPER_OP_UPPER`, a handler prototype `handle_op_lower()`, and a table slot.
They group into the following families.

### Memory access

| Op | Purpose |
|---|---|
| `read` | Read raw bytes from a target address (kernel or, with `pid`, a process). |
| `write` | Write raw bytes to a target address. |
| `read_str` | Read a NUL-terminated string. |
| `read_ptr_array` | Read an array of pointers (e.g. `argv`/`envp` vectors). |
| `dump` | Bulk-dump a memory range. |
| `copy_buf_guest` | Copy a host-provided buffer into guest memory. |

Implemented in `portal_mem.c` / `portal_dump.c`. The helper
`get_target_task_mm()` safely pins the target process's `mm` for cross-process
reads (see {doc}`api/portal_api`).

### OS introspection (OSI)

| Op | Purpose |
|---|---|
| `osi_proc` | Full process descriptor (`struct osi_proc`: pid, ppid, name, memory-layout bounds, times). |
| `osi_proc_all` | Bulk-walk **all** live processes in one operation (slimmer per-process node than `osi_proc`). |
| `osi_proc_handles` | Enumerate live processes as lightweight handles. |
| `osi_mappings` | The process's memory mappings (`struct osi_module` list). |
| `osi_proc_mem` | Access a process's memory via its OSI handle. |
| `osi_proc_exe` | The process's executable path. |
| `osi_proc_ptregs` | The process's saved `pt_regs`. |
| `read_procargs` | The process's `argv`. |
| `read_procenv` | The process's `environ`. |
| `read_fds` | The process's open file descriptors. |
| `read_time` | Read guest time. |

Implemented in `portal_osi.c`. The OSI structs are defined in `portal_types.h`
and rendered in {doc}`api/types_api`.

### Files

| Op | Purpose |
|---|---|
| `read_file` | Read a file from the guest filesystem by path. |
| `write_file` | Write a file to the guest filesystem. |

Implemented in `portal_fs.c`.

### Execution & foreign-function interface

| Op | Purpose |
|---|---|
| `exec` | Execute a program in the guest. |
| `ffi_exec` | Call an arbitrary kernel function with host-supplied arguments (FFI). |
| `kallsyms_lookup` | Resolve a symbol name to an address via `kallsyms`. |
| `tramp_generate` | Generate a per-architecture trampoline (see `scripts/gen_portal_tramp.py`). |

Implemented in `portal_exec.c` / `portal_ffi.c` / `portal_tramp.c`.

### Runtime hooks

| Op | Purpose |
|---|---|
| `register_kprobe` / `unregister_kprobe` | Install/remove a kprobe; hits are reported to the host. |
| `register_uprobe` / `unregister_uprobe` | Install/remove a uprobe. |
| `register_syscall_hook` / `unregister_syscall_hook` | Hook syscall entry/return. |
| `register_signal_hook` / `unregister_signal_hook` | Hook signal delivery. |
| `register_portalcall_magic` | Register the magic value that identifies a portal call. |
| `set_portalcall_fastpath` | Enable/disable the fast dispatch path. |

Implemented in `portal_kprobe.c` / `portal_uprobe.c` / `portal_syscall.c` and
the `src/hooks/` subsystem. Probe types are enumerated by `enum portal_type`
(entry / return / both, for both kprobes and uprobes). See [Hooks](hooks.md).

### Synthesized pseudo-files & devices

| Op | Purpose |
|---|---|
| `hyperfs_add_hyperfile` | Register a host-backed file with hyperfs. |
| `procfs_create_file` / `procfs_create_or_lookup_dir` | Synthesize `/proc` entries. |
| `sysfs_create_file` / `sysfs_create_or_lookup_dir` | Synthesize `/sys` entries. |
| `devfs_create_device` / `devfs_create_or_lookup_dir` | Synthesize `/dev` nodes. |
| `sysctl_create_file` | Synthesize a `sysctl` entry. |
| `anonfs_create_file` | Create an anonymous-inode-backed file. |
| `sockfs_create_socket` | Create a socket-backed pseudo-file. |
| `mtd_create` / `mtd_nuke` | Create / tear down synthetic MTD (flash) devices. |

Implemented in `portal_procfs.c`, `portal_sysfs.c`, `portal_devfs.c`,
`portal_sysctl.c`, `portal_anon.c`, `portal_net.c`, `portal_mtd.c`,
`portal_hyperfs.c`. See [Pseudo-files & devices](pseudofiles.md) and
[hyperfs](hyperfs.md).

### Synthetic network devices

| Op | Purpose |
|---|---|
| `register_netdev` | Register a synthetic network device. |
| `lookup_netdev` | Look up a synthetic device by name. |
| `set_netdev_state` / `get_netdev_state` | Set / query device state. |

Implemented in `src/netdevs/igloonet.c` and `portal_net.c`.

### Analysis scoping

| Op | Purpose |
|---|---|
| `set_scope_enabled` | Enable/disable event-emission gating to the firmware subtree. |

Implemented in `portal/scope.c`. See
[Analysis scoping](architecture.md#analysis-scoping).

## Response codes

Every handler sets a response code in `region->header.op` before returning.
These are defined alongside the operations in `portal_types.h`:

| Code | Meaning |
|---|---|
| `HYPER_RESP_READ_OK` | Read completed. |
| `HYPER_RESP_READ_PARTIAL` | Read completed partially (more data pending / truncated). |
| `HYPER_RESP_READ_FAIL` | Read failed. |
| `HYPER_RESP_READ_NUM` | Numeric result returned in the header. |
| `HYPER_RESP_WRITE_OK` | Write completed. |
| `HYPER_RESP_WRITE_FAIL` | Write failed / invalid operation. |
