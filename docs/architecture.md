# Architecture

igloo_driver is a **built-in** kernel module (compiled into the guest kernel,
not loaded at runtime — its `cleanup_module` is unreachable). It initializes
early in boot and immediately opens a communication channel to the host analysis
engine.

## The big picture

```
        GUEST (emulated firmware)                       HOST (PANDA / QEMU + Penguin)
  ┌───────────────────────────────────┐           ┌────────────────────────────────┐
  │  firmware userland                 │           │  Penguin pyplugins              │
  │      │  syscalls / signals / ...   │           │    plugins.portal.read_str()    │
  │      ▼                             │           │    kprobe / uprobe / syscall    │
  │  ┌─────────────────────────────┐   │  hypercall│    pseudo-file models           │
  │  │        igloo_driver         │◀──┼───────────┼──▶  Portal host handler         │
  │  │  hooks · portal · hyperfs   │   │  (shared  │                                 │
  │  │  netdevs · scope            │   │   memory) │                                 │
  │  └─────────────────────────────┘   │           │                                 │
  │      guest Linux kernel            │           │                                 │
  └───────────────────────────────────┘           └────────────────────────────────┘
```

Two layers carry every interaction:

1. **The hypercall ABI** (`ehypercall.h`, `igloo_hypercall_consts.h`) — a single
   privileged/no-op instruction per architecture that traps into the emulator,
   passing up to four register arguments. This is the raw signalling primitive.
   See [The hypercall ABI](hypercall_abi.md).

2. **Portal** (`src/portal/`) — a cooperative shared-memory protocol layered on
   top of the hypercall. The guest registers a page with the host; the host
   writes an *operation* into that page and re-enters the guest, which executes
   the operation and writes the result back. This is how the ~50 rich
   operations (read/write memory, OS introspection, hook management, pseudo-file
   creation, FFI) are carried. See [Portal](portal.md).

## Module layout

| Directory / file | Responsibility |
|---|---|
| `src/igloo_hc.c` | Module entry point (`init_module`): reports its load base, then initializes every subsystem in order. |
| `src/ehypercall.h` | The per-architecture hypercall instruction (`igloo_hypercall4`). |
| `src/igloo_hypercall_consts.h` | Hypercall number constants (network setup, uname, syscall/uprobe/kprobe events, memory-region registration, …). |
| `src/portal/` | The Portal protocol: dispatch loop, the op handlers, and the shared-memory types. |
| `src/hooks/` | Guest-kernel hooks: syscalls, ioctl, signals, sockets, uname, mount blocking, open interception. |
| `src/hyperfs/` | Host-backed pseudo-filesystem (`hyperfs`) — files whose reads/writes are answered by the host. |
| `src/netdevs/` | Synthetic network devices (`igloonet`). |
| `src/portal/scope.c` (+ `scope.h`) | **Analysis scoping** — gates event emission to the firmware-under-analysis process subtree. |
| `scripts/gen_portal_tramp.py` | Generates per-architecture trampoline code used by `tramp_generate`. |

## Initialization order

`init_module()` (in `src/igloo_hc.c`) runs these steps in sequence; a failure in
any one aborts module init:

1. `report_base_addr()` — looks up a known `.text` symbol via
   `kallsyms_lookup_name()` and reports the module's load base to the host with
   the `IGLOO_MODULE_BASE` hypercall, so the host can relocate symbols.
2. `igloo_scope_init()` — captures the **initial UTS namespace** while `current`
   is still Penguin's boot context, before `init.sh` unshares a fresh namespace
   for the real guest init. See [Analysis scoping](#analysis-scoping).
3. Hook subsystems: `syscalls_hc_init` → `signal_hc_init` → `ioctl_hc_init` →
   `sock_hc_init` → `uname_hc_init`.
4. `igloo_portal_init()` — registers the Portal shared-memory region and enables
   the interrupt path.
5. `igloo_procfs_compat_init()` — procfs compatibility hooks.
6. `block_mounts_init()`, `igloo_open_init()` — mount blocking and open
   interception.
7. `hyperfs_init()` — brings up the host-backed pseudo-filesystem.
8. A final `IGLOO_INIT_MODULE` hypercall tells the host the guest is fully up.

## Analysis scoping

Penguin's own infrastructure — boot machinery, the backgrounded VPN / console /
guest-command helpers, and anything launched via `call_usermodehelper` — stays
in the kernel's *initial* UTS namespace. At handoff, `init.sh` unshares a fresh
UTS namespace for the real guest init, so the firmware-under-analysis process
subtree lives *outside* the initial namespace.

`igloo_scope_init()` captures that initial namespace at module init. Event
emission is then gated on `igloo_in_scope(task)`, so analysis captures only the
firmware subtree and not Penguin's own helpers. Gating is **disabled by
default**: a driver paired with a Penguin that never enables scoping behaves
exactly as before and captures everything. Penguin toggles it at runtime via the
Portal `set_scope_enabled` operation.

See {doc}`api/scope_api` for the extracted `scope.h` reference.
