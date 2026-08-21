# Hooks

Beyond reading and writing state, igloo_driver can install **runtime hooks** in
the guest kernel and report each hit back to the host. Hooks are registered and
torn down through Portal operations (see [Portal](portal.md#runtime-hooks)); the
kernel-side machinery lives in `src/hooks/` and `src/portal/`.

Four kinds of hooks are supported:

| Hook | Registration op | Event hypercall(s) |
|---|---|---|
| **Syscall** (entry / return) | `register_syscall_hook` | `IGLOO_HYP_SYSCALL_ENTER`, `IGLOO_HYP_SYSCALL_RETURN` |
| **Signal delivery** | `register_signal_hook` | `IGLOO_HYP_SIGNAL_DELIVER` |
| **kprobe** (entry / return / both) | `register_kprobe` | `IGLOO_HYP_KPROBE_ENTER`, `IGLOO_HYP_KPROBE_RETURN` |
| **uprobe** (entry / return / both) | `register_uprobe` | `IGLOO_HYP_UPROBE_ENTER`, `IGLOO_HYP_UPROBE_RETURN` |

kprobe and uprobe direction is selected by `enum portal_type`
(`PORTAL_KPROBE_TYPE_ENTRY/RETURN/BOTH`, and the uprobe equivalents).

## Syscall hooks

Syscall hooks are the richest. A `struct syscall_hook` (in
[`src/hooks/syscalls_hc.h`](https://github.com/rehosting/igloo_driver/blob/main/src/hooks/syscalls_hc.h))
can fire on entry, return, or every syscall (`on_all`), and supports extensive
in-guest **filtering** so that only interesting events cross the hypercall
boundary:

- **By process** — a specific `pid`, or a process name (`comm`).
- **By argument value** — each argument can carry a `struct value_filter`.
- **By return value** — the return value has its own filter.

The `value_filter` comparison types cover far more than equality:

| Category | Types |
|---|---|
| Numeric | `EXACT`, `NOT_EQUAL`, `GREATER`, `GREATER_EQUAL`, `LESS`, `LESS_EQUAL`, `RANGE` |
| Return status | `SUCCESS` (≥ 0), `ERROR` (< 0) |
| Bitmask | `BITMASK_SET`, `BITMASK_CLEAR` |
| String | `STR_EXACT`, `STR_CONTAINS`, `STR_STARTSWITH`, `STR_ENDSWITH` |

String filters read the argument out of user space carefully — a stack fast-path
for short strings, falling back to a bounded heap allocation up to `PATH_MAX`.

Syscall names are **normalized** before matching, stripping arch- and
compat-specific prefixes (`sys_`, `_sys_`, `compat_sys_`, `arm64_sys_`,
`riscv_sys_`), so a single hook name matches across architectures. Hooks are
kept in an RCU-protected hash table keyed by normalized name.

When a hook fires, the host receives a `struct syscall_event` carrying the
arguments, program counter, task, `pt_regs`, return value, and syscall name. The
host can set `skip_syscall` to suppress the real syscall — this is how Penguin
*intervenes* (e.g. faking a syscall result) rather than merely observing.

### Scoping and interventions

`syscall_hook.scope_filter_enabled` ties into [analysis
scoping](architecture.md#analysis-scoping): logging (read-only) hooks set it so
they only fire for the firmware-under-analysis subtree, skipping Penguin's own
infrastructure; intervention hooks leave it clear so they apply everywhere.

### Portalcall fast path

For very hot paths, a **portalcall fast path** avoids full Portal round trips.
`register_portalcall_magic` registers the magic value that identifies a portal
call, and `set_portalcall_fastpath` toggles the optimization
(`portalcall_fastpath_*` in `syscalls_hc.h`).

## Signal hooks

A `struct signal_hook` fires on signal delivery, optionally filtered by signal
number (0 = any), pid, or process name. The resulting `struct signal_event`
carries the signal number, target task and registers, PC, `comm`, and pid — and
a `drop` flag the host can set to **suppress delivery** of the signal.

## ioctl, uname, mounts, and open

`src/hooks/` also contains several targeted interception points used during
rehosting:

- **ioctl** (`ioctl_hc.c`) — reports unhandled ioctls (`igloo_ioctl`) and
  ENOENT/ENOTTY conditions so the host can model missing hardware.
- **uname** (`uname_hc.c`) — cooperates with `IGLOO_HYP_UNAME` to let the host
  spoof `uname()` results.
- **block_mounts** (`block_mounts.c`) — suppresses mounts that would interfere
  with rehosting.
- **igloo_open** (`igloo_open.c`) — open() interception, coordinating with the
  `IGLOO_OPEN` hypercall and hyperfs.
- **sockets** (`sock_hc.c`) — socket-related hooks feeding the networking model.
