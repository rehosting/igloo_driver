# The hypercall ABI

Everything igloo_driver does ultimately rides on a single primitive: a
**hypercall** — one instruction that traps into the PANDA/QEMU emulator, which
recognizes it and hands control to the host analysis engine. Portal (the
shared-memory protocol) is built on top of this; the hypercall itself just moves
a small number of register-sized arguments across the guest/host boundary.

## The calling convention

The canonical entry point is `igloo_hypercall4()` in
[`src/ehypercall.h`](https://github.com/rehosting/igloo_driver/blob/main/src/ehypercall.h):

```c
static inline unsigned long
igloo_hypercall4(unsigned long num,
                 unsigned long arg1, unsigned long arg2,
                 unsigned long arg3, unsigned long arg4);
```

- `num` is the **hypercall number** (see [Hypercall numbers](#hypercall-numbers)).
- `arg1..arg4` are up to four argument words.
- The return value comes back in the same register the host writes its result
  into (the "input and output" register noted per-arch below).

The instruction chosen per architecture is a **no-op or otherwise-harmless
instruction** that the emulator intercepts — on real hardware it either does
nothing observable or is a coprocessor/model-specific access the emulator claims.
This lets the same kernel run under emulation (where the hypercall is live) and,
in principle, on hardware (where it is inert).

## Per-architecture instruction map

| Arch (`CONFIG_*`) | Instruction | Number reg | Arg regs (1–4) | Return reg |
|---|---|---|---|---|
| `ARM64` | `msr S0_0_c5_c0_0, xzr` | `x8` | `x0 x1 x2 x3` | `x0` |
| `ARM` | `mcr p7, 0, r0, c0, c0, 0` | `r7` | `r0 r1 r2 r3` | `r0` |
| `MIPS` | `movz $0, $0, $0` | `v0` | `a0 a1 a2 a3` | `v0` |
| `X86_64` | `outl %eax, $0x88` | `rax` | `rdi rsi rdx r10` | `rax` |
| `I386` | `outl %eax, $0x88` | `eax` | `ebx ecx edx esi` | `eax` |
| `PPC` / `PPC64` | `xori 10, 10, 0` | `r0` | `r3 r4 r5 r6` | `r3` |
| `RISCV` | `xori x0, x0, 0` | `a7` | `a0 a1 a2 a3` | `a0` |
| `LOONGARCH` | `cpucfg $r0, $r0` | `a7` | `a0 a1 a2 a3` | `a0` |

Architectures not in this list raise a compile-time `#error` — igloo_driver
only builds for targets it can signal from.

```{note}
On x86 the hypercall is a port I/O to `0x88` — this is why the emulator watches
that port. On the register-file architectures the argument registers follow (or
deliberately diverge from) the platform syscall ABI; see the comments in
`ehypercall.h` for the per-arch rationale (e.g. x86-64 uses `r10` for the fourth
argument to match the syscall ABI).
```

## Hypercall numbers

Hypercall numbers are enumerated in
[`src/igloo_hypercall_consts.h`](https://github.com/rehosting/igloo_driver/blob/main/src/igloo_hypercall_consts.h)
(`enum igloo_hypercall_constants`). They fall into a few families:

| Family | Examples | Meaning |
|---|---|---|
| General | `IGLOO_OPEN` (100), `IGLOO_IOCTL_ENOTTY` (105) | Open interception, ioctl fallbacks. |
| Networking | `IGLOO_IPV4_SETUP`/`_BIND`/`_RELEASE` (200–205), IPv6 equivalents | Synthetic network bring-up and bind tracking. |
| Hypervisor | `IGLOO_HYP_UNAME` (300), `IGLOO_HYP_ENOENT` (305) | uname spoofing, ENOENT handling. |
| Task / VMA | `HC_TASK_CHANGE` (5900), `HC_VMA_UPDATE`/`IGLOO_HYP_VMA_*` (5910–5914), `IGLOO_HYP_TASK_PSTIME` | Task-switch and VMA-update reporting for host-side OSI. |
| Syscall / signal | `IGLOO_HYP_SYSCALL_ENTER` (0x1338), `IGLOO_HYP_SYSCALL_RETURN` (0x1339), `IGLOO_HYP_SIGNAL_DELIVER` (0x133b), `IGLOO_HYP_SETUP_TASK_COMM` (0x133a) | Syscall and signal hook event delivery. |
| Uprobe / kprobe | `IGLOO_HYP_UPROBE_ENTER/RETURN` (0x6901/0x6902), `IGLOO_HYP_KPROBE_ENTER/RETURN` (0x6903/0x6904) | Probe hit reporting. |
| Portal | `IGLOO_HYPER_REGISTER_MEM_REGION` (0xbebebebe), `IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT` (0x7901), `IGLOO_HYPER_PORTAL_INTERRUPT` (0x7902), `IGLOO_HYP_TRAMP_HIT` (0x7903) | Portal region registration and the interrupt path. |
| Lifecycle / misc | `IGLOO_MODULE_BASE` (0x6408400C), `IGLOO_INIT_MODULE` (0x6408400D), `IGLOO_SYSCALL` (0x6408400B), `IGLOO_HYPERFS_MAGIC`, the `IGLOO_SIGSTOP_*` values | Module base reporting, init-complete signalling, hyperfs magic, kthread sigstop coordination. |

See the full extracted enum in {doc}`api/hypercall_api`.
