/*
 * kl_syscall_backup.c -- sys_call_table override as a BACKUP syscall-interception
 * path for Tier-A rehosting. #included at the end of hooks/syscalls_hc.c so it
 * sees igloo's static syscall_entry_handler / syscall_ret_handler directly.
 *
 * On a donor kernel igloo's syscall hooks are delivered through the compiled-in
 * globals igloo_syscall_enter_hook / igloo_syscall_return_hook. A faithful vendor
 * kernel has neither those nor CONFIG_KPROBES / CONFIG_FUNCTION_TRACER (verified
 * on a 3.4.96 vendor kernel: register_kprobe/register_ftrace_function absent; the
 * kretprobe attempt returns -ENOSYS). But sys_call_table IS resolvable via
 * kallsyms, so we intercept by overriding table entries and routing to igloo's
 * EXISTING name-based handlers. Args come from the wrapper's own registers (==
 * the syscall's user pt_regs on ARM EABI). Read-only delivery (no-op setter);
 * restored on unload. Called from syscalls_hc_init when the built-in hooks are
 * absent.
 */

/* ARM EABI syscalls routed through the backup. execve drives OSI triggers;
 * ioctl/uname/mount/socketcall back the igloo hypercall hooks; I/O ones give
 * general visibility. The handler no-ops cheaply for unwatched syscalls. */
/* NOTE: ARM's "special" syscalls have asm-stub / pt_regs table entries, NOT the
 * plain C ABI, so a generic trampoline that calls them as C functions corrupts
 * state and oopses. execve/clone/fork/vfork/sigreturn/rt_sigreturn/sigaltstack/
 * statfs64/fstatfs64 are excluded entirely. mmap2 (below) IS intercepted but its
 * kl_orig is redirected to the C impl sys_mmap_pgoff (see kl_syscall_backup_init)
 * because the mmap2 slot is an asm stub that reads its 6th arg from register r5. */
struct kl_sc { int nr; const char *name; int argc; };
static const struct kl_sc kl_tab[] = {
    {  3, "read",       3 },
    {  4, "write",      3 },
    {146, "writev",     3 },   /* fastsnap lap detector (plain C, no asm stub) */
    {  5, "open",       3 },
    {  6, "close",      1 },
    { 21, "mount",      5 },
    { 54, "ioctl",      3 },
    {102, "socketcall", 2 },
    {285, "accept",     3 },   /* return-side fd learning (direct ARM EABI accept) */
    {286, "accept4",    4 },   /* "" accept4; snapfeed gates every feed on the learned fd */
    {122, "uname",      1 },
    {192, "mmap2",      6 },
    {322, "openat",     4 },
    {282, "bind",       3 },   /* netbinds: ARM EABI has direct bind/listen, so */
    {284, "listen",     2 },   /* socketcall alone never sees them (calls.S) */
    {281, "socket",     3 },   /* netbinds: the socket type (TCP/UDP) of a bind */
};
#define KL_N ((int)(sizeof(kl_tab)/sizeof(kl_tab[0])))

typedef long (*kl_sysfn)(unsigned long, unsigned long, unsigned long,
                         unsigned long, unsigned long, unsigned long);

static unsigned long **kl_sct;          /* sys_call_table */
static kl_sysfn kl_orig[KL_N];          /* saved originals */
static int kl_installed;

/* BISECTION: bitmask of kl_tab[] entries to actually hook (bit i => kl_tab[i]).
 * Default ~0 = all. Pass e.g. `insmod igloo.ko kl_hook_mask=0` to install none,
 * 0x1f = first five (read/write/open/close/mount), etc. Lets us find which hook
 * corrupts userspace exec/jffs2 writes without rebuilding igloo each time. */
static unsigned long kl_hook_mask = ~0UL;
module_param(kl_hook_mask, ulong, 0);
MODULE_PARM_DESC(kl_hook_mask, "bitmask of syscall-backup entries to hook");

/* igloo's ABI: syscall_entry_handler/syscall_ret_handler receive an array of
 * POINTERS to the arg-value slots (igloo_syscall_arg_value derefs each; the
 * setter writes through them), NOT the raw values. So we pass &vals[i] and the
 * setter writes into vals[], which then flows to the original call. */
static void kl_setter(const unsigned long args_ptr_array[], int index,
                      unsigned long new_value)
{
    if (index >= 0 && index < 6 && args_ptr_array[index])
        *(unsigned long *)args_ptr_array[index] = new_value;
}

static long kl_dispatch(int idx, unsigned long a0, unsigned long a1,
                        unsigned long a2, unsigned long a3,
                        unsigned long a4, unsigned long a5)
{
    const struct kl_sc *e = &kl_tab[idx];
    unsigned long vals[6] = { a0, a1, a2, a3, a4, a5 };
    const unsigned long *ptrs[6] = {
        &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]
    };
    long skip_ret = 0, ret;
    bool skip;

    skip = syscall_entry_handler(e->name, &skip_ret, e->argc,
                                 (const unsigned long *)ptrs,
                                 (igloo_syscall_setter_t)kl_setter);
    if (skip)
        ret = skip_ret;
    else
        ret = kl_orig[idx](vals[0], vals[1], vals[2],
                           vals[3], vals[4], vals[5]);
    ret = syscall_ret_handler(e->name, ret, e->argc,
                              (const unsigned long *)ptrs);
    return ret;
}

/* One trampoline per hooked entry (each table slot needs a distinct function
 * that knows its index). */
#define KL_TRAMP(i) \
    static long kl_tramp_##i(unsigned long a0, unsigned long a1, \
                             unsigned long a2, unsigned long a3, \
                             unsigned long a4, unsigned long a5) \
    { return kl_dispatch((i), a0, a1, a2, a3, a4, a5); }
KL_TRAMP(0)  KL_TRAMP(1)  KL_TRAMP(2)  KL_TRAMP(3)  KL_TRAMP(4)
KL_TRAMP(5)  KL_TRAMP(6)  KL_TRAMP(7)  KL_TRAMP(8)  KL_TRAMP(9)
KL_TRAMP(10) KL_TRAMP(11) KL_TRAMP(12) KL_TRAMP(13) KL_TRAMP(14)
KL_TRAMP(15)
static const kl_sysfn kl_tramps[KL_N] = {
    kl_tramp_0, kl_tramp_1, kl_tramp_2, kl_tramp_3, kl_tramp_4,
    kl_tramp_5, kl_tramp_6, kl_tramp_7, kl_tramp_8, kl_tramp_9,
    kl_tramp_10, kl_tramp_11, kl_tramp_12, kl_tramp_13, kl_tramp_14,
    kl_tramp_15,
};

int kl_syscall_backup_init(void)
{
    int i;

    kl_sct = (unsigned long **)kallsyms_lookup_name("sys_call_table");
    if (!kl_sct) {
        printk(KERN_ERR "IGLOO: kl_syscall_backup: sys_call_table not found\n");
        return -ENOENT;
    }
    printk(KERN_INFO "IGLOO: kl_syscall_backup: sys_call_table @ %p, hooking %d "
           "syscalls (kprobes/ftrace unavailable on this vendor kernel)\n",
           kl_sct, KL_N);
    printk(KERN_INFO "IGLOO: kl_syscall_backup: kl_hook_mask=0x%lx\n", kl_hook_mask);
    for (i = 0; i < KL_N; i++) {
        int nr = kl_tab[i].nr;
        kl_orig[i] = (kl_sysfn)kl_sct[nr];         /* always save original */
        /* ARM __NR_mmap2 (192) is NOT a plain C function: the sys_call_table
         * slot is an asm stub (entry-common.S: `str r5,[sp,#4]; b sys_mmap_pgoff`)
         * that reads the 6th arg from register r5 and depends on the kernel's
         * own syscall-entry stack frame. Calling it via the C ABI (6th arg on
         * the stack, r5 undefined) corrupts the page offset -> bad mapping ->
         * SIGBUS on the next exec, and the corrupted writeback storms jffs2.
         * mmap2 is thus in the same "special syscall" class as execve/clone/
         * sigreturn. Route it to the real C implementation sys_mmap_pgoff, which
         * sys_mmap2 itself tail-calls; with PAGE_SHIFT==12 the 4K page-offset
         * units already match, so no conversion is needed. */
        if (nr == 192) {
            /* before 2.6.33 the C target is do_mmap2(), same arguments */
            unsigned long mp = kallsyms_lookup_name(
                LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) ? "do_mmap2"
                                                               : "sys_mmap_pgoff");
            if (mp) {
                kl_orig[i] = (kl_sysfn)mp;
            } else {
                printk(KERN_WARNING "IGLOO: kl_syscall_backup: sys_mmap_pgoff "
                       "not found; leaving mmap2 unhooked\n");
                continue;                          /* don't install a broken hook */
            }
        }
        if (!(kl_hook_mask & (1UL << i)))
            continue;                              /* bisection: skip this hook */
        kl_sct[nr] = (unsigned long *)kl_tramps[i];   /* table entry = data ptr */
    }
    smp_wmb();
    kl_installed = 1;
    printk(KERN_INFO "IGLOO: kl_syscall_backup: installed (execve/ioctl/uname/"
           "mount/socketcall/... -> igloo handlers)\n");
    return 0;
}

void kl_syscall_backup_exit(void)
{
    int i;
    if (!kl_installed)
        return;
    for (i = 0; i < KL_N; i++)
        kl_sct[kl_tab[i].nr] = (unsigned long *)kl_orig[i];
    smp_wmb();
    kl_installed = 0;
}
