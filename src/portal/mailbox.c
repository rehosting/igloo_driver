#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/preempt.h>
#include <asm/io.h>
#include <asm/barrier.h>
#include "portal_internal.h"
#include "mailbox.h"

static int mailbox = 1;
module_param(mailbox, int, 0444);
MODULE_PARM_DESC(mailbox, "Pass hypercall data through a per-CPU mailbox page (1, default) "
                 "or in registers only (0)");

int igloo_mb_mode = IGLOO_MB_OFF;

static DEFINE_PER_CPU(struct igloo_mailbox *, igloo_mb);
static DEFINE_PER_CPU(int, igloo_mb_reg_ret);
static u64 *igloo_mb_shared;
static u64 igloo_mb_interrupt_fallback;

u64 *igloo_mb_portal_interrupt(void)
{
    return igloo_mb_shared ? igloo_mb_shared : &igloo_mb_interrupt_fallback;
}

static inline void igloo_mb_doorbell(void)
{
#ifdef CONFIG_ARM64
    if (igloo_mb_mode == IGLOO_MB_HVC) {
        /*
         * SMCCC: x0 is the function ID, and x1-x17 are not preserved. The host
         * answers in the mailbox, so the registers' contents don't matter.
         */
        register unsigned long x0 asm("x0") = IGLOO_SMCCC_MAILBOX;
        asm volatile("hvc #0"
                     : "+r"(x0)
                     :
                     : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                       "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                       "memory");
        return;
    }
#endif
    igloo_hypercall4(IGLOO_HYPER_MAILBOX, 0, 0, 0, 0);
}

/*
 * Whether the host handles nr. The host fills the set before the mode is
 * turned on, and only adds to it afterwards; a number added while a CPU is
 * reading may be missed once, the same as a call made just before the plugin
 * registered it.
 */
static bool igloo_mb_wanted(u64 nr)
{
    const u64 *set = igloo_mb_shared + IGLOO_MB_SH_FILTER;
    unsigned int h = IGLOO_MB_FILTER_HASH(nr), i;

    if (smp_load_acquire(&igloo_mb_shared[IGLOO_MB_SH_FILTER_ON]) != 1)
        return true;
    for (i = 0; i < IGLOO_MB_FILTER_SLOTS; i++) {
        u64 v = READ_ONCE(set[(h + i) & (IGLOO_MB_FILTER_SLOTS - 1)]);

        if (v == nr)
            return true;
        if (!v)
            return false;
    }
    return true;
}

unsigned long igloo_mb_call(unsigned long nr,
                            unsigned long a0, unsigned long a1,
                            unsigned long a2, unsigned long a3,
                            unsigned long region_pa,
                            unsigned long event_pa, unsigned long event_len,
                            const char *str, int str_arg)
{
    struct igloo_mailbox *mb;
    unsigned long ret;

    if (!igloo_mb_wanted(nr))
        return a0;

    /*
     * The mailbox is per CPU and only has to hold this call's data across the
     * exit, so preemption is off only from the fill to the doorbell's return.
     */
    preempt_disable();
    mb = this_cpu_read(igloo_mb);
    mb->nr = nr;
    mb->args[0] = a0;
    mb->args[1] = a1;
    mb->args[2] = a2;
    mb->args[3] = a3;
    mb->args[4] = 0;
    mb->args[5] = 0;
    mb->ret = a0;   /* as with the register ABI, an unhandled call returns argument 0 */
    mb->region_pa = region_pa;
    mb->event_pa = event_pa;
    mb->event_len = event_len;
    if (str) {
        strlcpy((char *)mb->payload, str, IGLOO_MB_PAYLOAD_MAX);
        mb->str_arg = str_arg;
    } else {
        mb->str_arg = 0;
    }
    mb->seq++;
    igloo_mb_doorbell();   /* the asm's "memory" clobber orders the fill and the read */
    ret = mb->ret;
    preempt_enable();
    return ret;
}

static void igloo_mb_register_this_cpu(void *unused)
{
    struct igloo_mailbox *mb = this_cpu_read(igloo_mb);

    this_cpu_write(igloo_mb_reg_ret,
                   (int)igloo_hypercall4(IGLOO_HYPER_REGISTER_MAILBOX,
                                         (unsigned long)virt_to_phys(mb),
                                         (unsigned long)virt_to_phys(igloo_mb_shared),
                                         smp_processor_id(),
                                         sizeof(struct igloo_mailbox)));
}

int igloo_mailbox_init(void)
{
    int cpu, mode = INT_MAX;

    if (!mailbox)
        return 0;

    igloo_mb_shared = (u64 *)get_zeroed_page(GFP_KERNEL);
    if (!igloo_mb_shared)
        return 0;

    for_each_possible_cpu(cpu) {
        struct igloo_mailbox *mb = (struct igloo_mailbox *)get_zeroed_page(GFP_KERNEL);

        if (!mb)
            return 0;   /* stays IGLOO_MB_OFF; the pages are tiny, so leaking them is fine */
        memcpy(mb->magic, "IGLOOMB1", 8);
        per_cpu(igloo_mb, cpu) = mb;
        per_cpu(igloo_mb_reg_ret, cpu) = IGLOO_MB_OFF;
    }

    /*
     * Register from each CPU, so the host can key the mailbox by the vCPU
     * that exits. A register-ABI host answers an unknown number with argument
     * 0, a physical address, which is never a valid mode.
     */
    on_each_cpu(igloo_mb_register_this_cpu, NULL, 1);
    for_each_online_cpu(cpu) {
        int r = per_cpu(igloo_mb_reg_ret, cpu);

        if (r != IGLOO_MB_HC && r != IGLOO_MB_HVC)
            r = IGLOO_MB_OFF;
        if (r < mode)
            mode = r;
    }
    if (mode == INT_MAX)
        mode = IGLOO_MB_OFF;
#ifndef CONFIG_ARM64
    if (mode == IGLOO_MB_HVC)
        mode = IGLOO_MB_OFF;
#endif
    WRITE_ONCE(igloo_mb_mode, mode);
    printk(KERN_INFO "IGLOO: hypercall mailbox mode %d\n", mode);
    return 0;
}
