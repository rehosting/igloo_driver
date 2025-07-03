#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "hypercall.h"
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/utsname.h>
#include <linux/types.h>
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/version.h>
#include <asm/syscall.h>
#include <linux/tracepoint.h>
#include <linux/trace_events.h>
#include <trace/events/sched.h>
#include "osi_hc.h"
#include "args.h"
#include "igloo.h"


// Define a tracepoint probe function for sched_switch with the correct signature
static void probe_sched_switch(void *data, bool preempt, struct task_struct *prev, 
                               struct task_struct *next, unsigned int prev_state)
{
    // Notify hypervisor about task switch using task pointers
    igloo_hypercall2(IGLOO_HYP_OSI_TASK_SWITCH, (unsigned long)prev, (unsigned long)next);
}

int osi_hc_init(void) {
    int ret = 0;
    
    if (!igloo_do_hc) {
        printk(KERN_ERR "IGLOO: Hypercalls disabled\n");
        return 0;
    }

    // Register the sched_switch tracepoint
    ret = register_trace_sched_switch(probe_sched_switch, NULL);
    if (ret) {
        printk(KERN_ERR "IGLOO: Failed to register sched_switch tracepoint, returned %d\n", ret);
    } else {
        printk(KERN_INFO "IGLOO: Successfully registered sched_switch tracepoint\n");
    }
    return 0;
}
