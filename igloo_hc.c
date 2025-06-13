#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "igloo.h"
#include <linux/unistd.h>
#include "vma_hc.h"
#include "syscalls_hc.h"
#include "osi_hc.h"
#include "portal/portal.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IGLOO Kernel Inspection/Interventions");
MODULE_VERSION("0.1");

/* Register probes for mmap and munmap */
static int __init igloo_hc_init(void) {
	printk(KERN_EMERG "IGLOO: Initializing\n");
	int ret = 0;
	if ((ret = vma_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register vma_hc\n");
		return ret;
	}

    if ((ret = osi_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register osi_hc\n");
        return ret;
    }

    if ((ret = syscalls_hc_init()) != 0) {
		printk(KERN_ERR "Failed to register syscalls_hc returning %d\n", ret);
		return ret;
	}

    if ((ret = igloo_portal_init()) != 0) {
		printk(KERN_ERR "Failed to register igloo_portal returning %d\n", ret);
		return ret;
	}
	return 0;
}

/* Unregister probes */
static void __exit igloo_hc_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(igloo_hc_init);
module_exit(igloo_hc_exit);
