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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IGLOO Kernel Inspection/Interventions");
MODULE_VERSION("0.1");

/**
 * These will not work if this module isn't built-in
 */
unsigned long igloo_task_size = 0;
static int __init early_igloo_task_size(char *p)
{
    unsigned long task_size;
    if (kstrtoul(p, 0, &task_size) < 0 ) {
        pr_warn("Could not parse igloo_task_size parameter %s\n", p);
        return -1;
    }
    igloo_task_size = task_size;
    pr_warn_once("Using igloo_task_size: 0x%lx\n", igloo_task_size);
    return 0;
}
early_param("igloo_task_size", early_igloo_task_size);

bool igloo_do_hc = true;
static int __init early_igloo_do_hc(char *p)
{
    unsigned long do_hc;
    if (kstrtoul(p, 0, &do_hc) < 0 ) {
        pr_warn("Could not parse igloo_do_hc parameter %s\n", p);
        return -1;
    }
	igloo_do_hc = (do_hc > 0);
    pr_warn_once("Using igloo_do_hc: %d\n", igloo_do_hc);
    return 0;
}
early_param("igloo_do_hc", early_igloo_do_hc);

bool igloo_log_cov = false;
static int __init early_igloo_log_cov(char *p)
{
    unsigned long log_cov;
    if (kstrtoul(p, 0, &log_cov) < 0 ) {
        pr_warn("Could not parse igloo_log_cov parameter %s\n", p);
        return -1;
    }
	igloo_log_cov = (log_cov > 0);
    pr_warn_once("Using igloo_log_cov: %d\n", igloo_log_cov);
    return 0;
}
early_param("igloo_log_cov", early_igloo_log_cov);

/* Register probes for mmap and munmap */
static int __init igloo_hc_init(void) {
	printk(KERN_EMERG "IGLOO: Initializing\n");
	int ret = 0;
	if ((ret = vma_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register vma_hc\n");
		return ret;
	}
	if ((ret = syscalls_hc_init()) != 0) {
		printk(KERN_ERR "Failed to register syscalls_hc returning %d\n", ret);
		return ret;
	}

    if ((ret = osi_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register osi_hc\n");
        return ret;
    }
	return 0;
}
bool igloo_block_halt=false;

static int __init early_igloo_block_halt(char *p)
{
    unsigned long block_halt;
    if (kstrtoul(p, 0, &block_halt) < 0 ) {
        pr_warn("Could not parse igloo_block_halt parameter %s. Set to 0 (default) or 1\n", p);
        return -1;
    }
    igloo_block_halt = (block_halt > 0);
    pr_warn_once("Using igloo_block_halt: %d\n", igloo_block_halt);
    return 0;
}

early_param("igloo_block_halt", early_igloo_block_halt);

/* Unregister probes */
static void __exit igloo_hc_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(igloo_hc_init);
module_exit(igloo_hc_exit);
