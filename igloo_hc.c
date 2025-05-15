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

// Debug logging configuration for each module
struct igloo_debug_config {
    bool portal;       // Enable debug for portal module
    bool uprobe;       // Enable debug for uprobe module
    bool vma;          // Enable debug for VMA tracking
    bool syscall;      // Enable debug for syscall tracking
    bool osi;          // Enable debug for OSI features
};

// Global debug configuration
struct igloo_debug_config igloo_debug = {
    .portal = false,
    .uprobe = false,
    .vma = false,
    .syscall = false,
    .osi = false,
};

// Parse comma-separated list of modules to enable debug logging for
static int __init early_igloo_debug_modules(char *p)
{
    char *token;
    
    // By default, all modules have debug disabled
    memset(&igloo_debug, 0, sizeof(igloo_debug));
    
    // Special case: "all" enables all modules
    if (!strcmp(p, "all")) {
        memset(&igloo_debug, 1, sizeof(igloo_debug));
        pr_warn_once("IGLOO: Debug enabled for all modules\n");
        return 0;
    }
    
    // Special case: "none" disables all modules (default)
    if (!strcmp(p, "none")) {
        memset(&igloo_debug, 0, sizeof(igloo_debug));
        pr_warn_once("IGLOO: Debug disabled for all modules\n");
        return 0;
    }
    
    // Parse comma-separated module list
    while ((token = strsep(&p, ",")) != NULL) {
        if (!strcmp(token, "portal"))
            igloo_debug.portal = true;
        else if (!strcmp(token, "uprobe"))
            igloo_debug.uprobe = true;
        else if (!strcmp(token, "vma"))
            igloo_debug.vma = true;
        else if (!strcmp(token, "syscall"))
            igloo_debug.syscall = true;
        else if (!strcmp(token, "osi"))
            igloo_debug.osi = true;
        else
            pr_warn("IGLOO: Unknown debug module: %s\n", token);
    }
    
    pr_warn_once("IGLOO: Debug modules - portal:%d uprobe:%d vma:%d syscall:%d osi:%d\n",
               igloo_debug.portal, igloo_debug.uprobe, igloo_debug.vma,
               igloo_debug.syscall, igloo_debug.osi);
    
    return 0;
}

early_param("igloo_debug", early_igloo_debug_modules);

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
