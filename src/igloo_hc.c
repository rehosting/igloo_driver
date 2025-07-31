#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kmod.h>     // for request_module
#include <linux/delay.h>    // for msleep if needed
#include "igloo.h"
#include <linux/unistd.h>
#include "syscalls_hc.h"
#include "portal/portal.h"
#include "hypercall.h"
#include "igloo_hypercall_consts.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IGLOO Kernel Inspection/Interventions");
MODULE_VERSION("0.1");
MODULE_SOFTDEP("post: hyperfs");  // Load hyperfs after igloo
extern int hyperfs_init(void) __attribute__((weak)); // HyperFS init function

/**
 * Report the base address of the module by picking a function in the .text
 * section (just not init or exit)
 */
static void report_base_addr(void){
    unsigned long igloo_hc_addr = kallsyms_lookup_name("igloo_test_function");
    igloo_hypercall(IGLOO_MODULE_BASE, igloo_hc_addr);
}

/* Forward declarations for init functions */
int syscalls_hc_init(void);
int ioctl_hc_init(void);
int sock_hc_init(void);
int uname_hc_init(void);
int block_mounts_init(void);
int igloo_open_init(void);

/* Register probes for mmap and munmap */
static int __init igloo_hc_init(void) {
    printk(KERN_EMERG "IGLOO: Initializing\n");
    int ret = 0;
    report_base_addr();

    if ((ret = syscalls_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register syscalls_hc returning %d\n", ret);
        return ret;
    }

    if ((ret = ioctl_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register ioctl_hc returning %d\n", ret);
        return ret;
    }

    if ((ret = sock_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register sock_hc returning %d\n", ret);
        return ret;
    }

    if ((ret = uname_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register uname_hc returning %d\n", ret);
        return ret;
    }

    if ((ret = igloo_portal_init()) != 0) {
        printk(KERN_ERR "Failed to register igloo_portal returning %d\n", ret);
        return ret;
    }

    if ((ret = block_mounts_init()) != 0) {
        printk(KERN_ERR "Failed to register block_mounts returning %d\n", ret);
        return ret;
    }

    if ((ret = igloo_open_init()) != 0) {
        printk(KERN_ERR "Failed to register igloo_open returning %d\n", ret);
        return ret;
    }

    /* Now, load hyperfs if not already loaded */
	if ((ret = hyperfs_init()) != 0) {
		printk(KERN_ERR "Failed to initialize hyperfs, returning %d\n", ret);
        return ret;
    }
    igloo_portal(IGLOO_INIT_MODULE, 0, 0);
    return 0;
}

/* Unregister probes */
static void __exit igloo_hc_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(igloo_hc_init);
module_exit(igloo_hc_exit);
