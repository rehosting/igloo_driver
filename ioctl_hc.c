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
#include <trace/syscall.h>
#include <linux/utsname.h>
#include "ioctl_hc.h"


/**
 * Called from hyperfs_ioctl in fs/hyperfs/hyperfs.c
 */
void igloo_ioctl(int error, struct file *filp, unsigned int cmd) {
    if (!igloo_do_hc){
	    return;
    }
    if (error == -ENOTTY) {
        char *path;
        char *path_buffer = kmalloc(PATH_MAX, GFP_KERNEL);

        if (path_buffer == NULL) {
            // Handle error in allocating memory for path buffer
            printk(KERN_ERR "IGLOO ioctl: failed to allocate memory for path buffer\n");
            return;
        }
    
        // Attempt to resolve the file path
        path = d_path(&filp->f_path, path_buffer, PATH_MAX);
        if (IS_ERR(path)) {
            // Handle error in resolving path, maybe log this condition
            printk(KERN_ERR "IGLOO ioctl: failed to resolve file path\n");
        } else {
            // Log the path and the cmd that led to the -ENOTTY error
            int hrv;
            while (1) {
                hrv = igloo_hypercall2(IGLOO_IOCTL_ENOTTY, (unsigned long)path, cmd);
                if (hrv == 1) {
                    // Here, ensure path is logged if needed
                    printk(KERN_INFO "IGLOO ioctl: retry hc- path: %s\n", path);
                    continue;
                }
                break;
            }
        }
        kfree(path_buffer);
    }
}