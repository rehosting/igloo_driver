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
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "kprobe_syscalls.h"


// Helper function to register kretprobe with different syscall naming conventions
int register_syscall_kretprobe(struct kretprobe *krp, const char *syscall_name) {
    int ret;
    char buffer[256];
    
    // Array of prefix patterns to try (empty string = no prefix)
    const char *prefixes[] = {
                "",                     // No prefix 
                "__x64_",           // x86_64 syscall prefix
                "__ia32_",          // x86_32 compat syscalls
                "__arm64_",         // ARM64 syscalls
                "__arm_",           // ARM syscalls
                "__se_",            // Syscall wrappers
                "__do_",            // Some syscall implementations
                "__riscv_",         // RISC-V syscalls
                "__s390_",          // s390 syscalls
                "__s390x_",         // s390x syscalls
                "__aarch64_",       // Another ARM64 convention
                "__se_",            // syscall_wrapper.h for x86
                "__se_compat_",     // compat syscall for x86
                "__riscv_",         // syscall_wrapper.h for riscv
                "__riscv_compat",   // compat syscall for riscv
                "__x64_",
                "__ia32_",
                "__s390_",          // syscall_wrapper.h for s390
                "__s390_compat",    // compat syscall for s390
                "___",              // Triple underscore prefix seen in some kernels
            };
    int num_prefixes = sizeof(prefixes) / sizeof(prefixes[0]);
    int i;
    
    for (i = 0; i < num_prefixes; i++) {
        // Format the symbol name with the current prefix
        if (prefixes[i][0] == '\0') {
            // No prefix case
            krp->kp.symbol_name = kstrdup(syscall_name, GFP_KERNEL);
        } else {
            snprintf(buffer, sizeof(buffer), "%s%s", prefixes[i], syscall_name);
            krp->kp.symbol_name = kstrdup(buffer, GFP_KERNEL);
        }
        
        if (!krp->kp.symbol_name) {
            return -ENOMEM;
        }
        
        ret = register_kretprobe(krp);
        if (ret >= 0) {
            printk(KERN_DEBUG "IGLOO: Successfully registered kretprobe for %s\n", krp->kp.symbol_name);
            return ret;  // Success
        }
        
        // For EINVAL (-22), the symbol wasn't found, try the next prefix
        if (ret == -EINVAL && i < num_prefixes - 1) {
            kfree(krp->kp.symbol_name);
            continue;
        }
        
        kfree(krp->kp.symbol_name);
    }
    
    // No valid symbol found - set to NULL to avoid issues
    krp->kp.symbol_name = NULL;
    return ret;
}