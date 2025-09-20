#include "portal_internal.h"
#include <linux/version.h>
#include <linux/sched.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
static long do_snapshot_and_coredump(void)
{
    pid_t child_kpid_from_clone;
    struct pid *actual_child_pid_struct = NULL;
    long syscall_ret_val;

    struct kernel_clone_args args = {
        .exit_signal = SIGCHLD, // Keep for stability testing
    };

    printk(KERN_DEBUG "snapshot_module: (MinimalParent) Calling kernel_clone with exit_signal=%lu\n", (unsigned long)args.exit_signal);
    child_kpid_from_clone = kernel_clone(&args); // Assuming returns pid_t
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) kernel_clone returned kernel PID %d\n", child_kpid_from_clone);

    if (child_kpid_from_clone < 0) {
        syscall_ret_val = child_kpid_from_clone;
        printk(KERN_WARNING "snapshot_module: (MinimalParent) kernel_clone returned error %ld\n", syscall_ret_val);
        return syscall_ret_val;
    }
    if (child_kpid_from_clone == 0) {
        printk(KERN_WARNING "snapshot_module: (MinimalParent) kernel_clone returned PID 0, unexpected.\n");
        return -EFAULT;
    }

    actual_child_pid_struct = find_get_pid(child_kpid_from_clone);
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) find_get_pid(%d) returned struct pid pointer: %p\n", child_kpid_from_clone, actual_child_pid_struct);
    if (!actual_child_pid_struct) {
        printk(KERN_WARNING "snapshot_module: (MinimalParent) find_get_pid failed for kernel PID %d\n", child_kpid_from_clone);
        return -ESRCH;
    }

    {
        struct kernel_siginfo info;
        memset(&info, 0, sizeof(struct kernel_siginfo));
        info.si_signo = SIGABRT;
        info.si_code = SI_KERNEL;

        printk(KERN_DEBUG "snapshot_module: (MinimalParent) Sending SIGABRT to child (kernel PID %d, struct pid %p)\n",
               child_kpid_from_clone, actual_child_pid_struct);
        if (kill_pid_info(SIGABRT, &info, actual_child_pid_struct) < 0) {
            printk(KERN_WARNING "snapshot_module: (MinimalParent) kill_pid_info failed for child kernel PID %d\n", child_kpid_from_clone);
        } else {
            printk(KERN_DEBUG "snapshot_module: (MinimalParent) kill_pid_info for SIGABRT sent successfully to child kernel PID %d\n", child_kpid_from_clone);
        }
    }

    // Use child_kpid_from_clone for the KERN_INFO log as we don't have vnr without task_struct
    printk(KERN_INFO "snapshot_module: (MinimalParent) Parent PID %d forked. Child kernel PID %d sent SIGABRT.\n",
           task_pid_vnr(current), child_kpid_from_clone);

    syscall_ret_val = child_kpid_from_clone;

    // Only put the pid_struct reference
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) About to call put_pid(%p) for child pid struct.\n", actual_child_pid_struct);
    put_pid(actual_child_pid_struct);
    // NO put_task_struct(child_task);

    printk(KERN_DEBUG "snapshot_module: (MinimalParent) Exiting, returning %ld.\n", syscall_ret_val);
    return syscall_ret_val;
}
#else
static long do_snapshot_and_coredump(void)
{
    printk(KERN_WARNING "snapshot_module: do_snapshot_and_coredump is not supported on this kernel version.\n");
    return -ENOSYS;
}
#endif

// New function to just send SIGABRT to current process
static long do_self_abort(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    struct kernel_siginfo info;
#else
    struct siginfo info;
#endif
    
    printk(KERN_DEBUG "snapshot_module: Sending SIGABRT to self (PID %d)\n", 
           task_pid_vnr(current));
           
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGABRT;
    info.si_code = SI_KERNEL;
    
    if (send_sig_info(SIGABRT, &info, current) < 0) {
        printk(KERN_WARNING "snapshot_module: Failed to send SIGABRT to self\n");
        return -EFAULT;
    }
    
    printk(KERN_INFO "snapshot_module: SIGABRT sent successfully to self (PID %d)\n", 
           task_pid_vnr(current));
           
    return task_pid_vnr(current);
}

// New function to send a custom signal to current process
static long do_self_signal(int signal)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    struct kernel_siginfo info;
#else
    struct siginfo info;
#endif
    
    if (signal <= 0 || signal >= _NSIG) {
        printk(KERN_WARNING "snapshot_module: Invalid signal number: %d\n", signal);
        return -EINVAL;
    }
    
    printk(KERN_DEBUG "snapshot_module: Sending signal %d to self (PID %d)\n", 
           signal, task_pid_vnr(current));
           
    memset(&info, 0, sizeof(info));
    info.si_signo = signal;
    info.si_code = SI_KERNEL;
    
    if (send_sig_info(signal, &info, current) < 0) {
        printk(KERN_WARNING "snapshot_module: Failed to send signal %d to self\n", signal);
        return -EFAULT;
    }
    
    printk(KERN_INFO "snapshot_module: Signal %d sent successfully to self (PID %d)\n", 
           signal, task_pid_vnr(current));
           
    return task_pid_vnr(current);
}

void handle_op_dump(portal_region *mem_region)
{
    unsigned int dump_mode = 0;
    int signal = 0;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_DUMP\n");
    
    // Check if we have a mode specified in the header's addr field
    dump_mode = mem_region->header.addr & 0xFF;  // Lower 8 bits for mode
    signal = (mem_region->header.addr >> 8) & 0xFF;  // Next 8 bits for signal number
    
    igloo_pr_debug("igloo: Dump mode: %u, Signal: %d\n", dump_mode, signal);
    
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PID");
    
    // Select appropriate dump mode
    switch (dump_mode) {
        case 0: // Default - full snapshot and coredump
            mem_region->header.size = do_snapshot_and_coredump();
            break;
            
        case 1: // Self abort - just send SIGABRT to current process
            mem_region->header.size = do_self_abort();
            break;
            
        case 2: // Custom signal - send specified signal to current process
            mem_region->header.size = do_self_signal(signal);
            break;
            
        default: // Unknown mode - use default
            printk(KERN_WARNING "snapshot_module: Unknown dump mode %u, using default\n", dump_mode);
            mem_region->header.size = do_snapshot_and_coredump();
            break;
    }
    
    mem_region->header.op = HYPER_RESP_READ_NUM;
}