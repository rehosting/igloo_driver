#include "portal_internal.h"

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

void handle_op_dump(portal_region *mem_region)
{
    igloo_pr_debug("igloo: Handling HYPER_OP_DUMP\n");
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PID");
    mem_region->header.size = do_snapshot_and_coredump();
    mem_region->header.op = HYPER_RESP_READ_NUM;
}