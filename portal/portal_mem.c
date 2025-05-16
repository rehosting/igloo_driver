#include "portal_internal.h"
#include <linux/uaccess.h>
#include <linux/mm.h>     /* For access_ok */

/* Helper function to determine if an address is in kernel space */
static inline bool igloo_is_kernel_addr(unsigned long addr)
{
#ifdef CONFIG_ARM64
    return (addr >= MODULES_VADDR);
#elif defined(CONFIG_X86_64)
    return (addr >= PAGE_OFFSET);
#elif defined(CONFIG_RISCV)
    return (addr >= KERNEL_LINK_ADDR);
#elif defined(CONFIG_PPC)
    return is_kernel_addr(addr);
#else
    /* For other architectures, use a generic test based on access_ok */
    return !(access_ok(((void __user *)(uintptr_t)addr), 1));
#endif
}

struct task_struct *get_target_task_by_id(portal_region* mem_region)
{
    pid_t target_pid = (pid_t)(mem_region->header.pid);
    struct task_struct *task;
    // If addr is 0, use current process, otherwise find process by PID
    if (target_pid == CURRENT_PID_NUM) {
        igloo_pr_debug("igloo: Using current task (pid=%d)\n", current->pid);
        task = current;
    } else {
        igloo_pr_debug("igloo: Looking for task with pid=%d\n", target_pid);
        // Find task by PID
        rcu_read_lock();
        task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        rcu_read_unlock();
    }
    return task;
}

void handle_op_read(portal_region *mem_region)
{
    int resp;
    unsigned long addr = mem_region->header.addr;
    size_t size = mem_region->header.size;
    bool is_kernel_address = igloo_is_kernel_addr(addr);
    
    igloo_pr_debug("igloo: Handling HYPER_OP_READ: addr=%#llx, size=%#llx\n",
        (unsigned long long)addr, (unsigned long long)size);
    
    if (is_kernel_address) {
        // Handle kernel memory - directly copy with memcpy
        igloo_pr_debug("igloo: Reading from kernel address %#lx, size %zu\n", addr, size);
        if (size > CHUNK_SIZE) {
            igloo_pr_debug("igloo: Requested size too large, truncating to %zu\n", (size_t)CHUNK_SIZE);
            size = CHUNK_SIZE;
        }
        
        // Only access memory we think is valid
        if (virt_addr_valid((void *)addr)) {
            // Use memcpy with safety precautions
            unsigned long flags;
            local_irq_save(flags);
            pagefault_disable();
            memcpy(PORTAL_DATA(mem_region), (void *)addr, size);
            pagefault_enable();
            local_irq_restore(flags);
            
            mem_region->header.op = HYPER_RESP_READ_OK;
            mem_region->header.size = size;
        } else {
            igloo_pr_debug("igloo: Invalid kernel address %#lx\n", addr);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
        }
    } else {
        // Handle user memory - use copy_from_user
        resp = copy_from_user(
            (void*)PORTAL_DATA(mem_region),
            (const void __user *)(uintptr_t)addr,
            size);
        if (resp == 0) {
            mem_region->header.op = HYPER_RESP_READ_OK;
        } else if (resp > 0) {
            igloo_pr_debug(
                "igloo: copy_from_user partially failed for addr %#lx, size %zu, resp %d\n",
                addr, size, resp);
            mem_region->header.op = HYPER_RESP_READ_PARTIAL;
            mem_region->header.size = (size - resp);
        } else {
            igloo_pr_debug(
                "igloo: copy_from_user failed for addr %#lx, size %zu, resp %d\n",
                addr, size, resp);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
        }
    }
}

void handle_op_write(portal_region *mem_region)
{
    int resp;
    unsigned long addr = mem_region->header.addr;
    size_t size = mem_region->header.size;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_WRITE: addr=%#llx, size=%#llx\n",
        (unsigned long long)addr, (unsigned long long)size);
    
    if (igloo_is_kernel_addr(addr)) {
        // Handle kernel memory writes - use memcpy, but with caution
        igloo_pr_debug("igloo: Writing to kernel address %#lx, size %zu\n", addr, size);
        
        if (size > CHUNK_SIZE) {
            igloo_pr_debug("igloo: Requested size too large, truncating to %zu\n", (size_t)CHUNK_SIZE);
            size = CHUNK_SIZE;
        }
        
        // Only write to memory we think is valid and writable
        if (virt_addr_valid((void *)addr)) {
            // Use memcpy with safety precautions
            unsigned long flags;
            local_irq_save(flags);
            pagefault_disable();
            memcpy((void *)addr, PORTAL_DATA(mem_region), size);
            pagefault_enable();
            local_irq_restore(flags);
            
            igloo_pr_debug("igloo: Successfully wrote to kernel address %#lx\n", addr);
            mem_region->header.op = HYPER_RESP_WRITE_OK;
        } else {
            igloo_pr_debug("igloo: Invalid kernel address %#lx\n", addr);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        }
    } else {
        // Handle user memory writes - use copy_to_user
        resp = copy_to_user(
            (void __user *)(uintptr_t)addr,
            PORTAL_DATA(mem_region),
            size);
        
        if (resp == 0) {
            igloo_pr_debug("igloo: Successfully wrote to user address %#lx\n", addr);
            mem_region->header.op = HYPER_RESP_WRITE_OK;
        } else {
            igloo_pr_debug(
                "igloo: copy_to_user failed for addr %#lx, size %zu, resp %d\n",
                addr, size, resp);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        }
    }
}

void handle_op_read_str(portal_region *mem_region)
{
    unsigned long addr = (mem_region->header.addr);
    unsigned long max_size = (mem_region->header.size);
    ssize_t copied = 0;
    char *buf = PORTAL_DATA(mem_region);

    if (max_size == 0 || max_size > CHUNK_SIZE - 1){
        max_size = CHUNK_SIZE - 1;
    }
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_STR: addr=%#lx, max_size=%lu\n", addr, max_size);

    if (igloo_is_kernel_addr(addr)) {
        // Handle kernel string - use strlcpy with safety checks
        igloo_pr_debug("igloo: Reading string from kernel address %#lx\n", addr);
        
        if (!virt_addr_valid((void *)addr)) {
            igloo_pr_debug("igloo: Invalid kernel address %#lx\n", addr);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            mem_region->header.size = 0;
            return;
        }
        
        // For kernel addresses, we'll use pagefault_disable/enable for safety
        {
            unsigned long flags;
            local_irq_save(flags);
            pagefault_disable();
            // Try reading the first byte to check for access
            buf[0] = *((const char *)addr);
            pagefault_enable();
            local_irq_restore(flags);
        }
        
        // Safely copy the kernel string with pagefault protection
        {
            unsigned long flags;
            local_irq_save(flags);
            pagefault_disable();
            
            // First calculate the string length (up to max_size)
            copied = strnlen((const char *)addr, max_size);
            
            if (copied == max_size) {
                // String is longer than or equal to max_size
                memcpy(buf, (const char *)addr, max_size - 1);
                buf[max_size - 1] = '\0';
                copied = max_size - 1;
            } else {
                // String fits in buffer
                memcpy(buf, (const char *)addr, copied + 1); // Include null terminator
            }
            
            pagefault_enable();
            local_irq_restore(flags);
        }
        
        igloo_pr_debug("igloo: Read kernel string (len=%zd)\n", copied);
        mem_region->header.size = (copied);
        mem_region->header.op = (HYPER_RESP_READ_OK);
    } else {
        // Handle user string - use strncpy_from_user
        copied = strncpy_from_user(buf, (const char __user *)addr, max_size);
        if (copied < 0) {
            igloo_pr_debug("igloo: strncpy_from_user failed for addr %#lx, max_size %lu, ret %zd\n",
                          addr, max_size, copied);
            mem_region->header.op = (HYPER_RESP_READ_FAIL);
            mem_region->header.size = 0;
        } else {
            mem_region->header.size = (copied);
            mem_region->header.op = (HYPER_RESP_READ_OK);
            igloo_pr_debug("igloo: Read user string (len=%zd)\n", copied);
            
            // Ensure proper null termination
            if (copied < CHUNK_SIZE) {
                buf[copied] = '\0';
            } else {
                buf[CHUNK_SIZE - 1] = '\0';
            }
        }
    }
}
