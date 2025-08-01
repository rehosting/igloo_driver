#include "portal_internal.h"
#include <linux/uaccess.h>
#include <linux/mm.h>     /* For access_ok */

/* Helper function to determine if an address is in kernel space */
bool igloo_is_kernel_addr(unsigned long addr)
{
#if defined(CONFIG_ARM64)
    /* ARM64: Use proper macros from the kernel for address space checking */
    /* VA_BITS is typically 48 or 39 in ARM64 kernels */
    /* Kernel addresses have the high bits set like 0xffff... */
    unsigned long high_bits_mask = ~((1UL << VA_BITS) - 1);
    return (addr & high_bits_mask) == high_bits_mask;
    
#elif defined(CONFIG_X86_64)
    return (addr >= PAGE_OFFSET);
    
#elif defined(CONFIG_RISCV)
    return (addr >= KERNEL_LINK_ADDR);
    
#elif defined(CONFIG_PPC)
    return is_kernel_addr(addr);
    
#elif defined(CONFIG_MIPS)
    /* Handle both MIPS32 and MIPS64 */
    #if defined(CONFIG_64BIT)
        /* MIPS64: Very broad check for kernel address space */
        /* Kernel addresses have the most significant bit set on MIPS64 
           and are typically in the range 0xffffffff8xxxxxxx */
        return (addr >> 63) != 0; /* Check the MSB is set (sign bit) */
    #else
        /* MIPS32: Check for kernel address space (0x8/0x9/0xa/0xc) */
        return (addr >= 0x80000000);
    #endif
    
#else
    /* For other architectures, use a safer method that doesn't depend on specific memory protections */
    /* First try checking address_ok which is safer than the access_ok test we were using */
    if (addr >= TASK_SIZE)
        return true;
        
    /* Fallback to the old method if TASK_SIZE isn't defined */
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

// Handler for reading an array of pointers to null-terminated strings, terminated by a NULL pointer
// Returns: header.size = number of strings included, header.addr = 1 if more remain, 0 if all included
void handle_op_read_ptr_array(portal_region *mem_region)
{
    unsigned long ptr_array_addr = mem_region->header.addr;
    size_t max_buf = CHUNK_SIZE;
    size_t buf_offset = 0;
    unsigned long user_ptr;
    char *buf = PORTAL_DATA(mem_region);
    unsigned long __user *user_ptr_array = (unsigned long __user *)ptr_array_addr;
    char tmp[128];
    int ret;

    while (buf_offset < max_buf) {
        // Read pointer from user or kernel
        if (igloo_is_kernel_addr((unsigned long)user_ptr_array)) {
            user_ptr = *(unsigned long *)user_ptr_array;
        } else {
            if (copy_from_user(&user_ptr, user_ptr_array, sizeof(unsigned long)))
                break;
        }
        if (!user_ptr)
            break;
        // Read string from pointer
        if (igloo_is_kernel_addr(user_ptr)) {
            strncpy(tmp, (const char *)user_ptr, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
        } else {
            ret = strncpy_from_user(tmp, (const char __user *)user_ptr, sizeof(tmp) - 1);
            if (ret < 0) break;
            tmp[sizeof(tmp) - 1] = '\0';
        }
        size_t len = strnlen(tmp, sizeof(tmp));
        if (buf_offset + len + 1 > max_buf) {
            break;
        }
        memcpy(buf + buf_offset, tmp, len);
        buf[buf_offset + len] = '\0';
        buf_offset += len + 1;
        user_ptr_array++;
    }
    mem_region->header.size = buf_offset;
    mem_region->header.op = HYPER_RESP_READ_OK;
}
