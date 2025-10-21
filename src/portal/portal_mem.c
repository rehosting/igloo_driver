#include "portal_internal.h"
#include <linux/uaccess.h>
#include <linux/mm.h>     /* For access_ok */
#include <linux/thread_info.h>  /* For test_thread_flag */
#include <linux/compat.h>        /* For CONFIG_COMPAT */
#include <linux/version.h>

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
    /* RISC-V kernel virtual address space check */
    #if defined(CONFIG_64BIT)
        /* For RISC-V 64-bit, kernel addresses are in the upper half */
        /* Check if address is in kernel virtual address space */
        /* RISC-V uses canonical addresses where kernel space starts high */
        return (addr >= KERNEL_LINK_ADDR) || (addr >= PAGE_OFFSET);
    #else
        /* RISC-V 32-bit */
        return (addr >= PAGE_OFFSET);
    #endif
    
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
    #ifndef VERIFY_READ
    #define VERIFY_READ 0
    #endif
    /* Use correct access_ok arity for kernel version */
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
        return !(access_ok(VERIFY_READ, ((void __user *)(uintptr_t)addr), 1));
    #else
        return !(access_ok(((void __user *)(uintptr_t)addr), 1));
    #endif
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

// Helper for safe access_remote_vm with mmap_sem for old kernels
static ssize_t igloo_access_remote_vm(struct task_struct *task, struct mm_struct *mm, unsigned long addr, void *buf, size_t len, int flags)
{
    ssize_t ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0)
    if (!down_read_trylock(&mm->mmap_lock)) {
        igloo_pr_debug("igloo: Failed to trylock mmap_lock for portal_access_remote_vm\n");
        return -EAGAIN;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
    ret = access_remote_vm(task, mm, addr, buf, len, flags);
#else
    ret = access_remote_vm(mm, addr, buf, len, flags);
#endif
    up_read(&mm->mmap_lock);
#else
    if (!down_read_trylock(&mm->mmap_sem)) {
        igloo_pr_debug("igloo: Failed to trylock mmap_sem for portal_access_remote_vm\n");
        return -EAGAIN;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
    ret = access_remote_vm(task, mm, addr, buf, len, flags);
#else
    ret = access_remote_vm(mm, addr, buf, len, flags);
#endif
    up_read(&mm->mmap_sem);
#endif

    return ret;
}


static unsigned long igloo_copy_from_user_task(void *to, const void __user *from, unsigned long n, struct task_struct *task)
{
    struct mm_struct *mm = task->mm;

    if (!mm)
        return n; // Kernel thread, all bytes fail

    if (mm == current->mm) {
        return copy_from_user(to, from, n);
    } else {
        ssize_t ret;

        // We need to get our own reference to the mm_struct
        mm = get_task_mm(task);
        if (!mm)
            return n; // All bytes fail

        ret = igloo_access_remote_vm(task, mm, (unsigned long)from, to, n, 0);
        mmput(mm);

        if (ret < 0)
            return n; // All bytes failed

        return n - ret; // Return uncopied bytes
    }
}

static unsigned long igloo_copy_to_user_task(void __user *to, const void *from, unsigned long n, struct task_struct *task)
{
    struct mm_struct *mm = task->mm;

    if (!mm)
        return n; // Kernel thread, all bytes fail

    if (mm == current->mm) {
        return copy_to_user(to, from, n);
    } else {
        ssize_t ret;

        // We need to get our own reference to the mm_struct
        mm = get_task_mm(task);
        if (!mm)
            return n;

        ret = igloo_access_remote_vm(task, mm, (unsigned long)to, (void *)from, n, FOLL_WRITE);
        mmput(mm);

        if (ret < 0)
            return n;

        return n - ret;
    }
}

static int igloo_read_kernel_memory(unsigned long addr, void *buf, size_t size, bool is_string)
{
    ssize_t copied;
    unsigned long flags;

    if (!virt_addr_valid((void *)addr)) return -EFAULT;

    local_irq_save(flags);
    pagefault_disable();
    if (is_string) {
        copied = strnlen((const char *)addr, size);
        memcpy(buf, (const char *)addr, copied);
        if (copied < size)
            ((char *)buf)[copied] = '\0';
    } else {
        memcpy(buf, (void *)addr, size);
        copied = size;
    }
    pagefault_enable();
    local_irq_restore(flags);

    return size - copied; // 0 on success
}

static int __igloo_read_user_memory(struct task_struct *task, unsigned long addr, void *buf, size_t size, bool is_string)
{
    if (!task) return -ESRCH;

    // For current process, verify the area is accessible before trying to copy.
    // For other processes, access_remote_vm will do the checks.
    if (task->mm == current->mm) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
        if (!access_ok(VERIFY_READ, (const void __user *)addr, size))
            return -EFAULT;
#else
        if (!access_ok((const void __user *)addr, size))
            return -EFAULT;
#endif
    }

    if (is_string) {
        ssize_t copied;
        // Read byte-by-byte for strings to find null terminator safely.
        for (copied = 0; copied < size; copied++) {
            if (igloo_copy_from_user_task((char *)buf + copied, (const void __user *)(addr + copied), 1, task) != 0) {
                return size - copied; // Partial read
            }
            if (((char *)buf)[copied] == '\0') {
                break;
            }
        }
        return 0; // Returns 0 on success, `copied` has the length.
    } else {
        return igloo_copy_from_user_task(buf, (const void __user *)addr, size, task);
    }
}

int igloo_read_user_memory(struct task_struct *task, unsigned long addr, void *buf, size_t size)
{
    return __igloo_read_user_memory(task, addr, buf, size, false);
}

int igloo_read_user_string(struct task_struct *task, unsigned long addr, void *buf, size_t size)
{
    return __igloo_read_user_memory(task, addr, buf, size, true);
}

static int __igloo_read_memory(struct task_struct *task, unsigned long addr, void *buf, size_t size, bool is_string)
{
    if (igloo_is_kernel_addr(addr)) {
        return igloo_read_kernel_memory(addr, buf, size, is_string);
    }

    if (is_string) {
        return igloo_read_user_string(task, addr, buf, size);
    } else {
        return igloo_read_user_memory(task, addr, buf, size);
    }
}

int igloo_read_memory(struct task_struct *task, unsigned long addr, void *buf, size_t size)
{
    return __igloo_read_memory(task, addr, buf, size, false);
}

static int igloo_read_string(struct task_struct *task, unsigned long addr, void *buf, size_t size)
{
    return __igloo_read_memory(task, addr, buf, size, true);
}

int igloo_write_memory(struct task_struct *task, unsigned long addr, const void *buf, size_t size)
{
    if (size > CHUNK_SIZE) size = CHUNK_SIZE;

    if (igloo_is_kernel_addr(addr)) {
        unsigned long flags;
        if (!virt_addr_valid((void *)addr)) return -EFAULT;
        local_irq_save(flags);
        pagefault_disable();
        memcpy((void *)addr, buf, size);
        pagefault_enable();
        local_irq_restore(flags);
        return 0;
    }

    if (!task) return -ESRCH;

    if (task->mm == current->mm) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
        if (!access_ok(VERIFY_WRITE, (void __user *)addr, size))
            return -EFAULT;
#else
        if (!access_ok((void __user *)addr, size))
            return -EFAULT;
#endif
    }

    return igloo_copy_to_user_task((void __user *)addr, buf, size, task);
}

void handle_op_read(portal_region *mem_region)
{
    int resp;
    size_t original_size = mem_region->header.size;
    size_t size_to_read = original_size;
    struct task_struct *task;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_READ: addr=%#llx, size=%#llx\n",
        (unsigned long long)mem_region->header.addr, (unsigned long long)original_size);
    
    if (size_to_read > CHUNK_SIZE) {
        size_to_read = CHUNK_SIZE;
    }

    task = get_target_task_by_id(mem_region);
    resp = igloo_read_memory(task, mem_region->header.addr, PORTAL_DATA(mem_region), size_to_read);

    if (resp == 0) {
        mem_region->header.op = HYPER_RESP_READ_OK;
        mem_region->header.size = size_to_read;
    } else if (resp > 0 && resp < original_size) {
        igloo_pr_debug(
            "igloo: read partially failed for addr %#llx, size %zu, resp %d\n",
            (unsigned long long)mem_region->header.addr, original_size, resp);
        mem_region->header.op = HYPER_RESP_READ_PARTIAL;
        mem_region->header.size = (size_to_read - resp);
    } else {
        igloo_pr_debug(
            "igloo: read failed for addr %#llx, size %zu, resp %d\n",
            (unsigned long long)mem_region->header.addr, original_size, resp);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = 0;
    }
}

void handle_op_write(portal_region *mem_region)
{
    int resp;
    struct task_struct *task;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_WRITE: addr=%#llx, size=%#llx\n",
        (unsigned long long)mem_region->header.addr, (unsigned long long)mem_region->header.size);
    
    task = get_target_task_by_id(mem_region);
    resp = igloo_write_memory(task, mem_region->header.addr, PORTAL_DATA(mem_region), mem_region->header.size);
        
    if (resp == 0) {
        igloo_pr_debug("igloo: Successfully wrote to address %#llx\n", (unsigned long long)mem_region->header.addr);
        mem_region->header.op = HYPER_RESP_WRITE_OK;
    } else {
        igloo_pr_debug(
            "igloo: write failed for addr %#llx, size %llu, resp %d\n",
            (unsigned long long)mem_region->header.addr, (unsigned long long)mem_region->header.size, resp);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
    }
}

void handle_op_read_str(portal_region *mem_region)
{
    int resp;
    size_t max_size = mem_region->header.size;
    struct task_struct *task;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_STR: addr=%#llx, max_size=%llu\n",
                   (unsigned long long)mem_region->header.addr, (unsigned long long)max_size);

    if (max_size == 0 || max_size > CHUNK_SIZE - 1) {
        max_size = CHUNK_SIZE - 1;
    }

    task = get_target_task_by_id(mem_region);
    resp = igloo_read_string(task, mem_region->header.addr, PORTAL_DATA(mem_region), max_size);

    if (resp == 0) {
        mem_region->header.op = HYPER_RESP_READ_OK;
        // Calculate the actual length of the string read.
        mem_region->header.size = strnlen(PORTAL_DATA(mem_region), max_size);
        igloo_pr_debug("igloo: Read string (len=%llu)\n", (unsigned long long)mem_region->header.size);
        // Ensure null termination if buffer has space
        if (mem_region->header.size < CHUNK_SIZE) {
            PORTAL_DATA(mem_region)[mem_region->header.size] = '\0';
        } else {
            PORTAL_DATA(mem_region)[CHUNK_SIZE - 1] = '\0';
        }
    } else {
        igloo_pr_debug("igloo: read_str failed for addr %#llx, ret %d\n",
                      (unsigned long long)mem_region->header.addr, resp);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = 0;
    }
}

// Handler for reading an array of pointers to null-terminated strings, terminated by a NULL pointer
// Returns: header.size = number of strings included, header.addr = 1 if more remain, 0 if all included
void handle_op_read_ptr_array(portal_region *mem_region)
{
    unsigned long ptr_array_addr = mem_region->header.addr;
    size_t max_buf = CHUNK_SIZE;
    size_t buf_offset = 0;
    unsigned long user_ptr = 0;
    char *buf = PORTAL_DATA(mem_region);
    void __user *user_ptr_array = (void __user *)ptr_array_addr;
    char tmp[128];
    size_t user_ptr_size, len;
    bool is_32bit = false;
    struct task_struct *task = get_target_task_by_id(mem_region);

    /* Check if we're dealing with a 32-bit process on 64-bit kernel
     * using architecture-specific flags for 32-bit processes.
     */
#ifdef CONFIG_COMPAT
#ifdef TIF_32BIT
    is_32bit = is_32bit || test_thread_flag(TIF_32BIT);
#endif // TIF_32BIT

#ifdef TIF_32BIT_ADDR
    is_32bit = is_32bit || test_thread_flag(TIF_32BIT_ADDR);
#endif // TIF_32BIT_ADDR

#ifdef TIF_32BIT_REGS
    is_32bit = is_32bit || test_thread_flag(TIF_32BIT_REGS);
#endif // TIF_32BIT_REGS

#ifdef TIF_IA32
    is_32bit = is_32bit || test_thread_flag(TIF_IA32);
#endif // TIF_IA32

#ifdef TIF_ADDR32
    is_32bit = is_32bit || test_thread_flag(TIF_ADDR32);
#endif // TIF_ADDR32
#endif // CONFIG_COMPAT
    user_ptr_size = is_32bit ? sizeof(u32) : sizeof(unsigned long);

    while (buf_offset < max_buf) {
        // Read pointer from user or kernel
        if (igloo_is_kernel_addr((unsigned long)user_ptr_array)) {
            if (igloo_read_kernel_memory((unsigned long)user_ptr_array, &user_ptr, sizeof(user_ptr), false) != 0) break;
        } else {
            // For user addresses, handle 32-bit vs 64-bit
            if (is_32bit) {
                u32 ptr32;
                if (igloo_read_user_memory(task, (unsigned long)user_ptr_array, &ptr32, sizeof(u32)) != 0) {
                    break;
                }
                user_ptr = (unsigned long)ptr32;
            } else {
                if (igloo_read_user_memory(task, (unsigned long)user_ptr_array, &user_ptr, sizeof(unsigned long)) != 0) {
                    break;
                }
            }
        }

        if (!user_ptr)
            break;

        // Read string from pointer
        if (igloo_is_kernel_addr(user_ptr)) {
            if (igloo_read_kernel_memory(user_ptr, tmp, sizeof(tmp), true) != 0) break;
        } else {
            if (igloo_read_user_string(task, user_ptr, tmp, sizeof(tmp)) != 0) break;
        }
        len = strnlen(tmp, sizeof(tmp));
        if (buf_offset + len + 1 > max_buf) {
            break;
        }
        memcpy(buf + buf_offset, tmp, len);
        buf[buf_offset + len] = '\0';
        buf_offset += len + 1;
        user_ptr_array = (char *)user_ptr_array + user_ptr_size;
    }
    mem_region->header.size = buf_offset;
    mem_region->header.op = HYPER_RESP_READ_OK;
}
