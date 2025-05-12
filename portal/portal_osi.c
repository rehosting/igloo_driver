#include "portal_internal.h"

/* Helper function to get VMA name, similar to get_vma_name in task_mmu.c */
static void portal_get_vma_name(struct vm_area_struct *vma, char *buf, size_t buf_size)
{
    struct anon_vma_name *anon_name = vma->vm_mm ? anon_vma_name(vma) : NULL;
    const char *name = NULL;

    if (vma->vm_file) {
        /*
         * If user named this anon shared memory via prctl(PR_SET_VMA ...),
         * use the provided name.
         */
        if (anon_name) {
            snprintf(buf, buf_size, "[anon_shmem:%s]", anon_name->name);
            return;
        } else {
            char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (path_buf) {
                char *path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
                if (!IS_ERR(path)) {
                    strncpy(buf, path, buf_size - 1);
                    buf[buf_size - 1] = '\0';
                } else {
                    strncpy(buf, "[unknown file]", buf_size - 1);
                    buf[buf_size - 1] = '\0';
                }
                kfree(path_buf);
            }
            return;
        }
    }

    if (vma->vm_ops && vma->vm_ops->name) {
        name = vma->vm_ops->name(vma);
        if (name) {
            strncpy(buf, name, buf_size - 1);
            buf[buf_size - 1] = '\0';
            return;
        }
    }

    name = arch_vma_name(vma);
    if (name) {
        strncpy(buf, name, buf_size - 1);
        buf[buf_size - 1] = '\0';
        return;
    }

    if (!vma->vm_mm) {
        strncpy(buf, "[vdso]", buf_size - 1);
        buf[buf_size - 1] = '\0';
        return;
    }

    if (vma_is_initial_heap(vma)) {
        strncpy(buf, "[heap]", buf_size - 1);
        buf[buf_size - 1] = '\0';
        return;
    }

    if (vma_is_initial_stack(vma)) {
        strncpy(buf, "[stack]", buf_size - 1);
        buf[buf_size - 1] = '\0';
        return;
    }

    if (anon_name) {
        snprintf(buf, buf_size, "[anon:%s]", anon_name->name);
        return;
    }

    strncpy(buf, "[anonymous]", buf_size - 1);
    buf[buf_size - 1] = '\0';
}

void handle_op_osi_proc(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct osi_proc *proc;
    char *data_buf = PORTAL_DATA(mem_region);
    size_t name_len = 0;
    size_t total_size = sizeof(struct osi_proc);

    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task immediately after getting it
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC for NULL task\n");
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC for PID %d\n", task->pid);
    
    mm = task->mm;

    // Initialize the OSI proc structure at the beginning of data buffer
    proc = (struct osi_proc *)data_buf;
    proc->taskd = cpu_to_le64((unsigned long)task);
    
    if (mm && mm->pgd) {
        proc->pgd = cpu_to_le64((unsigned long)mm->pgd);
        proc->map_count = cpu_to_le64(mm->map_count);
        proc->start_brk = cpu_to_le64(mm->start_brk);
        proc->brk = cpu_to_le64(mm->brk);
        proc->start_stack = cpu_to_le64(mm->start_stack);
        proc->start_code = cpu_to_le64(mm->start_code);
        proc->end_code = cpu_to_le64(mm->end_code);
        proc->start_data = cpu_to_le64(mm->start_data);
        proc->end_data = cpu_to_le64(mm->end_data);
        proc->arg_start = cpu_to_le64(mm->arg_start);
        proc->arg_end = cpu_to_le64(mm->arg_end);
        proc->env_start = cpu_to_le64(mm->env_start);
        proc->env_end = cpu_to_le64(mm->env_end);
        // saved_auxv is now a pointer to an array, not an integer
        proc->saved_auxv = 0; // Don't try to cast pointer to integer
        proc->mmap_base = cpu_to_le64(mm->mmap_base);
        proc->task_size = cpu_to_le64(mm->task_size);
    } else {
        proc->pgd = 0;
    }
    
    proc->pid = cpu_to_le64(task->pid);
    proc->ppid = cpu_to_le64(task->real_parent ? task->real_parent->pid : 0);
    proc->uid = cpu_to_le64(task->cred->uid.val);
    proc->gid = cpu_to_le64(task->cred->gid.val);
    proc->euid = cpu_to_le64(task->cred->euid.val);
    proc->egid = cpu_to_le64(task->cred->egid.val);
    
    // Put name after the struct
    proc->name_offset = cpu_to_le64(sizeof(struct osi_proc));
    name_len = strnlen(task->comm, TASK_COMM_LEN);
    // Ensure we don't overflow our buffer
    if (sizeof(struct osi_proc) + name_len + 1 > CHUNK_SIZE) {
        name_len = CHUNK_SIZE - sizeof(struct osi_proc) - 1;
    }
    strncpy(data_buf + sizeof(struct osi_proc), task->comm, name_len);
    data_buf[sizeof(struct osi_proc) + name_len] = '\0';
    igloo_pr_debug("igloo: proc name: %s\n", task->comm);
    igloo_pr_debug("igloo: proc name in buf: %s\n", data_buf + sizeof(struct osi_proc));
    
    total_size += name_len; // do not null terminator
    
    // Set create time
    proc->create_time = cpu_to_le64(task->start_time);
    
    mem_region->header.size = cpu_to_le64(total_size);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

void handle_op_osi_proc_handles(portal_region *mem_region)
{
    struct task_struct *task;
    struct osi_proc_handle *handle;
    int count = 0;
    size_t max_handles;
    char *data_buf = PORTAL_DATA(mem_region);
    __le64 *handles_count = (__le64 *)data_buf;

    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_HANDLES\n");
    
    // Reserve space for count at beginning
    max_handles = (CHUNK_SIZE - sizeof(__le64)) / sizeof(struct osi_proc_handle);
    
    igloo_pr_debug("osi_proc_handles: max_handles=%zu\n", max_handles);
    
    // First 8 bytes will store the count
    *handles_count = 0;
    
    // Start filling handles after count field
    handle = (struct osi_proc_handle *)(data_buf + sizeof(__le64));
    
    // Iterate through tasks
    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm;
        
        if (count >= max_handles) {
            break;
        }
        
        mm = task->mm;
        if (!mm) {
            continue; // Skip kernel threads
        }
        
        handle->taskd = cpu_to_le64((unsigned long)task);
        handle->asid = cpu_to_le64((unsigned long)(mm ? mm->pgd : 0));
        handle->start_time = cpu_to_le64(task->start_time);
        
        handle++;
        count++;
    }
    rcu_read_unlock();
    
    // Update count
    *handles_count = cpu_to_le32(count);
    
    mem_region->header.size = cpu_to_le64(sizeof(__le64) + (count * sizeof(struct osi_proc_handle)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

void handle_op_osi_mappings(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct osi_module *mapping;
    int count = 0;
    int total_count = 0;
    int skip_count;
    size_t max_mappings;
    char *data_buf = PORTAL_DATA(mem_region);
    __le64 *mappings_count = (__le64 *)data_buf;
    __le64 *total_vmas_count = (__le64 *)(data_buf + sizeof(__le64));
    char *string_buf;
    size_t string_offset;

    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task before using task->pid
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_MAPPINGS for NULL task\n");
        mem_region->header.size = cpu_to_le64(sizeof(__le64) * 2);  // Return at least the two counters
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_MAPPINGS for PID %d\n", task->pid);
    
    mm = task->mm;

    // Reserve space for count at beginning (now two counts: returned mappings and total mappings)
    max_mappings = (CHUNK_SIZE / 2) / sizeof(struct osi_module);
    
    // First 8 bytes will store the count of mappings in this response
    *mappings_count = 0;
    
    // Second 8 bytes will store the total count of VMAs in the process
    *total_vmas_count = 0;
    
    // Check if we have a valid mm_struct
    if (!mm) {
        mem_region->header.size = cpu_to_le64(sizeof(__le64) * 2);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
        return;
    }
    
    // Store total number of VMAs in the process
    *total_vmas_count = cpu_to_le64(mm->map_count);
    igloo_pr_debug("igloo: Process has %d total VMAs\n", mm->map_count);
    
    // Start filling mappings after both counts
    mapping = (struct osi_module *)(data_buf + sizeof(__le64) * 2);
    
    // String buffer starts after module structures
    string_offset = (sizeof(__le64) * 2) + (max_mappings * sizeof(struct osi_module));
    string_buf = data_buf + string_offset;
    
    // Get skip count from the header - this is how many VMAs we've already processed
    skip_count = le64_to_cpu(mem_region->header.addr);
    igloo_pr_debug("igloo: Starting VMA scan, skipping first %d entries\n", skip_count);
    
    // Iterate through the process memory mappings
    if (mmap_read_lock_killable(mm)) {
        mem_region->header.size = cpu_to_le64(sizeof(__le64) * 2);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

    // Use VMA iteration API starting from the beginning
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        char mapping_name[256] = "";
        size_t name_len;
        char *curr_str;
        
        // Skip already processed VMAs
        if (total_count < skip_count) {
            total_count++;
            continue;
        }
        
        // Check if we'll exceed our limits with this entry
        if (count >= max_mappings || 
            string_offset >= CHUNK_SIZE - 256) {
            // Store the total count of VMAs we've processed across all calls
            mem_region->header.addr = cpu_to_le64(total_count);
            igloo_pr_debug("igloo: Buffer full, processed %d VMAs total\n", total_count);
            break;
        }
        
        // Get mapping name using our helper function
        portal_get_vma_name(vma, mapping_name, sizeof(mapping_name));
        
        // Fill mapping info
        mapping->base = cpu_to_le64(vma->vm_start);
        mapping->size = cpu_to_le64(vma->vm_end - vma->vm_start);
        
        // Add mapping name to string buffer
        curr_str = string_buf;
        name_len = strlen(mapping_name);
        
        // Check if we have enough space for the name
        if (string_offset + name_len + 1 > CHUNK_SIZE) {
            // Not enough space for this entry's name, don't increment total_count
            // so we'll process this VMA in the next call
            break;
        }
        
        strncpy(curr_str, mapping_name, name_len);
        curr_str[name_len] = '\0';
        
        mapping->name_offset = cpu_to_le64(string_offset);
        string_offset += name_len + 1;
        string_buf += name_len + 1;
        
        // Use the same string for file path
        mapping->file_offset = mapping->name_offset;
        
        // Additional fields
        mapping->offset = cpu_to_le64(vma->vm_pgoff << PAGE_SHIFT);
        mapping->flags = cpu_to_le64(vma->vm_flags);
        if (vma->vm_file){
            const struct inode *inode = file_user_inode(vma->vm_file);
            mapping->pgoff = cpu_to_le64(((loff_t)vma->vm_pgoff) << PAGE_SHIFT);
            dev_t dev = inode->i_sb->s_dev;
            unsigned int major = MAJOR(dev);
            unsigned int minor = MINOR(dev);
            mapping->dev = cpu_to_le64(dev);
            mapping->inode = cpu_to_le64(inode->i_ino);
            igloo_pr_debug("igloo: VMA mapping: %s, file: %s\n", 
                   mapping_name, mapping_name);
            igloo_pr_debug("igloo: VMA mapping: %s, offset: %llx, flags: %llx\n",
                   mapping_name, (unsigned long long)vma->vm_pgoff << PAGE_SHIFT, (unsigned long long)vma->vm_flags);
            igloo_pr_debug("igloo: VMA mapping: %s, dev: %x:%x (major:minor), raw: %llx, inode: %llx\n",
                   mapping_name, major, minor, (unsigned long long)dev, (unsigned long long)mapping->inode);
        }else{
            mapping->pgoff = 0;
            mapping->dev = 0;
            mapping->inode = 0;
        }
        
        mapping++;
        count++;
        total_count++;
    }
    
    // If we processed all VMAs, set next count to 0 to indicate completion
    if (total_count >= mm->map_count) {
        mem_region->header.addr = 0;
        igloo_pr_debug("igloo: All VMAs processed\n");
    }
    
    mmap_read_unlock(mm);
    
    // Update count of mappings we're returning
    *mappings_count = cpu_to_le32(count);
    
    mem_region->header.size = cpu_to_le64(string_offset);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    
    igloo_pr_debug("igloo: Returned %d VMA mappings (total VMAs: %d), buffer used: %zu bytes\n", 
                  count, mm->map_count, string_offset);
}

void handle_op_osi_proc_mem(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct osi_proc_mem {
        __le64 start_brk;
        __le64 brk;
    };
    struct osi_proc_mem *proc_mem;
    
    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task before using task->pid
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_MEM for NULL task\n");
        proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_MEM for PID %d\n", task->pid);
    
    mm = task->mm;

    // Check if we have enough buffer space for the structure
    if (sizeof(struct osi_proc_mem) > CHUNK_SIZE) {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
    
    if (!mm) {
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem->start_brk = cpu_to_le64(mm->start_brk);
    proc_mem->brk = cpu_to_le64(mm->brk);
    
    mem_region->header.size = cpu_to_le64(sizeof(struct osi_proc_mem));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

void handle_op_read_fd_name(portal_region *mem_region)
{
    struct file *file;
    int fd_num = le64_to_cpu(mem_region->header.addr);
    
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_FD_NAME: fd=%d\n", fd_num);
    
    file = fget(fd_num);
    if (!file) {
        igloo_pr_debug("igloo: Invalid file descriptor %d\n", fd_num);
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "INVALID_FD");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        fput(file);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        igloo_pr_debug("igloo: Failed to get file path, error=%ld\n", PTR_ERR(path));
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PATH");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    } else {
        size_t len = strlen(path);
        size_t copy_len = min_t(size_t, len, CHUNK_SIZE-1);
        
        igloo_pr_debug("igloo: File path for fd %d is '%s'\n", fd_num, path);
        memcpy(PORTAL_DATA(mem_region), path, copy_len);
        PORTAL_DATA(mem_region)[copy_len] = '\0';
        mem_region->header.size = cpu_to_le64(copy_len);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    }
    
    kfree(path_buf);
    fput(file);
}

void handle_op_read_procargs(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long arg_start, arg_end, len;
    char *buf = PORTAL_DATA(mem_region);
    int ret;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCARGS (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");
    
    if (!task){
        igloo_pr_debug("igloo: No task found for pid %d\n", le64_to_cpu(mem_region->header.addr));
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_TASK");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

    if (!mm || !mm->arg_end || !mm->arg_start || mm->arg_end <= mm->arg_start) {
        goto fail;
    }

    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    len = arg_end - arg_start;

    // Ensure we don't overflow our buffer, leave space for null terminator
    if (len >= CHUNK_SIZE) {
        len = CHUNK_SIZE - 1;
        igloo_pr_debug("igloo: procargs truncated to %lu bytes\n", len);
    }

    // Use different methods based on whether we're accessing current task or another task
    if (task != current) {
        // For other processes, use access_remote_vm
        igloo_pr_debug("igloo: Using access_remote_vm for process %d\n", task->pid);
        ret = 0;
        if (access_remote_vm(mm, arg_start, buf, len, FOLL_FORCE) != len) {
            igloo_pr_debug("igloo: access_remote_vm failed for procargs at %#lx (len %lu)\n",
                         arg_start, len);
            ret = -EFAULT;
        }
    } else {
        // For current process, use the standard copy_from_user
        igloo_pr_debug("igloo: Using copy_from_user for current process\n");
        // Check access permissions before copying
        if (!access_ok((void __user *)arg_start, len)) {
             igloo_pr_debug("igloo: access_ok failed for procargs at %#lx (len %lu)\n", arg_start, len);
             goto fail;
        }

        // Copy arguments from user space
        ret = copy_from_user(buf, (const void __user *)arg_start, len);
    }
    
    if (ret != 0) {
        igloo_pr_debug("igloo: memory access failed for procargs at %#lx (len %lu), ret %d\n",
                       arg_start, len, ret);
        goto fail;
    }
    
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->header.size = cpu_to_le64(len);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procargs from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCARGS");
    mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procargs failure, returning '%s'\n", PORTAL_DATA(mem_region));
}

void handle_op_read_procenv(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long env_start, env_end, len;
    char *buf = PORTAL_DATA(mem_region);
    int ret;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCENV (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");

    if (!mm || !mm->env_end || !mm->env_start || mm->env_end <= mm->env_start) {
        goto fail;
    }

    env_start = mm->env_start;
    env_end = mm->env_end;
    len = env_end - env_start;

    // Ensure we don't overflow our buffer, leave space for null terminator
    if (len >= CHUNK_SIZE) {
        len = CHUNK_SIZE - 1;
        igloo_pr_debug("igloo: procenv truncated to %lu bytes\n", len);
    }

    // Use different methods based on whether we're accessing current task or another task
    if (task != current) {
        // For other processes, use access_remote_vm
        igloo_pr_debug("igloo: Using access_remote_vm for process %d\n", task->pid);
        ret = 0;
        if (access_remote_vm(mm, env_start, buf, len, FOLL_FORCE) != len) {
            igloo_pr_debug("igloo: access_remote_vm failed for procenv at %#lx (len %lu)\n",
                         env_start, len);
            ret = -EFAULT;
        }
    } else {
        // For current process, use the standard copy_from_user
        igloo_pr_debug("igloo: Using copy_from_user for current process\n");
        // Check access permissions before copying
        if (!access_ok((void __user *)env_start, len)) {
             igloo_pr_debug("igloo: access_ok failed for procenv at %#lx (len %lu)\n", env_start, len);
             goto fail;
        }

        // Copy environment variables from user space
        ret = copy_from_user(buf, (const void __user *)env_start, len);
    }
    
    if (ret != 0) {
        igloo_pr_debug("igloo: memory access failed for procenv at %#lx (len %lu), ret %d\n",
                       env_start, len, ret);
        goto fail;
    }
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->header.size = cpu_to_le64(len);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procenv from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCENV");
    mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procenv failure, returning '%s'\n", PORTAL_DATA(mem_region));
}