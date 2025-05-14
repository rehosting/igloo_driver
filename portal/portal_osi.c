#include "portal_internal.h"
#include <linux/fdtable.h>  /* For files_fdtable and fdtable structure */
#include <linux/path.h>     /* For d_path */

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
        igloo_debug_osi("igloo: Handling HYPER_OP_OSI_PROC for NULL task\n");
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_debug_osi("igloo: Handling HYPER_OP_OSI_PROC for PID %d\n", task->pid);
    
    mm = task->mm;

    // Initialize the OSI proc structure at the beginning of data buffer
    proc = (struct osi_proc *)data_buf;
    proc->taskd = ((unsigned long)task);
    
    if (mm && mm->pgd) {
        proc->pgd = ((unsigned long)mm->pgd);
        proc->map_count = (mm->map_count);
        proc->start_brk = (mm->start_brk);
        proc->brk = (mm->brk);
        proc->start_stack = (mm->start_stack);
        proc->start_code = (mm->start_code);
        proc->end_code = (mm->end_code);
        proc->start_data = (mm->start_data);
        proc->end_data = (mm->end_data);
        proc->arg_start = (mm->arg_start);
        proc->arg_end = (mm->arg_end);
        proc->env_start = (mm->env_start);
        proc->env_end = (mm->env_end);
        // saved_auxv is now a pointer to an array, not an integer
        proc->saved_auxv = 0; // Don't try to cast pointer to integer
        proc->mmap_base = (mm->mmap_base);
        proc->task_size = (mm->task_size);
    } else {
        proc->pgd = 0;
    }
    
    proc->pid = (task->pid);
    proc->ppid = (task->real_parent ? task->real_parent->pid : 0);
    proc->uid = (task->cred->uid.val);
    proc->gid = (task->cred->gid.val);
    proc->euid = (task->cred->euid.val);
    proc->egid = (task->cred->egid.val);
    
    // Put name after the struct
    proc->name_offset = (sizeof(struct osi_proc));
    name_len = strnlen(task->comm, TASK_COMM_LEN);
    // Ensure we don't overflow our buffer
    if (sizeof(struct osi_proc) + name_len + 1 > CHUNK_SIZE) {
        name_len = CHUNK_SIZE - sizeof(struct osi_proc) - 1;
    }
    strncpy(data_buf + sizeof(struct osi_proc), task->comm, name_len);
    data_buf[sizeof(struct osi_proc) + name_len] = '\0';
    igloo_debug_osi("igloo: proc name: %s\n", task->comm);
    igloo_debug_osi("igloo: proc name in buf: %s\n", data_buf + sizeof(struct osi_proc));
    
    total_size += name_len; // do not null terminator
    
    // Set create time
    proc->create_time = (task->start_time);
    
    mem_region->header.size = (total_size);
    mem_region->header.op = (HYPER_RESP_READ_OK);
}

void handle_op_osi_proc_handles(portal_region *mem_region)
{
    struct task_struct *task;
    struct osi_proc_handle *handle;
    int count = 0;
    int total_count = 0;
    size_t max_handles;
    char *data_buf = PORTAL_DATA(mem_region);
    struct osi_result_header *header = (struct osi_result_header *)data_buf;

    igloo_debug_osi("igloo: Handling HYPER_OP_OSI_PROC_HANDLES\n");
    
    // Reserve space for count at beginning
    max_handles = (CHUNK_SIZE - sizeof(struct osi_result_header)) / sizeof(struct osi_proc_handle);
    
    igloo_debug_osi("osi_proc_handles: max_handles=%zu\n", max_handles);
    
    // Initialize header with zeros
    header->result_count = 0;
    header->total_count = 0;
    
    // Start filling handles after header
    handle = (struct osi_proc_handle *)(data_buf + sizeof(struct osi_result_header));
    
    // First pass: count total number of processes
    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm = task->mm;
        if (mm) {  // Only count user processes (with mm)
            total_count++;
        }
    }
    
    // Second pass: fill handles up to max_handles
    for_each_process(task) {
        struct mm_struct *mm;
        
        if (count >= max_handles) {
            break;  // Reached capacity
        }
        
        mm = task->mm;
        if (!mm) {
            continue; // Skip kernel threads
        }
        
        handle->pid = ((unsigned long)task->pid);
        handle->taskd = ((unsigned long)task);
        handle->start_time = (task->start_time);
        
        handle++;
        count++;
    }
    rcu_read_unlock();
    
    // Update counts
    header->result_count = (count);
    header->total_count = (total_count);
    
    igloo_debug_osi("igloo: Returning %d process handles (total processes: %d)\n", count, total_count);
    
    mem_region->header.size = (sizeof(struct osi_result_header) + (count * sizeof(struct osi_proc_handle)));
    mem_region->header.op = (HYPER_RESP_READ_OK);
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
    struct osi_result_header *header = (struct osi_result_header *)data_buf;
    char *string_buf;
    size_t string_offset;

    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task before using task->pid
    if (!task) {
        igloo_debug_osi("igloo: Handling HYPER_OP_OSI_MAPPINGS for NULL task\n");
        mem_region->header.size = (sizeof(struct osi_result_header));  // Return at least the header
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_debug_osi("igloo: Handling HYPER_OP_OSI_MAPPINGS for PID %d\n", task->pid);
    
    mm = task->mm;

    // Reserve space for count at beginning (now two counts: returned mappings and total mappings)
    max_mappings = (CHUNK_SIZE / 2) / sizeof(struct osi_module);
    
    // Initialize the header with zeros
    header->result_count = 0;
    header->total_count = 0;
    
    // Check if we have a valid mm_struct
    if (!mm) {
        mem_region->header.size = (sizeof(struct osi_result_header));
        mem_region->header.op = (HYPER_RESP_READ_OK);
        return;
    }
    
    // Store total number of VMAs in the process
    header->total_count = (mm->map_count);
    igloo_debug_osi("igloo: Process has %d total VMAs\n", mm->map_count);
    
    // Start filling mappings after the header
    mapping = (struct osi_module *)(data_buf + sizeof(struct osi_result_header));
    
    // String buffer starts after module structures
    string_offset = sizeof(struct osi_result_header) + (max_mappings * sizeof(struct osi_module));
    string_buf = data_buf + string_offset;
    
    // Get skip count from the header - this is how many VMAs we've already processed
    skip_count = (mem_region->header.addr);
    igloo_debug_osi("igloo: Starting VMA scan, skipping first %d entries\n", skip_count);
    
    // Iterate through the process memory mappings
    if (mmap_read_lock_killable(mm)) {
        mem_region->header.size = (sizeof(__le64) * 2);
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
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
            mem_region->header.addr = (total_count);
            igloo_debug_osi("igloo: Buffer full, processed %d VMAs total\n", total_count);
            break;
        }
        
        // Get mapping name using our helper function
        portal_get_vma_name(vma, mapping_name, sizeof(mapping_name));
        
        // Fill mapping info
        mapping->base = (vma->vm_start);
        mapping->size = (vma->vm_end - vma->vm_start);
        
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
        
        mapping->name_offset = (string_offset);
        string_offset += name_len + 1;
        string_buf += name_len + 1;
        
        // Use the same string for file path
        mapping->file_offset = mapping->name_offset;
        
        // Additional fields
        mapping->offset = (vma->vm_pgoff << PAGE_SHIFT);
        mapping->flags = (vma->vm_flags);
        if (vma->vm_file){
            const struct inode *inode = file_user_inode(vma->vm_file);
            mapping->pgoff = (((loff_t)vma->vm_pgoff) << PAGE_SHIFT);
            dev_t dev = inode->i_sb->s_dev;
            unsigned int major = MAJOR(dev);
            unsigned int minor = MINOR(dev);
            mapping->dev = (dev);
            mapping->inode = (inode->i_ino);
            igloo_debug_osi("igloo: VMA mapping: %s, file: %s\n", 
                   mapping_name, mapping_name);
            igloo_debug_osi("igloo: VMA mapping: %s, offset: %llx, flags: %llx\n",
                   mapping_name, (unsigned long long)vma->vm_pgoff << PAGE_SHIFT, (unsigned long long)vma->vm_flags);
            igloo_debug_osi("igloo: VMA mapping: %s, dev: %x:%x (major:minor), raw: %llx, inode: %llx\n",
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
        igloo_debug_osi("igloo: All VMAs processed\n");
    }
    
    mmap_read_unlock(mm);
    
    // Update count of mappings we're returning
    header->result_count = (count);
    
    mem_region->header.size = (string_offset);
    mem_region->header.op = (HYPER_RESP_READ_OK);
    
    igloo_debug_osi("igloo: Returned %d VMA mappings (total VMAs: %d), buffer used: %zu bytes\n", 
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
        igloo_debug_osi("igloo: Handling HYPER_OP_OSI_PROC_MEM for NULL task\n");
        proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_debug_osi("igloo: Handling HYPER_OP_OSI_PROC_MEM for PID %d\n", task->pid);
    
    mm = task->mm;

    // Check if we have enough buffer space for the structure
    if (sizeof(struct osi_proc_mem) > CHUNK_SIZE) {
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
    
    if (!mm) {
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem->start_brk = (mm->start_brk);
    proc_mem->brk = (mm->brk);
    
    mem_region->header.size = (sizeof(struct osi_proc_mem));
    mem_region->header.op = (HYPER_RESP_READ_OK);
}

void handle_op_read_procargs(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    char *buf = PORTAL_DATA(mem_region);
    unsigned long arg_start, arg_end;
    size_t len = 0;
    int i;

    igloo_debug_osi("igloo: Handling HYPER_OP_READ_PROCARGS (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");
    
    if (!task) {
        igloo_debug_osi("igloo: No task found for pid %llu\n", 
                     (unsigned long long)(mem_region->header.addr));
        goto fail;
    }

    if (!mm || !mm->arg_end || !mm->arg_start || mm->arg_end <= mm->arg_start) {
        igloo_debug_osi("igloo: Invalid memory area for procargs\n");
        goto fail;
    }
    
    /* Implementation inspired by fs/proc/base.c:get_mm_cmdline() */
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    
    /* Calculate max length to read, similar to get_mm_cmdline */
    len = min_t(size_t, arg_end - arg_start, CHUNK_SIZE - 1);
    
    if (len <= 0) {
        igloo_debug_osi("igloo: Zero-length arguments area\n");
        goto fail;
    }

    /* Read the arguments data */
    if (access_remote_vm(mm, arg_start, buf, len, FOLL_FORCE) != len) {
        igloo_debug_osi("igloo: Failed to read arguments area\n");
        goto fail;
    }

    /* In Linux, arguments in the memory are already null-terminated.
     * For our use, we need to convert these null terminators to spaces,
     * except for the final one. This matches get_mm_cmdline behavior.
     */
    for (i = 0; i < len - 1; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
    
    /* Ensure the buffer is null-terminated */
    buf[len] = '\0';

    mem_region->header.size = (len);
    mem_region->header.op = (HYPER_RESP_READ_OK);
    igloo_debug_osi("igloo: Read procargs: len=%zu\n", len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCARGS");
    mem_region->header.size = (strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = (HYPER_RESP_READ_FAIL);
    igloo_debug_osi("igloo: procargs failure, returning '%s'\n", PORTAL_DATA(mem_region));
}

void handle_op_read_procenv(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long env_start, env_end, len;
    char *buf = PORTAL_DATA(mem_region);
    int ret;

    igloo_debug_osi("igloo: Handling HYPER_OP_READ_PROCENV (pid=%d, comm='%s')\n",
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
        igloo_debug_osi("igloo: procenv truncated to %lu bytes\n", len);
    }

    // Use different methods based on whether we're accessing current task or another task
    if (task != current) {
        // For other processes, use access_remote_vm
        igloo_debug_osi("igloo: Using access_remote_vm for process %d\n", task->pid);
        ret = 0;
        if (access_remote_vm(mm, env_start, buf, len, FOLL_FORCE) != len) {
            igloo_debug_osi("igloo: access_remote_vm failed for procenv at %#lx (len %lu)\n",
                         env_start, len);
            ret = -EFAULT;
        }
    } else {
        // For current process, use the standard copy_from_user
        igloo_debug_osi("igloo: Using copy_from_user for current process\n");
        // Check access permissions before copying
        if (!access_ok((void __user *)env_start, len)) {
             igloo_debug_osi("igloo: access_ok failed for procenv at %#lx (len %lu)\n", env_start, len);
             goto fail;
        }

        // Copy environment variables from user space
        ret = copy_from_user(buf, (const void __user *)env_start, len);
    }
    
    if (ret != 0) {
        igloo_debug_osi("igloo: memory access failed for procenv at %#lx (len %lu), ret %d\n",
                       env_start, len, ret);
        goto fail;
    }
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->header.size = (len);
    mem_region->header.op = (HYPER_RESP_READ_OK);
    igloo_debug_osi("igloo: Read procenv from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCENV");
    mem_region->header.size = (strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = (HYPER_RESP_READ_FAIL);
    igloo_debug_osi("igloo: procenv failure, returning '%s'\n", PORTAL_DATA(mem_region));
}

void handle_op_read_fds(portal_region *mem_region)
{
    struct task_struct *task;
    struct file *file = NULL;
    struct files_struct *files;
    struct fdtable *fdt;
    int count = 0;
    int total_count = 0;
    int start_fd = 0;
    int i;
    size_t max_fds;
    char *data_buf = PORTAL_DATA(mem_region);
    struct osi_result_header *header = (struct osi_result_header *)data_buf;
    struct osi_fd_entry *fd_entry;
    char *string_buf;
    size_t string_offset;
    
    // Get start_fd from the header - this is where we'll start scanning FDs
    start_fd = (mem_region->header.addr);
    
    // Get target task using the same helper as other OSI functions
    task = get_target_task_by_id(mem_region);
    
    igloo_debug_osi("igloo: Handling HYPER_OP_READ_FDS starting at fd=%d for task %d\n", 
                  start_fd, task ? task->pid : -1);
    
    if (!task) {
        igloo_debug_osi("igloo: No task found\n");
        header->result_count = 0;
        header->total_count = 0;
        mem_region->header.size = (sizeof(struct osi_result_header));
        mem_region->header.op = (HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Reserve space for result header at beginning
    max_fds = (CHUNK_SIZE / 2) / sizeof(struct osi_fd_entry);
    
    // Initialize header with zeros
    header->result_count = 0;
    header->total_count = 0;
    
    // Start filling fd entries after header
    fd_entry = (struct osi_fd_entry *)(data_buf + sizeof(struct osi_result_header));
    
    // String buffer starts after fd entries
    string_offset = sizeof(struct osi_result_header) + (max_fds * sizeof(struct osi_fd_entry));
    string_buf = data_buf + string_offset;
    
    // Access the process's file descriptor table
    task_lock(task);
    if (!task->files) {
        task_unlock(task);
        mem_region->header.size = (sizeof(struct osi_result_header));
        mem_region->header.op = (HYPER_RESP_READ_OK);
        return;
    }
    
    files = task->files;
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    
    // Count total number of open files
    for (i = 0; i < fdt->max_fds; i++) {
        if (fdt->fd[i])
            total_count++;
    }
    
    // Store total count in header
    header->total_count = (total_count);
    
    // Start filling fd entries from start_fd
    for (i = start_fd; i < fdt->max_fds; i++) {
        file = fdt->fd[i];
        
        if (!file){
            igloo_debug_osi("igloo: No file for fd %d\n", i);
            continue;
        }
        
        if (count >= max_fds || string_offset >= CHUNK_SIZE - PATH_MAX) {
            // Store the next fd number to start from in the next call
            mem_region->header.addr = (i + 1);
            break;
        }
        
        // Get a reference to the file
        get_file(file);
        
        // Fill in fd entry
        fd_entry->fd = (i);
        fd_entry->name_offset = (string_offset);
        
        // Move to temporary string buffer for path
        char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (path_buf) {
            char *path = d_path(&file->f_path, path_buf, PATH_MAX);
            if (!IS_ERR(path)) {
                size_t name_len = strlen(path);
                
                // Check if we have enough space for this name
                if (string_offset + name_len + 1 <= CHUNK_SIZE) {
                    // Copy path to string buffer
                    strncpy(string_buf, path, name_len);
                    string_buf[name_len] = '\0';
                    
                    // Update string buffer position
                    string_buf += name_len + 1;
                    string_offset += name_len + 1;
                    
                    // Increment counts
                    fd_entry++;
                    count++;
                    
                    igloo_debug_osi("igloo: Processed fd %d: %s\n", i, path);
                } else {
                    // Not enough space for this entry's name
                    mem_region->header.addr = (i);
                    igloo_debug_osi("igloo: Not enough space for fd %d path, will continue from here next time\n", i);
                    break;
                }
            }
            kfree(path_buf);
        }
        
        // Release the file reference
        fput(file);
    }
    
    spin_unlock(&files->file_lock);
    task_unlock(task);
    
    // If we processed all FDs, set next count to 0 to indicate completion
    if (i >= fdt->max_fds) {
        mem_region->header.addr = 0;
    }
    
    // Update count of FDs we're returning
    header->result_count = (count);
    
    mem_region->header.size = (string_offset);
    mem_region->header.op = (HYPER_RESP_READ_OK);
    
    igloo_debug_osi("igloo: Returned %d file descriptors (total: %d), buffer used: %zu bytes\n", 
                  count, total_count, string_offset);
}