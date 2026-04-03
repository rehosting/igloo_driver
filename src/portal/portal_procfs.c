#include "portal_internal.h"
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/file.h>        // Required for fput()
#include <linux/shmem_fs.h>    // Required for shmem_file_setup()
#include <linux/vmalloc.h>     // Required for vzalloc()

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
#include "portal_procfs.h"
#define IGLOO_NEEDS_PROC_PERMANENT_CLEAR 1
#else
#define IGLOO_NEEDS_PROC_PERMANENT_CLEAR 0
#endif

static LIST_HEAD(procfs_entry_list);
static atomic_t procfs_entry_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(procfs_entry_lock);

static LIST_HEAD(procfs_dir_list);
static atomic_t procfs_dir_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(procfs_dir_lock);

static void igloo_remove_proc_entry(const char *name, struct proc_dir_entry *parent);
int igloo_proxy_mmap(struct file *file, struct vm_area_struct *vma);

// --- Forward declaration for the hypercall bridge ---
extern ssize_t igloo_fetch_mmap_page(struct file *file, void *buffer, loff_t offset, size_t size);

ssize_t igloo_fetch_mmap_page(struct file *file, void *buffer, loff_t offset, size_t size)
{
    loff_t pos = offset;
    ssize_t ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    mm_segment_t old_fs; // FIXED: C90 declaration at the top
#endif

    if (!file || !file->f_op || !file->f_op->read) {
        printk(KERN_ERR "igloo_mmap: No .read hook available to trampoline.\n");
        return -EINVAL;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    ret = file->f_op->read(file, (char __user *)buffer, size, &pos);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    set_fs(old_fs);
#endif

    return ret;
}

int igloo_proxy_mmap(struct file *file, struct vm_area_struct *vma)
{
    // Retrieve our tracking structure from the proc inode using the correct API for the kernel version
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
    struct portal_procfs_entry *pe = pde_data(file_inode(file));
#else
    struct portal_procfs_entry *pe = PDE_DATA(file_inode(file));
#endif
    struct file *shm_file;
    size_t size = vma->vm_end - vma->vm_start;
    int ret;

    if (!pe) {
        printk(KERN_ERR "igloo_mmap: No portal tracking data found for inode\n");
        return -ENODEV;
    }

    // Lock to ensure only the first mmap call triggers the hypervisor fetch
    mutex_lock(&pe->shm_lock);
    
    if (!pe->shm_file) {
        // LAZY INITIALIZATION: Create the backing file on first use
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        shm_file = shmem_kernel_file_setup(pe->name, size, vma->vm_flags | VM_NORESERVE);
#else
        shm_file = shmem_file_setup(pe->name, size, vma->vm_flags | VM_NORESERVE);
#endif
        
        if (!IS_ERR(shm_file)) {
            // kvzalloc introduced in 4.12. Fall back to vzalloc for older kernels.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
            void *buffer = kvzalloc(size, GFP_KERNEL);
#else
            void *buffer = vzalloc(size);
#endif
            if (buffer) {
                ssize_t bytes = igloo_fetch_mmap_page(file, buffer, 0, size);
                if (bytes > 0) {
                    loff_t pos = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
                    kernel_write(shm_file, buffer, bytes, &pos);
#else
                    mm_segment_t old_fs = get_fs();
                    set_fs(KERNEL_DS);
                    shm_file->f_op->write(shm_file, (char __user *)buffer, bytes, &pos);
                    set_fs(old_fs);
#endif
                }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
                kvfree(buffer);
#else
                vfree(buffer);
#endif
            }
            // Cache it for the next process!
            pe->shm_file = shm_file;
        }
    }
    
    // Grab the cached file
    shm_file = pe->shm_file;
    mutex_unlock(&pe->shm_lock);

    if (IS_ERR_OR_NULL(shm_file))
        return PTR_ERR(shm_file) ? PTR_ERR(shm_file) : -ENOMEM;

    // Swap the VMA backing file to our shared RAM file
    if (vma->vm_file) {
        fput(vma->vm_file);
    }
    
    // get_file() increments the refcount so the cached shm_file isn't 
    // destroyed when this specific process closes its VMA
    vma->vm_file = get_file(shm_file);

    // Let the kernel's shmem subsystem handle the rest natively
    if (shm_file->f_op && shm_file->f_op->mmap)
        ret = shm_file->f_op->mmap(shm_file, vma);
    else
        ret = -ENODEV;

    return ret;
}

// Add this forward declaration before any use of find_proc_dir_by_id
static struct proc_dir_entry *find_proc_dir_by_id(int id)
{
    struct portal_procfs_dir *dir;
    struct proc_dir_entry *entry = NULL;

    spin_lock(&procfs_dir_lock);
    list_for_each_entry(dir, &procfs_dir_list, list) {
        if (dir->id == id) {
            entry = dir->entry;
            break;
        }
    }
    spin_unlock(&procfs_dir_lock);
    return entry;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static inline const struct proc_ops *
igloo_convert_ops_to_proc_ops(const struct igloo_proc_ops *ops, struct proc_ops *out)
{
	memset(out, 0, sizeof(*out));
	out->proc_open    = ops->open;
	out->proc_read    = ops->read;
	out->proc_read_iter = ops->read_iter;
	out->proc_write   = ops->write;
	out->proc_lseek   = ops->lseek;
    out->proc_release = ops->release;
    out->proc_poll = ops->poll;
    out->proc_ioctl   = ops->ioctl;
#ifdef CONFIG_COMPAT
	out->proc_compat_ioctl = ops->compat_ioctl;
#endif
	out->proc_mmap    = ops->mmap;
	out->proc_get_unmapped_area = ops->get_unmapped_area;
	return out;
}
#else
static inline const struct file_operations *
igloo_convert_ops_to_fops(const struct igloo_proc_ops *ops, struct file_operations *out)
{
	memset(out, 0, sizeof(*out));
	out->owner   = THIS_MODULE;
	out->open    = ops->open;
	out->read    = ops->read;
	out->read_iter = ops->read_iter;
	out->write   = ops->write;
	out->llseek  = ops->lseek;
	out->release = ops->release;
	out->poll    = ops->poll;
	out->unlocked_ioctl = ops->ioctl;
#ifdef CONFIG_COMPAT
	out->compat_ioctl = ops->compat_ioctl;
#endif
	out->mmap    = ops->mmap;
	out->get_unmapped_area = ops->get_unmapped_area;
	return out;
}
#endif

// Unified proc_create wrapper
static struct proc_dir_entry *igloo_proc_create_data(const char *name, umode_t mode,
                        struct proc_dir_entry *parent,
                        struct igloo_proc_ops *uops,
                        void *data)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    struct proc_ops *pops;
#else
    struct file_operations *fops;
#endif

    if (uops->mmap == NULL){
        uops->mmap = igloo_proxy_mmap;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    pops = kmalloc(sizeof(struct proc_ops), GFP_KERNEL);
    igloo_convert_ops_to_proc_ops(uops, pops);
    return proc_create_data(name, mode, parent, pops, data); // <-- Updated API
#else
    fops = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
    igloo_convert_ops_to_fops(uops, fops);
    return proc_create_data(name, mode, parent, fops, data); // <-- Updated API
#endif
}

/* =========================================================================
 * 1. INTERNAL PROCFS SYMBOL RESOLUTION
 * ========================================================================= */
typedef struct proc_dir_entry *(*pde_subdir_find_t)(struct proc_dir_entry *dir, const char *name, unsigned int len);

static struct proc_dir_entry *internal_proc_root = NULL;
static pde_subdir_find_t internal_pde_subdir_find = NULL;

#if IGLOO_NEEDS_PROC_PERMANENT_CLEAR
#if defined(PROC_ENTRY_PERMANENT) && (PROC_ENTRY_PERMANENT != 0U)
#define IGLOO_PROC_ENTRY_PERMANENT_BIT PROC_ENTRY_PERMANENT
#else
/* Runtime internal procfs flag bit; public headers may map PROC_ENTRY_PERMANENT to 0 for modules. */
#define IGLOO_PROC_ENTRY_PERMANENT_BIT (1U << 0)
#endif
#endif

static int resolve_proc_symbols(void)
{
    if (internal_proc_root && internal_pde_subdir_find)
        return 0;

    internal_proc_root = (struct proc_dir_entry *)kallsyms_lookup_name("proc_root");
    if (!internal_proc_root) {
        printk(KERN_ERR "portal_procfs: Failed to lookup symbol: proc_root\n");
        return -ENOENT;
    }

    internal_pde_subdir_find = (pde_subdir_find_t)kallsyms_lookup_name("pde_subdir_find");
    if (!internal_pde_subdir_find) {
        printk(KERN_ERR "portal_procfs: Failed to lookup symbol: pde_subdir_find\n");
        return -ENOENT;
    }

    return 0;
}

static struct proc_dir_entry *find_proc_subdir_entry(struct proc_dir_entry *parent, const char *name)
{
    if (resolve_proc_symbols() < 0)
        return NULL;

    if (!parent)
        parent = internal_proc_root;

    // Directly accesses the internal unmounted tree!
    return internal_pde_subdir_find(parent, name, strlen(name));
}

static bool check_proc_entry_exists(struct proc_dir_entry *parent, const char *name)
{
    return (find_proc_subdir_entry(parent, name) != NULL);
}

static void clear_permanent_flag_if_needed(struct proc_dir_entry *entry,
					     const char *name)
{
#if IGLOO_NEEDS_PROC_PERMANENT_CLEAR
    if (!entry)
        return;

    if (!(entry->flags & IGLOO_PROC_ENTRY_PERMANENT_BIT))
        return;

    printk(KERN_EMERG "portal_procfs: Clearing PROC_ENTRY_PERMANENT for '%s'\n", name);
    entry->flags &= ~IGLOO_PROC_ENTRY_PERMANENT_BIT;
#else
    (void)entry;
    (void)name;
#endif
}

static void igloo_remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = find_proc_subdir_entry(parent, name);

    clear_permanent_flag_if_needed(entry, name);
    remove_proc_entry(name, parent);
}

/* =========================================================================
 * 2. DIRECTORY CREATION LOGIC
 * ========================================================================= */

// Find or create a directory, return its proc_dir_entry and id
static struct proc_dir_entry *get_or_create_proc_dir(const char *name, struct proc_dir_entry *parent, const char *full_path, int *out_id)
{
    struct portal_procfs_dir *dir;
    struct proc_dir_entry *entry = NULL;
    int found = 0;
    bool created_new = false;

    // 1. Check if we already track it
    spin_lock(&procfs_dir_lock);
    list_for_each_entry(dir, &procfs_dir_list, list) {
        if (strcmp(dir->path, full_path) == 0) {
            *out_id = dir->id;
            entry = dir->entry;
            found = 1;
            break;
        }
    }
    spin_unlock(&procfs_dir_lock);

    if (found)
        return entry;

    // 2. Check if the kernel already created it natively (bypassing VFS)
    entry = find_proc_subdir_entry(parent, name);

    // COLLISION CHECK: If it exists natively, it MUST be a directory
    if (entry && !S_ISDIR(entry->mode)) {
        printk(KERN_ERR "portal_procfs: Collision: '%s' exists but is a file, cannot use as directory\n", name);
        return NULL;
    }

    if (!entry) {
        entry = proc_mkdir(name, parent);
        if (!entry)
            return NULL;
        created_new = true;
    }

    dir = kzalloc(sizeof(*dir), GFP_KERNEL);
    if (!dir) {
        if (created_new)
            igloo_remove_proc_entry(name, parent);
        return NULL;
    }
    
    dir->entry = entry;
    dir->path = kstrdup(full_path, GFP_KERNEL);
    if (!dir->path) {
        kfree(dir);
        if (created_new)
            igloo_remove_proc_entry(name, parent);
        return NULL;
    }
    dir->id = atomic_inc_return(&procfs_dir_id);

    spin_lock(&procfs_dir_lock);
    list_add(&dir->list, &procfs_dir_list);
    spin_unlock(&procfs_dir_lock);

    *out_id = dir->id;
    return entry;
}

// Create a new procfs entry
void handle_op_procfs_create_file(portal_region *mem_region)
{
    struct portal_procfs_create_req *req = (struct portal_procfs_create_req *)PORTAL_DATA(mem_region);
    struct proc_dir_entry *parent = NULL, *file;
    struct proc_dir_entry *existing = NULL;
    struct portal_procfs_entry *pe;
    umode_t file_mode;
    int id;
    char *entry_name;
    bool exists;

    printk(KERN_EMERG "portal_procfs: handle_op_procfs_create_file called\n");

    req->path[PROCFS_MAX_PATH - 1] = '\0';
    entry_name = req->path;

    // Validate name: must not contain '/' and must not be empty
    if (!entry_name[0] || strchr(entry_name, '/')) {
        printk(KERN_EMERG "portal_procfs: Invalid file name: '%s'\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

    // Parent must be provided (0 means root)
    if (req->parent_id) {
        parent = find_proc_dir_by_id(req->parent_id);
        if (!parent) {
            printk(KERN_EMERG "portal_procfs: Invalid parent_id=%d for file '%s'\n", req->parent_id, entry_name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            goto out;
        }
    }

    // Safety: Fetch the entry to check its type
    existing = find_proc_subdir_entry(parent, entry_name);
    exists = (existing != NULL);

    printk(KERN_EMERG "portal_procfs: parent=%p, entry_name='%s'\n", parent, entry_name);

    // Remove only if exists and replace is set
    if (exists && req->replace) {
        // COLLISION PROTECTION: Do not allow a file registration to overwrite a directory
        if (S_ISDIR(existing->mode)) {
            printk(KERN_ERR "portal_procfs: Refusing to replace directory '%s' with a file\n", entry_name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            goto out;
        }

        printk(KERN_EMERG "portal_procfs: Removing existing proc entry: %s\n", entry_name);
        igloo_remove_proc_entry(entry_name, parent);
        exists = false;
    }

    // If it exists and replace is not set, fail
    if (exists) {
        printk(KERN_EMERG "portal_procfs: proc entry '%s' already exists\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }
    file_mode = req->mode ? req->mode : 0444;

    // --- FIXED: You must allocate 'pe' before using it! ---
    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        printk(KERN_EMERG "portal_procfs: Failed to allocate portal_procfs_entry\n");
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }
    // ------------------------------------------------------

    mutex_init(&pe->shm_lock); // Now this is safe
    pe->name = kstrdup(entry_name, GFP_KERNEL);

    // 2. Create the file and bind the tracker
    file = igloo_proc_create_data(entry_name, file_mode, parent, &req->fops, pe);
    if (!file) {
        printk(KERN_EMERG "portal_procfs: Failed to create proc entry: %s\n", entry_name);
        kfree(pe->name);
        kfree(pe);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }
    proc_set_size(file, req->size);
    
    pe->entry = file;
    pe->parent = parent;

    id = atomic_inc_return(&procfs_entry_id);
    pe->id = id;

    spin_lock(&procfs_entry_lock);
    list_add(&pe->list, &procfs_entry_list);
    spin_unlock(&procfs_entry_lock);

    printk(KERN_EMERG "portal_procfs: Created procfs entry '%s' with id %d\n", entry_name, id);

    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
out:
    // No need to kfree(entry_name) since it's now just req->path
    printk(KERN_EMERG "portal_procfs: handle_op_procfs_create_file exit, op=%d\n", mem_region->header.op);
}

// Handler for directory create/lookup operation
void handle_op_procfs_create_or_lookup_dir(portal_region *mem_region)
{
    struct portal_procfs_create_req *req = (struct portal_procfs_create_req *)PORTAL_DATA(mem_region);
    int dir_id = 0;
    struct proc_dir_entry *parent = NULL, *entry;
    char *dir_name;
    char full_path[PROCFS_MAX_PATH];
    size_t plen, dlen;

    struct portal_procfs_dir *parent_dir_struct = NULL;

    req->path[PROCFS_MAX_PATH - 1] = '\0';
    dir_name = req->path;

    // Validate name: must not contain '/' and must not be empty
    if (!dir_name[0] || strchr(dir_name, '/')) {
        printk(KERN_EMERG "portal_procfs: Invalid dir name: '%s'\n", dir_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // Parent must be provided (0 means root)
    if (req->parent_id) {
        parent = find_proc_dir_by_id(req->parent_id);
        if (!parent) {
            printk(KERN_EMERG "portal_procfs: Invalid parent_id=%d for dir '%s'\n", req->parent_id, dir_name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }
        // Find the portal_procfs_dir struct for this id
        spin_lock(&procfs_dir_lock);
        list_for_each_entry(parent_dir_struct, &procfs_dir_list, list) {
            if (parent_dir_struct->id == req->parent_id) {
                break;
            }
        }
        spin_unlock(&procfs_dir_lock);
        if (!parent_dir_struct || parent_dir_struct->id != req->parent_id || !parent_dir_struct->path) {
            printk(KERN_EMERG "portal_procfs: Could not find parent_dir struct for id=%d\n", req->parent_id);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }
        plen = strlen(parent_dir_struct->path);
        dlen = strlen(dir_name);
        if (plen + 1 + dlen + 1 > sizeof(full_path)) {
            printk(KERN_EMERG "portal_procfs: full_path too long for dir '%s'\n", dir_name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }
        
        /* 
         * Replaced snprintf with memcpy to avoid false positive -Wformat-truncation warning.
         * We have already verified the size fits in the check above.
         */
        memcpy(full_path, parent_dir_struct->path, plen);
        full_path[plen] = '/';
        memcpy(full_path + plen + 1, dir_name, dlen + 1); // +1 includes the null terminator
    } else {
        parent = NULL;
        snprintf(full_path, sizeof(full_path), "%s", dir_name);
    }

    entry = get_or_create_proc_dir(dir_name, parent, full_path, &dir_id);

    if (!entry) {
        printk(KERN_EMERG "portal_procfs: Failed to create/lookup dir: %s\n", full_path);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    printk(KERN_EMERG "portal_procfs: Created/Found dir '%s' with id %d\n", full_path, dir_id);
    mem_region->header.size = dir_id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}

