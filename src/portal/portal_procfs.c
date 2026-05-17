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
#include <linux/err.h>
#include <linux/kprobes.h>

#include "../args.h"
#include "portal_procfs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
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

struct portal_procfs_pid_template {
    struct list_head list;
    char *parent;
    char *name;
    struct portal_procfs_entry *entry;
};

static LIST_HEAD(procfs_pid_template_list);
static DEFINE_SPINLOCK(procfs_pid_template_lock);
static struct proc_dir_entry *pid_template_parent;

struct procfs_lookup_ctx {
    struct inode *dir;
    struct dentry *dentry;
};

static struct kretprobe proc_tgid_base_lookup_probe;

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

    if (pe->mmap_phys_addr) {
        // NATIVE QEMU MMAP: Directly map the physical address assigned by Penguin
        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
        return remap_pfn_range(vma, vma->vm_start, pe->mmap_phys_addr >> PAGE_SHIFT,
                               size, vma->vm_page_prot);
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
                    // FIX: Use vfs_write to safely handle the write vs write_iter abstraction
                    mm_segment_t old_fs = get_fs();
                    set_fs(KERNEL_DS);
                    vfs_write(shm_file, (char __user *)buffer, bytes, &pos);
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

static void igloo_flush_shm_to_hypervisor(struct file *file, struct portal_procfs_entry *pe)
{
    void *buffer;
    loff_t size;
    ssize_t bytes;
    loff_t pos = 0;

    if (!pe || !pe->shm_file) return;
    if (!file->f_op || !file->f_op->write) return; // Python didn't provide a write hook

    mutex_lock(&pe->shm_lock);
    
    // Get the exact size of the shared memory file
    size = i_size_read(file_inode(pe->shm_file));
    if (size <= 0) goto unlock;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
    buffer = kvzalloc(size, GFP_KERNEL);
#else
    buffer = vzalloc(size);
#endif

    if (buffer) {
        // 1. Read the modified data from the hidden RAM file
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
        bytes = kernel_read(pe->shm_file, buffer, size, &pos);
#else
        mm_segment_t old_fs = get_fs();
        set_fs(KERNEL_DS);
        bytes = vfs_read(pe->shm_file, (char __user *)buffer, size, &pos);
        set_fs(old_fs);
#endif

        // 2. Push it back to the Python plugin via the trampoline
        if (bytes > 0) {
            pos = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            file->f_op->write(file, (const char __user *)buffer, bytes, &pos);
            set_fs(old_fs);
#else
            // In newer kernels, our python hypercall still accepts this kernel pointer 
            // because dwarffi reads virtual memory seamlessly.
            file->f_op->write(file, (const char __user *)buffer, bytes, &pos);
#endif
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
        kvfree(buffer);
#else
        vfree(buffer);
#endif
    }

unlock:
    mutex_unlock(&pe->shm_lock);
}

static int igloo_proxy_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
    struct portal_procfs_entry *pe = pde_data(inode);
#else
    struct portal_procfs_entry *pe = PDE_DATA(inode);
#endif

    // 1. Flush any mmap writebacks to Python
    if (pe && pe->shm_file) {
        igloo_flush_shm_to_hypervisor(file, pe);
    }

    // 2. We don't have direct access to the original uops struct here, 
    // but you could store the original `release` pointer in `pe` if you need to
    // explicitly forward the release event to Python.
    // For now, if the file is closed, the VFS handles the cleanup.
    if (pe && pe->python_release) {
        int (*py_release)(struct inode *, struct file *) = pe->python_release;
        return py_release(inode, file);
    }

    return 0;
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
    
    // NEW: Route release through our writeback proxy
    out->proc_release = igloo_proxy_release; 
    
    out->proc_poll = ops->poll;
    out->proc_ioctl   = ops->ioctl;
#ifdef CONFIG_COMPAT
    out->proc_compat_ioctl = ops->compat_ioctl;
#endif
    out->proc_mmap    = ops->mmap;
    out->proc_get_unmapped_area = ops->get_unmapped_area;
    return out;
}
#endif

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
    
    // NEW: Route release through our writeback proxy
    out->release = igloo_proxy_release; 
    
    out->poll    = ops->poll;
    out->unlocked_ioctl = ops->ioctl;
#ifdef CONFIG_COMPAT
    out->compat_ioctl = ops->compat_ioctl;
#endif
    out->mmap    = ops->mmap;
    out->get_unmapped_area = ops->get_unmapped_area;
    return out;
}

// Unified proc_create wrapper
static struct proc_dir_entry *igloo_proc_create_data(const char *name, umode_t mode,
                        struct proc_dir_entry *parent,
                        struct igloo_proc_ops *uops,
                        void *data,
                        bool enable_default_mmap)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    struct proc_ops *pops;
#else
    struct file_operations *fops;
#endif

    // Conditionally attach our default mmap handler ONLY if requested
    // and the user hasn't provided their own override.
    if (enable_default_mmap && uops->mmap == NULL) {
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

static struct proc_dir_entry *igloo_proc_create_pid_file_data(const char *name, umode_t mode,
                        struct igloo_proc_ops *uops,
                        void *data,
                        bool enable_default_mmap)
{
    struct file_operations *fops;

    if (enable_default_mmap && uops->mmap == NULL) {
        uops->mmap = igloo_proxy_mmap;
    }

    fops = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
    if (!fops)
        return NULL;
    igloo_convert_ops_to_fops(uops, fops);
    return igloo_proc_create_pid_data(name, mode, fops, data);
}

/* =========================================================================
 * 1. INTERNAL PROCFS SYMBOL RESOLUTION
 * ========================================================================= */
typedef struct proc_dir_entry *(*pde_subdir_find_t)(struct proc_dir_entry *dir, const char *name, unsigned int len);
typedef struct inode *(*proc_get_inode_t)(struct super_block *sb, struct proc_dir_entry *de);

static struct proc_dir_entry *internal_proc_root = NULL;
static pde_subdir_find_t internal_pde_subdir_find = NULL;
static proc_get_inode_t internal_proc_get_inode = NULL;

#if IGLOO_NEEDS_PROC_PERMANENT_CLEAR
#if defined(PROC_ENTRY_PERMANENT) && (PROC_ENTRY_PERMANENT != 0U)
#define IGLOO_PROC_ENTRY_PERMANENT_BIT PROC_ENTRY_PERMANENT
#else
/* Runtime internal procfs flag bit; public headers may map PROC_ENTRY_PERMANENT to 0 for modules. */
#define IGLOO_PROC_ENTRY_PERMANENT_BIT (1U << 0)
#endif
#endif

// String matching exactly as implemented in fs/proc/generic.c
static int igloo_proc_match(unsigned int len, const char *name, struct proc_dir_entry *de)
{
    if (len < de->namelen)
        return -1;
    if (len > de->namelen)
        return 1;

    return memcmp(name, de->name, len);
}

// Fallback structural tree walker (Requires your portal_procfs.h definitions)
static struct proc_dir_entry *igloo_fallback_pde_subdir_find(struct proc_dir_entry *dir,
                                                             const char *name,
                                                             unsigned int len)
{
    struct rb_node *node = dir->subdir.rb_node;

    while (node) {
        // Because you defined the struct, container_of works perfectly here
        struct proc_dir_entry *de = container_of(node, struct proc_dir_entry, subdir_node);
        int result = igloo_proc_match(len, name, de);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return de;
    }
    return NULL;
}

static int resolve_proc_symbols(void)
{
    if (internal_proc_root && internal_pde_subdir_find && internal_proc_get_inode)
        return 0;

    internal_proc_root = (struct proc_dir_entry *)kallsyms_lookup_name("proc_root");
    if (!internal_proc_root) {
        printk(KERN_ERR "portal_procfs: Failed to lookup symbol: proc_root\n");
        return -ENOENT;
    }

    internal_pde_subdir_find = (pde_subdir_find_t)kallsyms_lookup_name("pde_subdir_find");
    if (!internal_pde_subdir_find) {
        printk(KERN_INFO "portal_procfs: pde_subdir_find missing. Using structural RB-tree fallback.\n");
        // Seamlessly route to your manual structural traverser
        internal_pde_subdir_find = igloo_fallback_pde_subdir_find; 
    }

    internal_proc_get_inode = (proc_get_inode_t)kallsyms_lookup_name("proc_get_inode");
    if (!internal_proc_get_inode) {
        printk(KERN_ERR "portal_procfs: Failed to lookup symbol: proc_get_inode\n");
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


static void clear_permanent_flag_if_needed(struct proc_dir_entry *entry,
					     const char *name)
{
#if IGLOO_NEEDS_PROC_PERMANENT_CLEAR
    if (!entry)
        return;

    if (!(entry->flags & IGLOO_PROC_ENTRY_PERMANENT_BIT))
        return;

    // printk(KERN_EMERG "portal_procfs: Clearing PROC_ENTRY_PERMANENT for '%s'\n", name);
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

static bool is_pid_compat_dir_name(const char *name)
{
    const char *p;

    if (!strcmp(name, "self"))
        return true;

    for (p = name; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
    }

    return name[0] != '\0';
}

static struct portal_procfs_dir *find_proc_dir_struct_by_id(int id)
{
    struct portal_procfs_dir *dir;
    struct portal_procfs_dir *found = NULL;

    spin_lock(&procfs_dir_lock);
    list_for_each_entry(dir, &procfs_dir_list, list) {
        if (dir->id == id) {
            found = dir;
            break;
        }
    }
    spin_unlock(&procfs_dir_lock);
    return found;
}

static struct portal_procfs_dir *create_pid_compat_dir(const char *full_path)
{
    struct portal_procfs_dir *dir;

    spin_lock(&procfs_dir_lock);
    list_for_each_entry(dir, &procfs_dir_list, list) {
        if (dir->synthetic_pid && strcmp(dir->path, full_path) == 0) {
            spin_unlock(&procfs_dir_lock);
            return dir;
        }
    }
    spin_unlock(&procfs_dir_lock);

    dir = kzalloc(sizeof(*dir), GFP_KERNEL);
    if (!dir)
        return NULL;

    dir->path = kstrdup(full_path, GFP_KERNEL);
    if (!dir->path) {
        kfree(dir);
        return NULL;
    }

    dir->id = atomic_inc_return(&procfs_dir_id);
    dir->entry = NULL;
    dir->synthetic_pid = 1;

    spin_lock(&procfs_dir_lock);
    list_add(&dir->list, &procfs_dir_list);
    spin_unlock(&procfs_dir_lock);
    return dir;
}

static struct proc_dir_entry *ensure_pid_template_parent(void)
{
    if (pid_template_parent)
        return pid_template_parent;

    pid_template_parent = find_proc_subdir_entry(NULL, ".igloo-pid-compat");
    if (pid_template_parent)
        return pid_template_parent;

    pid_template_parent = proc_mkdir(".igloo-pid-compat", NULL);
    return pid_template_parent;
}

static void remember_pid_template(const char *parent, const char *name, struct portal_procfs_entry *entry)
{
    struct portal_procfs_pid_template *tmpl;

    spin_lock(&procfs_pid_template_lock);
    list_for_each_entry(tmpl, &procfs_pid_template_list, list) {
        if (!strcmp(tmpl->parent, parent) && !strcmp(tmpl->name, name)) {
            tmpl->entry = entry;
            spin_unlock(&procfs_pid_template_lock);
            return;
        }
    }
    spin_unlock(&procfs_pid_template_lock);

    tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);
    if (!tmpl)
        return;

    tmpl->parent = kstrdup(parent, GFP_KERNEL);
    tmpl->name = kstrdup(name, GFP_KERNEL);
    if (!tmpl->parent || !tmpl->name) {
        kfree(tmpl->parent);
        kfree(tmpl->name);
        kfree(tmpl);
        return;
    }
    tmpl->entry = entry;

    spin_lock(&procfs_pid_template_lock);
    list_add(&tmpl->list, &procfs_pid_template_list);
    spin_unlock(&procfs_pid_template_lock);
}

static struct portal_procfs_entry *find_pid_template(const char *parent, const char *name, unsigned int len)
{
    struct portal_procfs_pid_template *tmpl;
    struct portal_procfs_entry *entry = NULL;

    spin_lock(&procfs_pid_template_lock);
    list_for_each_entry(tmpl, &procfs_pid_template_list, list) {
        if (!strcmp(tmpl->parent, parent) &&
            strlen(tmpl->name) == len && !memcmp(tmpl->name, name, len)) {
            entry = tmpl->entry;
            break;
        }
    }
    spin_unlock(&procfs_pid_template_lock);
    return entry;
}

static struct dentry *instantiate_pid_template(struct inode *dir, struct dentry *dentry)
{
    struct portal_procfs_entry *pe;
    struct inode *inode;
    const char *parent_name;
    char self_pid[16];

    if (resolve_proc_symbols() < 0)
        return ERR_PTR(-ENOENT);

    if (!dentry->d_parent)
        return ERR_PTR(-ENOENT);

    parent_name = dentry->d_parent->d_name.name;
    snprintf(self_pid, sizeof(self_pid), "%d", current->tgid);

    pe = NULL;
    if (!strcmp(parent_name, self_pid))
        pe = find_pid_template("self", dentry->d_name.name, dentry->d_name.len);
    if (!pe)
        pe = find_pid_template(parent_name, dentry->d_name.name, dentry->d_name.len);
    if (!pe || !pe->entry)
        return ERR_PTR(-ENOENT);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
    refcount_inc(&pe->entry->refcnt);
#else
    atomic_inc(&pe->entry->count);
#endif
    inode = internal_proc_get_inode(dir->i_sb, pe->entry);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    d_set_d_op(dentry, &simple_dentry_operations);
    d_add(dentry, inode);
    return NULL;
}

static int proc_tgid_base_lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct procfs_lookup_ctx *ctx = (struct procfs_lookup_ctx *)ri->data;

    ctx->dir = (struct inode *)regs_get_argument(regs, 0);
    ctx->dentry = (struct dentry *)regs_get_argument(regs, 1);
    return 0;
}

static int proc_tgid_base_lookup_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct procfs_lookup_ctx *ctx = (struct procfs_lookup_ctx *)ri->data;
    struct dentry *ret = (struct dentry *)igloo_regs_get_return_value(regs);
    struct dentry *replacement;

    if (!IS_ERR(ret) || PTR_ERR(ret) != -ENOENT)
        return 0;

    if (!ctx->dir || !ctx->dentry)
        return 0;

    replacement = instantiate_pid_template(ctx->dir, ctx->dentry);
    if (replacement == NULL || IS_ERR(replacement))
        igloo_regs_set_return_value(regs, (unsigned long)replacement);

    return 0;
}

int igloo_procfs_compat_init(void)
{
    int ret;

    memset(&proc_tgid_base_lookup_probe, 0, sizeof(proc_tgid_base_lookup_probe));
    proc_tgid_base_lookup_probe.kp.symbol_name = "proc_tgid_base_lookup";
    proc_tgid_base_lookup_probe.entry_handler = proc_tgid_base_lookup_entry;
    proc_tgid_base_lookup_probe.handler = proc_tgid_base_lookup_ret;
    proc_tgid_base_lookup_probe.data_size = sizeof(struct procfs_lookup_ctx);
    proc_tgid_base_lookup_probe.maxactive = 32;

    ret = register_kretprobe(&proc_tgid_base_lookup_probe);
    if (ret) {
        printk(KERN_ERR "portal_procfs: Failed to register proc_tgid_base_lookup kretprobe: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "portal_procfs: Registered proc pid lookup compatibility hook\n");
    return 0;
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
    struct portal_procfs_dir *parent_dir_struct = NULL;
    struct portal_procfs_entry *pe;
    umode_t file_mode;
    int id;
    char *entry_name;
    bool exists, enable_default_mmap, synthetic_pid_parent = false;

    req->path[PROCFS_MAX_PATH - 1] = '\0';
    entry_name = req->path;

    // Validate name: must not contain '/' and must not be empty
    if (!entry_name[0] || strchr(entry_name, '/')) {
        printk(KERN_EMERG "portal_procfs: Invalid file name: '%s'\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

    // Parent must be provided (0 means root, PROCFS_PID_PARENT_ID means /proc/<pid>)
    if (req->parent_id) {
        if (req->parent_id == PROCFS_PID_PARENT_ID) {
            parent = NULL;
        } else {
            parent_dir_struct = find_proc_dir_struct_by_id(req->parent_id);
            if (!parent_dir_struct) {
                printk(KERN_EMERG "portal_procfs: Invalid parent_id=%d for file '%s'\n", req->parent_id, entry_name);
                mem_region->header.op = HYPER_RESP_WRITE_FAIL;
                goto out;
            }
            synthetic_pid_parent = parent_dir_struct->synthetic_pid;
            if (synthetic_pid_parent) {
                parent = ensure_pid_template_parent();
                if (!parent) {
                    printk(KERN_EMERG "portal_procfs: Failed to create pid template parent for '%s'\n", entry_name);
                    mem_region->header.op = HYPER_RESP_WRITE_FAIL;
                    goto out;
                }
            } else {
                parent = parent_dir_struct->entry;
                if (!parent) {
                    printk(KERN_EMERG "portal_procfs: Invalid empty parent_id=%d for file '%s'\n", req->parent_id, entry_name);
                    mem_region->header.op = HYPER_RESP_WRITE_FAIL;
                    goto out;
                }
            }
        }
    }

    // Safety: Fetch the entry to check its type. PID-relative entries are
    // resolved by proc_tgid_base_lookup, not the root procfs rb-tree.
    if (req->parent_id == PROCFS_PID_PARENT_ID) {
        existing = NULL;
        exists = false;
    } else {
        existing = find_proc_subdir_entry(parent, entry_name);
        exists = (existing != NULL);
    }

    // printk(KERN_EMERG "portal_procfs: parent=%p, entry_name='%s'\n", parent, entry_name);

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
    pe->mmap_phys_addr = req->mmap_phys_addr;
    pe->python_release = req->fops.release;

    // Evaluate if we should fall back to the default mmap proxy
    enable_default_mmap = (req->size > 0 || req->support_mmap);

    // Create the file and bind the tracker
    if (req->parent_id == PROCFS_PID_PARENT_ID)
        file = igloo_proc_create_pid_file_data(entry_name, file_mode, &req->fops, pe, enable_default_mmap);
    else
        file = igloo_proc_create_data(entry_name, file_mode, parent, &req->fops, pe, enable_default_mmap);
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

    if (synthetic_pid_parent)
        remember_pid_template(parent_dir_struct->path, entry_name, pe);

    // printk(KERN_EMERG "portal_procfs: Created procfs entry '%s' with id %d\n", entry_name, id);

    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
    out:
        return;
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

    if (!req->parent_id && is_pid_compat_dir_name(dir_name)) {
        struct portal_procfs_dir *dir = create_pid_compat_dir(full_path);

        if (!dir) {
            printk(KERN_EMERG "portal_procfs: Failed to create synthetic pid dir: %s\n", full_path);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }

        mem_region->header.size = dir->id;
        mem_region->header.op = HYPER_RESP_READ_NUM;
        return;
    }

    entry = get_or_create_proc_dir(dir_name, parent, full_path, &dir_id);

    if (!entry) {
        printk(KERN_EMERG "portal_procfs: Failed to create/lookup dir: %s\n", full_path);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // printk(KERN_EMERG "portal_procfs: Created/Found dir '%s' with id %d\n", full_path, dir_id);
    mem_region->header.size = dir_id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}
