#include "portal_internal.h"
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

static LIST_HEAD(procfs_entry_list);
static atomic_t procfs_entry_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(procfs_entry_lock);

static LIST_HEAD(procfs_dir_list);
static atomic_t procfs_dir_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(procfs_dir_lock);

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
static struct proc_dir_entry *igloo_proc_create(const char *name, umode_t mode,
						struct proc_dir_entry *parent,
						const struct igloo_proc_ops *uops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
	struct proc_ops *pops = kmalloc(sizeof(struct proc_ops), GFP_KERNEL);
	igloo_convert_ops_to_proc_ops(uops, pops);
	return proc_create(name, mode, parent, pops);
#else
	struct file_operations *fops = kmalloc(sizeof(struct file_operations), GFP_KERNEL);
	igloo_convert_ops_to_fops(uops, fops);
	return proc_create(name, mode, parent, fops);
#endif
}



// Find or create a directory, return its proc_dir_entry and id
static struct proc_dir_entry *get_or_create_proc_dir(const char *name, struct proc_dir_entry *parent, const char *full_path, int *out_id)
{
    struct portal_procfs_dir *dir;
    struct proc_dir_entry *entry = NULL;
    int found = 0;

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

    entry = proc_mkdir(name, parent);
    if (!entry)
        return NULL;

    dir = kzalloc(sizeof(*dir), GFP_KERNEL);
    if (!dir) {
        remove_proc_entry(name, parent);
        return NULL;
    }
    dir->entry = entry;
    dir->path = kstrdup(full_path, GFP_KERNEL);
    if (!dir->path) {
        kfree(dir);
        remove_proc_entry(name, parent);
        return NULL;
    }
    dir->id = atomic_inc_return(&procfs_dir_id);

    spin_lock(&procfs_dir_lock);
    list_add(&dir->list, &procfs_dir_list);
    spin_unlock(&procfs_dir_lock);

    *out_id = dir->id;
    return entry;
}

/* Internal procfs symbol resolution for existence checks */
typedef struct proc_dir_entry *(*pde_subdir_find_t)(struct proc_dir_entry *dir, const char *name, unsigned int len);

static struct proc_dir_entry *internal_proc_root = NULL;
static pde_subdir_find_t internal_pde_subdir_find = NULL;

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

static bool check_proc_entry_exists(struct proc_dir_entry *parent, const char *name)
{
    struct proc_dir_entry *found;

    if (resolve_proc_symbols() < 0)
        return false;

    if (!parent)
        parent = internal_proc_root;

    found = internal_pde_subdir_find(parent, name, strlen(name));
    return (found != NULL);
}

// Create a new procfs entry
void handle_op_procfs_create_file(portal_region *mem_region)
{
    struct portal_procfs_create_req *req = (struct portal_procfs_create_req *)PORTAL_DATA(mem_region);
    struct proc_dir_entry *parent = NULL, *file;
    struct portal_procfs_entry *pe;
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

    // Use kallsyms/pde_subdir_find to check for existence before removing/creating
    exists = check_proc_entry_exists(parent, entry_name);

    // Parent must be provided (0 means root)
    if (req->parent_id) {
        parent = find_proc_dir_by_id(req->parent_id);
        if (!parent) {
            printk(KERN_EMERG "portal_procfs: Invalid parent_id=%d for file '%s'\n", req->parent_id, entry_name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            goto out;
        }
    } else {
        parent = NULL;
    }

    printk(KERN_EMERG "portal_procfs: parent=%p, entry_name='%s'\n", parent, entry_name);

    // Remove only if exists and replace is set
    if (exists && req->replace) {
        printk(KERN_EMERG "portal_procfs: Removing existing proc entry: %s\n", entry_name);
        remove_proc_entry(entry_name, parent);
        exists = false;
    }

    // If it exists and replace is not set, fail
    if (exists) {
        printk(KERN_EMERG "portal_procfs: proc entry '%s' already exists\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

    file = igloo_proc_create(entry_name, 0444, parent, &req->fops);
    if (!file) {
        printk(KERN_EMERG "portal_procfs: Failed to create proc entry: %s\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        printk(KERN_EMERG "portal_procfs: Failed to allocate portal_procfs_entry\n");
        remove_proc_entry(entry_name, parent);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

    pe->entry = file;
    pe->parent = parent;
    pe->name = kstrdup(entry_name, GFP_KERNEL);
    if (!pe->name) {
        printk(KERN_EMERG "portal_procfs: Failed to allocate name for procfs entry\n");
        remove_proc_entry(entry_name, parent);
        kfree(pe);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        goto out;
    }

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

