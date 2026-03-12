#include "portal_internal.h"
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

/* * -------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------
 */

// Comprehensive Operations Structure
struct igloo_dev_ops {
    int     (*open)(struct inode *, struct file *);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
    loff_t  (*lseek)(struct file *, loff_t, int);
    int     (*release)(struct inode *, struct file *);
    unsigned int (*poll)(struct file *, struct poll_table_struct *);
    long     (*ioctl)(struct file *, unsigned int, unsigned long);
#ifdef CONFIG_COMPAT
    long     (*compat_ioctl)(struct file *, unsigned int, unsigned long);
#endif
    int      (*mmap)(struct file *, struct vm_area_struct *);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    
    int     (*flush)(struct file *, fl_owner_t id);
    int     (*fsync)(struct file *, loff_t, loff_t, int datasync);
    int     (*fasync)(int, struct file *, int);
    int     (*lock)(struct file *, int, struct file_lock *);
};

// Request to create a directory in devfs
struct portal_devfs_dir_req {
    char name[64];
    int parent_id; // 0 if root
    int replace;   // Placeholder/Padding
};

// Request to create a device node
struct portal_devfs_create_req {
    char name[64];
    int major; // -1 for dynamic
    int minor;
    struct igloo_dev_ops ops;
    int replace;
    int parent_id; // <--- NEW: ID of the parent directory
};

// Internal: Track created devices
struct portal_devfs_entry {
    int id;
    dev_t devt;
    struct cdev cdev;
    struct device *device;
    struct file_operations fops;
    struct list_head list;
};

// Internal: Track created directories to reconstruct paths
struct portal_devfs_dir_entry {
    int id;
    char *full_path; // Stores "parent/this_dir"
    struct list_head list;
};

static LIST_HEAD(devfs_entry_list);
static atomic_t devfs_entry_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(devfs_entry_lock);

static LIST_HEAD(devfs_dir_list);
static atomic_t devfs_dir_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(devfs_dir_lock);

// We need a class to trigger devtmpfs to create /dev nodes.
static struct class *portal_class = NULL;

/* * -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------
 */

static void igloo_convert_ops_to_fops(const struct igloo_dev_ops *ops, struct file_operations *out)
{
    memset(out, 0, sizeof(*out));
    out->owner = THIS_MODULE;
    
    out->open = ops->open;
    out->read = ops->read;
    out->read_iter = ops->read_iter;
    out->write = ops->write;
    out->write_iter = ops->write_iter;
    out->llseek = ops->lseek;
    out->release = ops->release;
    out->poll = ops->poll;
    out->unlocked_ioctl = ops->ioctl;
#ifdef CONFIG_COMPAT
    out->compat_ioctl = ops->compat_ioctl;
#endif
    out->mmap = ops->mmap;
    out->get_unmapped_area = ops->get_unmapped_area;
    
    out->flush = ops->flush;
    out->fsync = ops->fsync;
    out->fasync = ops->fasync;
    out->lock = ops->lock;
}

/**
 * Look up a directory path by its ID.
 * Caller must kfree the returned string.
 */
static char *get_dir_path_by_id(int id)
{
    struct portal_devfs_dir_entry *dir;
    char *path = NULL;

    if (id <= 0) return NULL; // Root or invalid

    spin_lock(&devfs_dir_lock);
    list_for_each_entry(dir, &devfs_dir_list, list) {
        if (dir->id == id) {
            // Duplicate string because caller might modify/free or we might release lock
            path = kstrdup(dir->full_path, GFP_ATOMIC);
            break;
        }
    }
    spin_unlock(&devfs_dir_lock);
    return path;
}

/* * -------------------------------------------------------------------------
 * Initialization
 * -------------------------------------------------------------------------
 */

static void ensure_portal_class(void)
{
    if (portal_class) return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    portal_class = class_create("portal");
#else
    portal_class = class_create(THIS_MODULE, "portal");
#endif
    if (IS_ERR(portal_class)) {
        printk(KERN_ERR "portal_devfs: Failed to create portal class\n");
        portal_class = NULL;
    }
}

/* * -------------------------------------------------------------------------
 * Directory Logic (New)
 * -------------------------------------------------------------------------
 */

void handle_op_devfs_create_or_lookup_dir(portal_region *mem_region)
{
    struct portal_devfs_dir_req *req = (struct portal_devfs_dir_req *)PORTAL_DATA(mem_region);
    struct portal_devfs_dir_entry *entry;
    char *parent_path = NULL;
    char *new_full_path = NULL;
    
    req->name[63] = '\0';

    // 1. Resolve Parent Path
    if (req->parent_id > 0) {
        parent_path = get_dir_path_by_id(req->parent_id);
        if (!parent_path) {
            // Parent ID requested but not found
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }
        // Format: "parent/current"
        new_full_path = kasprintf(GFP_KERNEL, "%s/%s", parent_path, req->name);
        kfree(parent_path);
    } else {
        // Format: "current"
        new_full_path = kstrdup(req->name, GFP_KERNEL);
    }

    if (!new_full_path) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // Optional optimization: Check if path already exists to avoid duplicates?
    // For now, we just create a new ID tracking this string.

    // 2. Create Entry
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        kfree(new_full_path);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    entry->id = atomic_inc_return(&devfs_dir_id);
    entry->full_path = new_full_path;

    spin_lock(&devfs_dir_lock);
    list_add(&entry->list, &devfs_dir_list);
    spin_unlock(&devfs_dir_lock);

    // Return the new ID
    mem_region->header.size = entry->id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}

/* * -------------------------------------------------------------------------
 * Device Logic
 * -------------------------------------------------------------------------
 */

void handle_op_devfs_create_device(portal_region *mem_region)
{
    struct portal_devfs_create_req *req = (struct portal_devfs_create_req *)PORTAL_DATA(mem_region);
    struct portal_devfs_entry *pe;
    int ret, id;
    dev_t devt = 0;
    
    char *final_device_name = NULL;
    char *dir_path = NULL;

    ensure_portal_class();
    if (!portal_class) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    req->name[63] = '\0';
    if (!req->name[0]) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // --- Path Construction ---
    // If parent_id is provided, we prepend the directory path to the device name.
    // e.g., dir="foo", name="bar" -> "foo/bar"
    // The kernel's device_create will see the slash and create the directory in devtmpfs.
    
    if (req->parent_id > 0) {
        dir_path = get_dir_path_by_id(req->parent_id);
        if (!dir_path) {
            printk(KERN_ERR "portal_devfs: Parent Dir ID %d not found for device %s\n", req->parent_id, req->name);
            mem_region->header.op = HYPER_RESP_WRITE_FAIL;
            return;
        }
        final_device_name = kasprintf(GFP_KERNEL, "%s/%s", dir_path, req->name);
        kfree(dir_path);
    } else {
        final_device_name = kstrdup(req->name, GFP_KERNEL);
    }

    if (!final_device_name) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    /* 1. Allocation of Major/Minor */
    if (req->major >= 0) {
        devt = MKDEV(req->major, req->minor);
        
        if (req->replace) {
            unregister_chrdev_region(devt, 1);
        }

        // Note: register_chrdev_region mainly affects /proc/devices. Slashes here are
        // generally acceptable, or we could sanitize just for this call if it fails.
        // For now, passing full path.
        ret = register_chrdev_region(devt, 1, final_device_name);
    } else {
        ret = alloc_chrdev_region(&devt, 0, 1, final_device_name);
    }

    if (ret < 0) {
        printk(KERN_ERR "portal_devfs: Failed to register chrdev region %d:%d name=%s (err: %d)\n", 
               req->major, req->minor, final_device_name, ret);
        kfree(final_device_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    /* 2. Setup Structures */
    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        unregister_chrdev_region(devt, 1);
        kfree(final_device_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    pe->devt = devt;
    
    // Convert the hypervisor ops into the persistent fops struct inside the entry
    igloo_convert_ops_to_fops(&req->ops, &pe->fops);
    
    cdev_init(&pe->cdev, &pe->fops);
    pe->cdev.owner = THIS_MODULE;

    /* 3. Add Cdev */
    ret = cdev_add(&pe->cdev, devt, 1);
    if (ret) {
        printk(KERN_ERR "portal_devfs: cdev_add failed (err: %d)\n", ret);
        kfree(pe);
        kfree(final_device_name);
        unregister_chrdev_region(devt, 1);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    /* 4. Create Device Node */
    // Passing portal_class ensures devtmpfs creates the /dev node.
    // Passing a name with slashes triggers subdirectory creation in devtmpfs.
    pe->device = device_create(portal_class, NULL, devt, NULL, "%s", final_device_name);
    
    if (IS_ERR(pe->device)) {
        printk(KERN_ERR "portal_devfs: device_create failed for %s\n", final_device_name);
        cdev_del(&pe->cdev);
        unregister_chrdev_region(devt, 1);
        kfree(pe);
        kfree(final_device_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    /* 5. Track it */
    id = atomic_inc_return(&devfs_entry_id);
    pe->id = id;

    spin_lock(&devfs_entry_lock);
    list_add(&pe->list, &devfs_entry_list);
    spin_unlock(&devfs_entry_lock);

    printk(KERN_INFO "portal_devfs: Registered device '%s' (%d:%d) id=%d\n", 
           final_device_name, MAJOR(devt), MINOR(devt), id);

    kfree(final_device_name);
    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}