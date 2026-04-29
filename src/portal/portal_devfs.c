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
#include <linux/file.h>        // Required for fput()
#include <linux/shmem_fs.h>    // Required for shmem_kernel_file_setup()
#include <linux/vmalloc.h>     // Required for kvzalloc/vzalloc()
#include <linux/blkdev.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
#include <linux/genhd.h>
#endif
#include <linux/blk-mq.h>

#include "portal_devfs.h"

// Request to create a directory in devfs
struct portal_devfs_dir_req {
    char name[64];
    int parent_id; // 0 if root
    int replace;   // Placeholder/Padding
};

// Request to create a device node
struct portal_devfs_create_req {
    char name[64];
    uint64_t size;
    int support_mmap;
    int is_block;
    int logical_block_size;
    int major; 
    int minor;
    struct igloo_dev_ops ops;
    int replace;
    int parent_id;
};

// Internal: Track created devices
struct portal_devfs_entry {
    int id;
    dev_t devt;
    uint8_t is_block;

    struct cdev cdev;
    struct device *device;
    struct file_operations fops;
    struct list_head list;

    // Block dev specific
    struct gendisk *gd;
    struct block_device_operations bdops;
    struct blk_mq_tag_set tag_set;
    
    // MMAP / Release support
    struct mutex shm_lock;
    struct file *shm_file;
    int (*python_release)(struct inode *, struct file *);
    char *name;
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

// --- Forward declaration for the hypercall bridge (defined in portal_procfs.c) ---
extern ssize_t igloo_fetch_mmap_page(struct file *file, void *buffer, loff_t offset, size_t size);

static void igloo_devfs_flush_shm_to_hypervisor(struct file *file, struct portal_devfs_entry *pe)
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

static int igloo_devfs_proxy_release(struct inode *inode, struct file *file)
{
    struct portal_devfs_entry *pe;
    
    if (!inode->i_cdev) return 0;
    pe = container_of(inode->i_cdev, struct portal_devfs_entry, cdev);

    // 1. Flush any mmap writebacks to Python
    if (pe && pe->shm_file) {
        igloo_devfs_flush_shm_to_hypervisor(file, pe);
    }

    // 2. Forward to Python release if provided
    if (pe && pe->python_release) {
        return pe->python_release(inode, file);
    }

    return 0;
}

static int igloo_devfs_proxy_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct inode *inode = file_inode(file);
    struct portal_devfs_entry *pe;
    struct file *shm_file;
    size_t size = vma->vm_end - vma->vm_start;
    int ret;

    if (!inode || !inode->i_cdev) return -ENODEV;
    
    // Resolve tracking struct from cdev
    pe = container_of(inode->i_cdev, struct portal_devfs_entry, cdev);

    if (!pe) {
        printk(KERN_ERR "igloo_mmap: No portal tracking data found for devfs inode\n");
        return -ENODEV;
    }

    mutex_lock(&pe->shm_lock);
    
    if (!pe->shm_file) {
        // LAZY INITIALIZATION: Create the backing file on first use
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        shm_file = shmem_kernel_file_setup(pe->name, size, vma->vm_flags | VM_NORESERVE);
#else
        shm_file = shmem_file_setup(pe->name, size, vma->vm_flags | VM_NORESERVE);
#endif
        
        if (!IS_ERR(shm_file)) {
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
            pe->shm_file = shm_file;
        }
    }
    
    shm_file = pe->shm_file;
    mutex_unlock(&pe->shm_lock);

    if (IS_ERR_OR_NULL(shm_file))
        return PTR_ERR(shm_file) ? PTR_ERR(shm_file) : -ENOMEM;

    // Swap the VMA backing file
    if (vma->vm_file) {
        fput(vma->vm_file);
    }
    vma->vm_file = get_file(shm_file);

    if (shm_file->f_op && shm_file->f_op->mmap)
        ret = shm_file->f_op->mmap(shm_file, vma);
    else
        ret = -ENODEV;

    return ret;
}

void igloo_convert_ops_to_fops(const struct igloo_dev_ops *ops, struct file_operations *out, bool enable_default_mmap)
{
    memset(out, 0, sizeof(*out));
    out->owner = THIS_MODULE;
    
    out->open = ops->open;
    out->read = ops->read;
    out->read_iter = ops->read_iter;
    out->write = ops->write;
    out->write_iter = ops->write_iter;
    out->llseek = ops->lseek;
    
    // NEW: Route release through our writeback proxy
    out->release = igloo_devfs_proxy_release; 
    
    out->poll = ops->poll;
    out->unlocked_ioctl = ops->ioctl;
#ifdef CONFIG_COMPAT
    out->compat_ioctl = ops->compat_ioctl;
#endif

    // Conditionally attach our default mmap handler ONLY if requested
    // and the user hasn't provided their own override.
    if (enable_default_mmap && ops->mmap == NULL) {
        out->mmap = igloo_devfs_proxy_mmap;
    } else {
        out->mmap = ops->mmap;
    }
    
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
 * The Multi-Queue Request Handler
 * ------------------------------------------------------------------------- */

// Ensure cross-kernel compatibility for block status returns
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    typedef blk_status_t igloo_blk_status_t;
    #define IGLOO_BLK_SUCCESS BLK_STS_OK
#else
    typedef int igloo_blk_status_t;
    #define IGLOO_BLK_SUCCESS 0 /* BLK_MQ_RQ_QUEUE_OK / standard 0 success */
#endif

static igloo_blk_status_t igloo_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    struct request *req = bd->rq;
    struct portal_devfs_entry *pe;
    struct req_iterator iter;
    struct bio_vec bvec;
    loff_t pos;

    // API Break: rq_disk removed in 5.11
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    pe = req->q->disk->private_data;
#else
    pe = req->rq_disk->private_data;
#endif

    pos = (loff_t)blk_rq_pos(req) << 9; 

    blk_mq_start_request(req);

    rq_for_each_segment(bvec, req, iter) {
        char *kaddr = kmap_atomic(bvec.bv_page) + bvec.bv_offset;
        
        if (rq_data_dir(req) == WRITE) {
            if (pe->fops.write)
                pe->fops.write(NULL, (const char __user *)kaddr, bvec.bv_len, &pos);
        } else {
            if (pe->fops.read)
                pe->fops.read(NULL, (char __user *)kaddr, bvec.bv_len, &pos);
        }
        
        kunmap_atomic(kaddr);
    }

    blk_mq_end_request(req, IGLOO_BLK_SUCCESS);
    return IGLOO_BLK_SUCCESS;
}

static const struct blk_mq_ops igloo_mq_ops = {
    .queue_rq = igloo_queue_rq,
};

static void igloo_convert_ops_to_bdops(const struct igloo_dev_ops *ops, struct block_device_operations *out)
{
    memset(out, 0, sizeof(*out));
    out->owner = THIS_MODULE;
    
    // Forward block IOCTLs (HDIO_GETGEO, BLKGETSIZE, etc) to Python
    out->ioctl = (void*)ops->ioctl;
#ifdef CONFIG_COMPAT
    out->compat_ioctl = (void*)ops->compat_ioctl;
#endif
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

    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        kfree(final_device_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    mutex_init(&pe->shm_lock);
    pe->name = kstrdup(req->name, GFP_KERNEL);
    pe->python_release = req->ops.release;
    pe->is_block = req->is_block;

    /* =====================================================================
     * BLOCK DEVICE REGISTRATION
     * ===================================================================== */
    if (pe->is_block) {
        int major = req->major;
        
        // 1. Register Major
        if (major >= 0) {
            ret = register_blkdev(major, final_device_name);
        } else {
            ret = register_blkdev(0, final_device_name);
            major = ret; 
        }
        if (ret < 0) goto fail_alloc;

        // 2. Setup Operations
        igloo_convert_ops_to_bdops(&req->ops, &pe->bdops);
        // We STILL populate fops so our queue_rq can invoke the Python pointers!
        igloo_convert_ops_to_fops(&req->ops, &pe->fops, false); 

        // 3. Initialize Multi-Queue
        // The (void *) cast gracefully silences the const warning on 4.10
        pe->tag_set.ops = (void *)&igloo_mq_ops;
        pe->tag_set.nr_hw_queues = 1;
        pe->tag_set.queue_depth = 128;
        pe->tag_set.numa_node = NUMA_NO_NODE;
        pe->tag_set.cmd_size = 0;
        pe->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
        blk_mq_alloc_tag_set(&pe->tag_set);

        // 4. Allocate Disk (The API changed fundamentally in 5.14 and again in 6.9)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
        {
            struct queue_limits lim;
            memset(&lim, 0, sizeof(lim));
            lim.logical_block_size = req->logical_block_size ? req->logical_block_size : 512;
            pe->gd = blk_mq_alloc_disk(&pe->tag_set, &lim, pe);
        }
        if (IS_ERR(pe->gd)) {
            unregister_blkdev(major, final_device_name);
            goto fail_alloc;
        }
        pe->gd->minors = 1;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
        pe->gd = blk_mq_alloc_disk(&pe->tag_set, pe);
        if (IS_ERR(pe->gd)) {
            unregister_blkdev(major, final_device_name);
            goto fail_alloc;
        }
        pe->gd->minors = 1;
#else
        pe->gd = alloc_disk(1); 
        if (!pe->gd) {
            unregister_blkdev(major, final_device_name);
            goto fail_alloc;
        }
        pe->gd->queue = blk_mq_init_queue(&pe->tag_set);
#endif

        pe->gd->major = major;
        pe->gd->first_minor = req->minor;
        pe->gd->fops = &pe->bdops;
        pe->gd->private_data = pe;
        snprintf(pe->gd->disk_name, 32, "%s", req->name);
        
        // Block customizations (moved to queue_limits in 6.9+)
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
        blk_queue_logical_block_size(pe->gd->queue, req->logical_block_size ? req->logical_block_size : 512);
#endif
        set_capacity(pe->gd, req->size >> 9); // Size in 512-byte sectors

        // 5. Add Disk (Error handling became mandatory in 5.15)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        ret = add_disk(pe->gd);
        if (ret) {
            put_disk(pe->gd);
            unregister_blkdev(major, final_device_name);
            goto fail_alloc;
        }
#else
        add_disk(pe->gd);
#endif
        
        devt = MKDEV(major, req->minor);
        
    } else {
        bool enable_default_mmap = (req->size > 0 || req->support_mmap);

        if (req->major >= 0) {
            devt = MKDEV(req->major, req->minor);
            if (req->replace) unregister_chrdev_region(devt, 1);
            ret = register_chrdev_region(devt, 1, final_device_name);
        } else {
            ret = alloc_chrdev_region(&devt, 0, 1, final_device_name);
        }

        if (ret < 0) goto fail_alloc;

        pe->devt = devt;
        igloo_convert_ops_to_fops(&req->ops, &pe->fops, enable_default_mmap);
        
        cdev_init(&pe->cdev, &pe->fops);
        pe->cdev.owner = THIS_MODULE;

        if (cdev_add(&pe->cdev, devt, 1)) {
            unregister_chrdev_region(devt, 1);
            goto fail_alloc;
        }

        pe->device = device_create(portal_class, NULL, devt, NULL, "%s", final_device_name);
        if (IS_ERR(pe->device)) {
            cdev_del(&pe->cdev);
            unregister_chrdev_region(devt, 1);
            goto fail_alloc;
        }
    }

    /* Track it */
    id = atomic_inc_return(&devfs_entry_id);
    pe->id = id;

    spin_lock(&devfs_entry_lock);
    list_add(&pe->list, &devfs_entry_list);
    spin_unlock(&devfs_entry_lock);

    // printk(KERN_INFO "portal_devfs: Registered %s '%s' (%d:%d) id=%d\n", 
        //    pe->is_block ? "blkdev" : "chrdev", final_device_name, MAJOR(devt), MINOR(devt), id);

    kfree(final_device_name);
    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;

fail_alloc:
    kfree(pe->name);
    kfree(pe);
    kfree(final_device_name);
    mem_region->header.op = HYPER_RESP_WRITE_FAIL;
}