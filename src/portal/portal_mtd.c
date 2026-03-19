#include "portal_internal.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/version.h>

/* --- Callback Type Definitions --- */
typedef int (*py_read_cb_t)(int id, unsigned long offset, unsigned long len, uint8_t *buf);
typedef int (*py_write_cb_t)(int id, unsigned long offset, unsigned long len, const uint8_t *buf);
typedef int (*py_erase_cb_t)(int id, unsigned long offset, unsigned long len);

/* --- Data Structures --- */

struct portal_mtd_nuke_req {
    int max_scan_index;
};

struct portal_mtd_create_req {
    char label[64];
    uint64_t total_size;
    uint32_t erase_size;
    uint32_t write_size;
    uint32_t oob_size;
    uint8_t  is_nand;
    
    /* 0 = VIRTUAL_ZEROS, 1 = PYTHON_CALLBACK */
    uint8_t  mode; 

    /* Callback Pointers (Only used if mode=1) */
    uint64_t cb_read_ptr;
    uint64_t cb_write_ptr;
    uint64_t cb_erase_ptr;
};

struct portal_mtd_entry {
    int id;
    struct mtd_info *mtd;
    
    /* Callback Pointers (NULL if mode=0) */
    py_read_cb_t  py_read;
    py_write_cb_t py_write;
    py_erase_cb_t py_erase;

    struct list_head list;
};

static LIST_HEAD(mtd_entry_list);
static atomic_t mtd_entry_id = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(mtd_entry_lock);

/* --- MTD Operations --- */

static int hybrid_mtd_read(struct mtd_info *mtd, loff_t from, size_t len,
                           size_t *retlen, u_char *buf)
{
    struct portal_mtd_entry *dev = mtd->priv;

    if (dev->py_read) {
        /* MODE 1: CALLBACK */
        int ret = dev->py_read(dev->id, (unsigned long)from, (unsigned long)len, buf);
        if (ret == 0) *retlen = len;
        return ret;
    }

    /* MODE 0: VIRTUAL ZEROS */
    // Just fill the buffer with zeros. No allocation needed.
    if (from + len > mtd->size) return -EINVAL;
    memset(buf, 0x00, len);
    *retlen = len;
    return 0;
}

static int hybrid_mtd_write(struct mtd_info *mtd, loff_t to, size_t len,
                            size_t *retlen, const u_char *buf)
{
    struct portal_mtd_entry *dev = mtd->priv;

    if (dev->py_write) {
        /* MODE 1: CALLBACK */
        int ret = dev->py_write(dev->id, (unsigned long)to, (unsigned long)len, buf);
        if (ret == 0) *retlen = len;
        return ret;
    }

    /* MODE 0: VIRTUAL ZEROS */
    // Discard writes (black hole)
    if (to + len > mtd->size) return -EINVAL;
    *retlen = len;
    return 0;
}

static int hybrid_mtd_erase(struct mtd_info *mtd, struct erase_info *instr)
{
    struct portal_mtd_entry *dev = mtd->priv;
    int ret = 0;

    if (dev->py_erase) {
        /* MODE 1: CALLBACK */
        ret = dev->py_erase(dev->id, (unsigned long)instr->addr, (unsigned long)instr->len);
    }
    
    /* MODE 0: VIRTUAL ZEROS -> Do nothing (already clean) */

    if (ret == 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
        instr->state = MTD_ERASE_DONE;
        mtd_erase_callback(instr);
#endif
    }
    return ret;
}

static int fake_block_isbad(struct mtd_info *mtd, loff_t ofs) { return 0; }

/* --- Command Handlers --- */
/* OP: NUKE EXISTING MTDs */
void handle_op_mtd_nuke(portal_region *mem_region)
{
    struct portal_mtd_nuke_req *req = (struct portal_mtd_nuke_req *)PORTAL_DATA(mem_region);
    struct mtd_info *mtd;
    int i, err, count = 0;
    int limit = (req->max_scan_index > 0) ? req->max_scan_index : 64;

    printk(KERN_INFO "portal_mtd: Scorched Earth - Nuking up to %d devices...\n", limit);

    for (i = 0; i < limit; i++) {
        // 1. Get a handle (Increments refcount to 1)
        mtd = get_mtd_device(NULL, i);
        if (IS_ERR(mtd)) continue;

        // 2. Drop the handle IMMEDIATELY. 
        // We must drop the refcount back to 0. If we hold it, 
        // mtd_device_unregister sees refcount=1 and fails with -EBUSY.
        put_mtd_device(mtd);

        // 3. Attempt to unregister
        // If the device was truly idle (refcount 0), this will now succeed.
        // If it was mounted/used by others, refcount is > 0 and this still fails safely.
        err = mtd_device_unregister(mtd);
        
        if (!err) {
            printk(KERN_INFO "portal_mtd: Nuked mtd%d (%s)\n", i, mtd->name);
            count++;
        } else {
            // This happens if the device is mounted or held by another driver
            printk(KERN_INFO "portal_mtd: Failed to nuke mtd%d (Still Busy)\n", i);
        }
    }

    mem_region->header.size = count;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}
void handle_op_mtd_create(portal_region *mem_region)
{
    struct portal_mtd_create_req *req = (struct portal_mtd_create_req *)PORTAL_DATA(mem_region);
    struct portal_mtd_entry *entry;
    struct mtd_info *mtd;
    u32 req_writesize;
    u32 req_erasesize;
    uint64_t req_total_size;
    
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    mtd = kzalloc(sizeof(struct mtd_info), GFP_KERNEL);
    
    if (!entry || !mtd) {
        kfree(entry); kfree(mtd);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    req->label[sizeof(req->label) - 1] = '\0';

    req_writesize = req->write_size ? req->write_size : 1;
    req_erasesize = req->erase_size ? req->erase_size : req_writesize;
    req_total_size = req->total_size;

    if (!req_total_size || !req->label[0]) {
        printk(KERN_ERR "portal_mtd: invalid create request (label='%s', size=%llu)\n",
               req->label, (unsigned long long)req_total_size);
        kfree(entry);
        kfree(mtd);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    if (req_total_size < req_erasesize)
        req_total_size = req_erasesize;

    /* Configure Identity */
    mtd->name = kstrdup(req->label, GFP_KERNEL);
    if (!mtd->name) {
        kfree(entry);
        kfree(mtd);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    mtd->size = req_total_size;
    mtd->erasesize = req_erasesize;
    mtd->writesize = req_writesize;
    mtd->oobsize = req->is_nand ? req->oob_size : 0;
    mtd->owner = THIS_MODULE;
    mtd->priv = entry;

    mtd->_read = hybrid_mtd_read;
    mtd->_write = hybrid_mtd_write;
    mtd->_erase = hybrid_mtd_erase;
    
    if (req->is_nand) {
        mtd->type = MTD_NANDFLASH;
        mtd->flags = MTD_CAP_NANDFLASH | MTD_WRITEABLE;
        mtd->_block_isbad = fake_block_isbad;
        /*
         * Keep only ->_read/->_write hooks. Newer MTD core rejects
         * devices that provide both ->_read and ->_read_oob.
         */
    } else {
        mtd->type = MTD_RAM;
        mtd->flags = MTD_CAP_RAM | MTD_WRITEABLE;
    }

    /* Configure Mode */
    if (req->mode == 0) {
        // VIRTUAL ZERO MODE: No callbacks, No vmalloc.
        entry->py_read = NULL;
        entry->py_write = NULL;
        entry->py_erase = NULL;
    } else {
        // CALLBACK MODE: Assign pointers
        entry->py_read = (py_read_cb_t)(unsigned long)req->cb_read_ptr;
        entry->py_write = (py_write_cb_t)(unsigned long)req->cb_write_ptr;
        entry->py_erase = (py_erase_cb_t)(unsigned long)req->cb_erase_ptr;
    }

    /* Register */
    if (mtd_device_register(mtd, NULL, 0)) {
        printk(KERN_ERR "portal_mtd: failed to register mtd '%s'\n", req->label);
        kfree(mtd->name); kfree(entry); kfree(mtd);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    /* Track ID */
    entry->id = atomic_inc_return(&mtd_entry_id);
    entry->mtd = mtd;
    
    spin_lock(&mtd_entry_lock);
    list_add(&entry->list, &mtd_entry_list);
    spin_unlock(&mtd_entry_lock);

    mem_region->header.size = entry->id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}