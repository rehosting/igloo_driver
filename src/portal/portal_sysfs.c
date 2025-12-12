#include "portal_internal.h"
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h> /* Explicitly include for kernfs_node definition */
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

/* * -------------------------------------------------------------------------
 * Internal Sysfs/Kernfs Symbol Resolution
 * Needed for the "Override" functionality to nuke existing driver files.
 * -------------------------------------------------------------------------
 */

struct kernfs_node;

/* * struct kernfs_root is not defined in public headers on newer kernels.
 * On older kernels (4.x), it is defined in kernfs.h.
 * To avoid redefinition errors or incomplete type errors, we define
 * a local shadow structure and cast to it.
 */
struct portal_kernfs_root {
    struct kernfs_node *kn;
};

typedef struct kernfs_node *(*kernfs_find_and_get_ns_t)(struct kernfs_node *parent, const char *name, const void *ns);
typedef void (*kernfs_put_t)(struct kernfs_node *kn);
typedef void (*kernfs_remove_t)(struct kernfs_node *kn);

static struct kernfs_root **internal_sysfs_root = NULL;
static kernfs_find_and_get_ns_t internal_kernfs_find_and_get_ns = NULL;
static kernfs_put_t internal_kernfs_put = NULL;
static kernfs_remove_t internal_kernfs_remove = NULL;

static int resolve_sysfs_symbols(void)
{
    if (internal_kernfs_remove)
        return 0;

    internal_sysfs_root = (struct kernfs_root **)kallsyms_lookup_name("sysfs_root");
    internal_kernfs_find_and_get_ns = (kernfs_find_and_get_ns_t)kallsyms_lookup_name("kernfs_find_and_get_ns");
    internal_kernfs_put = (kernfs_put_t)kallsyms_lookup_name("kernfs_put");
    internal_kernfs_remove = (kernfs_remove_t)kallsyms_lookup_name("kernfs_remove");

    if (!internal_sysfs_root || !internal_kernfs_find_and_get_ns || 
        !internal_kernfs_put || !internal_kernfs_remove) {
        printk(KERN_ERR "portal_sysfs: Failed to resolve kernfs symbols\n");
        return -ENOENT;
    }
    return 0;
}

/* * -------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------
 */

// Function pointers passed from Hypervisor/Host
struct igloo_sysfs_ops {
    ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
    ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
};

// Mirrors the request structure from the host
struct portal_sysfs_create_req {
    char path[PROCFS_MAX_PATH];
    struct igloo_sysfs_ops ops; // Ops passed from hypervisor
    int parent_id;
    int replace;
    umode_t mode; 
};

struct portal_sysfs_dir {
    int id;
    struct kobject *kobj;
    struct list_head list;
};

struct portal_sysfs_entry {
    int id;
    struct kobj_attribute kattr; // Embedded standard attribute
    char *name;
    struct list_head list;
};

static LIST_HEAD(sysfs_entry_list);
static atomic_t sysfs_entry_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(sysfs_entry_lock);

static LIST_HEAD(sysfs_dir_list);
static atomic_t sysfs_dir_id = ATOMIC_INIT(1);
static DEFINE_SPINLOCK(sysfs_dir_lock);

/* * -------------------------------------------------------------------------
 * Lookup Helpers
 * -------------------------------------------------------------------------
 */

static struct kobject *find_sysfs_kobj_by_id(int id)
{
    struct portal_sysfs_dir *dir;
    struct kobject *kobj = NULL;

    if (id == 0) return NULL; // Default to root (kernel_kobj or similar usually)

    spin_lock(&sysfs_dir_lock);
    list_for_each_entry(dir, &sysfs_dir_list, list) {
        if (dir->id == id) {
            kobj = dir->kobj;
            break;
        }
    }
    spin_unlock(&sysfs_dir_lock);
    return kobj;
}

// "Nuclear Option" to remove an existing entry regardless of owner
static int force_remove_sysfs_entry(struct kobject *parent, const char *name)
{
    struct kernfs_node *kn_parent, *kn_target;

    if (resolve_sysfs_symbols() < 0) return -ENODEV;

    if (parent) {
        kn_parent = parent->sd; 
    } else {
        // Fallback to sysfs root if parent is NULL
        if (*internal_sysfs_root)
            kn_parent = ((struct portal_kernfs_root *)(*internal_sysfs_root))->kn;
        else
            return -ENOENT;
    }

    if (!kn_parent) return -ENOENT;

    kn_target = internal_kernfs_find_and_get_ns(kn_parent, name, NULL);
    if (kn_target) {
        printk(KERN_WARNING "portal_sysfs: Force removing existing entry '%s'\n", name);
        internal_kernfs_remove(kn_target);
        internal_kernfs_put(kn_target);
        return 1; // Removed
    }
    return 0; // Did not exist
}

/* * -------------------------------------------------------------------------
 * Create File Logic
 * -------------------------------------------------------------------------
 */

void handle_op_sysfs_create_file(portal_region *mem_region)
{
    struct portal_sysfs_create_req *req = (struct portal_sysfs_create_req *)PORTAL_DATA(mem_region);
    struct kobject *parent = NULL;
    struct portal_sysfs_entry *pe;
    int id;
    char *entry_name;
    int ret;

    printk(KERN_EMERG "portal_sysfs: handle_op_sysfs_create_file called\n");

    req->path[PROCFS_MAX_PATH - 1] = '\0';
    entry_name = req->path;

    if (!entry_name[0] || strchr(entry_name, '/')) {
        printk(KERN_EMERG "portal_sysfs: Invalid name: '%s'\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // 1. Resolve Parent
    parent = find_sysfs_kobj_by_id(req->parent_id);
    
    // Fix: sysfs_create_file triggers a BUG if parent is NULL.
    // If we are at root (id 0) and have no parent, try to find root kobject.
    if (!parent && req->parent_id == 0 && kernel_kobj) {
        parent = kernel_kobj->parent;
    }

    if (!parent) {
        printk(KERN_EMERG "portal_sysfs: Cannot create file '%s' - no valid parent kobject (root files requires root kobj)\n", entry_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // 2. Handle Overrides (Force Remove)
    if (req->replace) {
        force_remove_sysfs_entry(parent, entry_name);
    }

    // 3. Allocate wrapper structure
    pe = kzalloc(sizeof(*pe), GFP_KERNEL);
    if (!pe) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // 4. Setup kobj_attribute manually
    // We duplicate the name string because sysfs doesn't manage the lifetime of the name pointer
    pe->name = kstrdup(entry_name, GFP_KERNEL);
    if (!pe->name) {
        kfree(pe);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    sysfs_attr_init(&pe->kattr.attr);
    pe->kattr.attr.name = pe->name;
    pe->kattr.attr.mode = req->mode; 
    
    // 5. Assign pointers directly from the hypervisor request
    // These pointers MUST be valid in the kernel's address space.
    pe->kattr.show = req->ops.show;
    pe->kattr.store = req->ops.store;

    // 6. Create in Sysfs
    ret = sysfs_create_file(parent, &pe->kattr.attr);
    if (ret) {
        printk(KERN_EMERG "portal_sysfs: Failed to create sysfs file '%s' (err: %d)\n", entry_name, ret);
        kfree(pe->name);
        kfree(pe);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // 7. Register internally
    id = atomic_inc_return(&sysfs_entry_id);
    pe->id = id;

    spin_lock(&sysfs_entry_lock);
    list_add(&pe->list, &sysfs_entry_list);
    spin_unlock(&sysfs_entry_lock);

    printk(KERN_EMERG "portal_sysfs: Created entry '%s' [id:%d] [mode:%o]\n", entry_name, id, req->mode);
    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}

/* * -------------------------------------------------------------------------
 * Directory Creation (For completeness)
 * -------------------------------------------------------------------------
 */

void handle_op_sysfs_create_or_lookup_dir(portal_region *mem_region)
{
    struct portal_sysfs_create_req *req = (struct portal_sysfs_create_req *)PORTAL_DATA(mem_region);
    struct kobject *parent_kobj = NULL;
    struct kobject *new_kobj = NULL;
    struct portal_sysfs_dir *dir_entry;
    char *dir_name;
    int dir_id = 0;

    req->path[PROCFS_MAX_PATH - 1] = '\0';
    dir_name = req->path;

    if (!dir_name[0] || strchr(dir_name, '/')) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    if (req->parent_id) {
        parent_kobj = find_sysfs_kobj_by_id(req->parent_id);
    }

    // Check if tracked
    spin_lock(&sysfs_dir_lock);
    list_for_each_entry(dir_entry, &sysfs_dir_list, list) {
        if (dir_entry->kobj->parent == parent_kobj && 
            strcmp(dir_entry->kobj->name, dir_name) == 0) {
            dir_id = dir_entry->id;
            break;
        }
    }
    spin_unlock(&sysfs_dir_lock);

    if (dir_id != 0) {
        mem_region->header.size = dir_id;
        mem_region->header.op = HYPER_RESP_READ_NUM;
        return;
    }

    // Step 1: Attempt Lookup FIRST to avoid noisy warnings
    if (!req->replace && resolve_sysfs_symbols() == 0) {
        struct kernfs_node *kn_parent = NULL, *kn_target = NULL;
        
        // Find parent kernfs node
        if (parent_kobj) {
            kn_parent = parent_kobj->sd;
        } else {
             if (*internal_sysfs_root)
                 kn_parent = ((struct portal_kernfs_root *)(*internal_sysfs_root))->kn;
        }
        
        if (kn_parent) {
            kn_target = internal_kernfs_find_and_get_ns(kn_parent, dir_name, NULL);
            if (kn_target) {
                // In sysfs, for directories, the priv data is the kobject.
                if (kn_target->priv) {
                    new_kobj = (struct kobject *)kn_target->priv;
                    kobject_get(new_kobj); // Must bump refcount
                    printk(KERN_INFO "portal_sysfs: Hooked into existing kobject '%s'\n", dir_name);
                }
                internal_kernfs_put(kn_target);
            }
        }
    }

    // Step 2: If lookup failed, or we are replacing, create it
    if (!new_kobj) {
        if (req->replace) {
            force_remove_sysfs_entry(parent_kobj, dir_name);
        }

        new_kobj = kobject_create_and_add(dir_name, parent_kobj);
    }

    if (!new_kobj) {
        printk(KERN_ERR "portal_sysfs: Failed to create or lookup dir '%s'\n", dir_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    dir_entry = kzalloc(sizeof(*dir_entry), GFP_KERNEL);
    dir_entry->kobj = new_kobj;
    dir_entry->id = atomic_inc_return(&sysfs_dir_id);
    
    spin_lock(&sysfs_dir_lock);
    list_add(&dir_entry->list, &sysfs_dir_list);
    spin_unlock(&sysfs_dir_lock);

    mem_region->header.size = dir_entry->id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}