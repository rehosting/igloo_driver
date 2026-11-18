#include "portal_internal.h"
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h> /* Explicitly include for kernfs_node definition */
#include <linux/device.h> /* struct device, device kobj detection */
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
    uint64_t mmap_phys_addr;
    int parent_id;
    int replace;
    umode_t mode; 
};

struct portal_sysfs_dir {
    int id;
    struct kobject *kobj;
    int borrowed; /* 1 if kobj is kernel-owned (hooked/borrowed), not ours to free */
    int parent_id; /* logical parent id this dir was requested under */
    char name[PROCFS_MAX_PATH]; /* requested component name (for dedup) */
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

/*
 * -------------------------------------------------------------------------
 * Borrow an existing kernel-owned kobject.
 *
 * For a path like /sys/bus/pci/devices/0000:00:00.0, the final component is a
 * kernel-owned node (a symlink into /sys/devices/...). We must NOT recreate it
 * (that yields "sysfs: cannot create duplicate filename"); instead we resolve
 * the real kobject that backs it and attach our leaf attribute there, leaving
 * the directory's lifetime to its owning subsystem.
 *
 * Returns a kobject with its refcount bumped (caller must kobject_put), or
 * NULL if no existing node of a borrowable kind was found.
 * -------------------------------------------------------------------------
 */
static struct kobject *borrow_existing_kobj(struct kobject *parent, const char *name)
{
    struct kernfs_node *kn_parent, *kn_target;
    struct kobject *kobj = NULL;

    if (resolve_sysfs_symbols() < 0)
        return NULL;

    if (parent) {
        kn_parent = parent->sd;
    } else {
        if (*internal_sysfs_root)
            kn_parent = ((struct portal_kernfs_root *)(*internal_sysfs_root))->kn;
        else
            return NULL;
    }
    if (!kn_parent)
        return NULL;

    kn_target = internal_kernfs_find_and_get_ns(kn_parent, name, NULL);
    if (!kn_target)
        return NULL;

    /*
     * Follow one level of symlink. The bus/<bus>/devices/<addr> and
     * class/<class>/<dev> entries are KERNFS_LINK symlinks pointing at the
     * canonical device directory under /sys/devices/...; the kobject lives on
     * the *target* node's priv, not the symlink's.
     */
    if (kernfs_type(kn_target) == KERNFS_LINK) {
        struct kernfs_node *tgt = kn_target->symlink.target_kn;
        if (tgt) {
            /*
             * target_kn is a borrowed pointer owned by the symlink node; it
             * stays valid while we hold kn_target. Its priv is the kobject of
             * the canonical directory.
             */
            if (kernfs_type(tgt) == KERNFS_DIR && tgt->priv)
                kobj = (struct kobject *)tgt->priv;
        }
    } else if (kernfs_type(kn_target) == KERNFS_DIR) {
        /* A real directory node: priv is its kobject. */
        if (kn_target->priv)
            kobj = (struct kobject *)kn_target->priv;
    }
    /* KERNFS_FILE: an existing leaf attribute - not a dir to borrow. */

    if (kobj)
        kobject_get(kobj); /* pin for the caller */
    internal_kernfs_put(kn_target);
    return kobj;
}

/*
 * Whether a kobject belongs to the driver core (its ktype is device_ktype,
 * i.e. it is a struct device). Such kobjects dispatch sysfs attributes through
 * dev_sysfs_ops, which treats every attribute as a struct device_attribute and
 * calls show/store with (struct device *, struct device_attribute *, ...).
 *
 * struct kobj_attribute and struct device_attribute share an identical layout
 * ({struct attribute; show; store}), so our function pointers are still invoked
 * correctly - but the first argument is a struct device *, not a kobject *.
 * Const/discard models ignore it; a custom show/store that dereferences the
 * kobject would need to account for this. We only use the result to warn.
 */
static bool kobj_is_device(struct kobject *kobj)
{
    static const struct kobj_type *dev_ktype = NULL;
    static bool resolved = false;
    if (!resolved) {
        dev_ktype = (const struct kobj_type *)kallsyms_lookup_name("device_ktype");
        resolved = true;
    }
    return kobj && dev_ktype && kobj->ktype == dev_ktype;
}

/*
 * Whether adding a plain dynamic kobject as a CHILD of this (borrowed) kobject
 * is unsafe. A parent whose ktype defines child_ns_type uses NAMESPACED
 * children (e.g. /sys/class/net, which is per-network-namespace). Adding a
 * dynamic kobject there drives kobject_add_internal through the namespace path
 * (kobject_namespace -> kobj_child_ns_ops(parent)->...) which a dynamic child
 * does not satisfy, dereferencing a NULL op. A plain kobject like /sys/kernel
 * has no child_ns_type and hosts dynamic children fine. This is ktype-agnostic
 * (works for class/bus subsystems whose ktype is not the generic kset_ktype)
 * and needs no kallsyms.
 */
static bool kobj_rejects_dynamic_child(struct kobject *kobj)
{
    return kobj && kobj->ktype && kobj->ktype->child_ns_type;
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

    // printk(KERN_EMERG "portal_sysfs: handle_op_sysfs_create_file called\n");

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

    // When attaching to a borrowed struct device kobject, the driver core will
    // invoke show/store with a struct device * as the first argument (see
    // kobj_is_device). The struct layout is compatible so the call is safe for
    // const/discard models; warn for visibility since a kobject-deref custom
    // model would misbehave.
    if (kobj_is_device(parent))
        printk(KERN_INFO "portal_sysfs: '%s' attached to a struct device kobject; "
               "show/store receive a struct device * first arg\n", entry_name);

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

    // printk(KERN_EMERG "portal_sysfs: Created entry '%s' [id:%d] [mode:%o]\n", entry_name, id, req->mode);
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

    // Check if tracked. Match on the logical (requested) parent id and name so
    // that borrowed/symlink-resolved kobjects - whose real kobj->parent lives
    // elsewhere in the tree (e.g. /sys/devices/...) - still dedup correctly.
    spin_lock(&sysfs_dir_lock);
    list_for_each_entry(dir_entry, &sysfs_dir_list, list) {
        if (dir_entry->parent_id == req->parent_id &&
            strcmp(dir_entry->name, dir_name) == 0) {
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

    // Step 1: Borrow an existing kernel-owned kobject if present. This follows
    // one level of symlink so bus/class device aliases resolve to the canonical
    // /sys/devices/... kobject. On success we attach our files there and leave
    // the directory's lifetime to its owning subsystem.
    int borrowed = 0;
    if (!req->replace) {
        new_kobj = borrow_existing_kobj(parent_kobj, dir_name);
        if (new_kobj) {
            borrowed = 1;
            printk(KERN_INFO "portal_sysfs: Hooked into existing kobject '%s'\n",
                   dir_name);
        }
    }

    // Is the parent a kobject WE created and fully own, or one we borrowed from
    // the kernel? We can always add a child under a kobject we created. For a
    // BORROWED parent, adding a plain dynamic child is only safe if it is a
    // regular kobject (e.g. /sys/kernel) - NOT a kset (e.g. /sys/class/net),
    // whose child-ns ops oops kobject_add_internal for a dynamic child.
    int parent_is_ours = 0;
    if (req->parent_id != 0) {
        spin_lock(&sysfs_dir_lock);
        list_for_each_entry(dir_entry, &sysfs_dir_list, list) {
            if (dir_entry->id == req->parent_id) {
                parent_is_ours = !dir_entry->borrowed;
                break;
            }
        }
        spin_unlock(&sysfs_dir_lock);
    }
    int parent_rejects_child = (parent_kobj && !parent_is_ours)
                               ? kobj_rejects_dynamic_child(parent_kobj) : 0;

    // Step 2: If we could not borrow, decide whether it is safe to create.
    if (!new_kobj) {
        if (req->replace) {
            force_remove_sysfs_entry(parent_kobj, dir_name);
        } else {
            // Unsafe-parent guard: never add a dynamic child under a borrowed
            // parent that uses namespaced children (child_ns_type set), e.g.
            // the /sys/class/net kset. The kernel cannot host a plain kobject
            // there - kobject_add_internal walks the namespace path and
            // dereferences a NULL op. Such a node may also not exist yet at
            // registration time (so there is nothing to borrow), and creating
            // it under the kset is what triggers the fault.
            if (parent_rejects_child) {
                printk(KERN_WARNING
                    "portal_sysfs: refusing to create '%s' under a namespaced "
                    "kernel parent (unsafe for a dynamic child); skipping\n",
                    dir_name);
                mem_region->header.op = HYPER_RESP_WRITE_FAIL;
                return;
            }

            // Collision guard: refuse to recreate an existing kernel-owned node
            // (would duplicate/clobber it). Needs the kernfs helpers.
            if (resolve_sysfs_symbols() == 0) {
                struct kernfs_node *kn_parent =
                    parent_kobj ? parent_kobj->sd : NULL;
                if (!kn_parent && *internal_sysfs_root)
                    kn_parent = ((struct portal_kernfs_root *)(*internal_sysfs_root))->kn;
                if (kn_parent) {
                    struct kernfs_node *kn_dup =
                        internal_kernfs_find_and_get_ns(kn_parent, dir_name, NULL);
                    if (kn_dup) {
                        internal_kernfs_put(kn_dup);
                        printk(KERN_WARNING
                            "portal_sysfs: refusing to recreate existing "
                            "kernel-owned sysfs node '%s'; skipping\n", dir_name);
                        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
                        return;
                    }
                }
            }
        }

        if (!new_kobj)
            new_kobj = kobject_create_and_add(dir_name, parent_kobj);
    }

    if (!new_kobj) {
        printk(KERN_ERR "portal_sysfs: Failed to create or lookup dir '%s'\n", dir_name);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    dir_entry = kzalloc(sizeof(*dir_entry), GFP_KERNEL);
    dir_entry->kobj = new_kobj;
    dir_entry->borrowed = borrowed;
    dir_entry->parent_id = req->parent_id;
    strscpy(dir_entry->name, dir_name, sizeof(dir_entry->name));
    dir_entry->id = atomic_inc_return(&sysfs_dir_id);
    
    spin_lock(&sysfs_dir_lock);
    list_add(&dir_entry->list, &sysfs_dir_list);
    spin_unlock(&sysfs_dir_lock);

    mem_region->header.size = dir_entry->id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}