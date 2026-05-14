#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <net/net_namespace.h>
#include "portal_internal.h"

void handle_op_sysctl_create_file(portal_region *mem_region);

struct portal_sysctl_entry {
    struct ctl_table_header *header;
    struct ctl_table *table;
    struct ctl_table *replaced_leaf; 
    char *data_buffer;
    int id;
    struct list_head list;
};

static LIST_HEAD(sysctl_entry_list);
static DEFINE_SPINLOCK(sysctl_entry_lock);
static atomic_t sysctl_id_counter = ATOMIC_INIT(1);

/* Linux 6.5+ added const to the ctl_table argument in proc_handler */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#define IGLOO_CTL_CONST const
#else
#define IGLOO_CTL_CONST
#endif

// -----------------------------------------------------------------------------
// Default Handler Fallback
// -----------------------------------------------------------------------------
static int default_sysctl_handler(IGLOO_CTL_CONST struct ctl_table *ctl, int write,
                                  void __user *buffer, size_t *lenp, loff_t *ppos)
{
    return proc_dostring((IGLOO_CTL_CONST struct ctl_table *)ctl, write, buffer, lenp, ppos);
}

// -----------------------------------------------------------------------------
// VFS-based Sysctl Lookup
// -----------------------------------------------------------------------------
static struct ctl_table *igloo_find_sysctl_leaf(const char *dir_path, const char *entry_name, int offset)
{
    struct path path;
    char *full_path;
    int err;
    struct ctl_table *table = NULL;

    if (offset == 0) return NULL; // Offset required for VFS lookup safety

    full_path = kasprintf(GFP_KERNEL, "/proc/sys/%s/%s", dir_path, entry_name);
    if (!full_path) return NULL;

    // Remove any double slashes from normalization
    // (Simplistic cleanup: replace // with /)
    {
        char *p = full_path;
        while ((p = strstr(p, "//")) != NULL) {
            memmove(p, p + 1, strlen(p));
        }
    }

    err = kern_path(full_path, LOOKUP_FOLLOW, &path);
    kfree(full_path);

    if (err == 0) {
        struct inode *inode = d_backing_inode(path.dentry);
        if (inode) {
            // proc_inode contains both ctl_table_header and ctl_table *
            // We use the provided offset relative to vfs_inode.
            // Note: sysctl_entry is usually at a negative offset from vfs_inode.
            void **ptr_addr = (void **)((char *)inode + offset);
            
            // Safety: Verify we are actually in a proc_sysctl inode
            // (Heuristic: inode operations should be proc_sys_inode_operations)
            // But checking magic is easier if we had superblock.
            
            // For now, trust the offset provided by the trusted hypervisor/python layer.
            table = (struct ctl_table *)(*ptr_addr);
        }
        path_put(&path);
    }

    return table;
}


void handle_op_sysctl_create_file(portal_region *mem_region)
{
    struct portal_sysctl_create_req *req = (struct portal_sysctl_create_req *)PORTAL_DATA(mem_region);
    struct portal_sysctl_entry *entry;
    struct ctl_table *table;
    struct ctl_table *existing_leaf = NULL;
    char *clean_dir, *clean_name;
    size_t len;
    bool is_net;
    int id;
    
    // Ensure safety bounds from hypervisor shared memory
    req->dir_path[SYSCTL_MAX_PATH - 1] = '\0';
    req->entry_name[SYSCTL_MAX_NAME - 1] = '\0';

    clean_dir = req->dir_path;
    while (*clean_dir == '/') clean_dir++; 
    len = strlen(clean_dir);
    while (len > 0 && clean_dir[len - 1] == '/') {
        clean_dir[len - 1] = '\0'; 
        len--;
    }

    clean_name = req->entry_name;
    while (*clean_name == '/') clean_name++;
    len = strlen(clean_name);
    while (len > 0 && clean_name[len - 1] == '/') {
        clean_name[len - 1] = '\0';
        len--;
    }

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    entry->data_buffer = kzalloc(req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL, GFP_KERNEL);
    if (!entry->data_buffer) {
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }
    
    strncpy(entry->data_buffer, req->initial_value, 
            req->maxlen > 0 ? req->maxlen - 1 : SYSCTL_MAX_VAL - 1);

    // Attempt Mutation first
    existing_leaf = igloo_find_sysctl_leaf(clean_dir, clean_name, req->sysctl_entry_offset);

    if (existing_leaf) {
        // Mutation path
        existing_leaf->data = entry->data_buffer;
        existing_leaf->maxlen = req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL;
        existing_leaf->mode = req->mode ? req->mode : 0666; // Force override
        
        if (req->handler) {
            existing_leaf->proc_handler = (proc_handler *)req->handler;
        } else {
            existing_leaf->proc_handler = default_sysctl_handler;
        }

        entry->replaced_leaf = existing_leaf;
        entry->header = NULL; 
        entry->table = NULL;  
        goto success;
    }

    // Fallback: Shadowing path
    table = kzalloc(sizeof(struct ctl_table) * 2, GFP_KERNEL);
    if (!table) {
        kfree(entry->data_buffer);
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    table[0].procname = kstrdup(clean_name, GFP_KERNEL);
    table[0].data = entry->data_buffer;
    table[0].maxlen = req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL;
    table[0].mode = req->mode ? req->mode : 0644;
    
    table[0].proc_handler = req->handler ? (proc_handler *)req->handler : default_sysctl_handler;

    entry->table = table;
    is_net = (strncmp(clean_dir, "net/", 4) == 0 || strcmp(clean_dir, "net") == 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    if (is_net) entry->header = register_net_sysctl_sz(&init_net, clean_dir, table, 1);
    else entry->header = register_sysctl_sz(clean_dir, table, 1);
#else
    if (is_net) entry->header = register_net_sysctl(&init_net, clean_dir, table);
    else entry->header = register_sysctl(clean_dir, table);
#endif

    if (!entry->header) {
        printk(KERN_EMERG "portal_sysctl: Failed to register %s/%s\n", clean_dir, clean_name);
        kfree((void*)table[0].procname);
        kfree(entry->data_buffer);
        kfree(table);
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    // printk(KERN_EMERG "portal_sysctl: Created new %s/%s\n", clean_dir, clean_name);

success:
    id = atomic_inc_return(&sysctl_id_counter);
    entry->id = id;

    spin_lock(&sysctl_entry_lock);
    list_add(&entry->list, &sysctl_entry_list);
    spin_unlock(&sysctl_entry_lock);

    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}