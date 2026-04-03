#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <net/net_namespace.h>
#include "portal_internal.h"

void handle_op_sysctl_create_file(portal_region *mem_region);

struct portal_sysctl_entry {
    struct ctl_table_header *header;
    struct ctl_table *table;
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

void handle_op_sysctl_create_file(portal_region *mem_region)
{
    struct portal_sysctl_create_req *req = (struct portal_sysctl_create_req *)PORTAL_DATA(mem_region);
    struct portal_sysctl_entry *entry;
    struct ctl_table *table;
    bool is_net;
    int id;
    
    // Ensure safety bounds from hypervisor shared memory
    req->dir_path[SYSCTL_MAX_PATH - 1] = '\0';
    req->entry_name[SYSCTL_MAX_NAME - 1] = '\0';

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    table = kzalloc(sizeof(struct ctl_table) * 2, GFP_KERNEL);
    if (!table) {
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    entry->data_buffer = kzalloc(req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL, GFP_KERNEL);
    if (!entry->data_buffer) {
        kfree(table);
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }
    
    strncpy(entry->data_buffer, req->initial_value, 
            req->maxlen > 0 ? req->maxlen - 1 : SYSCTL_MAX_VAL - 1);

    table[0].procname = kstrdup(req->entry_name, GFP_KERNEL);
    table[0].data = entry->data_buffer;
    table[0].maxlen = req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL;
    table[0].mode = req->mode ? req->mode : 0644;
    
    if (req->handler) {
        table[0].proc_handler = (proc_handler *)req->handler;
    } else {
        table[0].proc_handler = default_sysctl_handler;
    }

    entry->table = table;

    // -------------------------------------------------------------------------
    // NAMESPACE & KERNEL-SPECIFIC REGISTRATION
    // -------------------------------------------------------------------------
    is_net = (strncmp(req->dir_path, "net/", 4) == 0 || strcmp(req->dir_path, "net") == 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    if (is_net) {
        entry->header = register_net_sysctl_sz(&init_net, req->dir_path, table, 1);
    } else {
        entry->header = register_sysctl_sz(req->dir_path, table, 1);
    }
#else
    if (is_net) {
        entry->header = register_net_sysctl(&init_net, req->dir_path, table);
    } else {
        entry->header = register_sysctl(req->dir_path, table);
    }
#endif

    if (!entry->header) {
        printk(KERN_EMERG "portal_sysctl: Failed to register %s/%s\n", req->dir_path, req->entry_name);
        kfree((void*)table[0].procname);
        kfree(entry->data_buffer);
        kfree(table);
        kfree(entry);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    id = atomic_inc_return(&sysctl_id_counter);
    entry->id = id;

    spin_lock(&sysctl_entry_lock);
    list_add(&entry->list, &sysctl_entry_list);
    spin_unlock(&sysctl_entry_lock);

    printk(KERN_EMERG "portal_sysctl: Created %s/%s\n", req->dir_path, req->entry_name);
    
    // Return an ID instead of WRITE_OK to align perfectly with the Python portal expectations
    mem_region->header.size = id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}