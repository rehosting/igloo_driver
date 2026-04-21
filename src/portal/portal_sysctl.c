#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
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
// Safe Memory Accessors (Bypass EXPORT_SYMBOL limits)
// -----------------------------------------------------------------------------
static long igloo_safe_strncpy(char *dst, const char *unsafe_addr, long count)
{
    typedef long (*strncpy_nofault_t)(char *, const void *, long);
    static strncpy_nofault_t fn = NULL;
    static bool init = false;

    if (!init) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        fn = (strncpy_nofault_t)kallsyms_lookup_name("strncpy_from_kernel_nofault");
#else
        fn = (strncpy_nofault_t)kallsyms_lookup_name("strncpy_from_unsafe");
#endif
        init = true;
    }

    if (fn) return fn(dst, unsafe_addr, count);
    if ((unsigned long)unsafe_addr < PAGE_OFFSET) return -EFAULT;
    
    strncpy(dst, unsafe_addr, count - 1);
    dst[count - 1] = '\0';
    return strlen(dst);
}

static bool igloo_safe_read_ptr(void *src, void **dst) 
{
    typedef long (*copy_nofault_t)(void *, const void *, size_t);
    static copy_nofault_t fn = NULL;
    static bool init = false;

    if (!init) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        fn = (copy_nofault_t)kallsyms_lookup_name("copy_from_kernel_nofault");
#else
        fn = (copy_nofault_t)kallsyms_lookup_name("probe_kernel_read");
#endif
        init = true;
    }

    if (fn) return fn(dst, src, sizeof(void *)) == 0;
    if ((unsigned long)src < PAGE_OFFSET) return false;
    
    *dst = *(void **)src;
    return true;
}

// -----------------------------------------------------------------------------
// Internal Kernel Struct Recreations for RB-Tree Walking 
// -----------------------------------------------------------------------------
struct igloo_ctl_dir {
    struct ctl_table_header header;
    struct rb_root root;
};

struct igloo_ctl_table_set {
    int (*is_seen)(struct ctl_table_set *);
    struct igloo_ctl_dir dir;
};

struct igloo_ctl_table_root {
    struct igloo_ctl_table_set default_set;
};

struct igloo_ctl_node {
    struct rb_node node;
    struct ctl_table_header *header;
};

static int igloo_namecmp(const char *name1, int len1, const char *name2, int len2)
{
    int cmp = memcmp(name1, name2, min(len1, len2));
    if (cmp == 0)
        cmp = len1 - len2;
    return cmp;
}

// Generic RB-Tree Node Resolver
static struct ctl_table *igloo_find_entry_in_dir(struct rb_root *root, const char *name, struct ctl_table_header **out_head)
{
    struct rb_node *node;
    int namelen;
    
    if (!root) return NULL;
    node = root->rb_node;
    namelen = strlen(name);

    while (node) {
        struct igloo_ctl_node *ctl_node = rb_entry(node, struct igloo_ctl_node, node);
        struct ctl_table_header *head;
        struct igloo_ctl_node *node_array;
        struct ctl_table *table_base;
        struct ctl_table *entry;
        const char *procname;
        char name_buf[64];
        int cmp;

        if (!igloo_safe_read_ptr(&ctl_node->header, (void **)&head)) break;
        if (!igloo_safe_read_ptr(&head->node, (void **)&node_array)) break;
        if (!igloo_safe_read_ptr(&head->ctl_table, (void **)&table_base)) break;

        long offset = (char *)ctl_node - (char *)node_array;
        int index = offset / sizeof(struct igloo_ctl_node);
        
        entry = &table_base[index];
        
        if (!igloo_safe_read_ptr(&entry->procname, (void **)&procname)) break;
        if (igloo_safe_strncpy(name_buf, procname, sizeof(name_buf)) <= 0) break;

        cmp = igloo_namecmp(name, namelen, name_buf, strlen(name_buf));
        
        if (cmp < 0)
            node = node->rb_left;
        else if (cmp > 0)
            node = node->rb_right;
        else {
            if (out_head) *out_head = head;
            return entry;
        }
    }
    return NULL;
}

// Main Sysctl Intercept Lookup
static struct ctl_table *igloo_find_sysctl_leaf(const char *dir_path, const char *entry_name)
{
    struct igloo_ctl_table_root *sysctl_root;
    struct igloo_ctl_dir *dir;
    struct ctl_table *entry = NULL;
    struct ctl_table_header *head = NULL;
    char path_copy[256];
    char *token, *rest;

    sysctl_root = (struct igloo_ctl_table_root *)kallsyms_lookup_name("sysctl_table_root");
    if (!sysctl_root) return NULL;

    dir = &sysctl_root->default_set.dir;

    if (dir_path && dir_path[0]) {
        strncpy(path_copy, dir_path, sizeof(path_copy) - 1);
        path_copy[sizeof(path_copy) - 1] = '\0';
        rest = path_copy;

        while ((token = strsep(&rest, "/")) != NULL) {
            if (*token == '\0') continue;
            
            entry = igloo_find_entry_in_dir(&dir->root, token, &head);
            if (!entry) return NULL;
            
            dir = container_of(head, struct igloo_ctl_dir, header);
        }
    }

    return igloo_find_entry_in_dir(&dir->root, entry_name, &head);
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

    existing_leaf = igloo_find_sysctl_leaf(clean_dir, clean_name);

    if (existing_leaf) {
        printk(KERN_EMERG "portal_sysctl: Mutating existing internal entry %s/%s\n", clean_dir, clean_name);
        
        existing_leaf->data = entry->data_buffer;
        existing_leaf->maxlen = req->maxlen > 0 ? req->maxlen : SYSCTL_MAX_VAL;
        
        // FORCED READ/WRITE OVERRIDE
        // Overrides original kernel properties (e.g. 0200) and ignores python-side 
        // serializations to guarantee our intercepted hypercall receives read and write requests.
        existing_leaf->mode = 0666; 
        
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