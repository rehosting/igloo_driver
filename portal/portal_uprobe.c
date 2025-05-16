#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/path.h>
#include <linux/fs.h>

// Helper macro for uprobe debug logs (using the designated uprobe module)
#define uprobe_debug(fmt, ...) igloo_debug_uprobe(fmt, ##__VA_ARGS__)

// Function prototypes with correct signatures
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data);
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data);

// Maximum number of uprobes we can register
#define MAX_UPROBES 1024

// Structure to track a registered uprobe
struct portal_uprobe {
    uint64_t id;                 // Unique ID for this probe
    struct path path;          // Path to the file with the uprobe
    uint64_t offset;             // Offset in the file
    struct hlist_node hlist;   // For tracking in hash table
    char *filename;            // Name of file (for reporting)
    char *filter_comm;         // Process name filter (NULL = no filter)
    uint64_t probe_type;         // Type of probe (entry or return)
    struct uprobe_consumer consumer; // Consumer for this probe
    
    // PID filtering support
    uint64_t filter_pid;         // PID to filter on (0 = no filter/match any)
};

// Structure for uprobe registration
struct uprobe_registration {
    char path[256];       // Path to the file with the uprobe
    unsigned long offset; // Offset in the file
    unsigned long type;   // ENTRY, RETURN, or BOTH
    unsigned long pid;    // PID filter or CURRENT_PID_NUM for any
    char comm[TASK_COMM_LEN]; // Process name filter (empty for none)
} __attribute__((packed));

// Hash table to track uprobes by ID
static DEFINE_HASHTABLE(uprobe_table, 10);  // 1024 buckets
static DEFINE_SPINLOCK(uprobe_lock);
static atomic_t uprobe_id_counter = ATOMIC_INIT(0);

// Global atomic counter for syscall sequence numbers
static atomic64_t syscall_sequence_counter = ATOMIC64_INIT(0);

struct portal_event {
    uint64_t id;
    struct task_struct *task;
    struct pt_regs *regs;
};

static void do_hyp(bool is_enter, uint64_t id, struct pt_regs *regs) {
    // Set the sequence number atomically
    uint64_t sequence = atomic64_inc_return(&syscall_sequence_counter);

    struct portal_event pe = {
	    .id = id,
	    .task = current,
	    .regs = regs,
    };

    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_UPROBE_ENTER : IGLOO_HYP_UPROBE_RETURN,
                sequence, (unsigned long)&pe);
}

static int portal_uprobe(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data, bool is_enter){
    struct portal_uprobe *pu = container_of(uc, struct portal_uprobe, consumer);
    
    // Apply process name filter if set
    if (pu->filter_comm && strncmp(current->comm, pu->filter_comm, TASK_COMM_LEN) != 0) {
        return 0; // Not our target process, silently continue
    }
    
    // Apply PID filter if set (non-zero)
    if ((pu->filter_pid) != CURRENT_PID_NUM && 
        (pu->filter_pid) != task_pid_nr(current)) {
        return 0; // Not our target PID, silently continue
    }
    
    // Explicitly inform the user which type of probe we're detecting
    uprobe_debug("igloo: %s uprobe hit: id=%llu, file=%s, offset=%lld, proc=%s, pid=%d\n",
                 is_enter ? "Entry" : "Return",
                 (unsigned long long)(pu->id), pu->filename, 
                 (long long)(pu->offset), current->comm, task_pid_nr(current));
    
    do_hyp(is_enter, pu->id, regs);
    return 0;
}

// Handler function for entry uprobe is hit
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data)
{
    return portal_uprobe(uc, regs, data, true);
}

// Handler function for return uprobe is hit
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data)
{
    return portal_uprobe(uc, regs, data, false);
}

// Search for a uprobe by ID
static struct portal_uprobe *find_uprobe_by_id(unsigned long id)
{
    struct portal_uprobe *pu;
    
    spin_lock(&uprobe_lock);
    hash_for_each_possible(uprobe_table, pu, hlist, id) {
        if ((pu->id) == id) {
            spin_unlock(&uprobe_lock);
            return pu;
        }
    }
    spin_unlock(&uprobe_lock);
    
    return NULL;
}

// Handler for registering a new uprobe
void handle_op_register_uprobe(portal_region *mem_region)
{
    struct portal_uprobe *pu;
    struct uprobe_registration *reg;
    unsigned long id;
    int ret;
    struct path file_path;
    struct inode *inode;
    char *filter_comm = NULL;
    
    // Map the input data to our registration structure
    reg = (struct uprobe_registration *) PORTAL_DATA(mem_region);
    
    // Ensure the path is null-terminated
    reg->path[sizeof(reg->path) - 1] = '\0';
    reg->comm[TASK_COMM_LEN - 1] = '\0';
    
    // Set filter_comm if not empty
    if (reg->comm[0] != '\0') {
        filter_comm = reg->comm;
    }
    
    uprobe_debug("igloo: Registering uprobe for path=%s, offset=%lu, type=%lu, filter=%s, pid=%lu\n", 
                 reg->path, reg->offset, reg->type, 
                 filter_comm ? filter_comm : "none", 
                 reg->pid);
    
    // Allocate a new uprobe structure
    pu = kzalloc(sizeof(*pu), GFP_KERNEL);
    if (!pu) {
        uprobe_debug("igloo: Failed to allocate uprobe structure\n");
        goto fail;
    }
    
    // Allocate memory for filename
    pu->filename = kstrdup(reg->path, GFP_KERNEL);
    if (!pu->filename) {
        uprobe_debug("igloo: Failed to allocate filename memory\n");
        goto fail_free_pu;
    }
    
    // Look up the file inode
    ret = kern_path(reg->path, LOOKUP_FOLLOW, &file_path);
    if (ret) {
        uprobe_debug("igloo: Failed to look up path %s: %d\n", reg->path, ret);
        goto fail_free_filename;
    }
    
    // Save the path 
    pu->path = file_path;
    pu->offset = reg->offset;
    pu->probe_type = reg->type;
    pu->filter_pid = reg->pid;
    
    // Save process filter if provided
    if (filter_comm) {
        pu->filter_comm = kstrdup(filter_comm, GFP_KERNEL);
        if (!pu->filter_comm) {
            uprobe_debug("igloo: Failed to allocate filter_comm memory\n");
            goto fail_free_filename;
        }
    }
    
    // Get a unique ID for this uprobe
    id = atomic_inc_return(&uprobe_id_counter);
    pu->id = id;
    
    // Zero the consumer struct to ensure clean state
    memset(&pu->consumer, 0, sizeof(pu->consumer));
    
    // Set up handlers based on probe type
    if (reg->type == PORTAL_UPROBE_TYPE_ENTRY) {
        // Entry-only probe
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = NULL;
    } else if (reg->type == PORTAL_UPROBE_TYPE_RETURN) {
        // Return-only probe
        pu->consumer.handler = NULL;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    } else if (reg->type == PORTAL_UPROBE_TYPE_BOTH) {
        // Both entry and return
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    }
    
    // Register the uprobe - this returns a pointer, we need to check for errors
    inode = file_path.dentry->d_inode;
    struct uprobe *uprobe = uprobe_register(inode, reg->offset, 0, &pu->consumer);
    if (IS_ERR(uprobe)) {
        ret = PTR_ERR(uprobe);
        uprobe_debug("igloo: Failed to register uprobe: %d\n", ret);
        goto fail_put_path;
    }
    
    // We don't need to store the uprobe pointer as uprobe_unregister_nosync takes the consumer
    
    // Add to hash table
    spin_lock(&uprobe_lock);
    hash_add(uprobe_table, &pu->hlist, id);
    spin_unlock(&uprobe_lock);
    
    // Return success with the unique ID
    mem_region->header.size = id; // Return the ID in size

    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;
    
fail_put_path:
    path_put(&file_path);
fail_free_filename:
    kfree(pu->filename);
fail_free_pu:
    kfree(pu);
fail:
    mem_region->header.op = HYPER_RESP_READ_FAIL;
}

// Handler for unregistering a uprobe
void handle_op_unregister_uprobe(portal_region *mem_region)
{
    unsigned long id;
    struct portal_uprobe *pu;
    
    // ID is stored in header.addr
    id = mem_region->header.addr;
    
    uprobe_debug("igloo: Unregistering uprobe with ID=%lu\n", id);
    
    // Find the uprobe
    pu = find_uprobe_by_id(id);
    if (!pu) {
        uprobe_debug("igloo: Uprobe with ID %lu not found\n", id);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    // Unregister the uprobe using the function from uprobes.h
    // NOTE: According to uprobes.h, uprobe_unregister_nosync() takes a struct uprobe*
    // Since we didn't store the returned uprobe pointer, we need to access the inode
    uprobe_unregister_nosync(NULL, &pu->consumer);
    
    // Remove from hash table
    spin_lock(&uprobe_lock);
    hash_del(&pu->hlist);
    spin_unlock(&uprobe_lock);
    
    // Free resources
    path_put(&pu->path);
    kfree(pu->filename);
    if (pu->filter_comm) {
        kfree(pu->filter_comm);
    }
    kfree(pu);
    
    // Return success
    mem_region->header.op = HYPER_RESP_READ_OK;
}