#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/sched.h>

// Helper macro for uprobe debug logs (using the designated uprobe module)
#define uprobe_debug(fmt, ...) igloo_debug_uprobe(fmt, ##__VA_ARGS__)

// Function prototypes with correct signatures
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data);
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data);
#else
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs);
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs);
#endif

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
    
    // Handle returned by uprobe_register (required for unregistering in newer kernels)
    struct uprobe *uprobe_handle;
    struct work_struct unregister_work;
    bool enabled;                // Flag to indicate if the probe is currently enabled
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
    pid_t tid;  // Thread ID
    pid_t tgid; // Thread Group ID (Process ID)
};

static void do_hyp(bool is_enter, uint64_t id, struct pt_regs *regs) {
    // Set the sequence number atomically
    uint64_t sequence = atomic64_inc_return(&syscall_sequence_counter);

    struct portal_event pe = {
        .id = id,
        .task = current,
        .regs = regs,
        .tid = current->pid,
        .tgid = current->tgid,
    };

    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_UPROBE_ENTER : IGLOO_HYP_UPROBE_RETURN,
                sequence, (unsigned long)&pe);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static int portal_uprobe(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data, bool is_enter){
#else
static int portal_uprobe(struct uprobe_consumer *uc, struct pt_regs *regs, bool is_enter){
#endif
    struct portal_uprobe *pu = container_of(uc, struct portal_uprobe, consumer);

    if (!pu->enabled){
        printk(KERN_EMERG "igloo: Received uprobe hit for disabled probe at ptr=%p\n", pu);
        return false;
    }

    uprobe_debug("igloo: portal_uprobe: ptr=%p, file=%s, offset=%lld, proc=%s, pid=%d\n",
                 pu, pu->filename, 
                 (long long)(pu->offset), current->comm, task_pid_nr(current));
    
    // Apply process name filter if set
    if (pu->filter_comm && strncmp(current->comm, pu->filter_comm, TASK_COMM_LEN) != 0) {
        uprobe_debug("igloo: Process name filter failed: %s != %s\n", current->comm, pu->filter_comm);
        return 0; // Not our target process, silently continue
    }
    
    // Apply PID filter if set (non-zero)
    if ((pu->filter_pid) != CURRENT_PID_NUM && 
        (pu->filter_pid) != task_pid_nr(current)) {
        uprobe_debug("igloo: PID filter failed: %d != %d\n", 
                     (int)(pu->filter_pid), task_pid_nr(current));
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data) {
    return portal_uprobe(uc, regs, data, true);
}
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long func_addr, struct pt_regs *regs, __u64 *data) {
    return portal_uprobe(uc, regs, data, false);
}
#else
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs) {
    return portal_uprobe(uc, regs, true);
}
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long func_addr, struct pt_regs *regs) {
    return portal_uprobe(uc, regs, false);
}
#endif


static void unregister_uprobe_deferred(struct work_struct *work)
{
    struct portal_uprobe *pu = container_of(work, struct portal_uprobe, unregister_work);
    
    uprobe_debug("igloo: Deferred unregistering uprobe at ptr=%p\n", pu);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)
    uprobe_unregister_nosync(pu->uprobe_handle, &pu->consumer);
    uprobe_unregister_sync();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    uprobe_unregister(pu->uprobe_handle, &pu->consumer);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    if (pu->uprobe_handle)
        uprobe_unregister(pu->uprobe_handle, &pu->consumer);
    else
        uprobe_unregister(pu->path.dentry->d_inode, pu->offset, &pu->consumer);
#else
    uprobe_unregister(pu->path.dentry->d_inode, pu->offset, &pu->consumer);
#endif
    
    synchronize_rcu();

    // Free resources
    path_put(&pu->path);
    kfree(pu->filename);
    if (pu->filter_comm) {
        kfree(pu->filter_comm);
    }
    kfree(pu);
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
    pu->enabled = true; // Mark the probe as enabled
    pu->path = file_path;
    pu->offset = reg->offset;
    pu->probe_type = reg->type;
    pu->filter_pid = reg->pid;
    
    // Save process filter if provided
    if (filter_comm) {
        pu->filter_comm = kstrdup(filter_comm, GFP_KERNEL);
        if (!pu->filter_comm) {
            uprobe_debug("igloo: Failed to allocate filter_comm memory\n");
            path_put(&file_path);
            kfree(pu->filename);
            kfree(pu);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            return;
        }
    }
    
    // Get a unique ID for this uprobe
    id = atomic_inc_return(&uprobe_id_counter);
    pu->id = id;

    // Initialize the work structure for deferred unregistration
    INIT_WORK(&pu->unregister_work, unregister_uprobe_deferred);
    
    // Zero the consumer struct to ensure clean state
    memset(&pu->consumer, 0, sizeof(pu->consumer));
    
    // Set up handlers based on probe type
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    if (reg->type == PORTAL_UPROBE_TYPE_ENTRY) {
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = NULL;
    } else if (reg->type == PORTAL_UPROBE_TYPE_RETURN) {
        pu->consumer.handler = NULL;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    } else if (reg->type == PORTAL_UPROBE_TYPE_BOTH) {
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    }
#else
    if (reg->type == PORTAL_UPROBE_TYPE_ENTRY) {
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = NULL;
    } else if (reg->type == PORTAL_UPROBE_TYPE_RETURN) {
        pu->consumer.handler = NULL;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    } else if (reg->type == PORTAL_UPROBE_TYPE_BOTH) {
        pu->consumer.handler = portal_uprobe_handler;
        pu->consumer.ret_handler = portal_uprobe_ret_handler;
    }
#endif

    // Register the uprobe
    inode = file_path.dentry->d_inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    {
        struct uprobe *uprobe;
        uprobe = uprobe_register(inode, reg->offset, 0, &pu->consumer);
        if (IS_ERR(uprobe)) {
            ret = PTR_ERR(uprobe);
            uprobe_debug("igloo: Failed to register uprobe: %d\n", ret);
            goto fail_put_path;
        }
        // Store the handle so we can safely unregister later
        pu->uprobe_handle = uprobe;
    }
#else
    ret = uprobe_register(inode, reg->offset, &pu->consumer);
    if (ret) {
        uprobe_debug("igloo: Failed to register uprobe: %d\n", ret);
        goto fail_put_path;
    }
#endif
    
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
    struct portal_uprobe *curr;
    struct hlist_node *tmp;
    
    // ID is stored in header.addr
    id = mem_region->header.addr;
    
    uprobe_debug("igloo: Unregistering uprobe with ID=%lu\n", id);
    spin_lock(&uprobe_lock);
    
    pu = NULL;
    
    hash_for_each_possible_safe(uprobe_table, curr, tmp, hlist, id) {
        if (curr->id == id) {
            pu = curr;
            hash_del(&curr->hlist); // Remove immediately while locked
            break;
        }
    }
    spin_unlock(&uprobe_lock);

    if (!pu) {
        uprobe_debug("igloo: Uprobe with ID %lu not found (or already unregistering)\n", id);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }

    // Now we own 'pu' exclusively. It is gone from the table.
    // It is safe to schedule the work.
    pu->enabled = false;
    schedule_work(&pu->unregister_work);
    
    // Return success
    mem_region->header.op = HYPER_RESP_READ_OK;
}