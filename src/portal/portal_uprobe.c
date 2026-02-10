#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/version.h>

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

// Structure to track a registered uprobe
struct portal_uprobe {
    struct path path;          // Path to the file with the uprobe
    uint64_t offset;             // Offset in the file
    char *filename;            // Name of file (for reporting)
    char *filter_comm;         // Process name filter (NULL = no filter)
    uint64_t probe_type;         // Type of probe (entry or return)
    struct uprobe_consumer consumer; // Consumer for this probe
    
    // PID filtering support
    uint64_t filter_pid;         // PID to filter on (0 = no filter/match any)

    // Handle returned by uprobe_register (required for unregistering in newer kernels)
    struct uprobe *uprobe_handle;
};

// Structure for uprobe registration
struct uprobe_registration {
    char path[256];       // Path to the file with the uprobe
    unsigned long offset; // Offset in the file
    unsigned long type;   // ENTRY, RETURN, or BOTH
    unsigned long pid;    // PID filter or CURRENT_PID_NUM for any
    char comm[TASK_COMM_LEN]; // Process name filter (empty for none)
} __attribute__((packed));

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static int portal_uprobe(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data, bool is_enter){
#else
static int portal_uprobe(struct uprobe_consumer *uc, struct pt_regs *regs, bool is_enter){
#endif
    struct portal_uprobe *pu = container_of(uc, struct portal_uprobe, consumer);

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
    uprobe_debug("igloo: %s uprobe hit: ptr=%p, file=%s, offset=%lld, proc=%s, pid=%d\n",
                 is_enter ? "Entry" : "Return",
                 pu, pu->filename, 
                 (long long)(pu->offset), current->comm, task_pid_nr(current));
    
    // Pass the pointer address as the ID
    do_hyp(is_enter, (uint64_t)(unsigned long)pu, regs);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data)
{
    return portal_uprobe(uc, regs, data, true);
}
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data)
{
    return portal_uprobe(uc, regs, data, false);
}
#else
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
    return portal_uprobe(uc, regs, true);
}
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs)
{
    return portal_uprobe(uc, regs, false);
}
#endif

// Handler for registering a new uprobe
void handle_op_register_uprobe(portal_region *mem_region)
{
    struct portal_uprobe *pu;
    struct uprobe_registration *reg;
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
            path_put(&file_path);
            kfree(pu->filename);
            kfree(pu);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            return;
        }
    }
    
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
    
    // Return success with the pointer address as the ID
    mem_region->header.size = (uint64_t)(unsigned long)pu;

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
    struct portal_uprobe *pu;
    
    // ID is stored in header.addr, which is now the pointer
    pu = (struct portal_uprobe *)(unsigned long)mem_region->header.addr;
    
    if (!pu) {
        uprobe_debug("igloo: Attempted to unregister NULL pointer\n");
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }

    uprobe_debug("igloo: Unregistering uprobe at ptr=%p\n", pu);
    
    // Unregister the uprobe using the stored handle
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)
    /* * In 6.12+, uprobe_unregister was removed.
     * We use uprobe_unregister_nosync to initiate removal,
     * and uprobe_unregister_sync (which takes NO arguments) to wait for completion.
     */
    uprobe_unregister_nosync(pu->uprobe_handle, &pu->consumer);
    uprobe_unregister_sync();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    /* Newer kernels providing pointer-based unregister (synchronous) */
    uprobe_unregister(pu->uprobe_handle, &pu->consumer);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    /* Fallback for 5.4-5.10 range */
    if (pu->uprobe_handle)
        uprobe_unregister(pu->uprobe_handle, &pu->consumer);
    else
        uprobe_unregister(pu->path.dentry->d_inode, pu->offset, &pu->consumer);
#else
    /* Old kernels (e.g. 4.10) require inode + offset + consumer */
    uprobe_unregister(pu->path.dentry->d_inode, pu->offset, &pu->consumer);
#endif
    
    // Extra safety barrier (redundant with unregister_sync but cheap protection against races on older kernels)
    synchronize_rcu();

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