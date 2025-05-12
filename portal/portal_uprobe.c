#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/namei.h>

// Helper macro for uprobe debug logs (using the designated uprobe module)
#define uprobe_debug(fmt, ...) igloo_debug_uprobe(fmt, ##__VA_ARGS__)

// Function prototypes with correct signatures
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data);
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data);

// Maximum number of uprobes we can register
#define MAX_UPROBES 256

// Define probe types
#define PORTAL_UPROBE_TYPE_ENTRY   0
#define PORTAL_UPROBE_TYPE_RETURN   1
#define PORTAL_UPROBE_TYPE_BOTH    2  // Both entry and return probes

// Structure to track a registered uprobe
struct portal_uprobe {
    __le64 id;                 // Unique ID for this probe
    struct path path;          // Path to the file with the uprobe
    __le64 offset;             // Offset in the file
    struct hlist_node hlist;   // For tracking in hash table
    char *filename;            // Name of file (for reporting)
    char *filter_comm;         // Process name filter (NULL = no filter)
    __le64 probe_type;         // Type of probe (entry or return)
    struct uprobe_consumer consumer; // Consumer for this probe
};

// Hash table to track uprobes by ID
static DEFINE_HASHTABLE(uprobe_table, 8);  // 256 buckets
static DEFINE_SPINLOCK(uprobe_lock);
static atomic_t uprobe_id_counter = ATOMIC_INIT(0);

// Handler function for entry uprobe is hit
static int portal_uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data)
{
    struct portal_uprobe *pu = container_of(uc, struct portal_uprobe, consumer);
    
    // Apply process name filter if set
    if (pu->filter_comm && strncmp(current->comm, pu->filter_comm, TASK_COMM_LEN) != 0) {
        return 0; // Not our target process, silently continue
    }
    
    // Log that the uprobe was hit
    uprobe_debug("igloo: uprobe hit: id=%llu, file=%s, offset=%lld, proc=%s\n",
                 (unsigned long long)le64_to_cpu(pu->id), pu->filename, 
                 (long long)le64_to_cpu(pu->offset), current->comm);
    
    // Here we record the event, notify the hypervisor with the ID
    igloo_hypercall2(IGLOO_HYP_UPROBE_HIT, le64_to_cpu(pu->id), (unsigned long)current->pid);
    
    // Return 0 to indicate the probe was handled and execution should continue
    return 0;
}

// Handler function for return uprobe is hit
static int portal_uprobe_ret_handler(struct uprobe_consumer *uc, unsigned long flags, struct pt_regs *regs, __u64 *data)
{
    struct portal_uprobe *pu = container_of(uc, struct portal_uprobe, consumer);
    
    // Apply process name filter if set
    if (pu->filter_comm && strncmp(current->comm, pu->filter_comm, TASK_COMM_LEN) != 0) {
        return 0; // Not our target process, silently continue
    }
    
    // Log that the uprobe was hit
    uprobe_debug("igloo: uprobe return hit: id=%llu, file=%s, offset=%lld, proc=%s\n",
                 (unsigned long long)le64_to_cpu(pu->id), pu->filename, 
                 (long long)le64_to_cpu(pu->offset), current->comm);
    
    // Here we record the event, notify the hypervisor with the ID, marking this as a return hit
    igloo_hypercall2(IGLOO_HYP_UPROBE_HIT, le64_to_cpu(pu->id) | (1UL << 63), (unsigned long)current->pid);
    
    // Return 0 to indicate the probe was handled and execution should continue
    return 0;
}

// Search for a uprobe by ID
static struct portal_uprobe *find_uprobe_by_id(unsigned long id)
{
    struct portal_uprobe *pu;
    
    spin_lock(&uprobe_lock);
    hash_for_each_possible(uprobe_table, pu, hlist, id) {
        if (le64_to_cpu(pu->id) == id) {
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
    char *path;
    char *filter_comm = NULL;
    unsigned long offset;
    unsigned long id;
    int ret;
    struct path file_path;
    struct inode *inode;
    unsigned long probe_type = PORTAL_UPROBE_TYPE_ENTRY; // Default is a standard uprobe
    unsigned long data_offset = 0;
    
    // Data format: path\0[process_filter]\0[probe_type]
    // Path is stored at the beginning of the data area as a null-terminated string
    path = PORTAL_DATA(mem_region);
    data_offset = strlen(path) + 1; // Move past path and null terminator
    
    // Check for process filter string (optional)
    if (data_offset < le64_to_cpu(mem_region->header.size)) {
        filter_comm = PORTAL_DATA(mem_region) + data_offset;
        if (strlen(filter_comm) > 0) {
            data_offset += strlen(filter_comm) + 1; // Move past filter and null terminator
        } else {
            filter_comm = NULL; // Empty string means no filter
        }
    }
    
    // Check for probe type (optional)
    if (data_offset + sizeof(unsigned long) <= le64_to_cpu(mem_region->header.size)) {
        probe_type = *(unsigned long*)(PORTAL_DATA(mem_region) + data_offset);
        if (probe_type != PORTAL_UPROBE_TYPE_ENTRY && 
            probe_type != PORTAL_UPROBE_TYPE_RETURN &&
            probe_type != PORTAL_UPROBE_TYPE_BOTH) {
            probe_type = PORTAL_UPROBE_TYPE_ENTRY; // Invalid type, use default
        }
    }
    
    // Offset is stored in header.addr
    offset = le64_to_cpu(mem_region->header.addr);
    
    uprobe_debug("igloo: Registering uprobe for path=%s, offset=%lu, type=%lu, filter=%s\n", 
                 path, offset, probe_type, filter_comm ? filter_comm : "none");
    
    // Allocate a new uprobe structure
    pu = kzalloc(sizeof(*pu), GFP_KERNEL);
    if (!pu) {
        uprobe_debug("igloo: Failed to allocate uprobe structure\n");
        goto fail;
    }
    
    // Allocate memory for filename
    pu->filename = kstrdup(path, GFP_KERNEL);
    if (!pu->filename) {
        uprobe_debug("igloo: Failed to allocate filename memory\n");
        goto fail_free_pu;
    }
    
    // Look up the file inode
    ret = kern_path(path, LOOKUP_FOLLOW, &file_path);
    if (ret) {
        uprobe_debug("igloo: Failed to look up path %s: %d\n", path, ret);
        goto fail_free_filename;
    }
    
    // Save the path 
    pu->path = file_path;
    pu->offset = cpu_to_le64(offset);
    pu->probe_type = cpu_to_le64(probe_type);
    
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
    pu->id = cpu_to_le64(id);
    
    // Set up the uprobe consumer
    pu->consumer.handler = portal_uprobe_handler;
    
    // For return probes or both, set the return handler
    if (probe_type == PORTAL_UPROBE_TYPE_RETURN || probe_type == PORTAL_UPROBE_TYPE_BOTH) {
        pu->consumer.ret_handler = portal_uprobe_ret_handler; // Separate return handler
        
        // For return-only probes, don't set the entry handler
        if (probe_type == PORTAL_UPROBE_TYPE_RETURN) {
            pu->consumer.handler = NULL; // No entry handler for uretprobe
        }
    }
    
    // Register the uprobe - this returns a pointer, we need to check for errors
    inode = file_path.dentry->d_inode;
    struct uprobe *uprobe = uprobe_register(inode, offset, 0, &pu->consumer);
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
    mem_region->header.addr = cpu_to_le64(id); // Return the ID in addr
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    return;
    
fail_put_path:
    path_put(&file_path);
fail_free_filename:
    kfree(pu->filename);
fail_free_pu:
    kfree(pu);
fail:
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
}

// Handler for unregistering a uprobe
void handle_op_unregister_uprobe(portal_region *mem_region)
{
    unsigned long id;
    struct portal_uprobe *pu;
    
    // ID is stored in header.addr
    id = le64_to_cpu(mem_region->header.addr);
    
    uprobe_debug("igloo: Unregistering uprobe with ID=%lu\n", id);
    
    // Find the uprobe
    pu = find_uprobe_by_id(id);
    if (!pu) {
        uprobe_debug("igloo: Uprobe with ID %lu not found\n", id);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
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
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}