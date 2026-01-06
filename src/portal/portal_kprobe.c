#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/syscalls.h>
#include <linux/version.h>

/* TODO: consider using tracepoints if available */

// Helper macro for kprobe debug logs
#define kprobe_debug(fmt, ...) igloo_debug_kprobe(fmt, ##__VA_ARGS__)

// Maximum number of kprobes we can register
#define MAX_KPROBES 1024

// Structure to track a registered kprobe
struct portal_kprobe {
    uint64_t id;                 // Unique ID for this probe
    struct hlist_node hlist;     // For tracking in hash table
    char *symbol;                // Symbol name
    char *filter_comm;           // Process name filter (NULL = no filter)
    uint64_t probe_type;         // Type of probe (entry or return)

    // kprobe specific structures
    struct kprobe kp;
    struct kretprobe rp;
    bool kp_registered;
    bool rp_registered;

    // PID filtering support
    uint64_t filter_pid;         // PID to filter on (0 = no filter/match any)
};

// Structure for kprobe registration
struct kprobe_registration {
    char symbol[256];     // Symbol name
    unsigned long offset; // Offset in the function (only for kprobe)
    unsigned long type;   // ENTRY, RETURN, or BOTH
    unsigned long pid;    // PID filter or CURRENT_PID_NUM for any
    char comm[TASK_COMM_LEN]; // Process name filter (empty for none)
} __attribute__((packed));

// Hash table to track kprobes by ID
static DEFINE_HASHTABLE(kprobe_table, 10);  // 1024 buckets
static DEFINE_SPINLOCK(kprobe_lock);
static atomic_t kprobe_id_counter = ATOMIC_INIT(0);

// Global atomic counter for syscall sequence numbers
static atomic64_t kprobe_sequence_counter = ATOMIC64_INIT(0);

struct portal_event {
    uint64_t id;
    struct task_struct *task;
    struct pt_regs *regs;
};

static void do_hyp_kprobe(bool is_enter, uint64_t id, struct pt_regs *regs) {
    // Set the sequence number atomically
    uint64_t sequence = atomic64_inc_return(&kprobe_sequence_counter);

    struct portal_event pe = {
	    .id = id,
	    .task = current,
	    .regs = regs,
    };

    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_KPROBE_ENTER : IGLOO_HYP_KPROBE_RETURN,
                sequence, (unsigned long)&pe);
}

// Kprobe pre_handler (Entry)
static int portal_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct portal_kprobe *pk = container_of(p, struct portal_kprobe, kp);

    kprobe_debug("igloo: kprobe entry: id=%llu, symbol=%s, proc=%s, pid=%d\n",
                 (unsigned long long)(pk->id), pk->symbol,
                 current->comm, task_pid_nr(current));

    if (pk->filter_comm && strncmp(current->comm, pk->filter_comm, TASK_COMM_LEN) != 0) {
        return 0;
    }

    if ((pk->filter_pid) != CURRENT_PID_NUM &&
        (pk->filter_pid) != task_pid_nr(current)) {
        return 0;
    }

    do_hyp_kprobe(true, pk->id, regs);
    return 0;
}

// Kretprobe handler (Return)
static int portal_kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct portal_kprobe *pk;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    struct kretprobe *curr_rp = get_kretprobe(ri);
    pk = container_of(curr_rp, struct portal_kprobe, rp);
    #else
    /* legacy path */
    pk = container_of(ri->rp, struct portal_kprobe, rp);
    #endif

    kprobe_debug("igloo: kprobe return: id=%llu, symbol=%s, proc=%s, pid=%d\n",
                 (unsigned long long)(pk->id), pk->symbol,
                 current->comm, task_pid_nr(current));

    if (pk->filter_comm && strncmp(current->comm, pk->filter_comm, TASK_COMM_LEN) != 0) {
        return 0;
    }

    if ((pk->filter_pid) != CURRENT_PID_NUM &&
        (pk->filter_pid) != task_pid_nr(current)) {
        return 0;
    }

    do_hyp_kprobe(false, pk->id, regs);
    return 0;
}

// Search for a kprobe by ID
static struct portal_kprobe *find_kprobe_by_id(unsigned long id)
{
    struct portal_kprobe *pk;

    spin_lock(&kprobe_lock);
    hash_for_each_possible(kprobe_table, pk, hlist, id) {
        if ((pk->id) == id) {
            spin_unlock(&kprobe_lock);
            return pk;
        }
    }
    spin_unlock(&kprobe_lock);

    return NULL;
}

// Handler for registering a new kprobe
void handle_op_register_kprobe(portal_region *mem_region)
{
    struct portal_kprobe *pk;
    struct kprobe_registration *reg;
    unsigned long id;
    int ret;
    char *filter_comm = NULL;

    // Map the input data to our registration structure
    reg = (struct kprobe_registration *) PORTAL_DATA(mem_region);

    // Ensure the symbol is null-terminated
    reg->symbol[sizeof(reg->symbol) - 1] = '\0';
    reg->comm[TASK_COMM_LEN - 1] = '\0';

    // Set filter_comm if not empty
    if (reg->comm[0] != '\0') {
        filter_comm = reg->comm;
    }

    kprobe_debug("igloo: Registering kprobe for symbol=%s, offset=%lu, type=%lu, filter=%s, pid=%lu\n",
                 reg->symbol, reg->offset, reg->type,
                 filter_comm ? filter_comm : "none",
                 reg->pid);

    // Allocate a new kprobe structure
    pk = kzalloc(sizeof(*pk), GFP_KERNEL);
    if (!pk) {
        kprobe_debug("igloo: Failed to allocate kprobe structure\n");
        goto fail;
    }

    // Allocate memory for symbol
    pk->symbol = kstrdup(reg->symbol, GFP_KERNEL);
    if (!pk->symbol) {
        kprobe_debug("igloo: Failed to allocate symbol memory\n");
        goto fail_free_pk;
    }

    pk->probe_type = reg->type;
    pk->filter_pid = reg->pid;

    // Save process filter if provided
    if (filter_comm) {
        pk->filter_comm = kstrdup(filter_comm, GFP_KERNEL);
        if (!pk->filter_comm) {
            kprobe_debug("igloo: Failed to allocate filter_comm memory\n");
            goto fail_free_symbol;
        }
    }

    // Get a unique ID for this kprobe
    id = atomic_inc_return(&kprobe_id_counter);
    pk->id = id;

    // Register KPROBE (Entry)
    if (reg->type == PORTAL_UPROBE_TYPE_ENTRY || reg->type == PORTAL_UPROBE_TYPE_BOTH) {
        pk->kp.symbol_name = pk->symbol;
        pk->kp.offset = reg->offset;
        pk->kp.pre_handler = portal_kprobe_pre_handler;

        ret = register_kprobe(&pk->kp);
        if (ret < 0) {
            kprobe_debug("igloo: Failed to register kprobe: %d\n", ret);
            goto fail_free_comm;
        }
        pk->kp_registered = true;
    }

    // Register KRETPROBE (Return)
    if (reg->type == PORTAL_UPROBE_TYPE_RETURN || reg->type == PORTAL_UPROBE_TYPE_BOTH) {
        // kretprobe doesn't support offset usually, or it must be 0 (entry)
        // We'll use the symbol.
        pk->rp.kp.symbol_name = pk->symbol;
        // pk->rp.kp.offset = reg->offset; // Usually 0 for kretprobe
        pk->rp.handler = portal_kretprobe_handler;
        pk->rp.maxactive = 0; // Default maxactive

        ret = register_kretprobe(&pk->rp);
        if (ret < 0) {
            kprobe_debug("igloo: Failed to register kretprobe: %d\n", ret);
            // If we already registered kprobe, we should unregister it
            if (pk->kp_registered) {
                unregister_kprobe(&pk->kp);
            }
            goto fail_free_comm;
        }
        pk->rp_registered = true;
    }

    // Add to hash table
    spin_lock(&kprobe_lock);
    hash_add(kprobe_table, &pk->hlist, id);
    spin_unlock(&kprobe_lock);

    // Return success with the unique ID
    mem_region->header.size = id; // Return the ID in size

    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;

fail_free_comm:
    if (pk->filter_comm) kfree(pk->filter_comm);
fail_free_symbol:
    kfree(pk->symbol);
fail_free_pk:
    kfree(pk);
fail:
    mem_region->header.op = HYPER_RESP_READ_FAIL;
}

// Handler for unregistering a kprobe
void handle_op_unregister_kprobe(portal_region *mem_region)
{
    unsigned long id;
    struct portal_kprobe *pk;

    // ID is stored in header.addr
    id = mem_region->header.addr;

    kprobe_debug("igloo: Unregistering kprobe with ID=%lu\n", id);

    // Find the kprobe
    pk = find_kprobe_by_id(id);
    if (!pk) {
        kprobe_debug("igloo: Kprobe with ID %lu not found\n", id);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }

    if (pk->kp_registered) {
        unregister_kprobe(&pk->kp);
    }
    if (pk->rp_registered) {
        unregister_kretprobe(&pk->rp);
    }

    // Remove from hash table
    spin_lock(&kprobe_lock);
    hash_del(&pk->hlist);
    spin_unlock(&kprobe_lock);

    // Free resources
    kfree(pk->symbol);
    if (pk->filter_comm) {
        kfree(pk->filter_comm);
    }
    kfree(pk);

    // Return success
    mem_region->header.op = HYPER_RESP_READ_OK;
}
