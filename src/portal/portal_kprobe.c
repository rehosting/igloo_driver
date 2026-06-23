#include "portal_internal.h"
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/sched.h>

// Helper macro for kprobe debug logs (using the designated kprobe module)
#define kprobe_debug(fmt, ...) igloo_debug_kprobe(fmt, ##__VA_ARGS__)

// Structure for kprobe registration (sent by the host as the portal data payload)
struct kprobe_registration {
    char symbol[256];          // kernel symbol name (null-terminated)
    unsigned long offset;      // offset within the function (entry probes only; 0 for kretprobe)
    unsigned long type;        // PORTAL_KPROBE_TYPE_*
    unsigned long pid;         // PID filter or CURRENT_PID_NUM for any
    char comm[TASK_COMM_LEN];  // process-name filter (empty = none)
} __attribute__((packed));

// Structure to track a registered kprobe
struct portal_kprobe {
    uint64_t id;
    char *symbol;                 // kstrdup'd; kp.symbol_name / rp.kp.symbol_name point at this — must outlive the probe
    uint64_t offset;
    uint64_t probe_type;          // PORTAL_KPROBE_TYPE_*
    struct hlist_node hlist;
    char *filter_comm;            // NULL = no filter
    uint64_t filter_pid;          // CURRENT_PID_NUM = any
    struct kprobe kp;             // entry probe (used for ENTRY and BOTH)
    struct kretprobe rp;          // return probe (used for RETURN and BOTH)
    struct work_struct unregister_work;
    bool enabled;
};

// Hash table to track kprobes by ID
static DEFINE_HASHTABLE(kprobe_table, 10);  // 1024 buckets
static DEFINE_SPINLOCK(kprobe_lock);
static atomic_t kprobe_id_counter = ATOMIC_INIT(0);

// Global atomic counter for kprobe sequence numbers
static atomic64_t kprobe_sequence_counter = ATOMIC64_INIT(0);

// Reuse the SAME portal_event layout as portal_uprobe.c — the host reads type
// "portal_event" from DWARF; both definitions must be byte-for-byte identical.
struct portal_event {
    uint64_t id;
    struct task_struct *task;
    struct pt_regs *regs;
    pid_t tid;  // Thread ID
    pid_t tgid; // Thread Group ID (Process ID)
};

static void do_hyp_kprobe(bool is_enter, uint64_t id, struct pt_regs *regs) {
    // Set the sequence number atomically
    uint64_t sequence = atomic64_inc_return(&kprobe_sequence_counter);

    struct portal_event pe = {
        .id = id,
        .task = current,
        .regs = regs,
        .tid = current->pid,
        .tgid = current->tgid,
    };

    igloo_portal(is_enter ? IGLOO_HYP_KPROBE_ENTER : IGLOO_HYP_KPROBE_RETURN,
                 sequence, (unsigned long)&pe);
}

// Shared filtering + reporting helper
static void portal_kprobe_report(struct portal_kprobe *pk, struct pt_regs *regs, bool is_enter)
{
    if (!pk->enabled) {
        printk(KERN_EMERG "igloo: Received kprobe hit for disabled probe at ptr=%p\n", pk);
        return;
    }

    kprobe_debug("igloo: portal_kprobe: ptr=%p, symbol=%s, offset=%lld, proc=%s, pid=%d\n",
                 pk, pk->symbol,
                 (long long)(pk->offset), current->comm, task_pid_nr(current));

    // Apply process name filter if set
    if (pk->filter_comm && strncmp(current->comm, pk->filter_comm, TASK_COMM_LEN) != 0) {
        kprobe_debug("igloo: Process name filter failed: %s != %s\n", current->comm, pk->filter_comm);
        return; // Not our target process, silently continue
    }

    // Apply PID filter if set (CURRENT_PID_NUM == any)
    if ((pk->filter_pid) != CURRENT_PID_NUM &&
        (pk->filter_pid) != task_pid_nr(current)) {
        kprobe_debug("igloo: PID filter failed: %d != %d\n",
                     (int)(pk->filter_pid), task_pid_nr(current));
        return; // Not our target PID, silently continue
    }

    kprobe_debug("igloo: %s kprobe hit: id=%llu, symbol=%s, offset=%lld, proc=%s, pid=%d\n",
                 is_enter ? "Entry" : "Return",
                 (unsigned long long)(pk->id), pk->symbol,
                 (long long)(pk->offset), current->comm, task_pid_nr(current));

    do_hyp_kprobe(is_enter, pk->id, regs);
}

#ifdef CONFIG_KPROBES

// Entry (pre) handler
static int portal_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct portal_kprobe *pk = container_of(p, struct portal_kprobe, kp);
    portal_kprobe_report(pk, regs, true);
    return 0;
}

#ifdef CONFIG_KRETPROBES
// Return handler
static int portal_kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
    struct kretprobe *rp = get_kretprobe(ri);
    struct portal_kprobe *pk = container_of(rp, struct portal_kprobe, rp);
#else
    struct portal_kprobe *pk = container_of(ri->rp, struct portal_kprobe, rp);
#endif
    portal_kprobe_report(pk, regs, false);
    return 0;
}
#endif /* CONFIG_KRETPROBES */

static void unregister_kprobe_deferred(struct work_struct *work)
{
    struct portal_kprobe *pk = container_of(work, struct portal_kprobe, unregister_work);

    kprobe_debug("igloo: Deferred unregistering kprobe at ptr=%p\n", pk);

    if (pk->probe_type == PORTAL_KPROBE_TYPE_ENTRY ||
        pk->probe_type == PORTAL_KPROBE_TYPE_BOTH) {
        unregister_kprobe(&pk->kp);
    }
#ifdef CONFIG_KRETPROBES
    if (pk->probe_type == PORTAL_KPROBE_TYPE_RETURN ||
        pk->probe_type == PORTAL_KPROBE_TYPE_BOTH) {
        unregister_kretprobe(&pk->rp);
    }
#endif

    synchronize_rcu();

    // Free resources
    kfree(pk->symbol);
    if (pk->filter_comm) {
        kfree(pk->filter_comm);
    }
    kfree(pk);
}

// Handler for registering a new kprobe
void handle_op_register_kprobe(portal_region *mem_region)
{
    struct portal_kprobe *pk;
    struct kprobe_registration *reg;
    unsigned long id;
    int ret;
    char *filter_comm = NULL;
    bool want_entry, want_return;

    // Map the input data to our registration structure
    reg = (struct kprobe_registration *) PORTAL_DATA(mem_region);

    // Ensure strings are null-terminated
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

    want_entry  = (reg->type == PORTAL_KPROBE_TYPE_ENTRY ||
                   reg->type == PORTAL_KPROBE_TYPE_BOTH);
    want_return = (reg->type == PORTAL_KPROBE_TYPE_RETURN ||
                   reg->type == PORTAL_KPROBE_TYPE_BOTH);

#ifndef CONFIG_KRETPROBES
    if (want_return) {
        kprobe_debug("igloo: kretprobes not supported in this kernel (CONFIG_KRETPROBES off)\n");
        goto fail;
    }
#endif

    // Allocate a new kprobe structure
    pk = kzalloc(sizeof(*pk), GFP_KERNEL);
    if (!pk) {
        kprobe_debug("igloo: Failed to allocate kprobe structure\n");
        goto fail;
    }

    // Allocate memory for the symbol name. kp.symbol_name / rp.kp.symbol_name
    // point at this storage, so it must outlive the probe.
    pk->symbol = kstrdup(reg->symbol, GFP_KERNEL);
    if (!pk->symbol) {
        kprobe_debug("igloo: Failed to allocate symbol memory\n");
        goto fail_free_pk;
    }

    pk->enabled = true;
    pk->offset = reg->offset;
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

    // Initialize the work structure for deferred unregistration
    INIT_WORK(&pk->unregister_work, unregister_kprobe_deferred);

    // Register entry probe if requested
    if (want_entry) {
        pk->kp.symbol_name = pk->symbol;
        pk->kp.offset = pk->offset;
        pk->kp.pre_handler = portal_kprobe_pre_handler;
        ret = register_kprobe(&pk->kp);
        if (ret < 0) {
            kprobe_debug("igloo: Failed to register kprobe: %d\n", ret);
            goto fail_free_comm;
        }
    }

#ifdef CONFIG_KRETPROBES
    // Register return probe if requested
    if (want_return) {
        pk->rp.kp.symbol_name = pk->symbol;
        pk->rp.handler = portal_kretprobe_handler;
        pk->rp.maxactive = 0;
        ret = register_kretprobe(&pk->rp);
        if (ret < 0) {
            kprobe_debug("igloo: Failed to register kretprobe: %d\n", ret);
            // If this was a BOTH probe, the entry kprobe is already registered;
            // tear it down before failing.
            if (want_entry) {
                unregister_kprobe(&pk->kp);
            }
            goto fail_free_comm;
        }
    }
#endif

    // Add to hash table
    spin_lock(&kprobe_lock);
    hash_add(kprobe_table, &pk->hlist, id);
    spin_unlock(&kprobe_lock);

    // Return success with the unique ID
    mem_region->header.size = id; // Return the ID in size
    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;

fail_free_comm:
    if (pk->filter_comm)
        kfree(pk->filter_comm);
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
    struct portal_kprobe *curr;
    struct hlist_node *tmp;

    // ID is stored in header.addr
    id = mem_region->header.addr;

    kprobe_debug("igloo: Unregistering kprobe with ID=%lu\n", id);
    spin_lock(&kprobe_lock);

    pk = NULL;

    hash_for_each_possible_safe(kprobe_table, curr, tmp, hlist, id) {
        if (curr->id == id) {
            pk = curr;
            hash_del(&curr->hlist); // Remove immediately while locked
            break;
        }
    }
    spin_unlock(&kprobe_lock);

    if (!pk) {
        kprobe_debug("igloo: Kprobe with ID %lu not found (or already unregistering)\n", id);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }

    // Now we own 'pk' exclusively. It is gone from the table.
    // It is safe to schedule the work.
    pk->enabled = false;
    schedule_work(&pk->unregister_work);

    // Return success
    mem_region->header.op = HYPER_RESP_READ_OK;
}

#else /* !CONFIG_KPROBES */

// Minimal stubs when kprobes are unavailable. The op table references these
// handlers unconditionally, so they must always be defined.
void handle_op_register_kprobe(portal_region *mem_region)
{
    kprobe_debug("igloo: kprobe support unavailable (CONFIG_KPROBES off), cannot register\n");
    mem_region->header.op = HYPER_RESP_READ_FAIL;
}

void handle_op_unregister_kprobe(portal_region *mem_region)
{
    kprobe_debug("igloo: kprobe support unavailable (CONFIG_KPROBES off), cannot unregister\n");
    mem_region->header.op = HYPER_RESP_READ_FAIL;
}

#endif /* CONFIG_KPROBES */
