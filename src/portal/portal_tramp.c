#include <linux/gfp.h>
#include <linux/mm.h>
#include "portal_internal.h"
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "portal_tramp.h"
#include "portal_tramp_gen.h"

/* We ALWAYS include kprobes as the universal fallback */
#include <linux/kprobes.h>

/* Try to include high-speed tracing mechanisms if the kernel version allows */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
    #define USE_FPROBE
    #include <linux/fprobe.h>
#elif defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
    #define USE_FTRACE
    #include <linux/ftrace.h>
#endif

// API to get a trampoline function pointer by index
static inline void *get_portal_tramp_fn(int id)
{
    if (id < 0 || id >= PORTAL_TRAMPOLINE_COUNT)
        return NULL;
    return portal_tramp_table[id];
}

static atomic_t tramp_id_counter = ATOMIC_INIT(0);

struct portal_tramp_entry {
    int tramp_id;
    int active_type; /* 1 = fprobe, 2 = ftrace, 3 = kprobe */
#ifdef USE_FPROBE
    struct fprobe fp;
#endif
#ifdef USE_FTRACE
    struct ftrace_ops fops;
#endif
    struct kprobe kp;
};

#define MAX_TRAMPOLINES 4096
static struct portal_tramp_entry *tramp_entries[MAX_TRAMPOLINES];

/* =====================================================================
 * 1. Fprobe Handler (6.13+)
 * ===================================================================== */
#ifdef USE_FPROBE
static int notrace portal_tramp_fprobe_handler(struct fprobe *fp, unsigned long entry_ip,
                                               unsigned long ret_ip, struct pt_regs *regs,
                                               void *entry_data)
{
    struct portal_tramp_entry *entry = container_of(fp, struct portal_tramp_entry, fp);
    if (regs) {
        igloo_portal(IGLOO_HYP_TRAMP_HIT, entry->tramp_id, (unsigned long)regs);
    }
    return 0;
}
#endif

/* =====================================================================
 * 2. Raw Ftrace Handler
 * ===================================================================== */
#ifdef USE_FTRACE
static void notrace portal_tramp_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                                struct ftrace_ops *op, struct pt_regs *regs)
{
    struct portal_tramp_entry *entry = container_of(op, struct portal_tramp_entry, fops);
    if (regs) {
        igloo_portal(IGLOO_HYP_TRAMP_HIT, entry->tramp_id, (unsigned long)regs);
    }
}
#endif

/* =====================================================================
 * 3. Kprobe Handler (Universal Fallback)
 * ===================================================================== */
static int portal_tramp_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct portal_tramp_entry *entry = container_of(p, struct portal_tramp_entry, kp);
    igloo_portal(IGLOO_HYP_TRAMP_HIT, entry->tramp_id, (unsigned long)regs);
    return 0;
}

// Returns trampoline id on success, <0 on error
int portal_tramp_generate(void)
{
    int id, ret;
    struct portal_tramp_entry *entry;
    unsigned long tramp_addr;

    id = atomic_inc_return(&tramp_id_counter) - 1;
    tramp_addr = (unsigned long)get_portal_tramp_fn(id);

    if (!tramp_addr || id >= MAX_TRAMPOLINES) {
        printk(KERN_EMERG "portal_tramp_generate: failed, id=%d addr=%p\n", id, (void *)tramp_addr);
        return -ENOENT;
    }

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    
    entry->tramp_id = id;

#ifdef USE_FPROBE
    // Cast to void* suppresses signature warnings on 6.12+ where pt_regs became ftrace_regs
    entry->fp.entry_handler = (void *)portal_tramp_fprobe_handler; 
    ret = register_fprobe_ips(&entry->fp, &tramp_addr, 1);
    if (ret == 0) {
        entry->active_type = 1;
        goto success;
    }
    // If we reach here, fprobe returned an error (like -95 EOPNOTSUPP). Fall back automatically.
#elif defined(USE_FTRACE)
    entry->fops.func = portal_tramp_ftrace_handler;
    entry->fops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_DYNAMIC;
    ret = ftrace_set_filter_ip(&entry->fops, tramp_addr, 0, 0);
    if (ret == 0) {
        ret = register_ftrace_function(&entry->fops);
        if (ret == 0) {
            entry->active_type = 2;
            goto success;
        }
    }
#endif

    // Universal Fallback: Use standard kprobes
    entry->kp.addr = (kprobe_opcode_t *)tramp_addr;
    entry->kp.pre_handler = portal_tramp_kprobe_handler;
    ret = register_kprobe(&entry->kp);
    if (ret == 0) {
        entry->active_type = 3;
        goto success;
    }

    pr_err("portal_tramp: Failed to register ALL tracing mechanisms for tramp %d (err %d)\n", id, ret);
    kfree(entry);
    return -EFAULT;

success:
    tramp_entries[id] = entry;
    return id;
}

void handle_op_tramp_generate(portal_region *mem_region)
{
    struct portal_tramp_generate *tramp_data;
    int id;

    tramp_data = (struct portal_tramp_generate *)PORTAL_DATA(mem_region);
    id = portal_tramp_generate();

    if (id >= 0) {
        tramp_data->tramp_id = id;
        tramp_data->tramp_addr = (unsigned long)get_portal_tramp_fn(id);
        tramp_data->status = 0;
        mem_region->header.op = HYPER_RESP_READ_OK;
    } else {
        tramp_data->tramp_id = -1;
        tramp_data->tramp_addr = 0;
        tramp_data->status = id;
        mem_region->header.op = HYPER_RESP_READ_FAIL;
    }
    mem_region->header.size = sizeof(struct portal_tramp_generate);
}

int portal_tramp_generate(void);
void *get_portal_tramp_fn(int id);
void handle_op_tramp_generate(portal_region *mem_region);