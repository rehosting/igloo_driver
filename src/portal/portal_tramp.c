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

/* * Choose the fastest available tracing mechanism.
 * 1. fprobe (5.18+)
 * 2. ftrace (if the architecture supports saving registers)
 * 3. kprobes (fallback for architectures like older 32-bit ARM)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
    #define USE_FPROBE
    #include <linux/fprobe.h>
#elif defined(CONFIG_DYNAMIC_FTRACE_WITH_REGS)
    #define USE_FTRACE
    #include <linux/ftrace.h>
#else
    #define USE_KPROBE
    #include <linux/kprobes.h>
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
#ifdef USE_FPROBE
    struct fprobe fp;
#elif defined(USE_FTRACE)
    struct ftrace_ops fops;
#else
    struct kprobe kp;
#endif
    int tramp_id;
};

#define MAX_TRAMPOLINES 4096
static struct portal_tramp_entry *tramp_entries[MAX_TRAMPOLINES];

/* =====================================================================
 * Kernel 6.13+ : fprobe implementation
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

/* =====================================================================
 * Older Kernels with ftrace register support
 * ===================================================================== */
#elif defined(USE_FTRACE)
static void notrace portal_tramp_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                                struct ftrace_ops *op, struct pt_regs *regs)
{
    struct portal_tramp_entry *entry = container_of(op, struct portal_tramp_entry, fops);
    if (regs) {
        igloo_portal(IGLOO_HYP_TRAMP_HIT, entry->tramp_id, (unsigned long)regs);
    }
}

/* =====================================================================
 * Fallback : kprobe implementation (e.g. armel 4.10)
 * ===================================================================== */
#else
static int portal_tramp_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct portal_tramp_entry *entry = container_of(p, struct portal_tramp_entry, kp);
    // printk(KERN_EMERG "igloo: Trampoline hit for ID %d\n", entry->tramp_id);
    igloo_portal(IGLOO_HYP_TRAMP_HIT, entry->tramp_id, (unsigned long)regs);
    return 0;
}
#endif

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
        printk(KERN_EMERG "portal_tramp_generate: failed to allocate entry for id=%d\n", id);
        return -ENOMEM;
    }
    
    entry->tramp_id = id;

#ifdef USE_FPROBE
    // 6.13: Register using fprobe API
    entry->fp.entry_handler = portal_tramp_fprobe_handler;
    ret = register_fprobe_ips(&entry->fp, &tramp_addr, 1);
    
#elif defined(USE_FTRACE)
    // Register using raw ftrace API
    entry->fops.func = portal_tramp_ftrace_handler;
    entry->fops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_DYNAMIC;
    
    ret = ftrace_set_filter_ip(&entry->fops, tramp_addr, 0, 0);
    if (ret == 0) {
        ret = register_ftrace_function(&entry->fops);
    }
    
#else
    // Fallback: Register using kprobe API
    entry->kp.addr = (kprobe_opcode_t *)tramp_addr;
    entry->kp.pre_handler = portal_tramp_kprobe_handler;
    ret = register_kprobe(&entry->kp);
#endif

    if (ret) {
        pr_err("portal_tramp: Failed to register hook for tramp %d (err %d)\n", id, ret);
        kfree(entry);
        return -EFAULT;
    }
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