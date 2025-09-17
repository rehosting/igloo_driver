#include <linux/gfp.h>
#include <linux/mm.h>
#include "portal_internal.h"
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "portal_internal.h"
#include <linux/kallsyms.h>
#include "portal_tramp.h"
#include "portal_tramp_gen.h"

// API to get a trampoline function pointer by index
static inline void *get_portal_tramp_fn(int id)
{
    if (id < 0 || id >= PORTAL_TRAMPOLINE_COUNT)
        return NULL;
    return portal_tramp_table[id];
}

static atomic_t tramp_id_counter = ATOMIC_INIT(0);

struct portal_tramp_entry {
    struct kprobe kp;
    int tramp_id;
};

#define MAX_TRAMPOLINES 4096
static struct portal_tramp_entry *tramp_entries[MAX_TRAMPOLINES];

static int portal_tramp_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct portal_tramp_entry *entry = container_of(p, struct portal_tramp_entry, kp);
    printk(KERN_EMERG "igloo: Trampoline hit for ID %d\n", entry->tramp_id);
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
        printk(KERN_EMERG "portal_tramp_generate: failed to allocate entry for id=%d\n", id);
        return -ENOMEM;
    }
    entry->tramp_id = id;
    entry->kp.addr = (kprobe_opcode_t *)tramp_addr;
    entry->kp.pre_handler = portal_tramp_kprobe_handler;
    ret = register_kprobe(&entry->kp);
    printk(KERN_EMERG "portal_tramp_generate: kprobe register ret=%d for id=%d\n", ret, id);
    if (ret) {
        pr_err("portal_tramp: Failed to register kprobe for tramp %d\n", id);
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