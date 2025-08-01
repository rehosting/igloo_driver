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

void handle_op_tramp_generate(portal_region *mem_region)
{
    struct portal_tramp_generate *tramp_data;
    int id;
    struct portal_tramp_entry *entry;
    int ret;

    tramp_data = (struct portal_tramp_generate *)PORTAL_DATA(mem_region);
    id = atomic_inc_return(&tramp_id_counter) - 1;
    tramp_data->tramp_id = id;
    tramp_data->tramp_addr = (unsigned long)get_portal_tramp_fn(id);
    char symname[64];
    snprintf(symname, sizeof(symname), "portal_tramp_fn_%d", id);
    unsigned long tramp_sym_addr = kallsyms_lookup_name(symname);
    printk(KERN_EMERG "handle_op_tramp_generate: id=%d addr=0x%llx fn_ptr=0x%llx kallsyms=0x%llx sym=%s\n", id, (unsigned long long)tramp_data->tramp_addr, (unsigned long long)portal_tramp_table[id], (unsigned long long)tramp_sym_addr, symname);
    
    if (tramp_data->tramp_addr && id < MAX_TRAMPOLINES) {
        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            printk(KERN_EMERG "handle_op_tramp_generate: failed to allocate entry for id=%d\n", id);
            tramp_data->status = -ENOMEM;
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            mem_region->header.size = sizeof(struct portal_tramp_generate);
            return;
        }
        entry->tramp_id = id;
        entry->kp.addr = (kprobe_opcode_t *)tramp_data->tramp_addr;
        entry->kp.pre_handler = portal_tramp_kprobe_handler;
        ret = register_kprobe(&entry->kp);
        printk(KERN_EMERG "handle_op_tramp_generate: kprobe register ret=%d for id=%d\n", ret, id);
        if (ret) {
            pr_err("portal_tramp: Failed to register kprobe for tramp %d\n", id);
            kfree(entry);
            tramp_data->status = -EFAULT;
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            mem_region->header.size = sizeof(struct portal_tramp_generate);
            return;
        }
        tramp_entries[id] = entry;
        tramp_data->status = 0;
        mem_region->header.op = HYPER_RESP_READ_OK;
    } else {
        printk(KERN_EMERG "handle_op_tramp_generate: failed, id=%d addr=%p\n", id, (void *)tramp_data->tramp_addr);
        tramp_data->status = -ENOENT;
        mem_region->header.op = HYPER_RESP_READ_FAIL;
    }
    printk(KERN_EMERG "handle_op_tramp_generate: final status=%d for id=%d\n", tramp_data->status, id);
    mem_region->header.size = sizeof(struct portal_tramp_generate);
}

void *get_portal_tramp_fn(int id);
void handle_op_tramp_generate(portal_region *mem_region);