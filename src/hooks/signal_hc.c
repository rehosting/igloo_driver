#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "igloo_hypercall.h"
#include "igloo.h"
#include "signal_hc.h"
#include "portal/portal.h"
#include "portal/portal_internal.h"
#include "args.h"

/* Global hash table for signal hooks */
static struct hlist_head signal_hook_table[64];
static struct hlist_head any_signal_hooks;
static DEFINE_SPINLOCK(signal_hook_lock);
static atomic_t global_signal_hook_count = ATOMIC_INIT(0);

struct signal_probe_data {
    struct task_struct *task;
};

static struct kretprobe signal_rp;

static void do_signal_hyp(struct signal_event *event) {
    igloo_portal(IGLOO_HYP_SIGNAL_DELIVER, (unsigned long)event, 0);
}

static bool hook_matches_signal(struct kernel_signal_hook *hook, int sig, struct task_struct *t) {
    if (hook->hook.sig != 0 && hook->hook.sig != sig)
        return false;
    
    if (hook->hook.pid_filter_enabled && hook->hook.filter_pid != task_tgid_vnr(t))
        return false;
    
    if (hook->hook.comm_filter_enabled && strcmp(hook->hook.comm_filter, t->comm) != 0)
        return false;
    
    return true;
}

static int handler_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct signal_probe_data *data = (struct signal_probe_data *)ri->data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    data->task = current;
#else
    data->task = (struct task_struct *)regs_get_argument(regs, 0);
    if (!data->task)
        data->task = current;
#endif

    return 0;
}

static int handler_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    int sig;
    struct task_struct *t;
    struct kernel_signal_hook *hook;
    struct signal_event event;
    bool drop = false;
    bool needs_hyp = false;
    struct signal_probe_data *data = (struct signal_probe_data *)ri->data;

    if (atomic_read(&global_signal_hook_count) == 0)
        return 0;

    sig = (int)igloo_regs_get_return_value(regs);
    if (sig <= 0)
        return 0;

    t = data->task ? data->task : current;

    rcu_read_lock();
    
    /* Check specific signal hooks */
    hash_for_each_possible_rcu(signal_hook_table, hook, hlist, sig) {
        if (hook->hook.enabled && hook_matches_signal(hook, sig, t)) {
            needs_hyp = true;
            break;
        }
    }

    /* Check "any" (*) signal hooks */
    if (!needs_hyp) {
        hlist_for_each_entry_rcu(hook, &any_signal_hooks, hlist) {
            if (hook->hook.enabled && hook_matches_signal(hook, sig, t)) {
                needs_hyp = true;
                break;
            }
        }
    }

    if (needs_hyp) {
        memset(&event, 0, sizeof(event));
        event.sig = sig;
        event.hook = &hook->hook;
        event.task = t;
        event.regs = task_pt_regs(t);
        if (event.regs) {
            event.pc = instruction_pointer(event.regs);
        }
        event.pid = task_tgid_vnr(t);
        strncpy(event.comm, t->comm, TASK_COMM_LEN);
        event.drop = false;

        do_signal_hyp(&event);

        if (event.drop) {
            drop = true;
        }
    }
    rcu_read_unlock();

    if (drop) {
        igloo_regs_set_return_value(regs, 0);
    }

    return 0;
}

int signal_hc_init(void) {
    int ret;
    hash_init(signal_hook_table);
    INIT_HLIST_HEAD(&any_signal_hooks);

    memset(&signal_rp, 0, sizeof(signal_rp));
    signal_rp.kp.symbol_name = "dequeue_signal";
    signal_rp.entry_handler = handler_entry;
    signal_rp.handler = handler_ret;
    signal_rp.data_size = sizeof(struct signal_probe_data);
    signal_rp.maxactive = 64;

    ret = register_kretprobe(&signal_rp);
    if (ret < 0)
        printk(KERN_ERR "IGLOO: Failed to register kretprobe on dequeue_signal: %d\n", ret);
    else
        printk(KERN_INFO "IGLOO: Registered signal kretprobe on dequeue_signal\n");

    return 0;
}

void handle_op_register_signal_hook(portal_region *mem_region) {
    struct signal_hook *h = (struct signal_hook *)PORTAL_DATA(mem_region);
    struct kernel_signal_hook *kh;

    kh = kzalloc(sizeof(*kh), GFP_KERNEL);
    if (!kh) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    memcpy(&kh->hook, h, sizeof(*h));
    kh->in_use = true;

    spin_lock(&signal_hook_lock);
    if (kh->hook.sig == 0) {
        hlist_add_head_rcu(&kh->hlist, &any_signal_hooks);
    } else {
        hash_add_rcu(signal_hook_table, &kh->hlist, kh->hook.sig);
    }
    atomic_inc(&global_signal_hook_count);
    spin_unlock(&signal_hook_lock);

    mem_region->header.addr = (unsigned long)kh;
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}

void handle_op_unregister_signal_hook(portal_region *mem_region) {
    struct kernel_signal_hook *kh = (struct kernel_signal_hook *)mem_region->header.addr;

    if (!kh || !kh->in_use) {
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }

    spin_lock(&signal_hook_lock);
    hash_del_rcu(&kh->hlist);
    atomic_dec(&global_signal_hook_count);
    kh->in_use = false;
    spin_unlock(&signal_hook_lock);

    kfree_rcu(kh, rcu);
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}
