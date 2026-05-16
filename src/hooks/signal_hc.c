#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "hypercall.h"
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

static struct kprobe signal_kp;

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

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    int sig;
    struct task_struct *t;
    struct kernel_signal_hook *hook;
    struct signal_event event;
    bool drop = false;
    bool needs_hyp = false;

    if (atomic_read(&global_signal_hook_count) == 0)
        return 0;

    /* sig is first arg, t is third arg in __send_signal(int sig, struct siginfo *info, struct task_struct *t...) */
    sig = (int)regs_get_argument(regs, 0);
    t = (struct task_struct *)regs_get_argument(regs, 2);

    if (!t) return 0;

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
        /* Set sig to 0 to effectively silence it in __send_signal */
        syscall_set_argument(current, regs, 0, 0);
    }

    return 0;
}

int signal_hc_init(void) {
    int ret;
    hash_init(signal_hook_table);
    INIT_HLIST_HEAD(&any_signal_hooks);

    signal_kp.symbol_name = "__send_signal";
    signal_kp.pre_handler = handler_pre;

    ret = register_kprobe(&signal_kp);
    if (ret < 0) {
        printk(KERN_ERR "IGLOO: Failed to register kprobe on __send_signal: %d\n", ret);
        return 0;
    }

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
