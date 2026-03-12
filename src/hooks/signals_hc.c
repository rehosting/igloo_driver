#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/jhash.h>

#include "signals_hc.h"
#include "portal/portal.h"
#include "igloo_hypercall_consts.h"
/* Include the updated args.h with getters */
#include "../args.h" 

/* Global table for signal hooks */
struct hlist_head signal_hook_table[1024];
DEFINE_SPINLOCK(signal_hook_lock);
atomic_t global_signal_hook_count = ATOMIC_INIT(0);

static struct kprobe kp_send_signal;

static inline u32 signal_hook_hash(int sig, pid_t pid) {
    return jhash_2words((u32)sig, (u32)pid, 0);
}

/* * Kprobe Pre-handler: Runs BEFORE send_signal executes.
 * Prototype: int send_signal(int sig, struct siginfo *info, struct task_struct *t, int group)
 * Argument Mapping via args.h:
 * Arg 0: sig
 * Arg 1: info
 * Arg 2: t
 */
static int pre_handler_send_signal(struct kprobe *p, struct pt_regs *regs)
{
    int sig;
    struct task_struct *t;
    struct signal_hook *hook;
    struct signal_event event;
    int bkt;
    bool match = false;
    int action = IG_SIG_ACT_MONITOR;
    int new_sig = 0;

    if (atomic_read(&global_signal_hook_count) == 0)
        return 0;

    /* USE ABSTRACTION: Read Arguments using helper from args.h */
    sig = (int)syscall_get_argument(current, regs, 0);
    t   = (struct task_struct *)syscall_get_argument(current, regs, 2);

    /* Basic sanity check */
    if (!t) return 0;

    rcu_read_lock();
    hash_for_each_rcu(signal_hook_table, bkt, hook, hlist) {
        if (!hook->enabled) continue;

        if (hook->filter_pid != 0 && hook->filter_pid != t->pid)
            continue;

        if (hook->sig != 0 && hook->sig != sig)
            continue;

        match = true;
        action = hook->action;
        if (action == IG_SIG_ACT_CONVERT)
            new_sig = hook->target_sig;
        
        break; 
    }
    rcu_read_unlock();

    if (match) {
        /* Send Event to Hypervisor */
        event.sig = sig;
        event.pid = t->pid;
        event.sender_pid = current->pid;
        event.errno_val = 0; 
        event.code = 0;
        event.info_ptr = 0; 
        event.action_taken = action;
        
        igloo_portal(IGLOO_HYP_SIGNAL_EVENT, (unsigned long)&event, 0);

        /* USE ABSTRACTION: Modify Argument using helper from args.h */
        if (action == IG_SIG_ACT_DROP) {
            /* Silence: Change sig (Arg 0) to 0 */
            syscall_set_argument(current, regs, 0, 0);
        }
        else if (action == IG_SIG_ACT_CONVERT) {
            /* Convert: Change sig (Arg 0) to new_sig */
            syscall_set_argument(current, regs, 0, new_sig);
        }
    }

    return 0;
}

int register_signal_hook(struct signal_hook *new_hook)
{
    struct signal_hook *hook_copy;
    unsigned long flags;

    hook_copy = kmalloc(sizeof(*hook_copy), GFP_KERNEL);
    if (!hook_copy)
        return -ENOMEM;

    memcpy(hook_copy, new_hook, sizeof(*hook_copy));

    spin_lock_irqsave(&signal_hook_lock, flags);
    /* Add to hash table - using sig/pid as hash key */
    hash_add_rcu(signal_hook_table, &hook_copy->hlist, signal_hook_hash(new_hook->sig, new_hook->filter_pid));
    atomic_inc(&global_signal_hook_count);
    spin_unlock_irqrestore(&signal_hook_lock, flags);

    return 0;
}

int unregister_signal_hook(struct signal_hook *hook_pattern)
{
    struct signal_hook *hook;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;
    int removed = 0;

    spin_lock_irqsave(&signal_hook_lock, flags);
    hash_for_each_safe(signal_hook_table, bkt, tmp, hook, hlist) {
        if (hook->sig == hook_pattern->sig && 
            hook->filter_pid == hook_pattern->filter_pid) {
            
            hash_del_rcu(&hook->hlist);
            atomic_dec(&global_signal_hook_count);
            kfree_rcu(hook, rcu);
            removed++;
        }
    }
    spin_unlock_irqrestore(&signal_hook_lock, flags);

    return removed;
}

int signals_hc_init(void)
{
    int ret;
    return 0;

    printk(KERN_INFO "IGLOO: Initializing signal kprobes\n");
    hash_init(signal_hook_table);

    memset(&kp_send_signal, 0, sizeof(kp_send_signal));
    kp_send_signal.symbol_name = "send_signal";
    kp_send_signal.pre_handler = pre_handler_send_signal;

    ret = register_kprobe(&kp_send_signal);
    if (ret < 0) {
        printk(KERN_ERR "IGLOO: Failed to register kprobe send_signal: %d\n", ret);
        kp_send_signal.symbol_name = "__send_signal";
        ret = register_kprobe(&kp_send_signal);
        if (ret < 0) {
             printk(KERN_ERR "IGLOO: Failed to register kprobe __send_signal: %d\n", ret);
             return ret;
        }
    }

    printk(KERN_INFO "IGLOO: Signal intervention enabled on %s.\n", kp_send_signal.symbol_name);
    return 0;
}