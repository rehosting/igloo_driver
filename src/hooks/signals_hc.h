#ifndef _SIGNALS_HC_H
#define _SIGNALS_HC_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

/* Actions */
enum {
    IG_SIG_ACT_MONITOR = 0,  /* Just report the event */
    IG_SIG_ACT_DROP,         /* Drop the signal (don't deliver) */
    IG_SIG_ACT_CONVERT       /* Convert to a different signal (target_sig) */
};

struct signal_hook {
    bool enabled;
    int sig;             /* Match Signal (0 for all) */
    pid_t filter_pid;    /* Match PID (0 for all) */
    
    int action;          /* MONITOR, DROP, or CONVERT */
    int target_sig;      /* New signal if action is CONVERT */

    struct hlist_node hlist;
    struct rcu_head rcu;
};

struct signal_event {
    int sig;
    int pid;
    int sender_pid;
    int errno_val;
    int code;
    unsigned long info_ptr;
    int action_taken;    /* What we did */
};

extern struct hlist_head signal_hook_table[1024];
extern spinlock_t signal_hook_lock;

int signals_hc_init(void);
int register_signal_hook(struct signal_hook *hook);
int unregister_signal_hook(struct signal_hook *hook);

#endif