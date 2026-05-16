#ifndef _SIGNAL_HC_H
#define _SIGNAL_HC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include "syscalls_hc.h"
#include "portal/portal_types.h"

#define SIGNAL_NAME_MAX_LEN 32

struct signal_hook {
    bool enabled;
    int sig;                            /* Signal number, 0 for any */
    
    /* PID filtering */
    bool pid_filter_enabled;
    pid_t filter_pid;
    
    /* Process filtering */
    bool comm_filter_enabled;
    char comm_filter[TASK_COMM_LEN];
};

struct signal_event {
    uint32_t sig;                      /* Signal number */
    struct signal_hook *hook;          /* Hook pointer */
    struct task_struct *task;          /* Target task */
    struct pt_regs *regs;              /* Target task regs */
    bool drop;                         /* Set to true to drop signal */
    uint64_t pc;                       /* PC of the target task */
    char comm[TASK_COMM_LEN];          /* Target task comm */
    pid_t pid;                         /* Target task pid */
};

struct kernel_signal_hook {
    struct signal_hook hook;
    struct hlist_node hlist;
    bool in_use;
    struct rcu_head rcu;
};

int signal_hc_init(void);
void handle_op_register_signal_hook(portal_region *mem_region);
void handle_op_unregister_signal_hook(portal_region *mem_region);

#endif /* _SIGNAL_HC_H */
