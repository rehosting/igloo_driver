#ifndef _SYSCALLS_HC_H
#define _SYSCALLS_HC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include "igloo_debug.h"

#include "igloo_syscall_macros.h"

/* Syscall hook structure */
struct syscall_hook {
    u32 id;                            /* Unique ID for this hook */
    bool enabled;                      /* Is this hook enabled? */
    bool on_enter;                     /* Hook on syscall entry */
    bool on_return;                    /* Hook on syscall return */
    bool on_all;                       /* Hook on all syscalls */
    char name[32];                     /* Name of syscall to hook */

    /* Filtering options */
    bool comm_filter_enabled;          /* Enable process name filtering */
    char comm_filter[TASK_COMM_LEN];   /* Process name to filter on */

    /* PID filtering */
    bool pid_filter_enabled;           /* Enable PID filtering */
    pid_t filter_pid;                  /* Process ID to filter on */

    /* Argument filtering */
    bool filter_args_enabled;          /* Enable arg filtering */
    bool filter_arg[IGLOO_SYSCALL_MAXARGS]; /* Which args to filter */
    unsigned long arg_filter[IGLOO_SYSCALL_MAXARGS]; /* Arg values to match */
};

/* Structure to track registered syscall hooks */
struct kernel_syscall_hook {
    struct syscall_hook hook;   /* The hook configuration */
    struct hlist_node hlist;    /* For tracking in hash table */
    bool in_use;                /* Whether this slot is used */
};

/* Global variables - defined in syscalls_hc.c */
extern struct hlist_head syscall_hook_table[1024];
extern spinlock_t syscall_hook_lock;

/* Check if a syscall matches a hook's criteria */
bool hook_matches_syscall(struct syscall_hook *hook, const char *syscall_name,
                         int argc, const unsigned long args[]);

/* Register a new syscall hook */
u32 register_syscall_hook(struct syscall_hook *hook);

/* Unregister a syscall hook */
int unregister_syscall_hook(u32 hook_id);

int syscalls_hc_init(void);

#define igloo_pr_debug(fmt, ...) igloo_debug_syscall(fmt, ##__VA_ARGS__)

#endif /* _SYSCALLS_HC_H */
