#ifndef _SYSCALLS_HC_H
#define _SYSCALLS_HC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>

#include "igloo_syscall_macros.h"

#define SYSCALL_NAME_MAX_LEN 48        // Maximum length for syscall name

/* Value comparison types for filtering */
enum value_filter_type {
    SYSCALLS_HC_FILTER_EXACT = 0,        /* Exact match */
    SYSCALLS_HC_FILTER_GREATER,          /* Greater than value */
    SYSCALLS_HC_FILTER_GREATER_EQUAL,    /* Greater than or equal to value */
    SYSCALLS_HC_FILTER_LESS,             /* Less than value */
    SYSCALLS_HC_FILTER_LESS_EQUAL,       /* Less than or equal to value */
    SYSCALLS_HC_FILTER_NOT_EQUAL,        /* Not equal to value */
    SYSCALLS_HC_FILTER_RANGE,            /* Within range [min, max] inclusive */
    SYSCALLS_HC_FILTER_SUCCESS,          /* >= 0 (success, for return values) */
    SYSCALLS_HC_FILTER_ERROR,            /* < 0 (error, for return values) */
    SYSCALLS_HC_FILTER_BITMASK_SET,      /* All specified bits are set */
    SYSCALLS_HC_FILTER_BITMASK_CLEAR,    /* All specified bits are clear */
};

/* Value filter structure for complex comparisons */
struct value_filter {
    bool enabled;                    /* Is this filter enabled? */
    enum value_filter_type type;     /* Type of comparison */
    long value;                      /* Primary value for comparison */
    long min_value;                  /* Minimum value for range filter */
    long max_value;                  /* Maximum value for range filter */
    unsigned long bitmask;           /* Bitmask for bit operations */
};

/* Syscall hook structure */
struct syscall_hook {
    bool enabled;                                   /* Is this hook enabled? */
    bool on_enter;                                  /* Hook on syscall entry */
    bool on_return;                                 /* Hook on syscall return */
    bool on_all;                                    /* Hook on all syscalls */
    char name[SYSCALL_NAME_MAX_LEN];                /* Name of syscall to hook */

    /* PID filtering */
    bool pid_filter_enabled;                        /* Enable PID filtering */
    pid_t filter_pid;                               /* Process ID to filter on */

    /* Process filtering */
    bool comm_filter_enabled;                       /* Enable process name filtering */
    char comm_filter[TASK_COMM_LEN];               /* Process name to match */

    /* Argument filtering with complex comparisons */
    struct value_filter arg_filters[IGLOO_SYSCALL_MAXARGS]; /* Argument filters */

    /* Return value filtering with complex comparisons */
    struct value_filter retval_filter;              /* Return value filter */
};

struct syscall_event {
    struct syscall_hook *hook;         /* Hook pointer that triggered this event */
    u32 argc;                          /* Number of arguments */
    uint64_t args[IGLOO_SYSCALL_MAXARGS]; /* Syscall arguments */
    uint64_t pc;                       /* Program counter */
    long retval;                       /* Return value */
    bool skip_syscall;                 /* Flag to skip syscall execution */
    struct task_struct *task;          /* Task pointer */
    struct pt_regs *regs;              /* Pointer to current registers */
    char syscall_name[SYSCALL_NAME_MAX_LEN]; /* Name of syscall (embedded in structure) */
};

/* Structure to track registered syscall hooks */
struct kernel_syscall_hook {
    struct syscall_hook hook;     /* The hook configuration */
    struct hlist_node hlist;      /* For tracking in main hash table */
    struct hlist_node name_hlist; /* For tracking in name-based hash table */
    bool in_use;                  /* Whether this slot is used */
    struct rcu_head rcu;          /* For RCU freeing */
    char normalized_name[SYSCALL_NAME_MAX_LEN]; /* Cached normalized syscall name */
};

/* Global variables - defined in syscalls_hc.c */
extern struct hlist_head syscall_hook_table[1024];
extern spinlock_t syscall_hook_lock;


int syscalls_hc_init(void);

/* Normalize syscall names by removing common prefixes like 'sys_', '_sys_', 'compat_sys_' */
static inline const char *normalize_syscall_name(const char *name)
{
    if (!name)
        return NULL;

    /* Skip leading underscores (e.g. _sys_) */
    while (*name == '_')
        name++;

    /* Check for 'sys_' prefix */
    if (strncmp(name, "sys_", 4) == 0)
        return name + 4;

    /* Check for 'compat_sys_' prefix */
    if (strncmp(name, "compat_sys_", 11) == 0)
        return name + 11;

    /* Check for other arch-specific prefixes */
    if (strncmp(name, "arm64_sys_", 10) == 0)
        return name + 10;

    if (strncmp(name, "riscv_sys_", 10) == 0)
        return name + 10;

    return name;
}

/* Hash a syscall name for lookups - normalizes the name first */
static inline u32 syscall_name_hash(const char *str)
{
    const char *normalized;
    if (!str)
        return 0;

    // First normalize the syscall name to handle various prefixes
    normalized = normalize_syscall_name(str);

    return full_name_hash(NULL, normalized, strlen(normalized));
}

#endif /* _SYSCALLS_HC_H */
