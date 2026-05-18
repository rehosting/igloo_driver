#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <asm/ftrace.h>
#include "igloo_hypercall.h" // Content is now included directly below
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "portal/portal.h"
#include "igloo_hypercall_consts.h"
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/workqueue.h>

/* [ADD] Global counter to allow early exit if no hooks exist */
atomic_t global_syscall_hook_count = ATOMIC_INIT(0);

/* Global hash tables for organizing hooks */
struct hlist_head syscall_hook_table[1024];                /* Main table indexed by hook pointer */
struct hlist_head syscall_name_table[1024];                /* Table indexed by syscall name hash */
struct hlist_head syscall_all_hooks;                       /* Special list for "match all syscalls" hooks */
DEFINE_SPINLOCK(syscall_hook_lock);

/* Export symbols for use by other modules */
EXPORT_SYMBOL(syscall_hook_table);
EXPORT_SYMBOL(syscall_name_table);
EXPORT_SYMBOL(syscall_all_hooks);
EXPORT_SYMBOL(syscall_hook_lock);

// syscall_name_hash is now defined in syscalls_hc.h

// Define IGLOO_DEBUG=1 during compilation to enable debug prints
#ifdef IGLOO_DEBUG
#define DBG_PRINTK(fmt, ...) printk(KERN_EMERG "IGLOO_DBG: " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) do {} while (0)
#endif

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock); // Keep commented out unless hypercall needs external locking

struct syscall_name_cache_entry {
    const char *raw_name;
    const char *normalized_name;
    u32 normalized_hash;
    u16 normalized_len;
    bool is_sendto;
    struct hlist_node hlist;
};

struct syscall_name_info {
    const char *normalized_name;
    u32 normalized_hash;
    u16 normalized_len;
    bool is_sendto;
};

#define SYSCALL_NAME_PTR_CACHE_BITS 8
#define SYSCALL_NAME_PTR_CACHE_MAX 1024

static DEFINE_HASHTABLE(syscall_name_ptr_cache, SYSCALL_NAME_PTR_CACHE_BITS);
static DEFINE_SPINLOCK(syscall_name_ptr_cache_lock);
static atomic_t syscall_name_ptr_cache_count = ATOMIC_INIT(0);

static inline struct syscall_name_info get_syscall_name_info(const char *syscall_name)
{
    struct syscall_name_cache_entry *entry;
    struct syscall_name_cache_entry *existing;
    struct syscall_name_info info = {
        .normalized_name = NULL,
        .normalized_hash = 0,
        .normalized_len = 0,
        .is_sendto = false,
    };
    const char *normalized_name;
    unsigned long key;

    if (!syscall_name) {
        return info;
    }

    key = (unsigned long)syscall_name;

    rcu_read_lock();
    hash_for_each_possible_rcu(syscall_name_ptr_cache, entry, hlist, key) {
        if (entry->raw_name == syscall_name) {
            info.normalized_name = entry->normalized_name;
            info.normalized_hash = entry->normalized_hash;
            info.normalized_len = entry->normalized_len;
            info.is_sendto = entry->is_sendto;
            rcu_read_unlock();
            return info;
        }
    }
    rcu_read_unlock();

    normalized_name = normalize_syscall_name(syscall_name);
    info.normalized_name = normalized_name;
    info.normalized_hash = syscall_normalized_name_hash(normalized_name);
    info.normalized_len = normalized_name ? strlen(normalized_name) : 0;
    info.is_sendto = normalized_name && strcmp(normalized_name, "sendto") == 0;

    if (atomic_read(&syscall_name_ptr_cache_count) >= SYSCALL_NAME_PTR_CACHE_MAX) {
        return info;
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        return info;
    }

    entry->raw_name = syscall_name;
    entry->normalized_name = info.normalized_name;
    entry->normalized_hash = info.normalized_hash;
    entry->normalized_len = info.normalized_len;
    entry->is_sendto = info.is_sendto;

    spin_lock(&syscall_name_ptr_cache_lock);
    hash_for_each_possible(syscall_name_ptr_cache, existing, hlist, key) {
        if (existing->raw_name == syscall_name) {
            spin_unlock(&syscall_name_ptr_cache_lock);
            kfree(entry);
            return info;
        }
    }
    if (atomic_read(&syscall_name_ptr_cache_count) >= SYSCALL_NAME_PTR_CACHE_MAX) {
        spin_unlock(&syscall_name_ptr_cache_lock);
        kfree(entry);
        return info;
    }
    hash_add_rcu(syscall_name_ptr_cache, &entry->hlist, key);
    atomic_inc(&syscall_name_ptr_cache_count);
    spin_unlock(&syscall_name_ptr_cache_lock);

    return info;
}

/* Function to print syscall information */
void print_syscall_info(const struct syscall_event *sc, const char *prefix);
void print_syscall_info(const struct syscall_event *sc, const char *prefix) {
    int i;
    if (!sc) {
        DBG_PRINTK( "IGLOO: %s NULL syscall structure\n", prefix ? prefix : "");
        return;
    }

    printk(KERN_INFO "IGLOO: %s Syscall Info --------\n", prefix ? prefix : "");
    printk(KERN_INFO "  Hook Ptr: %p\n", sc->hook);
    printk(KERN_INFO "  Syscall Name: %s\n", sc->syscall_name);
    printk(KERN_INFO "  PC: 0x%llx\n", sc->pc);
    printk(KERN_INFO "  Return Val: %ld\n", sc->retval);
    printk(KERN_INFO "  Skip: %d\n", sc->skip_syscall);
    printk(KERN_INFO "  Task: %p\n", sc->task);
    printk(KERN_INFO "  Regs: %p\n", sc->regs);

    printk(KERN_INFO "  Arguments (%u):\n", sc->argc);
    for (i = 0; i < sc->argc && i < IGLOO_SYSCALL_MAXARGS; i++)
    {
        printk(KERN_INFO "    arg[%d]: 0x%llx\n", i, sc->args[i]);
    }
    printk(KERN_INFO "IGLOO: ------------------------\n");
}

static inline void fill_handler(struct syscall_event *args, int argc, const unsigned long args_ptrs[], const char* syscall_name) {
    struct pt_regs *regs;
    int i;

    // Fill the syscall structure with arguments
    args->skip_syscall = false;
    args->argc = argc;

    // Copy syscall name into the structure (with bounds checking)
    if (syscall_name) {
        strncpy(args->syscall_name, syscall_name, SYSCALL_NAME_MAX_LEN - 1);
        args->syscall_name[SYSCALL_NAME_MAX_LEN - 1] = '\0';
    } else {
        args->syscall_name[0] = '\0';
    }

    // Copy arguments safely - add proper NULL checks before dereferencing
    for (i = 0; i < IGLOO_SYSCALL_MAXARGS; i++){
        if (i < argc && args_ptrs && args_ptrs[i]) {
            // Safely copy argument value - verify valid pointer first
            unsigned long arg_ptr = args_ptrs[i];
            if (arg_ptr && !IS_ERR_VALUE(arg_ptr)) {
                args->args[i] = *(unsigned long*)arg_ptr;
            } else {
                args->args[i] = 0;
                DBG_PRINTK("IGLOO: Invalid argument pointer at index %d\n", i);
            }
        } else {
            args->args[i] = 0; // Initialize unused args to 0
        }
    }

    args->task = current;
    args->retval = 0; // Initialize to 0, will be set by hypercall

    regs = task_pt_regs(current);
    args->regs = regs;

    if (regs != NULL) {
        // Use safe way to get instruction pointer that works across architectures
        args->pc = instruction_pointer(regs);
    } else {
        DBG_PRINTK("IGLOO: Failed to get pt_regs\n");
        args->pc = 0;
    }
}

static inline void do_hyp(bool is_enter, struct syscall_event* args) {
    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_SYSCALL_ENTER : IGLOO_HYP_SYSCALL_RETURN,
                (unsigned long)args, 0);
}

/* Check if a value matches a filter that is assumed to be enabled */
static inline bool value_matches_filter(long value, const struct value_filter *filter)
{
    switch (filter->type) {
        case SYSCALLS_HC_FILTER_EXACT:
            return value == filter->value;

        case SYSCALLS_HC_FILTER_GREATER:
            return value > filter->value;

        case SYSCALLS_HC_FILTER_GREATER_EQUAL:
            return value >= filter->value;

        case SYSCALLS_HC_FILTER_LESS:
            return value < filter->value;

        case SYSCALLS_HC_FILTER_LESS_EQUAL:
            return value <= filter->value;

        case SYSCALLS_HC_FILTER_NOT_EQUAL:
            return value != filter->value;

        case SYSCALLS_HC_FILTER_RANGE:
            return value >= filter->min_value && value <= filter->max_value;

        case SYSCALLS_HC_FILTER_SUCCESS:
            return value >= 0;

        case SYSCALLS_HC_FILTER_ERROR:
            return value < 0;

        case SYSCALLS_HC_FILTER_BITMASK_SET:
            return (value & filter->bitmask) == filter->bitmask;

        case SYSCALLS_HC_FILTER_BITMASK_CLEAR:
            return (value & filter->bitmask) == 0;
        case SYSCALLS_HC_FILTER_STR_EXACT:
            if (!value || !filter->pattern) return false;
            return check_str_exact(value, filter->pattern, filter->pattern_len);
            
        case SYSCALLS_HC_FILTER_STR_STARTSWITH:
            if (!value || !filter->pattern) return false;
            return check_str_startswith(value, filter->pattern, filter->pattern_len);
            
        case SYSCALLS_HC_FILTER_STR_ENDSWITH:
            if (!value || !filter->pattern) return false;
            return check_str_endswith(value, filter->pattern, filter->pattern_len);
            
        case SYSCALLS_HC_FILTER_STR_CONTAINS:
            if (!value || !filter->pattern) return false;
            return check_str_contains(value, filter->pattern, filter->pattern_len);
        default:
            // Unknown filter type, assume no match
            return false;
    }
}

// Change hook_matches_syscall and hook_matches_syscall_return to take struct kernel_syscall_hook *
static inline bool hook_matches_syscall(struct kernel_syscall_hook *hook,
                         const char *syscall_name, u32 syscall_name_hash,
                         u16 syscall_name_len,
                         int argc, const unsigned long args[])
{
    if (!hook->hook.enabled){
        return false;
    }
    if (hook->hook.on_all){
        return true;
    }
    if (syscall_name && hook->hook.name[0] != '\0') {
        if (hook->normalized_name_hash != syscall_name_hash) {
            return false;
        }
        if (hook->normalized_name_len != syscall_name_len) {
            return false;
        }
        if (unlikely(strcmp(hook->normalized_name, syscall_name) != 0)) {
            return false;
        }
    } else if (hook->hook.name[0] != '\0') {
        return false;
    }
    if (hook->hook.pid_filter_enabled) {
        if (task_pid_nr(current) != hook->hook.filter_pid){
            return false;
        }
    }
    if (hook->hook.comm_filter_enabled) {
        if (strncmp(current->comm, hook->hook.comm_filter, TASK_COMM_LEN) != 0){
            return false;
        }
    }
    // Unrolled argument filter checks for IGLOO_SYSCALL_MAXARGS == 6
    if (argc > 0) {
        struct value_filter *f = &hook->hook.arg_filters[0];
        if (f->enabled) {
            long arg_val = *(long *)args[0];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    if (argc > 1) {
        struct value_filter *f = &hook->hook.arg_filters[1];
        if (f->enabled) {
            long arg_val = *(long *)args[1];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    if (argc > 2) {
        struct value_filter *f = &hook->hook.arg_filters[2];
        if (f->enabled) {
            long arg_val = *(long *)args[2];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    if (argc > 3) {
        struct value_filter *f = &hook->hook.arg_filters[3];
        if (f->enabled) {
            long arg_val = *(long *)args[3];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    if (argc > 4) {
        struct value_filter *f = &hook->hook.arg_filters[4];
        if (f->enabled) {
            long arg_val = *(long *)args[4];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    if (argc > 5) {
        struct value_filter *f = &hook->hook.arg_filters[5];
        if (f->enabled) {
            long arg_val = *(long *)args[5];
            if (f->type == SYSCALLS_HC_FILTER_EXACT) {
                if (arg_val != f->value) return false;
            } else {
                if (!value_matches_filter(arg_val, f)) return false;
            }
        }
    }
    return true;
}

static inline bool hook_matches_syscall_return(struct kernel_syscall_hook *hook, const char *syscall_name,
                                 u32 syscall_name_hash, u16 syscall_name_len, int argc,
                                 const unsigned long args[], long retval)
{
    struct value_filter *f;
    if (!hook_matches_syscall(hook, syscall_name, syscall_name_hash, syscall_name_len, argc, args)){
        return false;
    }
    f = &hook->hook.retval_filter;
    if (!f->enabled) {
        return true;
    }
    if (f->type == SYSCALLS_HC_FILTER_EXACT) {
        return retval == f->value;
    }
    return value_matches_filter(retval, f);
}

// Unified syscall hook processing function
// Stack buffer size for the common case (fast path)
#define IGLOO_STACK_BATCH_SIZE 4

// Helper to fill event data
static inline void capture_syscall_event(struct syscall_event *dest, 
                                         struct kernel_syscall_hook *hook,
                                         struct syscall_event *template,
                                         bool is_entry,
                                         long retval) 
{
    memcpy(dest, template, sizeof(struct syscall_event));
    dest->hook = &hook->hook;
    if (!is_entry) dest->retval = retval;
}

static long process_syscall_hooks(
    bool is_entry,
    const char *syscall_name,
    const struct syscall_name_info *cached_name_info,
    int argc,
    const unsigned long args[],
    igloo_syscall_setter_t setter_func,
    long *skip_ret_val, // Only used for entry
    long orig_ret // Only used for return
) {
    struct syscall_event stack_batch[IGLOO_STACK_BATCH_SIZE];
    struct syscall_event *batch = stack_batch;
    struct syscall_event template_event;
    
    struct kernel_syscall_hook *hook;
    int match_count = 0;
    int capacity = IGLOO_STACK_BATCH_SIZE;
    bool template_initialized = false;
    bool using_heap = false;
    long modified_ret = orig_ret;
    long skip_ret_val_local = 0;
    bool skip_syscall = false;
    struct syscall_name_info name_info;
    const char *normsc;
    u32 name_hash;
    u16 name_len;
    int i;

    if (atomic_read(&global_syscall_hook_count) == 0) {
        return is_entry ? 0 : orig_ret;
    }
    if (cached_name_info) {
        name_info = *cached_name_info;
    } else {
        name_info = get_syscall_name_info(syscall_name);
    }
    normsc = name_info.normalized_name;
    name_hash = name_info.normalized_hash;
    name_len = name_info.normalized_len;
    rcu_read_lock();
    // 1. Check the "match all syscalls" list first
    if (!hlist_empty(&syscall_all_hooks)) {
        hlist_for_each_entry_rcu(hook, &syscall_all_hooks, name_hlist) {
             bool matches = is_entry ? 
                (hook->hook.on_enter && hook_matches_syscall(hook, normsc, name_hash, name_len, argc, args)) :
                (hook->hook.on_return && hook_matches_syscall_return(hook, normsc, name_hash, name_len, argc, args, modified_ret));
            if (matches) {
                if (match_count < IGLOO_STACK_BATCH_SIZE) {
                     if (unlikely(!template_initialized)) {
                        fill_handler(&template_event, argc, args, normsc);
                        template_initialized = true;
                    }
                    capture_syscall_event(&batch[match_count], hook, &template_event, is_entry, modified_ret);
                }
                match_count++;
            }
        }
    }

    // Check named list
    if (normsc) {
        hash_for_each_possible_rcu(syscall_name_table, hook, name_hlist, name_hash) {
            bool matches = is_entry ? 
                        (hook->hook.on_enter && hook_matches_syscall(hook, normsc, name_hash, name_len, argc, args)) :
                        (hook->hook.on_return && hook_matches_syscall_return(hook, normsc, name_hash, name_len, argc, args, modified_ret));
            if (matches) {
                if (match_count < IGLOO_STACK_BATCH_SIZE) {
                     if (unlikely(!template_initialized)) {
                        fill_handler(&template_event, argc, args, normsc);
                        template_initialized = true;
                    }
                    capture_syscall_event(&batch[match_count], hook, &template_event, is_entry, modified_ret);
                }
                match_count++;
            }
        }
    }
    rcu_read_unlock();

    // 3. Overflow Handling (Heap Allocation)
    // If we found more hooks than fit on the stack, we need to allocate and re-scan.
    if (unlikely(match_count > IGLOO_STACK_BATCH_SIZE)) {
        int total_matches = match_count;
        
        // Allocate exact size needed
        batch = kmalloc_array(total_matches, sizeof(struct syscall_event), GFP_KERNEL);
        if (!batch) {
            // Allocation failed: Fallback to processing just the stack batch
            // Log a warning that hooks are being dropped
            DBG_PRINTK("IGLOO: Failed to allocate batch for %d hooks, dropping %d\n", 
                       total_matches, total_matches - IGLOO_STACK_BATCH_SIZE);
            match_count = IGLOO_STACK_BATCH_SIZE;
            batch = stack_batch; // Point back to stack
        } else {
            using_heap = true;
            capacity = total_matches;
            
            // Re-acquire lock to populate the full heap buffer
            match_count = 0; // Reset count to fill buffer from scratch
            rcu_read_lock();
            
            // Re-scan "match all" list
            if (!hlist_empty(&syscall_all_hooks)) {
                hlist_for_each_entry_rcu(hook, &syscall_all_hooks, name_hlist) {
                    bool matches = is_entry ? 
                        (hook->hook.on_enter && hook_matches_syscall(hook, normsc, name_hash, name_len, argc, args)) :
                        (hook->hook.on_return && hook_matches_syscall_return(hook, normsc, name_hash, name_len, argc, args, modified_ret));
                    
                    if (matches && match_count < capacity) {
                        capture_syscall_event(&batch[match_count], hook, &template_event, is_entry, modified_ret);
                        match_count++;
                    }
                }
            }
            
            // Re-scan named list
            if (normsc) {
                hash_for_each_possible_rcu(syscall_name_table, hook, name_hlist, name_hash) {
                    bool matches = is_entry ? 
                        (hook->hook.on_enter && hook_matches_syscall(hook, normsc, name_hash, name_len, argc, args)) :
                        (hook->hook.on_return && hook_matches_syscall_return(hook, normsc, name_hash, name_len, argc, args, modified_ret));
                    
                    if (matches && match_count < capacity) {
                        capture_syscall_event(&batch[match_count], hook, &template_event, is_entry, modified_ret);
                        match_count++;
                    }
                }
            }
            rcu_read_unlock();
        }
    }

    // 4. Process Events
    for (i = 0; i < match_count; i++) {
        if (!is_entry) {
            batch[i].retval = modified_ret;
        }
        do_hyp(is_entry, &batch[i]);
        if (is_entry) {
            // Handle argument modifications
            bool was_modified = false;
            int j;
            for (j = 0; j < IGLOO_SYSCALL_MAXARGS && j < argc; j++) {
                if (batch[i].args[j] != template_event.args[j]) {
                    was_modified = true;
                    break;
                }
            }
            if (was_modified && setter_func && args) {
                setter_func(args, (const __le64 *)&batch[i].args[0]);
            }
            // Handle syscall skipping
            if (batch[i].skip_syscall) {
                skip_syscall = true;
                skip_ret_val_local = batch[i].retval;
                break;
            }
        } else {
            // Handle return value modifications
            long new_ret = batch[i].retval;
            if (new_ret != modified_ret) {
                modified_ret = new_ret;
                if (batch[i].retval != modified_ret) {
                    modified_ret = batch[i].retval;
                }
            }
        }
    }
    // 5. Cleanup
    if (using_heap) {
        kfree(batch);
    }
    if (is_entry) {
        if (skip_syscall) {
            *skip_ret_val = skip_ret_val_local;
            return 1;
        }
        return 0;
    } else {
        return modified_ret;
    }
}

//Entry handler for system calls
static bool syscall_entry_handler(const char *syscall_name, long *skip_ret_val, int argc, const unsigned long args[], igloo_syscall_setter_t setter_func)
{
    int i;
    unsigned long safe_args[IGLOO_SYSCALL_MAXARGS];
    struct syscall_name_info name_info;
    check_portal_interrupt();
    if (!args || !skip_ret_val) {
        return 0;
    }
    if (current->flags & PF_KTHREAD) {
        return 0;
    }
    if (atomic_read(&global_syscall_hook_count) == 0 &&
            !portalcall_fastpath_is_enabled()) {
        return 0;
    }
    for (i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
        safe_args[i] = args[i];
    }
    name_info = get_syscall_name_info(syscall_name);
    if (portalcall_fastpath_should_skip(name_info.is_sendto, argc, safe_args)) {
        *skip_ret_val = 0;
        return 1;
    }
    return process_syscall_hooks(true, syscall_name, &name_info, argc, safe_args, setter_func, skip_ret_val, 0);
}

// Return handler for system calls
static long syscall_ret_handler(const char *syscall_name, long orig_ret, int argc, const unsigned long args[]){
    check_portal_interrupt();
    if (!args) {
        return orig_ret;
    }
    if (current->flags & PF_KTHREAD) {
        return orig_ret;
    }
    if (atomic_read(&global_syscall_hook_count) == 0) {
        return orig_ret;
    }
    return process_syscall_hooks(false, syscall_name, NULL, argc, args, NULL, NULL, orig_ret);
}

int syscalls_hc_init(void) {
    igloo_syscall_enter_t *enter_hook_ptr;
    igloo_syscall_return_t *ret_hook_ptr;
    // printk(KERN_EMERG "IGLOO: Initializing syscall hypercalls\n");
    // Dynamically look up and set igloo_syscall_enter_hook

    enter_hook_ptr = (igloo_syscall_enter_t *)kallsyms_lookup_name("igloo_syscall_enter_hook");
    if (enter_hook_ptr) {
        *enter_hook_ptr = syscall_entry_handler;
        // printk(KERN_INFO "IGLOO: Set igloo_syscall_enter_hook via kallsyms\n");
    } else {
        printk(KERN_ERR "IGLOO: Failed to find igloo_syscall_enter_hook symbol via kallsyms\n");
    }

    // Dynamically look up and set igloo_syscall_return_hook
    ret_hook_ptr = (igloo_syscall_return_t *)kallsyms_lookup_name("igloo_syscall_return_hook");
    if (ret_hook_ptr) {
        *ret_hook_ptr = syscall_ret_handler;
        // printk(KERN_INFO "IGLOO: Set igloo_syscall_return_hook via kallsyms\n");
    } else {
        printk(KERN_ERR "IGLOO: Failed to find igloo_syscall_return_hook symbol via kallsyms\n");
    }

    /* Initialize the hash table */
    hash_init(syscall_hook_table);
    return 0;
}
