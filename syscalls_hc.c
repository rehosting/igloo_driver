#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <asm/ftrace.h>
#include "hypercall.h" // Content is now included directly below
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "kprobe_syscalls.h"
#include "portal/portal.h"

igloo_syscall_enter_t igloo_syscall_enter_hook;
igloo_syscall_return_t igloo_syscall_return_hook;

/* Global hash table and lock for syscall hooks */
struct hlist_head syscall_hook_table[1024];
DEFINE_SPINLOCK(syscall_hook_lock);

#define MAX_MATCHING_HOOKS 32

// Define IGLOO_DEBUG=1 during compilation to enable debug prints
#ifdef IGLOO_DEBUG
#define DBG_PRINTK(fmt, ...) printk(KERN_EMERG "IGLOO_DBG: " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) do {} while (0)
#endif

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

// add 1 if the struct syscall_event changes
#define SYSCALL_HC_KNOWN_MAGIC 0x1234  // Incremented due to structure change
#define SYSCALL_NAME_MAX_LEN 48        // Maximum length for syscall name

struct syscall_event {
    u16 known_magic;                   /* Magic value to validate structure integrity */
    u32 id;                            /* Hook ID that triggered this event */
    u32 argc;                          /* Number of arguments */
    uint64_t args[IGLOO_SYSCALL_MAXARGS]; /* Syscall arguments */
    uint64_t pc;                       /* Program counter */
    long retval;                       /* Return value */
    bool skip_syscall;                 /* Flag to skip syscall execution */
    struct task_struct *task;          /* Task pointer */
    struct pt_regs *regs;              /* Pointer to current registers */
    char syscall_name[SYSCALL_NAME_MAX_LEN]; /* Name of syscall (embedded in structure) */
} __packed __aligned(8);               /* Ensure 8-byte alignment */

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock); // Keep commented out unless hypercall needs external locking

/* Function to print syscall information */
void print_syscall_info(const struct syscall_event *sc, const char *prefix);
void print_syscall_info(const struct syscall_event *sc, const char *prefix) {
    if (!sc) {
        DBG_PRINTK( "IGLOO: %s NULL syscall structure\n", prefix ? prefix : "");
        return;
    }
    
    printk(KERN_INFO "IGLOO: %s Syscall Info --------\n", prefix ? prefix : "");
    printk(KERN_INFO "  Magic: 0x%x\n", sc->known_magic);
    printk(KERN_INFO "  Hook ID: %u\n", sc->id);
    printk(KERN_INFO "  Syscall Name: %s\n", sc->syscall_name);
    printk(KERN_INFO "  PC: 0x%llx\n", sc->pc);
    printk(KERN_INFO "  Return Val: %ld\n", sc->retval);
    printk(KERN_INFO "  Skip: %d\n", sc->skip_syscall);
    printk(KERN_INFO "  Task: %p\n", sc->task);
    printk(KERN_INFO "  Regs: %p\n", sc->regs);
    
    printk(KERN_INFO "  Arguments (%u):\n", sc->argc);
    for (int i = 0; i < sc->argc && i < IGLOO_SYSCALL_MAXARGS; i++) {
        printk(KERN_INFO "    arg[%d]: 0x%llx\n", i, sc->args[i]);
    }
    printk(KERN_INFO "IGLOO: ------------------------\n");
}

static void fill_handler(struct syscall_event *args, int argc, const unsigned long args_ptrs[], u32 hook_id, const char* syscall_name) {
    struct pt_regs *regs;
    
    // Fill the syscall structure with arguments
    args->known_magic = SYSCALL_HC_KNOWN_MAGIC;
    args->id = hook_id;
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
    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS; i++) {
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

// Global atomic counter for syscall sequence numbers
static atomic64_t syscall_sequence_counter = ATOMIC64_INIT(0);

static void do_hyp(bool is_enter, struct syscall_event* args) {
    // Set the sequence number atomically
    uint64_t sequence = atomic64_inc_return(&syscall_sequence_counter);
    
    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_SYSCALL_ENTER : IGLOO_HYP_SYSCALL_RETURN,
                sequence, (unsigned long)args);
}

// Check if a syscall matches a hook's criteria
bool hook_matches_syscall(struct syscall_hook *hook, const char *syscall_name, 
                         int argc, const unsigned long args[])
{
    // If hook is disabled, it doesn't match
    if (!hook->enabled){
        // printk(KERN_EMERG "Failed on hook enabled check: %d\n", hook->enabled);
        return false;
    }
    
    // Check if we should match all syscalls
    if (hook->on_all){
        return true;
    }
    
    // Check if we need to match syscall name
    if (syscall_name && hook->name[0] != '\0') {
        if (strcmp(hook->name, syscall_name) != 0 && strcmp(hook->name, syscall_name+1) != 0){
            // printk(KERN_EMERG "Failed on syscall name match: %s != %s\n", hook->name, syscall_name);
            return false;
        }
    } else if (hook->name[0] != '\0') {
        // Hook wants a specific syscall but we don't have a name
        return false;
    }
    
    // If comm_filter is enabled, check process name
    if (hook->comm_filter_enabled) {
        if (strncmp(current->comm, hook->comm_filter, TASK_COMM_LEN) != 0){
            // printk(KERN_EMERG "Failed on comm filter: %s != %s\n", current->comm, hook->comm_filter);
            return false;
        }
    }
    
    // If PID filter is enabled, check the current process ID
    if (hook->pid_filter_enabled) {
        if (task_pid_nr(current) != hook->filter_pid){
            // printk(KERN_EMERG "Failed on PID filter: %d != %d\n", task_pid_nr(current), hook->filter_pid);
            return false;
        }
    }
    
    // If arg filtering is enabled, check arguments - with safety checks
    if (hook->filter_args_enabled) {
        for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
            if (hook->filter_arg[i]) {
                unsigned long arg_ptr = args[i];
		        unsigned long arg_val = *(unsigned long *)arg_ptr;
		        if (arg_val != hook->arg_filter[i]) {
		        	// printk(KERN_EMERG
		        	//        "Failed on arg filter[%d]: %lx != %lx\n",
		        	//        i, arg_val, hook->arg_filter[i]);
		        	return false;
		        }
            }
        }
    }
    // printk(KERN_EMERG "IGLOO: Hook matches syscall %s\n", syscall_name);
    
    // All criteria matched
    return true;
}

//Entry handler for system calls
static bool syscall_entry_handler(const char *syscall_name, long *skip_ret_val, int argc, const unsigned long args[], igloo_syscall_setter_t setter_func)
{
    if (!igloo_do_hc || !args || !skip_ret_val) {
        return 0;
    }
    
    // Don't allow recursion into ourself from hypercalls
    if (current->flags & PF_KTHREAD) {
        return 0;
    }
    
    // Create our own copy of args to avoid dereferencing directly
    unsigned long safe_args[IGLOO_SYSCALL_MAXARGS] = {0};
    
    // Copy the args values safely without dereferencing
    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
        safe_args[i] = args[i];  // These are values, not pointers to values
    }
    
    // Check for hooks that match this syscall
    struct kernel_syscall_hook *hook;
    bool any_hook_matched = false;
    struct syscall_event syscall_args_holder, original_info;
    bool skip_syscall = false;
    long skip_ret_val_local = 0;
    
    // For collecting matching hooks
    u32 matching_hook_ids[MAX_MATCHING_HOOKS];
    int num_matching_hooks = 0;
    
    // First, safely collect all matching hook IDs
    int i;
    struct hlist_node *tmp;
    
    spin_lock(&syscall_hook_lock);
    hash_for_each_safe(syscall_hook_table, i, tmp, hook, hlist) {
        if (hook->hook.on_enter && hook_matches_syscall(&hook->hook, syscall_name, argc, safe_args)) {
            if (num_matching_hooks < MAX_MATCHING_HOOKS) {
                matching_hook_ids[num_matching_hooks++] = hook->hook.id;
                any_hook_matched = true;
            } else {
                DBG_PRINTK("IGLOO: Too many matching hooks for syscall %s, some will be ignored\n", syscall_name);
                break;
            }
        }
    }
    spin_unlock(&syscall_hook_lock);
    
    // If no hooks matched, we can skip the hypercall entirely
    if (!any_hook_matched) {
        DBG_PRINTK("IGLOO: No hooks matched for syscall %s, skipping hypercalls\n", syscall_name);
        return false;
    }
    
    // Now process each matching hook without holding the lock
    for (int hook_idx = 0; hook_idx < num_matching_hooks; hook_idx++) {
        u32 matched_hook_id = matching_hook_ids[hook_idx];
        
        // Fill syscall args structure once - we'll use it for all matching hooks
        fill_handler(&syscall_args_holder, argc, safe_args, matched_hook_id, syscall_name);
        
        // Make a local copy for this hook
        memcpy(&original_info, &syscall_args_holder, sizeof(struct syscall_event));
        
        DBG_PRINTK("IGLOO: Syscall %s matched hook ID %u (%d of %d)\n", 
                  syscall_name, matched_hook_id, hook_idx + 1, num_matching_hooks);
        
        // Make the hypercall for this hook
        do_hyp(true, &syscall_args_holder);
        
        // Check if arguments were modified
        bool was_modified = false;
        for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
            if (syscall_args_holder.args[i] != original_info.args[i]) {
                DBG_PRINTK("Hypercall modified arg[%d]: old=0x%lx, new=0x%lx\n",
                          i, original_info.args[i], syscall_args_holder.args[i]);
                was_modified = true;
                break;
            }
        }            
        if (was_modified && setter_func && args) {
            // Cast to the expected type (__le64 *) to match the function signature
            setter_func(args, (const __le64 *)&syscall_args_holder.args[0]);
        }
        
        // Check if syscall should be skipped
        if (syscall_args_holder.skip_syscall) {
            skip_syscall = true;
            skip_ret_val_local = syscall_args_holder.retval;
            DBG_PRINTK("IGLOO: Hook %u requested to skip syscall %s with return value %lx\n", 
                      matched_hook_id, syscall_name, skip_ret_val_local);
            break; // Exit early if any hook requests to skip
        }
    }
    
    // If any hook requested to skip the syscall, do so
    if (skip_syscall) {
        *skip_ret_val = skip_ret_val_local;
        return true;
    }
    
    // If no hooks matched, we didn't do anything
    if (!any_hook_matched) {
        DBG_PRINTK("IGLOO: No hooks matched for syscall %s, skipping hypercall\n", syscall_name);
        return 0;
    }
    
    // Continue with syscall execution - we already processed all matches above
    return false;
}

// Return handler for system calls
static long syscall_ret_handler(const char *syscall_name, long orig_ret, int argc, const unsigned long args[]){
    if (!igloo_do_hc) {
        return orig_ret;
    }
    // Don't allow recursion into ourself from hypercalls
    if (current->flags & PF_KTHREAD) {
        return orig_ret;
    }
    
    // Check for hooks that match this syscall
    struct kernel_syscall_hook *hook;
    bool any_hook_matched = false;
    struct syscall_event syscall_args_holder;
    long modified_ret = orig_ret;
    
    // For collecting matching hooks
    u32 matching_hook_ids[MAX_MATCHING_HOOKS];
    int num_matching_hooks = 0;
    
    // First, safely collect all matching hook IDs
    int i;
    struct hlist_node *tmp;
    
    spin_lock(&syscall_hook_lock);
    hash_for_each_safe(syscall_hook_table, i, tmp, hook, hlist) {
        if (hook->hook.on_return && hook_matches_syscall(&hook->hook, syscall_name, argc, args)) {
            if (num_matching_hooks < MAX_MATCHING_HOOKS) {
                matching_hook_ids[num_matching_hooks++] = hook->hook.id;
                any_hook_matched = true;
            } else {
                DBG_PRINTK("IGLOO: Too many matching hooks for syscall %s return, some will be ignored\n", syscall_name);
                break;
            }
        }
    }
    spin_unlock(&syscall_hook_lock);
    
    // If no hooks matched, we can skip the hypercall entirely
    if (!any_hook_matched) {
        DBG_PRINTK("IGLOO: No hooks matched for syscall %s return, skipping hypercalls\n", syscall_name);
        return orig_ret;
    }
    
    // Now process each matching hook without holding the lock
    for (int hook_idx = 0; hook_idx < num_matching_hooks; hook_idx++) {
        u32 matched_hook_id = matching_hook_ids[hook_idx];
        
        // Fill syscall args structure once - we'll use it for all matching hooks
        fill_handler(&syscall_args_holder, argc, args, matched_hook_id, syscall_name);
        
        // Update the return value
        syscall_args_holder.retval = modified_ret;
        
        DBG_PRINTK("IGLOO: Syscall %s return matched hook ID %u (%d of %d)\n", 
                  syscall_name, matched_hook_id, hook_idx + 1, num_matching_hooks);
        
        // Make the hypercall for this hook
        do_hyp(false, &syscall_args_holder);
        
        // Check if return value was modified
        long new_ret = syscall_args_holder.retval;
        if (new_ret != modified_ret) {
            DBG_PRINTK("Hypercall modified return value: old=%ld, new=%ld\n",
                      modified_ret, new_ret);
            modified_ret = new_ret;
        }
    }
    
    // If no hooks matched, just return the original value
    if (!any_hook_matched) {
        DBG_PRINTK("IGLOO: No hooks matched for syscall %s return, skipping hypercall\n", syscall_name);
        return orig_ret;
    }
    
    // Return the potentially modified value
    return modified_ret;
}

#ifndef ARCH_HAS_SYSCALL_MATCH_SYM_NAME
static inline bool arch_syscall_match_sym_name(const char *sym, const char *name)
{
	/*
	 * Only compare after the "sys" prefix. Archs that use
	 * syscall wrappers may have syscalls symbols aliases prefixed
	 * with ".SyS" or ".sys" instead of "sys", leading to an unwanted
	 * mismatch.
	 */
	return !strcmp(sym + 3, name + 3);
}
#endif

// copied from trace_syscalls.c
static struct syscall_metadata *
find_syscall_meta_copy(unsigned long syscall);
static struct syscall_metadata *
find_syscall_meta_copy(unsigned long syscall)
{
	struct syscall_metadata **start;
	struct syscall_metadata **stop;
	char str[KSYM_SYMBOL_LEN];


	start = __start_syscalls_metadata;
	stop = __stop_syscalls_metadata;
	kallsyms_lookup(syscall, NULL, NULL, NULL, str);

	if (arch_syscall_match_sym_name(str, "sys_ni_syscall"))
		return NULL;

	for ( ; start < stop; start++) {
		if ((*start)->name && arch_syscall_match_sym_name(str, (*start)->name))
			return *start;
	}
	return NULL;
}

static void report_syscall(char * buffer, struct syscall_metadata *meta){
    if (!meta || !meta->name) {
        return; // Skip invalid metadata
    }
    // Prepare JSON metadata for hypercall (ensure buffer is large enough)
    int x = snprintf(buffer, PAGE_SIZE,
                   "{\"name\": \"%s\", \"args\":[",
                    meta->name);

    for (int j = 0; j < meta->nb_args && x > 0 && x < PAGE_SIZE; j++) {
        // Append args safely, checking remaining buffer space
        x += snprintf((char*)buffer + x, PAGE_SIZE - x, "[\"%s\", \"%s\"]%s",
                      meta->types[j] ? meta->types[j] : "?", // Handle potential NULL type/arg names
                      meta->args[j] ? meta->args[j] : "?",
                      j + 1 < meta->nb_args ? ", " : "");
    }

    if (x > 0 && x < PAGE_SIZE) {
         x += snprintf((char*)buffer + x, PAGE_SIZE - x, "]}");
    }

    if (x <= 0 || x >= PAGE_SIZE) {
         DBG_PRINTK( "IGLOO: Failed to format JSON for syscall %s (nr %d) - buffer overflow or snprintf error.\n", meta->name, meta->syscall_nr);
         // Decide how to handle: skip this probe or abort? Skipping for now.
         return;
    }
    // Send metadata via hypercall (call returns value, but it's ignored here)
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
}

#ifdef CONFIG_COMPAT
/* For ARM64 */
#if defined(CONFIG_ARM64)
extern const syscall_fn_t compat_sys_call_table[];
/* Don't redeclare sys_call_table as it's already in syscall.h with correct type */
#define COMPAT_TABLE_SIZE __NR_compat32_syscalls

/* For x86_64 */
#elif defined(CONFIG_X86_64)
/* Use void* instead of syscall_fn_t for broader compatibility */
extern const void * const ia32_sys_call_table[];
#define compat_sys_call_table ia32_sys_call_table
#define COMPAT_TABLE_SIZE IA32_NR_syscalls

/* For MIPS64 */
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
extern const void *sys32_call_table[];
#define compat_sys_call_table sys32_call_table 
#define COMPAT_TABLE_SIZE __NR_syscalls

/* For PPC64 */
#elif defined(CONFIG_PPC64)
extern void *sys32_call_table[];
#define compat_sys_call_table sys32_call_table
#define COMPAT_TABLE_SIZE __NR_syscalls

/* For RISC-V64 */
#elif defined(CONFIG_RISCV) && defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
/* Use the correct declaration for RISC-V - it's already properly declared in syscall.h */
#define COMPAT_TABLE_SIZE __NR_syscalls
#endif
#endif

/* Add sys_ni_syscall declaration */
extern asmlinkage long sys_ni_syscall(const struct pt_regs *);

/* Get syscall name from a function pointer */
static const char *get_syscall_name_from_func(void *func_ptr) {
    char sym[KSYM_SYMBOL_LEN];
    
    if (!func_ptr || IS_ERR(func_ptr))
        return NULL;
        
    kallsyms_lookup((unsigned long)func_ptr, NULL, NULL, NULL, sym);
    
    /* Skip if we couldn't identify the symbol */
    if (!sym[0])
        return NULL;
    
    /* Skip the "sys_" or similar prefix */
    if (strncmp(sym, "sys_", 4) == 0)
        return kstrdup(sym, GFP_KERNEL);
    else if (strncmp(sym, "compat_sys_", 11) == 0) 
        return kstrdup(sym + 7, GFP_KERNEL); /* Return without the "compat_" prefix */
    else if (strncmp(sym, "__arm64_", 8) == 0)
        return kstrdup(sym + 8, GFP_KERNEL); /* Return without the "__arm64_" prefix */
    else if (strncmp(sym, "__loongarch_", 12) == 0)
        return kstrdup(sym + 12, GFP_KERNEL); /* Return without the "__loongarch_" prefix */
    else if (strncmp(sym, "__riscv_", 8) == 0)
        return kstrdup(sym + 8, GFP_KERNEL); /* Return without the "__riscv_" prefix */
    else if (strncmp(sym, "__se_", 5) == 0)
        return kstrdup(sym + 5, GFP_KERNEL); /* Return without the "__se_" prefix */
    
    return kstrdup(sym, GFP_KERNEL);
}

static void report_syscall_from_func(char *buffer, void *func_ptr, int syscall_nr) {
    const char *name;
    int x;
    
    if (!func_ptr || IS_ERR(func_ptr))
        return;
    
    name = get_syscall_name_from_func(func_ptr);
    if (!name)
        return;
    
    /* Create a simplified metadata report for compat syscalls */
    x = snprintf(buffer, PAGE_SIZE, "{\"name\": \"%s\", \"compat\": true, \"args\":\"unknown\"}", name);
    
    if (x > 0 && x < PAGE_SIZE) {
        /* Send this metadata via hypercall */
        igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
    }
    
    kfree(name);
}

int syscalls_hc_init(void) {
    printk(KERN_EMERG "IGLOO: Initializing syscall hypercalls\n");
    if (!igloo_do_hc) {
        printk(KERN_INFO "IGLOO: Hypercalls disabled, syscalls tracing not activated\n");
        return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

    igloo_syscall_enter_hook = syscall_entry_handler;
    igloo_syscall_return_hook = syscall_ret_handler;

    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    
    if (!buffer) {
        printk(KERN_ERR "IGLOO: Failed to allocate memory for syscall metadata buffer\n");
        return -ENOMEM;
    }

    // Count the number of syscalls
    int num_syscall_probes = end - p;
    if (num_syscall_probes <= 0) {
        printk(KERN_WARNING "IGLOO: No syscall metadata found.\n");
        return -EINVAL;
    }

    // Process regular syscalls first
    int i;
    for (i = 0; i < NR_syscalls+1000; i++) {
        struct syscall_metadata *meta;
        unsigned long addr;
        addr = arch_syscall_addr(i);
        meta = find_syscall_meta_copy(addr);
        if (!meta)
            continue;
        meta->syscall_nr = i;
        report_syscall(buffer, meta);
    }

    for (p = __start_syscalls_metadata; p < end; p++) {
        struct syscall_metadata *meta = *p;
        if (!meta) {
            continue; // Skip invalid metadata
        }
        report_syscall(buffer, meta);
    }
    
    // Process compat syscalls
#ifdef CONFIG_COMPAT
#ifdef COMPAT_TABLE_SIZE
    printk(KERN_INFO "IGLOO: Processing compat syscall table with %d entries\n", COMPAT_TABLE_SIZE);
    
    for (i = 0; i < COMPAT_TABLE_SIZE; i++) {
#if defined(CONFIG_RISCV) && defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
        /* For RISC-V, use the already declared variable without casting */
        void *func_ptr = compat_sys_call_table[i];
#else
        /* For other architectures, use proper casting based on architecture pointer size */
        void *func_ptr = (void *)(uintptr_t)compat_sys_call_table[i];
#endif
        
        /* Skip non-existent syscalls (usually NULL) */
        if (!func_ptr || IS_ERR(func_ptr)) {
            continue;
        }
            
        /* Only with MIPS and some other architectures, compare against sys_ni_syscall
         * But to avoid further compatibility issues, skip this check on ARM64
         */
#if !defined(CONFIG_ARM64)
        if (func_ptr == (void *)sys_ni_syscall)
            continue;
#endif
        
        report_syscall_from_func(buffer, func_ptr, i);
    }
#else
    printk(KERN_INFO "IGLOO: No compat syscall table found for this architecture\n");
#endif
#endif

    kfree(buffer);
    /* Initialize the hash table */
    hash_init(syscall_hook_table);
    return 0;
}