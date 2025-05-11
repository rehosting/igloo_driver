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

// Define IGLOO_DEBUG=1 during compilation to enable debug prints
#ifdef IGLOO_DEBUG
#define DBG_PRINTK(fmt, ...) printk(KERN_EMERG "IGLOO_DBG: " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) do {} while (0)
#endif

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

// add 1 if the struct syscall changes
#define SYSCALL_HC_KNOWN_MAGIC 0x1234
struct syscall {
    /* Use __le64 types to ensure consistent layout across endianness */
    __le64 known_magic;    /* Magic value to validate structure integrity */
    __le64 nr;             /* Syscall number */
    __le64 args[MAX_ARGS]; /* Syscall arguments */
    __le64 pc;             /* Program counter */
    __le64 retval;         /* Return value (signed value stored in unsigned) */
    __le64 skip_syscall;   /* Flag to skip syscall execution */
    __le64 task;           /* Task pointer */
    __le64 name_ptr;       /* Pointer to syscall name string */
} __packed __aligned(8);   /* Ensure 8-byte alignment */

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock); // Keep commented out unless hypercall needs external locking

/* Function to print syscall information */
void print_syscall_info(const struct syscall *sc, const char *prefix);
void print_syscall_info(const struct syscall *sc, const char *prefix) {
    if (!sc) {
        DBG_PRINTK( "IGLOO: %s NULL syscall structure\n", prefix ? prefix : "");
        return;
    }
    
    printk(KERN_INFO "IGLOO: %s Syscall Info --------\n", prefix ? prefix : "");
    printk(KERN_INFO "  Magic: 0x%llx\n", le64_to_cpu(sc->known_magic));
    printk(KERN_INFO "  Syscall #: %lld\n", le64_to_cpu(sc->nr));
    printk(KERN_INFO "  PC: 0x%llx\n", le64_to_cpu(sc->pc));
    printk(KERN_INFO "  Return Val: %lld\n", le64_to_cpu(sc->retval));
    printk(KERN_INFO "  Skip: %lld\n", le64_to_cpu(sc->skip_syscall));
    printk(KERN_INFO "  Task: 0x%llx\n", le64_to_cpu(sc->task));
    
    printk(KERN_INFO "  Arguments:\n");
    for (int i = 0; i < MAX_ARGS; i++) {
        printk(KERN_INFO "    arg[%d]: 0x%llx\n", i, le64_to_cpu(sc->args[i]));
    }
    printk(KERN_INFO "IGLOO: ------------------------\n");
}

static void fill_handler(struct syscall *args, int argc, const unsigned long args_ptrs[], const char * name_ptr){
    struct pt_regs *regs;
    
    // Fill the syscall structure with arguments
    args->known_magic = cpu_to_le64(SYSCALL_HC_KNOWN_MAGIC);
    args->skip_syscall = cpu_to_le64(0);
    args->name_ptr = cpu_to_le64((unsigned long) name_ptr);

    // Copy arguments safely - directly use args_ptrs values without dereferencing
    for (int i = 0; i < MAX_ARGS; i++) {
        if (i < argc){
            unsigned long arg = *(unsigned long*)(args_ptrs[i]);
            args->args[i] = cpu_to_le64(arg);
        }else{
            args->args[i] = cpu_to_le64(0); // Initialize unused args to 0
        }
    }
    args->task = cpu_to_le64((unsigned long)current);
    args->retval = cpu_to_le64(0); // Initialize to 0, will be set by hypercall
    
    regs = task_pt_regs(current);
    if (regs != NULL){
        // Use safe way to get instruction pointer that works across architectures
        args->pc = cpu_to_le64(instruction_pointer(regs));
        // Use proper syscall_get_nr function with just regs parameter
        args->nr = cpu_to_le64(syscall_get_nr(current, regs));
    } else {
        DBG_PRINTK( "IGLOO: Failed to get syscall number from pt_regs\n");
    	args->pc = 0;
	    args->nr = 0;
    }
}

static void do_hyp(bool is_enter, struct syscall* args){
    igloo_portal(is_enter ? IGLOO_HYP_SYSCALL_ENTER : IGLOO_HYP_SYSCALL_RETURN,
                (unsigned long)args, 0);
}

//Entry handler for system calls
static bool syscall_entry_handler(const char *syscall_name, long *skip_ret_val, int argc, const unsigned long args[], igloo_syscall_setter_t setter_func){
    if (!igloo_do_hc) {
        return 0;
    }
    // Don't allow recursion into ourself from hypercalls
    if (current->flags & PF_KTHREAD) {
        return 0;
    }
	struct syscall syscall_args_holder, original_info;
    unsigned long flags;

	DBG_PRINTK("IGLOO: Entering syscall %s with %d args\n",
	       syscall_name, argc);
    fill_handler(&syscall_args_holder, argc, args, syscall_name);
    memcpy(&original_info, &syscall_args_holder, sizeof(struct syscall));

    // print_syscall_info(&syscall_args_holder, "ENTRY");
    
    spin_lock_irqsave(&syscall_hc_lock, flags);
        
    do_hyp(true, &syscall_args_holder);

    // Release spinlock (if used)
    spin_unlock_irqrestore(&syscall_hc_lock, flags);

    bool was_modified = false;
    // Only update arguments that changed
    for (int i = 0; i < MAX_ARGS && i < argc; i++) {
	    if (syscall_args_holder.args[i] != original_info.args[i]) {
		    DBG_PRINTK(
			    "Hypercall modified arg[%d]: old=0x%llx, new=0x%llx\n",
			    i, le64_to_cpu(original_info.args[i]),
			    le64_to_cpu(syscall_args_holder.args[i]));
		    was_modified = true;
		    break;
	    }
    }
    if (was_modified){
        if (setter_func){
            setter_func(args, syscall_args_holder.args);
        }else{
            DBG_PRINTK( "IGLOO: Setter function is NULL, cannot set args\n");
        }
    }

    if (syscall_args_holder.skip_syscall != 0){
        *skip_ret_val = le64_to_cpu(syscall_args_holder.retval);
        DBG_PRINTK( "IGLOO: Skipping syscall %s and returning skip_ret_val %lx\n", syscall_name, *skip_ret_val);
    }
	return syscall_args_holder.skip_syscall != 0;
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
    struct syscall syscall_args_holder, original_info; // For comparison after hypercall
    unsigned long flags;

    DBG_PRINTK( "IGLOO: Exiting syscall %s with return value %ld\n", syscall_name, orig_ret);
    fill_handler(&syscall_args_holder, argc, args, syscall_name);
    syscall_args_holder.retval = cpu_to_le64(orig_ret);
    memcpy(&original_info, &syscall_args_holder, sizeof(struct syscall));

    // Print syscall info before handling return
    // print_syscall_info(&syscall_args_holder, "EXIT");
    spin_lock_irqsave(&syscall_hc_lock, flags);
        
    do_hyp(false, &syscall_args_holder);

    // Release spinlock (if used)
    spin_unlock_irqrestore(&syscall_hc_lock, flags);

    return le64_to_cpu(syscall_args_holder.retval);
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
                   "{\"syscall_nr\": %d, \"name\": \"%s\", \"args\":[",
                   meta->syscall_nr, meta->name);

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

int syscalls_hc_init(void) {
    if (!igloo_do_hc) {
        printk(KERN_INFO "IGLOO: Hypercalls disabled, syscalls tracing not activated\n");
        return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

    igloo_syscall_enter_hook = syscall_entry_handler;
    igloo_syscall_return_hook = syscall_ret_handler;

    // Count the number of syscalls
    int num_syscall_probes = end - p;
    if (num_syscall_probes <= 0) {
        printk(KERN_WARNING "IGLOO: No syscall metadata found.\n");
        return -EINVAL;
    }

    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        DBG_PRINTK( "IGLOO: Failed to allocate buffer for syscall metadata JSON\n");
        return -ENOMEM;
    }
    DBG_PRINTK("Allocated JSON buffer at 0x%px\n", buffer);

    int i = 0;
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

    for (; p < end; p++, i++) {
        struct syscall_metadata *meta = *p;
        if (!meta) {
             printk(KERN_WARNING "IGLOO: Found NULL metadata entry at index %d\n", i);
             continue; // Skip invalid metadata
        }
        report_syscall(buffer, meta);
    }
    kfree(buffer);

    igloo_hypercall(IGLOO_HYP_SETUP_TASK_COMM, offsetof(struct task_struct, comm));
    // Call hypercall (returns value, but it's ignored here)
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, 0); // Signal end of setup

    return 0;
}