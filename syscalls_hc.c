#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h> /* Add missing include for hashtable support */
#include "hypercall.h"
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "kprobe_syscalls.h"

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

/* Hash table to store address to syscall number mapping */
DEFINE_HASHTABLE(syscall_addr_map, 12); /* 2^12 buckets */
DEFINE_SPINLOCK(syscall_map_lock);

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
} __packed __aligned(8);   /* Ensure 8-byte alignment */

static struct kretprobe *syscall_kretprobes = NULL;
static int num_syscall_probes = 0;

static int min_syscall_num = INT_MAX;
static int max_syscall_num = 0;

#define VALID_SYSCALL(x) (x >= min_syscall_num && x <= max_syscall_num)


/* Structure to map function address to syscall number */
struct syscall_addr_entry {
    unsigned long addr;       /* Function address */
    int syscall_nr;           /* Syscall number */
    struct hlist_node node;   /* Hash list node */
};

/* Add a syscall address entry to the hash table */
static void add_syscall_addr_mapping(unsigned long addr, int syscall_nr)
{
    struct syscall_addr_entry *entry;
    
    if (!addr)
        return;
        
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return;
        
    entry->addr = addr;
    entry->syscall_nr = syscall_nr;
    
    spin_lock(&syscall_map_lock);
    hash_add(syscall_addr_map, &entry->node, addr);
    spin_unlock(&syscall_map_lock);
    
    pr_debug("IGLOO: Added syscall mapping: addr=0x%lx, nr=%d\n", addr, syscall_nr);
}

/**
 * get_syscall_nr_from_addr - Look up syscall number from function address
 * @addr: Function address to look up
 *
 * Returns the syscall number if found, or -1 if not found
 */
static int get_syscall_nr_from_addr(unsigned long addr)
{
    struct syscall_addr_entry *entry;
    int syscall_nr = -1;
    
    spin_lock(&syscall_map_lock);
    hash_for_each_possible(syscall_addr_map, entry, node, addr) {
        if (entry->addr == addr) {
            syscall_nr = entry->syscall_nr;
            break;
        }
    }
    spin_unlock(&syscall_map_lock);
    
    return syscall_nr;
}

/* For architectures that don't use direct function pointer calls for syscalls */
static long get_syscall_nr(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long syscall_nr = -1;

    // For other architectures, use the standard method
    syscall_nr = syscall_get_nr(current, regs);
    if (VALID_SYSCALL(syscall_nr)){
        return syscall_nr;
    }

    syscall_nr = get_syscall_nr_from_addr(instruction_pointer(regs));
    if (VALID_SYSCALL(syscall_nr)){
        return syscall_nr;
    }
    
	return -1;
}

static bool fill_syscall(struct kretprobe_instance *ri, struct pt_regs *regs, struct syscall *args) {
    // Initialize the structure to prevent memory corruption
    memset(args, 0, sizeof(struct syscall));
    
    // Set values with proper endianness conversion
    args->known_magic = cpu_to_le64(SYSCALL_HC_KNOWN_MAGIC);
    args->skip_syscall = cpu_to_le64(0);
    
    // Extract arguments using architecture-specific helper
    unsigned long args_tmp[MAX_ARGS] = {0};
    long nr;
    
    // Get the syscall number
    nr = get_syscall_nr(ri, regs);


    if (nr == -1) {
        printk(KERN_ERR "IGLOO: Invalid syscall number: %ld\n", nr);
        // Invalid syscall number, set defaults and return
        args->nr = cpu_to_le64(-1);
        args->pc = cpu_to_le64(instruction_pointer(regs));
        args->task = cpu_to_le64((unsigned long)current);
        return false;
    }
    unsigned long ip = instruction_pointer(regs);
    
    args->nr = cpu_to_le64(nr);
    args->pc = cpu_to_le64(ip);
    
    // Now safely get arguments
    syscall_get_arguments(current, regs, args_tmp);
    #if defined(__powerpc__) || defined(__PPC__)
    args_tmp[0] = regs->gpr[3];
    #endif
    
    // Copy arguments safely with endianness conversion
    for (int i = 0; i < MAX_ARGS && i < 6; i++) {
        args->args[i] = cpu_to_le64(args_tmp[i]);
    }

    long retval = syscall_get_return_value(current, regs);
    long task = (unsigned long)current;

    args->retval = cpu_to_le64(retval);
    args->task = cpu_to_le64(task);
    return true;
}

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock);

static int igloo_handler(struct kretprobe_instance *ri, struct pt_regs *regs, bool is_enter){
    if (!igloo_do_hc) {
        return 0;
    }
    // Don't allow recursion into ourself from hypercalls
    if (current->flags & PF_KTHREAD) {
        return 0;
    }
    
    struct syscall *args = (struct syscall *)ri->data;
    struct syscall original_info;

    if (!args){
        printk(KERN_ERR "Failure to resolve ri->data");
    }
    
    __le64 known_magic = cpu_to_le64(SYSCALL_HC_KNOWN_MAGIC);
    if (is_enter){
        if (!fill_syscall(ri, regs, args)){
            // Get the name of the kretprobe that failed
            const char *kprobe_name = "unknown";
            #ifdef CONFIG_KRETPROBE_ON_RETHOOK
            if (ri->node.rethook) {
                if (ri->node.rethook->data){
                    struct kretprobe *rp = (struct kretprobe*) ri->node.rethook->data;
                    if (rp && rp->kp.symbol_name){
                        kprobe_name = rp->kp.symbol_name;
                    }
                }
            }
            #endif
            printk(KERN_ERR "IGLOO: Failed to fill syscall structure in enter (kretprobe: %s)\n", kprobe_name);
            return 0;
        }
    } else if (args->known_magic != known_magic) {
        printk(KERN_ERR "IGLOO: Failure in known magic\n");
        return 0;
    }else {
        long retval = syscall_get_return_value(current, regs);
        long task = (unsigned long)current;
        args->retval = cpu_to_le64(retval);
        args->task = cpu_to_le64(task);
    }
    
    // Create a safe copy for comparison later
    memcpy(&original_info, args, sizeof(struct syscall));
    
    // Use spinlock instead of mutex - safe for atomic contexts
    unsigned long flags;
    spin_lock_irqsave(&syscall_hc_lock, flags);
    
    // Make sure we don't pass NULL to the hypercall
    if (regs != NULL && current != NULL) {
        igloo_hypercall(is_enter ? IGLOO_HYP_SYSCALL_ENTER: IGLOO_HYP_SYSCALL_RETURN, 
                       (unsigned long)args);
        
        // Only modify registers if something changed
        if (args->retval != original_info.retval) {
            syscall_set_return_value(current, regs, le64_to_cpu(args->retval), 0);
        }
        
        // Only update arguments that changed
        for (int i = 0; i < MAX_ARGS && i < 6; i++) {
            if (args->args[i] != original_info.args[i]) {
                syscall_set_argument(current, regs, i, le64_to_cpu(args->args[i]));
            }
        }
    }else{
        printk(KERN_EMERG "IGLOO: NULL pointer in igloo_handler\n");
    }
    
    // Release spinlock
    spin_unlock_irqrestore(&syscall_hc_lock, flags);
    
    if (is_enter && args->skip_syscall){
	    return 1;
    }
    return 0;
}

// Entry handler for system calls
static int syscall_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    return igloo_handler(ri, regs, true);
}

// Return handler for system calls
static int syscall_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    return igloo_handler(ri, regs, false);
}

int syscalls_hc_init(void) {
    if (!igloo_do_hc) {
        printk(KERN_INFO "IGLOO: Hypercalls disabled, syscalls tracing not activated\n");
        return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

    // Count the number of syscalls
    num_syscall_probes = end - p;
    
    // Allocate memory for kretprobes
    syscall_kretprobes = kzalloc(sizeof(struct kretprobe) * num_syscall_probes, GFP_KERNEL);
    if (!syscall_kretprobes) {
        printk(KERN_ERR "IGLOO: Failed to allocate memory for kretprobes\n");
        return -ENOMEM;
    }
    
    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        kfree(syscall_kretprobes);
        printk(KERN_ERR "IGLOO: Failed to allocate buffer\n");
        return -ENOMEM;
    }
    
    int i = 0;
    int successful_probes = 0;
    int failed_probes = 0;
    int skipped_syscalls = 0;
    
    for (; p < end; p++, i++) {
        struct syscall_metadata *meta = *p;
        if (meta->syscall_nr == -1){
		    continue;
	    }
	    min_syscall_num = min(min_syscall_num, meta->syscall_nr);
        max_syscall_num = max(max_syscall_num, meta->syscall_nr);
        int x = snprintf(buffer, PAGE_SIZE,
                 "{\"syscall_nr\": %d, \"name\": \"%s\", \"args\":[",
                 meta->syscall_nr, meta->name);

        for (int j = 0; j < meta->nb_args && x < PAGE_SIZE; j++) {
            // end the args array with a closing bracket
            x += snprintf(buffer+x, PAGE_SIZE-x, "[\"%s\", \"%s\"]%s", meta->types[j], meta->args[j], j+1 < meta->nb_args ? ", " : "]}");
        }

        if (meta->nb_args == 0){
            x += snprintf(buffer+x, PAGE_SIZE-x, "]}");
        }
        
        igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
        
        // Set up kretprobe for this syscall
        struct kretprobe *krp = &syscall_kretprobes[i];
        
        // Initialize kretprobe structure to zeros
        memset(krp, 0, sizeof(struct kretprobe));
        
        krp->handler = syscall_ret_handler;
        krp->entry_handler = syscall_entry_handler;
        krp->data_size = sizeof(struct syscall); // Allocate space for probe data
        krp->maxactive = 32;  // Max number of concurrent instances
        krp->kp.offset = 0;

        // Register the kretprobe with different possible naming conventions
        int ret = register_syscall_kretprobe(krp, meta->name);
        
        if (ret == -EINVAL) {
            printk(KERN_EMERG "IGLOO: Skipping unprobeable function %s (EINVAL)\n", 
                   meta->name);
            // EINVAL (-22) indicates that the symbol wasn't found with any naming convention
            skipped_syscalls++;
        } else if (ret == -EOPNOTSUPP) {
            printk(KERN_EMERG "IGLOO: Skipping unprobeable function %s (EOPNOTSUPP)\n", 
                   meta->name);
            // EOPNOTSUPP (-95) means the function can't be probed by design
            skipped_syscalls++;
        } else if (ret < 0) {
            // Other errors are real failures
            printk(KERN_EMERG "IGLOO: Failed to register kretprobe for %s: %d\n", 
                  meta->name, ret);
            failed_probes++;
        } else {
            // Success
            add_syscall_addr_mapping((unsigned long)krp->kp.addr, meta->syscall_nr);
            successful_probes++;
        }
    }
    
    printk(KERN_EMERG "IGLOO: Successfully registered %d syscall probes, skipped %d unprobeable syscalls, failed %d\n", 
           successful_probes, skipped_syscalls, failed_probes);
    
    kfree(buffer);
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, 0);
    
    // Return success even if some probes failed
    // This allows the module to continue operating with the successfully registered probes
    return successful_probes > 0 ? 0 : -ENOENT;
}
