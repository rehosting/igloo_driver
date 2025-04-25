#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h> /* Add missing include for hashtable support */
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



// Define IGLOO_DEBUG=1 during compilation to enable debug prints
#ifdef IGLOO_DEBUG
#define DBG_PRINTK(fmt, ...) printk(KERN_DEBUG "IGLOO_DBG: " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) do {} while (0)
#endif

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
    unsigned long addr;      /* Function address */
    int syscall_nr;          /* Syscall number */
    struct hlist_node node;  /* Hash list node */
};

/* Add a syscall address entry to the hash table */
static void add_syscall_addr_mapping(unsigned long addr, int syscall_nr)
{
    struct syscall_addr_entry *entry;

    if (!addr)
        return;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        printk(KERN_ERR "IGLOO: Failed to allocate memory for syscall_addr_entry\n");
        return;
    }

    entry->addr = addr;
    entry->syscall_nr = syscall_nr;

    spin_lock(&syscall_map_lock);
    hash_add(syscall_addr_map, &entry->node, addr);
    spin_unlock(&syscall_map_lock);

    DBG_PRINTK("Added syscall mapping: addr=0x%lx, nr=%d\n", addr, syscall_nr);
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

    // Note: This might be less reliable depending on architecture and kprobe type
    unsigned long ip = instruction_pointer(regs);
    syscall_nr = get_syscall_nr_from_addr(ip);
    if (VALID_SYSCALL(syscall_nr)){
        DBG_PRINTK("Syscall nr %ld found via instruction pointer lookup for ip=0x%lx\n", syscall_nr, ip);
        return syscall_nr;
    }
    
    // For other architectures, use the standard method
    syscall_nr = syscall_get_nr(current, regs);
    if (VALID_SYSCALL(syscall_nr)){
        return syscall_nr;
    }

    DBG_PRINTK("Failed to get valid syscall number for ip=0x%lx\n", ip);
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
        printk(KERN_WARNING "IGLOO: Invalid syscall number detected in fill_syscall.\n");
        // Invalid syscall number, set defaults and return false
        args->nr = cpu_to_le64(-1);
        args->pc = cpu_to_le64(instruction_pointer(regs));
        args->task = cpu_to_le64((unsigned long)current);
        return false; // Indicate failure
    }
    unsigned long ip = instruction_pointer(regs);

    args->nr = cpu_to_le64(nr);
    args->pc = cpu_to_le64(ip);

    // Now safely get arguments
    syscall_get_arguments(current, regs, args_tmp);
    #if defined(__powerpc__) || defined(__PPC__)
    // Specific handling for PowerPC if needed (example, might need adjustment)
    // args_tmp[0] = regs->gpr[3]; // Example: Ensure this is correct for your ABI
    #endif

    // Copy arguments safely with endianness conversion
    for (int i = 0; i < MAX_ARGS && i < 6; i++) { // Assuming max 6 args relevant
        args->args[i] = cpu_to_le64(args_tmp[i]);
    }

    long retval = syscall_get_return_value(current, regs); // Get retval even on entry (usually 0 or error)
    long task = (unsigned long)current;

    args->retval = cpu_to_le64(retval);
    args->task = cpu_to_le64(task);
    return true; // Indicate success
}

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock); // Keep commented out unless hypercall needs external locking

static int igloo_handler(struct kretprobe_instance *ri, struct pt_regs *regs, bool is_enter){
    if (!igloo_do_hc) {
        return 0;
    }
    // Don't allow recursion into ourself from hypercalls
    if (current->flags & PF_KTHREAD) {
        return 0;
    }

    struct syscall *args = (struct syscall *)ri->data;
    struct syscall original_info; // For comparison after hypercall
    __le64 known_magic = cpu_to_le64(SYSCALL_HC_KNOWN_MAGIC);
    unsigned long hc_ret = 0; // Re-introduce variable for hypercall return value

    // --- DEBUG: Check args pointer ---
    if (!args) {
        printk(KERN_ERR "IGLOO: CRITICAL - ri->data (args pointer) is NULL in %s handler!\n", is_enter ? "entry" : "return");
        return 0; // Cannot proceed
    }
    // Optional: Add check for valid kernel address range if possible
    // if (!virt_addr_valid(args)) { ... }

    if (is_enter){
        // Fill the struct on entry
        if (current && task_pt_regs(current)){
            regs = task_pt_regs(current);
        }else{
            printk(KERN_ERR "IGLOO: CRITICAL - Unable to get pt_regs for current task in entry handler!\n");
        }
        if (!fill_syscall(ri, regs, args)){
            // Error already printed in fill_syscall if nr was invalid
            // Determine the kprobe name for better context
            const char *kprobe_name = "unknown";
            // #ifdef CONFIG_KRETPROBE_ON_RETHOOK
            // if (ri->node.rethook && ri->node.rethook->data) {
            //     struct kretprobe *rp = (struct kretprobe*) ri->node.rethook->data;
            //     if (rp && rp->kp.symbol_name) {
            //         kprobe_name = rp->kp.symbol_name;
            //     }
            // }
            // #else
            // // Fallback if not using rethook or different kprobe config
            // if (ri->rp && ri->rp->kp.symbol_name) {
            //      kprobe_name = ri->rp->kp.symbol_name;
            // }
            // #endif
            printk(KERN_ERR "IGLOO: Failed to fill syscall structure in entry (kretprobe: %s)\n", kprobe_name);
            // Set magic to invalid to prevent processing in return handler if needed
            args->known_magic = 0;
            return 0; // Don't proceed to hypercall if filling failed
        }
        DBG_PRINTK("Entry: nr=%lld, pc=0x%llx, task=0x%llx, arg0=0x%llx\n",
                   le64_to_cpu(args->nr), le64_to_cpu(args->pc), le64_to_cpu(args->task), le64_to_cpu(args->args[0]));

    } else { // Return handler
        // --- DEBUG: Check magic number on return ---
        if (args->known_magic != known_magic) {
            printk(KERN_ERR "IGLOO: Return handler - Invalid magic number! Expected 0x%llx, got 0x%llx. Data possibly corrupted.\n",
                   le64_to_cpu(known_magic), le64_to_cpu(args->known_magic));
            return 0; // Don't trust this data
        }

        // Update return value and task pointer for the return hypercall
        long retval = syscall_get_return_value(current, regs);
        long task = (unsigned long)current; // Task pointer might be same, but update just in case
        args->retval = cpu_to_le64(retval);
        args->task = cpu_to_le64(task); // Update task ptr

        DBG_PRINTK("Return: nr=%lld, pc=0x%llx, task=0x%llx, retval=%lld\n",
                   le64_to_cpu(args->nr), le64_to_cpu(args->pc), le64_to_cpu(args->task), le64_to_cpu(args->retval));
    }

    // Create a safe copy *before* the hypercall for comparison later
    memcpy(&original_info, args, sizeof(struct syscall));

    // --- DEBUG: Print args pointer before hypercall ---
    DBG_PRINTK("Calling hypercall %lu with args struct at address: 0x%lx\n",
               is_enter ? (unsigned long)IGLOO_HYP_SYSCALL_ENTER : (unsigned long)IGLOO_HYP_SYSCALL_RETURN,
               (unsigned long)args);

    // Use spinlock instead of mutex - safe for atomic contexts (if needed)
    unsigned long flags;
    spin_lock_irqsave(&syscall_hc_lock, flags);

    // Make sure we don't pass NULL to the hypercall (redundant check, args checked above)
    if (regs != NULL && current != NULL) {
        if (is_enter) {
             hc_ret = igloo_hypercall2(IGLOO_HYP_SYSCALL_ENTER, (unsigned long)args, 0);
        } else {
             // Call the return hypercall
             hc_ret = igloo_hypercall2(IGLOO_HYP_SYSCALL_RETURN, (unsigned long)args, 0);

        }
        if (args->known_magic != original_info.known_magic) {
             printk(KERN_WARNING "IGLOO: Magic number changed after hypercall! Before=0x%llx, After=0x%llx\n",
                    le64_to_cpu(original_info.known_magic), le64_to_cpu(args->known_magic));
        }
        // Updated debug print to include hc_ret again
        DBG_PRINTK("Returned from hypercall (hc_ret=%lu). Checking for changes. args struct addr: 0x%lx\n", hc_ret, (unsigned long)args);


        // Only modify registers if something changed and debug flag is off
        if (args->retval != original_info.retval) {
            DBG_PRINTK("Hypercall modified retval: old=%lld, new=%lld\n",
                       le64_to_cpu(original_info.retval), le64_to_cpu(args->retval));
            syscall_set_return_value(current, regs, le64_to_cpu(args->retval), 0);
        }

        // Only update arguments that changed
        for (int i = 0; i < MAX_ARGS && i < 6; i++) {
            if (args->args[i] != original_info.args[i]) {
                 DBG_PRINTK("Hypercall modified arg[%d]: old=0x%llx, new=0x%llx\n",
                           i, le64_to_cpu(original_info.args[i]), le64_to_cpu(args->args[i]));
                syscall_set_argument(current, regs, i, le64_to_cpu(args->args[i]));
            }
        }

    }else{
        // This should ideally not happen if args check passed above
        printk(KERN_EMERG "IGLOO: NULL pointer detected just before hypercall (should not happen)!\n");
    }

    // Release spinlock (if used)
    spin_unlock_irqrestore(&syscall_hc_lock, flags);

    // Handle skip syscall flag (only relevant on entry)
    // NOTE: This check is now *before* the commented out block above.
    if (is_enter && args->skip_syscall != original_info.skip_syscall) {
         DBG_PRINTK("Hypercall requested syscall skip (flag changed from %lld to %lld)\n",
                    le64_to_cpu(original_info.skip_syscall), le64_to_cpu(args->skip_syscall));
    }

    if (is_enter && le64_to_cpu(args->skip_syscall)){
        DBG_PRINTK("Executing syscall skip for nr=%lld\n", le64_to_cpu(args->nr));
        // Returning 1 tells kprobes to skip the original function (syscall)
        // Ensure return value is already set correctly by hypercall if skipping
        return 1;
    }

    return 0; // Continue normal execution / return handler finished
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
    if (num_syscall_probes <= 0) {
        printk(KERN_WARNING "IGLOO: No syscall metadata found.\n");
        return -EINVAL;
    }

    printk(KERN_INFO "IGLOO: Found %d potential syscalls to probe.\n", num_syscall_probes);

    // Allocate memory for kretprobes
    syscall_kretprobes = kzalloc(sizeof(struct kretprobe) * num_syscall_probes, GFP_KERNEL);
    if (!syscall_kretprobes) {
        printk(KERN_ERR "IGLOO: Failed to allocate memory for kretprobes (%d needed)\n", num_syscall_probes);
        return -ENOMEM;
    }
    DBG_PRINTK("Allocated kretprobe array at 0x%px\n", syscall_kretprobes);

    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        kfree(syscall_kretprobes);
        printk(KERN_ERR "IGLOO: Failed to allocate buffer for syscall metadata JSON\n");
        return -ENOMEM;
    }
    DBG_PRINTK("Allocated JSON buffer at 0x%px\n", buffer);

    int i = 0;
    int successful_probes = 0;
    int failed_probes = 0;
    int skipped_syscalls = 0;

    hash_init(syscall_addr_map); // Initialize the hash table

    for (; p < end; p++, i++) {
        struct syscall_metadata *meta = *p;
        if (!meta || !meta->name) {
             printk(KERN_WARNING "IGLOO: Found NULL metadata entry at index %d\n", i);
             continue; // Skip invalid metadata
        }

        if (meta->syscall_nr == -1){
            DBG_PRINTK("Skipping metadata entry for '%s' with syscall_nr -1\n", meta->name);
            continue; // Skip syscalls explicitly marked as -1
        }

        // Update min/max syscall numbers seen
        min_syscall_num = min(min_syscall_num, meta->syscall_nr);
        max_syscall_num = max(max_syscall_num, meta->syscall_nr);

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
             printk(KERN_ERR "IGLOO: Failed to format JSON for syscall %s (nr %d) - buffer overflow or snprintf error.\n", meta->name, meta->syscall_nr);
             // Decide how to handle: skip this probe or abort? Skipping for now.
             failed_probes++;
             continue;
        }
        // printk(KERN_EMERG "IGLOO: JSON for syscall %s (nr %d): %s\n", meta->name, meta->syscall_nr, (char*)buffer);

        // Send metadata via hypercall (call returns value, but it's ignored here)
        igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);

        // Set up kretprobe for this syscall
        struct kretprobe *krp = &syscall_kretprobes[i];

        // Initialize kretprobe structure to zeros
        memset(krp, 0, sizeof(struct kretprobe));

        krp->handler = syscall_ret_handler;
        krp->entry_handler = syscall_entry_handler;
        krp->data_size = sizeof(struct syscall); // Allocate space for probe data
        krp->maxactive = 32;  // Max number of concurrent instances (adjust if needed)
        // krp->kp.offset = 0; // Offset is usually 0 for function entry
        // krp->kp.symbol_name = meta->name; // Set symbol name directly if register_syscall_kretprobe doesn't handle it


        // --- DEBUG: Print data_size ---
        DBG_PRINTK("Setting up kretprobe for %s (nr %d), data_size=%zu\n",
                   meta->name, meta->syscall_nr, krp->data_size);


        // Register the kretprobe using helper function which tries different naming conventions
        int ret = register_syscall_kretprobe(krp, meta->name);

        if (ret == -EINVAL || ret == -ENOENT) {
            // Symbol not found with any naming convention
            printk(KERN_WARNING "IGLOO: Skipping syscall %s (nr %d): Symbol not found or invalid.\n",
                   meta->name, meta->syscall_nr);
            skipped_syscalls++;
        } else if (ret == -EOPNOTSUPP) {
            // Function cannot be probed by design (e.g., marked __kprobes NOPROBE)
            printk(KERN_WARNING "IGLOO: Skipping unprobeable function %s (nr %d): EOPNOTSUPP.\n",
                   meta->name, meta->syscall_nr);
            skipped_syscalls++;
        } else if (ret < 0) {
            // Other registration errors
            printk(KERN_ERR "IGLOO: Failed to register kretprobe for %s (nr %d): error %d\n",
                   meta->name, meta->syscall_nr, ret);
            failed_probes++;
        } else {
            // Success
            DBG_PRINTK("Successfully registered kretprobe for %s at addr 0x%px\n", meta->name, krp->kp.addr);
            // Add mapping from resolved address to syscall number for fallback lookup
            add_syscall_addr_mapping((unsigned long)krp->kp.addr, meta->syscall_nr);
            successful_probes++;
        }
    }

    // printk(KERN_INFO "IGLOO: Syscall probe registration complete. Successful: %d, Skipped: %d, Failed: %d. Syscall range: [%d, %d]\n",
        //    successful_probes, skipped_syscalls, failed_probes, min_syscall_num, max_syscall_num);

    kfree(buffer);
    // Call hypercall (returns value, but it's ignored here)
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, 0); // Signal end of setup

    // Return success only if at least one probe was registered
    // Allows the module to load even if some syscalls are unavailable
    if (successful_probes == 0 && num_syscall_probes > 0) {
         printk(KERN_ERR "IGLOO: No syscall probes were successfully registered.\n");
         // Clean up already allocated kretprobes array if needed (though unregistering is complex here)
         kfree(syscall_kretprobes);
         syscall_kretprobes = NULL;
         num_syscall_probes = 0;
         return -ENOENT; // No probes active
    }

    return 0; // Success (at least one probe registered or no probes attempted)
}

// Remember to add a cleanup function (syscalls_hc_exit) to unregister probes
// and free syscall_kretprobes and clean up the hash table.
// ... (syscalls_hc_exit implementation needed) ...

