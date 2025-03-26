#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/igloo.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

// add 1 if the struct syscall changes
#define SYSCALL_HC_KNOWN_MAGIC 0x1234
struct syscall {
	uint64_t known_magic;
	uint64_t nr;
	uint64_t args[MAX_ARGS];
	uint64_t pc;
	int64_t retval;
	uint64_t skip_syscall;
	uint64_t task;
};

static struct kretprobe *syscall_kretprobes = NULL;
static int num_syscall_probes = 0;

static void fill_syscall(struct task_struct *ts, struct pt_regs *regs, struct syscall *args){
    args->known_magic = SYSCALL_HC_KNOWN_MAGIC;
    
    // Extract arguments using architecture-specific helper
    unsigned long args_tmp[MAX_ARGS];
    syscall_get_arguments(current, regs, args_tmp);

    args->pc = instruction_pointer(regs);
    args->nr = syscall_get_nr(current, regs);
    for (int i=0; i<MAX_ARGS-1; i++){
        args->args[i] = args_tmp[i+1];
    }
    args->retval = syscall_get_return_value(current, regs);
    args->skip_syscall = 0;
    args->task = current;
}

static int igloo_handler(struct kretprobe_instance *ri, struct pt_regs *regs, bool is_enter){
    if (!igloo_do_hc) {
		return 0;
	}
    struct syscall args;
    struct syscall original_info;
    fill_syscall(current, regs, &args);

    memcpy(&original_info, &args, sizeof(struct syscall));
	igloo_hypercall(is_enter ? IGLOO_HYP_SYSCALL_ENTER: IGLOO_HYP_SYSCALL_RETURN, (unsigned long) &args);

    if (args.retval != original_info.retval){
        printk(KERN_EMERG "IGLOO: Setting retval to %lu\n",args.retval);
        syscall_set_return_value(current, regs, args.retval, 0);
    }
    for (int i=0; i<MAX_ARGS; i++){
        if (args.args[i] != original_info.args[i]){
            printk(KERN_EMERG "IGLOO: Setting argument %d to %lu\n", i, args.args[i]);
            syscall_set_argument(current, regs, i, args.args[i]);
        }
    }

    
    return args.skip_syscall ? 1 : 0; // Return 1 to skip the syscall execution if needed
}

// Entry handler for system calls
static int syscall_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    return igloo_handler(ri, regs, true);
}

// Return handler for system calls
static int syscall_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
    return igloo_handler(ri, regs, false);
}

// Helper function to register kretprobe with different syscall naming conventions
static int try_register_syscall_kretprobe(struct kretprobe *krp, const char *syscall_name) {
    int ret;
    char buffer[256];
    
    // Try the original name first (often fails)
    krp->kp.symbol_name = syscall_name;
    ret = register_kretprobe(krp);
    if (ret >= 0) {
        return ret;
    }else{
        printk(KERN_ERR "Failed to register kretprobe for %s: %d\n", krp->kp.symbol_name, ret);
        printk(KERN_ERR "kallsyms %s %llx", krp->kp.symbol_name, kallsyms_lookup_name(krp->kp.symbol_name));
    }
    
    // Try with __x64_sys_ prefix (common in x86_64)
    snprintf(buffer, sizeof(buffer), "__x64_%s", syscall_name);
    krp->kp.symbol_name = buffer;
    ret = register_kretprobe(krp);
    if (ret >= 0) {
        return ret;
    }else{
        printk(KERN_ERR "Failed to register kretprobe for %s: %d\n", krp->kp.symbol_name, ret);
        printk(KERN_ERR "kallsyms %s %llx", krp->kp.symbol_name, kallsyms_lookup_name(krp->kp.symbol_name));
    }
    
    // Try with __se_sys_ prefix
    snprintf(buffer, sizeof(buffer), "__se_%s", syscall_name);
    krp->kp.symbol_name = buffer;
    ret = register_kretprobe(krp);
    if (ret >= 0) {
        return ret;
    }else{
        printk(KERN_ERR "Failed to register kretprobe for %s: %d\n", krp->kp.symbol_name, ret);
        printk(KERN_ERR "kallsyms %s %llx", krp->kp.symbol_name, kallsyms_lookup_name(krp->kp.symbol_name));
    }
    
    // Try with __ia32_sys_ prefix (for 32-bit compat syscalls)
    snprintf(buffer, sizeof(buffer), "__ia32_%s", syscall_name);
    krp->kp.symbol_name = buffer;
    ret = register_kretprobe(krp);
    if (ret >= 0) {
        return ret;
    }else{
        printk(KERN_ERR "Failed to register kretprobe for %s: %d\n", krp->kp.symbol_name, ret);
        printk(KERN_ERR "kallsyms %s %llx", krp->kp.symbol_name, kallsyms_lookup_name(krp->kp.symbol_name));
    }
    
    return ret;
}

int syscalls_hc_init(void) {
    if (!igloo_do_hc) {
	    printk(KERN_ERR "IGLOO: Hypercalls disabled\n");
	    // return 0;
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
    for (; p < end; p++, i++) {
        struct syscall_metadata *meta = *p;
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
        // printk(KERN_ERR "IGLOO: %s\n", buffer);
	    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
        
        // Set up kretprobe for this syscall
        struct kretprobe *krp = &syscall_kretprobes[i];
        
        krp->handler = syscall_ret_handler;
        krp->entry_handler = syscall_entry_handler;
        krp->data_size = 0; //sizeof(struct syscall);
        krp->maxactive = 32;  // Max number of concurrent instances
        krp->kp.offset = 0;

        // Register the kretprobe with different possible naming conventions
        int ret = try_register_syscall_kretprobe(krp, meta->name);
        if (ret < 0) {
            printk(KERN_ERR "IGLOO: Failed to register kretprobe for %s: %d\n", 
                  meta->name, ret);
        }
    }
    
    kfree(buffer);
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, 0);
    return 0;
}
