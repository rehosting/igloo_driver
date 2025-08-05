#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "syscalls_hc.h"

// Import functions and variables from syscalls_hc.c
extern struct hlist_head syscall_hook_table[1024];
extern struct hlist_head syscall_name_table[1024];
extern struct hlist_head syscall_all_hooks;
extern spinlock_t syscall_hook_lock;

// Using normalize_syscall_name and syscall_name_hash from syscalls_hc.h

// Using direct pointer addressing instead of ID lookup

// Handler for registering a new syscall hook
void handle_op_register_syscall_hook(portal_region *mem_region)
{
    struct syscall_hook *hook;
    struct kernel_syscall_hook *kernel_hook;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_REGISTER_SYSCALL_HOOK\n");
    
    // Map the data buffer to our hook structure
    hook = (struct syscall_hook *)PORTAL_DATA(mem_region);
    
    // Allocate a new kernel hook structure
    kernel_hook = kzalloc(sizeof(*kernel_hook), GFP_KERNEL);
    if (!kernel_hook) {
        igloo_pr_debug("igloo: Failed to allocate kernel_hook structure\n");
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    // Copy the hook configuration
    memcpy(&kernel_hook->hook, hook, sizeof(struct syscall_hook));
    kernel_hook->in_use = true;
    // Cache the normalized syscall name for fast matching
    if (kernel_hook->hook.name[0] != '\0') {
        strncpy(kernel_hook->normalized_name,
                normalize_syscall_name(kernel_hook->hook.name),
                SYSCALL_NAME_MAX_LEN - 1);
        kernel_hook->normalized_name[SYSCALL_NAME_MAX_LEN - 1] = '\0';
    } else {
        kernel_hook->normalized_name[0] = '\0';
    }
    
    // Add to the main hook table indexed by pointer address
    spin_lock(&syscall_hook_lock);
    hash_add_rcu(syscall_hook_table, &kernel_hook->hlist, (unsigned long)kernel_hook);
    
    // Also add to name-based hash table for faster lookups
    if (kernel_hook->hook.on_all) {
        // Special case for hooks that want all syscalls
        hlist_add_head_rcu(&kernel_hook->name_hlist, &syscall_all_hooks);
    } else if (kernel_hook->hook.name[0] != '\0') {
        // Add to hash table based on syscall name
        u32 name_hash = syscall_name_hash(kernel_hook->hook.name);
        hash_add_rcu(syscall_name_table, &kernel_hook->name_hlist, name_hash);
    }
    
    spin_unlock(&syscall_hook_lock);
    
    // Return the hook's memory address in the size field
    mem_region->header.size = (unsigned long)kernel_hook;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}