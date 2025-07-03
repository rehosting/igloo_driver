#include "portal_internal.h"
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "../syscalls_hc.h"

// Define maximum number of hooks we'll support
#define MAX_SYSCALL_HOOKS 1024

// Direct array lookup function prototype
struct kernel_syscall_hook *find_hook_by_id(u32 id);

// Pre-allocated array of hooks for quick lookup by ID
static struct kernel_syscall_hook syscall_hooks[MAX_SYSCALL_HOOKS];

// Find a hook by ID - now simply retrieves from the array if ID is valid
struct kernel_syscall_hook *find_hook_by_id(u32 id)
{
    // ID is the array index - bounds check and check if in use
    if (id < MAX_SYSCALL_HOOKS && syscall_hooks[id].in_use) {
        return &syscall_hooks[id];
    }
    
    return NULL;
}

// Find an available hook slot and return its index
static int get_free_hook_index(void)
{
    int i;
    
    spin_lock(&syscall_hook_lock);
    for (i = 0; i < MAX_SYSCALL_HOOKS; i++) {
        if (!syscall_hooks[i].in_use) {
            syscall_hooks[i].in_use = true;
            spin_unlock(&syscall_hook_lock);
            return i;
        }
    }
    spin_unlock(&syscall_hook_lock);
    
    return -1;  // No free hooks
}

// Handler for registering a new syscall hook
void handle_op_register_syscall_hook(portal_region *mem_region)
{
    struct syscall_hook *hook;
    int hook_id;
    struct kernel_syscall_hook *kernel_hook;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_REGISTER_SYSCALL_HOOK\n");
    
    // Map the data buffer to our hook structure
    hook = (struct syscall_hook *)PORTAL_DATA(mem_region);
    
    // Get a free slot index for the hook
    hook_id = get_free_hook_index();
    if (hook_id < 0) {
        igloo_pr_debug("igloo: Failed to register syscall hook - no free slots\n");
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    // Get the kernel hook at the allocated index
    kernel_hook = &syscall_hooks[hook_id];
    
    // Copy the hook configuration
    memcpy(&kernel_hook->hook, hook, sizeof(struct syscall_hook));
    kernel_hook->hook.id = hook_id;  // ID is now simply the array index
    
    // Add to hash table with the index as key
    spin_lock(&syscall_hook_lock);
    hash_add(syscall_hook_table, &kernel_hook->hlist, hook_id);
    spin_unlock(&syscall_hook_lock);
    
    // Return the hook ID (array index) in the addr field
    mem_region->header.size = hook_id;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}

// Handler for unregistering a syscall hook
void handle_op_unregister_syscall_hook(portal_region *mem_region)
{
    u32 hook_id;
    struct kernel_syscall_hook *hook;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_UNREGISTER_SYSCALL_HOOK\n");
    
    // Get the hook ID from the addr field
    hook_id = mem_region->header.addr;
    
    // Find the hook - now a direct array lookup
    if (hook_id >= MAX_SYSCALL_HOOKS || !syscall_hooks[hook_id].in_use) {
        igloo_pr_debug("igloo: Failed to unregister syscall hook - invalid ID\n");
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    hook = &syscall_hooks[hook_id];
    
    // Remove from hash table
    spin_lock(&syscall_hook_lock);
    hash_del(&hook->hlist);
    hook->in_use = false;
    spin_unlock(&syscall_hook_lock);
    
    mem_region->header.op = HYPER_RESP_READ_NUM;
}