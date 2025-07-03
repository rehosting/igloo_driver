#include "portal_internal.h"
#include <linux/wait.h>
#include <linux/sched.h>

long do_snapshot_and_coredump(void);

static DEFINE_PER_CPU(uint32_t, hypercall_num);

uint64_t portal_interrupt = 0;

// Operation handler table
static const portal_op_handler op_handlers[] = {
    [HYPER_OP_READ]            = handle_op_read,
    [HYPER_OP_WRITE]           = handle_op_write,
    [HYPER_OP_READ_STR]        = handle_op_read_str,
    [HYPER_OP_DUMP]            = handle_op_dump,
    [HYPER_OP_EXEC]            = handle_op_exec,
    [HYPER_OP_OSI_PROC]        = handle_op_osi_proc,
    [HYPER_OP_OSI_PROC_HANDLES]= handle_op_osi_proc_handles,
    [HYPER_OP_OSI_MAPPINGS]    = handle_op_osi_mappings,
    [HYPER_OP_OSI_PROC_MEM]    = handle_op_osi_proc_mem,
    [HYPER_OP_READ_PROCARGS]   = handle_op_read_procargs,
    [HYPER_OP_READ_PROCENV]    = handle_op_read_procenv,
    [HYPER_OP_READ_FDS]        = handle_op_read_fds,
    [HYPER_OP_READ_FILE]       = handle_op_read_file,
    [HYPER_OP_WRITE_FILE]      = handle_op_write_file,
    [HYPER_OP_REGISTER_UPROBE] = handle_op_register_uprobe,
    [HYPER_OP_UNREGISTER_UPROBE] = handle_op_unregister_uprobe,
    [HYPER_OP_REGISTER_SYSCALL_HOOK] = handle_op_register_syscall_hook,
    [HYPER_OP_UNREGISTER_SYSCALL_HOOK] = handle_op_unregister_syscall_hook,
    [HYPER_OP_FFI_EXEC] = handle_op_ffi_exec,
};

// bool -> was any work done?
static bool handle_post_memregion(portal_region *mem_region){
    int op;
    portal_op_handler handler;
    // Get the operation code
    op = mem_region->header.op;
    if (op == HYPER_OP_NONE) {
	    return false;
    }

    if (op <= HYPER_OP_NONE || op >= HYPER_OP_MAX) {
        igloo_pr_debug( "igloo: Invalid operation code: %d", op);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return false;
    }

    // Check if operation is within valid range
    if (op < 0 || op >= ARRAY_SIZE(op_handlers)) {
        igloo_pr_debug( "igloo: No handler for %d", op);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return false;
    }
    

    // Get the handler for this operation
    handler = op_handlers[op];

    // Execute the handler if it exists
    igloo_pr_debug( "igloo: Handling operation: %d\n", op);
    if (handler) {
        handler(mem_region);
    } else {
        igloo_pr_debug( "igloo: No handler for operation: %d\n", op);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
    }
    igloo_pr_debug( "igloo: Operation %d handled, result: %d\n", op, mem_region->header.op);
    return true;
}

/*
* bool -> should we stop the hypercall loop?
*/
static bool handle_post_memregions(struct cpu_mem_regions *regions){
	int count = regions->hdr.count;  // Use hdr.count instead of count
	int i = 0;
	bool any_responses = false;
	for (i = 0; i < count; i++) {
		portal_region *mem_region =
			(portal_region *)(unsigned long)(
				regions->regions[i].mem_region);
		if (!mem_region) {
			igloo_pr_debug(
			       "igloo: No mem_region found for CPU %d\n",
			       smp_processor_id());
			continue;
		}
		bool responded = handle_post_memregion(mem_region);
        if (responded){
            any_responses = true;
        }
	}
    return any_responses;
}

void check_portal_interrupt(void){
    if (unlikely(portal_interrupt != 0)) {
        // Clear the interrupt flag
        igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, (unsigned long) &portal_interrupt, 0);
    }
}

int igloo_portal(unsigned long num, unsigned long arg1, unsigned long arg2)
{
    unsigned long ret;
    portal_region *region = (portal_region *)get_zeroed_page(GFP_ATOMIC);
    
    // Check if memory allocation failed
    if (!region) {
        pr_err("igloo: Failed to allocate memory for portal region\n");
        return -ENOMEM;
    }
    
    region->header.call_num = this_cpu_inc_return(hypercall_num);
    igloo_pr_debug("igloo-call: portal call: call_num=%d\n", region->header.call_num);

    if (num != IGLOO_HYPER_PORTAL_INTERRUPT){
        check_portal_interrupt();
    }

    for (;;) {
        // Make the hypercall to get the next operation from the hypervisor
        ret = igloo_hypercall3(num, arg1, arg2, (unsigned long) region);
        // if no responses -> break
        if (!handle_post_memregion(region)) {
            break;
        }
    }

    igloo_pr_debug("portal call exit: ret=%lu\n", ret);
    
    // Free the allocated memory before returning
    free_page((unsigned long)region);
    
    return ret;
}


int igloo_portal_init(void)
{
    igloo_hypercall2(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long) PAGE_SIZE - sizeof(region_header), 0);
    igloo_hypercall2(IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT, (unsigned long) &portal_interrupt, 0);
    igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, 1, 0);
    return 0;
}
