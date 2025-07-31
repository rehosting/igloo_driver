#include <linux/gfp.h>
#include <linux/mm.h>
#include "portal_internal.h"
#include <linux/wait.h>
#include <linux/sched.h>

uint64_t portal_interrupt = 0;

// Operation handler table
static const portal_op_handler op_handlers[] = {
    [HYPER_OP_READ]            = handle_op_read,
    [HYPER_OP_WRITE]           = handle_op_write,
    [HYPER_OP_READ_STR]        = handle_op_read_str,
    [HYPER_OP_READ_PTR_ARRAY]   = handle_op_read_ptr_array,
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
    [HYPER_OP_FFI_EXEC] = handle_op_ffi_exec,
    [HYPER_OP_KALLSYMS_LOOKUP] = handle_op_kallsyms_lookup,
    [HYPER_OP_TRAMP_GENERATE] = handle_op_tramp_generate,
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

void check_portal_interrupt(void){
    if (unlikely(portal_interrupt != 0)) {
        // Clear the interrupt flag
        igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, (unsigned long) &portal_interrupt, 0);
    }
}

int igloo_portal(unsigned long num, unsigned long arg1, unsigned long arg2)
{
    igloo_pr_debug("IGLOO: igloo_portal entry num=%lu arg1=%lx arg2=%lx\n", num, arg1, arg2);
    unsigned long ret, page;
    portal_region *region;
    
    if (num != IGLOO_HYPER_PORTAL_INTERRUPT){
        check_portal_interrupt();
    }

    page = __get_free_page(GFP_KERNEL);
    region = (portal_region *)page;

    // Debug: log allocation
    igloo_pr_debug("igloo: Allocated portal_region at %p in igloo_portal\n", region);

    // Check if memory allocation failed
    if (!region) {
        pr_err("igloo: Failed to allocate memory for portal region\n");
        return -ENOMEM;
    }
    // Zero only the region_header
    memset(&region->header, 0, sizeof(region_header));

    for (;;) {
        // Make the hypercall to get the next operation from the hypervisor
        ret = igloo_hypercall3(num, arg1, arg2, (unsigned long) region);
        // if no responses -> break
        if (!handle_post_memregion(region)) {
            break;
        }
    }

    igloo_pr_debug("portal call exit: ret=%lu\n", ret);
    igloo_pr_debug("IGLOO: igloo_portal exit ret=%lu\n", ret);

    // Free the allocated memory before returning
    igloo_pr_debug("igloo: Freeing portal_region at %p in igloo_portal\n", region);
    free_page(page);

    return ret;
}


int igloo_portal_init(void)
{
    igloo_hypercall2(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long) PAGE_SIZE - sizeof(region_header), 0);
    igloo_hypercall2(IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT, (unsigned long) &portal_interrupt, 0);
    igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, 1, 0);
    return 0;
}
