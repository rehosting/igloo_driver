#include "portal_internal.h"

long do_snapshot_and_coredump(void);

static DEFINE_PER_CPU(struct cpu_mem_regions, cpu_regions);
static DEFINE_PER_CPU(int, hypercall_num);

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
    [HYPER_OP_FFI_EXEC] = handle_op_ffi_exec,
};

// Helper function to initialize memory regions for current CPU
static bool allocate_new_mem_region(struct cpu_mem_regions *regions)
{
    portal_region *mem_region = NULL;
    int current_count;

    // Allocate a page-aligned memory region
    mem_region = (portal_region *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
    if (mem_region == NULL) {
        pr_err("igloo: Failed to allocate page-aligned mem_region\n");
	    return false;
    }
    current_count = regions->hdr.count;  // Use hdr.count instead of count

    // Add to our array and increment count
    regions->regions[current_count].mem_region = mem_region;
    regions->regions[current_count].owner_id = 0;
    regions->hdr.count = (current_count + 1);  // Use hdr.count instead of count

    // Register with hypervisor
    igloo_pr_debug("igloo: Registered new mem_region %p for CPU %d (page-aligned, idx: %lld)\n", 
                  mem_region, smp_processor_id(), (long long)(regions->hdr.count) - 1);  // Use hdr.count
    return true;
}

// Helper function to initialize memory regions for current CPU
static void initialize_cpu_regions(struct cpu_mem_regions *regions)
{
    int i;
    
    // Allocate the default number of memory regions
    for (i = 0; i < DEFAULT_MEM_REGIONS; i++) {
        if (!allocate_new_mem_region(regions)) {
            pr_err("igloo: Failed to allocate memory region %d during initialization\n", i);
            return;
        }
    }
    igloo_hypercall2(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long)regions, (unsigned long) PAGE_SIZE - sizeof(region_header));
    
    pr_info("igloo: Initialized %d memory regions for CPU %d\n", 
           DEFAULT_MEM_REGIONS, smp_processor_id());
}


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

int igloo_portal(unsigned long num, unsigned long arg1, unsigned long arg2)
{
	unsigned long ret;
	struct cpu_mem_regions *regions = this_cpu_ptr(&cpu_regions);
	int i;

	int call_num = this_cpu_inc_return(hypercall_num);
	igloo_pr_debug( "igloo-call: portal call: call_num=%d\n", call_num);

	// Initialize regions if this is the first call on this CPU
	if (regions->hdr.count == 0) {  // Use hdr.count instead of count
		initialize_cpu_regions(regions);
    }

	regions->hdr.call_num = call_num;  // Use hdr.call_num instead of call_num

	// reset all memory regions to default values
	for (i = 0; i < regions->hdr.count; i++) {  // Use hdr.count instead of count
		portal_region *mem_region =
			(portal_region *)(unsigned long)(
				regions->regions[i].mem_region);
		mem_region->header.op = 0;
		mem_region->header.addr = 0;
		mem_region->header.size = 0;
		regions->regions[i].owner_id = 0;
	}
	int j = 0;
	for (;;) {
		// Make the hypercall to get the next operation from the hypervisor
		ret = igloo_hypercall2(num, arg1, arg2);
		j++;
		igloo_pr_debug("igloo: portal call loop %d\n", j);
		// if no responses -> break
		if (!handle_post_memregions(regions)) {
			break;
		}
	}

	igloo_pr_debug("portal call exit: ret=%lu\n", ret);
	return ret;
}
