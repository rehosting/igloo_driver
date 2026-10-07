#include <linux/gfp.h>
#include <linux/mm.h>
#include "portal_internal.h"
#include <linux/wait.h>
#include <linux/sched.h>
#include "portal_op_list.h"
#include "mailbox.h"

/* Points into the mailbox shared page once that is up, so the host can set it by PA. */
static uint64_t portal_interrupt_static;
static uint64_t *portal_interrupt = &portal_interrupt_static;

// Operation handler table
static const portal_op_handler op_handlers[] = {
    [HYPER_OP_NONE] = NULL,
#define X(lower, upper) [HYPER_OP_##upper] = handle_op_##lower,
    PORTAL_OP_LIST
#undef X
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
    if (unlikely(READ_ONCE(*portal_interrupt) != 0)) {
        // Clear the interrupt flag
        igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, (unsigned long) portal_interrupt, 0);
    }
}

static inline unsigned long portal_hypercall(unsigned long num, unsigned long arg1,
                                             unsigned long arg2, portal_region *region,
                                             unsigned long event_pa, unsigned long event_len)
{
    /* The mailbox carries the same four values the registers do, plus the region's PA. */
    if (igloo_mb_enabled())
        return igloo_mb_call(num, arg1, arg2, (unsigned long) region, region->header.op,
                             (unsigned long) virt_to_phys(region), event_pa, event_len,
                             NULL, 0);
    return igloo_hypercall4(num, arg1, arg2, (unsigned long) region, region->header.op);
}

int igloo_portal(unsigned long num, unsigned long arg1, unsigned long arg2)
{
    return igloo_portal_ev(num, arg1, arg2, NULL, 0);
}

/*
 * igloo_portal(), plus a linear-map buffer the host may read and write by
 * physical address on every round trip of this call (mailbox mode only).
 */
int igloo_portal_ev(unsigned long num, unsigned long arg1, unsigned long arg2,
                    void *event, size_t event_len)
{
    unsigned long event_pa = event ? (unsigned long) virt_to_phys(event) : 0;
    unsigned long ret, page;
    portal_region *region;
    igloo_pr_debug("IGLOO: igloo_portal entry num=%lu arg1=%lx arg2=%lx\n", num, arg1, arg2);
    
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
        ret = portal_hypercall(num, arg1, arg2, region, event_pa, event_len);
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
    igloo_mailbox_init();
    portal_interrupt = igloo_mb_portal_interrupt();
    igloo_hypercall2(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long) PAGE_SIZE - sizeof(region_header), 0);
    igloo_hypercall2(IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT, (unsigned long) portal_interrupt, 0);
    igloo_portal(IGLOO_HYPER_PORTAL_INTERRUPT, 1, 0);
    return 0;
}
