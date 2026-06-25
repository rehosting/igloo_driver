#include "portal_internal.h"
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include "scope.h"

static bool igloo_scope_enabled;
static struct uts_namespace *igloo_initial_uts_ns;

void igloo_scope_init(void)
{
    /*
     * Module init runs at boot / preinit, before init.sh unshares anything,
     * so current's UTS namespace here is the initial namespace shared by all
     * Penguin infrastructure. Capturing the pointer avoids depending on the
     * init_uts_ns symbol being exported to modules.
     */
    igloo_initial_uts_ns = current->nsproxy ? current->nsproxy->uts_ns : NULL;
}

void igloo_scope_set_enabled(bool enabled)
{
    WRITE_ONCE(igloo_scope_enabled, enabled);
}
EXPORT_SYMBOL(igloo_scope_set_enabled);

bool igloo_in_scope(struct task_struct *task)
{
    struct nsproxy *ns;

    if (!READ_ONCE(igloo_scope_enabled))
        return true;
    if (!task)
        return false;
    ns = task->nsproxy;
    if (!ns)
        return false;
    return ns->uts_ns != igloo_initial_uts_ns;
}
EXPORT_SYMBOL(igloo_in_scope);

void handle_op_set_scope_enabled(portal_region *mem_region)
{
    igloo_scope_set_enabled(mem_region->header.addr != 0);
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}
