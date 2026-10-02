#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include "igloo_debug.h"

struct igloo_debug_config igloo_debug_flags;

/*
 * Patched kernels parse the igloo_debug= boot argument into igloo_debug and
 * export it. Stock kernels have no such symbol, so take it weakly: the module
 * loader resolves a missing weak symbol to NULL instead of refusing the load.
 */
extern struct igloo_debug_config igloo_debug __attribute__((weak));

static bool debug_param_set;

/* Same syntax as the boot argument: "all", "none", or a comma-separated list. */
static int igloo_debug_param_set(const char *val, const struct kernel_param *kp)
{
    char buf[128], *p = buf, *token;

    strscpy(buf, val, sizeof(buf));
    strim(buf);
    memset(&igloo_debug_flags, 0, sizeof(igloo_debug_flags));
    debug_param_set = true;

    while ((token = strsep(&p, ",")) != NULL) {
        if (!strcmp(token, "all"))
            memset(&igloo_debug_flags, 1, sizeof(igloo_debug_flags));
        else if (!strcmp(token, "none") || !token[0])
            continue;
        else if (!strcmp(token, "portal"))
            igloo_debug_flags.portal = true;
        else if (!strcmp(token, "uprobe"))
            igloo_debug_flags.uprobe = true;
        else if (!strcmp(token, "kprobe"))
            igloo_debug_flags.kprobe = true;
        else if (!strcmp(token, "vma"))
            igloo_debug_flags.vma = true;
        else if (!strcmp(token, "syscall"))
            igloo_debug_flags.syscall = true;
        else if (!strcmp(token, "osi"))
            igloo_debug_flags.osi = true;
        else
            pr_emerg("IGLOO: Unknown debug module: %s\n", token);
    }
    return 0;
}

static const struct kernel_param_ops igloo_debug_param_ops = {
    .set = igloo_debug_param_set,
};
module_param_cb(debug, &igloo_debug_param_ops, NULL, 0);
MODULE_PARM_DESC(debug, "all, none, or a comma-separated list of portal,uprobe,kprobe,vma,syscall,osi");

/* The module parameter wins; otherwise inherit the kernel's boot argument. */
void igloo_debug_init(void)
{
    if (!debug_param_set && &igloo_debug)
        igloo_debug_flags = igloo_debug;
}
