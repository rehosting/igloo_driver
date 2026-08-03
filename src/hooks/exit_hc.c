#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "igloo_hypercall.h"   /* pulls in igloo_hypercall_consts.h (no guard) */
#include "igloo.h"
#include "exit_hc.h"
#include "portal/portal.h"
#include "portal/portal_internal.h"
#include "args.h"

/*
 * do_exit() task-exit hook.
 *
 * A kprobe on do_exit() fires on EVERY task death -- normal exit/exit_group,
 * fatal signals, OOM, kernel-forced -- which the exit/exit_group *syscall*
 * hooks miss (a signal death never issues an exit syscall). This is the
 * authoritative process-exit source for the `processes` model: it replaces the
 * host-side signal-death heuristic (which can't tell a caught SIGSEGV from a
 * fatal one) and gives the real, wait-status-encoded exit code.
 *
 * Gated by an enable flag toggled from the host (register/unregister ops) so it
 * costs nothing unless a plugin opts in -- same shape as signal_hc's hook count.
 */

static struct kprobe exit_kp;
static bool exit_kp_registered;   /* portal ops are serialized, so a plain bool */

static void do_exit_hyp(struct exit_event *event) {
    igloo_portal(IGLOO_HYP_PROC_EXIT, (unsigned long)event, 0);
}

static int exit_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *t = current;
    struct exit_event event;

    /* No enable-flag check: the probe is only installed while enabled (armed on
     * the host register op, removed on unregister), so if we are here it is on.
     * That makes the disabled case cost literally nothing -- no probe, no trap. */

    /* User processes only; kernel threads are not part of the process model.
     * At do_exit() entry the task's mm/flags are still intact (exit_mm runs
     * later inside do_exit), so PF_KTHREAD is reliable here. */
    if (t->flags & PF_KTHREAD)
        return 0;

    /* One event per process: report at thread-group-leader death, matching the
     * leader-only for_each_process walk. exit_group tears down every thread
     * including the leader, so a process death always reaches here via the
     * leader; non-leader thread exits are intentionally not surfaced. */
    if (!thread_group_leader(t))
        return 0;

    memset(&event, 0, sizeof(event));
    event.pid = task_tgid_vnr(t);
    event.tid = task_pid_vnr(t);
    event.create_time = t->start_time;               /* identity: pairs w/ ProcStart */
    event.code = (int64_t)(long)regs_get_argument(regs, 0);  /* do_exit(long code) */
    strncpy(event.comm, t->comm, TASK_COMM_LEN);

    do_exit_hyp(&event);
    return 0;
}

int exit_hc_init(void) {
    /* Nothing to arm at boot: the kprobe is installed lazily on the first host
     * enable() so an un-opted-in run pays zero cost (no probe, no per-exit
     * trap). Prep the probe descriptor only. */
    memset(&exit_kp, 0, sizeof(exit_kp));
    exit_kp.symbol_name = "do_exit";
    exit_kp.pre_handler = exit_pre_handler;
    exit_kp_registered = false;
    return 0;
}

/* Host enable/disable. Lazily arm/disarm the kprobe so the disabled state is
 * free. Portal op handlers run in the (sleepable) portal loop context, so
 * register_kprobe()/unregister_kprobe() are safe to call here. No per-process
 * filtering: the model wants every user-process death. */
void handle_op_register_exit_hook(portal_region *mem_region) {
    int ret = 0;

    if (!exit_kp_registered) {
        ret = register_kprobe(&exit_kp);
        if (ret < 0)
            /* do_exit is NOKPROBE-blacklisted on some kernels; degrade
             * gracefully (no exit events). If this ever bites a target kernel,
             * switch symbol_name to the sched_process_exit tracepoint, which is
             * never blacklisted. */
            printk(KERN_ERR "IGLOO: Failed to register kprobe on do_exit: %d "
                   "(exit events unavailable)\n", ret);
        else {
            exit_kp_registered = true;
            printk(KERN_INFO "IGLOO: Armed exit kprobe on do_exit\n");
        }
    }

    mem_region->header.op = (ret < 0) ? HYPER_RESP_WRITE_FAIL
                                      : HYPER_RESP_WRITE_OK;
}

void handle_op_unregister_exit_hook(portal_region *mem_region) {
    if (exit_kp_registered) {
        unregister_kprobe(&exit_kp);
        exit_kp_registered = false;
    }
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}
