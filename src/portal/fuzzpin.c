#include "portal_internal.h"
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/version.h>
#include <linux/string.h>
#include "fuzzpin.h"

/* Guest process trees are shallow. The bound exists so a corrupted or
 * cyclic parent chain cannot wedge the syscall hot path; `pin_truncated`
 * counts every walk that reached it, because a bound that is silently too
 * low would drop descendants and look exactly like a quiet fuzzer. */
#define IGLOO_FUZZ_PIN_MAX_DEPTH 64

static DEFINE_SPINLOCK(fuzz_pin_lock);   /* serialises set/clear only */
static struct pid *fuzz_pinned;          /* NULL: no pin, everything fires */
static u64 fuzz_pinned_start_time;
static bool fuzz_pin_children = true;
static u64 fuzz_pin_in, fuzz_pin_out, fuzz_pin_truncated;

bool igloo_fuzz_pin_active(void)
{
    return READ_ONCE(fuzz_pinned) != NULL;
}
EXPORT_SYMBOL(igloo_fuzz_pin_active);

int igloo_fuzz_pin_set(pid_t pid, u64 start_time, bool include_children)
{
    struct pid *p;
    struct task_struct *t;
    unsigned long flags;
    int ret = 0;

    if (pid <= 0) {
        igloo_fuzz_pin_clear();
        return 0;
    }

    p = find_get_pid(pid);
    if (!p)
        return -ESRCH;

    rcu_read_lock();
    t = pid_task(p, PIDTYPE_PID);
    if (!t) {
        ret = -ESRCH;
    } else if (start_time && t->start_time != start_time) {
        /* The host is naming a process that no longer exists and whose number
         * has been handed to something else. Pinning it would be worse than
         * not pinning at all: the loop would look correctly scoped and be
         * following an unrelated task. */
        ret = -EINVAL;
    } else {
        start_time = t->start_time;
    }
    rcu_read_unlock();

    if (ret) {
        put_pid(p);
        return ret;
    }

    spin_lock_irqsave(&fuzz_pin_lock, flags);
    if (fuzz_pinned)
        put_pid(fuzz_pinned);
    fuzz_pinned_start_time = start_time;
    fuzz_pin_children = include_children;
    fuzz_pin_in = fuzz_pin_out = fuzz_pin_truncated = 0;
    /* Published last: until this store lands, igloo_in_fuzz_pin() reports
     * "no pin" and every hook fires, which is the safe direction to be wrong
     * in for the microseconds this takes. */
    WRITE_ONCE(fuzz_pinned, p);
    spin_unlock_irqrestore(&fuzz_pin_lock, flags);
    return 0;
}
EXPORT_SYMBOL(igloo_fuzz_pin_set);

void igloo_fuzz_pin_clear(void)
{
    struct pid *old;
    unsigned long flags;

    /* Order matters. Thaw FIRST: dropping the pin while tasks are still
     * stopped would leave a guest frozen with nothing left that knows which
     * tasks to release, and the only way out would be a reboot. */
    igloo_fuzz_pin_exclusive(false);

    spin_lock_irqsave(&fuzz_pin_lock, flags);
    old = fuzz_pinned;
    WRITE_ONCE(fuzz_pinned, NULL);
    fuzz_pinned_start_time = 0;
    spin_unlock_irqrestore(&fuzz_pin_lock, flags);
    if (old)
        put_pid(old);
}
EXPORT_SYMBOL(igloo_fuzz_pin_clear);

/* The subtree test, with no side effects. Split out because the freeze walk
 * calls it once per process and would otherwise write thousands of misses
 * into the very counters used to judge whether the pin was aimed correctly. */
static bool pin_matches(struct task_struct *task)
{
    struct pid *pinned = READ_ONCE(fuzz_pinned);
    struct task_struct *t;
    bool match = false;
    int depth;

    if (!pinned)
        return true;
    if (!task)
        return false;

    rcu_read_lock();
    for (t = task, depth = 0; t; depth++) {
        if (depth >= IGLOO_FUZZ_PIN_MAX_DEPTH) {
            fuzz_pin_truncated++;
            break;
        }
        if (task_pid(t) == pinned) {
            match = true;
            break;
        }
        if (!READ_ONCE(fuzz_pin_children))
            break;                    /* exact task only */
        if (is_global_init(t))
            break;                    /* the walk cannot usefully go past init */
        t = rcu_dereference(t->real_parent);
        if (t == NULL)
            break;
    }
    rcu_read_unlock();
    return match;
}

bool igloo_in_fuzz_pin(struct task_struct *task)
{
    bool match = pin_matches(task);

    /* Plain increments: these are diagnostics, and the cost of making them
     * exact on the syscall hot path is not worth the precision. */
    if (!READ_ONCE(fuzz_pinned))
        return true;
    if (match)
        fuzz_pin_in++;
    else
        fuzz_pin_out++;
    return match;
}
EXPORT_SYMBOL(igloo_in_fuzz_pin);

/* ---- exclusive mode ------------------------------------------------- */

#define IGLOO_FUZZ_FROZEN_MAX 1024

static struct pid *frozen[IGLOO_FUZZ_FROZEN_MAX];
static int n_frozen;
static bool frozen_overflow;

static bool task_is_stopped_now(struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    unsigned int st = READ_ONCE(t->__state);
#else
    long st = READ_ONCE(t->state);
#endif
    return (st & __TASK_STOPPED) != 0;
}

/* Stop every userspace task outside the pin. Kernel threads and init are
 * exempt -- see the header for why both holes are deliberate. */
static int fuzz_freeze_others(void)
{
    struct task_struct *t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    struct kernel_siginfo info;
#else
    struct siginfo info;
#endif

    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSTOP;
    info.si_code = SI_KERNEL;

    n_frozen = 0;
    frozen_overflow = false;

    /* RCU, not tasklist_lock: the latter is not exported to modules, and
     * for_each_process is RCU-safe. Matches the existing walks in
     * portal_osi.c. Nothing in this loop sleeps -- the signalling is
     * deliberately deferred to after the unlock for exactly that reason. */
    rcu_read_lock();
    for_each_process(t) {
        if (t->flags & PF_KTHREAD)
            continue;
        if (!t->mm)
            continue;               /* no address space: a kernel thread */
        if (is_global_init(t))
            continue;
        if (pin_matches(t))
            continue;
        if (n_frozen >= IGLOO_FUZZ_FROZEN_MAX) {
            /* Recorded rather than silently dropped: an unstopped task is a
             * task that still runs inside the lap, and a run that does not
             * know that would report a determinism it does not have. */
            frozen_overflow = true;
            break;
        }
        frozen[n_frozen++] = get_task_pid(t, PIDTYPE_PID);
    }
    rcu_read_unlock();

    /* Signalling is done outside the tasklist lock: send_sig_info can sleep
     * on some configurations, and the portal op runs in a sleepable context
     * precisely so this is allowed. */
    {
        int i, sent = 0;
        for (i = 0; i < n_frozen; i++) {
            rcu_read_lock();
            t = pid_task(frozen[i], PIDTYPE_PID);
            if (t)
                sent++;
            rcu_read_unlock();
            if (t)
                send_sig_info(SIGSTOP, &info, t);
        }
        return sent;
    }
}

static void fuzz_thaw_others(void)
{
    struct task_struct *t;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    struct kernel_siginfo info;
#else
    struct siginfo info;
#endif
    int i;

    memset(&info, 0, sizeof(info));
    info.si_signo = SIGCONT;
    info.si_code = SI_KERNEL;

    for (i = 0; i < n_frozen; i++) {
        if (!frozen[i])
            continue;
        rcu_read_lock();
        t = pid_task(frozen[i], PIDTYPE_PID);
        rcu_read_unlock();
        if (t)
            send_sig_info(SIGCONT, &info, t);
        put_pid(frozen[i]);
        frozen[i] = NULL;
    }
    n_frozen = 0;
    frozen_overflow = false;
}

int igloo_fuzz_pin_exclusive(bool on)
{
    if (on && !igloo_fuzz_pin_active()) {
        /* Without a pin there is no "everything else" to define, and freezing
         * against an empty pin would stop the entire guest. */
        return -EINVAL;
    }
    if (on) {
        if (n_frozen)
            return -EBUSY;          /* already exclusive; thaw first */
        return fuzz_freeze_others();
    }
    fuzz_thaw_others();
    return 0;
}
EXPORT_SYMBOL(igloo_fuzz_pin_exclusive);

void igloo_fuzz_pin_settled(u64 *signalled, u64 *pending, bool *overflow)
{
    struct task_struct *t;
    u64 waiting = 0;
    int i;

    for (i = 0; i < n_frozen; i++) {
        if (!frozen[i])
            continue;
        rcu_read_lock();
        t = pid_task(frozen[i], PIDTYPE_PID);
        /* A task that exited on its way to stopping is not pending: it will
         * never run again either, which is all exclusive mode asked for. */
        if (t && !task_is_stopped_now(t))
            waiting++;
        rcu_read_unlock();
    }
    if (signalled)
        *signalled = (u64)n_frozen;
    if (pending)
        *pending = waiting;
    if (overflow)
        *overflow = frozen_overflow;
}
EXPORT_SYMBOL(igloo_fuzz_pin_settled);

void igloo_fuzz_pin_stats(u64 *in, u64 *out, u64 *truncated, bool *alive)
{
    struct pid *pinned = READ_ONCE(fuzz_pinned);

    if (in)
        *in = fuzz_pin_in;
    if (out)
        *out = fuzz_pin_out;
    if (truncated)
        *truncated = fuzz_pin_truncated;
    if (alive) {
        *alive = false;
        if (pinned) {
            rcu_read_lock();
            *alive = pid_task(pinned, PIDTYPE_PID) != NULL;
            rcu_read_unlock();
        }
    }
}
EXPORT_SYMBOL(igloo_fuzz_pin_stats);

/*
 * Portal op.
 *
 *   header.pid   pid to pin; 0 clears the pin
 *   header.addr  start_time of that pid (0 to skip the identity check)
 *   header.size  bit 0: follow descendants (else the exact task only)
 *
 * Writes back:
 *   header.addr  the pinned task's start_time, so the host records the
 *                identity the KERNEL resolved rather than the one it asked
 *                for -- those differ exactly when something is wrong
 *   header.size  0 on success, or a negative errno
 */
void handle_op_set_fuzz_pin(portal_region *mem_region)
{
    pid_t pid = (pid_t)mem_region->header.pid;
    u64 start_time = mem_region->header.addr;
    u64 flags = mem_region->header.size;
    bool children = (flags & IGLOO_FUZZ_PIN_F_CHILDREN) != 0;
    bool exclusive = (flags & IGLOO_FUZZ_PIN_F_EXCLUSIVE) != 0;
    int ret;

    if (pid == 0) {
        /* Clears the pin AND thaws, in that order -- see igloo_fuzz_pin_clear. */
        igloo_fuzz_pin_clear();
        mem_region->header.addr = 0;
        mem_region->header.size = 0;
        mem_region->header.op = HYPER_RESP_WRITE_OK;
        return;
    }

    ret = igloo_fuzz_pin_set(pid, start_time, children);
    if (ret == 0 && exclusive) {
        ret = igloo_fuzz_pin_exclusive(true);
        if (ret < 0) {
            /* Never leave a half-applied intervention behind: a pin without
             * the exclusivity it was asked for would silently measure a guest
             * that still schedules everything else. */
            igloo_fuzz_pin_clear();
        } else {
            ret = 0;
        }
    }
    mem_region->header.size = (u64)(long)ret;
    mem_region->header.addr = (ret == 0) ? fuzz_pinned_start_time : 0;
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}

void handle_op_get_fuzz_pin_stats(portal_region *mem_region)
{
    struct igloo_fuzz_pin_report *r =
        (struct igloo_fuzz_pin_report *)PORTAL_DATA(mem_region);
    struct pid *pinned = READ_ONCE(fuzz_pinned);
    struct task_struct *t;
    bool overflow = false;

    memset(r, 0, sizeof(*r));
    igloo_fuzz_pin_stats(&r->hits_in, &r->hits_out, &r->walk_truncated,
                         (bool *)&r->pinned_alive);
    igloo_fuzz_pin_settled(&r->frozen_signalled, &r->frozen_pending, &overflow);
    r->frozen_overflow = overflow ? 1 : 0;
    r->active = pinned ? 1 : 0;
    r->exclusive = n_frozen ? 1 : 0;
    r->pinned_start_time = fuzz_pinned_start_time;
    if (pinned) {
        rcu_read_lock();
        t = pid_task(pinned, PIDTYPE_PID);
        r->pinned_pid = t ? (u64)task_pid_nr(t) : 0;
        rcu_read_unlock();
    }
    mem_region->header.size = sizeof(*r);
    mem_region->header.op = HYPER_RESP_READ_OK;
}
