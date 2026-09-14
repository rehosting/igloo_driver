#ifndef __IGLOO_FUZZPIN_H__
#define __IGLOO_FUZZPIN_H__

#include <linux/sched.h>
#include <linux/types.h>

/*
 * Fuzzing process pin.
 *
 * A syscall hook can be filtered by `comm`, and a comm is a NAME, not an
 * identity. lighttpd forks workers that all carry it; a victim that dies and
 * is restarted comes back with the same name and a different pid. A fuzzing
 * loop that arms in one process and then closes its laps on another process's
 * syscalls is not measuring iterations of anything -- it is measuring the
 * interval between two unrelated processes, and it reports that as a rate.
 *
 * The pin makes the kernel stick to one process subtree: the task pinned by
 * the host, plus its descendants, and nothing else.
 *
 * WHY IT IS SET IMMEDIATELY BEFORE THE SNAPSHOT. The pin lives in driver
 * memory, which is guest RAM, so it is captured by the snapshot along with
 * everything else and restored byte-identically on every reset. Set before
 * the snapshot it is part of the armed state: every replayed lap begins with
 * the same pin, it never has to be re-applied per lap, and it cannot drift out
 * of step with the guest it is describing. Set AFTER the snapshot it would be
 * rewound away by the first reset.
 *
 * WHY struct pid AND NOT pid_t. Pids are reused. Holding a reference to the
 * `struct pid` makes the comparison identity-based: a recycled number resolves
 * to a different struct and does not match, so a restarted victim is correctly
 * seen as a different process rather than silently inherited.
 *
 * WHY A PARENT WALK AND NOT A TAG. Marking descendants at fork would be O(1)
 * to test but needs a fork hook and a place to keep the mark; task_struct has
 * no field to spare and adding one means patching the kernel. Guest process
 * trees are shallow, so walking real_parent is cheap, needs no kernel change,
 * and is correct for a subtree that is forking while being walked.
 */

/* Flag bits for the SET_FUZZ_PIN portal op's `size` field. */
#define IGLOO_FUZZ_PIN_F_CHILDREN   (1u << 0)   /* follow descendants */
#define IGLOO_FUZZ_PIN_F_EXCLUSIVE  (1u << 1)   /* stop every other userspace task */

/* Pin to `pid`, verifying it against `start_time` (0 skips the check).
 * Returns 0 on success, -ESRCH if no such live task, -EINVAL on identity
 * mismatch -- a stale pid from the host is refused rather than silently
 * pinning whatever now holds that number. */
int igloo_fuzz_pin_set(pid_t pid, u64 start_time, bool include_children);

/* Drop the pin. Every hook goes back to firing for every task. */
void igloo_fuzz_pin_clear(void);

/* True if this task's hooks should fire. Always true when nothing is pinned,
 * so a driver paired with a Penguin that never pins behaves as before. */
bool igloo_in_fuzz_pin(struct task_struct *task);

/* Whether a pin is currently in force. */
bool igloo_fuzz_pin_active(void);

/*
 * EXCLUSIVE MODE -- take the CPU away from everything else.
 *
 * The pin above only decides which tasks a HOOK fires for. The other
 * processes still run: they still get scheduled inside a lap, still dirty
 * pages the reset must then restore, and still spend the lap's wall clock. A
 * span replayed with a different set of other-process wakeups interleaved is
 * not the same span, and no amount of filtering on the reporting side changes
 * that.
 *
 * Exclusive mode stops every userspace task outside the pinned subtree, so the
 * only thing left runnable on the vCPU is the victim, its children, and kernel
 * threads. SIGSTOP is the mechanism: it needs no exported scheduler internals,
 * works identically on 4.10 and 6.13, is exactly reversible with SIGCONT, and
 * leaves the stopped state in the task_struct -- which is guest RAM, so it is
 * captured by the snapshot and restored with it. Frozen before the snapshot,
 * every replayed lap begins with the same tasks stopped.
 *
 * WHAT IS NOT STOPPED, and why. Kernel threads: stopping them starves RCU,
 * the softirq workers and the portal itself, and the guest wedges within
 * seconds. init (pid 1): it reaps, and a guest whose reaper is stopped
 * accumulates zombies for the rest of the run. Both are deliberate holes --
 * exclusive mode is "nothing else in USERSPACE runs", not "nothing else runs".
 *
 * TWO COSTS, both real. SIGSTOP is observable: a parent in waitpid() sees
 * WIFSTOPPED, so a guest that supervises its children can notice. And it is
 * asynchronous -- a task stops at its next signal check, not at the call. Use
 * igloo_fuzz_pin_settled() to wait for it to actually take effect; arming a
 * snapshot before it has is the bug this function exists to make avoidable.
 *
 * NOT IMPLEMENTED, deliberately: raising the victim to SCHED_FIFO instead.
 * That only guarantees it preempts others when it is RUNNABLE -- the moment it
 * blocks in read(), everything else runs again, which is precisely the window
 * that makes a lap non-deterministic. It is the weaker answer to the question.
 */
int igloo_fuzz_pin_exclusive(bool on);

/* How the freeze is progressing: how many tasks were signalled, and how many
 * have not yet reached a stopped state. Poll until `pending` is 0 before
 * arming a snapshot. */
void igloo_fuzz_pin_settled(u64 *signalled, u64 *pending, bool *overflow);

/* Observability, so a run that pinned the wrong thing is diagnosable rather
 * than merely quiet: hits/misses since the pin, whether the pinned task is
 * still alive, and how many walks hit the depth bound (a non-zero value means
 * the bound is too low and descendants are being missed). */
void igloo_fuzz_pin_stats(u64 *in, u64 *out, u64 *truncated, bool *alive);

/* Returned by HYPER_OP_GET_FUZZ_PIN_STATS in the portal data area. Read by
 * the host through DWARF like every other portal struct, so adding a field
 * here needs no host-side layout change. */
struct igloo_fuzz_pin_report {
    u64 hits_in;            /* hook firings inside the pinned subtree */
    u64 hits_out;           /* firings suppressed because they were outside */
    u64 walk_truncated;     /* parent walks that hit the depth bound: if this
                             * is non-zero the bound is too low and real
                             * descendants are being treated as outsiders */
    u64 frozen_signalled;   /* tasks sent SIGSTOP by exclusive mode */
    u64 frozen_pending;     /* of those, not yet actually stopped */
    u64 pinned_pid;
    u64 pinned_start_time;
    u8  active;             /* a pin is in force */
    u8  pinned_alive;       /* the pinned task still exists */
    u8  frozen_overflow;    /* more tasks to stop than the table holds, so
                             * some were left running -- reported rather than
                             * dropped, because an unstopped task still runs
                             * inside the lap */
    u8  exclusive;          /* exclusive mode is engaged */
    u8  pad[4];
};

#endif /* __IGLOO_FUZZPIN_H__ */
