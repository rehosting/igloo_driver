#ifndef __IGLOO_SCOPE_H__
#define __IGLOO_SCOPE_H__

#include <linux/sched.h>
#include <linux/types.h>

/*
 * Analysis scoping.
 *
 * Penguin's own infrastructure (boot machinery, the backgrounded vpnguin/
 * console/guesthopper helpers, and anything spawned via call_usermodehelper)
 * stays in the kernel's initial UTS namespace. At handoff init.sh unshares a
 * fresh UTS namespace for the real guest init, so the firmware-under-analysis
 * process subtree lives outside the initial namespace. Analysis emission is
 * gated on igloo_in_scope() so only the firmware subtree is captured.
 */

/* Capture the initial UTS namespace. Call once at module init (before any
 * unshare), while current is still Penguin's boot context. */
void igloo_scope_init(void);

/* Enable/disable gating. Default disabled, so a driver paired with a Penguin
 * that never enables scoping behaves exactly as before (captures everything). */
void igloo_scope_set_enabled(bool enabled);

/* True if task's analysis events should be emitted. When gating is disabled
 * this is always true. */
bool igloo_in_scope(struct task_struct *task);

#endif /* __IGLOO_SCOPE_H__ */
