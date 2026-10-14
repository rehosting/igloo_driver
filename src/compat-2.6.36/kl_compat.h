/* Pre-3.x vendor-kernel compat for igloo_driver (written for 4.10+).
 * Derived from kernel-lift's igloo-3.4-backport/kl_compat.h, extended for 2.6.36.
 * Force-included FIRST (via -include). It pulls the base headers, then overrides
 * the APIs that changed incompatibly. Include guards on the base headers keep the
 * kernel's own (old) definitions from coming back afterwards. */
#ifndef _KERNEL_LIFT_COMPAT_H
#define _KERNEL_LIFT_COMPAT_H
#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/kallsyms.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/module.h>

/* hlist_entry_safe (added 3.9) */
#ifndef hlist_entry_safe
#define hlist_entry_safe(ptr, type, member) \
    ({ typeof(ptr) ____ptr = (ptr); \
       ____ptr ? hlist_entry(____ptr, type, member) : NULL; })
#endif

/* hlist_for_each_entry* changed from 4-arg (<=3.8) to 3-arg (>=3.9). igloo uses
 * the 3-arg form; redefine over the old internals. */
#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member) \
    for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member); \
         pos; pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member) \
    for (pos = hlist_entry_safe(rcu_dereference_raw((head)->first), \
                                typeof(*(pos)), member); \
         pos; \
         pos = hlist_entry_safe(rcu_dereference_raw((pos)->member.next), \
                                typeof(*(pos)), member))
#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member) \
    for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member); \
         pos && ({ n = pos->member.next; 1; }); \
         pos = hlist_entry_safe(n, typeof(*(pos)), member))

/* full_name_hash gained a salt arg in 4.8 (2-arg -> 3-arg). */
#define full_name_hash(salt, name, len) full_name_hash((name), (len))

/* ktime_get_ns() added 3.17 */
#ifndef ktime_get_ns
#define ktime_get_ns() ktime_to_ns(ktime_get())
#endif

/* MODULE_SOFTDEP added 3.7 */
#ifndef MODULE_SOFTDEP
#define MODULE_SOFTDEP(x)
#endif

/* file_inode() added 3.9 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define file_inode(f) ((f)->f_path.dentry->d_inode)
#endif

/* READ_ONCE/WRITE_ONCE added 3.19 (ACCESS_ONCE before) */
#ifndef READ_ONCE
#define READ_ONCE(x) ACCESS_ONCE(x)
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) (ACCESS_ONCE(x) = (val))
#endif

/* -std=gnu99 (needed for the sources' C99 loops) turns the kernel's
 * compound-literal lock initialisers into non-constant expressions, which breaks
 * every static DEFINE_SPINLOCK/DEFINE_MUTEX/wait-queue head. Use the plain brace
 * initialiser instead; spin_lock_init() goes through the raw variant and is
 * unaffected. */
#include <linux/spinlock.h>
#undef __SPIN_LOCK_UNLOCKED
#define __SPIN_LOCK_UNLOCKED(lockname) __SPIN_LOCK_INITIALIZER(lockname)
#undef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = __SPIN_LOCK_INITIALIZER(x)

/* kmalloc_array() added 3.4 */
#include <linux/slab.h>
#ifndef kmalloc_array
static inline void *kl_kmalloc_array(size_t n, size_t size, gfp_t flags)
{
    if (size != 0 && n > ULONG_MAX / size)
        return NULL;
    return kmalloc(n * size, flags);
}
#define kmalloc_array kl_kmalloc_array
#endif

/* task_struct.start_time was a monotonic struct timespec until 3.17 (u64 ns after) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#define KL_TASK_START_NS(t) ((u64)timespec_to_ns(&(t)->start_time))
#else
#define KL_TASK_START_NS(t) ((t)->start_time)
#endif

#endif
