/* Pre-3.x vendor-kernel compat for igloo_driver (written for 4.10+).
 * Derived from kernel-lift's igloo-3.4-backport/kl_compat.h, extended for 2.6.36.
 * Force-included FIRST (via -include). It pulls the base headers, then overrides
 * the APIs that changed incompatibly. Include guards on the base headers keep the
 * kernel's own (old) definitions from coming back afterwards. */
#ifndef _KERNEL_LIFT_COMPAT_H
#define _KERNEL_LIFT_COMPAT_H

/* A vendor memory map that no vanilla machine/Kconfig produces (e.g. PAGE_OFFSET
 * 0xa0000000 with PHYS_OFFSET 0x20000000): take it from the build (KL_PAGE_OFFSET,
 * KL_PHYS_OFFSET, stock-binary facts) before any header expands virt_to_phys(). */
#ifdef KL_PAGE_OFFSET
/* 2.6.31's mmdebug.h re-includes the unguarded autoconf.h, which would put the
 * Kconfig value back: take that inclusion first. */
#include <linux/mmdebug.h>
#undef CONFIG_PAGE_OFFSET
#define CONFIG_PAGE_OFFSET KL_PAGE_OFFSET
#endif
#ifdef KL_PHYS_OFFSET
#include <mach/memory.h>
#undef PHYS_OFFSET
#define PHYS_OFFSET UL(KL_PHYS_OFFSET)
#endif

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

/* rcu_dereference_raw (added 2.6.34) */
#ifndef rcu_dereference_raw
#define rcu_dereference_raw(p) rcu_dereference(p)
#endif

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
#ifndef __SPIN_LOCK_INITIALIZER
/* Before 2.6.37 there is no brace-only initialiser, and spin_lock_init() assigns
 * SPIN_LOCK_UNLOCKED (built on __SPIN_LOCK_UNLOCKED), so give both their own. */
#ifdef CONFIG_DEBUG_SPINLOCK
#error "no brace initialiser for a debug spinlock_t on this kernel"
#endif
#define __SPIN_LOCK_INITIALIZER(lockname) \
    { .raw_lock = __RAW_SPIN_LOCK_UNLOCKED, SPIN_DEP_MAP_INIT(lockname) }
#undef SPIN_LOCK_UNLOCKED
#define SPIN_LOCK_UNLOCKED ((spinlock_t)__SPIN_LOCK_INITIALIZER(old_style_spin_init))
#endif
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

/* kvmalloc()/kvfree() (4.12/3.15), strchrnul() and bitmap_zalloc()/bitmap_free()
 * (4.19) for the /proc-backed OSI readers. kvmalloc here is always vmalloc. */
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
static inline void *kl_kvmalloc(size_t size, gfp_t flags) { return vmalloc(size); }
#define kvmalloc kl_kvmalloc
#define kvfree vfree
static inline char *kl_strchrnul(const char *s, int c)
{
    while (*s && *s != (char)c)
        s++;
    return (char *)s;
}
#define strchrnul kl_strchrnul
#define bitmap_zalloc(nbits, flags) \
    ((unsigned long *)kcalloc(BITS_TO_LONGS(nbits), sizeof(unsigned long), (flags)))
#define bitmap_free(p) kfree(p)

/* struct inet_sock members took their inet_ prefix in 2.6.33. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define inet_sport sport
#define inet_saddr saddr
#endif

/* FOLL_FORCE (2.6.32): before 2.6.39 it is only passed to igloo's own
 * get_user_pages()-based access_remote_vm stand-in, which ignores it. */
#include <linux/mm.h>
#ifndef FOLL_FORCE
#define FOLL_FORCE 0x10
#endif

/* strnstr() added 2.6.33 */
#include <linux/string.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static inline char *kl_strnstr(const char *s1, const char *s2, size_t len)
{
    size_t l2 = strlen(s2);

    if (!l2)
        return (char *)s1;
    while (len >= l2) {
        len--;
        if (!memcmp(s1, s2, l2))
            return (char *)s1;
        s1++;
    }
    return NULL;
}
#define strnstr kl_strnstr
#endif

/* kfree_rcu() added 3.0; some vendor 2.6.36 trees backport it, vanilla lacks it.
 * Fall back to waiting out a grace period, which needs a context that may
 * sleep: the callers are unregister paths (a workqueue item and a portal op). */
#include <linux/rcupdate.h>
#ifndef kfree_rcu
#define kfree_rcu(ptr, field) do { synchronize_rcu(); kfree(ptr); } while (0)
#endif

/* task_struct.start_time was a monotonic struct timespec until 3.17 (u64 ns after) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#define KL_TASK_START_NS(t) ((u64)timespec_to_ns(&(t)->start_time))
#else
#define KL_TASK_START_NS(t) ((t)->start_time)
#endif

#endif
