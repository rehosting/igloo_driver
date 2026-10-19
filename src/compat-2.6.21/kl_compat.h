/* 2.6.21 compat for igloo_driver: the 2.6.36 layer plus what changed between 2.6.21
 * and 2.6.36. Force-included first (IGLOO_COMPAT_DIR=compat-2.6.21); the shim headers
 * under linux/ cover headers that did not exist yet (rculist, path, fdtable, cred).
 * Faithful OSI-minimal only: no struct cred (ids are reported only when the host's
 * offsets trust them), fs_struct holds dentry + vfsmount pairs, d_path takes them. */
#ifndef _KL_COMPAT_2621_H
#define _KL_COMPAT_2621_H

#include <linux/types.h>
/* uintptr_t added to linux/types.h in 2.6.24 */
typedef unsigned long uintptr_t;

#include <linux/compiler.h>
/* ACCESS_ONCE added 2.6.22 (the 2.6.36 layer's READ_ONCE/WRITE_ONCE use it) */
#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

/* Without CONFIG_KALLSYMS (the vendor kernel has none) kallsyms.h defines an inline
 * kallsyms_lookup_name() stub, which the build's -Dkallsyms_lookup_name=kl_ksym_lookup
 * would turn into a second kl_ksym_lookup: take the header first under another name. */
#ifdef kallsyms_lookup_name
#undef kallsyms_lookup_name
#define kallsyms_lookup_name kl_hdr_kallsyms_lookup_name
#include <linux/kallsyms.h>
#undef kallsyms_lookup_name
#define kallsyms_lookup_name kl_ksym_lookup
unsigned long kl_ksym_lookup(const char *name);	/* portal/kl_ksyms.c */
#endif

#include "../compat-2.6.36/kl_compat.h"

#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>

/* path_get/path_put added 2.6.25 */
static inline void kl_path_get(struct path *p) { mntget(p->mnt); dget(p->dentry); }
static inline void kl_path_put(struct path *p) { dput(p->dentry); mntput(p->mnt); }
#define path_get kl_path_get
#define path_put kl_path_put

/* d_path took (dentry, vfsmount) until 2.6.25; igloo passes a struct path */
static inline char *kl_d_path(struct path *p, char *buf, int len)
{
    return d_path(p->dentry, p->mnt, buf, len);
}
#define d_path(p, buf, len) kl_d_path((struct path *)(p), (buf), (len))

/* pr_emerg/pr_err... added 2.6.24 (only pr_info/pr_debug before) */
#include <linux/kernel.h>
#ifndef pr_emerg
#define pr_emerg(fmt, ...) printk(KERN_EMERG fmt, ##__VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...) printk(KERN_ERR fmt, ##__VA_ARGS__)
#endif
#ifndef pr_warn
#define pr_warn(fmt, ...) printk(KERN_WARNING fmt, ##__VA_ARGS__)
#endif

/* hlist_del_init_rcu added 2.6.29 */
static inline void kl_hlist_del_init_rcu(struct hlist_node *n)
{
    if (!hlist_unhashed(n)) {
        __hlist_del(n);
        n->pprev = NULL;
    }
}
#define hlist_del_init_rcu kl_hlist_del_init_rcu

/* kern_path added 2.6.28: path_lookup into a nameidata (dentry/mnt members before 2.6.25) */
static inline int kl_kern_path(const char *name, unsigned int flags, struct path *out)
{
    struct nameidata nd;
    int err = path_lookup(name, flags, &nd);

    if (!err) {
        out->dentry = nd.dentry;
        out->mnt = nd.mnt;
    }
    return err;
}
#define kern_path kl_kern_path

/* ktime_get is not exported before 2.6.22(ish); ktime_get_ts (the same monotonic clock) is */
#include <linux/time.h>
#include <linux/hrtimer.h>
static inline u64 kl_ktime_get_ns(void)
{
    struct timespec ts;

    ktime_get_ts(&ts);
    return (u64)timespec_to_ns(&ts);
}
#undef ktime_get_ns
#define ktime_get_ns() kl_ktime_get_ns()

#endif
