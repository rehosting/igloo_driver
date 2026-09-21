#ifndef __PORTAL_PROCFS_H__
#define __PORTAL_PROCFS_H__

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#include <linux/refcount.h>
#endif
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/version.h>


#if LINUX_VERSION_CODE == KERNEL_VERSION(6,13,0)
struct proc_dir_entry {
	/*
	 * number of callers into module in progress;
	 * negative -> it's going away RSN
	 */
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	/* protects ->pde_openers and all struct pde_opener instances */
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[];
} __randomize_layout;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
/*
 * 5.6-era layout (matches linux-5.6.3 fs/proc/internal.h). Same as the 6.13
 * layout below EXCEPT there is no `u8 flags` field (added in 5.8). `proc_ops`
 * landed in 5.6, so the proc_ops/proc_dir_ops union and proc_dops are present.
 * Used for the faithful MikroTik RouterOS 7.21.4 (5.6.3/aarch64) Tier-A rehost;
 * the RB-tree walker in portal_procfs.c reads ->subdir / ->subdir_node here.
 */
struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 namelen;
	char inline_name[];
} __randomize_layout;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,10,0)
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;		/* use count */
	atomic_t in_use;	/* number of callers into module in progress; */
			/* negative -> it's going away RSN */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};
#else
#error Unsupported kernel version
#endif
#endif /* __PORTAL_PROCFS_H__ */