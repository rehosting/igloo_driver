#ifndef KL_FAITHFUL_H
#define KL_FAITHFUL_H
// See kl_faithful.c. Pointers to otherwise-unexported kernel helpers, resolved
// via kallsyms at init so igloo.ko loads into an unmodified vendor kernel that
// (unlike penguin's donor kernels) does not EXPORT_SYMBOL them.
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/version.h>

struct kernel_clone_args;
struct kernel_siginfo;
struct pid;

extern int (*kl_access_remote_vm)(struct mm_struct *, unsigned long, void *, int, unsigned int);
extern const char *(*kl_arch_vma_name)(struct vm_area_struct *);
extern int (*kl_kill_pid_info)(int, struct kernel_siginfo *, struct pid *);
extern struct file *(*kl_shmem_kernel_file_setup)(const char *, loff_t, unsigned long);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
extern long (*kl_do_fork)(struct kernel_clone_args *);
#endif

// Resolve all of the above; call once early in igloo init (before OSI runs).
void kl_faithful_resolve(void);

// Recover struct offsets (task_struct.tasks) from live memory and override the
// koff_table, for faithful vendor kernels whose layout differs from ours.
void kl_recover_offsets(void);

#endif /* KL_FAITHFUL_H */
