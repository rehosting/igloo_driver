#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/igloo.h>
#include <linux/binfmts.h>
#include "exec_hc.h"
#include "args.h"

DEFINE_MUTEX(execve_mutex);

// copied from exec.c
struct user_arg_ptr {
	#ifdef CONFIG_COMPAT
		bool is_compat;
	#endif
		union {
			const char __user *const __user *native;
	#ifdef CONFIG_COMPAT
			const compat_uptr_t __user *compat;
	#endif
		} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}
// end copied from exec.c

void igloo_exec_succeeded(struct filename *filename, 
	struct user_arg_ptr argv, struct user_arg_ptr envp, struct linux_binprm *bprm);

/**
 * Called from do_execveat_common in fs/exec.c
 */
void igloo_exec_succeeded(struct filename *filename, 
	struct user_arg_ptr argv, struct user_arg_ptr envp, struct linux_binprm *bprm) {
	if (!igloo_do_hc){
		return;
	}
	
	// Check for NULL pointers early
	if (!filename || !filename->name || !bprm) {
		printk(KERN_ERR "igloo_exec_succeeded: NULL pointer detected in critical parameters\n");
		return;
	}
	
	// /* execve succeeded */
	char arg_buf[256];
	int i, retval;
	if (current->flags & PF_KTHREAD) {
		// Kernel thread change
		igloo_hypercall(IGLOO_HYP_KTHREAD_CHANGE, (unsigned long)filename->name);
	} else {
		// Normal thread change
		igloo_hypercall(IGLOO_HYP_THREAD_CHANGE, (unsigned long)filename->name);
		igloo_hypercall(IGLOO_SIGSTOP_KTHREAD, (unsigned long)filename->name);
	}
	
	mutex_lock(&execve_mutex);		//prevents other kernel threads from issuing interleaved sequences of hypercalls
	
	// Process arguments if they exist
	if (bprm->argc > 0) {
		for (i = 0; i < bprm->argc; ++i) {
			const char __user *arg = get_user_arg_ptr(argv, i);
			if (IS_ERR_OR_NULL(arg)) {
				break;
			}
			if (strncpy_from_user(arg_buf, arg, sizeof(arg_buf)) < 0) {
				break;
			}
			//printk(KERN_CRIT "Arg %d: %s\n", i, arg_buf);
			//do a hypercall with each argv buffer and associated index
			igloo_hypercall2(IGLOO_HYP_TASK_ARGV, (unsigned long) arg_buf, i);
			igloo_hypercall2(IGLOO_SIGSTOP_ARGV, (unsigned long) arg_buf, i);
		}
	}
	igloo_hypercall(IGLOO_HYP_TASK_ARGC, bprm->argc);
	
	if ((retval = bprm->envc) < 0) {
		if (igloo_do_hc) {
			//unlock the mutex in case of early exit
			printk(KERN_CRIT "EXITING BEFORE ENVP ENUMERATION\n");
		}
		mutex_unlock(&execve_mutex);
		return;
	}

	// Process environment variables if they exist
	if (bprm->envc > 0) {
		for (i = 0; i < bprm->envc; ++i) {
			const char __user *arg = get_user_arg_ptr(envp, i);
			if (IS_ERR_OR_NULL(arg)) {
				break;
			}
			if (strncpy_from_user(arg_buf, arg, sizeof(arg_buf)) < 0) {
				break;
			}
			//printk(KERN_CRIT "Env %d: %s\n", i, arg_buf);
			igloo_hypercall2(IGLOO_HYP_TASK_ENVV, (unsigned long) arg_buf, i);
		}
	}
	igloo_hypercall(IGLOO_HYP_TASK_ENVC, bprm->envc);
	
	//the creds are set in the call to prepare_binprm above
	if (bprm->cred) {
		//printk(KERN_CRIT "EUID: %u, EGID: %u\n", bprm->cred->euid.val, bprm->cred->egid.val);
		igloo_hypercall(IGLOO_HYP_TASK_EUID, bprm->cred->euid.val);
		igloo_hypercall(IGLOO_HYP_TASK_EGID, bprm->cred->egid.val);
	}

	mutex_unlock(&execve_mutex);

	// Pause process until SIGCONT, if emulator wants to
	bool do_pause = false;
	igloo_hypercall2(IGLOO_SIGSTOP_QUERY, (unsigned long) &do_pause, current->pid);
	if (do_pause) {
		force_sig(SIGSTOP);
	}
}