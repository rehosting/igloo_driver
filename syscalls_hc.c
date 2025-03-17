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
#include <trace/syscall.h>
#include "syscalls_hc.h"
#include "args.h"

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

#define MAX_ARGS 6
#define __IGLOO_STR_SIZE 

struct syscall {
	uint64_t nr;
	uint64_t nargs;
	uint64_t argsptrs[6];
	uint64_t args[6];
	uint64_t retptr;
	uint64_t retval;
} __packed;

enum sysret_type {
    RETURN_OK = 0,
    RETURN_SKIP = 1, // skip the syscall on enter 
    RETURN_ZERO = 2, // 
};

#define __IGLOO_LOG_SC(x, name, ...)					\
	do {								\
		int igloo_i = 0;					\
		struct igloo_sysret *igloo_sysret =			\
			kzalloc(sizeof(struct igloo_sysret), GFP_KERNEL);\
		igloo_sysret->nr =					\
			cpu_to_be32(__syscall_meta_##name.syscall_nr);	\
		igloo_sysret->ret = cpu_to_be64(ret);			\
		__MAP(x,__IGLOO_LOG_SC_ARG,__VA_ARGS__);		\
		igloo_hypercall(IGLOO_SYSCALL, (unsigned long)igloo_sysret);\
		kfree(igloo_sysret);					\
	} while (0)

#define __IGLOO_MAYBE_LOG_SC(x, name, ...)				\
	do {								\
		if (__IGLOO_SHOULD_LOG_SC(name)) {			\
			__IGLOO_LOG_SC(x,name,__VA_ARGS__);		\
		}							\
	} while (0)

#ifndef __CHECK_SYSCALLS
#define __CHECK_SYSCALLS
static inline bool check_igloo_syscalls(int syscall_nr){
	int syscalls_to_check[] = {
	#if defined(__NR_open)
		__NR_open,
	#endif
	#if defined(__NR_openat)
		__NR_openat,
	#endif
	#if defined(__NR_ioctl)
		__NR_ioctl,
	#endif
	#if defined(__NR_close)
		__NR_close,
	#endif
	};
	for (int i = 0; i < sizeof(syscalls_to_check)/sizeof(syscalls_to_check[0]); i++){
		if (syscalls_to_check[i] == syscall_nr){
			return true;
		}
	}
	return false;
}
#endif


#define __IGLOO_SHOULD_LOG_SC(name)					\
	(								\
		ret == -ENOENT						\
		 && igloo_do_hc                     \
		 && check_igloo_syscalls(__syscall_meta_##name.syscall_nr)	\


// This needs to be wrapped in `({ ... })` and not `do { ... } while (0)`,
// since for `__MAP()` to work this macro needs to generate an expression
#define __IGLOO_LOG_SC_ARG(t, a)							\
	({										\
		char *igloo_s = igloo_sysret->strings[igloo_i];				\
		struct file *igloo_file = fget(a);					\
		igloo_sysret->args[igloo_i] = cpu_to_be64(a);				\
		if (__builtin_types_compatible_p(t, const char *)) {			\
			strncpy_from_user(igloo_s, (const char *)a, __IGLOO_STR_SIZE);	\
		} else if (__builtin_types_compatible_p(t, int) && igloo_file) {	\
			d_path(&igloo_file->f_path, igloo_s, __IGLOO_STR_SIZE);		\
		}									\
		igloo_i++;								\
	})

#define __IGLOO_STR_SIZE 4096
/**
 * Called from within __SYSCALL_DEFINEx in include/linux/syscalls.h
 * 
 * Returning 0 is passive
 * 
 * Returning 1 skips the syscall and returns the value in ret
 */
long igloo_hc_syscall_enter(char* name, uint64_t nr, int nb_args, uint64_t **args_ptrs, long *ret);
long igloo_hc_syscall_enter(char* name, uint64_t nr, int nb_args, uint64_t **args_ptrs, long* ret){
	if (!igloo_do_hc) {
		return 0;
	}
	long result;
    // printk(KERN_EMERG "IGLOO: Entering syscall %llx\n", nr);

	struct syscall sys;
	// cpu_to_le64 doesn't work
    sys.nr = nr;
    sys.nargs = nb_args;
    sys.retptr = ret;
    sys.retval = *ret;
    for (int i = 0; i < nb_args; i++) {
	    // printk(KERN_EMERG "IGLOO: Arg %d: %llx\n", i, args[i]);
	    sys.args[i] = *args_ptrs[i];
		sys.argsptrs[i] = args_ptrs[i];
    }

    // printk(KERN_EMERG "IGLOO %lx\n", (unsigned long) &sys);
	result = igloo_hypercall2(IGLOO_HYP_SYSCALL_ENTER, (unsigned long) &sys, 0);
	if (result == RETURN_SKIP){
		printk(KERN_EMERG "skipping syscall and returning %llx", *ret);
		return 1;
	}
	return 0;
}

/**
 * Called from within __SYSCALL_DEFINEx in include/linux/syscalls.h
 * 
 * Returning 0 is passive
 * 
 * Returning 1 replaces the syscall return value with the value in ret
 */
long igloo_hc_syscall_return(char* name, uint64_t nr, int nb_args, uint64_t **args_ptrs, long *ret);
long igloo_hc_syscall_return(char* name, uint64_t nr, int nb_args, uint64_t **args_ptrs, long *ret){
	if (!igloo_do_hc) {
		return 0;
	}
	long result;
    // printk(KERN_EMERG "IGLOO: Returning syscall %llx\n", nr);

	struct syscall sys;
	// cpu_to_le64 doesn't work
    sys.nr = nr;
    sys.nargs = nb_args;
    sys.retptr = ret;
    sys.retval = *ret;
    for (int i = 0; i < nb_args; i++) {
	    // printk(KERN_EMERG "IGLOO: Arg %d: %llx\n", i, args[i]);
	    sys.args[i] = *args_ptrs[i];
		sys.argsptrs[i] = args_ptrs[i];
    }
    // printk(KERN_EMERG "IGLOO %lx\n", (unsigned long) &sys);
	result = igloo_hypercall2(IGLOO_HYP_SYSCALL_RETURN, (unsigned long) &sys, 0);
	if (result == RETURN_SKIP){
		// printk(KERN_EMERG "skipping syscall and returning %llx", *ret);
		return 1;
	}
	return 0;
}

int syscalls_hc_init(void) {
    if (!igloo_do_hc) {
	    printk(KERN_ERR "IGLOO: Hypercalls disabled\n");
	    // return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    for (; p < end; p++) {
        struct syscall_metadata *meta = *p;
	    int x = snprintf(buffer, PAGE_SIZE,
			     "{\"syscall_nr\": %d, \"name\": \"%s\", \"args\":[",
			     meta->syscall_nr, meta->name);

        for (int j = 0; j < meta->nb_args && x < PAGE_SIZE; j++) {
            // end the args array with a closing bracket
            x += snprintf(buffer+x, PAGE_SIZE-x, "[\"%s\", \"%s\"]%s", meta->types[j], meta->args[j], j+1 < meta->nb_args ? ", " : "]}");
        }

        if (meta->nb_args == 0){
            x += snprintf(buffer+x, PAGE_SIZE-x, "]}");
        }
        // printk(KERN_ERR "IGLOO: %s\n", buffer);
	    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
    }
	kfree(buffer);
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, 0);
    return 0;
}
