#define MAX_PROBES 20
#define MAX_ARGS 7

#if defined(__mips__)
#include <asm/syscall.h>

static inline bool local_mips_syscall_is_indirect(struct task_struct *task,
					    struct pt_regs *regs)
{
	/* O32 ABI syscall() - Either 64-bit with O32 or 32-bit */
	return (IS_ENABLED(CONFIG_32BIT) ||
		test_tsk_thread_flag(task, TIF_32BIT_REGS)) &&
		(regs->regs[2] == __NR_syscall);
}


static inline void mips_set_syscall_arg(unsigned long arg,
	struct task_struct *task, struct pt_regs *regs, unsigned int n)
{
	unsigned long usp __maybe_unused = regs->regs[29];

	switch (n) {
	case 0: case 1: case 2: case 3:
		regs->regs[4 + n] = arg;

		return;

#ifdef CONFIG_32BIT
	case 4: case 5: case 6: case 7:
		put_user(arg, (int *)usp + n);
		return;
#endif

#ifdef CONFIG_64BIT
	case 4: case 5: case 6: case 7:
#ifdef CONFIG_MIPS32_O32
		if (test_tsk_thread_flag(task, TIF_32BIT_REGS))
			put_user(arg, (int *)usp + n);
		else
#endif
			regs->regs[4 + n] = arg;

		return;
#endif

	default:
		BUG();
	}

	unreachable();
}
static inline void syscall_set_argument(struct task_struct *task,
					 struct pt_regs *regs,
                     int i, unsigned long arg)
{
	/* O32 ABI syscall() */
	if (local_mips_syscall_is_indirect(task, regs))
		i++;
    
    mips_set_syscall_arg(arg, task, regs, i);
}

#elif defined(__arm__)
static inline void syscall_set_argument(struct task_struct *task,
					 struct pt_regs *regs,
					 int i, unsigned long arg)
{
    if (i == 0){
        regs->ARM_r0 = arg;
    }else if (i == 1){
        regs->ARM_r1 = arg;
    }else if (i == 2){
        regs->ARM_r2 = arg;
    }else if (i == 3){
        regs->ARM_r3 = arg;
    }else if (i == 4){
        regs->ARM_r4 = arg;
    }else if (i == 5){
        regs->ARM_r5 = arg;
    }else if (i == 6){
        regs->ARM_r6 = arg;
    }else{
        printk(KERN_EMERG "This is an issue in syscall_set_argument");
    }
}

#elif defined(__aarch64__)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->regs[0] = arg;
        break;
    case 1:
        regs->regs[1] = arg;
        break;
    case 2:
        regs->regs[2] = arg;
        break;
    case 3:
        regs->regs[3] = arg;
        break;
    case 4:
        regs->regs[4] = arg;
        break;
    case 5:
        regs->regs[5] = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}

#elif defined(__x86_64__)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->di = arg;
        break;
    case 1:
        regs->si = arg;
        break;
    case 2:
        regs->dx = arg;
        break;
    case 3:
        regs->cx = arg;
        break;
    case 4:
        regs->r8 = arg;
        break;
    case 5:
        regs->r9 = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}

#elif defined(__i386__)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->bx = arg;
        break;
    case 1:
        regs->cx = arg;
        break;
    case 2:
        regs->dx = arg;
        break;
    case 3:
        regs->si = arg;
        break;
    case 4:
        regs->di = arg;
        break;
    case 5:
        regs->bp = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}

#elif defined(__loongarch__)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->regs[4] = arg;
        break;
    case 1:
        regs->regs[5] = arg;
        break;
    case 2:
        regs->regs[6] = arg;
        break;
    case 3:
        regs->regs[7] = arg;
        break;
    case 4:
        regs->regs[8] = arg;
        break;
    case 5:
        regs->regs[9] = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}

#elif defined(__riscv)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->a0 = arg;
        break;
    case 1:
        regs->a1 = arg;
        break;
    case 2:
        regs->a2 = arg;
        break;
    case 3:
        regs->a3 = arg;
        break;
    case 4:
        regs->a4 = arg;
        break;
    case 5:
        regs->a5 = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}

#elif defined(__powerpc__) || defined(__PPC__)
static inline void syscall_set_argument(struct task_struct *task,
                                       struct pt_regs *regs,
                                       int i, unsigned long arg)
{
    switch (i) {
    case 0:
        regs->gpr[3] = arg;
        break;
    case 1:
        regs->gpr[4] = arg;
        break;
    case 2:
        regs->gpr[5] = arg;
        break;
    case 3:
        regs->gpr[6] = arg;
        break;
    case 4:
        regs->gpr[7] = arg;
        break;
    case 5:
        regs->gpr[8] = arg;
        break;
    default:
        printk(KERN_EMERG "Invalid argument index in syscall_set_argument");
    }
}
#else
#error "Architecture not supported"
#endif
