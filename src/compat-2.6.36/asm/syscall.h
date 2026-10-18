/* kernel-lift: minimal ARM asm/syscall.h shim for Linux 3.4 (which predates
 * arch/arm/include/asm/syscall.h, added ~3.18). Provides the syscall arg
 * accessors igloo_driver needs, implemented over ARM pt_regs (uregs[0..]). */
#ifndef _KERNEL_LIFT_ASM_ARM_SYSCALL_H
#define _KERNEL_LIFT_ASM_ARM_SYSCALL_H
#include <linux/sched.h>
#include <asm/ptrace.h>

#if defined(__mips__)
/* MIPS o32 before asm/syscall.h existed there (3.7): number in v0 (regs[2]), the first four
 * arguments in a0-a3 (regs[4..7]); a result is v0, with a3 as the error flag. Arguments 5 and
 * 6 are on the user stack and are not reached here (they read as 0, and are not written). */
static inline long syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
    return regs->regs[2];
}
static inline void syscall_get_arguments(struct task_struct *task,
        struct pt_regs *regs, unsigned int i, unsigned int n, unsigned long *args)
{
    for (; n; n--, i++)
        *args++ = i < 4 ? regs->regs[4 + i] : 0;
}
static inline void syscall_set_arguments(struct task_struct *task,
        struct pt_regs *regs, unsigned int i, unsigned int n,
        const unsigned long *args)
{
    for (; n; n--, i++, args++)
        if (i < 4)
            regs->regs[4 + i] = *args;
}
static inline long syscall_get_return_value(struct task_struct *task,
        struct pt_regs *regs)
{
    return regs->regs[7] ? -(long)regs->regs[2] : (long)regs->regs[2];
}
static inline void syscall_set_return_value(struct task_struct *task,
        struct pt_regs *regs, int error, long val)
{
    if (error) {
        regs->regs[2] = -error;
        regs->regs[7] = 1;
    } else {
        regs->regs[2] = val;
        regs->regs[7] = 0;
    }
}
#else

static inline long syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
    return regs->ARM_r7;
}
static inline void syscall_get_arguments(struct task_struct *task,
        struct pt_regs *regs, unsigned int i, unsigned int n, unsigned long *args)
{
    while (n--) *args++ = regs->uregs[i++];
}
static inline void syscall_set_arguments(struct task_struct *task,
        struct pt_regs *regs, unsigned int i, unsigned int n,
        const unsigned long *args)
{
    while (n--) regs->uregs[i++] = *args++;
}
static inline long syscall_get_return_value(struct task_struct *task,
        struct pt_regs *regs)
{
    return regs->ARM_r0;
}
static inline void syscall_set_return_value(struct task_struct *task,
        struct pt_regs *regs, int error, long val)
{
    regs->ARM_r0 = (long)error ? error : val;
}
#endif /* __mips__ */
#endif
