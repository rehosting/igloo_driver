/* kernel-lift: minimal ARM asm/syscall.h shim for Linux 3.4 (which predates
 * arch/arm/include/asm/syscall.h, added ~3.18). Provides the syscall arg
 * accessors igloo_driver needs, implemented over ARM pt_regs (uregs[0..]). */
#ifndef _KERNEL_LIFT_ASM_ARM_SYSCALL_H
#define _KERNEL_LIFT_ASM_ARM_SYSCALL_H
#include <linux/sched.h>
#include <asm/ptrace.h>

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
#endif
