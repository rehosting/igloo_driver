#define MAX_PROBES 20
/* Architecture-specific function to retrieve syscall number */
static inline int get_syscall_number(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->orig_ax;
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    #if defined(__thumb__) || defined(__thumb2__) || defined(CONFIG_THUMB2_KERNEL)
        return regs->uregs[7];  // Syscall number is in r7 in Thumb mode
    #else
        return regs->ARM_r7;    // Syscall number is in r7 in ARM mode
    #endif
#elif defined(CONFIG_ARM64)
    return regs->regs[8];  // Syscall number is stored in x8 in ARM64
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[2];  // Syscall number is in v0 for MIPS
#elif defined(CONFIG_LOONGARCH)
    return regs->regs[7];
#elif defined(CONFIG_PPC)
    return regs->gpr[3];
#elif defined(CONFIG_RISCV)
    return regs->a0;
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_first_syscall_arg(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->di;  // 1st argument in di
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r0;  // 1st argument in r0
#elif defined(CONFIG_ARM64)
    return regs->regs[0];  // 1st argument in x0
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[4];  // 1st argument in a0 (regs[4])
#elif defined(CONFIG_LOONGARCH)
    return regs->regs[0];
#elif defined(CONFIG_PPC)
    return regs->gpr[4];
#elif defined(CONFIG_RISCV)
    return regs->a1;
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_second_syscall_arg(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->si;  // 2nd argument in si
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r1;  // 2nd argument in r1
#elif defined(CONFIG_ARM64)
    return regs->regs[1];  // 2nd argument in x1
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[5];  // 2nd argument in a1 (regs[5])
#elif defined(CONFIG_LOONGARCH)
    return regs->regs[1];
#elif defined(CONFIG_PPC)
    return regs->gpr[5];
#elif defined(CONFIG_RISCV)
    return regs->a2;
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_return_value(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->ax;  // Return value in ax
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r0;  // Return value in r0
#elif defined(CONFIG_ARM64)
    return regs->regs[0];  // Return value in x0
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[2];  // Return value in v0 (regs[2])
#elif defined(CONFIG_LOONGARCH)
    return regs->regs[0];
#elif defined(CONFIG_PPC)
    return regs->gpr[3];
#elif defined(CONFIG_RISCV)
    return regs->a0;
#else
    #error "Unsupported architecture"
#endif
}

// Check if an mmap return value is an error based on TASK_SIZE
static inline int is_mmap_error(unsigned long addr) {
    return addr >= TASK_SIZE;
}