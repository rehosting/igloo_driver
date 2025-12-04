#ifndef EHYPERCALL_H
#define EHYPERCALL_H
static inline unsigned long igloo_hypercall4(unsigned long num, unsigned long arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4) {
#if defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    register unsigned long reg2 asm("x1") = arg2;
    register unsigned long reg3 asm("x2") = arg3;
    register unsigned long reg4 asm("x3") = arg4;
    
    asm volatile(
        "msr S0_0_c5_c0_0, xzr \n"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"
    );
    return reg1;

#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;
    register unsigned long reg2 asm("r1") = arg2;
    register unsigned long reg3 asm("r2") = arg3;
    register unsigned long reg4 asm("r3") = arg4;

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"
    );

    return reg1;

#elif defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;
    register unsigned long reg4 asm("a3") = arg4;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)  // Input and output in v0
        : "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"
    );
    return reg0;

#elif defined(CONFIG_X86_64)
    register unsigned long reg0 asm("rax") = num;
    register unsigned long reg1 asm("rdi") = arg1;
    register unsigned long reg2 asm("rsi") = arg2;
    register unsigned long reg3 asm("rdx") = arg3;
    register unsigned long reg4 asm("r10") = arg4; // r10 used for 4th arg in syscall ABI

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory", "rbx", "rcx"
    );

    return reg0;

#elif defined(CONFIG_I386)
    // Matches the "other implementation" (standard Linux Syscall ABI)
    register unsigned long reg0 asm("eax") = num;
    register unsigned long reg1 asm("ebx") = arg1;
    register unsigned long reg2 asm("ecx") = arg2;
    register unsigned long reg3 asm("edx") = arg3;
    register unsigned long reg4 asm("esi") = arg4;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in eax
        : "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"             // No specific register clobbers needed as they are all inputs/outputs
    );

    return reg0;

#elif defined(CONFIG_LOONGARCH)
    register unsigned long reg0 asm("a7") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;
    register unsigned long reg4 asm("a3") = arg4;

    asm volatile(
        "cpucfg $r0, $r0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"
    );
    return reg1;

#elif defined(CONFIG_PPC) || defined(CONFIG_PPC64)
    register unsigned long reg0 asm("r0") = num;
    register unsigned long reg1 asm("r3") = arg1;
    register unsigned long reg2 asm("r4") = arg2;
    register unsigned long reg3 asm("r5") = arg3;
    register unsigned long reg4 asm("r6") = arg4;
    
    asm volatile(
        "xori 10, 10, 0" // User-specified instruction
        : "+r"(reg1) // Input and output in r3
        : "r"(reg0), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory", "lr", "ctr",
          "cr0", "cr1", "cr5", "cr6", "cr7",
          "r7", "r8", "r9", "r10", "r11", "r12" // r6 removed from clobber
    );
    return reg1;

#elif defined(CONFIG_RISCV)
    register unsigned long reg0 asm("a7") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;
    register unsigned long reg4 asm("a3") = arg4;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2), "r"(reg3), "r"(reg4)
        : "memory"
    );
    return reg1; 

#else
#error "No igloo_hypercall4 support for architecture"
#endif
}
#endif