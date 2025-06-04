#ifndef HYPERCALL_H
#define HYPERCALL_H
#include <linux/types.h> // Use standard include path

static inline unsigned long igloo_hypercall(unsigned long num, unsigned long arg1) {
#if defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)
        : "r"(reg1) // num in register v0
        : "memory"
    );
    
    return reg0;

#elif defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    asm volatile(
            "msr S0_0_c5_c0_0, xzr \n"
            : "+r"(reg1)
            : "r"(reg0)
            : "memory"
        );
    
    return reg1;
    
#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;

    asm volatile(
    "mcr p7, 0, r0, c0, c0, 0"
      : "+r"(reg1)
      : "r"(reg0)
      : "memory"
  );
    
    return reg1;
    
#elif defined(CONFIG_X86_64)
    register unsigned long reg0 asm("rax") = num;
    register unsigned long reg1 asm("rdi") = arg1;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1)            // arguments
        : "memory", "rbx", "rcx", "rdx"  // No clobber
    );
    
    return reg0;
    
#elif defined(CONFIG_I386)
    register unsigned long reg0 asm("eax") = num;
    register unsigned long reg1 asm("edi") = arg1;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1)            // arguments
        : "memory", "ebx", "ecx", "edx"
    );
    
    return reg0;
    
#elif defined(CONFIG_LOONGARCH)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
        "cpucfg $r0, $r0"
        : "+r"(reg0)
        : "r"(reg1)
        : "memory"  // No clobber
    );
    
    return reg0;
    
#elif defined(CONFIG_PPC)
	register unsigned long reg0 asm("r0") = num;
	register unsigned long reg1 asm("r3") = arg1;

    asm volatile(
        "xori 10, 10, 0"  // User-specified instruction - ASSUMED CORRECT TRIGGER
        : "+r"(reg0)      // Input num in r0, Output retval in r0
        : "r"(reg1)       // Input arg1 in r3
        : "memory", "lr", "ctr", // CRITICAL: clobber link and count registers
          // Clobber volatile condition register fields:
          "cr0", "cr1", "cr5", "cr6", "cr7",
          // Clobber volatile GPRs (r4-r12) - r0,r3 handled by constraints:
          "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
          // Note: r2 (TOC) and r13 (thread ptr) are usually non-volatile but check hypervisor docs
    );
    
    return reg0;
    
#elif defined(CONFIG_RISCV)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg1)  /* Modified: a0/reg1 is both input and output */
        : "r"(reg0)
        : "memory"
    );
    
    return reg1;
    
#else
#error "No igloo_hypercall support for architecture"
#endif
}

static inline unsigned long igloo_hypercall2(unsigned long num, unsigned long arg1, unsigned long arg2) {
#if defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    register unsigned long reg2 asm("x1") = arg2;
    asm volatile(
       "msr S0_0_c5_c0_0, xzr \n"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2)
        : "memory"
    );
    return reg1;
#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;
    register unsigned long reg2 asm("r1") = arg2;

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2)
        : "memory"
    );

    return reg1;

#elif defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)  // Input and output in v0
        : "r"(reg1), "r"(reg2)
        : "memory"
    );
    return reg0;
#elif defined(CONFIG_X86_64)
    register unsigned long reg0 asm("rax") = num;
    register unsigned long reg1 asm("rdi") = arg1;
    register unsigned long reg2 asm("rsi") = arg2;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1), "r"(reg2) // arguments
        :  "memory", "rbx", "rcx", "rdx"
    );

    return reg0;
#elif defined(CONFIG_I386)
    register unsigned long reg0 asm("eax") = num;
    register unsigned long reg1 asm("edi") = arg1;
    register unsigned long reg2 asm("esi") = arg2;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1), "r"(reg2) // arguments
        : "memory", "ebx", "ecx", "edx"
    );

    return reg0;
#elif defined(CONFIG_LOONGARCH)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;
	register unsigned long reg2 asm("a1") = arg2;

    asm volatile(
        "cpucfg $r0, $r0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2)
        : "memory"
    );
    return reg1;  /* Return reg1 (a0) which contains the return value from the hypervisor */
#elif defined(CONFIG_PPC) || defined(CONFIG_PPC64)
	register unsigned long reg0 asm("r0") = num;
	register unsigned long reg1 asm("r3") = arg1;
	register unsigned long reg2 asm("r4") = arg2; // Second arg in r4
    
    asm volatile(
        "xori 10, 10, 0" // User-specified instruction
        : "+r"(reg1) // Input and output in r3
        : "r"(reg0), "r"(reg2)
        : "memory", "lr", "ctr",
          "cr0", "cr1", "cr5", "cr6", "cr7",
          "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
    return reg1;  /* Return reg1 (r3) which contains the return value from the hypervisor */
#elif defined(CONFIG_RISCV)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;
	register unsigned long reg2 asm("a1") = arg2;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2)
        : "memory"
    );
    return reg1;  /* Return reg1 (a0) which contains the return value from the hypervisor */
#else
#error "No igloo_hypercall2 support for architecture"
#endif
}

static inline unsigned long igloo_hypercall3(unsigned long num, unsigned long arg1, unsigned long arg2, unsigned long arg3) {
#if defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    register unsigned long reg2 asm("x1") = arg2;
    register unsigned long reg3 asm("x2") = arg3;
    asm volatile(
       "msr S0_0_c5_c0_0, xzr \n"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2), "r"(reg3)
        : "memory"
    );
    return reg1;
#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;
    register unsigned long reg2 asm("r1") = arg2;
    register unsigned long reg3 asm("r2") = arg3;

    asm volatile(
       "mcr p7, 0, r0, c0, c0, 0"
        : "+r"(reg1)  // Input and output
        : "r"(reg0), "r"(reg2), "r"(reg3)
        : "memory"
    );

    return reg1;

#elif defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)  // Input and output in v0
        : "r"(reg1), "r"(reg2), "r"(reg3)
        : "memory"
    );
    return reg0;
#elif defined(CONFIG_X86_64)
    register unsigned long reg0 asm("rax") = num;
    register unsigned long reg1 asm("rdi") = arg1;
    register unsigned long reg2 asm("rsi") = arg2;
    register unsigned long reg3 asm("rdx") = arg3;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1), "r"(reg2), "r"(reg3) // arguments
        : "memory", "rbx", "rcx"
    );

    return reg0;
#elif defined(CONFIG_I386)
    register unsigned long reg0 asm("eax") = num;
    register unsigned long reg1 asm("edi") = arg1;
    register unsigned long reg2 asm("esi") = arg2;
    register unsigned long reg3 asm("edx") = arg3;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in eax
        : "r"(reg1), "r"(reg2), "r"(reg3) // arguments
        : "memory", "ebx", "ecx"
    );

    return reg0;
#elif defined(CONFIG_LOONGARCH)
    register unsigned long reg0 asm("a7") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;

    asm volatile(
        "cpucfg $r0, $r0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2), "r"(reg3)
        : "memory"
    );
    return reg1;  /* Return reg1 (a0) which contains the return value from the hypervisor */
#elif defined(CONFIG_PPC) || defined(CONFIG_PPC64)
    register unsigned long reg0 asm("r0") = num;
    register unsigned long reg1 asm("r3") = arg1;
    register unsigned long reg2 asm("r4") = arg2;
    register unsigned long reg3 asm("r5") = arg3;
    
    asm volatile(
        "xori 10, 10, 0" // User-specified instruction
        : "+r"(reg1) // Input and output in r3
        : "r"(reg0), "r"(reg2), "r"(reg3)
        : "memory", "lr", "ctr",
          "cr0", "cr1", "cr5", "cr6", "cr7",
          "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
    return reg1;  /* Return reg1 (r3) which contains the return value from the hypervisor */
#elif defined(CONFIG_RISCV)
    register unsigned long reg0 asm("a7") = num;
    register unsigned long reg1 asm("a0") = arg1;
    register unsigned long reg2 asm("a1") = arg2;
    register unsigned long reg3 asm("a2") = arg3;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg1)  /* a0/reg1 is both input and output */
        : "r"(reg0), "r"(reg2), "r"(reg3)
        : "memory"
    );
    return reg1;  /* Return reg1 (a0) which contains the return value from the hypervisor */
#else
#error "No igloo_hypercall3 support for architecture"
#endif
}

#endif