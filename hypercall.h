#ifndef HYPERCALL_H
#define HYPERCALL_H
#include <linux/types.h> // Use standard include path

static inline void igloo_hypercall(unsigned long num, unsigned long arg1) {
#if defined(CONFIG_MIPS)
    register unsigned long reg0 asm("v0") = num;
    register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
       "movz $0, $0, $0"
        : "+r"(reg0)
        : "r"(reg1) // num in register v0
        : "memory"
    );


#elif defined(CONFIG_ARM64)
    register unsigned long reg0 asm("x8") = num;
    register unsigned long reg1 asm("x0") = arg1;
    asm volatile(
            "msr S0_0_c5_c0_0, xzr \n"
            : "+r"(reg1)
            : "r"(reg0)
            : "memory"
        );
#elif defined(CONFIG_ARM)
    register unsigned long reg0 asm("r7") = num;
    register unsigned long reg1 asm("r0") = arg1;

    asm volatile(
    "mcr p7, 0, r0, c0, c0, 0"
      : "+r"(reg1)
      : "r"(reg0)
      : "memory"
  );
#elif defined(CONFIG_X86_64)
    register unsigned long reg0 asm("rax") = num;
    register unsigned long reg1 asm("rdi") = arg1;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1)            // arguments
        : "memory", "rbx", "rcx", "rdx"  // No clobber
    );
#elif defined(CONFIG_I386)
    register unsigned long reg0 asm("eax") = num;
    register unsigned long reg1 asm("edi") = arg1;

    asm volatile(
        "cpuid"
        : "+r"(reg0)           // hypercall num + return value in rax
        : "r"(reg1)            // arguments
        : "memory", "ebx", "ecx", "edx"
    );
#elif defined(CONFIG_LOONGARCH)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
        "cpucfg $r0, $r0"
        : "+r"(reg0)
        : "r"(reg1)
        : "memory"  // No clobber
    );
#elif defined(CONFIG_PPC)
	register unsigned long reg0 asm("r0") = num;
	register unsigned long reg1 asm("r3") = arg1;
    // Assume return value is in r0 based on "+r"(reg0) before void change

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
#elif defined(CONFIG_RISCV)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg0)
        : "r"(reg1)
        : "memory"
    );
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
        : "+r"(reg0)  // Input and output in R0
        : "r"(reg1) , "r" (reg2)// arg2 in register A1
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
        : "+r"(reg0)
        : "r"(reg1), "r"(reg2)
        : "memory"  // No clobber
    );
    return reg1;
#elif defined(CONFIG_PPC) || defined(CONFIG_PPC64)
	register unsigned long reg0 asm("r0") = num;
	register unsigned long reg1 asm("r3") = arg1;
	register unsigned long reg2 asm("r4") = arg2; // Second arg in r4
    register unsigned long retval asm("r3"); // Assume return in r3

    asm volatile(
        "xori 10, 10, 0" // User-specified instruction
        : "=r"(retval) // Output: r3 (adjust if needed)
        : "r"(reg0), "r"(reg1), "r"(reg2) // Inputs: r0, r3, r4
        : "memory", "lr", "ctr",
          "cr0", "cr1", "cr5", "cr6", "cr7",
          // Clobber volatile GPRs excluding inputs (r0, r3, r4)
          "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
    return retval;
#elif defined(CONFIG_RISCV)
	register unsigned long reg0 asm("a7") = num;
	register unsigned long reg1 asm("a0") = arg1;
	register unsigned long reg2 asm("a1") = arg2;

    asm volatile(
        "xori x0, x0, 0"
        : "+r"(reg0)
        : "r"(reg1), "r" (reg2) 
        : "memory"
    );
    return reg1;
#else
#error "No igloo_hypercall2 support for architecture"
#endif
}

#endif