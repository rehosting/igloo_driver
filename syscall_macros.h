#ifndef _IGLOO_SYSCALL_MACROS_H

#include "syscalls_hc.h"


#define IGLOO_SYSCALL_MAXARGS 6

#define __SC_ASSIGN_ADDR_ITER_0(arr, ...)
#define __SC_ASSIGN_ADDR_ITER_1(arr, t1, a1) arr[0] = (unsigned long)&a1;
#define __SC_ASSIGN_ADDR_ITER_2(arr, t1, a1, t2, a2) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2;
#define __SC_ASSIGN_ADDR_ITER_3(arr, t1, a1, t2, a2, t3, a3) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3;
#define __SC_ASSIGN_ADDR_ITER_4(arr, t1, a1, t2, a2, t3, a3, t4, a4) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4;
#define __SC_ASSIGN_ADDR_ITER_5(arr, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4; arr[4] = (unsigned long)&a5;
#define __SC_ASSIGN_ADDR_ITER_6(arr, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4; arr[4] = (unsigned long)&a5; arr[5] = (unsigned long)&a6;



#define __SC_CONDITIONAL_ASSIGN(idx, type) \
	{ type __temp_val = (type)(uintptr_t)le64_to_cpu(new_args_le64[idx]); \
	  memcpy((void *)(uintptr_t)args_ptr_array[idx], &__temp_val, sizeof(type)); \
	  (void)0; }

#define __SC_GEN_SETTER_BODY_ITER_0(...)
#define __SC_GEN_SETTER_BODY_ITER_1(t1, a1) __SC_CONDITIONAL_ASSIGN(0, t1);
#define __SC_GEN_SETTER_BODY_ITER_2(t1, a1, t2, a2) __SC_CONDITIONAL_ASSIGN(0, t1); __SC_CONDITIONAL_ASSIGN(1, t2);
#define __SC_GEN_SETTER_BODY_ITER_3(t1, a1, t2, a2, t3, a3) __SC_CONDITIONAL_ASSIGN(0, t1); __SC_CONDITIONAL_ASSIGN(1, t2); __SC_CONDITIONAL_ASSIGN(2, t3);
#define __SC_GEN_SETTER_BODY_ITER_4(t1, a1, t2, a2, t3, a3, t4, a4) __SC_CONDITIONAL_ASSIGN(0, t1); __SC_CONDITIONAL_ASSIGN(1, t2); __SC_CONDITIONAL_ASSIGN(2, t3); __SC_CONDITIONAL_ASSIGN(3, t4);
#define __SC_GEN_SETTER_BODY_ITER_5(t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) __SC_CONDITIONAL_ASSIGN(0, t1); __SC_CONDITIONAL_ASSIGN(1, t2); __SC_CONDITIONAL_ASSIGN(2, t3); __SC_CONDITIONAL_ASSIGN(3, t4); __SC_CONDITIONAL_ASSIGN(4, t5);
#define __SC_GEN_SETTER_BODY_ITER_6(t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) __SC_CONDITIONAL_ASSIGN(0, t1); __SC_CONDITIONAL_ASSIGN(1, t2); __SC_CONDITIONAL_ASSIGN(2, t3); __SC_CONDITIONAL_ASSIGN(3, t4); __SC_CONDITIONAL_ASSIGN(4, t5); __SC_CONDITIONAL_ASSIGN(5, t6);


#ifndef CONFIG_IGLOO
#define igloo_syscall_enter_hook NULL
#define igloo_syscall_return_hook NULL
#define __SC_ASSIGN_ADDR_WRAPPER(nr, arr, ...) do {} while (0)
#define __SC_GEN_SETTER_BODY_WRAPPER(nr, ...) do {} while (0)
#else
#define __SC_ASSIGN_ADDR_WRAPPER(nr, arr, ...) \
	__SC_ASSIGN_ADDR_ITER_##nr(arr, __VA_ARGS__)
#define __SC_GEN_SETTER_BODY_WRAPPER(nr, ...) \
	__SC_GEN_SETTER_BODY_ITER_##nr(__VA_ARGS__)

#endif

#endif