#ifndef _IGLOO_SYSCALL_MACROS_H

/**
 * igloo_syscall_setter_t - Typedef for the syscall argument setter function.
 * @args_ptr_array: Array containing the ADDRESSES of the original syscall
 * arguments, each cast to unsigned long.
 * @new_args_le64:  Array containing the new argument values, provided as
 * little-endian 64-bit values.
 *
 * This function, generated per syscall, casts the pointers and new values
 * to the correct types and updates the original arguments.
 * NOTE: This function is generated even for syscalls with const args
 * (using a (void *) cast to bypass compile errors). The hook MUST NOT
 * call this setter with modified values for const arguments.
 */
typedef void (*igloo_syscall_setter_t)(const unsigned long args_ptr_array[],
                                       const __le64 new_args_le64[]);


/**
 * igloo_syscall_enter_t - Typedef for the enter hook function.
 * @syscall_name: The string name ("read", "openat", etc.) of the syscall.
 * @skip_ret_val: Pointer to store the return value if skipping the syscall.
 * @argc: Number of arguments passed to the syscall.
 * @args_ptr_array: Array containing the ADDRESSES of the syscall arguments.
 * @setter_func: Pointer to the type-safe setter function for this specific
 * syscall, or NULL if argc is 0. The hook can call this
 * function if it decides to modify arguments, but MUST respect
 * the const nature of arguments.
 *
 * Returns: true to skip the actual syscall execution, false to proceed.
 */
typedef bool (*igloo_syscall_enter_t)(const char *syscall_name,
                                      long *skip_ret_val,
                                      int argc,
                                      const unsigned long args_ptr_array[],
				igloo_syscall_setter_t setter_func);

/**
 * igloo_syscall_return_t - Typedef for the return hook function.
 * @syscall_name: The string name ("read", "openat", etc.) of the syscall.
 * @orig_ret: The original return value from the syscall (or skip value).
 * @argc: Number of arguments passed to the syscall.
 * @args_val_array: Array containing the final VALUES of the syscall arguments
 * (after potential modification by enter hook), each cast
 * to unsigned long.
 *
 * Returns: The potentially modified return value for the syscall.
 */
typedef long (*igloo_syscall_return_t)(const char *syscall_name,
				   long retval, int argc,
				   const unsigned long args[]);

extern igloo_syscall_enter_t igloo_syscall_enter_hook;
extern igloo_syscall_return_t igloo_syscall_return_hook;


#define IGLOO_SYSCALL_MAXARGS 6

#define __SC_ASSIGN_ADDR_ITER_0(arr, ...)
#define __SC_ASSIGN_ADDR_ITER_1(arr, t1, a1) arr[0] = (unsigned long)&a1;
#define __SC_ASSIGN_ADDR_ITER_2(arr, t1, a1, t2, a2) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2;
#define __SC_ASSIGN_ADDR_ITER_3(arr, t1, a1, t2, a2, t3, a3) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3;
#define __SC_ASSIGN_ADDR_ITER_4(arr, t1, a1, t2, a2, t3, a3, t4, a4) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4;
#define __SC_ASSIGN_ADDR_ITER_5(arr, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4; arr[4] = (unsigned long)&a5;
#define __SC_ASSIGN_ADDR_ITER_6(arr, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) arr[0] = (unsigned long)&a1; arr[1] = (unsigned long)&a2; arr[2] = (unsigned long)&a3; arr[3] = (unsigned long)&a4; arr[4] = (unsigned long)&a5; arr[5] = (unsigned long)&a6;



#define __SC_CONDITIONAL_ASSIGN(idx, type) \
	{ type __temp_val = (type)(uintptr_t)(new_args_le64[idx]); \
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