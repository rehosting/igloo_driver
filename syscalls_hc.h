#ifndef IGLOO_SYSCALLS_HC_H
#define IGLOO_SYSCALLS_HC_H 1
// Define the maximum number of arguments a syscall can have
#define IGLOO_SYSCALL_MAXARGS 6

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
                                       long orig_ret,
                                       int argc,
                                       const unsigned long args_val_array[]);


int syscalls_hc_init(void);

#endif /* IGLOO_SYSCALLS_HC_H */