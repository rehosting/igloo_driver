#ifndef _LINUX_IGLOO_H
#define _LINUX_IGLOO_H
#include <linux/utsname.h>
#include <linux/socket.h>
#include <linux/binfmts.h>

extern unsigned long igloo_task_size; // mmap.c
extern bool igloo_block_halt; // reboot.c

struct user_arg_ptr;  // Forward declaration
struct syscall_metadata; // Forward declaration for syscall metadata functions

unsigned long igloo_arch_syscall_addr(int nr);

/* Syscall metadata access functions */
struct syscall_metadata *igloo_get_syscall_metadata(int nr);
int igloo_get_nr_syscalls(void);
struct syscall_metadata *igloo_get_syscall_metadata_by_index(int index);
int igloo_get_syscall_metadata_count(void);
struct syscall_metadata *igloo_get_syscall_metadata_copy(int nr);
int igloo_get_syscall_metadata_count_copy(void);
struct syscall_metadata *igloo_get_syscall_metadata_by_index_copy(int index);

#endif /* _LINUX_IGLOO_H */