#ifndef _LINUX_IGLOO_H
#define _LINUX_IGLOO_H

extern unsigned long igloo_task_size; // mmap.c
extern bool igloo_do_hc; // mmap.c
extern bool igloo_log_cov; // mmap.c
extern bool igloo_block_halt; // reboot.c

#include "igloo_hypercall_consts.h"

#endif /* _LINUX_IGLOO_H */
