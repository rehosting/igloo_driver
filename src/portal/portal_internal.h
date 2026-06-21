#ifndef __PORTAL_INTERNAL_H__
#define __PORTAL_INTERNAL_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h> 
#include <linux/net.h>
#include <linux/inet.h>
#include <net/inet_sock.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include <linux/printk.h>
#include "igloo_hypercall.h"
#include "igloo.h"
#include "syscalls_hc.h"
#include "igloo_debug.h"
#include "igloo_hypercall_consts.h"
#include "portal.h"
#include "portal_types.h"
#include "portal_op_list.h"

bool igloo_is_kernel_addr(unsigned long addr);

// Always print debug messages with highest priority
#define igloo_pr_debug(fmt, ...) igloo_debug_portal(fmt, ##__VA_ARGS__)

// Need to define a way to access data since it's now part of the raw buffer
#define PORTAL_DATA_OFFSET (sizeof(region_header))
#define PORTAL_DATA(region) (&((region)->raw[PORTAL_DATA_OFFSET]))

#define CHUNK_SIZE (PAGE_SIZE - sizeof(region_header))

// Fixed staging-buffer size for seeding/flushing mmap'd pseudofiles. The shmem backing
// is sparse, so the seed/flush trampoline copies in bounded chunks instead of allocating
// a single buffer the size of the (guest-controlled) mmap length. This keeps kernel memory
// O(1) regardless of mmap size and avoids unbounded (k)vzalloc() failures on 32-bit donors.
#define IGLOO_DEVFS_STAGE_SZ (64 * 1024)

// Define handler function type
typedef void (*portal_op_handler)(portal_region *mem_region);

// Helper function to get task based on pid from mem_region
struct task_struct *get_target_task_by_id(portal_region *mem_region);

// Generate handler prototypes
#define X(lower, upper) void handle_op_##lower(portal_region *mem_region);
PORTAL_OP_LIST
#undef X

#endif /* __PORTAL_INTERNAL_H__ */