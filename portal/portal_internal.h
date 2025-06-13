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
#include <linux/sched/signal.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include <linux/printk.h>
#include "hypercall.h"
#include "igloo.h"
#include "../syscalls_hc.h"
#include "../igloo_debug.h"
#include "portal.h"
#include "portal_types.h"

bool igloo_is_kernel_addr(unsigned long addr);

// Always print debug messages with highest priority
#define igloo_pr_debug(fmt, ...) igloo_debug_portal(fmt, ##__VA_ARGS__)

// Need to define a way to access data since it's now part of the raw buffer
#define PORTAL_DATA_OFFSET (sizeof(region_header))
#define PORTAL_DATA(region) (&((region)->raw[PORTAL_DATA_OFFSET]))

#define CHUNK_SIZE (PAGE_SIZE - sizeof(region_header))

// Define handler function type
typedef void (*portal_op_handler)(portal_region *mem_region);

// Helper function to get task based on pid from mem_region
struct task_struct *get_target_task_by_id(portal_region *mem_region);

// Memory operation handlers
void handle_op_read(portal_region *mem_region);
void handle_op_write(portal_region *mem_region);
void handle_op_read_fds(portal_region *mem_region);
void handle_op_read_procargs(portal_region *mem_region);
void handle_op_read_str(portal_region *mem_region);
void handle_op_read_file(portal_region *mem_region);
void handle_op_write_file(portal_region *mem_region);
void handle_op_read_procenv(portal_region *mem_region);
void handle_op_dump(portal_region *mem_region);
void handle_op_exec(portal_region *mem_region);

// OSI operation handlers
void handle_op_osi_proc(portal_region *mem_region);
void handle_op_osi_proc_handles(portal_region *mem_region);
void handle_op_osi_mappings(portal_region *mem_region);
void handle_op_osi_proc_mem(portal_region *mem_region);

// Uprobe operation handlers
void handle_op_register_uprobe(portal_region *mem_region);
void handle_op_unregister_uprobe(portal_region *mem_region);

// Syscall hook operation handlers
void handle_op_register_syscall_hook(portal_region *mem_region);
void handle_op_unregister_syscall_hook(portal_region *mem_region);

// FFI operation handler
void handle_op_ffi_exec(portal_region *mem_region);

#endif /* __PORTAL_INTERNAL_H__ */
