#ifndef _EXIT_HC_H
#define _EXIT_HC_H

#include <linux/types.h>
#include <linux/sched.h>
#include "portal/portal_types.h"

/*
 * Emitted once per user-process death, from a kprobe on do_exit(). Unlike the
 * exit/exit_group *syscall* hooks, this fires on the kernel task-exit path, so
 * it also captures deaths that never issue an exit syscall -- fatal signals
 * (SIGSEGV/SIGKILL/...), OOM kills, and kernel-forced exits -- with the real
 * exit code. ``code`` is the raw do_exit() argument in wait(2) status encoding:
 *   (code & 0x7f) != 0  -> killed by signal (code & 0x7f); 0x80 bit = core dump
 *   else                -> exited normally, status = (code >> 8) & 0xff
 * so the host decodes WIFSIGNALED / WIFEXITED without guessing.
 *
 * ``create_time`` is task->start_time -- the same value osi_proc_node uses as
 * process identity -- so a ProcExit pairs exactly with its ProcStart.
 */
struct exit_event {
    uint64_t pid;                  /* thread-group id = process id (namespaced) */
    uint64_t tid;                  /* task pid = thread id (namespaced)         */
    uint64_t create_time;          /* task->start_time; identity, pairs w/ start */
    int64_t  code;                 /* raw do_exit() code, wait-status encoded    */
    char comm[TASK_COMM_LEN];      /* dying task comm                            */
};

int exit_hc_init(void);
void handle_op_register_exit_hook(portal_region *mem_region);
void handle_op_unregister_exit_hook(portal_region *mem_region);

#endif /* _EXIT_HC_H */
