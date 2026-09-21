// OSI-minimal profile (CONFIG_IGLOO_OSI_MINIMAL, see src/Kconfig).
//
// When igloo is loaded into a hardened vendor kernel that exports almost
// nothing, the feature units that need otherwise-unexported symbols cannot
// link. The Makefile drops those objects from this profile; this file supplies
// what the surviving units still reference:
//   * FAIL-stubs for every op handler whose unit was dropped, so portal.c's
//     dispatch links and the op ENUM (portal_op_list.h) stays whole for the
//     penguin/ISF contract -- unsupported ops just return FAIL at runtime.
//   * no-op init stubs for the dropped subsystems.
//   * minimal task-lookup helpers that need no extra exports.
//   * igloo_test_function (load-base anchor) + forced ISF enums.
//
// The whole file is gated on CONFIG_IGLOO_OSI_MINIMAL: in any other build it is
// empty (and the Makefile never compiles it), so its stubs can never collide
// with the real handlers.
#ifdef CONFIG_IGLOO_OSI_MINIMAL

#include "portal_internal.h"

void handle_op_read(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_write(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_read_str(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_read_ptr_array(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_dump(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_exec(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_read_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_write_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_uprobe(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_unregister_uprobe(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_kprobe(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_unregister_kprobe(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_syscall_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_unregister_syscall_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_portalcall_magic(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_set_portalcall_fastpath(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_signal_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_unregister_signal_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_exit_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_unregister_exit_hook(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_vfs_open(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_vfs_read(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_vfs_close(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_ffi_exec(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_kallsyms_lookup(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_tramp_generate(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_hyperfs_add_hyperfile(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_register_netdev(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_lookup_netdev(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_set_netdev_state(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_get_netdev_state(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_copy_buf_guest(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_procfs_create_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_procfs_create_or_lookup_dir(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_sysfs_create_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_sysfs_create_or_lookup_dir(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_devfs_create_device(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_devfs_create_or_lookup_dir(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_sysctl_create_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_anonfs_create_file(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_sockfs_create_socket(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_mtd_nuke(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }
void handle_op_mtd_create(portal_region *r){ r->header.op = HYPER_RESP_READ_FAIL; }

// init stubs for excluded subsystems (real ones live in dropped .o files)
int syscalls_hc_init(void){ return 0; }
int signal_hc_init(void){ return 0; }
int ioctl_hc_init(void){ return 0; }
int sock_hc_init(void){ return 0; }
int uname_hc_init(void){ return 0; }
int igloo_procfs_compat_init(void){ return 0; }
int block_mounts_init(void){ return 0; }
int igloo_open_init(void){ return 0; }
int hyperfs_init(void){ return 0; }
int exit_hc_init(void){ return 0; }

// Minimal task-lookup helpers (the real ones in portal_mem.c use the
// unexported pid_task/find_pid_ns/init_pid_ns). On a hardened vendor kernel
// those aren't available, so look a pid up by scanning for_each_process
// (anchored on init_task, which the vendor kernel does resolve) and read the
// pid through the runtime-offset table (KFIELD). get_task_mm/current are
// exported. This keeps OSI (incl. by-pid ops) working with no extra exports.
#include "portal_offsets.h"
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>

struct task_struct *get_target_task_by_id(portal_region *mem_region)
{
	pid_t target = (pid_t)(mem_region->header.pid);
	struct task_struct *task;
	if (target == CURRENT_PID_NUM)
		return current;
	for_each_process(task) {
		if (KFIELD(pid_t, task, task_struct, pid) == target)
			return task;
	}
	return NULL;
}

struct mm_struct *get_target_task_mm(portal_region *mem_region, bool *is_current)
{
	struct task_struct *task;
	struct mm_struct *mm = NULL;
	rcu_read_lock();
	task = get_target_task_by_id(mem_region);
	if (task) {
		if (is_current)
			*is_current = (task == current);
		mm = get_task_mm(task);
	}
	rcu_read_unlock();
	return mm;
}

// igloo_test_function normally lives in portal_ffi.c (excluded here). penguin's
// igloodriver computes igloo's load base from this symbol's runtime address vs
// its ISF offset, so keep it in the minimal profile.
int igloo_test_function(int a, int b, int c, int d, int e, int f, int g, int h);
int igloo_test_function(int a, int b, int c, int d, int e, int f, int g, int h)
{
	printk(KERN_EMERG "igloo: test_function called with args: %x %x %x %x %x %x %x %x\n",
	       a, b, c, d, e, f, g, h);
	return a + b + c + d + e + f + g + h;
}

/* --- ISF enum completeness for penguin's hyper.consts (fixed enum contract) ---
 * dwarf2json only emits enums a compiled object references. The OSI-minimal
 * profile drops the units that use these, so force them into the DWARF with
 * dummy variables. igloo_base_hypercalls lives in the kernel's igloo_base (not
 * in the module headers, not emitted to any ISF); define its one ABI-fixed
 * member here (same value penguin's harness supplements). */
#include "portal_types.h"
#include "hyperfs_consts.h"
#include "syscalls_hc.h"
enum igloo_base_hypercalls { IGLOO_HYP_SETUP_SYSCALL = 0x1337 };
volatile enum portal_type           _kl_f_portal_type;
volatile enum hyperfs_ops           _kl_f_hyperfs_ops;
volatile enum hyperfs_file_ops      _kl_f_hyperfs_file_ops;
volatile enum value_filter_type     _kl_f_value_filter_type;
volatile enum igloo_base_hypercalls _kl_f_igloo_base_hypercalls;

#endif /* CONFIG_IGLOO_OSI_MINIMAL */
