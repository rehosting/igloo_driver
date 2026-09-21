#ifndef __PORTAL_OFFSETS_H__
#define __PORTAL_OFFSETS_H__

/*
 * Runtime struct offsets.
 *
 * Historically igloo reads kernel structs with plain C member access
 * (task->pid, mm->mmap_base, ...), so every offset is baked in at BUILD time
 * from the donor kernel's headers. That is correct only while the running
 * kernel's layout matches the donor's — which breaks under randstruct, config
 * drift, or a genuinely different vendor kernel. kernel-lift's recovery work
 * pins the true offsets of the running kernel; this header lets those offsets be
 * injected at RUNTIME (host -> guest via the SET_OFFSETS portal op) and used in
 * place of the compile-time ones.
 *
 * It is fully back-compatible: KOFF(s, f) returns the injected offset when one
 * has been set for that field, and otherwise falls back to the compile-time
 * offsetof(s, f) — so an un-patched host, or a field the host did not send,
 * behaves exactly as before. The field set is an X-macro (like PORTAL_OP_LIST),
 * so the guest enum and the host's wire encoding stay in lock-step by ordering.
 *
 * NOTE (honest scope): this fixes struct-LAYOUT portability only. It does not
 * make igloo.ko loadable against an arbitrary kernel build (module vermagic/ABI
 * is a separate, per-build constraint); it makes igloo's introspection READ the
 * right fields once the module is running.
 */

#include <linux/types.h>
#include <linux/stddef.h>   /* offsetof */
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/cred.h>

/*
 * The runtime-offset field set. Each X(struct, field) must name a field that
 * also exists in the donor headers, so the offsetof() fallback compiles. Fields
 * that do not exist on every era (e.g. vm_area_struct.vm_next, removed in 6.1)
 * are deliberately NOT listed here; a pure-runtime slot without a compile-time
 * fallback would use KOFF_RT() instead (see below).
 */
#define KOFF_FIELD_LIST \
	X(task_struct, pid) \
	X(task_struct, tgid) \
	X(task_struct, mm) \
	X(task_struct, active_mm) \
	X(task_struct, comm) \
	X(task_struct, cred) \
	X(task_struct, real_parent) \
	X(task_struct, tasks) \
	X(task_struct, start_time) \
	X(task_struct, group_leader) \
	X(mm_struct, mmap_base) \
	X(mm_struct, pgd) \
	X(mm_struct, arg_start) \
	X(mm_struct, arg_end) \
	X(mm_struct, env_start) \
	X(mm_struct, env_end) \
	X(mm_struct, start_brk) \
	X(mm_struct, brk) \
	X(mm_struct, start_stack) \
	X(mm_struct, start_code) \
	X(mm_struct, end_code) \
	X(mm_struct, start_data) \
	X(mm_struct, end_data) \
	X(mm_struct, task_size) \
	X(mm_struct, map_count) \
	X(mm_struct, exe_file) \
	X(cred, uid) \
	X(cred, gid) \
	X(cred, euid) \
	X(cred, egid)

enum koff_field {
#define X(s, f) KF_##s##__##f,
	KOFF_FIELD_LIST
#undef X
	KF_MAX
};

/* Populated by the SET_OFFSETS portal op. koff_set[i] != 0 means koff_table[i]
 * carries an injected offset that overrides the compile-time one. */
extern long koff_table[KF_MAX];
extern u8   koff_set[KF_MAX];

/* The offset to use for (s, f): injected if present, else compile-time. `s` is a
 * bare struct tag (e.g. task_struct); the `struct` keyword is baked in here so
 * call sites read KFIELD(.., task_struct, pid) and the enum paste stays clean. */
#define KOFF(s, f) \
	(koff_set[KF_##s##__##f] ? (unsigned long)koff_table[KF_##s##__##f] \
				 : (unsigned long)offsetof(struct s, f))

/* Typed read of field f of type rtype from object `base` (a pointer to s). */
#define KFIELD(rtype, base, s, f) \
	(*(rtype *)((const char *)(base) + KOFF(s, f)))

/* Address of field f within object `base` (for sub-struct / array fields). */
#define KFIELD_PTR(base, s, f) \
	((void *)((const char *)(base) + KOFF(s, f)))

/* Wire entry the host writes into the SET_OFFSETS region's data buffer: a dense
 * or sparse list of (field_id, offset). field_id indexes enum koff_field, so the
 * host must serialize using the SAME KOFF_FIELD_LIST ordering. */
struct koff_wire_entry {
	uint32_t field_id;
	uint32_t _reserved;
	int64_t  offset;
};

void igloo_koff_reset(void);

#endif /* __PORTAL_OFFSETS_H__ */
