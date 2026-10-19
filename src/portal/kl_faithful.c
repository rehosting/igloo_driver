// Faithful-rehost compatibility unit.
//
// On penguin's own DONOR kernels, igloo is partly built into the kernel: the
// kernel is patched to EXPORT_SYMBOL a handful of otherwise-unexported helpers
// (access_remote_vm, arch_vma_name, _do_fork, kill_pid_info,
// shmem_kernel_file_setup) and to provide the `igloo_debug` config global. When
// igloo.ko is loaded into an UNMODIFIED VENDOR kernel (the Tier-A faithful path,
// e.g. a 5.6.3/aarch64 vendor kernel) none of that exists, so the module
// would fail to load with "Unknown symbol".
//
// This unit closes that gap. It is selected by CONFIG_IGLOO_FAITHFUL (see
// src/Kconfig); the build wires it through the profile logic in src/Makefile,
// so nothing here depends on an ad-hoc -D on the command line.
//
//   * Helper resolution DEGRADES: on a kernel that still exports
//     kallsyms_lookup_name we resolve the helpers by name; on a hardened kernel
//     that does not (CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS) we never reference it
//     (that would fail modpost): names resolve from the table the host passes
//     as ksyms= (kl_ksyms.c), and a name it didn't send leaves its kl_* pointer
//     NULL -- the call sites null-check them, so those ops degrade to FAIL and
//     OSI is driven purely by offsets. report_base_addr() (igloo_hc.c) likewise
//     degrades from a kallsyms lookup to taking a symbol's in-module address.
//
//   * Struct offsets are RECOVERED from live memory when the vendor kernel's
//     layout differs from the headers igloo was built against (config drift,
//     randstruct, or a genuinely different vendor build). See kl_recover_offsets.
#include "kl_faithful.h"
#include "igloo_debug.h"
#include <linux/kallsyms.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>

#if defined(KL_PAGE_OFFSET) && (CONFIG_PAGE_OFFSET != KL_PAGE_OFFSET)
#error "KL_PAGE_OFFSET was overridden by a later autoconf.h inclusion"
#endif

// igloo_debug is a built-in global on the donor kernels (drivers/igloobase), so
// define it here ONLY on the faithful path AND only on the eras where the kernel
// does not otherwise provide it -- otherwise it would clash with the built-in.
// A pre-4.10 vendor kernel (e.g. 2.6.36) never carries it either.
#if defined(CONFIG_IGLOO_FAITHFUL) && \
	(LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0) || \
	 (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0) && \
	  LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)))
struct igloo_debug_config igloo_debug;
#endif

int (*kl_access_remote_vm)(struct mm_struct *, unsigned long, void *, int, unsigned int);
const char *(*kl_arch_vma_name)(struct vm_area_struct *);
int (*kl_kill_pid_info)(int, struct kernel_siginfo *, struct pid *);
struct file *(*kl_shmem_kernel_file_setup)(const char *, loff_t, unsigned long);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
long (*kl_do_fork)(struct kernel_clone_args *);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
/* access_remote_vm() doesn't exist before 2.6.39 and isn't exported, and its
 * fifth argument is `int write` until 4.9 (gup_flags after): the FOLL_FORCE our
 * callers pass would make it a WRITE into the target. So until 4.6, use this
 * read-only equivalent of the mm-based core of access_process_vm(), over the
 * exported get_user_pages() (8-arg form until 4.6, tsk may be NULL), which needs
 * no symbol at all; the 2.6.36 ARM vendor config has no
 * HIGHMEM, so page_address() is the kmap. Returns bytes read, like the original.
 *
 * page_address() expands to the build tree's memory model (FLATMEM or
 * SPARSEMEM, PHYS_OFFSET, __va), which a vendor kernel can replace: the 2.6.36
 * one this targets is SPARSEMEM with a runtime DDR offset. Unless the build
 * has the kernel's own headers, map the page with vmap() instead, which leaves
 * the page -> address step to the kernel. */
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#if defined(CONFIG_IGLOO_EXACT_HEADERS)
#define kl_map_page(page)		page_address(page)
#define kl_unmap_page(addr)		do { } while (0)
#else
#define kl_map_page(page)		vmap(&(page), 1, VM_MAP, PAGE_KERNEL)
#define kl_unmap_page(addr)		vunmap(addr)
#endif
static int kl_access_remote_vm_old(struct mm_struct *mm, unsigned long addr,
				   void *buf, int len, unsigned int gup_flags)
{
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	while (len) {
		struct vm_area_struct *vma;
		struct page *page = NULL;
		int bytes, offset;
		void *kaddr;

		if (get_user_pages(NULL, mm, addr, 1, 0, 1, &page, &vma) <= 0)
			break;
		kaddr = kl_map_page(page);
		if (!kaddr) {
			put_page(page);
			break;
		}
		offset = addr & (PAGE_SIZE - 1);
		bytes = min_t(int, len, PAGE_SIZE - offset);
		memcpy(buf, (char *)kaddr + offset, bytes);
		kl_unmap_page(kaddr);
		put_page(page);
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);
	return buf - old_buf;
}
#endif

void kl_faithful_resolve(void)
{
	/* With CONFIG_IGLOO_FAITHFUL_NO_KALLSYMS, kallsyms_lookup_name() is the
	 * host's ksyms= table (kl_ksyms.c): a name it didn't send stays NULL. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	kl_access_remote_vm = kl_access_remote_vm_old;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	kl_access_remote_vm =
		(void *)kallsyms_lookup_name("access_remote_vm");
#endif	/* 4.6-4.8: int write and a new get_user_pages(); left NULL (FAIL) */
	kl_arch_vma_name =
		(void *)kallsyms_lookup_name("arch_vma_name");
	kl_kill_pid_info =
		(void *)kallsyms_lookup_name("kill_pid_info");
	kl_shmem_kernel_file_setup =
		(void *)kallsyms_lookup_name("shmem_kernel_file_setup");
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
	kl_do_fork =
		(void *)kallsyms_lookup_name("_do_fork");
#endif
	pr_info("igloo: kl_faithful_resolve: access_remote_vm=%p arch_vma_name=%p "
		"kill_pid_info=%p shmem_kernel_file_setup=%p\n",
		kl_access_remote_vm, kl_arch_vma_name, kl_kill_pid_info,
		kl_shmem_kernel_file_setup);
}

/* --- runtime offset recovery (LogicMem-style, in-guest) ---------------------
 * On a faithful vendor kernel whose .config differs from our build headers, the
 * compile-time / host-baseline struct offsets are wrong. Recover them directly
 * from live memory, anchored on `current`, and override koff_table so the
 * KFIELD-driven OSI reads use the REAL offsets.
 *
 * Recovered (each with an independent, cross-task-validated signature):
 *   task_struct.tasks       longest self-consistent same-offset list ring
 *   task_struct.comm        majority printable NUL-terminated, >=3 distinct
 *   task_struct.pid / tgid   adjacent equal ints, small, mostly distinct
 *   task_struct.real_parent  lowest ptr field a majority share and that
 *                            validates as a task (-> ppid)
 *   task_struct.mm/active_mm  adjacent ptr pair, mm NULL for kthreads else ==am
 *   task_struct.cred         real_cred==cred adjacent kptr pair to a small-usage
 *                            struct (cred internals via offsetof -> uid/gid/...)
 *
 * Honest scope: this recovers task_struct LAYOUT. cred internals (uid/gid/euid/
 * egid) and mm_struct internals are taken from build-header offsetof -- both are
 * far less config-sensitive than task_struct, but are an assumption, not a
 * recovery. start_time is left unrecovered (create_time reads 0).
 */
#include "portal_offsets.h"
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/cred.h>

#define KL_SCAN_BYTES 8192            /* task_struct is a few KB on real configs */
#define KL_MAXT       48              /* sampled task_structs for cross-validation */

static inline bool kl_is_lin(unsigned long p)
{
	if (p & (sizeof(long) - 1))
		return false;                 /* pointer-aligned; a list_head inside a
					 * task_struct is only 4-aligned on 32-bit */
#if defined(CONFIG_ARM64) || defined(__aarch64__)
	/* arm64 linear (direct) map, below the vmalloc/module region, where slab
	 * objects (task_struct, mm_struct, cred) live. VA_BITS-robust: lower bound
	 * is the TTBR1 half start, upper bound excludes vmalloc (0xffff8000...).
	 * We never dereference outside this range, so the scan cannot fault even
	 * without an exported probe_kernel_read. */
	return p >= 0xffff000000000000UL && p < 0xffff800000000000UL;
#elif defined(CONFIG_X86_64) || defined(__x86_64__)
	/* x86_64 direct map (page_offset_base default), 64TB window. */
	return p >= 0xffff888000000000UL && p < 0xffffc88000000000UL;
#elif defined(CONFIG_64BIT)
	/* Generic 64-bit: canonical higher-half kernel pointer. */
	return (p >> 48) == 0xffffUL;
#else
	/* 32-bit (e.g. armel): kernel lowmem, PAGE_OFFSET up to high_memory. The
	 * split is the build config's (2G vendor kernels put lowmem at 0x80000000). */
	return p >= PAGE_OFFSET && p < (unsigned long)high_memory;
#endif
}

/* A recovery-safe kernel pointer: the linear map (slab objects), or the inside
 * of init_task, which lives in the kernel image rather than the linear map (on
 * arm64 at 0xffff8000...). Without the second case the real tasks ring, which
 * passes through init_task, never closes, and the scan settles on a shorter
 * ring of linear-map tasks only (kthreadd's children/sibling ring): no pid 1,
 * no userspace. init_task is exported on every kernel this targets. */
static inline bool kl_is_kptr(unsigned long p)
{
	unsigned long it = (unsigned long)&init_task;

	if (p & (sizeof(long) - 1))
		return false;
	return kl_is_lin(p) || (p >= it && p < it + KL_SCAN_BYTES);
}

static int kl_ring_len(unsigned long head)
{
	unsigned long p = *(unsigned long *)head; /* head->next */
	int n = 0;
	while (kl_is_kptr(p) && p != head && n < 4096) {
		p = *(unsigned long *)p; /* node->next */
		n++;
	}
	return (p == head) ? n : -1;
}

/* Does p point at something that looks like a task_struct, judged by the
 * already-recovered pid and comm offsets? Used to validate parent pointers. */
static bool kl_ptr_is_task(unsigned long p, unsigned long pid_off, unsigned long comm_off)
{
	const char *c;
	int pid, k;
	if (!kl_is_kptr(p))
		return false;
	pid = *(const int *)(p + pid_off);
	if (pid < 0 || pid > 65535)
		return false;
	c = (const char *)(p + comm_off);
	for (k = 0; k < 16 && c[k] >= 0x20 && c[k] < 0x7f; k++)
		;
	return (k >= 1 && k < 16 && c[k] == 0);
}

void kl_recover_offsets(void)
{
#if !defined(CONFIG_IGLOO_FAITHFUL) || defined(CONFIG_IGLOO_EXACT_HEADERS)
	/* Donor kernels, or a faithful build compiled against the vendor kernel's
	 * own exact tree: build-header offsets are correct; recovery would only risk
	 * mis-firing. No-op (koff_set stays clear -> KFIELD uses offsetof). */
	return;
#else
	unsigned long base = (unsigned long)current;
	unsigned long o, toff, pid_off, comm_off;
	int best_len = -1, i, n;
	unsigned long best_o = 0;
	unsigned long tasks[KL_MAXT];
	int ntasks = 0;

	/* Fields the host set (SET_OFFSETS, from kernel-lift's trusted profile)
	 * are kept and never overwritten; only the rest are recovered. */
	for (i = 0; i < KF_MAX; i++)
		if (!koff_host[i])
			koff_set[i] = 0;

	/* 1) task_struct.tasks: longest self-consistent same-offset list ring. */
	if (koff_host[KF_task_struct__tasks]) {
		best_o = (unsigned long)koff_table[KF_task_struct__tasks];
		best_len = kl_ring_len(base + best_o);
		printk(KERN_EMERG "igloo: host task_struct.tasks = %lu (ring %d)\n", best_o, best_len);
	} else
	for (o = 0; o < KL_SCAN_BYTES; o += 8) {
		unsigned long lh = base + o;
		unsigned long nxt = ((unsigned long *)lh)[0];
		unsigned long prv = ((unsigned long *)lh)[1];
		int len;
		if (!kl_is_kptr(nxt) || !kl_is_kptr(prv) || nxt == lh)
			continue;
		if (((unsigned long *)nxt)[1] != lh || ((unsigned long *)prv)[0] != lh)
			continue;
		len = kl_ring_len(lh);
		if (len > best_len) { best_len = len; best_o = o; }
	}
	if (best_len < 2) { printk(KERN_EMERG "igloo: FAILED to recover tasks\n"); return; }
	toff = best_o;
	if (!koff_host[KF_task_struct__tasks]) {
		koff_table[KF_task_struct__tasks] = (long)toff;
		koff_set[KF_task_struct__tasks] = 1;
		printk(KERN_EMERG "igloo: RECOVERED task_struct.tasks = %lu (ring %d)\n", toff, best_len);
	}

	/* Sample up to KL_MAXT task_struct pointers from the ring. */
	tasks[ntasks++] = base;
	{
		unsigned long p = ((unsigned long *)(base + toff))[0];
		while (ntasks < KL_MAXT && kl_is_kptr(p) && (p - toff) != base) {
			tasks[ntasks++] = p - toff;
			p = ((unsigned long *)p)[0];
		}
	}

	/* 2) task_struct.comm: char[16] name. Require a MAJORITY of sampled tasks
	 * to hold a printable NUL-terminated name AND >=3 DISTINCT names (so it is
	 * the per-task comm, not a constant string field). */
	for (o = 0; !koff_host[KF_task_struct__comm] && o + 16 <= KL_SCAN_BYTES; o += 1) {
		int printable = 0, distinct = 0;
		const char *seen[KL_MAXT];
		for (n = 0; n < ntasks; n++) {
			const char *c = (const char *)(tasks[n] + o);
			int k = 0, j, dup = 0;
			while (k < 16 && c[k] >= 0x20 && c[k] < 0x7f) k++;
			if (!(k >= 1 && k < 16 && c[k] == 0)) continue;
			printable++;
			for (j = 0; j < distinct; j++)
				if (!strncmp(seen[j], c, 16)) { dup = 1; break; }
			if (!dup && distinct < KL_MAXT) seen[distinct++] = c;
		}
		if (printable >= ntasks - 1 && distinct >= 3) {
			koff_table[KF_task_struct__comm] = (long)o;
			koff_set[KF_task_struct__comm] = 1;
			printk(KERN_EMERG "igloo: RECOVERED task_struct.comm = %lu (cur=\"%s\", %d/%d printable, %d distinct)\n",
			       o, (const char *)(base + o), printable, ntasks, distinct);
			break;
		}
	}

	/* 3) task_struct.pid: pid and tgid are ADJACENT ints and EQUAL for kthreads
	 * (and single-threaded procs). Find the offset where every sampled task has
	 * v == *(+4), v in a small range, and the vs are nearly all distinct -- a
	 * strong, unambiguous pid/tgid signature. */
	for (o = 0; !koff_host[KF_task_struct__pid] && o + 8 <= KL_SCAN_BYTES; o += 4) {
		int vals[KL_MAXT], distinct = 0, ok = 1, threads = 0;
		for (n = 0; n < ntasks; n++) {
			int v = *(const int *)(tasks[n] + o);
			int tg = *(const int *)(tasks[n] + o + 4);
			int j, dup = 0;
			if (v < 0 || v > 65535 || tg < 0 || tg > 65535) { ok = 0; break; }
			/* a thread of a userspace process has pid != tgid (tgid < pid);
			 * the tasks ring holds group leaders only, but allow a few */
			if (v != tg && (tg > v || ++threads > 2)) { ok = 0; break; }
			for (j = 0; j < distinct; j++) if (vals[j] == v) { dup = 1; break; }
			if (!dup) vals[distinct++] = v;
		}
		if (ok && distinct >= ntasks - 2 && distinct >= 8) {
			koff_table[KF_task_struct__pid] = (long)o;
			koff_set[KF_task_struct__pid] = 1;
			koff_table[KF_task_struct__tgid] = (long)(o + 4);
			koff_set[KF_task_struct__tgid] = 1;
			printk(KERN_EMERG "igloo: RECOVERED task_struct.pid = %lu tgid = %lu (%d distinct)\n", o, o + 4, distinct);
			break;
		}
	}

	/* pid/comm are the anchors for the pointer-field signatures below. Without
	 * them we cannot validate parent pointers, so stop here. */
	if (!koff_set[KF_task_struct__pid] || !koff_set[KF_task_struct__comm]) {
		printk(KERN_EMERG "igloo: pid/comm not recovered; skipping ptr fields\n");
		return;
	}
	pid_off  = (unsigned long)koff_table[KF_task_struct__pid];
	comm_off = (unsigned long)koff_table[KF_task_struct__comm];

	/* Locate the well-known ancestor tasks in the sample by pid: swapper (0),
	 * init (1), kthreadd (2). These anchor the parent-pointer signature below
	 * with KNOWN pointer values, so it does not depend on how the vendor .config
	 * ordered task_struct. */
	{
	unsigned long known[3];
	int nknown = 0, kp;
	for (kp = 0; kp <= 2; kp++)
		for (n = 0; n < ntasks; n++)
			if (*(const int *)(tasks[n] + pid_off) == kp) {
				known[nknown++] = tasks[n];
				break;
			}
	/* 4) task_struct.real_parent (-> ppid). Two independent signatures, either of
	 * which is accepted (lowest matching offset), and BOTH validated across every
	 * sampled task so the walk's rp->pid deref always lands on a real task:
	 *   (a) parent-cluster: a plurality of tasks point at one of the sampled
	 *       ancestors {swapper,init,kthreadd} and few point at self (that excludes
	 *       group_leader); OR
	 *   (b) valid-task: a majority point at something whose comm/pid read like a
	 *       task and few at self -- works even when the shared parent itself is
	 *       not in the sampled ring.
	 * On a heavily reordered / randstruct vendor layout where neither signature is
	 * clean (e.g. the parent tasks are not reachable as printable-comm targets in
	 * the ring snapshot), this simply finds nothing and real_parent stays unset --
	 * ppid reads 0, and crucially no wrong offset is ever dereferenced. */
	for (o = 0; !koff_host[KF_task_struct__real_parent] && o + 8 <= KL_SCAN_BYTES; o += 8) {
		int hits = 0, self = 0, valid = 0, allok = 1, j;
		for (n = 0; n < ntasks; n++) {
			unsigned long p = *(unsigned long *)(tasks[n] + o);
			if (!kl_is_kptr(p)) { allok = 0; break; }   /* deref must be safe */
			if (p == tasks[n]) { self++; continue; }
			if (kl_ptr_is_task(p, pid_off, comm_off)) valid++;
			for (j = 0; j < nknown; j++)
				if (p == known[j]) { hits++; break; }
		}
		if (!allok || self > ntasks / 3)
			continue;
		if ((nknown >= 1 && hits >= 3 && hits >= (ntasks + 2) / 3) ||
		    valid >= (ntasks + 1) / 2) {
			koff_table[KF_task_struct__real_parent] = (long)o;
			koff_set[KF_task_struct__real_parent] = 1;
			printk(KERN_EMERG "igloo: RECOVERED task_struct.real_parent = %lu (known-hits %d, valid-task %d, self %d /%d)\n",
			       o, hits, valid, self, ntasks);
			break;
		}
	}
	}

	/* (mm/active_mm are deliberately NOT recovered here: they are not read for
	 * any OSI_PROC_ALL column, the by-pid mm ops use the exported get_task_mm
	 * accessor which needs no offset, and setting task_struct.mm would engage the
	 * walk's "user procs only" filter -- wrong for the faithful proc list, which
	 * includes kernel threads. mm_struct internals stay build-header-based.) */

	/* 5) task_struct.cred (-> uid/gid): real_cred and cred are adjacent, equal
	 * pointers to a struct cred whose first word (usage refcount) is a small
	 * positive count. The target must NOT look like a task_struct (excludes the
	 * real_parent/parent pair, whose targets' first word -- thread_info.flags --
	 * is also small). Require the signature for EVERY sampled task, so the pair
	 * cannot be a majority-only false positive and cred is a valid kptr for the
	 * whole ring (walk deref stays safe). Lowest match; cred is the 2nd of the
	 * pair. cred internals are config-stable at the head -> uid/... via offsetof. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)	/* no struct cred before */
	for (o = 0; !koff_host[KF_task_struct__cred] && o + 16 <= KL_SCAN_BYTES; o += 8) {
		int ok = 0, need = 0;
		for (n = 0; n < ntasks; n++) {
			unsigned long rc = *(unsigned long *)(tasks[n] + o);
			unsigned long cr = *(unsigned long *)(tasks[n] + o + 8);
			unsigned int usage;
			/* init_task's cred is the static init_cred in the kernel
			 * image, not a slab object: it is not held to the signature. */
			if (tasks[n] == (unsigned long)&init_task)
				continue;
			need++;
			if (!kl_is_kptr(rc) || rc != cr) break;
			/* Reject a pointer INTO the task's own object: several self-
			 * referential list/anchor fields form equal "pairs" whose target's
			 * first word is coincidentally small (e.g. base-16). cred lives in
			 * its own slab, well away from the task_struct. */
			if (rc + 64 >= tasks[n] && rc < tasks[n] + KL_SCAN_BYTES) break;
			if (kl_ptr_is_task(rc, pid_off, comm_off)) break; /* the parent pair */
			usage = *(const unsigned int *)rc;
			if (usage < 1 || usage > (1u << 20)) break;
			ok++;
		}
		if (ok == need && ok >= 8) {
			const struct cred *c0 = *(const struct cred **)(base + o + 8);
			koff_table[KF_task_struct__cred] = (long)(o + 8);
			koff_set[KF_task_struct__cred] = 1;
			koff_table[KF_cred__uid]  = offsetof(struct cred, uid);  koff_set[KF_cred__uid]  = 1;
			koff_table[KF_cred__gid]  = offsetof(struct cred, gid);  koff_set[KF_cred__gid]  = 1;
			koff_table[KF_cred__euid] = offsetof(struct cred, euid); koff_set[KF_cred__euid] = 1;
			koff_table[KF_cred__egid] = offsetof(struct cred, egid); koff_set[KF_cred__egid] = 1;
			printk(KERN_EMERG "igloo: RECOVERED task_struct.cred = %lu (uid@%zu; current uid=%u gid=%u)\n",
			       o + 8, offsetof(struct cred, uid),
			       *(const u32 *)((const char *)c0 + offsetof(struct cred, uid)),
			       *(const u32 *)((const char *)c0 + offsetof(struct cred, gid)));
			break;
		}
	}
#endif /* 2.6.29 */
#endif /* CONFIG_IGLOO_FAITHFUL */
}

/* /proc/<pid>/<name> read in the kernel, through the exported filp_open and
 * kernel_read: the kernel's own procfs formats it, so no mm_struct offset and
 * no access_remote_vm (unexported on a hardened vendor kernel) are needed.
 * Returns the bytes read, or a negative errno. */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/err.h>
#if defined(CONFIG_IGLOO_FAITHFUL) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/namei.h>
#include <linux/fs_struct.h>
/* exported from fs/namei.c; its prototype is not in a public header here */
extern int vfs_path_lookup(struct dentry *, struct vfsmount *, const char *,
			   unsigned int, struct path *);
/* Look @rel up relative to task @pid's own root, as that task would see it.
 * Our kthread's root is init_task's (rootfs); a firmware that chroots its
 * daemons (RouterOS: /init stays in rootfs, the rest run in /system) has
 * /proc only inside the chroot. The fs and fs_struct.root offsets come through KOFF; both
 * pointers of the path are sanity-checked before use. Exported calls only:
 * path_get/path_put, vfs_path_lookup, dentry_open. */
int kl_lookup_in_task_root(int pid, const char *rel, unsigned int flags, struct path *out)
{
	struct task_struct *t, *init = NULL;
	struct fs_struct *fs;
	struct path root;
	int err;

	rcu_read_lock();
	kl_for_each_process(t) {
		if (KFIELD(pid_t, t, task_struct, pid) == pid) {
			init = t;
			break;
		}
	}
	if (!init || !koff_set[KF_task_struct__fs]) {
		rcu_read_unlock();
		return -ENOENT;
	}
	fs = KFIELD(struct fs_struct *, init, task_struct, fs);
	if (!kl_is_kptr((unsigned long)fs)) {
		rcu_read_unlock();
		return -EFAULT;
	}
	root = *(struct path *)KFIELD_PTR(fs, fs_struct, root);
	if (!kl_is_kptr((unsigned long)root.mnt) || !kl_is_kptr((unsigned long)root.dentry)) {
		rcu_read_unlock();
		return -EFAULT;
	}
	path_get(&root);
	rcu_read_unlock();
	err = vfs_path_lookup(root.dentry, root.mnt, rel, flags, out);
	path_put(&root);
	return err;
}

static struct file *kl_open_in_task_root(int pid, const char *rel)
{
	const struct cred *cred;
	struct path p;
	struct file *f;
	int err = kl_lookup_in_task_root(pid, rel, 0, &p);

	if (err)
		return ERR_PTR(err);
	/* current_cred() bakes in task_struct.cred's compile-time offset */
	cred = KFIELD(const struct cred *, current, task_struct, cred);
	f = dentry_open(&p, O_RDONLY, cred);
	path_put(&p);
	return f;
}
#elif defined(CONFIG_IGLOO_FAITHFUL)
#include <linux/namei.h>
/* Before 4.14: look @rel up from our own root with the exported kern_path. This
 * does not enter a chrooted task's root (dentry_open's signature differs this
 * early); a firmware whose daemons all share the init root has /proc there. */
int kl_lookup_in_task_root(int pid, const char *rel, unsigned int flags, struct path *out)
{
	char *abs = kasprintf(GFP_KERNEL, "/%s", rel);
	int err;

	if (!abs)
		return -ENOMEM;
	err = kern_path(abs, flags, out);
	kfree(abs);
	return err;
}
#endif

long kl_read_proc_file(int pid, const char *name, char *buf, size_t len)
{
#if defined(CONFIG_IGLOO_FAITHFUL)
	char path[48];
	struct file *f;
	loff_t pos = 0;
	long n;

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	f = filp_open(path, O_RDONLY, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	if (IS_ERR(f))
		f = kl_open_in_task_root(pid, path + 1);
#endif
	if (IS_ERR(f))
		return PTR_ERR(f);
	/* seq_file may return less than asked: read to EOF or a full buffer */
	n = 0;
	while ((size_t)n < len) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		ssize_t r = kernel_read(f, buf + n, len - n, &pos);
#else
		/* the pre-4.14 kernel_read(file, offset, addr, count) */
		ssize_t r = kernel_read(f, pos, buf + n, len - n);
		if (r > 0)
			pos += r;
#endif
		if (r <= 0) {
			if (!n && r < 0)
				n = r;
			break;
		}
		n += r;
	}
	filp_close(f, NULL);
	return n;
#else
	return -ENOSYS;
#endif
}

/* mm->exe_file through the exported get_mm_exe_file (it takes a reference;
 * the caller fput()s it), so no mm_struct.exe_file offset is needed. */
struct file *kl_mm_exe_file(struct mm_struct *mm)
{
#if defined(CONFIG_IGLOO_FAITHFUL) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	return get_mm_exe_file(mm);
#elif defined(CONFIG_IGLOO_FAITHFUL) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	/* no mm->exe_file before 2.6.26: /proc/<pid>/exe was the file of the first
	 * VM_EXECUTABLE mapping, so do as it did (mmap_sem held; a reference taken) */
	struct vm_area_struct *v;
	struct file *f = NULL;

	down_read(&mm->mmap_sem);
	for (v = mm->mmap; v; v = v->vm_next) {
		if ((v->vm_flags & VM_EXECUTABLE) && v->vm_file) {
			f = v->vm_file;
			get_file(f);
			break;
		}
	}
	up_read(&mm->mmap_sem);
	return f;
#else
	return NULL;
#endif
}

/* The open fds of task @pid, through KOFF task_struct.files and files_struct.fdt
 * (both must be set by the host) and the fdtable head (max_fds, fd), into
 * @open (a bitmap of @nbits). Only NULL tests on the fd array: no struct file
 * is dereferenced. Returns max_fds, or a negative errno. */
int kl_open_fds(int pid, unsigned long *open, unsigned int nbits)
{
#if defined(CONFIG_IGLOO_FAITHFUL)
	struct task_struct *t, *task = NULL;
	struct files_struct *files;
	struct fdtable *fdt;
	unsigned int i, max;
	int ret = -ENOENT;

	if (!koff_set[KF_task_struct__files] || !koff_set[KF_files_struct__fdt])
		return -ENODATA;
	bitmap_zero(open, nbits);
	rcu_read_lock();
	kl_for_each_process(t) {
		if (KFIELD(pid_t, t, task_struct, pid) == pid) {
			task = t;
			break;
		}
	}
	if (!task)
		goto out;
	files = KFIELD(struct files_struct *, task, task_struct, files);
	ret = 0;
	if (!kl_is_kptr((unsigned long)files))
		goto out;
	fdt = KFIELD(struct fdtable *, files, files_struct, fdt);
	ret = -EFAULT;
	if (!kl_is_kptr((unsigned long)fdt) || !kl_is_kptr((unsigned long)fdt->fd))
		goto out;
	max = READ_ONCE(fdt->max_fds);
	for (i = 0; i < max && i < nbits; i++)
		if (READ_ONCE(fdt->fd[i]))
			set_bit(i, open);
	ret = max;
out:
	rcu_read_unlock();
	return ret;
#else
	return -ENOSYS;
#endif
}
