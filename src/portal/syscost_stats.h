/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-syscall cost accounting for the portal round trip.
 *
 * WHY THIS EXISTS. A pyplugin-hooked syscall was measured at 95.880 us against
 * an unhooked one's 1.161 us -- 83x, on bugbench's own architecture, with an
 * injected-delay control passing. That number came from a HOST clock, which
 * can say what the whole round trip cost but cannot say where inside it the
 * time went, and in particular cannot separate the emulated kernel from the
 * driver's hypercall. A host-side observer only ever learns whether the HOST
 * was told, never whether the guest trapped.
 *
 * The scoped experiment built to separate them could not: the clock is
 * delivered by a hooked marker syscall, and analysis_scope gates hooks off, so
 * the instrument gated away its own clock. This is the measurement from the
 * other side of the trap.
 *
 * WHAT IT MEASURES. ktime brackets around do_hyp() -- the igloo_portal() call
 * that suspends the guest and hands the syscall to the host -- accumulated per
 * syscall name as {count, total_ns, max_ns}.
 *
 * WHAT IT CANNOT BE ASSUMED TO MEASURE. Guest ktime during a hypercall is not
 * obviously meaningful: the guest is stopped while the host works, and whether
 * its clock advances depends on the timekeeping the emulator presents. This
 * instrument is therefore NOT to be trusted until a known host-side burn shows
 * up in total_ns. `enabled` starting false and a dedicated `control_ns` field
 * exist for exactly that check -- see the host-side validator. A number here
 * that has not been validated against an injected delay is a number that might
 * be measuring nothing.
 */
#ifndef __IGLOO_SYSCOST_STATS_H__
#define __IGLOO_SYSCOST_STATS_H__

#include <linux/types.h>

/* Internal table size. Open-addressed by normalized-name hash; a syscall that
 * cannot claim a slot is counted in `dropped` rather than silently misfiled
 * under another name, because a stats table that lies by aliasing is worse
 * than one that admits it ran out of room. */
#define IGLOO_SYSCOST_SLOTS 256
/* Entries returned in one portal read. The data area is PAGE_SIZE minus two
 * headers; 64 x 48 bytes leaves comfortable room. */
#define IGLOO_SYSCOST_REPORT_ENTRIES 64
#define IGLOO_SYSCOST_NAMELEN 24

/* Sub-commands, passed in the request's header.addr. */
enum igloo_syscost_cmd {
    IGLOO_SYSCOST_CMD_READ = 0,
    IGLOO_SYSCOST_CMD_ENABLE = 1,   /* enable AND reset */
    IGLOO_SYSCOST_CMD_DISABLE = 2,
};

struct igloo_syscost_entry {
    char name[IGLOO_SYSCOST_NAMELEN];
    u64 count;
    u64 total_ns;
    u64 max_ns;
};

/* Read by the host through DWARF like every other portal struct, so adding a
 * field needs no host-side layout change. */
struct igloo_syscost_report {
    u64 enabled;
    u64 n_calls;        /* hypercalls bracketed since the last enable */
    u64 total_ns;       /* summed across every syscall name */
    u64 dropped;        /* firings whose name found no free slot */
    u64 n_entries;      /* entries populated below */
    u64 names_seen;     /* distinct names, which may exceed n_entries */
    struct igloo_syscost_entry entries[IGLOO_SYSCOST_REPORT_ENTRIES];
};

/* Bracket one portal round trip. `ns` is the measured duration; `name` is the
 * normalized syscall name and may be NULL. No-op unless enabled, so the cost
 * when nobody asked is one predictable-branch read. */
void igloo_syscost_record(const char *name, u64 ns);
bool igloo_syscost_enabled(void);

#endif /* __IGLOO_SYSCOST_STATS_H__ */
