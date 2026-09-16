// SPDX-License-Identifier: GPL-2.0
/*
 * Per-syscall portal round-trip cost. See syscost_stats.h for what this can
 * and cannot be trusted to measure before reading any number it produces.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/sort.h>
#include "portal_internal.h"
#include "syscost_stats.h"

struct syscost_slot {
    char name[IGLOO_SYSCOST_NAMELEN];
    u64 count;
    u64 total_ns;
    u64 max_ns;
    bool used;
};

static struct syscost_slot syscost_table[IGLOO_SYSCOST_SLOTS];
static DEFINE_SPINLOCK(syscost_lock);
static bool syscost_on;          /* OFF by default: an always-on instrument
                                  * would be one more thing in the path this
                                  * very module exists to price. */
static u64 syscost_calls;
static u64 syscost_total_ns;
static u64 syscost_dropped;
static u64 syscost_names;

bool igloo_syscost_enabled(void)
{
    return READ_ONCE(syscost_on);
}

/* djb2 over the name. Only used to pick a starting slot; correctness comes
 * from the strncmp below, so a collision costs a probe and never a misfile. */
static inline u32 syscost_hash(const char *s)
{
    u32 h = 5381;

    while (*s)
        h = ((h << 5) + h) + (u8)(*s++);
    return h;
}

void igloo_syscost_record(const char *name, u64 ns)
{
    unsigned long flags;
    u32 idx;
    int probe;
    const char *nm = name ? name : "(anon)";

    if (!READ_ONCE(syscost_on))
        return;

    spin_lock_irqsave(&syscost_lock, flags);
    syscost_calls++;
    syscost_total_ns += ns;

    idx = syscost_hash(nm) % IGLOO_SYSCOST_SLOTS;
    for (probe = 0; probe < IGLOO_SYSCOST_SLOTS; probe++) {
        struct syscost_slot *s = &syscost_table[idx];

        if (!s->used) {
            strncpy(s->name, nm, IGLOO_SYSCOST_NAMELEN - 1);
            s->name[IGLOO_SYSCOST_NAMELEN - 1] = '\0';
            s->used = true;
            syscost_names++;
        }
        if (!strncmp(s->name, nm, IGLOO_SYSCOST_NAMELEN - 1)) {
            s->count++;
            s->total_ns += ns;
            if (ns > s->max_ns)
                s->max_ns = ns;
            spin_unlock_irqrestore(&syscost_lock, flags);
            return;
        }
        idx = (idx + 1) % IGLOO_SYSCOST_SLOTS;
    }
    /* Table full and this name is not in it. Counted, not aliased. */
    syscost_dropped++;
    spin_unlock_irqrestore(&syscost_lock, flags);
}

/* Caller holds syscost_lock. */
static void syscost_reset_locked(void)
{
    memset(syscost_table, 0, sizeof(syscost_table));
    syscost_calls = 0;
    syscost_total_ns = 0;
    syscost_dropped = 0;
    syscost_names = 0;
}

static int syscost_cmp(const void *a, const void *b)
{
    const struct igloo_syscost_entry *x = a, *y = b;

    if (x->total_ns < y->total_ns)
        return 1;                       /* descending */
    if (x->total_ns > y->total_ns)
        return -1;
    return 0;
}

void handle_op_syscall_cost_stats(portal_region *mem_region)
{
    struct igloo_syscost_report *r =
        (struct igloo_syscost_report *)PORTAL_DATA(mem_region);
    u64 cmd = mem_region->header.addr;
    unsigned long flags;
    int i, n = 0;

    spin_lock_irqsave(&syscost_lock, flags);
    if (cmd == IGLOO_SYSCOST_CMD_ENABLE) {
        syscost_reset_locked();
        WRITE_ONCE(syscost_on, true);
    } else if (cmd == IGLOO_SYSCOST_CMD_DISABLE) {
        WRITE_ONCE(syscost_on, false);
    }

    memset(r, 0, sizeof(*r));
    r->enabled = READ_ONCE(syscost_on) ? 1 : 0;
    r->n_calls = syscost_calls;
    r->total_ns = syscost_total_ns;
    r->dropped = syscost_dropped;
    r->names_seen = syscost_names;

    for (i = 0; i < IGLOO_SYSCOST_SLOTS &&
                n < IGLOO_SYSCOST_REPORT_ENTRIES; i++) {
        if (!syscost_table[i].used)
            continue;
        memcpy(r->entries[n].name, syscost_table[i].name,
               IGLOO_SYSCOST_NAMELEN);
        r->entries[n].count = syscost_table[i].count;
        r->entries[n].total_ns = syscost_table[i].total_ns;
        r->entries[n].max_ns = syscost_table[i].max_ns;
        n++;
    }
    spin_unlock_irqrestore(&syscost_lock, flags);

    /* Most expensive first, so a truncated report keeps what matters. */
    sort(r->entries, n, sizeof(r->entries[0]), syscost_cmp, NULL);
    r->n_entries = n;

    mem_region->header.size = sizeof(*r);
    mem_region->header.op = HYPER_RESP_READ_OK;
}
