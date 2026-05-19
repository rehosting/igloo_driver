#include "portal_internal.h"
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#define PORTALCALL_SYSCALL_MAGIC 0xc1d1e1f1UL

struct portalcall_magic_entry {
    u32 magic;
    struct hlist_node node;
    struct rcu_head rcu;
};

static DEFINE_HASHTABLE(portalcall_magic_table, 8);
static DEFINE_SPINLOCK(portalcall_magic_lock);
static bool portalcall_fastpath_enabled;

bool portalcall_fastpath_register_magic(u32 user_magic)
{
    struct portalcall_magic_entry *entry;

    spin_lock(&portalcall_magic_lock);
    hash_for_each_possible(portalcall_magic_table, entry, node, user_magic) {
        if (entry->magic == user_magic) {
            spin_unlock(&portalcall_magic_lock);
            return true;
        }
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock(&portalcall_magic_lock);
        return false;
    }

    entry->magic = user_magic;
    hash_add_rcu(portalcall_magic_table, &entry->node, user_magic);
    spin_unlock(&portalcall_magic_lock);
    return true;
}
EXPORT_SYMBOL(portalcall_fastpath_register_magic);

void portalcall_fastpath_set_enabled(bool enabled)
{
    WRITE_ONCE(portalcall_fastpath_enabled, enabled);
}
EXPORT_SYMBOL(portalcall_fastpath_set_enabled);

bool portalcall_fastpath_is_enabled(void)
{
    return READ_ONCE(portalcall_fastpath_enabled);
}
EXPORT_SYMBOL(portalcall_fastpath_is_enabled);

static bool portalcall_magic_is_registered(u32 user_magic)
{
    struct portalcall_magic_entry *entry;
    bool registered = false;

    rcu_read_lock();
    hash_for_each_possible_rcu(portalcall_magic_table, entry, node, user_magic) {
        if (entry->magic == user_magic) {
            registered = true;
            break;
        }
    }
    rcu_read_unlock();

    return registered;
}

bool portalcall_fastpath_should_skip(bool is_sendto,
                                     int argc,
                                     const unsigned long args[])
{
    unsigned long magic;
    unsigned long user_magic;

    if (!READ_ONCE(portalcall_fastpath_enabled) || !is_sendto ||
            !args || argc < 2) {
        return false;
    }

    magic = igloo_syscall_arg_value(args, 0);
    if ((magic & 0xffffffffUL) != PORTALCALL_SYSCALL_MAGIC) {
        return false;
    }

    user_magic = igloo_syscall_arg_value(args, 1);
    return !portalcall_magic_is_registered((u32)user_magic);
}
EXPORT_SYMBOL(portalcall_fastpath_should_skip);

void handle_op_register_portalcall_magic(portal_region *mem_region)
{
    if (!portalcall_fastpath_register_magic((u32)mem_region->header.addr)) {
        portalcall_fastpath_set_enabled(false);
        mem_region->header.op = HYPER_RESP_WRITE_FAIL;
        return;
    }
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}

void handle_op_set_portalcall_fastpath(portal_region *mem_region)
{
    portalcall_fastpath_set_enabled(mem_region->header.addr != 0);
    mem_region->header.op = HYPER_RESP_WRITE_OK;
}
