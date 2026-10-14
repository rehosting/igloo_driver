/*
 * SET_OFFSETS portal op: receive the running kernel's true struct offsets from
 * the host (recovered by kernel-lift) and install them into the runtime-offset
 * table used by KOFF()/KFIELD() (see portal_offsets.h).
 *
 * Wire format in the region data buffer (PORTAL_DATA): header.size = number of
 * struct koff_wire_entry records, each { field_id, _reserved, offset }. Entries
 * with field_id >= KF_MAX or a negative offset are ignored (forward-compatible:
 * a newer host can send fields this guest does not know without failing).
 */

#include <linux/string.h>   /* memset */
#include "portal_internal.h"
#include "portal_types.h"
#include "portal_offsets.h"

long koff_table[KF_MAX];
u8   koff_set[KF_MAX];

void igloo_koff_reset(void)
{
	memset(koff_table, 0, sizeof(koff_table));
	memset(koff_set, 0, sizeof(koff_set));
}

void handle_op_set_offsets(portal_region *mem_region)
{
	struct koff_wire_entry *entries;
	uint64_t count, i, max_by_space;
	unsigned int applied = 0;

	count = mem_region->header.size;
	entries = (struct koff_wire_entry *)PORTAL_DATA(mem_region);

	/* Never read past the region. */
	max_by_space = (CHUNK_SIZE - PORTAL_DATA_OFFSET) / sizeof(*entries);
	if (count > max_by_space)
		count = max_by_space;

	for (i = 0; i < count; i++) {
		uint32_t id = entries[i].field_id;
		int64_t off = entries[i].offset;

		if (id >= KF_MAX || off < 0)
			continue;
		koff_table[id] = (long)off;
		koff_set[id] = 1;
		applied++;
	}

	igloo_pr_debug("igloo: SET_OFFSETS applied %u/%llu offsets\n",
		       applied, (unsigned long long)count);

	/* Report how many were installed so the host can confirm the round-trip. */
	mem_region->header.size = applied;
	mem_region->header.op = HYPER_RESP_WRITE_OK;
}
