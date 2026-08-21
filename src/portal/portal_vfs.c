#include "portal_internal.h"
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mutex.h>

/*
 * Sequential VFS read bridge: vfs_open / vfs_read / vfs_close.
 *
 * WHY THIS EXISTS
 * ---------------
 * handle_op_read_file is stateless: every call does filp_open, reads at an
 * offset, then filp_close. That is fine for a regular file, whose bytes are at
 * stable offsets, and wrong for a synthetic filesystem. procfs, sysfs and
 * debugfs generate their contents when the file is opened and hand it out
 * through sequential reads of that one open file; the files report st_size 0,
 * and a seq_file's byte offset is not a stable cursor into a fixed object. So a
 * multi-chunk read re-generates the content per chunk, and even a single read
 * gives the host no way to learn WHY it got nothing.
 *
 * These ops keep the struct file open across reads, so the kernel's own f_pos
 * advances -- the same thing that happens when a guest process cats the file.
 *
 * ERRORS ARE DATA, NOT ABSENCE
 * ----------------------------
 * Every handler returns HYPER_RESP_READ_OK with a result struct carrying an
 * explicit negative errno. Signalling failure by returning no data (what
 * READ_FILE_FAIL does) is precisely what made an unreadable file
 * indistinguishable from an empty one, so a caller could not tell "/proc is not
 * readable" from "there are no processes". The errno also makes the failure
 * diagnosable: -ENOENT means the path is not there, -EACCES a permission
 * problem, -EINVAL a file the kernel will not let us read this way.
 *
 * fs_magic is reported on open so the host can name the filesystem it is
 * talking to (PROC_SUPER_MAGIC, SYSFS_MAGIC, ...) instead of guessing.
 */

#define VFS_SLOTS 16

struct vfs_slot {
    struct file *f;
    u32 gen;                  /* bumped on close, so a stale handle is rejected */
    unsigned long opened_at;  /* jiffies; used to reclaim the oldest slot */
};

static struct vfs_slot vfs_slots[VFS_SLOTS];
static DEFINE_MUTEX(vfs_lock);

/*
 * Handle layout: (gen << 8) | (slot + 1). The +1 keeps 0 permanently invalid,
 * so a zeroed/unset handle can never accidentally address slot 0, and the
 * generation makes a read after close fail loudly instead of hitting whatever
 * file has since taken the slot.
 */
static inline u32 vfs_mk_handle(u32 slot, u32 gen)
{
    return (gen << 8) | (slot + 1);
}

static struct file *vfs_get(u32 handle)
{
    int slot = (int)(handle & 0xff) - 1;

    if (slot < 0 || slot >= VFS_SLOTS)
        return NULL;
    if (!vfs_slots[slot].f)
        return NULL;
    if (vfs_slots[slot].gen != (handle >> 8))
        return NULL;
    return vfs_slots[slot].f;
}

/* Caller holds vfs_lock. Returns a free slot, reclaiming the oldest if full. */
static int vfs_claim_slot(void)
{
    int i, oldest = 0;

    for (i = 0; i < VFS_SLOTS; i++) {
        if (!vfs_slots[i].f)
            return i;
        if (time_before(vfs_slots[i].opened_at, vfs_slots[oldest].opened_at))
            oldest = i;
    }
    /*
     * All slots busy: the host leaked handles (a crashed generator, a plugin
     * that forgot to close). Reclaim the oldest rather than failing forever --
     * a leak must degrade into a stale-handle error for one reader, not a
     * permanent inability to read any file. Loud, because it is a host bug.
     */
    printk(KERN_WARNING "IGLOO: vfs handle table full, reclaiming slot %d "
           "(host leaked a handle?)\n", oldest);
    filp_close(vfs_slots[oldest].f, NULL);
    vfs_slots[oldest].f = NULL;
    vfs_slots[oldest].gen++;
    return oldest;
}

void handle_op_vfs_open(portal_region *mem_region)
{
    char path[256];
    struct file *f;
    struct vfs_open_result *res;
    int slot;

    /* Copy the path out before the result struct overwrites the data area. */
    strncpy(path, PORTAL_DATA(mem_region), sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    res = (struct vfs_open_result *)PORTAL_DATA(mem_region);
    memset(res, 0, sizeof(*res));

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        res->error = (int32_t)PTR_ERR(f);
        igloo_pr_debug("igloo: vfs_open('%s') failed: %d\n", path, res->error);
        goto out;
    }

    if (f->f_inode && f->f_inode->i_sb)
        res->fs_magic = (uint64_t)f->f_inode->i_sb->s_magic;

    mutex_lock(&vfs_lock);
    slot = vfs_claim_slot();
    vfs_slots[slot].f = f;
    vfs_slots[slot].opened_at = jiffies;
    res->handle = vfs_mk_handle((u32)slot, vfs_slots[slot].gen);
    mutex_unlock(&vfs_lock);

    igloo_pr_debug("igloo: vfs_open('%s') -> handle %u (fs_magic %#llx)\n",
                   path, res->handle, (unsigned long long)res->fs_magic);
out:
    mem_region->header.size = sizeof(*res);
    mem_region->header.op = HYPER_RESP_READ_OK;
}

void handle_op_vfs_read(portal_region *mem_region)
{
    u32 handle = (u32)mem_region->header.addr;
    size_t want = (size_t)mem_region->header.size;
    struct vfs_read_result *res = (struct vfs_read_result *)PORTAL_DATA(mem_region);
    char *payload = (char *)PORTAL_DATA(mem_region) + sizeof(*res);
    size_t maxlen = CHUNK_SIZE - sizeof(*res) - 1;
    struct file *f;
    loff_t pos;
    ssize_t n;

    memset(res, 0, sizeof(*res));
    if (want == 0 || want > maxlen)
        want = maxlen;

    mutex_lock(&vfs_lock);
    f = vfs_get(handle);
    if (!f) {
        mutex_unlock(&vfs_lock);
        res->error = -EINVAL;   /* unknown or already-closed handle */
        igloo_pr_debug("igloo: vfs_read: bad handle %u\n", handle);
        goto out;
    }

    /*
     * Read from the file's own position and write it back, so consecutive reads
     * walk the file the way read(2) would. This is the whole point of the op:
     * a seq_file must be consumed sequentially from one open file.
     */
    pos = f->f_pos;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    n = kernel_read(f, payload, want, &pos);
#else
    n = kernel_read(f, pos, payload, want);
    if (n > 0)
        pos += n;
#endif
    if (n >= 0)
        f->f_pos = pos;
    mutex_unlock(&vfs_lock);

    if (n < 0) {
        res->error = (int32_t)n;
        igloo_pr_debug("igloo: vfs_read(handle %u) failed: %zd\n", handle, n);
        goto out;
    }
    /* n == 0 is EOF, which is a successful read of nothing -- NOT an error.
     * handle_op_read_file conflates the two and reports EOF as READ_FILE_FAIL. */
    res->nbytes = (uint32_t)n;
    res->eof = (n == 0) ? 1 : 0;

out:
    mem_region->header.size = sizeof(*res) + res->nbytes;
    mem_region->header.op = HYPER_RESP_READ_OK;
}

void handle_op_vfs_close(portal_region *mem_region)
{
    u32 handle = (u32)mem_region->header.addr;
    struct vfs_close_result *res =
        (struct vfs_close_result *)PORTAL_DATA(mem_region);
    int slot = (int)(handle & 0xff) - 1;

    memset(res, 0, sizeof(*res));

    mutex_lock(&vfs_lock);
    if (!vfs_get(handle)) {
        res->error = -EINVAL;
    } else {
        filp_close(vfs_slots[slot].f, NULL);
        vfs_slots[slot].f = NULL;
        vfs_slots[slot].gen++;   /* invalidate any handle still held for it */
    }
    mutex_unlock(&vfs_lock);

    mem_region->header.size = sizeof(*res);
    mem_region->header.op = HYPER_RESP_READ_OK;
}
