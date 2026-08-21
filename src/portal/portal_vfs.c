#include "portal_internal.h"
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>   /* seq_read / seq_read_iter, for the fallback below */
#include <linux/uio.h>        /* iov_iter_kvec */

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
 * A read/close against an unknown or already-closed handle reports -EBADF, not
 * -EINVAL. That distinction is load-bearing rather than cosmetic: -EINVAL is
 * also what kernel_read() itself returns for a file it will not serve this way,
 * so using it for both made the two indistinguishable to the host. A live
 * failure on /proc/self/status could not be attributed to either our handle
 * table or the kernel's read path without a debug build, which CI does not run.
 * -EBADF is the errno read(2) uses for a bad descriptor, so it is also simply
 * the right answer.
 *
 * fs_magic is reported on open so the host can name the filesystem it is
 * talking to (PROC_SUPER_MAGIC, SYSFS_MAGIC, ...) instead of guessing.
 *
 * WHY kernel_read() IS NOT ENOUGH ON MODERN KERNELS
 * -------------------------------------------------
 * Verified against 6.13 source, and measured live on all 10 6.13 CI combos:
 * __kernel_read() refuses a whole class of file outright --
 *
 *     if (unlikely(!file->f_op->read_iter || file->f_op->read))
 *             return warn_unsupported(file, "read");   // -EINVAL
 *
 * -- so any file that has ->read wired up, or lacks ->read_iter, comes back
 * -EINVAL after zero bytes no matter how the read is framed. That is a property
 * of the file's f_op, NOT of statefulness, and it is why some procfs files read
 * fine here while others cannot be read at all:
 *
 *   readable   /proc/version, /proc/uptime, /proc/cmdline  proc_create_single*
 *                -> proc_iter_file_ops (.read_iter only)
 *              /proc/mounts   mounts_operations (.read_iter = seq_read_iter)
 *              /sys/...       kernfs_file_fops (.read_iter)
 *   -EINVAL    /proc/<pid>/status, /stat, ...  proc_single_file_operations
 *                (.read = seq_read, no .read_iter)
 *              /proc/net/tcp, /proc/net/*      proc_net_seq_ops.proc_read
 *                = seq_read -> inode gets proc_reg_file_ops (.read, no
 *                .read_iter)
 *
 * On 4.10 there is no such guard (kernel_read -> __vfs_read, which just calls
 * ->read), which is exactly why the same paths read fine on 4.10 and fail on
 * 6.13 -- both here and in the older stateless handle_op_read_file, which uses
 * the same kernel_read.
 *
 * For the ->read == seq_read case we can do better safely: seq_read's contract
 * is that file->private_data is a struct seq_file, so seq_read_iter can be
 * called directly with a kvec iterator, skipping __kernel_read's guard. That
 * covers /proc/<pid>/*.
 *
 * The proc_reg_file_ops case (/proc/net/*) is NOT covered and deliberately so:
 * its ->read is proc_reg_read, which forwards to a proc_ops we cannot inspect
 * from a module, so there is no way to prove private_data is a seq_file. It is
 * not, for instance, in /proc/<pid>/mem, where private_data is an mm_struct --
 * guessing there would corrupt memory rather than fail. Reading those needs a
 * user-address bounce buffer in the calling task, which touches guest state and
 * is a separate decision.
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

/*
 * One read of at most @want bytes at *@pos, advancing *@pos on success.
 *
 * Prefers kernel_read(), and falls back to calling seq_read_iter() directly for
 * the ->read == seq_read files kernel_read() refuses (see the header comment).
 * The fallback is gated on 5.10+, where seq_read_iter exists and where the
 * refusal it works around was introduced.
 */
static ssize_t vfs_read_chunk(struct file *f, char *buf, size_t want, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    if (!f->f_op->read_iter && f->f_op->read == seq_read) {
        struct kvec kv = { .iov_base = buf, .iov_len = want };
        struct iov_iter it;
        struct kiocb kio;
        ssize_t n;

        init_sync_kiocb(&kio, f);
        kio.ki_pos = *pos;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        iov_iter_kvec(&it, ITER_DEST, &kv, 1, want);
#else
        iov_iter_kvec(&it, READ, &kv, 1, want);
#endif
        n = seq_read_iter(&kio, &it);
        if (n > 0)
            *pos = kio.ki_pos;
        return n;
    }
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    return kernel_read(f, buf, want, pos);
#else
    {
        ssize_t n = kernel_read(f, *pos, buf, want);
        if (n > 0)
            *pos += n;
        return n;
    }
#endif
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
        res->error = -EBADF;    /* unknown or already-closed handle; NOT
                                 * -EINVAL, which kernel_read() also returns
                                 * and which would hide which one failed */
        igloo_pr_debug("igloo: vfs_read: bad handle %u\n", handle);
        goto out;
    }

    /*
     * Read from the file's own position and write it back, so consecutive reads
     * walk the file the way read(2) would. This is the whole point of the op:
     * a seq_file must be consumed sequentially from one open file.
     */
    pos = f->f_pos;
    n = vfs_read_chunk(f, payload, want, &pos);
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
        res->error = -EBADF;
    } else {
        filp_close(vfs_slots[slot].f, NULL);
        vfs_slots[slot].f = NULL;
        vfs_slots[slot].gen++;   /* invalidate any handle still held for it */
    }
    mutex_unlock(&vfs_lock);

    mem_region->header.size = sizeof(*res);
    mem_region->header.op = HYPER_RESP_READ_OK;
}
