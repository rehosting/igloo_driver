// External hyperfs module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/hashtable.h>
#include <linux/gfp.h>
#include <linux/time.h>
#include <hypercall.h>
#include "igloo.h"
#include "hyperfs_consts.h"
#include "portal.h"
#include "ioctl_hc.h"
#include "hyperfs.h"
#include "igloo_hypercall_consts.h"
#include <linux/kallsyms.h>
#include "portal_hyperfs.h"  // added


#define HYPERFS_DEBUG 0

struct hyperfs_tree {
	bool is_dir;
	struct inode *inode;
	const char *path;
	struct hlist_head dir_entries;
};

struct hyperfs_tree_dir_entry {
	struct hlist_node node;
	const char *name;
	struct hyperfs_tree *tree;
};

struct hyperfs {
	const char *passthrough_path;
	struct hyperfs_tree *tree;
	const char *fs_name; // added
};

// Must be castable from real_ctx for hyperfs_real_iter_actor
struct hyperfs_iterate_data {
	struct dir_context real_ctx;
	struct dir_context *hyperfs_ctx;
	struct hyperfs_tree *tree;
};

enum {
	HYPERFS_OPT_PASSTHROUGH_PATH,
	HYPERFS_OPT_ERR,
	HYPERFS_OPT_FS_NAME,
};

static const match_table_t hyperfs_tokens = {
	{ HYPERFS_OPT_PASSTHROUGH_PATH, "passthrough_path=%s" },
	{ HYPERFS_OPT_ERR, NULL },
	{ HYPERFS_OPT_FS_NAME, "fs_name=%s" },
};

enum { DEV_MODE = S_IFREG | 0666, DIR_MODE = S_IFDIR | 0777 };
struct hyperfs_data {
	int type;
	const char *path;
	union {
		struct {
			char *buf;
			size_t size;
			loff_t offset;
		} __packed read;
		struct {
			const char *buf;
			size_t size;
			loff_t offset;
		} __packed write;
		struct {
			unsigned int cmd;
			void *data;
		} __packed ioctl;
		struct {
			loff_t *size;
		} __packed getattr;
	} __packed;
} __packed;


ssize_t (*real_vfs_read)(struct file *, char __user *, size_t, loff_t *);
ssize_t (*real_vfs_write)(struct file *, const char __user *, size_t, loff_t *);

static struct inode *hyperfs_new_inode(struct super_block *sb,
				       struct hyperfs_tree *tree);
static struct inode *hyperfs_wrap_real_inode(struct super_block *sb,
					     struct inode *real);

static void hyperfs_tree_free(const struct hyperfs_tree *tree)
{
	struct hyperfs_tree_dir_entry *entry;
	struct hlist_node *tmp;

	if (!tree)
		return;

	hlist_for_each_entry_safe(entry, tmp, &tree->dir_entries, node) {
		hyperfs_tree_free(entry->tree);
		kfree(entry->name);
		kfree(entry);
	}

	iput(tree->inode);
	kfree(tree->path);
	kfree(tree);
}

#if HYPERFS_DEBUG
static void hyperfs_tree_print(int level, const struct hyperfs_tree *tree)
{
	struct hyperfs_tree_dir_entry *entry;

	if (tree) {
		pr_alert("%*s%s: %s inode=%p", level, "", tree->path,
			 tree->is_dir ? "dir" : "file", tree->inode);
		hlist_for_each_entry(entry, &tree->dir_entries, node) {
			pr_alert("%*sdent: %s", level + 1, "", entry->name);
			hyperfs_tree_print(level + 2, entry->tree);
		}
	} else {
		pr_alert("%*s(null)", level, "");
	}
}
#endif

static struct hyperfs_tree *hyperfs_dir_lookup(struct hlist_head *entries,
					       const char *comp,
					       size_t comp_len)
{
	struct hyperfs_tree_dir_entry *entry;
	hlist_for_each_entry(entry, entries, node) {
		if (!strncmp(comp, entry->name, comp_len) &&
		    strlen(entry->name) == comp_len) {
			return entry->tree;
		}
	}
	return NULL;
}

static struct hyperfs_tree *hyperfs_tree_make_dirs(struct super_block *sb,
						   struct hyperfs_tree *tree,
						   char *path)
{
	const char *comp, *path_origin, *path_copy;
	char *path_dir;
	struct hyperfs_tree *child;
	int err;

	path_origin = path;
	path_copy = kstrdup(path, GFP_KERNEL);
	if (!path_copy) {
		err = -ENOMEM;
		goto out;
	}

	while ((comp = strsep(&path, "/")) != NULL) {
		if (!*comp)
			continue;

		BUG_ON(!tree->is_dir);

		child = hyperfs_dir_lookup(&tree->dir_entries, comp,
					   strlen(comp));

		if (child) {
			if (!child->is_dir) {
				pr_err("hyperfs: a hyperfile path is both a directory and a file\n");
				err = -EINVAL;
				goto out_free_path;
			}

			tree = child;

		} else {
			struct hyperfs_tree_dir_entry *entry =
				kzalloc(sizeof(struct hyperfs_tree_dir_entry),
					GFP_KERNEL);
			if (!entry) {
				err = -ENOMEM;
				goto out_free_path;
			}

			hlist_add_head(&entry->node, &tree->dir_entries);

			entry->name = kstrdup(comp, GFP_KERNEL);
			if (!entry->name) {
				err = -ENOMEM;
				kfree(entry);
				goto out_free_path;
			}

			entry->tree = kzalloc(sizeof(struct hyperfs_tree),
					      GFP_KERNEL);
			if (!entry->tree) {
				err = -ENOMEM;
				kfree(entry->name);
				kfree(entry);
				goto out_free_path;
			}

			entry->tree->is_dir = true;

			path_dir = kstrdup(path_copy, GFP_KERNEL);
			if (!path_dir) {
				err = -ENOMEM;
				kfree(entry->tree);
				kfree(entry->name);
				kfree(entry);
				goto out_free_path;
			}
			if (path)
				path_dir[path - path_origin] = '\0';
			entry->tree->path = path_dir;

			entry->tree->inode = hyperfs_new_inode(sb, entry->tree);
			if (!entry->tree->inode) {
				err = -ENOMEM;
				kfree(entry->tree->path);
				kfree(entry->tree);
				kfree(entry->name);
				kfree(entry);
				goto out_free_path;
			}

			tree = entry->tree;
		}
	}
	return tree;

out_free_path:
	kfree(path_copy);
out:
	return ERR_PTR(err);
}

static int hyperfs_tree_add_hyperfile(struct super_block *sb,
				      struct hyperfs_tree *tree, char *path)
{
	int err;
	char *path_copy, *last_slash, *dirname, *basename;
	struct hyperfs_tree *dir;
	struct hyperfs_tree_dir_entry *entry;

	path_copy = kstrdup(path, GFP_KERNEL);
	if (!path_copy) {
		err = -ENOMEM;
		goto out;
	}

	last_slash = strrchr(path, '/');
	if (!last_slash) {
		pr_err("hyperfs: hyperfile path has no slash\n");
		err = -EINVAL;
		goto out;
	}
	*last_slash = '\0';
	dirname = path;
	basename = last_slash + 1;

	dir = hyperfs_tree_make_dirs(sb, tree, dirname);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto out;
	}
	BUG_ON(!dir->is_dir);

	if (hyperfs_dir_lookup(&dir->dir_entries, basename, strlen(basename))) {
		pr_err("hyperfs: a hyperfile path is specified twice or both a directory and a file\n");
		err = -EINVAL;
		goto out;
	}

	entry = kzalloc(sizeof(struct hyperfs_tree_dir_entry), GFP_KERNEL);
	if (!entry) {
		err = -ENOMEM;
		goto out;
	}

	hlist_add_head(&entry->node, &dir->dir_entries);

	entry->name = kstrdup(basename, GFP_KERNEL);
	if (!entry->name) {
		err = -ENOMEM;
		goto out;
	}

	entry->tree = kzalloc(sizeof(struct hyperfs_tree), GFP_KERNEL);
	if (!entry->tree) {
		err = -ENOMEM;
		goto out;
	}

	entry->tree->is_dir = false;
	entry->tree->path = path_copy;

	entry->tree->inode = hyperfs_new_inode(sb, entry->tree);
	if (!entry->tree->inode) {
		err = -ENOMEM;
		goto out;
	}

	return 0;

out:
	kfree(path_copy);
	return err;
}

static struct hyperfs_tree *hyperfs_tree_build(struct super_block *sb)
{
	struct hyperfs_tree *root = NULL;
	char **paths = NULL;
	int err = -ENOMEM;
	size_t i, num_hyperfiles = 0;

	root = kzalloc(sizeof(struct hyperfs_tree), GFP_KERNEL);
	if (!root)
		goto out;

	root->is_dir = true;

	root->path = kstrdup("/", GFP_KERNEL);
	if (!root->path)
		goto out;

	root->inode = hyperfs_new_inode(sb, root);
	if (!root->inode)
		goto out;

	igloo_hypercall2(IGLOO_HYPERFS_MAGIC, HYP_GET_NUM_HYPERFILES,
			 (long)&num_hyperfiles);

	paths = kcalloc(num_hyperfiles, sizeof(*paths), GFP_KERNEL);
	if (!paths)
		goto out;

	for (i = 0; i < num_hyperfiles; i++) {
		paths[i] = kzalloc(PATH_MAX, GFP_KERNEL);
		if (!paths[i])
			goto out;
	}

	igloo_hypercall2(IGLOO_HYPERFS_MAGIC, HYP_GET_HYPERFILE_PATHS, (long)paths);

	for (i = 0; i < num_hyperfiles; i++) {
		err = hyperfs_tree_add_hyperfile(sb, root, paths[i]);
		if (err)
			goto out;
	}

	err = 0;

out:
	if (paths) {
		for (i = 0; i < num_hyperfiles; i++)
			kfree(paths[i]);
		kfree(paths);
	}

	if (err) {
		if (root) {
			kfree(root->path);
			iput(root->inode);
		}
		kfree(root);
		return ERR_PTR(err);
	} else {
		return root;
	}
}

static void page_in_hyperfs_data(struct hyperfs_data *data)
{
	volatile unsigned char x = 0;
	size_t i;

	for (i = 0; i < sizeof(*data); i++)
		x += ((unsigned char *)data)[i];
	for (i = 0; data->path[i]; i++)
		x += data->path[i];
	switch (data->type) {
	case HYP_READ:
		for (i = 0; i < data->read.size; i++)
			x += data->read.buf[i];
		break;
	case HYP_WRITE:
		for (i = 0; i < data->write.size; i++)
			x += data->write.buf[i];
		break;
	case HYP_GETATTR:
		for (i = 0; i < sizeof(*data->getattr.size); i++)
			x += ((unsigned char *)data->getattr.size)[i];
		break;
	}
}

static int hyp_file_op(struct hyperfs_data data)
{
	unsigned long err = HYP_RETRY;

	do {
		page_in_hyperfs_data(&data);
		err = igloo_portal(IGLOO_HYPERFS_MAGIC, HYP_FILE_OP,
				       (unsigned long)&data);
	} while (err == HYP_RETRY);
	return err;
}

static const char *hyperfs_real_path_name(struct dentry *dentry)
{
	struct hyperfs *fs = dentry->d_sb->s_fs_info;
	char *real_name = NULL, *dentry_path_buf = NULL, *dentry_path;
	int err = 0;

	real_name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!real_name) {
		err = -ENOMEM;
		goto out;
	}

	dentry_path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!dentry_path_buf) {
		err = -ENOMEM;
		goto out;
	}

	dentry_path = dentry_path_raw(dentry, dentry_path_buf, PATH_MAX);
	if (IS_ERR(dentry_path)) {
		err = PTR_ERR(dentry_path);
		goto out;
	}

	err = snprintf(real_name, PATH_MAX, "%s/%s", fs->passthrough_path,
		       dentry_path);
	err = err >= PATH_MAX ? -ENAMETOOLONG : 0;

out:
	kfree(dentry_path_buf);
	if (err) {
		kfree(real_name);
		return ERR_PTR(err);
	} else
		return real_name;
}

static int hyperfs_real_path(struct dentry *dentry, struct path *real_path)
{
	int err = 0;
	const char *real_name = hyperfs_real_path_name(dentry);

	if (IS_ERR(real_name))
		return PTR_ERR(real_name);

	err = kern_path(real_name, 0, real_path);

	kfree(real_name);
	return err;
}

static struct dentry *hyperfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct hyperfs *fs = sb->s_fs_info;
	struct path real_path;
	struct dentry *real_dentry;
	struct inode *wrap_inode;
	int err = 0;
	struct file_operations *reg_fops = NULL;
	char *path_buf = NULL, *rel_path = NULL;

	// First try dynamic hyperfile via portal_hyperfs
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (path_buf) {
		rel_path = dentry_path_raw(dentry, path_buf, PATH_MAX);
		if (!IS_ERR(rel_path) && fs && fs->fs_name)
			reg_fops = hyperfs_lookup_file(fs->fs_name, rel_path);
		kfree(path_buf);
	}
	if (reg_fops) {
		struct inode *inode = new_inode(sb);
		if (!inode) {
			err = -ENOMEM;
			goto out;
		}
		inode->i_ino = get_next_ino();
		inode->i_mode = DEV_MODE;
		inode->i_flags |= S_NOCMTIME;
#ifdef CONFIG_FS_POSIX_ACL
		inode->i_acl = inode->i_default_acl = ACL_DONT_CACHE;
#endif
		inode->i_fop = reg_fops;
		d_add(dentry, inode);
		goto out;
	}

	// Fallback to passthrough
	err = hyperfs_real_path(dentry, &real_path);
	if (err == -ENOENT) {
		/* Report the full path of the missing entry (not just parent) */
		char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (path_buf) {
			char *full_path = dentry_path_raw(dentry, path_buf, PATH_MAX);
			if (!IS_ERR(full_path)) {
				igloo_enoent_path(full_path);
			} else {
				igloo_enoent(dentry); /* Fallback */
			}
			kfree(path_buf);
		} else {
			igloo_enoent(dentry); /* Fallback */
		}
		err = 0; // Clear error after reporting
		d_add(dentry, NULL);
		goto out;
	}
	if (err < 0)
		goto out;

	real_dentry = dget(real_path.dentry);
	path_put(&real_path);

	wrap_inode = hyperfs_wrap_real_inode(sb, d_inode(real_dentry));
	if (!wrap_inode) {
		dput(real_dentry);
		err = -ENOMEM;
		goto out;
	}

	dentry->d_fsdata = real_dentry;
	d_add(dentry, wrap_inode);

out:
	return err < 0 ? ERR_PTR(err) : NULL;
}

static int hyperfs_open(struct inode *inode, struct file *file)
{
	const char *real_name;
	struct file *real_file;
	int err = 0;

	/* Special case for directories - we don't need to actually open them */
	if (S_ISDIR(inode->i_mode)) {
		/* For directories, just succeed - the iterate function will handle actual access */
		return 0;
	}

	real_name = hyperfs_real_path_name(file->f_path.dentry);
	if (IS_ERR(real_name)){
		err = PTR_ERR(real_name);
	} else {
		real_file = filp_open(real_name, file->f_flags, inode->i_mode);
		if (IS_ERR(real_file)) {
			err = PTR_ERR(real_file);
		} else {
			file->private_data = real_file;
		}
	}
	if (err == -ENOENT){
		/* Get the complete path for missing files/directories */
		char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (path_buf) {
			char *full_path = dentry_path_raw(file->f_path.dentry, path_buf, PATH_MAX);
			if (!IS_ERR(full_path)) {
				igloo_enoent_path(full_path);
			} else {
				igloo_enoent(file->f_path.dentry);
			}
			kfree(path_buf);
		} else {
			igloo_enoent(file->f_path.dentry);
		}
	}
	kfree(real_name);
	return err;
}

static int hyperfs_release(struct inode *inode, struct file *file)
{
	struct file *real_file = file->private_data;

	if (real_file)
		fput(real_file);

	return 0;
}

static ssize_t hyperfs_read(struct file *file, char __user *buf, size_t size,
			    loff_t *offset)
{
	struct file *real_file = file->private_data;
	ssize_t ret = 0;

	if (real_file) {
		ret = real_vfs_read(real_file, buf, size, offset);
	} else {
		printk(KERN_EMERG "hyperfs: read on a file with no backing file");
		return -EBADF;
	}

	return ret;
}

static ssize_t hyperfs_write(struct file *file, const char __user *buf,
			     size_t size, loff_t *offset)
{
	struct file *real_file = file->private_data;
	ssize_t ret;

	if (real_file) {
		ret = real_vfs_write(real_file, buf, size, offset);
	} else {
		printk(KERN_EMERG "hyperfs: write on a file with no backing file");
		return -EBADF;
	}

	return ret;
}

static long hyperfs_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct file *real_file = file->private_data;

	if (real_file) {
		long ret;
		if (real_file->f_op && real_file->f_op->unlocked_ioctl)
			ret = real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
		else
			ret = -ENOTTY;
		igloo_ioctl(ret, file, cmd);
		return ret;
	} else {
		// Neither a hyperfs-managed file nor a real file
		printk(KERN_EMERG "hyperfs: ioctl on a file with no backing file");
		return -EBADF;
	}
}

static struct dentry *hyperfs_get_real_dentry(struct dentry *dentry)
{
	struct path real_parent_path;
	struct dentry *real_parent, *ret;
	int err;

	// Get real passthrough path
	err = hyperfs_real_path(dentry->d_parent, &real_parent_path);
	if (err < 0) {
		ret = ERR_PTR(err);
		goto out;
	}

	// Get a reference to the parent dentry before releasing the path
	real_parent = dget(real_parent_path.dentry);

	// Release the path before taking the inode lock
	path_put(&real_parent_path);

	// Now take the inode lock and perform lookup
	inode_lock(real_parent->d_inode);
	ret = lookup_one_len(dentry->d_name.name, real_parent,
			     dentry->d_name.len);
	inode_unlock(real_parent->d_inode);

	// Release our reference to the parent
	dput(real_parent);

out:
	return ret;
}

static int hyperfs_instantiate_common(struct inode *dir, struct dentry *dentry,
				      struct dentry *real_dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;

	inode = hyperfs_wrap_real_inode(sb, real_dentry->d_inode);
	if (!inode)
		return -ENOMEM;

	dentry->d_fsdata = dget(real_dentry);
	d_instantiate(dentry, inode);
	return 0;
}

static int hyperfs_create(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
			  umode_t mode, bool excl)
{
	struct dentry *real_dentry;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	err = vfs_create(idmap, real_dentry->d_parent->d_inode, real_dentry, mode,
			 excl);
	if (!err)
		err = hyperfs_instantiate_common(dir, dentry, real_dentry);

	dput(real_dentry);
	return err;
}

static int hyperfs_link(struct dentry *old, struct inode *new_dir,
	struct dentry *new)
{
	struct dentry *real_old, *real_new;
	struct mnt_idmap *idmap;
	int err;

	real_old = hyperfs_get_real_dentry(old);
	if (IS_ERR(real_old)) {
		err = PTR_ERR(real_old);
		goto out;
	}

	real_new = hyperfs_get_real_dentry(new);
	if (IS_ERR(real_new)) {
		err = PTR_ERR(real_new);
		goto put_old;
	}

	/* Get the idmap from current's mount */
	idmap = mnt_idmap(current->fs->pwd.mnt);

	/* Use the correct arguments for vfs_link */
	err = vfs_link(real_old, idmap, d_inode(real_new->d_parent), real_new, NULL);

	if (!err)
		err = hyperfs_instantiate_common(new_dir, new, real_new);

	dput(real_new);
put_old:
	dput(real_old);
out:
	return err;
}

static int hyperfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dentry *real_dentry;
	struct mnt_idmap *idmap;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	/* Get the idmap from current's mount */
	idmap = mnt_idmap(current->fs->pwd.mnt);

	err = vfs_unlink(idmap, real_dentry->d_parent->d_inode, real_dentry, NULL);

	dput(real_dentry);
	return err;
}

static int hyperfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, const char *link)
{
	struct dentry *real_dentry;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	err = vfs_symlink(idmap, real_dentry->d_parent->d_inode, real_dentry, link);

	dput(real_dentry);
	return err;
}

static int hyperfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
						struct dentry *dentry, umode_t mode)
{
	struct dentry *real_dentry;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	err = vfs_mkdir(idmap, real_dentry->d_parent->d_inode, real_dentry, mode);

	dput(real_dentry);
	return err;
}

static int hyperfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *real_dentry;
	struct mnt_idmap *idmap;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	/* Get the idmap from current's mount */
	idmap = mnt_idmap(current->fs->pwd.mnt);

	err = vfs_rmdir(idmap, real_dentry->d_parent->d_inode, real_dentry);

	dput(real_dentry);
	return err;
}

static int hyperfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct dentry *real_dentry;
	int err;

	real_dentry = hyperfs_get_real_dentry(dentry);
	if (IS_ERR(real_dentry))
		return PTR_ERR(real_dentry);

	err = vfs_mknod(idmap, real_dentry->d_parent->d_inode, real_dentry, mode,
			rdev);
	if (!err)
		err = hyperfs_instantiate_common(dir, dentry, real_dentry);

	dput(real_dentry);
	return err;
}

static int hyperfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			  struct dentry *old, struct inode *new_dir, struct dentry *new,
			  unsigned int flags)
{
	struct dentry *real_old, *real_new;
	int err;

	real_old = hyperfs_get_real_dentry(old);
	if (IS_ERR(real_old)) {
		err = PTR_ERR(real_old);
		goto out;
	}

	real_new = hyperfs_get_real_dentry(new);
	if (IS_ERR(real_new)) {
		err = PTR_ERR(real_new);
		goto put_old;
	}

	/* Use the inode operations directly for rename */
	if (real_old->d_parent->d_inode->i_op && 
	    real_old->d_parent->d_inode->i_op->rename) {
		err = real_old->d_parent->d_inode->i_op->rename(idmap,
			real_old->d_parent->d_inode, real_old,
			real_new->d_parent->d_inode, real_new, flags);
	} else {
		err = -EPERM;
	}

	dput(real_new);
put_old:
	dput(real_old);
out:
	return err;
}

static int hyperfs_getattr(struct mnt_idmap *idmap, const struct path *path,
                        struct kstat *stat, u32 request_mask,
                        unsigned int query_flags)
{
	struct path real_path;
	int err;
	struct inode *inode = path->dentry->d_inode;
	struct hyperfs_tree *tree = inode ? inode->i_private : NULL;

	/* First check if this is a hyperfs-managed directory or file */
	if (tree) {
		/* For hyperfs-managed entities, provide basic stats */
		generic_fillattr(idmap, request_mask, inode, stat);
		return 0;
	}

	/* Try to get real path - may fail if directory doesn't exist in passthrough */
	err = hyperfs_real_path(path->dentry, &real_path);
	if (err < 0){
		if (err == -ENOENT) {
			/* Report the full path of the missing entry */
			char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
			if (path_buf) {
				char *full_path = dentry_path_raw(path->dentry, path_buf, PATH_MAX);
				if (!IS_ERR(full_path)) {
					igloo_enoent_path(full_path);
				} else {
					igloo_enoent(path->dentry); /* Fallback */
				}
				kfree(path_buf);
			} else {
				igloo_enoent(path->dentry); /* Fallback */
			}

			if (inode && S_ISDIR(inode->i_mode)){
				/* For directories that don't exist in passthrough, provide generic attributes */
				generic_fillattr(idmap, request_mask, inode, stat);
				return 0;
			} else {
				/* For files that don't exist in passthrough, return error */
				return -ENOENT;
			}
		}
		return err;
	}

	/* Get attributes from real path */
	err = vfs_getattr(&real_path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	path_put(&real_path);
	return err;
}

static bool hyperfs_real_iter_actor(struct dir_context *ctx, const char *name,
                                  int name_len, loff_t offset, u64 ino,
                                  unsigned int d_type)
{
	struct hyperfs_iterate_data *iter_data =
		(struct hyperfs_iterate_data *)ctx;

	// Skip emitting dots, because we did that already
	if (!strncmp(name, ".", name_len) || !strncmp(name, "..", name_len))
		return true;

	// Filter duplicates with hyperfs-managed files
	if (iter_data->tree &&
	    hyperfs_dir_lookup(&iter_data->tree->dir_entries, name, name_len))
		return true;

	if (!dir_emit(iter_data->hyperfs_ctx, name, name_len, get_next_ino(),
		      d_type))
		return false;

	return true;
}

static int hyperfs_iterate(struct file *file, struct dir_context *ctx)
{
	struct path real_path;
	struct file *real_file;
	struct hyperfs_iterate_data iter_data = {
		.real_ctx.actor = hyperfs_real_iter_actor,
		.hyperfs_ctx = ctx,
		.tree = NULL,
	};
	loff_t i = 2;
	int err = 0;

	if (!dir_emit_dots(file, ctx))
		goto out;

	// No virtual entries; list only passthrough dir

	// Get real passthrough path
	err = hyperfs_real_path(file->f_path.dentry, &real_path);
	if (err == -ENOENT) {
		igloo_enoent(file->f_path.dentry);
		err = 0;
		goto out;  // Just show virtual entries for non-existent real directories
	}
	if (err < 0)
		return err;

	// Open passthrough dir
	real_file =
		dentry_open(&real_path, O_RDONLY | O_DIRECTORY, current_cred());
	if (IS_ERR(real_file)) {
		err = PTR_ERR(real_file);
		if (err == -ENOENT || err == -ENOTDIR || err == -EACCES){
			igloo_enoent(file->f_path.dentry);
			err = 0;  /* Accept more error types as "directory is empty" */
		}
		goto out_real_path;
	}

	err = vfs_llseek(real_file, ctx->pos - i, SEEK_SET);
	if (err < 0)
		goto out_real_file;

	err = iterate_dir(real_file, &iter_data.real_ctx);
	if (err < 0)
		goto out_real_file;

	ctx->pos = i + iter_data.real_ctx.pos;

out_real_file:
	fput(real_file);
out_real_path:
	path_put(&real_path);
out:
	return err;
}

static int hyperfs_read_folio(struct file *file, struct folio *folio)
{
	struct hyperfs_tree *tree = file->f_inode->i_private;
	void *data;

	data = kmap_local_folio(folio, 0);

	hyp_file_op((struct hyperfs_data){
		.type = HYP_READ,
		.path = tree->path,
		.read.buf = data,
		.read.size = folio_size(folio),
		.read.offset = folio_pos(folio),
	});

	kunmap_local(data);
	flush_dcache_folio(folio);
	folio_mark_uptodate(folio);
	folio_unlock(folio);

	return 0;
}

static int hyperfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct hyperfs_tree *tree = page->mapping->host->i_private;
	void *data;

	data = kmap(page);

	hyp_file_op((struct hyperfs_data){
		.type = HYP_WRITE,
		.path = tree->path,
		.write.buf = data,
		.write.size = PAGE_SIZE,
		.write.offset = page_offset(page),
	});

	kunmap(page);
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}

static const char *hyperfs_get_link(struct dentry *dentry, struct inode *inode,
				    struct delayed_call *done)
{
	struct dentry *real;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	real = dentry->d_fsdata;

	if (!real)
		return ERR_PTR(-EINVAL);

	return vfs_get_link(real, done);
}

static int hyperfs_readlink(struct dentry *dentry, char __user *buffer,
			    int buflen)
{
	struct dentry *real = dentry->d_fsdata;

	if (!dentry)
		return -ECHILD;

	if (!real)
		return -EINVAL;

	return vfs_readlink(real, buffer, buflen);
}

static const struct file_operations hyperfs_file_operations = {
	.owner = THIS_MODULE,
	.open = hyperfs_open,
	.release = hyperfs_release,
	.read = hyperfs_read,
	.write = hyperfs_write,
	.unlocked_ioctl = hyperfs_ioctl,
	.mmap = generic_file_mmap,
};

static const struct inode_operations hyperfs_inode_operations = {
	.get_link = hyperfs_get_link,
	.readlink = hyperfs_readlink,
	.lookup = hyperfs_lookup,
	.create = hyperfs_create,
	.link = hyperfs_link,
	.unlink = hyperfs_unlink,
	.symlink = hyperfs_symlink,
	.mkdir = hyperfs_mkdir,
	.rmdir = hyperfs_rmdir,
	.mknod = hyperfs_mknod,
	.rename = hyperfs_rename,
	.getattr = hyperfs_getattr,
};

static const struct file_operations hyperfs_dir_operations = {
	.owner = THIS_MODULE,
	.read = generic_read_dir,
	.open = generic_file_open,
	.iterate_shared = hyperfs_iterate,  // Changed from .iterate to .iterate_shared
};

static const struct address_space_operations hyperfs_aops = {
	.read_folio = hyperfs_read_folio,
	.writepage = hyperfs_writepage,
};

// NB: tree->is_dir and tree->path must be initialized before calling
static void hyperfs_fill_inode(struct inode *inode, struct hyperfs_tree *tree)
{
	inode->i_ino = get_next_ino();
	inode->i_mode = tree->is_dir ? DIR_MODE : DEV_MODE;
	inode->i_flags |= S_NOCMTIME;
#ifdef CONFIG_FS_POSIX_ACL
	inode->i_acl = inode->i_default_acl = ACL_DONT_CACHE;
#endif

	inode->i_private = tree;

	if (tree->is_dir) {
		inode->i_op = &hyperfs_inode_operations;
		inode->i_fop = &hyperfs_dir_operations;
	} else {
		inode->i_fop = &hyperfs_file_operations;
		inode->i_data.a_ops = &hyperfs_aops;

		hyp_file_op((struct hyperfs_data){
			.type = HYP_GETATTR,
			.path = tree->path,
			.getattr.size = &inode->i_size,
		});
	}
}

static struct inode *hyperfs_wrap_real_inode(struct super_block *sb,
					     struct inode *real)
{
	struct inode *inode;
	static const struct file_operations empty_fops;
	static const struct inode_operations empty_iops;

	inode = new_inode(sb);
	if (!inode) {
		return NULL;
	}

	spin_lock(&inode->i_lock);
	inode->i_ino = real->i_ino;
	inode->i_uid = real->i_uid;
	inode->i_gid = real->i_gid;
	inode->i_mode = real->i_mode;
	inode->i_rdev = real->i_rdev;
	inode->i_atime_sec = real->i_atime_sec;
	inode->i_atime_nsec = real->i_atime_nsec;
	inode->i_mtime_sec = real->i_mtime_sec;
	inode->i_mtime_nsec = real->i_mtime_nsec;
	inode->i_ctime_sec = real->i_ctime_sec;
	inode->i_ctime_nsec = real->i_ctime_nsec;

	i_size_write(inode, i_size_read(real));
	switch (real->i_mode & S_IFMT) {
	case S_IFDIR:
		inode->i_op = &hyperfs_inode_operations;
		inode->i_fop = &hyperfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &hyperfs_inode_operations;
		inode->i_fop = &empty_fops;
		break;
	default:
		inode->i_op = &empty_iops;
		inode->i_fop = &hyperfs_file_operations;
	}
	spin_unlock(&inode->i_lock);

	return inode;
}

// NB: tree->is_dir must be initialized before calling
static struct inode *hyperfs_new_inode(struct super_block *sb,
				       struct hyperfs_tree *tree)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (inode) {
		hyperfs_fill_inode(inode, tree);
	}
	return inode;
}

static void hyperfs_put_super(struct super_block *sb)
{
	struct hyperfs *fs = sb->s_fs_info;

	dput(sb->s_root);
	hyperfs_tree_free(fs->tree);
	kfree(fs->passthrough_path);
	kfree(fs);
}

static int hyperfs_show_options(struct seq_file *f, struct dentry *dentry)
{
	struct hyperfs *fs = dentry->d_sb->s_fs_info;

	seq_printf(f, ",passthrough_path=%s", fs->passthrough_path);
	seq_printf(f, ",fs_name=%s", fs->fs_name ? fs->fs_name : "(null)");
	return 0;
}

static const struct super_operations hyperfs_super_operations = {
	.put_super = hyperfs_put_super,
	.show_options = hyperfs_show_options,
	.drop_inode = generic_delete_inode,
};

// Forward declaration for use in super_operations
static void hyperfs_put_super(struct super_block *sb);

static void hyperfs_d_release(struct dentry *dentry)
{
	struct dentry *real = dentry->d_fsdata;

	if (real)
		dput(real);
}

static int hyperfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *real = dentry->d_fsdata;
	int ret = 1;

	if (!real)
		return 1;

	if (real->d_flags & DCACHE_OP_REVALIDATE) {
		ret = real->d_op->d_revalidate(real, flags);
		if (ret < 0)
			return ret;
		if (!ret) {
			if (!(flags & LOOKUP_RCU))
				d_invalidate(real);
			return -ESTALE;
		}
	}

	return 1;
}

static int hyperfs_d_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *real = dentry->d_fsdata;
	int ret = 1;

	if (real && (real->d_flags & DCACHE_OP_WEAK_REVALIDATE))
		ret = real->d_op->d_weak_revalidate(real, flags);

	return ret;
}

static const struct dentry_operations hyperfs_dentry_operations = {
	.d_release = hyperfs_d_release,
	.d_revalidate = hyperfs_d_revalidate,
	.d_weak_revalidate = hyperfs_d_weak_revalidate,
};

static int hyperfs_parse_options(char *options, struct super_block *sb,
				 struct hyperfs *fs)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	if (!options) {
		pr_err("hyperfs: missing required mount options\n");
		return -EINVAL;
	}

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, hyperfs_tokens, args);
		switch (token) {
		case HYPERFS_OPT_PASSTHROUGH_PATH:
			if (fs->passthrough_path)
				goto dup_option;
			fs->passthrough_path = match_strdup(args);
			if (!fs->passthrough_path)
				return -ENOMEM;
			break;
		case HYPERFS_OPT_FS_NAME:
			if (fs->fs_name)
				goto dup_option;
			fs->fs_name = match_strdup(args);
			if (!fs->fs_name)
				return -ENOMEM;
			break;
		default:
			pr_err("hyperfs: unrecognized mount option \"%s\" or missing value\n",
			       p);
			return -EINVAL;
		}
	}

	if (!fs->passthrough_path) {
		pr_err("hyperfs: missing option \"passthrough_path\"\n");
		return -EINVAL;
	}
	if (!fs->fs_name) {
		pr_err("hyperfs: missing option \"fs_name\"\n");
		return -EINVAL;
	}

	return 0;

dup_option:
	pr_err("hyperfs: option \"%s\" specified more than once\n", p);
	return -EINVAL;
}

static int hyperfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct hyperfs *fs;
	struct inode *root;
	int err;

	sb->s_op = &hyperfs_super_operations;
	sb->s_d_op = &hyperfs_dentry_operations;

	fs = kzalloc(sizeof(struct hyperfs), GFP_KERNEL);
	if (!fs) {
		err = -ENOMEM;
		goto out;
	}

	err = hyperfs_parse_options((char *)data, sb, fs);
	if (err)
		goto out_free_fs;

	fs->tree = hyperfs_tree_build(sb);
	if (IS_ERR(fs->tree)) {
		err = PTR_ERR(fs->tree);
		fs->tree = NULL;
		goto out_free_fs;
	}

#if HYPERFS_DEBUG
	pr_alert("hyperfs: DEBUG: tree: ");
	hyperfs_tree_print(0, fs->tree);
	pr_alert("\n");
#endif

	sb->s_root = d_make_root(fs->tree->inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_free_fs;
	}
	sb->s_fs_info = fs;
	return 0;

out_free_fs:
	hyperfs_tree_free(fs->tree);
	kfree(fs->passthrough_path);
	kfree(fs);
out:
	return err;
}

static struct dentry *hyperfs_mount(struct file_system_type *fs_type, int flags,
			     const char *dev_name, void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, hyperfs_fill_super);
}

static struct file_system_type hyperfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "hyperfs",
	.mount = hyperfs_mount,
	.kill_sb = kill_anon_super,
};

MODULE_SOFTDEP("pre: igloo");

int hyperfs_init(void)
{
    pr_info("hyperfs: loading (igloo symbols resolved)\n");
    // Resolve vfs_read and vfs_write using kallsyms_lookup_name
    real_vfs_read = (void *)kallsyms_lookup_name("vfs_read");
    real_vfs_write = (void *)kallsyms_lookup_name("vfs_write");
    if (!real_vfs_read || !real_vfs_write) {
        pr_err("hyperfs: could not resolve vfs_read/vfs_write\n");
        return -EINVAL;
    }
    register_filesystem(&hyperfs_fs_type);
    return 0;
}

void hyperfs_exit(void)
{
	unregister_filesystem(&hyperfs_fs_type);
}