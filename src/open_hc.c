#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "hypercall.h"
#include "igloo.h"
#include <linux/binfmts.h>
#include <trace/syscall.h>

void igloo_hc_open(int dfd, struct filename *tmp, int fd);

static char *resolve_dfd_to_path(int dfd, char *buf, int buflen) {
	struct file *file;
	char *path = ERR_PTR(-EBADF);

	file = fget(dfd);
	if (!file) {
		return path;
	}

	path = file_path(file, buf, buflen);
	fput(file);
	return path;
}

/**
 * Called from do_sys_openat2 in fs/open.c
 */
void igloo_hc_open(int dfd, struct filename *tmp, int fd){
    if (!igloo_do_hc) {
	    return;
    }
	char *resolved_path;
	// Allocate memory for resolved_path only when necessary
	resolved_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!resolved_path) {
	    return;
	}

	// Handle AT_FDCWD or resolve dfd to a path prefix
	if (dfd == AT_FDCWD) {
		// Using getname's result directly avoids unnecessary copy_from_user
		strscpy(resolved_path, tmp->name, PATH_MAX);
	} else {
		// Resolve the dfd to its absolute path
		char *path = resolve_dfd_to_path(dfd, resolved_path, PATH_MAX);
		if (IS_ERR(path)) {
			// XXX: rare failure, shows up with cgroups
			strscpy(resolved_path, "/path_resolve_error", PATH_MAX);
		}

		// Concatenate the resolved path with the provided filename
		if (resolved_path[0] != '\0' && resolved_path[strlen(resolved_path) - 1] != '/')
			strlcat(resolved_path, "/", PATH_MAX);
		strlcat(resolved_path, tmp->name, PATH_MAX);
	}
	// 100 = open/openat with args: open target, resulting fd
	igloo_hypercall2(IGLOO_OPEN, (unsigned long)resolved_path, (unsigned long)fd);

	kfree(resolved_path);
}