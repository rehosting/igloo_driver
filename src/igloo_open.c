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
#include "igloo_hypercall_consts.h"

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION) && LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
#define fget(fd) fget_light(fd, NULL)
#define fput(file) fput_light(file, 0)
static inline ssize_t strscpy(char *dest, const char *src, size_t count)
{
	strncpy(dest, src, count);
	if (count)
		dest[count - 1] = '\0';
	return strlen(dest);
}
#endif

static char *resolve_dfd_to_path(int dfd, char *buf, int buflen) {
	struct file *file;
	char *path;

	file = fget(dfd);
	if (!file) {
		return ERR_PTR(-EBADF);
	}

	path = file_path(file, buf, buflen);
	fput(file);
	return path;
}

/**
 * Called from do_sys_openat2 in fs/open.c
 */
void igloo_hc_open(int dfd, struct filename *tmp, int fd);
void igloo_hc_open(int dfd, struct filename *tmp, int fd)
{
    if (!igloo_do_hc)
    {
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

int igloo_open_init(void){
    void (**open_mod_ptr)(int, struct filename *, int);
    printk(KERN_EMERG "IGLOO: Initializing igloo_open hypercalls\n");
    open_mod_ptr = (void (**)(int, struct filename *, int))kallsyms_lookup_name("igloo_hc_open_module");
    if (open_mod_ptr) {
        *open_mod_ptr = igloo_hc_open;
        printk(KERN_INFO "IGLOO: Set igloo_hc_open_module via kallsyms\n");
    } else {
        printk(KERN_ERR "IGLOO: Failed to find igloo_hc_open_module symbol via kallsyms\n");
    }
    return 0;
}