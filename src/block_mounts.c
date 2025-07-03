#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include "hypercall.h"
#include "igloo.h"

bool igloo_should_block_mount(struct path *path);
bool igloo_should_block_mount(struct path *path){
	// IGLOO: Prevent guest from remounting one of our custom mounts
	if (path->dentry && path->dentry->d_sb && path->dentry->d_sb->s_type &&
		path->dentry->d_sb->s_type->name && path->dentry->d_name.name) {

		// What filesystem type is the *mount point* - not the requested mount, but the filesystem
		// we're mounting into. e.g., mounting tmpfs into /home/tmp would be of type ext2 if /home is ext2
		// If we see a mount_type of fuse, it's likely that we're mounting into one of our fuse filesystems
		const char *mount_type = path->dentry->d_sb->s_type->name;
		const char *mount_point = path->dentry->d_name.name; // Name of the directory we're mounting (e.g., /dev -> dev)

		//printk(KERN_INFO "Penguin: Requested mount point: %s, Requested mount type: %s, Actual mount type: %s\n",
		//		mount_point, type_page ? type_page : "NULL", mount_type);

		if (strncmp("hyperfs", mount_type, 4) == 0) {
			// We're mounting something at a hyperfs mount point. For example, we might be remounting /dev after we've set up our initial hyperfs mount
			// Let's check that it's one of the paths we care about: sys, dev, or proc. If so, we'll block it. Otherwise continue as normal
			if (strncmp(mount_point, "dev", 3) == 0 ||
				strncmp(mount_point, "sys", 3) == 0 ||
				strncmp(mount_point, "proc", 4) == 0) {
				//printk(KERN_INFO "Penguin: Blocking attempt to remount %s within a fuse as %s\n", mount_point, type_page ? type_page : "NULL");
				return true;
			}
		}
	//} else {
		//printk(KERN_WARNING "Penguin: Incomplete mount information\n");
	}
	return false;
}