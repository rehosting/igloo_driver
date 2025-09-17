#ifndef PORTAL_HYPERFS_H
#define PORTAL_HYPERFS_H

#include <linux/fs.h>
#include "portal_types.h"

struct file_operations *hyperfs_lookup_file(const char *fs, const char *file);
void handle_op_hyperfs_add_hyperfile(portal_region *region);

#endif // PORTAL_HYPERFS_H
