#include <linux/gfp.h>
#include <linux/mm.h>
#include "portal_internal.h"
#include <linux/fs.h>
#include <linux/string.h>
#include "portal_tramp.h"
#include <linux/slab.h>
#include <linux/export.h>
struct file_operations *hyperfs_lookup_file(const char *fs, const char *file);

#define HYPERFS_HASH_BITS 10
#define HYPERFS_HASH_SIZE (1 << HYPERFS_HASH_BITS)

struct hyperfs_file_entry {
    char *fs_name;
    char *file_name;
    struct file_operations *fops;
    struct hyperfs_file_entry *next;
};

static struct hyperfs_file_entry *hyperfs_table[HYPERFS_HASH_SIZE];

// Simple hash function for fs_name and file_name
static unsigned int hyperfs_hash(const char *fs, const char *file)
{
    unsigned int h = 0;
    while (*fs) h = (h * 31) + *fs++;
    while (*file) h = (h * 31) + *file++;
    return h & (HYPERFS_HASH_SIZE - 1);
}

// Add or update an entry
static int hyperfs_add_file(const char *fs, const char *file, struct file_operations *fops)
{
    unsigned int idx = hyperfs_hash(fs, file);
    struct hyperfs_file_entry *entry = hyperfs_table[idx];

    // Check if already exists, update if so
    while (entry) {
        if (!strcmp(entry->fs_name, fs) && !strcmp(entry->file_name, file)) {
            entry->fops = fops;
            return 0;
        }
        entry = entry->next;
    }

    // Allocate new entry
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    entry->fs_name = kstrdup(fs, GFP_KERNEL);
    entry->file_name = kstrdup(file, GFP_KERNEL);
    entry->fops = fops;
    entry->next = hyperfs_table[idx];
    hyperfs_table[idx] = entry;
    return 0;
}

// Lookup an entry
struct file_operations *hyperfs_lookup_file(const char *fs, const char *file)
{
    unsigned int idx = hyperfs_hash(fs, file);
    struct hyperfs_file_entry *entry = hyperfs_table[idx];
    while (entry) {
        if (!strcmp(entry->fs_name, fs) && !strcmp(entry->file_name, file))
            return entry->fops;
        entry = entry->next;
    }
    return NULL;
}

// Handler for HYPER_OP_HYPERFS_ADD_HYPERFILE
void handle_op_hyperfs_add_hyperfile(portal_region *region) {
    struct portal_hyperfs_add_hyperfile_args *args =
        (struct portal_hyperfs_add_hyperfile_args *)region->raw;
    char *fs_name = (char *)(region->raw + args->fs_name_offset);
    char *file_name = (char *)(region->raw + args->file_name_offset);
    struct file_operations *fops = (struct file_operations *)(uintptr_t)args->fops_ptr;

    int ret = hyperfs_add_file(fs_name, file_name, fops);
    region->header.op = (ret == 0) ? HYPER_RESP_WRITE_OK : HYPER_RESP_WRITE_FAIL;
}
