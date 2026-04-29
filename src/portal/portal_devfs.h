#ifndef IGLOO_DEVFS_H
#define IGLOO_DEVFS_H

struct igloo_dev_ops {
    int     (*open)(struct inode *, struct file *);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
    loff_t  (*lseek)(struct file *, loff_t, int);
    int     (*release)(struct inode *, struct file *);
    unsigned int (*poll)(struct file *, struct poll_table_struct *);
    long     (*ioctl)(struct file *, unsigned int, unsigned long);
#ifdef CONFIG_COMPAT
    long     (*compat_ioctl)(struct file *, unsigned int, unsigned long);
#endif
    int      (*mmap)(struct file *, struct vm_area_struct *);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    
    int     (*flush)(struct file *, fl_owner_t id);
    int     (*fsync)(struct file *, loff_t, loff_t, int datasync);
    int     (*fasync)(int, struct file *, int);
    int     (*lock)(struct file *, int, struct file_lock *);
};

void igloo_convert_ops_to_fops(const struct igloo_dev_ops *ops, struct file_operations *out, bool enable_default_mmap);
#endif // IGLOO_DEVFS_H