void igloo_ioctl(int error, struct file *filp, unsigned int cmd);
void igloo_enoent(struct dentry *dentry);
void igloo_enoent_path(const char *path);