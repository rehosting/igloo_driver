enum hyperfs_ops {
    HYP_FILE_OP,
    HYP_GET_NUM_HYPERFILES, 
    HYP_GET_HYPERFILE_PATHS
};

enum hyperfs_file_ops {
    HYP_READ, HYP_WRITE, HYP_IOCTL, HYP_GETATTR
};

enum { HYPERFILE_PATH_MAX = 1024 };

#define HYP_RETRY 0xdeadbeef