enum hyperfs_ops {
    HYP_FILE_OP,
    HYP_GET_NUM_HYPERFILES, 
    HYP_GET_HYPERFILE_PATHS
};

enum hyperfs_file_ops {
    HYP_READ, HYP_WRITE, HYP_IOCTL, HYP_GETATTR
};

/* Named rather than anonymous: Doxygen >= 1.9.8 emits an anonymous enum with an
 * empty <name>, and Breathe hands that empty string to Sphinx's C domain, which
 * fails to parse it ("Invalid C declaration ... [error at 0]"). Older Doxygen
 * emitted an "@N" placeholder that Breathe skipped, which is why the docs build
 * was clean locally and red in CI. */
enum hyperfs_limits { HYPERFILE_PATH_MAX = 1024 };

#define HYP_RETRY 0xdeadbeef