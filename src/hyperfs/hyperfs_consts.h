enum hyperfs_ops {
    HYP_FILE_OP,
    HYP_GET_NUM_HYPERFILES, 
    HYP_GET_HYPERFILE_PATHS
};

enum hyperfs_file_ops {
    HYP_READ, HYP_WRITE, HYP_IOCTL, HYP_GETATTR
};

/* Named, not anonymous, deliberately: Doxygen 1.9.8/1.10 (the version on the
 * docs CI runner) emits an anonymous enum with an empty <name>, which Breathe
 * turns into an empty C declaration and Sphinx rejects with "Invalid C
 * declaration: Expected identifier in nested name. [error at 0]" -- fatal under
 * the docs build's -W. Doxygen 1.9.1 and 1.17 instead emit a synthetic "@N"
 * name and build fine, so this only breaks on some versions. A real tag is
 * stable across all of them. */
enum hyperfs_limits { HYPERFILE_PATH_MAX = 1024 };

#define HYP_RETRY 0xdeadbeef