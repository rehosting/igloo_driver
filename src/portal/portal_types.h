#include "portal_op_list.h"

enum HYPER_OP {
    HYPER_OP_NONE = 0,
#define X(lower, upper) HYPER_OP_##upper,
    PORTAL_OP_LIST
#undef X
    HYPER_OP_MAX,

    HYPER_RESP_NONE = 0xf0000000,
    HYPER_RESP_READ_OK,
    HYPER_RESP_READ_FAIL,
    HYPER_RESP_READ_PARTIAL,
    HYPER_RESP_WRITE_OK,
    HYPER_RESP_WRITE_FAIL,
    HYPER_RESP_READ_NUM,
    HYPER_RESP_MAX,
};

enum portal_type {
	PORTAL_UPROBE_TYPE_ENTRY,
	PORTAL_UPROBE_TYPE_RETURN,
	PORTAL_UPROBE_TYPE_BOTH,
};

#define CURRENT_PID_NUM 0xffffffff

typedef struct {
    uint32_t op;          // operation type
    uint32_t pid;         // process ID (if relevant)
    uint64_t addr;        // address
    uint64_t size;        // size
} region_header;

typedef union {
    region_header header;  // Changed from mem_region_header to region_header
    uint8_t raw[PAGE_SIZE - sizeof(region_header)]; // Raw data buffer
} portal_region;

// OSI data structures based on osi_types.h
struct osi_proc_handle {
	uint64_t pid;
	uint64_t taskd;
	uint64_t start_time;
};

struct osi_module {
    uint64_t base;
    uint64_t size;
    uint64_t file_offset;    // Offset of file string in data buffer
    uint64_t name_offset;    // Offset of name string in data buffer
    uint64_t offset;         // Module load offset
    uint64_t flags;          // Module flags
    uint64_t pgoff;
    uint64_t dev;
    uint64_t inode;
};

struct osi_proc {
    uint64_t taskd;
    uint64_t pgd;
    uint64_t pid;
    uint64_t ppid;
    uint64_t name_offset;    // Offset of name string in data buffer
    uint64_t create_time;
    uint64_t map_count;
    uint64_t start_brk;
    uint64_t brk;
    uint64_t start_stack;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t arg_start;
    uint64_t arg_end;
    uint64_t env_start;
    uint64_t env_end;
    uint64_t saved_auxv;
    uint64_t mmap_base;
    uint64_t task_size;
    uint64_t uid;
    uint64_t gid;
    uint64_t euid;
    uint64_t egid;
    uint64_t start_time;
};

// File descriptor entry structure for handle_op_read_fds
struct osi_fd_entry {
    uint64_t fd;                 // File descriptor number
    uint64_t name_offset;        // Offset to the file name in the string buffer
};

// Generic header for OSI responses with pagination
struct osi_result_header {
    uint64_t result_count;      // Number of items returned in this response
    uint64_t total_count;       // Total number of items available
};

/* Define the FFI execution structure */
struct portal_ffi_call {
    unsigned long func_ptr;          /* Pointer to the function to call */
    unsigned long num_args;  /* Number of arguments (up to 8) */
    unsigned long args[8];   /* Array of arguments as unsigned long */
    unsigned long result;    /* Return value of the function call */
};

/* Structure for trampoline generate operation */
struct portal_tramp_generate {
    uint32_t tramp_id;         /* Unique trampoline id */
    int status;                /* 0 = success, <0 = error */
    unsigned long tramp_addr;          /* Function address */
};

/* Arguments for HYPER_OP_HYPERFS_ADD_HYPERFILE */
struct portal_hyperfs_add_hyperfile_args {
    uint64_t fs_name_offset;   // Offset to filesystem name string in data buffer
    uint64_t file_name_offset; // Offset to file name string in data buffer
    uint64_t fops_ptr;         // Pointer to struct file_operations
};