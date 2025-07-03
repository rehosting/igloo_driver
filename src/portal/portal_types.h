enum HYPER_OP {
    HYPER_OP_NONE = 0,

    // memory operations
    HYPER_OP_READ,
    HYPER_OP_WRITE,
    HYPER_OP_READ_STR,
    
    // dump operation
    HYPER_OP_DUMP,

    // exec
    HYPER_OP_EXEC,

    // Add OSI operation codes
    HYPER_OP_OSI_PROC,        // Get detailed process information
    HYPER_OP_OSI_PROC_HANDLES, // Get process handles
    HYPER_OP_OSI_MAPPINGS,    // Get memory mappings
    HYPER_OP_OSI_PROC_MEM,    // Get process memory info
    HYPER_OP_READ_PROCARGS,
    HYPER_OP_READ_PROCENV,
    HYPER_OP_READ_FDS,        // Get multiple file descriptors with names

    // file operations
    HYPER_OP_READ_FILE,
    HYPER_OP_WRITE_FILE,
    
    // Uprobe operations
    HYPER_OP_REGISTER_UPROBE,
    HYPER_OP_UNREGISTER_UPROBE,
    
    // Syscall operations
    HYPER_OP_REGISTER_SYSCALL_HOOK,
    HYPER_OP_UNREGISTER_SYSCALL_HOOK,
    
    // FFI operations
    HYPER_OP_FFI_EXEC,        // Execute kernel function via FFI
    
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
    uint64_t addr;        // address
    uint32_t size;        // size
    uint32_t pid;         // process ID (if relevant)
    uint32_t call_num;
} region_header;

typedef union {
    region_header header;  // Changed from mem_region_header to region_header
    uint8_t raw[PAGE_SIZE];
} portal_region;

// Maximum number of memory regions per CPU
#define MAX_MEM_REGIONS_PER_CPU 16
#define DEFAULT_MEM_REGIONS 8  // Number of memory regions to allocate by default

// Per-CPU array of memory regions

struct cpu_mem_region_hdr {
	int count; // Number of currently allocated regions
    uint64_t call_num;    // global atomic hypercall number
};

struct cpu_mem_region {
	int owner_id;
    portal_region *mem_region; // struct mem_region*
};

struct cpu_mem_regions {
    struct cpu_mem_region_hdr hdr;
	struct cpu_mem_region
		regions[MAX_MEM_REGIONS_PER_CPU]; //struct mem_region*
};

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
    void *func_ptr;          /* Pointer to the function to call */
    unsigned long num_args;  /* Number of arguments (up to 8) */
    unsigned long args[8];   /* Array of arguments as unsigned long */
    unsigned long result;    /* Return value of the function call */
};