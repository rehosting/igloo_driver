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
    __le64 op;          // operation type
    __le64 addr;        // address
    __le64 size;        // size
    __le64 pid;         // process ID (if relevant)
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
	__le64 count; // Number of currently allocated regions
    __le64 call_num;    // global atomic hypercall number
};

struct cpu_mem_region {
	__le64 owner_id;
    __le64 mem_region; // struct mem_region*
};

struct cpu_mem_regions {
    struct cpu_mem_region_hdr hdr;
	struct cpu_mem_region
		regions[MAX_MEM_REGIONS_PER_CPU]; //struct mem_region*
};

// OSI data structures based on osi_types.h
struct osi_proc_handle {
	__le64 pid;
	__le64 taskd;
	__le64 start_time;
};

struct osi_module {
    __le64 base;
    __le64 size;
    __le64 file_offset;    // Offset of file string in data buffer
    __le64 name_offset;    // Offset of name string in data buffer
    __le64 offset;         // Module load offset
    __le64 flags;          // Module flags
    __le64 pgoff;
    __le64 dev;
    __le64 inode;
};

struct osi_proc {
    __le64 taskd;
    __le64 pgd;
    __le64 pid;
    __le64 ppid;
    __le64 name_offset;    // Offset of name string in data buffer
    __le64 create_time;
    __le64 map_count;
    __le64 start_brk;
    __le64 brk;
    __le64 start_stack;
    __le64 start_code;
    __le64 end_code;
    __le64 start_data;
    __le64 end_data;
    __le64 arg_start;
    __le64 arg_end;
    __le64 env_start;
    __le64 env_end;
    __le64 saved_auxv;
    __le64 mmap_base;
    __le64 task_size;
    __le64 uid;
    __le64 gid;
    __le64 euid;
    __le64 egid;
};

// File descriptor entry structure for handle_op_read_fds
struct osi_fd_entry {
    __le64 fd;                 // File descriptor number
    __le64 name_offset;        // Offset to the file name in the string buffer
};

// Generic header for OSI responses with pagination
struct osi_result_header {
    __le64 result_count;      // Number of items returned in this response
    __le64 total_count;       // Total number of items available
};
