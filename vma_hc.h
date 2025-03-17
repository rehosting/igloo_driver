// #define DEBUG_PRINT

// Enum for types of VMA updates - insert, remove, update
typedef enum {
    VMA_INSERT,
    VMA_REMOVE,
    VMA_UPDATE
} vma_update_type_t;

// Struct to hold VMA update information
typedef struct {
    vma_update_type_t type;      // Type of update
    uint64_t start_addr;         // Start of the VMA
    uint64_t end_addr;           // End of the VMA
    char name[256];              // Name (or NULL for anonymous mappings)

    // Optional old value for VMA_UPDATE
    uint64_t old_start_addr;     // Old start (for VMA_UPDATE only)
} vma_update_t;

// Stuct to hold task information, shared via hypercall
typedef struct {
    uint32_t tgid; // TGID for userspace tasks, PID for kernel threads
    uint32_t start_time;
    uint32_t parent_tgid;
    uint32_t parent_start_time;
    uint32_t is_kernel;  // Flag to indicate if it's a kernel thread
    char comm[TASK_COMM_LEN]; // 16 bytes for task name
} task_info_t;


/* Passing data between entrance and exit of target functions */
struct munmap_data {
    unsigned long start_addr;
    unsigned long length;
};

struct mremap_data {
    unsigned long old_addr;  // Old start address
};

struct brk_data {
    unsigned long requested_brk;  // Requested brk address
    unsigned long old_brk;  // Old brk address
};

int vma_hc_init(void);