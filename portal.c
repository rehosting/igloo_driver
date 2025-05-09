#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h> /* Add missing include for hashtable support */
#include <linux/net.h>      /* For socket operations */
#include <linux/inet.h>     /* For inet socket operations */
#include <net/inet_sock.h>  /* For inet_sk() macro */
#include "hypercall.h" // Content is now included directly below
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/sched/signal.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "portal.h"
#include <linux/printk.h> // Add printk include

// Add conditional debug macro
#ifdef CONFIG_IGLOO_DEBUG
#define igloo_pr_debug(fmt, ...) if (do_debug) printk( KERN_EMERG fmt, ##__VA_ARGS__)
#else
#define igloo_pr_debug(fmt, ...) do {} while (0)
#endif


enum HYPER_OP {
    HYPER_OP_NONE = 0,
    HYPER_OP_READ,
    HYPER_OP_WRITE,
    HYPER_OP_READ_FD_NAME,
    HYPER_OP_READ_PROCARGS,
    HYPER_OP_READ_SOCKET_INFO,
    HYPER_OP_READ_STR,
    HYPER_OP_READ_FILE,
    HYPER_OP_READ_PROCENV,
    HYPER_OP_READ_PROCPID, 
    HYPER_OP_DUMP,
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

// #define CHUNK_SIZE 4096- (sizeof(__le64)*3) // 4KB - 24
#define CHUNK_SIZE 1000
struct mem_region {
    __le64 op;          // operation type
    __le64 addr;        // address
    __le64 size;        // size
    char data[CHUNK_SIZE];
};

// Maximum number of memory regions per CPU
#define MAX_MEM_REGIONS_PER_CPU 16
#define DEFAULT_MEM_REGIONS 8  // Number of memory regions to allocate by default

// Per-CPU array of memory regions

struct cpu_mem_region {
	__le64 owner_id;
    __le64 mem_region; // struct mem_region*
};

struct cpu_mem_regions {
	__le64 count; // Number of currently allocated regions
	__le64 request_memregion; // Request for N new mem regions
    __le64 call_num;    // global atomic hypercall number
	struct cpu_mem_region
		regions[MAX_MEM_REGIONS_PER_CPU]; //struct mem_region*
};

static DEFINE_PER_CPU(struct cpu_mem_regions, cpu_regions);
static bool do_debug = false;
static DEFINE_PER_CPU(int, hypercall_num);

// Define handler function type
typedef void (*portal_op_handler)(struct mem_region *mem_region);

// Forward declarations for all operation handlers
static void handle_op_read(struct mem_region *mem_region);
static void handle_op_write(struct mem_region *mem_region);
static void handle_op_read_fd_name(struct mem_region *mem_region);
static void handle_op_read_procargs(struct mem_region *mem_region);
static void handle_op_read_socket_info(struct mem_region *mem_region);
static void handle_op_read_str(struct mem_region *mem_region);
static void handle_op_read_file(struct mem_region *mem_region);
static void handle_op_read_procenv(struct mem_region *mem_region); // Add forward declaration
static void handle_op_read_procpid(struct mem_region *mem_region); // Add forward declaration for procpid
static void handle_op_dump(struct mem_region *mem_region);
static long do_snapshot_and_coredump(void);

// Operation handler table
static const portal_op_handler op_handlers[] = {
    [HYPER_OP_READ]             = handle_op_read,
    [HYPER_OP_WRITE]            = handle_op_write,
    [HYPER_OP_READ_FD_NAME]     = handle_op_read_fd_name,
    [HYPER_OP_READ_PROCARGS]    = handle_op_read_procargs,
    [HYPER_OP_READ_SOCKET_INFO] = handle_op_read_socket_info,
    [HYPER_OP_READ_STR]         = handle_op_read_str,
    [HYPER_OP_READ_FILE]        = handle_op_read_file,
    [HYPER_OP_READ_PROCENV]     = handle_op_read_procenv, // Add handler to table
    [HYPER_OP_READ_PROCPID]     = handle_op_read_procpid, // Add handler for procpid
    [HYPER_OP_DUMP]             = handle_op_dump, // Add handler for snapshot   
};

// Helper function to initialize memory regions for current CPU
static bool allocate_new_mem_region(struct cpu_mem_regions *regions)
{
    struct mem_region *mem_region = NULL;
    int current_count;

    // Allocate a page-aligned memory region
    mem_region = (struct mem_region *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
    if (mem_region == NULL) {
        pr_err("igloo: Failed to allocate page-aligned mem_region\n");
	    return false;
    }
    current_count = le64_to_cpu(regions->count);

    // Add to our array and increment count
    regions->regions[current_count].mem_region = cpu_to_le64((unsigned long)mem_region);
    regions->regions[current_count].owner_id = 0;
    regions->count = cpu_to_le64(current_count + 1);

    // Register with hypervisor
    igloo_pr_debug("igloo: Registered new mem_region %p for CPU %d (page-aligned, idx: %d)\n", 
                  mem_region, smp_processor_id(), le64_to_cpu(regions->count) - 1);
    return true;
}

// Helper function to initialize memory regions for current CPU
static void initialize_cpu_regions(struct cpu_mem_regions *regions)
{
    int i;
    
    // Allocate the default number of memory regions
    for (i = 0; i < DEFAULT_MEM_REGIONS; i++) {
        if (!allocate_new_mem_region(regions)) {
            pr_err("igloo: Failed to allocate memory region %d during initialization\n", i);
            return;
        }
    }
    igloo_hypercall(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long)regions);
    
    pr_info("igloo: Initialized %d memory regions for CPU %d\n", 
           DEFAULT_MEM_REGIONS, smp_processor_id());
}


// bool -> was any work done?
static bool handle_post_memregion(struct mem_region *mem_region){
    int op;
    portal_op_handler handler;
    // Get the operation code
    op = le64_to_cpu(mem_region->op);
    if (op == HYPER_OP_NONE) {
	    return false;
    }

    if (op <= HYPER_OP_NONE || op >= HYPER_OP_MAX) {
        igloo_pr_debug("igloo: Invalid operation code: %d", op);
        mem_region->op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return false;
    }

    // Check if operation is within valid range
    if (op < 0 || op >= ARRAY_SIZE(op_handlers)) {
        igloo_pr_debug( "igloo: No handler for %d", op);
        mem_region->op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return false;
    }
    

    // Get the handler for this operation
    handler = op_handlers[op];

    // Execute the handler if it exists
    if (handler) {
        handler(mem_region);
    } else {
        igloo_pr_debug( "igloo: No handler for operation: %d\n", op);
        mem_region->op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
    }
    return true;
}

/*
* bool -> should we stop the hypercall loop?
*/
static bool handle_post_memregions(struct cpu_mem_regions *regions){
	int count = le64_to_cpu(regions->count);
	int i = 0;
	bool any_responses = false;
	for (i = 0; i < count; i++) {
		struct mem_region *mem_region =
			(struct mem_region *)(unsigned long)le64_to_cpu(
				regions->regions[i].mem_region);
		if (!mem_region) {
			igloo_pr_debug(
			       "igloo: No mem_region found for CPU %d\n",
			       smp_processor_id());
			continue;
		}
		bool responded = handle_post_memregion(mem_region);
        if (responded){
            any_responses = true;
        }
	}
    return any_responses;
}

int igloo_portal(unsigned long num, unsigned long arg1, unsigned long arg2)
{
	unsigned long ret;
	struct cpu_mem_regions *regions = this_cpu_ptr(&cpu_regions);
	int i;

	int call_num = this_cpu_inc_return(hypercall_num);
	igloo_pr_debug("igloo: portal call: call_num=%d\n", call_num);

	// Initialize regions if this is the first call on this CPU
	if (le64_to_cpu(regions->count) == 0) {
		initialize_cpu_regions(regions);
	}

	regions->call_num = cpu_to_le64(call_num);

	// reset all memory regions to default values
	for (i = 0; i < le64_to_cpu(regions->count); i++) {
		struct mem_region *mem_region =
			(struct mem_region *)(unsigned long)le64_to_cpu(
				regions->regions[i].mem_region);
		mem_region->op = 0;
		mem_region->addr = 0;
		mem_region->size = 0;
		regions->regions[i].owner_id = 0;
	}
	int j = 0;
	for (;;) {
		// Make the hypercall to get the next operation from the hypervisor
		ret = igloo_hypercall2(num, arg1, arg2);
		j++;
		igloo_pr_debug("igloo: portal call loop %d\n", j);
		// if no responses -> break
		if (!handle_post_memregions(regions)) {
			break;
		}
	}

	igloo_pr_debug("igloo: portal call exit: ret=%lu\n", ret);
	do_debug = false;
	return ret;
}

static void handle_op_read(struct mem_region *mem_region)
{
    int resp;
    igloo_pr_debug("igloo: Handling HYPER_OP_READ: addr=%llu, size=%llu\n",
        (unsigned long long)le64_to_cpu(mem_region->addr),
        (unsigned long long)le64_to_cpu(mem_region->size));

    resp = copy_from_user(
        (void*)mem_region->data,
        (const void __user *)(uintptr_t)le64_to_cpu(mem_region->addr),
        le64_to_cpu(mem_region->size));
    if (resp == 0 || resp == mem_region->size){
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
    } else if (resp > 0) {
        igloo_pr_debug(
            "igloo: copy_from_user partially failed for addr %llx, size %llu, resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->addr),
            (unsigned long long)le64_to_cpu(mem_region->size), resp);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_PARTIAL);
        mem_region->size = cpu_to_le64(resp);
    } else {
        igloo_pr_debug(
            "igloo: copy_from_user failed for addr %llx, size %llu, resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->addr),
            (unsigned long long)le64_to_cpu(mem_region->size), resp);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    }
}

static void handle_op_write(struct mem_region *mem_region)
{
    int resp;
    igloo_pr_debug("igloo: Handling HYPER_OP_WRITE: addr=%llu, size=%llu\n",
        (unsigned long long)le64_to_cpu(mem_region->addr),
        (unsigned long long)le64_to_cpu(mem_region->size));

    resp = copy_to_user(
        (void __user *)(uintptr_t)le64_to_cpu(mem_region->addr),
        mem_region->data,
        le64_to_cpu(mem_region->size));
    if (resp < 0) {
        igloo_pr_debug(
            "igloo: copy_to_user failed for addr %llu, size %llu resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->addr),
            (unsigned long long)le64_to_cpu(mem_region->size), resp);
        mem_region->op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
    } else {
        mem_region->op = cpu_to_le64(HYPER_RESP_WRITE_OK);
    }
}

static void handle_op_read_fd_name(struct mem_region *mem_region)
{
    struct file *file;
    int fd_num = le64_to_cpu(mem_region->addr);
    
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_FD_NAME: fd=%d\n", fd_num);
    
    file = fget(fd_num);
    if (!file) {
        igloo_pr_debug("igloo: Invalid file descriptor %d\n", fd_num);
        snprintf(mem_region->data, CHUNK_SIZE, "INVALID_FD");
        mem_region->size = cpu_to_le64(strlen(mem_region->data));
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        fput(file);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        igloo_pr_debug("igloo: Failed to get file path, error=%ld\n", PTR_ERR(path));
        snprintf(mem_region->data, CHUNK_SIZE, "UNKNOWN_PATH");
        mem_region->size = cpu_to_le64(strlen(mem_region->data));
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    } else {
        size_t len = strlen(path);
        size_t copy_len = min_t(size_t, len, CHUNK_SIZE-1);
        
        igloo_pr_debug("igloo: File path for fd %d is '%s'\n", fd_num, path);
        memcpy(mem_region->data, path, copy_len);
        mem_region->data[copy_len] = '\0';
        mem_region->size = cpu_to_le64(copy_len);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
    }
    
    kfree(path_buf);
    fput(file);
}

static void handle_op_read_procargs(struct mem_region *mem_region)
{
    struct task_struct *task = current;
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long arg_start, arg_end, len;
    char *buf = mem_region->data;
    int ret;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCARGS (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");

    if (!mm || !mm->arg_end || !mm->arg_start || mm->arg_end <= mm->arg_start) {
        goto fail;
    }

    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    len = arg_end - arg_start;

    // Ensure we don't overflow our buffer, leave space for null terminator
    if (len >= CHUNK_SIZE) {
        len = CHUNK_SIZE - 1;
        igloo_pr_debug("igloo: procargs truncated to %lu bytes\n", len);
    }

    // Check access permissions before copying
    if (!access_ok((void __user *)arg_start, len)) {
         igloo_pr_debug("igloo: access_ok failed for procargs at %#lx (len %lu)\n", arg_start, len);
         goto fail;
    }

    // Copy arguments from user space
    ret = copy_from_user(buf, (const void __user *)arg_start, len);
    if (ret != 0) {
        igloo_pr_debug("igloo: copy_from_user failed for procargs at %#lx (len %lu), ret %d\n",
                       arg_start, len, ret);
        goto fail;
    }
    
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->size = cpu_to_le64(len);
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procargs from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(mem_region->data, CHUNK_SIZE, "UNKNOWN_PROCARGS");
    mem_region->size = cpu_to_le64(strlen(mem_region->data));
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procargs failure, returning '%s'\n", mem_region->data);
}

// Add new handler function for reading environment variables
static void handle_op_read_procenv(struct mem_region *mem_region)
{
    struct task_struct *task = current;
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long env_start, env_end, len;
    char *buf = mem_region->data;
    int ret;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCENV (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");

    if (!mm || !mm->env_end || !mm->env_start || mm->env_end <= mm->env_start) {
        goto fail;
    }

    env_start = mm->env_start;
    env_end = mm->env_end;
    len = env_end - env_start;

    // Ensure we don't overflow our buffer, leave space for null terminator
    if (len >= CHUNK_SIZE) {
        len = CHUNK_SIZE - 1;
        igloo_pr_debug("igloo: procenv truncated to %lu bytes\n", len);
    }

    // Check access permissions before copying
    if (!access_ok((void __user *)env_start, len)) {
         igloo_pr_debug("igloo: access_ok failed for procenv at %#lx (len %lu)\n", env_start, len);
         goto fail;
    }

    // Copy environment variables from user space
    ret = copy_from_user(buf, (const void __user *)env_start, len);
    if (ret != 0) {
        igloo_pr_debug("igloo: copy_from_user failed for procenv at %#lx (len %lu), ret %d\n",
                       env_start, len, ret);
        goto fail;
    }
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->size = cpu_to_le64(len);
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procenv from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(mem_region->data, CHUNK_SIZE, "UNKNOWN_PROCENV");
    mem_region->size = cpu_to_le64(strlen(mem_region->data));
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procenv failure, returning '%s'\n", mem_region->data);
}

static void handle_op_read_socket_info(struct mem_region *mem_region)
{
    struct file *file;
    struct socket *sock = NULL;
    int fd_num = le64_to_cpu(mem_region->addr);
    // Reduce buffer size to avoid large stack frame warning
    char buffer[512];

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_SOCKET_INFO: fd=%d\n", fd_num);

    file = fget(fd_num);
    if (!file) {
        igloo_pr_debug("igloo: Invalid file descriptor %d\n", fd_num);
        snprintf(mem_region->data, CHUNK_SIZE, "INVALID_FD");
        mem_region->size = cpu_to_le64(strlen(mem_region->data));
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

    // Check if this file is actually a socket
    if (file->f_inode && S_ISSOCK(file->f_inode->i_mode)) {
        sock = sock_from_file(file);
    }

    if (!sock) {
        igloo_pr_debug("igloo: FD %d is not a socket\n", fd_num);
        snprintf(mem_region->data, CHUNK_SIZE, "NOT_A_SOCKET");
        mem_region->size = cpu_to_le64(strlen(mem_region->data));
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        fput(file);
        return;
    }

    // Format socket information into the buffer
    buffer[0] = '\0';

    // Get socket family
    int family = sock->sk->sk_family;
    const char *family_name = "UNKNOWN";

    switch (family) {
        case AF_INET: family_name = "AF_INET"; break;
        case AF_INET6: family_name = "AF_INET6"; break;
        case AF_UNIX: family_name = "AF_UNIX"; break;
        case AF_NETLINK: family_name = "AF_NETLINK"; break;
        case AF_PACKET: family_name = "AF_PACKET"; break;
        // Add other families as needed
    }

    // Get socket type
    int type = sock->type;
    const char *type_name = "UNKNOWN";

    switch (type) {
        case SOCK_STREAM: type_name = "SOCK_STREAM"; break;
        case SOCK_DGRAM: type_name = "SOCK_DGRAM"; break;
        case SOCK_RAW: type_name = "SOCK_RAW"; break;
        case SOCK_SEQPACKET: type_name = "SOCK_SEQPACKET"; break;
        // Add other types as needed
    }

    // Get socket state
    int state = sock->sk->sk_state;
    const char *state_name = "UNKNOWN";

    // TCP socket states
    if (family == AF_INET || family == AF_INET6) {
        switch (state) {
            case TCP_ESTABLISHED: state_name = "ESTABLISHED"; break;
            case TCP_SYN_SENT: state_name = "SYN_SENT"; break;
            case TCP_SYN_RECV: state_name = "SYN_RECV"; break;
            case TCP_FIN_WAIT1: state_name = "FIN_WAIT1"; break;
            case TCP_FIN_WAIT2: state_name = "FIN_WAIT2"; break;
            case TCP_TIME_WAIT: state_name = "TIME_WAIT"; break;
            case TCP_CLOSE: state_name = "CLOSE"; break;
            case TCP_CLOSE_WAIT: state_name = "CLOSE_WAIT"; break;
            case TCP_LAST_ACK: state_name = "LAST_ACK"; break;
            case TCP_LISTEN: state_name = "LISTEN"; break;
            case TCP_CLOSING: state_name = "CLOSING"; break;
            // Add other states as needed
        }
    }

    // Format basic socket information
    snprintf(buffer, sizeof(buffer),
            "Socket Info for FD %d:\n"
            "Family: %s (%d)\n"
            "Type: %s (%d)\n"
            "State: %s (%d)\n",
            fd_num,
            family_name, family,
            type_name, type,
            state_name, state);

    // For inet sockets, add IP and port info
    if (family == AF_INET || family == AF_INET6) {
        struct inet_sock *inet = inet_sk(sock->sk);
        if (inet) {
            char local_ip[INET6_ADDRSTRLEN] = {0};
            char remote_ip[INET6_ADDRSTRLEN] = {0};
            __be32 src_addr = inet->inet_rcv_saddr;
            __be32 dst_addr = inet->inet_daddr;
            __be16 src_port = inet->inet_sport;
            __be16 dst_port = inet->inet_dport;

            // Convert network byte order to host byte order for ports
            src_port = ntohs(src_port);
            dst_port = ntohs(dst_port);

            // Convert IPs to strings (IPv4)
            if (family == AF_INET) {
                snprintf(local_ip, sizeof(local_ip), "%pI4", &src_addr);
                snprintf(remote_ip, sizeof(remote_ip), "%pI4", &dst_addr);
            }

            // Append to buffer
            int len = strlen(buffer);
            snprintf(buffer + len, sizeof(buffer) - len,
                    "Local: %s:%u\n"
                    "Remote: %s:%u\n",
                    local_ip, src_port,
                    remote_ip, dst_port);
        }
    }

    igloo_pr_debug("igloo: Socket info: %s\n", buffer);

    // Copy the formatted information to the output buffer
    size_t len = strlen(buffer);
    size_t copy_len = min_t(size_t, len, CHUNK_SIZE-1);
    memcpy(mem_region->data, buffer, copy_len);
    mem_region->data[copy_len] = '\0';
    mem_region->size = cpu_to_le64(copy_len);
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);

    fput(file);
}

static void handle_op_read_str(struct mem_region *mem_region)
{
    unsigned long user_addr = le64_to_cpu(mem_region->addr);
    unsigned long max_size = le64_to_cpu(mem_region->size);
    ssize_t copied = 0;

    if (max_size == 0 || max_size > CHUNK_SIZE - 1){
        max_size = CHUNK_SIZE - 1;
    }
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_STR: addr=%#lx, max_size=%lu\n",
                   user_addr, max_size);

    copied = strncpy_from_user(mem_region->data, (const char __user *)user_addr, max_size);
    if (copied < 0) {
        igloo_pr_debug( "igloo: strncpy_from_user failed for addr %#lx, max_size %lu, ret %zd\n",
                       user_addr, max_size, copied);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        mem_region->size = 0;
    } else {
        mem_region->size = cpu_to_le64(copied);
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
        igloo_pr_debug("igloo: Read string '%s' (len=%zd) written to %llx\n", mem_region->data, copied, (long long unsigned int) mem_region);
        mem_region->data[copied+1] = '\0';
    }
}

static void handle_op_read_file(struct mem_region *mem_region)
{
    // Use a fixed-size path buffer, not a VLA
    char path[256];
    size_t maxlen = CHUNK_SIZE - 1;
    struct file *f;
    ssize_t n;
    loff_t pos = 0;

    // Copy the path from mem_region->data, ensure null-termination
    strncpy(path, mem_region->data, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_FILE: path='%s', offset=%llu, maxlen=%zu\n",
                   path, (unsigned long long)pos, maxlen);

    f = filp_open(path, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        n = kernel_read(f, mem_region->data, maxlen, &pos);
        filp_close(f, NULL);
        if (n > 0) {
            mem_region->data[n] = '\0';
            mem_region->size = cpu_to_le64(n);
            mem_region->op = cpu_to_le64(HYPER_RESP_READ_OK);
            igloo_pr_debug("igloo: Read file '%s' (%zd bytes)\n", path, n);
            return;
        }
    }
    snprintf(mem_region->data, maxlen, "READ_FILE_FAIL");
    mem_region->size = cpu_to_le64(strlen(mem_region->data));
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
}

// Add new handler function for reading process ID
static void handle_op_read_procpid(struct mem_region *mem_region)
{
    struct task_struct *task = current;
    pid_t pid;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCPID\n");

    if (!task) {
        snprintf(mem_region->data, CHUNK_SIZE, "UNKNOWN_PID");
        mem_region->size = cpu_to_le64(strlen(mem_region->data));
        mem_region->op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        igloo_pr_debug("igloo: Failed to get current task\n");
        return;
    }

    pid = task->pid;
    mem_region->size = cpu_to_le64(pid);
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_NUM);
    igloo_pr_debug("igloo: Read process ID: %d\n", pid);
}

static long do_snapshot_and_coredump(void)
{
    pid_t child_kpid_from_clone;
    struct pid *actual_child_pid_struct = NULL;
    long syscall_ret_val;

    struct kernel_clone_args args = {
        .exit_signal = SIGCHLD, // Keep for stability testing
    };

    printk(KERN_DEBUG "snapshot_module: (MinimalParent) Calling kernel_clone with exit_signal=%lu\n", (unsigned long)args.exit_signal);
    child_kpid_from_clone = kernel_clone(&args); // Assuming returns pid_t
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) kernel_clone returned kernel PID %d\n", child_kpid_from_clone);

    if (child_kpid_from_clone < 0) {
        syscall_ret_val = child_kpid_from_clone;
        printk(KERN_WARNING "snapshot_module: (MinimalParent) kernel_clone returned error %ld\n", syscall_ret_val);
        return syscall_ret_val;
    }
    if (child_kpid_from_clone == 0) {
        printk(KERN_WARNING "snapshot_module: (MinimalParent) kernel_clone returned PID 0, unexpected.\n");
        return -EFAULT;
    }

    actual_child_pid_struct = find_get_pid(child_kpid_from_clone);
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) find_get_pid(%d) returned struct pid pointer: %p\n", child_kpid_from_clone, actual_child_pid_struct);
    if (!actual_child_pid_struct) {
        printk(KERN_WARNING "snapshot_module: (MinimalParent) find_get_pid failed for kernel PID %d\n", child_kpid_from_clone);
        return -ESRCH;
    }

    {
        struct kernel_siginfo info;
        memset(&info, 0, sizeof(struct kernel_siginfo));
        info.si_signo = SIGABRT;
        info.si_code = SI_KERNEL;

        printk(KERN_DEBUG "snapshot_module: (MinimalParent) Sending SIGABRT to child (kernel PID %d, struct pid %p)\n",
               child_kpid_from_clone, actual_child_pid_struct);
        if (kill_pid_info(SIGABRT, &info, actual_child_pid_struct) < 0) {
            printk(KERN_WARNING "snapshot_module: (MinimalParent) kill_pid_info failed for child kernel PID %d\n", child_kpid_from_clone);
        } else {
            printk(KERN_DEBUG "snapshot_module: (MinimalParent) kill_pid_info for SIGABRT sent successfully to child kernel PID %d\n", child_kpid_from_clone);
        }
    }

    // Use child_kpid_from_clone for the KERN_INFO log as we don't have vnr without task_struct
    printk(KERN_INFO "snapshot_module: (MinimalParent) Parent PID %d forked. Child kernel PID %d sent SIGABRT.\n",
           task_pid_vnr(current), child_kpid_from_clone);

    syscall_ret_val = child_kpid_from_clone;

    // Only put the pid_struct reference
    printk(KERN_DEBUG "snapshot_module: (MinimalParent) About to call put_pid(%p) for child pid struct.\n", actual_child_pid_struct);
    put_pid(actual_child_pid_struct);
    // NO put_task_struct(child_task);

    printk(KERN_DEBUG "snapshot_module: (MinimalParent) Exiting, returning %ld.\n", syscall_ret_val);
    return syscall_ret_val;
}


static void handle_op_dump(struct mem_region *mem_region)
{
    igloo_pr_debug("igloo: Handling HYPER_OP_DUMP\n");
    snprintf(mem_region->data, CHUNK_SIZE, "UNKNOWN_PID");
    mem_region->size = cpu_to_le64(do_snapshot_and_coredump());
    mem_region->op = cpu_to_le64(HYPER_RESP_READ_NUM);
}
