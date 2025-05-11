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
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/sched/signal.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include <linux/printk.h> // Add printk include
#include "../hypercall.h"
#include "../igloo.h"
#include "../syscalls_hc.h"
#include "portal.h"
#include "portal_types.h"

// Always print debug messages with highest priority
#define igloo_pr_debug(fmt, ...) printk(KERN_EMERG "igloo-debug: " fmt, ##__VA_ARGS__)

// Need to define a way to access data since it's now part of the raw buffer
#define PORTAL_DATA_OFFSET (sizeof(region_header))
#define PORTAL_DATA(region) (&((region)->raw[PORTAL_DATA_OFFSET]))

static DEFINE_PER_CPU(struct cpu_mem_regions, cpu_regions);
static bool do_debug = true; /* Always print debug messages by default */
static DEFINE_PER_CPU(int, hypercall_num);

#define CHUNK_SIZE (PAGE_SIZE - sizeof(region_header))

// Define handler function type
typedef void (*portal_op_handler)(portal_region *mem_region);

// Forward declarations for all operation handlers
static void handle_op_read(portal_region *mem_region);
static void handle_op_write(portal_region *mem_region);
static void handle_op_read_fd_name(portal_region *mem_region);
static void handle_op_read_procargs(portal_region *mem_region);
static void handle_op_read_socket_info(portal_region *mem_region);
static void handle_op_read_str(portal_region *mem_region);
static void handle_op_read_file(portal_region *mem_region);
static void handle_op_read_procenv(portal_region *mem_region);
static void handle_op_read_procpid(portal_region *mem_region);
static void handle_op_dump(portal_region *mem_region);
// Add new OSI operation handlers
static void handle_op_osi_proc(portal_region *mem_region);
static void handle_op_osi_proc_handles(portal_region *mem_region);
static void handle_op_osi_modules(portal_region *mem_region);
static void handle_op_osi_mappings(portal_region *mem_region);
static void handle_op_osi_proc_mem(portal_region *mem_region);
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
    [HYPER_OP_READ_PROCENV]     = handle_op_read_procenv,
    [HYPER_OP_READ_PROCPID]     = handle_op_read_procpid,
    [HYPER_OP_DUMP]             = handle_op_dump,
    // Add new OSI handlers to the table
    [HYPER_OP_OSI_PROC]         = handle_op_osi_proc,
    [HYPER_OP_OSI_PROC_HANDLES] = handle_op_osi_proc_handles,
    [HYPER_OP_OSI_MODULES]      = handle_op_osi_modules,
    [HYPER_OP_OSI_MAPPINGS]     = handle_op_osi_mappings,
    [HYPER_OP_OSI_PROC_MEM]     = handle_op_osi_proc_mem,
};

// Helper function to initialize memory regions for current CPU
static bool allocate_new_mem_region(struct cpu_mem_regions *regions)
{
    portal_region *mem_region = NULL;
    int current_count;

    // Allocate a page-aligned memory region
    mem_region = (portal_region *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
    if (mem_region == NULL) {
        pr_err("igloo: Failed to allocate page-aligned mem_region\n");
	    return false;
    }
    current_count = le64_to_cpu(regions->hdr.count);  // Use hdr.count instead of count

    // Add to our array and increment count
    regions->regions[current_count].mem_region = cpu_to_le64((unsigned long)mem_region);
    regions->regions[current_count].owner_id = 0;
    regions->hdr.count = cpu_to_le64(current_count + 1);  // Use hdr.count instead of count

    // Register with hypervisor
    printk(KERN_INFO "igloo: Registered new mem_region %p for CPU %d (page-aligned, idx: %d)\n", 
                  mem_region, smp_processor_id(), le64_to_cpu(regions->hdr.count) - 1);  // Use hdr.count
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
    igloo_hypercall2(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long)regions, (unsigned long) PAGE_SIZE - sizeof(region_header));
    
    pr_info("igloo: Initialized %d memory regions for CPU %d\n", 
           DEFAULT_MEM_REGIONS, smp_processor_id());
}


// bool -> was any work done?
static bool handle_post_memregion(portal_region *mem_region){
    int op;
    portal_op_handler handler;
    // Get the operation code
    op = le64_to_cpu(mem_region->header.op);
    if (op == HYPER_OP_NONE) {
	    return false;
    }

    if (op <= HYPER_OP_NONE || op >= HYPER_OP_MAX) {
        printk(KERN_EMERG "igloo: Invalid operation code: %d", op);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return false;
    }

    // Check if operation is within valid range
    if (op < 0 || op >= ARRAY_SIZE(op_handlers)) {
        printk(KERN_EMERG "igloo: No handler for %d", op);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
        return false;
    }
    

    // Get the handler for this operation
    handler = op_handlers[op];

    // Execute the handler if it exists
    printk(KERN_EMERG "igloo: Handling operation: %d\n", op);
    if (handler) {
        handler(mem_region);
    } else {
        igloo_pr_debug( "igloo: No handler for operation: %d\n", op);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
    }
    return true;
}

/*
* bool -> should we stop the hypercall loop?
*/
static bool handle_post_memregions(struct cpu_mem_regions *regions){
	int count = le64_to_cpu(regions->hdr.count);  // Use hdr.count instead of count
	int i = 0;
	bool any_responses = false;
	for (i = 0; i < count; i++) {
		portal_region *mem_region =
			(portal_region *)(unsigned long)le64_to_cpu(
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
	printk(KERN_EMERG "igloo-call: portal call: call_num=%d\n", call_num);

	// Initialize regions if this is the first call on this CPU
	if (le64_to_cpu(regions->hdr.count) == 0) {  // Use hdr.count instead of count
		initialize_cpu_regions(regions);
	}

	regions->hdr.call_num = cpu_to_le64(call_num);  // Use hdr.call_num instead of call_num

	// reset all memory regions to default values
	for (i = 0; i < le64_to_cpu(regions->hdr.count); i++) {  // Use hdr.count instead of count
		portal_region *mem_region =
			(portal_region *)(unsigned long)le64_to_cpu(
				regions->regions[i].mem_region);
		mem_region->header.op = 0;
		mem_region->header.addr = 0;
		mem_region->header.size = 0;
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

	igloo_pr_debug("portal call exit: ret=%lu\n", ret);
	// do_debug = false;  // keep debug enabled
	return ret;
}

static void handle_op_read(portal_region *mem_region)
{
    int resp;
    igloo_pr_debug("igloo: Handling HYPER_OP_READ: addr=%llu, size=%llu\n",
        (unsigned long long)le64_to_cpu(mem_region->header.addr),
        (unsigned long long)le64_to_cpu(mem_region->header.size));

    resp = copy_from_user(
        (void*)PORTAL_DATA(mem_region),
        (const void __user *)(uintptr_t)le64_to_cpu(mem_region->header.addr),
        le64_to_cpu(mem_region->header.size));
    if (resp == 0 || resp == mem_region->header.size){
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    } else if (resp > 0) {
        igloo_pr_debug(
            "igloo: copy_from_user partially failed for addr %llx, size %llu, resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->header.addr),
            (unsigned long long)le64_to_cpu(mem_region->header.size), resp);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_PARTIAL);
        mem_region->header.size = cpu_to_le64(resp);
    } else {
        igloo_pr_debug(
            "igloo: copy_from_user failed for addr %llx, size %llu, resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->header.addr),
            (unsigned long long)le64_to_cpu(mem_region->header.size), resp);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    }
}

static void handle_op_write(portal_region *mem_region)
{
    int resp;
    igloo_pr_debug("igloo: Handling HYPER_OP_WRITE: addr=%llu, size=%llu\n",
        (unsigned long long)le64_to_cpu(mem_region->header.addr),
        (unsigned long long)le64_to_cpu(mem_region->header.size));

    resp = copy_to_user(
        (void __user *)(uintptr_t)le64_to_cpu(mem_region->header.addr),
        PORTAL_DATA(mem_region),
        le64_to_cpu(mem_region->header.size));
    if (resp < 0) {
        igloo_pr_debug(
            "igloo: copy_to_user failed for addr %llu, size %llu resp %d\n",
            (unsigned long long)le64_to_cpu(mem_region->header.addr),
            (unsigned long long)le64_to_cpu(mem_region->header.size), resp);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
    } else {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_OK);
    }
}

static void handle_op_read_fd_name(portal_region *mem_region)
{
    struct file *file;
    int fd_num = le64_to_cpu(mem_region->header.addr);
    
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_FD_NAME: fd=%d\n", fd_num);
    
    file = fget(fd_num);
    if (!file) {
        igloo_pr_debug("igloo: Invalid file descriptor %d\n", fd_num);
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "INVALID_FD");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        fput(file);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    char *path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        igloo_pr_debug("igloo: Failed to get file path, error=%ld\n", PTR_ERR(path));
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PATH");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    } else {
        size_t len = strlen(path);
        size_t copy_len = min_t(size_t, len, CHUNK_SIZE-1);
        
        igloo_pr_debug("igloo: File path for fd %d is '%s'\n", fd_num, path);
        memcpy(PORTAL_DATA(mem_region), path, copy_len);
        PORTAL_DATA(mem_region)[copy_len] = '\0';
        mem_region->header.size = cpu_to_le64(copy_len);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    }
    
    kfree(path_buf);
    fput(file);
}

static struct task_struct * get_target_task_by_id(portal_region* mem_region){
    pid_t target_pid = (pid_t)le64_to_cpu(mem_region->header.pid);
    struct task_struct *task;
    // If addr is 0, use current process, otherwise find process by PID
    if (target_pid == CURRENT_PID_NUM) {
        printk(KERN_EMERG "igloo: Using current task (pid=%d)\n", current->pid);
        task = current;
    } else {
        printk(KERN_EMERG "igloo: Looking for task with pid=%d\n", target_pid);
        // Find task by PID
        task = NULL;
        rcu_read_lock();
        task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        rcu_read_unlock();
    }
    return task;
}

static void handle_op_read_procargs(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long arg_start, arg_end, len;
    char *buf = PORTAL_DATA(mem_region);
    int ret;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCARGS (pid=%d, comm='%s')\n",
                   task ? task->pid : -1, task ? task->comm : "NULL");
    
    if (!task){
        igloo_pr_debug("igloo: No task found for pid %d\n", le64_to_cpu(mem_region->header.addr));
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_TASK");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

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

    // Use different methods based on whether we're accessing current task or another task
    if (task != current) {
        // For other processes, use access_remote_vm
        igloo_pr_debug("igloo: Using access_remote_vm for process %d\n", task->pid);
        ret = 0;
        if (access_remote_vm(mm, arg_start, buf, len, FOLL_FORCE) != len) {
            igloo_pr_debug("igloo: access_remote_vm failed for procargs at %#lx (len %lu)\n",
                         arg_start, len);
            ret = -EFAULT;
        }
    } else {
        // For current process, use the standard copy_from_user
        igloo_pr_debug("igloo: Using copy_from_user for current process\n");
        // Check access permissions before copying
        if (!access_ok((void __user *)arg_start, len)) {
             igloo_pr_debug("igloo: access_ok failed for procargs at %#lx (len %lu)\n", arg_start, len);
             goto fail;
        }

        // Copy arguments from user space
        ret = copy_from_user(buf, (const void __user *)arg_start, len);
    }
    
    if (ret != 0) {
        igloo_pr_debug("igloo: memory access failed for procargs at %#lx (len %lu), ret %d\n",
                       arg_start, len, ret);
        goto fail;
    }
    
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->header.size = cpu_to_le64(len);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procargs from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCARGS");
    mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procargs failure, returning '%s'\n", PORTAL_DATA(mem_region));
}

// Add new handler function for reading environment variables
static void handle_op_read_procenv(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    struct mm_struct *mm = task ? task->mm : NULL;
    unsigned long env_start, env_end, len;
    char *buf = PORTAL_DATA(mem_region);
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

    // Use different methods based on whether we're accessing current task or another task
    if (task != current) {
        // For other processes, use access_remote_vm
        igloo_pr_debug("igloo: Using access_remote_vm for process %d\n", task->pid);
        ret = 0;
        if (access_remote_vm(mm, env_start, buf, len, FOLL_FORCE) != len) {
            igloo_pr_debug("igloo: access_remote_vm failed for procenv at %#lx (len %lu)\n",
                         env_start, len);
            ret = -EFAULT;
        }
    } else {
        // For current process, use the standard copy_from_user
        igloo_pr_debug("igloo: Using copy_from_user for current process\n");
        // Check access permissions before copying
        if (!access_ok((void __user *)env_start, len)) {
             igloo_pr_debug("igloo: access_ok failed for procenv at %#lx (len %lu)\n", env_start, len);
             goto fail;
        }

        // Copy environment variables from user space
        ret = copy_from_user(buf, (const void __user *)env_start, len);
    }
    
    if (ret != 0) {
        igloo_pr_debug("igloo: memory access failed for procenv at %#lx (len %lu), ret %d\n",
                       env_start, len, ret);
        goto fail;
    }
    // Ensure final null termination
    buf[len] = '\0';

    mem_region->header.size = cpu_to_le64(len);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
    igloo_pr_debug("igloo: Read procenv from stack: '%s' (len=%lu)\n", buf, len);
    return;

fail:
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PROCENV");
    mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
    igloo_pr_debug("igloo: procenv failure, returning '%s'\n", PORTAL_DATA(mem_region));
}

static void handle_op_read_socket_info(portal_region *mem_region)
{
    struct file *file;
    struct socket *sock = NULL;
    int fd_num = le64_to_cpu(mem_region->header.addr);
    // Reduce buffer size to avoid large stack frame warning
    char buffer[512];

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_SOCKET_INFO: fd=%d\n", fd_num);

    file = fget(fd_num);
    if (!file) {
        igloo_pr_debug("igloo: Invalid file descriptor %d\n", fd_num);
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "INVALID_FD");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

    // Check if this file is actually a socket
    if (file->f_inode && S_ISSOCK(file->f_inode->i_mode)) {
        sock = sock_from_file(file);
    }

    if (!sock) {
        igloo_pr_debug("igloo: FD %d is not a socket\n", fd_num);
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "NOT_A_SOCKET");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
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
    memcpy(PORTAL_DATA(mem_region), buffer, copy_len);
    PORTAL_DATA(mem_region)[copy_len] = '\0';
    mem_region->header.size = cpu_to_le64(copy_len);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);

    fput(file);
}

static void handle_op_read_str(portal_region *mem_region)
{
    unsigned long user_addr = le64_to_cpu(mem_region->header.addr);
    unsigned long max_size = le64_to_cpu(mem_region->header.size);
    ssize_t copied = 0;

    if (max_size == 0 || max_size > CHUNK_SIZE - 1){
        max_size = CHUNK_SIZE - 1;
    }
    igloo_pr_debug("igloo: Handling HYPER_OP_READ_STR: addr=%#lx, max_size=%lu\n",
                   user_addr, max_size);

    copied = strncpy_from_user(PORTAL_DATA(mem_region), (const char __user *)user_addr, max_size);
    if (copied < 0) {
        igloo_pr_debug( "igloo: strncpy_from_user failed for addr %#lx, max_size %lu, ret %zd\n",
                       user_addr, max_size, copied);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        mem_region->header.size = 0;
    } else {
        mem_region->header.size = cpu_to_le64(copied);
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
        igloo_pr_debug("igloo: Read string '%s' (len=%zd) written to %llx\n", PORTAL_DATA(mem_region), copied, (long long unsigned int) mem_region);
        PORTAL_DATA(mem_region)[copied+1] = '\0';
    }
}

static void handle_op_read_file(portal_region *mem_region)
{
    // Use a fixed-size path buffer, not a VLA
    char path[256];
    struct file *f;
    ssize_t n;
    loff_t pos = le64_to_cpu(mem_region->header.addr);  // Use addr as file offset
    size_t requested_size = le64_to_cpu(mem_region->header.size); // Use size as max bytes to read
    size_t maxlen;

    // Ensure we don't overflow our buffer
    if (requested_size == 0 || requested_size > CHUNK_SIZE - 1) {
        maxlen = CHUNK_SIZE - 1;
    } else {
        maxlen = requested_size;
    }

    // Copy the path from mem_region->data, ensure null-termination
    strncpy(path, PORTAL_DATA(mem_region), sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_FILE: path='%s', offset=%llu, maxlen=%zu\n",
                   path, (unsigned long long)pos, maxlen);

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        long err = PTR_ERR(f);
        igloo_pr_debug("igloo: Failed to open file '%s', error=%ld\n", path, err);
    } else {
        igloo_pr_debug("igloo: Successfully opened file '%s', attempting to read %zu bytes at offset %llu\n", 
                       path, maxlen, (unsigned long long)pos);
        n = kernel_read(f, PORTAL_DATA(mem_region), maxlen, &pos);
        
        if (n < 0) {
            igloo_pr_debug("igloo: kernel_read failed for '%s', error=%zd\n", path, n);
        } else if (n == 0) {
            igloo_pr_debug("igloo: End of file reached for '%s' at offset %llu\n", path, (unsigned long long)(pos));
        } else {
            PORTAL_DATA(mem_region)[n] = '\0';  // Null-terminate the data
            mem_region->header.size = cpu_to_le64(n);
            mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
            igloo_pr_debug("igloo: Read file '%s' (%zd bytes from offset %llu to %llu)\n", 
                          path, n, (unsigned long long)(pos - n), (unsigned long long)pos);
            filp_close(f, NULL);
            return;
        }
        
        filp_close(f, NULL);
    }
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE - 1, "READ_FILE_FAIL");
    mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
}

// Add new handler function for reading process ID
static void handle_op_read_procpid(portal_region *mem_region)
{
    struct task_struct *task = get_target_task_by_id(mem_region);
    pid_t pid;

    igloo_pr_debug("igloo: Handling HYPER_OP_READ_PROCPID\n");

    if (!task) {
        snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PID");
        mem_region->header.size = cpu_to_le64(strlen(PORTAL_DATA(mem_region)));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        igloo_pr_debug("igloo: Failed to get current task\n");
        return;
    }

    pid = task->pid;
    mem_region->header.size = cpu_to_le64(pid);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_NUM);
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


static void handle_op_dump(portal_region *mem_region)
{
    igloo_pr_debug("igloo: Handling HYPER_OP_DUMP\n");
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE, "UNKNOWN_PID");
    mem_region->header.size = cpu_to_le64(do_snapshot_and_coredump());
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_NUM);
}

// Implementation of OSI handler functions

static void handle_op_osi_proc(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct osi_proc *proc;
    char *data_buf = PORTAL_DATA(mem_region);
    size_t name_len = 0;
    size_t total_size = sizeof(struct osi_proc);

    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task immediately after getting it
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC for NULL task\n");
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC for PID %d\n", task->pid);
    
    mm = task->mm;

    // Initialize the OSI proc structure at the beginning of data buffer
    proc = (struct osi_proc *)data_buf;
    proc->taskd = cpu_to_le64((unsigned long)task);
    
    if (mm && mm->pgd) {
        proc->pgd = cpu_to_le64((unsigned long)mm->pgd);
        proc->map_count = cpu_to_le64(mm->map_count);
        proc->start_brk = cpu_to_le64(mm->start_brk);
        proc->brk = cpu_to_le64(mm->brk);
        proc->start_stack = cpu_to_le64(mm->start_stack);
        proc->start_code = cpu_to_le64(mm->start_code);
        proc->end_code = cpu_to_le64(mm->end_code);
        proc->start_data = cpu_to_le64(mm->start_data);
        proc->end_data = cpu_to_le64(mm->end_data);
        proc->arg_start = cpu_to_le64(mm->arg_start);
        proc->arg_end = cpu_to_le64(mm->arg_end);
        proc->env_start = cpu_to_le64(mm->env_start);
        proc->env_end = cpu_to_le64(mm->env_end);
        proc->saved_auxv = cpu_to_le64((unsigned long)mm->saved_auxv);
        proc->mmap_base = cpu_to_le64(mm->mmap_base);
        proc->task_size = cpu_to_le64(mm->task_size);
    } else {
        proc->pgd = 0;
    }
    
    proc->pid = cpu_to_le64(task->pid);
    proc->ppid = cpu_to_le64(task->real_parent ? task->real_parent->pid : 0);
    
    // Put name after the struct
    proc->name_offset = cpu_to_le64(sizeof(struct osi_proc));
    name_len = strnlen(task->comm, TASK_COMM_LEN);
    // Ensure we don't overflow our buffer
    if (sizeof(struct osi_proc) + name_len + 1 > CHUNK_SIZE) {
        name_len = CHUNK_SIZE - sizeof(struct osi_proc) - 1;
    }
    strncpy(data_buf + sizeof(struct osi_proc), task->comm, name_len);
    data_buf[sizeof(struct osi_proc) + name_len] = '\0';
    printk(KERN_EMERG "igloo: proc name: %s\n", task->comm);
    printk(KERN_EMERG "igloo: proc name in buf: %s\n", data_buf + sizeof(struct osi_proc));
    
    total_size += name_len; // do not null terminator
    
    // Set create time
    proc->create_time = cpu_to_le64(task->start_time);
    
    mem_region->header.size = cpu_to_le64(total_size);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

static void handle_op_osi_proc_handles(portal_region *mem_region)
{
    struct task_struct *task;
    struct osi_proc_handle *handle;
    int count = 0;
    size_t max_handles;
    char *data_buf = PORTAL_DATA(mem_region);
    __le64 *handles_count = (__le64 *)data_buf;

    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_HANDLES\n");
    
    // Reserve space for count at beginning
    max_handles = (CHUNK_SIZE - sizeof(__le64)) / sizeof(struct osi_proc_handle);
    
    igloo_pr_debug("osi_proc_handles: max_handles=%zu\n", max_handles);
    
    // First 8 bytes will store the count
    *handles_count = 0;
    
    // Start filling handles after count field
    handle = (struct osi_proc_handle *)(data_buf + sizeof(__le64));
    
    // Iterate through tasks
    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm;
        
        if (count >= max_handles) {
            break;
        }
        
        mm = task->mm;
        if (!mm) {
            continue; // Skip kernel threads
        }
        
        handle->taskd = cpu_to_le64((unsigned long)task);
        handle->asid = cpu_to_le64((unsigned long)(mm ? mm->pgd : 0));
        handle->start_time = cpu_to_le64(task->start_time);
        
        handle++;
        count++;
    }
    rcu_read_unlock();
    
    // Update count
    *handles_count = cpu_to_le32(count);
    
    mem_region->header.size = cpu_to_le64(sizeof(__le64) + (count * sizeof(struct osi_proc_handle)));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

static void handle_op_osi_modules(portal_region *mem_region)
{
    struct osi_module *osi_mod;
    int count = 0;
    size_t max_modules;
    char *data_buf = PORTAL_DATA(mem_region);
    __le64 *modules_count = (__le64 *)data_buf;
    char *string_buf;
    size_t string_offset;

    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_MODULES\n");
    
    // Reserve space for count at beginning
    max_modules = (CHUNK_SIZE / 2) / sizeof(struct osi_module);
    
    // First 4 bytes will store the count
    *modules_count = 0;
    
    // Start filling modules after count field
    osi_mod = (struct osi_module *)(data_buf + sizeof(__le64));
    
    // String buffer starts after module structures
    string_offset = sizeof(__le64) + (max_modules * sizeof(struct osi_module));
    string_buf = data_buf + string_offset;
    
    #ifdef CONFIG_MODULES
    // Get information about modules from /proc/modules as we can't access modules list directly
    struct file *f;
    char buf[256];
    ssize_t n;
    loff_t pos = 0;
    
    f = filp_open("/proc/modules", O_RDONLY, 0);
    if (!IS_ERR(f)) {
        while ((n = kernel_read(f, buf, sizeof(buf) - 1, &pos)) > 0) {
            char *line = buf;
            char *end = buf + n;
            buf[n] = '\0';
            
            while (line < end && count < max_modules) {
                char *name_end;
                char *size_start, *size_end;
                unsigned long mod_size = 0;
                size_t name_len;
                char *curr_str;
                
                // Parse module name
                name_end = strchr(line, ' ');
                if (!name_end)
                    break;
                
                *name_end = '\0';
                name_len = name_end - line;
                
                // Ensure we don't overflow the buffer
                if (string_offset + name_len + 1 > CHUNK_SIZE - 1) {
                    igloo_pr_debug("igloo: Module name would overflow buffer, stopping at %d modules\n", count);
                    break;
                }
                
                // Parse module size
                size_start = name_end + 1;
                while (*size_start == ' ' && size_start < end)
                    size_start++;
                
                size_end = strchr(size_start, ' ');
                if (size_end) {
                    *size_end = '\0';
                    if (kstrtoul(size_start, 10, &mod_size) != 0)
                        mod_size = 0;
                }
                
                // Fill module info
                osi_mod->modd = 0; // We don't have pointer to actual module
                osi_mod->base = 0; // We don't have base address from /proc/modules
                osi_mod->size = cpu_to_le64(mod_size);
                
                // Add module name to string buffer
                curr_str = string_buf;
                strncpy(curr_str, line, name_len);
                curr_str[name_len] = '\0';
                
                osi_mod->name_offset = cpu_to_le64(string_offset);
                string_offset += name_len + 1;
                string_buf += name_len + 1;
                
                // Use the same string for file
                osi_mod->file_offset = osi_mod->name_offset;
                
                // Additional fields
                osi_mod->offset = 0;
                osi_mod->flags = 0;
                
                osi_mod++;
                count++;
                
                // Move to next line
                line = size_end ? size_end + 1 : end;
                while (line < end && (*line == ' ' || *line == '\n'))
                    line++;
            }
            
            if (count >= max_modules)
                break;
        }
        filp_close(f, NULL);
    }
    #endif // CONFIG_MODULES
    
    // Update count
    *modules_count = cpu_to_le32(count);
    
    mem_region->header.size = cpu_to_le64(string_offset);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

static void handle_op_osi_mappings(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct osi_module *mapping;
    int count = 0;
    size_t max_mappings;
    char *data_buf = PORTAL_DATA(mem_region);
    __le64 *mappings_count = (__le64 *)data_buf;
    char *string_buf;
    size_t string_offset;

    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task before using task->pid
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_MAPPINGS for NULL task\n");
        mem_region->header.size = cpu_to_le64(sizeof(__le64));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_MAPPINGS for PID %d\n", task->pid);
    
    mm = task->mm;

    // Reserve space for count at beginning
    max_mappings = (CHUNK_SIZE / 2) / sizeof(struct osi_module);
    
    // First 4 bytes will store the count
    *mappings_count = 0;
    
    // Check if we have a valid mm_struct
    if (!mm) {
        mem_region->header.size = cpu_to_le64(sizeof(__le64));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
        return;
    }
    
    // Start filling mappings after count field
    mapping = (struct osi_module *)(data_buf + sizeof(__le64));
    
    // String buffer starts after module structures
    string_offset = sizeof(__le64) + (max_mappings * sizeof(struct osi_module));
    string_buf = data_buf + string_offset;
    
    // Iterate through the process memory mappings
    if (mmap_read_lock_killable(mm)) {
        mem_region->header.size = cpu_to_le64(sizeof(__le64));
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }

    // Use VMA iteration API (new API for Linux 6.x)
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        char mapping_name[256] = "[anonymous]";
        size_t name_len;
        char *curr_str;
        
        if (count >= max_mappings || string_offset >= CHUNK_SIZE - 256)
            break;
        
        // Get mapping name if it's a file
        if (vma->vm_file) {
            char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (path_buf) {
                char *path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
                if (!IS_ERR(path)) {
                    strncpy(mapping_name, path, sizeof(mapping_name)-1);
                    mapping_name[sizeof(mapping_name)-1] = '\0';
                }
                kfree(path_buf);
            }
        }
        
        // Fill mapping info
        mapping->modd = 0; // Not applicable
        mapping->base = cpu_to_le64(vma->vm_start);
        mapping->size = cpu_to_le64(vma->vm_end - vma->vm_start);
        
        // Add mapping name to string buffer
        curr_str = string_buf;
        name_len = strlen(mapping_name);
        // Check if we have enough space for the name
        if (string_offset + name_len + 1 > CHUNK_SIZE) {
            break;
        }
        strncpy(curr_str, mapping_name, name_len);
        curr_str[name_len] = '\0';
        
        mapping->name_offset = cpu_to_le64(string_offset);
        string_offset += name_len + 1;
        string_buf += name_len + 1;
        
        // Use the same string for file (in real implementation these might differ)
        mapping->file_offset = mapping->name_offset;
        
        // Additional fields
        mapping->offset = cpu_to_le64(vma->vm_pgoff << PAGE_SHIFT);
        mapping->flags = cpu_to_le64(vma->vm_flags);
        
        mapping++;
        count++;
    }
    
    mmap_read_unlock(mm);
    
    // Update count
    *mappings_count = cpu_to_le32(count);
    
    mem_region->header.size = cpu_to_le64(string_offset);
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}

static void handle_op_osi_proc_mem(portal_region *mem_region)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct osi_proc_mem {
        __le64 start_brk;
        __le64 brk;
    };
    struct osi_proc_mem *proc_mem;
    
    task = get_target_task_by_id(mem_region);
    
    // Check for NULL task before using task->pid
    if (!task) {
        igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_MEM for NULL task\n");
        proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    // Now we can safely use task->pid
    igloo_pr_debug("igloo: Handling HYPER_OP_OSI_PROC_MEM for PID %d\n", task->pid);
    
    mm = task->mm;

    // Check if we have enough buffer space for the structure
    if (sizeof(struct osi_proc_mem) > CHUNK_SIZE) {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem = (struct osi_proc_mem *)PORTAL_DATA(mem_region);
    
    if (!mm) {
        proc_mem->start_brk = 0;
        proc_mem->brk = 0;
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_FAIL);
        return;
    }
    
    proc_mem->start_brk = cpu_to_le64(mm->start_brk);
    proc_mem->brk = cpu_to_le64(mm->brk);
    
    mem_region->header.size = cpu_to_le64(sizeof(struct osi_proc_mem));
    mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_OK);
}
