#include "portal_internal.h"

struct task_struct *get_target_task_by_id(portal_region* mem_region)
{
    pid_t target_pid = (pid_t)le64_to_cpu(mem_region->header.pid);
    struct task_struct *task;
    // If addr is 0, use current process, otherwise find process by PID
    if (target_pid == CURRENT_PID_NUM) {
        igloo_pr_debug("igloo: Using current task (pid=%d)\n", current->pid);
        task = current;
    } else {
        igloo_pr_debug("igloo: Looking for task with pid=%d\n", target_pid);
        // Find task by PID
        rcu_read_lock();
        task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
        rcu_read_unlock();
    }
    return task;
}

void handle_op_read(portal_region *mem_region)
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

void handle_op_write(portal_region *mem_region)
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

void handle_op_read_str(portal_region *mem_region)
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
