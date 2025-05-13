#include "portal_internal.h"

// Handler for executing a program from the kernel
void handle_op_exec(portal_region *mem_region)
{
    char exe_path[256];
    char *arg_buf, *env_buf;
    char *argv[16] = {0};
    char *envp[16] = {0};
    size_t offset = 0;
    int i;
    int ret;

    // Read executable path (null-terminated)
    strncpy(exe_path, PORTAL_DATA(mem_region), sizeof(exe_path) - 1);
    exe_path[sizeof(exe_path) - 1] = '\0';
    offset += strlen(exe_path) + 1;
    igloo_pr_debug("igloo: handle_op_exec: exe_path='%s'\n", exe_path);

    // Read arguments (null-separated, double-null terminated)
    arg_buf = PORTAL_DATA(mem_region) + offset;
    for (i = 0; i < 15 && *arg_buf; i++) {
        argv[i] = arg_buf;
        igloo_pr_debug("igloo: handle_op_exec: argv[%d]='%s'\n", i, arg_buf);
        arg_buf += strlen(arg_buf) + 1;
    }
    argv[i] = NULL;
    offset = arg_buf - (char *)PORTAL_DATA(mem_region);

    // Read environment variables (null-separated, double-null terminated)
    env_buf = PORTAL_DATA(mem_region) + offset;
    for (i = 0; i < 15 && *env_buf; i++) {
        envp[i] = env_buf;
        igloo_pr_debug("igloo: handle_op_exec: envp[%d]='%s'\n", i, env_buf);
        env_buf += strlen(env_buf) + 1;
    }
    envp[i] = NULL;
    offset = env_buf - (char *)PORTAL_DATA(mem_region);

    igloo_pr_debug("igloo: handle_op_exec: exe='%s'\n", exe_path);


    // Determine wait mode from mem_region->header.addr
    int wait_mode = le64_to_cpu(mem_region->header.addr) ? UMH_WAIT_PROC : UMH_NO_WAIT;

    // Execute the program
    ret = call_usermodehelper(exe_path, argv, envp, wait_mode);
    igloo_pr_debug("igloo: handle_op_exec: call_usermodehelper returned %d\n", ret);

    // Write result back
    mem_region->header.size = cpu_to_le64(ret);
    if (ret == 0) {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_NUM);
        // Optionally, write output_path to buffer if requested
    } else {
        mem_region->header.op = cpu_to_le64(HYPER_RESP_READ_NUM);
    }
}

