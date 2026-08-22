#include "portal_internal.h"

/*
 * The blob is exe\0 argv..\0 \0 envp..\0 \0 \0, built by the host in
 * fs.exec_program. Two properties of the parse are worth stating because both
 * used to be assumed:
 *
 *   - It is BOUNDED by the region. The walk was `buf += strlen(buf) + 1` with
 *     no end pointer, so a blob that was not properly double-NUL terminated --
 *     a stale host, a truncated write -- walked strlen() off the end of the
 *     page. The host is the only caller and now always terminates it correctly,
 *     so this is defence in depth rather than a live bug; a length-free walk
 *     over a page boundary is still a bug.
 *
 *   - An over-long exe_path is REFUSED, not truncated. strncpy left a
 *     shortened path that call_usermodehelper would happily run as a different
 *     binary, and -- worse -- `offset += strlen(exe_path) + 1` then used the
 *     TRUNCATED length, so argv parsing started in the middle of the real path
 *     and every argument was garbage. Failing with -ENAMETOOLONG says so.
 */
#define EXEC_MAX_ARGS 15

/* Next NUL-terminated string at @p, or NULL if it is not fully inside [p,end). */
static char *exec_next(char *p, const char *end)
{
    char *q = p;

    while (q < end && *q)
        q++;
    return (q < end) ? q + 1 : NULL;
}

// Handler for executing a program from the kernel
void handle_op_exec(portal_region *mem_region)
{
    char exe_path[256];
    char *base = (char *)PORTAL_DATA(mem_region);
    const char *end = base + CHUNK_SIZE;
    char *arg_buf, *env_buf, *next;
    char *argv[EXEC_MAX_ARGS + 1] = {0};
    char *envp[EXEC_MAX_ARGS + 1] = {0};
    int i;
    int ret;
    int wait_mode;

    // Read executable path (null-terminated), refusing one that does not fit
    next = exec_next(base, end);
    if (!next || (size_t)(next - base) > sizeof(exe_path)) {
        printk(KERN_WARNING "IGLOO: handle_op_exec: exe_path is unterminated or "
               "longer than %zu bytes; refusing rather than running a "
               "truncated path\n", sizeof(exe_path) - 1);
        mem_region->header.size = -ENAMETOOLONG;
        mem_region->header.op = HYPER_RESP_READ_NUM;
        return;
    }
    strncpy(exe_path, base, sizeof(exe_path) - 1);
    exe_path[sizeof(exe_path) - 1] = '\0';
    igloo_pr_debug("igloo: handle_op_exec: exe_path='%s'\n", exe_path);

    // Read arguments (null-separated, double-null terminated)
    arg_buf = next;
    for (i = 0; i < EXEC_MAX_ARGS && arg_buf < end && *arg_buf; i++) {
        argv[i] = arg_buf;
        igloo_pr_debug("igloo: handle_op_exec: argv[%d]='%s'\n", i, arg_buf);
        arg_buf = exec_next(arg_buf, end);
        if (!arg_buf)
            goto unterminated;
    }
    argv[i] = NULL;
    if (arg_buf >= end)
        goto unterminated;
    if (i == EXEC_MAX_ARGS && *arg_buf) {
        /* More arguments than we can pass. Refused, because the old code did
         * not merely drop them: env_buf was derived from where the argv walk
         * stopped, which in this case is the MIDDLE of the argument list, so
         * the environment came out as garbage too. Silently running a
         * truncated command line with a corrupt environment is the worst of
         * the available outcomes. */
        printk(KERN_WARNING "IGLOO: handle_op_exec: more than %d arguments; "
               "refusing rather than truncating\n", EXEC_MAX_ARGS);
        mem_region->header.size = -E2BIG;
        mem_region->header.op = HYPER_RESP_READ_NUM;
        return;
    }

    // Read environment variables (null-separated, double-null terminated)
    env_buf = arg_buf + 1;   /* step over the argv terminator */
    for (i = 0; i < EXEC_MAX_ARGS && env_buf < end && *env_buf; i++) {
        envp[i] = env_buf;
        igloo_pr_debug("igloo: handle_op_exec: envp[%d]='%s'\n", i, env_buf);
        env_buf = exec_next(env_buf, end);
        if (!env_buf)
            goto unterminated;
    }
    envp[i] = NULL;
    if (i == EXEC_MAX_ARGS && env_buf < end && *env_buf) {
        printk(KERN_WARNING "IGLOO: handle_op_exec: more than %d environment "
               "variables; refusing rather than truncating\n", EXEC_MAX_ARGS);
        mem_region->header.size = -E2BIG;
        mem_region->header.op = HYPER_RESP_READ_NUM;
        return;
    }

    igloo_pr_debug("igloo: handle_op_exec: exe='%s'\n", exe_path);


    // Determine wait mode from mem_region->header.addr
    wait_mode = (mem_region->header.addr) ? UMH_WAIT_PROC : UMH_NO_WAIT;

    // Execute the program
    ret = call_usermodehelper(exe_path, argv, envp, wait_mode);
    igloo_pr_debug("igloo: handle_op_exec: call_usermodehelper returned %d\n", ret);

    // Write result back
    mem_region->header.size = ret;
    mem_region->header.op = HYPER_RESP_READ_NUM;
    return;

unterminated:
    printk(KERN_WARNING "IGLOO: handle_op_exec: blob is not double-NUL "
           "terminated inside the region; refusing\n");
    mem_region->header.size = -EINVAL;
    mem_region->header.op = HYPER_RESP_READ_NUM;
}

