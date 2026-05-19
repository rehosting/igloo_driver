#include "portal_internal.h"

void handle_op_config_syscall_logger(portal_region *mem_region)
{
    struct syscall_logger_config cfg;
    size_t sz = min_t(size_t, mem_region->header.size, sizeof(cfg));

    memset(&cfg, 0, sizeof(cfg));
    if (sz)
        memcpy(&cfg, PORTAL_DATA(mem_region), sz);
    syscall_logger_configure(&cfg);
    mem_region->header.op = HYPER_RESP_WRITE_OK;
    mem_region->header.size = 0;
}

void handle_op_register_syscall_logger_schema(portal_region *mem_region)
{
    struct syscall_logger_schema schema;
    size_t sz = min_t(size_t, mem_region->header.size, sizeof(schema));

    memset(&schema, 0, sizeof(schema));
    if (sz)
        memcpy(&schema, PORTAL_DATA(mem_region), sz);
    schema.name[SYSCALL_NAME_MAX_LEN - 1] = '\0';
    syscall_logger_register_schema(&schema);
    mem_region->header.op = HYPER_RESP_WRITE_OK;
    mem_region->header.size = 0;
}

void handle_op_drain_syscall_log(portal_region *mem_region)
{
    size_t copied;

    copied = syscall_logger_drain(PORTAL_DATA(mem_region), CHUNK_SIZE);
    if (copied) {
        mem_region->header.op = HYPER_RESP_READ_OK;
        mem_region->header.size = copied;
    } else {
        mem_region->header.op = HYPER_RESP_READ_NUM;
        mem_region->header.size = 0;
    }
}
