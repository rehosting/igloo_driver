#include "portal_internal.h"

void handle_op_read_file(portal_region *mem_region)
{
    // Use a fixed-size path buffer, not a VLA
    char path[256];
    struct file *f;
    ssize_t n;
    loff_t pos = mem_region->header.addr;  // Use addr as file offset
    size_t requested_size = mem_region->header.size; // Use size as max bytes to read
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
            mem_region->header.size = n;
            mem_region->header.op = HYPER_RESP_READ_OK;
            igloo_pr_debug("igloo: Read file '%s' (%zd bytes from offset %llu to %llu)\n", 
                          path, n, (unsigned long long)(pos - n), (unsigned long long)pos);
            filp_close(f, NULL);
            return;
        }
        
        filp_close(f, NULL);
    }
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE - 1, "READ_FILE_FAIL");
    mem_region->header.size = strlen(PORTAL_DATA(mem_region));
    mem_region->header.op = HYPER_RESP_READ_FAIL;
}

void handle_op_write_file(portal_region *mem_region)
{
    char path[256];
    struct file *f;
    ssize_t n;
    loff_t pos = (mem_region->header.addr);  // Use addr as file offset
    size_t write_size = (mem_region->header.size); // Use size as bytes to write
    size_t maxlen;
    char *data_ptr;

    // Ensure we don't overflow our buffer
    if (write_size == 0 || write_size > CHUNK_SIZE - 1) {
        maxlen = CHUNK_SIZE - 1;
    } else {
        maxlen = write_size;
    }

    // Copy the path from mem_region->data, ensure null-termination
    strncpy(path, PORTAL_DATA(mem_region), sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    // Data to write is after the path string
    data_ptr = PORTAL_DATA(mem_region) + strlen(path) + 1;

    igloo_pr_debug("igloo: Handling HYPER_OP_WRITE_FILE: path='%s', offset=%llu, size=%zu\n",
                   path, (unsigned long long)pos, maxlen);

    f = filp_open(path, O_WRONLY | O_CREAT, 0644);
    if (IS_ERR(f)) {
        long err = PTR_ERR(f);
        igloo_pr_debug("igloo: Failed to open file '%s' for write, error=%ld\n", path, err);
    } else {
        igloo_pr_debug("igloo: Successfully opened file '%s' for write, attempting to write %zu bytes at offset %llu\n", 
                       path, maxlen, (unsigned long long)pos);
        n = kernel_write(f, data_ptr, maxlen, &pos);
        if (n < 0) {
            igloo_pr_debug("igloo: kernel_write failed for '%s', error=%zd\n", path, n);
        } else {
            mem_region->header.size = n;
            mem_region->header.op = HYPER_RESP_READ_NUM;
            igloo_pr_debug("igloo: Wrote file '%s' (%zd bytes at offset %llu)\n", 
                          path, n, (unsigned long long)(pos - n));
            filp_close(f, NULL);
            return;
        }
        filp_close(f, NULL);
    }
    snprintf(PORTAL_DATA(mem_region), CHUNK_SIZE - 1, "WRITE_FILE_FAIL");
    mem_region->header.size = strlen(PORTAL_DATA(mem_region));
    mem_region->header.op = HYPER_RESP_WRITE_FAIL;
}
