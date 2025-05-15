#include "portal_internal.h"
#include <linux/slab.h>

int igloo_test_function(int a, int b, int c, int d, int e, int f, int g, int h);
void *igloo_kzalloc(size_t size);
void igloo_kfree(void *ptr);
int igloo_printk(const char *fmt, ...);

int igloo_test_function(int a, int b, int c, int d, int e, int f, int g, int h)
{
    printk(KERN_EMERG "igloo: test_function called with args: %d %d %d %d %d %d %d %d\n", 
           a, b, c, d, e, f, g, h);
    return a + b + c + d + e + f + g + h;
}

void* igloo_kzalloc(size_t size)
{
    void *ptr = kzalloc(size, GFP_KERNEL);
    if (!ptr) {
        printk(KERN_ERR "igloo: kzalloc failed for size %zu\n", size);
    }
    return ptr;
}

void igloo_kfree(void *ptr)
{
    if (ptr) {
        kfree(ptr);
    } else {
        printk(KERN_ERR "igloo: kfree called with NULL pointer\n");
    }
}

int igloo_printk(const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vprintk(fmt, args);
    va_end(args);

    return ret;
}


/*
 * Execute a function through the FFI mechanism
 * This allows calling kernel functions dynamically with up to 8 arguments
 */
void handle_op_ffi_exec(portal_region *mem_region)
{
    struct portal_ffi_call *ffi_data;
    unsigned long result = 0;
    
    igloo_pr_debug("igloo: Handling HYPER_OP_FFI_EXEC\n");
    
    /* Map the data buffer to our FFI structure */
    ffi_data = (struct portal_ffi_call *)PORTAL_DATA(mem_region);
    
    /* Validate function pointer */
    if (!ffi_data->func_ptr || !virt_addr_valid(ffi_data->func_ptr)) {
        igloo_pr_debug("igloo: Invalid function pointer %p\n", ffi_data->func_ptr);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    /* Safety check on number of arguments - limit to 8 */
    if (ffi_data->num_args > 8) {
        igloo_pr_debug("igloo: Too many arguments (%lu > 8)\n", ffi_data->num_args);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        return;
    }
    
    igloo_pr_debug("igloo: Calling function at %p with %lu arguments\n", 
                  ffi_data->func_ptr, ffi_data->num_args);
    
    /* Call the function with the appropriate number of arguments */
    switch (ffi_data->num_args) {
        case 0:
            result = ((unsigned long (*)(void))ffi_data->func_ptr)();
            break;
        case 1:
            result = ((unsigned long (*)(unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0]);
            break;
        case 2:
            result = ((unsigned long (*)(unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1]);
            break;
        case 3:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2]);
            break;
        case 4:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2], ffi_data->args[3]);
            break;
        case 5:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2], ffi_data->args[3], ffi_data->args[4]);
            break;
        case 6:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2], ffi_data->args[3], 
                ffi_data->args[4], ffi_data->args[5]);
            break;
        case 7:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2], ffi_data->args[3], 
                ffi_data->args[4], ffi_data->args[5], ffi_data->args[6]);
            break;
        case 8:
            result = ((unsigned long (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long))ffi_data->func_ptr)(
                ffi_data->args[0], ffi_data->args[1], ffi_data->args[2], ffi_data->args[3], 
                ffi_data->args[4], ffi_data->args[5], ffi_data->args[6], ffi_data->args[7]);
            break;
        default:
            igloo_pr_debug("igloo: Unsupported number of arguments: %lu\n", ffi_data->num_args);
            mem_region->header.op = HYPER_RESP_READ_FAIL;
            return;
    }
    
    /* Store the result back in the FFI structure */
    ffi_data->result = result;
    
    igloo_pr_debug("igloo: Function call completed with result: %lu\n", result);
    mem_region->header.op = HYPER_RESP_READ_OK;
    mem_region->header.size = sizeof(struct portal_ffi_call);
}