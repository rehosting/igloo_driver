#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h> /* Add missing include for hashtable support */
#include "hypercall.h" // Content is now included directly below
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "hypermemcall.h"
#include <linux/printk.h> // Add printk include

// Add conditional debug macro
#define CONFIG_IGLOO_DEBUG 1
// #ifdef CONFIG_IGLOO_DEBUG
#define igloo_pr_debug(fmt, ...) printk( KERN_EMERG fmt, ##__VA_ARGS__)
// #else
// #define igloo_pr_debug(fmt, ...) do {} while (0)
// #endif

#define CHUNK_SIZE 128

enum HYPER_OP {
    HYPER_OP_NONE = 0,
    HYPER_OP_READ,
    HYPER_OP_READ_OK,
    HYPER_OP_READ_FAIL,
    HYPER_OP_WRITE,
    HYPER_OP_WRITE_OK,
    HYPER_OP_WRITE_FAIL,
};

struct mem_region {
    __le64 op;
    __le64 addr;
    __le64 size;
    char data[CHUNK_SIZE];
};

static DEFINE_PER_CPU(struct mem_region*, mem_regions);

int igloo_hypermem_call(unsigned long num, unsigned long arg1, unsigned long arg2){
    unsigned long ret;
    struct mem_region* mem_region;

    // igloo_pr_debug("igloo: hypermem_call entry: num=%lu, arg1=%lu, arg2=%lu\n", num, arg1, arg2);

    mem_region = this_cpu_read(mem_regions); // Read the per-cpu pointer value
    if (mem_region == NULL){ // Check if the stored pointer is NULL
        igloo_pr_debug("igloo: Allocating new mem_region for CPU %d\n", smp_processor_id());
        // Use GFP_ATOMIC as this can be called in atomic context (e.g., kprobe)
        mem_region = kmalloc(sizeof(struct mem_region), GFP_ATOMIC);
        if (mem_region == NULL){
            pr_err("igloo: Failed to allocate mem_region\n");
            return -ENOMEM;
        }
        this_cpu_write(mem_regions, mem_region); // Store the allocated pointer back
        igloo_hypercall(IGLOO_HYPER_REGISTER_MEM_REGION, (unsigned long)mem_region);
        igloo_pr_debug("igloo: Registered new mem_region %p for CPU %d\n", mem_region, smp_processor_id());
    }

    mem_region->op = cpu_to_le64(HYPER_OP_NONE);
    mem_region->addr = 0;
    mem_region->size = 0;
    memset(mem_region->data, 0, sizeof(mem_region->data));

    for (;;) {
        // igloo_pr_debug("igloo: Before hypercall: op=%llu, addr=%llu, size=%llu\n",
                //  le64_to_cpu(mem_region->op), le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size));
        ret = igloo_hypercall2(num, arg1, arg2);
        // igloo_pr_debug("igloo: After hypercall: ret=%lu, op=%llu, addr=%llu, size=%llu\n",
                //  ret, le64_to_cpu(mem_region->op), le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size));
        int resp;
        if (mem_region->op == HYPER_OP_READ) {
            igloo_pr_debug("igloo: Handling HYPER_OP_READ: addr=%llu, size=%llu \n",
                     le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size));
            if (resp = copy_from_user(mem_region->data, (void *)mem_region->addr,
                               mem_region->size)) {
                igloo_pr_debug("igloo: copy_from_user failed for addr %llu, size %llu, resp %llu\n",
                        le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size), resp);
                mem_region->op = cpu_to_le64(HYPER_OP_READ_FAIL);
            }else{
                mem_region->op = cpu_to_le64(HYPER_OP_READ_OK);
            }
        } else if (mem_region->op == HYPER_OP_WRITE) {
            igloo_pr_debug("igloo: Handling HYPER_OP_WRITE: addr=%llu, size=%llu resp=%llu\n",
                     le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size));
            if (resp = copy_to_user((void *)mem_region->addr, mem_region->data,
                             mem_region->size)) {
                igloo_pr_debug("igloo: copy_to_user failed for addr %llu, size %llu resp %llu\n",
                        le64_to_cpu(mem_region->addr), le64_to_cpu(mem_region->size), resp);
                mem_region->op = cpu_to_le64(HYPER_OP_WRITE_FAIL);
            }else{
                mem_region->op = cpu_to_le64(HYPER_OP_WRITE_OK);
            }
        } else if (mem_region->op == HYPER_OP_NONE) {
            // igloo_pr_debug("igloo: Handling HYPER_OP_NONE, breaking loop\n");
            break;
        }else{
            printk(KERN_EMERG "igloo: hypercall error: %lu\n", mem_region->op);
            break;
        }
    }
    // igloo_pr_debug("igloo: hypermem_call exit: ret=%lu\n", ret);
    return ret;
}
