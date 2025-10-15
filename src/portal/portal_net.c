#include "portal_internal.h"
#include <linux/if.h>
#include <linux/string.h>
#include "../netdevs/igloonet.h"

void handle_op_register_netdev(portal_region *mem_region)
{
    struct net_device *ndev;
    char *devname = (char *)PORTAL_DATA(mem_region);

    printk(KERN_EMERG "igloo: register_netdev request for '%s'\n", devname);

    ndev = igloonet_init_one(devname);
    if (ndev) {
        printk(KERN_EMERG "igloo: registered netdev '%s' returned %p\n", devname, ndev);
        mem_region->header.op = HYPER_RESP_READ_NUM;
        mem_region->header.size = (uintptr_t)ndev;
    } else {
        printk(KERN_EMERG "igloo: failed to register netdev '%s'\n", devname);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = (uintptr_t)ndev;
    }
}

void handle_op_lookup_netdev(portal_region *mem_region)
{
    char *devname = (char *)PORTAL_DATA(mem_region);
    struct net_device *ndev = dev_get_by_name(&init_net, devname);

    printk(KERN_EMERG "igloo: lookup_netdev request for '%s'\n", devname);

    if (ndev) {
        printk(KERN_EMERG "igloo: found netdev '%s' at %p\n", devname, ndev);
        mem_region->header.op = HYPER_RESP_READ_NUM;
        mem_region->header.size = (uintptr_t)ndev;
        dev_put(ndev);
    } else {
        printk(KERN_EMERG "igloo: netdev '%s' not found\n", devname);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = 0;
    }
}