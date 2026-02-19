#include "portal_internal.h"
#include <linux/if.h>
#include <linux/string.h>
#include <linux/version.h>
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

void handle_op_set_netdev_state(portal_region *mem_region)
{
    char *devname = (char *)PORTAL_DATA(mem_region);
    struct net_device *ndev;
    int ret = 0;
    unsigned long requested_state = mem_region->header.size;

    printk(KERN_EMERG "igloo: set_netdev_state request for '%s' state=%lu\n", devname, requested_state);

    ndev = dev_get_by_name(&init_net, devname);
    if (!ndev) {
        printk(KERN_EMERG "igloo: netdev '%s' not found\n", devname);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = 0;
        return;
    }

    rtnl_lock();
    if (requested_state) {
        if (!(ndev->flags & IFF_UP)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
            ret = dev_open(ndev, NULL);
#else
            ret = dev_open(ndev);
#endif
        }
    } else {
        if (ndev->flags & IFF_UP) {
            dev_close(ndev); // dev_close returns void
            ret = 0;
        }
    }
    rtnl_unlock();

    if (ret == 0) {
        printk(KERN_EMERG "igloo: netdev '%s' state set to %lu\n", devname, requested_state);
        mem_region->header.op = HYPER_RESP_READ_NUM;
        mem_region->header.size = requested_state;
    } else {
        printk(KERN_EMERG "igloo: failed to set netdev '%s' state to %lu\n", devname, requested_state);
        mem_region->header.op = HYPER_RESP_READ_NUM;
        mem_region->header.size = ret;
    }
    dev_put(ndev);
}

void handle_op_get_netdev_state(portal_region *mem_region)
{
    char *devname = (char *)PORTAL_DATA(mem_region);
    struct net_device *ndev;
    unsigned int state = 0;

    printk(KERN_EMERG "igloo: get_netdev_state request for '%s'\n", devname);

    ndev = dev_get_by_name(&init_net, devname);
    if (!ndev) {
        printk(KERN_EMERG "igloo: netdev '%s' not found\n", devname);
        mem_region->header.op = HYPER_RESP_READ_FAIL;
        mem_region->header.size = 0;
        return;
    }

    state = !!(ndev->flags & IFF_UP);
    printk(KERN_EMERG "igloo: netdev '%s' state is %u\n", devname, state);

    mem_region->header.op = HYPER_RESP_READ_NUM;
    mem_region->header.size = state;
    dev_put(ndev);
}
