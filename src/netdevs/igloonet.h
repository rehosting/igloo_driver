#ifndef _IGLOONET_H
#define _IGLOONET_H

#include <linux/netdevice.h>
#include <linux/ethtool.h>

struct igloonet_priv {
    struct rtnl_link_ops link_ops;
    struct net_device_ops netdev_ops;
    struct ethtool_ops ethtool_ops;
};

struct net_device* igloonet_init_one(const char *devname);
#endif