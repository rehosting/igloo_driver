#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/string.h>
#include "igloonet.h"
#include "portal.h"
#include "igloo_hypercall_consts.h"

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev) {}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
// 6.13+ uses dev_lstats for stats
static void igloonet_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	dev_lstats_read(dev, &stats->tx_packets, &stats->tx_bytes);
}
#else
// 4.10 uses per-cpu stats
struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
};

static struct rtnl_link_stats64 *igloonet_get_stats64(struct net_device *dev,
						   struct rtnl_link_stats64 *stats)
{
	int i;
	for_each_possible_cpu(i) {
		const struct pcpu_dstats *dstats;
		u64 tbytes, tpackets;
		unsigned int start;
		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
		} while (u64_stats_fetch_retry_irq(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
	}
	return stats;
}
#endif

static netdev_tx_t igloonet_xmit(struct sk_buff *skb, struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	dev_lstats_add(dev, skb->len);
	skb_tx_timestamp(skb);
#else
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);
	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
#endif
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int igloonet_dev_init(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_LSTATS;
	netdev_lockdep_set_classes(dev);
	return 0;
#else
	dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
	return 0;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,13,0)
static void igloonet_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->dstats);
}
#endif

static int igloonet_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops igloonet_netdev_ops = {
	.ndo_init		= igloonet_dev_init,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,13,0)
	.ndo_uninit		= igloonet_dev_uninit,
#endif
	.ndo_start_xmit		= igloonet_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= igloonet_get_stats64,
	.ndo_change_carrier	= igloonet_change_carrier,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
static const struct ethtool_ops igloonet_ethtool_ops = {
	.get_ts_info		= ethtool_op_get_ts_info,
};
#else
static void igloonet_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "igloonet", sizeof(info->driver));
	strlcpy(info->version, "1.0", sizeof(info->version));
}
static const struct ethtool_ops igloonet_ethtool_ops = {
	.get_drvinfo            = igloonet_get_drvinfo,
};
#endif

static void igloonet_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &igloonet_netdev_ops;
	dev->ethtool_ops = &igloonet_ethtool_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	dev->needs_free_netdev = true;
#else
	dev->destructor = free_netdev;
#endif

	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	dev->lltx = true;
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features	|= NETIF_F_GSO_SOFTWARE;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA;
	dev->features	|= NETIF_F_GSO_ENCAP_ALL;
	dev->hw_features |= dev->features;
	dev->hw_enc_features |= dev->features;
	dev->min_mtu = 0;
	dev->max_mtu = 0;
#else
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features	|= NETIF_F_ALL_TSO | NETIF_F_UFO;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	dev->features	|= NETIF_F_GSO_ENCAP_ALL;
	dev->hw_features |= dev->features;
	dev->hw_enc_features |= dev->features;
	dev->min_mtu = 0;
	dev->max_mtu = ETH_MAX_MTU;
#endif
	eth_hw_addr_random(dev);
}

static void igloonet_dellink(struct net_device *dev, struct list_head *head)
{
    pr_info("igloonet: preventing deletion of %s\n", dev->name);
    return;
    // unregister_netdevice_queue(dev, head);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
static int igloonet_validate(struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
#else
static int igloonet_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static struct rtnl_link_ops igloonet_link_ops __read_mostly = {
	.kind		= "igloonet",
	.setup		= igloonet_setup,
	.validate	= igloonet_validate,
    .dellink    = igloonet_dellink,
};

struct net_device* igloonet_init_one(const char *devname)
{
	struct net_device *dev_igloonet;
	int err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	/* allocate without calling the setup callback so we can copy the
	 * requested name into dev->name before setup runs (setup may
	 * reference dev->name). We'll call igloonet_setup() ourselves. */
	dev_igloonet = alloc_netdev(0, devname, NET_NAME_USER, igloonet_setup);
#else
	dev_igloonet = alloc_netdev(0, devname, NET_NAME_USER, igloonet_setup);
#endif
	if (!dev_igloonet)
		return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
	/* copy the requested name into the netdev so igloonet_setup can use it */
	memcpy(dev_igloonet->name, devname, IFNAMSIZ - 1);
	dev_igloonet->name[IFNAMSIZ - 1] = '\0';
#else
	strlcpy(dev_igloonet->name, devname, IFNAMSIZ);
#endif

	dev_igloonet->rtnl_link_ops = &igloonet_link_ops;
	err = register_netdev(dev_igloonet);
	if (err < 0)
		goto err;
	return dev_igloonet;

err:
	free_netdev(dev_igloonet);
	return NULL;
}
