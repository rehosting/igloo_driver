// SPDX-License-Identifier: GPL-2.0
/*
 * portal_wifi — a portal-bridged virtual cfg80211 device (Wi-Fi RF-perception model).
 *
 * Mirrors portal_mtd.c: the host sends a WIFI_CREATE op with a request struct that carries
 * host-callback trampoline pointers; this handler registers a REAL cfg80211 wiphy + netdev and
 * wires the driver's nl80211 ops to those callbacks. The callbacks trap back into a host
 * penguin plugin (see plugins/wifi_model.py) which models the RF environment.
 *
 * First increment: SCAN. When userland scans (`iw dev <if> scan`, iwinfo, RUTOS site-survey),
 * .scan schedules work that asks the host for the current set of visible BSSes (bssid, ssid,
 * channel, signal) and reports each via cfg80211_inform_bss — so the device "sees" a
 * scriptable, host-modeled radio environment (the Wi-Fi analog of the cellular RadioState).
 * This needs only CONFIG_CFG80211/CONFIG_MAC80211 (already =y in the donor kernel) — no
 * mac80211_hwsim and no kernel rebuild; igloo_driver ships the whole thing.
 */
#include "portal_internal.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/ieee80211.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

/* Host callbacks. All fill a kernel-side scratch buffer that the host writes into via the
 * portal (plugins.mem.write_bytes) and return a small status code:
 *   scan    — fill `buf` with an array of struct portal_wifi_bss; return the entry count (>=0).
 *   survey  — fill one struct portal_wifi_survey for channel index `idx`;   1=present 0=end <0=err.
 *   station — fill one struct portal_wifi_station for peer index `idx`;     1=present 0=end <0=err.
 * survey/station are one-entry-per-call to match cfg80211's idx-based .dump_* iteration. */
typedef int (*py_scan_cb_t)(int id, uint8_t *buf, unsigned long maxlen);
typedef int (*py_survey_cb_t)(int id, int idx, uint8_t *buf, unsigned long maxlen);
typedef int (*py_station_cb_t)(int id, int idx, uint8_t *buf, unsigned long maxlen);

/* On-wire BSS entry the host packs into the scan buffer (packed, little-endian == mipsel). */
struct portal_wifi_bss {
	uint8_t  bssid[6];
	uint16_t freq_mhz;
	int16_t  signal_dbm;   /* dBm; cfg80211 wants mBm (see DBM_TO_MBM) */
	uint8_t  ssid_len;
	uint8_t  ssid[32];
	uint16_t capability;   /* 0 => default to WLAN_CAPABILITY_ESS */
} __attribute__((packed));

/* On-wire per-channel survey entry (channel noise + activity). Mirrors survey_info. */
struct portal_wifi_survey {
	uint16_t freq_mhz;
	int16_t  noise_dbm;
	uint8_t  in_use;       /* nonzero => mark this channel as the one in use */
	uint8_t  _pad[3];
	uint64_t time_ms;      /* SURVEY_INFO_TIME:      channel active time */
	uint64_t time_busy_ms; /* SURVEY_INFO_TIME_BUSY: channel busy time */
} __attribute__((packed));

/* On-wire per-station entry (a connected peer's link stats). Mirrors station_info. */
struct portal_wifi_station {
	uint8_t  mac[6];
	int16_t  signal_dbm;
	uint32_t inactive_ms;
	uint32_t connected_time_s;
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
} __attribute__((packed));

/* Request struct the host builds via kffi.new("struct portal_wifi_create_req"). */
struct portal_wifi_create_req {
	char     ifname[16];
	uint8_t  mac[6];
	uint8_t  _pad[2];
	uint64_t cb_scan_ptr;
	uint64_t cb_survey_ptr;    /* 0 => .dump_survey unsupported  */
	uint64_t cb_station_ptr;   /* 0 => .dump/.get_station unsupported */
};

#define PW_SCAN_BUF_SZ 8192
#define PW_MAX_BSS     ((int)(PW_SCAN_BUF_SZ / sizeof(struct portal_wifi_bss)))
#define PW_OP_BUF_SZ   256   /* single-entry scratch for survey/station .dump_* callbacks */
#define PW_MAX_STATION 128   /* .get_station scan cap when resolving a MAC via the idx callback */

struct portal_wifi_dev {
	int                          id;
	struct wiphy                *wiphy;
	struct net_device           *ndev;
	struct wireless_dev          wdev;
	struct cfg80211_scan_request *scan_req;
	struct delayed_work          scan_work;
	py_scan_cb_t                 py_scan;
	py_survey_cb_t               py_survey;
	py_station_cb_t              py_station;
	uint8_t                     *scan_buf;
	uint8_t                     *op_buf;    /* PW_OP_BUF_SZ scratch for survey/station */
};

static atomic_t wifi_id = ATOMIC_INIT(0);

/* --- Bands / channels (2.4 GHz). Single wiphy expected, so static is fine. --- */
#define CHAN2G(_freq) { \
	.band = NL80211_BAND_2GHZ, \
	.center_freq = (_freq), \
	.hw_value = (_freq), \
	.max_power = 20, \
}
static struct ieee80211_channel pw_2ghz_channels[] = {
	CHAN2G(2412), CHAN2G(2417), CHAN2G(2422), CHAN2G(2427),
	CHAN2G(2432), CHAN2G(2437), CHAN2G(2442), CHAN2G(2447),
	CHAN2G(2452), CHAN2G(2457), CHAN2G(2462), CHAN2G(2467),
	CHAN2G(2472),
};
static struct ieee80211_rate pw_2ghz_rates[] = {
	{ .bitrate = 10 }, { .bitrate = 20 }, { .bitrate = 55 }, { .bitrate = 110 },
	{ .bitrate = 60 }, { .bitrate = 120 }, { .bitrate = 240 },
};
static struct ieee80211_supported_band pw_band_2ghz = {
	.channels    = pw_2ghz_channels,
	.n_channels  = ARRAY_SIZE(pw_2ghz_channels),
	.bitrates    = pw_2ghz_rates,
	.n_bitrates  = ARRAY_SIZE(pw_2ghz_rates),
	.band        = NL80211_BAND_2GHZ,
	.ht_cap = {
		.ht_supported = true,
		.cap = IEEE80211_HT_CAP_SGI_20,
		.ampdu_factor = 0x3,
		.ampdu_density = 0x6,
		.mcs = { .rx_mask = { 0xff, 0xff }, .tx_params = IEEE80211_HT_MCS_TX_DEFINED },
	},
};

/* --- scan --- */
static void pw_scan_work(struct work_struct *work)
{
	struct portal_wifi_dev *d =
		container_of(work, struct portal_wifi_dev, scan_work.work);
	struct wiphy *wiphy = d->wiphy;
	struct cfg80211_scan_info info = { .aborted = false };
	u64 tsf = div_u64(ktime_get_boottime_ns(), 1000);
	int n = 0, i;

	if (d->py_scan && d->scan_buf)
		n = d->py_scan(d->id, d->scan_buf, PW_SCAN_BUF_SZ);
	if (n < 0)
		n = 0;
	if (n > PW_MAX_BSS)
		n = PW_MAX_BSS;

	for (i = 0; i < n; i++) {
		struct portal_wifi_bss *b =
			&((struct portal_wifi_bss *)d->scan_buf)[i];
		struct ieee80211_channel *chan;
		struct cfg80211_bss *bss;
		u8 ie[2 + 32];
		int ielen, slen;
		u16 cap = b->capability ? b->capability : WLAN_CAPABILITY_ESS;

		chan = ieee80211_get_channel(wiphy, b->freq_mhz);
		if (!chan)
			continue;

		slen = b->ssid_len > 32 ? 32 : b->ssid_len;
		ie[0] = WLAN_EID_SSID;
		ie[1] = slen;
		memcpy(&ie[2], b->ssid, slen);
		ielen = 2 + slen;

		bss = cfg80211_inform_bss(wiphy, chan, CFG80211_BSS_FTYPE_PRESP,
					  b->bssid, tsf, cap, 100,
					  ie, ielen,
					  DBM_TO_MBM(b->signal_dbm), GFP_KERNEL);
		if (bss)
			cfg80211_put_bss(wiphy, bss);
	}

	printk(KERN_INFO "portal_wifi: scan complete for id=%d, informed %d BSS(es)\n",
	       d->id, n);
	cfg80211_scan_done(d->scan_req, &info);
	d->scan_req = NULL;
}

static int pw_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
	struct portal_wifi_dev *d = wiphy_priv(wiphy);

	if (d->scan_req)
		return -EBUSY;
	d->scan_req = request;
	schedule_delayed_work(&d->scan_work, msecs_to_jiffies(150));
	return 0;
}

/* --- survey (per-channel noise/activity): `iw dev <if> survey dump` --- */
static int pw_dump_survey(struct wiphy *wiphy, struct net_device *netdev,
			  int idx, struct survey_info *survey)
{
	struct portal_wifi_dev *d = wiphy_priv(wiphy);
	struct portal_wifi_survey *s = (struct portal_wifi_survey *)d->op_buf;
	struct ieee80211_channel *chan;
	int rc;

	if (!d->py_survey || !d->op_buf)
		return -ENOENT;
	rc = d->py_survey(d->id, idx, d->op_buf, PW_OP_BUF_SZ);
	if (rc <= 0)
		return -ENOENT;   /* end of list (0) or error (<0) → stop the dump */

	chan = ieee80211_get_channel(wiphy, s->freq_mhz);
	if (!chan)
		return -ENOENT;

	memset(survey, 0, sizeof(*survey));
	survey->channel = chan;
	survey->noise = s->noise_dbm;
	survey->time = s->time_ms;
	survey->time_busy = s->time_busy_ms;
	survey->filled = SURVEY_INFO_NOISE_DBM |
			 SURVEY_INFO_TIME | SURVEY_INFO_TIME_BUSY;
	if (s->in_use)
		survey->filled |= SURVEY_INFO_IN_USE;
	return 0;
}

/* --- stations (connected-peer link stats): `iw dev <if> station dump/get` --- */
static void pw_fill_sinfo(struct station_info *sinfo, struct portal_wifi_station *st)
{
	memset(sinfo, 0, sizeof(*sinfo));
	sinfo->filled = BIT_ULL(NL80211_STA_INFO_SIGNAL) |
			BIT_ULL(NL80211_STA_INFO_INACTIVE_TIME) |
			BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME) |
			BIT_ULL(NL80211_STA_INFO_RX_BYTES64) |
			BIT_ULL(NL80211_STA_INFO_TX_BYTES64) |
			BIT_ULL(NL80211_STA_INFO_RX_PACKETS) |
			BIT_ULL(NL80211_STA_INFO_TX_PACKETS);
	sinfo->signal = st->signal_dbm;
	sinfo->inactive_time = st->inactive_ms;
	sinfo->connected_time = st->connected_time_s;
	sinfo->rx_bytes = st->rx_bytes;
	sinfo->tx_bytes = st->tx_bytes;
	sinfo->rx_packets = st->rx_packets;
	sinfo->tx_packets = st->tx_packets;
}

static int pw_dump_station(struct wiphy *wiphy, struct net_device *dev,
			   int idx, u8 *mac, struct station_info *sinfo)
{
	struct portal_wifi_dev *d = wiphy_priv(wiphy);
	struct portal_wifi_station *st = (struct portal_wifi_station *)d->op_buf;
	int rc;

	if (!d->py_station || !d->op_buf)
		return -ENOENT;
	rc = d->py_station(d->id, idx, d->op_buf, PW_OP_BUF_SZ);
	if (rc <= 0)
		return -ENOENT;
	memcpy(mac, st->mac, ETH_ALEN);
	pw_fill_sinfo(sinfo, st);
	return 0;
}

static int pw_get_station(struct wiphy *wiphy, struct net_device *dev,
			  const u8 *mac, struct station_info *sinfo)
{
	struct portal_wifi_dev *d = wiphy_priv(wiphy);
	struct portal_wifi_station *st = (struct portal_wifi_station *)d->op_buf;
	int idx, rc;

	if (!d->py_station || !d->op_buf)
		return -ENOENT;
	/* Resolve a specific MAC by walking the host's idx-based station list. */
	for (idx = 0; idx < PW_MAX_STATION; idx++) {
		rc = d->py_station(d->id, idx, d->op_buf, PW_OP_BUF_SZ);
		if (rc <= 0)
			break;
		if (ether_addr_equal(st->mac, mac)) {
			pw_fill_sinfo(sinfo, st);
			return 0;
		}
	}
	return -ENOENT;
}

static const struct cfg80211_ops pw_cfg80211_ops = {
	.scan         = pw_scan,
	.dump_survey  = pw_dump_survey,
	.dump_station = pw_dump_station,
	.get_station  = pw_get_station,
};

/* --- minimal netdev --- */
static int pw_ndo_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}
static int pw_ndo_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}
static netdev_tx_t pw_ndo_xmit(struct sk_buff *skb, struct net_device *dev)
{
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
static const struct net_device_ops pw_netdev_ops = {
	.ndo_open       = pw_ndo_open,
	.ndo_stop       = pw_ndo_stop,
	.ndo_start_xmit = pw_ndo_xmit,
};

/* --- WIFI_CREATE op handler --- */
void handle_op_wifi_create(portal_region *mem_region)
{
	struct portal_wifi_create_req *req =
		(struct portal_wifi_create_req *)PORTAL_DATA(mem_region);
	struct wiphy *wiphy;
	struct portal_wifi_dev *d;
	struct net_device *ndev;
	char ifname[16];
	int err;

	req->ifname[sizeof(req->ifname) - 1] = '\0';
	strscpy(ifname, req->ifname[0] ? req->ifname : "wlan-ig%d", sizeof(ifname));

	wiphy = wiphy_new(&pw_cfg80211_ops, sizeof(struct portal_wifi_dev));
	if (!wiphy) {
		printk(KERN_ERR "portal_wifi: wiphy_new failed\n");
		mem_region->header.op = HYPER_RESP_WRITE_FAIL;
		return;
	}

	d = wiphy_priv(wiphy);
	d->wiphy = wiphy;
	d->py_scan = (py_scan_cb_t)(unsigned long)req->cb_scan_ptr;
	d->py_survey = (py_survey_cb_t)(unsigned long)req->cb_survey_ptr;
	d->py_station = (py_station_cb_t)(unsigned long)req->cb_station_ptr;
	d->scan_buf = kzalloc(PW_SCAN_BUF_SZ, GFP_KERNEL);
	d->op_buf = kzalloc(PW_OP_BUF_SZ, GFP_KERNEL);
	INIT_DELAYED_WORK(&d->scan_work, pw_scan_work);

	wiphy->max_scan_ssids = 4;
	wiphy->max_scan_ie_len = 1000;
	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	wiphy->bands[NL80211_BAND_2GHZ] = &pw_band_2ghz;
	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	err = wiphy_register(wiphy);
	if (err < 0) {
		printk(KERN_ERR "portal_wifi: wiphy_register failed: %d\n", err);
		kfree(d->scan_buf);
		kfree(d->op_buf);
		wiphy_free(wiphy);
		mem_region->header.op = HYPER_RESP_WRITE_FAIL;
		return;
	}

	ndev = alloc_netdev(0, ifname, NET_NAME_UNKNOWN, ether_setup);
	if (!ndev) {
		printk(KERN_ERR "portal_wifi: alloc_netdev failed\n");
		wiphy_unregister(wiphy);
		kfree(d->scan_buf);
		kfree(d->op_buf);
		wiphy_free(wiphy);
		mem_region->header.op = HYPER_RESP_WRITE_FAIL;
		return;
	}

	ndev->netdev_ops = &pw_netdev_ops;
	d->wdev.wiphy = wiphy;
	d->wdev.iftype = NL80211_IFTYPE_STATION;
	d->wdev.netdev = ndev;
	ndev->ieee80211_ptr = &d->wdev;

	if (is_valid_ether_addr(req->mac))
		eth_hw_addr_set(ndev, req->mac);
	else
		eth_hw_addr_random(ndev);

	SET_NETDEV_DEV(ndev, wiphy_dev(wiphy));

	err = register_netdev(ndev);
	if (err < 0) {
		printk(KERN_ERR "portal_wifi: register_netdev failed: %d\n", err);
		free_netdev(ndev);
		wiphy_unregister(wiphy);
		kfree(d->scan_buf);
		kfree(d->op_buf);
		wiphy_free(wiphy);
		mem_region->header.op = HYPER_RESP_WRITE_FAIL;
		return;
	}

	d->ndev = ndev;
	d->id = atomic_inc_return(&wifi_id);

	printk(KERN_INFO "portal_wifi: created wiphy '%s' netdev '%s' id=%d "
	       "(scan=%px survey=%px station=%px)\n",
	       wiphy_name(wiphy), ndev->name, d->id, d->py_scan, d->py_survey, d->py_station);

	mem_region->header.size = d->id;
	mem_region->header.op = HYPER_RESP_READ_NUM;
}
