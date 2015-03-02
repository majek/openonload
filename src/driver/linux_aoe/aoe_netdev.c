/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "aoe_compat.h"


struct ethtool_string {
	char name[ETH_GSTRING_LEN];
};

struct aoe_ethtool_stat {
	const char *name;
	unsigned offset;
	u64(*get_stat) (void *field); /* Reader function */
};

/* Initialiser for a struct #aoe_ethtool_stat with type-checking */
#define AOE_ETHTOOL_STAT(stat_name, source_name, field, field_type, \
		get_stat_function) {                    \
	.name = #stat_name,                                             \
	.offset = ((((field_type *) 0) ==                               \
		      &((struct aoe_##source_name *)0)->field) ?        \
		    offsetof(struct aoe_##source_name, field) :         \
		    offsetof(struct aoe_##source_name, field)),         \
	.get_stat = get_stat_function,                                  \
}

static u64 aoe_get_u64_stat(void *field)
{
	return *(u64 *) field;
}

#define AOE_ETHTOOL_U64_MAC_STAT(field)                         \
	AOE_ETHTOOL_STAT(field, mac_stats, field,               \
			u64, aoe_get_u64_stat)

static const struct aoe_ethtool_stat aoe_ethtool_stats[] = {
	AOE_ETHTOOL_U64_MAC_STAT(tx_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(tx_good_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(tx_bad_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(tx_packets),
	AOE_ETHTOOL_U64_MAC_STAT(tx_bad),
	AOE_ETHTOOL_U64_MAC_STAT(tx_pause),
	AOE_ETHTOOL_U64_MAC_STAT(tx_control),
	AOE_ETHTOOL_U64_MAC_STAT(tx_unicast),
	AOE_ETHTOOL_U64_MAC_STAT(tx_multicast),
	AOE_ETHTOOL_U64_MAC_STAT(tx_broadcast),
	AOE_ETHTOOL_U64_MAC_STAT(tx_lt64),
	AOE_ETHTOOL_U64_MAC_STAT(tx_64),
	AOE_ETHTOOL_U64_MAC_STAT(tx_65_to_127),
	AOE_ETHTOOL_U64_MAC_STAT(tx_128_to_255),
	AOE_ETHTOOL_U64_MAC_STAT(tx_256_to_511),
	AOE_ETHTOOL_U64_MAC_STAT(tx_512_to_1023),
	AOE_ETHTOOL_U64_MAC_STAT(tx_1024_to_15xx),
	AOE_ETHTOOL_U64_MAC_STAT(tx_15xx_to_jumbo),
	AOE_ETHTOOL_U64_MAC_STAT(tx_gtjumbo),
	AOE_ETHTOOL_U64_MAC_STAT(tx_collision),
	AOE_ETHTOOL_U64_MAC_STAT(tx_single_collision),
	AOE_ETHTOOL_U64_MAC_STAT(tx_multiple_collision),
	AOE_ETHTOOL_U64_MAC_STAT(tx_excessive_collision),
	AOE_ETHTOOL_U64_MAC_STAT(tx_deferred),
	AOE_ETHTOOL_U64_MAC_STAT(tx_late_collision),
	AOE_ETHTOOL_U64_MAC_STAT(tx_excessive_deferred),
	AOE_ETHTOOL_U64_MAC_STAT(tx_non_tcpudp),
	AOE_ETHTOOL_U64_MAC_STAT(tx_mac_src_error),
	AOE_ETHTOOL_U64_MAC_STAT(tx_ip_src_error),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(rx_good_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad_bytes),
	AOE_ETHTOOL_U64_MAC_STAT(rx_packets),
	AOE_ETHTOOL_U64_MAC_STAT(rx_good),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad),
	AOE_ETHTOOL_U64_MAC_STAT(rx_pause),
	AOE_ETHTOOL_U64_MAC_STAT(rx_control),
	AOE_ETHTOOL_U64_MAC_STAT(rx_unicast),
	AOE_ETHTOOL_U64_MAC_STAT(rx_multicast),
	AOE_ETHTOOL_U64_MAC_STAT(rx_broadcast),
	AOE_ETHTOOL_U64_MAC_STAT(rx_lt64),
	AOE_ETHTOOL_U64_MAC_STAT(rx_64),
	AOE_ETHTOOL_U64_MAC_STAT(rx_65_to_127),
	AOE_ETHTOOL_U64_MAC_STAT(rx_128_to_255),
	AOE_ETHTOOL_U64_MAC_STAT(rx_256_to_511),
	AOE_ETHTOOL_U64_MAC_STAT(rx_512_to_1023),
	AOE_ETHTOOL_U64_MAC_STAT(rx_1024_to_15xx),
	AOE_ETHTOOL_U64_MAC_STAT(rx_15xx_to_jumbo),
	AOE_ETHTOOL_U64_MAC_STAT(rx_gtjumbo),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad_lt64),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad_64_to_15xx),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad_15xx_to_jumbo),
	AOE_ETHTOOL_U64_MAC_STAT(rx_bad_gtjumbo),
	AOE_ETHTOOL_U64_MAC_STAT(rx_overflow),
	AOE_ETHTOOL_U64_MAC_STAT(rx_missed),
	AOE_ETHTOOL_U64_MAC_STAT(rx_false_carrier),
	AOE_ETHTOOL_U64_MAC_STAT(rx_symbol_error),
	AOE_ETHTOOL_U64_MAC_STAT(rx_align_error),
	AOE_ETHTOOL_U64_MAC_STAT(rx_length_error),
	AOE_ETHTOOL_U64_MAC_STAT(rx_internal_error),
	AOE_ETHTOOL_U64_MAC_STAT(rx_char_error_lane0),
	AOE_ETHTOOL_U64_MAC_STAT(rx_char_error_lane1),
	AOE_ETHTOOL_U64_MAC_STAT(rx_char_error_lane2),
	AOE_ETHTOOL_U64_MAC_STAT(rx_char_error_lane3),
	AOE_ETHTOOL_U64_MAC_STAT(rx_disp_error_lane0),
	AOE_ETHTOOL_U64_MAC_STAT(rx_disp_error_lane1),
	AOE_ETHTOOL_U64_MAC_STAT(rx_disp_error_lane2),
	AOE_ETHTOOL_U64_MAC_STAT(rx_disp_error_lane3),
	AOE_ETHTOOL_U64_MAC_STAT(rx_match_fault),
};

#define AOE_ETHTOOL_NUM_STATS ARRAY_SIZE(aoe_ethtool_stats)

static int aoe_net_open(struct net_device *net_dev)
{
	return 0;
}

static int aoe_net_stop(struct net_device *net_dev)
{
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
static struct rtnl_link_stats64 *aoe_net_stats(struct net_device *net_dev,
					       struct rtnl_link_stats64 *stats)
#else
static struct net_device_stats *aoe_net_stats(struct net_device *net_dev)
#endif
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_NETDEV_STATS64)
#if defined(EFX_USE_NETDEV_STATS)
	struct net_device_stats *stats = &net_dev->stats;
#else
	struct aoe_netdev *aoe_net = netdev_priv(net_dev);
	struct net_device_stats *stats = &aoe_net->stats;
#endif
#endif

	return stats;
}

static void aoe_watchdog(struct net_device *net_dev)
{

}

static int aoe_change_mtu(struct net_device *net_dev, int new_mtu)
{
	return 0;
}

static int aoe_set_mac_address(struct net_device *net_dev, void *data)
{
	return 0;
}

static void aoe_set_rx_mode(struct net_device *net_dev)
{

}

netdev_tx_t aoe_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev)
{
	return NETDEV_TX_OK;
}

static int aoe_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	return 0;
}

static int aoe_ethtool_get_sset_count(struct net_device *net_dev,
		int string_set)
{
	switch (string_set) {
	case ETH_SS_STATS:
		return AOE_ETHTOOL_NUM_STATS;
	default:
		return -EINVAL;
	}
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_ETHTOOL_GET_SSET_COUNT)
static int aoe_ethtool_get_stats_count(struct net_device *net_dev)
{
	return aoe_ethtool_get_sset_count(net_dev, ETH_SS_STATS);
}
#endif


static void aoe_ethtool_get_drvinfo(struct net_device *net_dev,
				    struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strlcpy(info->version, "0.0.1", sizeof(info->version));
	strlcpy(info->fw_version, "0.0.1", sizeof(info->fw_version));
	strlcpy(info->bus_info, "NULL", sizeof(info->bus_info));
}

static void aoe_ethtool_update_stats(struct aoe_netdev *aoe_net)
{
	struct aoe_mac_stats *mac_stats = &aoe_net->mac_stats;
	__le64 *dma_stats = aoe_net->stats_buffer.addr;
	unsigned int retry;

	for (retry = 0; retry < 100; ++retry) {
		if (aoe_mcdi_update_stats(dma_stats, mac_stats) == 0)
			return;
		udelay(100);
	}
}

static void aoe_ethtool_get_stats(struct net_device *net_dev,
				  struct ethtool_stats *stats
				  __attribute__ ((unused)), u64 *data)
{
	int i;
	const struct aoe_ethtool_stat *stat;
	struct aoe_netdev *aoe_netdev = netdev_priv(net_dev);
	struct aoe_mac_stats *mac_stats = &aoe_netdev->mac_stats;

	
	aoe_ethtool_update_stats(aoe_netdev);

	for (i = 0; i < AOE_ETHTOOL_NUM_STATS; i++) {
		stat = &aoe_ethtool_stats[i];
		data[i] = stat->get_stat((void*)mac_stats + stat->offset);
	}
}

static void aoe_ethtool_get_strings(struct net_device *net_dev,
				    u32 string_set,
				    u8 *strings)
{
	int i;
	struct ethtool_string *ethtool_strings =
		(struct ethtool_string *)strings;

	switch (string_set) {
		case ETH_SS_STATS:
			for (i = 0; i < AOE_ETHTOOL_NUM_STATS; i++)
				strlcpy(ethtool_strings[i].name,
						aoe_ethtool_stats[i].name,
						sizeof(ethtool_strings[i].name));
			break;
		default:
			break;
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
static int aoe_set_features(struct net_device *net_dev, netdev_features_t data)
{
	return 0;
}
#endif

static const struct ethtool_ops aoe_ethtool_ops = {
	.get_drvinfo            = aoe_ethtool_get_drvinfo,
	.get_ethtool_stats	= aoe_ethtool_get_stats,
	.get_strings            = aoe_ethtool_get_strings,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_ETHTOOL_GET_SSET_COUNT)
	.get_sset_count         = aoe_ethtool_get_sset_count,
#else
	.get_stats_count        = aoe_ethtool_get_stats_count,
#endif
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
static const struct net_device_ops aoe_netdev_ops = {
	.ndo_open               = aoe_net_open,
	.ndo_stop               = aoe_net_stop,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64        = aoe_net_stats,
#else
	.ndo_get_stats          = aoe_net_stats,
#endif
	.ndo_tx_timeout         = aoe_watchdog,
	.ndo_start_xmit         = aoe_hard_start_xmit,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_do_ioctl           = aoe_ioctl,
	.ndo_change_mtu         = aoe_change_mtu,
	.ndo_set_mac_address    = aoe_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode        = aoe_set_rx_mode,
#else
	.ndo_set_multicast_list = aoe_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	.ndo_set_features       = aoe_set_features,
#endif
};
#endif
static int aoe_setup_netdev(struct aoe_netdev *aoe_net)
{
	int rc;
	struct net_device *net_dev = aoe_net->netdev;

	net_dev->watchdog_timeo = 100000;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	net_dev->netdev_ops = &aoe_netdev_ops;
#else
	net_dev->open = aoe_net_open;
	net_dev->stop = aoe_net_stop;
	net_dev->get_stats = aoe_net_stats;
	net_dev->tx_timeout = aoe_watchdog;
	net_dev->hard_start_xmit = aoe_hard_start_xmit;
	net_dev->do_ioctl = aoe_ioctl;
	net_dev->change_mtu = aoe_change_mtu;
	net_dev->set_mac_address = aoe_set_mac_address;
	net_dev->set_multicast_list = aoe_set_rx_mode;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	net_dev->vlan_rx_register = NULL;
#endif
#ifdef AOE_USE_VLAN_RX_KILL_VID
	net_dev->vlan_rx_kill_vid = NULL;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	net_dev->poll_controller = NULL;
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || !defined(SET_ETHTOOL_OPS)
	net_dev->ethtool_ops = &aoe_ethtool_ops;
#else
 	SET_ETHTOOL_OPS(net_dev, &aoe_ethtool_ops);
#endif

	rc = register_netdev(net_dev);
	netif_carrier_off(net_dev);

	return rc;
}

static bool debug = false;
module_param(debug, bool, 0444);
MODULE_PARM_DESC(debug,
		 "Enable visibilty of MAC stats on FPGA links to siena\n");

static bool force_sienastats = false;
module_param(force_sienastats, bool, 0444);
MODULE_PARM_DESC(force_sienastats,
		 "Force Siena MAC stats to ethernet interfaces\n");

static bool link_mode = false;
module_param(link_mode, bool, 0444);
MODULE_PARM_DESC(link_mode,
		 "Select external link mode reporting behaviour, 0=direct, 1=combined\n");

static int aoe_alloc_stats_buffer(struct aoe_netdev *dev)
{
	/* Allocated a coherant dma buffer and initialise */
	struct aoe_device *aoe_dev = dev->aoe_dev;
	struct aoe_stats_buffer *buffer = &dev->stats_buffer;

	buffer->len = get_aoe_stats_len();

	buffer->addr = dma_alloc_coherent(&aoe_dev->pci_dev->dev,
					  buffer->len,
					  &buffer->dma_addr, GFP_ATOMIC);

	if (!buffer->addr)
		return -ENOMEM;

	memset(buffer->addr, 0, buffer->len);
	memset(&dev->mac_stats, 0, sizeof(dev->mac_stats));

	return 0;
}

static void aoe_free_stats_buffer(struct aoe_netdev *dev)
{
	struct aoe_device *aoe_dev = dev->aoe_dev;
	struct aoe_stats_buffer *buffer = &dev->stats_buffer;

	if (!buffer->addr)
		return;

	dma_free_coherent(&aoe_dev->pci_dev->dev, buffer->len,
			  buffer->addr, buffer->dma_addr);

	buffer->addr = NULL;
}

static int aoe_enable_stats_net(struct aoe_netdev *dev)
{
	int ret;
	struct aoe_device *aoe_dev = dev->aoe_dev;
	struct aoe_stats_buffer *buffer = &dev->stats_buffer;

	ret = aoe_mcdi_mac_stats(aoe_dev, buffer->dma_addr,
			   	 buffer->len, 1, 0, dev->id,
				 dev->mac_type);

	if (!ret)
		printk(KERN_INFO "sfc_aoe: Stats set up for %s\n", dev->netdev->name);
	else
		printk(KERN_ERR "Stats set up for %s FAILED %d\n", dev->netdev->name, ret);

	return ret;
}

static int aoe_disable_stats_net(struct aoe_netdev *dev)
{
	int ret;
	struct aoe_device *aoe_dev = dev->aoe_dev;
	struct aoe_stats_buffer *buffer = &dev->stats_buffer;

	ret = aoe_mcdi_mac_stats(aoe_dev, buffer->dma_addr,
				 buffer->len, 0, 0, dev->id,
				 dev->mac_type);

	return ret;
}

/* might be worth doing some function pointer fun with these
 * to call something that always takes a type of aoe_netdev
 */

int aoe_enable_stats(struct aoe_device *aoe_dev)
{
	struct aoe_netdev *aoe_net;
	struct list_head *list_ptr = &aoe_dev->external_mac_list;

	list_for_each_entry(aoe_net, list_ptr, list) {
		if (aoe_net) {
			aoe_enable_stats_net(aoe_net);
		}
	}

	return 0;
}

void aoe_disable_stats(struct aoe_device *aoe_dev)
{
	struct aoe_netdev *aoe_net;
	struct list_head *list_ptr = &aoe_dev->external_mac_list;

	list_for_each_entry(aoe_net, list_ptr, list) {
		if (aoe_net) {
			aoe_disable_stats_net(aoe_net);
		}
	}
}

static inline int create_aoe_netdev(char *name,
				    struct list_head *list,
				    struct aoe_device *dev,
				    enum aoe_mac_type type,
				    int idx)
{
	struct net_device *new_dev;
	struct aoe_netdev *aoe_net;
	new_dev = alloc_etherdev_mq(sizeof(struct aoe_netdev), 1);

	dev_alloc_name(new_dev, name);

	if (!new_dev)
		return -ENOMEM;

	aoe_net = netdev_priv(new_dev);
	aoe_net->netdev = new_dev;
	aoe_net->aoe_dev = dev;
	aoe_net->id = idx;
	aoe_net->mac_type = type;

	if (aoe_alloc_stats_buffer(aoe_net))
		return -ENOMEM;

	if (aoe_setup_netdev(aoe_net)) {
		free_netdev(aoe_net->netdev);
		return -EINVAL;
	}

	aoe_enable_stats_net(aoe_net);

	/* add to list anyway and leave cleanup to caller */
	list_add(&aoe_net->list, list);

	return 0;
}

static void aoe_unregister_netdev(struct aoe_netdev *aoe_net)
{
	struct net_device *net_dev = aoe_net->netdev;

	unregister_netdev(net_dev);
	aoe_disable_stats_net(aoe_net);
	aoe_free_stats_buffer(aoe_net);
	free_netdev(net_dev);
}

/* Call without rtnl_lock held */
static void aoe_unregister_devs(struct list_head *list_ptr)
{
	struct aoe_netdev *temp;
	struct aoe_netdev *aoe_net;
	list_for_each_entry_safe(aoe_net, temp, list_ptr, list) {
		if (aoe_net) {
			aoe_unregister_netdev(aoe_net);
			list_del(&aoe_net->list);
		}
	}
}

/* This must have been called with rtnl_lock,
 * this is the case with driverlink callback
 */

int aoe_netdev_register(struct aoe_device *dev,
			unsigned int int_macs,
			unsigned int ext_macs)
{
	int idx;
	int ret = 0;

	/* If driver was loaded with "force_sienastats" then
 	 * we do not want to override the sienastats with the aoe ones
 	 * in this case create the extra interfaces, else do not
 	 */

	if (!force_sienastats)
		return 0;

	ASSERT_RTNL();

	rtnl_unlock();

	if (!debug)
		int_macs = 0;

	for (idx = 0; idx < ext_macs; idx++) {
		if (create_aoe_netdev("aoe_ext%d",
				      &dev->external_mac_list,
				      dev,
				      AOE_MAC_EXT,
				      idx))
			goto clean_devs;
	}

	for (idx = 0; idx < int_macs; idx++) {
		if (create_aoe_netdev("aoe_int%d",
				      &dev->internal_mac_list,
				      dev,
				      AOE_MAC_INT,
				      idx))
			goto clean_devs;
	}

out:
	rtnl_lock();
	return ret;

clean_devs:
	aoe_unregister_devs(&dev->internal_mac_list);
	aoe_unregister_devs(&dev->external_mac_list);

	ret = -ENOMEM;
	goto out;
}

/* This must have been called with rtnl_lock held
 */
void aoe_netdev_unregister(struct aoe_device *dev)
{

	/* If "force_sienastats" was set then we need to take
 	 * down the interfaces that where made and put siena back
 	 * to normal regardless
 	 */

	if (!force_sienastats)
		return;

	ASSERT_RTNL();

	rtnl_unlock();

	aoe_unregister_devs(&dev->internal_mac_list);
	aoe_unregister_devs(&dev->external_mac_list);

	rtnl_lock();
}

int aoe_netdev_reassign(void)
{
	return 0;
}

int aoe_apply_static_config(struct aoe_device *dev)
{
	int ret;
	ret = aoe_mcdi_set_siena_override(dev, !force_sienastats);
	if (ret)
		return ret;

	ret = aoe_mcdi_link_status_split(dev, link_mode);

	return ret;
}

void aoe_remove_static_config(struct aoe_device *dev)
{
	aoe_mcdi_set_siena_override(dev, false);
	aoe_mcdi_link_status_split(dev, false);
}
