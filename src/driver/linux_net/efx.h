/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_EFX_H
#define EFX_EFX_H

#include "net_driver.h"
#include "filter.h"

/* All PFs use BAR 0 for I/O space and BAR 2(&3) for memory */
/* All VFs use BAR 0/1 for memory */
#define EFX_MEM_BAR 2
#define EFX_MEM_VF_BAR 0

/* netdevice_ops */
int efx_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd);
#ifdef CONFIG_NET_POLL_CONTROLLER
void efx_netpoll(struct net_device *net_dev);
#endif
int efx_net_open(struct net_device *net_dev);
int efx_net_stop(struct net_device *net_dev);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
struct rtnl_link_stats64 *efx_net_stats(struct net_device *net_dev,
					struct rtnl_link_stats64 *stats);
#else
struct net_device_stats *efx_net_stats(struct net_device *net_dev);
#endif
void efx_watchdog(struct net_device *net_dev);
int efx_change_mtu(struct net_device *net_dev, int new_mtu);
int efx_set_mac_address(struct net_device *net_dev, void *data);
void efx_set_rx_mode(struct net_device *net_dev);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES) || defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
netdev_features_t efx_fix_features(struct net_device *net_dev, netdev_features_t data);
#else
u32 efx_fix_features(struct net_device *net_dev, u32 data);
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
int efx_set_features(struct net_device *net_dev, netdev_features_t data);
#else
int efx_set_features(struct net_device *net_dev, u32 data);
#endif
#endif

#ifdef CONFIG_NET_RX_BUSY_POLL
int efx_busy_poll(struct napi_struct *napi);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
void efx_vlan_rx_register(struct net_device *dev, struct vlan_group *vlan_group);
#endif

/* TX */
int efx_probe_tx_queue(struct efx_tx_queue *tx_queue);
void efx_remove_tx_queue(struct efx_tx_queue *tx_queue);
void efx_destroy_tx_queue(struct efx_tx_queue *tx_queue);
int efx_init_tx_queue(struct efx_tx_queue *tx_queue);
void efx_init_tx_queue_core_txq(struct efx_tx_queue *tx_queue);
void efx_fini_tx_queue(struct efx_tx_queue *tx_queue);
void efx_purge_tx_queue(struct efx_tx_queue *tx_queue);
netdev_tx_t efx_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_ENABLE_SFC_XPS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SELECT_QUEUE_FALLBACK)
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb,
		     void *accel_priv, select_queue_fallback_t fallback);
#elif defined(EFX_HAVE_NDO_SELECT_QUEUE_ACCEL_PRIV)
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb,
		     void *accel_priv);
#else
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb);
#endif
#endif
int efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index);
void fastcall efx_xmit_done_single(struct efx_tx_queue *tx_queue);
#else
void efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index);
void efx_xmit_done_single(struct efx_tx_queue *tx_queue);
#endif
unsigned int efx_tx_max_skb_descs(struct efx_nic *efx);
extern unsigned int efx_piobuf_size;
extern bool separate_tx_channels;

/* RX */
void efx_set_default_rx_indir_table(struct efx_nic *efx);
void efx_rx_config_page_split(struct efx_nic *efx);
int efx_probe_rx_queue(struct efx_rx_queue *rx_queue);
void efx_remove_rx_queue(struct efx_rx_queue *rx_queue);
void efx_destroy_rx_queue(struct efx_rx_queue *rx_queue);
int efx_init_rx_queue(struct efx_rx_queue *rx_queue);
void efx_fini_rx_queue(struct efx_rx_queue *rx_queue);
void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue, bool atomic);
void efx_rx_slow_fill(struct work_struct *data);
void __efx_rx_packet(struct efx_channel *channel);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
			    unsigned int n_frags, unsigned int len, u16 flags);
#else
void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int n_frags, unsigned int len, u16 flags);
#endif
static inline void efx_rx_flush_packet(struct efx_channel *channel)
{
	if (channel->rx_pkt_n_frags)
		__efx_rx_packet(channel);
}
void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue);
void efx_cancel_slow_fill(struct efx_rx_queue *rx_queue);

#define EFX_MAX_DMAQ_SIZE 4096UL
#define EFX_DEFAULT_RX_DMAQ_SIZE 1024UL
#define EFX_DEFAULT_TX_DMAQ_SIZE 1024UL
#define EFX_MIN_DMAQ_SIZE 512UL

#define EFX_MAX_EVQ_SIZE 16384UL
#define EFX_MIN_EVQ_SIZE 512UL
#ifdef EFX_NOT_UPSTREAM
/* Additional event queue entries to add on channel zero for driverlink. */
#define EFX_EVQ_DL_EXTRA_ENTRIES 1024UL
#endif

/* Maximum number of TCP segments we support for soft-TSO */
#define EFX_TSO_MAX_SEGS	100

/* The smallest [rt]xq_entries that the driver supports.  RX minimum
 * is a bit arbitrary.  For TX, we must have space for at least 2
 * TSO skbs.
 */
#define EFX_RXQ_MIN_ENT		16U
#define EFX_TXQ_MIN_ENT(efx)	(2 * efx_tx_max_skb_descs(efx))

/* All EF10 architecture NICs steal one bit of the DMAQ size for various
 * other purposes when counting TxQ entries, so we halve the queue size.
 */
#define EFX_TXQ_MAX_ENT(efx)	(EFX_WORKAROUND_EF10(efx) ? \
				 EFX_MAX_DMAQ_SIZE / 2 : EFX_MAX_DMAQ_SIZE)

#ifdef EFX_NOT_UPSTREAM
/* PCIe link bandwidth measure:
 * bw = (width << (speed - 1))
 */
#define EFX_BW_PCIE_GEN1_X8  (8  << (1 - 1))
#define EFX_BW_PCIE_GEN2_X8  (8  << (2 - 1))
#define EFX_BW_PCIE_GEN3_X8  (8  << (3 - 1))
#define EFX_BW_PCIE_GEN3_X16 (16 << (3 - 1))
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
extern bool efx_rss_enabled(const struct efx_nic *efx);
#else
static inline bool efx_rss_enabled(struct efx_nic *efx)
{
	return efx->n_rss_channels > 1;
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)

static inline bool efx_ssr_enabled(struct efx_nic *efx)
{
#ifdef NETIF_F_LRO
	return !!(efx->net_dev->features & NETIF_F_LRO);
#else
	return efx->lro_enabled;
#endif
}

#if defined(EFX_WITH_VMWARE_NETQ)
static inline bool efx_channel_ssr_enabled(struct efx_channel *channel)
{
	return !!(channel->netq_flags & NETQ_USE_LRO);
}
#else
static inline bool efx_channel_ssr_enabled(struct efx_channel *channel)
{
	return efx_ssr_enabled(channel->efx);
}
#endif

int efx_ssr_init(struct efx_channel *channel, struct efx_nic *efx);
void efx_ssr_fini(struct efx_channel *channel);
void __efx_ssr_end_of_burst(struct efx_channel *channel);
void efx_ssr(struct efx_channel *, struct efx_rx_buffer *rx_buf, u8 *eh);

static inline void efx_ssr_end_of_burst(struct efx_channel *channel)
{
	if (!list_empty(&channel->ssr.active_conns))
		__efx_ssr_end_of_burst(channel);
}

#endif /* EFX_USE_SFC_LRO */

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
int efx_sarfs_init(struct efx_nic *efx);
void efx_sarfs_disable(struct efx_nic *efx);
void efx_sarfs_fini(struct efx_nic *efx);
#endif

/* Filters */

int efx_mac_reconfigure(struct efx_nic *efx, bool mtu_only);

/**
 * efx_filter_insert_filter - add or replace a filter
 * @efx: NIC in which to insert the filter
 * @spec: Specification for the filter
 * @replace_equal: Flag for whether the specified filter may replace an
 *	existing filter with equal priority
 *
 * On success, return the filter ID.
 * On failure, return a negative error code.
 *
 * If existing filters have equal match values to the new filter spec,
 * then the new filter might replace them or the function might fail,
 * as follows.
 *
 * 1. If the existing filters have lower priority, or @replace_equal
 *    is set and they have equal priority, replace them.
 *
 * 2. If the existing filters have higher priority, return -%EPERM.
 *
 * 3. If !efx_filter_is_mc_recipient(@spec), or the NIC does not
 *    support delivery to multiple recipients, return -%EEXIST.
 *
 * This implies that filters for multiple multicast recipients must
 * all be inserted with the same priority and @replace_equal = %false.
 */
static inline s32 efx_filter_insert_filter(struct efx_nic *efx,
					   const struct efx_filter_spec *spec,
					   bool replace_equal)
{
	return efx->type->filter_insert(efx, spec, replace_equal);
}

/**
 * efx_filter_remove_id_safe - remove a filter by ID, carefully
 * @efx: NIC from which to remove the filter
 * @priority: Priority of filter, as passed to @efx_filter_insert_filter
 * @filter_id: ID of filter, as returned by @efx_filter_insert_filter
 *
 * This function will range-check @filter_id, so it is safe to call
 * with a value passed from userland.
 */
static inline int efx_filter_remove_id_safe(struct efx_nic *efx,
					    enum efx_filter_priority priority,
					    u32 filter_id)
{
	return efx->type->filter_remove_safe(efx, priority, filter_id);
}

/**
 * efx_filter_get_filter_safe - retrieve a filter by ID, carefully
 * @efx: NIC from which to remove the filter
 * @priority: Priority of filter, as passed to @efx_filter_insert_filter
 * @filter_id: ID of filter, as returned by @efx_filter_insert_filter
 * @spec: Buffer in which to store filter specification
 *
 * This function will range-check @filter_id, so it is safe to call
 * with a value passed from userland.
 */
static inline int
efx_filter_get_filter_safe(struct efx_nic *efx,
			   enum efx_filter_priority priority,
			   u32 filter_id, struct efx_filter_spec *spec)
{
	return efx->type->filter_get_safe(efx, priority, filter_id, spec);
}

/**
 * efx_filter_redirect_id - update the queue for an existing RX filter
 * @efx: NIC in which to update the filter
 * @filter_id: ID of filter, as returned by @efx_filter_insert_filter
 * @rxq_i: Index of RX queue
 * @stack_id: Stack id associated with the RX queue
 */
static inline int efx_filter_redirect_id(struct efx_nic *efx,
					 u32 filter_id, int rxq_i,
					 int stack_id)
{
	return efx->type->filter_redirect(efx, filter_id, rxq_i, stack_id);
}

static inline u32 efx_filter_count_rx_used(struct efx_nic *efx,
					   enum efx_filter_priority priority)
{
	return efx->type->filter_count_rx_used(efx, priority);
}
static inline u32 efx_filter_get_rx_id_limit(struct efx_nic *efx)
{
	return efx->type->filter_get_rx_id_limit(efx);
}
static inline s32 efx_filter_get_rx_ids(struct efx_nic *efx,
					enum efx_filter_priority priority,
					u32 *buf, u32 size)
{
	return efx->type->filter_get_rx_ids(efx, priority, buf, size);
}
#ifdef CONFIG_RFS_ACCEL
int efx_filter_rfs(struct net_device *net_dev, const struct sk_buff *skb,
		   u16 rxq_index, u32 flow_id);
bool __efx_filter_rfs_expire(struct efx_nic *efx, unsigned int quota);
static inline void efx_filter_rfs_expire(struct efx_channel *channel)
{
	if (channel->rfs_filters_added >= 60 &&
	    __efx_filter_rfs_expire(channel->efx, 100))
		channel->rfs_filters_added -= 60;
}
#define efx_filter_rfs_enabled() 1
#else
static inline void efx_filter_rfs_expire(struct efx_channel *channel) {}
#define efx_filter_rfs_enabled() 0
#endif
bool efx_filter_is_mc_recipient(const struct efx_filter_spec *spec);

/* Channels */
int efx_channel_dummy_op_int(struct efx_channel *channel);
void efx_channel_dummy_op_void(struct efx_channel *channel);
int efx_realloc_channels(struct efx_nic *efx, u32 rxq_entries, u32 txq_entries);

/* Ports */
int efx_reconfigure_port(struct efx_nic *efx);
int __efx_reconfigure_port(struct efx_nic *efx);

/* Ethtool support */
#ifdef EFX_NOT_UPSTREAM
int efx_ethtool_get_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd);
int efx_ethtool_set_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RESET)
int efx_ethtool_reset(struct net_device *net_dev, u32 *flags);
#endif
#ifdef EFX_USE_KCOMPAT
int efx_ethtool_get_rxnfc(struct net_device *net_dev,
			  struct efx_ethtool_rxnfc *info, u32 *rules);
int efx_ethtool_set_rxnfc(struct net_device *net_dev,
			  struct efx_ethtool_rxnfc *info);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_old_get_rxfh_indir(struct net_device *net_dev,
				   struct ethtool_rxfh_indir *indir);
int efx_ethtool_old_set_rxfh_indir(struct net_device *net_dev,
				   const struct ethtool_rxfh_indir *indir);
#endif
#ifdef CONFIG_SFC_DUMP
struct ethtool_dump;
int efx_ethtool_get_dump_flag(struct net_device *net_dev,
			      struct ethtool_dump *dump);
int efx_ethtool_get_dump_data(struct net_device *net_dev,
			      struct ethtool_dump *dump, void *buffer);
int efx_ethtool_set_dump(struct net_device *net_dev, struct ethtool_dump *val);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
int efx_ethtool_get_ts_info(struct net_device *net_dev,
			    struct ethtool_ts_info *ts_info);
#endif
#if defined(EFX_USE_KCOMPAT)
int efx_ethtool_get_module_eeprom(struct net_device *net_dev,
				  struct ethtool_eeprom *ee, u8 *data);
int efx_ethtool_get_module_info(struct net_device *net_dev,
				struct ethtool_modinfo *modinfo);
#endif
extern const struct ethtool_ops efx_ethtool_ops;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
extern const struct ethtool_ops_ext efx_ethtool_ops_ext;
#endif

/* Reset handling */
int efx_reset(struct efx_nic *efx, enum reset_type method);
void efx_reset_down(struct efx_nic *efx, enum reset_type method);
int efx_reset_up(struct efx_nic *efx, enum reset_type method, bool ok);
int efx_try_recovery(struct efx_nic *efx);

/* Global */
void efx_schedule_reset(struct efx_nic *efx, enum reset_type type);
unsigned int efx_usecs_to_ticks(struct efx_nic *efx, unsigned int usecs);
unsigned int efx_ticks_to_usecs(struct efx_nic *efx, unsigned int ticks);
int efx_init_irq_moderation(struct efx_nic *efx, unsigned int tx_usecs,
			    unsigned int rx_usecs, bool rx_adaptive,
			    bool rx_may_override_tx);
void efx_get_irq_moderation(struct efx_nic *efx, unsigned int *tx_usecs,
			    unsigned int *rx_usecs, bool *rx_adaptive);
void efx_set_stats_period(struct efx_nic *efx, unsigned int period_ms);
#ifdef EFX_NOT_UPSTREAM
extern int efx_target_num_vis;
#endif

void efx_stop_eventq(struct efx_channel *channel);
void efx_start_eventq(struct efx_channel *channel);

#ifdef EFX_NOT_UPSTREAM
/* Only used from driverlink. */
void efx_pause_napi(struct efx_nic *efx);
int efx_resume_napi(struct efx_nic *efx);
#endif

/* Dummy PHY ops for PHY drivers */
int efx_void_dummy_op_int(void);
void efx_void_dummy_op_void(void);
int efx_port_dummy_op_int(struct efx_nic *efx);
void efx_port_dummy_op_void(struct efx_nic *efx);
bool efx_port_dummy_op_poll(struct efx_nic *efx);

/* Update the generic software stats in the passed stats array */
void efx_update_sw_stats(struct efx_nic *efx, u64 *stats);

/* MTD */
#ifdef CONFIG_SFC_MTD
extern bool efx_allow_nvconfig_writes;
int efx_mtd_add(struct efx_nic *efx, struct efx_mtd_partition *parts,
		size_t n_parts, size_t sizeof_part);
static inline int efx_mtd_probe(struct efx_nic *efx)
{
	return efx->type->mtd_probe(efx);
}
void efx_mtd_rename(struct efx_nic *efx);
void efx_mtd_remove(struct efx_nic *efx);
#else
static inline int efx_mtd_probe(struct efx_nic *efx) { return 0; }
static inline void efx_mtd_rename(struct efx_nic *efx) {}
static inline void efx_mtd_remove(struct efx_nic *efx) {}
#endif

#ifdef CONFIG_SFC_SRIOV
static inline unsigned int efx_vf_size(struct efx_nic *efx)
{
	return 1 << efx->vi_scale;
}
#endif

static inline void efx_schedule_channel(struct efx_channel *channel)
{
	netif_vdbg(channel->efx, intr, channel->efx->net_dev,
		   "channel %d scheduling NAPI poll on CPU%d\n",
		   channel->channel, raw_smp_processor_id());

	napi_schedule(&channel->napi_str);
}

static inline void efx_schedule_channel_irq(struct efx_channel *channel)
{
	channel->event_test_cpu = raw_smp_processor_id();
	efx_schedule_channel(channel);
}

void efx_link_status_changed(struct efx_nic *efx);
void efx_link_set_advertising(struct efx_nic *efx, u32);
void efx_link_set_wanted_fc(struct efx_nic *efx, u8);

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
extern struct workqueue_struct *efx_workqueue;
#endif

static inline void efx_device_detach_sync(struct efx_nic *efx)
{
	struct net_device *dev = efx->net_dev;

	/* Lock/freeze all TX queues so that we can be sure the
	 * TX scheduler is stopped when we're done and before
	 * netif_device_present() becomes false.
	 */
	netif_tx_lock_bh(dev);
	netif_device_detach(dev);
	netif_tx_unlock_bh(dev);
}

static inline void efx_device_attach_if_not_resetting(struct efx_nic *efx)
{
	if ((efx->state != STATE_DISABLED) && !efx->reset_pending)
		netif_device_attach(efx->net_dev);
}

static inline void efx_rwsem_assert_write_locked(struct rw_semaphore *sem)
{
#ifdef DEBUG
	if (down_read_trylock(sem)) {
		up_read(sem);
		BUG();
	}
#endif
}

#endif /* EFX_EFX_H */
