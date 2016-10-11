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
 * Copyright 2005-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/notifier.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ethtool.h>
#include <linux/topology.h>
#include <linux/gfp.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/aer.h>
#include <linux/interrupt.h>
#include <xen/xen.h>
#endif
#ifdef EFX_NOT_UPSTREAM
#ifdef EFX_USE_LINUX_UACCESS_H
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#endif
#if defined(CONFIG_EEH)
#include <asm/pci-bridge.h>
#endif
#include "net_driver.h"
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PCI_AER)
#include <linux/aer.h>
#endif
#include "driverlink.h"
#include "debugfs.h"
#ifdef CONFIG_SFC_DUMP
#include "dump.h"
#endif
#include "efx.h"
#include "nic.h"
#include "selftest.h"
#include "sriov.h"
#ifdef EFX_USE_KCOMPAT
#include "efx_ioctl.h"
#endif
#ifdef EFX_USE_MCDI_PROXY_AUTH
#include "proxy_auth.h"
#ifdef EFX_USE_MCDI_PROXY_AUTH_NL
#include "mcdi_proxy.h"
#endif
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
#include "../linux/gcov.h"
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
#include "efx_netq.h"
#endif
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "workarounds.h"

#ifdef CONFIG_SFC_TRACING
#define CREATE_TRACE_POINTS
#include <trace/events/sfc.h>
#endif

/**************************************************************************
 *
 * Type name strings
 *
 **************************************************************************
 */

/* Loopback mode names (see LOOPBACK_MODE()) */
const unsigned int efx_loopback_mode_max = LOOPBACK_MAX;
const char *const efx_loopback_mode_names[] = {
	[LOOPBACK_NONE]		= "NONE",
	[LOOPBACK_DATA]		= "DATAPATH",
	[LOOPBACK_GMAC]		= "GMAC",
	[LOOPBACK_XGMII]	= "XGMII",
	[LOOPBACK_XGXS]		= "XGXS",
	[LOOPBACK_XAUI]		= "XAUI",
	[LOOPBACK_GMII]		= "GMII",
	[LOOPBACK_SGMII]	= "SGMII",
	[LOOPBACK_XGBR]		= "XGBR",
	[LOOPBACK_XFI]		= "XFI",
	[LOOPBACK_XAUI_FAR]	= "XAUI_FAR",
	[LOOPBACK_GMII_FAR]	= "GMII_FAR",
	[LOOPBACK_SGMII_FAR]	= "SGMII_FAR",
	[LOOPBACK_XFI_FAR]	= "XFI_FAR",
	[LOOPBACK_GPHY]		= "GPHY",
	[LOOPBACK_PHYXS]	= "PHYXS",
	[LOOPBACK_PCS]		= "PCS",
	[LOOPBACK_PMAPMD]	= "PMA/PMD",
	[LOOPBACK_XPORT]	= "XPORT",
	[LOOPBACK_XGMII_WS]	= "XGMII_WS",
	[LOOPBACK_XAUI_WS]	= "XAUI_WS",
	[LOOPBACK_XAUI_WS_FAR]  = "XAUI_WS_FAR",
	[LOOPBACK_XAUI_WS_NEAR] = "XAUI_WS_NEAR",
	[LOOPBACK_GMII_WS]	= "GMII_WS",
	[LOOPBACK_XFI_WS]	= "XFI_WS",
	[LOOPBACK_XFI_WS_FAR]	= "XFI_WS_FAR",
	[LOOPBACK_PHYXS_WS]	= "PHYXS_WS",
};

/* Interrupt mode names (see INT_MODE())) */
const unsigned int efx_interrupt_mode_max = EFX_INT_MODE_MAX;
const char *const efx_interrupt_mode_names[] = {
	[EFX_INT_MODE_MSIX]   = "MSI-X",
	[EFX_INT_MODE_MSI]    = "MSI",
	[EFX_INT_MODE_LEGACY] = "legacy",
};

const unsigned int efx_reset_type_max = RESET_TYPE_MAX;
const char *const efx_reset_type_names[] = {
	[RESET_TYPE_INVISIBLE]          = "INVISIBLE",
	[RESET_TYPE_ALL]                = "ALL",
	[RESET_TYPE_RECOVER_OR_ALL]     = "RECOVER_OR_ALL",
	[RESET_TYPE_WORLD]              = "WORLD",
	[RESET_TYPE_RECOVER_OR_DISABLE] = "RECOVER_OR_DISABLE",
	[RESET_TYPE_DATAPATH]           = "DATAPATH",
	[RESET_TYPE_MC_BIST]		= "MC_BIST",
	[RESET_TYPE_DISABLE]            = "DISABLE",
	[RESET_TYPE_TX_WATCHDOG]        = "TX_WATCHDOG",
	[RESET_TYPE_INT_ERROR]          = "INT_ERROR",
	[RESET_TYPE_RX_RECOVERY]        = "RX_RECOVERY",
	[RESET_TYPE_DMA_ERROR]          = "DMA_ERROR",
	[RESET_TYPE_TX_SKIP]            = "TX_SKIP",
	[RESET_TYPE_MC_FAILURE]         = "MC_FAILURE",
	[RESET_TYPE_MCDI_TIMEOUT]	= "MCDI_TIMEOUT (FLR)",
};

/* UDP tunnel type names */
static const char *efx_udp_tunnel_type_names[] = {
	[TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN] = "vxlan",
	[TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE] = "geneve",
};

void efx_get_udp_tunnel_type_name(u16 type, char *buf, size_t buflen)
{
	if (type < ARRAY_SIZE(efx_udp_tunnel_type_names) &&
	    efx_udp_tunnel_type_names[type] != NULL)
		snprintf(buf, buflen, "%s", efx_udp_tunnel_type_names[type]);
	else
		snprintf(buf, buflen, "type %d", type);
}

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
struct workqueue_struct *efx_workqueue;
#endif

/* Reset workqueue. If any NIC has a hardware failure then a reset will be
 * queued onto this work queue. This is not a per-nic work queue, because
 * efx_reset_work() acquires the rtnl lock, so resets are naturally serialised.
 */
static struct workqueue_struct *reset_workqueue;

/* How often and how many times to poll for a reset while waiting for a
 * BIST that another function started to complete.
 */
#define BIST_WAIT_DELAY_MS	100
#define BIST_WAIT_DELAY_COUNT	300

/**************************************************************************
 *
 * Configurable values
 *
 *************************************************************************/

#if defined(EFX_USE_KCOMPAT) && (defined(EFX_USE_GRO) || defined(EFX_USE_SFC_LRO))
/*
 * Enable large receive offload (LRO) aka soft segment reassembly (SSR)
 *
 * This sets the default for new devices.  It can be controlled later
 * using ethtool.
 */
static bool lro = true;
module_param(lro, bool, 0444);
MODULE_PARM_DESC(lro, "Large receive offload acceleration");
#endif

/*
 * Use separate channels for TX and RX events
 *
 * Set this to 1 to use separate channels for TX and RX. It allows us
 * to control interrupt affinity separately for TX and RX.
 *
 * This is only used in MSI-X interrupt mode
 */
bool separate_tx_channels;
module_param(separate_tx_channels, bool, 0444);
MODULE_PARM_DESC(separate_tx_channels,
		 "Use separate channels for TX and RX");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
/*
 * Number of RX netqs to allocate
 */
static unsigned int num_rx_netqs;
module_param(num_rx_netqs, uint, 0444);
MODULE_PARM_DESC(num_rx_netqs,
		 "The number of receive NETQs to allocate");

/*
 * Number of RX netqs with RSS support
 *
 * RSS support on ESX is asymmtetric since kernel does not provide RSS
 * hash information on trasmit. So, there is only one Tx channel and
 * many Rx channels per RSS NetQ. If different channels are used for the
 * flow directions, Tx completion processing (NAPI) may be delayed and
 * it may cause UDP socket send buffer overflow and ENOBUFS returned to
 * sender. The asymmetry may cause other problems as well.
 * So, be careful if you enable RSS.
 */
#define NUM_RSS_NETQS_DEF	0
static int num_rss_netqs = NUM_RSS_NETQS_DEF;
module_param(num_rss_netqs, int, 0444);
MODULE_PARM_DESC(num_rss_netqs,
	"The number of receive NETQs with RSS support (negative means all)");

/*
 * Maximum number of RSS channels per NETQ.
 */
static unsigned int max_netq_rss_channels = 4;
module_param(max_netq_rss_channels, int, 0444);
MODULE_PARM_DESC(max_netq_rss_channels,
		 "Maximum number of RSS channels per NETQ (zero to have no "
		 "artificial limit)");

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
/*
 * Number of TX channels to allocate
 */
static unsigned int num_tx_channels;
module_param(num_tx_channels, uint, 0444);
MODULE_PARM_DESC(num_tx_channels,
		 "Number of transmit channels to allocate");
#endif
#endif

/* This is the weight assigned to each of the (per-channel) virtual
 * NAPI devices.
 */
static int napi_weight = 64;

/* This is the time (in ms) between invocations of the hardware
 * monitor.
 * On Falcon-based NICs, this will:
 * - Check the on-board hardware monitor;
 * - Poll the link state and reconfigure the hardware as necessary.
 * On Siena-based NICs for power systems with EEH support, this will give EEH a
 * chance to start.
 */
static unsigned int monitor_interval_ms = 200;
module_param(monitor_interval_ms, uint, 0644);
MODULE_PARM_DESC(monitor_interval_ms, "Bus state test interval in ms");

/* Initial interrupt moderation settings.  They can be modified after
 * module load with ethtool.
 *
 * The default for RX should strike a balance between increasing the
 * round-trip latency and reducing overhead.
 */
static unsigned int rx_irq_mod_usec = 60;

/* Initial interrupt moderation settings.  They can be modified after
 * module load with ethtool.
 *
 * This default is chosen to ensure that a 10G link does not go idle
 * while a TX queue is stopped after it has become full.  A queue is
 * restarted when it drops below half full.  The time this takes (assuming
 * worst case 3 descriptors per packet and 1024 descriptors) is
 *   512 / 3 * 1.2 = 205 usec.
 */
static unsigned int tx_irq_mod_usec = 150;

/* This is the first interrupt mode to try out of:
 * 0 => MSI-X
 * 1 => MSI
 * 2 => legacy
 */
static unsigned int interrupt_mode;

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_core_cpumask) && !defined(__VMKLNX__))
#define HAVE_EFX_NUM_PACKAGES
#endif
#if !defined(EFX_USE_KCOMPAT) || (defined(topology_sibling_cpumask) && !defined(__VMKLNX__) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP))
#define HAVE_EFX_NUM_CORES
#endif

/* This is the requested number of CPUs to use for Receive-Side Scaling
 * (RSS), i.e. the number of CPUs among which we may distribute
 * simultaneous interrupt handling.  Or alternatively it may be set to
 * "packages", "cores" or "hyperthreads" to get one receive channel per
 * package, core or hyperthread.  The default is "cores".
 *
 * Systems without MSI-X will only target one CPU via legacy or MSI
 * interrupt.
 */
static char *rss_cpus;
module_param(rss_cpus, charp, 0444);
MODULE_PARM_DESC(rss_cpus, "Number of CPUs to use for Receive-Side Scaling, "
		 "or 'packages', 'cores' or 'hyperthreads'");

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
static bool rss_numa_local = true;
module_param(rss_numa_local, bool, 0444);
MODULE_PARM_DESC(rss_numa_local, "Restrict RSS to CPUs on the local NUMA node");
#endif

#ifdef EFX_NOT_UPSTREAM
/* A fixed key for RSS that has been tested and found to provide good
 * spreading behaviour.  It also has the desirable property of being
 * symmetric.
 */
static const u8 efx_rss_fixed_key[40] = {
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};

static bool efx_rss_use_fixed_key = true;
module_param_named(rss_use_fixed_key, efx_rss_use_fixed_key, bool, 0444);
MODULE_PARM_DESC(rss_use_fixed_key, "Use a fixed RSS hash key, "
		"tested for reliable spreading across channels");
#endif

static bool phy_flash_cfg;
module_param(phy_flash_cfg, bool, 0644);
MODULE_PARM_DESC(phy_flash_cfg,
		 "[SFE4001/SMC10GPCIe-10BT] Set PHYs into reflash mode initially");

static bool irq_adapt_enable = true;
module_param(irq_adapt_enable, bool, 0444);
MODULE_PARM_DESC(irq_adapt_enable,
		 "Enable adaptive interrupt moderation");

static unsigned int irq_adapt_low_thresh = 8000;
module_param(irq_adapt_low_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_low_thresh,
		 "Threshold score for reducing IRQ moderation");

static unsigned int irq_adapt_high_thresh = 16000;
module_param(irq_adapt_high_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_high_thresh,
		 "Threshold score for increasing IRQ moderation");

static unsigned int irq_adapt_irqs = 1000;
module_param(irq_adapt_irqs, uint, 0644);
MODULE_PARM_DESC(irq_adapt_irqs,
		 "Number of IRQs per IRQ moderation adaptation");

static unsigned int debug = (NETIF_MSG_DRV | NETIF_MSG_PROBE |
			 NETIF_MSG_LINK | NETIF_MSG_IFDOWN |
			 NETIF_MSG_IFUP | NETIF_MSG_RX_ERR |
			 NETIF_MSG_TX_ERR | NETIF_MSG_HW);
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Bitmapped debugging message enable value");

static unsigned int rx_ring = EFX_DEFAULT_RX_DMAQ_SIZE;
module_param(rx_ring, uint, 0644);
MODULE_PARM_DESC(rx_ring,
		 "Maximum number of descriptors in a receive ring");

static unsigned int tx_ring = EFX_DEFAULT_TX_DMAQ_SIZE;
module_param(tx_ring, uint, 0644);
MODULE_PARM_DESC(tx_ring,
		 "Maximum number of descriptors in a transmit ring");

#ifdef EFX_NOT_UPSTREAM
int efx_target_num_vis = -1;
module_param_named(num_vis, efx_target_num_vis, int, 0644);
MODULE_PARM_DESC(num_vis, "Set number of VIs");
#endif

#ifdef EFX_NOT_UPSTREAM
static bool phy_power_follows_link;
module_param(phy_power_follows_link, bool, 0444);
MODULE_PARM_DESC(phy_power_follows_link,
		 "Power down phy when interface is administratively down");
#endif

#ifdef EFX_NOT_UPSTREAM
static char *performance_profile;
module_param(performance_profile, charp, 0444);
MODULE_PARM_DESC(performance_profile,
		 "Tune settings for different performance profiles: 'throughput', 'latency' or (default) 'auto'");
#endif

/**************************************************************************
 *
 * Utility functions and prototypes
 *
 *************************************************************************/

static int efx_soft_enable_interrupts(struct efx_nic *efx);
static void efx_soft_disable_interrupts(struct efx_nic *efx);
static void efx_remove_channel(struct efx_channel *channel);
static void efx_remove_channels(struct efx_nic *efx);
static const struct efx_channel_type efx_default_channel_type;
static void efx_remove_port(struct efx_nic *efx);
static int efx_init_napi_channel(struct efx_channel *channel);
static void efx_fini_napi(struct efx_nic *efx);
static void efx_fini_napi_channel(struct efx_channel *channel);
static void efx_fini_struct(struct efx_nic *efx);
static void efx_start_all(struct efx_nic *efx);
static void efx_stop_all(struct efx_nic *efx);

#ifdef EFX_USE_IRQ_NOTIFIERS
static void efx_unregister_irq_notifiers(struct efx_nic *efx);
#endif

#define EFX_ASSERT_RESET_SERIALISED(efx)		\
	do {						\
		if ((efx->state == STATE_READY) ||	\
		    (efx->state == STATE_RECOVERY) ||	\
		    (efx->state == STATE_DISABLED))	\
			ASSERT_RTNL();			\
	} while (0)

static int efx_check_disabled(struct efx_nic *efx)
{
	if (efx->state == STATE_DISABLED || efx->state == STATE_RECOVERY) {
		netif_err(efx, drv, efx->net_dev,
			  "device is disabled due to earlier errors\n");
		return -EIO;
	}
	return 0;
}

/**************************************************************************
 *
 * Event queue processing
 *
 *************************************************************************/

/* Process channel's event queue
 *
 * This function is responsible for processing the event queue of a
 * single channel.  The caller must guarantee that this function will
 * never be concurrently called more than once on the same channel,
 * though different channels may be being processed concurrently.
 */
static int efx_process_channel(struct efx_channel *channel, int budget)
{
	int spent;
	struct efx_nic *efx = channel->efx;
	struct efx_tx_queue *tx_queue;
	unsigned int fill_level;

	if (unlikely(!channel->enabled))
		return 0;

	/* Notify the TX path that we are going to ping
	 * doorbell, do this early to maximise benefit
	 */
	channel->holdoff_doorbell = channel->tx_coalesce_doorbell;

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		tx_queue->pkts_compl = 0;
		tx_queue->bytes_compl = 0;
	}

	spent = efx_nic_process_eventq(channel, budget);
	if (spent && efx_channel_has_rx_queue(channel)) {
		struct efx_rx_queue *rx_queue =
			efx_channel_get_rx_queue(channel);

		efx_rx_flush_packet(channel);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx_ssr_end_of_burst(channel);
#endif
		efx_fast_push_rx_descriptors(rx_queue, true);
	}

	/* See if we need to ping doorbell if there is
	 * anything on the send queue that NIC has not been
	 * informed of.
	 */

	while (unlikely(channel->holdoff_doorbell)) {
		unsigned int unsent = 0;

		/* write_count and notify_count can be updated on the Tx path
		 * so use ACCESS_ONCE() in this loop to avoid optimizations that
		 * would avoid reading the latest values from memory.
		 */

		/* There are unsent packets, for this to be set
		 * the xmit thread knows we are running
		 */
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (ACCESS_ONCE(tx_queue->notify_count) !=
			    ACCESS_ONCE(tx_queue->write_count)) {
				efx_nic_notify_tx_desc(tx_queue);
				++tx_queue->doorbell_notify_comp;
			}
		}
		channel->holdoff_doorbell = false;
		smp_mb();
		efx_for_each_channel_tx_queue(tx_queue, channel)
			unsent += ACCESS_ONCE(tx_queue->write_count) -
				ACCESS_ONCE(tx_queue->notify_count);
		if (unsent) {
			channel->holdoff_doorbell = true;

			/* Ensure that all reads and writes are complete to
			 * allow the latest values to be read in the next
			 * iteration, and that the Tx path sees holdoff_doorbell
			 * true so there are no further updates at this point.
			 */
			smp_mb();
		}
	}

	/* Update BQL */
	efx_for_each_channel_tx_queue(tx_queue, channel) {
		if (tx_queue->bytes_compl) {
			netdev_tx_completed_queue(tx_queue->core_txq,
				tx_queue->pkts_compl, tx_queue->bytes_compl);
		}
	}

	tx_queue = channel->tx_queue;
	fill_level = efx_channel_tx_fill_level(channel);

	/* See if we need to restart the netif queue. */
	if ((fill_level <= efx->txq_wake_thresh) &&
	    likely(tx_queue->core_txq) &&
	    unlikely(netif_tx_queue_stopped(tx_queue->core_txq)) &&
	    likely(efx->port_enabled) &&
	    likely(netif_device_present(efx->net_dev)))
	    netif_tx_wake_queue(tx_queue->core_txq);

	return spent;
}

/* NAPI poll handler
 *
 * NAPI guarantees serialisation of polls of the same device, which
 * provides the guarantee required by efx_process_channel().
 */
static void efx_update_irq_mod(struct efx_nic *efx, struct efx_channel *channel)
{
	int step = efx->irq_mod_step_us;

	if (channel->irq_mod_score < irq_adapt_low_thresh) {
		if (channel->irq_moderation_us > step) {
			channel->irq_moderation_us -= step;
			efx->type->push_irq_moderation(channel);
		}
	} else if (channel->irq_mod_score > irq_adapt_high_thresh) {
		if (channel->irq_moderation_us <
		    efx->irq_rx_moderation_us) {
			channel->irq_moderation_us += step;
			efx->type->push_irq_moderation(channel);
		}
	}

	channel->irq_count = 0;
	channel->irq_mod_score = 0;
}

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_OLD_NAPI)
static int efx_poll(struct napi_struct *napi, int budget)
{
	struct efx_channel *channel =
		container_of(napi, struct efx_channel, napi_str);
#else
static int efx_poll(struct net_device *dev, int *budget_ret)
{
	struct efx_channel *channel = dev->priv;
	struct napi_struct *napi = &channel->napi_str;
	int budget = min(dev->quota, *budget_ret);
#endif
	struct efx_nic *efx = channel->efx;
	int spent;

	if (!efx_channel_lock_napi(channel))
		return budget;

	netif_vdbg(efx, intr, efx->net_dev,
		   "channel %d NAPI poll executing on CPU %d\n",
		   channel->channel, raw_smp_processor_id());

	spent = efx_process_channel(channel, budget);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_NAPI)
	dev->quota -= spent;
	*budget_ret -= spent;
#endif

	if (spent < budget) {
		if (efx_channel_has_rx_queue(channel) &&
		    efx->irq_rx_adaptive &&
		    unlikely(++channel->irq_count == irq_adapt_irqs)) {
			efx_update_irq_mod(efx, channel);
		}

		efx_filter_rfs_expire(channel);

		/* There is no race here; although napi_disable() will
		 * only wait for napi_complete(), this isn't a problem
		 * since efx_nic_eventq_read_ack() will have no effect if
		 * interrupts have already been disabled.
		 */
		napi_complete(napi);
		efx_nic_eventq_read_ack(channel);
	}

	efx_channel_unlock_napi(channel);
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_OLD_NAPI)
	return spent;
#else
	return (spent >= budget);
#endif
}

/* Create event queue
 * Event queue memory allocations are done only once.  If the channel
 * is reset, the memory buffer will be reused; this guards against
 * errors during channel reset and also simplifies interrupt handling.
 */
static int efx_probe_eventq(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct efx_tx_queue *txq;
	unsigned long entries;

	/* When sizing our event queue we need to allow for:
	 *  - one entry per rxq entry.
	 *  - one entry per txq entry - or three if we're using timestamping.
	 *  - some capacity for MCDI and other events. This is mostly on
	 *    channel zero.
	 */
	entries = efx->rxq_entries;

	efx_for_each_channel_tx_queue(txq, channel) {
		entries += txq->timestamping ?
			   efx->txq_entries * 3 :
			   efx->txq_entries;
	}

	entries += channel->channel == 0 ? 256 : 128;

#ifdef EFX_NOT_UPSTREAM
	/* Add additional event queue entries for driverlink activity on
	 * channel zero.
	 */
	if (channel->channel == 0 && efx_dl_supported(efx))
		entries += EFX_EVQ_DL_EXTRA_ENTRIES;
#endif

	if (entries > EFX_MAX_EVQ_SIZE) {
		netif_warn(efx, probe, efx->net_dev,
			   "chan %d ev queue too large at %lu, capped at %lu\n",
			   channel->channel, entries, EFX_MAX_EVQ_SIZE);
		entries = EFX_MAX_EVQ_SIZE;
	} else {
		entries = roundup_pow_of_two(entries);
		netif_dbg(efx, probe, efx->net_dev,
			   "chan %d ev queue created with %lu entries\n",
			   channel->channel, entries);
	}
	channel->eventq_mask = max(entries, EFX_MIN_EVQ_SIZE) - 1;

	return efx_nic_probe_eventq(channel);
}

/* Prepare channel's event queue */
static int efx_init_eventq(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	int rc;

	EFX_WARN_ON_PARANOID(channel->eventq_init);

	netif_dbg(efx, drv, efx->net_dev,
		  "chan %d init event queue\n", channel->channel);

	rc = efx_nic_init_eventq(channel);
	if (rc == 0) {
		efx->type->push_irq_moderation(channel);
		channel->eventq_read_ptr = 0;
		channel->eventq_init = true;
	}
	return rc;
}

/* Enable event queue processing and NAPI */
void efx_start_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, ifup, channel->efx->net_dev,
		  "chan %d start event queue\n", channel->channel);

	/* Make sure the NAPI handler sees the enabled flag set */
	channel->enabled = true;
	smp_wmb();

	efx_channel_enable(channel);
	napi_enable(&channel->napi_str);
	efx_nic_eventq_read_ack(channel);
}

/* Disable event queue processing and NAPI */
void efx_stop_eventq(struct efx_channel *channel)
{
	if (!channel->enabled)
		return;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
			"chan %d stop event queue\n", channel->channel);

	napi_disable(&channel->napi_str);
	while (!efx_channel_disable(channel))
		usleep_range(1000, 20000);
	channel->enabled = false;
}

static void efx_fini_eventq(struct efx_channel *channel)
{
	if (!channel->eventq_init || efx_nic_hw_unavailable(channel->efx))
		return;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d fini event queue\n", channel->channel);

	efx_nic_fini_eventq(channel);
	channel->eventq_init = false;
}

static void efx_remove_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d remove event queue\n", channel->channel);

	efx_nic_remove_eventq(channel);
}

/**************************************************************************
 *
 * Channel handling
 *
 *************************************************************************/

/* Allocate and initialise a channel structure. */
static struct efx_channel *
efx_alloc_channel(struct efx_nic *efx, int i, struct efx_channel *old_channel)
{
	struct efx_channel *channel;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;
	int j;

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	channel->efx = efx;
	channel->channel = i;
	channel->type = &efx_default_channel_type;
	channel->holdoff_doorbell = false;
	channel->tx_coalesce_doorbell = false;
	channel->irq_mem_node = NUMA_NO_NODE;

	for (j = 0; j < EFX_TXQ_TYPES; j++) {
		tx_queue = &channel->tx_queue[j];
		tx_queue->efx = efx;
		tx_queue->channel = channel;
		tx_queue->queue = -1;
	}

	rx_queue = &channel->rx_queue;
	rx_queue->efx = efx;

#ifdef EFX_TX_STEERING
	if (unlikely(!zalloc_cpumask_var(&channel->available_cpus, GFP_KERNEL))) {
		kfree(channel);
		return NULL;
	}
#endif

	return channel;
}

/* Allocate and initialise a channel structure, copying parameters
 * (but not resources) from an old channel structure.
 */
static struct efx_channel *
efx_copy_channel(const struct efx_channel *old_channel)
{
	struct efx_nic *efx = old_channel->efx;
	struct efx_channel *channel;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;
	int j;

	channel = kmalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	*channel = *old_channel;

	channel->napi_dev = NULL;
	memset(&channel->eventq, 0, sizeof(channel->eventq));

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* Invalidate SSR state */
	channel->ssr.conns = NULL;
#endif

	for (j = 0; j < efx->tx_queues_per_channel; j++) {
		tx_queue = &channel->tx_queue[j];
		if (tx_queue->channel)
			tx_queue->channel = channel;
		tx_queue->buffer = NULL;
		memset(&tx_queue->txd, 0, sizeof(tx_queue->txd));
	}

	rx_queue = &channel->rx_queue;
	rx_queue->buffer = NULL;
	memset(&rx_queue->rxd, 0, sizeof(rx_queue->rxd));

#ifdef EFX_TX_STEERING
	if (unlikely(!zalloc_cpumask_var(&channel->available_cpus, GFP_KERNEL))) {
		kfree(channel);
		return NULL;
	}
	cpumask_copy(channel->available_cpus, old_channel->available_cpus);
#endif

	return channel;
}

static void efx_channel_post_remove(struct efx_channel *channel)
{
#ifdef EFX_TX_STEERING
	free_cpumask_var(channel->available_cpus);
#endif
}

static int efx_probe_channel(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	int rc;

	netif_dbg(channel->efx, probe, channel->efx->net_dev,
		  "creating channel %d\n", channel->channel);

	rc = channel->type->pre_probe(channel);
	if (rc)
		goto fail;

	rc = efx_probe_eventq(channel);
	if (rc)
		goto fail;

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		rc = efx_probe_tx_queue(tx_queue);
		if (rc)
			goto fail;
	}

	efx_for_each_channel_rx_queue(rx_queue, channel) {
		rc = efx_probe_rx_queue(rx_queue);
		if (rc)
			goto fail;
	}

	return 0;

fail:
	efx_remove_channel(channel);
	return rc;
}

static void
efx_get_channel_name(struct efx_channel *channel, char *buf, size_t len)
{
	struct efx_nic *efx = channel->efx;
	const char *type;
	int number;

	number = channel->channel;
	if (efx->tx_channel_offset == 0) {
		type = "";
	} else if (channel->channel < efx->tx_channel_offset) {
		type = "-rx";
	} else {
		type = "-tx";
		number -= efx->tx_channel_offset;
	}
	snprintf(buf, len, "%s%s-%d", efx->name, type, number);
}

static void efx_set_channel_names(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		channel->type->get_name(channel,
					efx->msi_context[channel->channel].name,
					sizeof(efx->msi_context[0].name));
}

static int efx_probe_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

	/* Restart buffer table allocation */
	efx->next_buffer_table = 0;

	/* Probe channels in reverse, so that any 'extra' channels
	 * use the start of the buffer table. This allows the traffic
	 * channels to be resized without moving them or wasting the
	 * entries before them.
	 */
	efx_for_each_channel_rev(channel, efx) {
		rc = efx_probe_channel(channel);
		if (rc) {
			netif_err(efx, probe, efx->net_dev,
				  "failed to create channel %d\n",
				  channel->channel);
			goto fail;
		}
	}
	efx_set_channel_names(efx);

	return 0;

fail:
	efx_remove_channels(efx);
	return rc;
}

/* Channels are shutdown and reinitialised whilst the NIC is running
 * to propagate configuration changes (mtu, checksum offload), or
 * to clear hardware error conditions
 */
static void efx_start_datapath(struct efx_nic *efx)
{
	bool old_rx_scatter = efx->rx_scatter;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_channel *channel;
	size_t rx_buf_len;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_FEATURES_CHANGE)
	netdev_features_t old_features = efx->net_dev->features;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
#if defined(EFX_HAVE_NDO_SET_FEATURES) || defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
	bool old_lro_available = efx->lro_available;
#endif

	efx->lro_available = true;
#endif

	/* Calculate the rx buffer allocation parameters required to
	 * support the current MTU, including padding for header
	 * alignment and overruns.
	 */
	efx->rx_dma_len = (efx->rx_prefix_size +
			   EFX_MAX_FRAME_LEN(efx->net_dev->mtu) +
			   efx->type->rx_buffer_padding);
	rx_buf_len = (sizeof(struct efx_rx_page_state) +
		      efx->rx_ip_align + efx->rx_dma_len);
	if (rx_buf_len <= PAGE_SIZE) {
		efx->rx_scatter = efx->type->always_rx_scatter;
		efx->rx_buffer_order = 0;
	} else if (efx->type->can_rx_scatter) {
		BUILD_BUG_ON(EFX_RX_USR_BUF_SIZE % L1_CACHE_BYTES);
		BUILD_BUG_ON(sizeof(struct efx_rx_page_state) +
			     2 * ALIGN(NET_IP_ALIGN + EFX_RX_USR_BUF_SIZE,
				       EFX_RX_BUF_ALIGNMENT) >
			     PAGE_SIZE);
		efx->rx_scatter = true;
		efx->rx_dma_len = EFX_RX_USR_BUF_SIZE;
		efx->rx_buffer_order = 0;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx->lro_available = false;
#endif
	} else {
		efx->rx_scatter = false;
		efx->rx_buffer_order = get_order(rx_buf_len);
	}

	efx_rx_config_page_split(efx);
	if (efx->rx_buffer_order)
		netif_dbg(efx, drv, efx->net_dev,
			  "RX buf len=%u; page order=%u batch=%u\n",
			  efx->rx_dma_len, efx->rx_buffer_order,
			  efx->rx_pages_per_batch);
	else
		netif_dbg(efx, drv, efx->net_dev,
			  "RX buf len=%u step=%u bpp=%u; page batch=%u\n",
			  efx->rx_dma_len, efx->rx_page_buf_step,
			  efx->rx_bufs_per_page, efx->rx_pages_per_batch);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
#if defined(EFX_HAVE_NDO_SET_FEATURES) || defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
	/* This will call back into efx_fix_features() */
	if (efx->lro_available != old_lro_available)
		netdev_update_features(efx->net_dev);
#elif defined(NETIF_F_LRO)
	if (!efx->lro_available && efx->net_dev->features & NETIF_F_LRO)
		efx->net_dev->features &= ~NETIF_F_LRO;
#else
	if (!efx->lro_available)
		efx->lro_enabled = false;
#endif
#endif

	/* Restore previously fixed features in hw_features and remove
	 * features which are fixed now */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_HW_FEATURES)
	efx->net_dev->hw_features |= efx->net_dev->features;
	efx->net_dev->hw_features &= ~efx->fixed_features;
#elif defined(EFX_HAVE_NETDEV_EXTENDED_HW_FEATURES)
	netdev_extended(efx->net_dev)->hw_features |= efx->net_dev->features;
	netdev_extended(efx->net_dev)->hw_features &= ~efx->fixed_features;
#else
	efx->hw_features |= efx->net_dev->features;
	efx->hw_features &= ~efx->fixed_features;
#endif
	efx->net_dev->features |= efx->fixed_features;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_FEATURES_CHANGE)
	if (efx->net_dev->features != old_features)
		netdev_features_change(efx->net_dev);
#endif

	/* RX filters may also have scatter-enabled flags */
	if (efx->rx_scatter != old_rx_scatter)
		efx->type->filter_update_rx_scatter(efx);

	/* We must keep at least one descriptor in a TX ring empty.
	 * We could avoid this when the queue size does not exactly
	 * match the hardware ring size, but it's not that important.
	 * Therefore we stop the queue when one more skb might fill
	 * the ring completely.  We wake it when half way back to
	 * empty.
	 */
	efx->txq_stop_thresh = efx->txq_entries - efx_tx_max_skb_descs(efx);
	efx->txq_wake_thresh = efx->txq_stop_thresh / 2;

	/* Initialise the channels */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			efx_init_tx_queue(tx_queue);
			atomic_inc(&efx->active_queues);
		}

		efx_for_each_channel_rx_queue(rx_queue, channel) {
			efx_init_rx_queue(rx_queue);
			atomic_inc(&efx->active_queues);
			efx_stop_eventq(channel);
			efx_fast_push_rx_descriptors(rx_queue, false);
			efx_start_eventq(channel);
		}
	}

	efx_ptp_start_datapath(efx);

	if (netif_device_present(efx->net_dev))
		netif_tx_wake_all_queues(efx->net_dev);
}

static void efx_stop_datapath(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_mcdi_iface *mcdi = NULL;
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);
	BUG_ON(efx->port_enabled);

	efx_ptp_stop_datapath(efx);

	/* Stop RX refill */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_rx_queue(rx_queue, channel)
			rx_queue->refill_enabled = false;
	}

	efx_for_each_channel(channel, efx) {
		/* RX packet processing is pipelined, so wait for the
		 * NAPI handler to complete.  At least event queue 0
		 * might be kept active by non-data events, so don't
		 * use napi_synchronize() but actually disable NAPI
		 * temporarily.
		 */
		if (efx_channel_has_rx_queue(channel)) {
			efx_stop_eventq(channel);
			efx_start_eventq(channel);
		}
	}

	rc = efx->type->fini_dmaq(efx);
	if (rc && EFX_WORKAROUND_7803(efx)) {
		/* Schedule a reset to recover from the flush failure. The
		 * descriptor caches reference memory we're about to free,
		 * but falcon_reconfigure_mac_wrapper() won't reconnect
		 * the MACs because of the pending reset.
		 */
		netif_err(efx, drv, efx->net_dev,
			  "Resetting to recover from flush failure\n");
		efx_schedule_reset(efx, RESET_TYPE_ALL);
	} else if (rc) {
		if (efx->mcdi)
			mcdi = efx_mcdi(efx);
		if (mcdi && mcdi->mode == MCDI_MODE_FAIL) {
			netif_info(efx, drv, efx->net_dev,
				   "Ignoring flush queue failure as we're in MCDI_MODE_FAIL\n");
		} else {
			netif_err(efx, drv, efx->net_dev,
				  "Recover or disable due to flush queue failure\n");
			efx_schedule_reset(efx, RESET_TYPE_RECOVER_OR_DISABLE);
		}
	} else {
		netif_dbg(efx, drv, efx->net_dev,
			  "successfully flushed all queues\n");
	}

#if defined(EFX_NOT_UPSTREAM) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC))
	cancel_work_sync(&efx->schedule_all_channels_work);
#endif

	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_rx_queue(rx_queue, channel)
			efx_fini_rx_queue(rx_queue);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			efx_fini_tx_queue(tx_queue);
	}
}

static void efx_remove_channel(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "destroy chan %d\n", channel->channel);

	efx_for_each_channel_rx_queue(rx_queue, channel)
		efx_remove_rx_queue(rx_queue);
	efx_for_each_channel_tx_queue(tx_queue, channel)
		efx_remove_tx_queue(tx_queue);
	efx_remove_eventq(channel);
	channel->type->post_remove(channel);
}

static void efx_remove_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;

#if defined(EFX_NOT_UPSTREAM) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC))
	cancel_work_sync(&efx->schedule_all_channels_work);
#endif

	efx_for_each_channel(channel, efx)
		efx_remove_channel(channel);
}

int
efx_realloc_channels(struct efx_nic *efx, u32 rxq_entries, u32 txq_entries)
{
	struct efx_channel *other_channel[EFX_MAX_CHANNELS], *channel;
	u32 old_rxq_entries, old_txq_entries;
	unsigned int i, next_buffer_table = 0;
	int rc, rc2;

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;

	/* Not all channels should be reallocated. We must avoid
	 * reallocating their buffer table entries.
	 */
	efx_for_each_channel(channel, efx) {
		struct efx_rx_queue *rx_queue;
		struct efx_tx_queue *tx_queue;

		if (channel->type->copy)
			continue;
		next_buffer_table = max(next_buffer_table,
					channel->eventq.index +
					channel->eventq.entries);
		efx_for_each_channel_rx_queue(rx_queue, channel)
			next_buffer_table = max(next_buffer_table,
						rx_queue->rxd.index +
						rx_queue->rxd.entries);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			next_buffer_table = max(next_buffer_table,
						tx_queue->txd.index +
						tx_queue->txd.entries);
	}

	efx_device_detach_sync(efx);
	efx_stop_all(efx);
	efx_soft_disable_interrupts(efx);

	/* Clone channels (where possible) */
	memset(other_channel, 0, sizeof(other_channel));
	for (i = 0; i < efx->n_channels; i++) {
		channel = efx->channel[i];
		if (channel->type->copy)
			channel = channel->type->copy(channel);
		if (!channel) {
			rc = -ENOMEM;
			goto out;
		}
		other_channel[i] = channel;
	}

	/* Swap entry counts and channel pointers */
	old_rxq_entries = efx->rxq_entries;
	old_txq_entries = efx->txq_entries;
	efx->rxq_entries = rxq_entries;
	efx->txq_entries = txq_entries;
	for (i = 0; i < efx->n_channels; i++) {
		channel = efx->channel[i];
		efx->channel[i] = other_channel[i];
		other_channel[i] = channel;
	}

	/* Restart buffer table allocation */
	efx->next_buffer_table = next_buffer_table;

	for (i = 0; i < efx->n_channels; i++) {
		channel = efx->channel[i];
		if (!channel->type->copy)
			continue;
		rc = efx_probe_channel(channel);
		if (rc)
			goto rollback;
		rc = efx_init_napi_channel(efx->channel[i]);
		if (rc)
			goto rollback;
	}

out:
	/* Destroy unused channel structures */
	for (i = 0; i < efx->n_channels; i++) {
		channel = other_channel[i];
		if (channel && channel->type->copy) {
			efx_fini_napi_channel(channel);
			efx_remove_channel(channel);
			kfree(channel);
		}
	}

	rc2 = efx_soft_enable_interrupts(efx);
	if (rc2) {
		rc = rc ? rc : rc2;
		netif_err(efx, drv, efx->net_dev,
			  "unable to restart interrupts on channel reallocation\n");
		efx_schedule_reset(efx, RESET_TYPE_DISABLE);
	} else {
		efx_start_all(efx);
		efx_device_attach_if_not_resetting(efx);
	}
	return rc;

rollback:
	/* Swap back */
	efx->rxq_entries = old_rxq_entries;
	efx->txq_entries = old_txq_entries;
	for (i = 0; i < efx->n_channels; i++) {
		channel = efx->channel[i];
		efx->channel[i] = other_channel[i];
		other_channel[i] = channel;
	}
	goto out;
}

void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	schedule_delayed_work(&rx_queue->slow_fill_work,
                                msecs_to_jiffies(100));
#else
	queue_delayed_work(efx_workqueue, &rx_queue->slow_fill_work,
                                msecs_to_jiffies(100));
#endif
}

void efx_cancel_slow_fill(struct efx_rx_queue *rx_queue)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
        cancel_delayed_work_sync(&rx_queue->slow_fill_work);
#else
        cancel_delayed_work(&rx_queue->slow_fill_work);
        flush_workqueue(efx_workqueue);
#endif
}

static const struct efx_channel_type efx_default_channel_type = {
	.pre_probe		= efx_channel_dummy_op_int,
	.post_remove		= efx_channel_post_remove,
	.get_name		= efx_get_channel_name,
	.copy			= efx_copy_channel,
	.keep_eventq		= false,
};

int efx_channel_dummy_op_int(struct efx_channel *channel)
{
	return 0;
}

void efx_channel_dummy_op_void(struct efx_channel *channel)
{
}

/**************************************************************************
 *
 * Port handling
 *
 **************************************************************************/

/* This ensures that the kernel is kept informed (via
 * netif_carrier_on/off) of the link status, and also maintains the
 * link status's stop on the port's TX queue.
 */
void efx_link_status_changed(struct efx_nic *efx)
{
	struct efx_link_state *link_state = &efx->link_state;

	/* SFC Bug 5356: A net_dev notifier is registered, so we must ensure
	 * that no events are triggered between unregister_netdev() and the
	 * driver unloading. A more general condition is that NETDEV_CHANGE
	 * can only be generated between NETDEV_UP and NETDEV_DOWN */
	if (!netif_running(efx->net_dev))
		return;

	if (link_state->up != netif_carrier_ok(efx->net_dev)) {
		efx->n_link_state_changes++;

		if (link_state->up)
			netif_carrier_on(efx->net_dev);
		else
			netif_carrier_off(efx->net_dev);
	}

	/* Status message for kernel log */
	if (link_state->up) {
		netif_info(efx, link, efx->net_dev,
			   "link up at %uMbps %s-duplex (MTU %d)%s%s%s\n",
			   link_state->speed, link_state->fd ? "full" : "half",
			   efx->net_dev->mtu,
			   (efx->loopback_mode ? " [" : ""),
			   (efx->loopback_mode ? LOOPBACK_MODE(efx) : ""),
			   (efx->loopback_mode ? " LOOPBACK]" : ""));

		if ((efx->wanted_fc & EFX_FC_AUTO) &&
		    (efx->wanted_fc & EFX_FC_TX) &&
		    (~efx->link_state.fc & EFX_FC_TX))
			/* There is no way to report this state
			 * through ethtool, so print this information
			 * to the kernel log */
			netif_info(efx, link, efx->net_dev,
				   "Flow control autonegotiated "
				   "tx OFF (wanted ON)\n");
	} else {
		netif_info(efx, link, efx->net_dev, "link down%s\n",
			   (efx->phy_mode & PHY_MODE_LOW_POWER) ? " [OFF]" : "");
	}

}

void efx_link_set_advertising(struct efx_nic *efx, u32 advertising)
{
	efx->link_advertising = advertising;
	if (advertising & ADVERTISED_Autoneg) {
		if (advertising & ADVERTISED_Pause)
			efx->wanted_fc |= (EFX_FC_TX | EFX_FC_RX);
		else
			efx->wanted_fc &= ~(EFX_FC_TX | EFX_FC_RX);
		if (advertising & ADVERTISED_Asym_Pause)
			efx->wanted_fc ^= EFX_FC_TX;
	}
}

void efx_link_set_wanted_fc(struct efx_nic *efx, u8 wanted_fc)
{
	efx->wanted_fc = wanted_fc;
	if (efx->link_advertising & ADVERTISED_Autoneg) {
		if (wanted_fc & EFX_FC_RX)
			efx->link_advertising |= (ADVERTISED_Pause |
						  ADVERTISED_Asym_Pause);
		else
			efx->link_advertising &= ~(ADVERTISED_Pause |
						   ADVERTISED_Asym_Pause);
		if (wanted_fc & EFX_FC_TX)
			efx->link_advertising ^= ADVERTISED_Asym_Pause;
	}
}

static void efx_fini_port(struct efx_nic *efx);

/* We assume that efx->type->reconfigure_mac will always try to sync RX
 * filters and therefore needs to read-lock the filter table against freeing
 */
int efx_mac_reconfigure(struct efx_nic *efx, bool mtu_only)
{
	int rc;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	down_read(&efx->filter_sem);
	rc = efx->type->reconfigure_mac(efx, mtu_only);
	up_read(&efx->filter_sem);

	return rc;
}

/* Push loopback/power/transmit disable settings to the PHY, and reconfigure
 * the MAC appropriately. All other PHY configuration changes are pushed
 * through phy_op->set_settings(), and pushed asynchronously to the MAC
 * through efx_monitor().
 *
 * Callers must hold the mac_lock
 */
int __efx_reconfigure_port(struct efx_nic *efx)
{
	enum efx_phy_mode phy_mode;
	int rc;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	/* Disable PHY transmit in mac level loopbacks */
	phy_mode = efx->phy_mode;
	if (LOOPBACK_INTERNAL(efx))
		efx->phy_mode |= PHY_MODE_TX_DISABLED;
	else
		efx->phy_mode &= ~PHY_MODE_TX_DISABLED;

	rc = efx->type->reconfigure_port(efx);

	if (rc)
		efx->phy_mode = phy_mode;

	return rc;
}

/* Reinitialise the MAC to pick up new PHY settings, even if the port is
 * disabled. */
int efx_reconfigure_port(struct efx_nic *efx)
{
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	mutex_lock(&efx->mac_lock);
	rc = __efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	return rc;
}

/* Asynchronous work item for changing MAC promiscuity and multicast
 * hash.  Avoid a drain/rx_ingress enable by reconfiguring the current
 * MAC directly. */
static void efx_mac_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, mac_work);

	mutex_lock(&efx->mac_lock);
	if (efx->port_enabled)
		(void)efx_mac_reconfigure(efx, false);
	mutex_unlock(&efx->mac_lock);
}

static int efx_probe_port(struct efx_nic *efx)
{
	int rc;

	netif_dbg(efx, probe, efx->net_dev, "create port\n");

	if (phy_flash_cfg)
		efx->phy_mode = PHY_MODE_SPECIAL;

	/* Connect up MAC/PHY operations table */
	rc = efx->type->probe_port(efx);
	if (rc)
		return rc;

	/* Initialise MAC address to permanent address */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
	ether_addr_copy(efx->net_dev->dev_addr, efx->net_dev->perm_addr);
#else
	ether_addr_copy(efx->net_dev->dev_addr, efx->perm_addr);
#endif

	return 0;
}

static int efx_init_port(struct efx_nic *efx)
{
	int rc;

	netif_dbg(efx, drv, efx->net_dev, "init port\n");

	mutex_lock(&efx->mac_lock);

	rc = efx->phy_op->init(efx);
	if (rc)
		goto fail1;

	efx->port_initialized = true;

	/* Reconfigure the MAC before creating dma queues (required for
	 * Falcon/A1 where RX_INGR_EN/TX_DRAIN_EN isn't supported) */
	if (efx_nic_rev(efx) <= EFX_REV_SIENA_A0)
		(void)efx_mac_reconfigure(efx, false);

	/* Ensure the PHY advertises the correct flow control settings */
	rc = efx->phy_op->reconfigure(efx);
	if (rc && rc != -EPERM)
		goto fail2;
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	mutex_unlock(&efx->mac_lock);
	return 0;

fail2:
	efx->phy_op->fini(efx);
fail1:
	mutex_unlock(&efx->mac_lock);
	return rc;
}

static void efx_start_port(struct efx_nic *efx)
{
	netif_dbg(efx, ifup, efx->net_dev, "start port\n");
	BUG_ON(efx->port_enabled);

	mutex_lock(&efx->mac_lock);
	efx->port_enabled = true;
	/* Always come out of low power unless we're forced off */
	if (!efx->phy_power_force_off)
		efx->phy_mode &= ~PHY_MODE_LOW_POWER;
	__efx_reconfigure_port(efx);

	/* Ensure MAC ingress/egress is enabled */
	(void)efx_mac_reconfigure(efx, false);

	mutex_unlock(&efx->mac_lock);
}

/* Cancel work for MAC reconfiguration, periodic hardware monitoring
 * and the async self-test, wait for them to finish and prevent them
 * being scheduled again.  This doesn't cover online resets, which
 * should only be cancelled when removing the device.
 */
static void efx_stop_port(struct efx_nic *efx)
{
	netif_dbg(efx, ifdown, efx->net_dev, "stop port\n");

	EFX_ASSERT_RESET_SERIALISED(efx);

	mutex_lock(&efx->mac_lock);
	efx->port_enabled = false;
	if (efx->phy_power_follows_link)
		efx->phy_mode |= PHY_MODE_LOW_POWER;
	__efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	netif_addr_lock_bh(efx->net_dev);
	netif_addr_unlock_bh(efx->net_dev);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	cancel_delayed_work_sync(&efx->monitor_work);
#endif
	efx_selftest_async_cancel(efx);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&efx->mac_work);
#endif
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	/* Since we cannot synchronously cancel/wait for individual
	 * work items, we must use cancel_delayed_work() to cancel any
	 * work items that are currently delayed and then
	 * flush_workqueue() to cancel/wait for all work items that
	 * are ready to run.  Since monitor_work reschedules itself,
	 * it must check the port_enabled flag before doing so, and to
	 * close a race with that check we must repeat the process.
	 */
	cancel_delayed_work(&efx->monitor_work);
	flush_workqueue(efx_workqueue);
	cancel_delayed_work(&efx->monitor_work);
	flush_workqueue(efx_workqueue);
#endif
}

static void efx_fini_port(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "shut down port\n");

	if (!efx->port_initialized)
		return;

	efx->phy_op->fini(efx);
	efx->port_initialized = false;

	efx->link_state.up = false;
	efx_link_status_changed(efx);
}

static void efx_remove_port(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "destroying port\n");

	efx->type->remove_port(efx);
}

/**************************************************************************
 *
 * NIC handling
 *
 **************************************************************************/

static LIST_HEAD(efx_primary_list);
static LIST_HEAD(efx_unassociated_list);

static bool efx_same_controller(struct efx_nic *left, struct efx_nic *right)
{
	return left->type == right->type &&
		left->vpd_sn && right->vpd_sn &&
		!strcmp(left->vpd_sn, right->vpd_sn);
}

static void efx_associate(struct efx_nic *efx)
{
	struct efx_nic *other, *next;

	if (efx->primary == efx) {
		/* Adding primary function; look for secondaries */

		netif_dbg(efx, probe, efx->net_dev, "adding to primary list\n");
		list_add_tail(&efx->node, &efx_primary_list);

		list_for_each_entry_safe(other, next, &efx_unassociated_list,
					 node) {
			if (efx_same_controller(efx, other)) {
				list_del(&other->node);
				netif_dbg(other, probe, other->net_dev,
					  "moving to secondary list of %s %s\n",
					  pci_name(efx->pci_dev),
					  efx->net_dev->name);
				list_add_tail(&other->node,
					      &efx->secondary_list);
				other->primary = efx;
			}
		}
	} else {
		/* Adding secondary function; look for primary */

		list_for_each_entry(other, &efx_primary_list, node) {
			if (efx_same_controller(efx, other)) {
				netif_dbg(efx, probe, efx->net_dev,
					  "adding to secondary list of %s %s\n",
					  pci_name(other->pci_dev),
					  other->net_dev->name);
				list_add_tail(&efx->node,
					      &other->secondary_list);
				efx->primary = other;
				return;
			}
		}

		netif_dbg(efx, probe, efx->net_dev,
			  "adding to unassociated list\n");
		list_add_tail(&efx->node, &efx_unassociated_list);
	}
}

static void efx_dissociate(struct efx_nic *efx)
{
	struct efx_nic *other, *next;

	list_del(&efx->node);
	efx->primary = NULL;

	list_for_each_entry_safe(other, next, &efx->secondary_list, node) {
		list_del(&other->node);
		netif_dbg(other, probe, other->net_dev,
			  "moving to unassociated list\n");
		list_add_tail(&other->node, &efx_unassociated_list);
		other->primary = NULL;
	}
}

/* This configures the PCI device to enable I/O and DMA. */
static int efx_init_io(struct efx_nic *efx)
{
	struct pci_dev *pci_dev = efx->pci_dev;
	dma_addr_t dma_mask = efx->type->max_dma_mask;
	unsigned int mem_map_size = efx->type->mem_map_size(efx);
	int rc, bar;

	netif_dbg(efx, probe, efx->net_dev, "initialising I/O\n");

	bar = efx->type->mem_bar;
	rc = pci_enable_device(pci_dev);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to enable PCI device\n");
		goto fail1;
	}

	pci_set_master(pci_dev);

	/* Set the PCI DMA mask.  Try all possibilities from our
	 * genuine mask down to 32 bits, because some architectures
	 * (e.g. x86_64 with iommu_sac_force set) will allow 40 bit
	 * masks event though they reject 46 bit masks.
	 */
	while (dma_mask > 0x7fffffffUL) {
		rc = dma_set_mask_and_coherent(&pci_dev->dev, dma_mask);
		if (rc == 0)
			break;
		dma_mask >>= 1;
	}
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "could not find a suitable DMA mask\n");
		goto fail2;
	}
	netif_dbg(efx, probe, efx->net_dev,
		  "using DMA mask %llx\n", (unsigned long long) dma_mask);

	efx->membase_phys = pci_resource_start(efx->pci_dev, bar);
	rc = pci_request_region(pci_dev, bar, "sfc");

	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "request for memory BAR failed\n");
		rc = -EIO;
		goto fail3;
	}
	efx->membase = ioremap_nocache(efx->membase_phys, mem_map_size);
	if (!efx->membase) {
		netif_err(efx, probe, efx->net_dev,
			  "could not map memory BAR at %llx+%x\n",
			  (unsigned long long)efx->membase_phys, mem_map_size);
		rc = -ENOMEM;
		goto fail4;
	}
	netif_dbg(efx, probe, efx->net_dev,
		  "memory BAR at %llx+%x (virtual %p)\n",
		  (unsigned long long)efx->membase_phys, mem_map_size,
		  efx->membase);

	return 0;

 fail4:
	pci_release_region(efx->pci_dev, bar);
 fail3:
	efx->membase_phys = 0;
 fail2:
	pci_disable_device(efx->pci_dev);
 fail1:
	return rc;
}

static void efx_fini_io(struct efx_nic *efx)
{
	int bar;
	netif_dbg(efx, drv, efx->net_dev, "shutting down I/O\n");

	if (efx->membase) {
		iounmap(efx->membase);
		efx->membase = NULL;
	}

	if (efx->membase_phys) {
		bar = efx->type->mem_bar;
		pci_release_region(efx->pci_dev, bar);
		efx->membase_phys = 0;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	/* Don't disable bus-mastering if VFs are assigned */
	if (!pci_vfs_assigned(efx->pci_dev))
#endif
		pci_disable_device(efx->pci_dev);
}

void efx_set_default_rx_indir_table(struct efx_nic *efx)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(efx->rx_indir_table); i++)
		efx->rx_indir_table[i] =
			ethtool_rxfh_indir_default(i, efx->rss_spread);
}

#ifdef HAVE_EFX_NUM_PACKAGES
/* Count the number of unique packages in the given cpumask */
static unsigned int efx_num_packages(const cpumask_t *in)
{
	cpumask_var_t core_mask;
	unsigned int count;
	int cpu, cpu2;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_cpu(cpu, in) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;

			/* Treat each numa node as a seperate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, core_mask);
			}
		}
	}

	free_cpumask_var(core_mask);

	return count;
}
#endif

#ifdef HAVE_EFX_NUM_CORES
/* Count the number of unique cores in the given cpumask */
static unsigned int efx_num_cores(const cpumask_t *in)
{
	cpumask_var_t core_mask;
	unsigned int count;
	int cpu;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_cpu(cpu, in) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;
			cpumask_or(core_mask, core_mask,
				   topology_sibling_cpumask(cpu));
		}
	}

	free_cpumask_var(core_mask);
	return count;
}
#endif

static unsigned int efx_wanted_parallelism(struct efx_nic *efx)
{
	bool selected = false;
	unsigned int n_rxq;
	struct net_device *net_dev =
		efx->net_dev;

	efx->rss_mode = EFX_RSS_CORES;

	if (rss_cpus == NULL) {
		/* Leave at default. */
	} else if (strcmp(rss_cpus, "packages") == 0) {
		efx->rss_mode = EFX_RSS_PACKAGES;
		selected = true;
	} else if (strcmp(rss_cpus, "cores") == 0) {
		efx->rss_mode = EFX_RSS_CORES;
		selected = true;
	} else if (strcmp(rss_cpus, "hyperthreads") == 0) {
		efx->rss_mode = EFX_RSS_HYPERTHREADS;
		selected = true;
	} else if (sscanf(rss_cpus, "%u", &n_rxq) == 1 && n_rxq > 0) {
		efx->rss_mode = EFX_RSS_CUSTOM;
		selected = true;
	} else {
		netif_err(efx, drv, net_dev,
			  "Bad value for module parameter rss_cpus='%s'\n",
			  rss_cpus);
	}

	switch (efx->rss_mode) {
#if defined(HAVE_EFX_NUM_PACKAGES)
	case EFX_RSS_PACKAGES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology"
				   " on Xen reliably. Using 4 rss channels.\n");
			n_rxq = 4;
		} else {
			netif_dbg(efx,  drv, net_dev,
				  "using efx_num_packages()\n");
			n_rxq = efx_num_packages(cpu_online_mask);
			/* Create two RSS queues even with a single package */
			if (n_rxq == 1)
				n_rxq = 2;
		}
		break;
#endif
#if defined(HAVE_EFX_NUM_CORES)
	case EFX_RSS_CORES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology"
				   " on Xen reliably. Assuming hyperthreading"
				   " enabled.\n");
			n_rxq = max_t(int, 1, num_online_cpus() / 2);
		} else {
			netif_dbg(efx, drv, net_dev,
				  "using efx_num_cores()\n");
			n_rxq = efx_num_cores(cpu_online_mask);
		}
		break;
#endif
	case EFX_RSS_HYPERTHREADS:
		n_rxq = num_online_cpus();
		break;
	case EFX_RSS_CUSTOM:
		break;
	default:
		if (selected)
			netif_err(efx, drv, net_dev,
				  "Selected rss mode '%s' not available\n",
				  rss_cpus);
		efx->rss_mode = EFX_RSS_HYPERTHREADS;
		n_rxq = num_online_cpus();
		break;
	}

	if (n_rxq > EFX_MAX_RX_QUEUES) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of rss channels from %u to %u.\n",
			   n_rxq, EFX_MAX_RX_QUEUES);
		n_rxq = EFX_MAX_RX_QUEUES;
	}

#ifdef CONFIG_SFC_SRIOV
	/* If RSS is requested for the PF *and* VFs then we can't write RSS
	 * table entries that are inaccessible to VFs
	 */
	if (efx_sriov_wanted(efx) && efx_vf_size(efx) > 1 &&
	    n_rxq > efx_vf_size(efx)) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of RSS channels from %u"
			   " to %u for VF support. Increase "
			   "vf-msix-limit to use more channels on "
			   "the PF.\n",
			   n_rxq, efx_vf_size(efx));
		n_rxq = efx_vf_size(efx);
	}
#endif

	return n_rxq;
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
/* Allocation priority:
 * 1. One Rx channel
 * 2. One separate Tx channel if requested (fallback to shared if impossible)
 * 3. Extra channels
 * 4. Rx netqueues
 * 5. Tx netqueues
 * 6. RSS
 *
 * Total number of allocated channels:
 *  - if separate_tx_channels:
 *    n_rx_netqs * n_rss_channels + n_tx_channels
 *  - else
 *    max(n_tx_channels, n_rx_netqs) * n_rss_channels
 *
 * Rx netqueue [0 .. n_rx_netqs - 1] to channel mapping:
 *   channel = netqueueu * n_rss_channels
 *
 * Tx netqueue [0 .. n_tx_channels - 1] to channel mapping:
 *   channel = tx_channel_offset + netqueue * tx_channel_stride
 * where
 *   tx_channel_offset = separate_tx_channels ? n_rx_channels : 0
 *   tx_channel_stride = separate_tx_channels ? 1 : n_rss_channels
 */
static unsigned int efx_allocate_msix_channels(struct efx_nic *efx,
					       unsigned int max_channels,
					       unsigned int extra_channels,
					       unsigned int parallelism)
{
	unsigned int dedicated_tx_channels;
	unsigned int channels;
	unsigned int remaining_channels = max_channels;
	unsigned int n_groups;
/* If number of netqs is unspecified, do not allocate a large number of them */
#define DEFAULT_MAX_NETQS	8U
	unsigned int num_netqs_def = min(parallelism, DEFAULT_MAX_NETQS);
	unsigned int n_rss_pools;
	unsigned int remaining_parallelism_for_rss;

	/* allocate 1 channel to RX and TX if necessary before
	 * allocating further */
	BUG_ON(remaining_channels < 1U);
	efx->n_rx_netqs = 1;
	remaining_channels -= efx->n_rx_netqs;
	if (separate_tx_channels)
		dedicated_tx_channels = min(1U, remaining_channels);
	else
		dedicated_tx_channels = 0U;
	remaining_channels -= dedicated_tx_channels;

	/* if we have enough channels to dedicate to extra_channels then do so,
	 * otherwise merge extra_channels in with the rest */
	if (remaining_channels > extra_channels)
		remaining_channels -= extra_channels;

	/* then allocate netqs, beginning with a single channel each */
	channels = min((num_rx_netqs >= 1U ? num_rx_netqs : num_netqs_def) - 1,
		       remaining_channels);
	remaining_channels -= channels;
	efx->n_rx_netqs += channels;
	efx->n_rx_netqs_no_rss = num_rss_netqs < 0 ? 0 :
		(unsigned)num_rss_netqs > efx->n_rx_netqs ? 0 :
		(efx->n_rx_netqs - (unsigned)num_rss_netqs);
	n_rss_pools = efx->n_rx_netqs - efx->n_rx_netqs_no_rss;
	n_groups = efx->n_rx_netqs;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
	/* then allocate extra tx channels */
	if (dedicated_tx_channels > 0) {
		channels = min((num_tx_channels >= 1U ? num_tx_channels
						      : num_netqs_def) - 1,
			       remaining_channels);
		/* limit by max_tx_channels, taking in to account already
		 * allocated */
		channels = min(channels,
			       efx->max_tx_channels - dedicated_tx_channels);
		dedicated_tx_channels += channels;
		remaining_channels -= channels;
		efx->n_tx_channels = dedicated_tx_channels;
	} else {
		/* Tx share channels with Rx. n_groups Rx channels are
		 * allocated. Allocate more from remaining if required. */
		efx->n_tx_channels = min(num_tx_channels >= 1U ? num_tx_channels
							       : num_netqs_def,
					 remaining_channels + n_groups);
		/* limit by max_tx_channels */
		efx->n_tx_channels = min(efx->n_tx_channels,
					 efx->max_tx_channels);
		/* More Tx channels than already allocated Rx */
		if (efx->n_tx_channels > n_groups) {
			remaining_channels -= efx->n_tx_channels - n_groups;
			n_groups = efx->n_tx_channels;
		}
	}
#else
	if (dedicated_tx_channels > 0)
		efx->n_tx_channels = dedicated_tx_channels;
	else
		efx->n_tx_channels = 1;
#endif
	efx->n_rss_channels = 1;
	if (n_rss_pools > 0) {
		remaining_parallelism_for_rss =
			parallelism <= efx->n_rx_netqs ? 0 :
				(parallelism - efx->n_rx_netqs);

		/* Falcon B0 / Siena implements RSS as:
		 *   rx_qid = filter_rx_base_qid | rx_qid_offset
		 * So, n_rss_channels (step of base queue ID) must be a power
		 * of 2, but real number of used RSS channel (rss_spread) may
		 * be any less or equal to n_rss_channels.
		 * EF10 uses addition instead of bitwise 'or' and allocation
		 * may be done more efficient (if required in the future). */
		while (remaining_channels >= n_groups * efx->n_rss_channels &&
		       remaining_parallelism_for_rss >=
			       efx->n_rss_channels * n_rss_pools &&
		       (max_netq_rss_channels == 0 ||
			efx->n_rss_channels < max_netq_rss_channels)) {
			remaining_channels -= efx->n_rss_channels * n_groups;
			remaining_parallelism_for_rss -=
				efx->n_rss_channels * n_rss_pools;
			efx->n_rss_channels *= 2;
		}
	}

	efx->n_rx_channels = efx->n_rx_netqs * efx->n_rss_channels;
	efx->rss_spread = (max_netq_rss_channels == 0) ?
				efx->n_rss_channels :
				min(efx->n_rss_channels, max_netq_rss_channels);
	efx->n_channels =
		n_groups * efx->n_rss_channels + dedicated_tx_channels;
	if (dedicated_tx_channels > 0) {
		efx->tx_channel_offset = efx->n_rx_channels;
		efx->tx_channel_stride = 1;
	} else {
		efx->tx_channel_offset = 0;
		efx->tx_channel_stride = efx->n_rss_channels;
	}

	netif_info(efx, drv, efx->net_dev,
		   "Allocating %u RX netqs (%u with RSS, %u channels each), %u dedicated TX channels\n",
		   efx->n_rx_netqs, efx->n_rx_netqs - efx->n_rx_netqs_no_rss,
		   efx->n_rss_channels, dedicated_tx_channels);

	return efx->n_channels;
}
#else
static unsigned int efx_num_rss_channels(struct efx_nic *efx,
					 unsigned int extra_channels)
{
	unsigned int rss_channels = efx->n_rx_channels;

	if (rss_channels > extra_channels)
		rss_channels -= extra_channels;

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
	if (rss_numa_local) {
		cpumask_var_t local_online_cpus;

		if (unlikely(!zalloc_cpumask_var(&local_online_cpus,
						 GFP_KERNEL))) {
			netif_err(efx, drv, efx->net_dev,
				  "Not enough temporary memory to determine "
				  "local CPUs - using all CPUs for RSS.\n");
			rss_numa_local = false;
			return rss_channels;
		}

		cpumask_and(local_online_cpus, cpu_online_mask,
			    cpumask_of_pcibus(efx->pci_dev->bus));

		if (unlikely(!cpumask_weight(local_online_cpus))) {
			netif_info(efx, drv, efx->net_dev, "No local CPUs online - using all CPUs for RSS.\n");
			rss_numa_local = false;
			return rss_channels;
		}

		if (efx->rss_mode == EFX_RSS_PACKAGES)
			return min(rss_channels,
				   efx_num_packages(local_online_cpus));
#ifdef HAVE_EFX_NUM_CORES
		if (efx->rss_mode == EFX_RSS_CORES)
			return min(rss_channels,
				   efx_num_cores(local_online_cpus));
#endif
		return min(rss_channels,
			   cpumask_weight(local_online_cpus));
	}
#endif

	return rss_channels;
}

static unsigned int efx_allocate_msix_channels(struct efx_nic *efx,
					       unsigned int max_channels,
					       unsigned int extra_channels,
					       unsigned int parallelism)
{
	unsigned int n_channels = parallelism;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
	if (separate_tx_channels)
		n_channels *= 2;
#else
	if (separate_tx_channels)
		n_channels += 1;
#endif
	n_channels += extra_channels;
	n_channels = min(n_channels, max_channels);

	efx->n_channels = n_channels;

	/* Do not create the PTP TX queue(s) if PTP uses the MC directly. */
	if (extra_channels && !efx_ptp_use_mac_tx_timestamps(efx))
		n_channels--;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_TX_MQ)
	efx->n_tx_channels = 1;
#endif
	if (separate_tx_channels) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
		efx->n_tx_channels =
			min(max(n_channels / 2, 1U),
			    efx->max_tx_channels);
#endif
		efx->tx_channel_offset =
			n_channels - efx->n_tx_channels;
		efx->n_rx_channels =
			max(n_channels -
			    efx->n_tx_channels, 1U);
	} else {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
		efx->n_tx_channels = min(n_channels, efx->max_tx_channels);
#endif
		efx->tx_channel_offset = 0;
		efx->n_rx_channels = n_channels;
	}
	efx->n_rss_channels = efx_num_rss_channels(efx, extra_channels);
	efx->rss_spread = efx->n_rss_channels;

	netif_dbg(efx, drv, efx->net_dev,
		  "Allocating %u RX channels\n",
		  efx->n_rx_channels);

	return efx->n_channels;
}
#endif

/* Probe the number and type of interrupts we are able to obtain, and
 * the resulting numbers of channels and RX queues.
 */
static int efx_probe_interrupts(struct efx_nic *efx)
{
	unsigned int extra_channels = 0;
	unsigned int i, j;
	int rc;

	for (i = 0; i < EFX_MAX_EXTRA_CHANNELS; i++)
		if (efx->extra_channel_type[i])
			++extra_channels;

	if (efx->interrupt_mode == EFX_INT_MODE_MSIX) {
		struct msix_entry xentries[EFX_MAX_CHANNELS];
		unsigned int parallelism = efx_wanted_parallelism(efx);
		unsigned int n_channels =
			efx_allocate_msix_channels(efx, efx->max_channels,
						   extra_channels,
						   parallelism);
		efx->n_wanted_channels = n_channels +
			EFX_MAX_EXTRA_CHANNELS - extra_channels;

		for (i = 0; i < n_channels; i++)
			xentries[i].entry = i;
		rc = pci_enable_msix_range(efx->pci_dev, xentries, 1, n_channels);
		if (rc < 0) {
			/* Fall back to single channel MSI */
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI-X\n");
			if (efx->type->min_interrupt_mode >= EFX_INT_MODE_MSI)
				efx->interrupt_mode = EFX_INT_MODE_MSI;
			else
				return rc;
		} else if (rc < n_channels) {
			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Insufficient MSI-X vectors"
				  " available (%d < %u).\n", rc, n_channels);
			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Performance may be reduced.\n");
			n_channels = rc;
			efx_allocate_msix_channels(efx, n_channels,
						   extra_channels,
						   parallelism);
		}

		if (rc > 0) {
			for (i = 0; i < efx->n_channels; i++)
				efx_get_channel(efx, i)->irq =
					xentries[i].vector;
		}
	}

	/* Try single interrupt MSI */
	if (efx->interrupt_mode == EFX_INT_MODE_MSI) {
		efx->n_channels = 1;
		efx->n_rx_channels = 1;
		efx->n_rss_channels = 1;
		efx->rss_spread = 1;
		efx->n_tx_channels = 1;
		efx->tx_channel_offset = 0;
		efx->n_wanted_channels = 1;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
		efx->n_rx_netqs = 1;
		efx->n_rx_netqs_no_rss = 1;
#endif
		rc = pci_enable_msi(efx->pci_dev);
		if (rc == 0) {
			efx_get_channel(efx, 0)->irq = efx->pci_dev->irq;
		} else {
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI\n");
			if (efx->type->min_interrupt_mode >= EFX_INT_MODE_LEGACY)
				efx->interrupt_mode = EFX_INT_MODE_LEGACY;
			else
				return rc;
		}
	}

	/* Assume legacy interrupts */
	if (efx->interrupt_mode == EFX_INT_MODE_LEGACY) {
		efx->n_channels = 1 + (separate_tx_channels ? 1 : 0)
			+ (efx_sriov_wanted(efx) ? 1 : 0);
		efx->n_rx_channels = 1;
		efx->n_rss_channels = 1;
		efx->rss_spread = 1;
		efx->n_tx_channels = 1;
		efx->tx_channel_offset = separate_tx_channels ? 1 : 0;
		efx->n_wanted_channels = efx->n_channels;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
		efx->n_rx_netqs = 1;
		efx->n_rx_netqs_no_rss = 1;
#endif
		efx->legacy_irq = efx->pci_dev->irq;
	}

	/* Assign extra channels if possible */
	j = efx->n_channels;
	for (i = 0; i < EFX_MAX_EXTRA_CHANNELS; i++) {
		if (!efx->extra_channel_type[i])
			continue;
		if (efx->interrupt_mode != EFX_INT_MODE_MSIX ||
		    efx->n_channels <= extra_channels) {
			efx->extra_channel_type[i]->handle_no_channel(efx);
		} else {
			--j;
			efx_get_channel(efx, j)->type =
				efx->extra_channel_type[i];
		}
	}

	/* RSS on the PF might now be impossible due to interrupt allocation
	 * failure */
#ifdef CONFIG_SFC_SRIOV
	if (efx_sriov_wanted(efx) && efx->rss_spread == 1)
		efx->rss_spread = efx_vf_size(efx);
#endif
	return 0;
}

#if !defined(CONFIG_SMP) || defined(__VMKLNX__)
static void efx_set_interrupt_affinity(struct efx_nic *efx __always_unused)
{
}

static void efx_clear_interrupt_affinity(struct efx_nic *efx __always_unused)
{
}
#else
#if !defined(EFX_NOT_UPSTREAM)
static void efx_set_interrupt_affinity(struct efx_nic *efx)
{
	struct efx_channel *channel;
	unsigned int cpu;

	efx_for_each_channel(channel, efx) {
		cpu = cpumask_local_spread(channel->channel,
				pcibus_to_node(efx->pci_dev->bus));

		irq_set_affinity_hint(channel->irq, cpumask_of(cpu));
		channel->irq_mem_node = cpu_to_mem(cpu);
	}
}

static void efx_clear_interrupt_affinity(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		irq_set_affinity_hint(channel->irq, NULL);
}
#else
static bool efx_irq_set_affinity = true;
module_param_named(irq_set_affinity, efx_irq_set_affinity, bool, 0444);
MODULE_PARM_DESC(irq_set_affinity,
		 "Set SMP affinity of IRQs to support RSS "
		 "(N=>disabled Y=>enabled (default))");

/* Set CPU affinity hint and/or initial affinity for IRQ */
static int efx_set_cpu_affinity(struct efx_channel *channel, int cpu)
{
	struct efx_nic *efx = channel->efx;
	char *content, filename[64];
	int content_len, rc = 0;
	struct file *file;
	mm_segment_t old_fs;
	loff_t offset = 0;
	ssize_t written;

#ifdef EFX_USE_IRQ_SET_AFFINITY_HINT
	rc = irq_set_affinity_hint(channel->irq, cpumask_of(cpu));
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to set affinity hint for channel %d"
			  " interrupt %d\n", channel->channel, channel->irq);
		return rc;
	}
#endif
#ifdef EFX_TX_STEERING
	cpumask_copy(channel->available_cpus, cpumask_of(cpu));
#endif

	if (!efx_irq_set_affinity)
		return 0;

	/* Write the mask into a sufficient buffer. We need a byte
	 * for every 4 bits of mask, plus comma's, plus a NULL. */
	content_len = max(NR_CPUS, 8) / 2;
	content = kmalloc(content_len, GFP_KERNEL);
	if (!content)
		return -ENOMEM;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PRINTF_BITMAPS)
	snprintf(content, content_len, "%*pb", cpumask_pr_args(cpumask_of(cpu)));
#elif defined(EFX_HAVE_OLD_CPUMASK_SCNPRINTF)
	{
		cpumask_t mask = cpumask_of_cpu(cpu);
		cpumask_scnprintf(content, content_len, mask);
	}
#else
	cpumask_scnprintf(content, content_len, cpumask_of(cpu));
#endif

	/* Open /proc/irq/XXX/smp_affinity */
	snprintf(filename, sizeof(filename), "/proc/irq/%d/smp_affinity",
		 channel->irq);
	file = filp_open(filename, O_RDWR, 0);
	if (IS_ERR(file)) {
		netif_err(efx, drv, efx->net_dev,
			  "Could not open %s: error %ld\n",
			  filename, PTR_ERR(file));
		rc = -EIO;
		goto out1;
	}

	/* Write cpumask to file */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	written = file->f_op->write(file, (__force __user char *)content,
				    content_len, &offset);
	set_fs(old_fs);

	if (written != content_len) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to write affinity for channel %d"
			  " interrupt %d\n", channel->channel, channel->irq);
		rc = -EIO;
		goto out2;
	}

	netif_dbg(efx, drv, efx->net_dev,
		  "Set channel %d interrupt %d affinity\n",
		  channel->channel, channel->irq);

 out2:
	filp_close(file, NULL);
 out1:
	kfree(content);

	return rc;
}

/* Count of number of RSS channels allocated to each CPU
 * in the system. Protected by the rtnl lock */
static u16 *rss_cpu_usage;

#ifdef HAVE_EFX_NUM_PACKAGES
/* Select the package_set with the lowest usage count */
static void efx_rss_choose_package(cpumask_t *set, cpumask_t *package_set,
				   cpumask_t *used_set,
				   const cpumask_t *global_set)
{
	unsigned int thresh, count;
	int cpu, cpu2, sibling;

	thresh = 1;
	for_each_cpu(cpu, global_set)
		thresh += rss_cpu_usage[cpu];

	cpumask_clear(used_set);
	for_each_cpu(cpu, global_set) {
		if (!cpumask_test_cpu(cpu, used_set)) {
			cpumask_clear(package_set);
			/* Treat each numa node as a seperate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, package_set);
			}
			cpumask_and(package_set, package_set, global_set);
			cpumask_or(used_set, used_set, package_set);

			count = 0;
			for_each_cpu(sibling, package_set)
				count += rss_cpu_usage[sibling];

			if (count < thresh) {
				cpumask_copy(set, package_set);
				thresh = count;
			}
		}
	}
}
#endif

#ifdef HAVE_EFX_NUM_CORES
/* Select the thread siblings within the package with the lowest usage count */
static void efx_rss_choose_core(cpumask_t *set, const cpumask_t *package_set,
				cpumask_t *core_set, cpumask_t *used_set)
{
	unsigned int thresh, count;
	int cpu, sibling;

	thresh = 1;
	for_each_cpu(cpu, package_set)
		thresh += rss_cpu_usage[cpu];

	cpumask_clear(used_set);
	for_each_cpu(cpu, package_set) {
		if (!cpumask_test_cpu(cpu, used_set)) {
			cpumask_copy(core_set, topology_sibling_cpumask(cpu));
			cpumask_or(used_set, used_set, core_set);

			count = 0;
			for_each_cpu(sibling, core_set)
				count += rss_cpu_usage[sibling];

			if (count < thresh) {
				cpumask_copy(set, core_set);
				thresh = count;
			}
		}
	}
}
#endif

/* Select the thread within the mask with the lowest usage count */
static int efx_rss_choose_thread(const cpumask_t *set)
{
	int cpu, chosen;
	unsigned int thresh;

	thresh = 1;
	for_each_cpu(cpu, set)
		thresh += rss_cpu_usage[cpu];

	chosen = 0;
	for_each_cpu(cpu, set) {
		if (rss_cpu_usage[cpu] < thresh) {
			chosen = cpu;
			thresh = rss_cpu_usage[cpu];
		}
	}

	return chosen;
}

#ifdef EFX_TX_STEERING
#include <linux/sort.h>

struct efx_cpu_channel_count {
	size_t cpu;
	size_t channel_count;
};

static int cpu_channel_cmp(const void *lhs_, const void *rhs_)
{
	const struct efx_cpu_channel_count *lhs = lhs_, *rhs = rhs_;

	return lhs->channel_count - rhs->channel_count;
}

static void efx_build_cpu_channel_map(struct efx_nic *efx)
{
	int channel_usage[EFX_MAX_CHANNELS];
	struct efx_cpu_channel_count *cpu_channel_counts;
	const struct cpumask *threads;
	int cpu, cpu2;
	struct efx_channel *channel;
	size_t i, thresh;
	int cpus = num_possible_cpus();

	cpu_channel_counts = kmalloc(sizeof(*cpu_channel_counts) * cpus,
				     GFP_KERNEL);
	if (!cpu_channel_counts)
		return;

	for (cpu = 0; cpu < cpus; ++cpu) {
		cpu_channel_counts[cpu].cpu = cpu;
		cpu_channel_counts[cpu].channel_count = 0;
	}

	efx_for_each_channel(channel, efx)
		for_each_cpu(cpu, channel->available_cpus)
			++cpu_channel_counts[cpu].channel_count;

	sort(cpu_channel_counts, cpus, sizeof(*cpu_channel_counts),
	     cpu_channel_cmp, NULL);

	memset(channel_usage, 0, sizeof(channel_usage));

	for (i = 0; i < cpus; ++i) {
		cpu = cpu_channel_counts[i].cpu;
		thresh = (size_t) -1;
		efx->cpu_channel_map[cpu] = -1;

		efx_for_each_channel(channel, efx) {
			if (channel == efx_ptp_channel(efx))
				continue;

			if (cpumask_test_cpu(cpu, channel->available_cpus))
				if (channel_usage[channel->channel] < thresh) {
					efx->cpu_channel_map[cpu] =
						channel->channel;
					thresh =
						channel_usage[channel->channel];
				}
		}

		if (efx->cpu_channel_map[cpu] != -1)
			++channel_usage[efx->cpu_channel_map[cpu]];
	}

	for (cpu = 0; cpu < cpus; ++cpu)
		if (efx->cpu_channel_map[cpu] == -1) {
			/* CPU with no channel assigned to it.
			 * See if it's a hyperthread of a CPU that does.
			 * If not then leave it -1 and we'll fall back
			 * on skb_tx_hash.
			 */
			threads = topology_sibling_cpumask(cpu);

			for_each_cpu(cpu2, threads)
				if (cpu2 < cpus &&
				    efx->cpu_channel_map[cpu2] != -1) {
					efx->cpu_channel_map[cpu] =
						efx->cpu_channel_map[cpu2];
					break;
				}
		}

	kfree(cpu_channel_counts);
}
#endif

/* Stripe the RSS vectors across the CPUs. */
static void efx_set_interrupt_affinity(struct efx_nic *efx)
{
	enum {PACKAGE, CORE, TEMP1, TEMP2, LOCAL, SETS_MAX};
	cpumask_var_t sets[SETS_MAX];
	struct efx_channel *channel;
	int cpu, sets_allocd;

	/* Only do this for RSS/MSI-X */
	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

	for (sets_allocd = 0; sets_allocd < ARRAY_SIZE(sets); sets_allocd++) {
		if (!zalloc_cpumask_var(&sets[sets_allocd], GFP_KERNEL)) {
			netif_err(efx, drv, efx->net_dev,
				  "Not enough temporary memory to"
				  " set IRQ affinity\n");
			goto out;
		}
	}

#ifdef EFX_TX_STEERING
	efx->cpu_channel_map = kmalloc(sizeof(int) * num_possible_cpus(),
				       GFP_KERNEL);
	if (!efx->cpu_channel_map)
		netif_info(efx, drv, efx->net_dev,
			   "Not enough memory to record IRQ affinity map\n");
	else
		for (cpu = 0; cpu < num_possible_cpus(); ++cpu)
			efx->cpu_channel_map[cpu] = -1;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
	cpumask_and(sets[LOCAL], cpu_online_mask,
		    cpumask_of_pcibus(efx->pci_dev->bus));
#endif

	/* Serialise access to rss_cpu_usage */
	rtnl_lock();

	/* Assign each channel a CPU */
	efx_for_each_channel(channel, efx) {
#ifdef HAVE_EFX_NUM_PACKAGES
		/* Force channels 0-RSS to the local package, otherwise select
		 * the package with the lowest usage count */
		efx_rss_choose_package(sets[PACKAGE], sets[TEMP1], sets[TEMP2],
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
			rss_numa_local &&
			channel->channel < efx->n_rss_channels ?
				sets[LOCAL] :
#endif
				cpu_online_mask);
		WARN_ON(!cpumask_weight(sets[PACKAGE]));
#else
		cpumask_copy(sets[PACKAGE], &cpu_online_map);
#endif

		/* Select the thread siblings within this package with the
		 * lowest usage count */
#ifdef HAVE_EFX_NUM_CORES
		efx_rss_choose_core(sets[CORE], sets[PACKAGE], sets[TEMP1],
				    sets[TEMP2]);
		WARN_ON(!cpumask_weight(sets[CORE]));
#else
		cpumask_copy(sets[CORE], sets[PACKAGE]);
#endif

		/* Select the thread within this set with the lowest usage count */
		cpu = efx_rss_choose_thread(sets[CORE]);
		++rss_cpu_usage[cpu];
		efx_set_cpu_affinity(channel, cpu);
		channel->irq_mem_node = cpu_to_mem(cpu);
	}

	rtnl_unlock();

#ifdef EFX_TX_STEERING
	if (efx->cpu_channel_map)
		efx_build_cpu_channel_map(efx);
#endif

out:
	while (sets_allocd--)
		free_cpumask_var(sets[sets_allocd]);
}

static void efx_clear_interrupt_affinity(struct efx_nic *efx)
{
#ifdef EFX_USE_IRQ_SET_AFFINITY_HINT
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		(void)irq_set_affinity_hint(channel->irq, NULL);
#endif
#ifdef EFX_TX_STEERING
	kfree(efx->cpu_channel_map);
	efx->cpu_channel_map = NULL;
#endif
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETIF_SET_XPS_QUEUE)
static bool auto_config_xps = true;
module_param(auto_config_xps, bool, 0644);
MODULE_PARM_DESC(auto_config_xps,
		 "Toggle automatic XPS configuration (default is enabled).");

static void efx_set_xps_queues(struct efx_nic *efx)
{
	int tx_channel, cpu, rc;
	struct efx_channel *channel;
	cpumask_var_t mask;

	if (unlikely(!efx->cpu_channel_map))
		return;

	if (unlikely(!zalloc_cpumask_var(&mask, GFP_KERNEL)))
		return;

	efx_for_each_channel(channel, efx) {
		if (!efx_channel_has_tx_queues(channel) ||
		    channel == efx_ptp_channel(efx))
			continue;
		cpumask_clear(mask);
		tx_channel = channel->channel - efx->tx_channel_offset;
		for(cpu = 0; cpu < num_possible_cpus(); ++cpu)
			if (efx->cpu_channel_map[cpu] == channel->channel)
				cpumask_set_cpu(cpu, mask);
		rc = netif_set_xps_queue(efx->net_dev, mask, tx_channel);
		if (rc && net_ratelimit())
			netif_warn(efx, drv, efx->net_dev,
				   "Unable to set XPS affinity: queue %d"
				   " with cpu %d (rc=%d)\n", tx_channel, cpu, rc);
	}

	free_cpumask_var(mask);
}
#endif /* EFX_HAVE_NETIF_SET_XPS_QUEUE */
#endif /* EFX_NOT_UPSTREAM && CONFIG_XPS */
#endif /* EFX_NOT_UPSTREAM */
#endif /* CONFIG_SMP && !__VMKLNX__ */

#ifdef EFX_USE_IRQ_NOTIFIERS
static void efx_channel_reassign_irq(struct efx_channel *channel,
				    const cpumask_t *mask)
{
	struct efx_nic *efx = channel->efx;
#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
	cpumask_var_t temp_mask;
#endif

	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
	if (rss_numa_local && channel->channel < efx->n_rss_channels)
		if (likely(zalloc_cpumask_var(&temp_mask, GFP_KERNEL))) {
			cpumask_and(temp_mask, mask,
				    cpumask_of_pcibus(efx->pci_dev->bus));
			if (cpumask_weight(temp_mask))
				mask = temp_mask;
			else
				free_cpumask_var(temp_mask);
		}
#endif

	cpumask_copy(channel->available_cpus, mask);

	/* Lock out access to cpu_channel_map */
	rtnl_lock();

	/* Rebuild cpu_channel_map */
	efx_build_cpu_channel_map(efx);

	rtnl_unlock();

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
	if (mask == temp_mask)
		free_cpumask_var(temp_mask);
#endif
}

static void efx_irq_release(struct kref *ref)
{
	struct efx_irq_affinity_notify *this =
		container_of(ref, struct efx_irq_affinity_notify,
			     notifier.kref);

	kfree(this);
}

static void efx_irq_notify(struct irq_affinity_notify *this_,
			  const cpumask_t *mask)
{
	struct efx_irq_affinity_notify *this =
		container_of(this_, struct efx_irq_affinity_notify, notifier);
	struct efx_nic *efx = this->efx;
	struct efx_channel *channel = efx_get_channel(efx, this->channel);

	efx_channel_reassign_irq(channel, mask);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETIF_SET_XPS_QUEUE)
	if (auto_config_xps)
		efx_set_xps_queues(efx);
#endif
#endif
}

static void efx_register_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

	efx_for_each_channel(channel, efx) {
		struct efx_irq_affinity_notify *notifier =
			kmalloc(sizeof(*notifier), GFP_KERNEL);

		notifier->notifier.notify = efx_irq_notify;
		notifier->notifier.release = efx_irq_release;
		notifier->efx = efx;
		notifier->channel = channel->channel;
		rc = irq_set_affinity_notifier(channel->irq,
					       &notifier->notifier);
		if (rc) {
			netif_warn(channel->efx, probe, efx->net_dev,
				   "Failed to set irq notifier for IRQ %d",
				   channel->irq);
			kfree(notifier);
		}
	}
}

static void efx_unregister_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		irq_set_affinity_notifier(channel->irq, NULL);
}
#endif

static int efx_soft_enable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel, *end_channel;
	int rc;

	if (efx->state == STATE_DISABLED)
		return -ENETDOWN;

	efx->irq_soft_enabled = true;
	smp_wmb();

	efx_for_each_channel(channel, efx) {
		if (!channel->type->keep_eventq) {
			rc = efx_init_eventq(channel);
			if (rc)
				goto fail;
		}
		efx_start_eventq(channel);
	}

	efx_mcdi_mode_event(efx);

	return 0;
fail:
	end_channel = channel;
	efx_for_each_channel(channel, efx) {
		if (channel == end_channel)
			break;
		efx_stop_eventq(channel);
		if (!channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	return rc;
}

static void efx_soft_disable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state == STATE_DISABLED)
		return;

	efx_mcdi_mode_poll(efx);

	efx->irq_soft_enabled = false;
	smp_wmb();

	if (efx->legacy_irq)
		synchronize_irq(efx->legacy_irq);

	efx_for_each_channel(channel, efx) {
		if (channel->irq)
			synchronize_irq(channel->irq);

		efx_stop_eventq(channel);
		if (!channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	/* Flush the asynchronous MCDI request queue */
	efx_mcdi_flush_async(efx);
}

static int efx_enable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel, *end_channel;
	int rc;

	if (efx->state == STATE_DISABLED)
		return -ENETDOWN;

	if (efx->eeh_disabled_legacy_irq) {
		enable_irq(efx->legacy_irq);
		efx->eeh_disabled_legacy_irq = false;
	}

	efx->type->irq_enable_master(efx);

	efx_for_each_channel(channel, efx) {
		if (channel->type->keep_eventq) {
			rc = efx_init_eventq(channel);
			if (rc)
				goto fail;
		}
	}

	rc = efx_soft_enable_interrupts(efx);
	if (rc)
		goto fail;

	return 0;

fail:
	end_channel = channel;
	efx_for_each_channel(channel, efx) {
		if (channel == end_channel)
			break;
		if (channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	efx->type->irq_disable_non_ev(efx);

	return rc;
}

static void efx_disable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_soft_disable_interrupts(efx);

	efx_for_each_channel(channel, efx) {
		if (channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	efx->type->irq_disable_non_ev(efx);
}

static void efx_remove_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	/* Remove MSI/MSI-X interrupts */
	efx_for_each_channel(channel, efx)
		channel->irq = 0;
	pci_disable_msi(efx->pci_dev);
	pci_disable_msix(efx->pci_dev);

	/* Remove legacy interrupt */
	efx->legacy_irq = 0;
}

static void efx_set_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	int j;

	/* We need to mark which channels really have RX and TX
	 * queues, and adjust the TX queue numbers if we have separate
	 * RX-only and TX-only channels.
	 */
	efx_for_each_channel(channel, efx) {
		if (channel->channel < efx->n_rx_channels)
			channel->rx_queue.core_index = channel->channel;
		else
			channel->rx_queue.core_index = -1;

		if (efx_channel_has_tx_queues(channel))
			for (j = 0; j < efx->tx_queues_per_channel; ++j) {
				tx_queue = &channel->tx_queue[j];
				tx_queue->csum_offload = j;
				tx_queue->queue =
					efx->tx_queues_per_channel *
					 (channel->channel -
					  efx->tx_channel_offset) +
					j;
				/* When using an even number of queues, for
				 * even numbered channels alternate the queues.
				 * This stripes events across the NIC resources
				 * more effectively.
				 */
				if (efx->tx_queues_per_channel % 2 == 0)
					tx_queue->queue ^= channel->channel & 1;
			}
	}
}

static int efx_probe_nic(struct efx_nic *efx)
{
	int rc;
	unsigned int n_tx_channels;

	netif_dbg(efx, probe, efx->net_dev, "creating NIC\n");

	/* Register debugfs entries */
	rc = efx_init_debugfs_nic(efx);
	if (rc)
		return rc;

#ifdef CONFIG_SFC_DUMP
	rc = efx_dump_init(efx);
	if (rc)
		goto fail_dump;
#endif

	/* Initialise NIC resource information */
	efx->farch_resources = efx->type->farch_resources;
	efx->farch_resources.biu_lock = &efx->biu_lock;
	efx->ef10_resources = efx->type->ef10_resources;

	/* Carry out hardware-type specific initialisation */
	rc = efx->type->probe(efx);
	if (rc)
		goto fail2;
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	do {
		if (!efx->max_channels || !efx->max_tx_channels) {
			netif_err(efx, drv, efx->net_dev,
				  "Insufficient resources to allocate "
				  "any channels\n");
			rc = -ENOSPC;
			goto fail2;
		}

		/* Determine the number of channels and queues by trying to hook
		 * in MSI-X interrupts. */
		rc = efx_probe_interrupts(efx);
		if (rc)
			goto fail3;

		efx_set_channels(efx);

		/* dimension_resources can fail with EAGAIN */
		rc = efx->type->dimension_resources(efx);
		if (rc != 0 && rc != -EAGAIN)
			goto fail4;

		if (rc == -EAGAIN)
			/* try again with new max_channels */
			efx_remove_interrupts(efx);

	} while (rc == -EAGAIN);

#ifdef EFX_NOT_UPSTREAM
	if ((efx->n_channels > 1) && efx_rss_use_fixed_key) {
		BUILD_BUG_ON(sizeof(efx_rss_fixed_key) <
				sizeof(efx->rx_hash_key));
		memcpy(&efx->rx_hash_key, efx_rss_fixed_key,
				sizeof(efx->rx_hash_key));
	} else
#endif
	if (efx->n_channels > 1)
		netdev_rss_key_fill(&efx->rx_hash_key,
				sizeof(efx->rx_hash_key));
	efx_set_default_rx_indir_table(efx);

	n_tx_channels = efx->n_tx_channels;
	/* Hide the PTP TX queue from the network stack, so it is not
	 * used for normal packets.
	 */
	if (efx->extra_channel_type[EFX_EXTRA_CHANNEL_PTP] &&
	    efx_ptp_use_mac_tx_timestamps(efx))
		n_tx_channels--;
	netif_set_real_num_tx_queues(efx->net_dev, n_tx_channels);
	netif_set_real_num_rx_queues(efx->net_dev, efx->n_rx_channels);

	/* Initialise the interrupt moderation settings */
	efx->irq_mod_step_us = DIV_ROUND_UP(efx->timer_quantum_ns, 1000);
	efx_init_irq_moderation(efx, tx_irq_mod_usec, rx_irq_mod_usec,
				irq_adapt_enable, true);

	return 0;

fail4:
	efx_remove_interrupts(efx);
fail3:
	efx->type->remove(efx);
fail2:
#ifdef CONFIG_SFC_DUMP
	efx_dump_fini(efx);
fail_dump:
#endif
	efx->dl_info = NULL;
	efx_fini_debugfs_nic(efx);
	return rc;
}

static void efx_remove_nic(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "destroying NIC\n");

	efx_remove_interrupts(efx);
	efx->type->remove(efx);
#ifdef CONFIG_SFC_DUMP
	efx_dump_fini(efx);
#endif
	efx->dl_info = NULL;

	efx_fini_debugfs_nic(efx);
}

static int efx_probe_filters(struct efx_nic *efx)
{
	int rc;

	spin_lock_init(&efx->filter_lock);
	init_rwsem(&efx->filter_sem);
	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);
	rc = efx->type->filter_table_probe(efx);
	if (rc)
		goto out_unlock;

#ifdef CONFIG_RFS_ACCEL
	if (efx->net_dev->features & NETIF_F_NTUPLE) {
		struct efx_channel *channel;
		int i, success = 1;

		efx_for_each_channel(channel, efx) {
			channel->rps_flow_id =
				kcalloc(efx->type->max_rx_ip_filters,
					sizeof(*channel->rps_flow_id),
					GFP_KERNEL);
			if (!channel->rps_flow_id)
				success = 0;
			else
				for (i = 0;
				     i < efx->type->max_rx_ip_filters;
				     ++i)
					channel->rps_flow_id[i] =
						RPS_FLOW_ID_INVALID;
		}

		if (!success) {
			efx_for_each_channel(channel, efx)
				kfree(channel->rps_flow_id);
			efx->type->filter_table_remove(efx);
			rc = -ENOMEM;
			goto out_unlock;
		}

		efx->rps_expire_index = efx->rps_expire_channel = 0;
	}
#endif
out_unlock:
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
	return rc;
}

static void efx_remove_filters(struct efx_nic *efx)
{
#ifdef CONFIG_RFS_ACCEL
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		kfree(channel->rps_flow_id);
#endif
	down_write(&efx->filter_sem);
	efx->type->filter_table_remove(efx);
	up_write(&efx->filter_sem);
}

static void efx_restore_filters(struct efx_nic *efx)
{
	down_read(&efx->filter_sem);
	efx->type->filter_table_restore(efx);
	up_read(&efx->filter_sem);
}

/**************************************************************************
 *
 * NIC startup/shutdown
 *
 *************************************************************************/

static int efx_probe_all(struct efx_nic *efx)
{
	int rc;

#ifdef EFX_NOT_UPSTREAM
	if (performance_profile == NULL)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_AUTO;
	else if (strcmp(performance_profile, "throughput") == 0)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_THROUGHPUT;
	else if (strcmp(performance_profile, "latency") == 0)
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_LATENCY;
	else
		efx->performance_profile = EFX_PERFORMANCE_PROFILE_AUTO;
#endif

	rc = efx_probe_nic(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to create NIC\n");
		goto fail1;
	}
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	rc = efx_probe_port(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to create port\n");
		goto fail2;
	}

	efx->rxq_entries = rx_ring;
	efx->txq_entries = max(tx_ring, EFX_TXQ_MIN_ENT(efx));

	if (efx->rxq_entries < EFX_RXQ_MIN_ENT ||
	    efx->rxq_entries > EFX_MAX_DMAQ_SIZE) {
		netif_err(efx, drv, efx->net_dev,
			  "rx_ring parameter must be between %u and %lu",
			  EFX_RXQ_MIN_ENT, EFX_MAX_DMAQ_SIZE);
		rc = -EINVAL;
		goto fail3;
	}
	if (efx->txq_entries > EFX_TXQ_MAX_ENT(efx)) {
		netif_err(efx, drv, efx->net_dev,
			  "tx_ring parameter must be no greater than %lu",
			  EFX_TXQ_MAX_ENT(efx));
		rc = -EINVAL;
		goto fail3;
	}
	if (efx->txq_entries != tx_ring)
		netif_warn(efx, drv, efx->net_dev,
			   "increasing TX queue size to minimum of %u\n",
			   efx->txq_entries);

	rc = efx->type->vswitching_probe(efx);
	if (rc) /* not fatal; the PF will still work fine */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to setup vswitching rc=%d, VFs may not function\n",
			   rc);

	rc = efx_probe_filters(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to create filter tables\n");
		goto fail4;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	rc = efx_sarfs_init(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to initialise alt arfs table\n");
		goto fail5;
	}
#endif

	rc = efx_probe_channels(efx);
	if (rc)
		goto fail6;

	return 0;

 fail6:
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	efx_sarfs_fini(efx);
 fail5:
#endif
	efx_remove_filters(efx);
 fail4:
	efx->type->vswitching_remove(efx);
 fail3:
	efx_remove_port(efx);
 fail2:
	efx_remove_nic(efx);
 fail1:
	return rc;
}

/* If the interface is supposed to be running but is not, start
 * the hardware and software data path, regular activity for the port
 * (MAC statistics, link polling, etc.) and schedule the port to be
 * reconfigured.  Interrupts must already be enabled.  This function
 * is safe to call multiple times, so long as the NIC is not disabled.
 * Requires the RTNL lock.
 */
static void efx_start_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	/* Check that it is appropriate to restart the interface. All
	 * of these flags are safe to read under just the rtnl lock */
	if ((efx->state == STATE_DISABLED) || efx->port_enabled ||
			!netif_running(efx->net_dev) || efx->reset_pending)
		return;

	efx_start_port(efx);
	efx_start_datapath(efx);

	/* Start the hardware monitor if there is one */
	if (efx->type->monitor != NULL)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
		schedule_delayed_work(&efx->monitor_work,
				msecs_to_jiffies(monitor_interval_ms));
#else
		queue_delayed_work(efx_workqueue, &efx->monitor_work,
				msecs_to_jiffies(monitor_interval_ms));
#endif

	/* If link state detection is normally event-driven, we have
	 * to poll now because we could have missed a change
	 */
	if (efx_nic_rev(efx) >= EFX_REV_SIENA_A0) {
		mutex_lock(&efx->mac_lock);
		if (efx->phy_op->poll(efx))
			efx_link_status_changed(efx);
		mutex_unlock(&efx->mac_lock);
	}

	efx->type->start_stats(efx);
	efx->type->pull_stats(efx);
	efx->type->update_stats(efx, NULL, NULL);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);
}

/* Quiesce the hardware and software data path, and regular activity
 * for the port without bringing the link down.  Safe to call multiple
 * times with the NIC in almost any state, but interrupts should be
 * enabled.  Requires the RTNL lock.
 */
static void efx_stop_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	/* port_enabled can be read safely under the rtnl lock */
	if (!efx->port_enabled)
		return;

	/* update stats before we go down so we can accurately count
	 * rx_nodesc_drops
	 */
	efx->type->update_stats(efx, NULL, NULL);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);
	efx->type->stop_stats(efx);
	efx_stop_port(efx);

	/* Stop the kernel transmit interface.  This is only valid if
	 * the device is stopped or detached; otherwise the watchdog
	 * may fire immediately.
	 */
	WARN_ON(netif_running(efx->net_dev) &&
		netif_device_present(efx->net_dev));
	netif_tx_disable(efx->net_dev);

	efx_stop_datapath(efx);
}

static void efx_remove_all(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)) {
		efx_remove_nic(efx);
		return;
	}
#endif

	efx_remove_channels(efx);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	efx_sarfs_fini(efx);
#endif
	efx_remove_filters(efx);
	efx->type->vswitching_remove(efx);
	efx_remove_port(efx);
	efx_remove_nic(efx);
}

/**************************************************************************
 *
 * Interrupt moderation
 *
 **************************************************************************/
unsigned int efx_usecs_to_ticks(struct efx_nic *efx, unsigned int usecs)
{
	if (usecs == 0)
		return 0;
	if (usecs * 1000 < efx->timer_quantum_ns)
		return 1; /* never round down to 0 */
	return usecs * 1000 / efx->timer_quantum_ns;
}

unsigned int efx_ticks_to_usecs(struct efx_nic *efx, unsigned int ticks)
{
	/* We must round up when converting ticks to microseconds
	 * because we round down when converting the other way.
	 */
	return DIV_ROUND_UP(ticks * efx->timer_quantum_ns, 1000);
}

/* Set interrupt moderation parameters */
int efx_init_irq_moderation(struct efx_nic *efx, unsigned int tx_usecs,
			    unsigned int rx_usecs, bool rx_adaptive,
			    bool rx_may_override_tx)
{
	struct efx_channel *channel;
	unsigned int timer_max_us;

	EFX_ASSERT_RESET_SERIALISED(efx);

	timer_max_us = efx->timer_max_ns / 1000;

	if (tx_usecs > timer_max_us || rx_usecs > timer_max_us)
		return -EINVAL;

	if (tx_usecs != rx_usecs && efx->tx_channel_offset == 0 &&
	    !rx_may_override_tx) {
		netif_err(efx, drv, efx->net_dev, "Channels are shared. "
			  "RX and TX IRQ moderation must be equal\n");
		return -EINVAL;
	}

	efx->irq_rx_adaptive = rx_adaptive;
	efx->irq_rx_moderation_us = rx_usecs;
	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel))
			channel->irq_moderation_us = rx_usecs;
		else if (efx_channel_has_tx_queues(channel))
			channel->irq_moderation_us = tx_usecs;
	}

	return 0;
}

void efx_get_irq_moderation(struct efx_nic *efx, unsigned int *tx_usecs,
			    unsigned int *rx_usecs, bool *rx_adaptive)
{
	*rx_adaptive = efx->irq_rx_adaptive;
	*rx_usecs = efx->irq_rx_moderation_us;

	/* If channels are shared between RX and TX, so is IRQ
	 * moderation.  Otherwise, IRQ moderation is the same for all
	 * TX channels and is not adaptive.
	 */
	if (efx->tx_channel_offset == 0) {
		*tx_usecs = *rx_usecs;
	} else {
		struct efx_channel *tx_channel;

		tx_channel = efx->channel[efx->tx_channel_offset];
		*tx_usecs = tx_channel->irq_moderation_us;
	}
}

/**************************************************************************
 *
 * Hardware monitor
 *
 **************************************************************************/

/* Run periodically off the general workqueue */
static void efx_monitor(struct work_struct *data)
{
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_WORK_API_WRAPPERS)
	struct efx_nic *efx = container_of(data, struct efx_nic,
					   monitor_work.work);
#else
	struct efx_nic *efx = container_of(data, struct efx_nic,
					   monitor_work);
#endif

	netif_vdbg(efx, timer, efx->net_dev,
		   "hardware monitor executing on CPU %d\n",
		   raw_smp_processor_id());
	BUG_ON(efx->type->monitor == NULL);

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	/* Without cancel_delayed_work_sync(), we have to make sure that
	 * we don't rearm when !port_enabled */
	mutex_lock(&efx->mac_lock);
	if (!efx->port_enabled) {
		mutex_unlock(&efx->mac_lock);
		return;
	} else {
#else
	/* If the mac_lock is already held then it is likely a port
	 * reconfiguration is already in place, which will likely do
	 * most of the work of monitor() anyway. */
	if (mutex_trylock(&efx->mac_lock)) {
#endif
		if (efx->port_enabled && efx->type->monitor) {
			efx->type->monitor(efx);
		}
		mutex_unlock(&efx->mac_lock);
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	schedule_delayed_work(&efx->monitor_work,
			msecs_to_jiffies(monitor_interval_ms));
#else
	queue_delayed_work(efx_workqueue, &efx->monitor_work,
			msecs_to_jiffies(monitor_interval_ms));
#endif
}

/**************************************************************************
 *
 * ioctls
 *
 *************************************************************************/

/* Net device ioctl
 * Context: process, rtnl_lock() held.
 */
int efx_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct mii_ioctl_data *data = if_mii(ifr);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_BONDING_HACKS)
	if (in_interrupt())
		/* We can't execute mdio requests from an atomic context
		 * on Siena. Luckily, the bonding driver falls back to
		 * the ethtool API if this command fails. */
		return -ENOSYS;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_TSTAMP)
	if (cmd == SIOCSHWTSTAMP)
		return efx_ptp_set_ts_config(efx, ifr);
	if (cmd == SIOCGHWTSTAMP)
		return efx_ptp_get_ts_config(efx, ifr);
#endif

#if defined(EFX_NOT_UPSTREAM)
	if (cmd == SIOCEFX) {
		struct efx_sock_ioctl __user *user_data =
			(struct efx_sock_ioctl __user *)ifr->ifr_data;
		u16 efx_cmd;

		if (copy_from_user(&efx_cmd, &user_data->cmd, sizeof(efx_cmd)))
			return -EFAULT;
		return efx_private_ioctl(efx, efx_cmd, &user_data->u);
	}
#endif

	/* Convert phy_id from older PRTAD/DEVAD format */
	if ((cmd == SIOCGMIIREG || cmd == SIOCSMIIREG) &&
	    (data->phy_id & 0xfc00) == 0x0400)
		data->phy_id ^= MDIO_PHY_ID_C45 | 0x0400;

	return mdio_mii_ioctl(&efx->mdio, data, cmd);
}

/**************************************************************************
 *
 * NAPI interface
 *
 **************************************************************************/

static int efx_init_napi_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_OLD_NAPI)
	channel->napi_dev = efx->net_dev;
#else
	channel->napi_dev = alloc_etherdev(0);
	if (!channel->napi_dev) {
		efx_fini_napi(efx);
		return -ENOMEM;
	}
	channel->napi_dev->priv = channel;
	atomic_set(&channel->napi_dev->refcnt, 1);
#if defined(EFX_USE_GRO)
	channel->napi_str.dev = efx->net_dev;
#endif
#endif
	netif_napi_add(channel->napi_dev, &channel->napi_str,
		       efx_poll, napi_weight);
	napi_hash_add(&channel->napi_str);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	{
		int rc = efx_ssr_init(channel, efx);
		if (rc) {
			efx_fini_napi(efx);
			return rc;
		}
	}
#endif
	efx_channel_busy_poll_init(channel);

	return 0;
}

static int efx_init_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

	efx_for_each_channel(channel, efx) {
		rc = efx_init_napi_channel(channel);
		if (rc)
			return rc;
	}

	return 0;
}

static void efx_fini_napi_channel(struct efx_channel *channel)
{
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	efx_ssr_fini(channel);
#endif
	if (channel->napi_dev) {
		netif_napi_del(&channel->napi_str);
		napi_hash_del(&channel->napi_str);
	}
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_NAPI)
	if (channel->napi_dev) {
		channel->napi_dev->priv = NULL;
		free_netdev(channel->napi_dev);
	}
#endif
	channel->napi_dev = NULL;
}

static void efx_fini_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_fini_napi_channel(channel);
}

#ifdef EFX_NOT_UPSTREAM
static void efx_schedule_all_channels(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic,
			schedule_all_channels_work);
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx) {
		local_bh_disable();
		efx_schedule_channel(channel);
		local_bh_enable();
	}
}

void efx_pause_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state != STATE_READY)
		return;

	ASSERT_RTNL();
	netif_dbg(efx, drv, efx->net_dev, "Pausing NAPI\n");

	efx_for_each_channel(channel, efx) {
		napi_disable(&channel->napi_str);
		while (!efx_channel_lock_napi(channel))
			msleep(1);

	}
}

int efx_resume_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state != STATE_READY)
		return 0;

	ASSERT_RTNL();
	netif_dbg(efx, drv, efx->net_dev, "Resuming NAPI\n");

	efx_for_each_channel(channel, efx) {
		efx_channel_unlock_napi(channel);
		napi_enable(&channel->napi_str);
	}

	/* Schedule all channels in case we've
	 * missed something whilst paused. */
	schedule_work(&efx->schedule_all_channels_work);

	return 0;
}
#endif

/**************************************************************************
 *
 * Kernel netpoll interface
 *
 *************************************************************************/

#ifdef CONFIG_NET_POLL_CONTROLLER

/* Although in the common case interrupts will be disabled, this is not
 * guaranteed. However, all our work happens inside the NAPI callback,
 * so no locking is required.
 */
void efx_netpoll(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_schedule_channel(channel);
}

#endif

#ifdef CONFIG_NET_RX_BUSY_POLL
int efx_busy_poll(struct napi_struct *napi)
{
	struct efx_channel *channel =
		container_of(napi, struct efx_channel, napi_str);
	struct efx_nic *efx = channel->efx;
	int budget = 4;
	int old_rx_packets, rx_packets;

	if (!netif_running(efx->net_dev))
		return LL_FLUSH_FAILED;

	if (!efx_channel_try_lock_poll(channel))
		return LL_FLUSH_BUSY;

	old_rx_packets = channel->rx_queue.rx_packets;
	efx_process_channel(channel, budget);

	rx_packets = channel->rx_queue.rx_packets - old_rx_packets;

	/* There is no race condition with NAPI here.
	 * NAPI will automatically be rescheduled if it yielded during busy
	 * polling, because it was not able to take the lock and thus returned
	 * the full budget.
	 */
	efx_channel_unlock_poll(channel);

	return rx_packets;
}
#endif

/**************************************************************************
 *
 * Kernel net device interface
 *
 *************************************************************************/

/* Context: process, rtnl_lock() held. */
int efx_net_open(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	int rc;

	netif_dbg(efx, ifup, efx->net_dev, "opening device on CPU %d\n",
		  raw_smp_processor_id());

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;
	if (efx->phy_mode & PHY_MODE_SPECIAL)
		return -EBUSY;
	if (efx_mcdi_poll_reboot(efx) && efx_reset(efx, RESET_TYPE_ALL))
		return -EIO;

	/* Notify the kernel of the link state polled during driver load,
	 * before the monitor starts running */
	efx_link_status_changed(efx);

	efx_start_all(efx);
	if (efx->state == STATE_DISABLED || efx->reset_pending)
		netif_device_detach(efx->net_dev);
	efx_selftest_async_start(efx);
	return 0;
}

/* Context: process, rtnl_lock() held.
 * Note that the kernel will ignore our return code; this method
 * should really be a void.
 */
int efx_net_stop(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	netif_dbg(efx, ifdown, efx->net_dev, "closing on CPU %d\n",
		  raw_smp_processor_id());

	/* Stop the device and flush all the channels */
	efx_stop_all(efx);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_DEV_CLOSE_HACK)
	/* bug23395: Prior to 2.6.25, netif_running() can be true after
	 * dev_deactivate() has disabled watchdog_timer. If the link comes up
	 * during unregister_netdev() then efx_link_status_changed() will call
	 * netif_carrier_on() which will restart the watchdog timer, and
	 * dev_shutdown() will BUG_TRAP(timer_pending()). */
	if (del_timer(&net_dev->watchdog_timer))
		dev_put(net_dev);
#endif
	return 0;
}

/* Context: process, dev_base_lock or RTNL held, non-blocking. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
struct rtnl_link_stats64 *efx_net_stats(struct net_device *net_dev,
					struct rtnl_link_stats64 *stats)
#else
struct net_device_stats *efx_net_stats(struct net_device *net_dev)
#endif
{
	struct efx_nic *efx = netdev_priv(net_dev);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_NETDEV_STATS64)
#if defined(EFX_USE_NETDEV_STATS)
	struct net_device_stats *stats = &net_dev->stats;
#else
	struct net_device_stats *stats = &efx->stats;
#endif
#endif

	efx->type->update_stats(efx, NULL, stats);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);

	return stats;
}

/* Context: netif_tx_lock held, BHs disabled. */
void efx_watchdog(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;

	netif_info(efx, tx_err, efx->net_dev,
		   "TX queue timeout: printing stopped queue data\n");

	efx_for_each_channel(channel, efx) {
		struct efx_tx_queue *tx_queue;

		if (!efx_channel_has_tx_queues(channel))
			continue;

		tx_queue = &channel->tx_queue[0];

		/* The netdev watchdog must have triggered on a queue that had
		 * stopped transmitting, so ignore other queues.
		 */
		if (!netif_xmit_stopped(tx_queue->core_txq))
			continue;

		netif_info(efx, tx_err, efx->net_dev,
			   "Channel %u: NAPI state 0x%lx\n", channel->channel,
			   channel->napi_str.state);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			netif_info(efx, tx_err, efx->net_dev,
				   "Tx queue: insert %u, write %u, read %u\n",
				   tx_queue->insert_count,
				   tx_queue->write_count, tx_queue->read_count);
	}

	netif_err(efx, tx_err, efx->net_dev,
		  "TX stuck with port_enabled=%d: resetting channels\n",
		  efx->port_enabled);

	efx_schedule_reset(efx, RESET_TYPE_TX_WATCHDOG);
}


/* Context: process, rtnl_lock() held. */
int efx_change_mtu(struct net_device *net_dev, int new_mtu)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	int rc;
	int old_mtu;

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;
	if (new_mtu > EFX_MAX_MTU)
		return -EINVAL;

	netif_dbg(efx, drv, efx->net_dev, "changing MTU to %d\n", new_mtu);

	efx_device_detach_sync(efx);
	efx_stop_all(efx);

	mutex_lock(&efx->mac_lock);
	old_mtu = net_dev->mtu;
	net_dev->mtu = new_mtu;
	rc = efx_mac_reconfigure(efx, true);
	if (rc)
		net_dev->mtu = old_mtu;
	mutex_unlock(&efx->mac_lock);

	efx_start_all(efx);
	efx_device_attach_if_not_resetting(efx);
	return rc;
}

int efx_set_mac_address(struct net_device *net_dev, void *data)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct sockaddr *addr = data;
	u8 *new_addr = addr->sa_data;
	u8 old_addr[6];
	int rc;

	if (!is_valid_ether_addr(new_addr)) {
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_PRINT_MAC)
		netif_err(efx, drv, efx->net_dev,
			  "invalid ethernet MAC address requested: %pM\n",
			  new_addr);
#else
		DECLARE_MAC_BUF(mac);
		netif_err(efx, drv, efx->net_dev,
			  "invalid ethernet MAC address requested: %s\n",
			  print_mac(mac, new_addr));
#endif
		return -EADDRNOTAVAIL;
	}

	ether_addr_copy(old_addr, net_dev->dev_addr); /* save old address */
	ether_addr_copy(net_dev->dev_addr, new_addr);

	if (efx->type->set_mac_address) {
		rc = efx->type->set_mac_address(efx);
		if (rc) {
			ether_addr_copy(net_dev->dev_addr, old_addr);
			return rc;
		}
	}

	/* Reconfigure the MAC */
	mutex_lock(&efx->mac_lock);
	(void)efx_mac_reconfigure(efx, false);
	mutex_unlock(&efx->mac_lock);

	return 0;
}

/* Context: netif_addr_lock held, BHs disabled. */
void efx_set_rx_mode(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->port_enabled)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
		schedule_work(&efx->mac_work);
#else
		queue_work(efx_workqueue, &efx->mac_work);
#endif
	/* Otherwise efx_start_port() will do this */
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES) || defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
/* This is called by netdev_update_features() to apply any
 * restrictions on offload features.  We must disable LRO whenever RX
 * scattering is on since our implementation (SSR) does not yet
 * support it.
 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
netdev_features_t efx_fix_features(struct net_device *net_dev, netdev_features_t data)
#else
u32 efx_fix_features(struct net_device *net_dev, u32 data)
#endif
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (!efx->lro_available)
		data &= ~NETIF_F_LRO;

	return data;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
int efx_set_features(struct net_device *net_dev, netdev_features_t data)
#else
int efx_set_features(struct net_device *net_dev, u32 data)
#endif
{
	struct efx_nic *efx = netdev_priv(net_dev);
	int rc;

	/* If disabling RX n-tuple filtering, clear existing filters */
	if (net_dev->features & ~data & NETIF_F_NTUPLE) {
		rc = efx->type->filter_clear_rx(efx, EFX_FILTER_PRI_MANUAL);
		if (rc)
			return rc;
	}

	/* If Rx VLAN filter is changed, update filters via mac_reconfigure */
	if ((net_dev->features ^ data) & NETIF_F_HW_VLAN_CTAG_FILTER) {
		/* efx_set_rx_mode() will schedule MAC work to update filters
		 * when a new features are finally set in net_dev.
		 */
		efx_set_rx_mode(net_dev);
	}

	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
/* Determine whether the NIC will be able to TSO a given encapsulated packet */
static bool efx_can_encap_tso(struct efx_nic *efx, struct sk_buff *skb)
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
	return false;
#else
	__be16 dst_port;
	u8 ipproto;

	/* Does the NIC support encap offloads?
	 * If not, we should never get here, because we shouldn't have
	 * advertised encap TSO feature flags in the first place.
	 */
	if (WARN_ON_ONCE(!efx->type->udp_tnl_has_port))
		return false;

	/* Hardware can only do TSO with at most 208 bytes of headers */
	if (skb_inner_transport_offset(skb) > EFX_TSO2_MAX_HDRLEN)
		return false;

	/* Determine encapsulation protocol in use */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipproto = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		/* If there are extension headers, this will cause us to
		 * think we can't TSO something that we maybe could have.
		 */
		ipproto = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		/* Not IP, so can't TSO it */
		return false;
	}
	switch (ipproto) {
	case IPPROTO_GRE:
		/* We support NVGRE but not IP over GRE.  Assumes that any
		 * Ethernet-over-GRE packet is NVGRE - XXX this is probably
		 * bogus.
		 */
		return skb->inner_protocol_type == ENCAP_TYPE_ETHER;
	case IPPROTO_UDP:
		/* If the port is registered for a UDP tunnel, we assume the
		 * packet is for that tunnel, and the NIC will handle it as
		 * such.  If not, the NIC won't know what to do with it.
		 */
		dst_port = udp_hdr(skb)->dest;
		return efx->type->udp_tnl_has_port(efx, dst_port);
	default:
		return false;
	}
#endif
}

static netdev_features_t efx_features_check(struct sk_buff *skb,
					    struct net_device *dev,
					    netdev_features_t features)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_ENCAPSULATION)
	struct efx_nic *efx = netdev_priv(dev);

	if (skb->encapsulation && (features & (NETIF_F_GSO_MASK)))
		if (!efx_can_encap_tso(efx, skb))
			features &= ~(NETIF_F_GSO_MASK);
#endif
	return features;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO)
static int efx_vlan_rx_add_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}

static int efx_vlan_rx_kill_vid(struct net_device *net_dev, __be16 proto, u16 vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, proto, vid);
	else
		return -EOPNOTSUPP;
}
#elif defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC)
static int efx_vlan_rx_add_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		return efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
	else
		return -EOPNOTSUPP;
}

static int efx_vlan_rx_kill_vid(struct net_device *net_dev, u16 vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		return efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q), vid);
	else
		return -EOPNOTSUPP;
}
#elif defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
static void efx_vlan_rx_add_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_add_vid)
		efx->type->vlan_rx_add_vid(efx, htons(ETH_P_8021Q), vid);
}

static void efx_vlan_rx_kill_vid(struct net_device *net_dev, unsigned short vid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->vlan_rx_kill_vid)
		efx->type->vlan_rx_kill_vid(efx, htons(ETH_P_8021Q), vid);
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
void efx_vlan_rx_register(struct net_device *dev, struct vlan_group *vlan_group)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct efx_channel *channel;

	/* Before changing efx_nic::vlan_group to null, we must flush
	 * out all VLAN-tagged skbs currently in the software RX
	 * pipeline.  Changing it to non-null might be safe, but we
	 * conservatively pause the RX path in both cases.
	 */
	efx_for_each_channel(channel, efx)
		if (efx_channel_has_rx_queue(channel))
			efx_stop_eventq(channel);

	efx->vlan_group = vlan_group;

	efx_for_each_channel(channel, efx)
		if (efx_channel_has_rx_queue(channel))
			efx_start_eventq(channel);
}

#ifdef EFX_USE_VLAN_RX_KILL_VID
static void efx_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	/* Nothing to do since we don't filter */
}
#endif

#endif /* EFX_NOT_UPSTREAM */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
void efx_vxlan_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		(void) efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_vxlan_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		(void) efx->type->udp_tnl_del_port(efx, tnl);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
void efx_geneve_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		(void) efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_geneve_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		(void) efx->type->udp_tnl_del_port(efx, tnl);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
extern const struct net_device_ops efx_netdev_ops;
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
extern const struct net_device_ops_ext efx_net_device_ops_ext;
#endif

static void efx_update_name(struct efx_nic *efx)
{
	strcpy(efx->name, efx->net_dev->name);
	efx_mtd_rename(efx);
	efx_set_channel_names(efx);
#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	if (efx->debug_symlink) {
		efx_fini_debugfs_netdev(efx->net_dev);
		efx_init_debugfs_netdev(efx->net_dev);
	}
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
bool fastcall efx_dl_netdev_is_ours(const struct net_device *net_dev)
#else
bool efx_dl_netdev_is_ours(const struct net_device *net_dev)
#endif
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	return net_dev->netdev_ops == &efx_netdev_ops;
#else
	return net_dev->open == efx_net_open;
#endif
}
EXPORT_SYMBOL(efx_dl_netdev_is_ours);

static int efx_netdev_event(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NETDEV_NOTIFIER_NETDEV_PTR)
	struct net_device *net_dev = ptr;
#else
	struct netdev_notifier_info *info = ptr;
	struct net_device *net_dev = info->dev;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	if ((net_dev->netdev_ops == &efx_netdev_ops) &&
	    event == NETDEV_CHANGENAME)
#else
	if (net_dev->open == efx_net_open && event == NETDEV_CHANGENAME)
#endif
		efx_update_name(netdev_priv(net_dev));

	return NOTIFY_DONE;
}

static struct notifier_block efx_netdev_notifier = {
	.notifier_call = efx_netdev_event,
};

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_BONDING_HACKS)
/* Prior to Linux 2.6.24, the bonding driver may call change_mtu()
 * without holding the RTNL, unlike all other callers.  We try to
 * mitigate the risk of a race with other reconfiguration using
 * rtnl_trylock(), but we cannot eliminate it completely.
 */
static int efx_locked_change_mtu(struct net_device *net_dev, int new_mtu)
{
	int must_unlock = rtnl_trylock();
	int rc = efx_change_mtu(net_dev, new_mtu);
	if (must_unlock)
		rtnl_unlock();
	return rc;
}
#define efx_change_mtu efx_locked_change_mtu
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
static ssize_t show_lro(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	return sprintf(buf, "%d\n", efx_ssr_enabled(efx));
}
static ssize_t set_lro(struct device *dev, struct device_attribute *attr,
		       const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	bool enable = count > 0 && *buf != '0';
	ssize_t rc;

	rtnl_lock();
	if (!efx->lro_available && enable) {
		rc = -EINVAL;
		goto out;
	}
#ifdef NETIF_F_LRO
	if (enable != !!(efx->net_dev->features & NETIF_F_LRO)) {
		efx->net_dev->features ^= NETIF_F_LRO;
		netdev_features_change(efx->net_dev);
	}
#else
	efx->lro_enabled = enable;
#endif
	rc = count;
out:
	rtnl_unlock();
	return rc;
}
static DEVICE_ATTR(lro, 0644, show_lro, set_lro);
#endif

static ssize_t
show_phy_type(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	return sprintf(buf, "%d\n", efx->phy_type);
}
static DEVICE_ATTR(phy_type, 0444, show_phy_type, NULL);

#ifdef CONFIG_SFC_MCDI_LOGGING
static ssize_t show_mcdi_log(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	return scnprintf(buf, PAGE_SIZE, "%d\n", mcdi->logging_enabled);
}
static ssize_t set_mcdi_log(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	bool enable = count > 0 && *buf != '0';

	mcdi->logging_enabled = enable;
	return count;
}
static DEVICE_ATTR(mcdi_logging, 0644, show_mcdi_log, set_mcdi_log);
#endif

static int efx_register_netdev(struct efx_nic *efx)
{
	struct net_device *net_dev = efx->net_dev;
	struct efx_channel *channel;
	int rc;

	net_dev->watchdog_timeo = 5 * HZ;
	net_dev->irq = efx->pci_dev->irq;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	net_dev->netdev_ops = &efx_netdev_ops;
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		net_dev->priv_flags |= IFF_UNICAST_FLT;
#endif
#else
	net_dev->open = efx_net_open;
	net_dev->stop = efx_net_stop;
	net_dev->get_stats = efx_net_stats;
	net_dev->tx_timeout = efx_watchdog;
	net_dev->hard_start_xmit = efx_hard_start_xmit;
	net_dev->do_ioctl = efx_ioctl;
	net_dev->change_mtu = efx_change_mtu;
	net_dev->set_mac_address = efx_set_mac_address;

	/* On older kernel versions, set_rx_mode is expected to
	 * support multiple unicast addresses and set_multicast_list
	 * is expected to support only one.  (And on really old
	 * versions, set_rx_mode does not exist.)
	 */
#ifdef HAVE_SET_RX_MODE
	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		net_dev->set_rx_mode = efx_set_rx_mode;
	else
#endif
		net_dev->set_multicast_list = efx_set_rx_mode;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	net_dev->vlan_rx_register = efx_vlan_rx_register;
#endif
#ifdef EFX_USE_VLAN_RX_KILL_VID
	net_dev->vlan_rx_kill_vid = efx_vlan_rx_kill_vid;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	net_dev->poll_controller = efx_netpoll;
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	netdev_extended(net_dev)->rfs_data.ndo_rx_flow_steer = efx_filter_rfs;
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(SET_ETHTOOL_OPS)
	net_dev->ethtool_ops = &efx_ethtool_ops;
#else
	SET_ETHTOOL_OPS(net_dev, &efx_ethtool_ops);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
	set_ethtool_ops_ext(net_dev, &efx_ethtool_ops_ext);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_MAX_SEGS)
	net_dev->gso_max_segs = EFX_TSO_MAX_SEGS;
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	rc = efx_netq_init(efx);
	if (rc)
		return rc;
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	netdev_extended(net_dev)->ndo_busy_poll = efx_busy_poll;
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
	set_netdev_ops_ext(net_dev, &efx_net_device_ops_ext);
#endif

	rtnl_lock();

	/* If there was a scheduled reset during probe, the NIC is
	 * probably hosed anyway.  We must do this in the same locked
	 * section as we set state = READY.
	 */
	if (efx->reset_pending) {
		netif_err(efx, probe, efx->net_dev,
			  "aborting probe due to scheduled reset\n");
		rc = -EIO;
		goto fail_locked;
	}

	rc = dev_alloc_name(net_dev, net_dev->name);
	if (rc < 0)
		goto fail_locked;
	efx_update_name(efx);

	rc = register_netdevice(net_dev);
	if (rc)
		goto fail_locked;

	efx_for_each_channel(channel, efx) {
		struct efx_tx_queue *tx_queue;
		efx_for_each_channel_tx_queue(tx_queue, channel)
			efx_init_tx_queue_core_txq(tx_queue);
	}

	/* Always start with carrier off; PHY events will detect the link */
	netif_carrier_off(net_dev);

	/* Register with driverlink layer */
	if (efx_dl_supported(efx))
		efx_dl_register_nic(efx);

	efx_associate(efx);
	efx->state = STATE_READY;

	rtnl_unlock();

	/* Create debugfs symlinks */
#ifdef CONFIG_SFC_DEBUGFS
	mutex_lock(&efx->debugfs_symlink_mutex);
	rc = efx_init_debugfs_netdev(net_dev);
	mutex_unlock(&efx->debugfs_symlink_mutex);
#endif

	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev debugfs\n");
		goto fail_registered;
	}

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_phy_type);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail_attr_phy_type;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_lro);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail_attr_lro;
	}
#endif
#ifdef CONFIG_SFC_MCDI_LOGGING
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_mcdi_logging);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail_attr_mcdi_logging;
	}
#endif

	return 0;

#ifdef CONFIG_SFC_MCDI_LOGGING
fail_attr_mcdi_logging:
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	device_remove_file(&efx->pci_dev->dev, &dev_attr_lro);
#endif
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
fail_attr_lro:
	device_remove_file(&efx->pci_dev->dev, &dev_attr_phy_type);
#elif defined(CONFIG_SFC_MCDI_LOGGING)
	device_remove_file(&efx->pci_dev->dev, &dev_attr_phy_type);
#endif
fail_attr_phy_type:
	efx_fini_debugfs_netdev(net_dev);
fail_registered:
	rtnl_lock();
	efx->state = STATE_UNINIT;
	efx_dissociate(efx);
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(efx);
	unregister_netdevice(net_dev);
fail_locked:
	rtnl_unlock();
	netif_err(efx, drv, efx->net_dev, "could not register net dev\n");
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	efx_netq_fini(efx);
#endif
	return rc;
}

static void efx_unregister_netdev(struct efx_nic *efx)
{
	BUG_ON(netdev_priv(efx->net_dev) != efx);

#if defined(EFX_NOT_UPSTREAM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	/* bug11519: This has only been seen on fc4, but the bug has never
	 * been fully understood - so this workaround is applied to a range
	 * of kernels. The issue is that if dev_close() is run too close
	 * to a driver unload, then netlink can allow userspace to leak a
	 * reference count. Sleeping here for a bit lowers the probability
	 * of seeing this failure. */
	schedule_timeout_uninterruptible(HZ * 2);

#endif
#endif
	if (efx_dev_registered(efx)) {
		strlcpy(efx->name, pci_name(efx->pci_dev), sizeof(efx->name));
#ifdef CONFIG_SFC_MCDI_LOGGING
		device_remove_file(&efx->pci_dev->dev, &dev_attr_mcdi_logging);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		device_remove_file(&efx->pci_dev->dev, &dev_attr_lro);
#endif
		device_remove_file(&efx->pci_dev->dev, &dev_attr_phy_type);
		efx_fini_debugfs_netdev(efx->net_dev);
		unregister_netdev(efx->net_dev);
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	efx_netq_fini(efx);
#endif
}

/**************************************************************************
 *
 * Device reset and suspend
 *
 **************************************************************************/

/* Tears down driverlink clients, the entire software state,
 * and most of the hardware state before reset.  */
void efx_reset_down(struct efx_nic *efx, enum reset_type method)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->prepare_flr(efx);

	efx_stop_all(efx);
	efx_disable_interrupts(efx);

	mutex_lock(&efx->mac_lock);
	if (efx->port_initialized && method != RESET_TYPE_INVISIBLE &&
			method != RESET_TYPE_DATAPATH)
		efx->phy_op->fini(efx);
	efx->type->fini(efx);
}

/* This function will always ensure that the locks acquired in
 * efx_reset_down() are released. A failure return code indicates
 * that we were unable to reinitialise the hardware, and the
 * driver should be disabled. If ok is false, then the rx and tx
 * engines are not restarted, pending a RESET_DISABLE. */
int efx_reset_up(struct efx_nic *efx, enum reset_type method, bool ok)
{
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->finish_flr(efx);

	/* Ensure that SRAM is initialised even if we're disabling the device */
	rc = efx->type->init(efx);
	if (rc) {
		netif_err(efx, drv, efx->net_dev, "failed to initialise NIC\n");
		goto fail;
	}

	if (!ok)
		goto fail;

	if (efx->port_initialized && method != RESET_TYPE_INVISIBLE &&
			method != RESET_TYPE_DATAPATH) {
		rc = efx->phy_op->init(efx);
		if (rc)
			goto fail;
		rc = efx->phy_op->reconfigure(efx);
		if (rc && rc != -EPERM)
			netif_err(efx, drv, efx->net_dev,
				  "could not restore PHY settings\n");
	}

	rc = efx_enable_interrupts(efx);
	if (rc)
		goto fail;

#ifdef CONFIG_SFC_DUMP
	rc = efx_dump_reset(efx);
	if (rc)
		goto fail;
#endif

	/* If the MC has reset then re-attach the driver to restore the
	 * firmware state. Note that altough there are some ways we can get
	 * here that aren't the result of an MC reset, it is still safe to
	 * perform the attach operation.
	 */
	rc = efx_mcdi_drv_attach(efx, true, MC_CMD_FW_DONT_CARE, NULL, NULL);
	if (rc) /* not fatal: the PF will still work */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to re-attach driver to MCPU rc=%d, PPS & NCSI may malfunction\n",
			   rc);

	rc = efx->type->vswitching_restore(efx);
	if (rc) /* not fatal; the PF will still work fine */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to restore vswitching rc=%d, VFs may not function\n",
			   rc);

	efx_restore_filters(efx);
	if (efx->type->sriov_reset)
		efx->type->sriov_reset(efx);

	mutex_unlock(&efx->mac_lock);

	efx_start_all(efx);

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);

	return 0;

fail:
	efx->port_initialized = false;

	mutex_unlock(&efx->mac_lock);

	return rc;
}

/* Reset the NIC using the specified method.  Note that the reset may
 * fail, in which case the card will be left in an unusable state.
 *
 * Caller must hold the rtnl_lock.
 */
int efx_reset(struct efx_nic *efx, enum reset_type method)
{
	int rc, rc2;
	bool disabled;

	ASSERT_RTNL();

	/* Notify driverlink clients of imminent reset then serialise
	 * against other driver operations */
	efx_dl_reset_suspend(efx);

	netif_info(efx, drv, efx->net_dev, "resetting (%s)\n",
		   RESET_TYPE(method));

	efx_device_detach_sync(efx);
	efx_reset_down(efx, method);

	rc = efx->type->reset(efx, method);
	if (rc) {
		netif_err(efx, drv, efx->net_dev, "failed to reset hardware\n");
		goto out;
	}

	/* Clear flags for the scopes we covered.  We assume the NIC and
	 * driver are now quiescent so that there is no race here.
	 */
	if (method < RESET_TYPE_MAX_METHOD)
		efx->reset_pending &= -(1 << (method + 1));
	else /* it doesn't fit into the well-ordered scope hierarchy */
		__clear_bit(method, &efx->reset_pending);

	/* Reinitialise bus-mastering, which may have been turned off before
	 * the reset was scheduled. This is still appropriate, even in the
	 * RESET_TYPE_DISABLE since this driver generally assumes the hardware
	 * can respond to requests. */
	pci_set_master(efx->pci_dev);

out:
	/* Clean up outstanding async MCDI. Sync MCDI is done elsewhere */
	efx_mcdi_flush_async(efx);

	/* Leave device stopped if necessary */
	disabled = rc ||
		method == RESET_TYPE_DISABLE ||
		method == RESET_TYPE_RECOVER_OR_DISABLE;
	rc2 = efx_reset_up(efx, method, !disabled);
	if (rc2) {
		disabled = true;
		if (!rc)
			rc = rc2;
	}

	if (disabled) {
		dev_close(efx->net_dev);
		netif_err(efx, drv, efx->net_dev, "has been disabled\n");
		efx->state = STATE_DISABLED;
	} else {
		netif_dbg(efx, drv, efx->net_dev, "reset complete\n");
		efx_device_attach_if_not_resetting(efx);
	}
	efx_dl_reset_resume(efx, !disabled);
	return rc;
}

/* Try recovery mechanisms.
 * For now only EEH is supported.
 * Returns 0 if the recovery mechanisms are unsuccessful.
 * Returns a non-zero value otherwise.
 */
int efx_try_recovery(struct efx_nic *efx)
{
#ifdef CONFIG_EEH
	/* A PCI error can occur and not be seen by EEH because nothing
	 * happens on the PCI bus. In this case the driver may fail and
	 * schedule a 'recover or reset', leading to this recovery handler.
	 * Manually call the eeh failure check function.
	 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_EEH_DEV_CHECK_FAILURE)
	struct eeh_dev *eehdev =
		of_node_to_eeh_dev(pci_device_to_OF_node(efx->pci_dev));

	if (eeh_dev_check_failure(eehdev)) {
#else
	struct pci_dev *pcidev = efx->pci_dev;
	struct device_node *dn = pci_device_to_OF_node(pcidev);

	if (eeh_dn_check_failure(dn, pcidev)) {
#endif
		/* The EEH mechanisms will handle the error and reset the
		 * device if necessary.
		 */
		return 1;
	}
#endif
	return 0;
}

static void efx_wait_for_bist_end(struct efx_nic *efx)
{
	int i;

	for (i = 0; i < BIST_WAIT_DELAY_COUNT; ++i) {
		if (efx_mcdi_poll_reboot(efx))
			goto out;
		msleep(BIST_WAIT_DELAY_MS);
	}

	netif_err(efx, drv, efx->net_dev, "Warning: No MC reboot after BIST mode\n");
out:
	/* Either way unset the BIST flag. If we found no reboot we probably
	 * won't recover, but we should try.
	 */
	efx->mc_bist_for_other_fn = false;
}

/* The worker thread exists so that code that cannot sleep can
 * schedule a reset for later.
 */
static void efx_reset_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, reset_work);
	unsigned long pending;
	enum reset_type method;

	pending = ACCESS_ONCE(efx->reset_pending);
	method = fls(pending) - 1;

	if (method == RESET_TYPE_MC_BIST)
		efx_wait_for_bist_end(efx);

	if ((method == RESET_TYPE_RECOVER_OR_DISABLE ||
	     method == RESET_TYPE_RECOVER_OR_ALL) &&
	    efx_try_recovery(efx))
		return;

	if (!pending)
		return;

	rtnl_lock();

	/* We checked the state in efx_schedule_reset() but it may
	 * have changed by now.  Now that we have the RTNL lock,
	 * it cannot change again.
	 */
	if (efx->state == STATE_READY)
		(void)efx_reset(efx, method);

	rtnl_unlock();
}

void efx_schedule_reset(struct efx_nic *efx, enum reset_type type)
{
	enum reset_type method;

	if (efx->state == STATE_RECOVERY) {
		netif_dbg(efx, drv, efx->net_dev,
			  "recovering: skip scheduling %s reset\n",
			  RESET_TYPE(type));
		return;
	}

	switch (type) {
	case RESET_TYPE_INVISIBLE:
	case RESET_TYPE_ALL:
	case RESET_TYPE_RECOVER_OR_ALL:
	case RESET_TYPE_WORLD:
	case RESET_TYPE_DISABLE:
	case RESET_TYPE_RECOVER_OR_DISABLE:
	case RESET_TYPE_DATAPATH:
	case RESET_TYPE_MC_BIST:
	case RESET_TYPE_MCDI_TIMEOUT:
		method = type;
		netif_dbg(efx, drv, efx->net_dev, "scheduling %s reset\n",
			  RESET_TYPE(method));
		break;
	default:
		method = efx->type->map_reset_reason(type);
		netif_dbg(efx, drv, efx->net_dev,
			  "scheduling %s reset for %s\n",
			  RESET_TYPE(method), RESET_TYPE(type));
		break;
	}

	set_bit(method, &efx->reset_pending);

	/* If we're not READY then just leave the flags set as the cue
	 * to abort probing or reschedule the reset later.
	 */
	if (ACCESS_ONCE(efx->state) != STATE_READY)
		return;

	/* efx_process_channel() will no longer read events once a
	 * reset is scheduled. So switch back to poll'd MCDI completions. */
	efx_mcdi_mode_poll(efx);

	/* we might be resetting because things are broken, so detach so we don't get
	 * things like the TX watchdog firing while we wait to reset.
	 */
	netif_device_detach(efx->net_dev);

	queue_work(reset_workqueue, &efx->reset_work);
}

/**************************************************************************
 *
 * List of NICs we support
 *
 **************************************************************************/

/* PCI device ID table */
static DEFINE_PCI_DEVICE_TABLE(efx_pci_table) = {
#if !defined(EFX_NOT_UPSTREAM) && !defined(__VMKLNX__)
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE,
		    PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0),
	 .driver_data = (unsigned long) &falcon_a1_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE,
		    PCI_DEVICE_ID_SOLARFLARE_SFC4000B),
	 .driver_data = (unsigned long) &falcon_b0_nic_type},
#endif
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0803),	/* SFC9020 */
	 .driver_data = (unsigned long) &siena_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0813),	/* SFL9021 */
	 .driver_data = (unsigned long) &siena_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0903),  /* SFC9120 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1903),  /* SFC9120 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0923),  /* SFC9140 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1923),  /* SFC9140 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0a03),  /* SFC9220 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1a03),  /* SFC9220 VF */
	 .driver_data = (unsigned long) &efx_hunt_a0_vf_nic_type},
	{0}			/* end of list */
};

/**************************************************************************
 *
 * Dummy PHY/MAC operations
 *
 * Can be used for some unimplemented operations
 * Needed so all function pointers are valid and do not have to be tested
 * before use
 *
 **************************************************************************/
int efx_void_dummy_op_int(void)
{
	return 0;
}
void efx_void_dummy_op_void(void) {}

int efx_port_dummy_op_int(struct efx_nic *efx)
{
	return 0;
}
void efx_port_dummy_op_void(struct efx_nic *efx) {}

bool efx_port_dummy_op_poll(struct efx_nic *efx)
{
	return false;
}

static const struct efx_phy_operations efx_dummy_phy_operations = {
	.init		 = efx_port_dummy_op_int,
	.reconfigure	 = efx_port_dummy_op_int,
	.poll		 = efx_port_dummy_op_poll,
	.fini		 = efx_port_dummy_op_void,
#ifdef EFX_NOT_UPSTREAM
	.probe		 = efx_port_dummy_op_int,
	.remove		 = efx_port_dummy_op_void,
	.test_alive	 = efx_port_dummy_op_int,
#endif
};

/**************************************************************************
 *
 * Data housekeeping
 *
 **************************************************************************/

/* This zeroes out and then fills in the invariants in a struct
 * efx_nic (including all sub-structures).
 */
static int efx_init_struct(struct efx_nic *efx,
			   struct pci_dev *pci_dev, struct net_device *net_dev)
{
	int i;

	/* Initialise common structures */
	INIT_LIST_HEAD(&efx->node);
	INIT_LIST_HEAD(&efx->secondary_list);
	spin_lock_init(&efx->biu_lock);
#ifdef CONFIG_SFC_MTD
	INIT_LIST_HEAD(&efx->mtd_list);
#endif
	INIT_WORK(&efx->reset_work, efx_reset_work);
	INIT_DELAYED_WORK(&efx->monitor_work, efx_monitor);
	INIT_DELAYED_WORK(&efx->selftest_work, efx_selftest_async_work);
	efx->pci_dev = pci_dev;
	efx->msg_enable = debug;
	efx->state = STATE_UNINIT;
	strlcpy(efx->name, pci_name(pci_dev), sizeof(efx->name));

#ifdef EFX_NOT_UPSTREAM
	INIT_WORK(&efx->schedule_all_channels_work, efx_schedule_all_channels);
#endif

	efx->net_dev = net_dev;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_SET_FEATURES) && !defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
	efx->rx_checksum_enabled = true;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	efx->lro_available = true;
#ifndef NETIF_F_LRO
	efx->lro_enabled = lro;
#endif
#endif
#ifdef EFX_NOT_UPSTREAM
	efx->phy_power_follows_link = phy_power_follows_link;
#endif
	efx->rx_prefix_size = efx->type->rx_prefix_size;
	efx->rx_ip_align =
		NET_IP_ALIGN ? (efx->rx_prefix_size + NET_IP_ALIGN) % 4 : 0;
	efx->rx_packet_hash_offset =
		efx->type->rx_hash_offset - efx->type->rx_prefix_size;
	efx->rx_packet_ts_offset =
		efx->type->rx_ts_offset - efx->type->rx_prefix_size;
	spin_lock_init(&efx->stats_lock);
	mutex_init(&efx->mac_lock);
	efx->phy_op = &efx_dummy_phy_operations;
	efx->mdio.dev = net_dev;
	INIT_LIST_HEAD(&efx->dl_node);
	INIT_LIST_HEAD(&efx->dl_device_list);
#ifdef EFX_NOT_UPSTREAM
	mutex_init(&efx->dl_block_kernel_mutex);
#endif
	INIT_WORK(&efx->mac_work, efx_mac_work);
	init_waitqueue_head(&efx->flush_wq);

	for (i = 0; i < EFX_MAX_CHANNELS; i++) {
		efx->channel[i] = efx_alloc_channel(efx, i, NULL);
		if (!efx->channel[i])
			goto fail;
		efx->msi_context[i].efx = efx;
		efx->msi_context[i].index = i;
	}

	/* Higher numbered interrupt modes are less capable! */
	BUG_ON(efx->type->max_interrupt_mode > efx->type->min_interrupt_mode);
	efx->interrupt_mode = max(efx->type->max_interrupt_mode,
				  interrupt_mode);
	efx->interrupt_mode = min(efx->type->min_interrupt_mode,
				  interrupt_mode);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_DUMMY_MSIX)
	if (efx->interrupt_mode == EFX_INT_MODE_MSIX)
		efx->interrupt_mode = EFX_INT_MODE_MSI;
#endif

#ifdef CONFIG_SFC_DEBUGFS
	mutex_init(&efx->debugfs_symlink_mutex);
#endif

#ifdef EFX_USE_MCDI_PROXY_AUTH
	rwlock_init(&efx->proxy_admin_lock);
	mutex_init(&efx->proxy_admin_mutex);
	INIT_WORK(&efx->proxy_admin_stop_work, efx_proxy_auth_stop_work);
#endif

	return 0;

fail:
	efx_fini_struct(efx);
	return -ENOMEM;
}

static void efx_fini_struct(struct efx_nic *efx)
{
	int i;

	for (i = 0; i < EFX_MAX_CHANNELS; i++)
		kfree(efx->channel[i]);

	kfree(efx->vpd_sn);
}

void efx_update_sw_stats(struct efx_nic *efx, u64 *stats)
{
	u64 n_rx_nodesc_trunc = 0;
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		n_rx_nodesc_trunc += channel->n_rx_nodesc_trunc;
	stats[GENERIC_STAT_rx_nodesc_trunc] = n_rx_nodesc_trunc;
	stats[GENERIC_STAT_rx_noskb_drops] = atomic_read(&efx->n_rx_noskb_drops);
}

/**************************************************************************
 *
 * PCI interface
 *
 **************************************************************************/

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)

/*
 * VPD access through PCI 2.2+ VPD capability, roughly based on the
 * implementation present in Linux 2.6.26+.
 *
 * We could access VPD through our own NVRAM interfaces, but on Siena
 * the firmware merges VPD from two sources and it seems like a waste
 * of effort to duplicate that here.
 */

#define PCI_VPD_PCI22_SIZE (PCI_VPD_ADDR_MASK + 1)

struct pci_vpd_pci22 {
	struct mutex lock;
	u16	flag;
	bool	busy;
	u8	cap;
};

/*
 * Wait for last operation to complete.
 * This code has to spin since there is no notification.
 */
static int pci_vpd_pci22_wait(struct pci_dev *dev)
{
	struct efx_nic *efx = pci_get_drvdata(dev);
	struct pci_vpd_pci22 *vpd = efx->vpd;
	unsigned long timeout = jiffies + HZ/20 + 2;
	u16 status;
	int ret;

	if (!vpd->busy)
		return 0;

	for (;;) {
		ret = pci_read_config_word(dev, vpd->cap + PCI_VPD_ADDR,
					   &status);
		if (ret)
			return ret;

		if ((status & PCI_VPD_ADDR_F) == vpd->flag) {
			vpd->busy = false;
			return 0;
		}

		if (time_after(jiffies, timeout))
			return -ETIMEDOUT;
		if (signal_pending(current))
			return -EINTR;
		cond_resched();
	}
}

ssize_t efx_pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, void *buffer)
{
	struct efx_nic *efx = pci_get_drvdata(dev);
	struct pci_vpd_pci22 *vpd = efx->vpd;
	loff_t end;
	int ret;
	char *buf = (char *)buffer;

	if (!vpd)
		return -EINVAL;
	if (pos < 0)
		return -EINVAL;
	if (pos > PCI_VPD_PCI22_SIZE)
		return 0;
	if (count > PCI_VPD_PCI22_SIZE - pos)
		count = PCI_VPD_PCI22_SIZE - pos;
	end = pos + count;

	if (mutex_lock_interruptible(&vpd->lock))
		return -EINTR;

	ret = pci_vpd_pci22_wait(dev);
	if (ret < 0)
		goto out;

	while (pos < end) {
		u32 val;
		unsigned int i, skip;

		ret = pci_write_config_word(dev, vpd->cap + PCI_VPD_ADDR,
					    pos & ~3);
		if (ret < 0)
			break;
		vpd->busy = true;
		vpd->flag = PCI_VPD_ADDR_F;
		ret = pci_vpd_pci22_wait(dev);
		if (ret < 0)
			break;

		ret = pci_read_config_dword(dev, vpd->cap + PCI_VPD_DATA, &val);
		if (ret < 0)
			break;

		skip = pos & 3;
		for (i = 0;  i < sizeof(u32); i++) {
			if (i >= skip) {
				*buf++ = val;
				if (++pos == end)
					break;
			}
			val >>= 8;
		}
	}
out:
	mutex_unlock(&vpd->lock);
	return ret ? ret : count;
}

static ssize_t read_vpd_attr(
#ifdef EFX_HAVE_BIN_ATTRIBUTE_OP_FILE_PARAM
			     struct file *filp,
#endif
			     struct kobject *kobj,
#ifdef EFX_HAVE_BIN_ATTRIBUTE_OP_ATTR_PARAM
			     struct bin_attribute *bin_attr,
#endif
			     char *buf, loff_t pos, size_t count)
{
	struct pci_dev *dev =
		to_pci_dev(container_of(kobj, struct device, kobj));

	return pci_read_vpd(dev, pos, count, (void*)buf);
}

static struct bin_attribute efx_pci_vpd_attr = {
	.attr = {
		.name = "vpd",
		.mode = S_IRUSR,
	},
	.size = PCI_VPD_PCI22_SIZE,
	.read = read_vpd_attr,
};

static void efx_pci_vpd_probe(struct efx_nic *efx)
{
	struct pci_dev *dev = efx->pci_dev;
	struct pci_vpd_pci22 *vpd;
	u8 cap;

	cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
	if (!cap)
		return;
	vpd = kzalloc(sizeof(*vpd), GFP_ATOMIC);
	if (!vpd)
		return;

	mutex_init(&vpd->lock);
	vpd->cap = cap;
	vpd->busy = false;

	if (sysfs_create_bin_file(&dev->dev.kobj, &efx_pci_vpd_attr)) {
		kfree(vpd);
		return;
	}

	efx->vpd = vpd;
}

static void efx_pci_vpd_remove(struct efx_nic *efx)
{
	struct pci_dev *dev = efx->pci_dev;

	if (efx->vpd) {
		sysfs_remove_bin_file(&dev->dev.kobj, &efx_pci_vpd_attr);
		kfree(efx->vpd);
	}
}

#elif defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_READ_VPD)

ssize_t efx_pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, void *buffer)
{
	char *sys_dev_path, *path;
	struct file *file;
	mm_segment_t old_fs;
	ssize_t ret;

	/* The PCI core doesn't expose pci_read_vpd(), but we still
	 * need to serialise with it.  Therefore open the vpd file
	 * through sysfs.
	 */

	sys_dev_path = kobject_get_path(&dev->dev.kobj, GFP_KERNEL);
	if (!sys_dev_path)
		return -ENOMEM;
	path = kasprintf(GFP_KERNEL, "/sys/%s/vpd", sys_dev_path);
	kfree(sys_dev_path);
	if (!path)
		return -ENOMEM;
	file = filp_open(path, O_RDONLY, 0);
	kfree(path);
	if (IS_ERR(file))
		return PTR_ERR(file);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->read(file, (__force __user char *)buffer,
			       count, &pos);
	set_fs(old_fs);

	filp_close(file, NULL);
	return ret;
}

#endif /* EFX_USE_KCOMPAT && (EFX_NEED_PCI_VPD_ATTR || EFX_NEED_PCI_READ_VPD) */

/* Main body of final NIC shutdown code
 * This is called only at module unload (or hotplug removal).
 */
static void efx_pci_remove_main(struct efx_nic *efx)
{
	/* Flush reset_work. It can no longer be scheduled since we
	 * are not READY.
	 */
	BUG_ON(efx->state == STATE_READY);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&efx->reset_work);
#else
	flush_workqueue(reset_workqueue);
#endif
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		goto remove;
#endif

	efx_disable_interrupts(efx);
	efx_clear_interrupt_affinity(efx);
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_unregister_irq_notifiers(efx);
#endif
	efx_nic_fini_interrupt(efx);
	efx_fini_port(efx);
	efx->type->fini(efx);
	efx_fini_napi(efx);
#ifdef EFX_NOT_UPSTREAM
remove:
#endif
	efx_remove_all(efx);
}

/* Final NIC shutdown
 * This is called only at module unload (or hotplug removal).  A PF can call
 * this on its VFs to ensure they are unbound first.
 */
static void efx_pci_remove(struct pci_dev *pci_dev)
{
	struct efx_nic *efx;

	efx = pci_get_drvdata(pci_dev);
	if (!efx)
		return;

	/* Mark the NIC as fini, then stop the interface */
	rtnl_lock();
	efx_dissociate(efx);
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(efx);
	dev_close(efx->net_dev);
	efx_disable_interrupts(efx);

	if (!efx_nic_hw_unavailable(efx))
		efx->state = STATE_UNINIT;

	/* Allow any queued efx_resets() to complete */
	rtnl_unlock();

	if (efx->type->sriov_fini)
		efx->type->sriov_fini(efx);
	efx_unregister_netdev(efx);

	efx_mtd_remove(efx);
	efx_fini_debugfs_channels(efx);

	efx_pci_remove_main(efx);

	efx_fini_io(efx);
	netif_dbg(efx, drv, efx->net_dev, "shutdown successful\n");

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)
	efx_pci_vpd_remove(efx);
#endif
	efx_fini_struct(efx);
	pci_set_drvdata(pci_dev, NULL);
	free_netdev(efx->net_dev);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	pci_disable_pcie_error_reporting(pci_dev);
#endif
};

/* NIC VPD information
 * Called during probe to display the part number of the
 * installed NIC.  VPD is potentially very large but this should
 * always appear within the first 512 bytes.
 */
#define SFC_VPD_LEN 512
static void efx_probe_vpd_strings(struct efx_nic *efx)
{
	struct pci_dev *dev = efx->pci_dev;
	char vpd_data[SFC_VPD_LEN];
	ssize_t vpd_size;
	int ro_start, ro_size, i, j;

	/* Get the vpd data from the device */
	vpd_size = pci_read_vpd(dev, 0, sizeof(vpd_data), vpd_data);
	if (vpd_size <= 0) {
		netif_err(efx, drv, efx->net_dev, "Unable to read VPD\n");
		return;
	}

	/* Get the Read only section */
	ro_start = pci_vpd_find_tag(vpd_data, 0, vpd_size, PCI_VPD_LRDT_RO_DATA);
	if (ro_start < 0) {
		netif_err(efx, drv, efx->net_dev, "VPD Read-only not found\n");
		return;
	}

	ro_size = pci_vpd_lrdt_size(&vpd_data[ro_start]);
	j = ro_size;
	i = ro_start + PCI_VPD_LRDT_TAG_SIZE;
	if (i + j > vpd_size)
		j = vpd_size - i;

	/* Get the Part number */
	i = pci_vpd_find_info_keyword(vpd_data, i, j, "PN");
	if (i < 0) {
		netif_err(efx, drv, efx->net_dev, "Part number not found\n");
		return;
	}

	j = pci_vpd_info_field_size(&vpd_data[i]);
	i += PCI_VPD_INFO_FLD_HDR_SIZE;
	if (i + j > vpd_size) {
		netif_err(efx, drv, efx->net_dev, "Incomplete part number\n");
		return;
	}

	netif_info(efx, drv, efx->net_dev,
		   "Part Number : %.*s\n", j, &vpd_data[i]);

	/* We also want to store the serial number so this is available for potential
	 * errors at a later time */

	i = ro_start + PCI_VPD_LRDT_TAG_SIZE;
	j = ro_size;
	i = pci_vpd_find_info_keyword(vpd_data, i, j, "SN");
	if (i < 0) {
		netif_err(efx, drv, efx->net_dev, "Serial number not found\n");
		return;
	}

	j = pci_vpd_info_field_size(&vpd_data[i]);
	i += PCI_VPD_INFO_FLD_HDR_SIZE;
	if (i + j > vpd_size) {
		netif_err(efx, drv, efx->net_dev, "Incomplete serial number\n");
		return;
	}

	efx->vpd_sn = kmalloc(j + 1, GFP_KERNEL);
	if (!efx->vpd_sn)
		return;

	snprintf(efx->vpd_sn, j + 1, "%s", &vpd_data[i]);
}

/* Main body of NIC initialisation
 * This is called at module load (or hotplug insertion, theoretically).
 */
static int efx_pci_probe_main(struct efx_nic *efx)
{
	int rc;

	/* Do start-of-day initialisation */
	rc = efx_probe_all(efx);
	if (rc)
		goto fail1;

#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	rc = efx_init_napi(efx);
	if (rc)
		goto fail2;

	rc = efx->type->init(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to initialise NIC\n");
		goto fail3;
	}

	rc = efx_init_port(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to initialise port\n");
		goto fail4;
	}

	rc = efx_nic_init_interrupt(efx);
	if (rc)
		goto fail5;
	efx_set_interrupt_affinity(efx);
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_register_irq_notifiers(efx);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETIF_SET_XPS_QUEUE)
	if (auto_config_xps)
		efx_set_xps_queues(efx);
#endif
#endif
	rc = efx_enable_interrupts(efx);
	if (rc)
		goto fail6;

	return 0;

 fail6:
	efx_clear_interrupt_affinity(efx);
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_unregister_irq_notifiers(efx);
#endif
	efx_nic_fini_interrupt(efx);
 fail5:
	efx_fini_port(efx);
 fail4:
	efx->type->fini(efx);
 fail3:
	efx_fini_napi(efx);
 fail2:
	efx_remove_all(efx);
 fail1:
	return rc;
}

static int efx_pci_probe_post_io(struct efx_nic *efx)
{
	int rc = efx_pci_probe_main(efx);

	if (rc)
		return rc;

#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	rc = efx_init_debugfs_channels(efx);
	if (rc)
		goto fail1;

	if (efx->type->sriov_init) {
		rc = efx->type->sriov_init(efx);
		if (rc)
			netif_err(efx, probe, efx->net_dev,
				  "SR-IOV can't be enabled rc %d\n", rc);
	}

	rc = efx_register_netdev(efx);
	if (!rc)
		return 0;

	efx_fini_debugfs_channels(efx);
fail1:
	efx_pci_remove_main(efx);

	return rc;
}

/* NIC initialisation
 *
 * This is called at module load (or hotplug insertion,
 * theoretically).  It sets up PCI mappings, resets the NIC,
 * sets up and registers the network devices with the kernel and hooks
 * the interrupt service routine.  It does not prepare the device for
 * transmission; this is left to the first time one of the network
 * interfaces is brought up (i.e. efx_net_open).
 */
static int efx_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *entry)
{
	struct net_device *net_dev;
	struct efx_nic *efx;
	int rc;

	/* Allocate and initialise a struct net_device and struct efx_nic */
	net_dev = alloc_etherdev_mq(sizeof(*efx), EFX_MAX_CORE_TX_QUEUES);
	if (!net_dev)
		return -ENOMEM;
	efx = netdev_priv(net_dev);
	efx->type = (const struct efx_nic_type *) entry->driver_data;
	efx->fixed_features |= NETIF_F_HIGHDMA;
	net_dev->features |= (efx->type->offload_features | NETIF_F_SG |
			      NETIF_F_TSO |
			      NETIF_F_RXCSUM);
#if !defined(EFX_USE_KCOMPAT) || defined(NETIF_F_IPV6_CSUM)
	if (efx->type->offload_features & (NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM))
		net_dev->features |= NETIF_F_TSO6;
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_GRO)
	if (lro)
		net_dev->features |= NETIF_F_GRO;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if (lro) {
#if defined(NETIF_F_LRO)
 		net_dev->features |= NETIF_F_LRO;
#endif
	}
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	/* soft VLAN acceleration cannot be disabled at runtime */
	efx->fixed_features |= NETIF_F_HW_VLAN_CTAG_RX;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	if (!EFX_WORKAROUND_15592(efx))
		efx->fixed_features |= NETIF_F_HW_VLAN_CTAG_TX;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES)
	/* Mask for features that also apply to VLAN devices */
	net_dev->vlan_features |= (NETIF_F_HW_CSUM | NETIF_F_SG |
				   NETIF_F_HIGHDMA | NETIF_F_ALL_TSO |
				   NETIF_F_RXCSUM);
#else
	/* Alternative to vlan_features in RHEL 5.5+.  These all
	 * depend on NETIF_F_HW_CSUM or NETIF_F_HW_VLAN_TX because
	 * inline VLAN tags break the Ethertype check for IPv4-only
	 * checksum offload in dev_queue_xmit().
	 */
	if ((net_dev->features | efx->fixed_features) &
	    (NETIF_F_HW_CSUM | NETIF_F_HW_VLAN_TX)) {
#if defined(NETIF_F_VLAN_CSUM)
		net_dev->features |= NETIF_F_VLAN_CSUM;
#endif
#if defined(NETIF_F_VLAN_SG)
		net_dev->features |= NETIF_F_VLAN_SG;
#endif
#if defined(NETIF_F_VLAN_TSO)
		net_dev->features |= NETIF_F_VLAN_TSO;
#endif
#if defined(NETIF_F_VLAN_HIGHDMA)
		net_dev->features |= NETIF_F_VLAN_HIGHDMA;
#endif
	}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_HW_FEATURES)
	net_dev->hw_features = net_dev->features & ~efx->fixed_features;
#elif defined(EFX_HAVE_NETDEV_EXTENDED_HW_FEATURES)
	netdev_extended(net_dev)->hw_features =
		net_dev->features & ~efx->fixed_features;
#else
	efx->hw_features = net_dev->features & ~efx->fixed_features;
#endif

	/* Disable VLAN filtering by default.  It may be enforced if
	 * the feature is fixed (i.e. VLAN filters are required to
	 * receive VLAN tagged packets due to vPort restrictions).
	 */
	net_dev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
	net_dev->features |= efx->fixed_features;

	pci_set_drvdata(pci_dev, efx);
	SET_NETDEV_DEV(net_dev, &pci_dev->dev);
	rc = efx_init_struct(efx, pci_dev, net_dev);
	if (rc)
		goto fail1;

	netif_info(efx, probe, efx->net_dev,
		   "Solarflare NIC detected\n");

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)
	efx_pci_vpd_probe(efx); /* allowed to fail */
#endif

	if (!efx->type->is_vf)
		efx_probe_vpd_strings(efx);

	/* Set up basic I/O (BAR mappings etc) */
	rc = efx_init_io(efx);
	if (rc)
		goto fail2;

	rc = efx_pci_probe_post_io(efx);
	if (rc) {
		/* On failure, retry once immediately.
		 * If we aborted probe due to a scheduled reset, dismiss it.
		 */
		efx->reset_pending = 0;
		rc = efx_pci_probe_post_io(efx);
		if (rc) {
			/* On another failure, retry once more
			 * after a 50-305ms delay.
			 */
			unsigned char r;

			get_random_bytes(&r, 1);
			msleep((unsigned int)r + 50);
			efx->reset_pending = 0;
			rc = efx_pci_probe_post_io(efx);
		}
	}
	if (rc)
		goto fail3;

#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)) {
		netif_dbg(efx, probe, efx->net_dev,
			  "initialisation successful (no active port)\n");
		return 0;
	}
#endif

	netif_dbg(efx, probe, efx->net_dev, "initialisation successful\n");

	/* Try to create MTDs, but allow this to fail */
	rtnl_lock();
	rc = efx_mtd_probe(efx);
	rtnl_unlock();
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_MTD_TABLE)
	if (rc == -EBUSY)
		netif_warn(efx, probe, efx->net_dev,
			   "kernel MTD table is full; flash will not be "
			   "accessible\n");
	else
#endif
	if (rc && rc != -EPERM)
		netif_warn(efx, probe, efx->net_dev,
			   "failed to create MTDs (%d)\n", rc);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	rc = pci_enable_pcie_error_reporting(pci_dev);
#endif
	if (rc && rc != -EINVAL)
		netif_notice(efx, probe, efx->net_dev,
			"notice: PCIE error reporting unavailable (code %d).\n",
			rc);

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);

	return 0;

 fail3:
	efx_fini_io(efx);
 fail2:
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)
	efx_pci_vpd_remove(efx);
#endif
	efx_fini_struct(efx);
 fail1:
	pci_set_drvdata(pci_dev, NULL);
	WARN_ON(rc > 0);
	netif_dbg(efx, drv, efx->net_dev, "initialisation failed. rc=%d\n", rc);
	free_netdev(net_dev);
	return rc;
}

/* efx_pci_sriov_configure returns the actual number of Virtual Functions enabled
   on success*/

#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE) || defined(EFX_HAVE_PCI_DRIVER_RH)

static int efx_pci_sriov_configure(struct pci_dev *dev,
				   int num_vfs)
{
	int rc;
	struct efx_nic *efx = pci_get_drvdata(dev);

	if (efx->type->sriov_configure) {
		rc = efx->type->sriov_configure(efx, num_vfs);
		if (rc)
			return rc;
		else
			return num_vfs;
	}
	else
		return -ENOSYS;
}
#endif
#endif

static int efx_pm_freeze(struct device *dev)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	rtnl_lock();

	efx_dl_reset_suspend(efx);

	if (efx->state != STATE_DISABLED) {
		efx_device_detach_sync(efx);

		efx_stop_all(efx);
		efx_disable_interrupts(efx);

		efx->state = STATE_UNINIT;
	}

	rtnl_unlock();

	return 0;
}

static void efx_pci_shutdown(struct pci_dev *pci_dev)
{
	struct efx_nic *efx = pci_get_drvdata(pci_dev);

	if (!efx)
		return;

	efx_pm_freeze(&pci_dev->dev);
	pci_disable_device(pci_dev);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_PM)

static int efx_pm_thaw(struct device *dev)
{
	int rc;
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	rtnl_lock();

	if (efx->state != STATE_DISABLED) {
		rc = efx_enable_interrupts(efx);
		if (rc)
			goto fail;

		mutex_lock(&efx->mac_lock);
		efx->phy_op->reconfigure(efx);
		mutex_unlock(&efx->mac_lock);

		efx_start_all(efx);

		efx_device_attach_if_not_resetting(efx);

		efx->state = STATE_READY;

		efx->type->resume_wol(efx);
	}

	efx_dl_reset_resume(efx, efx->state != STATE_DISABLED);

	rtnl_unlock();

	/* Reschedule any quenched resets scheduled during efx_pm_freeze() */
	queue_work(reset_workqueue, &efx->reset_work);

	return 0;

fail:
	efx_dl_reset_resume(efx, false);

	rtnl_unlock();

	return rc;
}

static int efx_pm_poweroff(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct efx_nic *efx = pci_get_drvdata(pci_dev);

	efx->type->fini(efx);

	efx->reset_pending = 0;

	pci_save_state(pci_dev);
	return pci_set_power_state(pci_dev, PCI_D3hot);
}

/* Used for both resume and restore */
static int efx_pm_resume(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct efx_nic *efx = pci_get_drvdata(pci_dev);
	int rc;

	rc = pci_set_power_state(pci_dev, PCI_D0);
	if (rc)
		goto fail;
	pci_restore_state(pci_dev);
	rc = pci_enable_device(pci_dev);
	if (rc)
		goto fail;
	pci_set_master(efx->pci_dev);
	rc = efx->type->reset(efx, RESET_TYPE_ALL);
	if (rc)
		goto fail;
	rc = efx->type->init(efx);
	if (rc)
		goto fail;
	rc = efx_pm_thaw(dev);
	return rc;

fail:
	efx_dl_reset_resume(efx, false);
	return rc;
}

static int efx_pm_suspend(struct device *dev)
{
	int rc;

	efx_pm_freeze(dev);
	rc = efx_pm_poweroff(dev);
	if (rc)
		efx_pm_resume(dev);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEV_PM_OPS)

static const struct dev_pm_ops efx_pm_ops = {
	.suspend	= efx_pm_suspend,
	.resume		= efx_pm_resume,
	.freeze		= efx_pm_freeze,
	.thaw		= efx_pm_thaw,
	.poweroff	= efx_pm_poweroff,
	.restore	= efx_pm_resume,
};

#elif defined(EFX_USE_PM_EXT_OPS)

static struct pm_ext_ops efx_pm_ops = {
	.base = {
		.suspend	= efx_pm_suspend,
		.resume		= efx_pm_resume,
		.freeze		= efx_pm_freeze,
		.thaw		= efx_pm_thaw,
		.poweroff	= efx_pm_poweroff,
		.restore	= efx_pm_resume,
	}
};

#else /* !EFX_USE_DEV_PM_OPS && !EFX_USE_PM_EXT_OPS */

static int efx_pm_old_suspend(struct pci_dev *dev, pm_message_t state)
{
	switch (state.event) {
	case PM_EVENT_FREEZE:
#if defined(PM_EVENT_QUIESCE)
	case PM_EVENT_QUIESCE:
#elif defined(PM_EVENT_PRETHAW)
	case PM_EVENT_PRETHAW:
#endif
		return efx_pm_freeze(&dev->dev);
	default:
		return efx_pm_suspend(&dev->dev);
	}
}

static int efx_pm_old_resume(struct pci_dev *dev)
{
	return efx_pm_resume(&dev->dev);
}

#endif /* EFX_USE_PM_EXT_OPS */

#endif /* EFX_USE_PM */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
/* A PCI error affecting this device was detected.
 * At this point MMIO and DMA may be disabled.
 * Stop the software path and request a slot reset.
 */
static pci_ers_result_t efx_io_error_detected(struct pci_dev *pdev,
					      enum pci_channel_state state)
{
	pci_ers_result_t status = PCI_ERS_RESULT_RECOVERED;
	struct efx_nic *efx = pci_get_drvdata(pdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	rtnl_lock();

	if (efx->state != STATE_DISABLED) {
		efx->state = STATE_RECOVERY;
		efx->reset_pending = 0;

		efx_device_detach_sync(efx);

		efx_stop_all(efx);
		efx_disable_interrupts(efx);

		status = PCI_ERS_RESULT_NEED_RESET;
	} else {
		/* If the interface is disabled we don't want to do anything
		 * with it.
		 */
		status = PCI_ERS_RESULT_RECOVERED;
	}

	rtnl_unlock();

	pci_disable_device(pdev);

	return status;
}

/* Fake a successfull reset, which will be performed later in efx_io_resume. */
static pci_ers_result_t efx_io_slot_reset(struct pci_dev *pdev)
{
	struct efx_nic *efx = pci_get_drvdata(pdev);
	pci_ers_result_t status = PCI_ERS_RESULT_RECOVERED;
	int rc;

	if (pci_enable_device(pdev)) {
		netif_err(efx, hw, efx->net_dev,
			  "Cannot re-enable PCI device after reset.\n");
		status =  PCI_ERS_RESULT_DISCONNECT;
	}

	rc = pci_cleanup_aer_uncorrect_error_status(pdev);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
		"pci_cleanup_aer_uncorrect_error_status failed (%d)\n", rc);
		/* Non-fatal error. Continue. */
	}

	return status;
}

/* Perform the actual reset and resume I/O operations. */
static void efx_io_resume(struct pci_dev *pdev)
{
	struct efx_nic *efx = pci_get_drvdata(pdev);
	int rc;

	rtnl_lock();

	if (efx->state == STATE_DISABLED)
		goto out;

	rc = efx_reset(efx, RESET_TYPE_ALL);
	if (rc) {
		netif_err(efx, hw, efx->net_dev,
			  "efx_reset failed after PCI error (%d)\n", rc);
	} else {
		efx->state = STATE_READY;
		netif_dbg(efx, hw, efx->net_dev,
			  "Done resetting and resuming IO after PCI error.\n");
	}

out:
	rtnl_unlock();
}

/* For simplicity and reliability, we always require a slot reset and try to
 * reset the hardware when a pci error affecting the device is detected.
 * We leave both the link_reset and mmio_enabled callback unimplemented:
 * with our request for slot reset the mmio_enabled callback will never be
 * called, and the link_reset callback is not used by AER or EEH mechanisms.
 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CONST_PCI_ERR_HANDLER)
static const struct pci_error_handlers efx_err_handlers = {
#else
static struct pci_error_handlers efx_err_handlers = {
#endif
	.error_detected = efx_io_error_detected,
	.slot_reset	= efx_io_slot_reset,
	.resume		= efx_io_resume,
};
#endif	/* !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER) */

#if defined(CONFIG_SFC_SRIOV) && defined(EFX_HAVE_PCI_DRIVER_RH) && !defined(EFX_HAVE_SRIOV_CONFIGURE)
static struct pci_driver_rh efx_pci_driver_rh = {
	.sriov_configure = efx_pci_sriov_configure,
};
#endif

static struct pci_driver efx_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= efx_pci_table,
	.probe		= efx_pci_probe,
	.remove		= efx_pci_remove,
#if !defined(EFX_USE_KCOMPAT)
	.driver.pm	= &efx_pm_ops,
#elif defined(EFX_USE_DEV_PM_OPS)
	/* May need to cast away const */
	.driver.pm	= (struct dev_pm_ops *)&efx_pm_ops,
#elif defined(EFX_USE_PM_EXT_OPS)
	.pm		= &efx_pm_ops,
#elif defined(EFX_USE_PM)
	.suspend	= efx_pm_old_suspend,
	.resume		= efx_pm_old_resume,
#endif
	.shutdown	= efx_pci_shutdown,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	.err_handler	= &efx_err_handlers,
#endif
#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_CONFIGURE)
	.sriov_configure = efx_pci_sriov_configure,
#elif defined(EFX_HAVE_PCI_DRIVER_RH)
	.rh_reserved    = &efx_pci_driver_rh,
#endif
#endif
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
const struct net_device_ops efx_netdev_ops = {
	.ndo_open		= efx_net_open,
	.ndo_stop		= efx_net_stop,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64	= efx_net_stats,
#else
	.ndo_get_stats		= efx_net_stats,
#endif
	.ndo_tx_timeout		= efx_watchdog,
	.ndo_start_xmit		= efx_hard_start_xmit,
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_ENABLE_SFC_XPS)
	.ndo_select_queue       = efx_select_queue,
#endif
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= efx_ioctl,
	.ndo_change_mtu		= efx_change_mtu,
	.ndo_set_mac_address	= efx_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode	= efx_set_rx_mode, /* Lookout */
#else
	/* On older kernel versions, set_rx_mode is expected to
	 * support multiple unicast addresses and set_multicast_list
	 * is expected to support only one.  On newer versions the
	 * IFF_UNICAST_FLT flag distinguishes these.
	 */
	.ndo_set_multicast_list	= efx_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features	= efx_fix_features,
#endif
	.ndo_set_features	= efx_set_features,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
	.ndo_features_check	= efx_features_check,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
	.ndo_vlan_rx_add_vid	= efx_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= efx_vlan_rx_kill_vid,
#endif
#ifdef CONFIG_SFC_SRIOV
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
	.ndo_set_vf_mac         = efx_sriov_set_vf_mac,
	.ndo_set_vf_vlan        = efx_sriov_set_vf_vlan,
	.ndo_get_vf_config      = efx_sriov_get_vf_config,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_LINK_STATE)
	.ndo_set_vf_link_state  = efx_sriov_set_vf_link_state,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_SPOOFCHK)
	.ndo_set_vf_spoofchk	= efx_sriov_set_vf_spoofchk,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.ndo_get_phys_port_id	= efx_sriov_get_phys_port_id,
#endif
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	.ndo_vlan_rx_register	= efx_vlan_rx_register,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= efx_netpoll,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll		= efx_busy_poll,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	= efx_filter_rfs,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
	.ndo_add_vxlan_port	= efx_vxlan_add_port,
	.ndo_del_vxlan_port	= efx_vxlan_del_port,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
	.ndo_add_geneve_port	= efx_geneve_add_port,
	.ndo_del_geneve_port	= efx_geneve_del_port,
#endif
};
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
const struct net_device_ops_ext efx_net_device_ops_ext = {
#ifdef EFX_HAVE_EXT_NDO_SET_FEATURES
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features      = efx_fix_features,
#endif
	.ndo_set_features      = efx_set_features,
#endif

#ifdef CONFIG_SFC_SRIOV
#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= efx_sriov_get_phys_port_id,
#endif
#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_SPOOFCHK
	.ndo_set_vf_spoofchk	= efx_sriov_set_vf_spoofchk,
#endif
#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_LINK_STATE
	.ndo_set_vf_link_state	= efx_sriov_set_vf_link_state,
#endif
#endif /* CONFIG_SFC_SRIOV */
};
#endif
/**************************************************************************
 *
 * Kernel module interface
 *
 *************************************************************************/

#ifdef EFX_NOT_UPSTREAM

module_param(napi_weight, int, 0444);
MODULE_PARM_DESC(napi_weight, "NAPI weighting");

module_param(rx_irq_mod_usec, uint, 0444);
MODULE_PARM_DESC(rx_irq_mod_usec,
		 "Receive interrupt moderation (microseconds)");

module_param(tx_irq_mod_usec, uint, 0444);
MODULE_PARM_DESC(tx_irq_mod_usec,
		 "Transmit interrupt moderation (microseconds)");

#endif /* EFX_NOT_UPSTREAM */

module_param(interrupt_mode, uint, 0444);
MODULE_PARM_DESC(interrupt_mode,
		 "Interrupt mode (0=>MSIX 1=>MSI 2=>legacy)");

static int __init efx_init_module(void)
{
	int rc;

	printk(KERN_INFO "Solarflare NET driver v" EFX_DRIVER_VERSION "\n");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
	gcov_provider_init(THIS_MODULE);
#endif

	rc = efx_init_debugfs();
	if (rc)
		goto err_debugfs;

	rc = register_netdevice_notifier(&efx_netdev_notifier);
	if (rc) {
		printk(KERN_ERR "Failed to register netdevice notifier. rc=%d\n",
		       rc);
		goto err_notifier;
	}

	rc = efx_init_sriov();
	if (rc)
		goto err_sriov;

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	efx_workqueue = create_singlethread_workqueue("sfc_wq");
	if (!efx_workqueue) {
		printk(KERN_ERR "Failed to create workqueue\n");
		rc = -ENOMEM;
		goto err_wq;
	}
#endif

	reset_workqueue = create_singlethread_workqueue("sfc_reset");
	if (!reset_workqueue) {
		printk(KERN_ERR "Failed to create reset workqueue\n");
		rc = -ENOMEM;
		goto err_reset;
	}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)
	rss_cpu_usage = kzalloc(NR_CPUS * sizeof(rss_cpu_usage[0]), GFP_KERNEL);
	if (rss_cpu_usage == NULL) {
		rc = -ENOMEM;
		goto err_cpu_usage;
	}
#endif
#ifdef CONFIG_SFC_HWMON
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM87_DRIVER)
	rc = i2c_add_driver(&efx_lm87_driver);
	if (rc < 0) {
		printk(KERN_ERR "i2c_add_driver lm87 failed, rc=%d.\n", rc);
		goto err_lm87;
	}
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM90_DRIVER)
	rc = i2c_add_driver(&efx_lm90_driver);
	if (rc < 0) {
		printk(KERN_ERR "i2c_add_driver lm90 failed, rc=%d\n", rc);
		goto err_lm90;
	}
#endif
#endif /* CONFIG_SFC_HWMON */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_I2C_NEW_DUMMY)
	rc = i2c_add_driver(&efx_i2c_dummy_driver);
	if (rc < 0) {
		printl(KERN_ERR "i2c_add_driver failed, rc=%d\n", rc);
		goto err_i2c_dummy;
	}
#endif

#if defined(EFX_NOT_UPSTREAM)
	rc = efx_control_init();
	if (rc)
		goto err_control;
#endif

#ifdef EFX_USE_MCDI_PROXY_AUTH_NL
	efx_mcdi_proxy_nl_register();
#endif

	rc = pci_register_driver(&efx_pci_driver);
	if (rc < 0) {
		printk(KERN_ERR "pci_register_driver failed, rc=%d\n", rc);
		goto err_pci;
	}

	return 0;

 err_pci:
#ifdef EFX_USE_MCDI_PROXY_AUTH_NL
	efx_mcdi_proxy_nl_unregister();
#endif
#if defined(EFX_NOT_UPSTREAM)
	efx_control_fini();
 err_control:
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_I2C_NEW_DUMMY)
	i2c_del_driver(&efx_i2c_dummy_driver);
 err_i2c_dummy:
#endif
#ifdef CONFIG_SFC_HWMON
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM90_DRIVER)
	i2c_del_driver(&efx_lm90_driver);
 err_lm90:
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM87_DRIVER)
	i2c_del_driver(&efx_lm87_driver);
 err_lm87:
#endif
#endif /* CONFIG_SFC_HWMON */
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)
	kfree(rss_cpu_usage);
 err_cpu_usage:
#endif
	destroy_workqueue(reset_workqueue);
 err_reset:
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	destroy_workqueue(efx_workqueue);
 err_wq:
#endif
	efx_fini_sriov();
 err_sriov:
	unregister_netdevice_notifier(&efx_netdev_notifier);
 err_notifier:
	efx_fini_debugfs();
 err_debugfs:
	return rc;
}

static void __exit efx_exit_module(void)
{
	printk(KERN_INFO "Solarflare NET driver unloading\n");

	pci_unregister_driver(&efx_pci_driver);
#ifdef EFX_USE_MCDI_PROXY_AUTH_NL
	efx_mcdi_proxy_nl_unregister();
#endif
#if defined(EFX_NOT_UPSTREAM)
	efx_control_fini();
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_I2C_NEW_DUMMY)
	i2c_del_driver(&efx_i2c_dummy_driver);
#endif
#ifdef CONFIG_SFC_HWMON
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM90_DRIVER)
	i2c_del_driver(&efx_lm90_driver);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM87_DRIVER)
	i2c_del_driver(&efx_lm87_driver);
#endif
#endif /* CONFIG_SFC_HWMON */
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)
	kfree(rss_cpu_usage);
#endif
	destroy_workqueue(reset_workqueue);
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	destroy_workqueue(efx_workqueue);
#endif
	efx_fini_sriov();
	unregister_netdevice_notifier(&efx_netdev_notifier);
	efx_fini_debugfs();

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
	gcov_provider_fini(THIS_MODULE);
#endif
}

#if defined(EFX_NOT_UPSTREAM) && defined(DEBUG)
/* Used by load.sh to reliably indicate DEBUG vs RELEASE */
extern int __efx_enable_debug; /* placate sparse */
int __efx_enable_debug __attribute__((unused));
#endif

module_init(efx_init_module);
module_exit(efx_exit_module);

MODULE_AUTHOR("Solarflare Communications and "
	      "Michael Brown <mbrown@fensystems.co.uk>");
MODULE_DESCRIPTION("Solarflare network driver");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, efx_pci_table);
MODULE_VERSION(EFX_DRIVER_VERSION);
