/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
 * Copyright 2005-2011 Solarflare Communications Inc.
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
#include <linux/crc32.h>
#include <linux/ethtool.h>
#include <linux/topology.h>
#include <linux/gfp.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/cpu_rmap.h>
#endif
#ifdef EFX_NOT_UPSTREAM
#ifdef EFX_USE_LINUX_UACCESS_H
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#endif
#include "net_driver.h"
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_CPU_RMAP)
#include <linux/cpu_rmap.h>
#endif
#include "driverlink.h"
#include "debugfs.h"
#include "efx.h"
#include "nic.h"
#include "selftest.h"
#ifdef EFX_USE_KCOMPAT
#include "efx_ioctl.h"
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
#include "../linux/gcov.h"
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
#include "efx_netq.h"
#endif
#include "mcdi.h"
#include "workarounds.h"

/**************************************************************************
 *
 * Type name strings
 *
 **************************************************************************
 */

/* Loopback mode names (see LOOPBACK_MODE()) */
const unsigned int efx_loopback_mode_max = LOOPBACK_MAX;
const char *efx_loopback_mode_names[] = {
	[LOOPBACK_NONE]		= "NONE",
	[LOOPBACK_DATA]		= "DATAPATH",
	[LOOPBACK_GMAC]		= "GMAC",
	[LOOPBACK_XGMII]	= "XGMII",
	[LOOPBACK_XGXS]		= "XGXS",
	[LOOPBACK_XAUI]  	= "XAUI",
	[LOOPBACK_GMII] 	= "GMII",
	[LOOPBACK_SGMII] 	= "SGMII",
	[LOOPBACK_XGBR]		= "XGBR",
	[LOOPBACK_XFI]		= "XFI",
	[LOOPBACK_XAUI_FAR]	= "XAUI_FAR",
	[LOOPBACK_GMII_FAR]	= "GMII_FAR",
	[LOOPBACK_SGMII_FAR]	= "SGMII_FAR",
	[LOOPBACK_XFI_FAR]	= "XFI_FAR",
	[LOOPBACK_GPHY]		= "GPHY",
	[LOOPBACK_PHYXS]	= "PHYXS",
	[LOOPBACK_PCS]	 	= "PCS",
	[LOOPBACK_PMAPMD] 	= "PMA/PMD",
	[LOOPBACK_XPORT]	= "XPORT",
	[LOOPBACK_XGMII_WS]	= "XGMII_WS",
	[LOOPBACK_XAUI_WS]  	= "XAUI_WS",
	[LOOPBACK_XAUI_WS_FAR]  = "XAUI_WS_FAR",
	[LOOPBACK_XAUI_WS_NEAR] = "XAUI_WS_NEAR",
	[LOOPBACK_GMII_WS] 	= "GMII_WS",
	[LOOPBACK_XFI_WS]	= "XFI_WS",
	[LOOPBACK_XFI_WS_FAR]	= "XFI_WS_FAR",
	[LOOPBACK_PHYXS_WS]  	= "PHYXS_WS",
};

/* Interrupt mode names (see INT_MODE())) */
const unsigned int efx_interrupt_mode_max = EFX_INT_MODE_MAX;
const char *efx_interrupt_mode_names[] = {
	[EFX_INT_MODE_MSIX]   = "MSI-X",
	[EFX_INT_MODE_MSI]    = "MSI",
	[EFX_INT_MODE_LEGACY] = "legacy",
};

const unsigned int efx_reset_type_max = RESET_TYPE_MAX;
const char *efx_reset_type_names[] = {
	[RESET_TYPE_INVISIBLE]     = "INVISIBLE",
	[RESET_TYPE_ALL]           = "ALL",
	[RESET_TYPE_WORLD]         = "WORLD",
	[RESET_TYPE_DISABLE]       = "DISABLE",
	[RESET_TYPE_TX_WATCHDOG]   = "TX_WATCHDOG",
	[RESET_TYPE_INT_ERROR]     = "INT_ERROR",
	[RESET_TYPE_RX_RECOVERY]   = "RX_RECOVERY",
	[RESET_TYPE_RX_DESC_FETCH] = "RX_DESC_FETCH",
	[RESET_TYPE_TX_DESC_FETCH] = "TX_DESC_FETCH",
	[RESET_TYPE_TX_SKIP]       = "TX_SKIP",
	[RESET_TYPE_MC_FAILURE]    = "MC_FAILURE",
};

#define EFX_MAX_MTU (9 * 1024)

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
struct workqueue_struct *efx_workqueue;
#endif

#define EFX_DEFAULT_WATCHDOG (5 * HZ)

/* Reset workqueue. If any NIC has a hardware failure then a reset will be
 * queued onto this work queue. This is not a per-nic work queue, because
 * efx_reset_work() acquires the rtnl lock, so resets are naturally serialised.
 */
static struct workqueue_struct *reset_workqueue;

static unsigned debug = (NETIF_MSG_DRV | NETIF_MSG_PROBE |
			 NETIF_MSG_LINK | NETIF_MSG_IFDOWN |
			 NETIF_MSG_IFUP | NETIF_MSG_RX_ERR |
			 NETIF_MSG_TX_ERR | NETIF_MSG_HW);
module_param(debug, uint, 0);
MODULE_PARM_DESC(debug, "Bitmapped debugging message enable value");

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
static int lro = true;
module_param(lro, int, 0444);
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
static unsigned int separate_tx_channels;
module_param(separate_tx_channels, uint, 0444);
MODULE_PARM_DESC(separate_tx_channels,
		 "Use separate channels for TX and RX");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
/*
 * Number of RX netqs to allocate
 */
static int num_rx_netqs = -1;
module_param(num_rx_netqs, uint, 0444);
MODULE_PARM_DESC(num_rx_netqs,
		 "The number of receive NETQs to allocate");

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
/*
 * Number of TX channels to allocate
 */
static int num_tx_channels = -1;
module_param(num_tx_channels, uint, 0444);
MODULE_PARM_DESC(num_tx_channels,
		 "Number of transmit channels to allocate");
#endif
#endif

/* This is the weight assigned to each of the (per-channel) virtual
 * NAPI devices.
 */
static int napi_weight = 64;

/* This is the time (in jiffies) between invocations of the hardware
 * monitor.  On Falcon-based NICs, this will:
 * - Check the on-board hardware monitor;
 * - Poll the link state and reconfigure the hardware as necessary.
 */
static unsigned int efx_monitor_interval = 1 * HZ;

/* This controls whether or not the driver will initialise devices
 * with invalid MAC addresses stored in the EEPROM or flash.  If true,
 * such devices will be initialised with a random locally-generated
 * MAC address.  This allows for loading the sfc_mtd driver to
 * reprogram the flash, even if the flash contents (including the MAC
 * address) have previously been erased.
 */
static unsigned int allow_bad_hwaddr;

#ifdef EFX_NOT_UPSTREAM
/* This allows a card to continue operating after a fatal error has
 * been detected.  Consider any relevant warranties to be completely
 * voided by using this option.
 */
static unsigned int allow_zombie;
#endif

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

/* This is the requested number of CPUs to use for Receive-Side Scaling
 * (RSS), i.e. the number of CPUs among which we may distribute
 * simultaneous interrupt handling.  Or alternatively it may be set to
 * "packages", "cores" or "hyperthreads" to get one receive channel per
 * package, core or hyperthread.
 *
 * Systems without MSI-X will only target one CPU via legacy or MSI
 * interrupt.  The default is "packages".
 */
static char *rss_cpus;
module_param(rss_cpus, charp, 0444);
MODULE_PARM_DESC(rss_cpus, "Number of CPUs to use for Receive-Side Scaling, "
		 "or 'packages', 'cores' or 'hyperthreads'");

enum rss_mode {
	EFX_RSS_PACKAGES,
	EFX_RSS_CORES,
	EFX_RSS_HYPERTHREADS,
	EFX_RSS_CUSTOM,
};

static int phy_flash_cfg;
module_param(phy_flash_cfg, int, 0644);
MODULE_PARM_DESC(phy_flash_cfg, "Set PHYs into reflash mode initially");

static unsigned irq_adapt_enable = 1;
module_param(irq_adapt_enable, uint, 0444);
MODULE_PARM_DESC(irq_adapt_enable,
		 "Enable adaptive interrupt moderation");

static unsigned irq_adapt_low_thresh = 8000;
module_param(irq_adapt_low_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_low_thresh,
		 "Threshold score for reducing IRQ moderation");

static unsigned irq_adapt_high_thresh = 16000;
module_param(irq_adapt_high_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_high_thresh,
		 "Threshold score for increasing IRQ moderation");

static unsigned irq_adapt_irqs = 1000;
module_param(irq_adapt_irqs, uint, 0644);
MODULE_PARM_DESC(irq_adapt_irqs,
		 "Number of IRQs per IRQ moderation adaptation");

static unsigned int rx_ring = EFX_DEFAULT_DMAQ_SIZE;
module_param(rx_ring, uint, 0644);
MODULE_PARM_DESC(rx_ring,
		 "Maximum number of descriptors in a receive ring");

static unsigned int tx_ring = EFX_DEFAULT_DMAQ_SIZE;
module_param(tx_ring, uint, 0644);
MODULE_PARM_DESC(tx_ring,
		 "Maximum number of descriptors in a transmit ring");

#ifdef EFX_NOT_UPSTREAM
static bool rx_hash_insert = true;
module_param(rx_hash_insert, bool, 0444);
MODULE_PARM_DESC(rx_hash_insert,
		 "Enable insertion of flow hash in RX buffers");
#endif

/**************************************************************************
 *
 * Utility functions and prototypes
 *
 *************************************************************************/

static void efx_start_interrupts(struct efx_nic *efx, bool may_keep_eventq);
static void efx_stop_interrupts(struct efx_nic *efx, bool may_keep_eventq);
static int efx_init_napi_channel(struct efx_channel *channel);
static void efx_fini_napi_channel(struct efx_channel *channel);
static void efx_remove_channel(struct efx_channel *channel);
static void efx_remove_channels(struct efx_nic *efx);
static const struct efx_channel_type efx_default_channel_type;
static void efx_remove_port(struct efx_nic *efx);
static void efx_fini_napi(struct efx_nic *efx);
static void efx_fini_struct(struct efx_nic *efx);

#define EFX_ASSERT_RESET_SERIALISED(efx)		\
	do {						\
		if ((efx->state == STATE_RUNNING) ||	\
		    (efx->state == STATE_DISABLED))	\
			ASSERT_RTNL();			\
	} while (0)

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

	if (unlikely(!channel->enabled))
		return 0;

	spent = efx_nic_process_eventq(channel, budget);

	if (spent && efx_channel_has_rx_queue(channel)) {
		struct efx_rx_queue *rx_queue =
			efx_channel_get_rx_queue(channel);

		/* Deliver last RX packet. */
		if (channel->rx_pkt) {
			__efx_rx_packet(channel, channel->rx_pkt);
			channel->rx_pkt = NULL;
		}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx_ssr_end_of_burst(channel);
#endif
		if (rx_queue->enabled) {
			efx_rx_strategy(channel);
			efx_fast_push_rx_descriptors(rx_queue);
		}
	}

	return spent;
}

/* Mark channel as finished processing
 *
 * Note that since we will not receive further interrupts for this
 * channel before we finish processing and call the eventq_read_ack()
 * method, there is no need to use the interrupt hold-off timers.
 */
static inline void efx_channel_processed(struct efx_channel *channel)
{
	/* The interrupt handler for this channel may set work_pending
	 * as soon as we acknowledge the events we've seen.  Make sure
	 * it's cleared before then. */
	channel->work_pending = false;
	smp_wmb();

	efx_nic_eventq_read_ack(channel);
}

/* NAPI poll handler
 *
 * NAPI guarantees serialisation of polls of the same device, which
 * provides the guarantee required by efx_process_channel().
 */
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
			if (unlikely(channel->irq_mod_score <
				     irq_adapt_low_thresh)) {
				if (channel->irq_moderation > 1) {
					channel->irq_moderation -= 1;
					efx->type->push_irq_moderation(channel);
				}
			} else if (unlikely(channel->irq_mod_score >
					    irq_adapt_high_thresh)) {
				if (channel->irq_moderation <
				    efx->irq_rx_moderation) {
					channel->irq_moderation += 1;
					efx->type->push_irq_moderation(channel);
				}
			}
			channel->irq_count = 0;
			channel->irq_mod_score = 0;
		}

		efx_filter_rfs_expire(channel);

		/* There is no race here; although napi_disable() will
		 * only wait for napi_complete(), this isn't a problem
		 * since efx_channel_processed() will have no effect if
		 * interrupts have already been disabled.
		 */
		napi_complete(napi);
		efx_channel_processed(channel);
	}

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_OLD_NAPI)
	return spent;
#else
	return (spent >= budget);
#endif
}

/* Process the eventq of the specified channel immediately on this CPU
 *
 * Disable hardware generated interrupts, wait for any existing
 * processing to finish, then directly poll (and ack ) the eventq.
 * Finally reenable NAPI and interrupts.
 *
 * This is for use only during a loopback self-test.  It must not
 * deliver any packets up the stack as this can result in deadlock.
 */
void efx_process_channel_now(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

	BUG_ON(channel->channel >= efx->n_channels);
	BUG_ON(!channel->enabled);
	BUG_ON(!efx->loopback_selftest);

	/* Disable interrupts and wait for ISRs to complete */
	efx_nic_disable_interrupts(efx);
	if (efx->legacy_irq) {
		synchronize_irq(efx->legacy_irq);
		efx->legacy_irq_enabled = false;
	}
	if (channel->irq)
		synchronize_irq(channel->irq);

	/* Wait for any NAPI processing to complete */
	napi_disable(&channel->napi_str);

	/* Poll the channel */
	efx_process_channel(channel, channel->eventq_mask + 1);

	/* Ack the eventq. This may cause an interrupt to be generated
	 * when they are reenabled */
	efx_channel_processed(channel);

	napi_enable(&channel->napi_str);
	if (efx->legacy_irq)
		efx->legacy_irq_enabled = true;
	efx_nic_enable_interrupts(efx);
}

/* Create event queue
 * Event queue memory allocations are done only once.  If the channel
 * is reset, the memory buffer will be reused; this guards against
 * errors during channel reset and also simplifies interrupt handling.
 */
static int efx_probe_eventq(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	unsigned long entries;

	netif_dbg(efx, probe, channel->efx->net_dev,
		  "chan %d create event queue\n", channel->channel);

	/* Build an event queue with room for one event per tx and rx buffer,
	 * plus some extra for link state events and MCDI completions. */
	entries = roundup_pow_of_two(efx->rxq_entries + efx->txq_entries + 128);
	EFX_BUG_ON_PARANOID(entries > EFX_MAX_EVQ_SIZE);
	channel->eventq_mask = max(entries, EFX_MIN_EVQ_SIZE) - 1;

	return efx_nic_probe_eventq(channel);
}

/* Prepare channel's event queue */
static void efx_init_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d init event queue\n", channel->channel);

	channel->eventq_read_ptr = 0;

	efx_nic_init_eventq(channel);
}

/* Enable event queue processing and NAPI */
void efx_start_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, ifup, channel->efx->net_dev,
		  "chan %d start event queue\n", channel->channel);

	/* The interrupt handler for this channel may set work_pending
	 * as soon as we enable it.  Make sure it's cleared before
	 * then.  Similarly, make sure it sees the enabled flag set. */
	channel->work_pending = false;
	channel->enabled = true;
	smp_wmb();

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
	channel->enabled = false;
}

static void efx_fini_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d fini event queue\n", channel->channel);

	efx_nic_fini_eventq(channel);
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

	for (j = 0; j < EFX_TXQ_TYPES; j++) {
		tx_queue = &channel->tx_queue[j];
		tx_queue->efx = efx;
		tx_queue->queue = i * EFX_TXQ_TYPES + j;
		tx_queue->channel = channel;
	}

	rx_queue = &channel->rx_queue;
	rx_queue->efx = efx;
	setup_timer(&rx_queue->slow_fill, efx_rx_slow_fill,
		    (unsigned long)rx_queue);

	return channel;
}

/* Allocate and initialise a channel structure, copying parameters
 * (but not resources) from an old channel structure. */
static struct efx_channel *
efx_copy_channel(const struct efx_channel *old_channel)
{
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

	for (j = 0; j < EFX_TXQ_TYPES; j++) {
		tx_queue = &channel->tx_queue[j];
		if (tx_queue->channel)
			tx_queue->channel = channel;
		tx_queue->buffer = NULL;
		memset(&tx_queue->txd, 0, sizeof(tx_queue->txd));
	}

	rx_queue = &channel->rx_queue;
	rx_queue->buffer = NULL;
	memset(&rx_queue->rxd, 0, sizeof(rx_queue->rxd));
	setup_timer(&rx_queue->slow_fill, efx_rx_slow_fill,
		    (unsigned long)rx_queue);

	return channel;
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
					efx->channel_name[channel->channel],
					sizeof(efx->channel_name[0]));
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
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_channel *channel;

	/* Calculate the rx buffer allocation parameters required to
	 * support the current MTU, including padding for header
	 * alignment and overruns.
	 */
	efx->rx_buffer_len = (max(EFX_PAGE_IP_ALIGN, NET_IP_ALIGN) +
			      EFX_MAX_FRAME_LEN(efx->net_dev->mtu) +
			      efx->type->rx_buffer_hash_size +
			      efx->type->rx_buffer_padding);
	efx->rx_buffer_order = get_order(efx->rx_buffer_len +
					 sizeof(struct efx_rx_page_state));

	/* Initialise the channels */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_tx_queue(tx_queue, channel)
			efx_init_tx_queue(tx_queue);

		/* The rx buffer allocation strategy is MTU dependent */
		efx_rx_strategy(channel);

		efx_for_each_channel_rx_queue(rx_queue, channel) {
			efx_init_rx_queue(rx_queue);
			efx_nic_generate_fill_event(rx_queue);
		}

		WARN_ON(channel->rx_pkt != NULL);
		efx_rx_strategy(channel);
	}

	if (netif_device_present(efx->net_dev))
		netif_tx_wake_all_queues(efx->net_dev);
}

static void efx_stop_datapath(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct pci_dev *dev =  efx->pci_dev;
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);
	BUG_ON(efx->port_enabled);

	/* Only perform flush if dma is enabled */
	if (dev->is_busmaster) {
		rc = efx_nic_flush_queues(efx);

		if (rc && EFX_WORKAROUND_7803(efx)) {
			/* Schedule a reset to recover from the flush failure. The
			 * descriptor caches reference memory we're about to free,
			 * but falcon_reconfigure_mac_wrapper() won't reconnect
			 * the MACs because of the pending reset. */
			netif_err(efx, drv, efx->net_dev,
				  "Resetting to recover from flush failure\n");
			efx_schedule_reset(efx, RESET_TYPE_ALL);
		} else if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "Disabling due to flush queue failure\n");
			efx_schedule_reset(efx, RESET_TYPE_DISABLE);
		} else {
			netif_dbg(efx, drv, efx->net_dev,
				  "successfully flushed all queues\n");
		}
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

	efx_for_each_channel(channel, efx)
		efx_remove_channel(channel);
}

int
efx_realloc_channels(struct efx_nic *efx, u32 rxq_entries, u32 txq_entries)
{
	struct efx_channel *other_channel[EFX_MAX_CHANNELS], *channel;
	u32 old_rxq_entries, old_txq_entries;
	unsigned i, next_buffer_table = 0;
	int rc = 0;

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

	efx_stop_all(efx);
	efx_stop_interrupts(efx, true);

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

	efx_start_interrupts(efx, true);
	efx_start_all(efx);
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
	mod_timer(&rx_queue->slow_fill, jiffies + msecs_to_jiffies(100));
}

static const struct efx_channel_type efx_default_channel_type = {
	.pre_probe		= efx_channel_dummy_op_int,
	.post_remove		= efx_channel_dummy_op_void,
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
			   "link up at %uMbps %s-duplex (MTU %d)%s%s%s%s\n",
			   link_state->speed, link_state->fd ? "full" : "half",
			   efx->net_dev->mtu,
			   (efx->loopback_mode ? " [" : ""),
			   (efx->loopback_mode ? LOOPBACK_MODE(efx) : ""),
			   (efx->loopback_mode ? " LOOPBACK]" : ""),
			   (efx->promiscuous ? " [PROMISC]" : ""));

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

void efx_link_set_wanted_fc(struct efx_nic *efx, enum efx_fc_type wanted_fc)
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

	/* Serialise the promiscuous flag with efx_set_rx_mode. */
	netif_addr_lock_bh(efx->net_dev);
	netif_addr_unlock_bh(efx->net_dev);

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
		efx->type->reconfigure_mac(efx);
	mutex_unlock(&efx->mac_lock);
}

static int efx_probe_port(struct efx_nic *efx)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_PRINT_MAC)
	DECLARE_MAC_BUF(buf);
#endif
	unsigned char *perm_addr;
	int rc;

	netif_dbg(efx, probe, efx->net_dev, "create port\n");

	if (phy_flash_cfg)
		efx->phy_mode = PHY_MODE_SPECIAL;

	/* Register debugfs entries */
	rc = efx_init_debugfs_port(efx);
	if (rc)
		return rc;

	/* Connect up MAC/PHY operations table */
	rc = efx->type->probe_port(efx);
	if (rc)
		goto fail1;

	/* Sanity check MAC address */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
	perm_addr = efx->net_dev->perm_addr;
#else
	perm_addr = efx->perm_addr;
#endif
	if (is_valid_ether_addr(perm_addr)) {
		memcpy(efx->net_dev->dev_addr, perm_addr, ETH_ALEN);
	} else {
		if (!allow_bad_hwaddr) {
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_PRINT_MAC)
			netif_err(efx, probe, efx->net_dev,
				  "invalid MAC address %pM\n",
				  perm_addr);
#else
			netif_err(efx, probe, efx->net_dev,
				  "invalid MAC address %s\n",
				  print_mac(buf, perm_addr));
#endif
			rc = -EINVAL;
			goto fail2;
		}
		random_ether_addr(efx->net_dev->dev_addr);
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_PRINT_MAC)
		netif_info(efx, probe, efx->net_dev,
			   "using locally-generated MAC %pM\n",
			   efx->net_dev->dev_addr);
#else
		netif_info(efx, probe, efx->net_dev,
			   "using locally-generated MAC %s\n",
			   print_mac(buf, efx->net_dev->dev_addr));
#endif
	}

	return 0;

fail2:
	efx->type->remove_port(efx);
fail1:
	efx_fini_debugfs_port(efx);
	return rc;
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
	efx->type->reconfigure_mac(efx);

	/* Ensure the PHY advertises the correct flow control settings */
	rc = efx->phy_op->reconfigure(efx);
	if (rc)
		goto fail2;

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

	/* efx_mac_work() might have been scheduled after efx_stop_port(),
	 * and then cancelled by efx_flush_all(). Also reverse the actions
	 * of prepare_flush() */
	efx->type->reconfigure_mac(efx);

	mutex_unlock(&efx->mac_lock);
}

/* Prevent efx_mac_work() and efx_monitor() from working */
static void efx_stop_port(struct efx_nic *efx)
{
	netif_dbg(efx, ifdown, efx->net_dev, "stop port\n");

	mutex_lock(&efx->mac_lock);
	efx->port_enabled = false;
	mutex_unlock(&efx->mac_lock);

	netif_addr_lock_bh(efx->net_dev);
	netif_addr_unlock_bh(efx->net_dev);
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
	efx_fini_debugfs_port(efx);
}

/**************************************************************************
 *
 * NIC handling
 *
 **************************************************************************/

/* This configures the PCI device to enable I/O and DMA. */
static int efx_init_io(struct efx_nic *efx)
{
	struct pci_dev *pci_dev = efx->pci_dev;
	dma_addr_t dma_mask = efx->type->max_dma_mask;
	int rc;

	netif_dbg(efx, probe, efx->net_dev, "initialising I/O\n");

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
		if (pci_dma_supported(pci_dev, dma_mask) &&
		    ((rc = pci_set_dma_mask(pci_dev, dma_mask)) == 0))
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
	rc = pci_set_consistent_dma_mask(pci_dev, dma_mask);
	if (rc) {
		/* pci_set_consistent_dma_mask() is not *allowed* to
		 * fail with a mask that pci_set_dma_mask() accepted,
		 * but just in case...
		 */
		netif_err(efx, probe, efx->net_dev,
			  "failed to set consistent DMA mask\n");
		goto fail2;
	}

	efx->membase_phys = pci_resource_start(efx->pci_dev, EFX_MEM_BAR);
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_MSIX_TABLE_RESERVED)
	rc = pci_request_region(pci_dev, EFX_MEM_BAR, "sfc");
#else
	if (!request_mem_region(efx->membase_phys, efx->type->mem_map_size,
				"sfc"))
		rc = -EIO;
#endif
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "request for memory BAR failed\n");
		rc = -EIO;
		goto fail3;
	}
	efx->membase = ioremap_nocache(efx->membase_phys,
				       efx->type->mem_map_size);
	if (!efx->membase) {
		netif_err(efx, probe, efx->net_dev,
			  "could not map memory BAR at %llx+%x\n",
			  (unsigned long long)efx->membase_phys,
			  efx->type->mem_map_size);
		rc = -ENOMEM;
		goto fail4;
	}
	netif_dbg(efx, probe, efx->net_dev,
		  "memory BAR at %llx+%x (virtual %p)\n",
		  (unsigned long long)efx->membase_phys,
		  efx->type->mem_map_size, efx->membase);

	return 0;

 fail4:
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_MSIX_TABLE_RESERVED)
	pci_release_region(efx->pci_dev, EFX_MEM_BAR);
#else
	release_mem_region(efx->membase_phys, efx->type->mem_map_size);
#endif
 fail3:
	efx->membase_phys = 0;
 fail2:
	pci_disable_device(efx->pci_dev);
 fail1:
	return rc;
}

static void efx_fini_io(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "shutting down I/O\n");

	if (efx->membase) {
		iounmap(efx->membase);
		efx->membase = NULL;
	}

	if (efx->membase_phys) {
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_MSIX_TABLE_RESERVED)
		pci_release_region(efx->pci_dev, EFX_MEM_BAR);
#else
		release_mem_region(efx->membase_phys, efx->type->mem_map_size);
#endif
		efx->membase_phys = 0;
	}

	pci_disable_device(efx->pci_dev);
}

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_core_cpumask) && !defined(__VMKLNX__))
#define HAVE_EFX_NUM_PACKAGES
static int efx_num_packages(void)
{
	cpumask_var_t core_mask;
	int count;
	int cpu, cpu2;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_online_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;

			/* Treat each numa node as a seperate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, core_mask);
			}
		}
	}

	/* Create two RSS queues even on a single package host */
	if (count == 1)
		count = 2;

	free_cpumask_var(core_mask);
	return count;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_thread_cpumask) && !defined(__VMKLNX__) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP))
#define HAVE_EFX_NUM_CORES
static int efx_num_cores(void)
{
	cpumask_var_t core_mask;
	int count;
	int cpu;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_online_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;
			cpumask_or(core_mask, core_mask,
				   topology_thread_cpumask(cpu));
		}
	}

	free_cpumask_var(core_mask);
	return count;
}
#endif

static int efx_wanted_parallelism(struct efx_nic *efx)
{
	enum rss_mode rss_mode = EFX_RSS_CORES;
	bool selected = false;
	int n_rxq = -1;
	struct net_device *net_dev =
#ifdef __VMKLNX__
		!efx ? NULL :
#endif
		efx->net_dev;

	if (rss_cpus == NULL) {
		/* Leave at default. */
	} else if (strcmp(rss_cpus, "packages") == 0) {
		rss_mode = EFX_RSS_PACKAGES;
		selected = true;
	} else if (strcmp(rss_cpus, "cores") == 0) {
		rss_mode = EFX_RSS_CORES;
		selected = true;
	} else if (strcmp(rss_cpus, "hyperthreads") == 0) {
		rss_mode = EFX_RSS_HYPERTHREADS;
		selected = true;
	} else if (sscanf(rss_cpus, "%d", &n_rxq) == 1 && n_rxq > 0) {
		rss_mode = EFX_RSS_CUSTOM;
		selected = true;
	} else {
		netif_err(efx, drv, net_dev,
			  "Bad value for module parameter rss_cpus='%s'\n",
			  rss_cpus);
	}

	switch (rss_mode) {
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
			n_rxq = efx_num_packages();
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
			n_rxq = efx_num_cores();
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
		rss_mode = EFX_RSS_HYPERTHREADS;
		n_rxq = num_online_cpus();
		break;
	}

	if (n_rxq > EFX_MAX_RX_QUEUES) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of rss channels from %d to %d.\n",
			   n_rxq, EFX_MAX_RX_QUEUES);
		n_rxq = EFX_MAX_RX_QUEUES;
	}

	/* If RSS is requested for the PF *and* VFs then we can't write RSS
	 * table entries that are inaccessible to VFs */
#ifdef __VMKLNX__
	if (efx)
#endif
	if (efx->vf_count && efx->vi_scale && n_rxq > (1 << efx->vi_scale)) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of rss channels from %d to %d for "
			   "VF support. Increase vf-msix-limit to use more "
			   "channels on the PF.\n", n_rxq, 1 << efx->vi_scale);
		n_rxq = (1 << efx->vi_scale);
	}

	return n_rxq;
}

static int
efx_init_rx_cpu_rmap(struct efx_nic *efx, struct msix_entry *xentries)
{
#ifdef CONFIG_RFS_ACCEL
	int i, rc;

	efx->net_dev->rx_cpu_rmap = alloc_irq_cpu_rmap(efx->n_rx_channels);
	if (!efx->net_dev->rx_cpu_rmap)
		return -ENOMEM;
	for (i = 0; i < efx->n_rx_channels; i++) {
		rc = irq_cpu_rmap_add(efx->net_dev->rx_cpu_rmap,
					xentries[i].vector);
		if (rc) {
			free_irq_cpu_rmap(efx->net_dev->rx_cpu_rmap);
			efx->net_dev->rx_cpu_rmap = NULL;
			return rc;
		}
	}
#endif
	return 0;
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
static int efx_allocate_msix_channels(struct efx_nic *efx, int max_channels,
					int extra_channels, int parallelism)
{
	int dedicated_tx_channels;
	int channels;
	int remaining_channels = max_channels;
	/* allocate 1 channel to RX and TX if necessary before
	 * allocating further */
	efx->n_rss_channels = min(1, remaining_channels);
	remaining_channels -= efx->n_rss_channels;
	if (separate_tx_channels)
		dedicated_tx_channels = min(1, remaining_channels);
	else
		dedicated_tx_channels = 0;
	remaining_channels -= dedicated_tx_channels;

	/* if we have enough channels to dedicate to extra_channels then do so,
	 * otherwise merge extra_channels in with the rest */
	if (remaining_channels > extra_channels)
		remaining_channels -= extra_channels;

	/* then allocate netqs, beginning with a single channel each */
	efx->n_rx_netqs = min((num_rx_netqs >= 1 ? num_rx_netqs
						 : parallelism)-1,
				remaining_channels);
	remaining_channels -= efx->n_rx_netqs;

	/* then allocate extra tx and rx channels */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
	if (separate_tx_channels) {
		channels = min((num_tx_channels >= 1 ? num_tx_channels
						     : parallelism) - 1,
				remaining_channels/2);
		dedicated_tx_channels += channels;
		remaining_channels -= channels;
	}
#endif
	/* When using netq the rss channels per queue must be a power of 2 */
	if (efx->n_rss_channels)
		while (remaining_channels >=
				(efx->n_rx_netqs+1) * efx->n_rss_channels
				&& efx->n_rss_channels < parallelism) {
			remaining_channels -= efx->n_rss_channels *
					(efx->n_rx_netqs+1);
			efx->n_rss_channels *= 2;
		}

	efx->n_rx_channels = (efx->n_rx_netqs + 1) * efx->n_rss_channels;
	efx->rss_spread = min_t(int, efx->n_rss_channels, parallelism);
	efx->n_channels = efx->n_rx_channels + dedicated_tx_channels;
	if (dedicated_tx_channels > 0) {
		efx->n_tx_channels = dedicated_tx_channels;
		efx->tx_channel_offset = efx->n_rx_channels;
	} else {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
		efx->n_tx_channels = min_t(int,
					   efx->n_rx_channels,
					   (num_tx_channels >= 1
						? num_tx_channels
						: parallelism));
#else
		efx->n_tx_channels = 1;
#endif
		efx->tx_channel_offset = 0;
	}

	netif_info(efx, drv, efx->net_dev,
		"Allocating %d rss channels, %d dedicated TX channels\n",
		efx->n_rss_channels, dedicated_tx_channels);
	netif_info(efx, drv, efx->net_dev,
		"Also allocating %d RX netqs\n",
		efx->n_rx_netqs);

	return efx->n_channels;
}
#else
static int efx_allocate_msix_channels(struct efx_nic *efx, int max_channels,
					int extra_channels, int parallelism)
{
	int n_channels = parallelism;

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

	if (n_channels > extra_channels)
		n_channels -= extra_channels;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_TX_MQ)
	efx->n_tx_channels = 1;
#endif
	if (separate_tx_channels) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
		efx->n_tx_channels =
			max(n_channels / 2, 1);
#endif
		efx->tx_channel_offset =
			n_channels - efx->n_tx_channels;
		efx->n_rx_channels =
			max(n_channels -
			    efx->n_tx_channels, 1U);
	} else {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_TX_MQ)
		efx->n_tx_channels = n_channels;
#endif
		efx->tx_channel_offset = 0;
		efx->n_rx_channels = n_channels;
	}
	efx->n_rss_channels = efx->n_rx_channels;
	efx->rss_spread = efx->n_rss_channels;

	return efx->n_channels;
}
#endif

/* Probe the number and type of interrupts we are able to obtain, and
 * the resulting numbers of channels and RX queues.
 */
static int efx_probe_interrupts(struct efx_nic *efx)
{
	int max_channels =
		min_t(int, efx->type->phys_addr_channels, EFX_MAX_CHANNELS);
	unsigned extra_channels = 0;
	int rc, i, j;

	for (i = 0; i < EFX_MAX_EXTRA_CHANNELS; i++)
		if (efx->extra_channel_type[i])
			++extra_channels;

	if (efx->interrupt_mode == EFX_INT_MODE_MSIX) {
		struct msix_entry xentries[EFX_MAX_CHANNELS];
		int parallelism = efx_wanted_parallelism(efx);
		int n_channels = efx_allocate_msix_channels(efx, max_channels,
						extra_channels,	parallelism);
		efx->n_wanted_channels = n_channels +
			EFX_MAX_EXTRA_CHANNELS - extra_channels;

		for (i = 0; i < n_channels; i++)
			xentries[i].entry = i;
		rc = pci_enable_msix(efx->pci_dev, xentries, n_channels);
		if (rc > 0) {
			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Insufficient MSI-X vectors"
				  " available (%d < %d).\n", rc, n_channels);
			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Performance may be reduced.\n");
			EFX_BUG_ON_PARANOID(rc >= n_channels);
			n_channels = rc;
			efx_allocate_msix_channels(efx, n_channels,
						extra_channels, parallelism);
			rc = pci_enable_msix(efx->pci_dev, xentries,
					     n_channels);
		}

		if (rc == 0) {
			rc = efx_init_rx_cpu_rmap(efx, xentries);
			if (rc) {
				pci_disable_msix(efx->pci_dev);
				return rc;
			}
			for (i = 0; i < efx->n_channels; i++)
				efx_get_channel(efx, i)->irq =
					xentries[i].vector;
		} else {
			/* Fall back to single channel MSI */
			efx->interrupt_mode = EFX_INT_MODE_MSI;
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI-X\n");
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
		efx->n_rx_netqs = 0;
#endif
		rc = pci_enable_msi(efx->pci_dev);
		if (rc == 0) {
			efx_get_channel(efx, 0)->irq = efx->pci_dev->irq;
		} else {
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI\n");
			efx->interrupt_mode = EFX_INT_MODE_LEGACY;
		}
	}

	/* Assume legacy interrupts */
	if (efx->interrupt_mode == EFX_INT_MODE_LEGACY) {
		efx->n_channels = 1 + (separate_tx_channels ? 1 : 0)
			+ (efx->vf_count ? 1 : 0);
		efx->n_rx_channels = 1;
		efx->n_rss_channels = 1;
		efx->rss_spread = 1;
		efx->n_tx_channels = 1;
		efx->tx_channel_offset = 0;
		efx->n_wanted_channels = efx->n_channels;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
		efx->n_rx_netqs = 0;
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

#ifdef __VMKLNX__
	rx_set_num_qs_per_nic(efx);
#endif

	/* RSS on the PF might now be impossible due to interrupt allocation
	 * failure */
	efx->rss_spread = (efx->vf_count && efx->rss_spread == 1) ?
		(1 << efx->vi_scale) : efx->rss_spread;

	netif_info(efx, drv, efx->net_dev, "RSS spread is %d channels\n",
					efx->rss_spread);

	return 0;
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)

static int efx_irq_set_affinity = 1;
module_param_named(irq_set_affinity, efx_irq_set_affinity, int, 0444);
MODULE_PARM_DESC(irq_set_affinity,
		 "Set SMP affinity of IRQs to support RSS "
		 "(0=>disabled 1=>enabled (default))");

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

	if (!efx_irq_set_affinity)
		return 0;

	/* Write the mask into a sufficient buffer. We need a byte
	 * for every 4 bits of mask, plus comma's, plus a NULL. */
	content_len = max(NR_CPUS, 8) / 2;
	content = kmalloc(content_len, GFP_KERNEL);
	if (!content)
		return -ENOMEM;
#ifdef EFX_HAVE_OLD_CPUMASK_SCNPRINTF
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
/* Select the package_set with the lowest useage count */
static void efx_rss_choose_package(cpumask_t *set, cpumask_t *package_set,
				   cpumask_t *used_set)
{
	unsigned int thresh, count;
	int cpu, cpu2, sibling;

	thresh = 1;
	for_each_online_cpu(cpu)
		thresh += rss_cpu_usage[cpu];

	cpumask_clear(used_set);
	for_each_online_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, used_set)) {
			cpumask_clear(package_set);
			/* Treat each numa node as a seperate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, package_set);
			}
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
			cpumask_copy(core_set, topology_thread_cpumask(cpu));
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

/* Stripe the RSS vectors across the CPUs. */
static void efx_set_interrupt_affinity(struct efx_nic *efx)
{
	cpumask_var_t sets[4];
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

	/* Serialise access to rss_cpu_usage */
	rtnl_lock();

	/* Assign each channel a CPU */
	efx_for_each_channel(channel, efx) {
#ifdef HAVE_EFX_NUM_PACKAGES
		/* Select the package_set with the lowest useage count */
		efx_rss_choose_package(sets[0], sets[2], sets[3]);
		WARN_ON(!cpumask_weight(sets[0]));
#else
		cpumask_copy(sets[0], &cpu_online_map);
#endif

		/* Select the thread siblings within this package with the
		 * lowest usage count */
#ifdef HAVE_EFX_NUM_CORES
		efx_rss_choose_core(sets[1], sets[0], sets[2], sets[3]);
		WARN_ON(!cpumask_weight(sets[1]));
#else
		cpumask_copy(sets[1], sets[0]);
#endif

		/* Select the thread within this set with the lowest usage count */
		cpu = efx_rss_choose_thread(sets[1]);
		++rss_cpu_usage[cpu];
		efx_set_cpu_affinity(channel, cpu);
	}

	rtnl_unlock();

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
}

#endif

/* Enable interrupts, then probe and start the event queues */
static void efx_start_interrupts(struct efx_nic *efx, bool may_keep_eventq)
{
	struct efx_channel *channel;

	if (efx->legacy_irq)
		efx->legacy_irq_enabled = true;
	efx_nic_enable_interrupts(efx);

	efx_for_each_channel(channel, efx) {
		if (!channel->type->keep_eventq || !may_keep_eventq)
			efx_init_eventq(channel);
		efx_start_eventq(channel);
	}

#if EFX_NOT_UPSTREAM
	if (efx->state == STATE_RUNNING)
#endif
		efx_mcdi_mode_event(efx);
}

static void efx_stop_interrupts(struct efx_nic *efx, bool may_keep_eventq)
{
	struct efx_channel *channel;

	efx_mcdi_mode_poll(efx);

	efx_nic_disable_interrupts(efx);
	if (efx->legacy_irq) {
		synchronize_irq(efx->legacy_irq);
		efx->legacy_irq_enabled = false;
	}

	efx_for_each_channel(channel, efx) {
		if (channel->irq)
			synchronize_irq(channel->irq);

		efx_stop_eventq(channel);
		if (!channel->type->keep_eventq || !may_keep_eventq)
			efx_fini_eventq(channel);
	}
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

	/* We need to mark which channels really have RX and TX
	 * queues, and adjust the TX queue numbers if we have separate
	 * RX-only and TX-only channels.
	 */
	efx_for_each_channel(channel, efx) {
		if (channel->channel < efx->n_rx_channels)
			channel->rx_queue.core_index = channel->channel;
		else
			channel->rx_queue.core_index = -1;

		efx_for_each_channel_tx_queue(tx_queue, channel)
			tx_queue->queue -= (efx->tx_channel_offset *
					    EFX_TXQ_TYPES);
	}
}

static int efx_probe_nic(struct efx_nic *efx)
{
	size_t i;
	int rc;

	netif_dbg(efx, probe, efx->net_dev, "creating NIC\n");

	/* Initialise NIC resource information */
	efx->resources = efx->type->resources;
	efx->resources.biu_lock = &efx->biu_lock;
	efx->dl_info = &efx->resources.hdr;

	/* Carry out hardware-type specific initialisation */
	rc = efx->type->probe(efx);
	if (rc)
		goto fail1;

	/* Determine the number of channels and queues by trying to hook
	 * in MSI-X interrupts. */
	rc = efx_probe_interrupts(efx);
	if (rc)
		goto fail2;

	rc = efx->type->dimension_resources(efx);
	if (rc)
		goto fail3;

	if (EFX_INT_MODE_USE_MSI(efx))
		efx->resources.flags |= EFX_DL_FALCON_USE_MSI;

	if (efx->n_channels > 1)
		get_random_bytes(&efx->rx_hash_key, sizeof(efx->rx_hash_key));

	for (i = 0; i < ARRAY_SIZE(efx->rx_indir_table); i++)
		efx->rx_indir_table[i] =
			ethtool_rxfh_indir_default(i, efx->rss_spread);

	efx_set_channels(efx);
	netif_set_real_num_tx_queues(efx->net_dev, efx->n_tx_channels);
	netif_set_real_num_rx_queues(efx->net_dev, efx->n_rx_channels);

	/* Register debugfs entries */
	rc = efx_init_debugfs_nic(efx);
	if (rc)
		goto fail4;

	/* Initialise the interrupt moderation settings */
	efx_init_irq_moderation(efx, tx_irq_mod_usec, rx_irq_mod_usec,
				irq_adapt_enable, true);

	return 0;

fail4:
fail3:
	efx_remove_interrupts(efx);
fail2:
	efx->type->remove(efx);
fail1:
	efx->dl_info = NULL;
	return rc;
}

static void efx_remove_nic(struct efx_nic *efx)
{
	netif_dbg(efx, drv, efx->net_dev, "destroying NIC\n");

	efx_remove_interrupts(efx);
	efx->type->remove(efx);
	efx->dl_info = NULL;

	efx_fini_debugfs_nic(efx);
}

/**************************************************************************
 *
 * NIC startup/shutdown
 *
 *************************************************************************/

static int efx_probe_all(struct efx_nic *efx)
{
	int rc;

	rc = efx_probe_nic(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to create NIC\n");
		goto fail1;
	}

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
	if (efx->txq_entries > EFX_MAX_DMAQ_SIZE) {
		netif_err(efx, drv, efx->net_dev,
			  "tx_ring parameter must be no greater than %lu",
			  EFX_MAX_DMAQ_SIZE);
		rc = -EINVAL;
		goto fail3;
	}
	if (efx->txq_entries != tx_ring)
		netif_warn(efx, drv, efx->net_dev,
			   "increasing TX queue size to minimum of %u\n",
			   efx->txq_entries);

#ifdef EFX_NOT_UPSTREAM
	if (!rx_hash_insert) {
		struct efx_dl_device_info *dl_info, **prev;

		efx->rx_buffer_hash_size = 0;
		efx->net_dev->features &= ~NETIF_F_RXHASH;
#ifdef EFX_HAVE_NDO_SET_FEATURES
		efx->net_dev->hw_features &= ~NETIF_F_RXHASH;
#endif

		/* Unlink Driverlink hash insertion information */
		prev = &efx->dl_info;
		while ((dl_info = *prev) != NULL) {
			if (dl_info->type == EFX_DL_HASH_INSERTION) {
				*prev = dl_info->next;
				break;
			}
			prev = &dl_info->next;
		}
	}
#endif

	rc = efx_probe_filters(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to create filter tables\n");
		goto fail3;
	}

	rc = efx_probe_channels(efx);
	if (rc)
		goto fail4;

	return 0;

 fail4:
	efx_remove_filters(efx);
 fail3:
	efx_remove_port(efx);
 fail2:
	efx_remove_nic(efx);
 fail1:
	return rc;
}

/* Called after previous invocation(s) of efx_stop_all, restarts the port,
 * kernel transmit queues and NAPI processing, and ensures that the port is
 * scheduled to be reconfigured. This function is safe to call multiple
 * times when the NIC is in any state. */
void efx_start_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	/* Check that it is appropriate to restart the interface. All
	 * of these flags are safe to read under just the rtnl lock */
	if (efx->port_enabled)
		return;
	if ((efx->state != STATE_RUNNING) && (efx->state != STATE_INIT))
		return;
	if (!netif_running(efx->net_dev))
		return;

	efx_start_port(efx);
	efx_start_datapath(efx);

#ifdef __VMKLNX__
	efx->net_dev->trans_start = jiffies;
	efx->net_dev->watchdog_timeo = EFX_DEFAULT_WATCHDOG;
#endif

	/* Start the hardware monitor if there is one. Otherwise (we're link
	 * event driven), we have to poll the PHY because after an event queue
	 * flush we could have a missed a link state change */
	if (efx->type->monitor == NULL) {
		mutex_lock(&efx->mac_lock);
		if (efx->phy_op->poll(efx))
			efx_link_status_changed(efx);
		mutex_unlock(&efx->mac_lock);
#ifdef __VMKLNX__
	}
	/* under VMware always start the monitor, even if monitor==NULL. */
	{
#else
	} else {
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
		schedule_delayed_work(&efx->monitor_work, efx_monitor_interval);
#else
		queue_delayed_work(efx_workqueue, &efx->monitor_work,
					efx_monitor_interval);
#endif
	}

	efx->type->start_stats(efx);
}

/* Flush all delayed work. Should only be called when no more delayed work
 * will be scheduled. This doesn't flush pending online resets (efx_reset),
 * since we're holding the rtnl_lock at this point. */
static void efx_flush_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	/* Make sure the hardware monitor and event self-test are stopped */
	cancel_delayed_work_sync(&efx->monitor_work);
	efx_selftest_async_cancel(efx);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	/* Stop scheduled port reconfigurations */
	cancel_work_sync(&efx->mac_work);
#endif
#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	/* Ensure all consumers of efx_workqueue are complete. Since
	 * the hardware monitor runs on a long period, we put in some
	 * effort to cancel the delayed work safely rather than just
	 * flushing the queue twice (which is guaranteed to flush all
	 * the work since efx_monitor(), and efx_mac_work() disarm if
	 * !efx->port_enabled).
	 */
	if (timer_pending(&efx->monitor_work.timer))
		cancel_delayed_work(&efx->monitor_work);
	flush_workqueue(efx_workqueue);
	if (timer_pending(&efx->monitor_work.timer))
		cancel_delayed_work(&efx->monitor_work);
	flush_workqueue(efx_workqueue);
#endif
}

/* Quiesce hardware and software without bringing the link down.
 * Safe to call multiple times, when the nic and interface is in any
 * state. The caller is guaranteed to subsequently be in a position
 * to modify any hardware and software state they see fit without
 * taking locks. */
void efx_stop_all(struct efx_nic *efx)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	/* port_enabled can be read safely under the rtnl lock */
	if (!efx->port_enabled)
		return;

	efx->type->stop_stats(efx);
	efx_stop_port(efx);

	/* Flush efx_mac_work(), refill_workqueue and efx_monitor_work() */
	efx_flush_all(efx);

#ifdef __VMKLNX__
	{
		/* keep TX watchdog happy for the worst case flush time */
		unsigned timeout = msecs_to_jiffies(EFX_MAX_FLUSH_TIME * 3 / 2);
		if (efx->net_dev->watchdog_timeo < timeout)
			efx->net_dev->watchdog_timeo = timeout;
		efx->net_dev->trans_start = jiffies;
	}
#endif

	/* Stop the kernel transmit interface late, so the watchdog
	 * timer isn't ticking over the flush */
	netif_tx_disable(efx->net_dev);

	efx_stop_datapath(efx);
}

static void efx_remove_all(struct efx_nic *efx)
{
	efx_remove_channels(efx);
	efx_remove_filters(efx);
	efx_remove_port(efx);
	efx_remove_nic(efx);
}

/**************************************************************************
 *
 * Interrupt moderation
 *
 **************************************************************************/

static unsigned int irq_mod_ticks(unsigned int usecs, unsigned int quantum_ns)
{
	if (usecs == 0)
		return 0;
	if (usecs * 1000 < quantum_ns)
		return 1; /* never round down to 0 */
	return usecs * 1000 / quantum_ns;
}

/* Set interrupt moderation parameters */
int efx_init_irq_moderation(struct efx_nic *efx, unsigned int tx_usecs,
			    unsigned int rx_usecs, bool rx_adaptive,
			    bool rx_may_override_tx)
{
	struct efx_channel *channel;
	unsigned int irq_mod_max = DIV_ROUND_UP(efx->type->timer_period_max *
						efx->timer_quantum_ns,
						1000);
	unsigned int tx_ticks;
	unsigned int rx_ticks;

	EFX_ASSERT_RESET_SERIALISED(efx);

	if (tx_usecs > irq_mod_max || rx_usecs > irq_mod_max)
		return -EINVAL;

	tx_ticks = irq_mod_ticks(tx_usecs, efx->timer_quantum_ns);
	rx_ticks = irq_mod_ticks(rx_usecs, efx->timer_quantum_ns);

	if (tx_ticks != rx_ticks && efx->tx_channel_offset == 0 &&
	    !rx_may_override_tx) {
		netif_err(efx, drv, efx->net_dev, "Channels are shared. "
			  "RX and TX IRQ moderation must be equal\n");
		return -EINVAL;
	}

	efx->irq_rx_adaptive = rx_adaptive;
	efx->irq_rx_moderation = rx_ticks;
	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel))
			channel->irq_moderation = rx_ticks;
		else if (efx_channel_has_tx_queues(channel))
			channel->irq_moderation = tx_ticks;
	}

	return 0;
}

void efx_get_irq_moderation(struct efx_nic *efx, unsigned int *tx_usecs,
			    unsigned int *rx_usecs, bool *rx_adaptive)
{
	/* We must round up when converting ticks to microseconds
	 * because we round down when converting the other way.
	 */

	*rx_adaptive = efx->irq_rx_adaptive;
	*rx_usecs = DIV_ROUND_UP(efx->irq_rx_moderation *
				 efx->timer_quantum_ns,
				 1000);

	/* If channels are shared between RX and TX, so is IRQ
	 * moderation.  Otherwise, IRQ moderation is the same for all
	 * TX channels and is not adaptive.
	 */
	if (efx->tx_channel_offset == 0)
		*tx_usecs = *rx_usecs;
	else
		*tx_usecs = DIV_ROUND_UP(
			efx->channel[efx->tx_channel_offset]->irq_moderation *
			efx->timer_quantum_ns,
			1000);
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
#ifndef __VMKLNX__
	BUG_ON(efx->type->monitor == NULL);
#endif
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
	 * most of the work of check_hw() anyway. */
	if (mutex_trylock(&efx->mac_lock)) {
#endif
		if (efx->port_enabled)
#ifdef __VMKLNX__
			if (efx->type->monitor)
#endif
			efx->type->monitor(efx);
		mutex_unlock(&efx->mac_lock);
	}

#ifdef __VMKLNX__
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	rtnl_lock();
	if (!efx->port_enabled) {
		rtnl_unlock();
		return;
	} else {
#else
	if (rtnl_trylock()) {
#endif
		if (efx->port_enabled)
			efx_vmware_monitor_checks(efx);
		rtnl_unlock();
	}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	schedule_delayed_work(&efx->monitor_work, efx_monitor_interval);
#else
	queue_delayed_work(efx_workqueue, &efx->monitor_work,
			   efx_monitor_interval);
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
static int efx_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct mii_ioctl_data *data = if_mii(ifr);

	ASSERT_RTNL();

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_BONDING_HACKS)
	if (in_interrupt())
		/* We can't execute mdio requests from an atomic context
		 * on Siena. Luckily, the bonding driver falls back to
		 * the ethtool API if this command fails. */
		return -ENOSYS;
#endif
	EFX_ASSERT_RESET_SERIALISED(efx);

#if defined(SIOCSHWTSTAMP)
	if (cmd == SIOCSHWTSTAMP)
		return efx_ptp_ioctl(efx, ifr, cmd);
#endif

#if defined(EFX_NOT_UPSTREAM) || (defined(EFX_USE_KCOMPAT) &&  \
				  (!defined(EFX_HAVE_ETHTOOL_RESET) || \
				   !defined(EFX_HAVE_ETHTOOL_GMODULEEEPROM)))
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
#if defined(__VMKLNX__)
	channel->napi_str.dev = channel->napi_dev;
#endif
#endif
	netif_napi_add(channel->napi_dev, &channel->napi_str,
		       efx_poll, napi_weight);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	{
		int rc = efx_ssr_init(channel, efx);
		if (rc) {
			efx_fini_napi(efx);
			return rc;
		}
	}
#endif

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
	if (channel->napi_dev)
		netif_napi_del(&channel->napi_str);
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
static void efx_netpoll(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_schedule_channel(channel);
}

#endif

/**************************************************************************
 *
 * Kernel net device interface
 *
 *************************************************************************/

/* Context: process, rtnl_lock() held. */
static int efx_net_open(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	EFX_ASSERT_RESET_SERIALISED(efx);

	netif_dbg(efx, ifup, efx->net_dev, "opening device on CPU %d\n",
		  raw_smp_processor_id());

	if (efx->state == STATE_DISABLED) {
		netif_err(efx, ifup, efx->net_dev, "Device is disabled.\n");
		return -EIO;
	}
	if (efx->phy_mode & PHY_MODE_SPECIAL)
		return -EBUSY;
	if (efx_mcdi_poll_reboot(efx) && efx_reset(efx, RESET_TYPE_ALL))
		return -EIO;

	/* Notify the kernel of the link state polled during driver load,
	 * before the monitor starts running */
	efx_link_status_changed(efx);

	efx_start_all(efx);
	efx_selftest_async_start(efx);
	return 0;
}

/* Context: process, rtnl_lock() held.
 * Note that the kernel will ignore our return code; this method
 * should really be a void.
 */
static int efx_net_stop(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	ASSERT_RTNL();

	netif_dbg(efx, ifdown, efx->net_dev, "closing on CPU %d\n",
		  raw_smp_processor_id());

	if (efx->state != STATE_DISABLED) {
		/* Stop the device and flush all the channels */
		efx_stop_all(efx);
	}

#ifdef EFX_NEED_DEV_CLOSE_HACK
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
static struct rtnl_link_stats64 *efx_net_stats(struct net_device *net_dev,
					       struct rtnl_link_stats64 *stats)
#else
static struct net_device_stats *efx_net_stats(struct net_device *net_dev)
#endif
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_mac_stats *mac_stats = &efx->mac_stats;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_NETDEV_STATS64)
#if defined(EFX_USE_NETDEV_STATS)
	struct net_device_stats *stats = &net_dev->stats;
#else
	struct net_device_stats *stats = &efx->stats;
#endif
#endif
	spin_lock_bh(&efx->stats_lock);

	efx->type->update_stats(efx);

	stats->rx_packets = mac_stats->rx_packets;
	stats->tx_packets = mac_stats->tx_packets;
	stats->rx_bytes = mac_stats->rx_bytes;
	stats->tx_bytes = mac_stats->tx_bytes;
	stats->rx_dropped = efx->n_rx_nodesc_drop_cnt;
	stats->multicast = mac_stats->rx_multicast;
	stats->collisions = mac_stats->tx_collision;
	stats->rx_length_errors = (mac_stats->rx_gtjumbo +
				   mac_stats->rx_length_error);
	stats->rx_crc_errors = mac_stats->rx_bad;
	stats->rx_frame_errors = mac_stats->rx_align_error;
	stats->rx_fifo_errors = mac_stats->rx_overflow;
	stats->rx_missed_errors = mac_stats->rx_missed;
	stats->tx_window_errors = mac_stats->tx_late_collision;

	stats->rx_errors = (stats->rx_length_errors +
			    stats->rx_crc_errors +
			    stats->rx_frame_errors +
			    mac_stats->rx_symbol_error);
	stats->tx_errors = (stats->tx_window_errors +
			    mac_stats->tx_bad);

	spin_unlock_bh(&efx->stats_lock);

	return stats;
}

/* Context: netif_tx_lock held, BHs disabled. */
static void efx_watchdog(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	netif_err(efx, tx_err, efx->net_dev,
		  "TX stuck with port_enabled=%d: resetting channels\n",
		  efx->port_enabled);

	efx_schedule_reset(efx, RESET_TYPE_TX_WATCHDOG);
}


/* Context: process, rtnl_lock() held. */
static int efx_change_mtu(struct net_device *net_dev, int new_mtu)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	EFX_ASSERT_RESET_SERIALISED(efx);

	if (new_mtu > EFX_MAX_MTU)
		return -EINVAL;

	netif_dbg(efx, drv, efx->net_dev, "changing MTU to %d\n", new_mtu);

	efx_stop_all(efx);

	mutex_lock(&efx->mac_lock);
	/* Reconfigure the MAC before enabling the dma queues so that
	 * the RX buffers don't overflow */
	net_dev->mtu = new_mtu;
	efx->type->reconfigure_mac(efx);
	mutex_unlock(&efx->mac_lock);

	efx_start_all(efx);
	return 0;
}

static int efx_set_mac_address(struct net_device *net_dev, void *data)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct sockaddr *addr = data;
	u8 *new_addr = addr->sa_data;

	EFX_ASSERT_RESET_SERIALISED(efx);

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
		return -EINVAL;
	}

	memcpy(net_dev->dev_addr, new_addr, net_dev->addr_len);
	efx_sriov_mac_address_changed(efx);

	/* Reconfigure the MAC */
	mutex_lock(&efx->mac_lock);
	efx->type->reconfigure_mac(efx);
	mutex_unlock(&efx->mac_lock);

	return 0;
}

/* Context: netif_addr_lock held, BHs disabled. */
static void efx_set_rx_mode(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_DEV_MC_LIST)
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *ha;
#endif
	union efx_multicast_hash *mc_hash = &efx->multicast_hash;
	u32 crc;
	int bit;

	efx->promiscuous = !!(net_dev->flags & IFF_PROMISC);

	/* Build multicast hash table */
	if (efx->promiscuous || (net_dev->flags & IFF_ALLMULTI)) {
		memset(mc_hash, 0xff, sizeof(*mc_hash));
	} else {
		memset(mc_hash, 0x00, sizeof(*mc_hash));
		netdev_for_each_mc_addr(ha, net_dev) {
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_DEV_MC_LIST)
			crc = ether_crc_le(ETH_ALEN, ha->addr);
#else
			crc = ether_crc_le(ETH_ALEN, ha->dmi_addr);
#endif
			bit = crc & (EFX_MCAST_HASH_ENTRIES - 1);
			set_bit_le(bit, mc_hash->byte);
		}

		/* Broadcast packets go through the multicast hash filter.
		 * ether_crc_le() of the broadcast address is 0xbe2612ff
		 * so we always add bit 0xff to the mask.
		 */
		set_bit_le(0xff, mc_hash->byte);
	}

	if (efx->port_enabled)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
		schedule_work(&efx->mac_work);
#else
		queue_work(efx_workqueue, &efx->mac_work);
#endif
	/* Otherwise efx_start_port() will do this */
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
static int efx_set_features(struct net_device *net_dev, netdev_features_t data)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	/* If disabling RX n-tuple filtering, clear existing filters */
	if (net_dev->features & ~data & NETIF_F_NTUPLE)
		efx_filter_clear_rx(efx, EFX_FILTER_PRI_MANUAL);

	return 0;
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
static void
efx_vlan_rx_register(struct net_device *dev, struct vlan_group *vlan_group)
{
	struct efx_nic *efx = netdev_priv(dev);
	efx->vlan_group = vlan_group;
}

#ifdef EFX_USE_VLAN_RX_KILL_VID
static void efx_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	/* Nothing to do since we don't filter */
}
#endif

#endif /* EFX_NOT_UPSTREAM */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
static const struct net_device_ops efx_netdev_ops = {
	.ndo_open		= efx_net_open,
	.ndo_stop		= efx_net_stop,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64	= efx_net_stats,
#else
	.ndo_get_stats		= efx_net_stats,
#endif
	.ndo_tx_timeout		= efx_watchdog,
	.ndo_start_xmit		= efx_hard_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= efx_ioctl,
	.ndo_change_mtu		= efx_change_mtu,
	.ndo_set_mac_address	= efx_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode	= efx_set_rx_mode,
#else
	.ndo_set_multicast_list	= efx_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	.ndo_set_features	= efx_set_features,
#endif
#if defined(CONFIG_SFC_SRIOV) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC))
	.ndo_set_vf_mac		= efx_sriov_set_vf_mac,
	.ndo_set_vf_vlan	= efx_sriov_set_vf_vlan,
	.ndo_get_vf_config	= efx_sriov_get_vf_config,
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	.ndo_vlan_rx_register	= efx_vlan_rx_register,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = efx_netpoll,
#endif
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	= efx_filter_rfs,
#endif
};
#endif

static void efx_update_name(struct efx_nic *efx)
{
	strcpy(efx->name, efx->net_dev->name);
	efx_mtd_rename(efx);
	efx_set_channel_names(efx);
#ifdef CONFIG_SFC_DEBUGFS
	if (efx->debug_symlink) {
		efx_fini_debugfs_netdev(efx->net_dev);
		efx_init_debugfs_netdev(efx->net_dev);
	}
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
	struct net_device *net_dev = ptr;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	if (net_dev->netdev_ops == &efx_netdev_ops &&
	    event == NETDEV_CHANGENAME) {
#else
	if (net_dev->open == efx_net_open && event == NETDEV_CHANGENAME) {
#endif
		struct efx_nic *efx = netdev_priv(net_dev);

		if (efx->state == STATE_RUNNING)
			efx_update_name(efx);
	}

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
#ifdef NETIF_F_LRO
	if (enable != !!(efx->net_dev->features & NETIF_F_LRO)) {
		rtnl_lock();
		efx->net_dev->features ^= NETIF_F_LRO;
		netdev_features_change(efx->net_dev);
		rtnl_unlock();
	}
#else
	efx->lro_enabled = enable;
#endif
	return count;
}
static DEVICE_ATTR(lro, 0644, show_lro, set_lro);
#endif

static ssize_t
show_phy_type(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	return sprintf(buf, "%d\n", efx->phy_type);
}
static DEVICE_ATTR(phy_type, 0644, show_phy_type, NULL);

static int efx_register_netdev(struct efx_nic *efx)
{
	struct net_device *net_dev = efx->net_dev;
	struct efx_channel *channel;
	int rc;

	net_dev->watchdog_timeo = EFX_DEFAULT_WATCHDOG;
	net_dev->irq = efx->pci_dev->irq;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
	net_dev->netdev_ops = &efx_netdev_ops;
#else
	net_dev->open = efx_net_open;
	net_dev->stop = efx_net_stop;
	net_dev->get_stats = efx_net_stats;
	net_dev->tx_timeout = efx_watchdog;
	net_dev->hard_start_xmit = efx_hard_start_xmit;
	net_dev->do_ioctl = efx_ioctl;
	net_dev->change_mtu = efx_change_mtu;
	net_dev->set_mac_address = efx_set_mac_address;
	net_dev->set_multicast_list = efx_set_rx_mode;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	net_dev->vlan_rx_register = efx_vlan_rx_register;
#endif
#ifdef EFX_USE_VLAN_RX_KILL_VID
	net_dev->vlan_rx_kill_vid = efx_vlan_rx_kill_vid;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	net_dev->poll_controller = efx_netpoll;
#endif
#endif
	SET_ETHTOOL_OPS(net_dev, &efx_ethtool_ops);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	rc = efx_netq_init(efx);
	if (rc != 0)
		return rc;
#endif

	rtnl_lock();

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
	efx_dl_register_nic(efx);

	rtnl_unlock();

	/* Create debugfs symlinks */
	rc = efx_init_debugfs_netdev(net_dev);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev debugfs\n");
		goto fail_registered;
	}

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_phy_type);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail_debugfs;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_lro);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "failed to init net dev attributes\n");
		goto fail_attr_phy_type;
	}
#endif

	return 0;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
fail_attr_phy_type:
	device_remove_file(&efx->pci_dev->dev, &dev_attr_phy_type);
#endif
fail_debugfs:
	efx_fini_debugfs_netdev(net_dev);
fail_registered:
	rtnl_lock();
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
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;

	BUG_ON(netdev_priv(efx->net_dev) != efx);

	/* Free up any skbs still remaining. This has to happen before
	 * we try to unregister the netdev as running their destructors
	 * may be needed to get the device ref. count to 0. */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_tx_queue(tx_queue, channel)
			efx_release_tx_buffers(tx_queue);
	}

#if defined(EFX_NOT_UPSTREAM)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9) &&	\
	LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
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

	efx_stop_all(efx);
	mutex_lock(&efx->mac_lock);

	efx_stop_interrupts(efx, false);
	if (efx->port_initialized && method != RESET_TYPE_INVISIBLE)
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

	/* Ensure that SRAM is initialised even if we're disabling the device */
	rc = efx->type->init(efx);
	if (rc) {
		netif_err(efx, drv, efx->net_dev, "failed to initialise NIC\n");
		goto fail;
	}

	if (!ok)
		goto fail;

	if (efx->port_initialized && method != RESET_TYPE_INVISIBLE) {
		rc = efx->phy_op->init(efx);
		if (rc)
			goto fail;
		if (efx->phy_op->reconfigure(efx))
			EFX_FATAL(efx, drv, efx->net_dev,
				  "could not restore PHY settings\n");
	}

	efx->type->reconfigure_mac(efx);

	efx_start_interrupts(efx, false);
	efx_restore_filters(efx);
	efx_sriov_reset(efx);

	mutex_unlock(&efx->mac_lock);

	efx_start_all(efx);

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

	netif_device_detach(efx->net_dev);
	efx_reset_down(efx, method);

	rc = efx->type->reset(efx, method);
	if (rc) {
		netif_err(efx, drv, efx->net_dev, "failed to reset hardware\n");
		goto out;
	}

	/* Clear flags for the scopes we covered.  We assume the NIC and
	 * driver are now quiescent so that there is no race here.
	 */
	efx->reset_pending &= -(1 << (method + 1));

	/* Reinitialise bus-mastering, which may have been turned off before
	 * the reset was scheduled. This is still appropriate, even in the
	 * RESET_TYPE_DISABLE since this driver generally assumes the hardware
	 * can respond to requests. */
	pci_set_master(efx->pci_dev);

#if defined(EFX_NOT_UPSTREAM)
	if (method == RESET_TYPE_DISABLE && allow_zombie) {
		netif_err(efx, drv, efx->net_dev, "is now a zombie\n");
		method = RESET_TYPE_ALL;
	}
#endif

out:
	/* Leave device stopped if necessary */
	disabled = rc || method == RESET_TYPE_DISABLE;
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
		netif_device_attach(efx->net_dev);
	}
	efx_dl_reset_resume(efx, !disabled);
	return rc;
}

/* The worker thread exists so that code that cannot sleep can
 * schedule a reset for later.
 */
static void efx_reset_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, reset_work);
	unsigned long pending = ACCESS_ONCE(efx->reset_pending);

	if (!pending)
		return;

	/* If we're not RUNNING then don't reset. Leave the reset_pending
	 * flags set so that efx_pci_probe_main will be retried */
	if (efx->state != STATE_RUNNING) {
		netif_info(efx, drv, efx->net_dev,
			   "scheduled reset quenched. NIC not RUNNING\n");
		return;
	}

	rtnl_lock();
	(void)efx_reset(efx, fls(pending) - 1);
	rtnl_unlock();
}

void efx_schedule_reset(struct efx_nic *efx, enum reset_type type)
{
	enum reset_type method;

	switch (type) {
	case RESET_TYPE_INVISIBLE:
	case RESET_TYPE_ALL:
	case RESET_TYPE_WORLD:
	case RESET_TYPE_DISABLE:
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

	/* efx_process_channel() will no longer read events once a
	 * reset is scheduled. So switch back to poll'd MCDI completions. */
	efx_mcdi_mode_poll(efx);

	queue_work(reset_workqueue, &efx->reset_work);
}

/**************************************************************************
 *
 * List of NICs we support
 *
 **************************************************************************/

/* PCI device ID table */
static DEFINE_PCI_DEVICE_TABLE(efx_pci_table) = {
#ifndef __VMKERNEL_MODULE__
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE,
		    PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0),
	 .driver_data = (unsigned long) &falcon_a1_nic_type},
#endif
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE,
		    PCI_DEVICE_ID_SOLARFLARE_SFC4000B),
	 .driver_data = (unsigned long) &falcon_b0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, BETHPAGE_A_P_DEVID),
	 .driver_data = (unsigned long) &siena_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, SIENA_A_P_DEVID),
	 .driver_data = (unsigned long) &siena_a0_nic_type},
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
int efx_port_dummy_op_int(struct efx_nic *efx)
{
	return 0;
}
void efx_port_dummy_op_void(struct efx_nic *efx) {}

static bool efx_port_dummy_op_poll(struct efx_nic *efx)
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
static int efx_init_struct(struct efx_nic *efx, const struct efx_nic_type *type,
			   struct pci_dev *pci_dev, struct net_device *net_dev)
{
	int i;

	/* Initialise common structures */
	memset(efx, 0, sizeof(*efx));
	spin_lock_init(&efx->biu_lock);
#ifdef CONFIG_SFC_MTD
	INIT_LIST_HEAD(&efx->mtd_list);
#endif
	INIT_WORK(&efx->reset_work, efx_reset_work);
	INIT_DELAYED_WORK(&efx->monitor_work, efx_monitor);
	INIT_DELAYED_WORK(&efx->selftest_work, efx_selftest_async_work);
	efx->pci_dev = pci_dev;
	efx->msg_enable = debug;
	efx->state = STATE_INIT;
	strlcpy(efx->name, pci_name(pci_dev), sizeof(efx->name));

	efx->net_dev = net_dev;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_SET_FEATURES)
	efx->rx_checksum_enabled = true;
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_SFC_LRO) && !defined(NETIF_F_LRO)
	efx->lro_enabled = lro;
#endif
	efx->rx_buffer_hash_size = type->rx_buffer_hash_size;
	spin_lock_init(&efx->stats_lock);
	mutex_init(&efx->mac_lock);
	efx->phy_op = &efx_dummy_phy_operations;
	efx->mdio.dev = net_dev;
	INIT_LIST_HEAD(&efx->dl_node);
	INIT_LIST_HEAD(&efx->dl_device_list);
	INIT_WORK(&efx->mac_work, efx_mac_work);
	init_waitqueue_head(&efx->flush_wq);

	for (i = 0; i < EFX_MAX_CHANNELS; i++) {
		/* TODO: NUMA affinity */
		efx->channel[i] = efx_alloc_channel(efx, i, NULL);
		if (!efx->channel[i])
			goto fail;
	}

	efx->type = type;

	EFX_BUG_ON_PARANOID(efx->type->phys_addr_channels > EFX_MAX_CHANNELS);

	/* Higher numbered interrupt modes are less capable! */
	efx->interrupt_mode = max(efx->type->max_interrupt_mode,
				  interrupt_mode);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_DUMMY_MSIX)
	if (efx->interrupt_mode == EFX_INT_MODE_MSIX)
		efx->interrupt_mode = EFX_INT_MODE_MSI;
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

	if (efx->vpd_sn)
		kfree(efx->vpd_sn);
}

#if defined(EFX_NOT_UPSTREAM)

/**************************************************************************
 *
 * Automatic loading of the sfc_tune driver
 *
 **************************************************************************/

static void efx_probe_tune(struct work_struct *data)
{
	if (request_module("sfc_tune"))
		printk(KERN_ERR "Unable to autoprobe sfc_tune driver. "
		       "Expect reduced performance on Falcon/A1\n");
}

static struct work_struct probe_tune;
enum {
	PROBE_TUNE_WANT,
	PROBE_TUNE_ENABLE,
};

static void efx_schedule_probe_tune(int what)
{
	static bool wanted;
	static bool enabled;
	bool kick;

	rtnl_lock();
	if (what == PROBE_TUNE_WANT) {
		kick = enabled && !wanted;
		wanted = true;
	} else {
		kick = wanted;
		enabled = true;
	}
	rtnl_unlock();

	if (!kick)
		return;

	INIT_WORK(&probe_tune, efx_probe_tune);
	schedule_work(&probe_tune);
}

#endif

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

	return pci_read_vpd(dev, pos, count, (void *)buf);
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

/* NIC VPD information
 * Called during probe to display the serial/part numbers of the
 * installed NICs, It is expeted that the required will be at the start
 */
#define SFC_VPD_LEN	512
static void efx_print_product_vpd(struct efx_nic *efx)
{
	struct pci_dev *dev = efx->pci_dev;
	char vpd_data[SFC_VPD_LEN];
	int vpd_size;
	int ro_start, ro_size, i, j;

	/* Get the vpd data from the device */
	vpd_size = pci_read_vpd(dev, 0, sizeof(vpd_data), vpd_data);

	if (vpd_size <= 0) {
		netif_err(efx, drv, efx->net_dev, "Unable to read VPD\n");
		return;
	}

	/* Get the Read only section */
	ro_start = pci_vpd_find_tag(vpd_data, 0, vpd_size,
				    PCI_VPD_LRDT_RO_DATA);

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

	if (efx->vpd_sn)
		return;
 
	efx->vpd_sn = kmalloc(j++, GFP_ATOMIC);
	if (!efx->vpd_sn) {
		netif_err(efx, drv, efx->net_dev, "Unabled to allocate SN memory\n");
		return;
	}

	snprintf(efx->vpd_sn, j, "%s", &vpd_data[i]);
}

/* Main body of final NIC shutdown code
 * This is called only at module unload (or hotplug removal).
 */
static void efx_pci_remove_main(struct efx_nic *efx)
{
#ifdef CONFIG_RFS_ACCEL
	free_irq_cpu_rmap(efx->net_dev->rx_cpu_rmap);
	efx->net_dev->rx_cpu_rmap = NULL;
#endif
	efx_stop_interrupts(efx, false);
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)
	efx_clear_interrupt_affinity(efx);
#endif
	efx_nic_fini_interrupt(efx);
	efx_fini_port(efx);
	efx->type->fini(efx);
	efx_fini_napi(efx);
	efx_remove_all(efx);
}

/* Final NIC shutdown
 * This is called only at module unload (or hotplug removal).
 */
static void efx_pci_remove(struct pci_dev *pci_dev)
{
	struct efx_nic *efx;

	efx = pci_get_drvdata(pci_dev);
	if (!efx)
		return;

	/* Mark the NIC as fini, then stop the interface */
	rtnl_lock();
	efx_dl_unregister_nic(efx);
	efx->state = STATE_FINI;
	dev_close(efx->net_dev);

	/* Allow any queued efx_resets() to complete */
	rtnl_unlock();

	efx_stop_interrupts(efx, false);
	efx_sriov_fini(efx);
	efx_unregister_netdev(efx);

	efx_mtd_remove(efx);
	efx_fini_debugfs_channels(efx);

	/* Wait for any scheduled resets to complete. No more will be
	 * scheduled from this point because efx_stop_all() has been
	 * called, we are no longer registered with driverlink, and
	 * the net_device's have been removed. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&efx->reset_work);
#else
	flush_workqueue(reset_workqueue);
#endif

	efx_pci_remove_main(efx);

	efx_fini_io(efx);
	netif_dbg(efx, drv, efx->net_dev, "shutdown successful\n");

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)
	efx_pci_vpd_remove(efx);
#endif
	efx_fini_struct(efx);
	pci_set_drvdata(pci_dev, NULL);
	free_netdev(efx->net_dev);
};

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

#if defined(EFX_NOT_UPSTREAM)
	if (efx_nic_rev(efx) < EFX_REV_FALCON_B0) {
		/* Try and auto-probe the sfc_tune driver, so by default
		 * users see high performance on A1 cards */
		efx_schedule_probe_tune(PROBE_TUNE_WANT);
	}
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
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP) && !defined(__VMKLNX__)
	efx_set_interrupt_affinity(efx);
#endif
	efx_start_interrupts(efx, false);

	return 0;

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

/* NIC initialisation
 *
 * This is called at module load (or hotplug insertion,
 * theoretically).  It sets up PCI mappings, resets the NIC,
 * sets up and registers the network devices with the kernel and hooks
 * the interrupt service routine.  It does not prepare the device for
 * transmission; this is left to the first time one of the network
 * interfaces is brought up (i.e. efx_net_open).
 */
static int __devinit efx_pci_probe(struct pci_dev *pci_dev,
				   const struct pci_device_id *entry)
{
	const struct efx_nic_type *type = (const struct efx_nic_type *) entry->driver_data;
	struct net_device *net_dev;
	struct efx_nic *efx;
	int i, rc;

	/* Allocate and initialise a struct net_device and struct efx_nic */
	net_dev = alloc_etherdev_mq(sizeof(*efx), EFX_MAX_CORE_TX_QUEUES);
	if (!net_dev)
		return -ENOMEM;
	net_dev->features |= (type->offload_features | NETIF_F_SG |
			      NETIF_F_HIGHDMA | NETIF_F_TSO |
			      NETIF_F_RXCSUM);
	if (type->offload_features & NETIF_F_V6_CSUM)
		net_dev->features |= NETIF_F_TSO6;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_GRO)
	if (lro)
		net_dev->features |= NETIF_F_GRO;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO) && defined(NETIF_F_LRO)
	if (lro)
		net_dev->features |= NETIF_F_LRO;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	net_dev->features |= NETIF_F_HW_VLAN_RX;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES)
	/* Mask for features that also apply to VLAN devices */
	net_dev->vlan_features |= (NETIF_F_ALL_CSUM | NETIF_F_SG |
				   NETIF_F_HIGHDMA | NETIF_F_ALL_TSO |
				   NETIF_F_RXCSUM);
#else
	/* Alternative to vlan_features in RHEL 5.5+ */
#if defined(NETIF_F_VLAN_CSUM)
	net_dev->features |= NETIF_F_VLAN_CSUM;
#endif
#if defined(NETIF_F_VLAN_TSO)
	net_dev->features |= NETIF_F_VLAN_TSO;
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	/* All offloads can be toggled */
	net_dev->hw_features = net_dev->features & ~NETIF_F_HIGHDMA;
#endif
	efx = netdev_priv(net_dev);
	pci_set_drvdata(pci_dev, efx);
	SET_NETDEV_DEV(net_dev, &pci_dev->dev);
	rc = efx_init_struct(efx, type, pci_dev, net_dev);
	if (rc)
		goto fail1;

	netif_info(efx, probe, efx->net_dev,
		   "Solarflare NIC detected PCI(%x:%x)\n",
		   pci_dev->vendor, pci_dev->device);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_PCI_VPD_ATTR)
	efx_pci_vpd_probe(efx); /* allowed to fail */
#endif

	efx_print_product_vpd(efx);

	/* Set up basic I/O (BAR mappings etc) */
	rc = efx_init_io(efx);
	if (rc)
		goto fail2;

	/* No serialisation is required with the reset path because
	 * we're in STATE_INIT. */
	for (i = 0; i < 5; i++) {
		rc = efx_pci_probe_main(efx);

		/* Serialise against efx_reset(). No more resets will be
		 * scheduled since efx_stop_all() has been called, and we
		 * have not and never have been registered with either
		 * the rtnetlink or driverlink layers. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
		cancel_work_sync(&efx->reset_work);
#else
		flush_workqueue(reset_workqueue);
#endif

		if (rc == 0) {
			if (efx->reset_pending) {
				/* If there was a scheduled reset during
				 * probe, the NIC is probably hosed anyway */
				efx_pci_remove_main(efx);
				rc = -EIO;
			} else {
				break;
			}
		}

		/* Retry if a recoverably reset event has been scheduled */
		if (efx->reset_pending &
		    ~(1 << RESET_TYPE_INVISIBLE | 1 << RESET_TYPE_ALL) ||
		    !efx->reset_pending) {
			if (efx->reset_pending)
				netif_err(efx, probe, efx->net_dev,
					  "Unrecoverable scheduled reset: %s\n",
					  RESET_TYPE(fls(efx->reset_pending) - 1));
			goto fail3;
		}

		efx->reset_pending = 0;
	}

	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "Initialisation failed due to persistent reset\n");
		goto fail4;
	}

	rc = efx_init_debugfs_channels(efx);
	if (rc)
		goto fail5;

	/* Switch to the running state before we expose the device to the OS,
	 * so that dev_open()|efx_start_all() will actually start the device */
	efx->state = STATE_RUNNING;
#ifdef EFX_NOT_UPSTREAM
	if (efx_ignore_nvconfig)
		efx->state = STATE_DISABLED;
#endif

	rc = efx_register_netdev(efx);
	if (rc)
		goto fail6;

	if (efx->vf_count) {
		rc = efx_sriov_init(efx);
		if (rc) {
			netif_err(efx, probe, efx->net_dev,
				  "SR-IOV can't be enabled rc %d\n", rc);
			efx->vf_count = 0;
		}
	}

	netif_info(efx, probe, efx->net_dev,
		   "is Solarflare NIC PCI(%x:%x)\n",
		   pci_dev->vendor, pci_dev->device);

	/* Try to create MTDs, but allow this to fail */
	rtnl_lock();
	rc = efx_mtd_probe(efx);
	rtnl_unlock();
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_MTD_TABLE)
	if (rc == -EBUSY)
		netif_warn(efx, probe, efx->net_dev,
			   "kernel MTD table is full; flash will not be acccessible\n");
	else
#endif
	if (rc)
		netif_warn(efx, probe, efx->net_dev,
			   "failed to create MTDs (%d)\n", rc);

	return 0;

 fail6:
	efx_fini_debugfs_channels(efx);
 fail5:
	efx_pci_remove_main(efx);
 fail4:
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

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_PM)

static int efx_pm_freeze(struct device *dev)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	rtnl_lock();
	efx_dl_reset_suspend(efx);
	rtnl_unlock();

	efx->state = STATE_FINI;

	netif_device_detach(efx->net_dev);

	efx_stop_all(efx);
	efx_stop_interrupts(efx, false);

	return 0;
}

static int efx_pm_thaw(struct device *dev)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	efx->state = STATE_INIT;

	efx_start_interrupts(efx, false);

	mutex_lock(&efx->mac_lock);
	efx->phy_op->reconfigure(efx);
	mutex_unlock(&efx->mac_lock);

	efx_start_all(efx);

	netif_device_attach(efx->net_dev);

	efx->state = STATE_RUNNING;

	rtnl_lock();
	efx_dl_reset_resume(efx, true);
	rtnl_unlock();

	efx->type->resume_wol(efx);

	/* Reschedule any quenched resets scheduled during efx_pm_freeze() */
	queue_work(reset_workqueue, &efx->reset_work);

	return 0;
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
	efx_pm_thaw(dev);
	return 0;

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

static struct dev_pm_ops efx_pm_ops = {
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

static struct pci_driver efx_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= efx_pci_table,
	.probe		= efx_pci_probe,
	.remove		= efx_pci_remove,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEV_PM_OPS)
	.driver.pm	= &efx_pm_ops,
#elif defined(EFX_USE_PM_EXT_OPS)
	.pm		= &efx_pm_ops,
#elif defined(EFX_USE_PM)
	.suspend	= efx_pm_old_suspend,
	.resume		= efx_pm_old_resume,
#endif
};

/**************************************************************************
 *
 * Kernel module interface
 *
 *************************************************************************/

#ifdef EFX_NOT_UPSTREAM

module_param(napi_weight, int, 0444);
MODULE_PARM_DESC(napi_weight, "NAPI weighting");

module_param_named(monitor_interval, efx_monitor_interval, uint, 0644);
MODULE_PARM_DESC(monitor_interval, "Hardware monitor interval (in jiffies)");

module_param(allow_bad_hwaddr, uint, 0644);
MODULE_PARM_DESC(allow_bad_hwaddr,
		 "Initialise devices with bad MAC addresses");

module_param(allow_zombie, uint, 0644);
MODULE_PARM_DESC(allow_zombie, "Reanimate dead devices");

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
	if (rc)
		goto err_notifier;

	rc = efx_init_sriov();
	if (rc)
		goto err_sriov;

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
	efx_workqueue = create_singlethread_workqueue("sfc_wq");
	if (!efx_workqueue) {
		rc = -ENOMEM;
		goto err_wq;
	}
#endif

	reset_workqueue = create_singlethread_workqueue("sfc_reset");
	if (!reset_workqueue) {
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
	if (rc < 0)
		goto err_lm87;
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_LM90_DRIVER)
	rc = i2c_add_driver(&efx_lm90_driver);
	if (rc < 0)
		goto err_lm90;
#endif
#endif /* CONFIG_SFC_HWMON */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_I2C_NEW_DUMMY)
	rc = i2c_add_driver(&efx_i2c_dummy_driver);
	if (rc < 0)
		goto err_i2c_dummy;
#endif

#if defined(EFX_NOT_UPSTREAM)
	rc = efx_control_init();
	if (rc)
		goto err_control;
#endif
	rc = pci_register_driver(&efx_pci_driver);
	if (rc < 0)
		goto err_pci;

#ifdef EFX_NOT_UPSTREAM
	efx_schedule_probe_tune(PROBE_TUNE_ENABLE);
#endif

	return 0;

 err_pci:
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
