/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
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
#ifdef EFX_WORKAROUND_87308
#include <asm-generic/atomic.h>
#endif
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_ADD_VXLAN_PORT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
#include <net/gre.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
#include <net/udp_tunnel.h>
#endif
#include "debugfs.h"
#ifdef CONFIG_SFC_DUMP
#include "dump.h"
#endif
#include "efx.h"
#include "nic.h"
#include "io.h"
#include "selftest.h"
#include "sriov.h"
#ifdef EFX_USE_KCOMPAT
#include "efx_ioctl.h"
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_GCOV)
#include "../linux/gcov.h"
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

/* Default stats update time */
#define STATS_PERIOD_MS_DEFAULT 1000

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

#ifdef EFX_NOT_UPSTREAM
/* Allocate resources for XDP transmit and redirect functionality.
 *
 * This allocates a transmit queue per CPU and enough event queues to cover
 * those - multiple transmit queues will share a single event queue.
 */
bool xdp_alloc_tx_resources;
module_param(xdp_alloc_tx_resources, bool, 0444);
MODULE_PARM_DESC(xdp_alloc_tx_resources,
		 "[EXPERIMENTAL] Allocate resources for XDP TX");
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

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_core_cpumask))
#define HAVE_EFX_NUM_PACKAGES
#endif
#if !defined(EFX_USE_KCOMPAT) || (defined(topology_sibling_cpumask) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP))
#define HAVE_EFX_NUM_CORES
#endif

/* This is the requested number of CPUs to use for Receive-Side Scaling
 * (RSS), i.e. the number of CPUs among which we may distribute
 * simultaneous interrupt handling.  Or alternatively it may be set to
 * "packages", "cores", "hyperthreads", "numa_local_cores" or
 * "numa_local_hyperthreads" to get one receive channel per package, core,
 * hyperthread, numa local core or numa local hyperthread.  The default
 * is "cores".
 *
 * Systems without MSI-X will only target one CPU via legacy or MSI
 * interrupt.
 */
static char *rss_cpus;
module_param(rss_cpus, charp, 0444);
MODULE_PARM_DESC(rss_cpus, "Number of CPUs to use for Receive-Side Scaling, or 'packages', 'cores', 'hyperthreads', 'numa_local_cores' or 'numa_local_hyperthreads'");

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
static int efx_start_all(struct efx_nic *efx);
static void efx_stop_all(struct efx_nic *efx);

#ifdef EFX_USE_IRQ_NOTIFIERS
static void efx_unregister_irq_notifiers(struct efx_nic *efx);
static void efx_set_affinity_notifier(struct efx_channel *channel);
static void efx_clear_affinity_notifier(struct efx_channel *channel);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
static int efx_xdp_setup_prog(struct efx_nic *efx, struct bpf_prog *prog);
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

/** Check queue size for range and rounding.
 *
 *  If #fix is set it will clamp and round as required.
 *  Regardless of #fix this will return an error code if the value is
 *  invalid.
 */
int efx_check_queue_size(struct efx_nic *efx, u32 *entries,
			 u32 min, u32 max, bool fix)
{
	if (*entries < min || *entries > max) {
		if (fix)
			*entries = clamp_t(u32, *entries, min, max);
		return -ERANGE;
	}

	if (!is_power_of_2(*entries)) {
		if (fix)
			*entries = roundup_pow_of_two(*entries);
		return -EINVAL;
	}

	return 0;
}

#ifdef EFX_NOT_UPSTREAM
/* Is Driverlink supported on this device? */
static bool efx_dl_supported(struct efx_nic *efx)
{
	/* VI spreading will confuse driverlink clients, so prevent
	 * registration if it's in use.
	 */
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_TX_ONLY_VI_SPREADING_ENABLED)) {
		netif_info(efx, drv, efx->net_dev,
			   "Driverlink disabled: VI spreading in use\n");
		return false;
	}

	return efx->dl_info != NULL;
}
#endif


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
	struct netdev_queue *core_txq;
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
		 * so use READ_ONCE() in this loop to avoid optimizations that
		 * would avoid reading the latest values from memory.
		 */

		/* There are unsent packets, for this to be set
		 * the xmit thread knows we are running
		 */
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (READ_ONCE(tx_queue->notify_count) !=
			    READ_ONCE(tx_queue->write_count)) {
				efx_nic_notify_tx_desc(tx_queue);
				++tx_queue->doorbell_notify_comp;
			}
		}
		channel->holdoff_doorbell = false;
		smp_mb();
		efx_for_each_channel_tx_queue(tx_queue, channel)
			unsent += READ_ONCE(tx_queue->write_count) -
				  READ_ONCE(tx_queue->notify_count);
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
	smp_rmb(); /* ensure netdev_tx_sent updates are seen */
	efx_for_each_channel_tx_queue(tx_queue, channel) {
		if (tx_queue->bytes_compl && tx_queue->core_txq) {
			netdev_tx_completed_queue(tx_queue->core_txq,
				tx_queue->pkts_compl, tx_queue->bytes_compl);
		}
	}

	if (channel->tx_queues) {
		core_txq = channel->tx_queues[0].core_txq;
		fill_level = efx_channel_tx_fill_level(channel);

		/* See if we need to restart the netif queue. */
		if ((fill_level <= efx->txq_wake_thresh) &&
		    likely(core_txq) &&
		    unlikely(netif_tx_queue_stopped(core_txq)) &&
		    likely(efx->port_enabled) &&
		    likely(netif_device_present(efx->net_dev)))
		    netif_tx_wake_queue(core_txq);
	}

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

static int efx_poll(struct napi_struct *napi, int budget)
{
	struct efx_channel *channel =
		container_of(napi, struct efx_channel, napi_str);
	struct efx_nic *efx = channel->efx;
#ifdef CONFIG_RFS_ACCEL
	unsigned int time;
#endif
	int spent;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	if (!efx_channel_lock_napi(channel))
		return budget;
#endif

	netif_vdbg(efx, intr, efx->net_dev,
		   "channel %d NAPI poll executing on CPU %d\n",
		   channel->channel, raw_smp_processor_id());

	spent = efx_process_channel(channel, budget);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	xdp_do_flush_map();
#endif

	if (spent < budget) {
		if (efx_channel_has_rx_queue(channel) &&
		    efx->irq_rx_adaptive &&
		    unlikely(++channel->irq_count == irq_adapt_irqs)) {
			efx_update_irq_mod(efx, channel);
		}

#ifdef CONFIG_RFS_ACCEL
		/* Perhaps expire some ARFS filters */
		time = jiffies - channel->rfs_last_expiry;
		/* Would our quota be >= 20? */
		if (channel->rfs_filter_count * time >= 600 * HZ)
			mod_delayed_work(system_wq, &channel->filter_work, 0);
#endif

		/* There is no race here; although napi_disable() will
		 * only wait for napi_complete(), this isn't a problem
		 * since efx_nic_eventq_read_ack() will have no effect if
		 * interrupts have already been disabled.
		 */
		if (napi_complete_done(napi, spent))
			efx_nic_eventq_read_ack(channel);
	}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_unlock_napi(channel);
#endif
	return spent;
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
	if (efx_channel_has_rx_queue(channel))
		entries = efx->rxq_entries;
	else
		entries = 0;

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

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_enable(channel);
#endif
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
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	while (!efx_channel_disable(channel))
		usleep_range(1000, 20000);
	efx_channel_unlock_napi(channel);

#ifdef CONFIG_NET_RX_BUSY_POLL
	if (channel->busy_poll_state != (1 << EFX_CHANNEL_STATE_DISABLE_BIT))
		netif_err(channel->efx, drv, channel->efx->net_dev,
			  "chan %d bad state %#lx\n", channel->channel,
			  channel->busy_poll_state);
#endif
#endif
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

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	channel->efx = efx;
	channel->channel = i;
	channel->type = &efx_default_channel_type;
	channel->holdoff_doorbell = false;
	channel->tx_coalesce_doorbell = false;
	channel->irq_mem_node = NUMA_NO_NODE;
#ifdef CONFIG_RFS_ACCEL
	INIT_DELAYED_WORK(&channel->filter_work, efx_filter_rfs_expire);
#endif

	channel->rx_queue.efx = efx;

	return channel;
}

/* Allocate and initialise a channel structure, copying parameters
 * (but not resources) from an old channel structure.
 */
static struct efx_channel *
efx_copy_channel(struct efx_channel *old_channel)
{
	struct efx_tx_queue *new_tx_queues;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;
	struct efx_channel *channel;

	channel = kmalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	if (old_channel->tx_queue_count) {
		new_tx_queues = kcalloc(old_channel->tx_queue_count,
					sizeof(*new_tx_queues), GFP_KERNEL);
		if (!new_tx_queues) {
			kfree(channel);
			return NULL;
		}
	} else {
		new_tx_queues = NULL;
	}

#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_clear_affinity_notifier(old_channel);
#endif

	*channel = *old_channel;

	channel->napi_dev = NULL;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NAPI_STRUCT_NAPI_ID)
	INIT_HLIST_NODE(&channel->napi_str.napi_hash_node);
	channel->napi_str.napi_id = 0;
	channel->napi_str.state = 0;
#endif
	memset(&channel->eventq, 0, sizeof(channel->eventq));

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* Invalidate SSR state */
	channel->ssr.conns = NULL;
#endif

	if (channel->tx_queue_count) {
		channel->tx_queues = new_tx_queues;
		memcpy(channel->tx_queues, old_channel->tx_queues,
		       channel->tx_queue_count * sizeof(*tx_queue));

		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (tx_queue->channel)
				tx_queue->channel = channel;
			tx_queue->buffer = NULL;
			tx_queue->cb_page = NULL;
			memset(&tx_queue->txd, 0, sizeof(tx_queue->txd));
		}
	} else {
		channel->tx_queues = NULL;
	}

	rx_queue = &channel->rx_queue;
	rx_queue->buffer = NULL;
	memset(&rx_queue->rxd, 0, sizeof(rx_queue->rxd));

#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_set_affinity_notifier(channel);
#endif
#ifdef CONFIG_RFS_ACCEL
	INIT_DELAYED_WORK(&channel->filter_work, efx_filter_rfs_expire);
#endif

	return channel;
}

static void efx_fini_channel(struct efx_channel *channel)
{
}

static int efx_probe_channel(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_nic *efx;
	int rc;

	efx = channel->efx;

	netif_dbg(efx, probe, efx->net_dev,
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

	if (efx->xdp_channel_offset && number >= efx->xdp_channel_offset) {
		type = "-xdp";
		number -= efx->xdp_channel_offset;
	} else if (efx->tx_channel_offset == 0) {
		type = "";
	} else if (number < efx->tx_channel_offset) {
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
static int efx_start_datapath(struct efx_nic *efx)
{
	bool old_rx_scatter = efx->rx_scatter;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_channel *channel;
	size_t rx_page_buf_step;
	int rc = 0;
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
	rx_page_buf_step = efx_rx_buffer_step(efx);
	if (rx_page_buf_step <= PAGE_SIZE) {
		efx->rx_scatter = efx->type->always_rx_scatter;
		efx->rx_buffer_order = 0;
	} else if (efx->type->can_rx_scatter) {
		BUILD_BUG_ON(EFX_RX_USR_BUF_SIZE % L1_CACHE_BYTES);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		BUILD_BUG_ON(sizeof(struct efx_rx_page_state) +
			     2 * ALIGN(NET_IP_ALIGN + EFX_RX_USR_BUF_SIZE,
				       EFX_RX_BUF_ALIGNMENT) >
			     PAGE_SIZE);
#endif
		efx->rx_scatter = true;
		efx->rx_dma_len = EFX_RX_USR_BUF_SIZE;
		efx->rx_buffer_order = 0;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx->lro_available = false;
#endif
	} else {
		efx->rx_scatter = false;
		efx->rx_buffer_order = get_order(rx_page_buf_step);
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
	efx->txq_stop_thresh = efx->txq_entries -
			       efx->type->tx_max_skb_descs(efx);
	efx->txq_wake_thresh = efx->txq_stop_thresh / 2;

	/* Initialise the channels */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			rc = efx_init_tx_queue(tx_queue);
			if (rc)
				goto fail;
			atomic_inc(&efx->active_queues);
		}

		efx_for_each_channel_rx_queue(rx_queue, channel) {
			rc = efx_init_rx_queue(rx_queue);
			if (rc)
				goto fail;
			atomic_inc(&efx->active_queues);
			efx_stop_eventq(channel);
			efx_fast_push_rx_descriptors(rx_queue, false);
			efx_start_eventq(channel);
		}
	}

	efx_ptp_start_datapath(efx);

	if (netif_device_present(efx->net_dev))
		netif_tx_wake_all_queues(efx->net_dev);

	goto out;

fail:
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (atomic_read(&efx->active_queues) == 0)
				goto out;
			efx_remove_tx_queue(tx_queue);
			atomic_dec(&efx->active_queues);
		}

		efx_for_each_channel_rx_queue(rx_queue, channel) {
			if (atomic_read(&efx->active_queues) == 0)
				goto out;
			efx_remove_rx_queue(rx_queue);
			atomic_dec(&efx->active_queues);
		}
	}

out:
	return rc;
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
	if (rc) {
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

	efx_for_each_channel_rx_queue(rx_queue, channel) {
		efx_remove_rx_queue(rx_queue);
		efx_destroy_rx_queue(rx_queue);
	}
	efx_for_each_channel_tx_queue(tx_queue, channel) {
		efx_remove_tx_queue(tx_queue);
		efx_destroy_tx_queue(tx_queue);
	}
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

	kfree(efx->xdp_tx_queues);
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
			kfree(channel->tx_queues);
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
#ifdef EFX_USE_IRQ_NOTIFIERS
		efx_set_affinity_notifier(efx->channel[i]);
#endif
	}
	goto out;
}

void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	schedule_delayed_work(&rx_queue->slow_fill_work,
                                msecs_to_jiffies(1));
#else
	queue_delayed_work(efx_workqueue, &rx_queue->slow_fill_work,
                                msecs_to_jiffies(1));
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
	bool kernel_link_up;

	/* SFC Bug 5356: A net_dev notifier is registered, so we must ensure
	 * that no events are triggered between unregister_netdev() and the
	 * driver unloading. A more general condition is that NETDEV_CHANGE
	 * can only be generated between NETDEV_UP and NETDEV_DOWN */
	if (!netif_running(efx->net_dev))
		return;

	kernel_link_up = netif_carrier_ok(efx->net_dev);

	if (link_state->up != kernel_link_up) {
		efx->n_link_state_changes++;

		if (link_state->up)
			netif_carrier_on(efx->net_dev);
		else
			netif_carrier_off(efx->net_dev);
	}

	/* Status message for kernel log */
	if (!net_ratelimit())
		return;

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
	} else if (kernel_link_up) {
		netif_info(efx, link, efx->net_dev, "link down%s\n",
			   (efx->phy_mode & PHY_MODE_LOW_POWER) ? " [OFF]" : "");
	}

}

void efx_link_set_advertising(struct efx_nic *efx,
			      const unsigned long *advertising)
{
	memcpy(efx->link_advertising, advertising,
	       sizeof(__ETHTOOL_DECLARE_LINK_MODE_MASK()));
	if (advertising[0] & ADVERTISED_Autoneg) {
		if (advertising[0] & ADVERTISED_Pause)
			efx->wanted_fc |= (EFX_FC_TX | EFX_FC_RX);
		else
			efx->wanted_fc &= ~(EFX_FC_TX | EFX_FC_RX);
		if (advertising[0] & ADVERTISED_Asym_Pause)
			efx->wanted_fc ^= EFX_FC_TX;
	}
}

void efx_link_set_wanted_fc(struct efx_nic *efx, u8 wanted_fc)
{
	efx->wanted_fc = wanted_fc;
	if (efx->link_advertising[0] & ADVERTISED_Autoneg) {
		if (wanted_fc & EFX_FC_RX)
			efx->link_advertising[0] |= (ADVERTISED_Pause |
						     ADVERTISED_Asym_Pause);
		else
			efx->link_advertising[0] &= ~(ADVERTISED_Pause |
						      ADVERTISED_Asym_Pause);
		if (wanted_fc & EFX_FC_TX)
			efx->link_advertising[0] ^= ADVERTISED_Asym_Pause;
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

	/* Connect up MAC/PHY operations table */
	rc = efx->type->probe_port(efx);
	if (rc)
		return rc;

	/* Initialise MAC address to permanent address */
	ether_addr_copy(efx->net_dev->dev_addr, efx->net_dev->perm_addr);

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
	efx->port_initialized = false;
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

/* This configures the PCI device to enable I/O and DMA. */
static int efx_init_io(struct efx_nic *efx)
{
	struct pci_dev *pci_dev = efx->pci_dev;
	dma_addr_t dma_mask = efx->type->max_dma_mask;
	unsigned int mem_map_size = efx->type->mem_map_size(efx);
	int rc, bar;

	netif_dbg(efx, probe, efx->net_dev, "initialising I/O\n");

	bar = efx->type->mem_bar(efx);
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
	if (!efx->membase_phys) {
		netif_err(efx, probe, efx->net_dev,
			  "ERROR: No BAR%d mapping from the BIOS. "
			  "Try pci=realloc on the kernel command line\n", bar);
		rc = -ENODEV;
		goto fail3;
	}
	rc = pci_request_region(pci_dev, bar, "sfc");

	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "request for memory BAR failed\n");
		rc = -EIO;
		goto fail3;
	}
#if defined(EFX_USE_KCOMPAT)
	efx->membase = efx_ioremap(efx->membase_phys, mem_map_size);
#else
	efx->membase = ioremap(efx->membase_phys, mem_map_size);
#endif
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
		bar = efx->type->mem_bar(efx);
		pci_release_region(efx->pci_dev, bar);
		efx->membase_phys = 0;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	/* Don't disable bus-mastering if VFs are assigned */
	if (!pci_vfs_assigned(efx->pci_dev))
#endif
		pci_disable_device(efx->pci_dev);
}

void efx_set_default_rx_indir_table(struct efx_nic *efx,
				    struct efx_rss_context *ctx)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->rx_indir_table); i++)
		ctx->rx_indir_table[i] =
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
	struct net_device *net_dev = efx->net_dev;

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
	} else if (strcmp(rss_cpus, "numa_local_cores") == 0) {
		efx->rss_mode = EFX_RSS_NUMA_LOCAL_CORES;
		selected = true;
	} else if (strcmp(rss_cpus, "numa_local_hyperthreads") == 0) {
		efx->rss_mode = EFX_RSS_NUMA_LOCAL_HYPERTHREADS;
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
#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_CORES)
	case EFX_RSS_NUMA_LOCAL_CORES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Creating rss channels for half of cores/hyperthreads.\n");
			n_rxq = max_t(int, 1, num_online_cpus() / 2);
		} else {
			n_rxq = min(efx_num_cores(cpu_online_mask),
			            efx_num_cores(cpumask_of_pcibus(efx->pci_dev->bus)));
		}
		break;
#endif
#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS))
	case EFX_RSS_NUMA_LOCAL_HYPERTHREADS:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Creating rss channels for all cores/hyperthreads.\n");
			n_rxq = num_online_cpus();
		} else {
			n_rxq = min(num_online_cpus(),
			            cpumask_weight(cpumask_of_pcibus(efx->pci_dev->bus)));
		}
		break;
#endif
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
			free_cpumask_var(local_online_cpus);
			return rss_channels;
		}

		if (efx->rss_mode == EFX_RSS_PACKAGES)
			 rss_channels = min(rss_channels,
					 efx_num_packages(local_online_cpus));
#ifdef HAVE_EFX_NUM_CORES
		else if (efx->rss_mode == EFX_RSS_CORES)
			 rss_channels = min(rss_channels,
					    efx_num_cores(local_online_cpus));
#endif
		else
			rss_channels = min(rss_channels,
					   cpumask_weight(local_online_cpus));
		free_cpumask_var(local_online_cpus);
	}
#endif

	return rss_channels;
}

static int efx_allocate_msix_channels(struct efx_nic *efx,
				      unsigned int max_channels,
				      unsigned int extra_channels,
				      unsigned int parallelism)
{
	unsigned int n_channels = parallelism;
#ifdef EFX_HAVE_MSIX_CAP
	int vec_count;
#endif

	if (separate_tx_channels)
		n_channels *= 2;
	n_channels += extra_channels;

#ifdef EFX_NOT_UPSTREAM
	if (xdp_alloc_tx_resources) {
		/* To allow XDP transmit to happen from arbitrary NAPI contexts
		 * we allocate a TX queue per CPU. We share event queues across
		 * multiple tx queues, assuming tx and ev queues are both
		 * maximum size.
		 */
		int tx_per_ev = EFX_MAX_EVQ_SIZE / EFX_TXQ_MAX_ENT(efx);
		int n_xdp_tx;
		int n_xdp_ev;

		n_xdp_tx = num_possible_cpus();
		n_xdp_ev = DIV_ROUND_UP(n_xdp_tx, tx_per_ev);

		/* Check resources.
		 * We need a channel per event queue, plus a VI per tx queue.
		 * This may be more pessimistic than it needs to be.
		 */
		if (n_channels + n_xdp_ev > max_channels) {
			netif_err(efx, drv, efx->net_dev,
				  "Insufficient resources for %d XDP event queues (%d other channels, max %d)\n",
				  n_xdp_ev, n_channels, max_channels);
			efx->n_xdp_channels = 0;
			efx->xdp_tx_per_channel = 0;
			efx->xdp_tx_queue_count = 0;
		} else if (n_channels + n_xdp_tx > efx->max_vis) {
			netif_err(efx, drv, efx->net_dev,
				  "Insufficient resources for %d XDP TX queues (%d other channels, max VIs %d)\n",
				  n_xdp_tx, n_channels, efx->max_vis);
			efx->n_xdp_channels = 0;
			efx->xdp_tx_per_channel = 0;
			efx->xdp_tx_queue_count = 0;
		} else {
			efx->n_xdp_channels = n_xdp_ev;
			efx->xdp_tx_per_channel = tx_per_ev;
			efx->xdp_tx_queue_count = n_xdp_tx;
			n_channels += n_xdp_ev;
			netif_dbg(efx, drv, efx->net_dev,
				  "Allocating %d TX and %d event queues for XDP\n",
				  n_xdp_tx, n_xdp_ev);
		}
	} else {
		efx->n_xdp_channels = 0;
		efx->xdp_tx_per_channel = 0;
		efx->xdp_tx_queue_count = 0;
	}
#endif

	n_channels = min(n_channels, max_channels);

#ifdef EFX_HAVE_MSIX_CAP
	vec_count = pci_msix_vec_count(efx->pci_dev);
	if (vec_count < 0)
		return vec_count;
	if (vec_count < n_channels) {
		netif_err(efx, drv, efx->net_dev,
			  "WARNING: Insufficient MSI-X vectors available (%d < %u).\n",
			  vec_count, n_channels);
		netif_err(efx, drv, efx->net_dev,
			  "WARNING: Performance may be reduced.\n");
		n_channels = vec_count;
	}
#endif
	efx->n_channels = n_channels;

	/* Do not create the PTP TX queue(s) if PTP uses the MC directly. */
	if (extra_channels && !efx_ptp_use_mac_tx_timestamps(efx))
		n_channels--;

	/* Ignore XDP tx channels when creating rx channels. */
	n_channels -= efx->n_xdp_channels;

	if (separate_tx_channels) {
		efx->n_tx_channels =
			min(max(n_channels / 2, 1U),
			    efx->max_tx_channels);
		efx->tx_channel_offset =
			n_channels - efx->n_tx_channels;
		efx->n_rx_channels =
			max(n_channels -
			    efx->n_tx_channels, 1U);
	} else {
		efx->n_tx_channels = min(n_channels, efx->max_tx_channels);
		efx->tx_channel_offset = 0;
		efx->n_rx_channels = n_channels;
	}
	efx->n_rss_channels = efx_num_rss_channels(efx, extra_channels);
	efx->rss_spread = efx->n_rss_channels;

	if (efx->n_xdp_channels)
		efx->xdp_channel_offset = efx->tx_channel_offset +
					  efx->n_tx_channels;

	netif_dbg(efx, drv, efx->net_dev,
		  "Allocating %u RX channels\n",
		  efx->n_rx_channels);

	return efx->n_channels;
}

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
		unsigned int n_channels;

		rc = efx_allocate_msix_channels(efx, efx->max_channels,
						extra_channels, parallelism);
		if (rc >= 0) {
			n_channels = rc;
			for (i = 0; i < n_channels; i++)
				xentries[i].entry = i;
			rc = pci_enable_msix_range(efx->pci_dev, xentries, 1,
						   n_channels);
		}
		if (rc < 0) {
			/* Fall back to single channel MSI */
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI-X\n");
			if (efx->type->min_interrupt_mode >= EFX_INT_MODE_MSI)
				efx->interrupt_mode = EFX_INT_MODE_MSI;
			else
				return rc;
#ifndef EFX_HAVE_MSIX_CAP
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
#endif
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
		efx->n_xdp_channels = 0;
		efx->xdp_channel_offset = 0;
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
		efx->n_xdp_channels = 0;
		efx->xdp_channel_offset = 0;
		efx->legacy_irq = efx->pci_dev->irq;

		/* Warn unless this was forced by the module parameter.
		 * We'll already have warned if that's the case.
		 */
		if (interrupt_mode != EFX_INT_MODE_LEGACY)
			netif_warn(efx, drv, efx->net_dev,
				   "Use of legacy interrupts is deprecated and will be removed in a future release\n");
	}

	/* Assign extra channels if possible, before XDP channels */
	j = efx->xdp_channel_offset ? efx->xdp_channel_offset : efx->n_channels;
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

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETIF_SET_XPS_QUEUE)
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
static bool auto_config_xps = true;
module_param(auto_config_xps, bool, 0644);
MODULE_PARM_DESC(auto_config_xps,
		 "Toggle automatic XPS configuration (default is enabled).");
#endif /* EFX_NOT_UPSTREAM && CONFIG_XPS */

static void efx_set_xps_queue(struct efx_channel *channel,
			      const cpumask_t *mask)
{
	if (!efx_channel_has_tx_queues(channel) ||
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
	    !auto_config_xps ||
#endif
	    efx_channel_is_xdp_tx(channel) ||
	    channel == efx_ptp_channel(channel->efx))
		return;

	netif_set_xps_queue(channel->efx->net_dev, mask,
			    channel->channel - channel->efx->tx_channel_offset);
}
#else
static void efx_set_xps_queue(struct efx_channel *channel,
			      const cpumask_t *mask)
{
}
#endif

#if !defined(CONFIG_SMP)
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
		efx_set_xps_queue(channel, cpumask_of(cpu));
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

static int efx_set_cpu_affinity(struct efx_channel *channel, int cpu)
{
	int rc;

	if (!efx_irq_set_affinity)
		return 0;

	rc = irq_set_affinity_hint(channel->irq, cpumask_of(cpu));
	if (rc) {
		netif_err(channel->efx, drv, channel->efx->net_dev,
			  "Unable to set affinity hint for channel %d"
			  " interrupt %d\n", channel->channel, channel->irq);
		return rc;
	}
	efx_set_xps_queue(channel, cpumask_of(cpu));
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

/* Stripe the RSS vectors across the CPUs. */
static void efx_set_interrupt_affinity(struct efx_nic *efx)
{
	enum {PACKAGE, CORE, TEMP1, TEMP2, LOCAL, SETS_MAX};
	struct efx_channel *channel;
	struct cpumask *sets;
	int cpu;

	/* Only do this for RSS/MSI-X */
	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

	sets = kcalloc(SETS_MAX, sizeof(*sets), GFP_KERNEL);
	if (!sets) {
		netif_err(efx, drv, efx->net_dev,
			  "Not enough temporary memory to set IRQ affinity\n");
		return;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
	cpumask_and(&sets[LOCAL], cpu_online_mask,
		    cpumask_of_pcibus(efx->pci_dev->bus));
#endif

	/* Serialise access to rss_cpu_usage */
	rtnl_lock();

	/* Assign each channel a CPU */
	efx_for_each_channel(channel, efx) {
#ifdef HAVE_EFX_NUM_PACKAGES
		/* Force channels 0-RSS to the local package, otherwise select
		 * the package with the lowest usage count */
		efx_rss_choose_package(&sets[PACKAGE], &sets[TEMP1],
			&sets[TEMP2],
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
			rss_numa_local &&
			channel->channel < efx->n_rss_channels ?
				&sets[LOCAL] :
#endif
				cpu_online_mask);
		WARN_ON(!cpumask_weight(&sets[PACKAGE]));
#else
		cpumask_copy(&sets[PACKAGE], &cpu_online_map);
#endif

		/* Select the thread siblings within this package with the
		 * lowest usage count */
#ifdef HAVE_EFX_NUM_CORES
		efx_rss_choose_core(&sets[CORE], &sets[PACKAGE], &sets[TEMP1],
				    &sets[TEMP2]);
		WARN_ON(!cpumask_weight(&sets[CORE]));
#else
		cpumask_copy(&sets[CORE], &sets[PACKAGE]);
#endif

		/* Select the thread within this set with the lowest usage count */
		cpu = efx_rss_choose_thread(&sets[CORE]);
		++rss_cpu_usage[cpu];
		efx_set_cpu_affinity(channel, cpu);
		channel->irq_mem_node = cpu_to_mem(cpu);
	}

	rtnl_unlock();

	kfree(sets);
}

static void efx_clear_interrupt_affinity(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		(void)irq_set_affinity_hint(channel->irq, NULL);
}

#endif /* EFX_NOT_UPSTREAM */
#endif /* CONFIG_SMP */

#ifdef EFX_USE_IRQ_NOTIFIERS
static void efx_irq_release(struct kref *ref)
{
	struct efx_channel *channel = container_of(ref, struct efx_channel,
						   irq_affinity.notifier.kref);

	complete(&channel->irq_affinity.complete);
}

static void efx_irq_notify(struct irq_affinity_notify *this,
			   const cpumask_t *mask)
{
	struct efx_channel *channel = container_of(this, struct efx_channel,
						   irq_affinity.notifier);

	efx_set_xps_queue(channel, mask);
}

static void efx_set_affinity_notifier(struct efx_channel *channel)
{
	int rc;

	init_completion(&channel->irq_affinity.complete);
	channel->irq_affinity.notifier.notify = efx_irq_notify;
	channel->irq_affinity.notifier.release = efx_irq_release;
	rc = irq_set_affinity_notifier(channel->irq,
				       &channel->irq_affinity.notifier);
	if (rc)
		netif_warn(channel->efx, probe, channel->efx->net_dev,
			   "Failed to set irq notifier for IRQ %d",
			   channel->irq);
}

static void efx_clear_affinity_notifier(struct efx_channel *channel)
{
	irq_set_affinity_notifier(channel->irq, NULL);
	wait_for_completion(&channel->irq_affinity.complete);
}

static void efx_register_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_set_affinity_notifier(channel);
}

static void efx_unregister_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_clear_affinity_notifier(channel);
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

/* Configure a normal TX channel - add TX queues */
static int efx_set_channel_tx(struct efx_nic *efx, struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	int queue_base;
	int j;

	EFX_WARN_ON_PARANOID(channel->tx_queues);
	channel->tx_queues = kcalloc(efx->tx_queues_per_channel,
				     sizeof(*tx_queue),
				     GFP_KERNEL);
	if (!channel->tx_queues)
		return -ENOMEM;

	channel->tx_queue_count = efx->tx_queues_per_channel;
	queue_base = efx->tx_queues_per_channel *
		     (channel->channel - efx->tx_channel_offset);

	for (j = 0; j < channel->tx_queue_count; ++j) {
		tx_queue = &channel->tx_queues[j];
		tx_queue->efx = efx;
		tx_queue->channel = channel;
		tx_queue->csum_offload = j;
		tx_queue->label = j;
		tx_queue->queue = queue_base + j;
		/* When using an even number of queues, for even numbered
		 * channels alternate the queues. This stripes events across
		 * the NIC resources more effectively.
		 */
		if (efx->tx_queues_per_channel % 2 == 0)
			tx_queue->queue ^= channel->channel & 1;
	}

	return 0;
}

/* Configure an XDP TX channel - add TX queues */
static int efx_set_channel_xdp(struct efx_nic *efx, struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	int xdp_zero_base;
	int xdp_base;
	int j;

	/* TX queue index for first XDP queue overall. */
	xdp_zero_base = efx->tx_queues_per_channel * efx->n_tx_channels;
	/* TX queue index for first queue on this channel. */
	xdp_base = channel->channel - efx->xdp_channel_offset;
	xdp_base *= efx->xdp_tx_per_channel;

	/* Do we need the full allowance of XDP tx queues for this channel?
	 * If the total number of queues required is not a multiple of
	 * xdp_tx_per_channel we omit the surplus queues.
	 */
	if (xdp_base + efx->xdp_tx_per_channel > efx->xdp_tx_queue_count) {
		channel->tx_queue_count = efx->xdp_tx_queue_count %
					  efx->xdp_tx_per_channel;
	} else {
		channel->tx_queue_count = efx->xdp_tx_per_channel;
	}
	EFX_WARN_ON_PARANOID(channel->tx_queue_count == 0);

	EFX_WARN_ON_PARANOID(channel->tx_queues);
	channel->tx_queues = kcalloc(efx->xdp_tx_per_channel,
				     sizeof(*tx_queue),
				     GFP_KERNEL);
	if (!channel->tx_queues) {
		channel->tx_queue_count = 0;
		return -ENOMEM;
	}

	for (j = 0; j < channel->tx_queue_count; ++j) {
		tx_queue = &channel->tx_queues[j];
		tx_queue->efx = efx;
		tx_queue->channel = channel;
		tx_queue->csum_offload = EFX_TXQ_TYPE_NO_OFFLOAD;
		tx_queue->label = j;
		tx_queue->queue = xdp_zero_base + xdp_base + j;

		/* Stash pointer for use by XDP TX */
		efx->xdp_tx_queues[xdp_base + j] = tx_queue;
	}

	return 0;
}

static int efx_set_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

	if (efx->xdp_tx_queue_count) {
		EFX_WARN_ON_PARANOID(efx->xdp_tx_queues);

		/* Allocate array for XDP TX queue lookup. */
		efx->xdp_tx_queues = kcalloc(efx->xdp_tx_queue_count,
					     sizeof(*efx->xdp_tx_queues),
					     GFP_KERNEL);
		if (!efx->xdp_tx_queues)
			return -ENOMEM;
	}

	/* We need to mark which channels really have RX and TX
	 * queues, and adjust the TX queue numbers if we have separate
	 * RX-only and TX-only channels.
	 */
	efx_for_each_channel(channel, efx) {
		if (channel->channel < efx->n_rx_channels)
			channel->rx_queue.core_index = channel->channel;
		else
			channel->rx_queue.core_index = -1;

		if (efx_channel_is_xdp_tx(channel))
			rc = efx_set_channel_xdp(efx, channel);
		else if (efx_channel_has_tx_queues(channel))
			rc = efx_set_channel_tx(efx, channel);

		if (rc)
			return rc;
	}

	return 0;
}

/* Undo efx_set_channels() */
static void efx_unset_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;

	kfree(efx->xdp_tx_queues);
	efx->xdp_tx_queues = NULL;

	efx_for_each_channel(channel, efx) {
		kfree(channel->tx_queues);
		channel->tx_queues = NULL;
		channel->tx_queue_count = 0;
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

#ifdef EFX_NOT_UPSTREAM
	/* Initialise NIC resource information */
	efx->farch_resources = efx->type->farch_resources;
	efx->farch_resources.biu_lock = &efx->biu_lock;
	efx->ef10_resources = efx->type->ef10_resources;
#endif

	/* Carry out hardware-type specific initialisation */
	rc = efx->type->probe(efx);
	if (rc)
		goto fail2;
#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	efx->txq_min_entries = roundup_pow_of_two(2 * efx->type->tx_max_skb_descs(efx));

	do {
		if (!efx->max_channels || !efx->max_tx_channels) {
			netif_err(efx, drv, efx->net_dev,
				  "Insufficient resources to allocate "
				  "any channels\n");
			rc = -ENOSPC;
			goto fail3;
		}

		/* Determine the number of channels and queues by trying to hook
		 * in MSI-X interrupts. */
		rc = efx_probe_interrupts(efx);
		if (rc)
			goto fail3;

		rc = efx_set_channels(efx);
		if (rc)
			goto fail3;

		/* dimension_resources can fail with EAGAIN */
		rc = efx->type->dimension_resources(efx);
		if (rc != 0 && rc != -EAGAIN)
			goto fail4;

		if (rc == -EAGAIN) {
			/* try again with new max_channels */
			efx_unset_channels(efx);
			efx_remove_interrupts(efx);
		}

	} while (rc == -EAGAIN);

#ifdef EFX_NOT_UPSTREAM
	if ((efx->n_channels > 1) && efx_rss_use_fixed_key) {
		BUILD_BUG_ON(sizeof(efx_rss_fixed_key) <
				sizeof(efx->rss_context.rx_hash_key));
		memcpy(&efx->rss_context.rx_hash_key, efx_rss_fixed_key,
				sizeof(efx->rss_context.rx_hash_key));
	} else
#endif
	if (efx->n_channels > 1)
		netdev_rss_key_fill(efx->rss_context.rx_hash_key,
				    sizeof(efx->rss_context.rx_hash_key));
	efx_set_default_rx_indir_table(efx, &efx->rss_context);

	n_tx_channels = efx->n_tx_channels;
	/* Hide the PTP TX queue from the network stack, so it is not
	 * used for normal packets.
	 */
	if (efx->extra_channel_type[EFX_EXTRA_CHANNEL_PTP] &&
	    (n_tx_channels > 1) && efx_ptp_use_mac_tx_timestamps(efx))
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
#ifdef EFX_NOT_UPSTREAM
	efx->dl_info = NULL;
#endif

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
#ifdef EFX_NOT_UPSTREAM
	efx->dl_info = NULL;
#endif

	efx_fini_debugfs_nic(efx);
}

static int efx_probe_filters(struct efx_nic *efx)
{
	int rc;

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
			channel->rfs_expire_index = 0;
			channel->rfs_filter_count = 0;
		}

		if (!success) {
			efx_for_each_channel(channel, efx) {
				kfree(channel->rps_flow_id);
				channel->rps_flow_id = NULL;
			}
			efx->type->filter_table_remove(efx);
			rc = -ENOMEM;
			goto out_unlock;
		}
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

	efx_for_each_channel(channel, efx) {
		cancel_delayed_work_sync(&channel->filter_work);
		kfree(channel->rps_flow_id);
		channel->rps_flow_id = NULL;
	}
#endif
	down_write(&efx->filter_sem);
	efx->type->filter_table_remove(efx);
	up_write(&efx->filter_sem);
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

	rc = efx_check_queue_size(efx, &rx_ring,
				  EFX_RXQ_MIN_ENT, EFX_MAX_DMAQ_SIZE, true);
	if (rc == -ERANGE)
		netif_warn(efx, probe, efx->net_dev,
			   "rx_ring parameter must be between %u and %lu; clamped to %u\n",
			   EFX_RXQ_MIN_ENT, EFX_MAX_DMAQ_SIZE, rx_ring);
	else if (rc == -EINVAL)
		netif_warn(efx, probe, efx->net_dev,
			   "rx_ring parameter must be a power of two; rounded to %u\n",
			   rx_ring);
	efx->rxq_entries = rx_ring;

	rc = efx_check_queue_size(efx, &tx_ring,
				  efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx),
				  true);
	if (rc == -ERANGE)
		netif_warn(efx, probe, efx->net_dev,
			   "tx_ring parameter must be between %u and %lu; clamped to %u\n",
			   efx->txq_min_entries, EFX_TXQ_MAX_ENT(efx), tx_ring);
	else if (rc == -EINVAL)
		netif_warn(efx, probe, efx->net_dev,
			   "tx_ring parameter must be a power of two; rounded to %u\n",
			   tx_ring);
	efx->txq_entries = tx_ring;

	/* We fixed queue size errors so don't care about rc at this point */

	rc = efx->type->vswitching_probe(efx);
	if (rc) /* not fatal; the PF will still work fine */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to setup vswitching rc=%d, VFs may not function\n",
			   rc);

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
	efx->type->vswitching_remove(efx);
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
static int efx_start_all(struct efx_nic *efx)
{
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	/* Check that it is appropriate to restart the interface. All
	 * of these flags are safe to read under just the rtnl lock */
	if ((efx->state == STATE_DISABLED) || efx->port_enabled ||
			!netif_running(efx->net_dev) || efx->reset_pending)
		return 0;

	efx_start_port(efx);
	rc = efx_start_datapath(efx);
	if (rc) {
		efx_stop_port(efx);
		return rc;
	}

	/* Start the hardware monitor if there is one */
	if (efx->type->monitor != NULL)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
		schedule_delayed_work(&efx->monitor_work,
				msecs_to_jiffies(monitor_interval_ms));
#else
		queue_delayed_work(efx_workqueue, &efx->monitor_work,
				msecs_to_jiffies(monitor_interval_ms));
#endif

	/* Link state detection is normally event-driven; we have
	 * to poll now because we could have missed a change
	 */
	mutex_lock(&efx->mac_lock);
	if (efx->phy_op->poll(efx))
		efx_link_status_changed(efx);
	mutex_unlock(&efx->mac_lock);

	efx->type->start_stats(efx);
	efx->type->pull_stats(efx);
	efx->type->update_stats(efx, NULL, NULL);
	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);

	return 0;
}

void efx_reset_sw_stats(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;

	efx_for_each_channel(channel, efx) {
		efx_channel_get_rx_queue(channel)->rx_packets = 0;
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			tx_queue->tx_packets = 0;
			tx_queue->pushes = 0;
			tx_queue->pio_packets = 0;
			tx_queue->cb_packets = 0;
		}
	}
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

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	rtnl_lock();
	efx_xdp_setup_prog(efx, NULL);
	rtnl_unlock();
#endif
	efx_remove_channels(efx);
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
		else if (efx_channel_is_xdp_tx(channel))
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

	channel->napi_dev = efx->net_dev;
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
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_busy_poll_init(channel);
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
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
		while (!efx_channel_disable(channel))
			usleep_range(1000, 20000);
		efx_channel_unlock_napi(channel);

#ifdef CONFIG_NET_RX_BUSY_POLL
		if (channel->busy_poll_state !=
		    (1 << EFX_CHANNEL_STATE_DISABLE_BIT))
			netif_err(channel->efx, drv, channel->efx->net_dev,
				  "chan %d bad state %#lx in %s\n",
				  channel->channel,
				  channel->busy_poll_state, __func__);
#endif
#endif
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
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
		efx_channel_enable(channel);
#endif
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

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
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
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
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
	efx->reset_count = 0;

	/* Notify the kernel of the link state polled during driver load,
	 * before the monitor starts running */
	efx_link_status_changed(efx);

	rc = efx_start_all(efx);
	if (rc)
		return rc;

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

	return 0;
}

/* Context: process, dev_base_lock or RTNL held, non-blocking. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_STATS64_VOID)
static void efx_net_stats(struct net_device *net_dev,
			  struct rtnl_link_stats64 *stats)
#elif defined(EFX_USE_NETDEV_STATS64)
static struct rtnl_link_stats64 *efx_net_stats(struct net_device *net_dev,
					       struct rtnl_link_stats64 *stats)
#else
static struct net_device_stats *efx_net_stats(struct net_device *net_dev)
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
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NETDEV_STATS64_VOID)

	return stats;
#endif
}

void efx_set_stats_period(struct efx_nic *efx, unsigned int period_ms)
{
	efx->stats_period_ms = period_ms;
	efx->type->update_stats_period(efx);
}

/* Context: netif_tx_lock held, BHs disabled. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_TX_TIMEOUT_TXQUEUE)
static void efx_watchdog(struct net_device *net_dev, unsigned int txqueue)
#else
static void efx_watchdog(struct net_device *net_dev)
#endif
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;

	netif_info(efx, tx_err, efx->net_dev,
		   "TX queue timeout: printing stopped queue data\n");

	efx_for_each_channel(channel, efx) {
		struct efx_tx_queue *tx_queue;

		if (!efx_channel_has_tx_queues(channel))
			continue;

		/* The netdev watchdog must have triggered on a queue that had
		 * stopped transmitting, so ignore other queues.
		 */
		if (!netif_xmit_stopped(channel->tx_queues[0].core_txq))
			continue;

		netif_info(efx, tx_err, efx->net_dev,
			   "Channel %u: %senabled Busy poll %#lx NAPI state %#lx Doorbell %sheld %scoalescing\n",
			   channel->channel, (channel->enabled ? "" : "NOT "),
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
			   channel->busy_poll_state,
#else
			   (long unsigned int) 0xffff,
#endif
#else
			   (long unsigned int) 0xffff,
#endif
			   channel->napi_str.state,
			   (channel->holdoff_doorbell ? "" : "not "),
			   (channel->tx_coalesce_doorbell ? "" : "not "));
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

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
static unsigned int efx_xdp_max_mtu(struct efx_nic *efx)
{
	/* The maximum MTU that we can fit in a single page, allowing for
	 * framing, overhead and XDP headroom. */
	int overhead = EFX_MAX_FRAME_LEN(0) + sizeof(struct efx_rx_page_state) +
		       efx->rx_prefix_size + efx->type->rx_buffer_padding +
		       efx->rx_ip_align + XDP_PACKET_HEADROOM;

	return PAGE_SIZE - overhead;
}
#endif

/* Context: process, rtnl_lock() held. */
int efx_change_mtu(struct net_device *net_dev, int new_mtu)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	int rc;
	int old_mtu;

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;

#if defined(EFX_USE_KCOMPAT) && !(defined(EFX_HAVE_NETDEV_MTU_LIMITS) || defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS))
	if (new_mtu > EFX_MAX_MTU) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too big (max: %d)\n",
			  new_mtu, EFX_MAX_MTU);
		return -EINVAL;
	}
	if (new_mtu < EFX_MIN_MTU) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too small (min: %d)\n",
			  new_mtu, EFX_MIN_MTU);
		return -EINVAL;
	}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	if (rtnl_dereference(efx->xdp_prog) &&
	    new_mtu > efx_xdp_max_mtu(efx)) {
		netif_err(efx, drv, efx->net_dev,
			  "Requested MTU of %d too big for XDP (max: %d)\n",
			  new_mtu, efx_xdp_max_mtu(efx));
		return -EINVAL;
	}
#endif

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
		netif_err(efx, drv, efx->net_dev,
			  "invalid ethernet MAC address requested: %pM\n",
			  new_addr);
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

	/* If Rx VLAN filter is changed, update filters via mac_reconfigure.
	 * If forward-fcs is changed, mac_reconfigure updates that too.
	 */
	if ((net_dev->features ^ data) & (NETIF_F_HW_VLAN_CTAG_FILTER |
					  NETIF_F_RXFCS)) {
		/* efx_set_rx_mode() will schedule MAC work to update filters
		 * when a new features are finally set in net_dev.
		 */
		efx_set_rx_mode(net_dev);
	}

	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_NEED_GET_PHYS_PORT_ID)
static int efx_get_phys_port_id(struct net_device *net_dev,
				struct netdev_phys_item_id *ppid)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (efx->type->get_phys_port_id)
		return efx->type->get_phys_port_id(efx, ppid);
	else
		return -EOPNOTSUPP;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
static int efx_get_phys_port_name(struct net_device *net_dev,
				  char *name, size_t len)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (snprintf(name, len, "p%u", efx->port_num) >= len)
		return -EINVAL;
	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
/* Determine whether the NIC will be able to handle TX offloads for a given
 * encapsulated packet.
 */
static bool efx_can_encap_offloads(struct efx_nic *efx, struct sk_buff *skb)
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NDO_ADD_VXLAN_PORT) && !defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
	return false;
#else
	struct gre_base_hdr *greh;
	__be16 dst_port;
	u8 ipproto;

	/* Does the NIC support encap offloads?
	 * If not, we should never get here, because we shouldn't have
	 * advertised encap offload feature flags in the first place.
	 */
	if (WARN_ON_ONCE(!efx->type->udp_tnl_has_port))
		return false;

	/* Determine encapsulation protocol in use */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ipproto = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		/* If there are extension headers, this will cause us to
		 * think we can't offload something that we maybe could have.
		 */
		ipproto = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		/* Not IP, so can't offload it */
		return false;
	}
	switch (ipproto) {
	case IPPROTO_GRE:
		/* We support NVGRE but not IP over GRE or random gretaps.
		 * Specifically, the NIC will accept GRE as encapsulated if
		 * the inner protocol is Ethernet, but only handle it
		 * correctly if the GRE header is 8 bytes long.  Moreover,
		 * it will not update the Checksum or Sequence Number fields
		 * if they are present.  (The Routing Present flag,
		 * GRE_ROUTING, cannot be set else the header would be more
		 * than 8 bytes long; so we don't have to worry about it.)
		 */
		if (skb->inner_protocol_type != ENCAP_TYPE_ETHER)
			return false;
		if (ntohs(skb->inner_protocol) != ETH_P_TEB)
			return false;
		if (skb_inner_mac_header(skb) - skb_transport_header(skb) != 8)
			return false;
		greh = (struct gre_base_hdr *)skb_transport_header(skb);
		return !(greh->flags & (GRE_CSUM | GRE_SEQ));
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

	if (skb->encapsulation) {
		if (features & NETIF_F_GSO_MASK)
			/* Hardware can only do TSO with at most 208 bytes
			 * of headers.
			 */
			if (skb_inner_transport_offset(skb) > EFX_TSO2_MAX_HDRLEN)
				features &= ~(NETIF_F_GSO_MASK);
		if (features & (NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK))
			if (!efx_can_encap_offloads(efx, skb))
				features &= ~(NETIF_F_GSO_MASK |
					      NETIF_F_CSUM_MASK);
	}
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

#endif /* EFX_NOT_UPSTREAM */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
static int efx_udp_tunnel_type_map(enum udp_parsable_tunnel_type in)
{
	switch (in) {
	case UDP_TUNNEL_TYPE_VXLAN:
		return TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN;
	case UDP_TUNNEL_TYPE_GENEVE:
		return TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE;
	default:
		return -1;
	}
}

static void efx_udp_tunnel_add(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct efx_udp_tunnel tnl;
	int efx_tunnel_type;

	efx_tunnel_type = efx_udp_tunnel_type_map(ti->type);
	if (efx_tunnel_type < 0)
		return;

	tnl.type = (u16)efx_tunnel_type;
	tnl.port = ti->port;

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

static void efx_udp_tunnel_del(struct net_device *dev, struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct efx_udp_tunnel tnl;
	int efx_tunnel_type;

	efx_tunnel_type = efx_udp_tunnel_type_map(ti->type);
	if (efx_tunnel_type < 0)
		return;

	tnl.type = (u16)efx_tunnel_type;
	tnl.port = ti->port;

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#else
#if defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
void efx_vxlan_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_vxlan_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#endif
#if defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
void efx_geneve_add_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_add_port)
		efx->type->udp_tnl_add_port(efx, tnl);
}

void efx_geneve_del_port(struct net_device *dev, sa_family_t sa_family,
			__be16 port)
{
	struct efx_udp_tunnel tnl = {.port = port,
				     .type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE};
	struct efx_nic *efx = netdev_priv(dev);

	if (efx->type->udp_tnl_del_port)
		efx->type->udp_tnl_del_port(efx, tnl);
}
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
static int efx_xdp_setup_prog(struct efx_nic *efx, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;

	if (prog && (efx->net_dev->mtu > efx_xdp_max_mtu(efx))) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to configure XDP with MTU of %d (max: %d)\n",
			  efx->net_dev->mtu, efx_xdp_max_mtu(efx));
		return -EINVAL;
	}

	old_prog = rtnl_dereference(efx->xdp_prog);
	rcu_assign_pointer(efx->xdp_prog, prog);
	/* Release the reference that was originally passed by the caller. */
	if (old_prog)
		bpf_prog_put(old_prog);

	return 0;
}

/* Context: process, rtnl_lock() held. */
static int efx_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct bpf_prog *xdp_prog;

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return efx_xdp_setup_prog(efx, xdp->prog);
	case XDP_QUERY_PROG:
		xdp_prog = rtnl_dereference(efx->xdp_prog);
#if defined(EFX_USE_KCOMPAT) && (defined(EFX_HAVE_XDP_PROG_ATTACHED) || defined(EFX_HAVE_XDP_OLD))
		xdp->prog_attached = !!xdp_prog;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_PROG_ID) || !defined(EFX_HAVE_XDP_OLD)
		xdp->prog_id = xdp_prog ? xdp_prog->aux->id : 0;
#endif
		return 0;
	default:
		return -EINVAL;
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
/* Context: NAPI */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX_FLAGS)
static int efx_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **xdpfs,
			u32 flags)
{
	struct efx_nic *efx = netdev_priv(dev);

	if (!netif_running(dev))
		return -EINVAL;

	return efx_xdp_tx_buffers(efx, n, xdpfs, flags & XDP_XMIT_FLUSH);
}
#else
static int efx_xdp_xmit(struct net_device *dev, struct xdp_frame *xdpf)
{
	struct efx_nic *efx = netdev_priv(dev);
	int rc;

	if (!netif_running(dev))
		return -EINVAL;

	rc = efx_xdp_tx_buffers(efx, 1, &xdpf, false);

	if (rc == 1)
		return 0;
	if (rc == 0)
		return -ENOSPC;
	return rc;
}
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
/* Context: NAPI */
static void efx_xdp_flush(struct net_device *dev)
{
	efx_xdp_tx_buffers(netdev_priv(dev), 0, NULL, true);
}
#endif /* NEED_XDP_FLUSH */
#endif /* HAVE_XDP_REDIR */
#endif /* HAVE_XDP */

extern const struct net_device_ops efx_netdev_ops;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
extern const struct net_device_ops_ext efx_net_device_ops_ext;
#endif

static void efx_update_name(struct efx_nic *efx)
{
	strcpy(efx->name, efx->net_dev->name);

#if defined(CONFIG_SFC_MTD) && !defined(EFX_WORKAROUND_87308)
	efx_mtd_rename(efx);
#endif

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

#ifdef EFX_NOT_UPSTREAM
bool efx_dl_netdev_is_ours(const struct net_device *net_dev)
{
	return net_dev->netdev_ops == &efx_netdev_ops;
}
EXPORT_SYMBOL(efx_dl_netdev_is_ours);
#endif

static int efx_netdev_event(struct notifier_block *this,
			    unsigned long event, void *ptr)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NETDEV_NOTIFIER_NETDEV_PTR)
	struct net_device *net_dev = ptr;
#else
	struct netdev_notifier_info *info = ptr;
	struct net_device *net_dev = info->dev;
#endif

	if (event == NETDEV_CHANGENAME &&
	    (net_dev->netdev_ops == &efx_netdev_ops)) {
		struct efx_nic *efx = netdev_priv(net_dev);

		efx_update_name(efx);

#if defined(CONFIG_SFC_MTD) && defined(EFX_WORKAROUND_87308)
		if (atomic_xchg(&efx->mtd_struct->probed_flag, 1) == 0)
			(void)efx_mtd_probe(efx);
#endif
	}

	return NOTIFY_DONE;
}

static struct notifier_block efx_netdev_notifier = {
	.notifier_call = efx_netdev_event,
};

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
	net_dev->netdev_ops = &efx_netdev_ops;
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		net_dev->priv_flags |= IFF_UNICAST_FLT;
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_MTU_LIMITS)
	net_dev->min_mtu = EFX_MIN_MTU;
	net_dev->max_mtu = EFX_MAX_MTU;
#elif defined(EFX_HAVE_NETDEV_EXT_MTU_LIMITS)
	net_dev->extended->min_mtu = EFX_MIN_MTU;
	net_dev->extended->max_mtu = EFX_MAX_MTU;
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

#ifdef EFX_NOT_UPSTREAM
	/* Register with driverlink layer */
	if (efx_dl_supported(efx))
		efx_dl_register_nic(efx);
#endif

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
#ifdef EFX_NOT_UPSTREAM
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(efx);
#endif
	unregister_netdevice(net_dev);
fail_locked:
	rtnl_unlock();
	netif_err(efx, drv, efx->net_dev, "could not register net dev\n");
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
}

/**************************************************************************
 *
 * Device reset and suspend
 *
 **************************************************************************/

/* Tears down the entire software state and most of the hardware state
 * before reset.  */
void efx_reset_down(struct efx_nic *efx, enum reset_type method)
{
	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->prepare_flr(efx);

	efx_stop_all(efx);
	efx_disable_interrupts(efx);

	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);
	mutex_lock(&efx->rss_lock);
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
	u32 attach_flags;
	int rc;

	EFX_ASSERT_RESET_SERIALISED(efx);

	if (method == RESET_TYPE_MCDI_TIMEOUT)
		efx->type->finish_flr(efx);

	efx_mcdi_post_reset(efx);

	/* Ensure that SRAM is initialised even if we're disabling the device */
	rc = efx->type->init(efx);
	if (rc) {
		if (rc != -EAGAIN)
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
	rc = efx_mcdi_drv_attach(efx, MC_CMD_FW_DONT_CARE, &attach_flags, true);
	if (rc) /* not fatal: the PF will still work */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to re-attach driver to MCPU rc=%d, PPS & NCSI may malfunction\n",
			   rc);
	else
		/* Store new attach flags. */
		efx->mcdi->fn_flags = attach_flags;

	rc = efx->type->vswitching_restore(efx);
	if (rc) /* not fatal; the PF will still work fine */
		netif_warn(efx, probe, efx->net_dev,
			   "failed to restore vswitching rc=%d, VFs may not function\n",
			   rc);

	if (efx->type->rx_restore_rss_contexts)
		efx->type->rx_restore_rss_contexts(efx);
	mutex_unlock(&efx->rss_lock);
	efx->type->filter_table_restore(efx);
	up_write(&efx->filter_sem);
	if (efx->type->sriov_reset)
		efx->type->sriov_reset(efx);

	mutex_unlock(&efx->mac_lock);

	rc = efx_start_all(efx);
	if (rc) {
		efx->port_initialized = false;
		return rc;
	}

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);

	return 0;

fail:
	efx->port_initialized = false;

	mutex_unlock(&efx->rss_lock);
	up_write(&efx->filter_sem);
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
	bool disabled, retry;

	ASSERT_RTNL();

#ifdef EFX_NOT_UPSTREAM
	/* Notify driverlink clients of imminent reset then serialise
	 * against other driver operations */
	efx_dl_reset_suspend(efx);
#endif

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
	retry = rc == -EAGAIN;

	/* Leave device stopped if necessary */
	disabled = (rc && !retry) ||
		method == RESET_TYPE_DISABLE ||
		method == RESET_TYPE_RECOVER_OR_DISABLE;

	rc2 = efx_reset_up(efx, method, !disabled && !retry);
	if (rc2) {
		if (rc2 == -EAGAIN)
			retry = true;
		else
			disabled = true;
		if (!rc)
			rc = rc2;
	}

	if (disabled) {
		dev_close(efx->net_dev);
		netif_err(efx, drv, efx->net_dev, "has been disabled\n");
		efx->state = STATE_DISABLED;
	} else if (retry) {
		netif_info(efx, drv, efx->net_dev, "scheduling retry of reset\n");
		if (method == RESET_TYPE_MC_BIST)
			method = RESET_TYPE_DATAPATH;
		efx_schedule_reset(efx, method);
	} else {
		netif_dbg(efx, drv, efx->net_dev, "reset complete\n");
		efx_device_attach_if_not_resetting(efx);
		if (PCI_FUNC(efx->pci_dev->devfn) == 0)
			efx_mcdi_log_puts(efx, efx_reset_type_names[method]);
	}
#ifdef EFX_NOT_UPSTREAM
	efx_dl_reset_resume(efx, !disabled);
#endif
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
	struct eeh_dev *eehdev = pci_dev_to_eeh_dev(efx->pci_dev);

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
		if (efx->type->mcdi_poll_bist_end(efx))
			goto out;
		msleep(BIST_WAIT_DELAY_MS);
	}

	netif_err(efx, drv, efx->net_dev, "Warning: No MC reboot after BIST mode\n");
out:
	/* Either way unset the BIST flag. If we found no reboot we probably
	 * won't recover, but we should try.
	 */
	efx->mc_bist_for_other_fn = false;
	efx->reset_count = 0;
}

/* The worker thread exists so that code that cannot sleep can
 * schedule a reset for later.
 */
static void efx_reset_work(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic, reset_work);
	unsigned long pending;
	enum reset_type method;

	pending = READ_ONCE(efx->reset_pending);
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
	static const unsigned int RESETS_BEFORE_DISABLE = 5;
	unsigned long last_reset = READ_ONCE(efx->last_reset);
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
		netif_dbg(efx, drv, efx->net_dev,
			  "scheduling %s reset\n", RESET_TYPE(method));
		break;
	default:
		method = efx->type->map_reset_reason(type);
		netif_dbg(efx, drv, efx->net_dev,
			  "scheduling %s reset for %s\n",
			  RESET_TYPE(method), RESET_TYPE(type));
		break;
	}

	/* check we're scheduling a new reset and if so check we're
	 * not scheduling resets too often.
	 * this part is not atomically safe, but is also ultimately a
	 * heuristic; if we lose increments due to dirty writes
	 * that's fine and if we falsely increment or reset due to an
	 * inconsistent read of last_reset on 32-bit arch it's also ok.
	 */
	if (time_after(jiffies, last_reset + HZ))
		efx->reset_count = 0;
	if (!(efx->reset_pending & (1 << method)) &&
	    ++efx->reset_count > RESETS_BEFORE_DISABLE) {
		method = RESET_TYPE_DISABLE;
		netif_err(efx, drv, efx->net_dev,
			  "too many resets, scheduling %s\n",
			  RESET_TYPE(method));
	}

	/* It is not atomic-safe as well, but there is a high chance that
	 * this code will catch the just-set current_reset value.  If we
	 * fail once, we'll get the value next time. */
	if (time_after(efx->current_reset, last_reset) )
		efx->last_reset = efx->current_reset;

	set_bit(method, &efx->reset_pending);

	/* If we're not READY then just leave the flags set as the cue
	 * to abort probing or reschedule the reset later.
	 */
	if (READ_ONCE(efx->state) != STATE_READY)
		return;

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
static const struct pci_device_id efx_pci_table[] = {
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
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x0b03),  /* SFC9250 PF */
	 .driver_data = (unsigned long) &efx_hunt_a0_nic_type},
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1b03),  /* SFC9250 VF */
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
	spin_lock_init(&efx->biu_lock);
#ifdef CONFIG_SFC_MTD
	if(efx_mtd_init(efx) < 0)
		goto fail;
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
	INIT_LIST_HEAD(&efx->rss_context.list);
	mutex_init(&efx->rss_lock);
	INIT_LIST_HEAD(&efx->vport.list);
	mutex_init(&efx->vport_lock);
	spin_lock_init(&efx->stats_lock);
	efx->num_mac_stats = MC_CMD_MAC_NSTATS;
	BUILD_BUG_ON(MC_CMD_MAC_NSTATS - 1 != MC_CMD_MAC_GENERATION_END);
	efx->stats_period_ms = STATS_PERIOD_MS_DEFAULT;
	efx->vi_stride = EFX_DEFAULT_VI_STRIDE;
	mutex_init(&efx->mac_lock);
#ifdef CONFIG_RFS_ACCEL
	mutex_init(&efx->rps_mutex);
	spin_lock_init(&efx->rps_hash_lock);
	/* Failure to allocate is not fatal, but may degrade ARFS performance */
	efx->rps_hash_table = kcalloc(EFX_ARFS_HASH_TABLE_SIZE,
				      sizeof(*efx->rps_hash_table), GFP_KERNEL);
#endif
	efx->phy_op = &efx_dummy_phy_operations;
	efx->mdio.dev = net_dev;
#ifdef EFX_NOT_UPSTREAM
	INIT_LIST_HEAD(&efx->dl_node);
	INIT_LIST_HEAD(&efx->dl_device_list);
	mutex_init(&efx->dl_block_kernel_mutex);
#endif
	INIT_WORK(&efx->mac_work, efx_mac_work);
	init_waitqueue_head(&efx->flush_wq);

#ifdef CONFIG_SFC_DEBUGFS
	mutex_init(&efx->debugfs_symlink_mutex);
#endif

	for (i = 0; i < EFX_MAX_CHANNELS; i++) {
		efx->channel[i] = efx_alloc_channel(efx, i, NULL);
		if (!efx->channel[i])
			goto fail1;
		efx->msi_context[i].efx = efx;
		efx->msi_context[i].index = i;
	}

	if (interrupt_mode == EFX_INT_MODE_LEGACY)
		netif_warn(efx, drv, efx->net_dev,
			   "Use of legacy interrupts is deprecated and will be removed in a future release\n");

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

	return 0;

fail1:
	efx_fini_struct(efx);
fail:
	efx_mtd_free(efx);
	return -ENOMEM;
}

static void efx_fini_struct(struct efx_nic *efx)
{
	int i;

#ifdef CONFIG_RFS_ACCEL
	kfree(efx->rps_hash_table);
#endif

	for (i = 0; i < EFX_MAX_CHANNELS; i++)
		if (efx->channel[i]) {
			efx_fini_channel(efx->channel[i]);
			kfree(efx->channel[i]);
			efx->channel[i] = NULL;
		}

#ifdef CONFIG_SFC_DEBUGFS
	mutex_destroy(&efx->debugfs_symlink_mutex);
#endif
	if (efx->mtd_struct) {
		efx->mtd_struct->efx = NULL;
		efx->mtd_struct = NULL;
	}
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

bool efx_filter_spec_equal(const struct efx_filter_spec *left,
			   const struct efx_filter_spec *right)
{
	if ((left->match_flags ^ right->match_flags) |
	    ((left->flags ^ right->flags) &
	     (EFX_FILTER_FLAG_RX | EFX_FILTER_FLAG_TX)))
		return false;

	return memcmp(&left->vport_id, &right->vport_id,
		      sizeof(struct efx_filter_spec) -
		      offsetof(struct efx_filter_spec, vport_id)) == 0;
}

u32 efx_filter_spec_hash(const struct efx_filter_spec *spec)
{
	BUILD_BUG_ON(offsetof(struct efx_filter_spec, vport_id) & 3);
	return jhash2((const u32 *)&spec->vport_id,
		      (sizeof(struct efx_filter_spec) -
		       offsetof(struct efx_filter_spec, vport_id)) / 4,
		      0);
}

#ifdef CONFIG_RFS_ACCEL
bool efx_rps_check_rule(struct efx_arfs_rule *rule, unsigned int filter_idx,
			bool *force)
{
	if (rule->filter_id == EFX_ARFS_FILTER_ID_PENDING) {
		/* ARFS is currently updating this entry, leave it */
		return false;
	}
	if (rule->filter_id == EFX_ARFS_FILTER_ID_ERROR) {
		/* ARFS tried and failed to update this, so it's probably out
		 * of date.  Remove the filter and the ARFS rule entry.
		 */
		rule->filter_id = EFX_ARFS_FILTER_ID_REMOVING;
		*force = true;
		return true;
	} else if (WARN_ON(rule->filter_id != filter_idx)) { /* can't happen */
		/* ARFS has moved on, so old filter is not needed.  Since we did
		 * not mark the rule with EFX_ARFS_FILTER_ID_REMOVING, it will
		 * not be removed by efx_rps_hash_del() subsequently.
		 */
		*force = true;
		return true;
	}
	/* Remove it iff ARFS wants to. */
	return true;
}

static
struct hlist_head *efx_rps_hash_bucket(struct efx_nic *efx,
				       const struct efx_filter_spec *spec)
{
	u32 hash = efx_filter_spec_hash(spec);

	WARN_ON(!spin_is_locked(&efx->rps_hash_lock));
	if (!efx->rps_hash_table)
		return NULL;
	return &efx->rps_hash_table[hash % EFX_ARFS_HASH_TABLE_SIZE];
}

struct efx_arfs_rule *efx_rps_hash_find(struct efx_nic *efx,
					const struct efx_filter_spec *spec)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (!head)
		return NULL;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec))
			return rule;
	}
	return NULL;
}

struct efx_arfs_rule *efx_rps_hash_add(struct efx_nic *efx,
				       const struct efx_filter_spec *spec,
				       bool *new)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (!head)
		return NULL;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec)) {
			*new = false;
			return rule;
		}
	}
	rule = kmalloc(sizeof(*rule), GFP_ATOMIC);
	*new = true;
	if (rule) {
		memcpy(&rule->spec, spec, sizeof(rule->spec));
		hlist_add_head(&rule->node, head);
	}
	return rule;
}

void efx_rps_hash_del(struct efx_nic *efx, const struct efx_filter_spec *spec)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (WARN_ON(!head))
		return;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec)) {
			/* Someone already reused the entry.  We know that if
			 * this check doesn't fire (i.e. filter_id == REMOVING)
			 * then the REMOVING mark was put there by our caller,
			 * because caller is holding a lock on filter table and
			 * only holders of that lock set REMOVING.
			 */
			if (rule->filter_id != EFX_ARFS_FILTER_ID_REMOVING)
				return;
			hlist_del(node);
			kfree(rule);
			return;
		}
	}
	/* We didn't find it. */
	WARN_ON(1);
}
#endif

/* RSS contexts.  We're using linked lists and crappy O(n) algorithms, because
 * (a) this is an infrequent control-plane operation and (b) n is small (max 64)
 */
struct efx_rss_context *efx_alloc_rss_context_entry(struct efx_nic *efx)
{
	struct list_head *head = &efx->rss_context.list;
	struct efx_rss_context *ctx, *new;
	u32 id = 1; /* Don't use zero, that refers to the master RSS context */

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	/* Search for first gap in the numbering */
	list_for_each_entry(ctx, head, list) {
		if (ctx->user_id != id)
			break;
		id++;
		/* Check for wrap.  If this happens, we have nearly 2^32
		 * allocated RSS contexts, which seems unlikely.
		 */
		if (WARN_ON_ONCE(!id))
			return NULL;
	}

	/* Create the new entry */
	new = kmalloc(sizeof(struct efx_rss_context), GFP_KERNEL);
	if (!new)
		return NULL;
	new->context_id = EFX_EF10_RSS_CONTEXT_INVALID;
	new->flags = RSS_CONTEXT_FLAGS_DEFAULT;
#ifdef EFX_NOT_UPSTREAM
	new->num_queues = 0;
#endif

	/* Insert the new entry into the gap */
	new->user_id = id;
	list_add_tail(&new->list, &ctx->list);
	return new;
}

struct efx_rss_context *efx_find_rss_context_entry(struct efx_nic *efx, u32 id)
{
	struct list_head *head = &efx->rss_context.list;
	struct efx_rss_context *ctx;

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	list_for_each_entry(ctx, head, list)
		if (ctx->user_id == id)
			return ctx;
	return NULL;
}

void efx_free_rss_context_entry(struct efx_rss_context *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

/* V-port allocations.  Same algorithms (and justification for them) as RSS
 * contexts, above.
 */
static struct efx_vport *efx_alloc_vport_entry(struct efx_nic *efx)
{
	struct list_head *head = &efx->vport.list;
	struct efx_vport *ctx, *new;
	u16 id = 1; /* Don't use zero, that refers to the driver master vport */

	WARN_ON(!mutex_is_locked(&efx->vport_lock));

	/* Search for first gap in the numbering */
	list_for_each_entry(ctx, head, list) {
		if (ctx->user_id != id)
			break;
		id++;
		/* Check for wrap.  If this happens, we have nearly 2^16
		 * allocated vports, which seems unlikely.
		 */
		if (WARN_ON_ONCE(!id))
			return NULL;
	}

	/* Create the new entry */
	new = kzalloc(sizeof(struct efx_vport), GFP_KERNEL);
	if (!new)
		return NULL;

	/* Insert the new entry into the gap */
	new->user_id = id;
	list_add_tail(&new->list, &ctx->list);
	return new;
}

struct efx_vport *efx_find_vport_entry(struct efx_nic *efx, u16 id)
{
	struct list_head *head = &efx->vport.list;
	struct efx_vport *ctx;

	WARN_ON(!mutex_is_locked(&efx->vport_lock));

	list_for_each_entry(ctx, head, list)
		if (ctx->user_id == id)
			return ctx;
	return NULL;
}

void efx_free_vport_entry(struct efx_vport *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

int efx_vport_add(struct efx_nic *efx, u16 vlan, bool vlan_restrict)
{
	struct efx_vport *vpx;
	int rc;

	if (!efx->type->vport_add)
		return -EOPNOTSUPP;

	mutex_lock(&efx->vport_lock);
	vpx = efx_alloc_vport_entry(efx);
	if (!vpx) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	vpx->vlan = vlan;
	vpx->vlan_restrict = vlan_restrict;
	rc = efx->type->vport_add(efx, vpx->vlan, vpx->vlan_restrict,
				  &vpx->vport_id);
	if (rc < 0)
		efx_free_vport_entry(vpx);
	else
		rc = vpx->user_id;
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

int efx_vport_del(struct efx_nic *efx, u16 port_user_id)
{
	struct efx_vport *vpx;
	int rc;

	if (!efx->type->vport_del)
		return -EOPNOTSUPP;

	mutex_lock(&efx->vport_lock);
	vpx = efx_find_vport_entry(efx, port_user_id);
	if (!vpx) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = efx->type->vport_del(efx, vpx->vport_id);
	if (!rc)
		efx_free_vport_entry(vpx);
out_unlock:
	mutex_unlock(&efx->vport_lock);
	return rc;
}

/**************************************************************************
 *
 * PCI interface
 *
 **************************************************************************/

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
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_unregister_irq_notifiers(efx);
#endif
	efx_clear_interrupt_affinity(efx);
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
#ifdef EFX_NOT_UPSTREAM
	if (efx_dl_supported(efx))
		efx_dl_unregister_nic(efx);
#endif
	dev_close(efx->net_dev);
	efx_disable_interrupts(efx);

	if (!efx_nic_hw_unavailable(efx))
		efx->state = STATE_UNINIT;

	/* Allow any queued efx_resets() to complete */
	rtnl_unlock();

#if defined(CONFIG_SFC_MTD) && defined(EFX_WORKAROUND_87308)
	(void)cancel_delayed_work_sync(&efx->mtd_struct->creation_work);
#endif

	if (efx->type->sriov_fini)
		efx->type->sriov_fini(efx);
	efx_unregister_netdev(efx);

#ifdef CONFIG_SFC_MTD
#ifdef EFX_WORKAROUND_87308
	if (atomic_read(&efx->mtd_struct->probed_flag) == 1)
		efx_mtd_remove(efx);
#else
	efx_mtd_remove(efx);
#endif
#endif

	efx_fini_debugfs_channels(efx);

	efx_pci_remove_main(efx);

	efx_fini_io(efx);
	netif_dbg(efx, drv, efx->net_dev, "shutdown successful\n");

	efx_fini_struct(efx);
	pci_set_drvdata(pci_dev, NULL);
	free_netdev(efx->net_dev);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_AER)
	pci_disable_pcie_error_reporting(pci_dev);
#endif
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

#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

	rc = efx_init_napi(efx);
	if (rc)
		goto fail2;

	down_write(&efx->filter_sem);
	rc = efx->type->init(efx);
	up_write(&efx->filter_sem);
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
	rc = efx_enable_interrupts(efx);
	if (rc)
		goto fail6;

	return 0;

 fail6:
#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_unregister_irq_notifiers(efx);
#endif
	efx_clear_interrupt_affinity(efx);
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
			      NETIF_F_TSO | NETIF_F_TSO_ECN |
			      NETIF_F_RXCSUM | NETIF_F_RXALL);
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
	efx->fixed_features |= NETIF_F_HW_VLAN_CTAG_TX;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES)
	/* Mask for features that also apply to VLAN devices */
	net_dev->vlan_features |= (NETIF_F_CSUM_MASK | NETIF_F_SG |
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

	/* Disable receiving frames with bad FCS, by default. */
	net_dev->features &= ~NETIF_F_RXALL;

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
		   "Solarflare NIC detected: device %04x:%04x subsys %04x:%04x\n",
		   efx->pci_dev->vendor, efx->pci_dev->device,
		   efx->pci_dev->subsystem_vendor,
		   efx->pci_dev->subsystem_device);

	/* Set up basic I/O (BAR mappings etc) */
	rc = efx_init_io(efx);
	if (rc)
		goto fail2;

	rc = efx_pci_probe_post_io(efx);
	if (rc && (rc != -EBUSY)) {
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
	if (PCI_FUNC(pci_dev->devfn) == 0)
		efx_mcdi_log_puts(efx, "probe");

#ifdef CONFIG_SFC_MTD
#ifdef EFX_WORKAROUND_87308
	schedule_delayed_work(&efx->mtd_struct->creation_work, 5 * HZ);
#else
	/* Try to create MTDs, but allow this to fail */
	rtnl_lock();
	rc = efx_mtd_probe(efx);
	rtnl_unlock();
#endif
#endif

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
	(void)pci_enable_pcie_error_reporting(pci_dev);
#endif

	if (efx->type->udp_tnl_push_ports)
		efx->type->udp_tnl_push_ports(efx);


	return 0;

 fail3:
	efx_fini_io(efx);
 fail2:
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

#ifdef EFX_NOT_UPSTREAM
	efx_dl_reset_suspend(efx);
#endif

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

#ifdef EFX_NOT_UPSTREAM
	efx_dl_reset_resume(efx, efx->state != STATE_DISABLED);
#endif

	rtnl_unlock();

	/* Reschedule any quenched resets scheduled during efx_pm_freeze() */
	queue_work(reset_workqueue, &efx->reset_work);

	return 0;

fail:
#ifdef EFX_NOT_UPSTREAM
	efx_dl_reset_resume(efx, false);
#endif

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
	down_write(&efx->filter_sem);
	rc = efx->type->init(efx);
	up_write(&efx->filter_sem);
	if (rc)
		goto fail;
	rc = efx_pm_thaw(dev);
	return rc;

fail:
#ifdef EFX_NOT_UPSTREAM
	efx_dl_reset_resume(efx, false);
#endif
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
		efx->reset_count = 0;
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
#else
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
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= efx_ioctl,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_CHANGE_MTU)
	.extended.ndo_change_mtu = efx_change_mtu,
#else
	.ndo_change_mtu		= efx_change_mtu,
#endif
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
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO)
	.extended.ndo_set_vf_vlan = efx_sriov_set_vf_vlan,
#else
	.ndo_set_vf_vlan        = efx_sriov_set_vf_vlan,
#endif
	.ndo_get_vf_config      = efx_sriov_get_vf_config,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_LINK_STATE)
	.ndo_set_vf_link_state  = efx_sriov_set_vf_link_state,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_SPOOFCHK)
	.ndo_set_vf_spoofchk	= efx_sriov_set_vf_spoofchk,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.ndo_get_phys_port_id	= efx_get_phys_port_id,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_NAME)
	.ndo_get_phys_port_name	= efx_get_phys_port_name,
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	.ndo_vlan_rx_register	= efx_vlan_rx_register,
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= efx_netpoll,
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll		= efx_busy_poll,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NETDEV_RFS_INFO)
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer	= efx_filter_rfs,
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_UDP_TUNNEL_ADD)
	.ndo_udp_tunnel_add	= efx_udp_tunnel_add,
	.ndo_udp_tunnel_del	= efx_udp_tunnel_del,
#else
#if defined(EFX_HAVE_NDO_ADD_VXLAN_PORT)
	.ndo_add_vxlan_port	= efx_vxlan_add_port,
	.ndo_del_vxlan_port	= efx_vxlan_del_port,
#endif
#if defined(EFX_HAVE_NDO_ADD_GENEVE_PORT)
	.ndo_add_geneve_port	= efx_geneve_add_port,
	.ndo_del_geneve_port	= efx_geneve_del_port,
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	.ndo_bpf		= efx_xdp,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	.ndo_xdp_xmit		= efx_xdp_xmit,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
	.ndo_xdp_flush		= efx_xdp_flush,
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE)
	.ndo_size		= sizeof(struct net_device_ops),
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_SIZE_RH)
	.ndo_size_rh		= sizeof(struct net_device_ops),
#endif
};

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NET_DEVICE_OPS_EXT)
const struct net_device_ops_ext efx_net_device_ops_ext = {
#ifdef EFX_HAVE_EXT_NDO_SET_FEATURES
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	.ndo_fix_features      = efx_fix_features,
#endif
	.ndo_set_features      = efx_set_features,
#endif

#ifdef EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID
	.ndo_get_phys_port_id	= efx_get_phys_port_id,
#endif
#ifdef CONFIG_SFC_SRIOV
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

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP)
	rss_cpu_usage = kzalloc(NR_CPUS * sizeof(rss_cpu_usage[0]), GFP_KERNEL);
	if (rss_cpu_usage == NULL) {
		rc = -ENOMEM;
		goto err_cpu_usage;
	}
#endif

	rc = pci_register_driver(&efx_pci_driver);
	if (rc < 0) {
		printk(KERN_ERR "pci_register_driver failed, rc=%d\n", rc);
		goto err_pci;
	}

	return 0;

 err_pci:
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP)
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
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP)
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
