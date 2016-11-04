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

#include <linux/pci.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/ipv6.h>
#include <linux/if_ether.h>
#if !defined(EFX_USE_KCOMPAT)
#include <linux/highmem.h>
#else
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/highmem.h>
#endif
#endif
#include <linux/moduleparam.h>
#include <linux/cache.h>
#include "net_driver.h"
#include "efx.h"
#include "io.h"
#include "nic.h"
#include "tx.h"
#include "workarounds.h"
#include "ef10_regs.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif

/* Size of page-based copy buffers, used for TSO headers (normally),
 * padding and linearisation.
 *
 * Must be power-of-2 before subtracting NET_IP_ALIGN.  Values much
 * less than 128 are fairly useless; values larger than EFX_PAGE_SIZE
 * or PAGE_SIZE would be harder to support.
 */
#define TX_CB_ORDER_MIN	4
#define TX_CB_ORDER_MAX	min(12, PAGE_SHIFT)
#define TX_CB_ORDER_DEF	7
static unsigned int tx_cb_order __read_mostly = TX_CB_ORDER_DEF;
static unsigned int
tx_cb_size __read_mostly = (1 << TX_CB_ORDER_DEF) - NET_IP_ALIGN;

#if defined(EFX_NOT_UPSTREAM) && !defined(__VMKLNX__)
static int __init
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NON_CONST_KERNEL_PARAM)
tx_copybreak_set(const char *val, const struct kernel_param *kp)
#else
tx_copybreak_set(const char *val, struct kernel_param *kp)
#endif
{
	int rc;

	rc = param_set_uint(val, kp);
	if (rc)
		return rc;

	/* If disabled, copy buffers are still needed for VLAN tag insertion */
	if (!tx_cb_size) {
		tx_cb_order = TX_CB_ORDER_MIN;
		return 0;
	}

	tx_cb_order = order_base_2(tx_cb_size + NET_IP_ALIGN);
	if (tx_cb_order < TX_CB_ORDER_MIN)
		tx_cb_order = TX_CB_ORDER_MIN;
	else if (tx_cb_order > TX_CB_ORDER_MAX)
		tx_cb_order = TX_CB_ORDER_MAX;
	tx_cb_size = (1 << tx_cb_order) - NET_IP_ALIGN;
	return 0;
}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_KERNEL_PARAM_OPS)
static const struct kernel_param_ops tx_copybreak_ops = {
	.set = tx_copybreak_set,
	.get = param_get_uint,
};
module_param_cb(tx_copybreak, &tx_copybreak_ops, &tx_cb_size, 0444);
#else
module_param_call(tx_copybreak, tx_copybreak_set, param_get_uint,
		  &tx_cb_size, 0444);
#endif
MODULE_PARM_DESC(tx_copybreak,
		 "Maximum size of packet that may be copied to a new buffer on transmit, minimum is 16 bytes or 0 to disable (uint)");
#endif /* EFX_NOT_UPSTREAM && !__VMKLNX__ */

#ifdef EFX_USE_PIO

#define EFX_PIOBUF_SIZE_DEF ALIGN(256, L1_CACHE_BYTES)
unsigned int efx_piobuf_size __read_mostly = EFX_PIOBUF_SIZE_DEF;

#ifdef EFX_NOT_UPSTREAM
/* The size of the on-hardware buffer should always be at least this big;
 * it might be bigger but that's ok.
 */
#define EFX_PIOBUF_SIZE_MAX ER_DZ_TX_PIOBUF_SIZE

static int __init
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NON_CONST_KERNEL_PARAM)
efx_piobuf_size_set(const char *val, const struct kernel_param *kp)
#else
efx_piobuf_size_set(const char *val, struct kernel_param *kp)
#endif
{
	int rc;

	rc = param_set_uint(val, kp);
	if (rc)
		return rc;

	BUILD_BUG_ON(EFX_PIOBUF_SIZE_DEF > EFX_PIOBUF_SIZE_MAX);

	efx_piobuf_size = min_t(unsigned int,
				ALIGN(efx_piobuf_size, L1_CACHE_BYTES),
				EFX_PIOBUF_SIZE_MAX);
	return 0;
}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_KERNEL_PARAM_OPS)
static const struct kernel_param_ops efx_piobuf_size_ops = {
	.set = efx_piobuf_size_set,
	.get = param_get_uint,
};
module_param_cb(piobuf_size, &efx_piobuf_size_ops, &efx_piobuf_size, 0444);
#else
module_param_call(piobuf_size, efx_piobuf_size_set, param_get_uint,
		  &efx_piobuf_size, 0444);
#endif
MODULE_PARM_DESC(piobuf_size,
		 "[SFC9100-family] Maximum size of packet that may be copied to a PIO buffer on transmit (uint)");
#endif /* EFX_NOT_UPSTREAM */

#endif /* EFX_USE_PIO */

static inline u8 *efx_tx_get_copy_buffer(struct efx_tx_queue *tx_queue,
					 struct efx_tx_buffer *buffer)
{
	unsigned int index = efx_tx_queue_get_insert_index(tx_queue);
	struct efx_buffer *page_buf =
		&tx_queue->cb_page[index >> (PAGE_SHIFT - tx_cb_order)];
	unsigned int offset =
		((index << tx_cb_order) + NET_IP_ALIGN) & (PAGE_SIZE - 1);

	if (unlikely(!page_buf->addr) &&
	    efx_nic_alloc_buffer(tx_queue->efx, page_buf, PAGE_SIZE,
				 GFP_ATOMIC))
		return NULL;
	buffer->dma_addr = page_buf->dma_addr + offset;
	buffer->unmap_len = 0;
	return (u8 *)page_buf->addr + offset;
}

u8 *efx_tx_get_copy_buffer_limited(struct efx_tx_queue *tx_queue,
				   struct efx_tx_buffer *buffer, size_t len)
{
	if (len > tx_cb_size)
		return NULL;
	return efx_tx_get_copy_buffer(tx_queue, buffer);
}

static void efx_dequeue_buffer(struct efx_tx_queue *tx_queue,
			       struct efx_tx_buffer *buffer,
			       unsigned int *pkts_compl,
			       unsigned int *bytes_compl)
{
	if (buffer->unmap_len) {
		struct device *dma_dev = &tx_queue->efx->pci_dev->dev;
		dma_addr_t unmap_addr = buffer->dma_addr - buffer->dma_offset;
		if (buffer->flags & EFX_TX_BUF_MAP_SINGLE)
			dma_unmap_single(dma_dev, unmap_addr, buffer->unmap_len,
					 DMA_TO_DEVICE);
		else
			dma_unmap_page(dma_dev, unmap_addr, buffer->unmap_len,
				       DMA_TO_DEVICE);
		buffer->unmap_len = 0;
	}

	if (buffer->flags & EFX_TX_BUF_SKB) {
		struct sk_buff *skb = (struct sk_buff *)buffer->skb;

		(*pkts_compl)++;
		(*bytes_compl) += skb->len;

#if defined(EFX_HAVE_SKB_TSTAMP_TX)
		if (tx_queue->timestamping &&
		    (tx_queue->completed_timestamp_major ||
		     tx_queue->completed_timestamp_minor)) {
			struct skb_shared_hwtstamps hwtstamp;

			hwtstamp.hwtstamp =
				efx_ptp_nic_to_kernel_time(tx_queue);
			skb_tstamp_tx(skb, &hwtstamp);

			tx_queue->completed_timestamp_major = 0;
			tx_queue->completed_timestamp_minor = 0;
		}
#endif
		dev_kfree_skb_any(skb);
		netif_vdbg(tx_queue->efx, tx_done, tx_queue->efx->net_dev,
			   "TX queue %d transmission id %x complete\n",
			   tx_queue->queue, tx_queue->read_count);
	} else if (buffer->flags & EFX_TX_BUF_HEAP) {
		kfree(buffer->heap_buf);
	}

	buffer->len = 0;
	buffer->flags = 0;
}

unsigned int efx_tx_max_skb_descs(struct efx_nic *efx)
{
	/* Header and payload descriptor for each output segment, plus
	 * one for every input fragment boundary within a segment
	 */
	unsigned int max_descs = EFX_TSO_MAX_SEGS * 2 + MAX_SKB_FRAGS;

	/* Possibly one more per segment for the alignment workaround,
	 * or for option descriptors
	 */
	if (EFX_WORKAROUND_5391(efx) || efx_nic_rev(efx) >= EFX_REV_HUNT_A0)
		max_descs += EFX_TSO_MAX_SEGS;

	/* Possibly more for PCIe page boundaries within input fragments */
	if (PAGE_SIZE > EFX_PAGE_SIZE)
		max_descs += max_t(unsigned int, MAX_SKB_FRAGS,
				   DIV_ROUND_UP(GSO_MAX_SIZE, EFX_PAGE_SIZE));

	return max_descs;
}

static void efx_tx_maybe_stop_queue(struct efx_tx_queue *txq1)
{
	/* We need to consider both queues that the net core sees as one */
	struct efx_tx_queue *txq2;
	struct efx_nic *efx = txq1->efx;
	unsigned int fill_level;

	fill_level = efx_channel_tx_fill_level(txq1->channel);
	if (likely(fill_level < efx->txq_stop_thresh))
		return;

	/* We used the stale old_read_count above, which gives us a
	 * pessimistic estimate of the fill level (which may even
	 * validly be >= efx->txq_entries).  Now try again using
	 * read_count (more likely to be a cache miss).
	 *
	 * If we read read_count and then conditionally stop the
	 * queue, it is possible for the completion path to race with
	 * us and complete all outstanding descriptors in the middle,
	 * after which there will be no more completions to wake it.
	 * Therefore we stop the queue first, then read read_count
	 * (with a memory barrier to ensure the ordering), then
	 * restart the queue if the fill level turns out to be low
	 * enough.
	 */
	netif_tx_stop_queue(txq1->core_txq);
	smp_mb();
	efx_for_each_channel_tx_queue(txq2, txq1->channel)
		txq2->old_read_count = ACCESS_ONCE(txq2->read_count);

	fill_level = efx_channel_tx_fill_level(txq1->channel);
	EFX_BUG_ON_PARANOID(fill_level >= efx->txq_entries);
	if (likely(fill_level < efx->txq_stop_thresh)) {
		smp_mb();
		if (likely(!efx->loopback_selftest))
			netif_tx_start_queue(txq1->core_txq);
	}
}

static int efx_enqueue_skb_copy(struct efx_tx_queue *tx_queue,
				struct sk_buff *skb)
{
	unsigned int min_len = tx_queue->tx_min_size;
	unsigned int copy_len = skb->len;
	struct efx_tx_buffer *buffer;
	u8 *copy_buffer;
	int rc;

	EFX_BUG_ON_PARANOID(copy_len > tx_cb_size);

	buffer = efx_tx_queue_get_insert_buffer(tx_queue);

	copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
	if (unlikely(!copy_buffer))
		return -ENOMEM;

	rc = skb_copy_bits(skb, 0, copy_buffer, copy_len);
	EFX_WARN_ON_PARANOID(rc);
	if (unlikely(copy_len < min_len)) {
		memset(copy_buffer + copy_len, 0, min_len - copy_len);
		buffer->len = min_len;
	} else {
		buffer->len = copy_len;
	}

	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB;

	++tx_queue->insert_count;
	return rc;
}

#ifdef EFX_USE_PIO

struct efx_short_copy_buffer {
	int used;
	u8 buf[L1_CACHE_BYTES];
};

/* Copy in explicit 64-bit writes. */
static void efx_memcpy_64(void __iomem *dest, void *src, size_t len)
{
	u64 *src64 = src;
	u64 __iomem *dest64 = dest;
	size_t l64 = len / 8;
	size_t i;

	WARN_ON_ONCE(len % 8 != 0);
	WARN_ON_ONCE(((u8 *)dest - (u8 *) 0) % 8 != 0);

	for(i = 0; i < l64; i++)
		writeq(src64[i], &dest64[i]);
}

/* Copy to PIO, respecting that writes to PIO buffers must be dword aligned.
 * Advances piobuf pointer. Leaves additional data in the copy buffer.
 */
static void efx_memcpy_toio_aligned(struct efx_nic *efx, u8 __iomem **piobuf,
				    u8 *data, int len,
				    struct efx_short_copy_buffer *copy_buf)
{
	int block_len = len & ~(sizeof(copy_buf->buf) - 1);

	efx_memcpy_64(*piobuf, data, block_len);
	*piobuf += block_len;
	len -= block_len;

	if (len) {
		data += block_len;
		BUG_ON(copy_buf->used);
		BUG_ON(len > sizeof(copy_buf->buf));
		memcpy(copy_buf->buf, data, len);
		copy_buf->used = len;
	}
}

/* Copy to PIO, respecting dword alignment, popping data from copy buffer first.
 * Advances piobuf pointer. Leaves additional data in the copy buffer.
 */
static void efx_memcpy_toio_aligned_cb(struct efx_nic *efx, u8 __iomem **piobuf,
				       u8 *data, int len,
				       struct efx_short_copy_buffer *copy_buf)
{
	if (copy_buf->used) {
		/* if the copy buffer is partially full, fill it up and write */
		int copy_to_buf =
			min_t(int, sizeof(copy_buf->buf) - copy_buf->used, len);

		memcpy(copy_buf->buf + copy_buf->used, data, copy_to_buf);
		copy_buf->used += copy_to_buf;

		/* if we didn't fill it up then we're done for now */
		if (copy_buf->used < sizeof(copy_buf->buf))
			return;

		efx_memcpy_64(*piobuf, copy_buf->buf, sizeof(copy_buf->buf));
		*piobuf += sizeof(copy_buf->buf);
		data += copy_to_buf;
		len -= copy_to_buf;
		copy_buf->used = 0;
	}

	efx_memcpy_toio_aligned(efx, piobuf, data, len, copy_buf);
}

static void efx_flush_copy_buffer(struct efx_nic *efx, u8 __iomem *piobuf,
				  struct efx_short_copy_buffer *copy_buf)
{
	/* if there's anything in it, write the whole buffer, including junk */
	if (copy_buf->used)
		efx_memcpy_64(piobuf, copy_buf->buf, sizeof(copy_buf->buf));
}

/* Traverse skb structure and copy fragments in to PIO buffer.
 * Advances piobuf pointer.
 */
static void efx_skb_copy_bits_to_pio(struct efx_nic *efx, struct sk_buff *skb,
				     u8 __iomem **piobuf,
				     struct efx_short_copy_buffer *copy_buf)
{
	int i;

	efx_memcpy_toio_aligned(efx, piobuf, skb->data, skb_headlen(skb),
				copy_buf);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u8 *vaddr;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_KMAP_ATOMIC)
#ifdef CONFIG_HIGHMEM
		BUG_ON(in_irq());
		local_bh_disable();
#endif
		vaddr = kmap_atomic(skb_frag_page(f), KM_SKB_DATA_SOFTIRQ);
#else
		vaddr = kmap_atomic(skb_frag_page(f));
#endif

		efx_memcpy_toio_aligned_cb(efx, piobuf, vaddr + f->page_offset,
					   skb_frag_size(f), copy_buf);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_KMAP_ATOMIC)
		kunmap_atomic(vaddr, KM_SKB_DATA_SOFTIRQ);
#ifdef CONFIG_HIGHMEM
		local_bh_enable();
#endif
#else
		kunmap_atomic(vaddr);
#endif
	}

	EFX_BUG_ON_PARANOID(skb_shinfo(skb)->frag_list);
}

static int efx_enqueue_skb_pio(struct efx_tx_queue *tx_queue,
			       struct sk_buff *skb)
{
	struct efx_tx_buffer *buffer =
		efx_tx_queue_get_insert_buffer(tx_queue);
	u8 __iomem *piobuf = tx_queue->piobuf;

	/* Copy to PIO buffer. Ensure the writes are padded to the end
	 * of a cache line, as this is required for write-combining to be
	 * effective on at least x86.
	 */
#ifdef EFX_USE_KCOMPAT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0) && defined(CONFIG_SLOB)
	#error "This function doesn't work with SLOB and Linux < 3.4"
	/* SLOB is for tiny embedded systems; you probably want SLAB */
#endif
#endif

	if (skb_shinfo(skb)->nr_frags) {
		/* The size of the copy buffer will ensure all writes
		 * are the size of a cache line.
		 */
		struct efx_short_copy_buffer copy_buf;

		copy_buf.used = 0;

		efx_skb_copy_bits_to_pio(tx_queue->efx, skb,
					 &piobuf, &copy_buf);
		efx_flush_copy_buffer(tx_queue->efx, piobuf, &copy_buf);
	} else {
		/* Pad the write to the size of a cache line.
		 * We can do this because we know the skb_shared_info struct is
		 * after the source, and the destination buffer is big enough.
		 */
		BUILD_BUG_ON(L1_CACHE_BYTES >
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
		efx_memcpy_64(tx_queue->piobuf, skb->data,
			      ALIGN(skb->len, L1_CACHE_BYTES));
	}

	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB | EFX_TX_BUF_OPTION;

	EFX_POPULATE_QWORD_5(buffer->option,
			     ESF_DZ_TX_DESC_IS_OPT, 1,
			     ESF_DZ_TX_OPTION_TYPE, 1 /* PIO */,
			     ESF_DZ_TX_PIO_CONT, 0,
			     ESF_DZ_TX_PIO_BYTE_CNT, skb->len,
			     ESF_DZ_TX_PIO_BUF_ADDR,
			     tx_queue->piobuf_offset);
	++tx_queue->insert_count;
	return 0;
}

/* Decide whether we can use TX PIO, ie. write packet data directly into
 * a buffer on the device.  This can reduce latency at the expense of
 * throughput, so we only do this if both hardware and software TX rings
 * are empty, including all queues for the channel.  This also ensures that
 * only one packet at a time can be using the PIO buffer. If the xmit_more
 * flag is set then we don't use this - there'll be another packet along
 * shortly and we want to hold off the doorbell.
 */
static inline bool efx_tx_may_pio(struct efx_channel *channel,
				  struct efx_tx_queue *tx_queue,
				  struct sk_buff *skb)
{
	bool empty = true;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
	if (!tx_queue->piobuf || (skb->len > efx_piobuf_size) || skb->xmit_more)
#else
	if (!tx_queue->piobuf || (skb->len > efx_piobuf_size))
#endif
		return false;

	EFX_BUG_ON_PARANOID(!channel->efx->type->option_descriptors);

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		empty = empty &&
			__efx_nic_tx_is_empty(tx_queue,
					      tx_queue->packet_write_count);
	}

	return empty;
}
#endif /* EFX_USE_PIO */

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_ENABLE_SFC_XPS)
/* Whether to do XPS in the SFC driver, for use when kernel XPS is not enabled
 * or not configured
 */
static bool sxps_enabled = false;
module_param(sxps_enabled, bool, 0444);
MODULE_PARM_DESC(sxps_enabled, "Whether to perform TX flow steering at the "
			       "driver level. This or XPS is required for "
			       "SARFS.");
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
/* Size of the alt arfs hash table. Must be a power of 2. The size of this table
 * dictates the maximum number of filters we can use for this feature
 */
static unsigned int sarfs_table_size = 256;
module_param(sarfs_table_size, uint, 0444);
MODULE_PARM_DESC(sarfs_table_size, "Size of the SARFS hash table.");

/* The maximum rate we'll do alt arfs operations in ms */
static unsigned int sarfs_global_holdoff_ms = 10;
module_param(sarfs_global_holdoff_ms, uint, 0444);
MODULE_PARM_DESC(sarfs_global_holdoff_ms,
	"Maximum rate at which SARFS operations can occur.");

/* The maximum rate we'll do alt arfs operations on a single hash table entry.
 * This is designed to prevent filter flapping on hash collision */
static const unsigned int sarfs_entry_holdoff_ms = 1000;

/* The rate at which we'll sample TCP packets for new flows and CPU switches.
 * 0 = disable alt arfs. */
static unsigned int sarfs_sample_rate;
module_param(sarfs_sample_rate, uint, 0444);
MODULE_PARM_DESC(sarfs_sample_rate,
	"Frequency which SARFS samples packets. "
	"0 = disable, N = sample every N packets.");

/* Use destination only filters. This is the local IP and Port from the point
 * of view of the NIC */
static bool sarfs_dest_only = false;
module_param(sarfs_dest_only, bool, 0444);
MODULE_PARM_DESC(sarfs_dest_only,
	"Only insert SARFS filters that match on the destination IP and PORT");

static bool efx_sarfs_keys_eq(struct efx_sarfs_key *a,
				 struct efx_sarfs_key *b)
{
	return memcmp(a, b, sizeof(struct efx_sarfs_key)) == 0;
}

int efx_sarfs_init(struct efx_nic *efx)
{
	struct efx_sarfs_state *st = &efx->sarfs_state;
	bool xps_available =
#ifdef CONFIG_XPS
		true;
#else
		sxps_enabled;
#endif

	/* SARFS won't work unless sharing channels between TX and RX.
	 * It also won't work unless we have TX steering functionality.
	 */
	if (sarfs_sample_rate && sarfs_table_size) {
		if (!(efx->net_dev->features & NETIF_F_NTUPLE)) {
			netif_info(efx, drv, efx->net_dev, "notice: SARFS is "
				   "enabled but could not be activated because "
				   "the filters are not supported in this "
				   "firmware variant\n");
		} else if (efx->tx_channel_offset) {
			netif_info(efx, drv, efx->net_dev, "notice: SARFS is "
				   "enabled but could not be activated because "
				   "TX and RX channels are separate\n");
		} else if (!xps_available) {
			netif_info(efx, drv, efx->net_dev, "notice: SARFS is "
				   "enabled but could not be activated because "
				   "XPS is not available\n");
		} else {
			EFX_BUG_ON_PARANOID(st->enabled);

			st->conns = kzalloc(sarfs_table_size *
					    sizeof(struct efx_sarfs_entry),
					    GFP_KERNEL);
			if (!st->conns)
				return -ENOMEM;

			st->enabled = true;
		}
	}

	return 0;
}

void efx_sarfs_fini(struct efx_nic *efx)
{
	int i;
	struct efx_sarfs_state *st = &efx->sarfs_state;

	if (st->enabled)
		for (i = 0; i < sarfs_table_size; ++i)
			if (st->conns[i].filter_inserted)
				efx->type->filter_remove_safe(efx,
					EFX_FILTER_PRI_SARFS,
					st->conns[i].filter_id);
	kfree(st->conns);
	st->conns = NULL;
	st->enabled = false;
}

static int efx_sarfs_filter_insert(struct efx_nic *efx,
				      int rxq_id,
				      struct efx_sarfs_key *key)
{
	struct efx_filter_spec spec;

	efx_filter_init_rx(&spec, EFX_FILTER_PRI_SARFS,
			   efx->rx_scatter ? EFX_FILTER_FLAG_RX_SCATTER : 0,
			   rxq_id);

	spec.ether_type = htons(ETH_P_IP);
	spec.ip_proto = IPPROTO_TCP;
	spec.match_flags = sarfs_dest_only ?
		EFX_FILTER_MATCH_FLAGS_RFS_DEST_ONLY :
		EFX_FILTER_MATCH_FLAGS_RFS;
	spec.rem_host[0] = key->raddr;
	spec.loc_host[0] = key->laddr;
	spec.rem_port = key->rport;
	spec.loc_port = key->lport;

	return efx->type->filter_async_insert(efx, &spec);
}

static int efx_sarfs_filter_remove(struct efx_nic *efx,
			 	   struct efx_sarfs_entry *entry)
{
	return efx->type->filter_async_remove(efx, entry->filter_id);
}

/* Disable insertion of any new SARFS filters.
 * This doesn't cause any existing SARFS filters to be removed, but they
 * should gradually be subsumed by real ARFS filters.
 */
void efx_sarfs_disable(struct efx_nic *efx)
{
	if (cmpxchg(&efx->sarfs_state.enabled, true, false) == true)
		netif_dbg(efx, drv, efx->net_dev, "disabling SARFS\n");
}

static void efx_sarfs_insert(struct efx_nic *efx,
			     struct efx_sarfs_entry *entry,
			     int rxq_id,
			     struct efx_sarfs_key *key)
{
	s32 filter_id;

	/* if a previous filter exists with the same key, it will be
	 * transparently replaced, so don't remove
	 */
	if (entry->filter_inserted && !efx_sarfs_keys_eq(&entry->key, key)) {
		/* remove old filter */
		int rc = efx_sarfs_filter_remove(efx, entry);

		if (rc != 0 && rc != -ENOENT) {
			/* reassert entry holdoff period so we don't try to
			 * spam remove a problem filter
			 */
			entry->last_modified = jiffies;
			entry->problem = true;
			return;
		}
	}

	/* insert new filter */
	filter_id = efx_sarfs_filter_insert(efx, rxq_id, key);
	if (filter_id >= 0) {
		entry->filter_inserted = true;
		entry->filter_id = filter_id;
		entry->key = *key;
		entry->last_modified = jiffies;
		entry->problem = false;
		efx->sarfs_state.last_modified = jiffies;
		entry->queue = rxq_id;
	} else {
		entry->filter_inserted = false;
		/* assert entry holdoff period so we don't try to spam insert a
		 * problem filter
		 */
		entry->last_modified = jiffies;
		entry->problem = true;
	}
}

static u32 efx_sarfs_hash(struct efx_sarfs_key *key, bool partial)
{
	u32 part = (__force u32)ntohs(key->lport);

	if (!partial)
		part = (__force u32)(part ^ ntohs(key->rport));

	return (__force u32)(ip_fast_csum(&key->laddr, 2) ^ part);
}

static inline bool efx_sarfs_entry_in_holdoff(struct efx_sarfs_entry *entry)
{
	return jiffies - entry->last_modified <
		msecs_to_jiffies(sarfs_entry_holdoff_ms);
}

static void efx_sarfs(struct efx_nic *efx,
		      struct efx_tx_queue *txq,
		      struct efx_sarfs_key *key)
{
	u32 index = efx_sarfs_hash(key, sarfs_dest_only) % sarfs_table_size;
	struct efx_sarfs_entry *entry = &efx->sarfs_state.conns[index];
	int rxq_id = efx_rx_queue_index(efx_channel_get_rx_queue(txq->channel));
	bool keys_eq = efx_sarfs_keys_eq(&entry->key, key);

#define EFX_SARFS_ENTRY_NEEDS_UPDATE                                 \
		((keys_eq &&                                            \
		  (!entry->filter_inserted ||                           \
		   (entry->queue != rxq_id &&                           \
		    !(entry->problem &&                                 \
		      efx_sarfs_entry_in_holdoff(entry))))) ||       \
		 (!keys_eq && !efx_sarfs_entry_in_holdoff(entry)))

	/* do the check first without the spinlock. this is ok because if we
	 * get an inconsistent set of values and get a false negative we'll
	 * miss an update but hopefully get it right at our next sample of this
	 * flow, and if we get a false positive we'll discard it when we check
	 * again with the spinlock.
	 */
	if (EFX_SARFS_ENTRY_NEEDS_UPDATE) {
		spin_lock_bh(&efx->sarfs_state.lock);

		/* recheck the global holdoff and entry now we have the lock */
		if (jiffies - efx->sarfs_state.last_modified >=
				msecs_to_jiffies(sarfs_global_holdoff_ms)) {
			keys_eq = efx_sarfs_keys_eq(&entry->key, key);
			if (EFX_SARFS_ENTRY_NEEDS_UPDATE) {
				efx_sarfs_insert(efx,  entry, rxq_id, key);
#ifdef CONFIG_SFC_DEBUGFS
				++txq->sarfs_update;
#endif
			}
		}

		spin_unlock_bh(&efx->sarfs_state.lock);
	}

#undef EFX_SARFS_ENTRY_NEEDS_UPDATE
}

/* Inspect an skb for SARFS.
 * Only inspect if we're not in our global holdoff period, only inspect TCP
 * and only if the SYN flag is set, or it's the Nth TCP packet on this channel
 */
static void _efx_sarfs_skb(struct efx_nic *efx,
			   struct efx_tx_queue *txq,
			   struct sk_buff *skb)
{
	/* If we're still within the holdoff period of our last operation,
	 * don't check.
	 */
	if (jiffies - efx->sarfs_state.last_modified <
			msecs_to_jiffies(sarfs_global_holdoff_ms))
		return;


	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iphdr = ip_hdr(skb);

		if (iphdr->protocol == IPPROTO_TCP) {
			struct tcphdr *tcphdr = tcp_hdr(skb);
			if ((++txq->sarfs_sample_count == sarfs_sample_rate) ||
				(tcphdr->syn)) {

				struct efx_sarfs_key key = {
					.laddr = iphdr->saddr,
					.raddr = iphdr->daddr,
					.lport = tcphdr->source,
					.rport = tcphdr->dest
				};

				efx_sarfs(efx, txq, &key);
				txq->sarfs_sample_count = 0;
			}
		}
	}
}

/* Inspect an skb for SARFS if the feature is enabled.
 * Inline version for speed in the case SARFS is disabled.
 */
static inline void efx_sarfs_skb(struct efx_nic *efx,
				 struct efx_tx_queue *txq,
				 struct sk_buff *skb)
{
	if (efx->sarfs_state.enabled)
		return _efx_sarfs_skb(efx, txq, skb);
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_ENABLE_SFC_XPS)
/* query smp_processor_id to try to match the skb to the TX queue the user
 * space process is running on.
 */
static int get_xps_queue(struct net_device *dev, struct sk_buff *skb)
{
#ifdef EFX_HAVE_SKB_GET_RX_QUEUE
	if (skb_rx_queue_recorded(skb))
		return skb_get_rx_queue(skb);
#endif

	if (sxps_enabled) {
		struct efx_nic *efx = netdev_priv(dev);
		int cpu = smp_processor_id();

		EFX_BUG_ON_PARANOID(cpu < 0);
		EFX_BUG_ON_PARANOID(cpu >= num_possible_cpus());
		if (likely(efx->cpu_channel_map))
			return efx->cpu_channel_map[cpu];
	}

	return -1;
}

static u16 efx_select_queue_int(struct net_device *dev, struct sk_buff *skb)
{
	int queue_index = -1;
	/* counterintuitively, always allow out of order TCP, since this is
	 * required to make good use of the SARFS feature.
	 */
	bool ooo_okay = skb->protocol == htons(ETH_P_IP) &&
		ip_hdr(skb)->protocol == IPPROTO_TCP;
#ifdef EFX_HAVE_SK_SET_TX_QUEUE
	struct sock *sk = skb->sk;

	queue_index = sk_tx_queue_get(sk);
#endif
#ifdef EFX_HAVE_SKB_OOO_OKAY
	ooo_okay = ooo_okay || skb->ooo_okay;
#endif

	if (queue_index < 0 || queue_index >= dev->real_num_tx_queues ||
	    ooo_okay) {
		int new_index = get_xps_queue(dev, skb);

		if (new_index < 0)
			new_index = skb_tx_hash(dev, skb);

#ifdef EFX_HAVE_SK_SET_TX_QUEUE
		if (queue_index != new_index && sk &&
				rcu_access_pointer(sk->sk_dst_cache))
			sk_tx_queue_set(sk, new_index);
#endif

		queue_index = new_index;
	}

	return queue_index;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SELECT_QUEUE_FALLBACK)
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb,
		     void *accel_priv __always_unused,
		     select_queue_fallback_t fallback)
{
	if (!sxps_enabled)
		return fallback(dev, skb);
	return efx_select_queue_int(dev, skb);
}
#else
#if defined(EFX_HAVE_NDO_SELECT_QUEUE_ACCEL_PRIV)
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb,
		     void *accel_priv __always_unused)
#else
u16 efx_select_queue(struct net_device *dev, struct sk_buff *skb)
#endif
{
#if defined(EFX_HAVE_NETDEV_PICK_TX)
	if (!sxps_enabled)
		return __netdev_pick_tx(dev, skb);
#endif
	return efx_select_queue_int(dev, skb);
}
#endif
#endif

static struct efx_tx_buffer *efx_tx_map_chunk(struct efx_tx_queue *tx_queue,
					      dma_addr_t dma_addr,
					      size_t len)
{
	const struct efx_nic_type *nic_type = tx_queue->efx->type;
	struct efx_tx_buffer *buffer;
	unsigned int dma_len;

	/* Map the fragment taking account of NIC-dependent DMA limits. */
	do {
		buffer = efx_tx_queue_get_insert_buffer(tx_queue);
		dma_len = nic_type->tx_limit_len(tx_queue, dma_addr, len);

		buffer->len = dma_len;
		buffer->dma_addr = dma_addr;
		buffer->flags = EFX_TX_BUF_CONT;
		len -= dma_len;
		dma_addr += dma_len;
		++tx_queue->insert_count;
	} while (len);

	return buffer;
}

/* Map all data from an SKB for DMA and create descriptors on the queue.
 */
static int efx_tx_map_data(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
			   unsigned int segment_count)
{
	struct efx_nic *efx = tx_queue->efx;
	struct device *dma_dev = &efx->pci_dev->dev;
	unsigned int frag_index, nr_frags;
	dma_addr_t dma_addr, unmap_addr;
	unsigned short dma_flags;
	size_t len, unmap_len;

	nr_frags = skb_shinfo(skb)->nr_frags;
	frag_index = 0;

	/* Map header data. */
	len = skb_headlen(skb);
	dma_addr = dma_map_single(dma_dev, skb->data, len, DMA_TO_DEVICE);
	dma_flags = EFX_TX_BUF_MAP_SINGLE;
	unmap_len = len;
	unmap_addr = dma_addr;

	if (unlikely(dma_mapping_error(dma_dev, dma_addr)))
		return -EIO;

	if (segment_count) {
		/* For TSO we need to put the header in to a separate
		 * descriptor. Map this separately if necessary.
		 */
		size_t header_len;

#ifdef EFX_NOT_UPSTREAM
		if (efx_skb_encapsulation(skb))
#else
		if (skb->encapsulation)
#endif
#ifdef EFX_CAN_SUPPORT_ENCAP_TSO
			header_len = skb_inner_transport_header(skb) -
					skb->data +
					(inner_tcp_hdr(skb)->doff << 2u);
#else
		{
			/* We shouldn't have advertised encap TSO support,
			 * because this kernel doesn't have the bits we need
			 * to make it work.  So let's complain loudly.
			 */
			dma_unmap_single(dma_dev, dma_addr, len, DMA_TO_DEVICE);
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
#endif
		else
			header_len = skb_transport_header(skb) - skb->data +
					(tcp_hdr(skb)->doff << 2u);

		if (header_len != len) {
			efx_tx_map_chunk(tx_queue, dma_addr, header_len);
			len -= header_len;
			dma_addr += header_len;
		}
	}

	/* Add descriptors for each fragment. */
	do {
		struct efx_tx_buffer *buffer;
		skb_frag_t *fragment;

		buffer = efx_tx_map_chunk(tx_queue, dma_addr, len);

		/* The final descriptor for a fragment is responsible for
		 * unmapping the whole fragment.
		 */
		buffer->flags = EFX_TX_BUF_CONT | dma_flags;
		buffer->unmap_len = unmap_len;
		buffer->dma_offset = buffer->dma_addr - unmap_addr;

		if (frag_index >= nr_frags) {
			/* Store SKB details with the final buffer for
			 * the completion.
			 */
			buffer->skb = skb;
			buffer->flags = EFX_TX_BUF_SKB | dma_flags;
			return 0;
		}

		/* Move on to the next fragment. */
		fragment = &skb_shinfo(skb)->frags[frag_index++];
		len = skb_frag_size(fragment);
		dma_addr = skb_frag_dma_map(dma_dev, fragment,
				0, len, DMA_TO_DEVICE);
		dma_flags = 0;
		unmap_len = len;
		unmap_addr = dma_addr;

		if (unlikely(dma_mapping_error(dma_dev, dma_addr)))
			return -EIO;
	} while (1);
}

/* Remove buffers put into a tx_queue for the current packet.
 * None of the buffers must have an skb attached.
 */
static void efx_enqueue_unwind(struct efx_tx_queue *tx_queue,
			       unsigned int insert_count)
{
	struct efx_tx_buffer *buffer;

	/* Work backwards until we hit the original insert pointer value */
	while (tx_queue->insert_count != insert_count) {
		--tx_queue->insert_count;
		buffer = __efx_tx_queue_get_insert_buffer(tx_queue);
		efx_dequeue_buffer(tx_queue, buffer, NULL, NULL);
	}
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
static struct sk_buff *efx_tx_vlan_sw(struct efx_tx_queue *tx_queue,
				      struct sk_buff *skb)
{
	if (skb_vlan_tag_present(skb)) {
		struct vlan_ethhdr *veth;
		int delta = 0;

		if (skb_headroom(skb) < VLAN_HLEN)
			delta = VLAN_HLEN - skb_headroom(skb);

		if (delta || skb_header_cloned(skb)) {
			int rc;

			rc = pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD),
					      0, GFP_ATOMIC);
			if (rc) {
				dev_kfree_skb_any(skb);
				return NULL;
			}
		}

		veth = (struct vlan_ethhdr *)__skb_push(skb, VLAN_HLEN);
		/* Move the mac addresses to the beginning of the new header. */
		memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
		veth->h_vlan_proto = __constant_htons(ETH_P_8021Q);
		veth->h_vlan_TCI = htons(skb_vlan_tag_get(skb));
		skb->protocol = __constant_htons(ETH_P_8021Q);

		skb->mac_header -= VLAN_HLEN;
		skb->vlan_tci = 0;
	}
	return skb;
}
#else
static struct sk_buff *efx_tx_vlan_noaccel(struct efx_tx_queue *tx_queue,
					   struct sk_buff *skb)
{
	if (skb_vlan_tag_present(skb)) {
		WARN_ONCE(1, "VLAN tagging requested, but no support\n");
		dev_kfree_skb_any(skb);
		return ERR_PTR(-EINVAL);
	}
	return skb;
}
#endif

/*
 * Fallback to software TSO.
 *
 * This is used if we are unable to send a GSO packet through hardware TSO.
 * This should only ever happen due to per-queue restrictions - unsupported
 * packets should first be filtered by the feature flags and check_features.
 *
 * Returns 0 on success, error code otherwise.
 */
static int efx_tx_tso_fallback(struct efx_tx_queue *tx_queue,
			       struct sk_buff *skb)
{
	struct sk_buff *segments, *next;

	segments = skb_gso_segment(skb, 0);
	if (IS_ERR(segments))
		return PTR_ERR(segments);

	dev_kfree_skb_any(skb);
	skb = segments;

	while (skb) {
		next = skb->next;
		skb->next = NULL;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
		if (next)
			skb->xmit_more = true;
#endif
		efx_enqueue_skb(tx_queue, skb);
		skb = next;
	}

	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
/* Send any pending traffic for a channel. xmit_more is shared across all
 * queues for a channel, so we must check all of them.
 */
static void efx_tx_send_pending(struct efx_channel *channel)
{
	struct efx_tx_queue *q;

	efx_for_each_channel_tx_queue(q, channel) {
		if (q->xmit_pending)
			efx_nic_push_buffers(q);
	}
}
#endif

/*
 * Add a socket buffer to a TX queue
 *
 * This maps all fragments of a socket buffer for DMA and adds them to
 * the TX queue.  The queue's insert pointer will be incremented by
 * the number of fragments in the socket buffer.
 *
 * If any DMA mapping fails, any mapped fragments will be unmapped,
 * the queue's insert pointer will be restored to its original value.
 *
 * This function is split out from efx_hard_start_xmit to allow the
 * loopback test to direct packets via specific TX queues.
 *
 * Returns 0 on success, error code otherwise.
 * You must hold netif_tx_lock() to call this function.
 */
int efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	unsigned int old_insert_count = tx_queue->insert_count;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
	bool xmit_more = skb->xmit_more;
#endif
	struct efx_channel *channel;
	bool data_mapped = false;
	unsigned int segments;
	unsigned int skb_len;
	int rc = 0;

	channel = tx_queue->channel;

	/* We're pretty likely to want a descriptor to do this tx. */
	prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));

	EFX_BUG_ON_PARANOID(!tx_queue->handle_vlan);
	skb = tx_queue->handle_vlan(tx_queue, skb);
	if (IS_ERR_OR_NULL(skb))
		goto err;

	/* Copy the length *after* VLAN handling, in case we've inserted a
	 * tag in software.
	 */
	skb_len = skb->len;
	segments = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 0;
	if (segments == 1)
		segments = 0; /* Don't use TSO for a single segment. */

	/* Handle TSO first - it's *possible* (although unlikely) that we might
	 * be passed a packet to segment that's smaller than the copybreak/PIO
	 * size limit.
	 */
	if (segments) {
		EFX_BUG_ON_PARANOID(!tx_queue->handle_tso);
		rc = tx_queue->handle_tso(tx_queue, skb, &data_mapped);
		if (rc == -EINVAL) {
			rc = efx_tx_tso_fallback(tx_queue, skb);
			tx_queue->tso_fallbacks++;
			if (rc == 0)
				return 0;
		}
		if (rc)
			goto err;
#ifdef EFX_USE_PIO
	} else if (efx_tx_may_pio(channel, tx_queue, skb)) {
		/* Use PIO for short packets with an empty queue. */
		rc = efx_enqueue_skb_pio(tx_queue, skb);
		if (rc)
			goto err;
		tx_queue->pio_packets++;
		data_mapped = true;
#endif
	} else if (skb_len < tx_queue->tx_min_size ||
			(skb->data_len && skb_len <= tx_cb_size)) {
		/* Pad short packets or coalesce short fragmented packets. */
		rc = efx_enqueue_skb_copy(tx_queue, skb);
		if (rc)
			goto err;
		tx_queue->cb_packets++;
		data_mapped = true;
	}

	/* Map for DMA and create descriptors if we haven't done so already. */
	if (!data_mapped) {
		rc = efx_tx_map_data(tx_queue, skb, segments);
		if (rc)
			goto err;
	}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	efx_sarfs_skb(tx_queue->efx, tx_queue, skb);
#endif

	/* Update BQL */
	netdev_tx_sent_queue(tx_queue->core_txq, skb_len);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_TX_TIMESTAMP)
	skb_tx_timestamp(skb);
#endif

	efx_tx_maybe_stop_queue(tx_queue);

	tx_queue->xmit_pending = true;

	/* Pass to hardware. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
	if (!xmit_more || netif_xmit_stopped(tx_queue->core_txq))
		efx_tx_send_pending(channel);
	else
		/* There's another TX on the way. Prefetch next descriptor. */
		prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));
#else
	efx_nic_push_buffers(tx_queue);
#endif

	if (segments) {
		tx_queue->tso_bursts++;
		tx_queue->tso_packets += segments;
		tx_queue->tx_packets  += segments;
	} else {
		tx_queue->tx_packets++;
	}
#if defined(EFX_NOT_UPSTREAM)
	tx_queue->tx_bytes += skb_len;
#endif

	return 0;

err:
	efx_enqueue_unwind(tx_queue, old_insert_count);
	if (!IS_ERR_OR_NULL(skb))
		dev_kfree_skb_any(skb);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
	/* If we're not expecting another transmit and we had something to push
	 * on this queue or a partner queue then we need to push here to get the
	 * previous packets out.
	 */
	if (!xmit_more)
		efx_tx_send_pending(channel);
#endif

	return rc;
}

static bool efx_tx_buffer_in_use(struct efx_tx_buffer *buffer)
{
	return buffer->len || (buffer->flags & EFX_TX_BUF_OPTION);
}

/* Remove packets from the TX queue
 *
 * This removes packets from the TX queue, up to and including the
 * specified index.
 */
static void efx_dequeue_buffers(struct efx_tx_queue *tx_queue,
				unsigned int index,
				unsigned int *pkts_compl,
				unsigned int *bytes_compl)
{
	struct efx_nic *efx = tx_queue->efx;
	unsigned int stop_index, read_ptr;

	stop_index = (index + 1) & tx_queue->ptr_mask;
	read_ptr = tx_queue->read_count & tx_queue->ptr_mask;

	while (read_ptr != stop_index) {
		struct efx_tx_buffer *buffer = &tx_queue->buffer[read_ptr];

		if (!efx_tx_buffer_in_use(buffer)) {
			netif_err(efx, hw, efx->net_dev,
				  "TX queue %d spurious TX completion id %d\n",
				  tx_queue->queue, read_ptr);
			atomic_inc(&efx->errors.spurious_tx);
			efx_schedule_reset(efx, RESET_TYPE_TX_SKIP);
			return;
		}

		efx_dequeue_buffer(tx_queue, buffer, pkts_compl, bytes_compl);

		++tx_queue->read_count;
		read_ptr = tx_queue->read_count & tx_queue->ptr_mask;
	}
}

/* Initiate a packet transmission.  We use one channel per CPU
 * (sharing when we have more CPUs than channels).  On Falcon, the TX
 * completion events will be directed back to the CPU that transmitted
 * the packet, which should be cache-efficient.
 *
 * Context: non-blocking.
 * Note that returning anything other than NETDEV_TX_OK will cause the
 * OS to free the skb.
 */
netdev_tx_t efx_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	int rc;

#ifdef CONFIG_SFC_TRACING
	trace_sfc_transmit(skb, net_dev);
#endif

	channel = efx_get_tx_channel(efx, skb_get_queue_mapping(skb));

#if defined(CONFIG_SFC_PTP)
	/*
	 * PTP "event" packet
	 */
	if (unlikely(efx_xmit_with_hwtstamp(skb)) &&
		unlikely(efx_ptp_is_ptp_tx(efx, skb))) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_XMIT_MORE)
		/* If the xmit_more flag is set we clear it, because PTP
		 * transmissions will be going via a different path.
		 * If it isn't set, this may be the packet that's flushing out
		 * existing packets that had xmit_more set, so we must do that.
		 */
		if (skb->xmit_more) {
			skb->xmit_more = false;
		} else {
			efx_tx_send_pending(channel);
		}
#endif

		return efx_ptp_tx(efx, skb);
	}
#endif

	tx_queue = efx->select_tx_queue(channel, skb);

	rc = efx_enqueue_skb(tx_queue, skb);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_TRANS_START)
	if (likely(!rc)) {
		/* Update last TX timer */
		efx->net_dev->trans_start = jiffies;
	}
#endif
	return NETDEV_TX_OK;
}

void efx_init_tx_queue_core_txq(struct efx_tx_queue *tx_queue)
{
	/* Must be inverse of queue lookup in efx_hard_start_xmit() */
	tx_queue->core_txq = netdev_get_tx_queue(
		tx_queue->efx->net_dev,
		tx_queue->queue / tx_queue->efx->tx_queues_per_channel);
}

static void efx_xmit_done_check_empty(struct efx_tx_queue *tx_queue)
{
	if ((int)(tx_queue->read_count - tx_queue->old_write_count) >= 0) {
		tx_queue->old_write_count = ACCESS_ONCE(tx_queue->write_count);
		if (tx_queue->read_count == tx_queue->old_write_count) {
			smp_mb();
			tx_queue->empty_read_count =
				tx_queue->read_count | EFX_EMPTY_COUNT_VALID;
		}
	}
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index)
#else
void efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index)
#endif
{
	unsigned int pkts_compl = 0, bytes_compl = 0;

	EFX_BUG_ON_PARANOID(index > tx_queue->ptr_mask);

	efx_dequeue_buffers(tx_queue, index, &pkts_compl, &bytes_compl);
	tx_queue->pkts_compl += pkts_compl;
	tx_queue->bytes_compl += bytes_compl;

	if (pkts_compl > 1)
		++tx_queue->merge_events;

	efx_xmit_done_check_empty(tx_queue);
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_xmit_done_single(struct efx_tx_queue *tx_queue)
#else
void efx_xmit_done_single(struct efx_tx_queue *tx_queue)
#endif
{
	unsigned int pkts_compl = 0, bytes_compl = 0;
	unsigned int read_ptr;
	bool finished = false;

	read_ptr = tx_queue->read_count & tx_queue->ptr_mask;

	while (!finished) {
		struct efx_tx_buffer *buffer = &tx_queue->buffer[read_ptr];

		if (!efx_tx_buffer_in_use(buffer)) {
			struct efx_nic *efx = tx_queue->efx;

			netif_err(efx, hw, efx->net_dev,
				  "TX queue %d spurious single TX completion\n",
				  tx_queue->queue);
			atomic_inc(&efx->errors.spurious_tx);
			efx_schedule_reset(efx, RESET_TYPE_TX_SKIP);
			return;
		}

		/* Need to check the flag before dequeueing. */
		if (buffer->flags & EFX_TX_BUF_SKB)
			finished = true;
		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl);

		++tx_queue->read_count;
		read_ptr = tx_queue->read_count & tx_queue->ptr_mask;
	}

	tx_queue->pkts_compl += pkts_compl;
	tx_queue->bytes_compl += bytes_compl;

	EFX_WARN_ON_PARANOID(pkts_compl != 1);

	efx_xmit_done_check_empty(tx_queue);
}

static unsigned int efx_tx_cb_page_count(struct efx_tx_queue *tx_queue)
{
	return DIV_ROUND_UP(tx_queue->ptr_mask + 1, PAGE_SIZE >> tx_cb_order);
}

int efx_probe_tx_queue(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;
	unsigned int entries;
	int rc;

	/* Create the smallest power-of-two aligned ring */
	entries = max(roundup_pow_of_two(efx->txq_entries), EFX_MIN_DMAQ_SIZE);
	EFX_BUG_ON_PARANOID(entries > EFX_MAX_DMAQ_SIZE);
	tx_queue->ptr_mask = entries - 1;

	netif_dbg(efx, probe, efx->net_dev,
		  "creating TX queue %d size %#x mask %#x\n",
		  tx_queue->queue, efx->txq_entries, tx_queue->ptr_mask);

	/* Allocate software ring */
	tx_queue->buffer = kcalloc(entries, sizeof(*tx_queue->buffer),
				   GFP_KERNEL);
	if (!tx_queue->buffer)
		return -ENOMEM;

	tx_queue->cb_page = kcalloc(efx_tx_cb_page_count(tx_queue),
				    sizeof(tx_queue->cb_page[0]), GFP_KERNEL);
	if (!tx_queue->cb_page) {
		rc = -ENOMEM;
		goto fail1;
	}

	/* Allocate hardware ring */
	rc = efx_nic_probe_tx(tx_queue);
	if (rc)
		goto fail2;

	return 0;

fail2:
	kfree(tx_queue->cb_page);
	tx_queue->cb_page = NULL;
fail1:
	kfree(tx_queue->buffer);
	tx_queue->buffer = NULL;
	return rc;
}

int efx_init_tx_queue(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;

	netif_dbg(efx, drv, efx->net_dev,
		  "initialising TX queue %d\n", tx_queue->queue);

	tx_queue->insert_count = 0;
	tx_queue->write_count = 0;
	tx_queue->packet_write_count = 0;
	tx_queue->old_write_count = 0;
	tx_queue->read_count = 0;
	tx_queue->old_read_count = 0;
	tx_queue->empty_read_count = 0 | EFX_EMPTY_COUNT_VALID;
	tx_queue->xmit_pending = false;

	if (efx_ptp_use_mac_tx_timestamps(efx) &&
	    (tx_queue->channel == efx_ptp_channel(efx)))
		tx_queue->timestamping = true;
	else
		tx_queue->timestamping = false;
	tx_queue->completed_timestamp_major = 0;
	tx_queue->completed_timestamp_minor = 0;

	/* Set up default function pointers. These may get replaced by
	 * efx_nic_init_tx() based off NIC/queue capabilities.
	 */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	tx_queue->handle_vlan = efx_tx_vlan_sw;
#else
	tx_queue->handle_vlan = efx_tx_vlan_noaccel;
#endif
	tx_queue->handle_tso = efx_tx_tso_sw;

	/* Some older hardware requires Tx writes larger than 32. */
	tx_queue->tx_min_size = EFX_WORKAROUND_15592(efx) ? 33 : 0;

	/* Set up TX descriptor ring */
	return efx_nic_init_tx(tx_queue);
}

void efx_purge_tx_queue(struct efx_tx_queue *tx_queue)
{
	while (tx_queue->read_count != tx_queue->insert_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		struct efx_tx_buffer *buffer =
			&tx_queue->buffer[tx_queue->read_count &
					  tx_queue->ptr_mask];

		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl);
		++tx_queue->read_count;
	}
}

void efx_fini_tx_queue(struct efx_tx_queue *tx_queue)
{
	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "shutting down TX queue %d\n", tx_queue->queue);

	if (!tx_queue->buffer)
		return;

	efx_purge_tx_queue(tx_queue);
	tx_queue->xmit_pending = false;
	netdev_tx_reset_queue(tx_queue->core_txq);
}

void efx_remove_tx_queue(struct efx_tx_queue *tx_queue)
{

	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "removing TX queue %d\n", tx_queue->queue);
	efx_nic_remove_tx(tx_queue);
}

void efx_destroy_tx_queue(struct efx_tx_queue *tx_queue)
{
	int i;

	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "destroying TX queue %d\n", tx_queue->queue);

	if (tx_queue->cb_page) {
		for (i = 0; i < efx_tx_cb_page_count(tx_queue); i++)
			efx_nic_free_buffer(tx_queue->efx,
					    &tx_queue->cb_page[i]);
		kfree(tx_queue->cb_page);
		tx_queue->cb_page = NULL;
	}

	kfree(tx_queue->buffer);
	tx_queue->buffer = NULL;
}

