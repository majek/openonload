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

#define EFX_PIOBUF_SIZE_MAX ER_DZ_TX_PIOBUF_SIZE
#define EFX_PIOBUF_SIZE_DEF ALIGN(256, L1_CACHE_BYTES)
unsigned int efx_piobuf_size __read_mostly = EFX_PIOBUF_SIZE_DEF;

#ifdef EFX_NOT_UPSTREAM
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

static inline unsigned int
efx_tx_queue_get_insert_index(const struct efx_tx_queue *tx_queue)
{
	return tx_queue->insert_count & tx_queue->ptr_mask;
}

static inline struct efx_tx_buffer *
__efx_tx_queue_get_insert_buffer(const struct efx_tx_queue *tx_queue)
{
	return &tx_queue->buffer[efx_tx_queue_get_insert_index(tx_queue)];
}

static inline struct efx_tx_buffer *
efx_tx_queue_get_insert_buffer(const struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *buffer =
		__efx_tx_queue_get_insert_buffer(tx_queue);

	EFX_BUG_ON_PARANOID(buffer->len);
	EFX_BUG_ON_PARANOID(buffer->flags);
	EFX_BUG_ON_PARANOID(buffer->unmap_len);

	return buffer;
}

static u8 *efx_tx_get_copy_buffer(struct efx_tx_queue *tx_queue,
				  struct efx_tx_buffer *buffer)
{
	unsigned index = efx_tx_queue_get_insert_index(tx_queue);
	struct efx_buffer *page_buf =
		&tx_queue->cb_page[index >> (PAGE_SHIFT - tx_cb_order)];
	unsigned offset =
		((index << tx_cb_order) + NET_IP_ALIGN) & (PAGE_SIZE - 1);

	if (unlikely(!page_buf->addr) &&
	    efx_nic_alloc_buffer(tx_queue->efx, page_buf, PAGE_SIZE,
				 GFP_ATOMIC))
		return NULL;
	buffer->dma_addr = page_buf->dma_addr + offset;
	buffer->unmap_len = 0;
	return (u8 *)page_buf->addr + offset;
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
static inline void efx_skb_copy_insert_tag(const struct sk_buff *skb,
					   void *to, unsigned int len)
{
	struct vlan_ethhdr *veth = to;
	unsigned int offset = 2 * ETH_ALEN;
	int rc;

	EFX_BUG_ON_PARANOID(len < ETH_HLEN);

	memcpy(to, skb->data, offset);
	veth->h_vlan_proto = htons(ETH_P_8021Q);
	veth->h_vlan_TCI = htons(vlan_tx_tag_get(skb));

	if (len <= skb_headlen(skb)) {
		memcpy(to + offset + VLAN_HLEN, skb->data + offset,
		       len - offset);
	} else {
		rc = skb_copy_bits(skb, offset, to + offset + VLAN_HLEN,
				   len - offset);
		EFX_WARN_ON_PARANOID(rc);
	}
}
#endif

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
		(*pkts_compl)++;
		(*bytes_compl) += buffer->skb->len;
		dev_kfree_skb_any((struct sk_buff *) buffer->skb);
		netif_vdbg(tx_queue->efx, tx_done, tx_queue->efx->net_dev,
			   "TX queue %d transmission id %x complete\n",
			   tx_queue->queue, tx_queue->read_count);
	} else if (buffer->flags & EFX_TX_BUF_HEAP) {
		kfree(buffer->heap_buf);
	}

	buffer->len = 0;
	buffer->flags = 0;
}

static int efx_enqueue_skb_tso(struct efx_tx_queue *tx_queue,
			       struct sk_buff *skb);

static inline unsigned
efx_max_tx_len(struct efx_nic *efx, dma_addr_t dma_addr)
{
	/* Depending on the NIC revision, we can use descriptor
	 * lengths up to 8K or 8K-1.  However, since PCI Express
	 * devices must split read requests at 4K boundaries, there is
	 * little benefit from using descriptors that cross those
	 * boundaries and we keep things simple by not doing so.
	 */
	unsigned len = (~dma_addr & (EFX_PAGE_SIZE - 1)) + 1;

	/* Work around hardware bug for unaligned buffers. */
	if (EFX_WORKAROUND_5391(efx) && (dma_addr & 0xf))
		len = min_t(unsigned, len, 512 - (dma_addr & 0xf));

	return len;
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
	struct efx_tx_queue *txq2 = efx_tx_queue_partner(txq1);
	struct efx_nic *efx = txq1->efx;
	unsigned int fill_level;

	fill_level = max(txq1->insert_count - txq1->old_read_count,
			 txq2->insert_count - txq2->old_read_count);
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
	txq1->old_read_count = ACCESS_ONCE(txq1->read_count);
	txq2->old_read_count = ACCESS_ONCE(txq2->read_count);

	fill_level = max(txq1->insert_count - txq1->old_read_count,
			 txq2->insert_count - txq2->old_read_count);
	EFX_BUG_ON_PARANOID(fill_level >= efx->txq_entries);
	if (likely(fill_level < efx->txq_stop_thresh)) {
		smp_mb();
		if (likely(!efx->loopback_selftest))
			netif_tx_start_queue(txq1->core_txq);
	}
}

static struct efx_tx_buffer *
efx_enqueue_skb_copy(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
		     unsigned int min_len)
{
	struct efx_tx_buffer *buffer;
	unsigned int copy_len = skb->len;
	u8 *copy_buffer;
	int rc;

	EFX_BUG_ON_PARANOID(copy_len > tx_cb_size);

	buffer = efx_tx_queue_get_insert_buffer(tx_queue);

	copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
	if (unlikely(!copy_buffer))
		return NULL;

	rc = skb_copy_bits(skb, 0, copy_buffer, copy_len);
	EFX_WARN_ON_PARANOID(rc);
	if (unlikely(copy_len < min_len)) {
		memset(copy_buffer + copy_len, 0, min_len - copy_len);
		buffer->len = min_len;
	} else {
		buffer->len = copy_len;
	}

	++tx_queue->insert_count;
	return buffer;
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

static struct efx_tx_buffer *
efx_enqueue_skb_pio(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
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
		 * We can do this because we know the skb_shared_info sruct is
		 * after the source, and the destination buffer is big enough.
		 */
		BUILD_BUG_ON(L1_CACHE_BYTES >
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
		efx_memcpy_64(tx_queue->piobuf, skb->data,
			      ALIGN(skb->len, L1_CACHE_BYTES));
	}

	EFX_POPULATE_QWORD_5(buffer->option,
			     ESF_DZ_TX_DESC_IS_OPT, 1,
			     ESF_DZ_TX_OPTION_TYPE, 1 /* XXX */,
			     ESF_DZ_TX_PIO_CONT, 0,
			     ESF_DZ_TX_PIO_BYTE_CNT, skb->len,
			     ESF_DZ_TX_PIO_BUF_ADDR,
			     tx_queue->piobuf_offset);
	++tx_queue->pio_packets;
	++tx_queue->insert_count;
	return buffer;
}

/* Report whether the NIC considers this TX queue empty, using
 * packet_write_count (the write count recorded for the last completable
 * doorbell push).  May return false negative.  EF10 only, which is OK
 * because only EF10 supports PIO.
 */
static inline bool efx_nic_tx_is_empty(struct efx_tx_queue *tx_queue)
{
	EFX_BUG_ON_PARANOID(!tx_queue->efx->type->option_descriptors);
	return __efx_nic_tx_is_empty(tx_queue, tx_queue->packet_write_count);
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
static unsigned sarfs_table_size = 256;
module_param(sarfs_table_size, uint, 0444);
MODULE_PARM_DESC(sarfs_table_size, "Size of the SARFS hash table.");

/* The maximum rate we'll do alt arfs operations in ms */
static unsigned sarfs_global_holdoff_ms = 10;
module_param(sarfs_global_holdoff_ms, uint, 0444);
MODULE_PARM_DESC(sarfs_global_holdoff_ms,
	"Maximum rate at which SARFS operations can occur.");

/* The maximum rate we'll do alt arfs operations on a single hash table entry.
 * This is designed to prevent filter flapping on hash collision */
static const unsigned sarfs_entry_holdoff_ms = 1000;

/* The rate at which we'll sample TCP packets for new flows and CPU switches.
 * 0 = disable alt arfs. */
static unsigned sarfs_sample_rate = 0;
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

inline bool efx_sarfs_entry_in_holdoff(struct efx_sarfs_entry *entry)
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
inline void efx_sarfs_skb(struct efx_nic *efx,
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
 * Returns NETDEV_TX_OK.
 * You must hold netif_tx_lock() to call this function.
 */
netdev_tx_t efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	struct efx_nic *efx = tx_queue->efx;
	struct device *dma_dev = &efx->pci_dev->dev;
	struct efx_tx_buffer *buffer;
	skb_frag_t *fragment;
	unsigned int len, unmap_len = 0;
	dma_addr_t dma_addr, unmap_addr = 0;
	unsigned int dma_len;
	unsigned short dma_flags = 0;
	int i = 0;

	EFX_BUG_ON_PARANOID(tx_queue->write_count != tx_queue->insert_count);

	/* The use of likely() macros in this function are a hint to
	 * the compiler to try and co-locate conditional blocks close to
	 * the corresponding test towards the goal of reducing the
	 * icache miss rate.
	 */
	if (likely(skb_shinfo(skb)->gso_size))
		return efx_enqueue_skb_tso(tx_queue, skb);

	/* Pad if necessary */
	if (likely(EFX_WORKAROUND_15592(efx) && skb->len <= 32)) {
		buffer = efx_enqueue_skb_copy(tx_queue, skb, 32 + 1);
		if (unlikely(!buffer))
			goto err;
		goto finish_packet;
	}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	if (vlan_tx_tag_present(skb)) {
		u8 *copy_buffer;

		/* Insert into the headroom if possible */
		if (!skb_header_cloned(skb) && skb_headroom(skb) >= VLAN_HLEN) {
			struct vlan_ethhdr *veth = ((struct vlan_ethhdr *)
						    __skb_push(skb, VLAN_HLEN));
			memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
			veth->h_vlan_proto = htons(ETH_P_8021Q);
			veth->h_vlan_TCI = htons(vlan_tx_tag_get(skb));
			goto begin_packet;
		}

		buffer = efx_tx_queue_get_insert_buffer(tx_queue);

		copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
		if (unlikely(!copy_buffer))
			goto err;

		++tx_queue->insert_count;

		/* Must copy header.  Try to minimise number of fragments. */
		if (skb->len + VLAN_HLEN <= tx_cb_size && skb->data_len) {
			efx_skb_copy_insert_tag(skb, copy_buffer, skb->len);
			buffer->len = skb->len + VLAN_HLEN;
			goto finish_packet;
		} else if (skb_headlen(skb) + VLAN_HLEN <= tx_cb_size) {
			efx_skb_copy_insert_tag(skb, copy_buffer,
						skb_headlen(skb));
			buffer->len = skb_headlen(skb) + VLAN_HLEN;
			goto finish_fragment;
		} else {
			/* Must add another fragment.  At least try to
			 * cache-align the start of the next fragment.
			 */
			unsigned int align_len =
				ETH_HLEN +
				(-(unsigned long)(skb->data + ETH_HLEN)
				 & (L1_CACHE_BYTES - 1));
			unsigned int copy_len;

			if (align_len + VLAN_HLEN <= tx_cb_size)
				copy_len = align_len;
			else
				copy_len = ETH_HLEN;
			efx_skb_copy_insert_tag(skb, copy_buffer, copy_len);
			buffer->len = copy_len + VLAN_HLEN;
			buffer->flags = EFX_TX_BUF_CONT;

			len = skb_headlen(skb) - copy_len;
			dma_flags = EFX_TX_BUF_MAP_SINGLE;
			dma_addr = dma_map_single(dma_dev, skb->data + copy_len,
						  len, DMA_TO_DEVICE);
			goto begin_fragment;
		}
	}
begin_packet:
#endif

	/* Consider using PIO for short packets */
#ifdef EFX_USE_PIO
	if (likely((skb->len <= efx_piobuf_size && tx_queue->piobuf &&
		    efx_nic_tx_is_empty(tx_queue) &&
		    efx_nic_tx_is_empty(efx_tx_queue_partner(tx_queue))))) {
		buffer = efx_enqueue_skb_pio(tx_queue, skb);
		dma_flags = EFX_TX_BUF_OPTION;
		goto finish_packet;
	}
#endif
	/* Coalesce short fragmented packets */
	    if (likely(skb->data_len && skb->len <= tx_cb_size &&
		       !(NET_IP_ALIGN && EFX_WORKAROUND_5391(efx)))) {
		buffer = efx_enqueue_skb_copy(tx_queue, skb, 0);
		if (unlikely(!buffer))
			goto err;
		goto finish_packet;
	}

	/* Get size of the initial fragment */
	len = skb_headlen(skb);

	/* Map for DMA.  Use dma_map_single rather than dma_map_page
	 * since this is more efficient on machines with sparse
	 * memory.
	 */
	dma_flags = EFX_TX_BUF_MAP_SINGLE;
	dma_addr = dma_map_single(dma_dev, skb->data, len, DMA_TO_DEVICE);

	/* Process all fragments */
	while (1) {
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	begin_fragment:
#endif
		if (unlikely(dma_mapping_error(dma_dev, dma_addr)))
			goto dma_err;

		/* Store fields for marking in the per-fragment final
		 * descriptor */
		unmap_len = len;
		unmap_addr = dma_addr;

		/* Add to TX queue, splitting across DMA boundaries */
		do {
			buffer = efx_tx_queue_get_insert_buffer(tx_queue);

			dma_len = efx_max_tx_len(efx, dma_addr);
			if (likely(dma_len >= len))
				dma_len = len;

			/* Fill out per descriptor fields */
			buffer->len = dma_len;
			buffer->dma_addr = dma_addr;
			buffer->flags = EFX_TX_BUF_CONT;
			len -= dma_len;
			dma_addr += dma_len;
			++tx_queue->insert_count;
		} while (len);

		/* Transfer ownership of the unmapping to the final buffer */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	finish_fragment:
#endif
		buffer->flags = EFX_TX_BUF_CONT | dma_flags;
		buffer->unmap_len = unmap_len;
		buffer->dma_offset = buffer->dma_addr - unmap_addr;
		unmap_len = 0;

		/* Get address and size of next fragment */
		if (i >= skb_shinfo(skb)->nr_frags)
			break;
		fragment = &skb_shinfo(skb)->frags[i];
		len = skb_frag_size(fragment);
		i++;
		/* Map for DMA */
		dma_flags = 0;
		dma_addr = skb_frag_dma_map(dma_dev, fragment, 0, len,
					    DMA_TO_DEVICE);
	}

	/* Transfer ownership of the skb to the final buffer */
finish_packet:
	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB | dma_flags;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	efx_sarfs_skb(efx, tx_queue, skb);
#endif

	netdev_tx_sent_queue(tx_queue->core_txq, skb->len);

	/* Pass off to hardware */
	efx_nic_push_buffers(tx_queue);

	tx_queue->tx_packets++;
#if defined(EFX_NOT_UPSTREAM)
	tx_queue->tx_bytes += skb->len;
#endif

	efx_tx_maybe_stop_queue(tx_queue);

	return NETDEV_TX_OK;

dma_err:
	netif_err(efx, tx_err, efx->net_dev,
		  " TX queue %d could not map skb with %d bytes %d "
		  "fragments for DMA\n", tx_queue->queue, skb->len,
		  skb_shinfo(skb)->nr_frags + 1);

err:
	/* Mark the packet as transmitted, and free the SKB ourselves */
	dev_kfree_skb_any(skb);

	/* Work backwards until we hit the original insert pointer value */
	while (tx_queue->insert_count != tx_queue->write_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		--tx_queue->insert_count;
		buffer = __efx_tx_queue_get_insert_buffer(tx_queue);
		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl);
	}

	/* Free the fragment we were mid-way through pushing */
	if (unmap_len) {
		if (dma_flags & EFX_TX_BUF_MAP_SINGLE)
			dma_unmap_single(dma_dev, unmap_addr, unmap_len,
					 DMA_TO_DEVICE);
		else
			dma_unmap_page(dma_dev, unmap_addr, unmap_len,
				       DMA_TO_DEVICE);
	}

	return NETDEV_TX_OK;
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

		if (!(buffer->flags & EFX_TX_BUF_OPTION) &&
		    unlikely(buffer->len == 0)) {
			netif_err(efx, hw, efx->net_dev,
				  "TX queue %d spurious TX completion id %x\n",
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
	struct efx_tx_queue *tx_queue;
	int rc;

	EFX_WARN_ON_PARANOID(!netif_device_present(net_dev));

#ifdef CONFIG_SFC_TRACING
	trace_sfc_transmit(skb, net_dev);
#endif

#if defined(CONFIG_SFC_PTP)
	/*
	 * PTP "event" packet
	 */
	if (unlikely(efx_xmit_with_hwtstamp(skb)) &&
		unlikely(efx_ptp_is_ptp_tx(efx, skb))) {
		return efx_ptp_tx(efx, skb);
	}
#endif

	tx_queue = efx_get_tx_queue(efx, skb_get_queue_mapping(skb),
				    skb->ip_summed == CHECKSUM_PARTIAL ?
				    EFX_TXQ_TYPE_OFFLOAD : 0);

	rc = efx_enqueue_skb(tx_queue, skb);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_TRANS_START)
	if (likely(rc == NETDEV_TX_OK)) {
		/* Update last TX timer */
		efx->net_dev->trans_start = jiffies;
	}
#endif
	return rc;
}

void efx_init_tx_queue_core_txq(struct efx_tx_queue *tx_queue)
{
	/* Must be inverse of queue lookup in efx_hard_start_xmit() */
	tx_queue->core_txq = netdev_get_tx_queue(
		tx_queue->efx->net_dev, tx_queue->queue / EFX_TXQ_TYPES);
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
	netdev_tx_completed_queue(tx_queue->core_txq, pkts_compl, bytes_compl);

	if (pkts_compl > 1)
		++tx_queue->merge_events;

	/* Check whether the hardware queue is now empty */
	if ((int)(tx_queue->read_count - tx_queue->old_write_count) >= 0) {
		tx_queue->old_write_count = ACCESS_ONCE(tx_queue->write_count);
		if (tx_queue->read_count == tx_queue->old_write_count) {
			smp_mb();
			tx_queue->empty_read_count =
				tx_queue->read_count | EFX_EMPTY_COUNT_VALID;
		}
	}
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

void efx_init_tx_queue(struct efx_tx_queue *tx_queue)
{
	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "initialising TX queue %d\n", tx_queue->queue);

	tx_queue->insert_count = 0;
	tx_queue->write_count = 0;
	tx_queue->packet_write_count = 0;
	tx_queue->old_write_count = 0;
	tx_queue->read_count = 0;
	tx_queue->old_read_count = 0;
	tx_queue->empty_read_count = 0 | EFX_EMPTY_COUNT_VALID;

	/* Set up TX descriptor ring */
	efx_nic_init_tx(tx_queue);
}

void efx_fini_tx_queue(struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *buffer;

	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "shutting down TX queue %d\n", tx_queue->queue);

	if (!tx_queue->buffer)
		return;

	/* Free any buffers left in the ring */
	while (tx_queue->read_count != tx_queue->write_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		buffer = &tx_queue->buffer[tx_queue->read_count & tx_queue->ptr_mask];
		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl);

		++tx_queue->read_count;
	}
	netdev_tx_reset_queue(tx_queue->core_txq);
}

void efx_remove_tx_queue(struct efx_tx_queue *tx_queue)
{
	int i;

	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "destroying TX queue %d\n", tx_queue->queue);
	efx_nic_remove_tx(tx_queue);

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


/* Efx TCP segmentation acceleration.
 *
 * Why?  Because by doing it here in the driver we can go significantly
 * faster than the GSO.
 *
 * Requires TX checksum offload support.
 */

#define PTR_DIFF(p1, p2)  ((u8 *)(p1) - (u8 *)(p2))

/**
 * struct tso_state - TSO state for an SKB
 * @out_len: Remaining length in current segment
 * @seqnum: Current sequence number
 * @ipv4_id: Current IPv4 ID, host endian
 * @packet_space: Remaining space in current packet
 * @dma_addr: DMA address of current position
 * @in_len: Remaining length in current SKB fragment
 * @unmap_len: Length of SKB fragment
 * @unmap_addr: DMA address of SKB fragment
 * @dma_flags: TX buffer flags for DMA mapping - %EFX_TX_BUF_MAP_SINGLE or 0
 * @protocol: Network protocol (after any VLAN header)
 * @ip_off: Offset of IP header
 * @tcp_off: Offset of TCP header
 * @header_len: Number of bytes of header
 * @ip_base_len: IPv4 tot_len or IPv6 payload_len, before TCP payload
 * @header_dma_addr: Header DMA address, when using option descriptors
 * @header_unmap_len: Header DMA mapped length, or 0 if not using option
 *	descriptors
 *
 * The state used during segmentation.  It is put into this data structure
 * just to make it easy to pass into inline functions.
 */
struct tso_state {
	/* Output position */
	unsigned out_len;
	unsigned seqnum;
	u16 ipv4_id;
	unsigned packet_space;

	/* Input position */
	dma_addr_t dma_addr;
	unsigned in_len;
	unsigned unmap_len;
	dma_addr_t unmap_addr;
	unsigned short dma_flags;

	__be16 protocol;
	unsigned int ip_off;
	unsigned int tcp_off;
	unsigned header_len;
	unsigned int ip_base_len;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	unsigned int in_header_len;
#endif
	dma_addr_t header_dma_addr;
	unsigned int header_unmap_len;
};


static inline void prefetch_ptr(struct efx_tx_queue *tx_queue)
{
	unsigned insert_ptr = efx_tx_queue_get_insert_index(tx_queue);
	char *ptr;

	ptr = (char *) (tx_queue->buffer + insert_ptr);
	prefetch(ptr);
	prefetch(ptr + 0x80);

	ptr = (char *) (((efx_qword_t *)tx_queue->txd.buf.addr) + insert_ptr);
	prefetch(ptr);
	prefetch(ptr + 0x80);
}

/*
 * Verify that our various assumptions about sk_buffs and the conditions
 * under which TSO will be attempted hold true.  Return the protocol number.
 */
static __be16 efx_tso_check_protocol(struct sk_buff *skb)
{
	__be16 protocol = skb->protocol;

	EFX_BUG_ON_PARANOID(((struct ethhdr *)skb->data)->h_proto !=
			    protocol);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES) || defined(NETIF_F_VLAN_TSO) || defined(__VMKLNX__)
	if (protocol == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)skb->data;
		protocol = veh->h_vlan_encapsulated_proto;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_VLAN_NETWORK_HEADER_BUG)
		/* vlan_dev_hard_header() may have moved the nh pointer */
		skb_set_network_header(skb, sizeof(*veh));
#endif
	}
#endif

	if (protocol == htons(ETH_P_IP)) {
		EFX_BUG_ON_PARANOID(ip_hdr(skb)->protocol != IPPROTO_TCP);
	} else {
		EFX_BUG_ON_PARANOID(protocol != htons(ETH_P_IPV6));
		EFX_BUG_ON_PARANOID(ipv6_hdr(skb)->nexthdr != NEXTHDR_TCP);
	}
	EFX_BUG_ON_PARANOID((PTR_DIFF(tcp_hdr(skb), skb->data)
			     + (tcp_hdr(skb)->doff << 2u)) >
			    skb_headlen(skb));

	return protocol;
}

static u8 *efx_tsoh_get_buffer(struct efx_tx_queue *tx_queue,
			       struct efx_tx_buffer *buffer, unsigned int len)
{
	u8 *result;

	EFX_BUG_ON_PARANOID(buffer->len);
	EFX_BUG_ON_PARANOID(buffer->flags);
	EFX_BUG_ON_PARANOID(buffer->unmap_len);

	if (likely(len <= tx_cb_size)) {
		result = efx_tx_get_copy_buffer(tx_queue, buffer);
		if (unlikely(!result))
			return NULL;
		buffer->flags = EFX_TX_BUF_CONT;
	} else {
		tx_queue->tso_long_headers++;

		buffer->heap_buf = kmalloc(NET_IP_ALIGN + len, GFP_ATOMIC);
		if (unlikely(!buffer->heap_buf))
			return NULL;
		result = (u8 *)buffer->heap_buf + NET_IP_ALIGN;
		buffer->flags = EFX_TX_BUF_CONT | EFX_TX_BUF_HEAP;
	}

	buffer->len = len;

	return result;
}

/**
 * efx_tx_queue_insert - push descriptors onto the TX queue
 * @tx_queue:		Efx TX queue
 * @dma_addr:		DMA address of fragment
 * @len:		Length of fragment
 * @final_buffer:	The final buffer inserted into the queue
 *
 * Push descriptors onto the TX queue.
 */
static void efx_tx_queue_insert(struct efx_tx_queue *tx_queue,
				dma_addr_t dma_addr, unsigned len,
				struct efx_tx_buffer **final_buffer)
{
	struct efx_tx_buffer *buffer;
	struct efx_nic *efx = tx_queue->efx;
	unsigned dma_len;

	EFX_BUG_ON_PARANOID(len <= 0);

	while (1) {
		buffer = efx_tx_queue_get_insert_buffer(tx_queue);
		++tx_queue->insert_count;

		EFX_BUG_ON_PARANOID(tx_queue->insert_count -
				    tx_queue->read_count >=
				    efx->txq_entries);

		buffer->dma_addr = dma_addr;

		dma_len = efx_max_tx_len(efx, dma_addr);

		/* If there is enough space to send then do so */
		if (dma_len >= len)
			break;

		buffer->len = dma_len;
		buffer->flags = EFX_TX_BUF_CONT;
		dma_addr += dma_len;
		len -= dma_len;
	}

	EFX_BUG_ON_PARANOID(!len);
	buffer->len = len;
	*final_buffer = buffer;
}


/*
 * Put a TSO header into the TX queue.
 *
 * This is special-cased because we know that it is small enough to fit in
 * a single fragment, and we know it doesn't cross a page boundary.  It
 * also allows us to not worry about end-of-packet etc.
 */
static int efx_tso_put_header(struct efx_tx_queue *tx_queue,
			      struct efx_tx_buffer *buffer, u8 *header)
{
	if (unlikely(buffer->flags & EFX_TX_BUF_HEAP)) {
		buffer->dma_addr = dma_map_single(&tx_queue->efx->pci_dev->dev,
						  header, buffer->len,
						  DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(&tx_queue->efx->pci_dev->dev,
					       buffer->dma_addr))) {
			kfree(buffer->heap_buf);
			buffer->len = 0;
			buffer->flags = 0;
			return -ENOMEM;
		}
		buffer->unmap_len = buffer->len;
		buffer->dma_offset = 0;
		buffer->flags |= EFX_TX_BUF_MAP_SINGLE;
	}

	++tx_queue->insert_count;
	return 0;
}


/* Remove buffers put into a tx_queue.  None of the buffers must have
 * an skb attached.
 */
static void efx_enqueue_unwind(struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *buffer;

	/* Work backwards until we hit the original insert pointer value */
	while (tx_queue->insert_count != tx_queue->write_count) {
		--tx_queue->insert_count;
		buffer = __efx_tx_queue_get_insert_buffer(tx_queue);
		efx_dequeue_buffer(tx_queue, buffer, NULL, NULL);
	}
}


/* Parse the SKB header and initialise state. */
static int tso_start(struct tso_state *st, struct efx_nic *efx,
		     const struct sk_buff *skb)
{
	bool use_opt_desc = efx_nic_rev(efx) >= EFX_REV_HUNT_A0;
	struct device *dma_dev = &efx->pci_dev->dev;
	unsigned int header_len, in_len;
	dma_addr_t dma_addr;

	st->ip_off = skb_network_header(skb) - skb->data;
	st->tcp_off = skb_transport_header(skb) - skb->data;
	header_len = st->tcp_off + (tcp_hdr(skb)->doff << 2u);
	in_len = skb_headlen(skb) - header_len;
	st->header_len = header_len;
	st->in_len = in_len;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	st->in_header_len = header_len;
	if (vlan_tx_tag_present(skb)) {
		st->ip_off += VLAN_HLEN;
		st->tcp_off += VLAN_HLEN;
		st->header_len += VLAN_HLEN;
		use_opt_desc = false; /* until we insert VLAN options too */
	}
#endif
	if (st->protocol == htons(ETH_P_IP)) {
		st->ip_base_len = st->header_len - st->ip_off;
		st->ipv4_id = ntohs(ip_hdr(skb)->id);
	} else {
		st->ip_base_len = st->header_len - st->tcp_off;
		st->ipv4_id = 0;
	}
	st->seqnum = ntohl(tcp_hdr(skb)->seq);

	EFX_BUG_ON_PARANOID(tcp_hdr(skb)->urg);
	EFX_BUG_ON_PARANOID(tcp_hdr(skb)->syn);
	EFX_BUG_ON_PARANOID(tcp_hdr(skb)->rst);

	st->out_len = skb->len - header_len;

	if (!use_opt_desc) {
		st->header_unmap_len = 0;

		if (likely(in_len == 0)) {
			st->dma_flags = 0;
			st->unmap_len = 0;
			return 0;
		}

		dma_addr = dma_map_single(dma_dev, skb->data + header_len,
					  in_len, DMA_TO_DEVICE);
		st->dma_flags = EFX_TX_BUF_MAP_SINGLE;
		st->dma_addr = dma_addr;
		st->unmap_addr = dma_addr;
		st->unmap_len = in_len;
	} else {
		dma_addr = dma_map_single(dma_dev, skb->data,
					  skb_headlen(skb), DMA_TO_DEVICE);
		st->header_dma_addr = dma_addr;
		st->header_unmap_len = skb_headlen(skb);
		st->dma_flags = 0;
		st->dma_addr = dma_addr + header_len;
		st->unmap_len = 0;
	}

	return unlikely(dma_mapping_error(dma_dev, dma_addr)) ? -ENOMEM : 0;
}

static int tso_get_fragment(struct tso_state *st, struct efx_nic *efx,
			    skb_frag_t *frag)
{
	st->unmap_addr = skb_frag_dma_map(&efx->pci_dev->dev, frag, 0,
					  skb_frag_size(frag), DMA_TO_DEVICE);
	if (likely(!dma_mapping_error(&efx->pci_dev->dev, st->unmap_addr))) {
		st->dma_flags = 0;
		st->unmap_len = skb_frag_size(frag);
		st->in_len = skb_frag_size(frag);
		st->dma_addr = st->unmap_addr;
		return 0;
	}
	return -ENOMEM;
}


/**
 * tso_fill_packet_with_fragment - form descriptors for the current fragment
 * @tx_queue:		Efx TX queue
 * @skb:		Socket buffer
 * @st:			TSO state
 *
 * Form descriptors for the current fragment, until we reach the end
 * of fragment or end-of-packet.
 */
static void tso_fill_packet_with_fragment(struct efx_tx_queue *tx_queue,
					  const struct sk_buff *skb,
					  struct tso_state *st)
{
	struct efx_tx_buffer *buffer;
	int n;

	if (st->in_len == 0)
		return;
	if (st->packet_space == 0)
		return;

	EFX_BUG_ON_PARANOID(st->in_len <= 0);
	EFX_BUG_ON_PARANOID(st->packet_space <= 0);

	n = min(st->in_len, st->packet_space);

	st->packet_space -= n;
	st->out_len -= n;
	st->in_len -= n;

	efx_tx_queue_insert(tx_queue, st->dma_addr, n, &buffer);

	if (st->out_len == 0) {
		/* Transfer ownership of the skb */
		buffer->skb = skb;
		buffer->flags = EFX_TX_BUF_SKB;
	} else if (st->packet_space != 0) {
		buffer->flags = EFX_TX_BUF_CONT;
	}

	if (st->in_len == 0) {
		/* Transfer ownership of the DMA mapping */
		buffer->unmap_len = st->unmap_len;
		buffer->dma_offset = buffer->unmap_len - buffer->len;
		buffer->flags |= st->dma_flags;
		st->unmap_len = 0;
	}

	st->dma_addr += n;
}


/**
 * tso_start_new_packet - generate a new header and prepare for the new packet
 * @tx_queue:		Efx TX queue
 * @skb:		Socket buffer
 * @st:			TSO state
 *
 * Generate a new header and prepare for the new packet.  Return 0 on
 * success, or -%ENOMEM if failed to alloc header.
 */
static int tso_start_new_packet(struct efx_tx_queue *tx_queue,
				const struct sk_buff *skb,
				struct tso_state *st)
{
	struct efx_tx_buffer *buffer =
		efx_tx_queue_get_insert_buffer(tx_queue);
	bool is_last = st->out_len <= skb_shinfo(skb)->gso_size;
	u8 tcp_flags_clear;

	if (!is_last) {
		st->packet_space = skb_shinfo(skb)->gso_size;
		tcp_flags_clear = 0x09; /* mask out FIN and PSH */
	} else {
		st->packet_space = st->out_len;
		tcp_flags_clear = 0x00;
	}

	if (!st->header_unmap_len) {
		/* Allocate and insert a DMA-mapped header buffer. */
		struct tcphdr *tsoh_th;
		unsigned ip_length;
		u8 *header;
		int rc;

		header = efx_tsoh_get_buffer(tx_queue, buffer, st->header_len);
		if (!header)
			return -ENOMEM;

		tsoh_th = (struct tcphdr *)(header + st->tcp_off);

		/* Copy and update the headers. */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
		if (vlan_tx_tag_present(skb))
			efx_skb_copy_insert_tag(skb, header, st->in_header_len);
		else
			/* fall through */
#endif
		memcpy(header, skb->data, st->header_len);

		tsoh_th->seq = htonl(st->seqnum);
		((u8 *)tsoh_th)[13] &= ~tcp_flags_clear;

		ip_length = st->ip_base_len + st->packet_space;

		if (st->protocol == htons(ETH_P_IP)) {
			struct iphdr *tsoh_iph =
				(struct iphdr *)(header + st->ip_off);

			tsoh_iph->tot_len = htons(ip_length);
			tsoh_iph->id = htons(st->ipv4_id);
		} else {
			struct ipv6hdr *tsoh_iph =
				(struct ipv6hdr *)(header + st->ip_off);

			tsoh_iph->payload_len = htons(ip_length);
		}

		rc = efx_tso_put_header(tx_queue, buffer, header);
		if (unlikely(rc))
			return rc;
	} else {
		/* Send the original headers with a TSO option descriptor
		 * in front
		 */
		u8 tcp_flags = ((u8 *)tcp_hdr(skb))[13] & ~tcp_flags_clear;

		buffer->flags = EFX_TX_BUF_OPTION;
		buffer->len = 0;
		buffer->unmap_len = 0;
		EFX_POPULATE_QWORD_5(buffer->option,
				     ESF_DZ_TX_DESC_IS_OPT, 1,
				     ESF_DZ_TX_OPTION_TYPE,
				     ESE_DZ_TX_OPTION_DESC_TSO,
				     ESF_DZ_TX_TSO_TCP_FLAGS, tcp_flags,
				     ESF_DZ_TX_TSO_IP_ID, st->ipv4_id,
				     ESF_DZ_TX_TSO_TCP_SEQNO, st->seqnum);
		++tx_queue->insert_count;

		/* We mapped the headers in tso_start().  Unmap them
		 * when the last segment is completed.
		 */
		buffer = efx_tx_queue_get_insert_buffer(tx_queue);
		buffer->dma_addr = st->header_dma_addr;
		buffer->len = st->header_len;
		if (is_last) {
			buffer->flags = EFX_TX_BUF_CONT | EFX_TX_BUF_MAP_SINGLE;
			buffer->unmap_len = st->header_unmap_len;
			buffer->dma_offset = 0;
			/* Ensure we only unmap them once in case of a
			 * later DMA mapping error and rollback
			 */
			st->header_unmap_len = 0;
		} else {
			buffer->flags = EFX_TX_BUF_CONT;
			buffer->unmap_len = 0;
		}
		++tx_queue->insert_count;
	}

	st->seqnum += skb_shinfo(skb)->gso_size;

	/* Linux leaves suitable gaps in the IP ID space for us to fill. */
	++st->ipv4_id;

	++tx_queue->tso_packets;

	tx_queue->tx_packets++;

	return 0;
}

/**
 * efx_enqueue_skb_tso - segment and transmit a TSO socket buffer
 * @tx_queue:		Efx TX queue
 * @skb:		Socket buffer
 *
 * Context: You must hold netif_tx_lock() to call this function.
 *
 * Add socket buffer @skb to @tx_queue, doing TSO or return != 0 if
 * @skb was not enqueued.  In all cases @skb is consumed.  Return
 * %NETDEV_TX_OK.
 */
static int efx_enqueue_skb_tso(struct efx_tx_queue *tx_queue,
			       struct sk_buff *skb)
{
	struct efx_nic *efx = tx_queue->efx;
	int frag_i, rc;
	struct tso_state state;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_GSO_MAX_SEGS)
	/* Since the stack does not limit the number of segments per
	 * skb, we must do so.  Otherwise an attacker may be able to
	 * make the TCP produce skbs that will never fit in our TX
	 * queue, causing repeated resets.
	 */
	if (unlikely(skb_shinfo(skb)->gso_segs > EFX_TSO_MAX_SEGS)) {
		unsigned int excess =
			(skb_shinfo(skb)->gso_segs - EFX_TSO_MAX_SEGS) *
			skb_shinfo(skb)->gso_size;
		if (__pskb_trim(skb, skb->len - excess)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}
#endif

	prefetch(skb->data);

	/* Find the packet protocol and sanity-check it */
	state.protocol = efx_tso_check_protocol(skb);

	EFX_BUG_ON_PARANOID(tx_queue->write_count != tx_queue->insert_count);

	rc = tso_start(&state, efx, skb);
	if (rc)
		goto mem_err;

	if (likely(state.in_len == 0)) {
		/* Grab the first payload fragment. */
		EFX_BUG_ON_PARANOID(skb_shinfo(skb)->nr_frags < 1);
		frag_i = 0;
		rc = tso_get_fragment(&state, efx,
				      skb_shinfo(skb)->frags + frag_i);
		if (rc)
			goto mem_err;
	} else {
		/* Payload starts in the header area. */
		frag_i = -1;
	}

	if (tso_start_new_packet(tx_queue, skb, &state) < 0)
		goto mem_err;

	prefetch_ptr(tx_queue);

	while (1) {
		tso_fill_packet_with_fragment(tx_queue, skb, &state);

		/* Move onto the next fragment? */
		if (state.in_len == 0) {
			if (++frag_i >= skb_shinfo(skb)->nr_frags)
				/* End of payload reached. */
				break;
			rc = tso_get_fragment(&state, efx,
					      skb_shinfo(skb)->frags + frag_i);
			if (rc)
				goto mem_err;
		}

		/* Start at new packet? */
		if (state.packet_space == 0 &&
		    tso_start_new_packet(tx_queue, skb, &state) < 0)
			goto mem_err;
	}

#if defined(EFX_NOT_UPSTREAM)
	tx_queue->tx_bytes += skb->len;
#endif

	netdev_tx_sent_queue(tx_queue->core_txq, skb->len);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	efx_sarfs_skb(efx, tx_queue, skb);
#endif

	/* Pass off to hardware */
	efx_nic_push_buffers(tx_queue);

	efx_tx_maybe_stop_queue(tx_queue);

	tx_queue->tso_bursts++;
	return NETDEV_TX_OK;

 mem_err:
	netif_err(efx, tx_err, efx->net_dev,
		  "Out of memory for TSO headers, or DMA mapping error\n");
	dev_kfree_skb_any(skb);

	/* Free the DMA mapping we were in the process of writing out */
	if (state.unmap_len) {
		if (state.dma_flags & EFX_TX_BUF_MAP_SINGLE)
			dma_unmap_single(&efx->pci_dev->dev, state.unmap_addr,
					 state.unmap_len, DMA_TO_DEVICE);
		else
			dma_unmap_page(&efx->pci_dev->dev, state.unmap_addr,
				       state.unmap_len, DMA_TO_DEVICE);
	}

	/* Free the header DMA mapping, if using option descriptors */
	if (state.header_unmap_len)
		dma_unmap_single(&efx->pci_dev->dev, state.header_dma_addr,
				 state.header_unmap_len, DMA_TO_DEVICE);

	efx_enqueue_unwind(tx_queue);
	return NETDEV_TX_OK;
}
