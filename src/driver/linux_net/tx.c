/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
 * Copyright 2005-2010 Solarflare Communications Inc.
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
#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "workarounds.h"

/* Number of bytes inserted at the start of a copy buffer, similar to
 * NET_IP_ALIGN.
 */
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define TX_CB_OFFSET	0
#else
#define TX_CB_OFFSET	NET_IP_ALIGN
#endif

/* Size of page-based copy buffers, used for TSO headers (normally),
 * padding and linearisation.
 *
 * Must be power-of-2 before subtracting TX_CB_OFFSET.  Values much
 * less than 128 are fairly useless; values larger than EFX_PAGE_SIZE
 * or PAGE_SIZE would be harder to support.
 */
#define TX_CB_ORDER_MIN	7
#define TX_CB_ORDER_MAX	min(12, PAGE_SHIFT)
#define TX_CB_ORDER_DEF	7
static unsigned int tx_cb_order __read_mostly = TX_CB_ORDER_DEF;
static unsigned int
tx_cb_size __read_mostly = (1 << TX_CB_ORDER_DEF) - TX_CB_OFFSET;

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

	tx_cb_order = order_base_2(tx_cb_size + TX_CB_OFFSET);
	if (tx_cb_order < TX_CB_ORDER_MIN)
		tx_cb_order = TX_CB_ORDER_MIN;
	else if (tx_cb_order > TX_CB_ORDER_MAX)
		tx_cb_order = TX_CB_ORDER_MAX;
	tx_cb_size = (1 << tx_cb_order) - TX_CB_OFFSET;
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
		 "Maximum size of packet that may be copied to a new buffer on transmit (uint)");

static u8 *efx_tx_get_copy_buffer(struct efx_tx_queue *tx_queue,
				  struct efx_tx_buffer *buffer)
{
	unsigned index = tx_queue->insert_count & tx_queue->ptr_mask;
	struct efx_buffer *page_buf =
		&tx_queue->cb_page[index >> (PAGE_SHIFT - tx_cb_order)];
	unsigned offset =
		((index << tx_cb_order) + TX_CB_OFFSET) & (PAGE_SIZE - 1);

	if (unlikely(!page_buf->addr) &&
	    efx_nic_alloc_buffer(tx_queue->efx, page_buf, PAGE_SIZE))
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
		dma_addr_t unmap_addr = (buffer->dma_addr + buffer->len -
					 buffer->unmap_len);
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

	/* Possibly one more per segment for the alignment workaround */
	if (EFX_WORKAROUND_5391(efx))
		max_descs += EFX_TSO_MAX_SEGS;

	/* Possibly more for PCIe page boundaries within input fragments */
	if (PAGE_SIZE > EFX_PAGE_SIZE)
		max_descs += max_t(unsigned int, MAX_SKB_FRAGS,
				   DIV_ROUND_UP(GSO_MAX_SIZE, EFX_PAGE_SIZE));

	return max_descs;
}

/* Get partner of a TX queue, seen as part of the same net core queue */
static struct efx_tx_queue *efx_tx_queue_partner(struct efx_tx_queue *tx_queue)
{
	if (tx_queue->queue & EFX_TXQ_TYPE_OFFLOAD)
		return tx_queue - EFX_TXQ_TYPE_OFFLOAD;
	else
		return tx_queue + EFX_TXQ_TYPE_OFFLOAD;
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

static netdev_tx_t
efx_enqueue_skb_copy(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
		     unsigned int min_len)
{
	struct efx_tx_buffer *buffer;
	unsigned int copy_len = skb->len;
	u8 *copy_buffer;
	int rc;

	EFX_BUG_ON_PARANOID(copy_len > tx_cb_size);

	buffer = &tx_queue->buffer[tx_queue->insert_count & tx_queue->ptr_mask];
	EFX_BUG_ON_PARANOID(buffer->len);
	EFX_BUG_ON_PARANOID(buffer->flags);
	EFX_BUG_ON_PARANOID(buffer->unmap_len);

	copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
	if (unlikely(!copy_buffer)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	rc = skb_copy_bits(skb, 0, copy_buffer, copy_len);
	EFX_WARN_ON_PARANOID(rc);
	if (unlikely(copy_len < min_len)) {
		memset(copy_buffer + copy_len, 0, min_len - copy_len);
		buffer->len = min_len;
	} else {
		buffer->len = copy_len;
	}

	/* Attach skb to this buffer */
	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB;

	netdev_tx_sent_queue(tx_queue->core_txq, skb->len);

	++tx_queue->insert_count;
	efx_nic_push_buffers(tx_queue);

	efx_tx_maybe_stop_queue(tx_queue);

	return NETDEV_TX_OK;
}

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
	unsigned int len, unmap_len = 0, insert_ptr;
	dma_addr_t dma_addr, unmap_addr = 0;
	unsigned int dma_len;
	unsigned short dma_flags;
	int i = 0;

	EFX_BUG_ON_PARANOID(tx_queue->write_count != tx_queue->insert_count);

	if (skb_shinfo(skb)->gso_size)
		return efx_enqueue_skb_tso(tx_queue, skb);

	/* Pad if necessary */
	if (EFX_WORKAROUND_15592(efx) && skb->len <= 32)
		return efx_enqueue_skb_copy(tx_queue, skb, 32 + 1);

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

		buffer = &tx_queue->buffer[tx_queue->insert_count &
					   tx_queue->ptr_mask];
		EFX_BUG_ON_PARANOID(buffer->len);
		EFX_BUG_ON_PARANOID(buffer->flags);
		EFX_BUG_ON_PARANOID(buffer->unmap_len);

		copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
		if (unlikely(!copy_buffer)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}

		++tx_queue->insert_count;

		/* Must copy header.  Try to minimise number of fragments. */
		if (skb->len <= tx_cb_size - VLAN_HLEN && skb->data_len) {
			efx_skb_copy_insert_tag(skb, copy_buffer, skb->len);
			buffer->len = skb->len + VLAN_HLEN;

			dma_flags = 0;
			goto finish_packet;
		} else if (skb_headlen(skb) <= tx_cb_size - VLAN_HLEN) {
			efx_skb_copy_insert_tag(skb, copy_buffer,
						skb_headlen(skb));
			buffer->len = skb_headlen(skb) + VLAN_HLEN;

			dma_flags = 0;
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

			if (align_len <= tx_cb_size - VLAN_HLEN)
				copy_len = align_len;
			else
				copy_len = ETH_HLEN;
			efx_skb_copy_insert_tag(skb, copy_buffer, copy_len);
			buffer->len = copy_len + VLAN_HLEN;
			buffer->flags = EFX_TX_BUF_CONT;

			len = skb_headlen(skb) - copy_len;
			dma_flags = EFX_TX_BUF_MAP_SINGLE;
			dma_addr = dma_map_single(dma_dev, skb->data + copy_len,
						  len, PCI_DMA_TODEVICE);
			goto begin_fragment;
		}
	}
begin_packet:
#endif

	/* Coalesce short fragmented packets */
	if (skb->len <= tx_cb_size && skb->data_len &&
	    !(TX_CB_OFFSET && EFX_WORKAROUND_5391(efx)))
		return efx_enqueue_skb_copy(tx_queue, skb, 0);

	/* Get size of the initial fragment */
	len = skb_headlen(skb);

	/* Map for DMA.  Use dma_map_single rather than dma_map_page
	 * since this is more efficient on machines with sparse
	 * memory.
	 */
	dma_flags = EFX_TX_BUF_MAP_SINGLE;
	dma_addr = dma_map_single(dma_dev, skb->data, len, PCI_DMA_TODEVICE);

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
			insert_ptr = tx_queue->insert_count & tx_queue->ptr_mask;
			buffer = &tx_queue->buffer[insert_ptr];
			EFX_BUG_ON_PARANOID(buffer->flags);
			EFX_BUG_ON_PARANOID(buffer->len);
			EFX_BUG_ON_PARANOID(buffer->unmap_len);

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
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
finish_packet:
#endif
	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB | dma_flags;

	netdev_tx_sent_queue(tx_queue->core_txq, skb->len);

	/* Pass off to hardware */
	efx_nic_push_buffers(tx_queue);

#if defined(EFX_NOT_UPSTREAM)
	tx_queue->tx_packets++;
	tx_queue->tx_bytes += skb->len;
#endif

	efx_tx_maybe_stop_queue(tx_queue);

	return NETDEV_TX_OK;

 dma_err:
	netif_err(efx, tx_err, efx->net_dev,
		  " TX queue %d could not map skb with %d bytes %d "
		  "fragments for DMA\n", tx_queue->queue, skb->len,
		  skb_shinfo(skb)->nr_frags + 1);

	/* Mark the packet as transmitted, and free the SKB ourselves */
	dev_kfree_skb_any(skb);

	/* Work backwards until we hit the original insert pointer value */
	while (tx_queue->insert_count != tx_queue->write_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		--tx_queue->insert_count;
		insert_ptr = tx_queue->insert_count & tx_queue->ptr_mask;
		buffer = &tx_queue->buffer[insert_ptr];
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
		if (unlikely(buffer->len == 0)) {
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
	unsigned fill_level;
	struct efx_nic *efx = tx_queue->efx;
	struct efx_tx_queue *txq2;
	unsigned int pkts_compl = 0, bytes_compl = 0;

	EFX_BUG_ON_PARANOID(index > tx_queue->ptr_mask);

	efx_dequeue_buffers(tx_queue, index, &pkts_compl, &bytes_compl);
	netdev_tx_completed_queue(tx_queue->core_txq, pkts_compl, bytes_compl);

	/* See if we need to restart the netif queue.  This memory
	 * barrier ensures that we write read_count (inside
	 * efx_dequeue_buffers()) before reading the queue status.
	 */
	smp_mb();
	if (likely(tx_queue->core_txq) &&
	    unlikely(netif_tx_queue_stopped(tx_queue->core_txq)) &&
	    likely(efx->port_enabled) &&
	    likely(netif_device_present(efx->net_dev))) {
		txq2 = efx_tx_queue_partner(tx_queue);
		fill_level = max(tx_queue->insert_count - tx_queue->read_count,
				 txq2->insert_count - txq2->read_count);
		if (fill_level <= efx->txq_wake_thresh)
			netif_tx_wake_queue(tx_queue->core_txq);
	}

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
	tx_queue->old_write_count = 0;
	tx_queue->read_count = 0;
	tx_queue->old_read_count = 0;
	tx_queue->empty_read_count = 0 | EFX_EMPTY_COUNT_VALID;

	/* Set up TX descriptor ring */
	efx_nic_init_tx(tx_queue);
}

void efx_release_tx_buffers(struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *buffer;

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

void efx_fini_tx_queue(struct efx_tx_queue *tx_queue)
{
	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "shutting down TX queue %d\n", tx_queue->queue);

	/* Flush TX queue, remove descriptor ring */
	efx_nic_fini_tx(tx_queue);

	efx_release_tx_buffers(tx_queue);
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
 *
 * The state used during segmentation.  It is put into this data structure
 * just to make it easy to pass into inline functions.
 */
struct tso_state {
	/* Output position */
	unsigned out_len;
	unsigned seqnum;
	unsigned ipv4_id;
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
};


static inline void prefetch_ptr(struct efx_tx_queue *tx_queue)
{
	unsigned insert_ptr = tx_queue->insert_count & tx_queue->ptr_mask;
	char *ptr;

	ptr = (char *) (tx_queue->buffer + insert_ptr);
	prefetch(ptr);
	prefetch(ptr + 0x80);

	ptr = (char *) (((efx_qword_t *)tx_queue->txd.addr) + insert_ptr);
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_VLAN_FEATURES) || defined(NETIF_F_VLAN_TSO)
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

		buffer->heap_buf = kmalloc(TX_CB_OFFSET + len, GFP_ATOMIC);
		if (unlikely(!buffer->heap_buf))
			return NULL;
		result = (u8 *)buffer->heap_buf + TX_CB_OFFSET;
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
	unsigned dma_len, insert_ptr;

	EFX_BUG_ON_PARANOID(len <= 0);

	while (1) {
		insert_ptr = tx_queue->insert_count & tx_queue->ptr_mask;
		buffer = &tx_queue->buffer[insert_ptr];
		++tx_queue->insert_count;

		EFX_BUG_ON_PARANOID(tx_queue->insert_count -
				    tx_queue->read_count >=
				    efx->txq_entries);

		EFX_BUG_ON_PARANOID(buffer->len);
		EFX_BUG_ON_PARANOID(buffer->unmap_len);
		EFX_BUG_ON_PARANOID(buffer->flags);

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
		buffer = &tx_queue->buffer[tx_queue->insert_count &
					   tx_queue->ptr_mask];
		efx_dequeue_buffer(tx_queue, buffer, NULL, NULL);
	}
}


/* Parse the SKB header and initialise state. */
static void tso_start(struct tso_state *st, const struct sk_buff *skb)
{
	st->ip_off = skb_network_header(skb) - skb->data;
	st->tcp_off = skb_transport_header(skb) - skb->data;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	st->in_header_len = st->tcp_off + (tcp_hdr(skb)->doff << 2u);
	if (vlan_tx_tag_present(skb)) {
		st->ip_off += VLAN_HLEN;
		st->tcp_off += VLAN_HLEN;
	}
#endif
	st->header_len = st->tcp_off + (tcp_hdr(skb)->doff << 2u);
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

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	st->out_len = skb->len - st->in_header_len;
#else
	st->out_len = skb->len - st->header_len;
#endif
	st->unmap_len = 0;
	st->dma_flags = 0;
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

static int tso_get_head_fragment(struct tso_state *st, struct efx_nic *efx,
				 const struct sk_buff *skb)
{
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	int hl = st->in_header_len;
#else
	int hl = st->header_len;
#endif
	int len = skb_headlen(skb) - hl;

	st->unmap_addr = dma_map_single(&efx->pci_dev->dev, skb->data + hl,
					len, DMA_TO_DEVICE);
	if (likely(!dma_mapping_error(&efx->pci_dev->dev, st->unmap_addr))) {
		st->dma_flags = EFX_TX_BUF_MAP_SINGLE;
		st->unmap_len = len;
		st->in_len = len;
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
		&tx_queue->buffer[tx_queue->insert_count & tx_queue->ptr_mask];
	struct tcphdr *tsoh_th;
	unsigned ip_length;
	u8 *header;
	int rc;

	/* Allocate and insert a DMA-mapped header buffer. */
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
	st->seqnum += skb_shinfo(skb)->gso_size;
	if (st->out_len > skb_shinfo(skb)->gso_size) {
		/* This packet will not finish the TSO burst. */
		st->packet_space = skb_shinfo(skb)->gso_size;
		tsoh_th->fin = 0;
		tsoh_th->psh = 0;
	} else {
		/* This packet will be the last in the TSO burst. */
		st->packet_space = st->out_len;
		tsoh_th->fin = tcp_hdr(skb)->fin;
		tsoh_th->psh = tcp_hdr(skb)->psh;
	}
	ip_length = st->ip_base_len + st->packet_space;

	if (st->protocol == htons(ETH_P_IP)) {
		struct iphdr *tsoh_iph = (struct iphdr *)(header + st->ip_off);

		tsoh_iph->tot_len = htons(ip_length);

		/* Linux leaves suitable gaps in the IP ID space for us to fill. */
		tsoh_iph->id = htons(st->ipv4_id);
		st->ipv4_id++;
	} else {
		struct ipv6hdr *tsoh_iph =
			(struct ipv6hdr *)(header + st->ip_off);

		tsoh_iph->payload_len = htons(ip_length);
	}

	rc = efx_tso_put_header(tx_queue, buffer, header);
	if (unlikely(rc))
		return rc;

	++tx_queue->tso_packets;

#if defined(EFX_NOT_UPSTREAM)
	tx_queue->tx_packets++;
#endif

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

	tso_start(&state, skb);

	/* Assume that skb header area contains exactly the headers, and
	 * all payload is in the frag list.
	 */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	if (skb_headlen(skb) == state.in_header_len) {
#else
	if (skb_headlen(skb) == state.header_len) {
#endif
		/* Grab the first payload fragment. */
		EFX_BUG_ON_PARANOID(skb_shinfo(skb)->nr_frags < 1);
		frag_i = 0;
		rc = tso_get_fragment(&state, efx,
				      skb_shinfo(skb)->frags + frag_i);
		if (rc)
			goto mem_err;
	} else {
		rc = tso_get_head_fragment(&state, efx, skb);
		if (rc)
			goto mem_err;
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

	efx_enqueue_unwind(tx_queue);
	return NETDEV_TX_OK;
}
