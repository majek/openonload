/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * Copyright 2005-2013 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/prefetch.h>
#include <linux/moduleparam.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/iommu.h>
#endif
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#ifdef EFX_NOT_UPSTREAM
#include <net/ipv6.h>
#endif
#include "net_driver.h"
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_LINUX_IOMMU_H)
#include <linux/iommu.h>
#endif
#include "efx.h"
#include "filter.h"
#include "nic.h"
#include "selftest.h"
#include "workarounds.h"
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
#include "efx_netq.h"
#endif
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif

/* Preferred number of descriptors to fill at once */
#define EFX_RX_PREFERRED_BATCH 8U

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* Number of RX buffers to recycle pages for.  When creating the RX page recycle
 * ring, this number is divided by the number of buffers per page to calculate
 * the number of pages to store in the RX page recycle ring.
 */
#define EFX_RECYCLE_RING_SIZE_UNSET -1
#define EFX_RECYCLE_RING_SIZE_IOMMU 4096
#define EFX_RECYCLE_RING_SIZE_NOIOMMU (2 * EFX_RX_PREFERRED_BATCH)
static int rx_recycle_ring_size = EFX_RECYCLE_RING_SIZE_UNSET;
module_param(rx_recycle_ring_size, uint, 0444);
MODULE_PARM_DESC(rx_recycle_ring_size,
		 "Maximum number of RX buffers to recycle pages for");
#else
#define rx_recycle_ring_size	0
#endif

#ifdef EFX_NOT_UPSTREAM
static bool underreport_skb_truesize;
module_param(underreport_skb_truesize, bool, 0444);
MODULE_PARM_DESC(underreport_skb_truesize, "Give false skb truesizes. "
			"Debug option to restore previous driver behaviour.");
#endif


/* Size of buffer allocated for skb header area. */
#define EFX_SKB_HEADERS  128u

/* This is the percentage fill level below which new RX descriptors
 * will be added to the RX descriptor ring.
 */
static unsigned int rx_refill_threshold;

/* Each packet can consume up to ceil(max_frame_len / buffer_size) buffers */
#define EFX_RX_MAX_FRAGS DIV_ROUND_UP(EFX_MAX_FRAME_LEN(EFX_MAX_MTU), \
				      EFX_RX_USR_BUF_SIZE)

/*
 * RX maximum head room required.
 *
 * This must be at least 1 to prevent overflow, plus one packet-worth
 * to allow pipelined receives.
 */
#define EFX_RXD_HEAD_ROOM (1 + EFX_RX_MAX_FRAGS)

static inline struct efx_rx_buffer *
efx_rx_buf_next(struct efx_rx_queue *rx_queue, struct efx_rx_buffer *rx_buf)
{
	if (unlikely(rx_buf == efx_rx_buffer(rx_queue, rx_queue->ptr_mask)))
		return efx_rx_buffer(rx_queue, 0);
	else
		return rx_buf + 1;
}

#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_RX_PAGE_SHARE)
static void efx_unmap_rx_buffer(struct efx_nic *efx,
				struct efx_rx_buffer *rx_buf);
#endif

static inline void efx_sync_rx_buffer(struct efx_nic *efx,
				      struct efx_rx_buffer *rx_buf,
				      unsigned int len)
{
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	dma_sync_single_for_cpu(&efx->pci_dev->dev, rx_buf->dma_addr, len,
				DMA_FROM_DEVICE);
#else
	efx_unmap_rx_buffer(efx, rx_buf);
#endif
}

void efx_rx_config_page_split(struct efx_nic *efx)
{
	efx->rx_page_buf_step = ALIGN(efx->rx_dma_len + efx->rx_ip_align,
				      EFX_RX_BUF_ALIGNMENT);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	efx->rx_bufs_per_page = efx->rx_buffer_order ? 1 :
		((PAGE_SIZE - sizeof(struct efx_rx_page_state)) /
		 efx->rx_page_buf_step);
#else
	efx->rx_bufs_per_page = 1;
#endif
	efx->rx_buffer_truesize = (PAGE_SIZE << efx->rx_buffer_order) /
		efx->rx_bufs_per_page;
	efx->rx_pages_per_batch = DIV_ROUND_UP(EFX_RX_PREFERRED_BATCH,
					       efx->rx_bufs_per_page);
}

static inline u8 *efx_rx_buf_va(struct efx_rx_buffer *buf)
{
	return page_address(buf->page) + buf->page_offset;
}

static void efx_refill_skb_cache(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	struct sk_buff *skb;
	int i;

	for (i = 0; i < SKB_CACHE_SIZE; ++i) {
		skb = netdev_alloc_skb(efx->net_dev,
				       efx->rx_ip_align + efx->rx_prefix_size +
				       EFX_SKB_HEADERS);
		rx_queue->skb_cache[i] = skb;
		if (skb) {
			prefetch(skb->data);
			prefetch(skb_shinfo(skb));
		}
	}
	rx_queue->skb_cache_next_unused = 0;
}

static void efx_refill_skb_cache_check(struct efx_rx_queue *rx_queue)
{
	if (rx_queue->skb_cache_next_unused == SKB_CACHE_SIZE)
		efx_refill_skb_cache(rx_queue);
}

static void efx_fini_skb_cache(struct efx_rx_queue *rx_queue)
{
	/* free unused skbs in the cache */
	while (rx_queue->skb_cache_next_unused < SKB_CACHE_SIZE)
		dev_kfree_skb(
			rx_queue->skb_cache[rx_queue->skb_cache_next_unused++]);
}

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* Check the RX page recycle ring for a page that can be reused. */
static struct page *efx_reuse_page(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	struct page *page;
	struct efx_rx_page_state *state;
	unsigned index;

	index = rx_queue->page_remove & rx_queue->page_ptr_mask;
	page = rx_queue->page_ring[index];
	if (page == NULL)
		return NULL;

	rx_queue->page_ring[index] = NULL;
	/* page_remove cannot exceed page_add. */
	if (rx_queue->page_remove != rx_queue->page_add)
		++rx_queue->page_remove;

	/* If page_count is 1 then we hold the only reference to this page. */
	if (page_count(page) == 1) {
		++rx_queue->page_recycle_count;
		return page;
	} else {
		state = page_address(page);
		dma_unmap_page(&efx->pci_dev->dev, state->dma_addr,
			       PAGE_SIZE << efx->rx_buffer_order,
			       DMA_FROM_DEVICE);
		put_page(page);
		++rx_queue->page_recycle_failed;
	}

	return NULL;
}
#else
static struct page *efx_reuse_page(struct efx_rx_queue *rx_queue)
{
	(void)rx_queue;
	return NULL;
}
#endif

/**
 * efx_init_rx_buffers - create EFX_RX_BATCH page-based RX buffers
 *
 * @rx_queue:		Efx RX queue
 *
 * This allocates a batch of pages, maps them for DMA, and populates
 * struct efx_rx_buffers for each one. Return a negative error code or
 * 0 on success. If a single page can be used for multiple buffers,
 * then the page will either be inserted fully, or not at all.
 */
static int efx_init_rx_buffers(struct efx_rx_queue *rx_queue, bool atomic)
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_buffer *rx_buf;
	struct page *page;
	unsigned int page_offset;
	struct efx_rx_page_state *state;
	dma_addr_t dma_addr;
	unsigned index, count;
	unsigned i;

	count = 0;
	do {
		if (rx_recycle_ring_size == 0)
			page = NULL;
		else
			page = efx_reuse_page(rx_queue);
		if (page == NULL) {
			/* GFP_ATOMIC may fail because of various reasons,
			 * and we re-schedule rx_fill from non-atomic
			 * context in such a case.  So, use __GFP_NO_WARN
			 * in case of atomic. */
			page = alloc_pages(__GFP_COLD | __GFP_COMP |
					   (atomic ?
					    (GFP_ATOMIC | __GFP_NOWARN)
					    : GFP_KERNEL),
					   efx->rx_buffer_order);
			if (unlikely(page == NULL))
				return -ENOMEM;
			dma_addr =
				dma_map_page(&efx->pci_dev->dev, page, 0,
					     PAGE_SIZE << efx->rx_buffer_order,
					     DMA_FROM_DEVICE);
			if (unlikely(dma_mapping_error(&efx->pci_dev->dev,
						       dma_addr))) {
				__free_pages(page, efx->rx_buffer_order);
				return -EIO;
			}
			state = page_address(page);
			state->dma_addr = dma_addr;
		} else {
			state = page_address(page);
			dma_addr = state->dma_addr;
		}

		dma_addr += sizeof(struct efx_rx_page_state);
		page_offset = sizeof(struct efx_rx_page_state);

		i = 0;
		do {
			index = rx_queue->added_count & rx_queue->ptr_mask;
			rx_buf = efx_rx_buffer(rx_queue, index);
			rx_buf->dma_addr = dma_addr + efx->rx_ip_align;
			rx_buf->page = page;
			rx_buf->page_offset = page_offset + efx->rx_ip_align;
			rx_buf->len = efx->rx_dma_len;
			rx_buf->flags = 0;
			++rx_queue->added_count;
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
			get_page(page);
#endif
			dma_addr += efx->rx_page_buf_step;
			page_offset += efx->rx_page_buf_step;
			EFX_BUG_ON_PARANOID(page_offset >
					    PAGE_SIZE << efx->rx_buffer_order);
		} while (++i < efx->rx_bufs_per_page);

		rx_buf->flags = EFX_RX_BUF_LAST_IN_PAGE;
	} while (++count < efx->rx_pages_per_batch);

	return 0;
}

/* Unmap a DMA-mapped page.  This function is only called for the final RX
 * buffer in a page.
 */
static void efx_unmap_rx_buffer(struct efx_nic *efx,
				struct efx_rx_buffer *rx_buf)
{
	struct page *page = rx_buf->page;

	if (page) {
		struct efx_rx_page_state *state = page_address(page);
		dma_unmap_page(&efx->pci_dev->dev,
			       state->dma_addr,
			       PAGE_SIZE << efx->rx_buffer_order,
			       DMA_FROM_DEVICE);
	}
}

static void efx_free_rx_buffer(struct efx_rx_buffer *rx_buf)
{
	if (rx_buf->page) {
		put_page(rx_buf->page);
		rx_buf->page = NULL;
	}
}

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* Attempt to recycle the page if there is an RX recycle ring; the page can
 * only be added if this is the final RX buffer, to prevent pages being used in
 * the descriptor ring and appearing in the recycle ring simultaneously.
 */
static void efx_recycle_rx_page(struct efx_channel *channel,
				struct efx_rx_buffer *rx_buf)
{
	struct page *page = rx_buf->page;
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	struct efx_nic *efx = rx_queue->efx;
	unsigned index;

	/* Only recycle the page after processing the final buffer. */
	if (!(rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE))
		return;

	if (rx_recycle_ring_size != 0) {
		index = rx_queue->page_add & rx_queue->page_ptr_mask;
		if (rx_queue->page_ring[index] == NULL) {
			unsigned read_index = rx_queue->page_remove &
				rx_queue->page_ptr_mask;

			/* The next slot in the recycle ring is available, but
			 * increment page_remove if the read pointer currently
			 * points here.
			 */
			if (read_index == index)
				++rx_queue->page_remove;
			rx_queue->page_ring[index] = page;
			++rx_queue->page_add;
			return;
		}
		++rx_queue->page_recycle_full;
	}
	efx_unmap_rx_buffer(efx, rx_buf);
	put_page(rx_buf->page);
}
#endif

static void efx_fini_rx_buffer(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	/* Release the page reference we hold for the buffer. */
	if (rx_buf->page)
		put_page(rx_buf->page);
#endif

	/* If this is the last buffer in a page, unmap and free it. */
	if (rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE) {
		efx_unmap_rx_buffer(rx_queue->efx, rx_buf);
		efx_free_rx_buffer(rx_buf);
	}
	rx_buf->page = NULL;
}

#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_RX_PAGE_SHARE)
static void efx_recycle_rx_pages(struct efx_channel *channel,
				 struct efx_rx_buffer *rx_buf,
				 unsigned int n_frags)
{
	(void)channel;
	(void)rx_buf;
	(void)n_frags;
}
#else
/* Recycle the pages that are used by buffers that have just been received. */
static void efx_recycle_rx_pages(struct efx_channel *channel,
				 struct efx_rx_buffer *rx_buf,
				 unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);

	do {
		efx_recycle_rx_page(channel, rx_buf);
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	} while (--n_frags);
}
#endif

#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_RX_PAGE_SHARE)
/* Recycle Rx buffer directly back into the rx_queue.
 * If may be done on discard only when Rx buffers do not share page.
 * There is always room to add this buffer, because pipeline is empty and
 * we've just popped a buffer.
 */
static void efx_recycle_rx_buf(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
	struct efx_rx_buffer *new_buf;
	unsigned index;

	index = rx_queue->added_count & rx_queue->ptr_mask;
	new_buf = efx_rx_buffer(rx_queue, index);

	memcpy(new_buf, rx_buf, sizeof(*new_buf));
	rx_buf->page = NULL;
	/* Page is not shared, so it is always the last */
	new_buf->flags = EFX_RX_BUF_LAST_IN_PAGE;

	/* Since removed_count is updated after packet processing the
	 * following can happen here:
	 *   added_count > removed_count + efx->rxq_entries
	 * efx_fast_push_rx_descriptors() asserts this is not true.
	 * efx_fast_push_rx_descriptors() is only called at the end of
	 * a NAPI poll cycle, at which point removed_count has been updated.
	 */
	++rx_queue->added_count;
	++rx_queue->recycle_count;
}

static void efx_discard_rx_packet(struct efx_channel *channel,
				  struct efx_rx_buffer *rx_buf,
				  unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);

	do {
		efx_recycle_rx_buf(rx_queue, rx_buf);
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	} while (--n_frags);
}
#else
static void efx_discard_rx_packet(struct efx_channel *channel,
				  struct efx_rx_buffer *rx_buf,
				  unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);

	efx_recycle_rx_pages(channel, rx_buf, n_frags);

	do {
		efx_free_rx_buffer(rx_buf);
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	} while (--n_frags);
}
#endif

static inline u32 efx_rx_buf_hash(struct efx_nic *efx, const u8 *eh)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return __le32_to_cpup((const __le32 *)(eh + efx->rx_packet_hash_offset));
#else
	const u8 *data = eh + efx->rx_packet_hash_offset;
	return (u32)data[0]	  |
	       (u32)data[1] << 8  |
	       (u32)data[2] << 16 |
	       (u32)data[3] << 24;
#endif
}

/**
 * efx_fast_push_rx_descriptors - push new RX descriptors quickly
 * @rx_queue:		RX descriptor queue
 *
 * This will aim to fill the RX descriptor queue up to
 * @rx_queue->@max_fill. If there is insufficient atomic
 * memory to do so, a slow fill will be scheduled.
 *
 * The caller must provide serialisation (none is used here). In practise,
 * this means this function must run from the NAPI handler, or be called
 * when NAPI is disabled.
 */
void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue, bool atomic)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int fill_level, batch_size;
	int space, rc = 0;

	if (!rx_queue->refill_enabled)
		return;

	/* Calculate current fill level, and exit if we don't need to fill */
	fill_level = (rx_queue->added_count - rx_queue->removed_count);
	EFX_BUG_ON_PARANOID(fill_level > rx_queue->efx->rxq_entries);
	if (fill_level >= rx_queue->fast_fill_trigger)
		goto out;

	/* Record minimum fill level */
	if (unlikely(fill_level < rx_queue->min_fill)) {
		if (fill_level)
			rx_queue->min_fill = fill_level;
	}

	batch_size = efx->rx_pages_per_batch * efx->rx_bufs_per_page;
	space = rx_queue->max_fill - fill_level;
	EFX_BUG_ON_PARANOID(space < batch_size);

	netif_vdbg(rx_queue->efx, rx_status, rx_queue->efx->net_dev,
		   "RX queue %d fast-filling descriptor ring from"
		   " level %d to level %d\n",
		   efx_rx_queue_index(rx_queue), fill_level,
		   rx_queue->max_fill);


	do {
		rc = efx_init_rx_buffers(rx_queue, atomic);
		if (unlikely(rc)) {
			/* Ensure that we don't leave the rx queue empty */
			if (rx_queue->added_count == rx_queue->removed_count)
				efx_schedule_slow_fill(rx_queue);
			goto out;
		}
	} while ((space -= batch_size) >= batch_size);

	netif_vdbg(rx_queue->efx, rx_status, rx_queue->efx->net_dev,
		   "RX queue %d fast-filled descriptor ring "
		   "to level %d\n", efx_rx_queue_index(rx_queue),
		   rx_queue->added_count - rx_queue->removed_count);

out:
	if (rx_queue->notified_count != rx_queue->added_count)
		efx_nic_notify_rx_desc(rx_queue);
}

void efx_rx_slow_fill(unsigned long context)
{
	struct efx_rx_queue *rx_queue = (struct efx_rx_queue *)context;

	/* Post an event to cause NAPI to run and refill the queue */
	efx_nic_generate_fill_event(rx_queue);
	++rx_queue->slow_fill_count;
}

static void efx_rx_packet__check_len(struct efx_rx_queue *rx_queue,
				     struct efx_rx_buffer *rx_buf,
				     int len)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned max_len = rx_buf->len - efx->type->rx_buffer_padding;

	if (likely(len <= max_len))
		return;

	/* The packet must be discarded, but this is only a fatal error
	 * if the caller indicated it was
	 */
	rx_buf->flags |= EFX_RX_PKT_DISCARD;

	if ((len > rx_buf->len) && EFX_WORKAROUND_8071(efx)) {
		if (net_ratelimit())
			netif_err(efx, rx_err, efx->net_dev,
				  " RX queue %d seriously overlength "
				  "RX event (0x%x > 0x%x+0x%x). Leaking\n",
				  efx_rx_queue_index(rx_queue), len, max_len,
				  efx->type->rx_buffer_padding);
		efx_schedule_reset(efx, RESET_TYPE_RX_RECOVERY);
	} else {
		if (net_ratelimit())
			netif_err(efx, rx_err, efx->net_dev,
				  " RX queue %d overlength RX event "
				  "(0x%x > 0x%x)\n",
				  efx_rx_queue_index(rx_queue), len, max_len);
	}

	efx_rx_queue_channel(rx_queue)->n_rx_overlength++;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)

/* Pass a received packet up through GRO.  GRO can handle pages
 * regardless of checksum state and skbs with a good checksum.
 */
static void
efx_rx_packet_gro(struct efx_channel *channel, struct efx_rx_buffer *rx_buf,
		  unsigned int n_frags, u8 *eh)
{
#if (defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)) || defined(CONFIG_SFC_TRACING)
	struct efx_rx_buffer *head_buf = rx_buf;
#endif
	struct napi_struct *napi = &channel->napi_str;
	gro_result_t gro_result;
	struct efx_nic *efx = channel->efx;
	struct sk_buff *skb;

	skb = napi_get_frags(napi);
	if (unlikely(!skb)) {
		while (n_frags--) {
			put_page(rx_buf->page);
			rx_buf->page = NULL;
			rx_buf = efx_rx_buf_next(&channel->rx_queue, rx_buf);
		}
		return;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
	if (efx->net_dev->features & NETIF_F_RXHASH)
		skb_set_hash(skb, efx_rx_buf_hash(efx, eh),
			     PKT_HASH_TYPE_L3);
#endif
	skb->ip_summed = ((rx_buf->flags & EFX_RX_PKT_CSUMMED) ?
			  CHECKSUM_UNNECESSARY : CHECKSUM_NONE);

	for (;;) {
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
				   rx_buf->page, rx_buf->page_offset,
				   rx_buf->len);
		rx_buf->page = NULL;
		skb->len += rx_buf->len;
		if (skb_shinfo(skb)->nr_frags == n_frags)
			break;

		rx_buf = efx_rx_buf_next(&channel->rx_queue, rx_buf);
	}

	skb->data_len = skb->len;
	skb->truesize += n_frags * efx->rx_buffer_truesize;

	skb_record_rx_queue(skb, channel->rx_queue.core_index);

	skb_mark_napi_id(skb, &channel->napi_str);
#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(skb, true, head_buf->flags & EFX_RX_BUF_VLAN_XTAG,
			  head_buf->vlan_tci);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (head_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		gro_result = vlan_gro_frags(napi, efx->vlan_group,
					    head_buf->vlan_tci);
	else
		/* fall through */
#endif
	gro_result = napi_gro_frags(napi);
	if (gro_result != GRO_DROP)
		channel->irq_mod_score += 2;
}

#endif /* EFX_USE_GRO */

/* Allocate and construct an SKB around page fragments */
static struct sk_buff *efx_rx_mk_skb(struct efx_channel *channel,
				     struct efx_rx_buffer *rx_buf,
				     unsigned int n_frags,
				     u8 *eh, int hdr_len)
{
	struct efx_nic *efx = channel->efx;
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	struct sk_buff *skb = NULL;

	/* Allocate an SKB to store the headers */
	if (hdr_len <= EFX_SKB_HEADERS &&
	    likely(rx_queue->skb_cache_next_unused < SKB_CACHE_SIZE)) {
		skb = rx_queue->skb_cache[rx_queue->skb_cache_next_unused++];
	}
	if (unlikely(!skb)) {
		skb = netdev_alloc_skb(efx->net_dev,
				       efx->rx_ip_align + efx->rx_prefix_size +
				       hdr_len);
		if (unlikely(skb == NULL)) {
			atomic_inc(&efx->n_rx_noskb_drops);
			return NULL;
		}
	}

	EFX_BUG_ON_PARANOID(rx_buf->len < hdr_len);

	memcpy(skb->data + efx->rx_ip_align, eh - efx->rx_prefix_size,
	       efx->rx_prefix_size + hdr_len);
	skb_reserve(skb, efx->rx_ip_align + efx->rx_prefix_size);
	__skb_put(skb, hdr_len);

	/* Append the remaining page(s) onto the frag list */
	if (rx_buf->len > hdr_len) {
		rx_buf->page_offset += hdr_len;
		rx_buf->len -= hdr_len;

		for (;;) {
			skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
					   rx_buf->page, rx_buf->page_offset,
					   rx_buf->len);
			rx_buf->page = NULL;
			skb->len += rx_buf->len;
			skb->data_len += rx_buf->len;
			if (skb_shinfo(skb)->nr_frags == n_frags)
				break;

			rx_buf = efx_rx_buf_next(&channel->rx_queue, rx_buf);
		}
	} else {
		__free_pages(rx_buf->page, efx->rx_buffer_order);
		rx_buf->page = NULL;
		n_frags = 0;
	}

	skb->truesize += n_frags * efx->rx_buffer_truesize;

	/* Move past the ethernet header */
	skb->protocol = eth_type_trans(skb, efx->net_dev);

	skb_mark_napi_id(skb, &channel->napi_str);

	return skb;
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_rx_packet(struct efx_rx_queue *rx_queue,
			    unsigned int index, unsigned int n_frags,
			    unsigned int len, u16 flags)
#else
void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int n_frags, unsigned int len, u16 flags)
#endif
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	struct efx_rx_buffer *rx_buf;

	rx_queue->rx_packets++;

	rx_buf = efx_rx_buffer(rx_queue, index);
	rx_buf->flags |= flags;

	/* Validate the number of fragments and completed length */
	if (n_frags == 1) {
		if (!(flags & EFX_RX_PKT_PREFIX_LEN))
			efx_rx_packet__check_len(rx_queue, rx_buf, len);
	} else if (unlikely(n_frags > EFX_RX_MAX_FRAGS) ||
		   unlikely(len <= (n_frags - 1) * efx->rx_dma_len) ||
		   unlikely(len > n_frags * efx->rx_dma_len) ||
		   unlikely(!efx->rx_scatter)) {
		/* If this isn't an explicit discard request, either
		 * the hardware or the driver is broken.
		 */
		WARN_ON(!(len == 0 && rx_buf->flags & EFX_RX_PKT_DISCARD));
		rx_buf->flags |= EFX_RX_PKT_DISCARD;
	}

	netif_vdbg(efx, rx_status, efx->net_dev,
		   "RX queue %d received ids %x-%x len %d %s%s\n",
		   efx_rx_queue_index(rx_queue), index,
		   (index + n_frags - 1) & rx_queue->ptr_mask, len,
		   (rx_buf->flags & EFX_RX_PKT_CSUMMED) ? " [SUMMED]" : "",
		   (rx_buf->flags & EFX_RX_PKT_DISCARD) ? " [DISCARD]" : "");

	/* Discard packet, if instructed to do so.  Process the
	 * previous receive first.
	 */
	if (unlikely(rx_buf->flags & EFX_RX_PKT_DISCARD)) {
		efx_rx_flush_packet(channel);
		efx_discard_rx_packet(channel, rx_buf, n_frags);
		return;
	}

	if (n_frags == 1 && !(flags & EFX_RX_PKT_PREFIX_LEN))
		rx_buf->len = len;

	/* Release and/or sync the DMA mapping - assumes all RX buffers
	 * consumed in-order per RX queue.
	 */
	efx_sync_rx_buffer(efx, rx_buf, rx_buf->len);

	/* Prefetch nice and early so data will (hopefully) be in cache by
	 * the time we look at it.
	 */
	prefetch(efx_rx_buf_va(rx_buf));

	rx_buf->page_offset += efx->rx_prefix_size;
	rx_buf->len -= efx->rx_prefix_size;

	if (n_frags > 1) {
		/* Release/sync DMA mapping for additional fragments.
		 * Fix length for last fragment.
		 */
		unsigned int tail_frags = n_frags - 1;

		for (;;) {
			rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
			if (--tail_frags == 0)
				break;
			efx_sync_rx_buffer(efx, rx_buf, efx->rx_dma_len);
		}
		rx_buf->len = len - (n_frags - 1) * efx->rx_dma_len;
		efx_sync_rx_buffer(efx, rx_buf, rx_buf->len);
	}

	/* All fragments have been DMA-synced, so recycle pages. */
	rx_buf = efx_rx_buffer(rx_queue, index);
	efx_recycle_rx_pages(channel, rx_buf, n_frags);

	/* Pipeline receives so that we give time for packet headers to be
	 * prefetched into cache.
	 */
	efx_rx_flush_packet(channel);
	channel->rx_pkt_n_frags = n_frags;
	channel->rx_pkt_index = index;

	/* refill skb cache if needed */
	efx_refill_skb_cache_check(rx_queue);
}

static void efx_rx_deliver(struct efx_channel *channel, u8 *eh,
			   struct efx_rx_buffer *rx_buf,
			   unsigned int n_frags)
{
	struct sk_buff *skb;
	u16 hdr_len = min_t(u16, rx_buf->len, EFX_SKB_HEADERS);

	skb = efx_rx_mk_skb(channel, rx_buf, n_frags, eh, hdr_len);
	if (unlikely(skb == NULL)) {
		efx_free_rx_buffer(rx_buf);
		return;
	}
	skb_record_rx_queue(skb, channel->rx_queue.core_index);

	/* Set the SKB flags */
	skb_checksum_none_assert(skb);
	if (likely(rx_buf->flags & EFX_RX_PKT_CSUMMED))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	efx_rx_skb_attach_timestamp(channel, skb);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	/* This will mark the skb with the correct queue ID.
	 * It may also insert a hardware filter. We pass in
	 * the channel as a hint, since in the common case it
	 * should map to the correct queue. */
	if (channel->efx->netq_active)
		efx_netq_process_rx(channel->efx, channel, skb);
#endif

	if (channel->type->receive_skb)
#if defined(EFX_NOT_UPSTREAM)
		if (channel->type->receive_skb(channel, skb,
					       rx_buf->flags &
					       EFX_RX_BUF_VLAN_XTAG,
					       rx_buf->vlan_tci))
#else
		if (channel->type->receive_skb(channel, skb))
#endif
			return;

	/* Pass the packet up */
#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(skb, false, rx_buf->flags & EFX_RX_BUF_VLAN_XTAG,
			  rx_buf->vlan_tci);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG) {
		vlan_hwaccel_receive_skb(skb, channel->efx->vlan_group,
					 rx_buf->vlan_tci);
		return;
	}
#endif
	netif_receive_skb(skb);
}

/* Handle a received packet.  Second half: Touches packet payload. */
void __efx_rx_packet(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct efx_rx_buffer *rx_buf =
		efx_rx_buffer(&channel->rx_queue, channel->rx_pkt_index);
	u8 *eh = efx_rx_buf_va(rx_buf);

	/* Read length from the prefix if necessary.  This already
	 * excludes the length of the prefix itself.
	 */
	if (rx_buf->flags & EFX_RX_PKT_PREFIX_LEN)
		rx_buf->len = le16_to_cpup((__le16 *)
					   (eh + efx->rx_packet_len_offset));

	/* If we're in loopback test, then pass the packet directly to the
	 * loopback layer, and free the rx_buf here
	 */
	if (unlikely(efx->loopback_selftest)) {
		efx_loopback_rx_packet(efx, eh, rx_buf->len);
		efx_free_rx_buffer(rx_buf);
		goto out;
	}

	/* Driverlink clients can request that the packet be discarded */
	if (efx_dl_rx_packet(efx, channel->channel, eh, rx_buf->len)) {
		efx_free_rx_buffer(rx_buf);
		goto out;
	}

#if defined(EFX_NOT_UPSTREAM)
#if defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if ((rx_buf->flags & EFX_RX_PKT_VLAN) && efx->vlan_group) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)eh;

		rx_buf->vlan_tci = ntohs(veh->h_vlan_TCI);
		memmove(eh - efx->rx_prefix_size + VLAN_HLEN,
			eh - efx->rx_prefix_size,
			2 * ETH_ALEN + efx->rx_prefix_size);
		eh += VLAN_HLEN;
		rx_buf->page_offset += VLAN_HLEN;
		rx_buf->len -= VLAN_HLEN;
		rx_buf->flags |= EFX_RX_BUF_VLAN_XTAG;
	}
#else
	if ((rx_buf->flags & EFX_RX_PKT_VLAN)) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)eh;
		rx_buf->vlan_tci = ntohs(veh->h_vlan_TCI);
		rx_buf->flags |= EFX_RX_BUF_VLAN_XTAG;
	}
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	if (unlikely(!(efx->net_dev->features & NETIF_F_RXCSUM)))
#else
	if (unlikely(!efx->rx_checksum_enabled))
#endif
		rx_buf->flags &= ~EFX_RX_PKT_CSUMMED;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if ((rx_buf->flags & (EFX_RX_PKT_CSUMMED | EFX_RX_PKT_TCP)) ==
	    (EFX_RX_PKT_CSUMMED | EFX_RX_PKT_TCP) &&
	    efx_channel_ssr_enabled(channel) &&
	    likely(channel->rx_pkt_n_frags == 1))
		efx_ssr(channel, rx_buf, eh);
	else
		/* fall through */
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)
	if ((rx_buf->flags & EFX_RX_PKT_TCP) && !channel->type->receive_skb &&
	    !efx_channel_busy_polling(channel))
		efx_rx_packet_gro(channel, rx_buf, channel->rx_pkt_n_frags, eh);
	else
#endif
		efx_rx_deliver(channel, eh, rx_buf, channel->rx_pkt_n_frags);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_LAST_RX)
	efx->net_dev->last_rx = jiffies;
#endif
out:
	channel->rx_pkt_n_frags = 0;
}

int efx_probe_rx_queue(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int entries;
	int rc;

	/* Create the smallest power-of-two aligned ring */
	entries = max(roundup_pow_of_two(efx->rxq_entries), EFX_MIN_DMAQ_SIZE);
	EFX_BUG_ON_PARANOID(entries > EFX_MAX_DMAQ_SIZE);
	rx_queue->ptr_mask = entries - 1;

	netif_dbg(efx, probe, efx->net_dev,
		  "creating RX queue %d size %#x mask %#x\n",
		  efx_rx_queue_index(rx_queue), efx->rxq_entries,
		  rx_queue->ptr_mask);

	/* Allocate RX buffers */
	rx_queue->buffer = kcalloc(entries, sizeof(*rx_queue->buffer),
				   GFP_KERNEL);
	if (!rx_queue->buffer)
		return -ENOMEM;

	rc = efx_nic_probe_rx(rx_queue);
	if (rc) {
		kfree(rx_queue->buffer);
		rx_queue->buffer = NULL;
	}

	return rc;
}

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
void efx_init_rx_recycle_ring(struct efx_nic *efx,
			      struct efx_rx_queue *rx_queue)
{
	unsigned int bufs_in_recycle_ring, page_ring_size;

	/* Set the RX recycle ring size, if it hasn't already been set. */
	if (rx_recycle_ring_size == EFX_RECYCLE_RING_SIZE_UNSET) {
#ifdef CONFIG_PPC64
		bufs_in_recycle_ring = EFX_RECYCLE_RING_SIZE_IOMMU;
#else
		if (iommu_present(&pci_bus_type))
			bufs_in_recycle_ring = EFX_RECYCLE_RING_SIZE_IOMMU;
		else
			bufs_in_recycle_ring = EFX_RECYCLE_RING_SIZE_NOIOMMU;
#endif /* CONFIG_PPC64 */
	} else if (rx_recycle_ring_size > 0) {
		bufs_in_recycle_ring = rx_recycle_ring_size;
	} else {
		/* rx_recycle_ring = 0; do nothing */
		return;
	}

	page_ring_size = roundup_pow_of_two(bufs_in_recycle_ring /
					    efx->rx_bufs_per_page);
	rx_queue->page_ring = kcalloc(page_ring_size,
				      sizeof(*rx_queue->page_ring), GFP_KERNEL);
	rx_queue->page_ptr_mask = page_ring_size - 1;
}
#endif

void efx_init_rx_queue(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int max_fill, trigger, max_trigger;

	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "initialising RX queue %d\n", efx_rx_queue_index(rx_queue));

	/* Initialise ptr fields */
	rx_queue->added_count = 0;
	rx_queue->notified_count = 0;
	rx_queue->removed_count = 0;
	rx_queue->min_fill = -1U;
	rx_queue->failed_flush_count = 0;
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	efx_init_rx_recycle_ring(efx, rx_queue);

	rx_queue->page_remove = 0;
	rx_queue->page_add = rx_queue->page_ptr_mask + 1;
	rx_queue->page_recycle_count = 0;
	rx_queue->page_recycle_failed = 0;
	rx_queue->page_recycle_full = 0;
#endif

	/* Initialise limit fields */
	max_fill = efx->rxq_entries - EFX_RXD_HEAD_ROOM;
	max_trigger =
		max_fill - efx->rx_pages_per_batch * efx->rx_bufs_per_page;
	if (rx_refill_threshold != 0) {
		trigger = max_fill * min(rx_refill_threshold, 100U) / 100U;
		if (trigger > max_trigger)
			trigger = max_trigger;
	} else {
		trigger = max_trigger;
	}

	rx_queue->max_fill = max_fill;
	rx_queue->fast_fill_trigger = trigger;
	rx_queue->refill_enabled = true;

	/* Set up RX descriptor ring */
	efx_nic_init_rx(rx_queue);

	/* fill SKB cache */
	efx_refill_skb_cache(rx_queue);
}

void efx_fini_rx_queue(struct efx_rx_queue *rx_queue)
{
	int i;
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	struct efx_nic *efx = rx_queue->efx;
#endif
	struct efx_rx_buffer *rx_buf;

	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "shutting down RX queue %d\n", efx_rx_queue_index(rx_queue));

	del_timer_sync(&rx_queue->slow_fill);

	/* Release RX buffers from the current read ptr to the write ptr */
	if (rx_queue->buffer) {
		for (i = rx_queue->removed_count; i < rx_queue->added_count;
		     i++) {
			unsigned index = i & rx_queue->ptr_mask;
			rx_buf = efx_rx_buffer(rx_queue, index);
			efx_fini_rx_buffer(rx_queue, rx_buf);
		}
	}

	efx_fini_skb_cache(rx_queue);

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	if (rx_recycle_ring_size == 0)
		return;

	/* Unmap and release the pages in the recycle ring. Remove the ring. */
	for (i = 0; i <= rx_queue->page_ptr_mask; i++) {
		struct page *page = rx_queue->page_ring[i];
		struct efx_rx_page_state *state;

		if (page == NULL)
			continue;

		state = page_address(page);
		dma_unmap_page(&efx->pci_dev->dev, state->dma_addr,
			       PAGE_SIZE << efx->rx_buffer_order,
			       DMA_FROM_DEVICE);
		put_page(page);
	}
	kfree(rx_queue->page_ring);
	rx_queue->page_ring = NULL;
#endif
}

void efx_remove_rx_queue(struct efx_rx_queue *rx_queue)
{
	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "destroying RX queue %d\n", efx_rx_queue_index(rx_queue));

	efx_nic_remove_rx(rx_queue);

	kfree(rx_queue->buffer);
	rx_queue->buffer = NULL;
}


#if defined(EFX_NOT_UPSTREAM) && !defined(__VMKLNX__)
static int __init
#ifndef EFX_HAVE_NON_CONST_KERNEL_PARAM
efx_rx_alloc_method_set(const char *val, const struct kernel_param *kp)
#else
efx_rx_alloc_method_set(const char *val, struct kernel_param *kp)
#endif
{
	pr_warning("sfc: module parameter rx_alloc_method is obsolete\n");
	return 0;
}
#ifdef EFX_HAVE_KERNEL_PARAM_OPS
static const struct kernel_param_ops efx_rx_alloc_method_ops = {
	.set = efx_rx_alloc_method_set
};
module_param_cb(rx_alloc_method, &efx_rx_alloc_method_ops, NULL, 0);
#else
module_param_call(rx_alloc_method, efx_rx_alloc_method_set, NULL, NULL, 0);
#endif
#endif


module_param(rx_refill_threshold, uint, 0444);
MODULE_PARM_DESC(rx_refill_threshold,
		 "RX descriptor ring refill threshold (%)");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)

#define EFX_SSR_MAX_SKB_FRAGS	MAX_SKB_FRAGS

/* Size of the LRO hash table.  Must be a power of 2.  A larger table
 * means we can accelerate a larger number of streams.
 */
static unsigned lro_table_size = 128;
module_param(lro_table_size, uint, 0644);
MODULE_PARM_DESC(lro_table_size,
		 "Size of the LRO hash table.  Must be a power of 2");

/* Maximum length of a hash chain.  If chains get too long then the lookup
 * time increases and may exceed the benefit of LRO.
 */
static unsigned lro_chain_max = 20;
module_param(lro_chain_max, uint, 0644);
MODULE_PARM_DESC(lro_chain_max,
		 "Maximum length of chains in the LRO hash table");


/* Maximum time (in jiffies) that a connection can be idle before it's LRO
 * state is discarded.
 */
static unsigned lro_idle_jiffies = HZ / 10 + 1;	/* 100ms */
module_param(lro_idle_jiffies, uint, 0644);
MODULE_PARM_DESC(lro_idle_jiffies, "Time (in jiffies) after which an"
		 " idle connection's LRO state is discarded");


/* Number of packets with payload that must arrive in-order before a
 * connection is eligible for LRO.  The idea is we should avoid coalescing
 * segments when the sender is in slow-start because reducing the ACK rate
 * can damage performance.
 */
static int lro_slow_start_packets = 2000;
module_param(lro_slow_start_packets, uint, 0644);
MODULE_PARM_DESC(lro_slow_start_packets, "Number of packets that must "
		 "pass in-order before starting LRO.");


/* Number of packets with payload that must arrive in-order following loss
 * before a connection is eligible for LRO.  The idea is we should avoid
 * coalescing segments when the sender is recovering from loss, because
 * reducing the ACK rate can damage performance.
 */
static int lro_loss_packets = 20;
module_param(lro_loss_packets, uint, 0644);
MODULE_PARM_DESC(lro_loss_packets, "Number of packets that must "
		 "pass in-order following loss before restarting LRO.");


/* Flags for efx_ssr_conn::l2_id; must not collide with VLAN tag bits */
#define EFX_SSR_L2_ID_VLAN 0x10000
#define EFX_SSR_L2_ID_IPV6 0x20000
#define EFX_SSR_CONN_IS_VLAN_ENCAP(c) ((c)->l2_id & EFX_SSR_L2_ID_VLAN)
#define EFX_SSR_CONN_IS_TCPIPV4(c) (!((c)->l2_id & EFX_SSR_L2_ID_IPV6))
#define EFX_SSR_CONN_VLAN_TCI(c) ((c)->l2_id & 0xffff)

int efx_ssr_init(struct efx_channel *channel, struct efx_nic *efx)
{
	struct efx_ssr_state *st = &channel->ssr;
	unsigned i;

	st->conns_mask = lro_table_size - 1;
	if ((st->conns_mask + 1) & st->conns_mask) {
		netif_err(efx, drv, efx->net_dev,
			  "lro_table_size(=%u) must be a power of 2\n",
			  lro_table_size);
		return -EINVAL;
	}
	st->efx = efx;
	st->conns = kmalloc((st->conns_mask + 1)
			    * sizeof(st->conns[0]), GFP_KERNEL);
	if (st->conns == NULL)
		return -ENOMEM;
	st->conns_n = kmalloc((st->conns_mask + 1)
			      * sizeof(st->conns_n[0]), GFP_KERNEL);
	if (st->conns_n == NULL) {
		kfree(st->conns);
		st->conns = NULL;
		return -ENOMEM;
	}
	for (i = 0; i <= st->conns_mask; ++i) {
		INIT_LIST_HEAD(&st->conns[i]);
		st->conns_n[i] = 0;
	}
	INIT_LIST_HEAD(&st->active_conns);
	INIT_LIST_HEAD(&st->free_conns);
	return 0;
}

static inline bool efx_rx_buffer_is_full(struct efx_rx_buffer *rx_buf)
{
	return rx_buf->page != NULL;
}

static inline void efx_rx_buffer_set_empty(struct efx_rx_buffer *rx_buf)
{
	rx_buf->page = NULL;
}

/* Drop the given connection, and add it to the free list. */
static void efx_ssr_drop(struct efx_channel *channel, struct efx_ssr_conn *c)
{
	unsigned bucket;

	EFX_BUG_ON_PARANOID(c->skb);

	if (efx_rx_buffer_is_full(&c->next_buf)) {
		efx_rx_deliver(channel, c->next_eh, &c->next_buf, 1);
		list_del(&c->active_link);
	}

	bucket = c->conn_hash & channel->ssr.conns_mask;
	EFX_BUG_ON_PARANOID(channel->ssr.conns_n[bucket] <= 0);
	--channel->ssr.conns_n[bucket];
	list_del(&c->link);
	list_add(&c->link, &channel->ssr.free_conns);
}

void efx_ssr_fini(struct efx_channel *channel)
{
	struct efx_ssr_state *st = &channel->ssr;
	struct efx_ssr_conn *c;
	unsigned i;

	/* Return cleanly if efx_ssr_init() has not been called. */
	if (st->conns == NULL)
		return;

	EFX_BUG_ON_PARANOID(!list_empty(&st->active_conns));

	for (i = 0; i <= st->conns_mask; ++i) {
		while (!list_empty(&st->conns[i])) {
			c = list_entry(st->conns[i].prev,
				       struct efx_ssr_conn, link);
			efx_ssr_drop(channel, c);
		}
	}

	while (!list_empty(&st->free_conns)) {
		c = list_entry(st->free_conns.prev, struct efx_ssr_conn, link);
		list_del(&c->link);
		EFX_BUG_ON_PARANOID(c->skb);
		kfree(c);
	}

	kfree(st->conns_n);
	kfree(st->conns);
	st->conns = NULL;
}

static inline u8 *
efx_ssr_skb_iph(struct sk_buff *skb)
{
	return skb->data;
}

/* Calc IP checksum and deliver to the OS */
static void efx_ssr_deliver(struct efx_ssr_state *st, struct efx_ssr_conn *c)
{
	struct tcphdr *c_th;

	EFX_BUG_ON_PARANOID(!c->skb);

	++st->n_bursts;

	/* Finish off packet munging and recalculate IP header checksum. */
	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		iph->tot_len = htons(c->sum_len);
		iph->check = 0;
#if __GNUC__+0 == 4 && __GNUC_MINOR__+0 == 5 && __GNUC_PATCHLEVEL__+0 <= 1
		/* Compiler may wrongly eliminate the preceding assignment */
		barrier();
#endif
		iph->check = ip_fast_csum((u8 *) iph, iph->ihl);
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		iph->payload_len = htons(c->sum_len);
		c_th = (struct tcphdr *)(iph + 1);
	}

#ifdef EFX_NOT_UPSTREAM
	if (underreport_skb_truesize) {
		struct ethhdr *c_eh = eth_hdr(c->skb);
		int len = c->skb->len + ((u8 *)c->skb->data - (u8 *)c_eh);
		c->skb->truesize = len + sizeof(struct sk_buff);
	} else
#endif
	c->skb->truesize += c->skb->data_len;

	c->skb->ip_summed = CHECKSUM_UNNECESSARY;

	c_th->window = c->th_last->window;
	c_th->ack_seq = c->th_last->ack_seq;
	if (c_th->doff == c->th_last->doff) {
		/* Copy TCP options (take care to avoid going negative). */
		int optlen = ((c_th->doff - 5) & 0xf) << 2u;
		memcpy(c_th + 1, c->th_last + 1, optlen);
	}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	/* This will mark the skb with the correct queue ID.
	 * It may also insert a hardware filter. We pass in
	 * the channel as a hint, since in the common case it
	 * should map to the correct queue. */
	if (st->efx->netq_active)
		efx_netq_process_rx(st->efx,
			container_of(st, struct efx_channel, ssr), c->skb);
#endif

#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(c->skb, false, EFX_SSR_CONN_IS_VLAN_ENCAP(c),
			  EFX_SSR_CONN_VLAN_TCI(c));
#endif
#ifdef EFX_USE_FAKE_VLAN_RX_ACCEL
	if (EFX_SSR_CONN_IS_VLAN_ENCAP(c))
		vlan_hwaccel_receive_skb(c->skb, st->efx->vlan_group,
					 EFX_SSR_CONN_VLAN_TCI(c));
	else
#endif
		netif_receive_skb(c->skb);

	c->skb = NULL;
	c->delivered = 1;
}

/* Stop tracking connections that have gone idle in order to keep hash
 * chains short.
 */
static void efx_ssr_purge_idle(struct efx_channel *channel, unsigned now)
{
	struct efx_ssr_conn *c;
	unsigned i;

	EFX_BUG_ON_PARANOID(!list_empty(&channel->ssr.active_conns));

	channel->ssr.last_purge_jiffies = now;
	for (i = 0; i <= channel->ssr.conns_mask; ++i) {
		if (list_empty(&channel->ssr.conns[i]))
			continue;

		c = list_entry(channel->ssr.conns[i].prev,
			       struct efx_ssr_conn, link);
		if (now - c->last_pkt_jiffies > lro_idle_jiffies) {
			++channel->ssr.n_drop_idle;
			efx_ssr_drop(channel, c);
		}
	}
}

/* Construct an skb Push held skbs down into network stack.
 * Only called when active list is non-empty.
 */
static int
efx_ssr_merge(struct efx_ssr_state *st, struct efx_ssr_conn *c,
	      struct tcphdr *th, int data_length)
{
	struct tcphdr *c_th;

	/* Increase lengths appropriately */
	c->skb->len += data_length;
	c->skb->data_len += data_length;

#ifdef EFX_USE_GSO_SIZE_FOR_MSS
	if (data_length > skb_shinfo(c->skb)->gso_size)
		skb_shinfo(c->skb)->gso_size = data_length;
#endif

	/* Update the connection state flags */
	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		c_th = (struct tcphdr *)(iph + 1);
	}
	c->sum_len += data_length;
	c_th->psh |= th->psh;
	c->th_last = th;
	++st->n_merges;

#ifndef EFX_USE_GSO_SIZE_FOR_MSS
	/* This kernel version does not understand LRO, and uses the max
	 * frame received to update rcv_mss.  If we're going above 1/4 of
	 * max window size without scaling pass the packet up.  This is
	 * slightly conservative, but close enough, and avoids rcv_mss
	 * growing too large.  Also stop merging if we got a PSH flag
	 * because if the sender is pushing messages a few times larger
	 * than the real MSS and we let rcv_mss grow larger than that
	 * message size we will end up delaying ACKs that the sender
	 * is waiting for.
	 */
	return (c->skb->len > 16384 || th->psh);
#else
	/* Pass packet up now if another segment could overflow the IP
	 * length.
	 */
	return (c->skb->len > 65536 - 9200);
#endif
}

static void
efx_ssr_start(struct efx_ssr_state *st, struct efx_ssr_conn *c,
	      struct tcphdr *th, int data_length)
{
#ifdef EFX_USE_GSO_SIZE_FOR_MSS
	skb_shinfo(c->skb)->gso_size = data_length;
#endif

	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		c->sum_len = ntohs(iph->tot_len);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		c->sum_len = ntohs(iph->payload_len);
	}
}

static int
efx_ssr_merge_page(struct efx_ssr_state *st, struct efx_ssr_conn *c,
		   struct tcphdr *th, int hdr_length, int data_length)
{
	struct efx_rx_buffer *rx_buf = &c->next_buf;
	struct efx_channel *channel;
	char *eh = c->next_eh;

	if (likely(c->skb)) {
		skb_fill_page_desc(c->skb, skb_shinfo(c->skb)->nr_frags,
				   rx_buf->page,
				   rx_buf->page_offset + hdr_length,
				   data_length);
		rx_buf->page = NULL;

		if (efx_ssr_merge(st, c, th, data_length) ||
		    (skb_shinfo(c->skb)->nr_frags == EFX_SSR_MAX_SKB_FRAGS))
			efx_ssr_deliver(st, c);

		return 1;
	} else {
		channel = container_of(st, struct efx_channel, ssr);

		c->skb = efx_rx_mk_skb(channel, rx_buf, 1, eh, hdr_length);
		if (unlikely(c->skb == NULL))
			return 0;

#ifdef EFX_HAVE_RXHASH_SUPPORT
		skb_set_hash(c->skb, c->conn_hash, PKT_HASH_TYPE_L3);
#endif
		if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
			struct iphdr *iph =
				(struct iphdr *)efx_ssr_skb_iph(c->skb);
			c->th_last = (struct tcphdr *)(iph + 1);
		} else {
			struct ipv6hdr *iph =
				(struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
			c->th_last = (struct tcphdr *)(iph + 1);
		}
		efx_ssr_start(st, c, th, data_length);

		return 1;
	}
}

/* Try to merge or otherwise hold or deliver (as appropriate) the
 * packet buffered for this connection (c->next_buf).  Return a flag
 * indicating whether the connection is still active for SSR purposes.
 */
static bool
efx_ssr_try_merge(struct efx_channel *channel, struct efx_ssr_conn *c)
{
	struct efx_rx_buffer *rx_buf = &c->next_buf;
	u8 *eh = c->next_eh;
	int data_length, hdr_length, dont_merge;
	unsigned th_seq, pkt_length;
	struct tcphdr *th;
	unsigned now;

	now = jiffies;
	if (now - c->last_pkt_jiffies > lro_idle_jiffies) {
		++channel->ssr.n_drop_idle;
		if (c->skb)
			efx_ssr_deliver(&channel->ssr, c);
		efx_ssr_drop(channel, c);
		return false;
	}
	c->last_pkt_jiffies = jiffies;

	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = c->next_iph;
		th = (struct tcphdr *)(iph + 1);
		pkt_length = ntohs(iph->tot_len) + (u8 *) iph - (u8 *) eh;
	} else {
		struct ipv6hdr *iph = c->next_iph;
		th = (struct tcphdr *)(iph + 1);
		pkt_length = ntohs(iph->payload_len) + (u8 *) th - (u8 *) eh;
	}

	hdr_length = (u8 *) th + th->doff * 4 - (u8 *) eh;
	rx_buf->len = min_t(u16, pkt_length, rx_buf->len);
	data_length = rx_buf->len - hdr_length;
	th_seq = ntohl(th->seq);
	dont_merge = ((data_length <= 0)
		      | th->urg | th->syn | th->rst | th->fin);

	/* Check for options other than aligned timestamp. */
	if (th->doff != 5) {
		const __be32 *opt_ptr = (const __be32 *) (th + 1);
		if (th->doff == 8 &&
		    opt_ptr[0] == htonl((TCPOPT_NOP << 24) |
					(TCPOPT_NOP << 16) |
					(TCPOPT_TIMESTAMP << 8) |
					TCPOLEN_TIMESTAMP)) {
			/* timestamp option -- okay */
		} else {
			dont_merge = 1;
		}
	}

	if (unlikely(th_seq - c->next_seq)) {
		/* Out-of-order, so start counting again. */
		if (c->skb)
			efx_ssr_deliver(&channel->ssr, c);
		c->n_in_order_pkts -= lro_loss_packets;
		c->next_seq = th_seq + data_length;
		++channel->ssr.n_misorder;
		goto deliver_buf_out;
	}
	c->next_seq = th_seq + data_length;

	if (c->n_in_order_pkts < lro_slow_start_packets) {
		/* May be in slow-start, so don't merge. */
		++channel->ssr.n_slow_start;
		++c->n_in_order_pkts;
		goto deliver_buf_out;
	}

	if (unlikely(dont_merge)) {
		if (c->skb)
			efx_ssr_deliver(&channel->ssr, c);
		if (th->fin || th->rst) {
			++channel->ssr.n_drop_closed;
			efx_ssr_drop(channel, c);
			return false;
		}
		goto deliver_buf_out;
	}

	if (efx_ssr_merge_page(&channel->ssr, c, th,
			       hdr_length, data_length) == 0)
		goto deliver_buf_out;

	channel->irq_mod_score += 2;
	return true;

 deliver_buf_out:
	efx_rx_deliver(channel, eh, rx_buf, 1);
	return true;
}

static void efx_ssr_new_conn(struct efx_ssr_state *st, u32 conn_hash,
			     u32 l2_id, struct tcphdr *th)
{
	unsigned bucket = conn_hash & st->conns_mask;
	struct efx_ssr_conn *c;

	if (st->conns_n[bucket] >= lro_chain_max) {
		++st->n_too_many;
		return;
	}

	if (!list_empty(&st->free_conns)) {
		c = list_entry(st->free_conns.next, struct efx_ssr_conn, link);
		list_del(&c->link);
	} else {
		c = kmalloc(sizeof(*c), GFP_ATOMIC);
		if (c == NULL)
			return;
		c->skb = NULL;
		efx_rx_buffer_set_empty(&c->next_buf);
	}

	/* Create the connection tracking data */
	++st->conns_n[bucket];
	list_add(&c->link, &st->conns[bucket]);
	c->l2_id = l2_id;
	c->conn_hash = conn_hash;
	c->source = th->source;
	c->dest = th->dest;
	c->n_in_order_pkts = 0;
	c->last_pkt_jiffies = jiffies;
	c->delivered = 0;
	++st->n_new_stream;
	/* NB. We don't initialise c->next_seq, and it doesn't matter what
	 * value it has.  Most likely the next packet received for this
	 * connection will not match -- no harm done.
	 */
}

/* Process SKB and decide whether to dispatch it to the stack now or
 * later.
 */
void efx_ssr(struct efx_channel *channel, struct efx_rx_buffer *rx_buf,
	     u8 *rx_data)
{
	struct efx_nic *efx = channel->efx;
	struct ethhdr *eh = (struct ethhdr *)rx_data;
	struct efx_ssr_conn *c;
	u32 l2_id = 0;
	void *nh = eh + 1;
	struct tcphdr *th;
	u32 conn_hash;
	unsigned bucket;

	/* Get the hardware hash if available */
#ifdef EFX_HAVE_RXHASH_SUPPORT
	if (efx->net_dev->features & NETIF_F_RXHASH)
#else
	if (efx->rx_prefix_size)
#endif
		conn_hash = efx_rx_buf_hash(efx, rx_data);
	else
		conn_hash = 0;

#ifdef EFX_USE_FAKE_VLAN_RX_ACCEL
	if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		l2_id = rx_buf->vlan_tci | EFX_SSR_L2_ID_VLAN;
#endif

	/* Check whether this is a suitable packet (unfragmented
	 * TCP/IPv4 or TCP/IPv6).  If so, find the TCP header and
	 * length, and compute a hash if necessary.  If not, return.
	 */
	if (eh->h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = nh;
		if ((iph->protocol - IPPROTO_TCP) |
		    (iph->ihl - (sizeof(*iph) >> 2u)) |
		    (__force u16)(iph->frag_off & htons(IP_MF | IP_OFFSET)))
			goto deliver_now;
		th = (struct tcphdr *)(iph + 1);
		if (conn_hash == 0)
			conn_hash = ((__force u32)ip_fast_csum(&iph->saddr, 2) ^
				     (__force u32)(th->source ^ th->dest));
	} else if (eh->h_proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph = nh;
		if (iph->nexthdr != NEXTHDR_TCP)
			goto deliver_now;
		l2_id |= EFX_SSR_L2_ID_IPV6;
		th = (struct tcphdr *)(iph + 1);
		if (conn_hash == 0)
			conn_hash = ((__force u32)ip_fast_csum(&iph->saddr, 8) ^
				     (__force u32)(th->source ^ th->dest));
	} else {
		goto deliver_now;
	}

	bucket = conn_hash & channel->ssr.conns_mask;

	list_for_each_entry(c, &channel->ssr.conns[bucket], link) {
		if ((c->l2_id - l2_id) | (c->conn_hash - conn_hash))
			continue;
		if ((c->source ^ th->source) | (c->dest ^ th->dest))
			continue;
		if (c->skb) {
			if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
				struct iphdr *c_iph, *iph = nh;
				c_iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
				if ((c_iph->saddr ^ iph->saddr) |
				    (c_iph->daddr ^ iph->daddr))
					continue;
			} else {
				struct ipv6hdr *c_iph, *iph = nh;
				c_iph = (struct ipv6hdr *)
					efx_ssr_skb_iph(c->skb);
				if (ipv6_addr_cmp(&c_iph->saddr, &iph->saddr) |
				    ipv6_addr_cmp(&c_iph->daddr, &iph->daddr))
					continue;
			}
		}

		/* Re-insert at head of list to reduce lookup time. */
		list_del(&c->link);
		list_add(&c->link, &channel->ssr.conns[bucket]);

		if (efx_rx_buffer_is_full(&c->next_buf)) {
			if (!efx_ssr_try_merge(channel, c))
				goto deliver_now;
		} else {
			list_add(&c->active_link, &channel->ssr.active_conns);
		}
		c->next_buf = *rx_buf;
		c->next_eh = rx_data;
		efx_rx_buffer_set_empty(rx_buf);
		c->next_iph = nh;
		return;
	}

	efx_ssr_new_conn(&channel->ssr, conn_hash, l2_id, th);
 deliver_now:
	efx_rx_deliver(channel, rx_data, rx_buf, 1);
}

/* Push held skbs down into network stack.
 * Only called when active list is non-empty.
 */
void __efx_ssr_end_of_burst(struct efx_channel *channel)
{
	struct efx_ssr_state *st = &channel->ssr;
	struct efx_ssr_conn *c;
	unsigned j;

	EFX_BUG_ON_PARANOID(list_empty(&st->active_conns));

	do {
		c = list_entry(st->active_conns.next, struct efx_ssr_conn,
			       active_link);
		if (!c->delivered && c->skb)
			efx_ssr_deliver(st, c);
		if (efx_ssr_try_merge(channel, c)) {
			if (c->skb)
				efx_ssr_deliver(st, c);
			list_del(&c->active_link);
		}
		c->delivered = 0;
	} while (!list_empty(&st->active_conns));

	j = jiffies;
	if (unlikely(j != st->last_purge_jiffies))
		efx_ssr_purge_idle(channel, j);
}


#endif /* EFX_USE_SFC_LRO */

#ifdef CONFIG_RFS_ACCEL

int efx_filter_rfs(struct net_device *net_dev, const struct sk_buff *skb,
		   u16 rxq_index, u32 flow_id)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;
	struct efx_filter_spec spec;
	/* 60 octets is the maximum length of an IPv4 header (all IPv6 headers
	 * are 40 octets), and we pull 4 more to get the port numbers
	 */
	#define EFX_RFS_HEADER_LENGTH	(sizeof(struct vlan_hdr) + 60 + 4)
	unsigned char header[EFX_RFS_HEADER_LENGTH];
	int headlen = min_t(int, EFX_RFS_HEADER_LENGTH, skb->len);
	#undef EFX_RFS_HEADER_LENGTH
	void *hptr;
	const __be16 *ports;
	__be16 ether_type;
	int nhoff;
	int rc;

	if (flow_id == RPS_FLOW_ID_INVALID)
		return -EINVAL;

	hptr = skb_header_pointer(skb, 0, headlen, header);
	if (!hptr)
		return -EINVAL;

	if (skb->protocol == htons(ETH_P_8021Q)) {
		const struct vlan_hdr *vh = hptr;

		/* We can't filter on the IP 5-tuple and the vlan
		 * together, so just strip the vlan header and filter
		 * on the IP part.
		 */
		if (headlen < sizeof(*vh))
			return -EINVAL;
		ether_type = vh->h_vlan_encapsulated_proto;
		nhoff = sizeof(struct vlan_hdr);
	} else {
		ether_type = skb->protocol;
		nhoff = 0;
	}

	if (ether_type != htons(ETH_P_IP) && ether_type != htons(ETH_P_IPV6))
		return -EPROTONOSUPPORT;

	efx_filter_init_rx(&spec, EFX_FILTER_PRI_HINT,
			   efx->rx_scatter ? EFX_FILTER_FLAG_RX_SCATTER : 0,
			   rxq_index);
	spec.match_flags = EFX_FILTER_MATCH_FLAGS_RFS;
	spec.ether_type = ether_type;

	if (ether_type == htons(ETH_P_IP)) {
		const struct iphdr *ip = hptr + nhoff;

		if (headlen < nhoff + sizeof(*ip))
			return -EINVAL;
		if (ip_is_fragment(ip))
			return -EPROTONOSUPPORT;
		spec.ip_proto = ip->protocol;
		spec.rem_host[0] = ip->saddr;
		spec.loc_host[0] = ip->daddr;
		if (headlen < nhoff + 4 * ip->ihl + 4)
			return -EINVAL;
		ports = (const __be16 *)(hptr + nhoff + 4 * ip->ihl);
	} else {
		const struct ipv6hdr *ip6 = (hptr + nhoff);

		if (headlen < nhoff + sizeof(*ip6) + 4)
			return -EINVAL;
		spec.ip_proto = ip6->nexthdr;
		memcpy(spec.rem_host, &ip6->saddr, sizeof(ip6->saddr));
		memcpy(spec.loc_host, &ip6->daddr, sizeof(ip6->daddr));
		ports = (const __be16 *)(ip6 + 1);
	}

	spec.rem_port = ports[0];
	spec.loc_port = ports[1];

	rc = efx->type->filter_async_insert(efx, &spec);
	if (rc < 0)
		return rc;

	/* Remember this so we can check whether to expire the filter later */
	efx->rps_flow_id[rc] = flow_id;
	channel = efx_get_channel(efx, skb_get_rx_queue(skb));
	++channel->rfs_filters_added;

	if (ether_type == htons(ETH_P_IP))
		netif_info(efx, rx_status, efx->net_dev,
			   "steering %s %pI4:%u:%pI4:%u to queue %u [flow %u filter %d]\n",
			   (spec.ip_proto == IPPROTO_TCP) ? "TCP" : "UDP",
			   spec.rem_host, ntohs(ports[0]), spec.loc_host,
			   ntohs(ports[1]), rxq_index, flow_id, rc);
	else
		netif_info(efx, rx_status, efx->net_dev,
			   "steering %s [%pI6]:%u:[%pI6]:%u to queue %u [flow %u filter %d]\n",
			   (spec.ip_proto == IPPROTO_TCP) ? "TCP" : "UDP",
			   spec.rem_host, ntohs(ports[0]), spec.loc_host,
			   ntohs(ports[1]), rxq_index, flow_id, rc);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	/* since we have real ARFS, disable SARFS */
	efx_sarfs_disable(efx);
#endif

	return rc;
}

bool __efx_filter_rfs_expire(struct efx_nic *efx, unsigned int quota)
{
	bool (*expire_one)(struct efx_nic *efx, u32 flow_id, unsigned int index);
	unsigned int index, size;
	u32 flow_id;

	if (!spin_trylock_bh(&efx->filter_lock))
		return false;

	expire_one = efx->type->filter_rfs_expire_one;
	index = efx->rps_expire_index;
	size = efx->type->max_rx_ip_filters;
	while (quota--) {
		flow_id = efx->rps_flow_id[index];

		if (flow_id != RPS_FLOW_ID_INVALID &&
		    expire_one(efx, flow_id, index)) {
			netif_info(efx, rx_status, efx->net_dev,
				   "expired filter %d [flow %u]\n",
				   index, flow_id);
			efx->rps_flow_id[index] = RPS_FLOW_ID_INVALID;
		}
		if (++index == size)
			index = 0;
	}
	efx->rps_expire_index = index;

	spin_unlock_bh(&efx->filter_lock);
	return true;
}

#endif /* CONFIG_RFS_ACCEL */

/**
 * efx_filter_is_mc_recipient - test whether spec is a multicast recipient
 * @spec: Specification to test
 *
 * Return: %true if the specification is a non-drop RX filter that
 * matches a local MAC address I/G bit value of 1 or matches a local
 * IPv4 or IPv6 address value in the respective multicast address
 * range.  Otherwise %false.
 */
bool efx_filter_is_mc_recipient(const struct efx_filter_spec *spec)
{
	if (!(spec->flags & EFX_FILTER_FLAG_RX) ||
	    spec->dmaq_id == EFX_FILTER_RX_DMAQ_ID_DROP)
		return false;

	if (spec->match_flags &
	    (EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG) &&
	    is_multicast_ether_addr(spec->loc_mac))
		return true;

	if ((spec->match_flags &
	     (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) ==
	    (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) {
		if (spec->ether_type == htons(ETH_P_IP) &&
		    ipv4_is_multicast(spec->loc_host[0]))
			return true;
		if (spec->ether_type == htons(ETH_P_IPV6) &&
		    ((const u8 *)spec->loc_host)[0] == 0xff)
			return true;
	}

	return false;
}
