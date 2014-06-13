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

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/prefetch.h>
#include <linux/moduleparam.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#ifdef EFX_NOT_UPSTREAM
#include <linux/ipv6.h>
#include <net/ipv6.h>
#endif
#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "selftest.h"
#include "workarounds.h"
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
#include "efx_netq.h"
#endif

/* Number of RX descriptors pushed at once. */
#define EFX_RX_BATCH  8

/* Maximum size of a buffer sharing a page */
#define EFX_RX_HALF_PAGE ((PAGE_SIZE >> 1) - sizeof(struct efx_rx_page_state))

/* Size of buffer allocated for skb header area. */
#define EFX_SKB_HEADERS  64u

/*
 * rx_alloc_method - RX buffer allocation method
 *
 * This driver supports two methods for allocating and using RX buffers:
 * each RX buffer may be backed by an skb or by an order-n page.
 *
 * When GRO is in use then the second method has a lower overhead,
 * since we don't have to allocate then free skbs on reassembled frames.
 *
 * Values:
 *   - RX_ALLOC_METHOD_AUTO = 0
 *   - RX_ALLOC_METHOD_SKB  = 1
 *   - RX_ALLOC_METHOD_PAGE = 2
 *
 * The heuristic for %RX_ALLOC_METHOD_AUTO is a simple hysteresis count
 * controlled by the parameters below.
 *
 *   - Since pushing and popping descriptors are separated by the rx_queue
 *     size, so the watermarks should be ~rxd_size.
 *   - The performance win by using page-based allocation for GRO is less
 *     than the performance hit of using page-based allocation of non-GRO,
 *     so the watermarks should reflect this.
 *
 * Per channel we maintain a single variable, updated by each channel:
 *
 *   rx_alloc_level += (gro_performed ? RX_ALLOC_FACTOR_GRO :
 *                      RX_ALLOC_FACTOR_SKB)
 * Per NAPI poll interval, we constrain rx_alloc_level to 0..MAX (which
 * limits the hysteresis), and update the allocation strategy:
 *
 *   rx_alloc_method = (rx_alloc_level > RX_ALLOC_LEVEL_GRO ?
 *                      RX_ALLOC_METHOD_PAGE : RX_ALLOC_METHOD_SKB)
 */
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_USE_SFC_LRO) || defined(EFX_HAVE_DEV_DISABLE_LRO)
static int rx_alloc_method = RX_ALLOC_METHOD_AUTO;
#else
/* The above comment applies equally to SFC-LRO aka SSR. */
/* LRO using SKB chaining will cause a BUG() if bridging is used. This was
 * fixed by GRO, and worked around by dev_disable_lro(). Change the default
 * to avoid the BUG(), but allow the user to override this.
 */
static int rx_alloc_method = RX_ALLOC_METHOD_PAGE;
#endif

#define RX_ALLOC_LEVEL_GRO 0x2000
#define RX_ALLOC_LEVEL_MAX 0x3000
#define RX_ALLOC_FACTOR_GRO 1
#define RX_ALLOC_FACTOR_SKB (-2)

/* This is the percentage fill level below which new RX descriptors
 * will be added to the RX descriptor ring.
 */
static unsigned int rx_refill_threshold;

/*
 * RX maximum head room required.
 *
 * This must be at least 1 to prevent overflow and at least 2 to allow
 * pipelined receives.
 */
#define EFX_RXD_HEAD_ROOM 2

/* Offset of ethernet header within page */
static inline unsigned int efx_rx_buf_offset(struct efx_nic *efx,
					     struct efx_rx_buffer *buf)
{
	/* Offset is always within one page, so we don't need to consider
	 * the page order.
	 */
	return ((unsigned int) buf->dma_addr & (PAGE_SIZE - 1)) +
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
		((buf->flags & EFX_RX_BUF_VLAN_XTAG) ? VLAN_HLEN : 0) +
#endif
		efx->rx_buffer_hash_size;
}
static inline unsigned int efx_rx_buf_size(struct efx_nic *efx)
{
	return PAGE_SIZE << efx->rx_buffer_order;
}

/* Find the Ethernet header in an efx_rx_buffer.  This must not be
 * called after any other operation that moves the skb's data pointer.
 */
static u8 *efx_rx_buf_eh(struct efx_nic *efx, struct efx_rx_buffer *buf)
{
	if (buf->flags & EFX_RX_BUF_PAGE)
		return page_address(buf->u.page) + efx_rx_buf_offset(efx, buf);
	else
		return (u8 *)buf->u.skb->data + efx->rx_buffer_hash_size;
}

static inline u32 efx_rx_buf_hash(const u8 *eh)
{
	/* The ethernet header is always directly after any hash. */
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) || NET_IP_ALIGN % 4 == 0
	return __le32_to_cpup((const __le32 *)(eh - 4));
#else
	const u8 *data = eh - 4;
	return (u32)data[0]	  |
	       (u32)data[1] << 8  |
	       (u32)data[2] << 16 |
	       (u32)data[3] << 24;
#endif
}

/**
 * efx_init_rx_buffers_skb - create EFX_RX_BATCH skb-based RX buffers
 *
 * @rx_queue:		Efx RX queue
 *
 * This allocates EFX_RX_BATCH skbs, maps them for DMA, and populates a
 * struct efx_rx_buffer for each one. Return a negative error code or 0
 * on success. May fail having only inserted fewer than EFX_RX_BATCH
 * buffers.
 */
static int efx_init_rx_buffers_skb(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	struct net_device *net_dev = efx->net_dev;
	struct efx_rx_buffer *rx_buf;
	struct sk_buff *skb;
	int skb_len = efx->rx_buffer_len;
	unsigned index, count;

	for (count = 0; count < EFX_RX_BATCH; ++count) {
		index = rx_queue->added_count & rx_queue->ptr_mask;
		rx_buf = efx_rx_buffer(rx_queue, index);

		rx_buf->u.skb = skb = netdev_alloc_skb(net_dev, skb_len);
		if (unlikely(!skb))
			return -ENOMEM;

		/* Adjust the SKB for padding and checksum */
		skb_reserve(skb, NET_IP_ALIGN);
		rx_buf->len = skb_len - NET_IP_ALIGN;
		rx_buf->flags = 0;

		rx_buf->dma_addr = dma_map_single(&efx->pci_dev->dev,
						  skb->data, rx_buf->len,
						  DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(&efx->pci_dev->dev,
					       rx_buf->dma_addr))) {
			dev_kfree_skb_any(skb);
			rx_buf->u.skb = NULL;
			return -EIO;
		}

		++rx_queue->added_count;
		++rx_queue->alloc_skb_count;
	}

	return 0;
}

/**
 * efx_init_rx_buffers_page - create EFX_RX_BATCH page-based RX buffers
 *
 * @rx_queue:		Efx RX queue
 *
 * This allocates memory for EFX_RX_BATCH receive buffers, maps them for DMA,
 * and populates struct efx_rx_buffers for each one. Return a negative error
 * code or 0 on success. If a single page can be split between two buffers,
 * then the page will either be inserted fully, or not at at all.
 */
static int efx_init_rx_buffers_page(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_buffer *rx_buf;
	struct page *page;
	struct efx_rx_page_state *state;
	dma_addr_t dma_addr;
	unsigned index, count;

	/* We can split a page between two buffers */
	BUILD_BUG_ON(EFX_RX_BATCH & 1);

	for (count = 0; count < EFX_RX_BATCH; ++count) {
		page = alloc_pages(__GFP_COLD | __GFP_COMP | GFP_ATOMIC,
				   efx->rx_buffer_order);
		if (unlikely(page == NULL))
			return -ENOMEM;
		dma_addr = dma_map_page(&efx->pci_dev->dev, page, 0,
					efx_rx_buf_size(efx),
					DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(&efx->pci_dev->dev, dma_addr))) {
			__free_pages(page, efx->rx_buffer_order);
			return -EIO;
		}
		state = page_address(page);
		state->refcnt = 0;
		state->dma_addr = dma_addr;

		dma_addr += sizeof(struct efx_rx_page_state);

	split:
		index = rx_queue->added_count & rx_queue->ptr_mask;
		rx_buf = efx_rx_buffer(rx_queue, index);
		rx_buf->dma_addr = dma_addr + EFX_PAGE_IP_ALIGN;
		rx_buf->u.page = page;
		rx_buf->len = efx->rx_buffer_len - EFX_PAGE_IP_ALIGN;
		rx_buf->flags = EFX_RX_BUF_PAGE;
		++rx_queue->added_count;
		++rx_queue->alloc_page_count;
		++state->refcnt;

		if ((~count & 1) && (efx->rx_buffer_len <= EFX_RX_HALF_PAGE)) {
			/* Use the second half of the page */
			get_page(page);
			dma_addr += (PAGE_SIZE >> 1);
			++count;
			goto split;
		}
	}

	return 0;
}

static void efx_unmap_rx_buffer(struct efx_nic *efx,
				struct efx_rx_buffer *rx_buf)
{
	if ((rx_buf->flags & EFX_RX_BUF_PAGE) && rx_buf->u.page) {
		struct efx_rx_page_state *state;

		state = page_address(rx_buf->u.page);
		if (--state->refcnt == 0) {
			dma_unmap_page(&efx->pci_dev->dev,
				       state->dma_addr,
				       efx_rx_buf_size(efx),
				       DMA_FROM_DEVICE);
		}
	} else if (!(rx_buf->flags & EFX_RX_BUF_PAGE) && rx_buf->u.skb) {
		dma_unmap_single(&efx->pci_dev->dev, rx_buf->dma_addr,
				 rx_buf->len, DMA_FROM_DEVICE);
	}
}

static void efx_free_rx_buffer(struct efx_nic *efx,
			       struct efx_rx_buffer *rx_buf)
{
	if ((rx_buf->flags & EFX_RX_BUF_PAGE) && rx_buf->u.page) {
		__free_pages(rx_buf->u.page, efx->rx_buffer_order);
		rx_buf->u.page = NULL;
	} else if (!(rx_buf->flags & EFX_RX_BUF_PAGE) && rx_buf->u.skb) {
		dev_kfree_skb_any(rx_buf->u.skb);
		rx_buf->u.skb = NULL;
	}
}

static void efx_fini_rx_buffer(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
	efx_unmap_rx_buffer(rx_queue->efx, rx_buf);
	efx_free_rx_buffer(rx_queue->efx, rx_buf);
}

/* Attempt to resurrect the other receive buffer that used to share this page,
 * which had previously been passed up to the kernel and freed. */
static void efx_resurrect_rx_buffer(struct efx_rx_queue *rx_queue,
				    struct efx_rx_buffer *rx_buf)
{
	struct efx_rx_page_state *state = page_address(rx_buf->u.page);
	struct efx_rx_buffer *new_buf;
	unsigned fill_level, index;

	/* +1 because efx_rx_packet() incremented removed_count. +1 because
	 * we'd like to insert an additional descriptor whilst leaving
	 * EFX_RXD_HEAD_ROOM for the non-recycle path */
	fill_level = (rx_queue->added_count - rx_queue->removed_count + 2);
	if (unlikely(fill_level > rx_queue->max_fill)) {
		/* We could place "state" on a list, and drain the list in
		 * efx_fast_push_rx_descriptors(). For now, this will do. */
		++rx_queue->resurrect_failed_count;
		return;
	}

	++state->refcnt;
	get_page(rx_buf->u.page);

	index = rx_queue->added_count & rx_queue->ptr_mask;
	new_buf = efx_rx_buffer(rx_queue, index);
	new_buf->dma_addr = rx_buf->dma_addr ^ (PAGE_SIZE >> 1);
	new_buf->u.page = rx_buf->u.page;
	new_buf->len = rx_buf->len;
	new_buf->flags = EFX_RX_BUF_PAGE;
	++rx_queue->added_count;
	++rx_queue->recycle_count;
	++rx_queue->resurrect_count;
}

/* Recycle the given rx buffer directly back into the rx_queue. There is
 * always room to add this buffer, because we've just popped a buffer. */
static void efx_recycle_rx_buffer(struct efx_channel *channel,
				  struct efx_rx_buffer *rx_buf)
{
	struct efx_nic *efx = channel->efx;
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	struct efx_rx_buffer *new_buf;
	unsigned index;

	rx_buf->flags &= EFX_RX_BUF_PAGE;

	if ((rx_buf->flags & EFX_RX_BUF_PAGE) &&
	    efx->rx_buffer_len <= EFX_RX_HALF_PAGE &&
	    page_count(rx_buf->u.page) == 1)
		efx_resurrect_rx_buffer(rx_queue, rx_buf);

	index = rx_queue->added_count & rx_queue->ptr_mask;
	new_buf = efx_rx_buffer(rx_queue, index);

	memcpy(new_buf, rx_buf, sizeof(*new_buf));
	rx_buf->u.page = NULL;
	++rx_queue->added_count;
	++rx_queue->recycle_count;
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
void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	unsigned fill_level;
	int space, rc = 0;

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

	space = rx_queue->max_fill - fill_level;
	EFX_BUG_ON_PARANOID(space < EFX_RX_BATCH);

	netif_vdbg(rx_queue->efx, rx_status, rx_queue->efx->net_dev,
		   "RX queue %d fast-filling descriptor ring from"
		   " level %d to level %d using %s allocation\n",
		   efx_rx_queue_index(rx_queue), fill_level,
		   rx_queue->max_fill,
		   channel->rx_alloc_push_pages ? "page" : "skb");

	do {
		if (channel->rx_alloc_push_pages)
			rc = efx_init_rx_buffers_page(rx_queue);
		else
			rc = efx_init_rx_buffers_skb(rx_queue);
		if (unlikely(rc)) {
			/* Ensure that we don't leave the rx queue empty */
			if (rx_queue->added_count == rx_queue->removed_count)
				efx_schedule_slow_fill(rx_queue);
			goto out;
		}
	} while ((space -= EFX_RX_BATCH) >= EFX_RX_BATCH);

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
				     int len, bool *leak_packet)
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
		/* If this buffer was skb-allocated, then the meta
		 * data at the end of the skb will be trashed. So
		 * we have no choice but to leak the fragment.
		 */
		*leak_packet = !(rx_buf->flags & EFX_RX_BUF_PAGE);
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

static inline bool efx_gro_enabled(const struct efx_nic *efx)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)
	return !!(efx->net_dev->features & NETIF_F_GRO);
#else
	return false;
#endif
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)

/* Pass a received packet up through GRO.  GRO can handle pages
 * regardless of checksum state and skbs with a good checksum.
 */
static void efx_rx_packet_gro(struct efx_channel *channel,
			      struct efx_rx_buffer *rx_buf,
			      const u8 *eh)
{
	struct napi_struct *napi = &channel->napi_str;
	gro_result_t gro_result;

	if (rx_buf->flags & EFX_RX_BUF_PAGE) {
		struct efx_nic *efx = channel->efx;
		struct page *page = rx_buf->u.page;
		struct sk_buff *skb;

		rx_buf->u.page = NULL;

		skb = napi_get_frags(napi);
		if (!skb) {
			put_page(page);
			return;
		}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
		if (efx->net_dev->features & NETIF_F_RXHASH)
			skb->rxhash = efx_rx_buf_hash(eh);
#endif

		skb_fill_page_desc(skb, 0, page,
				   efx_rx_buf_offset(efx, rx_buf), rx_buf->len);

		skb->len = rx_buf->len;
		skb->data_len = rx_buf->len;
		skb->truesize += rx_buf->len;
		skb->ip_summed = ((rx_buf->flags & EFX_RX_PKT_CSUMMED) ?
				  CHECKSUM_UNNECESSARY : CHECKSUM_NONE);

		skb_record_rx_queue(skb, channel->rx_queue.core_index);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
		if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
			gro_result = vlan_gro_frags(napi, efx->vlan_group,
						    rx_buf->vlan_tci);
		else
			/* fall through */
#endif
		gro_result = napi_gro_frags(napi);
	} else {
		struct sk_buff *skb = rx_buf->u.skb;

		EFX_BUG_ON_PARANOID(!(rx_buf->flags & EFX_RX_PKT_CSUMMED));
		rx_buf->u.skb = NULL;
		skb->ip_summed = CHECKSUM_UNNECESSARY;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
		if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
			gro_result = vlan_gro_receive(napi,
						      channel->efx->vlan_group,
						      rx_buf->vlan_tci, skb);
		else
			/* fall through */
#endif
		gro_result = napi_gro_receive(napi, skb);
	}

	if (gro_result == GRO_NORMAL) {
		channel->rx_alloc_level += RX_ALLOC_FACTOR_SKB;
	} else if (gro_result != GRO_DROP) {
		channel->rx_alloc_level += RX_ALLOC_FACTOR_GRO;
		channel->irq_mod_score += 2;
	}
}

#endif /* EFX_USE_GRO */

#if (defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_GRO)) || (defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO))

/* Allocate and construct an SKB around a struct page.*/
static struct sk_buff *efx_rx_mk_skb(struct efx_nic *efx,
				     struct efx_rx_buffer *rx_buf,
				     u8 *eh, int hdr_len)
{
	struct sk_buff *skb;

	/* Allocate an SKB to store the headers */
	skb = netdev_alloc_skb(efx->net_dev, hdr_len + EFX_PAGE_SKB_ALIGN);
	if (unlikely(skb == NULL)) {
		if (net_ratelimit())
			netif_err(efx, drv, efx->net_dev,
				  "RX out of memory for skb\n");
		return NULL;
	}

	EFX_BUG_ON_PARANOID(skb_shinfo(skb)->nr_frags);
	EFX_BUG_ON_PARANOID(rx_buf->len < hdr_len);

	skb_reserve(skb, EFX_PAGE_SKB_ALIGN);

	skb->len = rx_buf->len;
	skb->truesize = rx_buf->len + sizeof(struct sk_buff);
	memcpy(skb->data, eh, hdr_len);
	skb->tail += hdr_len;

	/* Append the remaining page onto the frag list */
	if (unlikely(rx_buf->len > hdr_len)) {
		skb->data_len = skb->len - hdr_len;
		skb_fill_page_desc(skb, 0, rx_buf->u.page,
				   efx_rx_buf_offset(efx, rx_buf) + hdr_len,
				   skb->data_len);
	} else {
		__free_pages(rx_buf->u.page, efx->rx_buffer_order);
		skb->data_len = 0;
	}

	/* Ownership has transferred from the rx_buf to skb */
	rx_buf->u.page = NULL;

	/* Move past the ethernet header */
	skb->protocol = eth_type_trans(skb, efx->net_dev);

	return skb;
}

#endif /* !EFX_USE_GRO || EFX_USE_SFC_LRO */

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
void fastcall efx_rx_packet(struct efx_rx_queue *rx_queue,
			    unsigned int index, unsigned int len,
			    u16 flags)
#else
void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int len, u16 flags)
#endif
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	struct efx_rx_buffer *rx_buf;
	bool leak_packet = false;

	rx_buf = efx_rx_buffer(rx_queue, index);
	rx_buf->flags |= flags;

	/* This allows the refill path to post another buffer.
	 * EFX_RXD_HEAD_ROOM ensures that the slot we are using
	 * isn't overwritten yet.
	 */
	rx_queue->removed_count++;

	/* Validate the length encoded in the event vs the descriptor pushed */
	efx_rx_packet__check_len(rx_queue, rx_buf, len, &leak_packet);

	netif_vdbg(efx, rx_status, efx->net_dev,
		   "RX queue %d received id %x at %llx+%x %s%s\n",
		   efx_rx_queue_index(rx_queue), index,
		   (unsigned long long)rx_buf->dma_addr, len,
		   (rx_buf->flags & EFX_RX_PKT_CSUMMED) ? " [SUMMED]" : "",
		   (rx_buf->flags & EFX_RX_PKT_DISCARD) ? " [DISCARD]" : "");

	/* Discard packet, if instructed to do so */
	if (unlikely(rx_buf->flags & EFX_RX_PKT_DISCARD)) {
		if (unlikely(leak_packet))
			channel->n_skbuff_leaks++;
		else
			efx_recycle_rx_buffer(channel, rx_buf);

		/* Don't hold off the previous receive */
		rx_buf = NULL;
		goto out;
	}

	/* Release card resources - assumes all RX buffers consumed in-order
	 * per RX queue
	 */
	efx_unmap_rx_buffer(efx, rx_buf);

	/* Prefetch nice and early so data will (hopefully) be in cache by
	 * the time we look at it.
	 */
	prefetch(efx_rx_buf_eh(efx, rx_buf));

	/* Pipeline receives so that we give time for packet headers to be
	 * prefetched into cache.
	 */
	rx_buf->len = len - efx->rx_buffer_hash_size;
out:
	if (channel->rx_pkt)
		__efx_rx_packet(channel, channel->rx_pkt);
	channel->rx_pkt = rx_buf;
}

static void efx_rx_deliver(struct efx_channel *channel, u8 *eh,
			   struct efx_rx_buffer *rx_buf)
{
	struct sk_buff *skb;

#if (defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_GRO)) || (defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO))
	/* Form an skb if required */
	if (rx_buf->flags & EFX_RX_BUF_PAGE) {
		int hdr_len = min(rx_buf->len, EFX_SKB_HEADERS);
		skb = efx_rx_mk_skb(channel->efx, rx_buf, eh, hdr_len);
		if (unlikely(skb == NULL)) {
			efx_free_rx_buffer(channel->efx, rx_buf);
			return;
		}
		skb_record_rx_queue(skb, channel->rx_queue.core_index);
	} else {
		/* We now own the SKB */
		skb = rx_buf->u.skb;
		rx_buf->u.skb = NULL;
	}
#else
	/* We now own the SKB */
	EFX_BUG_ON_PARANOID(rx_buf->flags & EFX_RX_BUF_PAGE);
	skb = rx_buf->u.skb;
	rx_buf->u.skb = NULL;
#endif

	/* Set the SKB flags */
	skb_checksum_none_assert(skb);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_GRO)
	if (likely(rx_buf->flags & EFX_RX_PKT_CSUMMED))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_WITH_VMWARE_NETQ)
	/* This will mark the skb with the correct queue ID.
	 * It may also insert a hardware filter. We pass in
	 * the channel as a hint, since in the common case it
	 * should map to the correct queue. Note that this
	 * is the only netif_receive_skb() call site that is
	 * active in the VMWare build.*/
	if (channel->efx->netq_active)
		efx_netq_process_rx(channel->efx, channel, skb);
#endif

	/* Pass the packet up */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		vlan_hwaccel_receive_skb(skb, channel->efx->vlan_group,
					 rx_buf->vlan_tci);
	else
		/* fall through */
#endif
	if (channel->type->receive_skb)
		channel->type->receive_skb(channel, skb);
	else
		netif_receive_skb(skb);

	/* Update allocation strategy method */
	channel->rx_alloc_level += RX_ALLOC_FACTOR_SKB;
}

/* Handle a received packet.  Second half: Touches packet payload. */
void __efx_rx_packet(struct efx_channel *channel, struct efx_rx_buffer *rx_buf)
{
	struct efx_nic *efx = channel->efx;
	u8 *eh = efx_rx_buf_eh(efx, rx_buf);

	/* If we're in loopback test, then pass the packet directly to the
	 * loopback layer, and free the rx_buf here
	 */
	if (unlikely(efx->loopback_selftest)) {
		efx_loopback_rx_packet(efx, eh, rx_buf->len);
		efx_free_rx_buffer(efx, rx_buf);
		return;
	}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if ((rx_buf->flags & EFX_RX_PKT_VLAN) && efx->vlan_group) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)eh;
		unsigned int hash_size =
			efx->rx_buffer_hash_size ? 4 : 0;

		rx_buf->vlan_tci = ntohs(veh->h_vlan_TCI);
		memmove(eh - hash_size + VLAN_HLEN, eh - hash_size,
			hash_size + 2 * ETH_ALEN);
		eh += VLAN_HLEN;
		rx_buf->len -= VLAN_HLEN;
		rx_buf->flags |= EFX_RX_BUF_VLAN_XTAG;
	}
#endif

	if (!(rx_buf->flags & EFX_RX_BUF_PAGE)) {
		struct sk_buff *skb = rx_buf->u.skb;

		prefetch(skb_shinfo(skb));
		skb_reserve(skb, efx->rx_buffer_hash_size);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
		if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
			skb_reserve(skb, VLAN_HLEN);
#endif
		skb_put(skb, rx_buf->len);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
		if (efx->net_dev->features & NETIF_F_RXHASH)
			skb->rxhash = efx_rx_buf_hash(eh);
#endif

		/* Move past the ethernet header */
		skb->protocol = eth_type_trans(skb, efx->net_dev);

		skb_record_rx_queue(skb, channel->channel);
	}
#ifdef EFX_NOT_UPSTREAM
	channel->rx_packets++;
	channel->rx_bytes += rx_buf->len;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	if (unlikely(!(efx->net_dev->features & NETIF_F_RXCSUM)))
#else
	if (unlikely(!efx->rx_checksum_enabled))
#endif
		rx_buf->flags &= ~EFX_RX_PKT_CSUMMED;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* SFC-SSR supports both skb and page based, but not switching
	 * from one to the other on the fly. If we spot that the
	 * allocation mode has changed, then flush the LRO state.
	 */
	if (unlikely(channel->rx_alloc_pop_pages !=
		     !!(rx_buf->flags & EFX_RX_BUF_PAGE))) {
		efx_ssr_end_of_burst(channel);
		channel->rx_alloc_pop_pages =
			!!(rx_buf->flags & EFX_RX_BUF_PAGE);
	}
	if (likely((rx_buf->flags & EFX_RX_PKT_CSUMMED) &&
		   efx_ssr_enabled(efx)))
		efx_ssr(channel, rx_buf, eh);
	else
		/* fall through */
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)
	if (likely(rx_buf->flags & (EFX_RX_BUF_PAGE | EFX_RX_PKT_CSUMMED)) &&
	    !channel->type->receive_skb)
		efx_rx_packet_gro(channel, rx_buf, eh);
	else
#endif
		efx_rx_deliver(channel, eh, rx_buf);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_LAST_RX)
	efx->net_dev->last_rx = jiffies;
#endif
}

void efx_rx_strategy(struct efx_channel *channel)
{
	enum efx_rx_alloc_method method = rx_alloc_method;

#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_USE_COMPOUND_PAGES)
	if (channel->efx->rx_buffer_order > 0) {
		channel->rx_alloc_push_pages = false;
		return;
	}
#endif
	if (channel->type->receive_skb) {
		channel->rx_alloc_push_pages = false;
		return;
	}

	/* Only makes sense to use page based allocation if GRO is enabled */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* or if SSR is enabled */
	if (!(efx_ssr_enabled(channel->efx) || efx_gro_enabled(channel->efx))) {
#else
	if (!efx_gro_enabled(channel->efx)) {
#endif
		method = RX_ALLOC_METHOD_SKB;
	} else if (method == RX_ALLOC_METHOD_AUTO) {
		/* Constrain the rx_alloc_level */
		if (channel->rx_alloc_level < 0)
			channel->rx_alloc_level = 0;
		else if (channel->rx_alloc_level > RX_ALLOC_LEVEL_MAX)
			channel->rx_alloc_level = RX_ALLOC_LEVEL_MAX;

		/* Decide on the allocation method */
		method = ((channel->rx_alloc_level > RX_ALLOC_LEVEL_GRO) ?
			  RX_ALLOC_METHOD_PAGE : RX_ALLOC_METHOD_SKB);
	}

	/* Push the option */
	channel->rx_alloc_push_pages = (method == RX_ALLOC_METHOD_PAGE);
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

	/* Initialise limit fields */
	max_fill = efx->rxq_entries - EFX_RXD_HEAD_ROOM;
	max_trigger = max_fill - EFX_RX_BATCH;
	if (rx_refill_threshold != 0) {
		trigger = max_fill * min(rx_refill_threshold, 100U) / 100U;
		if (trigger > max_trigger)
			trigger = max_trigger;
	} else {
		trigger = max_trigger;
	}

	rx_queue->max_fill = max_fill;
	rx_queue->fast_fill_trigger = trigger;

	/* Set up RX descriptor ring */
	rx_queue->enabled = true;
	efx_nic_init_rx(rx_queue);
}

void efx_fini_rx_queue(struct efx_rx_queue *rx_queue)
{
	int i;
	struct efx_rx_buffer *rx_buf;

	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "shutting down RX queue %d\n", efx_rx_queue_index(rx_queue));

	/* A flush failure might have left rx_queue->enabled */
	rx_queue->enabled = false;

	del_timer_sync(&rx_queue->slow_fill);
	efx_nic_fini_rx(rx_queue);

	/* Release RX buffers NB start at index 0 not current HW ptr */
	if (rx_queue->buffer) {
		for (i = 0; i <= rx_queue->ptr_mask; i++) {
			rx_buf = efx_rx_buffer(rx_queue, i);
			efx_fini_rx_buffer(rx_queue, rx_buf);
		}
	}
}

void efx_remove_rx_queue(struct efx_rx_queue *rx_queue)
{
	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "destroying RX queue %d\n", efx_rx_queue_index(rx_queue));

	efx_nic_remove_rx(rx_queue);

	kfree(rx_queue->buffer);
	rx_queue->buffer = NULL;
}


module_param(rx_alloc_method, int, 0644);
MODULE_PARM_DESC(rx_alloc_method, "Allocation method used for RX buffers");

module_param(rx_refill_threshold, uint, 0444);
MODULE_PARM_DESC(rx_refill_threshold,
		 "RX descriptor ring refill threshold (%)");

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)


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
	return rx_buf->u.page;
}

static inline void efx_rx_buffer_set_empty(struct efx_rx_buffer *rx_buf)
{
	rx_buf->u.page = NULL;
}

/* Drop the given connection, and add it to the free list. */
static void efx_ssr_drop(struct efx_channel *channel, struct efx_ssr_conn *c)
{
	unsigned bucket;

	EFX_BUG_ON_PARANOID(c->skb);

	if (efx_rx_buffer_is_full(&c->next_buf)) {
		efx_rx_deliver(channel, c->next_eh, &c->next_buf);
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

/* Calc IP checksum and deliver to the OS */
static void efx_ssr_deliver(struct efx_ssr_state *st, struct efx_ssr_conn *c)
{
	struct ethhdr *c_eh;
	struct tcphdr *c_th;
	int len;

	EFX_BUG_ON_PARANOID(!c->skb);

	++st->n_bursts;

	/* Finish off packet munging and recalculate IP header checksum. */
	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *) c->skb->data;
		iph->tot_len = htons(c->sum_len);
		iph->check = 0;
#if __GNUC__+0 == 4 && __GNUC_MINOR__+0 == 5 && __GNUC_PATCHLEVEL__+0 <= 1
		/* Compiler may wrongly eliminate the preceding assignment */
		barrier();
#endif
		iph->check = ip_fast_csum((u8 *) iph, iph->ihl);
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *) c->skb->data;
		iph->payload_len = htons(c->sum_len);
		c_th = (struct tcphdr *)(iph + 1);
	}

	c_eh = eth_hdr(c->skb);
	len = c->skb->len + ((u8 *)c->skb->data - (u8 *)c_eh);
	c->skb->truesize = len + sizeof(struct sk_buff);
	c->skb->ip_summed = CHECKSUM_UNNECESSARY;

	c_th->window = c->th_last->window;
	c_th->ack_seq = c->th_last->ack_seq;
	if (c_th->doff == c->th_last->doff) {
		/* Copy TCP options (take care to avoid going negative). */
		int optlen = ((c_th->doff - 5) & 0xf) << 2u;
		memcpy(c_th + 1, c->th_last + 1, optlen);
	}

#if defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
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
		struct iphdr *iph = (struct iphdr *) c->skb->data;
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *) c->skb->data;
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
		struct iphdr *iph = (struct iphdr *) c->skb->data;
		c->sum_len = ntohs(iph->tot_len);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *) c->skb->data;
		c->sum_len = ntohs(iph->payload_len);
	}
}

static int
efx_ssr_merge_page(struct efx_ssr_state *st, struct efx_ssr_conn *c,
		   struct tcphdr *th, int hdr_length, int data_length)
{
	struct efx_nic *efx = st->efx;
	struct efx_rx_buffer *rx_buf = &c->next_buf;
	char *eh = c->next_eh;

	if (likely(c->skb)) {
		skb_fill_page_desc(c->skb, skb_shinfo(c->skb)->nr_frags,
				   rx_buf->u.page,
				   efx_rx_buf_offset(efx, rx_buf) + hdr_length,
				   data_length);
		rx_buf->u.page = NULL;

		if (efx_ssr_merge(st, c, th, data_length) ||
		    (skb_shinfo(c->skb)->nr_frags == MAX_SKB_FRAGS))
			efx_ssr_deliver(st, c);

		return 1;
	} else {
		c->skb = efx_rx_mk_skb(efx, rx_buf, eh, hdr_length);
		if (unlikely(c->skb == NULL))
			return 0;

#ifdef EFX_HAVE_RXHASH_SUPPORT
		c->skb->rxhash = c->conn_hash;
#endif
		if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
			struct iphdr *iph = (struct iphdr *) c->skb->data;
			c->th_last = (struct tcphdr *)(iph + 1);
		} else {
			struct ipv6hdr *iph = (struct ipv6hdr *) c->skb->data;
			c->th_last = (struct tcphdr *)(iph + 1);
		}
		efx_ssr_start(st, c, th, data_length);

		return 1;
	}
}

static void
efx_ssr_merge_skb(struct efx_ssr_state *st, struct efx_ssr_conn *c,
		  struct efx_rx_buffer *rx_buf,
		  struct tcphdr *th, int data_length)
{
	/* Transfer ownership of the rx_buf->skb to the LRO chain */
	struct sk_buff *skb = rx_buf->u.skb;
	rx_buf->u.skb = NULL;

	/* Remove any padding */
	skb_trim(skb, rx_buf->len - ETH_HLEN);

	if (likely(c->skb)) {
		/* Remove TCP/IP headers */
		skb_pull(skb, skb->len - data_length);

		/* Tack the new skb onto the head skb's frag_list. */
		EFX_BUG_ON_PARANOID(skb->next);
		if (!skb_shinfo(c->skb)->frag_list)
			skb_shinfo(c->skb)->frag_list = skb;
		else
			c->skb_tail->next = skb;
		c->skb_tail = skb;

		if (efx_ssr_merge(st, c, th, data_length))
			efx_ssr_deliver(st, c);
	} else {
		c->skb = skb;
		c->th_last = th;
		efx_ssr_start(st, c, th, data_length);
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
	rx_buf->len = min(pkt_length, rx_buf->len);
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

	now = jiffies;
	if (now - c->last_pkt_jiffies > lro_idle_jiffies) {
		++channel->ssr.n_drop_idle;
		if (c->skb)
			efx_ssr_deliver(&channel->ssr, c);
		efx_ssr_drop(channel, c);
		return false;
	}
	c->last_pkt_jiffies = jiffies;

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

	if (rx_buf->flags & EFX_RX_BUF_PAGE) {
		if (efx_ssr_merge_page(&channel->ssr, c, th,
				       hdr_length, data_length) == 0)
			goto deliver_buf_out;
	} else {
		efx_ssr_merge_skb(&channel->ssr, c, rx_buf, th, data_length);
	}
	channel->rx_alloc_level += RX_ALLOC_FACTOR_GRO;
	channel->irq_mod_score += 2;
	return true;

 deliver_buf_out:
	efx_rx_deliver(channel, eh, rx_buf);
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
	if (efx->rx_buffer_hash_size)
#endif
		conn_hash = efx_rx_buf_hash(rx_data);
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
				c_iph = (struct iphdr *) c->skb->data;
				if ((c_iph->saddr ^ iph->saddr) |
				    (c_iph->daddr ^ iph->daddr))
					continue;
			} else {
				struct ipv6hdr *c_iph, *iph = nh;
				c_iph = (struct ipv6hdr *) c->skb->data;
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
	efx_rx_deliver(channel, rx_data, rx_buf);
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
