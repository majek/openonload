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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains allocation of VI resources.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efrm/nic_table.h>
#include <ci/efhw/iopage.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/public.h>
#include <ci/efhw/falcon.h>
#include <ci/efhw/eventq.h>
#include <ci/efrm/private.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/pd.h>
#include <ci/affinity/k_drv_intf.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"
#include "efrm_pd.h"


struct vi_attr {
	struct efrm_pd     *pd;
	struct efrm_vf     *vf;
	struct efrm_vi_set *vi_set;
	int16_t             interrupt_core;
	int16_t             channel;
	uint8_t             vi_set_instance;
	int8_t              with_interrupt;
	int8_t              with_timer;
};


union vi_attr_u {
	struct vi_attr      vi_attr;
	struct efrm_vi_attr efrm_vi_attr;
};


#define VI_ATTR_FROM_O_ATTR(attr)					\
  (&(container_of((attr), union vi_attr_u, efrm_vi_attr)->vi_attr))


/*** Data definitions ****************************************************/

static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };

struct vi_resource_manager *efrm_vi_manager;


/*** Forward references **************************************************/

static void
__efrm_vi_resource_free(struct efrm_vi *virs);


/*** Reference count handling ********************************************/

static void efrm_vi_rm_get_ref(struct efrm_vi *virs)
{
	atomic_inc(&virs->evq_refs);
}

static void efrm_vi_rm_drop_ref(struct efrm_vi *virs)
{
	EFRM_ASSERT(atomic_read(&virs->evq_refs) != 0);
	if (atomic_dec_and_test(&virs->evq_refs))
		__efrm_vi_resource_free(virs);
}

/*** Instance numbers ****************************************************/

static int efrm_vi_rm_alloc_instance(struct efrm_pd *pd,
				     struct efrm_vi *virs,
				     const struct vi_attr *vi_attr)
{
	struct efrm_nic *efrm_nic;
#ifdef CONFIG_SFC_RESOURCE_VF
	struct efrm_vf *vf;
#endif
	unsigned vi_props;
	int channel;

	if (vi_attr->vi_set != NULL) {
		virs->allocation.instance =
			vi_attr->vi_set->allocation.instance +
			vi_attr->vi_set_instance;
		virs->allocation.order = 0;
		virs->allocation.allocator_id = -1;
		virs->vi_set = vi_attr->vi_set;
		virs->allocation.vf = vi_attr->vi_set->allocation.vf;
		efrm_resource_ref(efrm_vi_set_to_resource(virs->vi_set));
		return 0;
	}

#ifdef CONFIG_SFC_RESOURCE_VF
	vf = efrm_pd_get_vf(pd);
	if (vf != NULL)
		return efrm_vf_alloc_vi_set(vf, 1, &virs->allocation);
#endif

	
	efrm_nic = container_of(efrm_pd_to_resource(pd)->rs_client->nic,
				struct efrm_nic, efhw_nic);
	channel = vi_attr->channel;
	if (vi_attr->interrupt_core >= 0) {
		int ifindex = efrm_nic->efhw_nic.ifindex;
		channel = sfc_affinity_cpu_to_channel(ifindex,
						      vi_attr->interrupt_core);
		if (channel < 0) {
			EFRM_ERR("%s: ERROR: could not map core_id=%d using "
				 "ifindex=%d", __FUNCTION__,
				 (int) vi_attr->interrupt_core, ifindex);
			EFRM_ERR("%s: ERROR: Perhaps sfc_affinity is not "
				 "configured?", __FUNCTION__);
			return -EINVAL;
		}
	}

	if (vi_attr->with_interrupt)
		vi_props = vi_with_interrupt;
	else
		vi_props = vi_with_timer;
	return efrm_vi_allocator_alloc_set(efrm_nic, vi_props, 1,
					   channel, &virs->allocation);
}

/*** Queue sizes *********************************************************/

uint32_t efrm_vi_rm_evq_bytes(struct efrm_vi *virs, int n_entries)
{
	if (n_entries < 0)
		n_entries = virs->q[EFHW_EVQ].capacity;
	return n_entries * sizeof(efhw_event_t);
}
EXPORT_SYMBOL(efrm_vi_rm_evq_bytes);


static uint32_t efrm_vi_rm_txq_bytes(struct efrm_vi *virs, int n_entries)
{
	return n_entries * FALCON_DMA_TX_DESC_BYTES;
}


static uint32_t efrm_vi_rm_rxq_bytes(struct efrm_vi *virs, int n_entries)
{
	uint32_t bytes_per_desc = ((virs->flags & EFHW_VI_RX_PHYS_ADDR_EN)
				   ? FALCON_DMA_RX_PHYS_DESC_BYTES
				   : FALCON_DMA_RX_BUF_DESC_BYTES);
	return n_entries * bytes_per_desc;
}


static int efrm_vi_q_bytes(struct efrm_vi *virs, enum efhw_q_type q_type,
			   int n_entries)
{
	switch (q_type) {
	case EFHW_TXQ:
		return efrm_vi_rm_txq_bytes(virs, n_entries);
	case EFHW_RXQ:
		return efrm_vi_rm_rxq_bytes(virs, n_entries);
	case EFHW_EVQ:
		return efrm_vi_rm_evq_bytes(virs, n_entries);
	default:
		return -EINVAL;
	}
}


static int choose_size(int size_rq, unsigned sizes)
{
	int size;

	/* size_rq < 0 means default, but we interpret this as 'minimum'. */

	for (size = 256;; size <<= 1)
		if ((size & sizes) && size >= size_rq)
			return size;
		else if ((sizes & ~((size - 1) | size)) == 0)
			return -1;
}


/*************************************************************************/

static void efrm_vi_attach_evq(struct efrm_vi *virs, enum efhw_q_type q_type,
			       struct efrm_vi *evq)
{
	EFRM_ASSERT(evq != NULL);
	EFRM_ASSERT(atomic_read(&evq->evq_refs) != 0);
	EFRM_ASSERT(virs->q[q_type].evq_ref == NULL);
	virs->q[q_type].evq_ref = evq;
	if (evq != virs)
		efrm_vi_rm_get_ref(evq);
}


static void efrm_vi_detach_evq(struct efrm_vi *virs, enum efhw_q_type q_type)
{
	struct efrm_vi *evq = virs->q[q_type].evq_ref;
	virs->q[q_type].evq_ref = NULL;
	if (evq != NULL && evq != virs)
		efrm_vi_rm_drop_ref(evq);
}


/*************************************************************************/

static unsigned q_flags_to_vi_flags(unsigned q_flags, enum efhw_q_type q_type)
{
	unsigned vi_flags = 0;

	switch (q_type) {
	case EFHW_TXQ:
		if (q_flags & EFRM_VI_PHYS_ADDR)
			vi_flags |= EFHW_VI_TX_PHYS_ADDR_EN;
		if (!(q_flags & EFRM_VI_IP_CSUM))
			vi_flags |= EFHW_VI_TX_IP_CSUM_DIS;
		if (!(q_flags & EFRM_VI_TCP_UDP_CSUM))
			vi_flags |= EFHW_VI_TX_TCPUDP_CSUM_DIS;
		if (q_flags & EFRM_VI_ISCSI_HEADER_DIGEST)
			vi_flags |= EFHW_VI_ISCSI_TX_HDIG_EN;
		if (q_flags & EFRM_VI_ISCSI_DATA_DIGEST)
			vi_flags |= EFHW_VI_ISCSI_TX_DDIG_EN;
		if (q_flags & EFRM_VI_ETH_FILTER)
			vi_flags |= EFHW_VI_TX_ETH_FILTER_EN;
		if (q_flags & EFRM_VI_TCP_UDP_FILTER)
			vi_flags |= EFHW_VI_TX_IP_FILTER_EN;
		if (!(q_flags & EFRM_VI_CONTIGUOUS))
			vi_flags |= EFHW_VI_JUMBO_EN;
		break;
	case EFHW_RXQ:
		if (q_flags & EFRM_VI_PHYS_ADDR)
			vi_flags |= EFHW_VI_RX_PHYS_ADDR_EN;
		break;
	default:
		break;
	}

	return vi_flags;
}


static unsigned vi_flags_to_q_flags(unsigned vi_flags, enum efhw_q_type q_type)
{
	unsigned q_flags = 0;

	switch (q_type) {
	case EFHW_TXQ:
		if (vi_flags & EFHW_VI_TX_PHYS_ADDR_EN)
			q_flags |= EFRM_VI_PHYS_ADDR;
		if (!(vi_flags & EFHW_VI_TX_IP_CSUM_DIS))
			q_flags |= EFRM_VI_IP_CSUM;
		if (!(vi_flags & EFHW_VI_TX_TCPUDP_CSUM_DIS))
			q_flags |= EFRM_VI_TCP_UDP_CSUM;
		if (vi_flags & EFHW_VI_ISCSI_TX_HDIG_EN)
			q_flags |= EFRM_VI_ISCSI_HEADER_DIGEST;
		if (vi_flags & EFHW_VI_ISCSI_TX_DDIG_EN)
			q_flags |= EFRM_VI_ISCSI_DATA_DIGEST;
		if (vi_flags & EFHW_VI_TX_ETH_FILTER_EN)
			q_flags |= EFRM_VI_ETH_FILTER;
		if (vi_flags & EFHW_VI_TX_IP_FILTER_EN)
			q_flags |= EFRM_VI_TCP_UDP_FILTER;
		if (!(vi_flags & EFHW_VI_JUMBO_EN))
			q_flags |= EFRM_VI_CONTIGUOUS;
		break;
	case EFHW_RXQ:
		if (vi_flags & EFHW_VI_RX_PHYS_ADDR_EN)
			q_flags |= EFRM_VI_PHYS_ADDR;
		break;
	default:
		break;
	}

	return q_flags;
}


/*** Per-NIC allocations *************************************************/

void
efrm_vi_rm_init_dmaq(struct efrm_vi *virs, enum efhw_q_type queue_type,
		     struct efhw_nic *nic)
{
	struct efrm_vi_q *q = &virs->q[queue_type];
	int instance, evq_instance;

	instance = virs->rs.rs_instance;

	switch (queue_type) {
	case EFHW_TXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
		efhw_nic_dmaq_tx_q_init(nic, instance, evq_instance,
					efrm_pd_owner_id(virs->pd),
					virs->q[queue_type].tag, q->capacity,
					q->buf_tbl_alloc.base, virs->flags);
		break;
	case EFHW_RXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
		efhw_nic_dmaq_rx_q_init(nic, instance, evq_instance,
					efrm_pd_owner_id(virs->pd),
					virs->q[queue_type].tag, q->capacity,
					q->buf_tbl_alloc.base, virs->flags);
		break;
	case EFHW_EVQ:
		efhw_nic_event_queue_enable(nic, instance, q->capacity,
					    q->buf_tbl_alloc.base,
					    /* make siena look like falcon */
					    instance < 64 ||
					    efrm_pd_get_vf(virs->pd),
					    1 /* DOS protection */);
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
}


static void
efrm_vi_rm_fini_dmaq(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	int instance = virs->rs.rs_instance;
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[queue_type];
	struct efrm_vf *vf = virs->allocation.vf;
	efhw_iommu_domain *iommu_domain = efrm_vf_get_iommu_domain(vf);

	if (q->capacity == 0)
		return;

	switch (queue_type) {
	case EFHW_TXQ:
		/* Ensure TX pacing turned off -- queue flush doesn't reset
		 * this.
		 */
		falcon_nic_pace(nic, instance, 0);
		break;
	case EFHW_EVQ:
		efhw_nic_event_queue_disable(nic, instance, 0);
		break;
	default:
		break;
	}

	/* NB. No need to disable DMA queues here.  Nobody is using it
	 * anyway.
	 */
	if (efhw_iopages_n_pages(&q->pages))
		efhw_iopages_free(efrm_vi_get_pci_dev(virs), &q->pages,
			iommu_domain);
	if (q->buf_tbl_alloc.base != -1)
		efrm_nic_buffer_table_free(efrm_nic(nic), &q->buf_tbl_alloc);
}


static void
__efrm_vi_resource_free(struct efrm_vi *virs)
{
	struct efrm_nic *efrm_nic;
	int instance;

	EFRM_ASSERT(efrm_vi_manager);
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_vi_manager->rm);
	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 1);

	efrm_nic = container_of(virs->rs.rs_client->nic, struct efrm_nic,
				efhw_nic);
	instance = virs->rs.rs_instance;

	EFRM_TRACE("%s: Freeing %d", __FUNCTION__, instance);
	EFRM_ASSERT(atomic_read(&virs->evq_refs) == 0);
	EFRM_ASSERT(virs->evq_callback_fn == NULL);
	EFRM_ASSERT(virs->q[EFHW_TXQ].evq_ref == NULL);
	EFRM_ASSERT(virs->q[EFHW_RXQ].evq_ref == NULL);

	efrm_vi_rm_fini_dmaq(virs, EFHW_RXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_TXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_EVQ);
	efrm_vi_detach_evq(virs, EFHW_RXQ);
	efrm_vi_detach_evq(virs, EFHW_TXQ);
	if (virs->vi_set != NULL) {
		efrm_vi_set_release(virs->vi_set);
#ifdef CONFIG_SFC_RESOURCE_VF
	} else if (virs->allocation.vf != NULL) {
		efrm_vf_vi_drop(virs);
		efrm_vf_free_vi_set(&virs->allocation);
#endif
	} else {
		efrm_vi_allocator_free_set(efrm_nic, &virs->allocation);
	}
	efrm_pd_release(virs->pd);
	efrm_client_put(virs->rs.rs_client);
	EFRM_DO_DEBUG(memset(virs, 0, sizeof(*virs)));
	kfree(virs);
}

/*** Resource object  ****************************************************/

int
efrm_vi_q_alloc(struct efrm_vi *virs, enum efhw_q_type q_type,
		int n_q_entries, int q_tag_in, unsigned vi_flags,
		struct efrm_vi *evq)
{
	dma_addr_t *dma_addrs;
	int dma_addrs_size;
	struct efrm_vi_q *q = &virs->q[q_type];
	struct efrm_vi_q_size qsize;
	int i, rc, q_flags;
	struct efrm_vf *vf = virs->allocation.vf;
	efhw_iommu_domain *iommu_domain = efrm_vf_get_iommu_domain(vf);
	unsigned long iova_base = 0;

	if (n_q_entries == 0)
		return 0;
	if(n_q_entries < 0)
		n_q_entries = 1;
	if (efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize) < 0) {
		EFRM_ERR("%s: ERROR: bad %s size %d (supported=%x)",
			 __FUNCTION__, q_names[q_type],
			 virs->q[q_type].capacity,
			 virs->rs.rs_client->nic->q_sizes[q_type]);
		return -EINVAL;
	}
	if (evq != NULL) {
		int vi_ifindex = efrm_client_get_ifindex(virs->rs.rs_client);
		int evq_ifindex = efrm_client_get_ifindex(evq->rs.rs_client);
		if (vi_ifindex != evq_ifindex) {
			EFRM_ERR("%s: ERROR: %s on %d but EVQ on %d",
				 __FUNCTION__, q_names[q_type],
				 vi_ifindex, evq_ifindex);
			return -EINVAL;
		}
	}

#ifdef CONFIG_SFC_RESOURCE_VF
	iova_base = vf ? efrm_vf_alloc_ioaddrs(vf,
		1 << qsize.q_len_page_order, NULL) : 0;
#endif
	rc = efhw_iopages_alloc(efrm_vi_get_pci_dev(virs), &q->pages,
				qsize.q_len_page_order, iommu_domain,
				iova_base);
	if (rc < 0) {
		EFRM_ERR("%s: Failed to allocate %s DMA buffer",
			 __FUNCTION__, q_names[q_type]);
		return rc;
		goto fail_iopages;
	}
	if (q_type == EFHW_EVQ)
		memset(efhw_iopages_ptr(&q->pages), EFHW_CLEAR_EVENT_VALUE,
		       qsize.q_len_bytes);

	dma_addrs_size = 1 << qsize.q_len_page_order;
	EFRM_ASSERT(dma_addrs_size <= EFRM_VI_MAX_DMA_ADDR);
	dma_addrs = kmalloc(sizeof(*dma_addrs) * dma_addrs_size, GFP_KERNEL);
	for (i = 0; i < dma_addrs_size; ++i)
		dma_addrs[i] = efhw_iopages_dma_addr(&q->pages, i);

	q_flags = vi_flags_to_q_flags(vi_flags, q_type);
	rc = efrm_vi_q_init(virs, q_type, qsize.q_len_entries,
			    dma_addrs,
			    efhw_iopages_n_pages(&q->pages),
			    q_tag_in, q_flags, evq);
	kfree(dma_addrs);
	if (rc < 0)
		goto fail_q_init;

	virs->mem_mmap_bytes += PAGE_SIZE * (1 << qsize.q_len_page_order);
	return 0;


fail_q_init:
	efhw_iopages_free(efrm_vi_get_pci_dev(virs), &q->pages, iommu_domain);
fail_iopages:
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_alloc);


int
efrm_vi_resource_alloc(struct efrm_client *client,
		       struct efrm_vi *evq_virs,
		       struct efrm_vi_set *vi_set, int vi_set_instance,
		       struct efrm_pd *pd, const char *name,
		       unsigned vi_flags,
		       int evq_capacity, int txq_capacity, int rxq_capacity,
		       int tx_q_tag, int rx_q_tag, int wakeup_cpu_core,
		       int wakeup_channel,
		       struct efrm_vi **virs_out,
		       uint32_t *out_io_mmap_bytes,
		       uint32_t *out_mem_mmap_bytes,
		       uint32_t *out_txq_capacity, uint32_t *out_rxq_capacity)
{
	struct efrm_vi_attr attr;
	struct efrm_vi *virs;
	int rc;

	efrm_vi_attr_init(&attr);
	if (vi_flags & EFHW_VI_RM_WITH_INTERRUPT)
		efrm_vi_attr_set_with_interrupt(&attr, 1);
	if (vi_set != NULL)
		efrm_vi_attr_set_instance(&attr, vi_set, vi_set_instance);
	if (pd != NULL)
		efrm_vi_attr_set_pd(&attr, pd);
	if (wakeup_cpu_core >= 0)
		efrm_vi_attr_set_interrupt_core(&attr, wakeup_cpu_core);
	if (wakeup_channel >= 0)
		efrm_vi_attr_set_wakeup_channel(&attr, wakeup_channel);

	if ((rc = efrm_vi_alloc(client, &attr, &virs)) < 0)
		goto fail_vi_alloc;

#ifdef CONFIG_SFC_RESOURCE_VF
	if (efrm_pd_get_vf(pd))
		efrm_vf_vi_set_name(virs, name);
#endif
	if (efrm_pd_owner_id(pd) == 0) {
		EFRM_ASSERT(vi_flags & EFHW_VI_RX_PHYS_ADDR_EN);
		EFRM_ASSERT(vi_flags & EFHW_VI_TX_PHYS_ADDR_EN);
		virs->flags |= EFHW_VI_RX_PHYS_ADDR_EN |
				EFHW_VI_TX_PHYS_ADDR_EN;
	}

	if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
				  tx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
				  rx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;

	if (evq_virs == NULL && evq_capacity < 0)
		evq_capacity = (virs->q[EFHW_RXQ].capacity +
				virs->q[EFHW_TXQ].capacity);

	if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
				  0, vi_flags, NULL)) < 0)
		goto fail_q_alloc;

	if (out_io_mmap_bytes != NULL)
		*out_io_mmap_bytes = PAGE_SIZE;
	if (out_mem_mmap_bytes != NULL)
		*out_mem_mmap_bytes = virs->mem_mmap_bytes;
	if (out_txq_capacity != NULL)
		*out_txq_capacity = virs->q[EFHW_TXQ].capacity;
	if (out_rxq_capacity != NULL)
		*out_rxq_capacity = virs->q[EFHW_RXQ].capacity;

	*virs_out = virs;
	return 0;


fail_q_alloc:
	efrm_vi_resource_release(virs);
fail_vi_alloc:
	return rc;
}
EXPORT_SYMBOL(efrm_vi_resource_alloc);


void efrm_vi_rm_free_flushed_resource(struct efrm_vi *virs)
{
	EFRM_ASSERT(virs != NULL);
	EFRM_ASSERT(virs->rs.rs_ref_count == 0);

	EFRM_TRACE("%s: " EFRM_RESOURCE_FMT, __FUNCTION__,
		   EFRM_RESOURCE_PRI_ARG(&virs->rs));
	/* release the associated event queue then drop our own reference
	 * count */
	efrm_vi_detach_evq(virs, EFHW_RXQ);
	efrm_vi_detach_evq(virs, EFHW_TXQ);
	efrm_vi_rm_drop_ref(virs);
}


/**********************************************************************
 * The new interface...
 */

int __efrm_vi_attr_init(struct efrm_client *client_obsolete,
			struct efrm_vi_attr *attr, int attr_size)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	if (attr_size < sizeof(struct vi_attr)) {
		EFRM_ERR("efrm_vi_attr_init: Interface mismatch (%d %d)",
			 attr_size, (int) sizeof(struct vi_attr));
		return -EINVAL;
	}
	a->with_interrupt = 0;
	a->with_timer = 0;
	a->pd = NULL;
	a->vi_set = NULL;
	a->vf = NULL;
	a->interrupt_core = -1;
	a->channel = -1;
	return 0;
}
EXPORT_SYMBOL(__efrm_vi_attr_init);


void efrm_vi_attr_set_pd(struct efrm_vi_attr *attr, struct efrm_pd *pd)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->pd = pd;
}
EXPORT_SYMBOL(efrm_vi_attr_set_pd);


void efrm_vi_attr_set_with_interrupt(struct efrm_vi_attr *attr,
				     int with_interrupt)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->with_interrupt = with_interrupt;
}
EXPORT_SYMBOL(efrm_vi_attr_set_with_interrupt);


void efrm_vi_attr_set_with_timer(struct efrm_vi_attr *attr, int with_timer)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->with_timer = with_timer;
}
EXPORT_SYMBOL(efrm_vi_attr_set_with_timer);


int efrm_vi_attr_set_instance(struct efrm_vi_attr *attr,
			      struct efrm_vi_set *vi_set,
			      int instance_in_set)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	int end_of_set = vi_set->allocation.instance
		+ (1 << vi_set->allocation.order);
	if (instance_in_set >= 0 && instance_in_set < end_of_set) {
		a->vi_set = vi_set;
		a->vi_set_instance = instance_in_set;
		return 0;
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(efrm_vi_attr_set_instance);


int efrm_vi_attr_set_vf(struct efrm_vi_attr *attr, struct efrm_vf *vf)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->vf = vf;
	return 0;
}
EXPORT_SYMBOL(efrm_vi_attr_set_vf);


int efrm_vi_attr_set_interrupt_core(struct efrm_vi_attr *attr, int core_id)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->interrupt_core = core_id;
	return 0;
}
EXPORT_SYMBOL(efrm_vi_attr_set_interrupt_core);


int efrm_vi_attr_set_wakeup_channel(struct efrm_vi_attr *attr, int channel_id)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->channel = channel_id;
	return 0;
}
EXPORT_SYMBOL(efrm_vi_attr_set_wakeup_channel);


int  efrm_vi_alloc(struct efrm_client *client,
		   const struct efrm_vi_attr *o_attr,
		   struct efrm_vi **p_virs_out)
{
	struct efrm_vi_attr s_attr;
	struct efrm_vi *virs;
	struct vi_attr *attr;
	int rc, vi_flags = 0;
	struct efrm_pd *pd;

	if (o_attr == NULL) {
		efrm_vi_attr_init(&s_attr);
		o_attr = &s_attr;
	}
	attr = VI_ATTR_FROM_O_ATTR(o_attr);

	pd = NULL;
	if (attr->pd != NULL)
		pd = attr->pd;
	if (attr->vi_set != NULL)
		pd = attr->vi_set->pd;
	if (pd == NULL) {
		/* Legacy compatibility.  Create a [pd] from [client]. */
		if (client == NULL)
			return -EINVAL;
#ifdef CONFIG_SFC_RESOURCE_VF
		if (attr->vf != NULL &&
		    efrm_vf_to_resource(attr->vf)->rs_client != client)
			return -EINVAL;
#endif
		rc = efrm_pd_alloc(&pd, client, attr->vf, attr->vf != NULL);
		if (rc < 0)
			goto fail_alloc_pd;
	} else {
		efrm_resource_ref(efrm_pd_to_resource(pd));
		client = efrm_pd_to_resource(pd)->rs_client;
	}
	if (efrm_pd_owner_id(pd) == 0)
		vi_flags |= EFHW_VI_TX_PHYS_ADDR_EN | EFHW_VI_RX_PHYS_ADDR_EN;

	/* At this point we definitely have a valid [client] and a [pd]. */

	rc = -EINVAL;
	if (attr->with_interrupt && attr->with_timer)
		goto fail_checks;
	if (attr->vi_set != NULL) {
		struct efrm_resource *rs;
		rs = efrm_vi_set_to_resource(attr->vi_set);
		if (efrm_client_get_ifindex(rs->rs_client) !=
		    efrm_client_get_ifindex(client))
			goto fail_checks;
	}

	if (attr->with_interrupt)
		vi_flags |= EFHW_VI_RM_WITH_INTERRUPT;

	virs = kmalloc(sizeof(*virs), GFP_KERNEL);
	if (virs == NULL) {
		EFRM_ERR("%s: Out of memory", __FUNCTION__);
		rc = -ENOMEM;
		goto fail_alloc;
	}
	memset(virs, 0, sizeof(*virs));
	EFRM_ASSERT(&virs->rs == (struct efrm_resource *) (virs));

	rc = efrm_vi_rm_alloc_instance(pd, virs, attr);
	if (rc < 0) {
		efrm_vi_rm_salvage_flushed_vis(client->nic);
		rc = efrm_vi_rm_alloc_instance(pd, virs, attr);
	}
	if (rc < 0) {
		EFRM_ERR("%s: Out of VI instances (%d)", __FUNCTION__, rc);
		rc = -EBUSY;
		goto fail_alloc_id;
	}

	efrm_resource_init(&virs->rs, EFRM_RESOURCE_VI,
			   virs->allocation.instance);

	/* Start with one reference.  Any external VIs using the EVQ of
	 * this resource will increment this reference rather than the
	 * resource reference to avoid DMAQ flushes from waiting for other
	 * DMAQ flushes to complete.  When the resource reference goes to
	 * zero, the DMAQ flush happens.  When the flush completes, this
	 * reference is decremented.  When this reference reaches zero, the
	 * instance is freed.
	 */
	atomic_set(&virs->evq_refs, 1);
	virs->flags = vi_flags;
	virs->pd = pd;
#ifdef CONFIG_SFC_RESOURCE_VF
	if (virs->allocation.vf != NULL)
		efrm_vf_vi_set(virs);
#endif
	efrm_client_add_resource(client, &virs->rs);
	*p_virs_out = virs;
	return 0;


fail_alloc_id:
	kfree(virs);
fail_alloc:
fail_checks:
	efrm_pd_release(pd);
fail_alloc_pd:
	return rc;
}
EXPORT_SYMBOL(efrm_vi_alloc);


void efrm_vi_get_info(struct efrm_vi *virs,
		      struct efrm_vi_info *info_out)
{
	int instance = virs->rs.rs_instance;
	struct efhw_nic *nic = virs->rs.rs_client->nic;

	info_out->vi_window_base =
		nic->ctr_ap_dma_addr + falcon_tx_dma_page_base(instance);
	info_out->vi_instance = instance;
	info_out->vi_mem_mmap_bytes = virs->mem_mmap_bytes;
}
EXPORT_SYMBOL(efrm_vi_get_info);


int  efrm_vi_q_get_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			int n_q_entries, struct efrm_vi_q_size *qso)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;

	/* We return [q_sizes_supported] even if we fail. */
	qso->q_sizes_supported = nic->q_sizes[q_type];
	if (n_q_entries == EFRM_VI_Q_GET_SIZE_CURRENT)
		n_q_entries = virs->q[q_type].capacity;
	else
		n_q_entries = choose_size(n_q_entries, nic->q_sizes[q_type]);
	if (n_q_entries <= 0)
		return -EINVAL;

	qso->q_len_entries = n_q_entries;
	qso->q_len_bytes = efrm_vi_q_bytes(virs, q_type, n_q_entries);
	qso->q_len_page_order = get_order(qso->q_len_bytes);
	return 0;
}
EXPORT_SYMBOL(efrm_vi_q_get_size);


int
efrm_vi_q_init_common(struct efrm_vi *virs, enum efhw_q_type q_type,
		      int n_q_entries,
		      const dma_addr_t *dma_addrs, int dma_addrs_n,
		      int q_tag, unsigned q_flags)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[q_type];
	struct efrm_vi_q_size qsize;
	int n_pages, i;
	int mask;

	if (q->capacity != 0)
		return -EBUSY;

	switch (q_type) {
	case EFHW_TXQ:
		mask = (1 << FRF_AZ_RX_DESCQ_LABEL_WIDTH) - 1;
		if (q_tag != (q_tag & mask))
			return -EINVAL;
		break;
	case EFHW_RXQ:
		mask = (1 << FRF_AZ_TX_DESCQ_LABEL_WIDTH) - 1;
		if (q_tag != (q_tag & mask))
			return -EINVAL;
		break;
	case EFHW_EVQ:
		break;
	default:
		return -EINVAL;
	}

	if (n_q_entries != choose_size(n_q_entries, nic->q_sizes[q_type]))
		return -EINVAL;
	efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize);
	n_pages = 1 << qsize.q_len_page_order;
	if (n_pages > dma_addrs_n)
		return -EINVAL;

	q->page_order = qsize.q_len_page_order;
	q->tag = q_tag;
	q->flags = q_flags;
	q->capacity = qsize.q_len_entries;
	q->bytes = qsize.q_len_bytes;
	virs->flags |= q_flags_to_vi_flags(q_flags, q_type);
	for (i = 0; i < n_pages; ++i)
		q->dma_addrs[i] = dma_addrs[i];
	return 0;
}


static int efrm_vi_q_init_pf(struct efrm_vi *virs, enum efhw_q_type q_type,
			     const dma_addr_t *dma_addrs, int dma_addrs_n,
			     int q_tag, struct efrm_vi *evq)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc, i;

	if (evq == NULL)
		evq = virs;

	rc = efrm_nic_buffer_table_alloc(efrm_nic(nic), q->page_order,
					 &q->buf_tbl_alloc);
	if (rc != 0) {
		EFRM_ERR("%s: Failed to allocate %s buffer table entries",
			 __FUNCTION__, q_names[q_type]);
		return rc;
	}

	for (i = 0; i < (1 << q->page_order); ++i)
		efhw_nic_buffer_table_set(nic, q->dma_addrs[i],
					  0, 0, q->buf_tbl_alloc.base + i);
	falcon_nic_buffer_table_confirm(nic);

	if (q_type != EFHW_EVQ)
		efrm_vi_attach_evq(virs, q_type, evq);
	efrm_vi_rm_init_dmaq(virs, q_type, nic);
	return 0;
}


int efrm_vi_q_init(struct efrm_vi *virs, enum efhw_q_type q_type,
		   int n_q_entries,
		   const dma_addr_t *dma_addrs, int dma_addrs_n,
		   int q_tag, unsigned q_flags, struct efrm_vi *evq)
{
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc;

	rc = efrm_vi_q_init_common(virs, q_type, n_q_entries,
				   dma_addrs, dma_addrs_n, q_tag, q_flags);
	if (rc != 0)
		return rc;
	rc = efrm_vi_q_init_pf(virs, q_type, dma_addrs,
			       efhw_iopages_n_pages(&q->pages),
			       q_tag, evq);
	if (rc != 0)
		q->capacity = 0;
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_init);



int efrm_vi_q_reinit(struct efrm_vi *virs, enum efhw_q_type q_type)
{
	int i;
	struct efrm_vi_q *q;
	struct efhw_nic *nic;

	EFRM_WARN("%s: %p %d", __FUNCTION__, virs, q_type);

	q = &virs->q[q_type];
	nic = virs->rs.rs_client->nic;

	if (q->capacity == 0) 
		return -EINVAL;

	for (i = 0; i < (1 << q->page_order); ++i)
		efhw_nic_buffer_table_set(nic, q->dma_addrs[i],
					  0, 0, q->buf_tbl_alloc.base + i);
	falcon_nic_buffer_table_confirm(nic);

	efrm_vi_rm_init_dmaq(virs, q_type, nic);

	return 0;
}
EXPORT_SYMBOL(efrm_vi_q_reinit);
