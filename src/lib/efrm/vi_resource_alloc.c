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
#include <ci/efhw/eventq.h>
#include <ci/efhw/falcon.h> /*for falcon_nic_buffer_table_confirm*/
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/pio.h>
#include <ci/affinity/k_drv_intf.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"
#include "efrm_pd.h"
#include "bt_manager.h"


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

static int ci_ffs64(uint64_t x)
{
#if BITS_PER_LONG == 64
	return __builtin_ffsll(x);
#else
	uint32_t l = (uint32_t)x;
	uint32_t h;
	if (l) 
		return ffs(l);
	h = (uint32_t)(x >> 32);
	return ffs(h)+32;
#endif
}


/* Returns -ve code on error and 0 on success. */
static int efrm_vi_set_alloc_instance_try(struct efrm_vi *virs,
					  struct efrm_vi_set* vi_set,
					  int instance)
{
	assert_spin_locked(&vi_set->allocation_lock);
	if (instance != 0xff) {
		if (instance >= (1 << vi_set->allocation.order) ) {
			EFRM_ERR("%s: ERROR: vi_set instance=%d out-of-range "
				 "(size=%d)", __FUNCTION__, instance,
				 1 << vi_set->allocation.order);
			return -EINVAL;
		}
	} else {
		if ((instance = ci_ffs64(vi_set->free) - 1) < 0) {
			EFRM_TRACE("%s: ERROR: vi_set no free members",
				  __FUNCTION__);
			return -ENOSPC;
		}
	}

	if(! (vi_set->free & ((uint64_t)1 << instance))) {
		EFRM_TRACE("%s: instance %d already allocated.", __FUNCTION__,
			   instance);
		return -EEXIST;
	}

	EFRM_ASSERT(vi_set->free & ((uint64_t)1 << instance));
	vi_set->free &= ~((uint64_t)1 << instance);

	virs->allocation.instance = vi_set->allocation.instance + instance;
	virs->allocation.allocator_id = -1;
	virs->allocation.vf = vi_set->allocation.vf;
	virs->vi_set = vi_set;
	efrm_resource_ref(efrm_vi_set_to_resource(vi_set));
	return 0;
}


/* Try to allocate an instance out of the VIset.  If no free instances
 * and some instances are flushing, block.  Else return error.
 */
static int efrm_vi_set_alloc_instance(struct efrm_vi *virs,
				      struct efrm_vi_set* vi_set, int instance)
{
	int rc;
	while (1) {
		spin_lock(&vi_set->allocation_lock);
		rc = efrm_vi_set_alloc_instance_try(virs, vi_set, instance);
		EFRM_ASSERT(rc <= 0);
		if ((rc == -ENOSPC || rc == -EEXIST) &&
		    vi_set->n_vis_flushing > 0) {
			++vi_set->n_flushing_waiters;
			rc = 1;
		}
		spin_unlock(&vi_set->allocation_lock);
		if (rc != 1)
			return rc;
		EFRM_TRACE("%s: %d waiting for flush", __FUNCTION__,
			   current->pid);
		rc = wait_for_completion_interruptible(
			&vi_set->allocation_completion);
		spin_lock(&vi_set->allocation_lock);
		--vi_set->n_flushing_waiters;
		spin_unlock(&vi_set->allocation_lock);
		if (rc != 0)
			return rc;
	}
}


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

	if (vi_attr->vi_set != NULL)
		return efrm_vi_set_alloc_instance(virs, vi_attr->vi_set,
						  vi_attr->vi_set_instance);

#ifdef CONFIG_SFC_RESOURCE_VF
	vf = efrm_pd_get_vf(pd);
	if (vf != NULL)
		return efrm_vf_alloc_vi_set(vf, 1, &virs->allocation);
#endif

	efrm_nic = efrm_nic(efrm_pd_to_resource(pd)->rs_client->nic);
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
	virs->net_drv_wakeup_channel = channel;

	if (vi_attr->with_interrupt)
		vi_props = vi_with_interrupt;
	else
		vi_props = vi_with_timer;
	return efrm_vi_allocator_alloc_set(efrm_nic, vi_props, 1, 0,
					   channel, &virs->allocation);
}


static void efrm_vi_rm_free_instance(struct efrm_vi *virs)
{
	if (virs->vi_set != NULL) {
		struct efrm_vi_set* vi_set = virs->vi_set;
		int si = virs->allocation.instance -
			vi_set->allocation.instance;
		int need_complete;
		spin_lock(&vi_set->allocation_lock);
		EFRM_ASSERT((vi_set->free & (1 << si)) == 0);
		vi_set->free |= 1 << si;
		--vi_set->n_vis_flushing;
		need_complete = vi_set->n_flushing_waiters > 0;
		spin_unlock(&vi_set->allocation_lock);
		efrm_vi_set_release(vi_set);
		if (need_complete)
			complete(&vi_set->allocation_completion);
	}
#ifdef CONFIG_SFC_RESOURCE_VF
	else if (virs->allocation.vf != NULL) {
		efrm_vf_vi_drop(virs);
		efrm_vf_free_vi_set(&virs->allocation);
	}
#endif
	else {
		efrm_vi_allocator_free_set(efrm_nic(virs->rs.rs_client->nic),
					   &virs->allocation);
	}
}

/*** Queue sizes *********************************************************/

static int efrm_vi_is_phys(const struct efrm_vi* virs)
{
	return efrm_pd_owner_id(virs->pd) == 0;
}


uint32_t efrm_vi_rm_evq_bytes(struct efrm_vi *virs, int n_entries)
{
	if (n_entries < 0)
		n_entries = virs->q[EFHW_EVQ].capacity;
	return n_entries * sizeof(efhw_event_t);
}
EXPORT_SYMBOL(efrm_vi_rm_evq_bytes);


static uint32_t efrm_vi_rm_txq_bytes(struct efrm_vi *virs, int n_entries)
{
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
	if (nic->devtype.arch == EFHW_ARCH_EF10)
		return n_entries * EF10_DMA_TX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_FALCON)
		return n_entries * FALCON_DMA_TX_DESC_BYTES;
	else {
		EFRM_ASSERT(0);
		return -EINVAL;
	}
}


static uint32_t efrm_vi_rm_rxq_bytes(struct efrm_vi *virs, int n_entries)
{
	uint32_t bytes_per_desc;
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

	if (nic->devtype.arch == EFHW_ARCH_EF10)
		bytes_per_desc = EF10_DMA_RX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_FALCON)
		bytes_per_desc = efrm_vi_is_phys(virs)
			? FALCON_DMA_RX_PHYS_DESC_BYTES
			: FALCON_DMA_RX_BUF_DESC_BYTES;
	else {
		EFRM_ASSERT(0);	
		return -EINVAL;
	}
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
		break;
	case EFHW_RXQ:
		if (!(q_flags & EFRM_VI_CONTIGUOUS))
			vi_flags |= EFHW_VI_JUMBO_EN;
		if (q_flags & EFRM_VI_RX_TIMESTAMPS)
			vi_flags |= EFHW_VI_RX_PREFIX | EFHW_VI_RX_TIMESTAMPS;
		break;
	case EFHW_EVQ:
		if (q_flags & EFRM_VI_RX_TIMESTAMPS)
			vi_flags |= EFHW_VI_RX_TIMESTAMPS;
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
		break;
	case EFHW_RXQ:
		if (!(vi_flags & EFHW_VI_JUMBO_EN))
			q_flags |= EFRM_VI_CONTIGUOUS;
		if (vi_flags & EFHW_VI_RX_TIMESTAMPS)
			q_flags |= EFRM_VI_RX_TIMESTAMPS;
		break;
	case EFHW_EVQ:
		if (vi_flags & EFHW_VI_RX_TIMESTAMPS)
			q_flags |= EFRM_VI_RX_TIMESTAMPS;
		break;
	default:
		break;
	}

	return q_flags;
}


/*** Per-NIC allocations *************************************************/

int
efrm_vi_rm_init_dmaq(struct efrm_vi *virs, enum efhw_q_type queue_type,
		     struct efhw_nic *nic)
{
	int rc = 0;
	struct efrm_vi_q *q = &virs->q[queue_type];
	struct efrm_nic* efrm_nic;
	int instance, evq_instance, interrupting, wakeup_evq;
	unsigned flags = virs->flags;

	efrm_nic = efrm_nic(nic);
	instance = virs->rs.rs_instance;
	if (efrm_vi_is_phys(virs))
		flags |= EFHW_VI_TX_PHYS_ADDR_EN | EFHW_VI_RX_PHYS_ADDR_EN;

	switch (queue_type) {
	case EFHW_TXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
		rc = efhw_nic_dmaq_tx_q_init
			(nic, instance, evq_instance,
			 efrm_pd_owner_id(virs->pd),
			 virs->q[queue_type].tag, q->capacity,
			 efrm_bt_allocation_base(&q->bt_alloc),
			 q->dma_addrs,
			 (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
			 flags);
		break;
	case EFHW_RXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
                rc = efhw_nic_dmaq_rx_q_init
                       (nic, instance, evq_instance,
                        efrm_pd_owner_id(virs->pd),
                        virs->q[queue_type].tag, q->capacity,
                        efrm_bt_allocation_base(&q->bt_alloc),
                        q->dma_addrs,
                        (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
                        flags);
                if( rc >= 0 ) {
                  virs->rx_prefix_len = rc;
                  rc = 0;
                }
		break;
	case EFHW_EVQ:
		if (nic->devtype.arch == EFHW_ARCH_EF10)
			interrupting = (efrm_pd_get_vf(virs->pd) != NULL);
		else if (nic->devtype.arch ==  EFHW_ARCH_FALCON)
			/* make siena look like falcon */
			interrupting = instance<64 || efrm_pd_get_vf(virs->pd);
		else {
			EFRM_ASSERT(0);
			interrupting = 0;
		}
	
		wakeup_evq = virs->net_drv_wakeup_channel >= 0?
			virs->net_drv_wakeup_channel:
			efrm_nic->rss_channel_count == 0?
			0:
			instance % efrm_nic->rss_channel_count;
		/* NB. We do not enable DOS protection because of bug12916. */
		rc = efhw_nic_event_queue_enable
			(nic, instance, q->capacity,
			 efrm_bt_allocation_base(&q->bt_alloc),
			 q->dma_addrs,
			 (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
			 interrupting, 0 /* DOS protection */,
			 wakeup_evq,
			 (flags & EFHW_VI_RX_TIMESTAMPS) != 0,
			 &virs->rx_ts_correction);
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
	return rc;
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
		efhw_nic_pace(nic, instance, 0);
		break;
	case EFHW_EVQ:
		efhw_nic_event_queue_disable(nic, instance,
				(virs->flags & EFHW_VI_RX_TIMESTAMPS) != 0);
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
	if (q->bt_alloc.bta_size != 0)
		efrm_bt_manager_free(nic, &virs->bt_manager, &q->bt_alloc);
}


static int
efrm_vi_io_map(struct efrm_vi* virs, struct efhw_nic *nic, int instance)
{
	int offset;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_FALCON:
		offset = falcon_tx_dma_page_base(instance);
		virs->io_page = nic->bar_ioaddr + offset;
		break;
	case EFHW_ARCH_EF10:
		offset = instance * ER_DZ_EVQ_RPTR_REG_STEP;
		virs->io_page = ioremap_nocache(nic->ctr_ap_dma_addr +
						offset, PAGE_SIZE);
		if (virs->io_page == NULL)
			return -ENOMEM;
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
	return 0;
}


static void
efrm_vi_io_unmap(struct efrm_vi* virs)
{
	struct efhw_nic* nic = virs->rs.rs_client->nic;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_FALCON:
		break;
	case EFHW_ARCH_EF10:
		iounmap(virs->io_page);
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
}


static void
__efrm_vi_resource_free(struct efrm_vi *virs)
{
	struct efrm_nic *efrm_nic;
	int instance;
	int rc;

	EFRM_ASSERT(efrm_vi_manager);
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_vi_manager->rm);
	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 1);

	efrm_nic = efrm_nic(virs->rs.rs_client->nic);
	instance = virs->rs.rs_instance;

	EFRM_TRACE("%s: Freeing %d", __FUNCTION__, instance);
	EFRM_ASSERT(atomic_read(&virs->evq_refs) == 0);
	EFRM_ASSERT(virs->evq_callback_fn == NULL);
	EFRM_ASSERT(virs->q[EFHW_TXQ].evq_ref == NULL);
	EFRM_ASSERT(virs->q[EFHW_RXQ].evq_ref == NULL);

	if (virs->pio != NULL) {
		/* Unlink also manages reference accounting. */
		rc = efrm_pio_unlink_vi(virs->pio, virs);
		if (rc < 0)
			/* If txq has been flushed already, this can
			 * fail benignly */
			if (rc != -EALREADY)
				EFRM_ERR("%s: efrm_pio_unlink_vi failed: %d.\n",
					 __FUNCTION__, rc);
	}
	efrm_vi_rm_fini_dmaq(virs, EFHW_RXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_TXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_EVQ);
	efrm_vi_detach_evq(virs, EFHW_RXQ);
	efrm_vi_detach_evq(virs, EFHW_TXQ);
	if (virs->rs.rs_client->nic->devtype.arch == EFHW_ARCH_FALCON)
		efrm_bt_manager_dtor(&virs->bt_manager);
	efrm_vi_io_unmap(virs);
	efrm_vi_rm_free_instance(virs);
	efrm_pd_release(virs->pd);
	efrm_client_put(virs->rs.rs_client);
	EFRM_DO_DEBUG(memset(virs, 0, sizeof(*virs)));
	kfree(virs);
}

/*** Resource object  ****************************************************/

int
efrm_vi_q_alloc_sanitize_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			      int n_q_entries)
{
	struct efrm_vi_q_size qsize;
	if (n_q_entries == 0)
		return 0;
	if (n_q_entries < 0)
		n_q_entries = 1;
	if (efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize) < 0) {
		EFRM_ERR("%s: ERROR: bad %s size %d (supported=%x)",
			 __FUNCTION__, q_names[q_type],
			 virs->q[q_type].capacity,
			 virs->rs.rs_client->nic->q_sizes[q_type]);
		return -EINVAL;
	}
	return qsize.q_len_entries;
}
EXPORT_SYMBOL(efrm_vi_q_alloc_sanitize_size);


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
	if (n_q_entries < 0)
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

	dma_addrs_size = 1 << EFHW_GFP_ORDER_TO_NIC_ORDER(qsize.q_len_page_order);
	EFRM_ASSERT(dma_addrs_size <= EFRM_VI_MAX_DMA_ADDR);
	dma_addrs = kmalloc(sizeof(*dma_addrs) * dma_addrs_size, GFP_KERNEL);
	for (i = 0; i < dma_addrs_size; ++i)
		dma_addrs[i] = efhw_iopages_dma_addr(&q->pages, i);

	q_flags = vi_flags_to_q_flags(vi_flags, q_type);
	rc = efrm_vi_q_init(virs, q_type, qsize.q_len_entries,
			    dma_addrs,
			    efhw_iopages_n_pages(&q->pages) *
			      EFHW_NIC_PAGES_IN_OS_PAGE,
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
		       uint32_t *out_txq_capacity,
		       uint32_t *out_rxq_capacity)
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

	/* We have to jump through some hoops here:
	 * - EF10 needs the event queue allocated before rx and tx queues
	 * - Event queue needs to know the size of the rx and tx queues
	 *
	 * So we first work out the sizes, then create the evq, then create
	 * the rx and tx queues.
	 */

	rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_TXQ, txq_capacity);
	if (rc < 0)
		goto fail_q_alloc;
	txq_capacity = rc;
	
	rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_RXQ, rxq_capacity);
	if (rc < 0)
		goto fail_q_alloc;
	rxq_capacity = rc;

	if (evq_virs == NULL && evq_capacity < 0)
		evq_capacity = rxq_capacity + txq_capacity;

	if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
				  0, vi_flags, NULL)) < 0)
		goto fail_q_alloc;

	if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
				  tx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
				  rx_q_tag, vi_flags, evq_virs)) < 0)
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
	int set_size = 1 << vi_set->allocation.order;
	if (instance_in_set >= 0 && instance_in_set < set_size) {
		a->vi_set = vi_set;
		a->vi_set_instance = instance_in_set;
		return 0;
	} else if (instance_in_set < 0) {
		a->vi_set = vi_set;
		a->vi_set_instance = 0xff;
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

	efrm_vi_rm_salvage_flushed_vis(client->nic);
	rc = efrm_vi_rm_alloc_instance(pd, virs, attr);
	if (rc < 0) {
		EFRM_ERR("%s: Out of VI instances (%d)", __FUNCTION__, rc);
		rc = -EBUSY;
		goto fail_alloc_id;
	}
	rc = efrm_vi_io_map(virs, client->nic, virs->allocation.instance);
	if (rc < 0) {
		EFRM_ERR("%s: failed to I/O map id=%d (rc=%d)\n",
			 __FUNCTION__, virs->rs.rs_instance, rc);
		goto fail_mmap;
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
	if (client->nic->devtype.arch == EFHW_ARCH_FALCON)
		efrm_bt_manager_ctor(&virs->bt_manager,
				     0/*owner*/, 0/*order*/);

	efrm_client_add_resource(client, &virs->rs);
	*p_virs_out = virs;
	return 0;


fail_mmap:
	efrm_vi_rm_free_instance(virs);
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
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

	if (nic->devtype.arch == EFHW_ARCH_EF10)	
		info_out->vi_window_base = nic->ctr_ap_dma_addr + 
			ef10_tx_dma_page_base(instance);
	else if (nic->devtype.arch == EFHW_ARCH_FALCON)
		info_out->vi_window_base = nic->ctr_ap_dma_addr + 
			falcon_tx_dma_page_base(instance);
	else 
		EFRM_ASSERT(0);

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
	int n_pages, i, j;
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
	for (i = 0; i < n_pages; ++i) {
		for (j = 0; j < EFHW_NIC_PAGES_IN_OS_PAGE; ++j) {
			q->dma_addrs[i * EFHW_NIC_PAGES_IN_OS_PAGE + j] =
				dma_addrs[i] + EFHW_NIC_PAGE_SIZE * j;
		}
	}
	return 0;
}


static int efrm_vi_q_init_pf(struct efrm_vi *virs, enum efhw_q_type q_type,
			     const dma_addr_t *dma_addrs, int dma_addrs_n,
			     int q_tag, struct efrm_vi *evq)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc;

	if (evq == NULL)
		evq = virs;

	if (nic->devtype.arch == EFHW_ARCH_FALCON) {
		rc = efrm_bt_manager_alloc(nic, &virs->bt_manager,
				1 << EFHW_GFP_ORDER_TO_NIC_ORDER(q->page_order),
				&q->bt_alloc);
		if (rc != 0) {
			EFRM_ERR("%s: Failed to allocate %s "
				 "buffer table entries",
				 __FUNCTION__, q_names[q_type]);
			return rc;
		}

		efrm_bt_nic_set(nic, &q->bt_alloc, q->dma_addrs);
		falcon_nic_buffer_table_confirm(nic);
	}
	else
		q->bt_alloc.bta_size = 0;

	if (q_type != EFHW_EVQ)
		efrm_vi_attach_evq(virs, q_type, evq);
	rc = efrm_vi_rm_init_dmaq(virs, q_type, nic);
	if (rc != 0)
		if (nic->devtype.arch == EFHW_ARCH_FALCON)
			efrm_bt_manager_free(nic, &virs->bt_manager,
					     &q->bt_alloc);
	return rc;
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
	struct efrm_vi_q *q;
	struct efhw_nic *nic;

	EFRM_TRACE("%s: %p %d", __FUNCTION__, virs, q_type);

	q = &virs->q[q_type];
	nic = virs->rs.rs_client->nic;

	if (q->capacity == 0) 
		return -EINVAL;

	if (nic->devtype.arch == EFHW_ARCH_FALCON) {
		/* Ignore rc from efrm_bt_manager_realloc:
		 * it does not fail for Siena/Falcon. */
		efrm_bt_manager_realloc(nic, &virs->bt_manager,
					&q->bt_alloc);
		efrm_bt_nic_set(nic, &q->bt_alloc, q->dma_addrs);
		falcon_nic_buffer_table_confirm(nic);
	}

	return efrm_vi_rm_init_dmaq(virs, q_type, nic);
}
EXPORT_SYMBOL(efrm_vi_q_reinit);
