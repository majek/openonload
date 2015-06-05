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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for protection domain resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/private.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/vf_resource_private.h>
#include <ci/efhw/ef10.h>
#include "efrm_internal.h"
#include "bt_manager.h"
#include "efrm_pd.h"


#define N_OWNER_IDS_PER_WORD  	 (sizeof(unsigned long) * 8)
#define OWNER_ID_WORD_ALLOCATED  ((unsigned long) -1)

#define OWNER_ID_ALLOC_FAIL      -1

#define EFRM_PD_VPORT_ID_NONE    -1


struct efrm_pd {
	struct efrm_resource rs;
	/* [owner_id] is a token used by the NIC to authenticate access to
	 * the buffer table by a VI.  All VIs and memory regions in a
	 * protection domain use the same owner_id.
	 *
	 * If the [owner_id] is negative then the protection domain uses
	 * physical addresses.
	 */
	int owner_id;
#ifdef CONFIG_SFC_RESOURCE_VF
	/* If the protection domain is a VF, then [vf] will be non-null. */
	struct efrm_vf *vf;
#endif

	/* OS-specific data */
	void *os_data;

	/* This is the minimun alignment that all packet buffers to be
	 * mapped in should meet. */
	int min_nic_order;

	/* Identifies the virtual port we're using on the adapter.  This
	 * typically comes from driverlink (via efhw_nic.vport_id) but a PD
	 * can have its own unique vport.
	 */
	unsigned vport_id;

	/* stack_id required for self-traffic suppression during hw
	 * multicast loopback */
	int stack_id;

	/* Buffer table manager.  Needed iff vf==NULL.
	 * For Huntington, we'll need separate managers for different
	 * page orders.*/
	struct efrm_bt_manager bt_managers[0];

	/* !! DANGER !!  Do not add any fields here; bt_managers must be
	 * the last field.
	 */
};


struct efrm_pd_manager {
	struct efrm_resource_manager rm;
	/* TODO: ensure this doesn't wrap */
	unsigned next_instance;
};


struct efrm_pd_owner_ids {
	/* An owner id block allows allocation of n owner_ids.  The absolute
	 * value of the owner_id is relative to value base.  This allows
	 * a single owner_id space to be shared across pds on siena by basing
	 * owner_ids on base VI ID.  On ef10 all owner_ids are 0 based as they
	 * are function relative. */
	int base, n;
	unsigned long used_ids[1];
	/* When allocating an owner id block enough memory is allocated to
	 * continue the used_ids array sufficiently to contain n owner ids.
	 */
};


static struct efrm_pd_manager *pd_manager;


#define efrm_pd(rs1)  container_of((rs1), struct efrm_pd, rs)


static int efrm_pd_owner_id_alloc(struct efrm_pd_owner_ids* owner_ids)
{
	/* Must hold pd_manager lock. */
	int i;
	int n_owner_id_words = DIV_ROUND_UP(owner_ids->n, N_OWNER_IDS_PER_WORD);
	for (i = 0; i < n_owner_id_words; ++i)
		if (owner_ids->used_ids[i] != OWNER_ID_WORD_ALLOCATED) {
			i *= N_OWNER_IDS_PER_WORD;
			while (test_bit(i, owner_ids->used_ids))
				++i;
			if( i < owner_ids->n ) {
				__set_bit(i, owner_ids->used_ids);
				return i + owner_ids->base;
			}
			else {
				return OWNER_ID_ALLOC_FAIL;
			}
		}
	return OWNER_ID_ALLOC_FAIL;
}


static void efrm_pd_owner_id_free(struct efrm_pd_owner_ids* owner_ids,
				  int owner_id)
{
	/* Must hold pd_manager lock. */
	EFRM_ASSERT(test_bit(owner_id - owner_ids->base, owner_ids->used_ids));
	__clear_bit(owner_id - owner_ids->base, owner_ids->used_ids);
}


struct efrm_pd_owner_ids *efrm_pd_owner_ids_ctor(int base, int n)
{
	int extra_words = DIV_ROUND_UP(n, N_OWNER_IDS_PER_WORD) - 1;
	struct efrm_pd_owner_ids *owner_ids = kmalloc(
		sizeof(*owner_ids) + (extra_words * sizeof(owner_ids[0])),
		GFP_KERNEL);

	if( owner_ids ) {
		memset(owner_ids, 0, sizeof(*owner_ids) +
					(extra_words * sizeof(owner_ids[0])));
		owner_ids->n = n;
		owner_ids->base = base;
	}

	return owner_ids;
}


void efrm_pd_owner_ids_dtor(struct efrm_pd_owner_ids* owner_ids)
{
	kfree(owner_ids);
}


/***********************************************************************/
/* Stack ids */
/***********************************************************************/

static int efrm_pd_stack_id_alloc(struct efrm_pd *pd)
{
	struct efrm_nic *nic = efrm_nic(pd->rs.rs_client->nic);
	const int word_bitcount = sizeof(*nic->stack_id_usage) * 8;
	int i, v, bitno, id;

	spin_lock(&nic->lock);
	for (i = 0; i < sizeof(nic->stack_id_usage) /
		     sizeof(*nic->stack_id_usage) &&
		     ((v = nic->stack_id_usage[i]) == ~0u); ++i)
		;
	bitno = v ? ci_ffs64(~v) - 1 : 0;
	id = i * word_bitcount + bitno + 1;
	if (id <= EFRM_MAX_STACK_ID)
		nic->stack_id_usage[i] |= 1 << bitno;
	spin_unlock(&nic->lock);

	if (id > EFRM_MAX_STACK_ID) {
		/* we run out of stack ids suppression of self traffic
		 * is not possible. */
		EFRM_TRACE("%s: WARNING: no free stack ids", __FUNCTION__);
		pd->stack_id = 0;
		return -ENOMEM;
	}
	pd->stack_id = id;
	return 0;
}


static void efrm_pd_stack_id_free(struct efrm_pd *pd)
{
	if (pd->stack_id != 0) {
		struct efrm_nic *nic = efrm_nic(pd->rs.rs_client->nic);
		const int word_bitcount = sizeof(*nic->stack_id_usage) * 8;
		int id = pd->stack_id - 1;
		int i = id / word_bitcount;
		int bitno = id % word_bitcount;
		spin_lock(&nic->lock);
		nic->stack_id_usage[i] &= ~(1 << bitno);
		spin_unlock(&nic->lock);
	}
}


unsigned efrm_pd_stack_id_get(struct efrm_pd *pd)
{
	return pd->stack_id;
}
EXPORT_SYMBOL(efrm_pd_stack_id_get);


/***********************************************************************/

int efrm_pd_alloc(struct efrm_pd **pd_out, struct efrm_client *client_opt,
		  struct efrm_vf *vf_opt, int flags)
{
	struct efrm_pd *pd;
	int rc, instance;
	struct efrm_pd_owner_ids *owner_ids;
	int orders_num = 0;


	EFRM_ASSERT((client_opt != NULL) || (vf_opt != NULL));
	if ((flags &
	    ~(EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE |
	    EFRM_PD_ALLOC_FLAG_HW_LOOPBACK)) != 0) {
		rc = -EINVAL;
		goto fail1;
	}

	if (!(flags & EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE)) {
		orders_num = efhw_nic_buffer_table_orders_num(
						client_opt->nic);
		EFRM_ASSERT(orders_num);
		EFRM_ASSERT(efhw_nic_buffer_table_orders(
						client_opt->nic)[0] == 0);
	}
	pd = kmalloc(sizeof(*pd) + orders_num * sizeof(pd->bt_managers[0]),
		     GFP_KERNEL);
	if (pd == NULL) {
		rc = -ENOMEM;
		goto fail1;
	}
	pd->stack_id = 0;

	spin_lock_bh(&pd_manager->rm.rm_lock);
	instance = pd_manager->next_instance++;
	if (flags & EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE) {
		pd->owner_id = OWNER_ID_PHYS_MODE;
	}
	else {
#ifdef CONFIG_SFC_RESOURCE_VF
		if (vf_opt != NULL)
			owner_ids = vf_opt->owner_ids;
		else
#endif
		owner_ids = efrm_nic_from_client(client_opt)->owner_ids;
		EFRM_ASSERT(owner_ids != NULL);
		pd->owner_id = efrm_pd_owner_id_alloc(owner_ids);
	}
	spin_unlock_bh(&pd_manager->rm.rm_lock);
	if (pd->owner_id == OWNER_ID_ALLOC_FAIL) {
		rc = -EBUSY;
		goto fail2;
	}
#ifdef CONFIG_SFC_RESOURCE_VF
	pd->vf = vf_opt;
	if (pd->vf != NULL) {
		struct efrm_resource *vfrs = efrm_vf_to_resource(pd->vf);
		efrm_resource_ref(vfrs);
		client_opt = vfrs->rs_client;
	}
#endif
	if (!(flags & EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE)) {
		int ord;
		for (ord = 0; ord < orders_num; ord++) {
			efrm_bt_manager_ctor(
				&pd->bt_managers[ord], pd->owner_id,
				efhw_nic_buffer_table_orders(
						client_opt->nic)[ord]
				);
		}
	}
	efrm_resource_init(&pd->rs, EFRM_RESOURCE_PD, instance);
	efrm_client_add_resource(client_opt, &pd->rs);

	pd->os_data = efrm_pd_os_stats_ctor(pd);
	pd->min_nic_order = 0;
	pd->vport_id = EFRM_PD_VPORT_ID_NONE;

	if (flags & EFRM_PD_ALLOC_FLAG_HW_LOOPBACK) {
		if ((rc = efrm_pd_stack_id_alloc(pd)) != 0) {
			efrm_pd_release(pd);
			return rc;
		}
	}

	*pd_out = pd;
	return 0;


fail2:
	kfree(pd);
fail1:
	return rc;
}
EXPORT_SYMBOL(efrm_pd_alloc);


void efrm_pd_release(struct efrm_pd *pd)
{
	if (__efrm_resource_release(&pd->rs))
		efrm_pd_free(pd);
}
EXPORT_SYMBOL(efrm_pd_release);


void efrm_pd_free(struct efrm_pd *pd)
{
	struct efrm_pd_owner_ids *owner_ids;

	efrm_pd_os_stats_dtor(pd, pd->os_data);

	if (pd->vport_id != EFRM_PD_VPORT_ID_NONE)
		ef10_vport_free(pd->rs.rs_client->nic, pd->vport_id);

	efrm_pd_stack_id_free(pd);

	spin_lock_bh(&pd_manager->rm.rm_lock);
	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
#ifdef CONFIG_SFC_RESOURCE_VF
		if (pd->vf)
			owner_ids = pd->vf->owner_ids;
		else
#endif
		owner_ids = efrm_nic_from_rs(&pd->rs)->owner_ids;
		EFRM_ASSERT(owner_ids != NULL);
		efrm_pd_owner_id_free(owner_ids, pd->owner_id);
	}
	spin_unlock_bh(&pd_manager->rm.rm_lock);
#ifdef CONFIG_SFC_RESOURCE_VF
	if (pd->vf != NULL)
		efrm_vf_resource_release(pd->vf);
#endif
	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
		int ord;
		for (ord = 0;
		     ord < efhw_nic_buffer_table_orders_num(
					pd->rs.rs_client->nic);
		     ord++)
			efrm_bt_manager_dtor(&pd->bt_managers[ord]);
	}
	efrm_client_put(pd->rs.rs_client);
	kfree(pd);
}


struct efrm_resource * efrm_pd_to_resource(struct efrm_pd *pd)
{
	return &pd->rs;
}
EXPORT_SYMBOL(efrm_pd_to_resource);


struct efrm_pd * efrm_pd_from_resource(struct efrm_resource *rs)
{
	return efrm_pd(rs);
}
EXPORT_SYMBOL(efrm_pd_from_resource);


int efrm_pd_owner_id(struct efrm_pd *pd)
{
	return pd->owner_id;
}
EXPORT_SYMBOL(efrm_pd_owner_id);


void efrm_pd_set_min_align(struct efrm_pd *pd, int alignment)
{
	pd->min_nic_order = __ffs((alignment) >> EFHW_NIC_PAGE_SHIFT);
}
EXPORT_SYMBOL(efrm_pd_set_min_align);


int efrm_pd_get_min_align(struct efrm_pd *pd)
{
	return ((1 << pd->min_nic_order) << EFHW_NIC_PAGE_SHIFT);
}
EXPORT_SYMBOL(efrm_pd_get_min_align);


struct efrm_vf *efrm_pd_get_vf(struct efrm_pd *pd)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	return pd->vf;
#else
	return NULL;
#endif
}


struct pci_dev *efrm_pd_get_pci_dev(struct efrm_pd *pd)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	if (pd->vf)
		return pd->vf->pci_dev;
	else
#endif
		return pd->rs.rs_client->nic->pci_dev;
}


int efrm_pd_share_dma_mapping(struct efrm_pd *pd, struct efrm_pd *pd1)
{
#ifndef CONFIG_SFC_RESOURCE_VF_IOMMU
	return false;
#else
	efhw_iommu_domain *dom, *dom1;

	if (pd->owner_id != OWNER_ID_PHYS_MODE ||
	    pd1->owner_id != OWNER_ID_PHYS_MODE)
		return false;

	if (pd->vf == NULL || pd1->vf == NULL)
		return false;

	dom = efrm_vf_get_iommu_domain(pd->vf);
	dom1 = efrm_vf_get_iommu_domain(pd1->vf);
	if (dom == NULL || dom1 == NULL)
		return false;
	if (dom != dom1)
		return false;
	return true;
#endif
}
EXPORT_SYMBOL(efrm_pd_share_dma_mapping);


int
efrm_pd_has_vport(struct efrm_pd *pd)
{
	return pd->vport_id != EFRM_PD_VPORT_ID_NONE;
}
EXPORT_SYMBOL(efrm_pd_has_vport);


unsigned
efrm_pd_get_vport_id(struct efrm_pd *pd)
{
	if (pd->vport_id == EFRM_PD_VPORT_ID_NONE)
		return pd->rs.rs_client->nic->vport_id;
	else
		return pd->vport_id;
}
EXPORT_SYMBOL(efrm_pd_get_vport_id);


int
efrm_pd_vport_alloc(struct efrm_pd *pd, int vlan_id)
{
	unsigned vport_id;
	int rc;

	if (pd->vport_id != EFRM_PD_VPORT_ID_NONE)
		return -EBUSY;
	rc = ef10_vport_alloc(pd->rs.rs_client->nic, vlan_id, &vport_id);
	if (rc == 0)
		pd->vport_id = vport_id;
	return rc;
}
EXPORT_SYMBOL(efrm_pd_vport_alloc);

/**********************************************************************/


#define NIC_ORDER_TO_BYTES(nic_order) \
  ((size_t)EFHW_NIC_PAGE_SIZE << (size_t)(nic_order))

static void efrm_pd_dma_unmap_pci(struct pci_dev *pci_dev,
				  int n_pages, int nic_order,
				  dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	while (--n_pages >= 0) {
		dma_unmap_single(&pci_dev->dev, *pci_addrs,
				 NIC_ORDER_TO_BYTES(nic_order),
				 DMA_BIDIRECTIONAL);
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
}


static int efrm_pd_dma_map_pci(struct pci_dev *pci_dev,
			       int n_pages, int nic_order,
			       void **addrs, int addrs_stride,
			       dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	int i;

	for (i = 0; i < n_pages; ++i) {
		*pci_addrs = dma_map_single(&pci_dev->dev, *addrs,
					    NIC_ORDER_TO_BYTES(nic_order),
					    DMA_BIDIRECTIONAL);
		if (dma_mapping_error(&pci_dev->dev, *pci_addrs)) {
			EFRM_ERR("%s: ERROR: dma_map_single failed",
				 __FUNCTION__);
			goto fail;
		}
		addrs = (void *)((char *)addrs + addrs_stride);
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
	return 0;

fail:
	pci_addrs = (void *)((char *)pci_addrs - i * pci_addrs_stride);
	addrs = (void *)((char *)addrs - i * addrs_stride);
	efrm_pd_dma_unmap_pci(pci_dev, i, nic_order,
			      pci_addrs, pci_addrs_stride);
	return -ENOMEM;
}


#ifdef CONFIG_SFC_RESOURCE_VF
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
static void efrm_pd_dma_unmap_iommu(efhw_iommu_domain *iommu_domain,
				    int n_pages, int nic_order,
				    dma_addr_t *pci_addrs,
				    int pci_addrs_stride)
{
	while (--n_pages >= 0) {
		mutex_lock(&efrm_iommu_mutex);
		iommu_unmap(iommu_domain, *pci_addrs,
			    NIC_ORDER_TO_BYTES(nic_order));
		mutex_unlock(&efrm_iommu_mutex);
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
}


static int efrm_pd_dma_map_iommu(efhw_iommu_domain *iommu_domain,
				 unsigned long iovaddr,
				 int n_pages, int nic_order,
				 void **addrs, int addrs_stride,
				 dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	/* TODO: Is there any benefit to mapping larger chunks? */

	int i, rc;

	for (i = 0; i < n_pages; ++i) {
		rc = iommu_map(iommu_domain, iovaddr,
			       __pa(*addrs),
			       NIC_ORDER_TO_BYTES(nic_order),
			       IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: iommu_map failed (%d)",
				 __FUNCTION__, rc);
			goto fail;
		}
		*pci_addrs = iovaddr;
		iovaddr += NIC_ORDER_TO_BYTES(nic_order),
		addrs = (void *)((char *)addrs + addrs_stride);
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
	return 0;

fail:
	pci_addrs = (void *)((char *)pci_addrs - i * pci_addrs_stride);
	addrs = (void *)((char *)addrs - i * addrs_stride);
	efrm_pd_dma_unmap_iommu(iommu_domain, i, nic_order,
				pci_addrs, pci_addrs_stride);
	return rc;
}
#endif

static void efrm_pd_dma_unmap_vf(struct efrm_pd *pd,
				 int n_pages, int nic_order,
				 dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	efhw_iommu_domain *iommu_domain;
	efrm_vf_alloc_ioaddrs(pd->vf, 0, &iommu_domain);

#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
	if (iommu_domain != NULL)
		efrm_pd_dma_unmap_iommu(iommu_domain, n_pages, nic_order,
				        pci_addrs, pci_addrs_stride);
	else
#endif
		efrm_pd_dma_unmap_pci(pd->vf->pci_dev, n_pages, nic_order,
				      pci_addrs, pci_addrs_stride);
}


static int efrm_pd_dma_map_vf(struct efrm_pd *pd, int n_pages, int nic_order,
			      void **addrs, int addrs_stride,
			      dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	efhw_iommu_domain *iommu_domain;
	unsigned long iovaddr;
	int n_sys_pages;

	n_sys_pages = ((n_pages * NIC_ORDER_TO_BYTES(nic_order) +
				PAGE_SIZE - 1) & PAGE_MASK) >> PAGE_SHIFT;

	iovaddr = efrm_vf_alloc_ioaddrs(pd->vf, n_sys_pages,
					&iommu_domain);

#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
	if (iommu_domain != NULL)
		return efrm_pd_dma_map_iommu(iommu_domain, iovaddr,
					     n_pages, nic_order,
					     addrs, addrs_stride,
					     pci_addrs, pci_addrs_stride);
	else
#endif
		return efrm_pd_dma_map_pci(pd->vf->pci_dev,
					   n_pages, nic_order,
					   addrs, addrs_stride,
					   pci_addrs, pci_addrs_stride);
}
#endif


static void efrm_pd_dma_unmap_nic(struct efrm_pd *pd,
				  int n_pages, int nic_order,
				  dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	efrm_pd_dma_unmap_pci(efrm_client_get_nic(pd->rs.rs_client)->pci_dev,
			      n_pages, nic_order,
			      pci_addrs, pci_addrs_stride);
}


static int efrm_pd_dma_map_nic(struct efrm_pd *pd,
			       int n_pages, int nic_order,
			       void **addrs, int addrs_stride,
			       dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	return efrm_pd_dma_map_pci(
			efrm_client_get_nic(pd->rs.rs_client)->pci_dev,
			n_pages, nic_order, addrs, addrs_stride,
			pci_addrs, pci_addrs_stride);
}


static inline int efrm_pd_bt_find_order_idx(struct efrm_pd *pd,
					    int max_order)
{
	int ord_idx;

	ord_idx = efhw_nic_buffer_table_orders_num(pd->rs.rs_client->nic) - 1;
	while (pd->bt_managers[ord_idx].order > max_order) {
		ord_idx--;
		EFRM_ASSERT(ord_idx >= 0);
	}

	return ord_idx;
}

static void efrm_pd_dma_unmap_bt(struct efrm_pd *pd,
				 struct efrm_bt_collection *bt_alloc)
{
	int ord_idx;
	int i;

	for (i = 0; i < bt_alloc->num_allocs; i++) {
		if (bt_alloc->allocs[i].bta_size == 0)
			break;
		ord_idx = efrm_pd_bt_find_order_idx(
				pd, bt_alloc->allocs[i].bta_order);

		efrm_bt_manager_free(efrm_client_get_nic(pd->rs.rs_client),
				     &pd->bt_managers[ord_idx],
				     &bt_alloc->allocs[i]);
	}

	kfree(bt_alloc->allocs);
}


static int efrm_pd_bt_map(struct efrm_pd *pd, int n_pages, int nic_order,
			  dma_addr_t *pci_addrs, int pci_addrs_stride,
			  uint64_t *user_addrs, int user_addrs_stride,
			  void (*user_addr_put)(uint64_t, uint64_t *),
			  struct efrm_bt_collection *bt_alloc)
{
	int i, n, first, rc, rc1 = 0;
	dma_addr_t *dma_addrs;
	uint64_t user_addr;
	struct efhw_buffer_table_block *block;
	int dma_size, bt_num;
	dma_addr_t page_offset;

	EFRM_ASSERT(pd->owner_id != OWNER_ID_PHYS_MODE);

	dma_size = 0;
	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		if (dma_size < bt_alloc->allocs[bt_num].bta_size)
			dma_size = bt_alloc->allocs[bt_num].bta_size;
	}
	dma_addrs = kmalloc(dma_size * sizeof(dma_addr_t), GFP_ATOMIC);
	/* We should not get this far without setting up at least one
	 * buffer table allocation.
	 */
	EFRM_ASSERT(dma_size != 0);
	if (dma_addrs == NULL)
		return -ENOMEM;

	/* Program dma address for the buffer table entries. */
	page_offset = 0;
	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		for (i = 0; i < bt_alloc->allocs[bt_num].bta_size; i++) {
			dma_addrs[i] = *pci_addrs + page_offset;
			page_offset += NIC_ORDER_TO_BYTES(
				bt_alloc->allocs[bt_num].bta_order);
			if (page_offset == NIC_ORDER_TO_BYTES(nic_order)) {
				page_offset = 0;
				pci_addrs++;
			}
		}
		rc = efrm_bt_nic_set(efrm_client_get_nic(pd->rs.rs_client),
				     &bt_alloc->allocs[bt_num], dma_addrs);
		if( rc != 0 ) {
			if( ~bt_alloc->allocs[bt_num].bta_flags & 
			    EFRM_BTA_FLAG_IN_RESET ) {
				kfree(dma_addrs);
				return rc;
			}
			rc1 = rc;
		}
	}
	kfree(dma_addrs);

	/* Copy buftable addresses to user. */
	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		block = bt_alloc->allocs[bt_num].bta_blocks;
		n = bt_alloc->allocs[bt_num].bta_size;
		first = bt_alloc->allocs[bt_num].bta_first_entry_offset;
		do {
			user_addr = block->btb_vaddr +
				(first << (EFHW_NIC_PAGE_SHIFT +
					   bt_alloc->allocs[bt_num].bta_order));
			first = 0;
			for (i = 0;
			     i < min(n, EFHW_BUFFER_TABLE_BLOCK_SIZE) <<
					bt_alloc->allocs[bt_num].bta_order;
			     i++) {
				user_addr_put(user_addr, user_addrs);
				user_addrs = (void *)((char *)user_addrs +
						      user_addrs_stride);
				user_addr += EFHW_NIC_PAGE_SIZE;
			}
			block = block->btb_next;
			n -= EFHW_BUFFER_TABLE_BLOCK_SIZE;
		} while (n > 0);
	}

	return rc1;
}

/* Check that PCI addresses are properly aligned for the buffer table
 * pages we have selected. */
static inline int
efrm_pd_nic_order_fixup(struct efrm_pd *pd, int ord_idx, int n_pages,
			dma_addr_t *pci_addrs, int pci_addrs_stride)
{
	dma_addr_t pci_addr_or = 0;
	int i;

	if (ord_idx == 0)
		return 0;

	for (i =0; i < n_pages; i++) {
		pci_addr_or |= *pci_addrs;
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
	EFRM_ASSERT((pci_addr_or & (EFHW_NIC_PAGE_SIZE - 1)) == 0);
	pci_addr_or >>= EFHW_NIC_PAGE_SHIFT;

	if (pci_addr_or & ((1 << pd->bt_managers[ord_idx].order) - 1))
		return efrm_pd_bt_find_order_idx(pd, __ffs(pci_addr_or));

	return ord_idx;
}

static inline int efrm_pd_bt_alloc(struct efrm_pd *pd, size_t bytes,
				   int ord_idx,
				   struct efrm_buffer_table_allocation *bt)
{
	return efrm_bt_manager_alloc(efrm_client_get_nic(pd->rs.rs_client),
				    &pd->bt_managers[ord_idx],
				    bytes >> (EFHW_NIC_PAGE_SHIFT +
					      pd->bt_managers[ord_idx].order),
				    bt);
}

static int
efrm_pd_bt_alloc_unaligned(struct efrm_pd *pd, int n_pages, int nic_order,
			   dma_addr_t *pci_addrs, int pci_addrs_stride,
			   struct efrm_bt_collection *bt_alloc,
			   int ord_idx, int ord_idx_min)
{
	int ord_idx_mid = ord_idx;
	int bt_num, i;
	int rc = 0;
	dma_addr_t mask = (EFHW_NIC_PAGE_SIZE <<
			   pd->bt_managers[ord_idx].order) - 1;
	dma_addr_t mask_mid = mask;

	/* ord_idx_min: bt order which can always be used: everything is
	 * aligned.
	 * ord_idx: bt order we'd like to use if the dma address is
	 * aligned.
	 * Else we map non-aligned parts with ord_idx_min, and
	 * use ord_idx or (ord_idx-1) for the middle.
	 */
	bt_alloc->num_allocs = n_pages * 3;
	if (nic_order == pd->bt_managers[ord_idx].order) {
		ord_idx_mid = ord_idx - 1;
		mask_mid = NIC_ORDER_TO_BYTES(
				pd->bt_managers[ord_idx_mid].order) - 1;
		if (ord_idx_mid == ord_idx_min)
			bt_alloc->num_allocs = n_pages;
	}
	EFRM_ASSERT(ord_idx_mid >= ord_idx_min);

	bt_alloc->allocs = kmalloc(
			sizeof(struct efrm_buffer_table_allocation) *
						bt_alloc->num_allocs,
			GFP_ATOMIC);
	memset(bt_alloc->allocs, 0,
	       sizeof(struct efrm_buffer_table_allocation) *
	       bt_alloc->num_allocs);
	if (bt_alloc->allocs == NULL)
		return -ENOMEM;

	bt_num = 0;
	for (i = 0; i < n_pages; i++) {
		if ((*pci_addrs & mask) == 0) {
			/* Aligned page: map it */
			rc = efrm_pd_bt_alloc(
				pd, NIC_ORDER_TO_BYTES(nic_order), ord_idx,
				&bt_alloc->allocs[bt_num++]);
			if( rc != 0 )
				break;
		}
		else if ((*pci_addrs & mask_mid) == 0) {
			/* Aligned page, smaller order: map it */
			rc = efrm_pd_bt_alloc(pd, NIC_ORDER_TO_BYTES(nic_order),
					      ord_idx_mid,
					      &bt_alloc->allocs[bt_num++]);
			if( rc != 0 )
				break;
		}
		else {
			/* Non-aligned page: map non-aligned pieces
			 * separately. */
			rc = efrm_pd_bt_alloc(
				pd,
				((mask_mid + 1) - ((*pci_addrs) & mask_mid)),
				ord_idx_min,
				&bt_alloc->allocs[bt_num++]);
			if (rc != 0)
				break;
			rc = efrm_pd_bt_alloc(
				pd,
				NIC_ORDER_TO_BYTES(nic_order) - (mask_mid + 1),
				ord_idx_mid,
				&bt_alloc->allocs[bt_num++]);
			if (rc != 0)
				break;
			rc = efrm_pd_bt_alloc(
				pd,
				((*pci_addrs) & mask_mid),
				ord_idx_min,
				&bt_alloc->allocs[bt_num++]);
			if (rc != 0)
				break;
		}
		EFRM_ASSERT(bt_num <= bt_alloc->num_allocs);
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}

	if (rc != 0)
		efrm_pd_dma_unmap_bt(pd, bt_alloc);
	return rc;
}

static int efrm_pd_dma_map_bt(struct efrm_pd *pd, int n_pages, int nic_order,
			      dma_addr_t *pci_addrs, int pci_addrs_stride,
			      uint64_t *user_addrs, int user_addrs_stride,
			      void (*user_addr_put)(uint64_t, uint64_t *),
			      struct efrm_bt_collection *bt_alloc)
{
	int rc = 0;
	int ord_idx, ord_idx_min;

	ord_idx = efrm_pd_bt_find_order_idx(pd, nic_order);
	ord_idx_min = efrm_pd_nic_order_fixup(pd, ord_idx, n_pages,
					      pci_addrs, pci_addrs_stride);

	if (pd->min_nic_order > pd->bt_managers[ord_idx_min].order) {
		EFRM_ERR("%s: ERROR: insufficient DMA mapping alignment "
			 "(required=%d got=%d)", __FUNCTION__,
			 pd->min_nic_order, pd->bt_managers[ord_idx_min].order);
		return -EFAULT;
	}

	if (ord_idx == ord_idx_min) {
		bt_alloc->num_allocs = 1;
		bt_alloc->allocs = kmalloc(
			sizeof(struct efrm_buffer_table_allocation),
			GFP_ATOMIC);
		if (bt_alloc->allocs == NULL)
			return -ENOMEM;
		rc = efrm_pd_bt_alloc(
				pd, n_pages * NIC_ORDER_TO_BYTES(nic_order),
				ord_idx, &bt_alloc->allocs[0]);
	}
	else {
		rc = efrm_pd_bt_alloc_unaligned(pd, n_pages, nic_order,
						pci_addrs, pci_addrs_stride,
						bt_alloc,
						ord_idx, ord_idx_min);
	}

	if (rc < 0) {
		EFRM_ERR("%s: ERROR: buffer table entry allocation failed "
			 "(%d pages nic_order %d) rc=%d",
			 __FUNCTION__, n_pages, nic_order, rc);
		return rc;
	}

	rc = efrm_pd_bt_map(pd, n_pages, nic_order,
			    pci_addrs, pci_addrs_stride,
			    user_addrs, user_addrs_stride,
			    user_addr_put, bt_alloc);
	if (rc == 0)
		return rc;

	/* Error: free already-allocated buftable entries */
	efrm_pd_dma_unmap_bt(pd, bt_alloc);
	return rc;
}


static int efrm_pd_check_pci_addr_alignment(struct efrm_pd *pd,
					    dma_addr_t *pci_addrs,
					    int pci_addrs_stride, int n_pages)
{
	dma_addr_t pci_addr_or = 0;
	int pci_addr_ord;
	int i;

	for (i = 0; i < n_pages; i++) {
		pci_addr_or |= *pci_addrs;
		pci_addrs = (void*)((char*)pci_addrs + pci_addrs_stride);
	}
	EFRM_ASSERT((pci_addr_or & (EFHW_NIC_PAGE_SIZE - 1)) == 0);
	pci_addr_ord = __ffs(pci_addr_or >> EFHW_NIC_PAGE_SHIFT);

	if (pd->min_nic_order > pci_addr_ord) {
		EFRM_ERR("%s: ERROR: insufficient DMA mapping alignment "
			 "(required=%d got=%d)", __FUNCTION__,
			 pd->min_nic_order, pci_addr_ord);
		return -EPROTO;
	}
	return 0;
}


static void efrm_pd_copy_user_addrs(struct efrm_pd *pd,
			    int n_pages, int nic_order,
			    dma_addr_t *pci_addrs, int pci_addrs_stride,
			    uint64_t *user_addrs, int user_addrs_stride,
			    void (*user_addr_put)(uint64_t, uint64_t *))
{
	int i, j;

	/* user_addrs is for pages of size EFHW_NIC_PAGE_SIZE, always */
	for (i = 0; i < n_pages; ++i) {
		for (j = 0; j < 1 << nic_order; j++) {
			user_addr_put(*pci_addrs + EFHW_NIC_PAGE_SIZE * j,
				      user_addrs);
			user_addrs = (void *)((char *)user_addrs +
					      user_addrs_stride);
		}
		pci_addrs = (void *)((char *)pci_addrs + pci_addrs_stride);
	}
}


int efrm_pd_dma_remap_bt(struct efrm_pd *pd, int n_pages, int nic_order,
			 dma_addr_t *pci_addrs, int pci_addrs_stride,
			 uint64_t *user_addrs, int user_addrs_stride,
			 void (*user_addr_put)(uint64_t, uint64_t *),
			 struct efrm_bt_collection *bt_alloc)
{
	int rc, rc1 = 0;
	int bt_num;

	if (pd->owner_id == OWNER_ID_PHYS_MODE)
		return -ENOSYS;

	for (bt_num = 0; bt_num < bt_alloc->num_allocs; bt_num++) {
		int ord_idx;
		if (bt_alloc->allocs[bt_num].bta_size == 0)
			break;
		ord_idx = efrm_pd_bt_find_order_idx(
				pd, bt_alloc->allocs[bt_num].bta_order);
		rc = efrm_bt_manager_realloc(
				efrm_client_get_nic(pd->rs.rs_client),
				&pd->bt_managers[ord_idx],
				&bt_alloc->allocs[bt_num]);
		if (rc != 0 && rc1 == 0)
			rc1 = rc;
	}

	if (rc1 != 0)
		return rc1;
	return efrm_pd_bt_map(pd, n_pages, nic_order,
			      pci_addrs, pci_addrs_stride,
			      user_addrs, user_addrs_stride,
			      user_addr_put, bt_alloc);
}
EXPORT_SYMBOL(efrm_pd_dma_remap_bt);


int efrm_pd_dma_map(struct efrm_pd *pd, int n_pages, int nic_order,
		    void **addrs, int addrs_stride,
		    void *p_pci_addrs, int pci_addrs_stride,
		    uint64_t *user_addrs, int user_addrs_stride,
		    void (*user_addr_put)(uint64_t, uint64_t *),
		    struct efrm_bt_collection *bt_alloc)
{
	dma_addr_t *pci_addrs = p_pci_addrs;
	int rc;

	/* This checks that physical memory meets the alignment
	 * requirement.  We also check that the DMA addresses meet the
	 * alignment requirements further below: in
	 * efrm_pd_dma_map_bt() and efrm_pd_check_pci_addr_alignment().
	 */
	if (pd->min_nic_order > nic_order) {
		EFRM_ERR("%s: ERROR: min_nic_order(%d) > nic_order(%d)",
			 __FUNCTION__, pd->min_nic_order, nic_order);
		return -EPROTO;
	}

#ifdef CONFIG_SFC_RESOURCE_VF
	if (pd->vf != NULL)
		rc = efrm_pd_dma_map_vf(pd, n_pages, nic_order,
					addrs, addrs_stride,
					pci_addrs, pci_addrs_stride);
	else
#endif
		rc = efrm_pd_dma_map_nic(pd, n_pages, nic_order,
					 addrs, addrs_stride,
					 pci_addrs, pci_addrs_stride);
	if (rc < 0)
		goto fail1;

	if (pd->owner_id != OWNER_ID_PHYS_MODE) {
		rc = efrm_pd_dma_map_bt(pd, n_pages, nic_order,
					pci_addrs, pci_addrs_stride,
					user_addrs, user_addrs_stride,
					user_addr_put, bt_alloc);
		if (rc < 0)
			goto fail2;
	} else {
		rc = efrm_pd_check_pci_addr_alignment(
			pd, pci_addrs, pci_addrs_stride, n_pages);
		if (rc < 0)
			goto fail2;
		efrm_pd_copy_user_addrs(pd, n_pages, nic_order,
					pci_addrs, pci_addrs_stride,
					user_addrs, user_addrs_stride,
					user_addr_put);
	}
	return 0;


fail2:
#ifdef CONFIG_SFC_RESOURCE_VF
	if (pd->vf != NULL)
		efrm_pd_dma_unmap_vf(pd, n_pages, nic_order,
				     pci_addrs, pci_addrs_stride);
	else
#endif
		efrm_pd_dma_unmap_nic(pd, n_pages, nic_order,
				      pci_addrs, pci_addrs_stride);
fail1:
	return rc;
}
EXPORT_SYMBOL(efrm_pd_dma_map);


void efrm_pd_dma_unmap(struct efrm_pd *pd, int n_pages, int nic_order,
		       void *p_pci_addrs, int pci_addrs_stride,
		       struct efrm_bt_collection *bt_alloc)
{
	dma_addr_t *pci_addrs = p_pci_addrs;
	if (pd->owner_id != OWNER_ID_PHYS_MODE)
		efrm_pd_dma_unmap_bt(pd, bt_alloc);
#ifdef CONFIG_SFC_RESOURCE_VF
	if (pd->vf != NULL)
		efrm_pd_dma_unmap_vf(pd, n_pages, nic_order,
				     pci_addrs, pci_addrs_stride);
	else
#endif
		efrm_pd_dma_unmap_nic(pd, n_pages, nic_order,
				      pci_addrs, pci_addrs_stride);
}
EXPORT_SYMBOL(efrm_pd_dma_unmap);

/**********************************************************************/

static void efrm_pd_rm_dtor(struct efrm_resource_manager *rm)
{
}


int
efrm_create_pd_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_pd_manager *rm;
	int rc;

	rm = kmalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;
	memset(rm, 0, sizeof(*rm));

	rc = efrm_resource_manager_ctor(&rm->rm, efrm_pd_rm_dtor,
					"PD", EFRM_RESOURCE_PD);
	if (rc < 0)
		goto fail1;

	pd_manager = rm;
	*rm_out = &rm->rm;
	return 0;

fail1:
	kfree(rm);
	return rc;
}


struct efrm_bt_manager *
efrm_pd_bt_manager_next(struct efrm_pd *pd, struct efrm_bt_manager *prev)
{
	int i;

	if (prev == NULL)
		return &pd->bt_managers[0];

	for (i = 0;
	     i < efhw_nic_buffer_table_orders_num(pd->rs.rs_client->nic) - 1;
	     i++) {
		if (prev == &pd->bt_managers[i])
			return &pd->bt_managers[i+1];
	}

	return NULL;
}

