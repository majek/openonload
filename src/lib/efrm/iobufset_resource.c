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
 * This file contains non-contiguous I/O buffers support.
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
#include <ci/efrm/private.h>
#include <ci/efrm/iobufset.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/pd.h>
#include "efrm_internal.h"
#include "efrm_iobufset.h"


#define EFRM_IOBUFSET_MAX_NUM_INSTANCES 0x00010000


struct iobufset_resource_manager {
	struct efrm_resource_manager rm;
	struct kfifo free_ids;
};

static struct iobufset_resource_manager *efrm_iobufset_manager;


#define iobsrs(rs1)  iobufset_resource(rs1)

/* Returns size of iobufset resource data structure. */
static inline size_t iobsrs_size(int n_pages)
{
	return offsetof(struct iobufset_resource, bufs) +
	    n_pages * sizeof(struct efhw_iopage);
}


static inline
efhw_iommu_domain *get_iommu_domain(struct iobufset_resource *iob)
{
	return efrm_vf_get_iommu_domain(efrm_pd_get_vf(iob->pd));
}


void efrm_iobufset_resource_free(struct iobufset_resource *rs)
{
	struct iobufset_resource *linked;
	unsigned int i;
	int id;
	efhw_iommu_domain *iommu_domain;

	EFRM_RESOURCE_ASSERT_VALID(&rs->rs, 1);

	if (!rs->linked && rs->buf_tbl_alloc.base != (unsigned) -1)
		efrm_buffer_table_free(&rs->buf_tbl_alloc);
	linked = rs->linked;

	iommu_domain = get_iommu_domain(rs);
	for (i = 0; i < rs->n_bufs; ++i)
		efhw_iopage_unmap(rs->pci_dev, &rs->bufs[i], iommu_domain);
	if (!linked) {
		for (i = 0; i < rs->n_bufs; ++i)
			efhw_iopage_free(&rs->bufs[i]);
	}

	/* free the instance number */
	id = rs->rs.rs_instance;
	spin_lock_bh(&efrm_iobufset_manager->rm.rm_lock);
	EFRM_VERIFY_EQ(kfifo_in(&efrm_iobufset_manager->free_ids,
				(unsigned char *)&id, sizeof(id)),
		       sizeof(id));
	spin_unlock_bh(&efrm_iobufset_manager->rm.rm_lock);

	if (rs->pd != NULL)
		efrm_pd_release(rs->pd);
	if (rs->linked)
		efrm_iobufset_resource_release(rs->linked);

	efrm_client_put(rs->rs.rs_client);
	if (iobsrs_size(rs->n_bufs) < PAGE_SIZE) {
		EFRM_DO_DEBUG(memset(rs, 0, sizeof(*rs)));
		kfree(rs);
	} else {
		EFRM_DO_DEBUG(memset(rs, 0, sizeof(*rs)));
		vfree(rs);
	}
}


void efrm_iobufset_resource_release(struct iobufset_resource *iobrs)
{
	if (__efrm_resource_release(&iobrs->rs))
		efrm_iobufset_resource_free(iobrs);
}
EXPORT_SYMBOL(efrm_iobufset_resource_release);



int
efrm_iobufset_resource_alloc(int n_pages, struct efrm_pd *pd,
			     struct iobufset_resource *linked,
			     struct iobufset_resource **iobrs_out)
{
	struct efrm_client *client;
	struct iobufset_resource *iobrs;
	int rc, instance, object_size;
	efhw_iommu_domain *iommu_domain;
	struct efrm_vf *vf = efrm_pd_get_vf(pd);
	unsigned int i;
	int owner_id;

	EFRM_ASSERT(iobrs_out);
	EFRM_ASSERT(efrm_iobufset_manager);
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_iobufset_manager->rm);

	client = efrm_pd_to_resource(pd)->rs_client;
	iommu_domain = efrm_vf_get_iommu_domain(vf);

        /* We can't allow a resource to be linked to a linked resource
         * because it can cause unbounded recursion during resource
         * destruction.  We could throw an error here, but it's just
         * as easy to link to the underlying resource instead. */
	if (linked && linked->linked)
		linked = linked->linked;

	/* In many cases, DMA mapping is the same for 2 PCI functions.
	 * In Linux, the cases are:
	 * - no iommu or swiotlb (i.e. nommu_dma_ops used);
	 * - swiotlb, low physical address;
	 * - 2 virtual functions, same iommu domain.
	 * The last can be easily detected, so we do not allocate 
	 * a separate iobufset resource, also saving iommu space.
	 * We use pd of the first VF - but it should be OK,
	 * since it holds iommu domain.
	 */
	if (linked && iommu_domain != NULL &&
	    iommu_domain ==
	    efrm_vf_get_iommu_domain(efrm_pd_get_vf(linked->pd))) {
		efrm_resource_ref(&linked->rs);
		*iobrs_out = linked;
		return 0;
	}

	if (linked) {
		/* This instance will share memory with another.  This is
		 * usually used to map the buffers into another protection
		 * domain.
		 */
		n_pages = linked->n_bufs;
	}

	/* allocate the resource data structure. */
	object_size = iobsrs_size(n_pages);
	if (object_size < PAGE_SIZE) {
		/* this should be OK from a tasklet */
		/* Necessary to do atomic alloc() as this
		   can be called from a weird-ass iSCSI context that is
		   !in_interrupt but is in_atomic - See BUG3163 */
		iobrs = kmalloc(object_size, GFP_ATOMIC);
	} else {		/* can't do this within a tasklet */
#ifndef NDEBUG
		if (in_interrupt() || in_atomic()) {
			EFRM_ERR("%s(): alloc->u.iobufset.in_n_pages=%d",
				 __FUNCTION__, n_pages);
			EFRM_ASSERT(!in_interrupt());
			EFRM_ASSERT(!in_atomic());
		}
#endif
		iobrs = (struct iobufset_resource *) vmalloc(object_size);
	}
	if (iobrs == NULL) {
		EFRM_WARN_LIMITED("%s: failed to allocate container",
			__FUNCTION__);
		rc = -ENOMEM;
		goto fail1;
	}

	/* Allocate an instance number. */
	spin_lock_bh(&efrm_iobufset_manager->rm.rm_lock);
	rc = kfifo_out(&efrm_iobufset_manager->free_ids,
		       (unsigned char *)&instance, sizeof(instance));
	spin_unlock_bh(&efrm_iobufset_manager->rm.rm_lock);
	if (rc != sizeof(instance)) {
		EFRM_WARN_LIMITED("%s: out of instances", __FUNCTION__);
		EFRM_ASSERT(rc == 0);
		rc = -EBUSY;
		goto fail3;
	}

	efrm_resource_init(&iobrs->rs, EFRM_RESOURCE_IOBUFSET, instance);

	iobrs->pci_dev = efrm_pd_get_pci_dev(pd);
	iobrs->pd = pd;
	iobrs->linked = linked;
	iobrs->n_bufs = n_pages;
	iobrs->buf_tbl_alloc.base = (unsigned) -1;

	EFRM_TRACE("%s: " EFRM_RESOURCE_FMT " %u pages", __FUNCTION__,
		   EFRM_RESOURCE_PRI_ARG(&iobrs->rs), iobrs->n_bufs);

	/* Allocate or map the iobuffers. */
	memset(iobrs->bufs, 0, iobrs->n_bufs * sizeof(iobrs->bufs[0]));
	if (linked) {
		for (i = 0; i < iobrs->n_bufs; ++i)
			efhw_iopage_copy(&iobrs->bufs[i], &linked->bufs[i]);
	} else {
		for (i = 0; i < iobrs->n_bufs; ++i) {
			rc = efhw_iopage_alloc(&iobrs->bufs[i]);
			if (rc < 0) {
				EFRM_WARN("%s: failed (rc %d) to allocate "
					  "page (i=%u)", __FUNCTION__, rc, i);
				goto fail4;
			}
		}
	}
	for (i = 0; i < iobrs->n_bufs; ++i) {
		unsigned long iova_base = 0;
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
		iova_base = vf ? efrm_vf_alloc_ioaddrs(vf, 1, NULL) : 0;
#endif
		rc = efhw_iopage_map(iobrs->pci_dev, &iobrs->bufs[i],
				     iommu_domain, iova_base);
		if (rc < 0) {
			EFRM_WARN("%s: failed (rc %d) to map "
				  "page (i=%u)", __FUNCTION__, rc, i);
			goto fail5;
		}
	}

	owner_id = efrm_pd_owner_id(pd);
	if (owner_id != 0) {
		EFRM_ASSERT(vf == NULL);
		if (!linked) {
			/* Allocate space in the NIC's buffer table. */
			rc = efrm_buffer_table_alloc(fls(iobrs->n_bufs - 1),
						     &iobrs->buf_tbl_alloc);
			if (rc < 0) {
				EFRM_WARN("%s: failed (%d) to alloc %d buffer "
					  "table entries", __FUNCTION__, rc,
					  iobrs->n_bufs);
				goto fail6;
			}
			EFRM_ASSERT(((unsigned)1 << iobrs->buf_tbl_alloc.order)
				    >= (unsigned) iobrs->n_bufs);
		} else {
			iobrs->buf_tbl_alloc = linked->buf_tbl_alloc;
		}

		/* Initialise the buffer table entries. */
		for (i = 0; i < iobrs->n_bufs; ++i) {
			/*\ ?? \TODO burst them! */
			efrm_buffer_table_set(&iobrs->buf_tbl_alloc,
					      efrm_client_get_nic(client), i,
					      efhw_iopage_dma_addr(&iobrs->
								   bufs[i]),
					      owner_id);
		}
		efrm_buffer_table_commit(efrm_client_get_nic(client));
	}

	EFRM_TRACE("%s: " EFRM_RESOURCE_FMT " %d pages @ "
		   EFHW_BUFFER_ADDR_FMT, __FUNCTION__,
		   EFRM_RESOURCE_PRI_ARG(&iobrs->rs),
		   iobrs->n_bufs, EFHW_BUFFER_ADDR(iobrs->buf_tbl_alloc.base,
						   0));
	if( pd != NULL )
		efrm_resource_ref(efrm_pd_to_resource(pd));
	if (linked != NULL)
		efrm_resource_ref(&linked->rs);
	efrm_client_add_resource(client, &iobrs->rs);
	*iobrs_out = iobrs;
	return 0;

fail6:
	i = iobrs->n_bufs;
fail5:
	while (i--) {
		efhw_iopage_unmap(efrm_pd_get_pci_dev(pd),
				  &iobrs->bufs[i], iommu_domain);
	}
	i = iobrs->n_bufs;
fail4:
	if (!linked) {
		while (i--)
			efhw_iopage_free(&iobrs->bufs[i]);
	}
fail3:
	if (object_size < PAGE_SIZE)
		kfree(iobrs);
	else
		vfree(iobrs);
fail1:
	return rc;
}
EXPORT_SYMBOL(efrm_iobufset_resource_alloc);

static void iobufset_rm_dtor(struct efrm_resource_manager *rm)
{
	EFRM_ASSERT(&efrm_iobufset_manager->rm == rm);
	efrm_kfifo_id_dtor(&efrm_iobufset_manager->free_ids);
}

int
efrm_create_iobufset_resource_manager(struct efrm_resource_manager **rm_out)
{
	int rc, max;

	EFRM_ASSERT(rm_out);

	efrm_iobufset_manager =
	    kmalloc(sizeof(*efrm_iobufset_manager), GFP_KERNEL);
	if (efrm_iobufset_manager == 0)
		return -ENOMEM;
	memset(efrm_iobufset_manager, 0, sizeof(*efrm_iobufset_manager));

	/* HACK: Magic number! */
	max = 32768;
	rc = efrm_kfifo_id_ctor(&efrm_iobufset_manager->free_ids, 0, max);
	if (rc != 0)
		goto fail1;

	rc = efrm_resource_manager_ctor(&efrm_iobufset_manager->rm,
					iobufset_rm_dtor, "IOBUFSET",
					EFRM_RESOURCE_IOBUFSET);
	if (rc < 0)
		goto fail2;

	*rm_out = &efrm_iobufset_manager->rm;
	return 0;

fail2:
	efrm_kfifo_id_dtor(&efrm_iobufset_manager->free_ids);
fail1:
	EFRM_DO_DEBUG(memset(efrm_iobufset_manager, 0,
			     sizeof(*efrm_iobufset_manager)));
	kfree(efrm_iobufset_manager);
	return rc;
}
