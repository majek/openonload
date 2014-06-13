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
 * This file provides public API for protection domain resource.
 *
 * Copyright 2012-2012: Solarflare Communications Inc,
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

#ifndef __CI_EFRM_PD_H__
#define __CI_EFRM_PD_H__


struct efrm_pd;
struct efrm_vf;
struct efrm_resource;
struct efrm_client;
struct efhw_buffer_table_allocation;
struct page;


/* Allocate a protection domain.
 *
 * If [vf_opt] is NULL, then [client_opt] must not be NULL.  If [vf_opt] is
 * supplied then [client_opt] is ignored.
 *
 * [phys_addr_mode] determines whether the protection domain will use
 * physical addresses, or virtual addresses translated via the buffer
 * table.
 */
extern int
efrm_pd_alloc(struct efrm_pd **pd_out, struct efrm_client *client_opt,
	      struct efrm_vf *vf_opt, int phys_addr_mode);

extern void
efrm_pd_release(struct efrm_pd *);

extern struct efrm_resource *
efrm_pd_to_resource(struct efrm_pd *);

extern struct efrm_pd *
efrm_pd_from_resource(struct efrm_resource *);

/* Return the owner-id associated with this PD.  If the protection domain
 * uses physical addressing, then this function returns 0.
 */
extern int
efrm_pd_owner_id(struct efrm_pd *);

/* Returns a borrowed reference, or NULL.  Reference remains valid as long
 * as the reference to the pd is held.
 */
extern struct efrm_vf *
efrm_pd_get_vf(struct efrm_pd *);

/* Return the PCI device associated with the protection domain. */
struct pci_dev *efrm_pd_get_pci_dev(struct efrm_pd *pd);

/* Return true if a mapping to one protection domain may be re-used by
 * another.  It happens when:
 * - DMA map is the same (for example, same IOMMU domain);
 * - buffer table is not used (physicall address mode).
 */
int efrm_pd_share_dma_mapping(struct efrm_pd *pd, struct efrm_pd *pd1);

extern int efrm_pd_dma_map(struct efrm_pd *, int n_pages, int gfp_order,
			   struct page **pages, int pages_stride,
			   void *dma_addrs, int dma_addrs_stride,
			   uint64_t *user_addrs, int user_addrs_stride,
			   void (*user_addr_put)(uint64_t, uint64_t *),
			   struct efhw_buffer_table_allocation *);

extern void efrm_pd_dma_unmap(struct efrm_pd *, int n_pages, int gfp_order,
			      void *dma_addrs, int dma_addrs_stride,
			      struct efhw_buffer_table_allocation *);

extern int efrm_pd_dma_remap_bt(struct efrm_pd *pd, int n_pages, int gfp_order,
                                dma_addr_t *pci_addrs, int pci_addrs_stride,
                                struct efhw_buffer_table_allocation *bt_alloc);
#endif /* __CI_EFRM_PD_H__ */
