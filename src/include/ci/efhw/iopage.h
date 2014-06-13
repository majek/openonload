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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains OS-independent API for allocating iopage types.
 * The implementation of these functions is highly OS-dependent.
 * This file is not designed for use outside of the SFC resource driver.
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

#ifndef __CI_DRIVER_RESOURCE_IOPAGE_H__
#define __CI_DRIVER_RESOURCE_IOPAGE_H__

#include <ci/efhw/efhw_types.h>

/*--------------------------------------------------------------------
 *
 * memory allocation
 *
 *--------------------------------------------------------------------*/

/* Allocate a single IO page, and initialise the efhw_iopage structure (p).
 * The caller must release the page using efhw_iopage_free when it is
 * no longer needed.
 * Returns zero on success or a negative error number on failure. */
extern int efhw_iopage_alloc(struct efhw_iopage *p);

/* Free an IO page allocated using efhw_iopage_alloc.  This reverses
 * the effects of efhw_iopage_alloc. */
extern void efhw_iopage_free(struct efhw_iopage *p);

/* Map an existing IO page (p) into PCI device or IOMMU domain.
 * efhw_iopage structure should be reserved by efhw_iopage_alloc or
 * efhw_iopage_copy functions.
 * It is invalid to free the IO page until the effects of this function
 * have been reversed by calling efhw_iopage_unmap.
 * Returns zero on success or a negative error number on failure. */
extern int efhw_iopage_map(struct pci_dev *pci_dev,
			   struct efhw_iopage *p,
			   efhw_iommu_domain *vf_domain,
			   unsigned long iova_base);

/* Unmap an IO page (orig) from a PCI device.  This reverses the
 * effects of efhw_iopage_map.  The same parameters must be supplied
 * to both functions. */
extern void efhw_iopage_unmap(struct pci_dev *pci_dev,
			      struct efhw_iopage *p,
			      efhw_iommu_domain *vf_domain);

/* Allocate a set of IO pages, map them into the specified NIC (nic)
 * and initialise the efhw_iopages structure (p).  The pages will be
 * contiguous in the kernel address space but not in the device
 * address space.  The number of pages allocated is 1<<order.  The
 * caller must release the pages using efhw_iopages_free when they is
 * no longer needed.  Returns zero on success or a negative error
 * number on failure. */
extern int efhw_iopages_alloc(struct pci_dev *pci_dev, struct efhw_iopages *p,
			      unsigned order,
			      efhw_iommu_domain *vf_domain,
			      unsigned long iova_base);

/* Free IO pages allocated using efhw_iopages_alloc.  This reverses
 * the effects of efhw_iopages_alloc.  The same values must be
 * supplied to the nic and p arguments to the two functions. */
extern void efhw_iopages_free(struct pci_dev *pci_dev, struct efhw_iopages *p,
			      efhw_iommu_domain *vf_domain);

#endif /* __CI_DRIVER_RESOURCE_IOPAGE_H__ */
