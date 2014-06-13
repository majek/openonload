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
 * This file provides Linux-specific implementation for iopage API used
 * from efhw library.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
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

#include <ci/driver/resource/linux_efhw_nic.h>
#include "kernel_compat.h"
#include <ci/efhw/common_sysdep.h> /* for dma_addr_t */
#include <ci/efrm/debug.h>

int efhw_iopage_alloc(struct pci_dev *pci_dev, struct efhw_iopage *p,
		      efhw_iommu_domain *vf_domain, unsigned long iova_base)
{
	/* dma_alloc_coherent() is really the right interface to use here.
	 * However, it allocates memory "close" to the device, but we want
	 * memory on the current numa node.
	 */
	struct device *dev = &pci_dev->dev;
	struct page *page;
	int rc = -ENOMEM;

	/* In non-VF case, we sometimes call this from atomic context. */
	page = alloc_pages_node(numa_node_id(),
				(in_atomic() || in_interrupt()) ?
				GFP_ATOMIC : GFP_KERNEL,
				0);
	if (page == NULL)
		goto fail1;
	p->kva = (char *)page_address(page);

	if (!vf_domain) {
		p->dma_addr = dma_map_page(dev, page, 0, PAGE_SIZE,
					   DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, p->dma_addr)) {
			EFHW_ERR("%s: ERROR dma_map_page failed", __FUNCTION__);
			goto fail2;
		}
	} else
#ifdef CONFIG_IOMMU_API
	{
		EFRM_ASSERT(!in_atomic() && !in_interrupt());

		p->dma_addr = iova_base;
		rc = iommu_map(vf_domain, p->dma_addr, page_to_phys(page), 0,
			       IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
		if (rc) {
			EFHW_ERR("%s: ERROR iommu_map_page failed (%d)",
				 __FUNCTION__, rc);
			goto fail2;
		}
	}
#else
	EFRM_ASSERT(0);
#endif

	memset(p->kva, 0, PAGE_SIZE);
	return 0;

fail2:
	free_page((unsigned long)page_address(page));
fail1:
	return rc;
}


void efhw_iopage_free(struct pci_dev *pci_dev, struct efhw_iopage *p,
		      efhw_iommu_domain *vf_domain)
{
	struct device *dev = &pci_dev->dev;

	if (!vf_domain)
		dma_unmap_page(dev, p->dma_addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
	else {
#ifdef CONFIG_IOMMU_API
		EFRM_ASSERT(!in_atomic() && !in_interrupt());

		iommu_unmap(vf_domain, p->dma_addr, 0);
#else
		EFRM_ASSERT(0);
#endif
	}

	free_page((unsigned long)p->kva);
}


int efhw_iopage_map(struct pci_dev *pci_dev,
		    const struct efhw_iopage *orig,
		    struct efhw_iopage *p, efhw_iommu_domain *vf_domain,
		    unsigned long iova_base)
{
	struct device *dev = &pci_dev->dev;
	char *kva;
	struct page *page;
	int rc;

	kva = orig->kva;
	p->kva = kva;
	page = virt_to_page(kva);

	if (!vf_domain) {
		p->dma_addr = dma_map_page(dev, page, 0, PAGE_SIZE,
					   DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, p->dma_addr)) {
			EFHW_ERR("%s: ERROR dma_map_page failed", __FUNCTION__);
			rc = -ENOMEM;
			goto fail1;
		}
	} else
#ifdef CONFIG_IOMMU_API
	{
		EFRM_ASSERT(!in_atomic() && !in_interrupt());

		p->dma_addr = iova_base;
		rc = iommu_map(vf_domain, p->dma_addr, page_to_phys(page), 0,
			       IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
		if (rc) {
			EFHW_ERR("%s: ERROR iommu_map_page failed (%d)",
				 __FUNCTION__, rc);
			goto fail1;
		}
	}
#else
	EFRM_ASSERT(0);
#endif
	return 0;

fail1:
	return rc;
}

void efhw_iopage_unmap(struct pci_dev *pci_dev,
		       const struct efhw_iopage *orig,
		       struct efhw_iopage *p,
		       efhw_iommu_domain *vf_domain)
{
	struct device *dev = &pci_dev->dev;

	EFHW_ASSERT(p->kva == orig->kva);

	if (!vf_domain)
		dma_unmap_page(dev, p->dma_addr, PAGE_SIZE, DMA_BIDIRECTIONAL);
	else {
#ifdef CONFIG_IOMMU_API
		EFRM_ASSERT(!in_atomic() && !in_interrupt());
		/* NB IOVA is not reused */
		iommu_unmap(vf_domain, p->dma_addr, 0);
#else
		EFRM_ASSERT(0);
#endif
	}
}


int
efhw_iopages_alloc(struct pci_dev *pci_dev, struct efhw_iopages *p,
		   unsigned order, efhw_iommu_domain *vf_domain,
		   unsigned long iova_base)
{
	/* dma_alloc_coherent() is really the right interface to use here.
	 * However, it allocates memory "close" to the device, but we want
	 * memory on the current numa node.  Also we need the memory to be
	 * contiguous in the kernel, but not necessarily in physical
	 * memory.
	 *
	 * vf_domain is the IOMMU protection domain - it imples that pci_dev
	 * is a VF that should not use the normal DMA mapping APIs
	 */
	struct device *dev = &pci_dev->dev;
	int i = 0;

	p->n_pages = 1 << order;
	p->dma_addrs = kmalloc(p->n_pages * sizeof(p->dma_addrs[0]), 0);
	if (p->dma_addrs == NULL)
		goto fail1;
	p->ptr = vmalloc_node(p->n_pages << PAGE_SHIFT, -1);
	if (p->ptr == NULL)
		goto fail2;
	for (i = 0; i < p->n_pages; ++i) {
		struct page *page;
		page = vmalloc_to_page(p->ptr + (i << PAGE_SHIFT));

		if (!vf_domain) {
			p->dma_addrs[i] = dma_map_page(dev, page, 0, PAGE_SIZE,
						       DMA_BIDIRECTIONAL);
			
			if (dma_mapping_error(dev, p->dma_addrs[i])) {
				EFHW_ERR("%s: ERROR dma_map_page failed",
					 __FUNCTION__);
				goto fail3;
			}
		} else
#ifdef CONFIG_IOMMU_API
		{
			int rc;

			EFRM_ASSERT(!in_atomic() && !in_interrupt());

			p->dma_addrs[i] = iova_base;
			rc = iommu_map(vf_domain, p->dma_addrs[i],
				       page_to_phys(page), 0,
				       IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
			if (rc) {
				EFHW_ERR("%s: ERROR iommu_map_page failed (%d)",
					 __FUNCTION__, rc);
				goto fail3;
			}
			iova_base += PAGE_SIZE;
		}
#else
		EFRM_ASSERT(0);
#endif
	}
	return 0;

fail3:
	while (i-- > 0)
		if (!vf_domain) {
			dma_unmap_page(dev, p->dma_addrs[i],
				       PAGE_SIZE, DMA_BIDIRECTIONAL);
		} else
#ifdef CONFIG_IOMMU_API
			iommu_unmap(vf_domain, iova_base, 0);
#endif
fail2:
	kfree(p->dma_addrs);
fail1:
	return -ENOMEM;
}

void efhw_iopages_free(struct pci_dev *pci_dev, struct efhw_iopages *p,
		       efhw_iommu_domain *vf_domain)
{
	struct device *dev = &pci_dev->dev;
	int i;

	for (i = 0; i < p->n_pages; ++i)
		if (!vf_domain)
			dma_unmap_page(dev, p->dma_addrs[i],
				       PAGE_SIZE, DMA_BIDIRECTIONAL);
		else {
#ifdef CONFIG_IOMMU_API
			EFRM_ASSERT(!in_atomic() && !in_interrupt());

			iommu_unmap(vf_domain, p->dma_addrs[i], 0);
#else
			EFRM_ASSERT(0);
#endif
		}
	vfree(p->ptr);
	kfree(p->dma_addrs);
}
