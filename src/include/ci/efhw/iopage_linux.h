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
 * This file provides struct efhw_page and struct efhw_iopage for Linux
 * kernel.
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

#ifndef __CI_EFHW_IOPAGE_LINUX_H__
#define __CI_EFHW_IOPAGE_LINUX_H__

#include <linux/version.h>
#include <linux/gfp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
#include <linux/hardirq.h>
#else
#include <asm/hardirq.h>
#endif
#include <linux/types.h>
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
# include <linux/iommu.h>
#endif
#include <linux/errno.h>
#include <linux/mm.h>
#include <ci/efhw/debug.h>
#include <driver/linux_net/kernel_compat.h>
#include <ci/efrm/config.h>


/*--------------------------------------------------------------------
 *
 * struct efhw_page: A single page of memory.  Directly mapped in the
 * driver, and can be mapped to userlevel.
 *
 *--------------------------------------------------------------------*/

struct efhw_page {
	unsigned long kva;
};

#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
typedef struct iommu_domain efhw_iommu_domain;
extern struct mutex efrm_iommu_mutex;
#else
typedef unsigned int efhw_iommu_domain;
#endif

static inline int efhw_page_alloc(struct efhw_page *p)
{
	p->kva = __get_free_page(in_interrupt()? GFP_ATOMIC : GFP_KERNEL);
	return p->kva ? 0 : -ENOMEM;
}

static inline int efhw_page_alloc_zeroed(struct efhw_page *p)
{
	p->kva = get_zeroed_page(in_interrupt()? GFP_ATOMIC : GFP_KERNEL);
	return p->kva ? 0 : -ENOMEM;
}

static inline void efhw_page_free(struct efhw_page *p)
{
	free_page(p->kva);
	EFHW_DO_DEBUG(memset(p, 0, sizeof(*p)));
}

static inline char *efhw_page_ptr(struct efhw_page *p)
{
	return (char *)p->kva;
}

static inline unsigned efhw_page_pfn(struct efhw_page *p)
{
	return (unsigned)(__pa(p->kva) >> PAGE_SHIFT);
}

static inline void efhw_page_mark_invalid(struct efhw_page *p)
{
	p->kva = 0;
}

static inline int efhw_page_is_valid(struct efhw_page *p)
{
	return p->kva != 0;
}

static inline void efhw_page_init_from_va(struct efhw_page *p, void *va)
{
	p->kva = (unsigned long)va;
}

/*--------------------------------------------------------------------
 *
 * struct efhw_iopages: A set of pages that are contiguous in the kernel
 * address space, may be mapped to user-level and may be DMA mapped.  Not
 * physically contiguous.
 *
 *--------------------------------------------------------------------*/

struct efhw_iopages {
	void *ptr;
	unsigned n_pages;
	dma_addr_t *dma_addrs;
};

static inline caddr_t efhw_iopages_ptr(struct efhw_iopages *p)
{
	return p->ptr;
}

static inline unsigned efhw_iopages_pfn(struct efhw_iopages *p, int page_i)
{
	return vmalloc_to_pfn(p->ptr + (page_i << PAGE_SHIFT));
}

static inline dma_addr_t efhw_iopages_dma_addr(struct efhw_iopages *p,
					       int page_i)
{
	return p->dma_addrs[page_i];
}

static inline unsigned efhw_iopages_size(struct efhw_iopages *p)
{
	return p->n_pages << PAGE_SHIFT;
}

static inline unsigned efhw_iopages_n_pages(struct efhw_iopages *p)
{
	return p->n_pages;
}


#endif /* __CI_EFHW_IOPAGE_LINUX_H__ */
