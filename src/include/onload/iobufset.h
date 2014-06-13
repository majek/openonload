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
 * Driver for Solarflare network controllers - Onload driver
 *
 * This file provides public API for iobufset resource.
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

#ifndef __CI_EFRM_IOBUFSET_H__
#define __CI_EFRM_IOBUFSET_H__

#include <ci/efrm/buffer_table.h>
#include <ci/efrm/sysdep.h>
#include <onload/common.h>
#include <onload/linux_onload.h>
#include <onload/atomics.h>
#include <ci/driver/efab/workqueue.h>

/********************************************************************
 *
 * Compound pages.
 *
 ********************************************************************/

/* It looks like 2.6.18 and 2.6.26 can't mmap
 * compound pages, so we should not try. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#define OO_HAVE_COMPOUND_PAGES
#endif

struct efrm_pd;

/*
 * For all these structures, users should not access the structure fields
 * directly, but use the API below.
 *
 * However, the structure should not be moved out of public headers,
 * because part of API (ex. oo_iobufset_ptr function) is inline and
 * is used in the fast-path code.
 */


/*! Continuous memorry allocation structure.
 * All pages MUST have the same order. */
struct oo_buffer_pages {
  int n_bufs;               /*!< number of entries in pages array */
  oo_atomic_t ref_count;
#ifdef OO_DO_HUGE_PAGES
  int shmid;
#ifdef CLONE_NEWIPC
  struct ipc_namespace *ipc_ns;
  ci_workitem_t wi;
#endif
#endif
  struct page **pages;     /*!< array of Linux compound pages */
};

/*! Iobufset resource structture. */
struct oo_iobufset {
  struct efrm_pd *pd;
  oo_atomic_t ref_count;
  struct efrm_buffer_table_allocation buf_tbl_alloc;
  struct oo_buffer_pages *pages;   /*!< allocated memory */
  dma_addr_t *dma_addrs;            /*!< array of pages->n_buf entries */
};


/*********** Find memory parameters ******************/
#ifdef OO_DO_HUGE_PAGES
/*! Are we shared memory backed? */
ci_inline int oo_iobufset_get_shmid(struct oo_buffer_pages *pages)
{
  return pages->shmid;
}
#endif

/*! Find memory address in buffer offset. */
ci_inline void *oo_iobufset_ptr(struct oo_buffer_pages *pages, int offset)
{
  int order = compound_order(pages->pages[0]);
  return page_address(pages->pages[offset >> PAGE_SHIFT >> order]) +
      (offset & ((PAGE_SIZE << order) - 1));
}

/*! Find pfn of the given page in the buffer. */
ci_inline unsigned long oo_iobufset_pfn(struct oo_buffer_pages *pages, int offset)
{
  int order = compound_order(pages->pages[0]);

  /* This function is used from nopage handler.  Huge pages should not be
   * mmaped in this way. */
#ifdef OO_DO_HUGE_PAGES
  ci_assert_equal(pages->shmid, -1);
#endif

  return page_to_pfn(pages->pages[offset >> PAGE_SHIFT >> order]) +
      ((offset >> PAGE_SHIFT) & ((1 << order) - 1));
}


ci_inline void o_iobufset_resource_ref(struct oo_iobufset *iobrs)
{
  oo_atomic_inc(&iobrs->ref_count);
}

/************** Alloc/free buffer ****************/

#if CI_CFG_PKTS_AS_HUGE_PAGES
/* Flag is EF_USE_HUGE_PAGES value possibly or'ed with
 * OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED */
#define OO_IOBUFSET_FLAG_TRY_HUGE_PAGE    1
#define OO_IOBUFSET_FLAG_FORCE_HUGE_PAGE  2
#define OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED 0x1000
#endif

/*!
 * Allocate oo_buffer_pagess.
 *
 * \param order      page order to allocate
 * \param flags      see OO_IOBUFSET_FLAG_*, in/out
 * \param pages_out  pointer to return the allocated pages
 *
 * \return           status code; if non-zero, pages_out is unchanged
 *
 * \note \p order is not the OS page order, but the order assuming
 * EFHW_NIC_PAGE_SIZE has order=0.  It is important difference for the case
 * EFHW_NIC_PAGE_SIZE != PAGE_SIZE, as on PPC.
 */
extern int
oo_iobufset_pages_alloc(int nic_order, int *flags,
                        struct oo_buffer_pages **pages_out);
extern void oo_iobufset_pages_release(struct oo_buffer_pages *);

/*!
 * Map oo_buffer_pagess to protection domain and create iobufset resource.
 *
 * \param pages      Pages to map. Grabs a reference on success.
 * \param pd         PD that "owns" these buffers. Grabs a reference
 *                   on success.
 * \param iobrs_out  pointer to return the new IO buffer set
 * \param hw_addrs   array to store hw addresses
 *
 * \return           status code; if non-zero, iobrs_out is unchanged
 */
extern int
oo_iobufset_resource_alloc(struct oo_buffer_pages *pages, struct efrm_pd *pd,
                           struct oo_iobufset **iobrs_out, uint64_t *hw_addrs);

extern void oo_iobufset_resource_release(struct oo_iobufset *);

extern int oo_iobufset_resource_remap_bt(struct oo_iobufset *iobrs,
                                         uint64_t *hw_addrs);

#endif /* __CI_EFRM_IOBUFSET_H__ */
