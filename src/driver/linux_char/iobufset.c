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


#include <ci/driver/efab/debug.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/efab/efch.h>
#include <ci/driver/efab/mmap_iopage.h>
#include <ci/efrm/iobufset.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efrm/pd.h>
#include <ci/efch/op_types.h>
#include "char_internal.h"


static int
iobufset_lookup_linked(const struct efch_iobufset_alloc *alloc,
                       struct iobufset_resource **iobs_out)
{
  struct efrm_resource *rs;
  int rc;

  *iobs_out = NULL;
  if (alloc->in_linked_fd < 0)
    return 0;

  rc = efch_lookup_rs(alloc->in_linked_fd, alloc->in_linked_rs_id,
                      EFRM_RESOURCE_IOBUFSET, &rs);
  if (rc == 0)
    *iobs_out = iobufset_resource(rs);
  return rc;
}


static int
iobufset_rm_alloc(ci_resource_alloc_t* alloc_,
		  ci_resource_table_t* priv_opt,
		  efch_resource_t* rs, int intf_ver_id)
{
  struct efch_iobufset_alloc *alloc = &alloc_->u.iobufset;
  struct iobufset_resource *linked_iobs;
  struct iobufset_resource* iobrs;
  struct efrm_resource *vi_rs = NULL;
  struct efrm_resource *pd_rs = NULL;
  struct efrm_pd *pd;
  int rc;

  /* Check sensible-ness of incoming args. */
  if (alloc->in_linked_fd < 0) {
    if (alloc->in_n_pages < 1) {
      DEBUGERR(ci_log("%s: bad number of pages %d", __FUNCTION__, 
                      alloc->in_n_pages));
      return -EINVAL;
    }
  }

  if ((rc = efch_lookup_rs(alloc->in_pd_or_vi_fd, alloc->in_pd_or_vi_rs_id,
                           EFRM_RESOURCE_PD, &pd_rs)) < 0)
    if ((rc = efch_lookup_rs(alloc->in_pd_or_vi_fd, alloc->in_pd_or_vi_rs_id,
                             EFRM_RESOURCE_VI, &vi_rs)) < 0)
      goto fail1;

  rc = iobufset_lookup_linked(alloc, &linked_iobs);
  if (rc < 0) {
    DEBUGERR(ci_log("%s: ERROR: linked_fd=%d linked_id="EFCH_RESOURCE_ID_FMT
                    " (%d)", __FUNCTION__, alloc->in_linked_fd,
                    EFCH_RESOURCE_ID_PRI_ARG(alloc->in_linked_rs_id), rc));
    goto fail2;
  }

  if (pd_rs == NULL) {
    pd_rs = efrm_pd_to_resource(efrm_vi_get_pd(efrm_to_vi_resource(vi_rs)));
    efrm_resource_ref(pd_rs);
  }
  pd = efrm_pd_from_resource(pd_rs);

  rc = efrm_iobufset_resource_alloc(alloc->in_n_pages, pd,
                                    linked_iobs, &iobrs);
  if (rc != 0)
    goto fail3;

  if (linked_iobs != NULL)
    efrm_resource_release(&linked_iobs->rs);
  if (efrm_pd_owner_id(pd) != 0)
    alloc->out_bufaddr = EFHW_BUFFER_ADDR(iobrs->buf_tbl_alloc.base, 0);
  efrm_resource_release(pd_rs);
  if (vi_rs != NULL)
    efrm_resource_release(vi_rs);
  alloc->out_mmap_bytes = iobrs->n_bufs * CI_PAGE_SIZE;
  rs->rs_base = &iobrs->rs;
  return 0;


 fail3:
  if (linked_iobs != NULL)
    efrm_resource_release(&linked_iobs->rs);
 fail2:
  if (pd_rs != NULL)
    efrm_resource_release(pd_rs);
  if (vi_rs != NULL)
    efrm_resource_release(vi_rs);
 fail1:
  return rc;
}


int
efab_iobufset_resource_mmap(struct iobufset_resource *iobrs, unsigned long* bytes,
                            void* opaque, int* map_num, unsigned long* offset,
                            int index)
{
  unsigned long n;
  unsigned i;
  int rc = 0;

  EFRM_RESOURCE_ASSERT_VALID(&iobrs->rs, 0);
  ci_assert((*bytes &~ CI_PAGE_MASK) == 0);

  DEBUGVM(ci_log("%s: "EFRM_RESOURCE_FMT" bytes=0x%lx mapped=0x%x",
                 __FUNCTION__, EFRM_RESOURCE_PRI_ARG(&iobrs->rs), *bytes,
		 (unsigned)
		   CI_MIN((signed)*bytes, iobrs->n_bufs << CI_PAGE_SHIFT)));

  n = (unsigned long)iobrs->n_bufs << CI_PAGE_SHIFT;
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  n >>= CI_PAGE_SHIFT;
  ci_assert_le((unsigned int)n, iobrs->n_bufs);
  
  for( i = 0; i < n; ++i ) {
    rc = ci_mmap_iopage(&iobrs->bufs[i], opaque, map_num, offset);
    if( rc < 0 ) {
      DEBUGERR(ci_log("%s: "EFRM_RESOURCE_FMT" failed at buffer %d",
                      __FUNCTION__, EFRM_RESOURCE_PRI_ARG(&iobrs->rs), i));
/*XXX shouldn't this unmap any done so far? */

      break;
    }
  }

  return rc;
}
EXPORT_SYMBOL(efab_iobufset_resource_mmap);

static int
iobufset_rm_mmap(struct efrm_resource* ors, unsigned long* bytes,
		void* opaque, int* map_num, unsigned long* offset, int index)
{
  return efab_iobufset_resource_mmap(iobufset_resource(ors), bytes, opaque,
                                     map_num, offset, index);
}

#if defined CI_HAVE_OS_NOPAGE
unsigned
efab_iobufset_resource_nopage(struct iobufset_resource* iobrs, void* opaque, 
                              unsigned long offset, unsigned long map_size)
{
  int page_offset = offset >> CI_PAGE_SHIFT;

  ci_assert_lt(page_offset, iobrs->n_bufs);

  return efhw_iopage_pfn(&iobrs->bufs[page_offset]);
}
EXPORT_SYMBOL(efab_iobufset_resource_nopage);

static unsigned
iobufset_rm_nopage(struct efrm_resource* ors, void* opaque, 
				   unsigned long offset,
				   unsigned long map_size)
{
  return efab_iobufset_resource_nopage(iobufset_resource(ors), opaque,
                                       offset, map_size);
}
#endif


#define MAXDUMP 10
static void
iobufset_rm_dump(struct efrm_resource* ors, ci_resource_table_t *priv_opt,
			     const char *line_prefix)
{
  struct iobufset_resource* rs = iobufset_resource(ors);
  int i;
#ifdef MAXDUMP	/*XXX jgh */
  int lim = CI_MIN(rs->n_bufs, MAXDUMP);

  for( i = 0; i < lim; ++i )
#else
  for( i = 0; i < rs->n_bufs; ++i )
#endif
    ci_log("%s0x%x: bufaddr=%08x dma="DMA_ADDR_T_FMT" ptr=%p", line_prefix,
	   i, EFHW_BUFFER_ADDR((rs->buf_tbl_alloc.base + i),0),
	   efhw_iopage_dma_addr(&rs->bufs[i]), efhw_iopage_ptr(&rs->bufs[i]));
#ifdef MAXDUMP
  if (rs->n_bufs > MAXDUMP)
    ci_log("%s(more, total %d)\n", line_prefix, rs->n_bufs);
#endif
}


efch_resource_ops efch_iobufset_ops = {
  iobufset_rm_alloc,
  NULL /*rm_free*/,
  iobufset_rm_mmap,
#ifdef CI_HAVE_OS_NOPAGE
  iobufset_rm_nopage,
#else
  NULL /*rm_nopage*/,
#endif
  iobufset_rm_dump,
  NULL /*iobufset_rm_rsops*/,
};


