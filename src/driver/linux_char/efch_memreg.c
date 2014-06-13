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

#include "efch.h"
#include <ci/efrm/vi_resource.h>
#include <ci/efch/op_types.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/buffer_table.h>
#include "char_internal.h"


struct efch_memreg {
  struct efhw_buffer_table_allocation buf_tbl_alloc;
  struct efrm_pd                     *pd;
  int                                 n_pages;
  bool                                mapped;
  struct page                       **pages;
  dma_addr_t                         *dma_addrs;
};


static void efch_memreg_free(struct efch_memreg *mr)
{
  int i;
  if (mr->mapped)
    efrm_pd_dma_unmap(mr->pd, mr->n_pages, 0,
                      mr->dma_addrs, sizeof(mr->dma_addrs[0]),
                      &mr->buf_tbl_alloc);
  for (i = 0; i < mr->n_pages; ++i)
    put_page(mr->pages[i]);
  if (mr->pd != NULL)
    efrm_pd_release(mr->pd);
  kfree(mr->dma_addrs);
  kfree(mr->pages);
  kfree(mr);
}


static struct efch_memreg *efch_memreg_alloc(int max_pages)
{
  struct efch_memreg *mr = NULL;
  int bytes;

  if ((mr = kmalloc(sizeof(*mr), GFP_KERNEL)) == NULL)
    goto fail1;
  memset(mr, 0, sizeof(*mr));
  bytes = max_pages * sizeof(mr->pages[0]);
  if ((mr->pages = kmalloc(bytes, GFP_KERNEL)) == NULL)
    goto fail2;
  bytes = max_pages * sizeof(mr->dma_addrs[0]);
  if ((mr->dma_addrs = kmalloc(bytes, GFP_KERNEL)) == NULL)
    goto fail3;
  return mr;


 fail3:
  kfree(mr->pages);
 fail2:
  kfree(mr);
 fail1:
  return NULL;
}

/**********************************************************************/

static void put_user_64(uint64_t v, uint64_t *p)
{
  put_user(v, p);
}


static int
memreg_rm_alloc(ci_resource_alloc_t* alloc_,
                ci_resource_table_t* priv_opt,
                efch_resource_t* ch_rs, int intf_ver_id)
{
  struct efch_memreg_alloc *alloc = &alloc_->u.memreg;
  struct efrm_resource *vi_or_pd = NULL;
  struct efch_memreg *mr;
  struct efrm_pd *pd;
  int rc, max_pages;

  rc = efch_lookup_rs(alloc->in_vi_or_pd_fd, alloc->in_vi_or_pd_id,
                      EFRM_RESOURCE_VI, &vi_or_pd);
  if (rc < 0)
    rc = efch_lookup_rs(alloc->in_vi_or_pd_fd, alloc->in_vi_or_pd_id,
                        EFRM_RESOURCE_PD, &vi_or_pd);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: fd=%d id="EFCH_RESOURCE_ID_FMT" (%d)",
             __FUNCTION__, alloc->in_vi_or_pd_fd,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_vi_or_pd_id), rc);
    goto fail1;
  }

  /* For convenience we allow caller to give us a VI instead of a PD.  But
   * what we really want is the PD.
   */
  if (vi_or_pd->rs_type == EFRM_RESOURCE_VI) {
    pd = efrm_vi_get_pd(efrm_to_vi_resource(vi_or_pd));
    efrm_resource_ref(efrm_pd_to_resource(pd));
    efrm_resource_release(vi_or_pd);
  } else {
    pd = efrm_pd_from_resource(vi_or_pd);
  }

  max_pages = DIV_ROUND_UP(alloc->in_mem_bytes, PAGE_SIZE);
  if ((mr = efch_memreg_alloc(max_pages)) == NULL) {
    EFCH_ERR("%s: ERROR: out of mem (max_pages=%d)", __FUNCTION__, max_pages);
    rc = -ENOMEM;
    goto fail2;
  }

  down_read(&current->mm->mmap_sem);
  for (mr->n_pages = 0; mr->n_pages < max_pages; mr->n_pages += rc) {
    rc = get_user_pages(current, current->mm,
                        alloc->in_mem_ptr + mr->n_pages * PAGE_SIZE,
                        max_pages - mr->n_pages, 1, 0,
                        mr->pages + mr->n_pages, NULL);
    if (rc <= 0) {
      EFCH_ERR("%s: ERROR: get_user_pages(%d) returned %d",
               __FUNCTION__, max_pages - mr->n_pages, rc);
      break;
    }
  }
  up_read(&current->mm->mmap_sem);
  if (mr->n_pages < max_pages) {
    if (rc == 0)
      rc = -EFAULT;
    goto fail3;
  }

  rc = efrm_pd_dma_map(pd, mr->n_pages, 0,
                       mr->pages, sizeof(mr->pages[0]),
                       mr->dma_addrs, sizeof(mr->dma_addrs[0]),
                       (void *)(ci_uintptr_t)alloc->in_addrs_out_ptr,
                       alloc->in_addrs_out_stride,
                       put_user_64, &mr->buf_tbl_alloc);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: efrm_pd_dma_map failed (%d)", __FUNCTION__, rc);
    goto fail4;
  }
  mr->mapped = true;

  mr->pd = pd;
  ch_rs->rs_base = NULL;
  ch_rs->memreg = mr;
  /* ?? todo: alloc->something = something_else; */
  return 0;


 fail4:
 fail3:
  efch_memreg_free(mr);
 fail2:
  efrm_pd_release(pd);
 fail1:
  return rc;
}


static void memreg_rm_free(efch_resource_t *rs)
{
  efch_memreg_free(rs->memreg);
}


efch_resource_ops efch_memreg_ops = {
  .rm_alloc = memreg_rm_alloc,
  .rm_free = memreg_rm_free,
  .rm_mmap = NULL,
  .rm_nopage = NULL,
  .rm_dump = NULL,
  .rm_rsops = NULL,
  .rm_mmap_bytes = NULL,
};
