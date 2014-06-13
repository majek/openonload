/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Resource for managing sets of I/O buffers.
**   \date  2003/10/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/base.h>
#include <etherfabric/iobufset.h>
#include <ci/driver/efab/os_intf.h>
#include <ci/efch/op_types.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include "efch_intf_ver.h"


int ef_iobufset_alloc(ef_iobufset* bufs, ef_driver_handle bufs_dh, 
		      ef_vi* vi, ef_driver_handle vi_dh,
		      int phys_addr_mode,
		      int size, int num, int align, int offset)
{
  ci_resource_alloc_t ra;
  void* p;
  int rc;

  EF_VI_BUG_ON(size <= 0);
  EF_VI_BUG_ON(num <= 0);
  EF_VI_BUG_ON(!EF_VI_IS_POW2(align));
  EF_VI_BUG_ON(align < 1);
  EF_VI_BUG_ON(offset < 0);

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_IOBUFSET;
  ra.u.iobufset.in_pd_or_vi_rs_id = efch_make_resource_id(vi->vi_resource_id);
  ra.u.iobufset.in_pd_or_vi_fd = vi_dh;
  ra.u.iobufset.in_linked_fd = -1;
  ra.u.iobufset.in_linked_rs_id = efch_resource_id_none();
  ra.u.iobufset.in_n_pages = ef_iobufset_dimension(bufs, size + offset,
						   num, align);
  ra.u.iobufset.in_phys_addr_mode = phys_addr_mode;

  rc = ci_resource_alloc(bufs_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("ef_iobufset_alloc: ci_resource_alloc %d", rc));
    return rc;
  }

  rc = ci_resource_mmap(bufs_dh, ra.out_id.index, 0,
                        ra.u.iobufset.out_mmap_bytes, &p);
  if( rc < 0 ) {
    LOGVV(ef_log("ef_iobufset_alloc: ci_resource_mmap %d", rc));
    return rc;
  }

  ef_iobufset_init(bufs, ra.u.iobufset.out_bufaddr, p, offset);
  bufs->bufs_mmap_bytes = ra.u.iobufset.out_mmap_bytes;
  bufs->bufs_resource_id = ra.out_id.index;
  return 0;
}


int ef_iobufset_remap(ef_iobufset* bs, ef_driver_handle bs_dh,
		      ef_vi* vi, ef_driver_handle vi_dh,
		      ef_driver_handle dh_for_this_op)
{
  ci_resource_alloc_t ra;
  int rc;

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_IOBUFSET;
  ra.u.iobufset.in_linked_fd = bs_dh;
  ra.u.iobufset.in_linked_rs_id = efch_make_resource_id(bs->bufs_resource_id);
  ra.u.iobufset.in_pd_or_vi_fd = vi_dh;
  ra.u.iobufset.in_pd_or_vi_rs_id = efch_make_resource_id(vi->vi_resource_id);
  rc = ci_resource_alloc(dh_for_this_op, &ra);
  if( rc < 0 )
    LOGVV(ef_log("ef_iobufset_alloc: ci_resource_alloc %d", rc));
  return rc;
}


int ef_iobufset_free(ef_iobufset* bufs, ef_driver_handle driver_handle)
{
  int rc;

  rc = ci_resource_munmap(driver_handle,
                          EF_VI_PTR_ALIGN_BACK(bufs->bufs_ptr,
                                               EF_VI_PAGE_SIZE),
                          bufs->bufs_mmap_bytes);
  if( rc < 0 ) {
    LOGV(ef_log("ef_iobufset_free: ci_resource_munmap %d", rc));
    return rc;
  }

  EF_VI_DEBUG(memset(bufs, 0, sizeof(*bufs)));

  return 0;
}


/*! \cidoxg_end */
