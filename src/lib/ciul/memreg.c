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
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  Registered memory.
**   \date  2012/02/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <etherfabric/base.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include <ci/driver/efab/os_intf.h>
#include <ci/efch/op_types.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include "efch_intf_ver.h"


int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh, 
		    ef_pd* pd, ef_driver_handle pd_dh,
		    void* p_mem, int len_bytes)
{
  ci_resource_alloc_t ra;
  int n_pages;
  int rc;

  n_pages = (len_bytes + 4095) >> 12u;
  mr->mr_dma_addrs = malloc(n_pages * sizeof(mr->mr_dma_addrs[0]));
  if( mr->mr_dma_addrs == NULL )
    return -ENOMEM;

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_MEMREG;
  ra.u.memreg.in_vi_or_pd_id = efch_make_resource_id(pd->pd_resource_id);
  ra.u.memreg.in_vi_or_pd_fd = pd_dh;
  ra.u.memreg.in_mem_ptr = (uintptr_t) p_mem;
  ra.u.memreg.in_mem_bytes = len_bytes;
  ra.u.memreg.in_addrs_out_ptr = (uintptr_t) mr->mr_dma_addrs;
  ra.u.memreg.in_addrs_out_stride = sizeof(mr->mr_dma_addrs[0]);

  rc = ci_resource_alloc(mr_dh, &ra);
  if( rc < 0 ) {
	  LOGVV(ef_log("ef_memreg_alloc: ci_resource_alloc %d", rc));
	  free(mr->mr_dma_addrs);
	  return rc;
  }

  mr->mr_resource_id = ra.out_id.index;
  return 0;
}


int ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh)
{
  EF_VI_DEBUG(memset(mr, 0, sizeof(*mr)));
  return 0;
}
