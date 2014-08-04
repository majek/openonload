/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

#include <ci/efhw/common.h>
#include <etherfabric/base.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"
#include "efch_intf_ver.h"


int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh, 
		    ef_pd* pd, ef_driver_handle pd_dh,
		    void* p_mem, int len_bytes)
{
  /* Note: At time of writing the driver rounds the registered region to
   * whole system pages.  It then writes a DMA address for each 4K page
   * within the system-aligned region.  This means that on PPC (where
   * system page size is 64K) we potentially get a bunch of DMA addresses
   * for 4K pages before the region we're registering.
   */
  int n_nic_pages, rc;
  ci_resource_alloc_t ra;
  char* p_mem_sys_base;
  char* p_end;
  size_t sys_len;

  /* The memory region must be aligned on a 4K boundary. */
  if( ((uintptr_t) p_mem & (EFHW_NIC_PAGE_SIZE - 1)) != 0 )
    return -EINVAL;

  p_mem_sys_base = (void*) ((uintptr_t) p_mem & CI_PAGE_MASK);
  p_end = (char*) p_mem + len_bytes;
  sys_len = CI_PTR_ALIGN_FWD(p_end, CI_PAGE_SIZE) - p_mem_sys_base;
  n_nic_pages = sys_len >> EFHW_NIC_PAGE_SHIFT;

  mr->mr_dma_addrs_base = malloc(n_nic_pages * sizeof(mr->mr_dma_addrs[0]));
  if( mr->mr_dma_addrs_base == NULL )
    return -ENOMEM;

  /* For a pd in a cluster, use the handle from clusterd */
  if( pd->pd_cluster_sock != -1 )
    pd_dh = pd->pd_cluster_dh;

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_MEMREG;
  ra.u.memreg.in_vi_or_pd_id = efch_make_resource_id(pd->pd_resource_id);
  ra.u.memreg.in_vi_or_pd_fd = pd_dh;
  ra.u.memreg.in_mem_ptr = (uintptr_t) p_mem_sys_base;
  ra.u.memreg.in_mem_bytes = sys_len;
  ra.u.memreg.in_addrs_out_ptr = (uintptr_t) mr->mr_dma_addrs_base;
  ra.u.memreg.in_addrs_out_stride = sizeof(mr->mr_dma_addrs_base[0]);

  rc = ci_resource_alloc(mr_dh, &ra);
  if( rc < 0 ) {
	  LOGVV(ef_log("ef_memreg_alloc: ci_resource_alloc %d", rc));
	  free(mr->mr_dma_addrs_base);
	  return rc;
  }

  mr->mr_dma_addrs = mr->mr_dma_addrs_base;
  mr->mr_dma_addrs +=
    ((char*) p_mem - p_mem_sys_base) >> EFHW_NIC_PAGE_SHIFT;
  mr->mr_resource_id = ra.out_id.index;
  return 0;
}


int ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh)
{
  free(mr->mr_dma_addrs_base);
  EF_VI_DEBUG(memset(mr, 0, sizeof(*mr)));
  return 0;
}
