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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ndt
**  \brief  Memory mapping of the VI resources.
**   \date  2006/10/19
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <ci/driver/internal.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/vi_resource_manager.h>
#include <etherfabric/ef_vi.h> /* For VI_MAPPING_* macros, vi_mappings type */
#include <ci/efrm/efrm_client.h>
#include "linux_char_internal.h"
#include "char_internal.h"


#ifndef NDEBUG
static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };
#endif


/*************************************************************************/


static int
efab_vi_rm_mmap_io(struct efrm_vi *virs,
                   unsigned long *bytes, void *opaque,
                   int *map_num, unsigned long *offset)
{
  int rc;
  int len;
  int instance;
  struct efhw_nic *nic;

  nic = efrm_client_get_nic(virs->rs.rs_client);

  instance = virs->rs.rs_instance;

  /* Map the control page. */
  len = CI_MIN(*bytes, CI_PAGE_SIZE);
  *bytes -=len;

  /* Make sure we can get away with a single page here. */
  ci_assert_lt(falcon_tx_dma_page_offset(instance), CI_PAGE_SIZE);
  ci_assert_lt(falcon_rx_dma_page_offset(instance), CI_PAGE_SIZE);
  ci_assert_lt(falcon_timer_page_offset(instance), CI_PAGE_SIZE);
  ci_assert_equal(falcon_tx_dma_page_base(instance),
                  falcon_rx_dma_page_base(instance));
  rc =  ci_mmap_bar(nic, falcon_tx_dma_page_base(instance), len, opaque,
                    map_num, offset);
  if (rc < 0 ) {
    EFCH_ERR("%s: ERROR: ci_mmap_bar failed rc=%d", __FUNCTION__, rc);
    return rc;
  }

  return 0;
}

static int 
efab_vi_rm_mmap_mem(struct efrm_vi *virs,
                    unsigned long *bytes, void *opaque,
                    int *map_num, unsigned long *offset)
{
  int queue_type;
  uint32_t len;

  if( virs->q[EFHW_EVQ].capacity != 0 ) {
    len = efhw_iopages_size(&virs->q[EFHW_EVQ].pages);
    len = CI_MIN(len, *bytes);
    ci_assert_gt(len, 0);
    ci_mmap_iopages(&virs->q[EFHW_EVQ].pages, 0,
                    len, bytes, opaque, map_num, offset);
    if(*bytes == 0)
      return 0;
  }

  for( queue_type=EFRM_VI_RM_DMA_QUEUE_COUNT-1;
       queue_type>=0;
       queue_type-- ) {
    if( virs->q[queue_type].capacity != 0 ) {
      len = efhw_iopages_size(&virs->q[queue_type].pages);
      len = CI_MIN(len, *bytes);
      ci_assert_gt(len, 0);
      ci_mmap_iopages(&virs->q[queue_type].pages, 0,
                      len, bytes, opaque, map_num, offset);
      if(*bytes == 0)
        return 0;
    }
  }

  return 0;
}

int efab_vi_resource_mmap(struct efrm_vi *virs, unsigned long *bytes,
                          void *opaque, int *map_num, unsigned long *offset,
                          int index)
{
  int rc;

  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
  ci_assert_equal((*bytes &~ CI_PAGE_MASK), 0);

  if( index == 0 )
    /* This is the IO mapping. */
    rc = efab_vi_rm_mmap_io(virs, bytes, opaque, map_num, offset);
  else
    /* This is the memory mapping. */
    rc = efab_vi_rm_mmap_mem(virs, bytes, opaque, map_num, offset);

  return rc;
}
EXPORT_SYMBOL(efab_vi_resource_mmap);

int
efab_vi_resource_mmap_bytes(struct efrm_vi* virs, int map_type)
{
  int bytes = 0;

  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);

  if( map_type == 0 ) {  /* I/O mapping. */
    bytes += CI_PAGE_SIZE;
  }
  else {              /* Memory mapping. */
    if( virs->q[EFHW_EVQ].capacity != 0 )
      bytes += efhw_iopages_size(&virs->q[EFHW_EVQ].pages);
    if( virs->q[EFHW_TXQ].capacity )
      bytes += efhw_iopages_size(&virs->q[EFHW_TXQ].pages);
    if( virs->q[EFHW_RXQ].capacity )
      bytes += efhw_iopages_size(&virs->q[EFHW_RXQ].pages);
  }

  /* Round up to whole number of pages. */
  return bytes;
}
EXPORT_SYMBOL(efab_vi_resource_mmap_bytes);


#if defined(CI_HAVE_OS_NOPAGE)
static 
ci_boolean_t
efab_vi_rm_nopage_nic(struct efrm_vi *virs, unsigned *pfn_ptr,
                      unsigned long offset)
{
  unsigned long len;
  int queue_type;

  if( virs->q[EFHW_EVQ].capacity != 0 ) {
    len = efhw_iopages_size(&virs->q[EFHW_EVQ].pages);
    if( offset < len ) {
      *pfn_ptr = efhw_iopages_pfn(&virs->q[EFHW_EVQ].pages,
                                  offset >> PAGE_SHIFT);
      EFCH_TRACE("%s: Matched the EVQ", __FUNCTION__);
      return CI_TRUE;
    }
    offset -= len;
  }

  for( queue_type=EFRM_VI_RM_DMA_QUEUE_COUNT-1;
       queue_type>=0;
       queue_type--) {
    len = efhw_iopages_size(&virs->q[queue_type].pages);
    if( offset < len ) {
      *pfn_ptr = efhw_iopages_pfn(&virs->q[queue_type].pages,
                                  offset >> PAGE_SHIFT);
      EFCH_TRACE("%s: Matched the %s", __FUNCTION__, q_names[queue_type]);
      return CI_TRUE;
    }
    offset -= len;
  }

  return CI_FALSE;
}

unsigned long
efab_vi_resource_nopage(struct efrm_vi *virs, void *opaque,
                        unsigned long offset, unsigned long map_size)
{
  unsigned result = -1;
  ci_boolean_t found = CI_FALSE;

  found = efab_vi_rm_nopage_nic(virs, &result, offset);
  ci_assert(found);

  return result;
}
EXPORT_SYMBOL(efab_vi_resource_nopage);

#endif /* CI_HAVE_OS_NOPAGE */

/* ************************************************************************** */

