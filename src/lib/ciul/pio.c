/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"
#include "efch_intf_ver.h"


int ef_pio_alloc(ef_pio* pio, ef_driver_handle pio_dh, ef_pd* pd,
                 unsigned len_hint, ef_driver_handle pd_dh)
{
  ci_resource_alloc_t ra;
  int rc;

  memset(pio, 0, sizeof(*pio));
  pio->pio_len = len_hint < 2048 ? len_hint : 2048;
  pio->pio_buffer = calloc(sizeof(uint8_t), pio->pio_len);
  if( ! pio->pio_buffer ) {
    LOGVV(ef_log("%s: calloc of pio_buffer failed", __FUNCTION__));
    return -ENOMEM;
  }

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_PIO;
  ra.u.pio.in_pd_fd = pd_dh;
  ra.u.pio.in_pd_id = efch_make_resource_id(pd->pd_resource_id);

  rc = ci_resource_alloc(pio_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc failed %d", __FUNCTION__, rc));
    goto err;
  }

  pio->pio_resource_id = ra.out_id.index;
  return 0;

 err:
  free(pio->pio_buffer);
  return rc;
}


int ef_pio_free(ef_pio* pio, ef_driver_handle dh)
{
  free(pio->pio_buffer);
  EF_VI_DEBUG(memset(pio, 0, sizeof(*pio)));
  return 0;
}


int ef_pio_link_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                   ef_driver_handle vi_dh)
{
  void* p;
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PIO_LINK_VI;
  op.id = efch_make_resource_id(pio->pio_resource_id);
  op.u.pio_link_vi.in_vi_fd = vi_dh;
  op.u.pio_link_vi.in_vi_id = efch_make_resource_id(vi->vi_resource_id);

  rc = ci_resource_op(pio_dh, &op);
  if( rc < 0 ) {
    LOGV(ef_log("%s: ci_resource_op failed %d", __FUNCTION__, rc));
    return rc;
  }

  if( pio->pio_io == NULL ) {
    rc = ci_resource_mmap(vi_dh, vi->vi_resource_id, 2, 4096, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (pio) %d", __FUNCTION__, rc));
      return rc;
    }
    pio->pio_io = (uint8_t*) p;
  }

  vi->linked_pio = pio;
  return 0;
}


int ef_pio_unlink_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                     ef_driver_handle vi_dh)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PIO_UNLINK_VI;
  op.id = efch_make_resource_id(pio->pio_resource_id);
  op.u.pio_unlink_vi.in_vi_fd = vi_dh;
  op.u.pio_unlink_vi.in_vi_id = efch_make_resource_id(vi->vi_resource_id);

  rc = ci_resource_op(pio_dh, &op);
  if( rc < 0 )
    LOGV(ef_log("%s: ci_resource_op failed %d", __FUNCTION__, rc));
  return rc;
}


int ef_vi_get_pio_size(ef_vi* vi)
{
  ef_pio* pio = vi->linked_pio;
  return pio->pio_len;
}
