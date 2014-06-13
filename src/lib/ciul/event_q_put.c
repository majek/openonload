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
**  \brief  ef_eventq_put()
**   \date  2004/05/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ef */
#include <ci/driver/efab/os_intf.h>
#include <ci/efch/op_types.h>
#include "ef_vi_internal.h"
#include <etherfabric/misc.h>


int ef_eventq_put(efch_resource_id_t evq_id, ef_driver_handle fd, unsigned ev)
{
  ci_resource_op_t  op;
  int64_t ev64;

  BUG_ON((ev & EFVI_FALCON_EVENT_SW_DATA_MASK) != ev);
  ev64 = ev;
  ev64 |= (uint64_t) DRV_GEN_EV_DECODE << EV_CODE_LBN;

  op.op = CI_RSOP_EVENTQ_PUT;
  op.id = evq_id;
  op.u.evq_put.ev.u64 = cpu_to_le64(ev64);
  return ci_resource_op(fd, &op);
}
