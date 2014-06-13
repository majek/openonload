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
#include <etherfabric/pd.h>
#include <ci/driver/efab/os_intf.h>
#include <ci/efch/op_types.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include "efch_intf_ver.h"


int ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
		int ifindex, enum ef_pd_flags flags)
{
  ci_resource_alloc_t ra;
  const char* s;
  int rc;

  if( (s = getenv("EF_VI_PD_FLAGS")) != NULL ) {
    if( strstr(s, "vf") != NULL )
      flags |= EF_PD_VF;
    if( strstr(s, "phys") != NULL )
      flags |= EF_PD_PHYS_MODE;
  }

  if( flags & EF_PD_VF )
    flags |= EF_PD_PHYS_MODE;

  memset(&ra, 0, sizeof(ra));
  strncpy(ra.intf_ver, EFCH_INTF_VER, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_PD;
  ra.u.pd.in_ifindex = ifindex;
  ra.u.pd.in_flags = 0;
  if( flags & EF_PD_VF )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_VF;
  if( (flags & EF_PD_VF) || (flags & EF_PD_PHYS_MODE) )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_PHYS_ADDR;

  rc = ci_resource_alloc(pd_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("ef_pd_alloc: ci_resource_alloc %d", rc));
    return rc;
  }

  pd->pd_flags = flags;
  pd->pd_resource_id = ra.out_id.index;
  return 0;
}


int ef_pd_free(ef_pd* pd, ef_driver_handle pd_dh)
{
  EF_VI_DEBUG(memset(pd, 0, sizeof(*pd)));
  return 0;
}
