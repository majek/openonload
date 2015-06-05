/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"

#include <net/if.h>


static int __ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
			 int ifindex, enum ef_pd_flags flags, int vlan_id)
{
  ci_resource_alloc_t ra;
  const char* s;
  int rc;

  if( (s = getenv("EF_VI_PD_FLAGS")) != NULL ) {
    if( ! strcmp(s, "vf") )
      flags = EF_PD_VF;
    else if( ! strcmp(s, "phys") )
      flags = EF_PD_PHYS_MODE;
    else if( ! strcmp(s, "default") )
      flags = 0;
  }

  if( flags & EF_PD_VF )
    flags |= EF_PD_PHYS_MODE;

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_PD;
  ra.u.pd.in_ifindex = ifindex;
  ra.u.pd.in_flags = 0;
  if( flags & EF_PD_VF )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_VF;
  if( flags & EF_PD_PHYS_MODE )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_PHYS_ADDR;
  if( flags & EF_PD_RX_PACKED_STREAM )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_RX_PACKED_STREAM;
  if( flags & EF_PD_VPORT )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_VPORT;
  if( flags & EF_PD_MCAST_LOOP )
    ra.u.pd.in_flags |= EFCH_PD_FLAG_MCAST_LOOP;
  ra.u.pd.in_vlan_id = vlan_id;

  rc = ci_resource_alloc(pd_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("ef_pd_alloc: ci_resource_alloc %d", rc));
    return rc;
  }

  pd->pd_flags = flags;
  pd->pd_resource_id = ra.out_id.index;

  pd->pd_intf_name = malloc(IF_NAMESIZE);
  if( pd->pd_intf_name == NULL ) {
    LOGVV(ef_log("ef_pd_alloc: malloc failed"));
    return -ENOMEM;
  }
  if( if_indextoname(ifindex, pd->pd_intf_name) == NULL ) {
    free(pd->pd_intf_name);
    LOGVV(ef_log("ef_pd_alloc: if_indextoname failed %d", errno));
    return -errno;
  }

  pd->pd_cluster_name = NULL;
  pd->pd_cluster_sock = -1;
  pd->pd_cluster_dh = 0;
  pd->pd_cluster_viset_resource_id = 0;

  return 0;
}


int ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
		int ifindex, enum ef_pd_flags flags)
{
  return __ef_pd_alloc(pd, pd_dh, ifindex, flags, -1);
}


int ef_pd_alloc_with_vport(ef_pd* pd, ef_driver_handle pd_dh,
			   const char* intf_name,
			   enum ef_pd_flags flags, int vlan_id)
{
  int ifindex = if_nametoindex(intf_name);
  if( ifindex == 0 )
    return -errno;
  return __ef_pd_alloc(pd, pd_dh, ifindex, flags | EF_PD_VPORT, vlan_id);
}


const char* ef_pd_interface_name(ef_pd* pd)
{
  return pd->pd_intf_name;
}


int ef_pd_free(ef_pd* pd, ef_driver_handle pd_dh)
{
  free(pd->pd_intf_name);
  if( pd->pd_cluster_sock != -1 ) {
    return ef_pd_cluster_free(pd, pd_dh);
  }
  else {
    EF_VI_DEBUG(memset(pd, 0, sizeof(*pd)));
    return 0;
  }
}
