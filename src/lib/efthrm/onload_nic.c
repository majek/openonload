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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/09/10
** Description: Onload nic management.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/nic.h>
#include <ci/efhw/efhw_types.h>
#include <ci/efrm/efrm_client.h>
#include <onload/cplane.h>
#include <onload/tcp_driver.h>


struct oo_nic oo_nics[CI_CFG_MAX_REGISTER_INTERFACES];
int oo_n_nics;


static void cplane_add(struct oo_nic* onic)
{
  int oo_nic_i = onic - oo_nics;
  ci_hwport_id_t hwport = CI_HWPORT_ID(oo_nic_i);
  cicp_encap_t encapsulation;

  cicp_hwport_add_nic(&CI_GLOBAL_CPLANE, hwport);

  encapsulation.type = CICP_LLAP_TYPE_SFC;
  encapsulation.vlan_id = 0;
  cicp_llap_set_hwport(&CI_GLOBAL_CPLANE,
                       efrm_client_get_ifindex(onic->efrm_client),
                       hwport, &encapsulation);
}


static void cplane_remove(struct oo_nic* onic)
{
  cicp_llap_set_hwport(&CI_GLOBAL_CPLANE,
                       efrm_client_get_ifindex(onic->efrm_client),
                       CI_HWPORT_ID_BAD, NULL);
  cicp_hwport_remove_nic(&CI_GLOBAL_CPLANE, CI_HWPORT_ID(onic - oo_nics));
}


struct oo_nic* oo_nic_add(struct efrm_client* efrm_client)
{
  struct oo_nic* onic;
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  int ifindex = efrm_client_get_ifindex(efrm_client);

  for( i = 0; i < max; ++i )
    if( (onic = &oo_nics[i])->efrm_client == NULL )
      break;
  if( i == max ) {
    ci_log("%s: NOT registering ifindex=%d (too many)", __FUNCTION__, ifindex);
    return NULL;
  }

  onic->efrm_client = efrm_client;
  ++oo_n_nics;
  ci_log("%s: ifindex=%d oo_index=%d", __FUNCTION__, ifindex, i);
  cplane_add(onic);
  return onic;
}


void oo_nic_remove(struct oo_nic* onic)
{
  int ifindex = efrm_client_get_ifindex(onic->efrm_client);
  ci_log("%s: ifindex=%d oo_index=%d",
         __FUNCTION__, ifindex, (int) (onic - oo_nics));
  ci_assert(oo_n_nics > 0);
  ci_assert(onic->efrm_client != NULL);
  cplane_remove(onic);
  --oo_n_nics;
  onic->efrm_client = NULL;
}


struct oo_nic* oo_nic_find_ifindex(int ifindex)
{
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  for( i = 0; i < max; ++i )
    if( oo_nics[i].efrm_client != NULL &&
        efrm_client_get_ifindex(oo_nics[i].efrm_client) == ifindex )
      return &oo_nics[i];
  return NULL;
}


int oo_nic_hwport(struct oo_nic* onic)
{
  int oo_nic_i = onic - oo_nics;
  return CI_HWPORT_ID(oo_nic_i);
}
