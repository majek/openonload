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
** \author Martin Porter
**  \brief Filter handling code for TCP stack
**   \date Sept 2004
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/cplane.h>
#include <onload/debug.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/driverlink_filter.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vi_resource.h>
#include <ci/driver/efab/hardware.h>
#include "tcp_filters_internal.h"
#include "oo_hw_filter.h"
#include <driver/linux_net/driverlink_api.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <onload/nic.h>


static struct efx_dl_device* dl_device(tcp_helper_resource_t* trs,
                                       int intf_i)
{
  struct efhw_nic* efhw_nic;
  efhw_nic = efrm_client_get_nic(trs->nic[intf_i].oo_nic->efrm_client);
  return linux_efhw_nic(efhw_nic)->dl_device;
}


void oo_hw_filter_clear(struct oo_hw_filter* oofilter)
{
  int intf_i;

  if( oofilter->trs == NULL )
    return;

  OO_STACK_FOR_EACH_INTF_I(&oofilter->trs->netif, intf_i)
    if( oofilter->filter_id[intf_i] >= 0 ) {
      efx_dl_filter_remove(dl_device(oofilter->trs, intf_i),
                           oofilter->filter_id[intf_i]);
      oofilter->filter_id[intf_i] = -1;
    }
  oofilter->trs = NULL;
}


void oo_hw_filter_init(struct oo_hw_filter* oofilter)
{
  int i, max;
  oofilter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
  oofilter->trs = NULL;
  max = sizeof(oofilter->filter_id) / sizeof(oofilter->filter_id[0]);
  for( i = 0; i < max; ++i )
    oofilter->filter_id[i] = -1;
}


int oo_hw_filter_set(struct oo_hw_filter* oofilter,
                     tcp_helper_resource_t* trs, int protocol,
                     unsigned saddr, int sport,
                     unsigned daddr, int dport,
                     unsigned hwport_mask)
{
  struct efx_filter_spec spec;
  struct efrm_vi* efrm_vi;
  int rc, intf_i;

  if( oofilter->trs )
    oo_hw_filter_clear(oofilter);

  oofilter->trs = trs;

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( hwport_mask & (1 << trs->netif.intf_i_to_hwport[intf_i]) ) {
      efrm_vi = tcp_helper_rx_vi_rs(trs, intf_i);
      efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                         EFX_FILTER_FLAG_RX_SCATTER,
                         EFAB_VI_RESOURCE_INSTANCE(efrm_vi));
      if( saddr != 0 )
        rc = efx_filter_set_ipv4_full(&spec, protocol, daddr, dport,
                                      saddr, sport);
      else
        rc = efx_filter_set_ipv4_local(&spec, protocol, daddr, dport);
      ci_assert_equal(rc, 0);
      rc = efx_dl_filter_insert(dl_device(trs, intf_i), &spec, false);
      if( rc < 0 ) {
        oo_hw_filter_clear(oofilter);
        return rc;
      }
      oofilter->filter_id[intf_i] = rc;
    }
  }
  return 0;
}


void oo_hw_filter_move(struct oo_hw_filter* oofilter,
                       struct tcp_helper_resource_s* new_stack)
{
  struct efrm_vi* efrm_vi;
  int intf_i;

  ci_assert(oofilter->trs != NULL);
  ci_assert(new_stack != NULL);
  ci_assert(new_stack != oofilter->trs);

  /* ?? FIXME: What if set of interfaces for old and new stacks are
   * different?
   */
  OO_STACK_FOR_EACH_INTF_I(&new_stack->netif, intf_i) {
    efrm_vi = tcp_helper_rx_vi_rs(new_stack, intf_i);
    efx_dl_filter_redirect(dl_device(oofilter->trs, intf_i),
                           oofilter->filter_id[intf_i],
                           EFAB_VI_RESOURCE_INSTANCE(efrm_vi));
  }
  oofilter->trs = new_stack;
}
