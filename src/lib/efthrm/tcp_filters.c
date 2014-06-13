/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
#include <ci/efrm/efrm_filter.h>
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


void oo_hw_filter_init(struct oo_hw_filter* oofilter)
{
  int i;
  oofilter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
  oofilter->trs = NULL;
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    oofilter->filter_id[i] = -1;
}


void oo_hw_filter_clear(struct oo_hw_filter* oofilter)
{
  int intf_i;

  if( oofilter->trs == NULL )
    return;

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i )
    if( oofilter->filter_id[intf_i] >= 0 ) {
      efx_dl_filter_remove(dl_device(oofilter->trs, intf_i),
                           oofilter->filter_id[intf_i]);
      oofilter->filter_id[intf_i] = -1;
    }
  oofilter->trs = NULL;
}


void oo_hw_filter_clear_hwports(struct oo_hw_filter* oofilter,
                                unsigned hwport_mask)
{
  int intf_i, hwport;

  if( oofilter->trs != NULL )
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      hwport = oofilter->trs->netif.intf_i_to_hwport[intf_i];
      if( oofilter->filter_id[intf_i] >= 0 &&
          (hwport < 0 || (hwport_mask & (1u << hwport))) ) {
        efx_dl_filter_remove(dl_device(oofilter->trs, intf_i),
                             oofilter->filter_id[intf_i]);
        oofilter->filter_id[intf_i] = -1;
      }
    }
}


static int oo_hw_filter_set_intf(struct oo_hw_filter* oofilter, int intf_i,
                                 int protocol,
                                 unsigned saddr, int sport,
                                 unsigned daddr, int dport)
{
  struct efx_filter_spec spec;
  struct efrm_vi* efrm_vi;
  int rc;

  ci_assert(oofilter->filter_id[intf_i] < 0);

  efrm_vi = tcp_helper_rx_vi_rs(oofilter->trs, intf_i);
  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                     EFX_FILTER_FLAG_RX_SCATTER,
                     EFAB_VI_RESOURCE_INSTANCE(efrm_vi));
  if( saddr != 0 )
    rc = efx_filter_set_ipv4_full(&spec, protocol, daddr, dport,
                                  saddr, sport);
  else
    rc = efx_filter_set_ipv4_local(&spec, protocol, daddr, dport);
  ci_assert_equal(rc, 0);
  rc = efrm_filter_insert(dl_device(oofilter->trs, intf_i), &spec, false);
  if( rc >= 0 ) {
    oofilter->filter_id[intf_i] = rc;
    rc = 0;
  }
  return rc;
}


int oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                             int protocol,
                             unsigned saddr, int sport,
                             unsigned daddr, int dport,
                             unsigned hwport_mask)
{
  tcp_helper_resource_t* trs = oofilter->trs;
  int rc = 0, intf_i;
  int ok_seen = 0;

  ci_assert(trs != NULL);

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    if( (hwport_mask & (1u << trs->netif.intf_i_to_hwport[intf_i])) &&
        oofilter->filter_id[intf_i] < 0 ) {
      int rc1 = oo_hw_filter_set_intf(oofilter, intf_i, protocol, saddr, sport,
                                      daddr, dport);
      /* Need to know if any interfaces are ok */
      if( !rc1 )
        ok_seen = 1;
      /* Preserve the most severe error seen - other errors are more severe
       * then firewall denial, and it is more severe than no error.
       */
      if( rc1 && ( !rc || rc == -EACCES ) )
        rc = rc1;
    }
  if( ok_seen && rc == -EACCES ) {
    /* If some interfaces, but not ALL interfaces, have blocked the filter
     *  then consider the filter added.
     */
    rc = 0;
  }
  return rc;
}


int oo_hw_filter_set(struct oo_hw_filter* oofilter,
                     tcp_helper_resource_t* trs, int protocol,
                     unsigned saddr, int sport,
                     unsigned daddr, int dport,
                     unsigned hwport_mask)
{
  int rc;

  if( oofilter->trs )
    oo_hw_filter_clear(oofilter);

  oofilter->trs = trs;
  rc = oo_hw_filter_add_hwports(oofilter, protocol, saddr, sport,
                                daddr, dport, hwport_mask);
  if( rc < 0 )
    oo_hw_filter_clear(oofilter);
  return rc;
}


static void oo_hw_filter_redirect(struct oo_hw_filter* oofilter,
                                  struct tcp_helper_resource_s* new_stack,
                                  int protocol,
                                  unsigned saddr, int sport,
                                  unsigned daddr, int dport,
                                  unsigned hwport_mask)
{
  tcp_helper_resource_t* old_stack = oofilter->trs;
  int new_filter_id[CI_CFG_MAX_INTERFACES];
  int i, old_intf_i, new_intf_i, hwport;
  struct efrm_vi* efrm_vi;

  /* For each filter pointing at old stack, redirect to new stack. */
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    new_filter_id[i] = -1;
  for( old_intf_i = 0; old_intf_i < CI_CFG_MAX_INTERFACES; ++old_intf_i )
    if( oofilter->filter_id[old_intf_i] >= 0 &&
        (hwport = old_stack->netif.intf_i_to_hwport[old_intf_i]) >= 0 &&
        (new_intf_i = new_stack->netif.hwport_to_intf_i[hwport]) >= 0 &&
        (hwport_mask & (1u << hwport)) ) {
      efrm_vi = tcp_helper_rx_vi_rs(new_stack, new_intf_i);
      efx_dl_filter_redirect(dl_device(old_stack, old_intf_i),
                             oofilter->filter_id[old_intf_i],
                             EFAB_VI_RESOURCE_INSTANCE(efrm_vi));
      new_filter_id[new_intf_i] = oofilter->filter_id[old_intf_i];
      oofilter->filter_id[old_intf_i] = -1;
    }
  oo_hw_filter_clear_hwports(oofilter, OO_HW_PORT_ALL);
  memcpy(oofilter->filter_id, new_filter_id, sizeof(oofilter->filter_id));
  oofilter->trs = new_stack;
}


int oo_hw_filter_update(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* new_stack,
                        int protocol,
                        unsigned saddr, int sport,
                        unsigned daddr, int dport,
                        unsigned hwport_mask)
{
  if( oofilter->trs != NULL ) {
    /* Clear filters we don't want any more, and if redirecting to a
     * different stack, then redirect filters on interfaces we want to
     * keep.
     */
    if( new_stack != oofilter->trs )
      oo_hw_filter_redirect(oofilter, new_stack, protocol, saddr, sport,
                            daddr, dport, hwport_mask);
    else
      oo_hw_filter_clear_hwports(oofilter, ~hwport_mask);
  }
  oofilter->trs = new_stack;

  /* Insert new filters for any other interfaces in hwport_mask. */
  return oo_hw_filter_add_hwports(oofilter, protocol, saddr, sport,
                                  daddr, dport, hwport_mask);
}


unsigned oo_hw_filter_hwports(struct oo_hw_filter* oofilter)
{
  tcp_helper_resource_t* trs = oofilter->trs;
  unsigned hwport_mask = 0;
  int intf_i;
  if( trs != NULL )
    OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
      if( oofilter->filter_id[intf_i] >= 0 )
        hwport_mask |= 1 << trs->netif.intf_i_to_hwport[intf_i];
  return hwport_mask;
}
