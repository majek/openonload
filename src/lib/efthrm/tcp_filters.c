/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
#include <ci/efrm/vi_set.h>
#include <ci/driver/efab/hardware.h>
#include "tcp_filters_internal.h"
#include "oo_hw_filter.h"
#include <driver/linux_net/driverlink_api.h>
#include <onload/nic.h>

/*
 * Module option to control whether getting an error (EBUSY) on some
 * ports when adding a filter is fatal or not.
 *
 * We need this to support the case where we have >1 PF on a physical
 * port
 */
int oof_all_ports_required = 1;


static struct efrm_client* get_client(int hwport)
{
  ci_assert((unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES);
  return oo_nics[hwport].efrm_client;
}


void oo_hw_filter_init(struct oo_hw_filter* oofilter)
{
  int i;
  oofilter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
  oofilter->trs = NULL;
  oofilter->thc = NULL;
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    oofilter->filter_id[i] = -1;
}


static void oo_hw_filter_clear_hwport(struct oo_hw_filter* oofilter,
                                      int hwport)
{
  ci_assert((unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES);
  if( oofilter->filter_id[hwport] >= 0 ) {
    efrm_filter_remove(get_client(hwport), oofilter->filter_id[hwport]);
    oofilter->filter_id[hwport] = -1;
  }
}


void oo_hw_filter_clear(struct oo_hw_filter* oofilter)
{
  int hwport;

  if( oofilter->trs != NULL || oofilter->thc != NULL ) {
    for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
      oo_hw_filter_clear_hwport(oofilter, hwport);
    oofilter->trs = NULL;
    oofilter->thc = NULL;
  }
  else {
    for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
      ci_assert(oofilter->filter_id[hwport] < 0);
  }
}


void oo_hw_filter_clear_hwports(struct oo_hw_filter* oofilter,
                                unsigned hwport_mask)
{
  int hwport;

  ci_assert_equal(oofilter->thc, NULL);
  if( oofilter->trs != NULL )
    for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
      if( hwport_mask & (1 << hwport) )
        oo_hw_filter_clear_hwport(oofilter, hwport);
}


static int oo_hw_filter_set_hwport(struct oo_hw_filter* oofilter, int hwport,
                                   int protocol,
                                   unsigned saddr, int sport,
                                   unsigned daddr, int dport,
                                   ci_uint16 vlan_id, unsigned src_flags)
{
  struct efx_filter_spec spec;
  int rc = 0, vi_id;

  ci_assert_equal(oofilter->thc, NULL);
  ci_assert(oofilter->filter_id[hwport] < 0);

  if( (vi_id = tcp_helper_rx_vi_id(oofilter->trs, hwport)) >= 0 ) {
    int flags = EFX_FILTER_FLAG_RX_SCATTER;
    int hw_rx_loopback_supported =
      tcp_helper_vi_hw_rx_loopback_supported(oofilter->trs, hwport);

    ci_assert( hw_rx_loopback_supported >= 0 );
    if( hw_rx_loopback_supported && (src_flags & OO_HW_SRC_FLAG_LOOPBACK) ) {
      flags |= EFX_FILTER_FLAG_TX;
    }

    efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED, flags, vi_id);

#if EFX_DRIVERLINK_API_VERSION >= 15
    {
      unsigned stack_id = tcp_helper_vi_hw_stack_id(oofilter->trs, hwport);
      ci_assert( stack_id >= 0 );
      efx_filter_set_stack_id(&spec, stack_id);
    }
#endif

    if( saddr != 0 )
      rc = efx_filter_set_ipv4_full(&spec, protocol, daddr, dport,
                                    saddr, sport);
    else
      rc = efx_filter_set_ipv4_local(&spec, protocol, daddr, dport);
    ci_assert_equal(rc, 0);
    /* note: bug 42561 affecting loopback on VLAN 0 with fw <= v4_0_6_6688 */
    if( vlan_id != OO_HW_VLAN_UNSPEC ) {
      rc = efx_filter_set_eth_local(&spec, vlan_id, NULL);
      ci_assert_equal(rc, 0);
    }
    rc = efrm_filter_insert(get_client(hwport), &spec, false);
    if( rc >= 0 ) {
      oofilter->filter_id[hwport] = rc;
      rc = 0;
    }
  }
  return rc;
}


int oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                             int protocol,
                             unsigned saddr, int sport,
                             unsigned daddr, int dport,
                             ci_uint16 vlan_id, unsigned set_vlan_mask,
                             unsigned hwport_mask, unsigned src_flags)
{
  int rc1, rc = 0, ok_seen = 0, hwport;
  uint16_t set_vlan_id;

  ci_assert(oofilter->trs != NULL);
  ci_assert_equal(oofilter->thc, NULL);

  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( (hwport_mask & (1u << hwport)) && oofilter->filter_id[hwport] < 0 ) {
      /* If we've been told to set the vlan when installing the filter on this
       * port then use provided vlan_id, otherwise use OO_HW_VLAN_UNSPEC.
       */
      set_vlan_id = (set_vlan_mask & (1u << hwport)) ?
        vlan_id : OO_HW_VLAN_UNSPEC;
      rc1 = oo_hw_filter_set_hwport(oofilter, hwport, protocol,
                                    saddr, sport, daddr, dport, set_vlan_id,
                                    src_flags);
      /* Need to know if any interfaces are ok */
      if( ! rc1 )
        ok_seen = 1;
      /* Preserve the most severe error seen - other errors are more severe
       * then firewall denial, and it is more severe than no error.
       */
      if( rc1 && ( !rc || rc == -EACCES ||
                   (rc == -EBUSY && !oof_all_ports_required) ) )
        rc = rc1;
    }
  if( ok_seen && 
      ( ( rc == -EACCES ) || 
        ( !oof_all_ports_required && ( rc == -EBUSY ) ) ) ) {
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
                     ci_uint16 vlan_id, unsigned set_vlan_mask,
                     unsigned hwport_mask, unsigned src_flags)
{
  int rc;

  ci_assert_equal(oofilter->thc, NULL);
  oo_hw_filter_clear(oofilter);
  oofilter->trs = trs;
  rc = oo_hw_filter_add_hwports(oofilter, protocol, saddr, sport, daddr, dport,
                                vlan_id, set_vlan_mask, hwport_mask, src_flags);
  if( rc < 0 )
    oo_hw_filter_clear(oofilter);
  return rc;
}


int oo_hw_filter_update(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* new_stack,
                        int protocol,
                        unsigned saddr, int sport,
                        unsigned daddr, int dport,
                        ci_uint16 vlan_id, unsigned set_vlan_mask,
                        unsigned hwport_mask, unsigned src_flags)
{
  unsigned add_hwports = 0u;
  int hwport, vi_id;

  /* TODO: clustering: This needed for handling NIC resets
   */
  if( oofilter->thc != NULL ) {
    ci_log("%s: ERROR: not supported on clustered filters", __FUNCTION__);
    return -EINVAL;
  }

  oo_hw_filter_clear_hwports(oofilter, ~hwport_mask);

  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( hwport_mask & (1 << hwport) ) {
      if( (vi_id = tcp_helper_rx_vi_id(new_stack, hwport)) >= 0 ) {
        if( oofilter->filter_id[hwport] >= 0 ) {
          unsigned stack_id = tcp_helper_vi_hw_stack_id(new_stack, hwport);
          ci_assert( stack_id >= 0 );
          efrm_filter_redirect(get_client(hwport), oofilter->filter_id[hwport],
                               vi_id, stack_id);
        }
        else {
          add_hwports |= 1 << hwport;
        }
      }
      else {
        oo_hw_filter_clear_hwport(oofilter, hwport);
      }
    }

  /* Insert new filters for any other interfaces in hwport_mask. */
  oofilter->trs = new_stack;
  return oo_hw_filter_add_hwports(oofilter, protocol, saddr, sport,
                                  daddr, dport, vlan_id, set_vlan_mask,
                                  add_hwports, src_flags);
}


void oo_hw_filter_transfer(struct oo_hw_filter* oofilter_old,
                           struct oo_hw_filter* oofilter_new,
                           unsigned hwport_mask)
{
  int hwport;

  ci_assert_equal(oofilter_new->thc, NULL);
  ci_assert_equal(oofilter_old->thc, NULL);
  if( oofilter_old->trs == NULL )
    return;

  ci_assert_equal(oofilter_old->trs, oofilter_new->trs);

  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( (hwport_mask & (1u << hwport)) &&
        oofilter_old->filter_id[hwport] >= 0 ) {
      ci_assert(oofilter_new->filter_id[hwport] < 0);
      oofilter_new->filter_id[hwport] = oofilter_old->filter_id[hwport];
      oofilter_old->filter_id[hwport] = -1;
    }
}


unsigned oo_hw_filter_hwports(struct oo_hw_filter* oofilter)
{
  unsigned hwport_mask = 0;
  int hwport;

  if( oofilter->trs != NULL || oofilter->thc != NULL )
    for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
      if( oofilter->filter_id[hwport] >= 0 )
        hwport_mask |= 1 << hwport;
  return hwport_mask;
}


int oo_hw_filter_set_thc(struct oo_hw_filter* oofilter,
                         tcp_helper_cluster_t* thc, int protocol,
                         unsigned daddr, int dport,
                         unsigned hwport_mask)
{
  struct efx_filter_spec spec;
  int hwport, base_vi_id, rc;

  ci_assert_equal(oofilter->trs, NULL);
  oofilter->thc = thc;
  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( hwport_mask & (1 << hwport) && thc->thc_vi_set[hwport] != NULL ) {
      base_vi_id = efrm_vi_set_get_base(thc->thc_vi_set[hwport]);
      efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                         EFX_FILTER_FLAG_RX_SCATTER | EFX_FILTER_FLAG_RX_RSS,
                         base_vi_id);
      spec.rss_context = efrm_vi_set_get_rss_context(thc->thc_vi_set[hwport]);
#if EFX_DRIVERLINK_API_VERSION >= 15
      {
        int stack_id = tcp_helper_cluster_vi_hw_stack_id(thc, hwport);
        ci_assert( stack_id >= 0 );
        efx_filter_set_stack_id(&spec, stack_id);
      }
#endif
      rc = efx_filter_set_ipv4_local(&spec, protocol, daddr, dport);
      ci_assert_equal(rc, 0);
      rc = efrm_filter_insert(get_client(hwport), &spec, false);
      if( rc < 0 ) {
        oo_hw_filter_clear(oofilter);
        return rc;
      }
      oofilter->filter_id[hwport] = rc;
    }
  return 0;
}
