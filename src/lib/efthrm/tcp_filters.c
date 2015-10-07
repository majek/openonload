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

#define KERNEL_REDIRECT_VI_ID 0

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


void oo_hw_filter_init2(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* trs,
                        struct tcp_helper_cluster_s* thc)
{
  int i;
  oofilter->dlfilter_handle = EFX_DLFILTER_HANDLE_BAD;
  oofilter->trs = trs;
  oofilter->thc = thc;
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    oofilter->filter_id[i] = -1;
}


void oo_hw_filter_init(struct oo_hw_filter* oofilter)
{
  oo_hw_filter_init2(oofilter, NULL, NULL);
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
                                unsigned hwport_mask, int redirect)
{
  int hwport;

  if( redirect || oofilter->trs != NULL || oofilter->thc != NULL )
    for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
      if( hwport_mask & (1 << hwport) )
        oo_hw_filter_clear_hwport(oofilter, hwport);
}


static int
oo_hw_filter_set_hwport(struct oo_hw_filter* oofilter, int hwport,
                        const struct oo_hw_filter_spec* oo_filter_spec,
                        unsigned src_flags)
{
  struct efx_filter_spec spec;
  int rc = 0;
  int vi_id;
  const u8* mac_ptr = NULL;
  int replace = false;
  int kernel_redirect = src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT;
  int cluster = (oofilter->thc != NULL) && ! kernel_redirect;

  if( ! kernel_redirect )
    ci_assert_nequal(oofilter->trs == NULL, oofilter->thc == NULL);
  ci_assert(oofilter->filter_id[hwport] < 0);

  if( kernel_redirect )
    vi_id = KERNEL_REDIRECT_VI_ID;
  else {
    vi_id = cluster ?
      tcp_helper_cluster_vi_base(oofilter->thc, hwport) :
      tcp_helper_rx_vi_id(oofilter->trs, hwport);
  }

  if( vi_id  >= 0 ) {
    int flags = EFX_FILTER_FLAG_RX_SCATTER;
    int hw_rx_loopback_supported = (cluster || kernel_redirect) ?
      0 : tcp_helper_vi_hw_rx_loopback_supported(oofilter->trs, hwport);

    ci_assert( hw_rx_loopback_supported >= 0 );
    if( hw_rx_loopback_supported && (src_flags & OO_HW_SRC_FLAG_LOOPBACK) ) {
      flags |= EFX_FILTER_FLAG_TX;
    }

    if( cluster )
      flags |= EFX_FILTER_FLAG_RX_RSS;

    efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED, flags, vi_id);

    if( cluster ) {
      int rss_context = -1;
      if( src_flags & OO_HW_SRC_FLAG_RSS_DST )
        rss_context = efrm_vi_set_get_rss_context
            (oofilter->thc->thc_vi_set[hwport], EFRM_RSS_MODE_ID_DST);
      if( rss_context == -1 )
        /* fallback to default RSS context */
        rss_context = efrm_vi_set_get_rss_context
            (oofilter->thc->thc_vi_set[hwport], EFRM_RSS_MODE_ID_DEFAULT);
      spec.rss_context = rss_context;
    }

#if EFX_DRIVERLINK_API_VERSION >= 15
    if( ! kernel_redirect ) {
      unsigned stack_id = cluster ?
        tcp_helper_cluster_vi_hw_stack_id(oofilter->thc, hwport) :
        tcp_helper_vi_hw_stack_id(oofilter->trs, hwport);
      ci_assert( stack_id >= 0 );
      efx_filter_set_stack_id(&spec, stack_id);
    }
#endif

    switch( oo_filter_spec->type ) {
    case OO_HW_FILTER_TYPE_MAC:
      mac_ptr = oo_filter_spec->addr.mac.mac;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_ETHERTYPE:
      /* Ethertype filter is not MAC-qualified. There are no primitives in the
       * net driver, so we need to set filter flags manually. */
      spec.ether_type = oo_filter_spec->addr.ethertype.t;
      mac_ptr = oo_filter_spec->addr.ethertype.mac;
      spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_IP_PROTO_MAC:
      mac_ptr = oo_filter_spec->addr.ipproto.mac;
      /* Fall through. */
    case OO_HW_FILTER_TYPE_IP_PROTO:
      /* As in the case of the ethertype filter above, we have to populate
       * [spec] ourselves. */
      spec.ether_type = CI_ETHERTYPE_IP;
      spec.ip_proto = oo_filter_spec->addr.ipproto.p;
      spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE |
                          EFX_FILTER_MATCH_IP_PROTO;
      replace = true;
      break;

    case OO_HW_FILTER_TYPE_IP:
      if( oo_filter_spec->addr.ip.saddr != 0 )
        rc = efx_filter_set_ipv4_full(&spec,
                                      oo_filter_spec->addr.ip.protocol,
                                      oo_filter_spec->addr.ip.daddr,
                                      oo_filter_spec->addr.ip.dport,
                                      oo_filter_spec->addr.ip.saddr,
                                      oo_filter_spec->addr.ip.sport);
      else
        rc = efx_filter_set_ipv4_local(&spec,
                                       oo_filter_spec->addr.ip.protocol,
                                       oo_filter_spec->addr.ip.daddr,
                                       oo_filter_spec->addr.ip.dport);
      ci_assert_equal(rc, 0);
      break;

    default:
      /* Invalid filter type. */
      ci_assert(0);
      return -EINVAL;
    }

    /* note: bug 42561 affecting loopback on VLAN 0 with fw <= v4_0_6_6688 */
    if( oo_filter_spec->vlan_id != OO_HW_VLAN_UNSPEC || mac_ptr != NULL ) {
      u16 efx_vlan_id = (oo_filter_spec->vlan_id == OO_HW_VLAN_UNSPEC) ?
                        EFX_FILTER_VID_UNSPEC : (u16) oo_filter_spec->vlan_id;
      rc = efx_filter_set_eth_local(&spec, efx_vlan_id, mac_ptr);
      ci_assert_equal(rc, 0);
    }
    rc = efrm_filter_insert(get_client(hwport), &spec, replace);
    /* ENETDOWN indicates that the hardware has gone away. This is not a
     * failure condition at this layer as we can attempt to restore filters
     * when the hardware comes back. A negative filter ID signifies that there
     * is no filter from the net driver's point of view, so we are justified in
     * storing [rc] in the [filter_id] array. */
    if( rc >= 0 || rc == -ENETDOWN ) {
      oofilter->filter_id[hwport] = rc;
      rc = 0;
    }
  }
  return rc;
}


int oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                             const struct oo_hw_filter_spec* oo_filter_spec,
                             unsigned set_vlan_mask, unsigned hwport_mask,
                             unsigned src_flags)
{
  int rc1, rc = 0, ok_seen = 0, hwport;

  /* We will change this copy of the filter spec according to [set_vlan_mask]
   * as we iterate over the hwports. */
  struct oo_hw_filter_spec masked_spec = *oo_filter_spec;

  if( (src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT) == 0 )
    ci_assert_nequal(oofilter->trs != NULL, oofilter->thc != NULL);

  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( (hwport_mask & (1u << hwport)) && oofilter->filter_id[hwport] < 0 ) {
      /* If we've been told to set the vlan when installing the filter on this
       * port then use provided vlan_id, otherwise use OO_HW_VLAN_UNSPEC.
       */
      masked_spec.vlan_id = (set_vlan_mask & (1u << hwport)) ?
        oo_filter_spec->vlan_id : OO_HW_VLAN_UNSPEC;
      rc1 = oo_hw_filter_set_hwport(oofilter, hwport, &masked_spec, src_flags);
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
                     const struct oo_hw_filter_spec* oo_filter_spec,
                     unsigned set_vlan_mask, unsigned hwport_mask,
                     unsigned src_flags)
{
  int rc;

  rc = oo_hw_filter_add_hwports(oofilter, oo_filter_spec, set_vlan_mask,
                                hwport_mask, src_flags);
  if( rc < 0 )
    oo_hw_filter_clear(oofilter);
  return rc;
}


int oo_hw_filter_update(struct oo_hw_filter* oofilter,
                        struct tcp_helper_resource_s* new_stack,
                        const struct oo_hw_filter_spec* oo_filter_spec,
                        unsigned set_vlan_mask, unsigned hwport_mask,
                        unsigned src_flags)
{
  unsigned add_hwports = 0u;
  int hwport, vi_id;
  int redirect = src_flags & OO_HW_SRC_FLAG_KERNEL_REDIRECT;

  /* TODO: clustering: This needed for handling NIC resets.
   * For clusters we can only add/remove filters from intefaces.
   */
  if( new_stack != NULL && oofilter->thc != NULL ) {
    ci_log("%s: ERROR: Stack moving not supported on clustered filters",
           __FUNCTION__);
    return -EINVAL;
  }

  oo_hw_filter_clear_hwports(oofilter, ~hwport_mask, redirect);

  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( hwport_mask & (1 << hwport) ) {
      /* has the target stack got hwport */
      if( new_stack != NULL )
        vi_id = tcp_helper_rx_vi_id(new_stack, hwport);
      else if( oofilter->thc != NULL )
        vi_id = tcp_helper_cluster_vi_base(oofilter->thc, hwport);
      else
        vi_id = redirect ? 0 : -1;

      /* Remove filter due to lack of hardware? */
      if( vi_id < 0 ) {
        /* if the target stack has no vi on this hwport, we will not install
         * the filter even though with KERNEL_REDIRECT it would be possible
         * This means that KERNEL_REDIRECT filter hwports will match
         * MAC_FILTER's hwport allocation.
         *
         * For KERNEL_REDIRECT filters not to owned by a stack,
         * we install filters on all suggested hwports.
         */
        oo_hw_filter_clear_hwport(oofilter, hwport);
        continue;
      }

      /* Mark for installing new filter? */
      if( oofilter->filter_id[hwport] < 0 ) {
        add_hwports |= 1 << hwport;
        continue;
      }

      /* Move filter between stacks */
      /*
       * Only in non-clustered stack case there is work to do.
       */
      if( redirect ) {
        /* Always need to point to vi_id 0, so nothing to do */
      }
      else if( oofilter->thc != NULL ) {
        /* Nothing to do. We would only enter here with new_stack == NULL,
         * as the check is done above */
      }
      else {
        /* Move filter between stacks we attempt this even when new_stack
         * == old_stack */
        unsigned stack_id = tcp_helper_vi_hw_stack_id(new_stack, hwport);
        ci_assert_ge( stack_id, 0 );
        efrm_filter_redirect(get_client(hwport),
                             oofilter->filter_id[hwport], vi_id,
                             stack_id);
      }
    }

  /* Insert new filters for any other interfaces in hwport_mask. */
  oofilter->trs = new_stack;
  return oo_hw_filter_add_hwports(oofilter, oo_filter_spec, set_vlan_mask,
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
