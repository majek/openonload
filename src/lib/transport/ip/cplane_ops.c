/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane kernel code
**   \date  2005/07/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is available both in the kernel and from the
 *  user-mode libraries.
 *
 *  This code could be split among a number of different files but is divided
 *  instead into the following sections:
 *
 *      ACM  - Functions on Abstract Cacheable MIBs
 *             (which hide use of CM and support protocols)
 *      CM   - Functions on Cacheable MIBs
 *             (which hide use of SYN)
 *      SYN  - Functions on local MIB caches required for O/S synchronization
 *
 *  These divisions are documented in L5-CGG/1-SD 'IP "Control Plane" Design
 *  Notes'
 *
 *  Within each section code supporting each of the following Management
 *  Information Bases (MIBs) potentially occur.
 *
 *  User and kernel visible information
 *
 *      cicp_mac_kmib_t    - IP address resolution table
 *
 *      cicp_fwdinfo_t     - cache of kernel forwarding information table
 *
 *  The information is related as follows:
 *
 *   * the IP address resolution table provides link layer addresses usable at
 *     a given link layer access point that identify IP entities directly
 *     connected to IP interfaces the access point supports
 *
 *   * the cache of forwarding information remembers a complete set of the
 *     data that needs to be known when transmitting to a destination
 *     IP address - including the first hop and its link layer access point
 *     for example
 *
 */




/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/





#include <onload/cplane_ops.h>



#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif



/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DPRINTF ci_log

#define CODEID "cplane(onload)"












ci_inline int
ci_ip_cache_is_onloadable(ci_netif* ni, ci_ip_cached_hdrs* ipcache)
{
  /* Return true if [ipcache->hwport] can be accelerated by [ni], and also
   * sets [ipcache->intf_i] in that case.
   *
   * [ipcache->hwport] must have a legal value here.
   */
  ci_hwport_id_t hwport = ipcache->hwport;
  ci_assert(hwport == CI_HWPORT_ID_BAD ||
            (unsigned) hwport < CI_CFG_MAX_HWPORTS);
  return (unsigned) hwport < CI_CFG_MAX_HWPORTS &&
    (ipcache->intf_i = __ci_hwport_to_intf_i(ni, hwport)) >= 0;
}


#if CI_CFG_TEAMING
static int
cicp_user_bond_hash_get_hwport(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                               cicp_hwport_mask_t hwports,
                               ci_uint16 src_port_be16)
{
  /* For an active-active bond that uses hashing, choose the appropriate
   * interface to send out of.
   */
  struct cicp_hash_state hs;

  if( src_port_be16 != 0 || ipcache->dport_be16 != 0)
    hs.flags = CICP_HASH_STATE_FLAGS_IS_TCP_UDP | 
      CICP_HASH_STATE_FLAGS_IS_IP;
  else
    hs.flags = CICP_HASH_STATE_FLAGS_IS_IP;
  memcpy(&hs.dst_mac, ci_ip_cache_ether_dhost(ipcache), ETH_ALEN);
  memcpy(&hs.src_mac, ci_ip_cache_ether_shost(ipcache), ETH_ALEN);
  hs.src_addr_be32 = ipcache->ip_saddr_be32;
  hs.dst_addr_be32 = ipcache->ip.ip_daddr_be32;
  hs.src_port_be16 = src_port_be16;
  hs.dst_port_be16 = ipcache->dport_be16;
  ipcache->hwport = oo_cp_hwport_bond_get(ni->cplane, ipcache->ifindex,
                                          &ipcache->encap, hwports, &hs);
  return ! ci_ip_cache_is_onloadable(ni, ipcache);
}
#endif

#ifdef __KERNEL__
#include <net/flow.h>
#include <net/route.h>

static void
cicp_kernel_resolve(ci_netif* ni, struct cp_fwd_key* key,
                    struct cp_fwd_data* data)
{
  int rc;
  struct rtable *rt = NULL;
  cicp_hwport_mask_t rx_hwports = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38)
  /* rhel6 case */
  struct flowi fl;

  memset(&fl, 0, sizeof(fl));
  fl.fl4_dst = key->dst;
  fl.fl4_src = key->src;
  fl.fl4_tos = key->tos;
  fl.oif = key->ifindex;

  rc = ip_route_output_key(ni->cplane->cp_netns, &rt, &fl);
  if( rc < 0 ) {
    data->type = CICP_ROUTE_ALIEN;
    return;
  }
  data->src = fl.fl4_src;
  data->ifindex = rt->u.dst.dev->ifindex;
#else /* linux-2.6.39 and newer */
  struct flowi4 fl4;

  memset(&fl4, 0, sizeof(fl4));
  fl4.daddr = key->dst;
  fl4.saddr = key->src;
  fl4.flowi4_tos = key->tos;
  fl4.flowi4_oif = key->ifindex;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  fl4.flowi4_uid = make_kuid(current_user_ns(), ni->state->uuid);
#endif

  rt = ip_route_output_key(ni->cplane->cp_netns, &fl4);
  if( IS_ERR(rt) ) {
    data->type = CICP_ROUTE_ALIEN;
    return;
  }
  data->src = fl4.saddr;
  data->ifindex = rt->dst.dev->ifindex;
#endif /* 2.6.39 */

  data->next_hop = rt->rt_gateway;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
  data->mtu = 0;
  /* We'll use interface MTU and ignore the route MTU even if it has one
   * for the older kernels.  This code is mostly used for SYN-ACK replies,
   * so MTU value is not too important. */
#else
  data->mtu = rt->rt_pmtu;
#endif

  ip_rt_put(rt);

  if( data->ifindex == 1 ) {
    data->type = CICP_ROUTE_LOCAL;
    return;
  }

  /* We've got the route.  Let's look into llap table to find out the
   * network interface details. */
  rc = oo_cp_find_llap(ni->cplane, data->ifindex,
                       data->mtu == 0 ? &data->mtu : NULL,
                       &data->hwports, &rx_hwports, &data->src_mac, &data->encap);

  if( rc < 0 || rx_hwports == 0 )
    data->type = CICP_ROUTE_ALIEN;
  else
    data->type = CICP_ROUTE_NORMAL;
  data->arp_valid = 0;
}
#endif

static int cicp_user_resolve(ci_netif* ni, cicp_verinfo_t* verinfo,
                             struct cp_fwd_key* key, struct cp_fwd_data* data)
{
  int rc=  __oo_cp_route_resolve(ni->cplane, verinfo, key,
                                 1/*ask_server*/, data);
#ifdef __KERNEL__
  ci_assert_impl(ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT,
                 ! (key->flag & CP_FWD_KEY_REQ_WAIT));
  if( !(key->flag & CP_FWD_KEY_REQ_WAIT) && rc < 0 ) {
    /* We've scheduled an addition of this route to the route cache, but we
     * can't sleep for the time when it really happens.  Let's use more
     * direct way to resolve a route. */
    cicp_kernel_resolve(ni, key, data);
    return 0;
  }
#else
  /* There is no reason to call this in UL without WAIT; so we don't. */
  ci_assert(key->flag & CP_FWD_KEY_REQ_WAIT);
#endif
  if( rc < 0 )
    data->type = CICP_ROUTE_ALIEN;
  return rc;
}


void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp)
{
  struct cp_fwd_key key;
  struct cp_fwd_data data;
  int rc;

  /* This function must be called when "the route is unusable".  I.e. when
   * the route is invalid or if there is no ARP.  In the second case, we
   * can expedite ARP resolution by explicit request just now. */
  if( oo_cp_verinfo_is_valid(ni->cplane, &ipcache->mac_integrity) ) {
    ci_assert_equal(ipcache->status, retrrc_nomac);
    oo_cp_arp_resolve(ni->cplane, &ipcache->mac_integrity);

    /* Re-check the version of the fwd entry after ARP resolution.
     * Return if nothing changed; otherwise handle the case when ARP has
     * already been resolved. */
    if( oo_cp_verinfo_is_valid(ni->cplane, &ipcache->mac_integrity) )
      return;
  }

  key.dst = ipcache->ip.ip_daddr_be32;
  key.tos = sock_cp->ip_tos;
  key.flag = 0;

  if( ipcache->ip.ip_protocol == IPPROTO_UDP )
    key.flag |= CP_FWD_KEY_UDP;

  key.ifindex = sock_cp->so_bindtodevice;
  if( CI_IP_IS_MULTICAST(key.dst) ) {
    /* In linux, SO_BINDTODEVICE has the priority over IP_MULTICAST_IF */
    if( key.ifindex == 0 )
      key.ifindex = sock_cp->ip_multicast_if;
    key.src = sock_cp->ip_multicast_if_laddr_be32;
    if( key.src == 0 && sock_cp->ip_laddr_be32 != 0 )
      key.src = sock_cp->ip_laddr_be32;
  }
  else {
    key.src = sock_cp->ip_laddr_be32;
    if( sock_cp->sock_cp_flags & OO_SCP_TPROXY )
      key.flag |= CP_FWD_KEY_TRANSPARENT;
  }

  if(CI_UNLIKELY( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) &&
                  (sock_cp->sock_cp_flags & OO_SCP_NO_MULTICAST) )) {
    ipcache->status = retrrc_alienroute;
    ipcache->hwport = CI_HWPORT_ID_BAD;
    ipcache->intf_i = -1;
    return;
  }

  if( key.src == 0 && sock_cp->sock_cp_flags & OO_SCP_UDP_WILD )
    key.flag |= CP_FWD_KEY_SOURCELESS;

#ifdef __KERNEL__
  if( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) )
#endif
    key.flag |= CP_FWD_KEY_REQ_WAIT;

  rc = cicp_user_resolve(ni, &ipcache->mac_integrity, &key, &data);
  if( rc == 0 && key.src == 0 &&
      ! (sock_cp->sock_cp_flags & OO_SCP_UDP_WILD) ) {
    key.src = data.src;
    rc = cicp_user_resolve(ni, &ipcache->mac_integrity, &key, &data);
  }

  switch( data.type ) {
    case CICP_ROUTE_LOCAL:
      ipcache->status = retrrc_localroute;
      ipcache->encap.type = CICP_LLAP_TYPE_NONE;
      ipcache->ether_offset = 4;
      ipcache->intf_i = OO_INTF_I_LOOPBACK;
      return;
    case CICP_ROUTE_NORMAL:
    {
      cicp_hwport_mask_t hwports = 0;
      /* Can we accelerate interface in this stack ? */
      if( (data.encap.type & CICP_LLAP_TYPE_BOND) == 0 &&
          (data.hwports & ~(ci_netif_get_hwport_mask(ni))) == 0 )
        break;
      /* Check bond */
      rc = oo_cp_find_llap(ni->cplane, data.ifindex, NULL/*mtu*/,
                           NULL /*tx_hwports*/, &hwports /*rx_hwports*/,
                           NULL/*mac*/, NULL /*encap*/);
      if( rc == 0 && (hwports & ~(ci_netif_get_hwport_mask(ni))) == 0 )
        break;
      /* FALL through to alien path */
    }
    case CICP_ROUTE_ALIEN:
      ipcache->status = retrrc_alienroute;
      ipcache->intf_i = -1;
      return;
  }

  ipcache->encap = data.encap;
#if CI_CFG_TEAMING
  if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH ) {
     if( cicp_user_bond_hash_get_hwport(ni, ipcache, data.hwports,
                                    sock_cp->lport_be16) != 0 ) {
      ipcache->status = retrrc_alienroute;
      ipcache->intf_i = -1;
      return;
    }
  }
  else
#endif
    ipcache->hwport = cp_hwport_mask_first(data.hwports);

  ipcache->mtu = data.mtu;
  ipcache->ip_saddr_be32 = key.src == INADDR_ANY ? data.src : key.src;
  ipcache->ifindex = data.ifindex;
  ipcache->nexthop = data.next_hop;
  if( ! ci_ip_cache_is_onloadable(ni, ipcache)) {
    ipcache->status = retrrc_alienroute;
    ipcache->intf_i = -1;
    return;
  }

  /* Layout the Ethernet header, and set the source mac.
   * Route resolution already issues ARP request, so there is no need to
   * call oo_cp_arp_resolve() explicitly in case of retrrc_nomac. */
  ipcache->status = data.arp_valid ? retrrc_success : retrrc_nomac;
  cicp_ipcache_vlan_set(ipcache);
  memcpy(ci_ip_cache_ether_shost(ipcache), &data.src_mac, ETH_ALEN);
  if( data.arp_valid )
    memcpy(ci_ip_cache_ether_dhost(ipcache), &data.dst_mac, ETH_ALEN);

  if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) )
    ipcache->ip.ip_ttl = sock_cp->ip_mcast_ttl;
  else
    ipcache->ip.ip_ttl = sock_cp->ip_ttl;
}


void
cicp_ip_cache_update_from(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                          const ci_ip_cached_hdrs* from_ipcache)
{
  /* We can't check the inputs that come from oo_sock_cplane, but this at
   * least gives us a little checking...
   */
  ci_assert_equal(ipcache->ip.ip_daddr_be32, from_ipcache->ip.ip_daddr_be32);
  ci_assert_equal(ipcache->dport_be16, from_ipcache->dport_be16);

  ipcache->mac_integrity = from_ipcache->mac_integrity;
  ipcache->ip_saddr_be32 = from_ipcache->ip_saddr_be32;
  ipcache->ip.ip_ttl = from_ipcache->ip.ip_ttl;
  ipcache->status = from_ipcache->status;
  ipcache->flags = from_ipcache->flags;
  ipcache->nexthop = from_ipcache->nexthop;
  /* ipcache->pmtus = something; */
  ipcache->mtu = from_ipcache->mtu;
  ipcache->ifindex = from_ipcache->ifindex;
  ipcache->encap = from_ipcache->encap;
  ipcache->intf_i = from_ipcache->intf_i;
  ipcache->hwport = from_ipcache->hwport;
  ipcache->ether_offset = from_ipcache->ether_offset;
  memcpy(ipcache->ether_header, from_ipcache->ether_header,
         sizeof(ipcache->ether_header));
}


