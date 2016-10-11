/*
** Copyright 2005-2016  Solarflare Communications Inc.
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



#ifdef __KERNEL__
# include <cplane/exported.h>
#endif


/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DPRINTF ci_log

#define CODEID "cplane(onload)"












ci_inline int cicp_all_slaves_in_stack(const cicp_ul_mibs_t *user,
                                       ci_netif *ni, ci_int16 bond_rowid)
{
  /* Check all slaves are in this stack.
   *
   * NB. Caller must check the forwarding table lock.
   */
  cicp_bond_row_t* bond_row;
  ci_hwport_id_t hwport;

  ci_assert(bond_rowid >= 0 && bond_rowid < user->bondinfo_utable->rows_max);
  bond_row = &user->bondinfo_utable->bond[bond_rowid];

  while( bond_row->next != CICP_BOND_ROW_NEXT_BAD ) {
    ci_assert(bond_row->next < user->bondinfo_utable->rows_max);
    bond_row = &user->bondinfo_utable->bond[bond_row->next];
    if( bond_row->type != CICP_BOND_ROW_TYPE_SLAVE )
      return 0;
    hwport = bond_row->slave.hwport;
    if( (unsigned) hwport >= CPLANE_MAX_REGISTER_INTERFACES ||
        __ci_hwport_to_intf_i(ni, hwport) < 0 )
      return 0;
  }

  return 1;
}


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
            (unsigned) hwport < CPLANE_MAX_REGISTER_INTERFACES);
  return (unsigned) hwport < CPLANE_MAX_REGISTER_INTERFACES &&
    (ipcache->intf_i = __ci_hwport_to_intf_i(ni, hwport)) >= 0;
}


#if CPLANE_TEAMING
static int
cicp_user_bond_hash_get_hwport(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                               const cicp_llap_row_t* llap_row,
                               ci_uint16 src_port_be16,
                               cicp_encap_t encap)
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
  CI_MAC_ADDR_SET(&hs.dst_mac, ci_ip_cache_ether_dhost(ipcache));
  CI_MAC_ADDR_SET(&hs.src_mac, ci_ip_cache_ether_shost(ipcache));
  hs.src_addr_be32 = ipcache->ip_saddr_be32;
  hs.dst_addr_be32 = ipcache->ip.ip_daddr_be32;
  hs.src_port_be16 = src_port_be16;
  hs.dst_port_be16 = ipcache->dport_be16;
  ipcache->hwport = ci_hwport_bond_get(CICP_HANDLE(ni), &encap,
                                       llap_row->bond_rowid, &hs);
  return ! ci_ip_cache_is_onloadable(ni, ipcache);
}
#endif


ci_inline int
cicp_mcast_use_gw_mac(const cicp_fwd_row_t* row,
                      const struct oo_sock_cplane* sock_cp)
{
  /* If:
   * - route table says (via explicit route) that this mcast addr should be
   *   delivered via a gateway
   *
   *   If:
   *   - have set IP_MULTICAST_IF to the same dev (as route table)
   *   Or:
   *   - have NOT set IP_MULTICAST_IF
   *   - and socket laddr is not bound
   *   - and socket is not connected
   *   Then:
   *   => use GATEWAY mac.
   *
   * Else:
   * => use MCAST mac.
   */
  if( row != NULL && row->first_hop != 0 && row->destnet_ipset != 0 ) {
    if( sock_cp->ip_multicast_if == CI_IFID_BAD ) {
      return (sock_cp->sock_cp_flags &
              (OO_SCP_LADDR_BOUND | OO_SCP_CONNECTED)) == 0;
    }
    else {
      return sock_cp->ip_multicast_if == row->dest_ifindex;
    }
  }
  return 0;
}


ci_inline void
ci_ip_cache_init_mcast_mac(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                           unsigned daddr_be32)
{
  ci_uint8* dhost = ci_ip_cache_ether_dhost(ipcache);
  unsigned daddr = CI_BSWAP_BE32(daddr_be32);
  dhost[0] = 1;
  dhost[1] = 0;
  dhost[2] = 0x5e;
  dhost[3] = (daddr >> 16) & 0x7f;
  dhost[4] = (daddr >>  8) & 0xff;
  dhost[5] =  daddr        & 0xff;
  cicp_mac_set_mostly_valid(CICP_USER_MIBS(CICP_HANDLE(ni)).mac_utable,
                            &ipcache->mac_integrity);
  ipcache->nexthop = 0;
}


void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp)
{
  const cicp_ul_mibs_t* user = &CICP_USER_MIBS(CICP_HANDLE(ni));
  cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;
  cicp_llapinfo_t* llapt = user->llapinfo_utable;
  const cicp_fwd_row_t* row;
  const cicp_llap_row_t* lrow = NULL;
  cicp_mac_verinfo_t mac_info;
  int osrc;

  ci_assert(user);
  ci_assert(llapt);
  (void) llapt;  /* Not used in kernel NDEBUG. */
  CI_DEBUG(ipcache->status = -1);

  if(CI_UNLIKELY( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) &&
                  (sock_cp->sock_cp_flags & OO_SCP_NO_MULTICAST) ))
    goto alienroute_no_verlock;

 again:
  CICP_READ_LOCK(CICP_HANDLE(ni), llapt->version)

  /* We need to do a route table lookup even when hwport is selected by
   * IP_MULTICAST_IF, due to the baroque rules for selecting the MAC addr.
   *
   * ?? TODO: Are there scenarious with SO_BINDTODEVICE where a route table
   * lookup can be avoided?  Probably there are.
   */
  row = _cicp_fwd_find_ip(fwdt, ipcache->ip.ip_daddr_be32,
                          sock_cp->so_bindtodevice);
  if( row != NULL ) {
    lrow = &user->llapinfo_utable->llap[row->llap_rowid];
    ci_assert_equal(row->dest_ifindex, lrow->ifindex);
  }

  if( sock_cp->so_bindtodevice != CI_IFID_BAD ) {
    ipcache->ifindex = sock_cp->so_bindtodevice;
    goto handle_bound_dev;
  }
  else if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) &&
           sock_cp->ip_multicast_if != CI_IFID_BAD ) {
    /* TODO: Optimisation: Remember non-mac info associated with the
     * ifindex selected by IP_MULTICAST_IF or SO_BINDTODEVICE when
     * destination changes.  Requires that we remember the fwd table
     * version.
     */

    ipcache->ifindex = sock_cp->ip_multicast_if;
    /* In case of multicast traffic with multicast_if set
     * route info ignored */
    row = NULL;
  handle_bound_dev:
    lrow = cicp_llap_find_ifid(user->llapinfo_utable, ipcache->ifindex);
    if( lrow == NULL )
      goto alienroute;
    ipcache->mtu = lrow->mtu;
    ipcache->hwport = lrow->hwport;
    ipcache->encap = lrow->encap;

    if( ! ci_ip_cache_is_onloadable(ni, ipcache)
#if CPLANE_TEAMING
        || ( (ipcache->encap.type & CICP_LLAP_TYPE_BOND) && 
             ! cicp_all_slaves_in_stack(user, ni, lrow->bond_rowid) )
#endif
        )
      goto alienroute;
    /* Select source IP:
     * 1. Bound local IP,
     * 2. IP_MULTICAST_IF addr, where both mcast local addr and iface provided
     * 3. IP from routing table lookup (SO_BINDTODEVICE interface
     *    could have multiple IPs assigned to it). This case includes multicast
     *    where IP_MULTICAST_IF has not been provided (neither local ip or if)
     * 4. arbitrary IP on this interface - this includes multicast, where
     *    multicast local addr is not provided while interface is
     *
     * NB. We're handling SO_BINDTODEVICE as well as IP_MULTICAST_IF here.
     */
    if( sock_cp->ip_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_laddr_be32;
    else if( sock_cp->ip_multicast_if != CI_IFID_BAD &&
             sock_cp->ip_multicast_if_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_multicast_if_laddr_be32;
    /* Present route preferred source address is used,
     * unless we deal with multicast traffic, for which there is interface but
     * not local ip address specified. However, in this case the row
     * variable has been set to NULL - see above - therefore no
     * special check here */
    else if( row != NULL )
      ipcache->ip_saddr_be32 = row->pref_source;
    else if( lrow->ip_addr != INADDR_ANY )
      ipcache->ip_saddr_be32 = lrow->ip_addr;
    else
      goto alienroute;  /* really this is "no source addr" */
  }
  else {
    if(CI_UNLIKELY( row == NULL ))
      goto noroute;
    if(CI_UNLIKELY( row->type == CICP_ROUTE_ALIEN ))
      goto alienroute;
    ipcache->mtu = row->mtu == 0 ? lrow->mtu : row->mtu;
    ci_assert(ipcache->mtu);
     /* Is the destination address the same as the local one? */
    if( ipcache->ip.ip_daddr_be32 == row->pref_source ||
        lrow->encap.type == CICP_LLAP_TYPE_LOOP) {
      ipcache->status = retrrc_localroute;
      ipcache->encap.type = CICP_LLAP_TYPE_SFC;
      ipcache->ether_offset = 4;
      ipcache->intf_i = OO_INTF_I_LOOPBACK;
      cicp_mac_set_mostly_valid(CICP_USER_MIBS(CICP_HANDLE(ni)).mac_utable,
                                &ipcache->mac_integrity);
      goto check_verlock_and_out;
    }
    ipcache->hwport = lrow->hwport;
    if( ! ci_ip_cache_is_onloadable(ni, ipcache)
#if CPLANE_TEAMING
        || ( (lrow->encap.type & CICP_LLAP_TYPE_BOND) && 
             ! cicp_all_slaves_in_stack(user, ni, lrow->bond_rowid) )
#endif
        )
      goto alienroute;
    ipcache->ifindex = row->dest_ifindex;
    if( sock_cp->ip_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_laddr_be32;
    else
      ipcache->ip_saddr_be32 = row->pref_source;
    ipcache->encap = lrow->encap;
  }

  /* Layout the Ethernet header, and set the source mac. */
  cicp_ipcache_vlan_set(ipcache);
  memcpy(ci_ip_cache_ether_shost(ipcache), lrow->mac, ETH_ALEN);

  /* Find the next hop, initialise the destination mac and select TTL. */
  if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) ) {
    ipcache->ip.ip_ttl = sock_cp->ip_mcast_ttl;
    if( ! cicp_mcast_use_gw_mac(row, sock_cp) ) {
      ci_ip_cache_init_mcast_mac(ni, ipcache, ipcache->ip.ip_daddr_be32);
#if CPLANE_TEAMING
      if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH )
        if( cicp_user_bond_hash_get_hwport(ni, ipcache, lrow, 
                                           sock_cp->lport_be16,
                                           ipcache->encap) != 0 )
          goto alienroute;
#endif
      ipcache->status = retrrc_success;
      goto check_verlock_and_out;
    }
    ipcache->nexthop = row->first_hop;
  }
  else {
    ipcache->ip.ip_ttl = sock_cp->ip_ttl;
    if( row != NULL && row->first_hop != 0 && 
        (sock_cp->so_bindtodevice == CI_IFID_BAD || 
         ipcache->ifindex == row->dest_ifindex) ) {
      ipcache->nexthop = row->first_hop;
    }
    else {
      ipcache->nexthop = ipcache->ip.ip_daddr_be32;
    }
  }

  /* Find the MAC address of the first hop destination.
   *
   * TODO: This requires two rmb()s, and can I think be significantly
   * improved upon.  One approach could be to add a new verlock that is
   * bumped both when updating the fwd+bond tables, and also when updating
   * any mac entry.  Thus a single pair of verlock checks would suffice for
   * this entire function.
   */
  osrc = cicp_mac_get(user->mac_utable, ipcache->ifindex, ipcache->nexthop,
                      ci_ip_cache_ether_dhost(ipcache), &mac_info);

  if( osrc == 0 ) {
#if CPLANE_TEAMING
    if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH )
      if( cicp_user_bond_hash_get_hwport(ni, ipcache, lrow, sock_cp->lport_be16,
                                         ipcache->encap) != 0 )
        goto alienroute;
#endif
    ipcache->mac_integrity = mac_info;
    ipcache->status = retrrc_success;
    if( user->mac_utable->ipmac[mac_info.row_index].need_update ) {
      ipcache->flags |= CI_IP_CACHE_NEED_UPDATE_SOON;
      if( user->mac_utable->ipmac[mac_info.row_index].need_update ==
          CICP_MAC_ROW_NEED_UPDATE_STALE )
        ipcache->flags |= CI_IP_CACHE_NEED_UPDATE_STALE;
    }
    goto check_verlock_and_out;
  }
  else if( osrc == -EDESTADDRREQ ) {
    /* TODO out_hwport is wrong if bonding encap */
    ipcache->mac_integrity.row_version = CI_VERLOCK_BAD;
    ipcache->status = retrrc_nomac;
    goto check_verlock_and_out;
  }
  else if( osrc == -EAGAIN ) {
    goto again;
  }
  else {
    /* TODO out_hwport is wrong if bonding encap */
    /* At time of writing, osrc is taken from a ci_uint16, which is
     * assigned to with either 0 or a -ve constant int.  Ugly.
     */
    ipcache->status = (ci_int16) osrc;
    if( ipcache->status == -EHOSTUNREACH ) {
      /* Treat this the same as nomac.  Arguably it would be better to
       * handle this exception when writing the table rather than when
       * reading it, but modifying the write code scares the willies out of
       * me.
       */
      ipcache->mac_integrity.row_version = CI_VERLOCK_BAD;
      ipcache->status = retrrc_nomac;
      goto check_verlock_and_out;
    }
    goto not_onloadable;
  }

 check_verlock_and_out:
  ;
  CICP_READ_UNLOCK(CICP_HANDLE(ni), llapt->version)
 out:
  ci_assert(ipcache->status != -1);
  return;

 not_onloadable:
  ipcache->hwport = CI_HWPORT_ID_BAD;
  ipcache->intf_i = -1;
  cicp_mac_set_mostly_valid(CICP_USER_MIBS(CICP_HANDLE(ni)).mac_utable,
                            &ipcache->mac_integrity);
  goto check_verlock_and_out;

 alienroute:
  ipcache->status = retrrc_alienroute;
  goto not_onloadable;

 noroute:
  ipcache->status = retrrc_noroute;
  goto not_onloadable;

 alienroute_no_verlock:
  ipcache->hwport = CI_HWPORT_ID_BAD;
  ipcache->intf_i = -1;
  cicp_mac_set_mostly_valid(CICP_USER_MIBS(CICP_HANDLE(ni)).mac_utable,
                            &ipcache->mac_integrity);
  ipcache->status = retrrc_alienroute;
  goto out;
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


