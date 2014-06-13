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

#ifndef __OOF_IMPL_H__
#define __OOF_IMPL_H__

#include <ci/tools.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/oof_hw_filter.h>


#define OOF_LOCAL_PORT_TBL_SIZE      16
#define OOF_LOCAL_PORT_TBL_MASK      (OOF_LOCAL_PORT_TBL_SIZE - 1)

struct tcp_helper_resource_s;
struct oo_hw_filter;


/* State per protocol/local-ip/local-port triple. */
struct oof_local_port_addr {

  /* Wildcard H/W filters that demux to this addr/port/protocol, or NULL.
   *
   * If [lpa_semi_wild_socks] is non-empty, this will filter to the stack
   * of the socket at the head of the list.  If [lpa_semi_wild_socks] is
   * empty, then this will filter to the stack at the head of
   * [lp_wild_socks].
   *
   * If [lpa_semi_wild_socks] and [lp_wild_socks] are both empty then this
   * filter will be disabled.
   *
   * EXCEPT: Sometimes this h/w filter will point at the wrong stack
   * because we weren't able to (or chose not to) insert full match filters
   * for full-match sockets sharing the filter.  This should only be true
   * if [lpa_n_full_sharers > 0].
   */
  struct oo_hw_filter lpa_filter;

  /* List of [oof_socket]s that would like to receive packets from
   * [wild_filter] only.  i.e. Sockets receiving packets addressed to
   * [laddr:lport] for a single [laddr] (no those receiving to any IP).
   */
  ci_dllist lpa_semi_wild_socks;

  /* Full-match sockets bound to this local address and [lp_lport].
   * Includes sockets with their own full-match H/W filter, and ones
   * sharing [lpa_filter].
   */
  ci_dllist lpa_full_socks;

  /* Number of full-match sockets sharing [lpa_filter]. */
  int       lpa_n_full_sharers;

};


/* There is one of these per protocol/local-port pair.  Used to coordinate
 * and manage h/w and s/w filters.
 *
 * Every socket that needs to have packets delivered to it is associated
 * with one of these.  Each oof_local_port may be associated with multiple
 * sockets, all using the same local port number (and protocol).
 */
struct oof_local_port {

  ci_uint16 lp_lport;
  ci_uint16 lp_protocol;
  ci_dllink lp_manager_link;

  /* Ref count includes all users and transient references. */
  int       lp_refs;

  /* [oof_socket]s that would like to receive any packet addressed to
   * [lp_lport].
   */
  ci_dllist lp_wild_socks;

  ci_dllist lp_mcast_filters;

  /* Per-local-address state.  Entries in this table correspond to entries
   * in [oof_manager::local_addrs].
   */
  struct oof_local_port_addr *lp_addr;

};


struct oof_local_interface {

  ci_dllink li_active_ifs_link;

  unsigned  li_ifindex;

};


struct oof_local_addr {
  unsigned la_laddr;

  /* Number of sockets explicitly using this address (i.e. full match and
   * semi-wild).
   */
  int      la_sockets;

  /* List of ifindexes that have added this address */
  ci_dllist la_active_ifs;
};


enum oof_cplane_update_type {
  OOF_CU_ADDR_ADD,
  OOF_CU_ADDR_DEL,
  OOF_CU_UPDATE_FILTERS,
};


struct oof_cplane_update {

  ci_dllink cu_cplane_updates_link;

  enum oof_cplane_update_type cu_type;

  unsigned  cu_addr;

  unsigned  cu_ifindex;

};


struct oof_manager {

  /* Pointer to state belonging to the code module using this module. */
  void*        fm_owner_private;

  /* Protects all state not protected by fm_cplane_updates_lock. */
  spinlock_t   fm_inner_lock;

  /* Used together with [fm_inner_lock] to ensure that calls to modify
   * hardware filters are serialised with respect to everything else.
   *
   * Hardware filter updates cannot be done in atomic context (hence
   * mutex).  But other state in this module does need to be accessed in
   * atomic context (hence spinlock).
   */
  struct mutex fm_outer_lock;

  /* Protects state associated with control plane updates. */
  spinlock_t   fm_cplane_updates_lock;

  int          fm_local_addr_n;

  /* Size of fm_local_addrs array */
  int          fm_local_addr_max;

  ci_dllist    fm_local_ports[OOF_LOCAL_PORT_TBL_SIZE];

  struct oof_local_addr* fm_local_addrs;

  ci_dllist    fm_mcast_laddr_socks;

  /* This mask tracks which hwports are up.  Unicast filters are usually
   * installed on all interfaces that are up and mapped into the
   * corresponding stack and not unavailable (see below).
   */
  unsigned     fm_hwports_up;

  /* This mask tracks which hwports are unavailable because they are
   * members of an unacceleratable bond.  ie. Filters should not be used
   * with unavailable hwports because traffic arriving on them goes via the
   * kernel stack.
   */
  unsigned     fm_hwports_available;

  /* This mask tracks which hwports are capable of multicast replication.
   */
  unsigned     fm_hwports_mcast_replicate_capable;

  /* This mask tracks which hwports can by used with filters specifying a
   * VLAN.
   */
  unsigned     fm_hwports_vlan_filters;


  /* New values of the above masks, staged here in order to resolve the
   * lock order requirements.
   *
   * Protected by [fm_cplane_updates_lock].
   */
  unsigned     fm_hwports_up_new;
  unsigned     fm_hwports_available_new;
  unsigned     fm_hwports_mcast_replicate_capable_new;
  unsigned     fm_hwports_vlan_filters_new;

  /* Queue of oof_cplane_update objects representing changes to control
   * plane.  They are queued temporarily to be applied in a workitem in
   * order to get locking order right.
   *
   * Protected by [fm_cplane_updates_lock].
   */
  ci_dllist    fm_cplane_updates;

};


/* A multicast filter.  Shared by all sockets in a stack that have
 * subscribed to a particular {maddr, port, vlan}.
 */
struct oof_mcast_filter {

  struct oo_hw_filter mf_filter;

  unsigned            mf_maddr;

  /* Union of the physical interfaces wanted by the [mf_memberships]. */
  unsigned            mf_hwport_mask;

  /* Link for [oof_local_port::lp_mcast_filters]. */
  ci_dllink           mf_lp_link;

  ci_dllist           mf_memberships;

  ci_uint16           mf_vlan_id;

};


/* A multicast group membership (or subscription if you like).  A
 * bi-directional link between oof_socket and oof_mcast_filter.
 */
struct oof_mcast_member {

  /* The filter, or NULL if the socket does not yet have filters installed. */
  struct oof_mcast_filter* mm_filter;

  /* The owning socket. */
  struct oof_socket*       mm_socket;

  /* Multicast address.  (Needed here for when [mm_filter] is NULL). */
  unsigned                 mm_maddr;

  /* Master ifindex that uses this filter. In case of bonds, VLANs etc
   * it will be the master interface rather than any of the slaves 
   */
  int                      mm_ifindex;

  /* The physical interfaces underlying [mm_ifindex]. */
  unsigned                 mm_hwport_mask;

  /* Link for [struct oof_socket::sf_mcast_memberships]. */
  ci_dllink                mm_socket_link;

  /* Link for [struct oof_mcast_filter::mf_memberships]. */
  ci_dllink                mm_filter_link;

  /* The vlan id of [mm_ifindex]. */
  ci_uint16                mm_vlan_id;

};


#endif  /* __OOF_IMPL_H__ */
