/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

#ifndef __ONLOAD_OOF_SOCKET_H__
#define __ONLOAD_OOF_SOCKET_H__


struct oof_local_port;
struct oof_thc;


/* Per-socket state for the filtering module.
 *
 * All fields are protected by [oof_manager::lock].
 */
struct oof_socket {

  /* If NULL then no packets are filtered to this socket. */
  struct oof_local_port* sf_local_port;

  /* List of [struct oof_mcast_member]s. */
  ci_dllist sf_mcast_memberships;

  /* All other fields are only valid when [sf_local_port] is not NULL. */

  struct oo_hw_filter sf_full_match_filter;

  unsigned  sf_laddr, sf_raddr;
  int       sf_rport;
  /* See [sf_local_port] for local port and protocol. */

  /* Link for one of:
   * - [oof_local_port::lp_wild_socks]
   * - [oof_local_port_addr::lpa_semi_wild_socks]
   * - [oof_local_port_addr::lpa_full_socks]
   * - [oof_manager::fm_mcast_laddr_socks]
   */
  ci_dllink sf_lp_link;

};


/* A clustered filter.  Shared by all sockets that have been bound to
 * a clustering {laddr, lport}.
 */
struct oof_thc {
  struct oo_hw_filter*         tf_filters;
  struct tcp_helper_cluster_s* tf_thc;
  struct oof_thc*              tf_next;
  unsigned                     tf_laddr;
  int                          tf_ref;
  int                          tf_filters_installed;
};

#endif  /* __ONLOAD_OOF_SOCKET_H__ */
