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

#ifndef __ONLOAD_OOF_SOCKET_H__
#define __ONLOAD_OOF_SOCKET_H__


struct oof_local_port;


/* Per-socket state for the filtering module.
 *
 * All fields are protected by [oof_manager::lock].
 */
struct oof_socket {

  /* If NULL then no packets are filtered to this socket. */
  struct oof_local_port* sf_local_port;

  /* List of [struct oof_mcast_member]s. */
  ci_dllist sf_mcast_memberships;

/* sf_flags field can be nonzero only when sf_local_port != NULL
 * and when socket is fully deleted all flags are cleared. */
#define OOF_SOCKET_MCAST_FULL_SW_FILTER   0x00000001
#define OOF_SOCKET_SW_FILTER_WAS_REMOVED  0x00000002
#define OOF_SOCKET_CLUSTERED              0x00000004
/* socket is inserted but not armed */
#define OOF_SOCKET_DUMMY                  0x00000008
/* a dummy socket that has no stack (no endpoint association) */
#define OOF_SOCKET_NO_STACK               0x00000010
/* full socket will not share filter of a semi-wild one */
#define OOF_SOCKET_NO_SHARING             0x00000020
  unsigned  sf_flags;

  /* All other fields are only valid when [sf_local_port] is not NULL */
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

#endif  /* __ONLOAD_OOF_SOCKET_H__ */
