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

/************************************************************************** \
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  ci_sock_cmn routines.
**   \date  2010/11/22
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"


void ci_sock_cmn_reinit(ci_netif* ni, ci_sock_cmn* s)
{
  s->so_error = 0;

  s->tx_errno = EPIPE;

  s->rx_errno = ENOTCONN;
  s->pkt.ether_type = CI_ETHERTYPE_IP;
  ci_ip_cache_init(&s->pkt);

  s->s_flags &= ~(CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_MAC_FILTER);
}




void oo_sock_cplane_init(struct oo_sock_cplane* cp)
{
  cp->ip_laddr_be32 = 0;
  cp->lport_be16 = 0;
  cp->so_bindtodevice = CI_IFID_BAD;
  cp->ip_multicast_if = CI_IFID_BAD;
  cp->ip_multicast_if_laddr_be32 = 0;
  cp->ip_ttl = CI_IP_DFLT_TTL;
  cp->ip_mcast_ttl = 1;
  cp->sock_cp_flags = 0;
}


void ci_sock_cmn_init(ci_netif* ni, ci_sock_cmn* s, int can_poison)
{
  oo_p sp;

  /* Poison. */
  CI_DEBUG(
  if( can_poison )
    memset(&s->b + 1, 0xf0, (char*) (s + 1) - (char*) (&s->b + 1));
  )

  citp_waitable_reinit(ni, &s->b);
  oo_sock_cplane_init(&s->cp);

  s->s_flags = CI_SOCK_FLAG_CONNECT_MUST_BIND | CI_SOCK_FLAG_PMTU_DO;
  s->s_aflags = 0u;

  ci_assert_equal( 0, CI_IP_DFLT_TOS );
  s->so_priority = 0;

  /* SO_SNDBUF & SO_RCVBUF.  See also ci_tcp_set_established_state() which
   * may modify these values.
   */
  memset(&s->so, 0, sizeof(s->so));
  s->so.sndbuf = NI_OPTS(ni).tcp_sndbuf_def;
  s->so.rcvbuf = NI_OPTS(ni).tcp_rcvbuf_def;

  s->rx_bind2dev_ifindex = CI_IFID_BAD;
  /* These don't really need to be initialised, as only significant when
   * rx_bind2dev_ifindex != CI_IFID_BAD.  But makes stackdump output
   * cleaner this way...
   */
  s->rx_bind2dev_base_ifindex = 0;
  s->rx_bind2dev_vlan = 0;

  s->cmsg_flags = 0u;
  s->timestamping_flags = 0u;
  s->os_sock_status = OO_OS_STATUS_TX;


  ci_sock_cmn_reinit(ni, s);

  sp = oo_sockp_to_statep(ni, SC_SP(s));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_sock_cmn, reap_link));
  ci_ni_dllist_link_init(ni, &s->reap_link, sp, "reap");
  ci_ni_dllist_self_link(ni, &s->reap_link);

  /* Not functionally necessary, but avoids garbage addresses in stackdump. */
  sock_laddr_be32(s) = sock_raddr_be32(s) = 0;
  sock_lport_be16(s) = sock_rport_be16(s) = 0;
}




void ci_sock_cmn_dump(ci_netif* ni, ci_sock_cmn* s, const char* pf,
                      oo_dump_log_fn_t logger, void* log_arg)
{
  logger(log_arg, "%s  uid=%d"CI_DEBUG(" pid=%d")
         " s_flags: "CI_SOCK_FLAGS_FMT, pf,
         (int) s->uid CI_DEBUG_ARG((int)s->pid),
         CI_SOCK_FLAGS_PRI_ARG(s));
  logger(log_arg, "%s  rcvbuf=%d sndbuf=%d bindtodev=%d(%d,%d:%d) ttl=%d", pf,
         s->so.rcvbuf, s->so.sndbuf, s->cp.so_bindtodevice,
         s->rx_bind2dev_ifindex, s->rx_bind2dev_base_ifindex,
         s->rx_bind2dev_vlan, s->cp.ip_ttl);
  logger(log_arg, "%s  rcvtimeo_ms=%d sndtimeo_ms=%d sigown=%d "
         "cmsg="OO_CMSG_FLAGS_FMT"%s",
         pf, s->so.rcvtimeo_msec, s->so.sndtimeo_msec, s->b.sigown,
         OO_CMSG_FLAGS_PRI_ARG(s->cmsg_flags),
         (s->cp.sock_cp_flags & OO_SCP_NO_MULTICAST) ? " NO_MCAST_TX":"");
  logger(log_arg, "%s  rx_errno=%x tx_errno=%x so_error=%d os_sock=%u%s%s", pf,
         s->rx_errno, s->tx_errno, s->so_error,
         s->os_sock_status >> OO_OS_STATUS_SEQ_SHIFT,
         (s->os_sock_status & OO_OS_STATUS_RX) ? ",RX":"",
         (s->os_sock_status & OO_OS_STATUS_TX) ? ",TX":"");

  if( s->b.ready_list_id > 0 )
    logger(log_arg, "%s  epoll3: ready_list_id %d epoll_pid %d",
           pf, s->b.ready_list_id, s->b.eitem_pid);
  else
    logger(log_arg, "%s  epoll3: ready_list_id %d", pf, s->b.ready_list_id);
}

