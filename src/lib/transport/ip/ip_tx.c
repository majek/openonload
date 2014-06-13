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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ds
**  \brief  IP transmit
**   \date  2004/05/25
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "ip_tx.h"
#include <ci/tools/pktdump.h>


void ci_ip_send_pkt_lookup(ci_netif* ni,
                           const struct oo_sock_cplane* sock_cp_opt,
                           ci_ip_pkt_fmt* pkt,
                           ci_ip_cached_hdrs* ipcache)
{
  ci_ip4_hdr* pkt_ip = oo_tx_ip_hdr(pkt);
  struct oo_sock_cplane sock_cp;

  ci_assert(pkt_ip->ip_saddr_be32 != 0);
  ci_assert(pkt_ip->ip_daddr_be32 != 0);

  if( sock_cp_opt != NULL )
    sock_cp = *sock_cp_opt;
  else
    oo_sock_cplane_init(&sock_cp);
  ci_ip_cache_init(ipcache);
  sock_cp.ip_laddr_be32 = pkt_ip->ip_saddr_be32;
  ipcache->ip.ip_daddr_be32 = pkt_ip->ip_daddr_be32;

  switch( pkt_ip->ip_protocol ) {
  case IPPROTO_UDP:
  case IPPROTO_TCP:
    sock_cp.lport_be16 = TX_PKT_SPORT_BE16(pkt);
    ipcache->dport_be16 = TX_PKT_DPORT_BE16(pkt);
    break;
  default:
    sock_cp.lport_be16 = 0;
    ipcache->dport_be16 = 0;
    break;
  }

  cicp_user_retrieve(ni, ipcache, &sock_cp);
}

int ci_ip_send_pkt_send(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                        const ci_ip_cached_hdrs* ipcache)
{
  int os_rc = 0;

  switch( ipcache->status ) {
  case retrrc_success:
    ci_ip_set_mac_and_port(ni, ipcache, pkt);
    ci_netif_send(ni, pkt);
    return 0;
  case retrrc_nomac:
    cicp_user_defer_send(ni, retrrc_nomac, &os_rc, OO_PKT_P(pkt),
                         ipcache->ifindex);
    return 0;
  case retrrc_noroute:
    return -EHOSTUNREACH;
  case retrrc_alienroute:
    return -ENETUNREACH;
  case retrrc_localroute:
    if( ipcache->flags & CI_IP_CACHE_IS_LOCALROUTE )
        ci_assert(0);
    /*passthrough*/
  default:
    if( ipcache->status < 0 )
      return ipcache->status;
    else
      /* belt and braces... */
      return 0;
  }
}


int ci_ip_send_pkt(ci_netif* ni, const struct oo_sock_cplane* sock_cp_opt,
                   ci_ip_pkt_fmt* pkt)
{
  ci_ip_cached_hdrs ipcache;
  ci_ip_send_pkt_lookup(ni, sock_cp_opt, pkt, &ipcache);
  return ci_ip_send_pkt_send(ni, pkt, &ipcache);
}


void ci_ip_send_tcp_slow(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_fmt* pkt)
{
  /* We're here because the ipcache is not valid. */
  int rc, prev_mtu = ts->s.pkt.mtu;

  cicp_user_retrieve(ni, &ts->s.pkt, &ts->s.cp);

  if( ts->s.pkt.status == retrrc_success ) {
    if( ts->s.pkt.mtu != prev_mtu )
      CI_PMTU_TIMER_NOW(ni, &ts->s.pkt.pmtus);
    ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);
    ci_netif_send(ni, pkt);
    return;
  }
  else if( ts->s.pkt.status == retrrc_localroute &&
           (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE) )
    ci_ip_local_send(ni, pkt, &ts->s, OO_SP_NULL);

  /* For TCP, we want the ipcache to only be valid when onloadable. */
  ci_ip_cache_invalidate(&ts->s.pkt);

  switch( ts->s.pkt.status ) {
  case retrrc_nomac:
    rc = 0;
    /* If we resend SYN, and there is no MAC - it means ARP failed.
     * Connect() should return with EHOSTUNREACH.
     * We verify twice - on the first and the second retransmit.
     * Very hackish.
     */
    if( ts->s.b.state == CI_TCP_SYN_SENT ) {
      if( ts->retransmits == 1 )
        ts->tcpflags |= CI_TCPT_FLAG_NO_ARP;
      else if( (ts->tcpflags & CI_TCPT_FLAG_NO_ARP) &&
               ts->retransmits == 2 ) {
        ci_tcp_drop(ni, ts, EHOSTUNREACH);
        return;
      }
    }
    cicp_user_defer_send(ni, retrrc_nomac, &rc, OO_PKT_P(pkt), 
                         ts->s.pkt.ifindex);
    ++ts->stats.tx_nomac_defer;
    return;
  case retrrc_noroute:
    rc = -EHOSTUNREACH;
    break;
  case retrrc_alienroute:
  case retrrc_localroute:
    /* ?? TODO: inc some stat */
    return;
  default:
    ci_assert_lt(ts->s.pkt.status, 0);
    if( ts->s.pkt.status < 0 )
      rc = ts->s.pkt.status;
    else
      /* belt and braces... */
      rc = 0;
  }

  ci_assert_le(rc, 0);

  /* In most cases, we should ignore return code; the packet will be resend
   * later, because of RTO.  However, in SYN-SENT we should pass errors to
   * user.  At the same time, we should not pass ENOBUFS to user - it is
   * pretty internal problem of cplane, so we should try again.  Possibly,
   * there may be other internal problems, such as ENOMEM.
   *
   * Also, do not break connection when the first SYN fails:
   * - Linux does not do it;
   * - cplane has some latency, so we have false positives here;
   * - ci_tcp_connect() does not expect it.
   */
  if( ts->s.b.state == CI_TCP_SYN_SENT && rc < 0 && ts->retransmits > 0 &&
      (rc == -EHOSTUNREACH || rc == -ENETUNREACH || rc == -ENETDOWN) )
    ci_tcp_drop(ni, ts, -rc);
}

/*! \cidoxg_end */
