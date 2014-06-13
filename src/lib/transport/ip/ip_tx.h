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
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  Header file for ip_tx.c
**   \date  2005/09/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_ip_tx */

#ifndef __CI_INTERNAL_IP_TX_H__
#define __CI_INTERNAL_IP_TX_H__

#include <ci/internal/ip.h>
#include <ci/internal/cplane_ops.h>
#include "netif_tx.h"


/* Send packet to the IP layer.
 *
 * This function is used when sending packets that are not part of the
 * normal "stream" of packets associated with a socket.  It is assumed that
 * the caller has already filled in the source and dest IP addresses and
 * (if applicable) port numbers.
 *
 * If [sock_cp_opt] is provided then it is used only for the
 * SO_BINDTODEVICE and IP_MULTICAST_IF options.  The source IP and port in
 * [sock_cp_opt] are ignored, and rather are taken from the packet headers.
 */
extern int ci_ip_send_pkt(ci_netif* ni,
                          const struct oo_sock_cplane* sock_cp_opt,
                          ci_ip_pkt_fmt* pkt) CI_HF;

/* Do control plane lookup to send [pkt], but don't actually send it.  This
 * is a subset of ci_ip_send_pkt(), and is needed when information from the
 * control plane lookup is needed before sending.
 *
 * [ipcache] points to storage provided by caller, and need not be
 * initialised by the caller.  [sock_cp_opt] is used as described in
 * ci_ip_send_pkt().
 */
extern void ci_ip_send_pkt_lookup(ci_netif* ni,
                                  const struct oo_sock_cplane* sock_cp_opt,
                                  ci_ip_pkt_fmt* pkt,
                                  ci_ip_cached_hdrs* ipcache) CI_HF;

/* Second half of split version of ci_ip_send_pkt(). */
extern int ci_ip_send_pkt_send(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                               const ci_ip_cached_hdrs* ipcache) CI_HF;

/* Send the [pkt] via loopback from socket [s] to socket [dst].
 */
ci_inline void ci_ip_local_send(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                ci_sock_cmn *s, oo_sp dst)
{
  ci_assert(ci_netif_is_locked(ni));
  pkt->pf.lo.tx_sock = SC_SP(s);
  pkt->pf.lo.rx_sock = OO_SP_IS_NULL(dst) ? s->local_peer : dst;
  ci_assert(OO_SP_NOT_NULL(pkt->pf.lo.rx_sock));
  LOG_NT(ci_log(NS_FMT "loopback TX pkt %d to %d", NS_PRI_ARGS(ni, s),
                OO_PKT_FMT(pkt), OO_SP_FMT(pkt->pf.lo.rx_sock)));
  ci_netif_pkt_hold(ni, pkt);
  pkt->next = ni->state->looppkts;
  ni->state->looppkts = OO_PKT_P(pkt);
  ni->state->poll_work_outstanding = 1;
}

ci_inline void
ci_ip_set_mac_and_port(ci_netif* ni, const ci_ip_cached_hdrs* ipcache,
                       ci_ip_pkt_fmt* pkt)
{
  ci_assert_equal(ipcache->ether_type, CI_ETHERTYPE_IP);
  if (ipcache->ether_offset)
    oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_TX_SIMPLE);
  else
    oo_pkt_layout_set(pkt, CI_PKT_LAYOUT_TX_VLAN);
  memcpy(oo_ether_dhost(pkt), ci_ip_cache_ether_hdr(ipcache),
         ETH_HLEN + ETH_VLAN_HLEN - ipcache->ether_offset);
  pkt->intf_i = ipcache->intf_i;
#if CI_CFG_PORT_STRIPING
  /* ?? FIXME: This code assumes that the two ports we're striping over
   * have macs that differ only in the bottom bit (both local and remote).
   */
  pkt->intf_i ^= pkt->netif.tx.intf_swap;
  oo_ether_dhost(pkt)[5]  ^= pkt->netif.tx.intf_swap;
  oo_ether_shost(pkt)[5]  ^= pkt->netif.tx.intf_swap;
#endif
  ci_assert_equal(oo_ether_type_get(pkt), CI_ETHERTYPE_IP);
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(pkt)), sizeof(ci_ip4_hdr));
}


extern void ci_ip_send_tcp_slow(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*)CI_HF;


ci_inline void
__ci_ip_send_tcp(ci_netif* ni, ci_ip_pkt_fmt* pkt, ci_tcp_state* ts)
{
  if( ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE ) {
    ci_ip_local_send(ni, pkt, &ts->s, OO_SP_NULL);
    return;
  }
  ci_ip_cache_check(&ts->s.pkt);
  CI_IPV4_STATS_INC_OUT_REQUESTS(ni);
  if(CI_LIKELY( cicp_ip_cache_is_valid(CICP_HANDLE(ni), &ts->s.pkt) )) {
    ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);
    ci_netif_send(ni, pkt);
  }
  else {
    ci_ip_send_tcp_slow(ni, ts, pkt);
  }
}


ci_inline void
ci_ip_send_tcp(ci_netif *ni, ci_ip_pkt_fmt *pkt, ci_tcp_state *ts)
{
#if CI_CFG_PORT_STRIPING
  pkt->netif.tx.intf_swap = 0;
#endif
  __ci_ip_send_tcp(ni, pkt, ts);
}


#endif /* __CI_INTERNAL_IP_TX_H__ */
/*! \cidoxg_end */
