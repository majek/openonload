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
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk/stg
**  \brief  UDP receive
**   \date  2003/12/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "udp_internal.h"
#include <onload/sleep.h>

#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif


#define LPF "ci_udp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF

#define VERB(x)





int ci_udp_timestamp_q_enqueue(ci_netif* ni, ci_udp_state* us, 
                               ci_ip_pkt_fmt* pkt)
{
  ci_ip_pkt_fmt* p;
  int tsonly = us->s.timestamping_flags &
    ONLOAD_SOF_TIMESTAMPING_OPT_TSONLY;

  /* Limit timestamp queue by SO_SNDBUF */
  if( ci_udp_recv_q_pkts(&us->timestamp_q) + pkt->n_buffers >
      ci_udp_recv_q_bytes2packets(us->s.so.sndbuf) ) {
    /* recv(MSG_ERRQUEUE) does not lock the stack and can not reap the
     * timestamp queue, so the queue should be reaped if it looks
     * overfilled. */
    ci_udp_recv_q_reap(ni, &us->timestamp_q);
    if( ci_udp_recv_q_pkts(&us->timestamp_q) + pkt->n_buffers >= 
        ci_udp_recv_q_bytes2packets(us->s.so.sndbuf) ) {
      return -ENOSPC;
    }
  }

  if( tsonly && OO_PP_NOT_NULL(pkt->frag_next) ) {
    p = PKT_CHK(ni, pkt->frag_next);
    pkt->frag_next = OO_PP_NULL;
    ci_netif_pkt_release(ni, p);
  }

  ci_udp_recv_q_put(ni, &us->timestamp_q, pkt);
  /* Tells post-poll loop to put socket on the [reap_list]. */
  us->s.b.sb_flags |= CI_SB_FLAG_RX_DELIVERED;

  /* TODO is this necessary? - mirroring ci_udp_recv_q_put() */
  ci_wmb();

  ci_netif_put_on_post_poll(ni, &us->s.b);
  ci_udp_wake_possibly_not_in_poll(ni, us, CI_SB_FLAG_WAKE_RX);

  return 0;
}


int ci_udp_recv_q_reap(ci_netif* ni, ci_udp_recv_q* q)
{
  int freed = 0;
  while( ! OO_PP_EQ(q->head, q->extract) ) {
    ci_ip_pkt_fmt* pkt = PKT_CHK(ni, q->head);
    int n_buffers = pkt->n_buffers;
    q->head = pkt->udp_rx_next;
    freed += ci_netif_pkt_release_check_keep(ni, pkt);
    q->pkts_reaped += n_buffers;
  }
  return freed;
}


void ci_udp_recv_q_drop(ci_netif* ni, ci_udp_recv_q* q)
{
  ci_ip_pkt_fmt* pkt;
  while( OO_PP_NOT_NULL(q->head) ) {
    pkt = PKT_CHK(ni, q->head);
    q->head = pkt->udp_rx_next;
    ci_netif_pkt_release_check_keep(ni, pkt);
  }
}


int ci_udp_csum_correct(ci_ip_pkt_fmt* pkt, ci_udp_hdr* udp)
{
  int ip_len, ip_paylen;
  ci_ip4_pseudo_hdr ph;
  unsigned csum;

  ip_len = CI_BSWAP_BE16(oo_ip_hdr(pkt)->ip_tot_len_be16);
  ip_paylen = ip_len - sizeof(ci_ip4_hdr);
  pkt->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16);

  if( pkt->pf.udp.pay_len + sizeof(ci_udp_hdr) > ip_paylen )
    return 0;

  if( udp->udp_check_be16 == 0 )
    return 1;  /* RFC768: csum not computed */

  ph.ip_saddr_be32 = oo_ip_hdr(pkt)->ip_saddr_be32;
  ph.ip_daddr_be32 = oo_ip_hdr(pkt)->ip_daddr_be32;
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_UDP;
  ph.length_be16 = CI_BSWAP_BE16(pkt->pf.udp.pay_len);

  csum = ci_ip_csum_partial(0, &ph, sizeof(ph));
  csum = ci_ip_csum_partial(csum, udp, pkt->pf.udp.pay_len);
  csum = ci_ip_hdr_csum_finish(csum);
  return csum == 0;
}




int ci_udp_rx_deliver(ci_sock_cmn* s, void* opaque_arg)
{
  /* Deliver a received packet to a socket. */

  struct ci_udp_rx_deliver_state* state = opaque_arg;
  ci_ip_pkt_fmt* pkt = state->pkt;
  ci_ip_pkt_fmt* q_pkt;
  ci_udp_state* us = SOCK_TO_UDP(s);
  ci_netif* ni = state->ni;
  int recvq_depth = ci_udp_recv_q_pkts(&us->recv_q) + pkt->n_buffers;

  LOG_UV(log("%s: "NS_FMT "pay_len=%d "CI_IP_PRINTF_FORMAT" -> "
             CI_IP_PRINTF_FORMAT, __FUNCTION__,
             NS_PRI_ARGS(ni, s), pkt->pf.udp.pay_len,
             CI_IP_PRINTF_ARGS(&oo_ip_hdr(pkt)->ip_saddr_be32),
             CI_IP_PRINTF_ARGS(&oo_ip_hdr(pkt)->ip_daddr_be32)));

  state->delivered = 1;

#ifdef ONLOAD_OFE
  if( s->ofe_code_start != OFE_ADDR_NULL &&
      ofe_process_packet(ni->ofe_channel, s->ofe_code_start, ci_ip_time_now(ni),
                         oo_ether_hdr(pkt), pkt->pay_len, pkt->vlan,
                         CI_BSWAP_BE16(oo_ether_type_get(pkt)),
                         oo_ip_hdr(pkt))
      != OFE_ACCEPT ) {
    return 0; /* deliver to other sockets if their rules allow */
  }
#endif

  if( (recvq_depth <= us->stats.max_recvq_pkts) &&
      ! (ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL) ) {
    int multi_destination_pkt;

  fast_receive:
    multi_destination_pkt =
      CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ||
      oo_ip_hdr(pkt)->ip_daddr_be32 == CI_IP_ALL_BROADCAST;

    /* The same queue link is used for both the TX timestamp_q and the
     * udp recv_q, so we need to use an indirect packet if this is
     * timestamped.  This can only occur in the loopback case, where the
     * state->queued flag is ignored.
     */
    if( ! state->queued && !(pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED) ) {
      state->queued = 1;
      ci_netif_pkt_hold(ni, pkt);
    }
    else {
      /* Packet already queued on at least one socket.  Wrap it with an
       * "indirect" packet so we can queue it in this one too.  The
       * indirect packet needs to have some fields initialised that are
       * looked at on the receive path.  The indirect packet looks like an
       * empty "fragment" at the head of the real packet.
       */
      if( ni->state->n_rx_pkts > NI_OPTS(ni).max_rx_packets ||
          (q_pkt = ci_netif_pkt_alloc(ni)) == NULL )
        goto drop;
      ++ni->state->n_rx_pkts;
      q_pkt->pf.udp.pay_len = pkt->pf.udp.pay_len;
      q_pkt->pf.udp.rx_stamp = pkt->pf.udp.rx_stamp;
      q_pkt->pf.udp.rx_hw_stamp.tv_sec = pkt->pf.udp.rx_hw_stamp.tv_sec;
      oo_offbuf_init(&q_pkt->buf, PKT_START(q_pkt), 0);
      q_pkt->flags = (CI_PKT_FLAG_RX_INDIRECT | CI_PKT_FLAG_UDP |
                      CI_PKT_FLAG_RX);
      q_pkt->frag_next = OO_PKT_P(pkt);
      q_pkt->n_buffers = pkt->n_buffers + 1;
      ci_netif_pkt_hold(ni, pkt);
      pkt = q_pkt;
    }
    ci_assert( (pkt->rx_flags & CI_PKT_RX_FLAG_UDP_KEEP) == 0 );
    ci_udp_recv_q_put(ni, &us->recv_q, pkt);
    us->s.b.sb_flags |= CI_SB_FLAG_RX_DELIVERED;
    ci_netif_put_on_post_poll(ni, &us->s.b);
    ci_udp_wake_possibly_not_in_poll(ni, us, CI_SB_FLAG_WAKE_RX);
    if( multi_destination_pkt ) {
      /* Multicast or all-broadcast address:
       * continue delivering to other sockets */
      return 0;
    }
    else {
      /* We should also check for the interface broadcast address,
       * but we don't */
      return 1;
    }
  }

  /* First check if we've come here just to update max_recvq_depth */
  if( recvq_depth > us->stats.max_recvq_pkts ) {
    if( recvq_depth <= ci_udp_recv_q_bytes2packets(us->s.so.rcvbuf)  &&
        ! (ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL) ) {
      us->stats.max_recvq_pkts = recvq_depth;
      goto fast_receive;
    }
  }

  /* Receive queue overflow or memory pressure. */
 drop:
  if( recvq_depth > ci_udp_recv_q_bytes2packets(us->s.so.rcvbuf) ) {
    LOG_UR(log(FNS_FMT "OVERFLOW pay_len=%d",
               FNS_PRI_ARGS(ni, s), pkt->pf.udp.pay_len));
    ++us->stats.n_rx_overflow;
  }
  else {
    LOG_UR(log(FNS_FMT "DROP (memory pressure) pay_len=%d",
               FNS_PRI_ARGS(ni, s), pkt->pf.udp.pay_len));
    CITP_STATS_NETIF_INC(ni, memory_pressure_drops);
    ++us->stats.n_rx_mem_drop;
  }
  return 0;  /* continue delivering to other sockets */
}


/* Called with the IP hdr's ip_tot_len_be16 field swapped to processor
 * endian and no fragments or IP options - therefore headers are
 * sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr) in length.
 */
void ci_udp_handle_rx(ci_netif* ni, ci_ip_pkt_fmt* pkt, ci_udp_hdr* udp,
                      int ip_paylen)
{
  struct ci_udp_rx_deliver_state state;
  int dealt_with;

  ASSERT_VALID_PKT(ni, pkt);
  ci_assert(oo_ip_hdr(pkt)->ip_protocol == IPPROTO_UDP);
  ci_assert(oo_offbuf_ptr(&pkt->buf) == PKT_START(pkt));
  ci_assert_gt(pkt->pay_len, ip_paylen);

  pkt->pf.udp.rx_stamp = IPTIMER_STATE(ni)->frc;

  LOG_UV( log( LPF "handle_rx: UDP:%p IP:%p", udp, oo_ip_hdr(pkt)));

  /* Check for bad length. */
  pkt->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16);
  if( (pkt->pf.udp.pay_len < sizeof(ci_udp_hdr)) |
      (pkt->pf.udp.pay_len > ip_paylen) )
    goto length_error;
  pkt->pf.udp.pay_len -= sizeof(ci_udp_hdr);

  oo_offbuf_set_start(&pkt->buf, udp + 1);
  CI_UDP_STATS_INC_IN_DGRAMS(ni);

  state.ni = ni;
  state.pkt = pkt;
  state.queued = 0;
  state.delivered = 0;

  dealt_with = 
    ci_netif_filter_for_each_match(ni,
                                   oo_ip_hdr(pkt)->ip_daddr_be32,
                                   udp->udp_dest_be16,
                                   oo_ip_hdr(pkt)->ip_saddr_be32,
                                   udp->udp_source_be16,
                                   IPPROTO_UDP, pkt->intf_i, pkt->vlan,
                                   ci_udp_rx_deliver, &state, NULL);
  if( ! dealt_with ) {
    ci_netif_filter_for_each_match(ni,
                                   oo_ip_hdr(pkt)->ip_daddr_be32,
                                   udp->udp_dest_be16,
                                   0, 0, IPPROTO_UDP, pkt->intf_i, pkt->vlan,
                                   ci_udp_rx_deliver, &state, NULL);
  }

  if( state.queued ) {
    ci_assert_gt(pkt->refcount, 1);
    --pkt->refcount;
    return;
  }

  if( state.delivered == 0 ) {
    LOG_U( log(LPFOUT "handle_rx: NO MATCH %s:%u->%s:%u",
               ip_addr_str(oo_ip_hdr(pkt)->ip_saddr_be32),
               (unsigned) CI_BSWAP_BE16(udp->udp_source_be16),
               ip_addr_str(oo_ip_hdr(pkt)->ip_daddr_be32),
               (unsigned) CI_BSWAP_BE16(udp->udp_dest_be16)));
    CITP_STATS_NETIF_INC(ni, udp_rx_no_match_drops);
    if( ! CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ) {
      CI_UDP_STATS_INC_NO_PORTS(ni);
      ci_icmp_send_port_unreach(ni, pkt);
    }
  }
  goto drop_out;

 length_error:
  CI_UDP_STATS_INC_IN_ERRS(ni);
  LOG_U(log("%s: ip_paylen=%d udp_len=%d",
            __FUNCTION__, ip_paylen, pkt->pf.udp.pay_len));
  goto drop_out;

 drop_out:
  ci_netif_pkt_release_rx_1ref(ni, pkt);
  return;
}

/*! \cidoxg_end */
