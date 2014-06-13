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

#ifndef __TCP_RX_H__
#define __TCP_RX_H__

#include <onload/sleep.h>


ci_inline void ci_tcp_rx_set_isn(ci_tcp_state* ts, unsigned isn)
{
  ci_assert_equal(tcp_rcv_usr(ts), 0);
  tcp_rcv_nxt(ts) = isn;
  ts->rcv_added = ts->rcv_delivered = isn;
}


ci_inline int ci_tcp_need_ack(ci_netif* ni, ci_tcp_state* ts)
{
  /* - More than [delack_thresh] ACKs have been requested, 
   *
   * - Right edge has moved significantly.  (This breaks RFC, but
   * reduces ack rate (and linux behaves like this).
   *
   * - We're in fast-start.
   */
  int max_window = CI_MIN(tcp_rcv_buff(ts), (0xffff << ts->rcv_wscl));
  return 
#if CI_CFG_DYNAMIC_ACK_RATE 
    /* We only need to look at dynack_thresh, not also delack_thresh,
     * because we know dynack_thresh >= delack_thresh, and they are
     * equal if that feature is disabled
     */
    ((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > NI_OPTS(ni).dynack_thresh)
#else
    ((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > NI_OPTS(ni).delack_thresh)
#endif
    || ( SEQ_GE(ts->rcv_delivered + max_window,
                ts->rcv_wnd_right_edge_sent+ci_tcp_ack_trigger_delta(ts)) |
         (ci_tcp_is_in_faststart(ts)                                    ) );
}


ci_inline void ci_tcp_rx_post_poll(ci_netif* ni, ci_tcp_state* ts)
{
  LOG_TR(ci_log("%s: "NTS_FMT "acks=%x %s", __FUNCTION__,
                NTS_PRI_ARGS(ni, ts), ts->acks_pending,
                ci_tcp_sendq_not_empty(ts) ? " SENDQ":""));

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.b.sb_flags & CI_SB_FLAG_TCP_POST_POLL);

  ts->s.b.sb_flags &=~ CI_SB_FLAG_TCP_POST_POLL;


  if( ci_tcp_sendq_not_empty(ts) ) {
    ci_tcp_tx_advance(ts, ni);
    if( ci_tcp_tx_advertise_space(ts) )
      ci_tcp_wake(ni, ts, CI_SB_FLAG_WAKE_TX);
  }

#if CI_CFG_TCP_FASTSTART
  if( ci_tcp_time_now(ni) - ts->t_prev_recv_payload > NI_CONF(ni).tconst_idle )
    ts->faststart_acks = NI_OPTS(ni).tcp_faststart_idle;
  ts->t_prev_recv_payload = ts->t_last_recv_payload;
#endif

  if( ts->acks_pending ) {
#ifndef NDEBUG
    if( TCP_ACK_FORCED(ts) )
      ci_log("%s: "NTS_FMT "ACK_FORCED flag set unexpectedly: %x", 
             __FUNCTION__, NTS_PRI_ARGS(ni, ts), ts->acks_pending);
#endif

    if( OO_SP_NOT_NULL(ts->s.local_peer) ) {
      if( ts->acks_pending )
        ci_tcp_send_ack_loopback(ni, ts);
      return;
    }
    if( ci_tcp_need_ack(ni, ts) ) {
      ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni);
      if(CI_LIKELY( pkt != NULL )) {
        ci_tcp_send_ack(ni, ts, pkt);
        return;
      }
    }
#if CI_CFG_DYNAMIC_ACK_RATE
    /* If these values are equal it implies dynamic_ack_rate is off */
    if( NI_OPTS(ni).dynack_thresh > NI_OPTS(ni).delack_thresh) {
      /* If up-to delack_thresh ACK request, then set delack timer as normal
       * If subsequent ACK request, then set delack timer to 1 timer tick
       * (delack soon mode)
       * Otherwise do nothing until timer expires or larger threshold
       * exceeded and ACK is sent
       */
      if( (ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) <= 
          NI_OPTS(ni).delack_thresh )
        ci_tcp_delack_check_and_set(ni, ts);
      else if( !(ts->acks_pending & CI_TCP_DELACK_SOON_FLAG) )
        ci_tcp_delack_soon(ni, ts);
    } else
      ci_tcp_delack_check_and_set(ni, ts);
#else
    ci_tcp_delack_check_and_set(ni, ts);
#endif
  }
}

/* Set send window, both initially at handshake time and later when
 * receiving a new ACK.
 *
 * Caller should check for window shrinkage constraints.
 *
 * Caller must guarantee that ack + wnd >= ts->snd_una (which is
 * always true on fast path so no additional checks should be
 * necessary there).
 */
ci_inline void ci_tcp_set_snd_max(ci_tcp_state *ts, ci_uint32 seq, 
                                  ci_uint32 ack, ci_uint32 wnd)
{
#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
  ts->snd_wl1 = seq;
#endif
  ts->snd_max = ack + wnd;
}


#endif  /* __TCP_RX_H__ */
