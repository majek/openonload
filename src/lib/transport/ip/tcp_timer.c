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
** <L5_PRIVATE L5_SOURCE>
** \author  ctk
**  \brief  TCP timer initiated actions.
**   \date  2004/01/14
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include <ci/internal/cplane_ops.h>
#include "tcp_rx.h" /* for ci_tcp_set_snd_max() */

#define LPF "TCP TIMER "


#ifndef __KERNEL__
#ifndef NDEBUG
static void ci_tcp_timer_dump_consts(ci_netif* netif)
{
  log(LPF "time constants for this CPU\n"
      "  rto_initial: %uticks (%ums)\n" 
      "  rto_min: %uticks (%ums)\n" 
      "  rto_max: %uticks (%ums)\n"
      "  delack: %uticks (%ums)",
      NI_CONF(netif).tconst_rto_initial, NI_OPTS(netif).rto_initial,
      NI_CONF(netif).tconst_rto_min, NI_OPTS(netif).rto_min,
      NI_CONF(netif).tconst_rto_max, NI_OPTS(netif).rto_max,
      NI_CONF(netif).tconst_delack, CI_TCP_TCONST_DELACK);
  log("  keepalive_time: %uticks (%ums)\n" 
      "  keepalive_intvl: %uticks (%ums)\n" 
      "  keepalive_probes: %u\n"
      "  zwin_max: %uticks (%ums)",
      NI_CONF(netif).tconst_keepalive_time, NI_OPTS(netif).keepalive_time,
      NI_CONF(netif).tconst_keepalive_intvl, NI_OPTS(netif).keepalive_intvl,
      NI_OPTS(netif).keepalive_probes,
      NI_CONF(netif).tconst_zwin_max, CI_TCP_TCONST_ZWIN_MAX);
  log("  listen_time: %uticks (%ums)\n"
      "  listen_synack_retries: %d\n"
      "  paws_idle: %uticks (%ums)",
      NI_CONF(netif).tconst_listen_time, CI_TCP_TCONST_LISTEN_TIME,
      NI_CONF(netif).listen_synack_retries,
      NI_CONF(netif).tconst_paws_idle, CI_TCP_TCONST_PAWS_IDLE);
  log("  PMTU slow discover: %uticks (%ums)\n"
      "  PMTU fast discover: %uticks (%ums)\n"
      "  PMTU recover: %uticks (%ums)",
      NI_CONF(netif).tconst_pmtu_discover_slow, CI_PMTU_TCONST_DISCOVER_SLOW,
      NI_CONF(netif).tconst_pmtu_discover_fast, CI_PMTU_TCONST_DISCOVER_FAST,
      NI_CONF(netif).tconst_pmtu_discover_recover, 
      CI_PMTU_TCONST_DISCOVER_RECOVER);
  log("  Intrumentation: %uticks (%ums)",
      NI_CONF(netif).tconst_stats, CI_TCONST_STATS);
}
#endif /* NDEBUG */

#endif


/* Called to setup the TCP time constants in terms of ticks for this
** machine.
**
** TODO: Could be done once per driver, rather than once per stack...
*/
void ci_tcp_timer_init(ci_netif* netif)
{
  NI_CONF(netif).tconst_rto_initial = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_initial);
  NI_CONF(netif).tconst_rto_min = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_min);
  NI_CONF(netif).tconst_rto_max = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_max);


  NI_CONF(netif).tconst_delack = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_DELACK);

  NI_CONF(netif).tconst_keepalive_time = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_time);
  NI_CONF(netif).tconst_keepalive_intvl = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_intvl);
  
  NI_CONF(netif).tconst_zwin_max = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_ZWIN_MAX);

  NI_CONF(netif).tconst_listen_time = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_LISTEN_TIME);
  NI_CONF(netif).listen_synack_retries = CI_TCP_LISTEN_SYNACK_RETRIES;
  
  NI_CONF(netif).tconst_paws_idle = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_PAWS_IDLE);

  NI_CONF(netif).tconst_2msl_time = 
    ci_tcp_time_ms2ticks(netif, 2*NI_OPTS(netif).msl_seconds*1000);
  NI_CONF(netif).tconst_fin_timeout = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).fin_timeout*1000);


  NI_CONF(netif).tconst_pmtu_discover_slow = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_SLOW);

  NI_CONF(netif).tconst_pmtu_discover_fast = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_FAST);

  NI_CONF(netif).tconst_pmtu_discover_recover = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_RECOVER);

  NI_CONF(netif).tconst_stats = 
    ci_tcp_time_ms2ticks(netif, CI_TCONST_STATS);

#ifndef __KERNEL__
  LOG_S(ci_tcp_timer_dump_consts(netif));
#endif
}


ci_inline void
ci_tcp_synrecv_set_retries_and_timeout(ci_netif* ni,
                                       ci_tcp_socket_listen* tls,
                                       ci_tcp_state_synrecv* tsr)
{
  if( tsr->retries++ == 0 )
    --tls->n_listenq_new;
  tsr->timeout = NI_CONF(ni).tconst_rto_initial << tsr->retries;
  tsr->timeout = CI_MIN(tsr->timeout, NI_CONF(ni).tconst_rto_max);
  tsr->timeout += ci_tcp_time_now(ni);
}


/* Called as action on a listen timeout */
void ci_tcp_timeout_listen(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  ci_ni_dllist_link* l;
  int max_retries, i;

  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);

  ci_assert(tls->n_listenq > 0);

  if( tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF )
    max_retries = tls->c.tcp_defer_accept;
  else
    max_retries = NI_CONF(netif).listen_synack_retries;

  /*
  ** Trawl listen queue and for each SYNRECV block:
  **  - send any pending SYNACK retranmsits 
  **  - delete connections which have exceeded X retries
  */
  for( i = 0; i < CI_CFG_TCP_LISTENQ_BUCKETS; ++i ) {
  l = ci_ni_dllist_start(netif, &tls->listenq[i]);
  while ( l != ci_ni_dllist_end(netif, &tls->listenq[i]) ) {

    ci_tcp_state_synrecv* tsr = 
          CI_CONTAINER(ci_tcp_state_synrecv, link, l);
    /* move to next link as code below can remove this link from the list */
    ci_ni_dllist_iter(netif, l);

    if( TIME_LT(tsr->timeout, ci_tcp_time_now(netif)) ) {      
      if( tsr->retries < max_retries ) {
        int rc = ci_tcp_synrecv_send(netif, tls, tsr, 0,
                                     CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK, NULL);
        ci_tcp_synrecv_set_retries_and_timeout(netif, tls, tsr);
        if( rc == 0 ) {
          CITP_STATS_NETIF(++netif->state->stats.synrecv_retransmits);
          LOG_TC(log(LPF "SYNRECV retransmited %d SYNACK\n" 
                     "  next will be sent at %d", tsr->retries, tsr->timeout));
        }
        else {
          LOG_U(ci_log("%s: no return route exists "CI_IP_PRINTF_FORMAT,
                       __FUNCTION__, CI_IP_PRINTF_ARGS(&tsr->r_addr)));
        }
      }
      else {
	ci_tcp_listenq_remove(netif, tls, tsr);
	ci_tcp_synrecv_free(netif, tsr);
        CITP_STATS_NETIF(++netif->state->stats.synrecv_timeouts);

	LOG_TC(log(LPF "SYNRECV retries %d exceeded %d,"
		   " returned to listen",
		   tsr->retries,
		   NI_CONF(netif).listen_synack_retries));
      }
    }
  }
  }

  /* if still any pending connectings */
  if( tls->n_listenq > 0 &&
      (~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) ) {
    ci_ip_timer_set(netif, &tls->listenq_tid,
		  ci_tcp_time_now(netif) + NI_CONF(netif).tconst_listen_time);
  }
}


/* Called as action on a keep alive timeout (KALIVE) */
void ci_tcp_timeout_kalive(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);


  /* Check to see if this has expired prematurely */
  if (ts->ka_probes == 0 && 
      ci_tcp_time_now(netif) - ts->t_last_recv < ci_tcp_kalive_idle_get(ts)) {
    /* NB. The above old code alludes to a special case on Linux where
     * instead of waiting for t_idle it waits for t_intvl if t_idle <
     * t_intvl.  It's not clear if this is just the case when we've
     * received a keepalive-ACK or from the start of the algorithm.
     * Ignoring this for now - fix again if it's a problem */

    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_idle_get(ts) - 
                          (ci_tcp_time_now(netif) - ts->t_last_recv));
    return;
  }

  if (ts->ka_probes != 0 && 
      ci_tcp_time_now(netif) - ts->t_last_recv < 
      ci_tcp_kalive_intvl_get(netif, ts)) {
    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_intvl_get(netif, ts) - 
                          (ci_tcp_time_now(netif) - ts->t_last_recv));
    return;
  }


#ifndef NDEBUG
  /* Might want to assert this, just log for now */
  if (!ci_ip_queue_is_empty(&ts->retrans))
    LOG_U(log(LPF "%d KALIVE with unacknowledged data", S_FMT(ts)));
#endif

  LOG_TL(log(LPF "%d KALIVE: 0x%x rto:%u\n",
	     S_FMT(ts), ci_tcp_time_now(netif), ts->rto));
  if (ts->ka_probes > ci_tcp_kalive_probes_get(ts) )
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_TIMEOUT( netif );
  if( ts->ka_probes >= ci_tcp_kalive_probes_get(ts) ) {
    LOG_U(log(LPF "%d KALIVE: (should drop) ka_probes=%u ka_probe_th=%u",
	      S_FMT(ts), ts->ka_probes, ci_tcp_kalive_probes_get(ts)));

    ci_tcp_send_rst(netif, ts);
    ts->ka_probes = 0;
    ci_tcp_drop(netif, ts, ETIMEDOUT);
    return;
  }

  ci_tcp_send_zwin_probe(netif, ts);

  ++ts->ka_probes;
  ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_intvl_get(netif, ts));
}


/* Called as action on a zero window probe timeout (ZWIN) */
void ci_tcp_timeout_zwin(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Either 
   * - Window has opened up;
   * - TCP is in state where we won't send anything;
   * - Retrans queue is not empty (and so retransmissions will be
   *   forcing ACKs)
   * so we can stop probing.  If retrans queue goes empty they will be
   * restarted
   */
  if( tcp_snd_wnd(ts) >= tcp_eff_mss(ts) ||
      ! (ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE) ||
      ci_ip_queue_not_empty(&ts->retrans) ) {
    ts->zwin_probes = 0;
    ts->zwin_acks = 0;
    return;
  }
  if( ci_tcp_sendq_is_empty(ts) ) {
    /* Keep running timer so we don't have to start it (and make the
     * associated check) on the data fast path when sendq goes
     * non-empty */
    ci_tcp_zwin_set(netif, ts);
    return;
  }

  LOG_TT(log(LNTS_FMT "ZWIN: now=0x%x rto=%u snd_wnd=%d probes=%d,%d",
	     LNTS_PRI_ARGS(netif, ts), ci_tcp_time_now(netif), ts->rto,
	     tcp_snd_wnd(ts), ts->zwin_probes, ts->zwin_acks));


  if( CI_UNLIKELY(tcp_snd_wnd(ts) > 0) ) {
    /* We consider window < eff_mss to be zero, but it is not always
     * correct.  First, sometimes we have a short packet in the sendq.
     * Let's send it.  Next, we really should split the first packet (by
     * RFC 793) if peer refuses to increase its small window, but we cheat.
     *
     * With small non-zero window, we wait for 2 zwin_acks (in hope to get
     * better window) and, after thet, send the first packet.
     * Some IP stacks (Linux) accept such packet.  Others will reject and
     * re-send the correct window, so we'll fix our window back.
     */
    if( CI_UNLIKELY(tcp_snd_wnd(ts) >=
                    PKT_TCP_TX_SEQ_SPACE(PKT_CHK(netif, ts->send.head))) ) {
      /* Really unlikely, but could happen as a result of various race
       * conditions. */
      ci_tcp_tx_advance(ts, netif);
      return;
    }
    if( ts->zwin_probes == 0 && ts->zwin_acks > 2 ) {
      /* Cheat and send the full packet.  We do similar thing in
       * ci_tcp_tx_advance when eff_mss have changed. */
      ci_tcp_set_snd_max(ts, tcp_rcv_nxt(ts) - 1, ts->snd_max,
                         tcp_eff_mss(ts) - tcp_snd_wnd(ts));
      ci_assert_equal(tcp_snd_wnd(ts), tcp_eff_mss(ts));
      ci_tcp_tx_advance(ts, netif);
      ts->zwin_acks = 0;
      /* Count it as zero window probe, so go forward.  Moreover, it IS zero
       * window probe - a packet with unacceptable sequence numbers. */
    }
    else
      ci_tcp_send_zwin_probe(netif, ts);
  }
  else
    ci_tcp_send_zwin_probe(netif, ts);
  ci_tcp_zwin_set(netif, ts);
  ts->zwin_probes++;
}


/* Called as action on a delayed acknowledgement timeout (DELACK) */
void ci_tcp_timeout_delack(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_fmt* pkt;

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);
  ci_assert((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > 0);

  LOG_TV(log(LNT_FMT "DELACK now=0x%x acks_pending=%x", LNT_PRI_ARGS(netif,ts),
	     ci_tcp_time_now(netif), ts->acks_pending));

  pkt = ci_netif_pkt_alloc(netif);
  if( pkt ) {
    CI_TCP_EXT_STATS_INC_DELAYED_ACK( netif );
    CITP_STATS_NETIF_INC(netif, acks_sent);
    ci_tcp_send_ack(netif, ts, pkt);
  }
  else {
    LOG_TR(log(LNT_FMT "DELACK now=%x acks_pending=%x NO BUFS (will retry)",
	       LNT_PRI_ARGS(netif, ts),
	       ci_tcp_time_now(netif), ts->acks_pending));
    ci_ip_timer_set(netif, &ts->delack_tid,
		    ci_tcp_time_now(netif) + NI_CONF(netif).tconst_delack);
  }
}


static void ci_tcp_drop_due_to_rto(ci_netif *ni, ci_tcp_state *ts,
                                   int max_retrans)
{
  LOG_U(log(LNTS_FMT " (%s) state=%u so_error=%d retransmits=%u max=%u",
            LNTS_PRI_ARGS(ni, ts), __FUNCTION__,
            ts->s.b.state, ts->s.so_error, ts->retransmits, max_retrans));
  ci_tcp_send_rst(ni, ts);
  ts->retransmits = 0;
  ci_tcp_drop(ni, ts, ETIMEDOUT);

}

/* Called as TCP_CORK timeout */
void ci_tcp_timeout_cork(ci_netif* netif, ci_tcp_state* ts)
{
  /* We do not stop the timer when a packet is send (just because we do not
   * know when we should do it).  So, let's check if we have only one packet
   * in sendq.  Well, possibly it is not our packet, but there is no harm
   * here. */
  if( ts->send.num == 1 ) {
    TX_PKT_TCP(PKT_CHK(netif, ts->send.head))->tcp_flags |= CI_TCP_FLAG_PSH;
    ci_tcp_tx_advance(ts, netif);
  }
  return;
}

/* Called as action on a retransmission timer timeout (RTO) */
void ci_tcp_timeout_rto(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  unsigned max_retrans;

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Must have data unacknowledged for an RTO timeout. */
  ci_assert(!ci_ip_queue_is_empty(rtq));

  LOG_TL(ci_ip_pkt_fmt* pkt = PKT(netif, rtq->head);
	 log(LNTS_FMT "RTO now=%x srtt=%u rttvar=%u rto=%u retransmits=%d",
	     LNTS_PRI_ARGS(netif, ts), ci_tcp_time_now(netif), 
	     tcp_srtt(ts), tcp_rttvar(ts), ts->rto, ts->retransmits);
	 log("  "TCP_SND_FMT, TCP_SND_PRI_ARG(ts));
	 log("  "TCP_CONG_FMT, TCP_CONG_PRI_ARG(ts));
	 log("  head=%08x-%08x tsval=%x pkt_flag=%u",
	     pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq,
	     (ts->tcpflags&CI_TCPT_FLAG_TSO) ? PKT_TCP_TSO_TSVAL(pkt):0x0,
	     pkt->flags));
  CI_IP_SOCK_STATS_INC_RTTO( ts );

#if CI_CFG_BURST_CONTROL
  /* We've waited a whole RTO timeout, so disable any burst control
     from previous sends. Otherwise we might not send anything at
     all. (Bug 1208). */
  ts->burst_window = 0;
#endif

#if CI_CFG_TAIL_DROP_PROBE
  /* RTO generally means a dropped tail, so be more inquisitive from
     now on. */
  if(NI_OPTS(netif).tail_drop_probe &&
     ts->taildrop_state != CI_TCP_TAIL_DROP_ACTIVE){
    ts->taildrop_state = CI_TCP_TAIL_DROP_ACTIVE;
  }
#endif

  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    max_retrans = NI_OPTS(netif).retransmit_threshold_syn;
  }
  else {
    max_retrans = NI_OPTS(netif).retransmit_threshold;
    CITP_STATS_NETIF(++netif->state->stats.tcp_rtos);
  }

  if( ts->retransmits >= max_retrans || NI_OPTS(netif).rst_delayed_conn ) {
    ts->s.so_error = ETIMEDOUT;
    ci_tcp_drop_due_to_rto(netif, ts, max_retrans);
    return;
  }

  if( ts->s.b.state == CI_TCP_SYN_SENT && ts->s.so_error != 0 &&
       ts->retransmits > 0 /* ts->retransmits is incremented further down */ )
  {
    ci_tcp_drop_due_to_rto(netif, ts, max_retrans);
    return;
  }

  if( ts->congstate == CI_TCP_CONG_RTO ){
    /* RTO after a retransmission based on an RTO.
    **
    ** Ambiguous what to do here, but 2*SMSS is sensible: See:
    ** http://www.postel.org/pipermail/end2end-interest/2003-July/003244.html
    **
    ** (NB. ctk had 003374.html here, but it doesn't exist!  The one I've
    ** replaced it with looks right).
    */
    ts->ssthresh = tcp_eff_mss(ts) << 1u;
  }
  else {
    /* Set cwnd to 1SMSS and ssthresh to half flightsize.  But careful as
    ** NewReno fast-recovery will have an inflated flightsize.
    */
    if( ts->congstate == CI_TCP_CONG_FAST_RECOV &&
	!(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
      unsigned x = ts->ssthresh >> 1u;
      unsigned y = tcp_eff_mss(ts) << 1u;
      ts->ssthresh = CI_MAX(x, y);
    }
    else
      ts->ssthresh = ci_tcp_losswnd(ts);

    ts->congstate = CI_TCP_CONG_RTO;
    ts->cwnd_extra = 0;
    ++ts->stats.rtos;
  }

  ts->congrecover = tcp_snd_nxt(ts);

  /* Reset congestion window to one segment (RFC2581 p5). */
  ts->cwnd = CI_MAX(tcp_eff_mss(ts), NI_OPTS(netif).loss_min_cwnd);
  ts->bytes_acked = 0;

  /* Backoff RTO timer and restart. */
  ts->rto <<= 1u;
  ts->rto = CI_MIN(ts->rto, NI_CONF(netif).tconst_rto_max);    
  ci_tcp_rto_set(netif, ts);

  /* Delete all SACK marks (RFC2018 p6).  The reason is that the receiver
  ** is permitted to drop data that it has SACKed but not ACKed.  This
  ** ensures that we will eventually retransmit such data.
  */
  ci_tcp_clear_sacks(netif, ts);

  if( ci_tcp_inflight(ts) < (tcp_eff_mss(ts) >> 1) * ts->retrans.num )
    /* At least half the space in the retransmit queue is wasted, so see if
    ** we can coalesce it to make retransmits more efficient.
    */
    ci_tcp_retrans_coalesce_block(netif, ts, PKT_CHK(netif, rtq->head));

  /* Start recovery.  Because cwnd is only 1 MSS, we'll only transmit one
  ** packet from here.  (This is the right thing to do).
  */
  ++ts->retransmits;
  ci_tcp_retrans_recover(netif, ts, 0);
}


#if CI_CFG_TAIL_DROP_PROBE
/* Called as action on a tail drop timer timeout */
void ci_tcp_timeout_taildrop(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_queue *rtq = &ts->retrans;
  ci_ip_pkt_fmt *rtq_tail;
  unsigned rtq_tail_seq;

  ci_assert(NI_OPTS(netif).tail_drop_probe);

  /* check that there is >1 packet in the RTQ: otherwise could be a DELACK */
  if(ts->taildrop_state == CI_TCP_TAIL_DROP_PRIMED
     && rtq->num > 1){
    
    rtq_tail = PKT_CHK(netif, ts->retrans.tail);
    rtq_tail_seq = CI_BSWAP_BE32(TX_PKT_TCP(rtq_tail)->tcp_seq_be32);

    if (SEQ_LE(rtq_tail_seq, ts->taildrop_mark)){
      if(ci_tcp_send_taildrop_probe(netif, ts)){
	LOG_TV(log("Sending tail drop probe, mark %08x, una %08x seq %08x-%08x", 
		  ts->taildrop_mark, tcp_snd_una(ts), rtq_tail_seq,
		  rtq_tail->pf.tcp_tx.end_seq));
	/* probe sent */
	ts->taildrop_state = CI_TCP_TAIL_DROP_PROBED;
      }
      else{
	/* try again later? */
	ci_tcp_taildrop_check_and_set(netif, ts);
      }
      return;
    }
  }

  /* if conditions couldn't be met, suggests that tail drop didn't take place */
  ts->taildrop_state = CI_TCP_TAIL_DROP_ACTIVE;
}
#endif


/*! \cidoxg_end */
