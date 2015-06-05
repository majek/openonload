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
      "  delack: %uticks (%ums)\n"
      "  idle: %uticks (%ums)",
      NI_CONF(netif).tconst_rto_initial, NI_OPTS(netif).rto_initial,
      NI_CONF(netif).tconst_rto_min, NI_OPTS(netif).rto_min,
      NI_CONF(netif).tconst_rto_max, NI_OPTS(netif).rto_max,
      NI_CONF(netif).tconst_delack, CI_TCP_TCONST_DELACK,
      NI_CONF(netif).tconst_idle, CI_TCP_TCONST_IDLE);
  log("  keepalive_time: %uticks (%ums)\n" 
      "  keepalive_intvl: %uticks (%ums)\n" 
      "  keepalive_probes: %u\n"
      "  zwin_max: %uticks (%ums)",
      NI_CONF(netif).tconst_keepalive_time, NI_OPTS(netif).keepalive_time,
      NI_CONF(netif).tconst_keepalive_intvl, NI_OPTS(netif).keepalive_intvl,
      NI_OPTS(netif).keepalive_probes,
      NI_CONF(netif).tconst_zwin_max, CI_TCP_TCONST_ZWIN_MAX);
  log("  paws_idle: %uticks (%ums)",
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
  /* When converting to ticks we will end up with a rounded down value.  This
   * would result in an effective lower min, so add an extra tick to ensure
   * that the minimum value does not fall below that requested.
   */
  NI_CONF(netif).tconst_rto_min = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_min) + 1;
  NI_CONF(netif).tconst_rto_max = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_max);

  NI_CONF(netif).tconst_delack = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_DELACK);

  NI_CONF(netif).tconst_idle = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_IDLE);

  NI_CONF(netif).tconst_keepalive_time = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_time);
  NI_CONF(netif).tconst_keepalive_intvl = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_intvl);
  
  NI_CONF(netif).tconst_zwin_max = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_ZWIN_MAX);

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


/* Called as action on a listen timeout */
void ci_tcp_timeout_listen(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  ci_ni_dllist_link* l;
  int max_retries, retries, synrecv_timeout = 0;
  int out_of_packets = 0;
  ci_iptime_t next_timeout = ci_tcp_time_now(netif);

  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);

  ci_assert(tls->n_listenq > 0);

  if( tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF )
    max_retries = tls->c.tcp_defer_accept;
  else
    max_retries = NI_OPTS(netif).retransmit_threshold_synack;

  /*
  **  - send any pending SYNACK retranmsits 
  */
  for( retries = 0; retries < max_retries; ++retries ) {
    ci_ni_dllist_t* list = &tls->listenq[retries];
    ci_ni_dllist_link* last_l = NULL;

    for( l = ci_ni_dllist_start(netif, list);
         l != ci_ni_dllist_end(netif, list);
         ci_ni_dllist_iter(netif, l) ) {
      ci_tcp_state_synrecv* tsr =  ci_tcp_link2synrecv(l);

      ci_assert( OO_SP_IS_NULL(tsr->local_peer) );

      /* The list is time-ordered - break if timeout is ahead */
      if( TIME_GT(tsr->timeout, ci_tcp_time_now(netif)) ) {
        if( next_timeout == ci_tcp_time_now(netif) ||
            TIME_LT(tsr->timeout, next_timeout) )
          next_timeout = tsr->timeout;
        break;
      }

      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries);
      last_l = l;

      /* We have to re-send our SYN-ACK if:
       * - not acked: let's get an ACK!
       * - acked, but TCP_DEFER_ACCEPT is off: probably, we've failed to
       *   promote. Check that the peer is alive and try to promote
       *   again.
       */
      if( tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF &&
          (tsr->retries & CI_FLAG_TSR_RETRIES_MASK) == max_retries - 1 )
        tsr->retries &= ~CI_FLAG_TSR_RETRIES_ACKED;
      if( (~tsr->retries & CI_FLAG_TSR_RETRIES_ACKED) ||
          tls->c.tcp_defer_accept == OO_TCP_DEFER_ACCEPT_OFF ) {
        int rc = 0;
        ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(netif);

        if( pkt == NULL )
          goto out_of_packet;
        rc = ci_tcp_synrecv_send(netif, tls, tsr, pkt,
                                 CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK, NULL);
        if( rc == 0 ) {
          CITP_STATS_NETIF(++netif->state->stats.synrecv_retransmits);
          LOG_TC(log(LPF "SYNRECV retransmited %d SYNACK%s\n" 
                     "  next will be sent at %d",
                     tsr->retries & CI_FLAG_TSR_RETRIES_MASK,
                     (tsr->retries & CI_FLAG_TSR_RETRIES_ACKED) ?
                                                        " ACKed" : "",
                     tsr->timeout));
        }
        else {
          LOG_U(ci_log("%s: no return route exists "CI_IP_PRINTF_FORMAT,
                       __FUNCTION__, CI_IP_PRINTF_ARGS(&tsr->r_addr)));
        }
      }

      if( retries == 0 )
        --tls->n_listenq_new;
      tsr->retries++;
      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries + 1);

      tsr->timeout = NI_CONF(netif).tconst_rto_initial << (retries + 1);
      tsr->timeout = CI_MIN(tsr->timeout, NI_CONF(netif).tconst_rto_max);
      tsr->timeout += ci_tcp_time_now(netif);
    }

    /* Move the beginning of the processed listenq[retries] list
     * to the end of listenq[retries + 1] list. */
    if( last_l != NULL ) {
      ci_ni_dllist_t* next_list = &tls->listenq[retries + 1];
      ci_ni_dllist_link* start_l = ci_ni_dllist_start(netif, list);
      ci_ni_dllist_link* link_to_l = ci_ni_dllist_start_last(netif, next_list);
      ci_ni_dllist_link* unlink_from_l =
                (ci_ni_dllist_link*) CI_NETIF_PTR(netif, last_l->next);

      /* cut the beginning off the list: */
      list->l.next = ci_ni_dllist_link_addr(netif, unlink_from_l);
      unlink_from_l->prev = ci_ni_dllist_link_addr(netif, &list->l);

      /* append the processed part of the old "list"
       * to the end of the "next_list" */
      start_l->prev = ci_ni_dllist_link_addr(netif, link_to_l);
      link_to_l->next = ci_ni_dllist_link_addr(netif, start_l);
      last_l->next = ci_ni_dllist_link_addr(netif, &next_list->l);
      next_list->l.prev = ci_ni_dllist_link_addr(netif, last_l);
    }
  }

  /*
  **  - delete connections which have exceeded max_retries
  */
  for( retries = max_retries;
       retries <= CI_CFG_TCP_SYNACK_RETRANS_MAX;
       ++retries ) {
    l = ci_ni_dllist_start(netif, &tls->listenq[retries]);
    while ( l != ci_ni_dllist_end(netif, &tls->listenq[retries]) ) {
      ci_tcp_state_synrecv* tsr =  ci_tcp_link2synrecv(l);

      /* move to next link as code below can remove this link from the list */
      ci_ni_dllist_iter(netif, l);

      ci_assert( OO_SP_IS_NULL(tsr->local_peer) );

      /* The list is time-ordered - break if timeout is ahead */
      if( TIME_GT(tsr->timeout, ci_tcp_time_now(netif)) ) {
        if( next_timeout == ci_tcp_time_now(netif) ||
            TIME_LT(tsr->timeout, next_timeout) )
          next_timeout = tsr->timeout;
        break;
      }

      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries);

      ci_tcp_listenq_drop(netif, tls, tsr);
      ci_tcp_synrecv_free(netif, tsr);
      CITP_STATS_NETIF(++netif->state->stats.synrecv_timeouts);

      LOG_TC(log(LPF "SYNRECV retries %d exceeded %d,"
                 " returned to listen",
                 tsr->retries & CI_FLAG_TSR_RETRIES_MASK,
                 NI_OPTS(netif).retransmit_threshold_synack));

      ++synrecv_timeout;
    }
  }

out:
  if( synrecv_timeout )
    NI_LOG(netif, CONN_DROP, "%s: [%d] %d half-open timeouts\n", __func__,
           NI_ID(netif), synrecv_timeout);

  /* if still any pending connectings */
  if( next_timeout != ci_tcp_time_now(netif) ) {
    /* If out-of-packets, we should return here soon to send the synacks
     * we've failed to send now.  But not too soon - get a chance to
     * fix the problem as time passes. */
    ci_ip_timer_set(netif, &tls->listenq_tid,
                    out_of_packets ?
                            ci_tcp_time_now(netif) + 1 : next_timeout);
  }
  return;

out_of_packet:
  LOG_TV(ci_log(LNT_FMT"SYNRECV[retries=%d] no buffers, not re-sending synacks "
                "for %d half-opened connections",
                LNT_PRI_ARGS(netif, tls), retries,
                tls->n_listenq - tls->n_listenq_new));
  CITP_STATS_NETIF_INC(netif, tcp_listen_synack_retrans_no_buffer);
  out_of_packets = 1;
  goto out;
}


/* Called as action on a keep alive timeout (KALIVE) */
void ci_tcp_timeout_kalive(ci_netif* netif, ci_tcp_state* ts)
{
  ci_iptime_t t_last_recv = 
    CI_MAX(ts->t_last_recv_payload, ts->t_last_recv_ack);

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Check to see if this has expired prematurely */
  if (ts->ka_probes == 0 && 
      ci_tcp_time_now(netif) - t_last_recv < ci_tcp_kalive_idle_get(ts)) {
    /* NB. The above old code alludes to a special case on Linux where
     * instead of waiting for t_idle it waits for t_intvl if t_idle <
     * t_intvl.  It's not clear if this is just the case when we've
     * received a keepalive-ACK or from the start of the algorithm.
     * Ignoring this for now - fix again if it's a problem */

    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_idle_get(ts) - 
                          (ci_tcp_time_now(netif) - t_last_recv));
    return;
  }

  if (ts->ka_probes != 0 && 
      ci_tcp_time_now(netif) - t_last_recv < 
      ci_tcp_kalive_intvl_get(netif, ts)) {
    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_intvl_get(netif, ts) - 
                          (ci_tcp_time_now(netif) - t_last_recv));
    return;
  }

  ci_assert(ci_ip_queue_is_empty(&ts->retrans));

  /* TCP loopback does not have ACKs, so we just check the other side. */
  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    citp_waitable* peer = ID_TO_WAITABLE(netif, ts->local_peer);
    if( ~peer->state & CI_TCP_STATE_TCP_CONN )
      ci_tcp_drop(netif, ts, ETIMEDOUT);
    return;
  }

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
    ci_ip_pkt_fmt* first_pkt = PKT_CHK(netif, ts->send.head);
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
    if( CI_UNLIKELY(tcp_snd_wnd(ts) + ((1 << ts->snd_wscl) - 1) >=
                    PKT_TCP_TX_SEQ_SPACE(first_pkt)) ) {
      /* Window scaling might make the window a bit smaller than
       * mss, when out peer wanted it to be mss exactly.
       * We improve things by sending this packet
       * when zwin timer fires.  If the peer disagree, it'll tell
       * us in his ACK packet. */
      if( SEQ_GT(first_pkt->pf.tcp_tx.end_seq, ts->snd_max) )
        ts->snd_max += (1 << ts->snd_wscl) - 1;
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
    ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
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
