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

/************************************************************************** \
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Initialisation for TCP state.
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/cplane_ops.h> /* for ip.h ci_ip_cache_init */


#define TCP_STATE_POISON 0xff


#define LPF "TCP "


static void ci_tcp_state_setup_timers(ci_netif* ni, ci_tcp_state* ts)
{
#define ci_tcp_setup_timer(name, callback, label)                      \
  do {                                                          \
    ci_ip_timer* t = &ts->name##_tid;                           \
    oo_p sp;                                                    \
    t->param1 = S_SP(ts);                                       \
    t->fn = callback;                                           \
    sp = TS_OFF(ni, ts);                                        \
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, name##_tid));   \
    ci_ip_timer_init(ni, &ts->name##_tid, sp, label);           \
  } while(0)

  ci_tcp_setup_timer(rto,      CI_IP_TIMER_TCP_RTO,    "rtot");
  ci_tcp_setup_timer(delack,   CI_IP_TIMER_TCP_DELACK, "dela");
  ci_tcp_setup_timer(zwin,     CI_IP_TIMER_TCP_ZWIN,   "zwin");
  ci_tcp_setup_timer(kalive,   CI_IP_TIMER_TCP_KALIVE, "kalv");
#if CI_CFG_TCP_SOCK_STATS
  ci_tcp_setup_timer(stats,    CI_IP_TIMER_TCP_STATS,  "stat");
#endif
#if CI_CFG_TAIL_DROP_PROBE
  ci_tcp_setup_timer(taildrop, CI_IP_TIMER_TCP_TAIL_DROP,"tdrp");
#endif
  ci_tcp_setup_timer(cork,     CI_IP_TIMER_TCP_CORK,   "cork");

#undef ci_tcp_setup_timer
}


static void ci_tcp_state_connected_opts_init(ci_netif* netif, ci_tcp_state* ts)
{
  oo_p sp;
  int i;

  ts->send_prequeue = CI_ILL_END;
  oo_atomic_set(&ts->send_prequeue_in, 0);
  ts->send_in = 0;
  ts->send_out = 0;

  /* Queues. */
  ci_ip_queue_init(&ts->recv1);
  ci_ip_queue_init(&ts->recv2);
  TS_QUEUE_RX_SET(ts, recv1);
  ts->recv1_extract = OO_PP_NULL;

  /* Re-order buffer length is limited by our window. */
  ci_ip_queue_init(&ts->rob);
  /* Send queue max length will be set in ci_tcp_set_eff_mss() using
   * so.sndbuf value. */
  ts->send_max = 0;
  ci_ip_queue_init(&ts->send);
  /* Retransmit queue is limited by peer window. */
  ci_ip_queue_init(&ts->retrans);
  for(i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      ts->last_sack[i] = OO_PP_NULL;
  ts->dsack_block = OO_PP_INVALID;

  sp = oo_sockp_to_statep(netif, S_SP(ts));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, timeout_q_link));
  ci_ni_dllist_link_init(netif, &ts->timeout_q_link, sp, "tmoq");
  CI_DEBUG(ci_ni_dllist_mark_free(&ts->timeout_q_link));

  sp = oo_sockp_to_statep(netif, S_SP(ts));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, tx_ready_link));
  ci_ni_dllist_link_init(netif, &ts->tx_ready_link, sp, "tmoq");
  ci_ni_dllist_self_link(netif, &ts->tx_ready_link);
}


static void ci_tcp_state_tcb_init_fixed(ci_netif* netif, ci_tcp_state* ts)
{
  /* SO_RCVLOWAT */
  ts->s.so.rcvlowat = 1;

  /* keep alive probes options */
  ts->c.ka_probe_th = NI_OPTS(netif).keepalive_probes;
  ts->c.t_ka_time = NI_CONF(netif).tconst_keepalive_time;
  ts->c.t_ka_time_in_secs = NI_OPTS(netif).keepalive_time / 1000;
  ts->c.t_ka_intvl = NI_CONF(netif).tconst_keepalive_intvl;
  ts->c.t_ka_intvl_in_secs = NI_OPTS(netif).keepalive_intvl / 1000;

  /* Initialise packet header and flow control state. */
  ci_ip_hdr_init_fixed(&ts->s.pkt.ip, IPPROTO_TCP,
                       CI_IP_DFLT_TTL, CI_IP_DFLT_TOS);

  sock_laddr_be32(&(ts->s)) = 0;
  TS_TCP(ts)->tcp_source_be16 = 0;
#if CI_CFG_FD_CACHING
  ts->cached_on_pid = -1;
#endif
}

/* Reset state for a connection, used for shutdown following listen. */
static void ci_tcp_state_tcb_reinit(ci_netif* netif, ci_tcp_state* ts)
{
  ci_tcp_state_setup_timers(netif, ts);

#if CI_CFG_FD_CACHING
  {
    oo_p sp;
    ts->cached_on_fd = -1;
    sp = TS_OFF(netif, ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, epcache_link));
    ci_ni_dllist_link_init(netif, &ts->epcache_link, sp, "epch");
    CI_DEBUG (ci_ni_dllist_mark_free (&ts->epcache_link));
  }
#endif

  ts->s.b.state = CI_TCP_CLOSED;
  ci_tcp_fast_path_disable(ts);

  ts->tcpflags = NI_OPTS(netif).syn_opts;

  ts->outgoing_hdrs_len = sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr);
  if( ts->tcpflags & CI_TCPT_FLAG_TSO )  ts->outgoing_hdrs_len += 12;
  ts->incoming_tcp_hdr_len = sizeof(ci_tcp_hdr);
  ts->c.tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;

  ci_tcp_state_connected_opts_init(netif, ts);

  /* Initialise packet header and flow control state. */
  TS_TCP(ts)->tcp_urg_ptr_be16 = 0;
  tcp_enq_nxt(ts) = tcp_snd_una(ts) = tcp_snd_nxt(ts) = tcp_snd_up(ts) = 0;
  ts->snd_max = tcp_snd_nxt(ts) + 1;
  /* ?? snd_nxt, snd_max, should be set as SYN is sent */
  /* WSCL option variables RFC1323 */
  ts->snd_wscl = 0;
  CI_IP_SOCK_STATS_VAL_TXWSCL( ts, ts->snd_wscl);
  ts->rcv_wscl = ci_tcp_wscl_by_buff(netif, tcp_rcv_buff(ts));
  CI_IP_SOCK_STATS_VAL_RXWSCL( ts, ts->rcv_wscl);

  /* receive window */
  tcp_rcv_wnd_right_edge_sent(ts) = tcp_rcv_wnd_advertised(ts) = 0;
  ts->rcv_added = ts->rcv_delivered = tcp_rcv_nxt(ts) = 0;
  tcp_rcv_up(ts) = SEQ_SUB(tcp_rcv_nxt(ts), 1);

  /* setup header length */
  CI_TCP_HDR_SET_LEN(TS_TCP(ts),
                     (ts->outgoing_hdrs_len - sizeof(ci_ip4_hdr)));
  TS_TCP(ts)->tcp_flags = 0u;


  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;
  ts->bytes_acked = 0;

#if CI_CFG_BURST_CONTROL
  /* Burst control */
  ts->burst_window = 0;
#endif

  /* congestion window validation RFC2861 */
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  ts->t_last_sent = ci_tcp_time_now(netif);
  ts->t_last_full = ci_tcp_time_now(netif);
  ts->cwnd_used = 0;
#endif
  ts->t_last_recv_ack = ts->t_last_recv_payload = ts->t_prev_recv_payload = 
    ci_tcp_time_now(netif);

  ts->eff_mss = 0;
  ts->amss = 0;
  ts->ssthresh = 0;

  /* PAWs RFC1323, connections always start idle */
  ts->tspaws = ci_tcp_time_now(netif) - (NI_CONF(netif).tconst_paws_idle+1);
  ts->tsrecent = 0;

  /* delayed acknowledgements */
  ts->acks_pending = 0;

  /* Faststart */
  CITP_TCP_FASTSTART(ts->faststart_acks = 0);

#if CI_CFG_TAIL_DROP_PROBE
  /* probing for dropped tails */
  ts->taildrop_state = CI_TCP_TAIL_DROP_INACTIVE;
#endif
  /* dupack threshold */
  ci_tcp_set_dupack_thresh(ts, 0);

  ts->zwin_probes = 0;
  ts->zwin_acks = 0;
  ts->ka_probes = 0;
  /* TCP_MAXSEG */
  ts->c.user_mss = 0;

  /* number of retransmissions */
  ts->retransmits = 0;

  /* TCP timers, RTO, SRTT, RTTVAR */
  ts->rto = NI_CONF(netif).tconst_rto_initial;
  ts->sa = 0; /* set to zero to provoke initialisation in ci_tcp_update_rtt */
  ts->sv = NI_CONF(netif).tconst_rto_initial; /* cwndrecover b4 rtt measured */

#if CI_CFG_TCP_SOCK_STATS
  ci_tcp_stats_init(netif, ts);
#endif
  tcp_urg_data(ts) = 0;

  memset(&ts->stats, 0, sizeof(ts->stats));
}


void ci_tcp_state_init(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(CI_PTR_OFFSET(&ts->s.pkt.ip, 4) == 0);
  LOG_TV(ci_log(LPF "%s(): %d", __FUNCTION__, S_FMT(ts)));

#if defined(TCP_STATE_POISON) && !defined(NDEBUG)
  {
    void *poison_start = &ts->s.b + 1;
    memset(poison_start, TCP_STATE_POISON,
           ((char*)(ts+1)) - (char*)poison_start);
  }
#endif

  /* Initialise the lower level. */
  ci_sock_cmn_init(netif, &ts->s);
  /* Initialise this level. */
  ci_tcp_state_tcb_init_fixed(netif, ts);
  ci_tcp_state_tcb_reinit(netif, ts);
}

void ci_tcp_state_reinit(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(CI_PTR_OFFSET(&ts->s.pkt.ip, 4) == 0);
  LOG_TV(ci_log(LPF "%s(): %d", __FUNCTION__, S_FMT(ts)));

  /* This functions leaves ts->s.addr_spc_id alone so that 
     the state can still be freed correctly. */

  /* Reinitialise the lower level. */
  ci_sock_cmn_reinit(netif, &ts->s);
  /* Reinitialise this level. */
  ci_tcp_state_tcb_reinit(netif, ts);
}


ci_tcp_state* ci_tcp_get_state_buf(ci_netif* netif)
{
  citp_waitable_obj* wo;

  ci_assert(netif);

  wo = citp_waitable_obj_alloc(netif);
  if( ! wo )  {
    LOG_TV(ci_log("%s: [%d] out of socket buffers",__FUNCTION__,NI_ID(netif)));
    return NULL;
  }

  ci_tcp_state_init(netif, &wo->tcp);
  return &wo->tcp;
}

/*! \cidoxg_end */
