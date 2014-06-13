/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  djr
**  \brief  TCP misc stuff.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <onload/sleep.h>


#define LPF "TCP MISC "

#define VERB(x)


enum {
  CI_LINUX_TCP_ESTABLISHED = 1,
  CI_LINUX_TCP_SYN_SENT,
  CI_LINUX_TCP_SYN_RECV,
  CI_LINUX_TCP_FIN_WAIT1,
  CI_LINUX_TCP_FIN_WAIT2,
  CI_LINUX_TCP_TIME_WAIT,
  CI_LINUX_TCP_CLOSE,
  CI_LINUX_TCP_CLOSE_WAIT,
  CI_LINUX_TCP_LAST_ACK,
  CI_LINUX_TCP_LISTEN,
  CI_LINUX_TCP_CLOSING,  /* now a valid state */
};


/* Mapping between socket states in L5 stack and Linux */
const unsigned char ci_sock_states_linux_map [] = {
  CI_LINUX_TCP_CLOSE,        /* CI_TCP_CLOSED */
  CI_LINUX_TCP_LISTEN,       /* CI_TCP_LISTEN */
  CI_LINUX_TCP_SYN_SENT,     /* CI_TCP_SYN_SENT */
  CI_LINUX_TCP_ESTABLISHED,  /* CI_TCP_ESTABLISHED */
  CI_LINUX_TCP_CLOSE_WAIT,   /* CI_TCP_CLOSE_WAIT */
  CI_LINUX_TCP_LAST_ACK,     /* CI_TCP_LAST_ACK */
  CI_LINUX_TCP_FIN_WAIT1,    /* CI_TCP_FIN_WAIT1 */
  CI_LINUX_TCP_FIN_WAIT2,    /* CI_TCP_FIN_WAIT2 */
  CI_LINUX_TCP_CLOSING,      /* CI_TCP_CLOSING */
  /* Linux does not have sockets in TIME-WAIT state; socket is CLOSED,
   * and timewait object is in TIME-WAIT. */
  CI_LINUX_TCP_CLOSE         /* CI_TCP_TIME_WAIT */
};


const char* type_str(int type)
{
  static const char* type_strs[] = {
    "<unknown>",              /* 0 */
    "SOCK_STREAM",            /* 1 */
    "SOCK_DGRAM",             /* 2 */
    "SOCK_RAW",               /* 3 */
    "SOCK_RDM",               /* 4 */
    "SOCK_SEQPACKET",         /* 5 */
    "<unknown>",              /* 6 */
    "<unknown>",              /* 7 */
    "<unknown>",              /* 8 */
    "<unknown>",              /* 9 */
    "SOCK_PACKET"             /* 10 */
  };

  if (type < 0 || type >= (sizeof (type_strs) / sizeof (type_strs[0])))
    return "<out of range>";

  return type_strs[type];
}

const char* domain_str(int domain)
{
  static const char* domain_strs[] = {
    "AF_UNSPEC",              /* 0 */
    "AF_UNIX/LOCAL",          /* 1 */
    "AF_INET",                /* 2 */
    "AF_AX25",                /* 3 */
    "AF_IPX",                 /* 4 */
    "AF_APPLETALK",           /* 5 */
    "AF_NETROM",              /* 6 */
    "AF_BRIDGE",              /* 7 */
    "AF_ATMPVC",              /* 8 */
    "AF_X25",                 /* 9 */
    "AF_INET6",               /* 10 */
    "AF_ROSE",                /* 11 */
    "AF_DECnet",              /* 12 */
    "AF_NETBEUI",             /* 13 */
    "AF_SECURITY",            /* 14 */
    "AF_KEY",                 /* 15 */
    "AF_NETLINK/ROUTE",       /* 16 */
    "AF_PACKET",              /* 17 */
    "AF_ASH",                   /* 18 */
    "AF_ECONET",              /* 19 */
    "AF_ATMSVC",              /* 20 */
    "<unknown>",              /* 21 */
    "AF_SNA",                   /* 22 */
    "AF_IRDA",                /* 23 */
    "AF_PPPOX",               /* 24 */
    "AF_WANPIPE",             /* 25 */
    "<unknown>",              /* 26 */
    "<unknown>",              /* 27 */
    "<unknown>",              /* 28 */
    "<unknown>",              /* 29 */
    "<unknown>",              /* 30 */
    "AF_BLUETOOTH",           /* 31 */
    "AF_MAX"                    /* 32 */
  };

  if (domain < 0 || domain >= (sizeof (domain_strs) / sizeof (domain_strs[0])))
    return "<out of range>";

  return domain_strs[domain];
}

const char* ip_addr_str(ci_uint32 addr_be32)
{
  static char buf[4][16];
  static int buf_i;
  int i = ++buf_i & 3;

  ci_format_ip4_addr(buf[i], addr_be32);
  return buf[i];
}


const char* ci_tcp_state_num_str(int state_i)
{
  static const char* state_strs[] = {
    "CLOSED",
    "LISTEN",
    "SYN-SENT",
    "ESTABLISHED",
    "CLOSE-WAIT",
    "LAST-ACK",
    "FIN-WAIT1",
    "FIN-WAIT2",
    "CLOSING",
    "TIME-WAIT",
    "FREE",
#if CI_CFG_UDP
    "UDP",
#endif
#if CI_CFG_USERSPACE_PIPE
    "PIPE",
#endif
  };

  if( state_i < 0 || state_i >= (sizeof(state_strs) / sizeof(state_strs[0])) )
    return "<invalid-TCP-state>";

  return state_strs[state_i];
}


const char* ci_tcp_congstate_str(unsigned s)
{
  switch( s ) {
  case CI_TCP_CONG_OPEN:        return "Open";
  case CI_TCP_CONG_RTO:         return "RTO";
  case CI_TCP_CONG_RTO_RECOV:   return "RTORecovery";
  case CI_TCP_CONG_FAST_RECOV:  return "FastRecovery";
  case CI_TCP_CONG_COOLING:     return "Cooling";
  case CI_TCP_CONG_NOTIFIED:    return "Notified";
  default:
    ci_log("BAD CONGESTION STATE %x", s);
    return "<invalid-congstate>";
  }
}

/* The actual innards of freeing a tcp state - called from one of
   ci_tcp_state_[free,free_now,free_now_nnl] below*/
static void ci_tcp_state_free_internal(ci_netif *ni, ci_tcp_state *ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));
  ci_assert(ni);
  ci_assert(ts);

  /* Disconnect local peer if any */
  if( OO_SP_NOT_NULL(ts->s.local_peer) ) {
    ci_sock_cmn* peer = ID_TO_SOCK_CMN(ni, ts->s.local_peer);
    if( peer->local_peer == S_SP(ts) )
      peer->local_peer = OO_SP_NULL;
  }

  /* Remove from any lists we're in. */
  ci_ni_dllist_remove_safe(ni, &ts->s.b.post_poll_link);
  ci_ni_dllist_remove(ni, &ts->s.reap_link);

  /* By the time we get here the send queues must be empty (otherwise it
  ** means we have a leak!).  Receive queues may have data due to
  ** asynchronous receive.
  */
  ci_assert(ci_tcp_sendq_is_empty(ts));
  ci_assert(ci_ip_queue_is_empty(&ts->rob));
  ci_assert(ci_ip_queue_is_empty(&ts->retrans));

  ci_ip_queue_drop(ni, &ts->recv1);
  ci_ip_queue_drop(ni, &ts->recv2);

#if CI_CFG_FD_CACHING
  ci_assert((ts->cached_on_fd != -1) || (ts->s.b.state == CI_TCP_CLOSED));
  ci_assert((ts->cached_on_fd != -1) ||
            (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  if (ts->cached_on_fd != -1) {
    /* This is a cached EP.  The only time we can be freeing a cached TCP
     * state is if the state is unaccepted, and the app is closing down.
     * (Otherwise we deal with cleaning all this from user level)
     */
    LOG_TC (log ("Warning: freeing a cached EP state!"));
    ci_tcp_ep_clear_filters(ni, S_SP(ts), 1);
  }
#endif

# define chk(x) ci_assert(!ci_ip_timer_pending(ni, &ts->x))
  chk(rto_tid);
  chk(delack_tid);
  chk(zwin_tid);
  chk(kalive_tid);
  chk(cork_tid);
  chk(s.pkt.pmtus.tid);
#if CI_CFG_TCP_SOCK_STATS
  chk(stats_tid);
#endif
#undef chk
}


/* This frees up the resources used by the tcp state, but if there are
   outstanding async ops on the netif it will delay clearing the
   address space and freeing the tcp state until they are complete.
   If no aops outstanding, it does that immediately */
void ci_tcp_state_free(ci_netif* ni, ci_tcp_state* ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));
  ci_assert(ci_netif_is_locked(ni));

  ci_tcp_state_free_internal(ni, ts);

  ci_tcp_state_free_now(ni, ts);
}


#ifdef __KERNEL__
/* Can call this without the netif lock.  Clears the address space and
   atomically puts the tcp state on the deferred_free_eps_head.
   Equivalent to ci_tcp_state_free_now().  You must have previously
   called ci_tcp_state_free()! */
void ci_tcp_state_free_now_nnl(ci_netif *ni, ci_tcp_state *ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));

  do
    ts->s.b.next_id = ni->state->deferred_free_eps_head;
  while( ci_cas32u_fail(&ni->state->deferred_free_eps_head,
                        ts->s.b.next_id, S_ID(ts)) );
}
#endif  /* __KERNEL__ */


/* Must have netif lock, clears the address space and puts the tcp
   state on the free_eps_head.  You must have previously called
   ci_tcp_state_free()! */
void ci_tcp_state_free_now(ci_netif* ni, ci_tcp_state* ts)
{
  VERB(ci_log("%s("NTS_FMT")", __FUNCTION__, NTS_PRI_ARGS(ni,ts)));
  ci_assert(ci_netif_is_locked(ni));

  citp_waitable_obj_free(ni, &ts->s.b);
}


/* care about established connections counters */
ci_inline void ci_tcp_estabs_handle(ci_netif *ni, ci_tcp_state *ts, int state)
{
#if CI_CFG_SUPPORT_STATS_COLLECTION
  /* On linux this counter only reflects the number of TCP connections for
  ** which the current state is ESTABLISHED.
  **
  ** ?? So on what platform(s) does it represent something else?
  */
  if( (ts->s.b.state == CI_TCP_ESTABLISHED
                                         ) )
    CI_TCP_STATS_DEC_CURR_ESTAB(ni);

  if ((state == CI_TCP_CLOSED) &&
      ((ts->s.b.state == CI_TCP_ESTABLISHED) ||
       (ts->s.b.state == CI_TCP_CLOSE_WAIT)))
    CI_TCP_STATS_INC_ESTAB_RESETS( ni );
#endif
}


void ci_tcp_set_established_state(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts);

  ts->s.b.state = CI_TCP_ESTABLISHED;
  CI_TCP_STATS_INC_CURR_ESTAB( ni );

  ts->s.tx_errno = 0;
  ts->s.rx_errno = 0;
  ts->tcpflags |= CI_TCPT_FLAG_WAS_ESTAB;

  /* ?? HACK: Reset window sizes to a suitable value (if app hasn't already
  ** modified them).  The defaults are too small, but we need to stick with
  ** them at socket creation time because some apps (e.g. netperf) modify
  ** their behaviour depending on what they see in SO_SNDBUF and SO_RCVBUF.
  ** TODO: If would be more elegant to grow them dynamically as needed.
  */
  if( NI_OPTS(ni).tcp_sndbuf_user != 0 ) {
    ts->s.so.sndbuf = oo_adjust_SO_XBUF(NI_OPTS(ni).tcp_sndbuf_user);
    ci_tcp_set_sndbuf(ts);
  }
  else if( ! (ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF) ) {
    ts->s.so.sndbuf = 128 * 1024;
    ci_tcp_set_sndbuf(ts);
  }
  if( NI_OPTS(ni).tcp_rcvbuf_user != 0 )
    ts->s.so.rcvbuf = oo_adjust_SO_XBUF(NI_OPTS(ni).tcp_rcvbuf_user);
  else if( ! (ts->s.s_flags & CI_SOCK_FLAG_SET_RCVBUF) )
    ts->s.so.rcvbuf = 128 * 1024;

  /* Make RCVBUF a multiple of MSS, as recommended by RFC1191 sec 6.4. */
  ts->s.so.rcvbuf -= ts->s.so.rcvbuf % ts->amss;


#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE ) {
    ts->dup_thresh = NI_OPTS(ni).stripe_dupack_threshold;
    LOG_TC(ci_log(NT_FMT "striping on (l=%x r=%x m=%x)", NT_PRI_ARGS(ni, ts),
                  tcp_laddr_be32(ts), tcp_raddr_be32(ts),
                  NI_OPTS(ni).stripe_netmask_be32));
  }
#endif

  CITP_TCP_FASTSTART(ts->faststart_acks = NI_OPTS(ni).tcp_faststart_init);
  /* dirty hack to abuse this, init for faststart */
  CITP_TCP_FASTSTART(ts->tslastack = tcp_rcv_nxt(ts));

#if CI_CFG_TAIL_DROP_PROBE
  if(NI_OPTS(ni).tail_drop_probe)
    ts->taildrop_state = CI_TCP_TAIL_DROP_ACTIVE;
#endif

  if( ci_tcp_can_use_fast_path(ts) )
    ci_tcp_fast_path_enable(ts);
}


void ci_tcp_set_slow_state(ci_netif *ni, ci_tcp_state* ts, int state)
{
  ci_assert(ts);
  ci_assert(state & CI_TCP_STATE_SLOW_PATH);

#ifndef NDEBUG
  /* temporary checks to try and track down a set of possibly related
     bugs: 557, 908, 936 & 940 */
  if(ts->s.b.state != CI_TCP_LISTEN){
    if(!(state & CI_TCP_STATE_TXQ_ACTIVE)){
      ci_assert(ci_tcp_sendq_is_empty(ts));
      ci_assert(ci_ip_queue_is_empty(&ts->retrans));
    }
    if(state & CI_TCP_STATE_NO_TIMERS){
# define chk_timer(x)   ci_assert(!ci_ip_timer_pending(ni, &ts->x))
      chk_timer(rto_tid);
      chk_timer(delack_tid);
      chk_timer(zwin_tid);
      chk_timer(kalive_tid);
      chk_timer(cork_tid);
      chk_timer(s.pkt.pmtus.tid);
#if CI_CFG_TCP_SOCK_STATS
      chk_timer(stats_tid);
#endif
#undef chk_timer
    }
  }

  /* to try and track down Bug 1427 and similar we check that errno
     has been set when moving the state to closed */
  if (CI_TCP_CLOSED == state) {
    ci_assert(ts->s.rx_errno != 0);
    ci_assert(ts->s.tx_errno != 0);
  }

  if(ts->s.b.state == CI_TCP_TIME_WAIT){
    /* basic sanity */
    ci_assert(state != CI_TCP_TIME_WAIT);
    /* make sure it's not still in the list */
    ci_assert(ci_ni_dllist_is_free(&ts->timeout_q_link));
  }
#endif

  ci_tcp_estabs_handle(ni, ts, state);

  ts->s.b.state = state;
  ci_tcp_fast_path_disable(ts);
}


int ci_tcp_parse_options(ci_netif* ni, ciip_tcp_rx_pkt* rxp,
                         ci_tcp_options* topts)
{
  /* Parse TCP header options.
  **
  ** We can come through here 0, 1 or 2 times per packet.  0 if we see a
  ** case that we handle inline in tcp_rx.c.  Otherwise once, unless its a
  ** SYN segment, in which case we call this a second time to get the SYN
  ** options.  In this case [topts] will be non-null.
  */
  ci_tcp_hdr* tcp;
  ci_uint8* opt;
  int i, bytes;

  ci_assert(rxp);
  ci_assert(rxp->pkt);
  ci_assert(rxp->tcp);
  ci_assert(rxp->tcp == PKT_TCP_HDR(rxp->pkt));

  tcp = rxp->tcp;
  opt = CI_TCP_HDR_OPTS(tcp);
  bytes = CI_TCP_HDR_OPT_LEN(tcp);
  rxp->flags = 0;

  LOG_TV(log(LPF "parsing options packet %d, optlen %d",
             OO_PKT_FMT(rxp->pkt), bytes));

  /* parse valid TCP options */
  while( bytes > 0 ) {
    switch(opt[0]) {
    case CI_TCP_OPT_TIMESTAMP:
      if( bytes < 10 ) {
        LOG_U(log(LPF "TSopt(truncated)"));
        goto fail_out;
      }
      if( opt[1] != 0xa ) {
        LOG_U(log(LPF "TSopt(bad length %d)", (int) opt[1]));
        goto fail_out;
      }
      rxp->flags |= CI_TCPT_FLAG_TSO;
      if( topts == NULL ) {  /* must only byte-swap first time through */
	rxp->timestamp = CI_BSWAP_BE32(*(ci_uint32*) &opt[2]);
	rxp->timestamp_echo = CI_BSWAP_BE32(*(ci_uint32*) &opt[6]);
      }
      opt += 10; bytes -= 10;
      break;
    case CI_TCP_OPT_SACK:
      if( bytes < 10 || bytes < opt[1] ) {
        LOG_U(log(LPF "SACK(truncated)"));
        goto fail_out;
      }
      if( opt[1] < 2 + 8 || (opt[1] & 7) != 2 ) {
        LOG_U(log(LPF "SACK(bad length %d)", (int) opt[1]));
        goto fail_out;
      }
      if( topts == NULL ) {
        rxp->flags |= CI_TCPT_FLAG_SACK;
        rxp->sack_blocks = (int)(opt[1] >> 3u);
        for( i = 0; i < 2 * rxp->sack_blocks; i++ )
          rxp->sack[i] = CI_BSWAP_BE32(*(ci_uint32*) &opt[2 + i * 4]);
      }
      bytes -= opt[1]; opt += opt[1];
      break;
    case CI_TCP_OPT_END:
      goto out;
    case CI_TCP_OPT_NOP:
      ++opt; --bytes;
      break;
    case CI_TCP_OPT_MSS:
      if( bytes < 4 ) {
        LOG_U(log(LPF "MSS(truncated)"));
        goto fail_out;
      }
      if( opt[1] != 0x4 ) {
        LOG_U(log(LPF "MSS(bad length %d)", (int) opt[1]));
        goto fail_out;
      }
      if( topts )  topts->smss = CI_BSWAP_BE16(*(ci_uint16*)(opt + 2));
      opt += 4; bytes -= 4;
      break;
    case CI_TCP_OPT_WINSCALE:
      if( bytes < 3 ) {
        LOG_U(log(LPF "WSopt(truncated)"));
        goto fail_out;
      }
      if( opt[1] != 0x3 ) {
        LOG_U(log(LPF "WSopt(bad length %d)", (int) opt[1]));
        goto fail_out;
      }
      if ( opt[2] > CI_TCP_WSCL_MAX ) {
        /* RFC1323 check and silently truncate the WSCL option */
        LOG_U(log( LPF "WSCL_SHFT of %u larger than %d, truncating",
                   CI_TCP_WSCL_MAX, opt[2]));
        opt[2] = CI_TCP_WSCL_MAX;
      }
      if( topts ) {
        topts->flags |= CI_TCPT_FLAG_WSCL;
        topts->wscl_shft = opt[2];
      }
      opt += 3; bytes -= 3;
      break;
    case CI_TCP_OPT_SACK_PERM:
      if( bytes < 2 ) {
        LOG_U(log(LPF "SACKperm(truncated)"));
        goto fail_out;
      }
      if( opt[1] != 0x2 ) {
        LOG_U(log(LPF "SACKperm(bad length %d)", (int) opt[1]));
        goto fail_out;
      }
      if( topts )  topts->flags |= CI_TCPT_FLAG_SACK;
      opt += 2; bytes -= 2;
      break;
    default:
#if CI_CFG_PORT_STRIPING
      if( opt[0] == NI_OPTS(ni).stripe_tcp_opt ) {
        if( bytes < 2 ) {
          LOG_U(log(LPF "STRIPE(truncated)"));
          goto fail_out;
        }
        if( opt[1] != 0x2 ) {
          LOG_U(log(LPF "STRIPE(bad length %d)", (int) opt[1]));
          goto fail_out;
        }
        if( topts )  topts->flags |= CI_TCPT_FLAG_STRIPE;
        opt += 2; bytes -= 2;
        break;
      }
#endif

      /*
      ** RFC 1122 "(all TCP options defined in the future will have
      **      length fields)"
      */
      if( bytes < 2 || bytes < opt[1] ) {
        LOG_U(log(LPF "truncated options"));
        goto fail_out;
      }
      if( (int) opt[1] < 2 ) {
        LOG_U(log(LPF "unknown/invalid TCP option %x length %d [ILLEGAL]",
                  (unsigned) opt[0], (int) opt[1]));
        goto fail_out;
      } else {
        LOG_U(log(LPF "unknown/invalid TCP option %x length %d",
                  (unsigned) opt[0], (int) opt[1]));
        bytes -= opt[1]; opt += opt[1];
      }
      break;
    }
  }

 out:
  return 0;
 fail_out:
  LOG_U(log(LPF "failed to process (some) TCP option(s)"));
  return -1;
}


/* ci_ip_timer_clear() actually expands to a surprisingly large amount of code
 * and uses quite a lot of stack, and gcc stupidly allocates that amount of
 * stack for *each* call in ci_tcp_stop_timers(), which adds up to far too much
 * when running in a kernel with 4K stacks.  So here's an out-of-lined version
 * of it for ci_tcp_stop_timers() to use -- saves nearly 1/2 K of stack!
 */
static void ci_ip_timer_clear_ool(ci_netif* netif, ci_ip_timer* tmr)
{
  ci_ip_timer_clear(netif, tmr);
}

void ci_tcp_stop_timers(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_timer_clear_ool(netif, &ts->rto_tid);
  ci_ip_timer_clear_ool(netif, &ts->delack_tid);
  ci_ip_timer_clear_ool(netif, &ts->zwin_tid);
  ci_ip_timer_clear_ool(netif, &ts->kalive_tid);
  ci_ip_timer_clear_ool(netif, &ts->cork_tid);
  ci_ip_timer_clear_ool(netif, &ts->s.pkt.pmtus.tid);
#if CI_CFG_TCP_SOCK_STATS
  ci_ip_timer_clear_ool(netif, &ts->stats_tid);
#endif
#if CI_CFG_TAIL_DROP_PROBE
  if(NI_OPTS(netif).tail_drop_probe)
    ci_ip_timer_clear_ool(netif, &ts->taildrop_tid);
#endif
}


/*
** Drop anything on an IP queue
*/
void ci_ip_queue_drop(ci_netif* netif, ci_ip_pkt_queue *qu)
{
  ci_ip_pkt_fmt* p;
  CI_DEBUG(int i = qu->num);

  ci_assert(netif);
  ci_assert(qu);
  ci_assert(ci_ip_queue_is_valid(netif, qu));

  while( OO_PP_NOT_NULL(qu->head)   CI_DEBUG( && i-- > 0) ) {
    p = PKT_CHK(netif, qu->head);
    qu->head = p->next;
    ci_netif_pkt_release(netif, p);
  }
  ci_assert_equal(i, 0);
  ci_assert(OO_PP_IS_NULL(qu->head));
  qu->num = 0;
}


static void ci_tcp_tx_drop_queues(ci_netif* ni, ci_tcp_state* ts)
{
  ci_tcp_retrans_drop(ni, ts);
  ci_tcp_sendq_drop(ni, ts);

  /* Maintain invarients. */
  tcp_snd_nxt(ts) = tcp_enq_nxt(ts) = tcp_snd_una(ts);
  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;
}


static void ci_tcp_drop_cached(ci_netif* ni, ci_tcp_state* ts,
                               unsigned laddr, unsigned lport)
{
#if CI_CFG_FD_CACHING
  /* We're caching this state.  Put it on the cache pool, as opposed to
   * freeing it (note we didn't call ci_tcp_state_free above)
   */
  int rc;

  ci_assert (laddr);
  ci_assert (lport);

  rc = ci_netif_filter_lookup(ni, laddr, lport, 0, 0, tcp_protocol(ts));
  if (rc >= 0) {
    ci_tcp_socket_listen* tlo =
      SP_TO_TCP_LISTEN(ni, CI_NETIF_FILTER_ID_TO_SOCK_ID(ni, rc));
    
    ci_assert(tlo->s.b.state == CI_TCP_LISTEN);

    /* Pop off the pending list, push on the cached list. Means that next
     * time a SYNACK is received, try_promote will reuse this cached item,
     * rather than allocating a new TCP state
     */
#if CI_CFG_DETAILED_CHECKS
    {
      /* Check that this TS is really on the pending list */
      ci_ni_dllist_link *link = ci_ni_dllist_start (ni, &tlo->epcache_pending);
      while (link != ci_ni_dllist_end (ni, &tlo->epcache_pending)) {
        if (ts == CI_CONTAINER (ci_tcp_state, epcache_link, link))
          break;
        ci_ni_dllist_iter(ni, link);
      }
      ci_assert (link != ci_ni_dllist_end(ni, &tlo->epcache_pending));
    }
#endif
    /* Switch lists */
    LOG_EP (ci_log ("Cached fd %d from pending to cached", ts->cached_on_fd));
    ci_assert(!ci_ni_dllist_is_free(&ts->epcache_link));
    ci_ni_dllist_remove(ni, &ts->epcache_link);
    ci_ni_dllist_push(ni, &tlo->epcache_cache, &ts->epcache_link);
  }
  else {
    /* We don't expect this to happen -- assert fail in debug builds.
     * In release builds, let's do our best to cope
     */
    LOG_U (log ("No listening socket; cannot cache EP for fd %d",
                ts->cached_on_fd));
    ci_assert (0);
    ts->cached_on_fd = -1;
  }
#endif
}


/*
** Drop a connection to CLOSED, flush buffers and set error code as given.
** After calling this [ts] may have been freed, so you must not touch it
** again.  The only exception is if you know that it is not orphaned.
*/
void ci_tcp_drop(ci_netif* netif, ci_tcp_state* ts, int so_error)
{
  unsigned laddr = 0, lport = 0, raddr, rport, protocol;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ts);

  LOG_TC(log(LPF "%d TCP_DROP %s->CLOSED so_error=%d%s%s",
             S_FMT(ts), ci_tcp_state_str(ts->s.b.state), so_error,
             (ts->s.b.sb_aflags&CI_SB_AFLAG_ORPHAN) ? " orphan":"",
             (ts->s.b.sb_aflags&CI_SB_AFLAG_TCP_IN_ACCEPTQ) ? " acceptq":""));
  if( so_error != 0 )
    ts->s.so_error = so_error;

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    /* This will happen to connections which get established, but
       left on the accept queue, and then RST. See bug 3189 */
    LOG_TC(log(LPF "%d TCP drop but already CLOSED", S_FMT(ts)));
    if( ts->s.b.sb_aflags&CI_SB_AFLAG_ORPHAN && 
        ! (ts->s.b.sb_aflags&CI_SB_AFLAG_TCP_IN_ACCEPTQ) )
      ci_tcp_state_free(netif, ts);
    return;
  }
  else {
    ci_assert(ts->s.b.state != CI_TCP_LISTEN);

    /* remove TIME_WAIT/FIN_WAIT2 connections from timeout queue */
    if ( (ts->s.b.state == CI_TCP_TIME_WAIT) || ci_tcp_is_timeout_ophan(ts) ) {
      ci_netif_timeout_remove(netif, ts);
    }

    ci_ni_dllist_remove_safe(netif, &ts->tx_ready_link);
    ci_tcp_tx_drop_queues(netif, ts);
    ci_ip_queue_drop(netif, &ts->rob);

    ts->s.tx_errno = EPIPE;
    ts->s.rx_errno = CI_SHUT_RD;
    ci_tcp_stop_timers(netif, ts);
    ts->acks_pending = 0;

    /* clear out filters that this endpoint is using.  If we're caching
     * the EP and it's not on the accept queue, then we only clear the
     * s/w filters; otherwise we clear the h/w filter as well
     * (Note we want to clear filters for cached EPs on the accept queue,
     * because this means they come off the accept queue in the CLOSED state,
     * and as such they are assumed by various parts of the code not to have
     * filters set.   This is Bug #1359)
     */
    if( ! ci_tcp_is_cached(ts) ||
        (ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ) ) {
      ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
    }
    else {
      laddr = tcp_laddr_be32(ts);
      lport = tcp_lport_be16(ts);
      raddr = tcp_raddr_be32(ts);
      rport = tcp_rport_be16(ts);
      protocol = tcp_protocol(ts);
      ci_netif_filter_remove(netif, S_SP(ts), laddr, lport,
                             raddr, rport, protocol);
    }

    if (ts->s.b.state == CI_TCP_SYN_SENT) {
      ts->retransmits = 0;
      ts->tcpflags &= ~CI_TCPT_FLAG_NO_ARP;
    }
    ci_tcp_set_slow_state(netif, ts, CI_TCP_CLOSED);
  }

  if( ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ ) {
    /* We don't free unaccepted states -- they stay on the acceptq */
  }
  else {
    /* This TCP state has been accepted */
    if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) {
      ci_tcp_state_free(netif, ts);
      return;
    }
    else {
      ci_tcp_wake_possibly_not_in_poll(netif, ts,
                                       CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX);
    }

    if( ci_tcp_is_cached(ts) )
      ci_tcp_drop_cached(netif, ts, laddr, lport);
  }
}

/*!
 * Calculate Window Scale to be advertised in accordance with Rx buffer size.
 *
 * \todo May be it's better to keep better precision and use less window
 *       scale.
 */
unsigned int ci_tcp_wscl_by_buff(ci_netif *netif, int rcv_buff)
{
  unsigned int wscl;

  ci_assert(rcv_buff > 0);
  for( wscl = 0;
       (wscl < NI_OPTS(netif).tcp_adv_win_scale_max) &&
         ((unsigned)(CI_CFG_TCP_MAX_WINDOW << wscl) < (unsigned int)rcv_buff);
       ++wscl );

  return wscl;
}


void ci_tcp_clear_sacks(ci_netif* ni, ci_tcp_state* ts)
{
  /* Clear all SACK marks (and associated pointers) in retransmit queue. */

  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p id = rtq->head;

  while( OO_PP_NOT_NULL(id) ) {
    pkt = PKT_CHK(ni, id);
    pkt->pf.tcp_tx.block_end = OO_PP_NULL;
    pkt->flags &=~ (CI_PKT_FLAG_RTQ_RETRANS | CI_PKT_FLAG_RTQ_SACKED);
    id = pkt->next;
  }

  ts->retrans_seq = tcp_snd_una(ts);
  ts->retrans_ptr = rtq->head;
}


void ci_tcp_retrans_init_ptrs(ci_netif* ni, ci_tcp_state* ts,
                              unsigned* recover_seq_out)
{
  /* Clear the RETRANS flag on unSACKed packets. */

  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* pkt;

  ci_assert(!ci_ip_queue_is_empty(rtq));
  pkt = PKT_CHK(ni, rtq->head);
  ts->retrans_ptr = rtq->head;
  ts->retrans_seq = pkt->pf.tcp_tx.start_seq;

  while( 1 ) {
    if( pkt->flags & CI_PKT_FLAG_RTQ_SACKED ) {
      /* Skip the SACK block. */
      *recover_seq_out = pkt->pf.tcp_tx.start_seq;
      pkt = PKT_CHK(ni, pkt->pf.tcp_tx.block_end);
    }
    else
      pkt->flags &=~ CI_PKT_FLAG_RTQ_RETRANS;

    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, pkt->next);
  }
}


void ci_tcp_get_fack(ci_netif* ni, ci_tcp_state* ts,
                     unsigned* fack_out, int* retrans_data_out)
{
  /* Determines the forward ACK and calculates the number of bytes of
  ** retransmission we've done since starting.
  **
  ** The forward ACK is the highest sequence number our peer has
  ** acknowledged using SACK info.
  */
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* block;
  ci_ip_pkt_fmt* end;
  int retrans_data = 0;
  unsigned fack;

  ci_assert(! ci_ip_queue_is_empty(rtq));

  block = PKT_CHK(ni, rtq->head);
  fack = tcp_snd_una(ts);

  while( 1 ) {
    if( OO_PP_IS_NULL(block->pf.tcp_tx.block_end) ) {
      /* We're in the last (unsacked) block. */
      ci_assert(~block->flags & CI_PKT_FLAG_RTQ_SACKED);
      ci_assert(SEQ_LE(block->pf.tcp_tx.start_seq, fack));
      if( SEQ_LT(fack, ts->retrans_seq) )
        retrans_data += SEQ_SUB(ts->retrans_seq, fack);
      break;
    }
    end = PKT_CHK(ni, block->pf.tcp_tx.block_end);

    if( block->flags & CI_PKT_FLAG_RTQ_SACKED )
      fack = end->pf.tcp_tx.end_seq;
    else if( SEQ_LT(block->pf.tcp_tx.start_seq, ts->retrans_seq) ) {
      /* At least some of this block has been retransmitted. */
      if( SEQ_LE(end->pf.tcp_tx.end_seq, ts->retrans_seq) )
        /* This whole block has been retransmitted. */
        retrans_data += SEQ_SUB(end->pf.tcp_tx.end_seq,
                                block->pf.tcp_tx.start_seq);
      else
        retrans_data += SEQ_SUB(ts->retrans_seq, block->pf.tcp_tx.start_seq);
    }

    if( OO_PP_IS_NULL(end->next) )  break;
    block = PKT_CHK(ni, end->next);
  }

  *fack_out = fack;
  *retrans_data_out = retrans_data;
}


void ci_tcp_recovered(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts->congstate != CI_TCP_CONG_OPEN &&
            ts->congstate != CI_TCP_CONG_NOTIFIED);

  if( ts->congstate == CI_TCP_CONG_FAST_RECOV ) {
    if( !(ts->tcpflags & CI_TCPT_FLAG_SACK) )
      /* RFC2581 says set cwnd to ssthresh on exit from fast recovery.
      ** NewReno (RFC2582) says min(ssthresh, FlightSize+MSS) or ssthresh.
      ** So I guess we could use either.
      ** chosen as the more aggresive and to allow ANVL tcp-advanced/4.17 to pass
      */
      ts->cwnd = CI_MAX(ts->ssthresh, NI_OPTS(ni).loss_min_cwnd);
  }
  else if( ts->congstate == CI_TCP_CONG_RTO_RECOV ) {
    if( ts->dup_acks >= ts->dup_thresh ) {
      ci_tcp_enter_fast_recovery(ni, ts);
      return;
    }
  }

  ts->congstate = CI_TCP_CONG_OPEN;
  ts->cwnd_extra = 0;
  ts->dup_acks = 0;

  LOG_TL(log(LNT_FMT "RECOVERED "TCP_SND_FMT" cwnd=%d ssthresh=%d rto=%d",
             LNT_PRI_ARGS(ni, ts), TCP_SND_PRI_ARG(ts),
             ts->cwnd, ts->ssthresh, ts->rto));

  ci_assert(ts->cwnd >= tcp_eff_mss(ts));
}


static int ci_tcp_rx_pkt_coalesce(ci_netif* ni, ci_ip_pkt_queue* q,
                                  ci_ip_pkt_fmt* pkt
                                  CI_DEBUG_ARG(ci_tcp_state* ts))
{
  /* Coalesces [pkt] with the one that follows it.  Requires that there is
  ** a packet that follows it.  Also requires that the sock-lock be held,
  ** and that ts->recv1_extract cannot point at the packet following the
  ** one given.
  **
  ** Returns true if there is further space available in [pkt].
  */
  ci_tcp_hdr* pkt_tcp = PKT_TCP_HDR(pkt);
  char* pkt_payload = CI_TCP_PAYLOAD(pkt_tcp);
  oo_offbuf* pkt_buf = &pkt->buf;
  char* pkt_buf_end = (char*) pkt + CI_CFG_PKT_BUF_SIZE;

  ci_assert(oo_offbuf_ptr(pkt_buf) >= pkt_payload);
  PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt);

  /* Move contents of packet to the beginning of the buffer. */
  if( oo_offbuf_ptr(pkt_buf) != pkt_payload ) {
    int n = (int)(oo_offbuf_ptr(pkt_buf) - pkt_payload);
    memmove(pkt_payload, oo_offbuf_ptr(pkt_buf), oo_offbuf_left(pkt_buf));
    pkt_buf->off -= n;
    pkt_buf->end -= n;
    pkt_tcp->tcp_seq_be32 = CI_BSWAP_BE32(
                                CI_BSWAP_BE32(pkt_tcp->tcp_seq_be32) + n);
  }

  { /* Move data from next buffer into remaining space in this buffer. */
    ci_ip_pkt_fmt* next = PKT_CHK(ni, pkt->next);
    oo_offbuf* next_buf = &next->buf;
    int n, space = (int)(pkt_buf_end - oo_offbuf_end(pkt_buf));

    if( next->refcount != 1 || space == 0 )
      return 0;

    n = oo_offbuf_left(next_buf);
    n = CI_MIN(space, n);
    memcpy(oo_offbuf_end(pkt_buf), oo_offbuf_ptr(next_buf), n);

    pkt_buf->end += n;
    pkt->pf.tcp_rx.end_seq += n;
    oo_offbuf_advance(next_buf, n);

    if( oo_offbuf_is_empty(next_buf) ) {
      pkt->next = next->next;
      if( OO_PP_IS_NULL(pkt->next) ) {
        ci_assert(OO_PP_EQ(q->tail, OO_PKT_P(next)));
        q->tail = OO_PKT_P(pkt);
      }
      ci_assert( ! OO_PP_EQ(ts->recv1_extract, OO_PKT_P(next)) );
      ci_netif_pkt_release_rx_1ref(ni, next);
      --q->num;
    }

    PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt);
    PKT_TCP_RX_BUF_ASSERT_VALID(ni, next);

    /* Return the amount of space left in [pkt]. */
    return (int)(pkt_buf_end - oo_offbuf_end(pkt_buf));
  }
}


static void ci_tcp_rx_coalesce_recv(ci_netif* ni, ci_tcp_state* ts,
                                    ci_ip_pkt_queue* q)
{
  ci_ip_pkt_fmt* pkt;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ci_sock_is_locked(ni, &ts->s.b));

  pkt = PKT_CHK(ni, q->head);
  if( pkt->refcount != 1 )
    return;

  for( ; OO_PP_NOT_NULL(pkt->next); pkt = PKT_CHK(ni, pkt->next) ) {

    while( OO_PP_NOT_NULL(pkt->next) )
      if( ! ci_tcp_rx_pkt_coalesce(ni, q, pkt CI_DEBUG_ARG(ts)) )
        break;
  }
}


void ci_tcp_drop_rob(ci_netif* ni, ci_tcp_state* ts)
{
  int i;
  ci_ip_queue_drop(ni, &ts->rob);
  for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; ++i )
    ts->last_sack[i] = OO_PP_NULL;
  ts->dsack_block = OO_PP_INVALID;
}


void ci_tcp_try_to_free_pkts(ci_netif* ni, ci_tcp_state* ts,
                             int desperation)
{
  ci_assert(ts->s.b.state & CI_TCP_STATE_TCP_CONN);

  switch( desperation ) {
  case 0:
    ci_tcp_rx_reap_rxq_bufs(ni, ts);
    break;
  case 1:
    if( ! ci_sock_trylock(ni, &ts->s.b) )  break;
    { ci_ip_pkt_queue* recv1 = &ts->recv1;
      if( ! OO_PP_EQ(recv1->head, ts->recv1_extract) )
        ci_tcp_rx_reap_rxq_bufs(ni, ts);
      ci_assert(OO_PP_EQ(recv1->head, ts->recv1_extract));
      if( OO_PP_NOT_NULL(ts->recv1_extract) ) {
        ci_ip_pkt_fmt* pkt = PKT_CHK(ni, ts->recv1_extract);
        if( oo_offbuf_is_empty(&pkt->buf) ) {
          ts->recv1_extract = recv1->head = pkt->next;
          ci_netif_pkt_release_rx_1ref(ni, pkt);
          --recv1->num;
        }
      }
      ci_tcp_rx_coalesce_recv(ni, ts, &ts->recv1);
      ci_tcp_rx_coalesce_recv(ni, ts, &ts->recv2);
      ci_sock_unlock(ni, &ts->s.b);
      break;
    }
  case 2:
    ci_tcp_drop_rob(ni, ts);
    break;
  default:
    break;
  }

  /* ?? TODO: could also coalesce the retrans queue. */
}



#if CI_CFG_LIMIT_AMSS || CI_CFG_LIMIT_SMSS
#include <ci/driver/efab/hardware.h>
int ci_tcp_limit_mss(int mss, ci_netif_state* ni_state, const char* caller)
{
  int max_mss = FALCON_RX_USR_BUF_SIZE - ETH_HLEN - ETH_VLAN_HLEN
    - sizeof(ci_tcp_hdr) - sizeof(ci_tcp_hdr)
#if CI_CFG_RSS_HASH
    - 16
#endif
    ;
  if( mss > max_mss ) {
#if CI_CFG_STATS_NETIF
    if (1 == ++ni_state->stats.mss_limitations) {
        ci_log("%s: (%s) limiting mss %d => %d", __FUNCTION__, caller,
               mss, max_mss);
    }
#else
    (void)ni_state;
    ci_log("%s: (%s) limiting mss %d => %d", __FUNCTION__, caller,
           mss, max_mss);
#endif
    mss = max_mss;
  }
  return mss;
}
#endif

void ci_tcp_perform_deferred_socket_work(ci_netif* ni, ci_tcp_state* ts)
{
  /* There are configurations where connection can be closed here. */
  ci_assert((ts->s.b.state & CI_TCP_STATE_TCP)
            && (ts->s.b.state != CI_TCP_LISTEN));

  ci_tcp_sendmsg_enqueue_prequeue_deferred(ni, ts);
  if( ts->s.s_aflags & CI_SOCK_AFLAG_NEED_ACK ) {
    ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NEED_ACK_BIT);
    ci_tcp_send_wnd_update(ni, ts);
  }
}

/*! \cidoxg_end */
