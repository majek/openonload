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
**  \brief  TCP socket option control; getsockopt, setsockopt
**   \date  2004/01/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_stats.h>
#include <ci/net/sockopts.h>

#if !defined(__KERNEL__)
#  include <netinet/tcp.h>
#else
#  include <linux/tcp.h>
#endif


#define LPF "TCP SOCKOPTS "

/* Mapping for congestion states */
static const unsigned char sock_congstate_linux_map[] = {
  CI_TCPF_CA_Open,                        /* CI_TCP_CONG_OPEN */
  CI_TCPF_CA_Loss,                        /* CI_TCP_CONG_RTO */
  CI_TCPF_CA_Recovery,                    /* CI_TCP_CONG_FRECOVER */
  CI_TCPF_CA_Loss,                        /* CI_TCP_CONG_ECN */
  CI_TCPF_CA_Recovery | CI_TCPF_CA_Loss   /* CI_TCP_CONG_RTO_RECOVER */
};


static int
ci_tcp_info_get(ci_netif* netif, ci_sock_cmn* s, struct ci_tcp_info* info)
{
  ci_iptime_t now = ci_ip_time_now(netif);

  memset(info, 0, sizeof(*info));

  info->tcpi_state = ci_sock_states_linux_map[CI_TCP_STATE_NUM(s->b.state)];
  /* info->tcpi_backoff = 0; */

  info->tcpi_ato = 
    ci_ip_time_ticks2ms(netif, netif->state->conf.tconst_delack) * 1000;
  info->tcpi_rcv_mss    = 536; /* no way to get the actual value */
  /* info->tcpi_sacked     = 0; */ /* there is no way to get any of these */
  /* info->tcpi_lost       = 0; */
  /* info->tcpi_fackets    = 0; */
  /* info->tcpi_reordering = 0; */
  /* info->tcpi_last_ack_sent = 0; */
  /* info->tcpi_last_ack_recv = 0; */
  if( cicp_ip_cache_is_valid(CICP_HANDLE(netif), &s->pkt) )
    info->tcpi_pmtu       = s->pkt.pmtus.pmtu;

  if( s->b.state != CI_TCP_LISTEN ) {
    ci_tcp_state* ts = SOCK_TO_TCP(s);

    info->tcpi_ca_state = sock_congstate_linux_map[ts->congstate];
    info->tcpi_retransmits = ts->retransmits;
    info->tcpi_probes = ts->ka_probes;

    /* info->tcpi_options = 0; */
    if( ts->tcpflags & CI_TCPT_FLAG_TSO )
      info->tcpi_options |= CI_TCPI_OPT_TIMESTAMPS;
    if( ts->tcpflags & CI_TCPT_FLAG_ECN )
      info->tcpi_options |= CI_TCPI_OPT_ECN;
    if( ts->tcpflags & CI_TCPT_FLAG_SACK )
      info->tcpi_options |= CI_TCPI_OPT_SACK;

    if( ts->tcpflags & CI_TCPT_FLAG_WSCL ) {
      info->tcpi_options |= CI_TCPI_OPT_WSCALE;
      info->tcpi_snd_wscale = ts->snd_wscl;
      info->tcpi_rcv_wscale = ts->rcv_wscl;
    }

    info->tcpi_rto = ci_ip_time_ticks2ms(netif, ts->rto) * 1000;
    info->tcpi_snd_mss    = ts->eff_mss;
    info->tcpi_unacked    = ts->acks_pending & CI_TCP_ACKS_PENDING_MASK;
#if CI_CFG_TCP_SOCK_STATS
    info->tcpi_retrans    = ts->stats_cumulative.count.tx_retrans_pkt;
#endif
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
    info->tcpi_last_data_sent = ci_ip_time_ticks2ms(netif,
						    now - ts->t_last_sent);
#else
    info->tcpi_last_data_sent = 0;
#endif
    info->tcpi_last_data_recv = ci_ip_time_ticks2ms(netif,
						    now - ts->tspaws);
    
    info->tcpi_rtt = ci_ip_time_ticks2ms(netif, ts->sa) * 1000 / 8;
    info->tcpi_rttvar = ci_ip_time_ticks2ms(netif, ts->sv) * 1000 / 4;
    info->tcpi_rcv_ssthresh = ts->ssthresh;
    if( tcp_eff_mss(ts) != 0 ) {
      info->tcpi_snd_ssthresh = ts->ssthresh / tcp_eff_mss(ts);
      info->tcpi_snd_cwnd     = ts->cwnd / tcp_eff_mss(ts);
    }
    else { /* non-initialised connection */
      info->tcpi_snd_ssthresh = 0;
      info->tcpi_snd_cwnd     = 0;
    }
    info->tcpi_advmss     = ts->amss;
  }

  return 0;
}


/* [fd] is unused in the kernel version */
int ci_tcp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, void *optval, socklen_t *optlen )
{
  ci_sock_cmn* s = ep->s;
#if defined(__linux__) || \
    defined(__sun__) && defined(TCP_KEEPALIVE_THRESHOLD) || \
    defined(__sun__) && defined(TCP_KEEPALIVE_ABORT_THRESHOLD)
  ci_tcp_socket_cmn *c = &(SOCK_TO_WAITABLE_OBJ(s)->tcp.c);
#endif
  ci_netif* netif = ep->netif;
  unsigned u = 0;

  /* NOTE: The setsockopt() call is reflected into the os socket to
   * keep the two in sync - it's assumed that we know everything
   * to allow us to give good answers here - and therefore we don't
   * bother the os with the get call */

  /* ?? what to do about optval and optlen checking
   * Kernel can raise EFAULT, here we are a little in the dark.
   *  - sockcall_intercept.c checks that optlen is non-NULL and if *optlen
   *    is non-zero that optval is non-NULL, returning EFAULT if false
   */

  if(level == SOL_SOCKET) {
    /* Common SOL_SOCKET handler */
    return ci_get_sol_socket(netif, s, optname, optval, optlen);

  } else if (level ==  IPPROTO_IP) {
    /* IP level options valid for TCP */
    return ci_get_sol_ip(ep, s, fd, optname, optval, optlen);

#if CI_CFG_FAKE_IPV6
  } else if (level ==  IPPROTO_IPV6 && s->domain == AF_INET6) {
    /* IP6 level options valid for TCP */
    return ci_get_sol_ip6(ep, s, fd, optname, optval, optlen);
#endif

  } else if (level == IPPROTO_TCP) {
    /* TCP level options valid for TCP */
    switch(optname){
    case TCP_NODELAY:
      /* gets status of TCP Nagle algorithm  */
      u = ((s->s_aflags & CI_SOCK_AFLAG_NODELAY) != 0);
      goto u_out;
    case TCP_MAXSEG:
      /* gets the MSS size for this connection */
      if ((s->b.state & CI_TCP_STATE_TCP_CONN)) {
        u = tcp_eff_mss(SOCK_TO_TCP(s));
      } else {
        u = 536;
      }
      goto u_out;
# ifdef TCP_CORK
    case TCP_CORK:
      /* don't send partial framses, all partial frames sent
      ** when the option is cleared */
      u = ((s->s_aflags & CI_SOCK_AFLAG_CORK) != 0);
      goto u_out;
# endif


    case TCP_KEEPIDLE:
      {
        /* idle time for keepalives  */
        u = (unsigned) c->t_ka_time_in_secs;
      }
      goto u_out;
    case TCP_KEEPINTVL:
      {
        /* time between keepalives */
        u = (unsigned) c->t_ka_intvl_in_secs;
      }
      goto u_out;
    case TCP_KEEPCNT:
      {
        /* number of keepalives before giving up */
        u = c->ka_probe_th;
      }
      goto u_out;
    case TCP_INFO:
      /* struct tcp_info to be filled */
      return ci_tcp_info_get(netif, s, (struct ci_tcp_info*) optval);
    case TCP_DEFER_ACCEPT:
      {
        u = 0;
        if( c->tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF ) {
          u = ci_ip_time_ticks2ms(netif, NI_CONF(netif).tconst_rto_initial);
          u = ((u + 500) / 1000) << c->tcp_defer_accept;
        }
        goto u_out;
      }
    case TCP_QUICKACK:
      {
        u = 0;
        if( s->b.state & CI_TCP_STATE_TCP_CONN ) {
          ci_tcp_state* ts = SOCK_TO_TCP(s);
          u = ci_tcp_is_in_faststart(ts);
        }
        goto u_out;
      }
    default:
      LOG_TC( log(LPF "getsockopt: unimplemented or bad option: %i", 
                  optname));
      RET_WITH_ERRNO(ENOPROTOOPT);
    }
  } else {
    SOCKOPT_RET_INVALID_LEVEL(s);
  }

  return 0;

 u_out:
  return ci_getsockopt_final(optval, optlen, level, &u, sizeof(u));
}




static int ci_tcp_setsockopt_lk(citp_socket* ep, ci_fd_t fd, int level,
				int optname, const void* optval,
				socklen_t optlen )
{
  ci_sock_cmn* s = ep->s;
#if defined(__linux__) || \
    defined(__sun__) && defined(TCP_KEEPALIVE_THRESHOLD) || \
    defined(__sun__) && defined(TCP_KEEPALIVE_ABORT_THRESHOLD)
  ci_tcp_socket_cmn* c = &(SOCK_TO_WAITABLE_OBJ(s)->tcp.c);
#endif
  ci_netif* netif = ep->netif;
  int zeroval = 0;
  int rc;

  /* ?? what to do about optval and optlen checking
  ** Kernel can raise EFAULT, here we are a little in the dark.
  ** Note: If the OS sock is sync'd then we get this checking for free.
  */

  if (optlen == 0) {
    /* Match kernel behaviour: if length is 0, it treats the value as 0; and
     * some applications rely on this.
     */
    optval = &zeroval;
    optlen = sizeof(zeroval);
  }

  /* If you're adding to this please remember to look in common_sockopts.c
   * and decide if the option is common to all protocols. */

  if(level == SOL_SOCKET) {
    switch(optname) {
    case SO_KEEPALIVE:
      /* Over-ride the default common handler.
       * Enable sending of keep-alive messages */
      if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      	goto fail_inval;

      if( *(unsigned*) optval ) {
	unsigned prev_flags = s->s_flags;
	s->s_flags |= CI_SOCK_FLAG_KALIVE;
	/* Set KEEPALIVE timer only if we are not in
	** CLOSE or LISTENING state. */
	if( s->b.state != CI_TCP_CLOSED && s->b.state != CI_TCP_LISTEN &&
	    !(prev_flags & CI_SOCK_FLAG_KALIVE) ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
	  LOG_TV(log("%s: "NSS_FMT" run KEEPALIVE timer from setsockopt()",
		     __FUNCTION__, NSS_PRI_ARGS(netif, s)));
	  ci_assert(ts->ka_probes == 0);
	  ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
	}
      }
      else {
      	s->s_flags &=~ CI_SOCK_FLAG_KALIVE;
	if( s->b.state != CI_TCP_LISTEN ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
	  ci_tcp_kalive_check_and_clear(netif, ts);
	  ts->ka_probes = 0;
	}
      }
      break;

    default:
      {
        /* Common socket level options */
        return ci_set_sol_socket(netif, s, optname, optval, optlen);
      }
    }
  }
  else if( level == IPPROTO_IP ) {
    /* IP level options valid for TCP */
    return ci_set_sol_ip(netif, s, optname, optval, optlen);
  }
  else if( level == IPPROTO_TCP ) {
    switch(optname) {

     
    case TCP_MAXSEG:
      /* sets the MSS size for this connection */
      if( (rc = opt_not_ok(optval, optlen, unsigned)) )
        goto fail_inval;
      if( (*(unsigned*)optval < 8) || 
          (*(unsigned*)optval > CI_CFG_TCP_MAX_WINDOW)) {
        rc = -EINVAL;
        goto fail_inval;
      }
      c->user_mss = *(unsigned*)optval;
      break;

    case TCP_KEEPIDLE:
      /* idle time for keepalives  */
      c->t_ka_time = ci_ip_time_ms2ticks_slow(netif, *(unsigned*)optval*1000);
      c->t_ka_time_in_secs = *(unsigned*)optval;
      break;

    case TCP_KEEPINTVL:
      /* time between keepalives */
      c->t_ka_intvl = ci_ip_time_ms2ticks_slow(netif, *(unsigned*)optval*1000);
      c->t_ka_intvl_in_secs = *(unsigned*)optval;
      break;

    case TCP_KEEPCNT:
      /* number of keepalives before giving up */
      c->ka_probe_th = *(unsigned*)optval;
      break;
    case TCP_DEFER_ACCEPT:
      if( *(int*) optval > 0 ) {
        /* Value is timeout in seconds.  Convert to a number of retries. */
        int timeo = CI_MIN(*(int*) optval, 100000) * 1000;
#ifndef __KERNEL__
        timeo = ci_ip_time_ms2ticks_fast(netif, timeo);
#else
        timeo = ci_ip_time_ms2ticks_slow(netif, timeo);
#endif
        timeo = CI_MIN(timeo, NI_CONF(netif).tconst_rto_max);
        c->tcp_defer_accept = 0;
        while( timeo > ((int) NI_CONF(netif).tconst_rto_initial
                        << c->tcp_defer_accept) )
          ++c->tcp_defer_accept;
      }
      else
        c->tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;
      break;
    case TCP_QUICKACK:
      {
        if( s->b.state & CI_TCP_STATE_TCP_CONN ) {
          ci_tcp_state* ts = SOCK_TO_TCP(s);
          if( *(int*) optval != 0 ) {
            CITP_TCP_FASTSTART(ts->faststart_acks = 
                               NI_OPTS(netif).tcp_faststart_idle);
            if( ts->acks_pending ) {
              ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(netif);
              if( CI_LIKELY(pkt != NULL) )
                ci_tcp_send_ack(netif, ts, pkt);
            }
          }
          else {
            CITP_TCP_FASTSTART(ts->faststart_acks = 0);
          }
        }
      }
      break;
    default:
      LOG_TC(log("%s: "NSS_FMT" option %i unimplemented (ENOPROTOOPT)", 
                 __FUNCTION__, NSS_PRI_ARGS(netif,s), optname));
      RET_WITH_ERRNO(ENOPROTOOPT);
    }
  }
  else {
    LOG_U(log(FNS_FMT "unknown level=%d optname=%d accepted by O/S",
              FNS_PRI_ARGS(netif, s), level, optname));
  }

  return 0;

 fail_inval:
  LOG_TC(log("%s: "NSS_FMT" option %i  bad param (EINVAL or EFAULT)",
	     __FUNCTION__, NSS_PRI_ARGS(netif,s), optname));
  RET_WITH_ERRNO(-rc);
}


/* Setsockopt() handler called by appropriate Unix/Windows intercepts.
 * \param ep       Context
 * \param fd       Linux: Our FD, Windows: ignored (CI_INVALID_SOCKET)
 * \param level    From intercept
 * \param optname  From intercept
 * \param optval   From intercept
 * \param optlen   From intercept
 * \return         As for setsockopt()
 */
int ci_tcp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, const void* __optval,
		      socklen_t optlen )
{
  ci_sock_cmn* s = ep->s;
  ci_netif* ni = ep->netif;
  int rc = 0;
#if defined(__KERNEL__) && defined (__linux__)
  union {
    long l;
    int  i;
    char dummy[16];
  } opts;
  void* optval = &opts;

  /* Security (bug27705): User may have specified a short optlen, in which
   * case [opts] may include some data from the stack which can leak into
   * the shared state.
   */
  memset(&opts, 0, sizeof(opts));

  rc = copy_from_user(optval, __optval, CI_MIN(optlen, sizeof(opts)));
  if( rc )
    return -EFAULT;
#else
# define optval __optval
#endif

  /* If not yet connected, apply to the O/S socket.  This keeps the O/S
  ** socket in sync in case we need to hand-over.
  **
  ** WINDOWS: Thanks to disconnectex() we have to make sure that the OS
  ** socket stays in sync with our socket at all times so that we can
  ** handover to the OS on one use, handback on disconnect and then re-use
  ** the socket for an Efab connection (&vv).
  */
  /*! \todo This is very much a "make it work" change.  Ideally we should
   * do the updates lazily so that we don't waste time with a socket that
   * may never be used for an OS connection.
   */
  if( ! (s->b.state & CI_TCP_STATE_SYNCHRONISED) ) 
  {
#ifndef __KERNEL__
    ci_fd_t os_sock = ci_get_os_sock_fd(ep, fd);
    if( CI_IS_VALID_SOCKET(os_sock) ) {
      rc = ci_sys_setsockopt(os_sock, level, optname, optval, optlen);
      ci_rel_os_sock_fd(os_sock);
#else
    {
      rc = ci_khelper_setsockopt(ni, SC_SP(s), level, optname, __optval, optlen);
#endif
      if( rc < 0 )  return rc;
    }
  }

  /* We can set some sockopts without the netif lock. */
  if( level == IPPROTO_TCP ) {
    switch( optname ) {
# ifdef TCP_CORK
    case TCP_CORK:
      if( *(unsigned*) optval ) {
	ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
      } else {
	ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
	/* We need to push out a segment that was corked.  Note that CORK
	** doesn't prevent full segments from going out, so if the send
	** queue contains more than one segment, it must be limited by
	** something else (and therefore not our problem).
	**
	** ?? We could be even more clever here and use the existing
	** deferred mechanism to advance the sendq if the netif lock were
	** contended.
	*/
	if( s->b.state != CI_TCP_LISTEN ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
	  if( ts->send.num == 1 ) {
	    ci_netif_lock_fixme(ni);
	    if( ts->send.num == 1 ) {
              TX_PKT_TCP(PKT_CHK(ni, ts->send.head))->tcp_flags |=
                                                    CI_TCP_FLAG_PSH;
	      ci_tcp_tx_advance(ts, ni);
            }
	    ci_netif_unlock(ni);
	  }
	}
      }
      goto success;
# endif
    case TCP_NODELAY:
      if( *(unsigned*) optval ) {
	ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

	if( s->b.state != CI_TCP_LISTEN ) {
	  ci_tcp_state* ts = SOCK_TO_TCP(s);
          ci_uint32 cork; 

	  if( ts->send.num == 1 ) {
            /* When TCP_NODELAY is set, push out pending segments (even if
            ** CORK is set).
            */
            if( (cork = (s->s_aflags & CI_SOCK_AFLAG_CORK)) )
              ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);

            ci_netif_lock_fixme(ni);
            if( ci_ip_queue_not_empty(&ts->send) )
              ci_tcp_tx_advance(ts, ni);
	    ci_netif_unlock(ni);

            if ( cork )
              ci_bit_set(&s->s_aflags, CI_SOCK_AFLAG_CORK_BIT);
          }
        }
      }
      else
        ci_bit_clear(&s->s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);
      goto success;
    }
  }
  else if( level == SOL_SOCKET ) {
    rc = ci_set_sol_socket_nolock(ni, s, optname, optval, optlen);
    if( rc <= 0 )  return rc;
  }
  else if( level == IPPROTO_IPV6 ) {
#ifdef IPV6_V6ONLY
    if( optname == IPV6_V6ONLY && *(unsigned*) optval )
      return CI_SOCKET_HANDOVER;
#endif
    /* All socket options are already set for system socket, and we do not
    ** handle IPv6 option natively. */
    goto success;
  }

  /* Otherwise we need to grab the netif lock. */
  ci_netif_lock_count(ni, setsockopt_ni_lock_contends);
  rc = ci_tcp_setsockopt_lk(ep, fd, level, optname, optval, optlen);
  ci_netif_unlock(ni);
  return rc;

 success:
  return 0;
}

/*! \cidoxg_end */
