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
** \author  ctk
**  \brief  synrecv state functions
**   \date  2004/01/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "tcp_rx.h"


#define LPF "TCP SYNRECV "


ci_inline unsigned listenq_hash(unsigned saddr, unsigned daddr,
                                unsigned sport)
{
  unsigned h = saddr ^ daddr ^ sport;
  h ^= h >> 16;
  h ^= h >> 8;
  return h & (CI_CFG_TCP_LISTENQ_BUCKETS - 1);
}


void ci_tcp_listenq_insert(ci_netif* ni, ci_tcp_socket_listen* tls,
                           ci_tcp_state_synrecv* tsr)
{
  unsigned h = listenq_hash(tsr->r_addr, tsr->l_addr, tsr->r_port);
  ci_ni_dllist_put(ni, &tls->listenq[h], &tsr->link);
  tsr->retries = 0;
  tsr->timeout = ci_tcp_time_now(ni) + NI_CONF(ni).tconst_rto_initial;

  ++tls->n_listenq_new;
  if( tls->n_listenq++ == 0 &&
      (~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) )
    ci_ip_timer_set(ni, &tls->listenq_tid, tsr->timeout);
}


void ci_tcp_listenq_remove(ci_netif* ni, ci_tcp_socket_listen* tls,
                           ci_tcp_state_synrecv* tsr)
{
  ci_assert(ni);
  ci_assert(tsr);
  ci_assert(tls);

  ci_ni_dllist_remove(ni, &tsr->link);

  if( tsr->retries == 0 )  --tls->n_listenq_new;

  /* cancel timer if no more synrecv on queue */
  if( --tls->n_listenq == 0 &&
     (~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) )
    ci_ip_timer_clear(ni, &tls->listenq_tid);
}


/*
** See if there is a synrecv object that matches this syn request already.
*/
ci_tcp_state_synrecv*
ci_tcp_listenq_lookup(ci_netif* netif, ci_tcp_socket_listen* tls,
                      ciip_tcp_rx_pkt* rxp)
{
  ci_ni_dllist_t* list;
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;
  ci_tcp_state_synrecv* tsr;
  ci_ni_dllist_link *l;
  unsigned saddr, daddr, sport;

  ci_assert(netif);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);
  ci_assert(pkt);

  saddr = oo_ip_hdr(pkt)->ip_saddr_be32;
  daddr = oo_ip_hdr(pkt)->ip_daddr_be32;
  sport = tcp->tcp_source_be16;

  list = &tls->listenq[listenq_hash(saddr, daddr, sport)];

  /* traverse the listen queue */
  for( l = ci_ni_dllist_start(netif, list);
       l != ci_ni_dllist_end(netif, list);
       ci_ni_dllist_iter(netif, l) ) {

    tsr = CI_CONTAINER(ci_tcp_state_synrecv, link, l);

    if( ! ((saddr - tsr->r_addr) | (daddr - tsr->l_addr) |
           (sport - tsr->r_port)) )
      return tsr;
  }

  LOG_TV(log(LPF "no match for %s:%d->%s:%d",
             ip_addr_str(saddr), (int) CI_BSWAP_BE16(sport),
             ip_addr_str(daddr), (int) CI_BSWAP_BE16(tcp->tcp_dest_be16)));

  /* if not there then return nothing */
  return NULL;
}


void ci_tcp_listenq_drop_oldest(ci_netif* ni, ci_tcp_socket_listen* tls)
{
  ci_tcp_state_synrecv* tsr;
  ci_iptime_t min_to = 0 /* to prevent compiler whinge only */;
  int min_i = -1, i;

  for( i = 0; i < CI_CFG_TCP_LISTENQ_BUCKETS; ++i ) {
    if( ci_ni_dllist_not_empty(ni, &tls->listenq[i]) ) {
      tsr = CI_CONTAINER(ci_tcp_state_synrecv, link,
                         ci_ni_dllist_head(ni, &tls->listenq[i]));
      if( min_i < 0 || TIME_LT(min_to, tsr->timeout) ) {
        min_i = i;
        min_to = tsr->timeout;
      }
    }
  }
  ci_assert_ge(min_i, 0);
  ci_assert_lt(min_i, CI_CFG_TCP_LISTENQ_BUCKETS);
  ci_assert(ci_ni_dllist_not_empty(ni, &tls->listenq[min_i]));
  tsr = CI_CONTAINER(ci_tcp_state_synrecv, link,
                     ci_ni_dllist_head(ni, &tls->listenq[min_i]));
  ci_tcp_listenq_remove(ni, tls, tsr);
  ci_tcp_synrecv_free(ni, tsr);
  CITP_STATS_NETIF(++ni->state->stats.synrecv_purge);
}


ci_inline ci_tcp_state*
get_ts_from_cache (ci_netif *netif, 
                   ci_tcp_state_synrecv* tsr, 
                   ci_tcp_socket_listen* tls)
{
  ci_tcp_state *ts = NULL;
#if CI_CFG_FD_CACHING
  if (!ci_ni_dllist_is_empty (netif, &tls->epcache_cache)) {
    int rc, switch_filter = 0;
    unsigned protocol, laddr, lport, raddr, rport;
    ci_ni_dllist_link *link = ci_ni_dllist_pop (netif, &tls->epcache_cache);

    /* Take the entry from the cache */
    ts = CI_CONTAINER (ci_tcp_state, epcache_link, link);
    ci_assert (ts);
    netif->state->epcache_n++;

    LOG_EP (ci_log ("Taking cached fd %d off cached list, (onto acceptq)",
            ts->cached_on_fd));

    if( tcp_raddr_be32(ts) != tsr->r_addr ) {
      /* Oh dear -- the tcp-state we cached was using a different local IP
       * address.  This means we've accepted a connection from a different
       * interface as we did for the thing we've cached.  Which means we
       * can't share the hardware filter after all.  So "switch filters".
       */
      switch_filter = 1;
      LOG_EP (ci_log ("changed interface of cached EP, uncaching filters"));
      rc = ci_tcp_ep_clear_filters(netif, S_SP(ts));
      if (rc < 0) {
        LOG_E (ci_log ("Failed to clear filter on cache switch! (%d)", rc));
        return NULL;
      }
    }

    /* copy and initialise state */
    ts->s.pkt.ip.ip_saddr_be32 = tsr->l_addr;
    TS_TCP(ts)->tcp_source_be16 = sock_lport_be16(&tls->s);
    ts->s.cp.ip_laddr_be32 = tsr->l_addr;
    ts->s.cp.lport_be16 = sock_lport_be16(&tls->s);
    ci_tcp_set_peer(ts, tsr->r_addr, tsr->r_port);

    /* Pull out the parts we'll use for the filter */
    protocol = tcp_protocol(ts);
    laddr = tcp_laddr_be32(ts);
    raddr = tcp_raddr_be32(ts);
    lport = tcp_lport_be16(ts);
    rport = tcp_rport_be16(ts);

    ci_sock_cmn_init(netif, &ts->s);
    ci_pmtu_state_init(netif, &ts->s, &ts->pmtus, CI_IP_TIMER_PMTU_DISCOVER);
	
    if (NI_OPTS(netif).tcp_force_nodelay == 1)
      ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

    if (switch_filter) {
      LOG_EP (ci_log ("Resetting filters for cached EP"));
      rc = ci_tcp_ep_set_filters(netif, S_SP(ts), ts->s.cp.so_bindtodevice, 
                                 S_SP(tls));
      if (rc < 0) {
        LOG_E (ci_log ("Failed to set filter on cache switch (%d)", rc));
        ci_tcp_state_free(netif, ts);
        return NULL;
      }
    }
    else {
      /* Now set the s/w filter (note that we leave the h/w filter in place
       * for cached EPs
       */
      rc =  ci_netif_filter_insert(netif, S_SP(ts),
                                   laddr, lport, raddr, rport, protocol);
      
      if (rc < 0) {
        /* Free the state.  Will also clear filter and remove FD */
        ci_log ("Unable to create s/w filter!");
        ci_tcp_state_free(netif, ts);
        return NULL;
      }
    }
  }
#endif
  return ts;
}


/*! Copy socket options and related fields that should be inherited.
 * Inherits into [ts] from [s] & [c]. Options are inherited during EP
 * promotion for unix, during accept handler in Windows & as a result of
 * setsockopt:SOL_SOCKET:SO_UPDATE_ACCEPT_CONTEXT.  MUST have a lock on
 * [ts].  [or_nonblock] controls whether the non-blocking state from [s]
 * overwrites that in [ts] or is OR'd into it.
 */
static void ci_tcp_inherit_options(ci_netif* ni, ci_sock_cmn* s,
                                   ci_tcp_socket_cmn* c, 
                                   ci_tcp_state* ts, const char* ctxt)
{
  ci_assert(ni);
  ci_assert(s);
  ci_assert(c);
  ci_assert(ts);

  ts->s.so = s->so;
  ts->s.cp.so_bindtodevice = s->cp.so_bindtodevice;
  ts->s.cp.ip_ttl = s->cp.ip_ttl;
  ts->s.rx_bind2dev_ifindex = s->rx_bind2dev_ifindex;
  ts->s.rx_bind2dev_base_ifindex = s->rx_bind2dev_base_ifindex;
  ts->s.rx_bind2dev_vlan = s->rx_bind2dev_vlan;
  ci_tcp_set_sndbuf(ni, ts);      /* eff_mss must be valid */

  {
    /* NB. We have exclusive access to [ts], so it is safe to manipulate
    ** s_aflags without using bit-ops. */
    unsigned inherited_sflags = CI_SOCK_AFLAG_TCP_INHERITED;
    unsigned inherited_sbflags = 0;

    if( NI_OPTS(ni).accept_inherit_nonblock )
      inherited_sbflags |= CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY;

    if( NI_OPTS(ni).tcp_force_nodelay == 1 )
      ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

    if( NI_OPTS(ni).accept_inherit_nodelay )
      inherited_sflags |= CI_SOCK_AFLAG_NODELAY;

    ci_assert((ts->s.s_aflags & inherited_sflags) == 0);
    ci_atomic32_or(&ts->s.s_aflags, s->s_aflags & inherited_sflags);

    ci_assert((ts->s.b.sb_aflags & inherited_sbflags) == 0);
    ci_atomic32_or(&ts->s.b.sb_aflags, s->b.sb_aflags & inherited_sbflags);

    ci_assert_equal((ts->s.s_flags & CI_SOCK_FLAG_TCP_INHERITED),
                    CI_SOCK_FLAG_PMTU_DO);
    ts->s.s_flags &= ~CI_SOCK_FLAG_PMTU_DO;
    ts->s.s_flags |= s->s_flags & CI_SOCK_FLAG_TCP_INHERITED;
  }

  /* Bug1861: while not defined as such, various SOL_TCP/SOL_IP sockopts
   * are inherited in Linux. */
  /* TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT */
  ts->c.t_ka_time          = c->t_ka_time;
  ts->c.t_ka_time_in_secs  = c->t_ka_time_in_secs;
  ts->c.t_ka_intvl         = c->t_ka_intvl;
  ts->c.t_ka_intvl_in_secs = c->t_ka_intvl_in_secs;
  ts->c.ka_probe_th        = c->ka_probe_th;
  ci_ip_hdr_init_fixed(&ts->s.pkt.ip, IPPROTO_TCP,
                        s->pkt.ip.ip_ttl,
                        s->pkt.ip.ip_tos);
  ts->s.cmsg_flags = s->cmsg_flags;
  ts->s.timestamping_flags = s->timestamping_flags;

  /* Must have set up so.sndbuf */
  ci_tcp_init_rcv_wnd(ts, ctxt);
}


/*! Copy socket options & related fields that should be inherited.
 * Inherits into [ts] from [tls].
 */
static void ci_tcp_inherit_accept_options(ci_netif* ni, 
                                          ci_tcp_socket_listen* tls,
                                          ci_tcp_state* ts, const char* ctxt)
{
  ci_tcp_inherit_options(ni, &tls->s, &tls->c, ts, ctxt);
}


/* Copy socket options & related fields that should be inherited. 
 * Inherits into [ts] from [tls] */
    
/*
** promote a synrecv structure to an established socket
**
** Assumes that the caller will handle a fail if we can't allocate a new
** tcp_state structure due to memory pressure or the like
*/
int ci_tcp_listenq_try_promote(ci_netif* netif, ci_tcp_socket_listen* tls,
                               ci_tcp_state_synrecv* tsr,
                               ci_ip_cached_hdrs* ipcache,
                               ci_tcp_state** ts_out)
{
  int rc = 0;
  
  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);
  ci_assert(tsr);

  if( (int) ci_tcp_acceptq_n(tls) < tls->acceptq_max ) {
    ci_tcp_state* ts;

    /* grab a tcp_state structure that will go onto the accept queue.  We take
     * from the cache of EPs if any are available
     */
    ts = get_ts_from_cache (netif, tsr, tls); 
    if( !ts ) {
        /* None on cache; try allocating a new ts */
        ts = ci_tcp_get_state_buf(netif);
#if CI_CFG_FD_CACHING
        if( ts == NULL && netif->state->epcache_n > 0 ) {
          /* We've reaped.  Did this result in any being cached */
          ts = get_ts_from_cache(netif, tsr, tls);
          if (ts == NULL ) {
            /* No -- try again to allocate. */
            ts = ci_tcp_get_state_buf(netif);
          }
        }
#endif
        if( ts == NULL ) {
          LOG_TV(ci_log("%s: [%d] out of socket buffers",
                        __FUNCTION__, NI_ID(netif)));
	  CITP_STATS_TCP_LISTEN(++tls->stats.n_acceptq_no_sock);
          return -ENOMEM;
	}

        ci_assert(ci_tcp_is_cached(ts) ||
                  (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
    }

    if( ! ci_tcp_is_cached(ts) ) {
      /* copy and initialise state */
      ts->s.pkt.ip.ip_saddr_be32 = tsr->l_addr;
      TS_TCP(ts)->tcp_source_be16 = sock_lport_be16(&tls->s);
      ts->s.cp.ip_laddr_be32 = tsr->l_addr;
      ts->s.cp.lport_be16 = sock_lport_be16(&tls->s);
      ci_tcp_set_peer(ts, tsr->r_addr, tsr->r_port);

      /* "filter" equivalent for loopback socket */
      if( OO_SP_NOT_NULL(tsr->local_peer) ) {
        ci_tcp_state *peer = ID_TO_TCP(netif, tsr->local_peer);
        ts->s.local_peer = tsr->local_peer;
        peer->s.local_peer = S_SP(ts);
      }

      /* "borrow" filter from listening socket.  For loopback socket, we
       * do not need filters, but we have to take a reference of the OS
       * socket. */
      rc = ci_tcp_ep_set_filters(netif, S_SP(ts), ts->s.cp.so_bindtodevice,
                                 S_SP(tls));
      if( rc < 0 ) {
        LOG_U(ci_log("%s: Unable to set filters %d", __FUNCTION__, rc));
        /* Either put this back on the list (at the head) or free it */
        ci_tcp_state_free(netif, ts);
        return -1;
      }
    }

    ci_assert(IS_VALID_SOCK_P(netif, S_SP(ts)));
    ci_assert(ts->s.b.state == CI_TCP_CLOSED);
    ts->s.domain = tls->s.domain;

    cicp_ip_cache_update_from(netif, &ts->s.pkt, ipcache);
    ci_pmtu_state_init(netif, &ts->s, &ts->pmtus,
                       CI_IP_TIMER_PMTU_DISCOVER);
    ci_pmtu_set(netif, &ts->pmtus,
                CI_MIN(ts->s.pkt.mtu,
                       tsr->tcpopts.smss + sizeof(ci_tcp_hdr)
                         + sizeof(ci_ip4_hdr)));

    /* If we've got SYN via local route, we can handle it */
    ci_assert_equiv(ts->s.pkt.status == retrrc_localroute,
                    OO_SP_NOT_NULL(tsr->local_peer));
    if( ts->s.pkt.status == retrrc_localroute )
      ts->s.pkt.flags |= CI_IP_CACHE_IS_LOCALROUTE;

    /* Now that we know the outgoing the outgoing route, set the MTU related
     * values. Note, even these values are speculative since the real MTU
     * could change between now and passing the packet to the lower layers
     *
     * If we have a rcvbuf smaller than the mss we would advertise, then
     * limit amss to that.  Note that we take size from the listening socket
     * as our new socket hasn't been fully setup yet.
     */
    ts->amss = CI_MIN(tls->s.so.rcvbuf,
                      ts->s.pkt.mtu - sizeof(ci_tcp_hdr) - sizeof(ci_ip4_hdr));
#if CI_CFG_LIMIT_AMSS
    ts->amss = ci_tcp_limit_mss(ts->amss, netif, __FUNCTION__);
#endif

    /* options and flags */
    ts->tcpflags = 0;
    ts->tcpflags |= tsr->tcpopts.flags;
    ts->tcpflags |= CI_TCPT_FLAG_PASSIVE_OPENED;
    ts->outgoing_hdrs_len = sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr);
    if( ts->tcpflags & CI_TCPT_FLAG_WSCL ) {
      ts->snd_wscl = tsr->tcpopts.wscl_shft;
      ts->rcv_wscl = tsr->rcv_wscl;
    } else {
      ts->snd_wscl = ts->rcv_wscl = 0u;
    }
    CI_IP_SOCK_STATS_VAL_TXWSCL( ts, ts->snd_wscl);
    CI_IP_SOCK_STATS_VAL_RXWSCL( ts, ts->rcv_wscl);

    /* Send and receive sequence numbers */
    tcp_snd_una(ts) = tcp_snd_nxt(ts) = tcp_enq_nxt(ts) = tcp_snd_up(ts) =
      tsr->snd_isn + 1;
    ci_tcp_set_snd_max(ts, tsr->rcv_nxt, tcp_snd_una(ts), 0);
    ci_tcp_rx_set_isn(ts, tsr->rcv_nxt);
    tcp_rcv_up(ts) = SEQ_SUB(tcp_rcv_nxt(ts), 1);

    if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
      ts->incoming_tcp_hdr_len += 12;
      ts->outgoing_hdrs_len += 12;
      ts->tspaws = ci_tcp_time_now(netif);
      ts->tsrecent = tsr->tspeer;
      ts->tslastack = tsr->rcv_nxt;
    }
    else {
      /* Must be after initialising snd_una. */
      ci_tcp_clear_rtt_timing(ts);
    }
    /* SACK has nothing to be done. */

    /* ?? ECN */
    ci_tcp_set_hdr_len(ts, (ts->outgoing_hdrs_len - sizeof(ci_ip4_hdr)));

    ts->smss = tsr->tcpopts.smss;
    ts->c.user_mss = tls->c.user_mss;
    if (ts->c.user_mss && ts->c.user_mss < ts->smss)
      ts->smss = ts->c.user_mss;
#if CI_CFG_LIMIT_SMSS
    ts->smss = ci_tcp_limit_mss(ts->smss, netif, __FUNCTION__);
#endif
    ci_assert(ts->smss>0);
    ci_tcp_set_eff_mss(netif, ts);
    ci_tcp_set_initialcwnd(netif, ts);

    /* Copy socket options & related fields that should be inherited. 
     * Note: Windows does not inherit rcvbuf until the call to accept 
     * completes. The assumption here is that all options can be
     * inherited at the same time (most won't have an effect until there
     * is a socket available for use by the app.).
     */
    ci_tcp_inherit_accept_options(netif, tls, ts, "SYN RECV (LISTENQ PROMOTE)");

    /* NB. Must have already set peer (which we have). */
    ci_tcp_set_established_state(netif, ts);
    CITP_STATS_NETIF(++netif->state->stats.synrecv2established);
  
    ci_assert(ts->ka_probes == 0);
    ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
    ci_tcp_set_flags(ts, CI_TCP_FLAG_ACK);

    /* Remove the synrecv structure from the listen queue, and free the
    ** buffer. */
    if( tsr->tcpopts.flags & CI_TCPT_FLAG_SYNCOOKIE )
      ci_free(tsr);
    else {
      ci_tcp_listenq_remove(netif, tls, tsr);
      ci_tcp_synrecv_free(netif, tsr);
    }

    ci_bit_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
    ci_tcp_acceptq_put(netif, tls, &ts->s.b);

    LOG_TC(log(LNT_FMT "new ts=%d SYN-RECV->ESTABLISHED flags=0x%x",
               LNT_PRI_ARGS(netif, tls), S_FMT(ts), ts->tcpflags);
           log(LNTS_FMT RCV_WND_FMT " snd=%08x-%08x-%08x enq=%08x",
               LNTS_PRI_ARGS(netif, ts), RCV_WND_ARGS(ts),
               tcp_snd_una(ts),
               tcp_snd_nxt(ts), ts->snd_max, tcp_enq_nxt(ts)));

    citp_waitable_wake(netif, &tls->s.b, CI_SB_FLAG_WAKE_RX);
    *ts_out = ts;
    return 0;
  }
  CI_TCP_EXT_STATS_INC_LISTEN_OVERFLOWS( netif );
  LOG_U(log(LPF LNT_FMT" accept queue is full (n=%d max=%d)",
            LNT_PRI_ARGS(netif, tls), ci_tcp_acceptq_n(tls), tls->acceptq_max));
  CITP_STATS_TCP_LISTEN(++tls->stats.n_acceptq_overflow);

  return -1;
}

/*! \cidoxg_end */
