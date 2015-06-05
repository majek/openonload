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

#define TSR_FMT "ptr:%x next:%x hash:%x l:%s r:%s:%d"
#define TSR_ARGS(tsr)                                               \
  oo_ptr_to_statep(ni, CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr)),\
  tsr->bucket_link, tsr->hash,                                      \
  ip_addr_str(tsr->l_addr),                                         \
  ip_addr_str(tsr->r_addr), CI_BSWAP_BE16(tsr->r_port)

#ifdef __KERNEL__
/* We do not expect per-bucket list to be longer than a few members.
 * However, we must not break things if attacker managed to make a lot of
 * connection with the same hash (and the hash used here is not
 * cryptographically strong).
 * Finally, we must impose some limit to avoid malicious userland from
 * making kernel spin in the loop undefinetly long. */
#define CI_LISTENQ_BUCKET_LIST_LIMIT(ni) NI_OPTS(ni).tcp_backlog_max
#endif

/* tcp_backlog_max <= 2^4:
 *      max level is 0 (2^4 different lists)
 * tcp_backlog_max <= 2^8:
 *      max level is 1 (2^8 different lists if no hash collisions happen)
 * tcp_backlog_max <= 2^12 = 4096:
 *      max level is 2.
 */
#define CI_LISTENQ_BUCKET_MAX_DEPTH(ni) \
    ((ci_log2_le(NI_OPTS(ni).tcp_backlog_max) - 1) / 4)

ci_inline int ci_tcp_listenq_hash2idx(ci_uint32 hash, int level)
{
  return (hash >> (CI_TCP_LISTEN_BUCKET_S * level)) &
      ((1 << CI_TCP_LISTEN_BUCKET_S) - 1);
}

ci_inline ci_tcp_listen_bucket*
ci_tcp_listenq_p2bucket(ci_netif* ni, oo_p p)
{
  return &ci_tcp_listenq_p2aux(ni, p)->u.bucket;
}


static int
ci_tcp_listenq_bucket_drop(ci_netif* ni, ci_tcp_listen_bucket* bucket)
{
  ci_ni_aux_mem* aux;
  int idx;
  oo_p tsr_p;
  ci_tcp_state_synrecv* tsr;
  int ret = 0;

  for( idx = 0; idx < CI_TCP_LISTEN_BUCKET_SIZE; idx++ ) {
    if( OO_P_IS_NULL(bucket->bucket[idx]) )
      continue;
    aux = ci_tcp_listenq_p2aux(ni, bucket->bucket[idx]);
    if( aux->type == CI_TCP_AUX_TYPE_BUCKET )
      ret += ci_tcp_listenq_bucket_drop(ni, &aux->u.bucket);
    else {
      tsr_p = bucket->bucket[idx];
      do {
        tsr = &ci_tcp_listenq_p2aux(ni, tsr_p)->u.synrecv;
        tsr_p = tsr->bucket_link;
        if( OO_SP_IS_NULL(tsr->local_peer) )
          ci_ni_dllist_remove(ni, ci_tcp_synrecv2link(tsr));
        /* RFC 793 tells us to send FIN and move to FIN-WAIT1 state.
         * However, Linux (and probably everybody else) does not do it. */
        ci_tcp_synrecv_free(ni, tsr);
        ret++;
      } while( OO_P_NOT_NULL(tsr_p) );
    }
  }
  ci_ni_aux_free(ni, CI_CONTAINER(ci_ni_aux_mem, u.bucket, bucket));

  return ret;
}


static void
ci_tcp_listenq_bucket_insert(ci_netif* ni, ci_tcp_socket_listen* tls,
                             ci_tcp_listen_bucket* bucket,
                             ci_tcp_state_synrecv* tsr, int level)
{
  ci_ni_aux_mem* aux;
  int idx = ci_tcp_listenq_hash2idx(tsr->hash, level);
  oo_p tsr_p = oo_ptr_to_statep(ni, CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr));
#ifdef __KERNEL__
  int i = 0;
#endif

  LOG_TV(ci_log("%s([%d] level=%d "TSR_FMT")", __func__,
                NI_ID(ni), level, TSR_ARGS(tsr)));

  if( OO_P_IS_NULL(bucket->bucket[idx]) ) {
    bucket->bucket[idx] = tsr_p;
    return;
  }

  level++;
  aux = ci_tcp_listenq_p2aux(ni, bucket->bucket[idx]);
  if( aux->type == CI_TCP_AUX_TYPE_BUCKET ) {
    ci_tcp_listenq_bucket_insert(ni, tls, &aux->u.bucket, tsr, level);
    return;
  }

  /* So, this bucket contains of a list of other synrecv states.  We add
   * our trs to this list and try to improve things by allocating
   * next-level bucket. */
  tsr->bucket_link = bucket->bucket[idx];
  bucket->bucket[idx] = tsr_p;

  if( level > CI_LISTENQ_BUCKET_MAX_DEPTH(ni) ||
      OO_P_IS_NULL(ni->state->free_aux_mem) )
    return;

  bucket->bucket[idx] = ni->state->free_aux_mem;
  bucket = ci_tcp_bucket_alloc(ni);
  tls->n_buckets++;

  while( OO_P_NOT_NULL(tsr_p) ) {
    tsr = &ci_tcp_listenq_p2aux(ni, tsr_p)->u.synrecv;
#ifdef __KERNEL__
    if( i++ > CI_LISTENQ_BUCKET_LIST_LIMIT(ni) ) {
      ci_tcp_listenq_bucket_insert(ni, tls, bucket, tsr, level);
      ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE,
                              __FUNCTION__);
      return;
    }
#endif
    tsr_p = tsr->bucket_link;
    tsr->bucket_link = OO_P_NULL;
    ci_tcp_listenq_bucket_insert(ni, tls, bucket, tsr, level);
  }
}

/* Return 1 if the bucket is empty now */
static int
ci_tcp_listenq_bucket_remove(ci_netif* ni, ci_tcp_socket_listen* tls,
                             ci_tcp_listen_bucket* bucket,
                             ci_tcp_state_synrecv* tsr, int level)
{
  ci_ni_aux_mem* aux;
  int idx = ci_tcp_listenq_hash2idx(tsr->hash, level);
  oo_p tsr_p = oo_ptr_to_statep(ni, CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr));

  /* Fixme: we remove empty buckets only.  In theory, it may be useful to
   * remove a bucket with one non-empty list, but it maked code more
   * complicated. */
  int empty = 0;
#ifdef __KERNEL__
  int i = 0;

  if( level > CI_LISTENQ_BUCKET_MAX_DEPTH(ni) ) {
    ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE, __FUNCTION__);
    return 0;
  }
#endif

  LOG_TV(ci_log("%s([%d] level=%d "TSR_FMT")", __func__,
                NI_ID(ni), level, TSR_ARGS(tsr)));
  ci_assert( OO_P_NOT_NULL(bucket->bucket[idx]) );
#ifdef __KERNEL__
  if( OO_P_IS_NULL(bucket->bucket[idx]) ) {
    ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE,
                            __FUNCTION__);
    return 0;
  }
#endif

  level++;
  aux = ci_tcp_listenq_p2aux(ni, bucket->bucket[idx]);
  if( aux->type == CI_TCP_AUX_TYPE_BUCKET ) {
    empty = ci_tcp_listenq_bucket_remove(ni, tls, &aux->u.bucket, tsr, level);
    if( empty ) {
      bucket->bucket[idx] = OO_P_NULL;
      ci_ni_aux_free(ni, aux);
      tls->n_buckets--;
    }
  }
  else {
    if( bucket->bucket[idx] == tsr_p ) {
      bucket->bucket[idx] = tsr->bucket_link;
      empty = OO_P_IS_NULL(bucket->bucket[idx]);
    }
    else {
      ci_tcp_state_synrecv* prev = &aux->u.synrecv;
      while( prev->bucket_link != tsr_p ) {
        aux = ci_tcp_listenq_p2aux(ni, prev->bucket_link);
        prev = &aux->u.synrecv;
#ifdef __KERNEL__
        if( i++ > CI_LISTENQ_BUCKET_LIST_LIMIT(ni) ) {
          ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE,
                                  __FUNCTION__);
          return 0;
        }
#endif
      }
      prev->bucket_link = tsr->bucket_link;
    }
  }

  if( empty ) {
    int i;
    for( i = 0; i < CI_TCP_LISTEN_BUCKET_SIZE; i++ )
      if( OO_P_NOT_NULL(bucket->bucket[i]) )
        return 0;
    return 1;
  }
  return 0;
}

static ci_tcp_state_synrecv*
ci_tcp_listenq_bucket_lookup(ci_netif* ni, ci_tcp_listen_bucket* bucket,
                             ciip_tcp_rx_pkt* rxp,
                             int level)
{
  ci_ni_aux_mem* aux;
  int idx = ci_tcp_listenq_hash2idx(rxp->hash, level);
  ci_tcp_state_synrecv* tsr;
  unsigned saddr, daddr, sport;
#ifdef __KERNEL__
  int i = 0;

  if( level > CI_LISTENQ_BUCKET_MAX_DEPTH(ni) ) {
    ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE,
                            __FUNCTION__);
    return 0;
  }
#endif

  LOG_TV(ci_log("%s([%d] level=%d hash:%x l:%s r:%s:%d)", __func__,
                NI_ID(ni), level, rxp->hash,
                ip_addr_str(oo_ip_hdr(rxp->pkt)->ip_daddr_be32),
                ip_addr_str(oo_ip_hdr(rxp->pkt)->ip_saddr_be32),
                CI_BSWAP_BE16(rxp->tcp->tcp_source_be16)));
  if( OO_P_IS_NULL(bucket->bucket[idx]) )
    return NULL;

  level++;
  aux = ci_tcp_listenq_p2aux(ni, bucket->bucket[idx]);
  if( aux->type == CI_TCP_AUX_TYPE_BUCKET )
    return ci_tcp_listenq_bucket_lookup(ni, &aux->u.bucket, rxp, level);

  saddr = oo_ip_hdr(rxp->pkt)->ip_saddr_be32;
  daddr = oo_ip_hdr(rxp->pkt)->ip_daddr_be32;
  sport = rxp->tcp->tcp_source_be16;

  tsr = &aux->u.synrecv;
  do {
    if( ! ((saddr - tsr->r_addr) | (daddr - tsr->l_addr) |
           (sport - tsr->r_port)) )
      return tsr;
    if( OO_P_IS_NULL(tsr->bucket_link) )
      return NULL;
    aux = ci_tcp_listenq_p2aux(ni, tsr->bucket_link);
    tsr = &aux->u.synrecv;
#ifdef __KERNEL__
    if( i++ > CI_LISTENQ_BUCKET_LIST_LIMIT(ni) ) {
      ci_netif_error_detected(ni, CI_NETIF_ERROR_SYNRECV_TABLE,
                              __FUNCTION__);
      return NULL;
    }
#endif
  } while(1);

  /* unreachable */
  return NULL;
}

static void
ci_tcp_listen_timer_set(ci_netif* ni, ci_tcp_socket_listen* tls,
                        ci_iptime_t timeout)
{
  int i;

  if( ! ci_ip_timer_pending(ni, &tls->listenq_tid) ) {
    ci_ip_timer_set(ni, &tls->listenq_tid, timeout);
    return;
  }

  for( i = 0; i <= CI_CFG_TCP_SYNACK_RETRANS_MAX; i++ ) {
    ci_tcp_state_synrecv* tsr =
        ci_tcp_link2synrecv(ci_ni_dllist_start(ni, &tls->listenq[i]));
    if( TIME_LT(tsr->timeout, timeout) )
      return;
  }
  ci_ip_timer_modify(ni, &tls->listenq_tid, timeout);
}


int ci_tcp_listenq_drop_all(ci_netif* ni, ci_tcp_socket_listen* tls)
{
  return
      ci_tcp_listenq_bucket_drop(ni,
                                 ci_tcp_listenq_p2bucket(ni, tls->bucket));
}

void ci_tcp_listenq_insert(ci_netif* ni, ci_tcp_socket_listen* tls,
                           ci_tcp_state_synrecv* tsr)
{
  int is_first;

  tls->n_listenq++;

  ci_tcp_listenq_bucket_insert(ni, tls,
                               ci_tcp_listenq_p2bucket(ni, tls->bucket),
                               tsr, 0);

  if( OO_SP_NOT_NULL(tsr->local_peer) )
    return;

  is_first = ci_ni_dllist_is_empty(ni, &tls->listenq[0]);
  ci_ni_dllist_push_tail(ni, &tls->listenq[0], ci_tcp_synrecv2link(tsr));
  tsr->retries = 0;
  tsr->timeout = ci_tcp_time_now(ni) + NI_CONF(ni).tconst_rto_initial;

  ++tls->n_listenq_new;
  if( is_first )
    ci_tcp_listen_timer_set(ni, tls, tsr->timeout);
}


void ci_tcp_listenq_remove(ci_netif* ni, ci_tcp_socket_listen* tls,
                           ci_tcp_state_synrecv* tsr)
{
  ci_assert(ni);
  ci_assert(tsr);
  ci_assert(tls);

  ci_tcp_listenq_bucket_remove(ni, tls,
                               ci_tcp_listenq_p2bucket(ni, tls->bucket),
                               tsr, 0);
  if( OO_SP_IS_NULL(tsr->local_peer) ) {
    ci_ni_dllist_remove(ni, ci_tcp_synrecv2link(tsr));

    if( (tsr->retries & CI_FLAG_TSR_RETRIES_MASK) == 0 )
      --tls->n_listenq_new;
  }

  /* cancel timer if no more synrecv on queue */
  if( --tls->n_listenq == 0 &&
     (~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) )
    ci_ip_timer_clear(ni, &tls->listenq_tid);
}

void ci_tcp_listenq_drop(ci_netif* ni, ci_tcp_socket_listen* tls,
                         ci_tcp_state_synrecv* tsr)
{
  /* ACKED means that the connection is in ESTABLISHED state.
   * We should reset it when dropping. */
  if( tsr->retries & CI_FLAG_TSR_RETRIES_ACKED ) {
    ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni);
    if( pkt != NULL )
      ci_tcp_synrecv_send(ni, tls, tsr, pkt,
                          CI_TCP_FLAG_RST | CI_TCP_FLAG_ACK, NULL);
  }
  ci_tcp_listenq_remove(ni, tls, tsr);
}


/*
** See if there is a synrecv object that matches this syn request already.
*/
ci_tcp_state_synrecv*
ci_tcp_listenq_lookup(ci_netif* netif, ci_tcp_socket_listen* tls,
                      ciip_tcp_rx_pkt* rxp)
{
  ci_tcp_state_synrecv* tsr;

  tsr = ci_tcp_listenq_bucket_lookup(
                        netif, ci_tcp_listenq_p2bucket(netif, tls->bucket),
                        rxp, 0);
  if( tsr == NULL ) {
    LOG_TV(log(LPF "no match for %s:%d->%s:%d",
               ip_addr_str(oo_ip_hdr(rxp->pkt)->ip_saddr_be32),
               (int) CI_BSWAP_BE16(rxp->tcp->tcp_source_be16),
               ip_addr_str(oo_ip_hdr(rxp->pkt)->ip_daddr_be32),
               (int) CI_BSWAP_BE16(rxp->tcp->tcp_dest_be16)));
  }

  return tsr;
}


void ci_tcp_listenq_drop_oldest(ci_netif* ni, ci_tcp_socket_listen* tls)
{
  ci_tcp_state_synrecv* tsr;
  int i;

  for( i = CI_CFG_TCP_SYNACK_RETRANS_MAX; i >= 0; --i ) {
    if( ci_ni_dllist_not_empty(ni, &tls->listenq[i]) )
      break;
  }
  ci_assert(ci_ni_dllist_not_empty(ni, &tls->listenq[i]));
  tsr = ci_tcp_link2synrecv(ci_ni_dllist_head(ni, &tls->listenq[i]));
  ci_tcp_listenq_drop(ni, tls, tsr);
  ci_tcp_synrecv_free(ni, tsr);
  CITP_STATS_NETIF(++ni->state->stats.synrecv_purge);
}


ci_inline ci_tcp_state*
get_ts_from_cache(ci_netif *netif, 
                  ci_tcp_state_synrecv* tsr, 
                  ci_tcp_socket_listen* tls)
{
  ci_tcp_state *ts = NULL;
#if CI_CFG_FD_CACHING
  if( ci_ni_dllist_not_empty(netif, &tls->epcache_cache) ) {
    /* Take the entry from the cache */
    ci_ni_dllist_link *link = ci_ni_dllist_pop(netif, &tls->epcache_cache);
    ts = CI_CONTAINER (ci_tcp_state, epcache_link, link);
    ci_assert (ts);
    ci_ni_dllist_self_link(netif, &ts->epcache_link);

    LOG_EP(ci_log("Taking cached fd %d off cached list, (onto acceptq)",
           ts->cached_on_fd));

    if( tcp_laddr_be32(ts) == tsr->l_addr ) {
      ci_tcp_state_init(netif, ts, 1);
      /* Shouldn't have touched these bits of state */
      ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
      ci_assert(ci_tcp_is_cached(ts));

      CITP_STATS_NETIF(++netif->state->stats.sockcache_hit);
      CITP_STATS_TCP_LISTEN(++tls->stats.n_sockcache_hit);
    }
    else {
      /* Oh dear -- the tcp-state we cached was using a different local IP
       * address.  This means we've accepted a connection from a different
       * interface as we did for the thing we've cached.  Which means we
       * can't share the hardware filter after all.  For now, just bung it
       * back on the list.
       */
      LOG_EP(ci_log("changed interface of cached EP, re-queueing"));
      ci_ni_dllist_push_tail(netif, &tls->epcache_cache, &ts->epcache_link);
      ts = NULL;
      CITP_STATS_NETIF(++netif->state->stats.sockcache_miss_intmismatch);
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
  ci_tcp_set_rcvbuf(ni, ts);      /* and amss, and rcv_wscl */

  {
    /* NB. We have exclusive access to [ts], so it is safe to manipulate
    ** s_aflags without using bit-ops. */
    unsigned inherited_sflags = CI_SOCK_AFLAG_TCP_INHERITED;
    unsigned inherited_sbflags = 0;

    if( NI_OPTS(ni).accept_inherit_nonblock )
      inherited_sbflags |= CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY;

    ci_assert((ts->s.s_aflags & inherited_sflags) == 0);
    ci_atomic32_or(&ts->s.s_aflags, s->s_aflags & inherited_sflags);

    if( NI_OPTS(ni).tcp_force_nodelay == 1 )
      ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);
    else if( NI_OPTS(ni).tcp_force_nodelay == 2 )
      ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT);

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


ci_inline void ci_tcp_set_addr_on_promote(ci_netif* netif, ci_tcp_state* ts,
                                          ci_tcp_state_synrecv* tsr,
                                          ci_tcp_socket_listen* tls)
{
  /* copy and initialise state */
  ts->s.pkt.ip.ip_saddr_be32 = tsr->l_addr;
  TS_TCP(ts)->tcp_source_be16 = sock_lport_be16(&tls->s);
  ts->s.cp.ip_laddr_be32 = tsr->l_addr;
  ts->s.cp.lport_be16 = sock_lport_be16(&tls->s);
  ci_tcp_set_peer(ts, tsr->r_addr, tsr->r_port);

  /* "filter" equivalent for loopback socket */
  if( OO_SP_NOT_NULL(tsr->local_peer) ) {
    ci_tcp_state *peer = ID_TO_TCP(netif, tsr->local_peer);
    ts->local_peer = tsr->local_peer;
    peer->local_peer = S_SP(ts);
  }
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
      if( ts == NULL ) {
        /* We've reaped.  Did this result in any being cached */
        ts = get_ts_from_cache(netif, tsr, tls);
        if (ts == NULL ) {
          /* No -- try again to allocate. */
          ts = ci_tcp_get_state_buf(netif);
        }
        else {
          CITP_STATS_NETIF(++netif->state->stats.sockcache_hit_reap);
        }
      }
#endif
      if( ts == NULL ) {
        LOG_TV(ci_log("%s: [%d] out of socket buffers",
                      __FUNCTION__, NI_ID(netif)));
        CITP_STATS_TCP_LISTEN(++tls->stats.n_acceptq_no_sock);
        CI_SET_SO_ERROR(&tls->s, ENOMEM);
        citp_waitable_wake(netif, &tls->s.b, CI_SB_FLAG_WAKE_RX);
        return -ENOMEM;
      }


      ci_assert(ci_tcp_is_cached(ts) ||
                (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
    }

#ifdef ONLOAD_OFE
    ts->s.ofe_code_start = tls->ofe_promote;
#endif

    if( ! ci_tcp_is_cached(ts) ) {
      /* Need to initialise address information for use when setting filters */
      ci_tcp_set_addr_on_promote(netif, ts, tsr, tls);

      /* "borrow" filter from listening socket.  For loopback socket, we
       * do not need filters, but we have to take a reference of the OS
       * socket. */
      rc = ci_tcp_ep_set_filters(netif, S_SP(ts), ts->s.cp.so_bindtodevice,
                                 S_SP(tls));
      if( rc < 0 ) {
        LOG_U(ci_log("%s: Unable to set filters %d", __FUNCTION__, rc));
        /* Either put this back on the list (at the head) or free it */
        ci_tcp_state_free(netif, ts);
        return rc;
      }
    }
#if CI_CFG_FD_CACHING
    else {
      /* Now set the s/w filter.  We leave the hw filter in place for cached
       * EPS. This will probably not have the correct raddr and rport, but as
       * it's sharing the listening socket's filter that's not a problem.  It
       * will be updated if this is still around when the listener is closed.
       */
      rc = ci_netif_filter_insert(netif, S_SP(ts), tsr->l_addr,
                                  sock_lport_be16(&tls->s), tsr->r_addr,
                                  tsr->r_port, tcp_protocol(ts));

      if (rc < 0) {
        /* Bung it back on the cache list */
        LOG_EP(ci_log("Unable to create s/w filter!"));
        ci_ni_dllist_push(netif, &tls->epcache_cache, &ts->epcache_link);
        return rc;
      }

      /* Need to initialise address information.  We do this after trying to
       * insert the sw filter, so we can push the tcp state back onto the
       * cache queue with as few changes as possible if we fail to add the
       * sw filter.
       */
      ci_tcp_set_addr_on_promote(netif, ts, tsr, tls);

      LOG_EP(ci_log("Cached fd %d from cached to connected", ts->cached_on_fd));
      ci_ni_dllist_push(netif, &tls->epcache_connected, &ts->epcache_link);
    }
#endif

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

    ts->amss = tsr->amss;

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
      ts->timed_ts = tsr->timest;
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

  return -ENOSPC;
}

/*! \cidoxg_end */
