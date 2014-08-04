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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2003/08/18
** Description: General network interface routines.
** </L5_PRIVATE>
\**************************************************************************/

#include "ip_internal.h"

#define LPF "NETIF "

#if CI_CFG_DETAILED_CHECKS
char* CI_NETIF_PTR(ci_netif* ni, oo_p off)
{
  ASSERT_VALID_NETIF_ADDR(ni, off, 1);
  return __CI_NETIF_PTR(ni, off);
}
#endif


/*--------------------------------------------------------------------
 *
 * Common routines for timeout list
 *
 *--------------------------------------------------------------------*/

/*! set global netif "timeout state" timer */
ci_inline void ci_netif_timeout_set_timer(ci_netif* ni)
{
  ci_tcp_state* ts;

  ci_assert( !ci_ni_dllist_is_empty(ni, &ni->state->timeout_q) );
  ts = TCP_STATE_FROM_LINK(ci_ni_dllist_head(ni, &ni->state->timeout_q));
  /* ts->t_last_sent is now time we want to timeout this state */
  ci_ip_timer_set(ni, &ni->state->timeout_tid, ts->t_last_sent);
}


/*! clear global netif "timeout state" timer */
ci_inline void ci_netif_timeout_clear_timer(ci_netif* ni)
{
  ci_assert( ci_ni_dllist_is_empty(ni, &ni->state->timeout_q) );
  ci_ip_timer_clear(ni, &ni->state->timeout_tid);
}


/*! add a state to the timeout list */
ci_inline void ci_netif_timeout_add(ci_netif* ni, ci_tcp_state* ts)
{
  ci_ni_dllist_link* link;
  ci_tcp_state* link_ts;
  ci_ni_dllist_t* list = &ni->state->timeout_q;

  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  /* run backwards through the list to find out where to insert */
  for( link = ci_ni_dllist_start_last(ni, list);
       link != ci_ni_dllist_end(ni, list);
       ci_ni_dllist_backiter(ni, link) ) {
    link_ts = TCP_STATE_FROM_LINK(link);
    if ( TIME_GE(ts->t_last_sent, link_ts->t_last_sent) )
      break;
  }
  ci_ni_dllist_insert_after(ni, link, &ts->timeout_q_link);

  /* if we've now the head of the list */
  if( &ts->timeout_q_link == ci_ni_dllist_head(ni, list) ) {
    /* if we've not the tail then list must have been non-empty */
    if( &ts->timeout_q_link != ci_ni_dllist_tail(ni, list) )
      ci_ip_timer_clear(ni, &ni->state->timeout_tid);
    ci_netif_timeout_set_timer(ni);
  }
}

/*! remove a state from the timeout list */
void ci_netif_timeout_remove(ci_netif* ni, ci_tcp_state* ts)
{
  /* WIN32: ci_tcp_is_timeout_ophan() does not check for orphaned EP */
  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_ophan(ts));
  ci_assert( !ci_ni_dllist_is_free(&ts->timeout_q_link) );

  /* remove from the list */
  ci_ni_dllist_remove(ni, &ts->timeout_q_link);
  CI_DEBUG(ci_ni_dllist_mark_free(&ts->timeout_q_link));

  /* if needed clear timer */
  if( ci_ni_dllist_is_empty(ni, &ni->state->timeout_q) )
    ci_netif_timeout_clear_timer(ni);
}

/*! timeout a state from the list */
void ci_netif_timeout_leave(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  /* WIN32: ci_tcp_is_timeout_ophan() does not check for orphaned EP */
  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_ophan(ts) );

#ifndef NDEBUG
  if (ts->s.b.state == CI_TCP_TIME_WAIT)
      LOG_TC(log(LPF "%d TIME_WAIT->CLOSED (2MSL expired)", S_FMT(ts)));
  else
      LOG_TC(log(LPF "%d Droping ORPHANed %s", S_FMT(ts), state_str(ts)));
#endif

  /* drop will call ci_netif_timeout_remove;
   * See bug 10638 for details about CI_SHUT_RD */
  ci_tcp_drop(netif, ts, 0);
}

/*! called to try and free up a connection from
    this list when we are low on tcp states */
int ci_netif_timeout_reap(ci_netif* ni)
{
  ci_tcp_state* ts;
  ci_assert(ni);
  ci_assert(OO_SP_IS_NULL(ni->state->free_eps_head));

  /* TODO check a connection is orphaned before trying to reap it
   * - a non-orphaned one will not yield its tcp_state for re-use */

  while( OO_SP_IS_NULL(ni->state->free_eps_head) ) {

    if(ci_ni_dllist_is_empty(ni, &ni->state->timeout_q)){
      LOG_U(log(LPF "No more connections to reap from TIME_WAIT/FIN_WAIT2"));
      return 0;
    }

    ts = TCP_STATE_FROM_LINK(
            ci_ni_dllist_head(ni, &ni->state->timeout_q));
    LOG_NV(log(LPF "Reaping %d from %s", S_FMT(ts), state_str(ts)));
    ci_netif_timeout_leave(ni, ts);
    CITP_STATS_NETIF(++ni->state->stats.timewait_reap);

#if CI_CFG_FD_CACHING
    if (ts->cached_on_fd != -1) {
      /* This was a cached EP; will have been returned to the cache */
      return 2;
    }
#endif
  }

  return 1;
}

/*! this is the timeout timer callback function */
void
ci_netif_timeout_state(ci_netif* ni)
{
  ci_ni_dllist_link* lnk;
  ci_tcp_state* ts;
  ci_iptime_t now = ci_ip_time_now(ni);

  LOG_NV(log(LPF "timeout state timer, now=0x%x", now));

  /* check last active state of each connection in TIME_WAIT */

  while( ci_ni_dllist_not_empty(ni, &ni->state->timeout_q) ) {
    lnk = ci_ni_dllist_head(ni, &ni->state->timeout_q);
    ts = TCP_STATE_FROM_LINK(lnk);
    /* WIN32: ci_tcp_is_timeout_ophan() does not check for orphaned EP */
    ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
                ci_tcp_is_timeout_ophan(ts) );

    if( TIME_LE(ts->t_last_sent, now) ){
      ci_netif_timeout_leave(ni, ts);
      /* Don't need to clear the timeout timer here as it's not set if
         it's just timed out! */
    }
    else {
      ci_netif_timeout_set_timer(ni);
      return;
    }
  }
  /* the queue is empty, so no need to restart the timer. */
  ci_assert(!ci_ip_timer_pending(ni, &ni->state->timeout_tid));
}

/*--------------------------------------------------------------------
 *
 * TIME_WAIT handling
 *
 *--------------------------------------------------------------------*/

/* restart a timewait state
 * - remove from timeout list
 * - store time to leave TIMEOUT state
 * - add back onto timeout list
 */

void ci_netif_timewait_restart(ci_netif *ni, ci_tcp_state *ts)
{
  ci_assert(ts);
  ci_assert(ts->s.b.state == CI_TCP_TIME_WAIT);

  /* take it off the list */
  ci_netif_timeout_remove(ni, ts);
  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
  /* add to list */
  ci_netif_timeout_add(ni, ts);
}


/*
** - add a connection to the timewait queue,
** - stop its timers
*/
void ci_netif_timewait_enter(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ts);

  /* If we're entering time-wait, then our FIN has been acked, so send-q
   * and retrans-q should be empty.  We've received and processed an
   * incoming FIN, so reorder buffer has already been purged by
   * ci_tcp_rx_process_fin().
   */
  ci_assert(ci_tcp_sendq_is_empty(ts));
  ci_assert(ci_ip_queue_is_empty(&ts->retrans));
  ci_assert(ci_ip_queue_is_empty(&ts->rob));

  /* called before the state is changed to TIME_WAIT */
  ci_assert(ts->s.b.state != CI_TCP_TIME_WAIT);
  /* if already in the timeout list */
  /* WIN32: ci_tcp_is_timeout_ophan() does not check for orphaned EP */
  if ( ci_tcp_is_timeout_ophan(ts) ) {
    ci_netif_timeout_remove(ni, ts);
  }
  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  ci_tcp_stop_timers(ni, ts);

  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
  /* add to list */
  ci_netif_timeout_add(ni, ts);
}


int ci_netif_timewait_try_to_free_filter(ci_netif* ni)
{
  ci_ni_dllist_t* list = &ni->state->timeout_q;
  ci_ni_dllist_link* l;

  ci_assert(ci_netif_is_locked(ni));

  for( l = ci_ni_dllist_start(ni, list); l != ci_ni_dllist_end(ni, list);
       ci_ni_dllist_iter(ni, l) ) {
    ci_tcp_state* ts = TCP_STATE_FROM_LINK(l);
    if( ts->s.b.state != CI_TCP_TIME_WAIT )  continue;
    if( ts->s.s_flags & CI_SOCK_FLAG_FILTER ) {
      ci_netif_timeout_leave(ni, ts);
      CITP_STATS_NETIF(++ni->state->stats.timewait_reap_filter);
      return 1;
    }
  }

  return 0;
}


/*--------------------------------------------------------------------
 *
 * FIN_WAIT2 handling
 *
 *--------------------------------------------------------------------*/

/*! add a state to the fin timeout list */
void ci_netif_fin_timeout_enter(ci_netif* ni, ci_tcp_state* ts)
{
  /* For Windows we have to be able to timeout when in FIN_WAIT2 but not
   * orphaned so that we can re-use the socket post-disconnectex */
  /* check endpoint is an orphan */
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
  /* check state is correct */
  ci_assert(ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN);
  /* and not already in the list */
  ci_assert(ci_ni_dllist_is_free(&ts->timeout_q_link));

  LOG_TC(log(LPF "%s: %d %s", __FUNCTION__, S_FMT(ts), state_str(ts)));
  /* store time to leave FIN_WAIT2 state */
  ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_fin_timeout;
  ci_netif_timeout_add(ni, ts);
}


static int ci_netif_try_to_reap_udp(ci_netif* ni, ci_udp_state* udp,
                                    ci_udp_recv_q* recv_q, 
                                    int* add_to_reap_list)
{
  int freed_n;
  ci_uint32 reaped_b4 = recv_q->pkts_reaped;
  ci_udp_recv_q_reap(ni, recv_q);
  freed_n = recv_q->pkts_reaped - reaped_b4;
  if( recv_q->pkts_reaped != recv_q->pkts_added )
    ++(*add_to_reap_list);
  return freed_n;
}


static int ci_netif_try_to_reap_timestamp_q(ci_netif* ni, 
                                            struct ci_sock_cmn_s* s,
                                            int* add_to_reap_list)
{
  ci_ip_pkt_queue* tsq = &s->timestamp_q;
  int tsq_num_before = tsq->num;

  ci_assert(ci_netif_is_locked(ni));

  while( ! OO_PP_EQ(tsq->head, s->timestamp_q_extract) ) {
    ci_ip_pkt_fmt* pkt = PKT_CHK(ni, tsq->head);
    oo_pkt_p next = pkt->tsq_next;

    ci_netif_pkt_release(ni, pkt);
    --tsq->num;
    tsq->head = next;
  }

  if( tsq->num > 1 )
    ++(*add_to_reap_list);
  return tsq_num_before - tsq->num;
}


void ci_netif_try_to_reap(ci_netif* ni, int stop_once_freed_n)
{
  /* Look for packet buffers that can be reaped. */

  ci_ni_dllist_link* lnk;
  ci_ni_dllist_link* last;
  citp_waitable_obj* wo;
  int freed_n = 0;
  int add_to_reap_list;

  if( ci_ni_dllist_is_empty(ni, &ni->state->reap_list) )
    return;

  /* Caller has told us how many packet buffers it needs.  But really we
   * should reap more -- otherwise we can get into a steady state of not
   * having enough free buffers around.
   */
  stop_once_freed_n <<= 1u;

  lnk = ci_ni_dllist_start(ni, &ni->state->reap_list);
  last = ci_ni_dllist_start_last(ni, &ni->state->reap_list);

  do {
    add_to_reap_list = 0;

    wo = CI_CONTAINER(citp_waitable_obj, sock.reap_link, lnk);
    lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next);
    ci_ni_dllist_remove_safe(ni, &wo->sock.reap_link);

    if( wo->waitable.state & CI_TCP_STATE_TCP_CONN ) {
      ci_tcp_state* ts = &wo->tcp;
      int q_num_b4 = ts->recv1.num;
      ci_tcp_rx_reap_rxq_bufs(ni, ts);
      freed_n += q_num_b4 - ts->recv1.num;
      freed_n += ci_netif_try_to_reap_timestamp_q(ni, &ts->s,
                                                  &add_to_reap_list);
      if( ts->recv1.num > 1 || add_to_reap_list)
        ci_ni_dllist_put(ni, &ni->state->reap_list, &ts->s.reap_link);
    }
    else if( wo->waitable.state == CI_TCP_STATE_UDP ) {
      ci_udp_state* us = &wo->udp;
      freed_n += ci_netif_try_to_reap_udp(ni, us, &us->recv_q,
                                          &add_to_reap_list);
      freed_n += ci_netif_try_to_reap_timestamp_q(ni, &us->s,
                                                  &add_to_reap_list);
      if( add_to_reap_list )
        ci_ni_dllist_put(ni, &ni->state->reap_list, &us->s.reap_link);
    }
  } while( freed_n < stop_once_freed_n && &wo->sock.reap_link != last );

  CITP_STATS_NETIF_ADD(ni, pkts_reaped, freed_n);
}


void ci_netif_rxq_low_on_recv(ci_netif* ni, ci_sock_cmn* s,
                              int bytes_freed)
{
  /* Called by the recv() paths when [ni->state->rxq_low] is non-zero.  It
   * is moderately hard to track exactly how many packet buffers were freed
   * by the recv() call, so we approximate by assuming approx standard-mtu
   * sized packets.
   *
   * [bytes_freed] may be negative or zero.  This is just to save the
   * caller a little work.
   */
  int intf_i;
  if( bytes_freed <= 0 ||
      (ni->state->rxq_low -= (bytes_freed / 1500 + 1)) > 0 )
    return;
  if( ! ci_netif_trylock(ni) ) {
    /* TODO: Probably better to defer the work of refilling to lock holder. */
    ni->state->rxq_low = 1;
    return;
  }
  /* Multiple threads can do the above decrement concurrently, so [rxq_low]
   * can go negative.  If it does, we want to reset to zero to avoid
   * hitting this path constantly.
   */
  ni->state->rxq_low = 0;

  /* We've just received from [s], so very likely to have buffers 'freed'
   * and ripe for reaping.  ci_netif_rx_post() will also try to reap more
   * buffers from other sockets if necessary.
   */
  if( s->b.state == CI_TCP_STATE_UDP )
    ci_udp_recv_q_reap(ni, &SOCK_TO_UDP(s)->recv_q);
  else if( s->b.state & CI_TCP_STATE_TCP_CONN )
    ci_tcp_rx_reap_rxq_bufs(ni, SOCK_TO_TCP(s));

  if( ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    /* See if we've freed enough to exit memory pressure.  Done here so
     * we'll fill the rings properly below if we succeed in exiting.
     */
    if( ci_netif_mem_pressure_try_exit(ni) )
      CITP_STATS_NETIF_INC(ni, memory_pressure_exit_recv);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ci_netif_rx_vi_space(ni, ci_netif_rx_vi(ni, intf_i))
        >= CI_CFG_RX_DESC_BATCH )
      ci_netif_rx_post(ni, intf_i);
  CITP_STATS_NETIF_INC(ni, rx_refill_recv);
  ci_netif_unlock(ni);
}


void ci_netif_mem_pressure_pkt_pool_fill(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int intf_i, n = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    n += CI_CFG_RX_DESC_BATCH;
  while( ni->state->mem_pressure_pkt_pool_n < n &&
         (pkt = ci_netif_pkt_alloc(ni)) != NULL ) {
    pkt->flags |= CI_PKT_FLAG_RX;
    ++ni->state->n_rx_pkts;
    ++ni->state->mem_pressure_pkt_pool_n;
    pkt->refcount = 0;
    pkt->next = ni->state->mem_pressure_pkt_pool;
    ni->state->mem_pressure_pkt_pool = OO_PKT_P(pkt);
  }
}


static void ci_netif_mem_pressure_pkt_pool_use(ci_netif* ni)
{
  /* Empty the special [mem_pressure_pkt_pool] into the free pool. */
  ci_ip_pkt_fmt* pkt;
  while( ! OO_PP_IS_NULL(ni->state->mem_pressure_pkt_pool) ) {
    pkt = PKT(ni, ni->state->mem_pressure_pkt_pool);
    ni->state->mem_pressure_pkt_pool = pkt->next;
    --ni->state->mem_pressure_pkt_pool_n;
    ci_assert_equal(pkt->refcount, 0);
    ci_assert(pkt->flags & CI_PKT_FLAG_RX);
    ci_netif_pkt_free(ni, pkt);
  }
}


static void ci_netif_mem_pressure_enter_critical(ci_netif* ni, int intf_i)
{
  if( ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    return;

  CITP_STATS_NETIF_INC(ni, memory_pressure_enter);
  ni->state->mem_pressure |= OO_MEM_PRESSURE_CRITICAL;
  ni->state->rxq_limit = CI_CFG_RX_DESC_BATCH;
  ci_netif_mem_pressure_pkt_pool_use(ni);
  if( ci_netif_rx_vi_space(ni, ci_netif_rx_vi(ni, intf_i)) >=
      CI_CFG_RX_DESC_BATCH )
    ci_netif_rx_post(ni, intf_i);
}


static void ci_netif_mem_pressure_exit_critical(ci_netif* ni)
{
  ci_assert(OO_PP_IS_NULL(ni->state->mem_pressure_pkt_pool));
  ci_netif_mem_pressure_pkt_pool_fill(ni);
  ni->state->rxq_limit = NI_OPTS(ni).rxq_limit;
  ni->state->mem_pressure &= ~OO_MEM_PRESSURE_CRITICAL;
}


int ci_netif_mem_pressure_try_exit(ci_netif* ni)
{
  /* Exit memory pressure only when there are enough packet buffers free
   * (and available to RX path) to be able to fill all of the RX rings.
   *
   * Returns true if we do exit critical memory pressure.
   */
  int intf_i, pkts_needed = 0;
  ci_ip_pkt_fmt* pkt;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ef_vi* vi = ci_netif_rx_vi(ni, intf_i);
    pkts_needed += NI_OPTS(ni).rxq_limit - ef_vi_receive_fill_level(vi);
  }

  if( NI_OPTS(ni).max_rx_packets - ni->state->n_rx_pkts < pkts_needed ||
      ni->state->n_freepkts < pkts_needed ) {
    /* TODO: May not be necessary in future, as rxq_low should be set, and
     * should provoke the recv() path to free packet bufs.  For now this is
     * needed though.
     */
    ci_netif_try_to_reap(ni, pkts_needed);

    if( NI_OPTS(ni).max_rx_packets - ni->state->n_rx_pkts < pkts_needed )
      return 0;

    /* The RX packet limit is okay, but do we have enough free buffers?
     * Take from async pool if not.
     *
     * TODO: Be more efficient here by grabbing the whole pool, taking what
     * we need, and put back.
     */
    while( ni->state->n_freepkts < pkts_needed ) {
      if( (pkt = ci_netif_pkt_alloc_nonb(ni)) == NULL )
        return 0;
      --ni->state->n_async_pkts;
      CITP_STATS_NETIF_INC(ni, pkt_nonb_steal);
      pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
      ci_netif_pkt_release_1ref(ni, pkt);
    }
  }

  ci_netif_mem_pressure_exit_critical(ni);
  return 1;
}


/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

static void __ci_netif_rx_post(ci_netif* ni, ef_vi* vi, int intf_i, int max)
{
  ci_ip_pkt_fmt* pkt;
  int i;

  ci_assert_ge(max, CI_CFG_RX_DESC_BATCH);
  ci_assert_ge(ni->state->n_freepkts, max);

  do {
    for( i = 0; i < CI_CFG_RX_DESC_BATCH; ++i ) {
      /* We know we have free pkts, so this is faster than calling
      ** ci_netif_pkt_alloc().  Nasty, but this is really performance
      ** critical.
      */
      ci_assert(OO_PP_NOT_NULL(ni->state->freepkts));
      pkt = PKT(ni, ni->state->freepkts);
      ci_assert(OO_PP_EQ(ni->state->freepkts, OO_PKT_P(pkt)));
      ni->state->freepkts = pkt->next;
      pkt->refcount = 1;
      pkt->flags |= CI_PKT_FLAG_RX;
      pkt->intf_i = intf_i;
      pkt->pkt_start_off = ef_vi_receive_prefix_len(vi);
      ef_vi_receive_init(vi, pkt->dma_addr[pkt->intf_i], OO_PKT_ID(pkt));
#ifdef __powerpc__
      {
        /* Flush RX buffer from cache.  This saves significant latency when
         * data is DMAed into the buffer (on ppc at least).
         *
         * TODO: I think the reason we're seeing dirty buffers is because
         * TX buffers are being recycled into the RX ring.  Might be better
         * to segregate buffers so that doesn't happen so much.
         *
         * TODO: See if any benefit/downside to enabling on x86.  (Likely
         * to be less important on systems with DDIO).
         */
        int off;
        for( off = 0; off < pkt->buf_len; off += EF_VI_DMA_ALIGN )
          ci_clflush(pkt->dma_start + off);
        /* This seems like a good idea (only flush buffer if it was last
         * used for TX) but it seems to make latency worse by around 30ns:
         *
         *   pkt->buf_len = 0;
         */
      }
#endif
    }
    ni->state->n_freepkts -= CI_CFG_RX_DESC_BATCH;
    ni->state->n_rx_pkts  += CI_CFG_RX_DESC_BATCH;
    ef_vi_receive_push(vi);
    max -= CI_CFG_RX_DESC_BATCH;
  } while( max >= CI_CFG_RX_DESC_BATCH );
}


#define low_thresh(ni)       ((ni)->state->rxq_limit / 2)


void ci_netif_rx_post(ci_netif* netif, int intf_i)
{
  /* TODO: When under packet buffer pressure, post fewer on the receive
  ** queue.  As an easy first stab could have a threshold for the number of
  ** free buffers, and not post any on receive queue when below that level.
  **
  ** It would also be sensible to not post (many) more buffers than can
  ** possibly be consumed by existing sockets receive windows.  This would
  ** reduce resource consumption for apps that have few sockets.
  */
  ef_vi* vi = ci_netif_rx_vi(netif, intf_i);
  ci_ip_pkt_fmt* pkt;
  int max_n_to_post, rx_allowed;

  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ci_netif_rx_vi_space(netif, vi) >= CI_CFG_RX_DESC_BATCH);

  max_n_to_post = ci_netif_rx_vi_space(netif, vi);
  rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
  if( max_n_to_post > rx_allowed )
    goto rx_limited;
 not_rx_limited:

  if( netif->state->n_freepkts < max_n_to_post )
    goto not_enough_pkts;
 enough_pkts:

  ci_assert_ge(max_n_to_post, CI_CFG_RX_DESC_BATCH);
  ci_assert_le(max_n_to_post, netif->state->n_freepkts);
  __ci_netif_rx_post(netif, vi, intf_i, max_n_to_post);
  CHECK_FREEPKTS(netif);
  return;


 rx_limited:
  /* [rx_allowed] can go negative. */
  if( rx_allowed < 0 )
    rx_allowed = 0;
  /* Only reap if ring is getting pretty empty. */
  if( ef_vi_receive_fill_level(vi) + rx_allowed < low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_rx_limited);
    ci_netif_try_to_reap(netif, max_n_to_post - rx_allowed);
    rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
    max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
    if( ef_vi_receive_fill_level(vi) + max_n_to_post < low_thresh(netif) )
      /* Ask recv() path to refill when some buffers are freed. */
      netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi) - max_n_to_post;
    if( max_n_to_post >= CI_CFG_RX_DESC_BATCH )
      goto not_rx_limited;
  }
  max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
  if(CI_LIKELY( max_n_to_post >= CI_CFG_RX_DESC_BATCH ))
    goto not_rx_limited;
  CITP_STATS_NETIF_INC(netif, refill_rx_limited);
  if( ef_vi_receive_fill_level(vi) < CI_CFG_RX_DESC_BATCH )
    ci_netif_mem_pressure_enter_critical(netif, intf_i);
  return;

 not_enough_pkts:
#if ! CI_CFG_PP_IS_PTR
  /* Grab buffers from the non-blocking pool. */
  while( (pkt = ci_netif_pkt_alloc_nonb(netif)) != NULL ) {
    --netif->state->n_async_pkts;
    CITP_STATS_NETIF_INC(netif, pkt_nonb_steal);
    pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
    ci_netif_pkt_release_1ref(netif, pkt);
    if( netif->state->n_freepkts >= max_n_to_post )
      goto enough_pkts;
  }
#endif

  /* Still not enough -- allocate more memory if possible. */
  while( netif->state->pkt_sets_n < netif->state->pkt_sets_max ) {
    int old_n_freepkts = netif->state->n_freepkts;
    ci_tcp_helper_more_bufs(netif);
    if( old_n_freepkts == netif->state->n_freepkts ) {
#ifndef __KERNEL__
      ci_assert_equal(netif->state->pkt_sets_n, netif->state->pkt_sets_max);
#else
      /* Probably, we are in atomic context and can not allocate more
       * buffers just now. */
      tcp_helper_resource_t *trs = netif2tcp_helper_resource(netif);
      if( netif->state->pkt_sets_n ==  netif->state->pkt_sets_max )
        break;
      ci_assert(netif->flags & CI_NETIF_FLAG_IN_DL_CONTEXT);
      ci_assert(netif->flags & CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION);
      if( OO_STACK_NEEDS_MORE_PACKETS(netif) )
        queue_work(trs->wq, &trs->non_atomic_work);
      if( netif->state->n_freepkts >= CI_CFG_RX_DESC_BATCH &&
          netif->state->n_freepkts >=
            CI_MIN(4 * CI_CFG_RX_DESC_BATCH,
                   NI_OPTS(netif).free_packets_low / 2)
        ) {
        max_n_to_post = netif->state->n_freepkts;
        goto enough_pkts;
      }
      return;
#endif
    }
    if( netif->state->n_freepkts >= max_n_to_post )
      goto enough_pkts;
  }

  if( ef_vi_receive_fill_level(vi) + netif->state->n_freepkts <
      low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_buf_limited);
    ci_netif_try_to_reap(netif, max_n_to_post - netif->state->n_freepkts);
    max_n_to_post = CI_MIN(max_n_to_post, netif->state->n_freepkts);
    if( ef_vi_receive_fill_level(vi) + max_n_to_post < low_thresh(netif) )
      /* Ask recv() path to refill when some buffers are freed. */
      netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi) - max_n_to_post;
    if( max_n_to_post >= CI_CFG_RX_DESC_BATCH )
      goto enough_pkts;
  }

  if( netif->state->n_freepkts >= CI_CFG_RX_DESC_BATCH ) {
    max_n_to_post = netif->state->n_freepkts;
    goto enough_pkts;
  }

  CITP_STATS_NETIF_INC(netif, refill_buf_limited);
  if( ef_vi_receive_fill_level(vi) < CI_CFG_RX_DESC_BATCH )
    ci_netif_mem_pressure_enter_critical(netif, intf_i);
}


static void citp_waitable_deferred_work(ci_netif* ni, citp_waitable* w)
{
  citp_waitable_obj* wo = CI_CONTAINER(citp_waitable_obj, waitable, w);

  if( wo->waitable.state & CI_TCP_STATE_TCP )
    ci_tcp_perform_deferred_socket_work(ni, &wo->tcp);
#if CI_CFG_UDP
  else if( wo->waitable.state == CI_TCP_STATE_UDP )
    ci_udp_perform_deferred_socket_work(ni, &wo->udp);
#endif
  else {
    /* This happens when we move socket and continue to use it from another
     * thread or signal handler */
    ci_log("%s: unexpected status %s for socket [%d:%d]", __func__,
           ci_tcp_state_str(wo->waitable.state), NI_ID(ni), w->bufid);
  }
}


int ci_netif_lock_or_defer_work(ci_netif* ni, citp_waitable* w)
{
  if( ni->state->defer_work_count >= NI_OPTS(ni).defer_work_limit ) {
    int rc = ci_netif_lock(ni);
    if( rc == 0 ) {
      CITP_STATS_NETIF_INC(ni, defer_work_limited);
      citp_waitable_deferred_work(ni, w);
      return 1;
    }
    /* We got a signal while waiting for the stack lock.  Best thing to do
     * here is to just go ahead and defer the work despite exceeding the
     * limit.  (Returning the error to the caller is much more complex).
     */
  }

  if( ci_bit_test_and_set(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT) ) {
    /* Already set.  Another thread is guaranteed to either (a) put this
     * socket on the deferred list and the stack lock holder will do our
     * work on unlock; or (b) lock the stack lock and do our work.
     */
    ++ni->state->defer_work_count;
    return 0;
  }

  while( 1 ) {
    unsigned new_v, v = ni->state->lock.lock;
    if( v & CI_EPLOCK_UNLOCKED ) {
      if( ci_netif_trylock(ni) ) {
        ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT);
        citp_waitable_deferred_work(ni, w);
        return 1;
      }
    }
    else {
      ci_assert(w->next_id == CI_ILL_END);
      w->next_id = v & CI_EPLOCK_NETIF_SOCKET_LIST;
      new_v = (v & ~CI_EPLOCK_NETIF_SOCKET_LIST) | (W_ID(w) + 1);
      if( ci_cas32_succeed(&ni->state->lock.lock, v, new_v) ) {
        ++ni->state->defer_work_count;
        return 0;
      }
      CI_DEBUG(w->next_id = CI_ILL_END);
    }
  }
}


static void ci_netif_perform_deferred_socket_work(ci_netif* ni,
                                                  unsigned sock_id)
{
  citp_waitable* w;
  oo_sp sockp;

  ci_assert(ci_netif_is_locked(ni));

  do {
    ci_assert(sock_id > 0);
    --sock_id;
    sockp = OO_SP_FROM_INT(ni, sock_id);
    w = SP_TO_WAITABLE(ni, sockp);
    sock_id = w->next_id;
    CI_DEBUG(w->next_id = CI_ILL_END);
    ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_DEFERRED_BIT);
    CITP_STATS_NETIF(++ni->state->stats.deferred_work);

    citp_waitable_deferred_work(ni, w);
  }
  while( sock_id > 0 );
}


unsigned ci_netif_purge_deferred_socket_list(ci_netif* ni)
{
  unsigned l;

  ci_assert(ci_netif_is_locked(ni));

  while( (l = ni->state->lock.lock) & CI_EPLOCK_NETIF_SOCKET_LIST )
    if( ci_cas32_succeed(&ni->state->lock.lock, l,
                        l &~ CI_EPLOCK_NETIF_SOCKET_LIST) )
      ci_netif_perform_deferred_socket_work(ni,
                                            l & CI_EPLOCK_NETIF_SOCKET_LIST);

  return l;
}

#ifdef __KERNEL__
#define KERNEL_DL_CONTEXT_DECL , int in_dl_context
#define KERNEL_DL_CONTEXT , in_dl_context
#else
#define KERNEL_DL_CONTEXT_DECL
#define KERNEL_DL_CONTEXT
#endif

static void ci_netif_unlock_slow(ci_netif* ni KERNEL_DL_CONTEXT_DECL)
{
#ifndef __KERNEL__
  /* All we are doing here is seeing if we can avoid a syscall.  Everything
  ** we do here has to be checked again if we do take the
  ** efab_eplock_unlock_and_wake() path, so no need to do this stuff if
  ** already in kernel.
  */
  int l = ni->state->lock.lock;
  int intf_i;
  unsigned after_unlock_flags;

  ci_assert(ci_netif_is_locked(ni));  /* double unlock? */

  if( l & CI_EPLOCK_NETIF_IS_PKT_WAITER )
    if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
      ef_eplock_clear_flags(&ni->state->lock, CI_EPLOCK_NETIF_IS_PKT_WAITER);
      ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_PKT_WAKE);
      l = ni->state->lock.lock;
      CITP_STATS_NETIF_INC(ni, unlock_slow_pkt_waiter);
    }

  if( l & CI_EPLOCK_NETIF_SOCKET_LIST ) {
    CITP_STATS_NETIF_INC(ni, unlock_slow_socket_list);
    l = ci_netif_purge_deferred_socket_list(ni);
  }
  ci_assert(! (l & CI_EPLOCK_NETIF_SOCKET_LIST));
  /* OK to clear this before dropping the lock here, as not in a loop */
  ni->state->defer_work_count = 0;

  if( l & CI_EPLOCK_NETIF_NEED_POLL ) {
    CITP_STATS_NETIF(++ni->state->stats.deferred_polls);
    ef_eplock_clear_flags(&ni->state->lock, CI_EPLOCK_NETIF_NEED_POLL);
    ci_netif_poll(ni);
    l = ni->state->lock.lock;
  }

  /* Store NEED_PRIME flag and clear it - we'll handle it if set,
   * either below or by dropping to the kernel 
   */
  after_unlock_flags = l;
  if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME )
    ef_eplock_clear_flags(&ni->state->lock, CI_EPLOCK_NETIF_NEED_PRIME);

  /* Could loop here if flags have been set again, but to keep things
   * simple just drop to the kernel unless we've already done
   * everything we needed to do
   */

  if( !(l & (CI_EPLOCK_NETIF_UNLOCK_FLAGS |
             CI_EPLOCK_NETIF_SOCKET_LIST |
             CI_EPLOCK_FL_NEED_WAKE)) ) {
    if( ci_cas32_succeed(&ni->state->lock.lock,
                         l, (l &~ CI_EPLOCK_LOCKED) | CI_EPLOCK_UNLOCKED) ) {
      /* If the NEED_PRIME flag was set, handle it here */
      if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME ) {
        CITP_STATS_NETIF_INC(ni, unlock_slow_need_prime);
        ci_assert(NI_OPTS(ni).int_driven);
        /* TODO: When interrupt driven, evq_primed is never cleared, so we
         * don't know here which subset of interfaces needs to be primed.
         * Would be more efficient if we did.
         */
        OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
          ef_eventq_prime(&ni->nic_hw[intf_i].vi);
      }

      /* We've handled everything we needed to, so can return without
       * dropping to the kernel 
       */
      return;
    }
  }

  /* We cleared NEED_PRIME above, but haven't handled it - restore setting */
  if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME )
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_PRIME);

#endif

  {
    int rc;

#ifndef __KERNEL__
    ci_assert(ni->state->lock.lock & CI_EPLOCK_LOCKED);
    ci_assert(~ni->state->lock.lock & CI_EPLOCK_UNLOCKED);
    CITP_STATS_NETIF_INC(ni, unlock_slow_syscall);
    rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_EPLOCK_WAKE, NULL);
#else
    rc = efab_eplock_unlock_and_wake(ni, in_dl_context);
#endif

    if( rc < 0 )  LOG_NV(ci_log("%s: rc=%d", __FUNCTION__, rc));
  }
}


void ci_netif_unlock(ci_netif* ni)
{
#ifdef __KERNEL__
  int in_dl_context = ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT;

  ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
#endif

  ci_assert_equal(ni->state->in_poll, 0);
  if(CI_LIKELY( ni->state->lock.lock == CI_EPLOCK_LOCKED &&
                ci_cas32_succeed(&ni->state->lock.lock,
                                 CI_EPLOCK_LOCKED, CI_EPLOCK_UNLOCKED) ))
    return;
  CITP_STATS_NETIF_INC(ni, unlock_slow);
  ci_netif_unlock_slow(ni KERNEL_DL_CONTEXT);
}


#if  !defined(__KERNEL__) && !defined(CI_HAVE_OS_NOPAGE)
int ci_netif_mmap_shmbuf(ci_netif* netif, int shmbufid)
{
  void* p;
  int rc;

  ci_assert(netif);

  if(CI_UNLIKELY( netif->u_shmbufs[shmbufid] == NULL )) {
    /* Map a buffer of epbufs into userland. */
    rc = oo_resource_mmap(ci_netif_get_driver_handle(netif), 0,
                          CI_NETIF_MMAP_ID_PAGE(shmbufid - 1),
                          EP_BUF_BLOCKPAGES * CI_PAGE_SIZE, &p);
    if( rc < 0 )  return -EINVAL;

    netif->u_shmbufs[shmbufid] = (char*) p;
  }

  return 0;
}
#endif


void ci_netif_error_detected(ci_netif* ni, unsigned error_flag,
                             const char* caller)
{
  if( ni->error_flags & error_flag )
    return;
  ci_log("%s: ERROR: [%d] runtime error %x detected in %s()",
         __FUNCTION__, NI_ID(ni), error_flag, caller);
  ci_log("%s: ERROR: [%d] errors detected: %x %x "CI_NETIF_ERRORS_FMT,
         __FUNCTION__, NI_ID(ni), ni->error_flags, ni->state->error_flags,
         CI_NETIF_ERRORS_PRI_ARG(ni->error_flags | ni->state->error_flags));
  ni->error_flags |= error_flag;
  ni->state->error_flags |= ni->error_flags;
}

/*! \cidoxg_end */
