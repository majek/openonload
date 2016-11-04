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
 * Common routines for timeout lists
 *
 *--------------------------------------------------------------------*/

/*! set or clear global netif "timeout state" timer */
ci_inline void ci_netif_timeout_set_timer(ci_netif* ni, ci_iptime_t prev_time)
{
  ci_iptime_t time = 0; /* shut up gcc */
  int i, found = 0;

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_tcp_state* ts;
    if( ci_ni_dllist_is_empty(ni, &ni->state->timeout_q[i]) )
      continue;
    ts = TCP_STATE_FROM_LINK(ci_ni_dllist_head(ni, &ni->state->timeout_q[i]));
    if( TIME_LE(ts->t_last_sent, prev_time) )
      return;
    if( !found || TIME_LT(ts->t_last_sent, time) ) {
      found = 1;
      time = ts->t_last_sent;
    }
  }
  /* We can be called both from timer handler (when the timer is not
   * running) and from RX handler (the timer is running).
   * Take care about all cases. */
  if( ! found )
    ci_ip_timer_clear(ni, &ni->state->timeout_tid);
  else if( ci_ip_timer_pending(ni, &ni->state->timeout_tid) )
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, time);
  else
    ci_ip_timer_set(ni, &ni->state->timeout_tid, time);
}


/*! add a state to the timeout list */
ci_inline void ci_netif_timeout_add(ci_netif* ni, ci_tcp_state* ts, int idx)
{
  int is_first;
  ci_ni_dllist_t* my_list = &ni->state->timeout_q[idx];
  ci_ni_dllist_t* other_list;
  ci_tcp_state* other_ts;

  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  is_first = ci_ni_dllist_is_empty(ni, my_list);
  ci_ni_dllist_push_tail(ni, my_list, &ts->timeout_q_link);

  /* Set up the timer */
  if( ! is_first )
    return;

  other_list = &ni->state->timeout_q[1-idx];
  if( ci_ni_dllist_is_empty(ni, other_list) ) {
    ci_ip_timer_set(ni, &ni->state->timeout_tid, ts->t_last_sent);
    return;
  }

  other_ts = TCP_STATE_FROM_LINK(ci_ni_dllist_head(ni, other_list));
  if( TIME_LT(ts->t_last_sent, other_ts->t_last_sent) )
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, ts->t_last_sent);
  else
    ci_ip_timer_modify(ni, &ni->state->timeout_tid, other_ts->t_last_sent);
}

/*! remove a state from the timeout list */
void ci_netif_timeout_remove(ci_netif* ni, ci_tcp_state* ts)
{
  int is_first, idx;

  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_orphan(ts));
  ci_assert( !ci_ni_dllist_is_free(&ts->timeout_q_link) );

  if( ts->s.b.state == CI_TCP_TIME_WAIT )
    idx = OO_TIMEOUT_Q_TIMEWAIT;
  else
    idx = OO_TIMEOUT_Q_FINWAIT;
  is_first = OO_P_EQ( ci_ni_dllist_link_addr(ni, &ts->timeout_q_link),
               ci_ni_dllist_link_addr(ni, ci_ni_dllist_head(ni,
                                                &ni->state->timeout_q[idx])) );

  /* remove from the list */
  ci_ni_dllist_remove(ni, &ts->timeout_q_link);
  ci_ni_dllist_mark_free(&ts->timeout_q_link);

  /* if needed re-set or clear timer */
  if( ! is_first )
    return;

  ci_netif_timeout_set_timer(ni, ts->t_last_sent);
}

/*! timeout a state from the list */
void ci_netif_timeout_leave(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
              ci_tcp_is_timeout_orphan(ts) );

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
/* todo: pass listening socket as a parameter
 * if we are satisfyed by a cached ep */
void ci_netif_timeout_reap(ci_netif* ni)
{
  int i;
  int reaped = 0;

  ci_assert(ni);
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(OO_SP_IS_NULL(ni->state->free_eps_head));

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];
    ci_ni_dllist_link* l;
    oo_p next;

    for( l = ci_ni_dllist_start(ni, list); l != ci_ni_dllist_end(ni, list);
         l = (void*) CI_NETIF_PTR(ni, next) ) {
      ci_tcp_state* ts = TCP_STATE_FROM_LINK(l);
      next = l->next;

#if CI_CFG_FD_CACHING
      if( ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_IN_CACHE) ) {
#else
      if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) {
#endif
        LOG_NV(log(LPF "Reaping %d from %s", S_FMT(ts), state_str(ts)));
        ci_netif_timeout_leave(ni, ts);
        CITP_STATS_NETIF(++ni->state->stats.timewait_reap);
        if( OO_SP_NOT_NULL(ni->state->free_eps_head) )
          return;

        /* We've probably reaped a cached connection,
         * but in some cases it can be used by the caller. */
        reaped = 1;
      }
    }
  }

  if( ! reaped )
    LOG_U(log(LPF "No more connections to reap from TIME_WAIT/FIN_WAIT2"));
}

/*! this is the timeout timer callback function */
void
ci_netif_timeout_state(ci_netif* ni)
{
  int i;

  LOG_NV(log(LPF "timeout state timer, now=0x%x", ci_ip_time_now(ni)));

  /* check last active state of each connection in TIME_WAIT */

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_link* lnk;
    ci_tcp_state* ts;
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];

    while( ci_ni_dllist_not_empty(ni, list) ) {
      lnk = ci_ni_dllist_head(ni, list);
      ts = TCP_STATE_FROM_LINK(lnk);
      ci_assert( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
                  ci_tcp_is_timeout_orphan(ts) );

      if( TIME_GT(ts->t_last_sent, ci_ip_time_now(ni)) )
        break; /* break from the inner loop */

      /* ci_netif_timeout_leave() calls ci_tcp_drop() calls
       * ci_netif_timeout_remove() which re-enables timer */
      ci_netif_timeout_leave(ni, ts);
    }
  }
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

void ci_netif_timeout_restart(ci_netif *ni, ci_tcp_state *ts)
{
  int is_tw = (ts->s.b.state == CI_TCP_TIME_WAIT);
  ci_assert(ts);
  ci_assert( is_tw || ci_tcp_is_timeout_orphan(ts));

  /* take it off the list */
  ci_netif_timeout_remove(ni, ts);
  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) +
      ( is_tw ?
        NI_CONF(ni).tconst_2msl_time : NI_CONF(ni).tconst_fin_timeout );
  /* add to list */
  ci_netif_timeout_add(
                ni, ts,
                is_tw ?  OO_TIMEOUT_Q_TIMEWAIT : OO_TIMEOUT_Q_FINWAIT);
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
  if ( ci_tcp_is_timeout_orphan(ts) ) {
    ci_netif_timeout_remove(ni, ts);
  }
  ci_assert( ci_ni_dllist_is_free(&ts->timeout_q_link) );

  ci_tcp_stop_timers(ni, ts);

  /* store time to leave TIMEWAIT state */
  ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
  /* add to list */
  ci_netif_timeout_add(ni, ts, OO_TIMEOUT_Q_TIMEWAIT);
}


int ci_netif_timewait_try_to_free_filter(ci_netif* ni)
{
  int i;
  int found = 0;

  ci_assert(ci_netif_is_locked(ni));

  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    ci_ni_dllist_t* list = &ni->state->timeout_q[i];
    ci_ni_dllist_link* l;
    oo_p next;

    for( l = ci_ni_dllist_start(ni, list); l != ci_ni_dllist_end(ni, list);
         l = (void*) CI_NETIF_PTR(ni, next) ) {
      ci_tcp_state* ts = TCP_STATE_FROM_LINK(l);
      next = l->next;

      if( ts->s.s_flags & CI_SOCK_FLAG_FILTER ) {
        /* No cached sockets here: orphaned or timewait only.
         * They really free the hw filter when we drop them. */
        ci_assert( (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ||
                   ts->s.b.state == CI_TCP_TIME_WAIT );

        ci_netif_timeout_leave(ni, ts);
        CITP_STATS_NETIF(++ni->state->stats.timewait_reap_filter);

        /* With EF10, there is no guarantee that the filter we've freed can
         * be reused for the filter parameters needed now.  Moreover, in most
         * cases it can't.
         * We reap ALL time-wait sockets in hope they'll help us.
         * Reaping finwait&friends is a more sensitive action - so we reap
         * one and go away. */
        if( i == OO_TIMEOUT_Q_FINWAIT )
          return 1;
        found = 1;
      }
    }
    if( found )
      return 1;
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
  /* check endpoint is an orphan */
#if CI_CFG_FD_CACHING
  ci_assert(ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN|CI_SB_AFLAG_IN_CACHE));
#else
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
#endif
  /* check state is correct */
  ci_assert(ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN);

  /* It's possible to come down this path twice in the caching case.  We can
   * queue a fin-timeout when the user socket is closed and the socket enters
   * the cache.  However, it if becomes a true orphan while still cached we
   * will come this way again, so need to avoid re-queueing.  At the point it
   * may have been removed from the cache (for example if clearing the cache
   * queue on listener shutdown), so we've lost it's history, so can't check
   * unfortunately.
   */
#if CI_CFG_FD_CACHING
  if( ci_ni_dllist_is_free(&ts->timeout_q_link) ) {
#else
  ci_assert(ci_ni_dllist_is_free(&ts->timeout_q_link));
#endif
    LOG_TC(log(LPF "%s: %d %s", __FUNCTION__, S_FMT(ts), state_str(ts)));
    /* store time to leave FIN_WAIT2 state */
    ts->t_last_sent = ci_ip_time_now(ni) + NI_CONF(ni).tconst_fin_timeout;
    ci_netif_timeout_add(ni, ts, OO_TIMEOUT_Q_FINWAIT);
#if CI_CFG_FD_CACHING
  }
#endif
}


static int ci_netif_try_to_reap_udp_recv_q(ci_netif* ni,
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


void ci_netif_try_to_reap(ci_netif* ni, int stop_once_freed_n)
{
  /* Look for packet buffers that can be reaped. */

  ci_ni_dllist_link* lnk;
  ci_ni_dllist_link* last;
  citp_waitable_obj* wo;
  int freed_n = 0;
  int add_to_reap_list;
  int reap_harder = ni->packets->sets_n == ni->packets->sets_max
      || ni->state->mem_pressure;

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
      ci_int32 q_num_b4 = ts->recv1.num;
      ci_tcp_rx_reap_rxq_bufs(ni, ts);

      freed_n += q_num_b4 - ts->recv1.num;
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &ts->timestamp_q,
                                                 &add_to_reap_list);

      /* Try to reap the last packet */
      if( reap_harder && ts->recv1.num == 1 &&
          ci_sock_trylock(ni, &ts->s.b) ) {
        q_num_b4 = ts->recv1.num;
        ci_tcp_rx_reap_rxq_bufs_socklocked(ni, ts);
        freed_n += q_num_b4 - ts->recv1.num;
        ci_sock_unlock(ni, &ts->s.b);
      }
      if( ts->recv1.num > 1 || add_to_reap_list)
        ci_ni_dllist_put(ni, &ni->state->reap_list, &ts->s.reap_link);
    }
    else if( wo->waitable.state == CI_TCP_STATE_UDP ) {
      ci_udp_state* us = &wo->udp;
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &us->recv_q,
                                                 &add_to_reap_list);
      freed_n += ci_netif_try_to_reap_udp_recv_q(ni, &us->timestamp_q,
                                                 &add_to_reap_list);

      if( add_to_reap_list )
        ci_ni_dllist_put(ni, &ni->state->reap_list, &us->s.reap_link);
    }
  } while( freed_n < stop_once_freed_n && &wo->sock.reap_link != last );

  if( freed_n < (stop_once_freed_n >> 1) ) {
    /* We do not get here from ci_netif_pkt_alloc_slow,
     * because it uses stop_once_freed_n=1. */
    freed_n += ci_netif_pkt_try_to_free(ni, 0, stop_once_freed_n - freed_n);
    if( freed_n < (stop_once_freed_n >> 1) && reap_harder ) {
      freed_n += ci_netif_pkt_try_to_free(ni, 1,
                                          stop_once_freed_n - freed_n);
    }
  }

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
  if( s->b.state == CI_TCP_STATE_UDP ) {
    ci_udp_recv_q_reap(ni, &SOCK_TO_UDP(s)->recv_q);
    ci_udp_recv_q_reap(ni, &SOCK_TO_UDP(s)->timestamp_q);
  }
  else if( s->b.state & CI_TCP_STATE_TCP_CONN ) {
    ci_tcp_rx_reap_rxq_bufs(ni, SOCK_TO_TCP(s));
    ci_udp_recv_q_reap(ni, &SOCK_TO_TCP(s)->timestamp_q);
  }

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
    n += (2*CI_CFG_RX_DESC_BATCH);
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
#ifdef __KERNEL__
  int is_locked = 1;
#endif
  while( ! OO_PP_IS_NULL(ni->state->mem_pressure_pkt_pool) ) {
    pkt = PKT(ni, ni->state->mem_pressure_pkt_pool);
    ni->state->mem_pressure_pkt_pool = pkt->next;
    --ni->state->mem_pressure_pkt_pool_n;
    ci_assert_equal(pkt->refcount, 0);
    ci_assert(pkt->flags & CI_PKT_FLAG_RX);
    ci_netif_pkt_free(ni, pkt CI_KERNEL_ARG(&is_locked));
  }
}


static void ci_netif_mem_pressure_enter_critical(ci_netif* ni, int intf_i)
{
  if( ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    return;

  CITP_STATS_NETIF_INC(ni, memory_pressure_enter);
  ni->state->mem_pressure |= OO_MEM_PRESSURE_CRITICAL;
  ni->state->rxq_limit = 2*CI_CFG_RX_DESC_BATCH;
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
      ni->packets->n_free < pkts_needed ) {
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
    while( ni->packets->n_free < pkts_needed ) {
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

static int __ci_netif_rx_post(ci_netif* ni, ef_vi* vi, int intf_i,
                               int bufset_id, int max)
{
  ci_ip_pkt_fmt* pkt;
  int i;
  int posted = 0;

  ci_assert_ge(max, CI_CFG_RX_DESC_BATCH);
  ci_assert_ge(ni->packets->set[bufset_id].n_free, max);

  do {
    for( i = 0; i < CI_CFG_RX_DESC_BATCH; ++i ) {
      /* We know we have free pkts, so this is faster than calling
      ** ci_netif_pkt_alloc().  Nasty, but this is really performance
      ** critical.
      */
      ci_assert(OO_PP_NOT_NULL(ni->packets->set[bufset_id].free));
      pkt = PKT(ni, ni->packets->set[bufset_id].free);
      ci_assert(OO_PP_EQ(ni->packets->set[bufset_id].free, OO_PKT_P(pkt)));
      ni->packets->set[bufset_id].free = pkt->next;
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
    ni->packets->set[bufset_id].n_free -= CI_CFG_RX_DESC_BATCH;
    ni->packets->n_free -= CI_CFG_RX_DESC_BATCH;
    ni->state->n_rx_pkts  += CI_CFG_RX_DESC_BATCH;
    ef_vi_receive_push(vi);
    posted += CI_CFG_RX_DESC_BATCH;
  } while( max - posted >= CI_CFG_RX_DESC_BATCH );

  return posted;
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
  int max_n_to_post, rx_allowed, n_to_post;
  int bufset_id = NI_PKT_SET(netif);
  int ask_for_more_packets = 0;

  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ci_netif_rx_vi_space(netif, vi) >= CI_CFG_RX_DESC_BATCH);

  max_n_to_post = ci_netif_rx_vi_space(netif, vi);
  rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
  if( max_n_to_post > rx_allowed )
    goto rx_limited;
 not_rx_limited:

  ci_assert_ge(max_n_to_post, CI_CFG_RX_DESC_BATCH);
  /* We could have enough packets in all sets together, but we need them
   * in one set. */
  if( netif->packets->set[bufset_id].n_free < CI_CFG_RX_DESC_BATCH )
    goto find_new_bufset;

 good_bufset:
  do {
    n_to_post = CI_MIN(max_n_to_post, netif->packets->set[bufset_id].n_free);
    max_n_to_post -= __ci_netif_rx_post(netif, vi, intf_i,
                                        bufset_id, n_to_post);
    ci_assert_ge(max_n_to_post, 0);

    if( max_n_to_post < CI_CFG_RX_DESC_BATCH ) {
      if( bufset_id != netif->packets->id ) {
        ci_netif_pkt_set_change(netif, bufset_id,
                                ask_for_more_packets);
      }
      CHECK_FREEPKTS(netif);
      return;
    }

 find_new_bufset:
    bufset_id = ci_netif_pktset_best(netif);
    if( bufset_id == -1 ||
        netif->packets->set[bufset_id].n_free < CI_CFG_RX_DESC_BATCH )
      goto not_enough_pkts;
    ask_for_more_packets = ci_netif_pkt_set_is_underfilled(netif,
                                                           bufset_id);
  } while( 1 );
  /* unreachable */


 rx_limited:
  /* [rx_allowed] can go negative. */
  if( rx_allowed < 0 )
    rx_allowed = 0;
  /* Only reap if ring is getting pretty empty. */
  if( ef_vi_receive_fill_level(vi) + rx_allowed < low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_rx_limited);
    ci_netif_try_to_reap(netif, max_n_to_post - rx_allowed);
    rx_allowed = NI_OPTS(netif).max_rx_packets - netif->state->n_rx_pkts;
    if( rx_allowed < 0 )
      rx_allowed = 0;
    max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
    if( ef_vi_receive_fill_level(vi) + max_n_to_post < low_thresh(netif) )
      /* Ask recv() path to refill when some buffers are freed. */
      netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi) - max_n_to_post;
    if( max_n_to_post >= CI_CFG_RX_DESC_BATCH )
      goto not_rx_limited;
  }
  if( netif->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL ) {
    /* We want to always be able to post a small number of buffers to
     * the rxq when in critical memory pressure as otherwise we may
     * drop packets that would release queued buffers.
     *
     * When we enter critical memory pressure we release a few packet
     * buffers for exactly this purpose, so make sure we can use them
     * here.
     */
    rx_allowed = CI_CFG_RX_DESC_BATCH;
    max_n_to_post = ci_netif_rx_vi_space(netif, vi);
  }
  max_n_to_post = CI_MIN(max_n_to_post, rx_allowed);
  if(CI_LIKELY( max_n_to_post >= CI_CFG_RX_DESC_BATCH ))
    goto not_rx_limited;
  CITP_STATS_NETIF_INC(netif, refill_rx_limited);
  if( ef_vi_receive_fill_level(vi) < CI_CFG_RX_DESC_BATCH )
    ci_netif_mem_pressure_enter_critical(netif, intf_i);
  return;

 not_enough_pkts:
  /* The best packet set has less than CI_CFG_RX_DESC_BATCH packets.
   * We should free some packets or allocate a new set. */

  /* Even if we free packets and find a good bufset, we'd better to
   * allocate more packets when time allows: */
  ask_for_more_packets = 1;

  /* Grab buffers from the non-blocking pool. */
  while( (pkt = ci_netif_pkt_alloc_nonb(netif)) != NULL ) {
    --netif->state->n_async_pkts;
    CITP_STATS_NETIF_INC(netif, pkt_nonb_steal);
    pkt->flags &= ~CI_PKT_FLAG_NONB_POOL;
    bufset_id = PKT_SET_ID(pkt);
    ci_netif_pkt_release_1ref(netif, pkt);
    if( netif->packets->set[bufset_id].n_free >= CI_CFG_RX_DESC_BATCH )
      goto good_bufset;
  }

  /* Still not enough -- allocate more memory if possible. */
  if( netif->packets->sets_n < netif->packets->sets_max &&
      ci_tcp_helper_more_bufs(netif) == 0 ) {
    bufset_id = netif->packets->sets_n - 1;
    ci_assert_equal(netif->packets->set[bufset_id].n_free,
                    1 << CI_CFG_PKTS_PER_SET_S);
    ask_for_more_packets = 0;
    goto good_bufset;
  }

  if( ef_vi_receive_fill_level(vi) < low_thresh(netif) ) {
    CITP_STATS_NETIF_INC(netif, reap_buf_limited);
    ci_netif_try_to_reap(netif, max_n_to_post);
    max_n_to_post = CI_MIN(max_n_to_post, netif->packets->n_free);
    bufset_id = ci_netif_pktset_best(netif);
    if( bufset_id != -1 &&
        netif->packets->set[bufset_id].n_free >= CI_CFG_RX_DESC_BATCH )
      goto good_bufset;
    /* Ask recv() path to refill when some buffers are freed. */
    netif->state->rxq_low = ci_netif_rx_vi_space(netif, vi);
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
#if CI_CFG_FD_CACHING && !defined(NDEBUG)
  /* Cached sockets should not be deferring work - there are no user references
   */
  if( (w->state & CI_TCP_STATE_TCP) && !(w->state == CI_TCP_LISTEN) )
    ci_assert(!ci_tcp_is_cached(&CI_CONTAINER(citp_waitable_obj,
                                              waitable, w)->tcp));
#endif
  /* Orphaned sockets should not be deferring work - no-one has a reference to
   * them, and the queue link can be used for other things.
   */
  ci_assert(!(w->sb_aflags & CI_SB_AFLAG_ORPHAN));

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
    ci_uint64 new_v, v = ni->state->lock.lock;
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
      if( ci_cas64u_succeed(&ni->state->lock.lock, v, new_v) ) {
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
  ci_uint64 l;

  ci_assert(ci_netif_is_locked(ni));

  while( (l = ni->state->lock.lock) & CI_EPLOCK_NETIF_SOCKET_LIST )
    if( ci_cas64u_succeed(&ni->state->lock.lock, l,
                        l &~ CI_EPLOCK_NETIF_SOCKET_LIST) )
      ci_netif_perform_deferred_socket_work(ni,
                                            l & CI_EPLOCK_NETIF_SOCKET_LIST);

  return l;
}

void ci_netif_merge_atomic_counters(ci_netif* ni)
{
  ci_int32 val;
#define merge(ni, field) \
  do {                                                          \
    val = ni->state->atomic_##field;                            \
  } while( ci_cas32_fail(&ni->state->atomic_##field, val, 0) );\
  ni->state->field += val;

  merge(ni, n_rx_pkts);
  merge(ni, n_async_pkts);
#undef merge
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
  ci_uint64 l = ni->state->lock.lock;
  int intf_i;
  ci_uint64 after_unlock_flags;

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

  if( l & CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS ) {
    ef_eplock_clear_flags(&ni->state->lock,
                          CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS);
    ci_netif_merge_atomic_counters(ni);
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
    if( ci_cas64u_succeed(&ni->state->lock.lock,
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
                ci_cas64u_succeed(&ni->state->lock.lock,
                                  CI_EPLOCK_LOCKED, CI_EPLOCK_UNLOCKED) ))
    return;
  CITP_STATS_NETIF_INC(ni, unlock_slow);
  ci_netif_unlock_slow(ni KERNEL_DL_CONTEXT);
}


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


#ifndef __KERNEL__
int ci_netif_get_ready_list(ci_netif* ni)
{
  int i = 0;

  /* First list is used for eps not in a set */
  ci_netif_lock(ni);
  while( i++ < CI_CFG_N_READY_LISTS ) {
    if( !((ni->state->ready_lists_in_use >> i) & 1) ) {
      ni->state->ready_lists_in_use |= 1 << i;
      break;
    }
  }
  ci_netif_unlock(ni);

  return i < CI_CFG_N_READY_LISTS ? i : 0;
}
#endif


void ci_netif_put_ready_list(ci_netif* ni, int id)
{
  ci_ni_dllist_link* lnk;
  citp_waitable* w;

  ci_assert(ni->state->ready_lists_in_use & (1 << id));
  ci_assert_nequal(id, 0);

  if( ci_netif_lock(ni) != 0 ) {
    ci_log("epoll: Leaking ready list [%d:%d]", NI_ID(ni), id);
    return;
  }
  while( ci_ni_dllist_not_empty(ni, &ni->state->ready_lists[id]) ) {
    lnk = ci_ni_dllist_pop(ni, &ni->state->ready_lists[id]);
    w = CI_CONTAINER(citp_waitable, ready_link, lnk);

    ci_ni_dllist_self_link(ni, lnk);
    w->ready_list_id = 0;
  }
  ni->state->ready_lists_in_use &= ~(1 << id);
  ci_netif_unlock(ni);
}


#ifndef __KERNEL__
int ci_netif_raw_send(ci_netif* ni, int intf_i,
                      const ci_iovec *iov, int iovlen)
{
  ci_ip_pkt_fmt* pkt;
  ci_uint8* p;
  int i;

  ci_netif_lock(ni);
  pkt = ci_netif_pkt_alloc(ni);
  if( pkt == NULL )
    return -ENOBUFS;

  pkt->intf_i = intf_i;
  if( intf_i < 0 || intf_i >= CI_CFG_MAX_INTERFACES )
    return -ENETDOWN;

  pkt->pkt_start_off = 0;
  pkt->buf_len = 0;
  p = pkt->dma_start;
  for( i = 0; i < iovlen; i++ ) {
    if( p + CI_IOVEC_LEN(iov) - pkt->dma_start >
        CI_CFG_PKT_BUF_SIZE - sizeof(pkt) ) {
      ci_netif_pkt_release(ni, pkt);
      ci_netif_unlock(ni);
      return -EMSGSIZE;
    }

    memcpy(p, CI_IOVEC_BASE(iov), CI_IOVEC_LEN(iov));
    p += CI_IOVEC_LEN(iov);
    pkt->buf_len += CI_IOVEC_LEN(iov);
    iov++;
  }

  pkt->pay_len = pkt->buf_len;
  ci_netif_pkt_hold(ni, pkt);
  ci_netif_send(ni, pkt);
  ci_netif_pkt_release(ni, pkt);

  ci_netif_unlock(ni);
  return 0;
}


/* By using ports from the active wild pool we can potentially be re-using
 * ports very quickly, including to the same remote addr/port.  In that case
 * we may overlap with an earlier incarnation that's still in TIME-WAIT, so
 * we need to ensure that we don't cause the peer to think we're reopening
 * that connection.
 *
 * To do that we record the details of the last closed connection on this port
 * in a way that would leave the peer in TIME-WAIT (if we're in TIME-WAIT we
 * won't re-use the port, as we still have a sw filter for the 4-tuple, if
 * the connection is reset then we're ok).
 *
 * When we assign a new port we check if we expect the peer to be out of
 * TIME-WAIT by now (assuming they're using the same length of timer as us).
 * If so we can give them a new active wild port as usual.  If not, we'll
 * keep looking (potentially increasing the pool).
 */
static int __ci_netif_active_wild_allow_reuse(ci_netif* ni, ci_active_wild* aw,
                                              unsigned laddr, unsigned raddr,
                                              unsigned rport)
{
  if( ci_ip_time_now(ni) > aw->expiry )
    return 1;
  else
    return (aw->last_laddr != laddr) || (aw->last_raddr != raddr) ||
           (aw->last_rport != rport);
}


static oo_sp __ci_netif_active_wild_get(ci_netif* ni, unsigned laddr,
                                        unsigned raddr, unsigned rport,
                                        ci_uint16* port_out,
                                        ci_uint32* prev_seq_out)
{
  ci_active_wild* aw;
  ci_uint16 lport;
  int rc;

  ci_assert(ci_netif_is_locked(ni));

  *prev_seq_out = 0;

  ci_ni_dllist_link* link = NULL;
  ci_ni_dllist_link* tail = ci_ni_dllist_tail(ni,
                                              &ni->state->active_wild_pool);

  /* This can happen if active wilds are configured, but we failed to allocate
   * any at stack creation time, for example because there were no filters
   * available.
   */
  if( ci_ni_dllist_is_empty(ni, &ni->state->active_wild_pool) )
    return OO_SP_NULL;

  while( link != tail ) {
    link = ci_ni_dllist_pop(ni, &ni->state->active_wild_pool);
    ci_ni_dllist_push_tail(ni, &ni->state->active_wild_pool, link);

    aw = CI_CONTAINER(ci_active_wild, pool_link, link);

    lport = sock_lport_be16(&aw->s);
    rc = ci_netif_filter_lookup(ni, laddr, lport, raddr, rport,
                                sock_protocol(&aw->s));

    if( rc >= 0 ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, ni->filter_table->table[rc].id);
      if( s->b.state == CI_TCP_TIME_WAIT ) {
        /* This 4-tuple is in use as TIME_WAIT, but it is safe to re-use
         * TIME_WAIT for active open.  We ensure we use an initial sequence
         * number that is a long way from the one used by the old socket.
         */
        ci_tcp_state* ts = SOCK_TO_TCP(s);
        CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_reused_tw);
        *prev_seq_out = ts->snd_nxt;
        ci_netif_timeout_leave(ni, ts);
        *port_out = lport;
        return SC_SP(&aw->s);
      }
    }

    /* If no-one's using this 4-tuple we can let the caller share this
     * active wild.
     */
    if( rc == -ENOENT &&
        __ci_netif_active_wild_allow_reuse(ni, aw, laddr, raddr, rport) ) {
      *port_out = lport;
      return SC_SP(&aw->s);
    }
  }

  return OO_SP_NULL;
}


oo_sp ci_netif_active_wild_get(ci_netif* ni, unsigned laddr,
                               unsigned raddr, unsigned rport,
                               ci_uint16* port_out, ci_uint32* prev_seq_out)
{
  oo_sp active_wild;

  ci_assert(ci_netif_is_locked(ni));

  if( NI_OPTS(ni).tcp_shared_local_ports == 0 )
    return OO_SP_NULL;

  active_wild = __ci_netif_active_wild_get(ni, laddr, raddr, rport,
                                           port_out, prev_seq_out);

  /* If we failed to get an active wild try and grow the pool */
  if( active_wild == OO_SP_NULL &&
      ni->state->active_wild_n < NI_OPTS(ni).tcp_shared_local_ports_max ) {
    LOG_TC(ci_log(FN_FMT "Didn't get active wild on first try, getting more",
                  FN_PRI_ARGS(ni)));
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_grow);
    ci_tcp_helper_alloc_active_wild(ni);
    active_wild = __ci_netif_active_wild_get(ni, laddr, raddr, rport,
                                             port_out, prev_seq_out);
  }

  if( active_wild != OO_SP_NULL ) {
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_used);
    LOG_TC(ci_log(FN_FMT "Lookup active wild for %s:0 %s:%u FOUND - lport %u",
                  FN_PRI_ARGS(ni), ip_addr_str(laddr), ip_addr_str(raddr),
                  htons(rport), htons(*port_out)));
  }
  else {
    CITP_STATS_NETIF_INC(ni, tcp_shared_local_ports_exhausted);
    LOG_TC(ci_log(FN_FMT "Lookup active wild for %s:0 %s:%u NOT AVAILABLE",
                FN_PRI_ARGS(ni), ip_addr_str(laddr), ip_addr_str(raddr),
                htons(rport)));
  }
  return active_wild;
}
#endif

/* See comment on __ci_netif_active_wild_allow_reuse() to explain the reason
 * we need this.
 */
void ci_netif_active_wild_sharer_closed(ci_netif* ni, ci_sock_cmn* s)
{
  int rc;
  oo_sp id;
  ci_active_wild* aw;

  rc = ci_netif_filter_lookup(ni, sock_laddr_be32(s), sock_lport_be16(s),
                              0, 0, sock_protocol(s));

  if( rc >= 0 ) {
    id = CI_NETIF_FILTER_ID_TO_SOCK_ID(ni, rc);
    aw = SP_TO_ACTIVE_WILD(ni, id);
    ci_assert(aw->s.b.state == CI_TCP_STATE_ACTIVE_WILD);
    aw->expiry = ci_ip_time_now(ni) + NI_CONF(ni).tconst_2msl_time;
    aw->last_laddr = sock_laddr_be32(s);
    aw->last_raddr = sock_raddr_be32(s);
    aw->last_rport = sock_rport_be16(s);
  }
}


/*! \cidoxg_end */
