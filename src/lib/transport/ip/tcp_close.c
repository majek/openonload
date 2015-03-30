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
** \author  djr/ctk
**  \brief  TCP connection routines:
**          accept, bind, close, connect, shutdown, getpeername
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#if defined(__linux__) && defined(__KERNEL__)
# include <onload/linux_onload.h>
#endif
#include <onload/sleep.h>
#include <onload/tmpl.h>

#define LPF "tcp_close: "



/* Transform a listening socket back to a normal socket. */
void __ci_tcp_listen_to_normal(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  citp_waitable_obj* wo = SOCK_TO_WAITABLE_OBJ(&tls->s);

  ci_assert(tls->n_listenq == 0);
  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);
  ci_assert_equal(ci_tcp_acceptq_not_empty(tls), 0);

  if( ~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN )
    ci_ip_timer_clear(netif, &tls->listenq_tid);
  ci_ni_dllist_remove_safe(netif, &tls->s.b.post_poll_link);
  ci_tcp_state_reinit(netif, &wo->tcp);
}


static int ci_tcp_add_fin(ci_tcp_state* ts, ci_netif* netif)
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr *tcp_hdr;

  ci_assert(ci_netif_is_locked(netif));

  LOG_TC(log(FNTS_FMT "sendq_num=%d cork=%d", FNTS_PRI_ARGS(netif, ts),
             sendq->num, !!(ts->s.s_aflags & CI_SOCK_AFLAG_CORK)));

  if( sendq->num ) {
    /* Bang the fin on the end of the send queue. */
    pkt = PKT_CHK(netif, sendq->tail);
    tcp_hdr = TX_PKT_TCP(pkt);
    tcp_hdr->tcp_flags |= CI_TCP_FLAG_FIN;
    tcp_enq_nxt(ts) += 1;
    pkt->pf.tcp_tx.end_seq = tcp_enq_nxt(ts);
    if( SEQ_LE(pkt->pf.tcp_tx.end_seq, ts->snd_max) )
      /* It may now be possible to push data that was delayed by TCP_CORK
       * or MSG_MORE.
       */
      ci_tcp_tx_advance(ts, netif);
    return 0;
  }

#ifdef __KERNEL__
  /* In theory we could call ci_netif_pkt_alloc_block() here (if the caller
   * passes can_block=1), but the pain of trying to recover from the case
   * where it drops the lock and can't retake it makes it desirable to
   * avoid that case, even if it means we more frequently fail to get
   * a packet 
   */
  pkt = ci_netif_pkt_alloc(netif);
#else
  {
    int is_locked = 1;
    pkt = ci_netif_pkt_alloc_block(netif, &ts->s, &is_locked);
    --netif->state->n_async_pkts;
    if (is_locked == 0)
      ci_netif_lock(netif);
    ci_assert(pkt != NULL);
  }
#endif

  if( pkt )
    ci_tcp_enqueue_no_data(ts, netif, pkt);
  else {
    LOG_U(log(LNTS_FMT "%s: out of pkt bufs",
              LNTS_PRI_ARGS(netif, ts), __FUNCTION__));
    return ENOBUFS;
  }
  return 0;
}


int __ci_tcp_shutdown(ci_netif* netif, ci_tcp_state* ts, int how)
{
  int rc;

  /* Behaviour of shutdown() on Linux is a bit eccentric.
  **
  ** SHUT_RD seems to put recv()s into a non-blocking mode: If no data
  ** available, return 0, else return the data.  ie. It doesn't prevent
  ** further data getting through.
  */

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(netif));

  /* Free up any associated templated sends */
  if( how == SHUT_WR || how == SHUT_RDWR )
    ci_tcp_tmpl_free_all(netif, ts);

  /* "Not connected" here means a FIN has gone both ways.  ie. TIME-WAIT,
  ** CLOSED, CLOSING, LAST-ACK.  Also LISTEN and SYN-SENT of course.
  */
  if( ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED ) {
    switch( ts->s.b.state ) {
    case CI_TCP_SYN_SENT:
      ci_tcp_drop(netif, ts, ECONNRESET);
      ts->s.rx_errno = ENOTCONN;
      return 0;

    case CI_TCP_CLOSING:
    case CI_TCP_LAST_ACK:
      /* already shut down */
      return 0;

    default:
      return -ENOTCONN;
    }
  }

  /* SHUT_RD case */
  if( how == SHUT_RD ) {
    ts->s.rx_errno = CI_SHUT_RD;
    ci_tcp_wake_not_in_poll(netif, ts, CI_SB_FLAG_WAKE_RX);
    return 0;
  }


  /* Now we should do SHUT_WR; set CI_SHUT_RD  also if necessary */
  if( ! (ts->s.b.state & CI_TCP_STATE_CAN_FIN) ) {
    if( how == SHUT_RDWR ) {
      ts->s.rx_errno = CI_SHUT_RD;
      ci_tcp_wake_not_in_poll(netif, ts, CI_SB_FLAG_WAKE_RX);
    }
    return 0;
  }

  /* Minimise race condtion with spinning poll/select/epoll:
   * ci_tcp_set_slow_state() sets write event, so we set read event just
   * after this.  See bug 22390. */
  ci_tcp_set_flags(ts, CI_TCP_FLAG_FIN | CI_TCP_FLAG_ACK);
  if( ts->s.b.state == CI_TCP_CLOSE_WAIT )
    ci_tcp_set_slow_state(netif, ts, CI_TCP_LAST_ACK);
  else
    ci_tcp_set_slow_state(netif, ts, CI_TCP_FIN_WAIT1);
  /* if not tied to an fd, make sure we leave this state at some point */
  if( ts->s.b.sb_aflags & (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_IN_CACHE) )
    ci_netif_fin_timeout_enter(netif, ts);

  if( how == SHUT_RDWR )
    ts->s.rx_errno = CI_SHUT_RD;
  ts->s.tx_errno = EPIPE;

  /* Add the FIN now. */
  if( (rc = ci_tcp_add_fin(ts, netif)) != 0 ) {
    LOG_E(ci_log("%s: failed to enqueue FIN, error %d", __FUNCTION__, rc));
    /* Drop the connection to avoid it getting stuck in LAST-ACK. Note
     * that this is far from ideal as we're breaking the TCP state
     * diagram, but there's not a lot of choice in this scenario.
     * It's not as bad as you might think though: we can only really
     * get here in-kernel (as we do not block in kernel mode),
     * which mainly means we've come from all_fds_gone which has found
     * a socket in acceptq that is not an orphan, so the bad case is
     * limited in scope.
     */
    ci_tcp_drop(netif, ts, 0);
    CITP_STATS_NETIF_INC(netif, tcp_drop_cant_fin);
   }

  ci_tcp_wake_not_in_poll(netif, ts,
                          CI_SB_FLAG_WAKE_TX |
                          (how == SHUT_RDWR ? CI_SB_FLAG_WAKE_RX : 0));
  return 0;
}


#if CI_CFG_FD_CACHING
#ifdef __KERNEL__
#include <onload/linux_onload_internal.h>

ci_inline void clear_cached_state(ci_tcp_state *ts)
{
  ci_atomic32_and(&ts->s.b.sb_aflags, ~CI_SB_AFLAG_IN_CACHE);
  ts->cached_on_fd = -1;
  ts->cached_on_pid = -1;
}


/* Uncache an EP.
 * This unsets the cache related state:
 * - cached_on_fd
 * - cached_on_pid
 * - removes from cache queue
 * - removes filters if we're in a state where they would otherwise have been
 *   removed already
 * - frees fd
 * It should now be handled as normal when we process the close via all fds
 * gone.
 */
static void uncache_ep(ci_netif *netif, ci_tcp_socket_listen* tls,
                       ci_tcp_state *ts)
{
  int fd = ts->cached_on_fd;
  int pid = ts->cached_on_pid;

  LOG_EP(ci_log("Uncaching ep %d on pid %d running pid %d", fd,
                pid, current->tgid));
  ci_assert( ci_tcp_is_cached(ts) );

  ci_ni_dllist_link_assert_valid(netif, &ts->epcache_link);
  ci_ni_dllist_remove_safe(netif, &ts->epcache_link);
  
  /* EPs on the cached list have hw filters present, even though notionally
   * they are 'freed'.  So we clear filters here.  Note that we leave the
   * filters in place for cached EPs on the acceptq or pending lists because
   * they still need to be closed down, and in the non-cached case have
   * filters.  We can tell whether the EP is on the cached list as opposed to
   * pending or accept-q, because it will be in the closed state if and only
   * if it is on the cache list.
   */
  if (ts->s.b.state == CI_TCP_CLOSED)
    ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);

  /* After we clear CI_SB_AFLAG_IN_CACHE flag, we are not
   * ci_tcp_is_timeout_orphan() any more.  Do not confuse other
   * parts of code: get out from timewait list. */
  if ( ci_tcp_is_timeout_orphan(ts) )
    ci_netif_timeout_remove(netif, ts);

  clear_cached_state(ts);

  /* No tasklets or other bottom-halves - we always have "current" */
  ci_assert(current);

  if(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) {
    /* Already released the fd, just free endpoint */
    /* Fixme: what about timewait? */
    efab_tcp_helper_close_endpoint(netif2tcp_helper_resource(netif),
                                   S_SP(ts));
  }
  else if( pid != current->tgid ) {
    NI_LOG(netif, RESOURCE_WARNINGS,
           "%s: pid mismatch: cached_on_pid=%d current=%d", __func__,
           pid, current->tgid);
  }
  else if( ~current->flags & PF_EXITING ) {
    /* If the process is exiting, there is nothing to do.
     * Otherwise, we try to close fd. */
    /* There is peril here.  We don't currently have the NO_FD flag set, so
     * close the fd via the kernel - hope that the fd isn't currently being
     * replaced.  We can't tell whether this has happened, as we can't rely
     * on the close having completed on kernels using deferred fput.  It's
     * probably feasible to handle this with some furtling with the fdtable,
     * but for now we just don't handle that case.
     *
     * It is also possible that we are called inside another process from
     * the stack unlock hook.
     */
    /* Fixme: we re-enter timewait and restart the timer.  It is wrong.
     * We should reuse already-calculated values which were in use before
     * we've called ci_netif_timeout_remove() above. */
    struct file* filp;

    if( current->files != NULL ) {
      filp = fget(fd);
      if( filp == NULL ) {
        NI_LOG(netif, RESOURCE_WARNINGS,
               "%s: pid %d does not has cached file under fd=%d",
                __func__, fd, pid);
      }
      else if( filp->f_op != &linux_tcp_helper_fops_tcp ) {
        NI_LOG(netif, RESOURCE_WARNINGS,
               "%s: pid %d has unexpected file under fd=%d",
                __func__, fd, pid);
        fput(filp);
      }
      else {
        fput(filp);
        efab_linux_sys_close(fd);
      }
    }
    else {
      NI_LOG(netif, RESOURCE_WARNINGS,
             "%s: called from workqueue - can not close "
             "file descriptor %d.", __func__, fd);
    }
  }

  ci_atomic32_inc(&netif->state->cache_avail_stack);
  ci_atomic32_inc(&tls->cache_avail_sock);

  ci_assert_le(netif->state->cache_avail_stack,
               netif->state->opts.sock_cache_max);
  ci_assert_le(tls->cache_avail_sock,
               netif->state->opts.per_sock_cache_max);
}


static void
uncache_list(ci_netif *netif, ci_tcp_socket_listen* tls,
             ci_ni_dllist_t *thelist)
{
  ci_ni_dllist_link *l = ci_ni_dllist_start (netif, thelist);
  while (l != ci_ni_dllist_end (netif, thelist)) {
    ci_tcp_state *cached_state = CI_CONTAINER (ci_tcp_state, epcache_link, l);
    ci_ni_dllist_iter (netif, l);

    /* We don't free up cached state directly.  We call uncache_ep, which will
     * close the fd, resulting in all_fds_gone being called, and we'll tidy up
     * from there.
     */
    ci_assert(cached_state);
    ci_assert(ci_tcp_is_cached(cached_state));
    ci_ni_dllist_link_assert_valid(netif, &cached_state->epcache_link);
    uncache_ep(netif, tls, cached_state);
  }
}


/* Drop the socket cache by freeing up epcache_pending and epcache_cache */
void ci_tcp_epcache_drop_cache(ci_netif* ni)
{
  unsigned id;
  for( id = 0; id < ni->state->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state == CI_TCP_LISTEN ) {
      citp_waitable* w = &wo->waitable;
      ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
      ci_tcp_socket_listen* tls = SOCK_TO_TCP_LISTEN(s);
      uncache_list(ni, tls, &tls->epcache_pending);
      uncache_list(ni, tls, &tls->epcache_cache);
    }
  }
}

#endif
#endif


#if CI_CFG_FD_CACHING || defined(__KERNEL__)
#if defined(__KERNEL__)
static
#endif
int ci_tcp_close(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    LOG_TV(ci_log(LPF "%d CLOSE already closed", S_FMT(ts)));
    /* Still must clear filters in case socket is clustered. */
    ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
    if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN )
      ci_tcp_state_free(netif, ts);
    return 0;
  }

  if( (ts->s.b.sb_flags & CI_SB_FLAG_MOVED) )
    goto drop;

  if( tcp_rcv_usr(ts) != 0 ) {
    /* Linux specific behaviour: send reset and ditch
     * connection if all rx data not read.
     */
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_CLOSE(netif);
    LOG_TV(log(LPF "%d CLOSE sent RST, as rx data present added %u "
               "delivered %u tcp_rcv_usr=%u", S_FMT(ts), ts->rcv_added,
               ts->rcv_delivered, tcp_rcv_usr(ts)));
    ci_tcp_send_rst(netif, ts);
    goto drop;
  }
  if( ts->snd_delegated != 0 ) {
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_DELEGATED_SEND(netif);
    ci_tcp_send_rst(netif, ts);
    goto drop;
  }
  if( (ts->s.s_flags & CI_SOCK_FLAG_LINGER) && ts->s.so.linger == 0 ) {
    /* TCP abort, drop connection, send reset only if connected,
    ** rfc793 p62.
    */
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_DATA(netif);
    if( ! (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ) {
      LOG_TV(log(LPF "%d ABORT sent reset", S_FMT(ts)));
      ci_tcp_send_rst(netif, ts);
    }
    goto drop;
  }

  if( (ts->s.b.state == CI_TCP_TIME_WAIT) ||
      (ts->s.b.state == CI_TCP_CLOSING)   ||
      (ts->s.b.state == CI_TCP_LAST_ACK) )
    return 0;

  if( ! (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ) {
    int rc;

    if( ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ ) {
      ci_tcp_send_rst(netif, ts);
      ci_tcp_ep_clear_filters(netif, S_SP(ts), 0);
      ci_tcp_state_free(netif, ts);
      return 0;
    }

    rc = __ci_tcp_shutdown(netif, ts, SHUT_RDWR);

    if( (ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      if( ts->s.b.state == CI_TCP_CLOSED )
        ci_tcp_state_free(netif, ts);
      else if( ts->s.s_flags & CI_SOCK_FLAG_LINGER &&
          ! SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts)) ) {
        ci_assert(ts->s.so.linger != 0);
        ci_bit_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_IN_SO_LINGER_BIT);
      }
    }
    return rc;
  }

 drop:
  LOG_TC(log(LPF "%d drop connection in %s state", S_FMT(ts), 
              ci_tcp_state_str(ts->s.b.state)));
  /* ci_tcp_drop should really drop connection instead of leaking it,
   * because we can get here only when asyncronyously closing alien
   * non-accepted connection from listen socket closure. */
  ci_bit_clear(&ts->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
  ci_tcp_drop(netif, ts, ECONNRESET);
  return 0;
}
#endif /* CI_CFG_FD_CACHING || defined(__KERNEL__) */


#ifdef __KERNEL__
void ci_tcp_listen_shutdown_queues(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  int synrecvs;

  /* we are going to lock/unlock stacks, so do not call this from interrupt
   * context */
  ci_assert(ci_netif_is_locked(netif));

  /* clear up synrecv queue */
  LOG_TV(ci_log("%s: %d clear out synrecv queue", __FUNCTION__,
		S_FMT(tls)));
  if( tls->n_listenq != 0  &&
     (~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN) )
    ci_ip_timer_clear(netif, &tls->listenq_tid);
  synrecvs = ci_tcp_listenq_drop_all(netif, tls);
  ci_assert_equal(tls->n_listenq, synrecvs);
  ci_assert_le(tls->n_listenq_new, synrecvs);
  tls->n_listenq -= synrecvs;
  tls->n_listenq_new = 0;

  /*
  ** close each associated socket that is not already accepted
  ** and free resources associated with sockets on acceptq
  */
  LOG_TV(log("%s: %d clear out accept queue (%d entries)", __FUNCTION__,
             S_FMT(tls), ci_tcp_acceptq_n(tls)));

  while( ci_tcp_acceptq_not_empty(tls) ) {
    citp_waitable* w;
    ci_tcp_state* ats;    /* accepted ts */
    tcp_helper_resource_t *thr = NULL;

    w = ci_tcp_acceptq_get(netif, tls);

    if( w->sb_aflags & CI_SB_AFLAG_MOVED_AWAY ) {
      oo_sp sp;
      ci_uint32 stack_id;
      ci_netif *ani;        /* netif of the accepted socket */

#ifdef NDEBUG
      if( in_interrupt() ) {
        LOG_U(log("%s: invalid acceptq member", __FUNCTION__));
        citp_waitable_obj_free(netif, w);
        continue;
      }
#else
      ci_assert(!in_interrupt());
#endif

      sp = w->moved_to_sock_id;
      stack_id = w->moved_to_stack_id;
      citp_waitable_obj_free(netif, w);
      /* do not use w any more */

      LOG_TV(log("%s: alien socket %d:%d in accept queue %d:%d", __FUNCTION__,
                 stack_id, OO_SP_FMT(sp), NI_ID(netif), S_FMT(tls)));

      if( efab_thr_table_lookup(NULL, stack_id,
                                EFAB_THR_TABLE_LOOKUP_CHECK_USER,
                                &thr) != 0 ) {
        LOG_U(log("%s: listening socket %d:%d can't find "
                  "acceptq memeber %d:%d", __FUNCTION__,
                  netif->state->stack_id, tls->s.b.bufid, stack_id, sp));
        continue;
      }
      ani = &thr->netif;

      if( !(SP_TO_WAITABLE(ani, sp)->state & CI_TCP_STATE_TCP) ||
          SP_TO_WAITABLE(ani, sp)->state == CI_TCP_LISTEN ) {
        LOG_U(log("%s: listening socket %d:%d has non-TCP "
                  "acceptq memeber %d:%d", __FUNCTION__,
                  netif->state->stack_id, tls->s.b.bufid, stack_id, sp));
        continue;
      }
      ats = SP_TO_TCP(ani, sp);

      /* Do not remove IN_ACCEPTQ flag: ci_tcp_close should know that we
       * are sending RST, not FIN. */
      ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
      efab_tcp_helper_close_endpoint(thr, sp);
      efab_thr_release(thr);
      continue;
    }

    ats = &CI_CONTAINER(citp_waitable_obj, waitable, w)->tcp;

    ci_assert(ci_tcp_is_cached(ats) ||
              (ats->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
    ci_assert(ats->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);

#if CI_CFG_FD_CACHING
    /* We leave the acceptq flag for cached eps - the state free will be
     * triggered from the close once we've closed the fd.
     */
    if( !ci_tcp_is_cached(ats) )
#endif
      /* Remove acceptq flag to allow state free on drop */
        ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);

    if( ats->s.b.state != CI_TCP_CLOSED &&
        ats->s.b.state != CI_TCP_TIME_WAIT ) {
      LOG_TV(log("%s: send reset to accepted connection", __FUNCTION__));
      ci_tcp_send_rst(netif, ats);
    }

    ci_tcp_drop(netif, ats, ECONNRESET);

#if CI_CFG_FD_CACHING
    if( ci_tcp_is_cached(ats) ) {
      LOG_EP(ci_log ("listen_shutdown - uncache from acceptq"));
      uncache_ep(netif, tls, ats);

      /* Remove acceptq flag to allow state free on drop */
      ci_bit_clear(&ats->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
    }
#endif
  }

  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);

#if CI_CFG_FD_CACHING
  /* Above we uncached and closed EPs on the accept q.  While an EP is cached
   * it will move across three queues: the pending queue, the cached queue,
   * then the accept queue.  Here we ensure that any EPs on cached on the
   * cached list are uncached (and freed).
   */
  LOG_EP(ci_log("listen_shutdown - uncache all on cache list"));
  uncache_list(netif, tls, &tls->epcache_cache);
  LOG_EP(ci_log("listen_shutdown - uncache all on pending list"));
  uncache_list(netif, tls, &tls->epcache_pending);
#endif
}

#if CI_CFG_FD_CACHING
void ci_tcp_listen_update_cached(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  tcp_helper_endpoint_t * cached_ep;
  ci_ni_dllist_link *l;
  ci_tcp_state *cached_state;

  /* Before we clear our filters we must update the filters for any connected
   * sockets which were accepted from our cache.  We do not update the filter
   * at accept time, to avoid having to enter the kernel.  This means that
   * their details remain those of the original accepted socket.  This is fine
   * while they can share our wild filter, but the details need to be correct
   * before they get their own full match filter.
   */
  while( (l = ci_ni_dllist_try_pop(netif, &tls->epcache_connected)) ) {
    cached_state = CI_CONTAINER(ci_tcp_state, epcache_link, l);
    ci_ni_dllist_self_link(netif, &cached_state->epcache_link);

    cached_ep = ci_netif_ep_get(netif, cached_state->s.b.bufid);
    tcp_helper_endpoint_update_filter_details(cached_ep);
  }
  ci_assert(ci_ni_dllist_is_valid(netif, &tls->epcache_connected.l));
  ci_assert(ci_ni_dllist_is_empty(netif, &tls->epcache_connected));

  /* We also need to update the filters for the pending list, so they can be
   * shutdown cleanly.
   */
  l = ci_ni_dllist_start(netif, &tls->epcache_pending);
  while( l != ci_ni_dllist_end(netif, &tls->epcache_pending) ) {
    cached_state = CI_CONTAINER(ci_tcp_state, epcache_link, l);
    cached_ep = ci_netif_ep_get(netif, cached_state->s.b.bufid);

    tcp_helper_endpoint_update_filter_details(cached_ep);
    ci_ni_dllist_iter(netif, l);
  }
  ci_assert(ci_ni_dllist_is_valid(netif, &tls->epcache_pending.l));
}
#endif
#endif

/* NOTE: in the kernel version [fd] is assumed to be unused */
void __ci_tcp_listen_shutdown(ci_netif* netif, ci_tcp_socket_listen* tls,
                              ci_fd_t fd)
{
  int rc;

  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);
  /* unlocked when called from ci_tcp_all_fds_gone() */
  ci_assert(ci_sock_is_locked(netif, &tls->s.b) ||
            (tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));

  /* Set state at start-of-day: fop_poll should return proper events when
   * we wake up this endpoint in the process of shutdown.
   * Also, this prevents new loopback connections. */
  tls->s.b.state = CI_TCP_CLOSED;

  LOG_TV(ci_log("%s: S_FMT=%d", __FUNCTION__, S_FMT(tls)));

  /* We should re-bind socket on the next use if the port was determined by
   * OS. */
  if( ! (tls->s.s_flags & CI_SOCK_FLAG_PORT_BOUND) )
    tls->s.s_flags &= ~CI_SOCK_FLAG_BOUND;
  /* Shutdown the OS socket and clear out the filters. */
# ifdef __KERNEL__
  rc = tcp_helper_endpoint_shutdown(netif2tcp_helper_resource(netif),
                                    S_SP(tls), SHUT_RDWR, CI_TCP_LISTEN);
  if( rc == -EINVAL )
    /* This means there is no O/S socket.  This is expected when socket has
     * been closed, as the O/S socket has already been shutdown and
     * released.
     */
    rc = 0;
# else
  rc = ci_tcp_helper_endpoint_shutdown(fd, SHUT_RDWR, CI_TCP_LISTEN);
# endif
  if( rc < 0 )
    LOG_E(ci_log("%s: [%d:%d] shutdown(os_sock) failed %d",
                 __FUNCTION__, NI_ID(netif), S_FMT(tls), rc));
}


#ifdef __KERNEL__
void ci_tcp_listen_all_fds_gone(ci_netif* ni, ci_tcp_socket_listen* tls,
                                int do_free)
{
  /* All process references to this socket have gone.  So we should
   * shutdown() if necessary, and arrange for all resources to eventually
   * get cleaned up.
   *
   * This is called by the driver only.  ci_netif_poll() is called just
   * before calling this function, so we're up-to-date.
   */
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);

  __ci_tcp_listen_shutdown(ni, tls, NULL);
  __ci_tcp_listen_to_normal(ni, tls);
  if( do_free )
    citp_waitable_obj_free(ni, &tls->s.b);
}


void ci_tcp_all_fds_gone(ci_netif* ni, ci_tcp_state* ts, int do_free)
{
  /* All process references to this socket have gone.  So we should
   * shutdown() if necessary, and arrange for all resources to eventually
   * get cleaned up.
   *
   * This is called by the driver only.  ci_netif_poll() is called just
   * before calling this function, so we're up-to-date.
   */
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.b.state & CI_TCP_STATE_TCP);

  /* If we are in a state where we time out orphaned connections: */
  if( (ts->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN) &&
      !(ts->s.b.sb_flags & CI_SB_FLAG_MOVED) )
    ci_netif_fin_timeout_enter(ni, ts);

  /* This frees [ts] if appropriate. */
  if( do_free )
    ci_tcp_close(ni, ts);
}
#endif


/*! \cidoxg_end */
