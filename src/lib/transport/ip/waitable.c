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
** \author  djr
**  \brief  citp_waitable support.
**   \date  2006/01/31
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <onload/sleep.h>


void citp_waitable_reinit(ci_netif* ni, citp_waitable* w)
{
  /* Reinitialise fields between separate uses. */
  w->sleep_seq.all = 0;
  w->sigown = 0;
  w->spin_cycles = ni->state->sock_spin_cycles;
}


void citp_waitable_init(ci_netif* ni, citp_waitable* w, int id)
{
  /* NB. Some members initialised in citp_waitable_obj_free(). */

  oo_p sp;

#if CI_CFG_SOCKP_IS_PTR
  w->bufid = id;
#else
  w->bufid = OO_SP_FROM_INT(ni, id);
#endif
  w->sb_flags = 0;
  w->sb_aflags = CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_NOT_READY;

  sp = oo_sockp_to_statep(ni, W_SP(w));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(citp_waitable, post_poll_link));
  ci_ni_dllist_link_init(ni, &w->post_poll_link, sp, "ppll");
  ci_ni_dllist_self_link(ni, &w->post_poll_link);

  sp = oo_sockp_to_statep(ni, W_SP(w));
  OO_P_ADD(sp, CI_MEMBER_OFFSET(citp_waitable, ready_link));
  ci_ni_dllist_link_init(ni, &w->ready_link, sp, "rll");
  ci_ni_dllist_self_link(ni, &w->ready_link);

  w->lock.wl_val = 0;
  CI_DEBUG(w->wt_next = OO_SP_NULL);
  CI_DEBUG(w->next_id = CI_ILL_END);

  citp_waitable_reinit(ni, w);
}


citp_waitable_obj* citp_waitable_obj_alloc(ci_netif* netif)
{
  citp_waitable_obj* wo;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));

  if( netif->state->deferred_free_eps_head != CI_ILL_END ) {
    ci_uint32 link;
    do
      link = netif->state->deferred_free_eps_head;
    while( ci_cas32_fail(&netif->state->deferred_free_eps_head,
                         link, CI_ILL_END));
    while( link != CI_ILL_END ) {
      citp_waitable* w = ID_TO_WAITABLE(netif, link);
      link = w->next_id;
      CI_DEBUG(w->next_id = CI_ILL_END);
      ci_assert_equal(w->state, CI_TCP_STATE_FREE);
      ci_assert(OO_SP_IS_NULL(w->wt_next));
      w->wt_next = netif->state->free_eps_head;
      netif->state->free_eps_head = W_SP(w);
    }
  }

  if( OO_SP_IS_NULL(netif->state->free_eps_head) ) {
    ci_tcp_helper_more_socks(netif);

    if( OO_SP_IS_NULL(netif->state->free_eps_head) )
      ci_netif_timeout_reap(netif);
  }

  if( OO_SP_IS_NULL(netif->state->free_eps_head) )
    return NULL;

  LOG_TV(ci_log("%s: allocating %d", __FUNCTION__,
                OO_SP_FMT(netif->state->free_eps_head)));

  ci_assert(IS_VALID_SOCK_P(netif, netif->state->free_eps_head));
#if !defined(__KERNEL__) && !defined (CI_HAVE_OS_NOPAGE)
  ci_netif_mmap_shmbuf(netif,
                       (netif->state->free_eps_head >> EP_BUF_BLOCKSHIFT) + 1);
#endif
  wo = SP_TO_WAITABLE_OBJ(netif, netif->state->free_eps_head);

  ci_assert(OO_SP_EQ(W_SP(&wo->waitable), netif->state->free_eps_head));
  ci_assert_equal(wo->waitable.state, CI_TCP_STATE_FREE);
  ci_assert_equal(wo->waitable.sb_aflags, (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_NOT_READY));
  ci_assert_equal(wo->waitable.lock.wl_val, 0);

  netif->state->free_eps_head = wo->waitable.wt_next;
  CI_DEBUG(wo->waitable.wt_next = OO_SP_NULL);
  ci_assert_equal(wo->waitable.state, CI_TCP_STATE_FREE);

  return wo;
}


#ifdef __KERNEL__
static void ci_drop_orphan(ci_netif * ni)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t* trs;
  int dec_needed; 

  /* Called when connection closes AFTER the file descriptor closes
   *  - in kernel mode, if user mode has gone away, we call
   *    efab_tcp_helper_k_ref_count_dec() to decrement count
   *    of such connections so we can free the stack when
   *    they've all gone away.
   */
  if( ni->flags & CI_NETIF_FLAGS_DROP_SOCK_REFS ) {
    trs = netif2tcp_helper_resource(ni);
    dec_needed = 0;

    ci_irqlock_lock(&trs->lock, &lock_flags);
    if( trs->n_ep_closing_refs > 0 ) {
      --trs->n_ep_closing_refs;
      dec_needed = 1;
    }
    ci_irqlock_unlock(&trs->lock, &lock_flags);

    if( dec_needed )
      efab_tcp_helper_k_ref_count_dec(trs, 0);
  }
}
#else
# define ci_drop_orphan(ni)  do{}while(0)
#endif


#if CI_CFG_FD_CACHING
void citp_waitable_obj_free_to_cache(ci_netif* ni, citp_waitable* w)
{
#if defined (__KERNEL__) && !defined(NDEBUG)
  /* There should be no non-atomic work queued for endpoints going to cache -
   * they don't get their filters removed.
   */
  tcp_helper_endpoint_t* ep = ci_netif_get_valid_ep(ni, w->bufid);
  ci_assert(!(ep->ep_aflags & OO_THR_EP_AFLAG_NON_ATOMIC));
#endif
  ci_assert(!(w->sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(w->sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_assert(w->sb_aflags & CI_SB_AFLAG_IN_CACHE);
  ci_assert(w->state == CI_TCP_CLOSED);
  ci_assert(ci_ni_dllist_is_self_linked(ni, &w->post_poll_link));
  ci_assert(OO_SP_IS_NULL(w->wt_next));

  /* This resets a subset of the state done by __citp_waitable_obj_free.
   * We do not set the orphan flag, as cached endpoints remain attached.
   * We do not alter the state, as that too remains accurate.
   *
   * We preserve cache related aflags.  If the endpoint is freed before being
   * accepted from the cache then these will be cleared when
   * __citp_waitable_obj_free is called, otherwise they'll be checked for
   * correctness, and updated if necessary when the socket is accepted.
   */
  w->wake_request = 0;
  w->sb_flags = 0;
  ci_atomic32_and(&w->sb_aflags, CI_SB_AFLAG_NOT_READY |
                                 CI_SB_AFLAG_CACHE_PRESERVE);
  w->lock.wl_val = 0;
  w->ready_list_id = 0;
  CI_USER_PTR_SET(w->eitem, NULL);
}
#endif


static void __citp_waitable_obj_free(ci_netif* ni, citp_waitable* w)
{
  ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
  ci_assert(w->state != CI_TCP_STATE_FREE);
  ci_assert(ci_ni_dllist_is_self_linked(ni, &w->post_poll_link));
  ci_assert(OO_SP_IS_NULL(w->wt_next));

  w->wake_request = 0;
  w->sb_flags = 0;
  w->sb_aflags = CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_NOT_READY;
  w->state = CI_TCP_STATE_FREE;
  w->lock.wl_val = 0;
  w->ready_list_id = 0;
  CI_USER_PTR_SET(w->eitem, NULL);
}


void citp_waitable_obj_free(ci_netif* ni, citp_waitable* w)
{
  ci_assert(ci_netif_is_locked(ni));

#ifdef __KERNEL__
  {
    /* Avoid racing with tcp_helper_do_non_atomic(). */
    tcp_helper_endpoint_t* ep = ci_netif_get_valid_ep(ni, w->bufid);
    unsigned ep_aflags;
  again:
    if( (ep_aflags = ep->ep_aflags) & OO_THR_EP_AFLAG_NON_ATOMIC ) {
      ci_assert(!(ep_aflags & OO_THR_EP_AFLAG_NEED_FREE));
      if( ci_cas32_fail(&ep->ep_aflags, ep_aflags,
                        ep_aflags | OO_THR_EP_AFLAG_NEED_FREE) )
        goto again;
      return;
    }
    ci_rmb();
  }
#endif

  __citp_waitable_obj_free(ni, w);
  w->wt_next = ni->state->free_eps_head;
  ni->state->free_eps_head = W_SP(w);
  /* Must be last, as may result in stack going away. */
  ci_drop_orphan(ni);
}


void citp_waitable_obj_free_nnl(ci_netif* ni, citp_waitable* w)
{
  /* Stack lock is probably not held (but not guaranteed). */

  __citp_waitable_obj_free(ni, w);
  do
    w->next_id = ni->state->deferred_free_eps_head;
  while( ci_cas32_fail(&ni->state->deferred_free_eps_head,
                       w->next_id, OO_SP_TO_INT(W_SP(w))) );
  /* Must be last, as may result in stack going away. */
  ci_drop_orphan(ni);
}


#ifdef __KERNEL__

void citp_waitable_cleanup(ci_netif* ni, citp_waitable_obj* wo, int do_free)
{
  if( wo->waitable.sb_aflags & CI_SB_AFLAG_MOVED_AWAY ) {
    if( do_free )
      citp_waitable_obj_free(ni, &wo->waitable);
  }
  else if( wo->waitable.state == CI_TCP_LISTEN )
    ci_tcp_listen_all_fds_gone(ni, &wo->tcp_listen, do_free);
  else if( wo->waitable.state & CI_TCP_STATE_TCP )
    ci_tcp_all_fds_gone(ni, &wo->tcp, do_free);
#if CI_CFG_UDP
  else if( wo->waitable.state == CI_TCP_STATE_UDP )
    ci_udp_all_fds_gone(ni, wo->waitable.bufid, do_free);
#endif
#if CI_CFG_USERSPACE_PIPE
  else if( wo->waitable.state == CI_TCP_STATE_PIPE )
    ci_pipe_all_fds_gone(ni, &wo->pipe, do_free);
#endif
  else if( do_free ) {
    /* The only non-TCP and non-UDP state in FREE.  But FREE endpoint is
     * already free, we can't free it again.  Possibly, it is a
     * placeholder for future endpoint types, such as epoll? */
    citp_waitable_obj_free(ni, &wo->waitable);
  }
}

void citp_waitable_all_fds_gone(ci_netif* ni, oo_sp w_id)
{
  citp_waitable_obj* wo;

  ci_assert(ni);
  ci_assert(IS_VALID_SOCK_P(ni, w_id));
  ci_assert(ci_netif_is_locked(ni));

  wo = SP_TO_WAITABLE_OBJ(ni, w_id);
  ci_assert(wo->waitable.state != CI_TCP_STATE_FREE);

  LOG_NC(ci_log("%s: %d:%d %s", __FUNCTION__, NI_ID(ni), OO_SP_FMT(w_id),
		ci_tcp_state_str(wo->waitable.state)));

  /* listening socket is closed in blocking conext, see
   * efab_tcp_helper_close_endpoint().
   * CI_SB_AFLAG_ORPHAN is set earlier in this case.. */
  CI_DEBUG(if( (wo->waitable.sb_aflags & CI_SB_AFLAG_ORPHAN) &&
               wo->waitable.state != CI_TCP_LISTEN )
	     ci_log("%s: %d:%d already orphan", __FUNCTION__,
                    NI_ID(ni), OO_SP_FMT(w_id)));

  /* It's essential that an ORPHANed socket not be on the deferred
   * socket list, because the same link field is used as timewait
   * list, free list etc.  We must purge the deferred list before
   * setting the orphan flag.
   *
   * NB. This socket cannot now be added to the deferred list, because
   * no-one has a reference to it.
   */
  ci_netif_purge_deferred_socket_list(ni);
  ci_bit_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);

  /* We also need to remove the socket from the post-poll list.  It may
   * have been left there because the stack believes a wakeup is needed.
   */
  ci_ni_dllist_remove_safe(ni, &wo->waitable.post_poll_link);
  ci_ni_dllist_remove_safe(ni, &wo->waitable.ready_link);
  wo->waitable.ready_list_id = 0;

  citp_waitable_cleanup(ni, wo, 1);
}

#endif  /* __KERNEL__ */


const char* citp_waitable_type_str(citp_waitable* w)
{
  if( w->state & CI_TCP_STATE_TCP )         return "TCP";
  else if( w->state == CI_TCP_STATE_UDP )   return "UDP";
  else if( w->state == CI_TCP_STATE_FREE )  return "FREE";
#if CI_CFG_USERSPACE_PIPE
  else if( w->state == CI_TCP_STATE_PIPE )  return "PIPE";
#endif
  else return "<unknown-citp_waitable-type>";
}


static void citp_waitable_dump2(ci_netif* ni, citp_waitable* w, const char* pf,
                                oo_dump_log_fn_t logger, void* log_arg)
{
  unsigned tmp;

  if( w->state & CI_TCP_STATE_SOCKET ) {
    ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
    logger(log_arg, "%s%s "NT_FMT"lcl="OOF_IP4PORT" rmt="OOF_IP4PORT" %s",
           pf, citp_waitable_type_str(w), NI_ID(ni), W_FMT(w),
           OOFA_IP4PORT(sock_laddr_be32(s), sock_lport_be16(s)),
           OOFA_IP4PORT(sock_raddr_be32(s), sock_rport_be16(s)),
           ci_tcp_state_str(w->state));
  }
  else
    logger(log_arg, "%s%s "NT_FMT, pf,
           citp_waitable_type_str(w), NI_ID(ni), W_FMT(w));

  if( w->state == CI_TCP_STATE_FREE )
    return;

  tmp = w->lock.wl_val;
  logger(log_arg, "%s  lock: %x %s%s", pf, tmp,
         (tmp & OO_WAITABLE_LK_LOCKED) ? "LOCKED" : "",
         (tmp & OO_WAITABLE_LK_NEED_WAKE) ? " CONTENDED": "");

  logger(log_arg, "%s  rx_wake=%08x%s tx_wake=%08x%s flags: "CI_SB_FLAGS_FMT,
         pf,
         w->sleep_seq.rw.rx,
         ci_bit_test(&w->wake_request, CI_SB_FLAG_WAKE_RX_B) ? "(RQ)":"    ",
         w->sleep_seq.rw.tx,
         ci_bit_test(&w->wake_request, CI_SB_FLAG_WAKE_TX_B) ? "(RQ)":"    ",
         CI_SB_FLAGS_PRI_ARG(w));

  if( w->spin_cycles == -1 )
    logger(log_arg, "%s  ul_poll: -1 spin cycles -1 usecs", pf);
  else
    logger(log_arg, "%s  ul_poll: %llu spin cycles %u usec", pf,
         w->spin_cycles, oo_cycles64_to_usec(ni, w->spin_cycles));
}


void citp_waitable_dump(ci_netif* ni, citp_waitable* w, const char* pf)
{
  citp_waitable_dump_to_logger(ni, w, pf, ci_log_dump_fn, NULL);
}

void citp_waitable_dump_to_logger(ci_netif* ni, citp_waitable* w,
                                  const char* pf,
                                  oo_dump_log_fn_t logger, void* log_arg)
{
  citp_waitable_obj* wo = CI_CONTAINER(citp_waitable_obj, waitable, w);

  citp_waitable_dump2(ni, w, pf, logger, log_arg);
  if( w->state & CI_TCP_STATE_SOCKET ) {
    ci_sock_cmn_dump(ni, &wo->sock, pf, logger, log_arg);
    if( w->state == CI_TCP_LISTEN )
      ci_tcp_socket_listen_dump(ni, &wo->tcp_listen, pf, logger, log_arg);
    else if( w->state & CI_TCP_STATE_TCP )
      ci_tcp_state_dump(ni, &wo->tcp, pf, logger, log_arg);
#if CI_CFG_UDP
    else if( w->state == CI_TCP_STATE_UDP )
      ci_udp_state_dump(ni, &wo->udp, pf, logger, log_arg);
#endif
  }
#if CI_CFG_USERSPACE_PIPE
  else if( w->state == CI_TCP_STATE_PIPE )
    oo_pipe_dump(ni, &wo->pipe, pf, logger, log_arg);
#endif
}


void citp_waitable_print(citp_waitable* w)
{
  /* Output socket using netstat style output:
   *   TCP 2 0 0.0.0.0:12865 0.0.0.0:0 LISTEN
   *   UDP 0 0 172.16.129.131:57521 0.0.0.0:0 UDP
   */
  if( w->state & CI_TCP_STATE_SOCKET ) {
    ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
    citp_waitable_obj* wo = CI_CONTAINER(citp_waitable_obj, waitable, w);
    int tq = 0;
    int rq = 0;
    
    if( (w->state & CI_TCP_STATE_TCP) &&
       !(w->state & CI_TCP_STATE_NOT_CONNECTED) ) {
      tq = ci_tcp_sendq_n_pkts(&wo->tcp);
      rq = wo->tcp.recv1.num + wo->tcp.recv2.num;
    }
    else if( w->state == CI_TCP_STATE_UDP ) {
      tq = wo->udp.tx_count + oo_atomic_read(&wo->udp.tx_async_q_level);
      rq = ci_udp_recv_q_pkts(&wo->udp.recv_q);
    }
    log("%s %d %d "OOF_IP4PORT" "OOF_IP4PORT" %s",
        citp_waitable_type_str(w), rq, tq,
        OOFA_IP4PORT(sock_laddr_be32(s), sock_lport_be16(s)),
        OOFA_IP4PORT(sock_raddr_be32(s), sock_rport_be16(s)),
        ci_tcp_state_str(w->state));
  }
}


#ifndef __KERNEL__

void citp_waitable_wakeup(ci_netif* ni, citp_waitable* w)
{
  oo_waitable_wake_t op;
  op.sock_id = w->bufid;
  oo_resource_op(ci_netif_get_driver_handle(ni),
                 OO_IOC_WAITABLE_WAKE, &op);
}

#endif

void citp_waitable_wake_not_in_poll(ci_netif* ni, citp_waitable* sb,
                                    unsigned what)
{
  ci_assert(what);
  ci_assert((what & ~(CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX)) == 0u);
  ci_assert(!ni->state->in_poll);
  ci_wmb();
  if( what & CI_SB_FLAG_WAKE_RX )
    ++sb->sleep_seq.rw.rx;
  if( what & CI_SB_FLAG_WAKE_TX )
    ++sb->sleep_seq.rw.tx;
  ci_mb();

#ifdef __KERNEL__
  /* Normally we put an object on a ready list in ci_netif_put_on_post_poll,
   * but in this case we don't go via there, so have to explicitly queue on
   * the ready list here.
   */
  ci_ni_dllist_remove(ni, &sb->ready_link);
  ci_ni_dllist_put(ni, &ni->state->ready_lists[sb->ready_list_id],
                   &sb->ready_link);

  if( what & sb->wake_request ) {
    sb->sb_flags |= what;
    citp_waitable_wakeup(ni, sb);
  }

  /* Wake the ready list too, if that's requested it. */
  if( ni->state->ready_list_flags[sb->ready_list_id] &
      CI_NI_READY_LIST_FLAG_WAKE )
    efab_tcp_helper_ready_list_wakeup(netif2tcp_helper_resource(ni),
                                      sb->ready_list_id);
#else
  if( what & sb->wake_request ) {
    sb->sb_flags |= what;
    ci_netif_put_on_post_poll(ni, sb);
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_WAKE);
  }
  else {
    /* Normally we put an object on a ready list in ci_netif_put_on_post_poll,
     * but in this case we don't go via there, so have to explicitly queue on
     * the ready list here.
     */
    ci_ni_dllist_remove(ni, &sb->ready_link);
    ci_ni_dllist_put(ni, &ni->state->ready_lists[sb->ready_list_id],
                     &sb->ready_link);

    if( ni->state->ready_list_flags[sb->ready_list_id] &
        CI_NI_READY_LIST_FLAG_WAKE )
      ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_WAKE);
  }
#endif
}

/*! \cidoxg_end */
