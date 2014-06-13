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
**  \brief  citp_waitable support.
**   \date  2006/01/31
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"


void citp_waitable_reinit(ci_netif* ni, citp_waitable* w)
{
  /* Reinitialise fields between separate uses. */
  w->sleep_seq.all = 0;
  w->sigown = 0;
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
      ci_assert(w->state == CI_TCP_STATE_FREE);
      ci_assert(OO_SP_IS_NULL(w->wt_next));
      w->wt_next = netif->state->free_eps_head;
      netif->state->free_eps_head = W_SP(w);
    }
  }

  if( OO_SP_IS_NULL(netif->state->free_eps_head) ) {
    ci_tcp_helper_more_socks(netif);

    if( OO_SP_IS_NULL(netif->state->free_eps_head) &&
        OO_SP_NOT_NULL(netif->state->free_pipe_bufs) )
      ci_tcp_helper_pipebufs_to_socks(netif);

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

  if( wo->waitable.state == CI_TCP_LISTEN )
    ci_tcp_listen_all_fds_gone(ni, &wo->tcp_listen);
  else if( wo->waitable.state & CI_TCP_STATE_TCP )
    ci_tcp_all_fds_gone(ni, &wo->tcp);
#if CI_CFG_UDP
  else if( wo->waitable.state == CI_TCP_STATE_UDP )
    ci_udp_all_fds_gone(ni, w_id);
#endif
#if CI_CFG_USERSPACE_PIPE
  else if( wo->waitable.state == CI_TCP_STATE_PIPE )
    ci_pipe_all_fds_gone(ni, &wo->pipe);
#endif
  else {
    /* The only non-TCP and non-UDP state in FREE.  But FREE endpoint is
     * already free, we can't free it again.  Possibly, it is a
     * placeholder for future endpoint types, such as epoll? */
    citp_waitable_obj_free(ni, &wo->waitable);
  }
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


void citp_waitable_dump2(ci_netif* ni, citp_waitable* w, const char* pf)
{
  unsigned tmp;

  if( w->state & CI_TCP_STATE_SOCKET ) {
    ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
    log("%s%s "NT_FMT"lcl="OOF_IP4PORT" rmt="OOF_IP4PORT" %s", pf,
	citp_waitable_type_str(w), NI_ID(ni), W_FMT(w),
        OOFA_IP4PORT(sock_laddr_be32(s), sock_lport_be16(s)),
        OOFA_IP4PORT(sock_raddr_be32(s), sock_rport_be16(s)),
	ci_tcp_state_str(w->state));
  }
  else
    log("%s%s "NT_FMT, pf,
	citp_waitable_type_str(w), NI_ID(ni), W_FMT(w));

  if( w->state == CI_TCP_STATE_FREE )
    return;

  tmp = w->lock.wl_val;
  log("%s  lock: %x %s%s", pf, tmp,
      (tmp & OO_WAITABLE_LK_LOCKED) ? "LOCKED" : "",
      (tmp & OO_WAITABLE_LK_NEED_WAKE) ? " CONTENDED": "");

  log("%s  rx_wake=%08x%s tx_wake=%08x%s flags: "CI_SB_FLAGS_FMT, pf,
      w->sleep_seq.rw.rx,
      ci_bit_test(&w->wake_request, CI_SB_FLAG_WAKE_RX_B) ? "(RQ)":"    ",
      w->sleep_seq.rw.tx,
      ci_bit_test(&w->wake_request, CI_SB_FLAG_WAKE_TX_B) ? "(RQ)":"    ",
      CI_SB_FLAGS_PRI_ARG(w));
}


void citp_waitable_dump(ci_netif* ni, citp_waitable* w, const char* pf)
{
  citp_waitable_obj* wo = CI_CONTAINER(citp_waitable_obj, waitable, w);

  citp_waitable_dump2(ni, w, pf);
  if( w->state & CI_TCP_STATE_SOCKET ) {
    ci_sock_cmn_dump(ni, &wo->sock, pf);
    if( w->state == CI_TCP_LISTEN )
      ci_tcp_socket_listen_dump(ni, &wo->tcp_listen, pf);
    else if( w->state & CI_TCP_STATE_TCP )
      ci_tcp_state_dump(ni, &wo->tcp, pf);
#if CI_CFG_UDP
    else if( w->state == CI_TCP_STATE_UDP )
      ci_udp_state_dump(ni, &wo->udp, pf);
#endif
  }
#if CI_CFG_USERSPACE_PIPE
  else if( w->state == CI_TCP_STATE_PIPE )
    oo_pipe_dump(ni, &wo->pipe, pf);
#endif
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

/*! \cidoxg_end */
