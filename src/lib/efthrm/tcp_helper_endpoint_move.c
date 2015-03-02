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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/02/20
** Description: Implementation of "ops" invoked by user-level.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>
# include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/version.h>
#include <onload/oof_interface.h>


static int efab_file_move_supported_tcp(ci_netif *ni, ci_tcp_state *ts)
{
#if CI_CFG_FD_CACHING
  /* Don't support moving cached sockets for now */
  if( ci_tcp_is_cached(ts) ||
      !ci_ni_dllist_is_self_linked(ni, &ts->epcache_link) )
    return false;
#endif

  /* TCP closed: supported */
  if( ts->s.b.state == CI_TCP_CLOSED )
    return true;

  /* everything except TCP connected is not supported */
  if( !(ts->s.b.state & CI_TCP_STATE_TCP_CONN) )
    return false;
  if( ts->local_peer != OO_SP_NULL )
    return false;
  if( !(ts->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED) )
    return false;

  /* send queue is not supported
   * NB: retrans_ptr is uninitialised when retrans was not used yet,
   * so do not check for !OO_PP_IS_NULL(ts->retrans_ptr) */
  if( !ci_ip_queue_is_empty(&ts->send) ||
      ts->send_prequeue != OO_PP_ID_NULL ||
      oo_atomic_read(&ts->send_prequeue_in) != 0 ||
      !ci_ip_queue_is_empty(&ts->retrans) ||
      ci_ip_timer_pending(ni, &ts->rto_tid) ||
      ci_ip_timer_pending(ni, &ts->zwin_tid) ||
#if CI_CFG_TAIL_DROP_PROBE
      ci_ip_timer_pending(ni, &ts->taildrop_tid) ||
#endif
      ci_ip_timer_pending(ni, &ts->cork_tid) )
    return false;

  /* Sockets with allocated templates are not supported */
  if( OO_PP_NOT_NULL(ts->tmpl_head) )
    return false;

  return true;
}
static int efab_file_move_supported_udp(ci_netif *ni, ci_udp_state *us)
{
  /* Unbound (without filters) sockets only */
  if( ci_netif_ep_get(ni, us->s.b.bufid)->oofilter.sf_local_port != NULL )
    return false;

  /* Do not copy any packets */
  if( ci_udp_recv_q_not_empty(us) ||
      us->zc_kernel_datagram != OO_PP_ID_NULL ||
      us->zc_kernel_datagram_count != 0 ||
      us->tx_count != 0 || us->tx_async_q != CI_ILL_END )
    return false;

  return true;
}

/* Returns true if move of this endpoint is supported */
static int efab_file_move_supported(ci_netif *ni, ci_sock_cmn *s)
{

  /* We do not copy TX timestamping queue yet. */
  if( s->timestamping_flags != 0 )
    return false;

  /* UDP:  */
  if( s->b.state == CI_TCP_STATE_UDP )
    return efab_file_move_supported_udp(ni, SOCK_TO_UDP(s));

  /* TCP or UDP only */
  if( ! (s->b.state & CI_TCP_STATE_TCP ) )
    return false;

  /* No listening sockets */
  if( s->b.state == CI_TCP_LISTEN )
    return false;

  return efab_file_move_supported_tcp(ni, SOCK_TO_TCP(s));
}

static void efab_ip_queue_copy(ci_netif *ni_to, ci_ip_pkt_queue *q_to,
                               ci_netif *ni_from, ci_ip_pkt_queue *q_from)
{
  ci_ip_pkt_fmt *pkt_to, *pkt_from;
  oo_pkt_p pp;

  ci_ip_queue_init(q_to);
  if( q_from->num == 0 )
    return;

  ci_assert( OO_PP_NOT_NULL(q_from->head) );
  pp = q_from->head;
  do {
    pkt_from = PKT_CHK(ni_from, pp);
    pkt_to = ci_netif_pkt_alloc(ni_to);
    memcpy(&pkt_to->pay_len, &pkt_from->pay_len,
           CI_CFG_PKT_BUF_SIZE - CI_MEMBER_OFFSET(ci_ip_pkt_fmt, pay_len));
    ci_ip_queue_enqueue(ni_to, q_to, pkt_to);
    if( pp == q_from->tail )
      break;
    pp = pkt_from->next;
  } while(1);
}

/* Move priv file to the alien_ni stack.
 * Should be called with the locked priv stack and socket;
 * the function returns with this stack being unlocked.
 * If rc=0, it returns with alien_ni stack locked;
 * otherwise, both stacks are unlocked.
 * Socket is always unlocked on return. */
int efab_file_move_to_alien_stack(ci_private_t *priv, ci_netif *alien_ni)
{
  tcp_helper_resource_t *old_thr = priv->thr;
  tcp_helper_resource_t *new_thr = netif2tcp_helper_resource(alien_ni);
  ci_sock_cmn *old_s = SP_TO_SOCK(&old_thr->netif, priv->sock_id);
  ci_sock_cmn *new_s;
  ci_sock_cmn *mid_s;
  tcp_helper_endpoint_t *old_ep, *new_ep;
  int rc, i;
  int pollwait_register = 0;
#if CI_CFG_FD_CACHING
  oo_p sp;
#endif

  OO_DEBUG_TCPH(ci_log("%s: move %d:%d to %d", __func__,
                       old_thr->id, priv->sock_id, new_thr->id));
  /* Poll the old stack - deliver all data to our socket */
  ci_netif_poll(&old_thr->netif);

  /* Endpoints in epoll list should not be moved, because waitq is already
   * in the epoll internal structures (bug 41152). */
  if( !list_empty(&priv->_filp->f_ep_links) ) {
    rc = -EBUSY;
    goto fail1;
  }

  if( !efab_file_move_supported(&old_thr->netif, old_s) ) {
    rc = -EINVAL;
    goto fail1;
  }

  /* Lock the second stack */
  i = 0;
  while( ! ci_netif_trylock(alien_ni) ) {
    ci_netif_unlock(&old_thr->netif);
    if( i++ >= 1000 ) {
      rc = -EBUSY;
      goto fail1_ni_unlocked;
    }
    rc = ci_netif_lock(&old_thr->netif);
    if( rc != 0 )
      goto fail1_ni_unlocked;
  }

  /* Allocate a new socket in the alien_ni stack */
  rc = -ENOMEM;
  if( old_s->b.state == CI_TCP_STATE_UDP ) {
    ci_udp_state *new_us = ci_udp_get_state_buf(alien_ni);
    if( new_us == NULL )
      goto fail2;
    new_s = &new_us->s;
  }
  else {
    ci_tcp_state *new_ts = ci_tcp_get_state_buf(alien_ni);
    if( new_ts == NULL )
      goto fail2;
    new_s = &new_ts->s;
  }

  /* Allocate an intermediate "socket" outside of everything */
  mid_s = ci_alloc(CI_MAX(sizeof(ci_tcp_state), sizeof(ci_udp_state)));
  if( mid_s == NULL )
    goto fail3;

  OO_DEBUG_TCPH(ci_log("%s: move %d:%d to %d:%d", __func__,
                       old_thr->id, priv->sock_id,
                       new_thr->id, new_s->b.bufid));

  /* Copy TCP/UDP state */
  memcpy(mid_s, old_s, CI_MAX(sizeof(ci_tcp_state), sizeof(ci_udp_state)));

  /* do not copy old_s->b.bufid
   * and other fields in stack adress space */
  mid_s->b.sb_aflags |= CI_SB_AFLAG_ORPHAN;
  mid_s->b.bufid = new_s->b.bufid;
  mid_s->b.post_poll_link = new_s->b.post_poll_link;
  mid_s->b.ready_link = new_s->b.ready_link;
  mid_s->reap_link = new_s->reap_link;

  if( old_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_state *mid_ts = SOCK_TO_TCP(mid_s);

    mid_ts->timeout_q_link = new_ts->timeout_q_link;
    mid_ts->tx_ready_link = new_ts->tx_ready_link;
    mid_ts->rto_tid = new_ts->rto_tid;
    mid_ts->delack_tid = new_ts->delack_tid;
    mid_ts->zwin_tid = new_ts->zwin_tid;
    mid_ts->kalive_tid = new_ts->kalive_tid;
    mid_ts->cork_tid = new_ts->cork_tid;
    ci_ip_queue_init(&mid_ts->recv1);
    ci_ip_queue_init(&mid_ts->recv2);
    ci_ip_queue_init(&mid_ts->send);
    ci_ip_queue_init(&mid_ts->retrans);
    mid_ts->send_prequeue = OO_PP_ID_NULL;
    new_ts->retrans_ptr = OO_PP_NULL;
    mid_ts->tmpl_head = OO_PP_NULL;
    oo_atomic_set(&mid_ts->send_prequeue_in, 0);

    *new_ts = *mid_ts;
    ci_pmtu_state_init(alien_ni, &new_ts->s, &new_ts->pmtus,
                       CI_IP_TIMER_PMTU_DISCOVER);
#if CI_CFG_FD_CACHING
    sp = TS_OFF(alien_ni, new_ts);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_state, epcache_link));
    ci_ni_dllist_link_init(alien_ni, &new_ts->epcache_link, sp, "epch");
    ci_ni_dllist_self_link(alien_ni, &new_ts->epcache_link);
#endif
   
    /* free temporary mid_ts storage */
    CI_FREE_OBJ(mid_ts);
  }
  else {
    ci_udp_state *mid_us = SOCK_TO_UDP(mid_s);

    *SOCK_TO_UDP(new_s) = *mid_us;
    CI_FREE_OBJ(mid_us);
  }

  /* Move the filter */
  old_ep = ci_trs_ep_get(old_thr, priv->sock_id);
  new_ep = ci_trs_ep_get(new_thr, new_s->b.bufid);
  rc = tcp_helper_endpoint_move_filters_pre(old_ep, new_ep);
  if( rc != 0 ) {
    rc = -EINVAL;
    goto fail3;
  }

  /* Allocate a new file for the new endpoint */
  rc = onload_alloc_file(new_thr, new_s->b.bufid, priv->_filp->f_flags,
                         priv->fd_type, &old_ep->alien_ref);
  if( rc != 0 )
    goto fail4;
  ci_assert(old_ep->alien_ref);

  /* Copy F_SETOWN_EX, F_SETSIG to the new file */
#ifdef F_SETOWN_EX
  rcu_read_lock();
  __f_setown(old_ep->alien_ref->_filp, priv->_filp->f_owner.pid,
             priv->_filp->f_owner.pid_type, 1);
  rcu_read_unlock();
#endif
  old_ep->alien_ref->_filp->f_owner.signum = priv->_filp->f_owner.signum;
  old_ep->alien_ref->_filp->f_flags |= priv->_filp->f_flags & O_NONBLOCK;

  /* Move os_socket from one ep to another */
  if( tcp_helper_endpoint_set_aflags(new_ep, OO_THR_EP_AFLAG_ATTACHED) &
      OO_THR_EP_AFLAG_ATTACHED ) {
    fput(old_ep->alien_ref->_filp);
    rc = -EBUSY;
    goto fail2; /* state & filters are cleared by fput() */
  }

  /********* Point of no return  **********/
  ci_wmb();
  priv->fd_type = CI_PRIV_TYPE_ALIEN_EP;
  priv->_filp->f_op = &linux_tcp_helper_fops_alien;
  ci_wmb();
  oo_file_moved(priv);

  /* Read all already-arrived packets after the filters move but before
   * copying of the receive queue. */
  ci_netif_poll(&old_thr->netif);
  tcp_helper_endpoint_move_filters_post(old_ep, new_ep);
  ci_assert( efab_file_move_supported(&old_thr->netif, old_s));

  /* There's a gap between un-registering the old ep, and registering the
   * the new.  However, the notifications shouldn't be in use for sockets
   * that are in a state that can be moved, so this shouldn't be a problem.
   */
  if( old_ep->os_sock_pt.whead ) {
    pollwait_register = 1;
    efab_tcp_helper_os_pollwait_unregister(old_ep);
  }
  ci_assert_equal(new_ep->os_socket, NULL);
  new_ep->os_socket = oo_file_ref_xchg(&old_ep->os_socket, NULL);
  ci_assert_equal(old_ep->os_socket, NULL);
  if( pollwait_register )
    efab_tcp_helper_os_pollwait_register(new_ep);

  ci_bit_clear(&new_s->b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
  if( new_s->b.state == CI_TCP_ESTABLISHED )
    CI_TCP_STATS_INC_CURR_ESTAB(alien_ni);


  /* Copy recv queue */
  if( new_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    ci_tcp_state *old_ts = SOCK_TO_TCP(old_s);
    int i;

    /* Stop timers */
    ci_ip_timer_clear(&old_thr->netif, &old_ts->kalive_tid);
    ci_ip_timer_clear(&old_thr->netif, &old_ts->delack_tid);

    efab_ip_queue_copy(alien_ni, &new_ts->recv1,
                       &old_thr->netif, &old_ts->recv1);
    efab_ip_queue_copy(alien_ni, &new_ts->recv2,
                       &old_thr->netif, &old_ts->recv2);
    new_ts->recv1_extract = new_ts->recv1.head;

    /* Drop reorder buffer */
    ci_ip_queue_init(&new_ts->rob);
    new_ts->dsack_block = OO_PP_INVALID;
    new_ts->dsack_start = new_ts->dsack_end = 0;
    for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      new_ts->last_sack[i] = OO_PP_NULL;
  }
  else {
    /* There should not be any recv q, but drop it to be sure */
    ci_udp_recv_q_init(&SOCK_TO_UDP(new_s)->recv_q);
  }

  /* Old stack can be unlocked */
  old_s->b.sb_flags |= CI_SB_FLAG_MOVED;
  ci_netif_unlock(&old_thr->netif);

  ci_assert( efab_file_move_supported(alien_ni, new_s) );

  /* Move done: poll for any new data. */
  ci_netif_poll(alien_ni);

  if( new_s->b.state & CI_TCP_STATE_TCP ) {
    ci_tcp_state *new_ts = SOCK_TO_TCP(new_s);
    /* Timers setup: delack, keepalive */
    if( (new_ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > 0)
      ci_tcp_timeout_delack(alien_ni, new_ts);
    ci_tcp_kalive_reset(alien_ni, new_ts);
  }


  /* Old ep: we are done. */
  ci_bit_set(&old_s->b.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_BIT);
  old_s->b.moved_to_stack_id = alien_ni->state->stack_id;
  old_s->b.moved_to_sock_id = new_s->b.bufid;
  if( ! list_empty(&priv->_filp->f_ep_links) )
    ci_bit_set(&old_s->b.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL_BIT);

  ci_sock_unlock(&old_thr->netif, &old_s->b);
  ci_sock_unlock(alien_ni, &new_s->b);
  ci_assert(ci_netif_is_locked(alien_ni));
  OO_DEBUG_TCPH(ci_log("%s: -> [%d:%d] %s", __func__,
                       new_thr->id, new_s->b.bufid,
                       ci_tcp_state_str(new_s->b.state)));
  return 0;

fail4:
  /* We clear the filters from the new ep.
   * For now, we do not need to re-insert old filters because hw filters
   * are alredy here (in case of accepted socket) or not needed.
   * We have not removed old sw filters yet. */
  tcp_helper_endpoint_move_filters_undo(old_ep, new_ep);
fail3:
  if( new_s->b.state & CI_TCP_STATE_TCP )
    ci_tcp_state_free(alien_ni, SOCK_TO_TCP(new_s));
  else
    ci_udp_state_free(alien_ni, SOCK_TO_UDP(new_s));
fail2:
  ci_netif_unlock(alien_ni);
fail1:
  ci_netif_unlock(&old_thr->netif);
fail1_ni_unlocked:
  ci_sock_unlock(&old_thr->netif, &old_s->b);
  OO_DEBUG_TCPH(ci_log("%s: rc=%d", __func__, rc));
  return rc;
}

int efab_file_move_to_alien_stack_rsop(ci_private_t *stack_priv, void *arg)
{
  ci_fixed_descriptor_t sock_fd = *(ci_fixed_descriptor_t *)arg;
  struct file *sock_file = fget(sock_fd);
  ci_private_t *sock_priv;
  tcp_helper_resource_t *old_thr;
  tcp_helper_resource_t *new_thr;
  citp_waitable *w;
  int rc;

  if( sock_file == NULL )
    return -EINVAL;
  if( !FILE_IS_ENDPOINT_SOCK(sock_file) ||
      stack_priv->fd_type != CI_PRIV_TYPE_NETIF ) {
    fput(sock_file);
    return -EINVAL;
  }
  sock_priv = sock_file->private_data;
  ci_assert(sock_priv->fd_type == CI_PRIV_TYPE_TCP_EP ||
            sock_priv->fd_type == CI_PRIV_TYPE_UDP_EP);

  old_thr = sock_priv->thr;
  new_thr = stack_priv->thr;
  ci_assert(old_thr);
  ci_assert(new_thr);

  if( old_thr == new_thr ) {
    fput(sock_file);
    return 0;
  }

  if( tcp_helper_cluster_from_cluster(old_thr) != 0 ) {
    LOG_S(ci_log("%s: move_fd() not permitted on clustered stacks", __func__));
    fput(sock_file);
    return -EINVAL;
  }

  w = SP_TO_WAITABLE(&old_thr->netif, sock_priv->sock_id);
  rc = ci_sock_lock(&old_thr->netif, w);
  if( rc != 0 ) {
    fput(sock_file);
    return rc;
  }

  rc = ci_netif_lock(&old_thr->netif);
  if( rc != 0 ) {
    ci_sock_unlock(&old_thr->netif, w);
    fput(sock_file);
    return rc;
  }

  efab_thr_ref(new_thr);
  rc = efab_file_move_to_alien_stack(sock_priv, &stack_priv->thr->netif);
  fput(sock_file);

  if( rc != 0 )
    efab_thr_release(new_thr);
  else
    ci_netif_unlock(&new_thr->netif);

  return rc;
}

/* Locking policy:
 * Enterance: priv->thr->netif is assumed to be locked.
 * Exit: all stacks (the client stack and the listener's stack) are
 * unlocked.
 */
int efab_tcp_loopback_connect(ci_private_t *priv, void *arg)
{
  struct oo_op_loopback_connect *carg = arg;
  ci_netif *alien_ni = NULL;
  oo_sp tls_id;

  ci_assert(ci_netif_is_locked(&priv->thr->netif));
  carg->out_moved = 0;

  if( !CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type) )
    return -EINVAL;
  if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_CONNSTACK &&
      NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_LISTSTACK &&
      NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
      CITP_TCP_LOOPBACK_TO_NEWSTACK) {
    ci_netif_unlock(&priv->thr->netif);
    return -EINVAL;
  }

  while( iterate_netifs_unlocked(&alien_ni) == 0 ) {

    if( !efab_thr_can_access_stack(netif2tcp_helper_resource(alien_ni),
                                   EFAB_THR_TABLE_LOOKUP_CHECK_USER) )
      continue; /* no permission to look in here */

    if( NI_OPTS(alien_ni).tcp_server_loopback == CITP_TCP_LOOPBACK_OFF )
      continue; /* server does not accept loopback connections */

    if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_TO_LISTSTACK &&
        NI_OPTS(alien_ni).tcp_server_loopback !=
        CITP_TCP_LOOPBACK_ALLOW_ALIEN_IN_ACCEPTQ )
      continue; /* options of the stacks to not match */

    if( NI_OPTS(&priv->thr->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_TO_LISTSTACK &&
        !efab_thr_user_can_access_stack(alien_ni->uid, alien_ni->euid,
                                        &priv->thr->netif) )
      continue; /* server can't accept our socket */

    tls_id = ci_tcp_connect_find_local_peer(alien_ni, carg->dst_addr,
                                            carg->dst_port);

    if( OO_SP_NOT_NULL(tls_id) ) {
      int rc;

      /* We are going to exit in this or other way: get ref and
       * drop kref of alien_ni */
      efab_thr_ref(netif2tcp_helper_resource(alien_ni));
      iterate_netifs_unlocked_dropref(alien_ni);

      switch( NI_OPTS(&priv->thr->netif).tcp_client_loopback ) {
      case CITP_TCP_LOOPBACK_TO_CONNSTACK:
        /* connect_lo_toconn unlocks priv->thr->netif */
        carg->out_rc =
            ci_tcp_connect_lo_toconn(&priv->thr->netif, priv->sock_id,
                                     carg->dst_addr, alien_ni, tls_id);
        efab_thr_release(netif2tcp_helper_resource(alien_ni));
        return 0;

      case CITP_TCP_LOOPBACK_TO_LISTSTACK:
        /* Nobody should be using this socket, so trylock should succeed.
         * Overwise we hand over the socket and do not accelerate this
         * loopback connection. */
        rc = ci_sock_trylock(&priv->thr->netif,
                             SP_TO_WAITABLE(&priv->thr->netif,
                                            priv->sock_id));
        if( rc == 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          return -ECONNREFUSED;
        }

        /* move_to_alien changes locks - see comments near it */
        rc = efab_file_move_to_alien_stack(priv, alien_ni);
        if( rc != 0 ) {
          /* error - everything is already unlocked */
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          /* if we return error, UL will hand the socket over. */
          return rc;
        }
        /* now alien_ni is locked */

        /* Connect again, using new endpoint */
        carg->out_rc =
            ci_tcp_connect_lo_samestack(
                            alien_ni,
                            SP_TO_TCP(alien_ni,
                                      SP_TO_WAITABLE(&priv->thr->netif,
                                                     priv->sock_id)
                                      ->moved_to_sock_id),
                            tls_id);
        ci_netif_unlock(alien_ni);
        carg->out_moved = 1;
        return 0;


      case CITP_TCP_LOOPBACK_TO_NEWSTACK:
      {
        tcp_helper_resource_t *new_thr;
        ci_resource_onload_alloc_t alloc;

        /* create new stack
         * todo: no hardware interfaces are necessary */
        strcpy(alloc.in_version, ONLOAD_VERSION);
        strcpy(alloc.in_uk_intf_ver, oo_uk_intf_ver);
        alloc.in_name[0] = '\0';
        alloc.in_flags = 0;

        rc = tcp_helper_alloc_kernel(&alloc, &NI_OPTS(&priv->thr->netif), 0,
                                     &new_thr);
        if( rc != 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          return -ECONNREFUSED;
        }

        rc = ci_sock_trylock(&priv->thr->netif,
                             SP_TO_WAITABLE(&priv->thr->netif,
                                            priv->sock_id));
        if( rc == 0 ) {
          ci_netif_unlock(&priv->thr->netif);
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          efab_thr_release(new_thr);
          return -ECONNREFUSED;
        }

        /* move connecting socket to the new stack */
        rc = efab_file_move_to_alien_stack(priv, &new_thr->netif);
        if( rc != 0 ) {
          /* error - everything is already unlocked */
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          efab_thr_release(new_thr);
          return -ECONNREFUSED;
        }
        /* now new_thr->netif is locked */
        carg->out_moved = 1;
        carg->out_rc = -ECONNREFUSED;

        /* now connect via CITP_TCP_LOOPBACK_TO_CONNSTACK */
        /* connect_lo_toconn unlocks new_thr->netif */
        carg->out_rc =
            ci_tcp_connect_lo_toconn(
                            &new_thr->netif,
                            SP_TO_WAITABLE(&priv->thr->netif,
                                           priv->sock_id)->moved_to_sock_id,
                            carg->dst_addr, alien_ni, tls_id);
        efab_thr_release(netif2tcp_helper_resource(alien_ni));
        return 0;
      }
      }
    }
    else if( tls_id == OO_SP_INVALID )
      break;
  }

  ci_netif_unlock(&priv->thr->netif);
  return -ENOENT;
}

