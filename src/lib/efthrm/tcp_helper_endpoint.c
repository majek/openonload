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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
**  \brief Kernel-private endpoints routines
**   \date Started at Jul, 29 2004
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/debug.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/oof_interface.h>
#include <onload/drv/dump_to_user.h>
#include "tcp_filters_internal.h"
#include "oof_impl.h"


/************************************************************************** \
*
\**************************************************************************/

/* See description in include/driver/efab/tcp_helper_endpoint.h */
void
tcp_helper_endpoint_ctor(tcp_helper_endpoint_t *ep,
                         tcp_helper_resource_t * thr,
                         int id)
{
  OO_DEBUG_VERB(ci_log("%s: ID=%d", __FUNCTION__, id));

  CI_ZERO(ep);
  ep->thr = thr;
  ep->id = OO_SP_FROM_INT(&thr->netif, id);

  ci_dllink_self_link(&ep->ep_with_pinned_pages);
  ci_dllist_init(&ep->pinned_pages);
  ep->n_pinned_pages = 0;

  ci_waitable_ctor(&ep->waitq);

  ep->os_port_keeper = NULL;
  ep->os_socket = NULL;
  ep->wakeup_next = 0;
  ep->fasync_queue = NULL;
  ep->ep_aflags = 0;
  ep->alien_ref = NULL;
  spin_lock_init(&ep->lock);
  oo_os_sock_poll_ctor(&ep->os_sock_poll);
  init_waitqueue_func_entry(&ep->os_sock_poll.wait, efab_os_sock_callback);

  ci_dllink_self_link(&ep->os_ready_link);

  oof_socket_ctor(&ep->oofilter);
}

/*--------------------------------------------------------------------*/


/* See description in include/onload/tcp_helper_endpoint.h */
void
tcp_helper_endpoint_dtor(tcp_helper_endpoint_t * ep)
{
  unsigned long lock_flags;

  /* We need to release zero, one or two file references after dropping a
   * spinlock. */
  struct oo_file_ref* files_to_drop[2];
  int num_files_to_drop = 0;
  int i;

  /* the endpoint structure stays in the array in the THRM even after
     it is freed - therefore ensure properly cleaned up */
  OO_DEBUG_VERB(ci_log(FEP_FMT, FEP_PRI_ARGS(ep)));

  oof_socket_del(efab_tcp_driver.filter_manager, &ep->oofilter);
  oof_socket_mcast_del_all(efab_tcp_driver.filter_manager, &ep->oofilter);
  oof_socket_dtor(&ep->oofilter);

  spin_lock_irqsave(&ep->lock, lock_flags);
  if( ep->os_socket != NULL ) {
    OO_DEBUG_ERR(ci_log(FEP_FMT "ERROR: O/S socket still referenced",
                        FEP_PRI_ARGS(ep)));
    files_to_drop[num_files_to_drop++] = ep->os_socket;
    ep->os_socket = NULL;
  }
  if( ep->os_port_keeper != NULL ) {
    files_to_drop[num_files_to_drop++] = ep->os_port_keeper;
    ep->os_port_keeper = NULL;
  }
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  for( i = 0; i < num_files_to_drop; ++i )
    oo_file_ref_drop(files_to_drop[i]);

  if( ep->alien_ref != NULL ) {
    OO_DEBUG_ERR(ci_log(FEP_FMT "ERROR: alien socket still referenced",
                        FEP_PRI_ARGS(ep)));
    fput(ep->alien_ref->_filp);
    ep->alien_ref = NULL;
  }

  ci_waitable_dtor(&ep->waitq);

  ci_assert(ep->n_pinned_pages == 0);

  ep->id = OO_SP_NULL;
}


static int
tcp_helper_endpoint_reuseaddr_cleanup(ci_netif* ni, ci_sock_cmn* s)
{
  int i;

  if( (~s->b.state & CI_TCP_STATE_TCP) || s->b.state == CI_TCP_LISTEN )
    return 0;

  for( i = 0; i < (int)ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, i);
    
    if( wo->waitable.state != CI_TCP_TIME_WAIT )
      continue;

    if( sock_raddr_be32(s) != sock_raddr_be32(&wo->sock) ||
        sock_rport_be16(s) != sock_rport_be16(&wo->sock) ||
        sock_laddr_be32(s) != sock_laddr_be32(&wo->sock) ||
        sock_lport_be16(s) != sock_lport_be16(&wo->sock) )
      continue;

    /* We've found something to drop! */
    ci_tcp_drop(ni, SOCK_TO_TCP(&wo->sock), 0);
    return 1;
  }

  return 0;
}

/*--------------------------------------------------------------------
 *!
 * Called by TCP/IP stack to setup all the filters needed for a
 * TCP/UDP endpoint. This includes
 *    - hardware IP filters
 *    - filters in the software connection hash table
 *    - filters for NET to CHAR driver comms to support fragments
 *
 * \param ep              endpoint kernel data structure
 * \param phys_port       L5 physical port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 *
 * \return                standard error codes
 *
 * Examples supported:
 *    laddr/lport   raddr/rport    extra        Comment
 *      ------       --------     ------        -------
 *      lIP/lp        rIP/rp     from_tcp_id<0  Fully specified
 *      lIP/lp        0/0        from_tcp_id<0  listen on local IP address
 *      0/lp          0/0        phys_port=-1   listen on IPADDR_ANY
 *      0/lp          0/0        phys_port=n    listen on BINDTODEVICE
 *      lIP/lp        rIP/rp     from_tcp_id=n  TCP connection passively opened
 *                                              (use filter from this TCP ep)
 *      aIP/ap        rIP/rp     s_flags & TPROXY
 *                               && phys_port=n TCP connection using transparent
 *                                              shared filter
 *
 *
 *--------------------------------------------------------------------*/


int
tcp_helper_endpoint_set_filters(tcp_helper_endpoint_t* ep,
                                ci_ifid_t bindto_ifindex, oo_sp from_tcp_id)
{
  struct oo_file_ref* os_sock_ref;
  ci_netif* ni = &ep->thr->netif;
  ci_sock_cmn* s = SP_TO_SOCK(ni, ep->id);
  tcp_helper_endpoint_t* listen_ep = NULL;
  unsigned laddr, raddr;
  int protocol, lport, rport;
  int rc;
  unsigned long lock_flags;

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] bindto_ifindex=%d from_tcp_id=%d",
                       __FUNCTION__, ep->thr->id,
                       OO_SP_FMT(ep->id), bindto_ifindex, from_tcp_id));

  /* The lock is needed for assertions with CI_NETIF_FLAG_IN_DL_CONTEXT
   * flag only. */
  ci_assert( ci_netif_is_locked(&ep->thr->netif) );

  laddr = sock_laddr_be32(s);
  raddr = sock_raddr_be32(s);
  lport = sock_lport_be16(s);
  rport = sock_rport_be16(s);
  protocol = sock_protocol(s);

  /* Grab reference to the O/S socket.  This will be consumed by
   * oof_socket_add() if it succeeds.  [from_tcp_id] identifies a listening
   * TCP socket, and is used when we're setting filters for a passively
   * opened TCP connection.
   */
  spin_lock_irqsave(&ep->lock, lock_flags);
  if( OO_SP_NOT_NULL(from_tcp_id) ) {
    listen_ep = ci_trs_get_valid_ep(ep->thr, from_tcp_id);
    os_sock_ref = listen_ep->os_socket;
  }
  else {
    os_sock_ref = ep->os_socket;
  }
  if( os_sock_ref != NULL )
    os_sock_ref = oo_file_ref_add(os_sock_ref);
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  /* Loopback sockets do not need filters */
  if( (s->b.state & CI_TCP_STATE_TCP) && s->b.state != CI_TCP_LISTEN &&
      OO_SP_NOT_NULL(SOCK_TO_TCP(s)->local_peer) ) {
    rc = 0;
    goto set_os_port_keeper_and_out;
  }

  if( oof_socket_is_armed(&ep->oofilter) ) {
    /* We already have a filter.  The only legitimate way to get here is
     * UDP connect() including disconnect.
     * However, the user can call OO_IOC_EP_FILTER_SET for any endpoint,
     * and we should not crash (at least in NDEBUG build). */
    ci_assert(ep->os_port_keeper);
    ci_assert( ! in_atomic() );
    ci_assert( ~ep->thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );
    ci_assert_equal(protocol, IPPROTO_UDP);

    /* Closing a listening socket without being able to get the stack
     * lock will free the OS socket but not much else, so we need to
     * cope with os_sock_ref == NULL.  We don't expect this to also
     * result in the filter already existing (so shouldn't get here in
     * that situation) but need to be robust to misbehaving UL.
     */
    if( os_sock_ref != NULL ) {
      oo_file_ref_drop(os_sock_ref);
      os_sock_ref = NULL;
    }
    else {
      OO_DEBUG_ERR(ci_log(
        "ERROR: %s is changing the socket [%d:%d] filter to "
        "%s %s:%d -> %s:%d, "
        "the filter already exists and there is no backing socket.  "
        "Something went awry.",
        __func__, ep->thr->id, OO_SP_FMT(ep->id),
        protocol == IPPROTO_UDP ? "UDP" : "TCP",
        ip_addr_str(laddr), lport, ip_addr_str(raddr), rport));
      ci_assert(0);
    }
    if( protocol == IPPROTO_UDP && raddr != 0 &&
        ep->oofilter.sf_raddr == 0 ) {
      return oof_udp_connect(efab_tcp_driver.filter_manager, &ep->oofilter,
                             laddr, raddr, rport);
    }
    if( protocol != IPPROTO_UDP ) {
      /* UDP re-connect is OK, but we do not expect anything else.
       * We've already crashed in DEBUG, but let's complain in NDEBUG. */
      OO_DEBUG_ERR(ci_log(
        "ERROR: %s is changing the socket [%d:%d] filter to "
        "%s %s:%d -> %s:%d, "
        "but some filter is already installed.  Something went awry.",
        __func__, ep->thr->id, OO_SP_FMT(ep->id),
        protocol == IPPROTO_UDP ? "UDP" : "TCP",
        ip_addr_str(laddr), lport, ip_addr_str(raddr), rport));
      /* Filter is cleared so that endpoint comes back to consistent state:
       * tcp sockets after failed set filter operations have no filter.
       * However, as we are afraid that endpoint is compromised we
       * return error to prevent its use. */
      tcp_helper_endpoint_clear_filters
        (ep, ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT, 0);
      return -EALREADY;
    }
    oof_socket_del(efab_tcp_driver.filter_manager, &ep->oofilter);
  }

  /* Assuming that sockets that already use MAC filter do not enter here.
   * We would have no information on how to clear the MAC filter. */
  ci_assert((s->s_flags & CI_SOCK_FLAG_MAC_FILTER) == 0);

  if( ci_tcp_use_mac_filter(ni, s, bindto_ifindex, from_tcp_id) )
    rc = ci_tcp_sock_set_scalable_filter(ni, SP_TO_TCP(ni, ep->id));
  else if( OO_SP_NOT_NULL(from_tcp_id) )
    rc = oof_socket_share(efab_tcp_driver.filter_manager, &ep->oofilter,
                          &listen_ep->oofilter, laddr, raddr, rport);
  else {
    int flags;
    ci_assert( ! in_atomic() );
    ci_assert( ~ep->thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );

    flags = (ep->thr->thc != NULL && (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0) ?
            OOF_SOCKET_ADD_FLAG_CLUSTERED : 0;
    rc = oof_socket_add(efab_tcp_driver.filter_manager, &ep->oofilter,
                        flags, protocol, laddr, lport, raddr, rport, NULL);
    if( rc != 0 && rc != -EFILTERSSOME &&
        (s->s_flags & CI_SOCK_FLAG_REUSEADDR) &&
        tcp_helper_endpoint_reuseaddr_cleanup(&ep->thr->netif, s) ) {
      rc = oof_socket_add(efab_tcp_driver.filter_manager, &ep->oofilter,
                          flags, protocol, laddr, lport, raddr, rport, NULL);
    }
    if( rc == 0 || rc == -EFILTERSSOME )
      s->s_flags |= CI_SOCK_FLAG_FILTER;
  }

 set_os_port_keeper_and_out:
  if( os_sock_ref != NULL && (rc == 0 || rc == -EFILTERSSOME) )
    os_sock_ref = oo_file_ref_xchg(&ep->os_port_keeper, os_sock_ref);
  if( os_sock_ref != NULL )
    oo_file_ref_drop(os_sock_ref);
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param ep              endpoint kernel data structure
 * \param supress_hw_ops  set to 1 if you know you are in a context 
 *                        where hw ops are not safe
 * \param need_update     whether the filter details need update before clear
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

int
tcp_helper_endpoint_clear_filters(tcp_helper_endpoint_t* ep, 
                                  int supress_hw_ops, int need_update)
{
  struct oo_file_ref* os_sock_ref;
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int rc = 0;

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] %s %s", __FUNCTION__, ep->thr->id,
                       OO_SP_FMT(ep->id), 
                       in_atomic() ? "ATOMIC":"",
                       supress_hw_ops ? "SUPRESS_HW":""));

  ci_assert((s->s_flags & CI_SOCK_FLAG_FILTER) == 0 ||
            (s->s_flags & CI_SOCK_FLAG_MAC_FILTER) == 0);

#if CI_CFG_FD_CACHING
  if( need_update && !(s->s_flags & CI_SOCK_FLAG_MAC_FILTER) )
    tcp_helper_endpoint_update_filter_details(ep);
#endif

  if( in_atomic() ) {
    ci_assert( supress_hw_ops );
  }

  if( (s->s_flags & CI_SOCK_FLAG_MAC_FILTER) != 0 ) {
    ci_tcp_sock_clear_scalable_filter(&ep->thr->netif,
                                      SP_TO_TCP(&ep->thr->netif,ep->id));

    os_sock_ref = oo_file_ref_xchg(&ep->os_port_keeper, NULL);
    if( os_sock_ref != NULL )
      oo_file_ref_drop(os_sock_ref);
  }
  else if( supress_hw_ops ) {
    /* Remove software filters immediately to ensure packets are not
     * delivered to this endpoint.  Defer oof_socket_del() if needed
     * to non-atomic context.
     */
    if( oof_socket_del_sw(efab_tcp_driver.filter_manager, &ep->oofilter) ) {
      tcp_helper_endpoint_queue_non_atomic(ep, OO_THR_EP_AFLAG_CLEAR_FILTERS);
      /* If we have been called from atomic context, we sill might actually
       * have a hw filter. However in such a case there is a non-atomic work
       * pending on endpoint to sort that out - we fall through to clearing
       * socket filter flags */
      rc = -EAGAIN;
    }
    else {
      os_sock_ref = oo_file_ref_xchg(&ep->os_port_keeper, NULL);
      if( os_sock_ref != NULL )
        oo_file_ref_drop(os_sock_ref);
    }
  }
  else {
    oof_socket_del(efab_tcp_driver.filter_manager, &ep->oofilter);
    oof_socket_mcast_del_all(efab_tcp_driver.filter_manager, &ep->oofilter);
    os_sock_ref = oo_file_ref_xchg(&ep->os_port_keeper, NULL);
    if( os_sock_ref != NULL )
      oo_file_ref_drop(os_sock_ref);
  }

  SP_TO_SOCK(&ep->thr->netif, ep->id)->s_flags &=
                              ~(CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_MAC_FILTER);

  return rc;
}

/******************* Move Filters from one ep to another ****************/
/* We support full move in 3 cases:
 * - closed TCP socket: no filters;
 * - closed UDP socket: no filters;
 * - accepted TCP socket:
 *   ep_from has shared filter,
 *   ep_to gets full filter and os socket ref
 *
 * We also support move without filters (drop_filter = true) in one case:
 * - clustered dummy tcp socket that is connecting to loopback address.
 *   hw and sw filter is left behind to be cleared in '_post' phase function.
 *   That is in fact we move os_port_keeper only.
 */

/* Move filters from one endpoint to another: called BEFORE the real move.
 * This function MUST NOT clear software filters from ep_from,
 * because there might be handled packets for it in the stack rx queue.
 */
int
tcp_helper_endpoint_move_filters_pre(tcp_helper_endpoint_t* ep_from,
                                     tcp_helper_endpoint_t* ep_to,
                                     int drop_filter)
{
  struct oo_file_ref* os_sock_ref;
  int rc;
  ci_sock_cmn* s = SP_TO_SOCK(&ep_from->thr->netif, ep_from->id);

  ci_assert(!in_atomic());

  if( ep_to->os_port_keeper != NULL ) {
    ci_log("%s: non-null target port keeper", __func__);
    ci_assert(0);
    return -EINVAL;
  }

  if( ! drop_filter && s->b.state != CI_TCP_CLOSED &&
      ep_from->oofilter.sf_local_port != NULL ) {
    if( (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0 ) {
      LOG_E(ci_log("%s: ERROR: reuseport being set and socket not closed",
                   __func__));
      return -EINVAL;
    }
    rc = tcp_helper_endpoint_set_filters(ep_to, CI_IFID_ALL, OO_SP_NULL);
    if( rc != 0 )
      return rc;
  }

  os_sock_ref = oo_file_ref_xchg(&ep_from->os_port_keeper, NULL);
  if( os_sock_ref != NULL ) {
    struct oo_file_ref* old_ref;
    old_ref = oo_file_ref_xchg(&ep_to->os_port_keeper, os_sock_ref);
    ci_assert_equal(old_ref, NULL);
    if( old_ref != NULL )
      oo_file_ref_drop(old_ref);
  }


  return 0;
}

/* Move filters from one endpoint to another: called AFTER the real move.
 * All ep_from filters should be cleared;
 * ep_to should have properly-installed filters.
 */
void
tcp_helper_endpoint_move_filters_post(tcp_helper_endpoint_t* ep_from,
                                      tcp_helper_endpoint_t* ep_to)
{
  tcp_helper_endpoint_clear_filters(ep_from, 0, 0);
}

/* Move filters from one endpoint to another: undo the actions from pre().
 * All ep_to filters should be cleared;
 * ep_from should have properly-installed filters.
 */
void
tcp_helper_endpoint_move_filters_undo(tcp_helper_endpoint_t* ep_from,
                                      tcp_helper_endpoint_t* ep_to)
{
  struct oo_file_ref* os_sock_ref;

  os_sock_ref = oo_file_ref_xchg(&ep_to->os_port_keeper, NULL);
  if( os_sock_ref != NULL ) {
    struct oo_file_ref* old_ref;
    old_ref = oo_file_ref_xchg(&ep_from->os_port_keeper, os_sock_ref);
    ci_assert_equal(old_ref, NULL);
    if( old_ref != NULL )
      oo_file_ref_drop(old_ref);
  }

  tcp_helper_endpoint_clear_filters(ep_to, 0, 0);
}

void
tcp_helper_endpoint_update_filter_details(tcp_helper_endpoint_t* ep)
{
  ci_netif* ni = &ep->thr->netif;
  ci_sock_cmn* s = SP_TO_SOCK(ni, ep->id);

  if( !(s->s_flags & CI_SOCK_FLAG_MAC_FILTER) )
    oof_socket_update_sharer_details(efab_tcp_driver.filter_manager,
                                     &ep->oofilter,
                                     sock_raddr_be32(s), sock_rport_be16(s));
}

static void oof_socket_dump_fn(void* arg, oo_dump_log_fn_t log, void* log_arg)
{
  oof_socket_dump(efab_tcp_driver.filter_manager, arg, log, log_arg);
}


static void oof_manager_dump_fn(void* arg, oo_dump_log_fn_t log, void* log_arg)
{
  oof_manager_dump(efab_tcp_driver.filter_manager, log, log_arg);
}


int
tcp_helper_endpoint_filter_dump(tcp_helper_resource_t* thr, oo_sp sockp,
                                void* user_buf, int user_buf_len)
{
  if( OO_SP_NOT_NULL(sockp) ) {
    tcp_helper_endpoint_t* ep = ci_trs_get_valid_ep(thr, sockp);
    return oo_dump_to_user(oof_socket_dump_fn, &ep->oofilter,
                           user_buf, user_buf_len);
  }
  else {
    return oo_dump_to_user(oof_manager_dump_fn, NULL, user_buf, user_buf_len);
  }
}


/*--------------------------------------------------------------------
 *!
 * Shutdown endpoint socket
 *
 * \param thr             TCP helper resource
 * \param ep_id           ID of endpoint
 * \param how             How to shutdown the socket
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

int
tcp_helper_endpoint_shutdown(tcp_helper_resource_t* thr, oo_sp ep_id,
                             int how, ci_uint32 old_state)
{
  tcp_helper_endpoint_t * ep = ci_trs_ep_get(thr, ep_id);
  int rc, supress_hw_ops = thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT;

#if CI_CFG_FD_CACHING
  /* This must be done before we remove filters, as the information must be
   * correct for sockets sharing our filter when we do the un-share fixup.
   */
  if( old_state == CI_TCP_LISTEN )
    ci_tcp_listen_update_cached(&thr->netif,
                                SP_TO_TCP_LISTEN(&thr->netif, ep->id));
#endif

  /* Calling shutdown on the socket unbinds it in most situations.
   * Since we must never have a filter configured for an unbound
   * socket, we clear the filters here. */
  tcp_helper_endpoint_clear_filters(ep, supress_hw_ops, 0);
  /* Filter flags should have been cleared by
   * tcp_helper_endpoint_clear_filters.
   */
  ci_assert_nflags(SP_TO_SOCK(&thr->netif, ep_id)->s_flags,
                   (CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_MAC_FILTER));

  rc = efab_tcp_helper_shutdown_os_sock(ep, how);

  if( old_state == CI_TCP_LISTEN ) {
    ci_assert(ci_netif_is_locked(&thr->netif));
    ci_tcp_listen_shutdown_queues(&thr->netif,
                                  SP_TO_TCP_LISTEN(&thr->netif, ep->id));
  }
  return rc;
}
