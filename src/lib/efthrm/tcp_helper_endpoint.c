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

  oof_socket_ctor(&ep->oofilter);
}

/*--------------------------------------------------------------------*/


/* See description in include/driver/efab/tcp_helper_endpoint.h */
void
tcp_helper_endpoint_dtor(tcp_helper_endpoint_t * ep)
{
  ci_irqlock_state_t lock_flags;

  /* the endpoint structure stays in the array in the THRM even after
     it is freed - therefore ensure properly cleaned up */
  OO_DEBUG_VERB(ci_log(FEP_FMT, FEP_PRI_ARGS(ep)));

  oof_socket_del(efab_tcp_driver.filter_manager, &ep->oofilter);
  oof_socket_mcast_del_all(efab_tcp_driver.filter_manager, &ep->oofilter);
  oof_socket_dtor(&ep->oofilter);

  ci_irqlock_lock(&ep->thr->lock, &lock_flags);
  if( ep->os_socket != NULL ) {
    OO_DEBUG_ERR(ci_log(FEP_FMT "ERROR: O/S socket still referenced",
                        FEP_PRI_ARGS(ep)));
    oo_file_ref_drop(ep->os_socket);
    ep->os_socket = NULL;
  }
  ci_irqlock_unlock(&ep->thr->lock, &lock_flags);

  ci_waitable_dtor(&ep->waitq);

  ci_assert(ep->n_pinned_pages == 0);

  ep->id = OO_SP_NULL;
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
  ci_irqlock_state_t lock_flags;

  /* Grab reference to the O/S socket.  This will be consumed by
   * oof_socket_add() if it succeeds.  [from_tcp_id] identifies a listening
   * TCP socket, and is used when we're setting filters for a passively
   * opened TCP connection.
   */
  ci_irqlock_lock(&ep->thr->lock, &lock_flags);
  if( OO_SP_NOT_NULL(from_tcp_id) ) {
    listen_ep = ci_trs_get_valid_ep(ep->thr, from_tcp_id);
    os_sock_ref = listen_ep->os_socket;
  }
  else {
    os_sock_ref = ep->os_socket;
  }
  if( os_sock_ref != NULL )
    os_sock_ref = oo_file_ref_add(os_sock_ref);
  ci_irqlock_unlock(&ep->thr->lock, &lock_flags);

  /* Loopback sockets do not need filters */
  if( OO_SP_NOT_NULL(s->local_peer) ) {
    rc = 0;
    goto set_os_port_keeper_and_out;
  }

  laddr = sock_laddr_be32(s);
  raddr = sock_raddr_be32(s);
  lport = sock_lport_be16(s);
  rport = sock_rport_be16(s);
  protocol = sock_protocol(s);

  if( ep->oofilter.sf_local_port != NULL ) {
    /* we already have a filter; and we also have a reference of OS socket. */
    ci_assert(ep->os_port_keeper);
    oo_file_ref_drop(os_sock_ref);
    os_sock_ref = NULL;
    if( protocol == IPPROTO_UDP && raddr != 0 &&
        ep->oofilter.sf_raddr == 0 ) {
      return oof_udp_connect(efab_tcp_driver.filter_manager, &ep->oofilter,
                             laddr, raddr, rport);
    }
    oof_socket_del(efab_tcp_driver.filter_manager, &ep->oofilter);
  }

  if( OO_SP_NOT_NULL(from_tcp_id) )
    rc = oof_socket_share(efab_tcp_driver.filter_manager, &ep->oofilter,
                          &listen_ep->oofilter, laddr, raddr, rport);
  else
    rc = oof_socket_add(efab_tcp_driver.filter_manager, &ep->oofilter,
                        protocol, laddr, lport, raddr, rport);

 set_os_port_keeper_and_out:
  if( os_sock_ref != NULL && rc == 0 )
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
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

int
tcp_helper_endpoint_clear_filters(tcp_helper_endpoint_t* ep)
{
  struct oo_file_ref* os_sock_ref;

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] %s", __FUNCTION__, ep->thr->id,
                       OO_SP_FMT(ep->id), in_atomic() ? "ATOMIC":""));

  if( in_atomic() ) {
    /* Remove software filters immediately to ensure packets are not
     * delivered to this endpoint.  Defer oof_socket_del() if needed
     * to non-atomic context.
     */
    if( oof_socket_del_sw(efab_tcp_driver.filter_manager, &ep->oofilter) )
      tcp_helper_endpoint_queue_non_atomic(ep, OO_THR_EP_AFLAG_CLEAR_FILTERS);
    else {
      os_sock_ref = oo_file_ref_xchg(&ep->os_port_keeper, NULL);
      ci_assert(os_sock_ref);
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
  return 0;
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
  int rc;

  /* Calling shutdown on the socket unbinds it in most situations.
   * Since we must never have a filter configured for an unbound
   * socket, we clear the filters here. */
  tcp_helper_endpoint_clear_filters(ep);

  rc = efab_tcp_helper_shutdown_os_sock(ep, how);

  if( old_state == CI_TCP_LISTEN ) {
    ci_assert(ci_netif_is_locked(&thr->netif));
    ci_tcp_listen_shutdown_queues(&thr->netif,
                                  SP_TO_TCP_LISTEN(&thr->netif, ep->id));
  }
  return rc;
}
