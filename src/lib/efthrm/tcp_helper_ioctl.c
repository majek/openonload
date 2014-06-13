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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/02/20
** Description: Implementation of "ops" invoked by user-level.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>
# include <onload/linux_onload_internal.h>
# include <onload/linux_onload.h>
# include <onload/linux_sock_ops.h>
# include <onload/linux_trampoline.h>
#include <onload/cplane.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/efabcfg.h>
#include <onload/oof_interface.h>
#include <onload/version.h>


int
efab_ioctl_get_ep(ci_private_t* priv, oo_sp sockp,
                  tcp_helper_endpoint_t** ep_out)
{
  ci_assert(ep_out != NULL);
  if( priv->thr == NULL || ! IS_VALID_SOCK_P(&priv->thr->netif, sockp) )
    return -EINVAL;
  *ep_out = ci_trs_ep_get(priv->thr, sockp);
  ci_assert(*ep_out != NULL);
  return 0;
}


static int
oo_priv_set_stack(ci_private_t* priv, tcp_helper_resource_t* trs)
{
  ci_uintptr_t* p = (ci_uintptr_t*) &priv->thr;
  ci_uintptr_t old, new = (ci_uintptr_t) trs;

  do {
    if( (old = *p) != 0 ) {
      LOG_E(ci_log("%s: ERROR: stack already attached", __FUNCTION__));
      return -EINVAL;
    }
  } while( ci_cas_uintptr_fail(p, old, new) );

  return 0;
}


static int
oo_priv_lookup_and_attach_stack(ci_private_t* priv, const char* name,
                                unsigned id)
{
  tcp_helper_resource_t* trs;
  int rc;
  if( (rc = efab_thr_table_lookup(name, id,
                                  EFAB_THR_TABLE_LOOKUP_CHECK_USER,
                                  &trs)) == 0 ) {
    if( (rc = oo_priv_set_stack(priv, trs)) == 0 ) {
      priv->fd_type = CI_PRIV_TYPE_NETIF;
      priv->sock_id = OO_SP_NULL;
    }
    else
      efab_thr_release(trs);
  }
  return rc;
}


static int
efab_tcp_helper_stack_attach(ci_private_t* priv, void *arg)
{
  oo_stack_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  int rc;

  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }
  OO_DEBUG_TCPH(ci_log("%s: [%d]", __FUNCTION__, NI_ID(&trs->netif)));

  rc = oo_create_stack_fd(trs);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: oo_create_stack_fd failed (%d)",
                        __FUNCTION__, rc));
    return rc;
  }
  op->fd = rc;

  /* Re-read the OS socket buffer size settings.  This ensures we'll use
   * up-to-date values for this new socket.
   */
  efab_get_os_settings(&NI_OPTS_TRS(trs));
  op->out_nic_set = trs->netif.nic_set;
  op->out_map_size = trs->mem_mmap_bytes;
  return 0;
}

static int
efab_tcp_helper_sock_attach(ci_private_t* priv, void *arg)
{
  oo_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc, flags, type = op->type;

/* SOCK_CLOEXEC and SOCK_NONBLOCK exist from 2.6.27 both */
#ifdef SOCK_TYPE_MASK
  BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
  flags = type & (SOCK_CLOEXEC | SOCK_NONBLOCK);
  type &= SOCK_TYPE_MASK;
# ifdef SOCK_NONBLOCK
    if( SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK) )
      flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
# endif
#else
  flags = 0;
#endif

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;
  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  if( ci_cas32u_fail(&ep->aflags, 0, OO_THR_EP_AFLAG_ATTACHED ) )
    return -EBUSY;
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);

  /* create OS socket */
  if( op->domain != AF_UNSPEC ) {
    struct socket *sock;
    int sock_fd;

    rc = sock_create(op->domain, type, 0, &sock);
    if( rc < 0 ) {
      LOG_E(ci_log("%s: ERROR: sock_create(%d, %d, 0) failed (%d)",
                   __FUNCTION__, op->domain, type, rc));
      ep->aflags = 0;
      return rc;
    }
#ifdef SOCK_TYPE_MASK
    sock_fd = sock_map_fd(sock, flags | SOCK_CLOEXEC);
#else
    sock_fd = sock_map_fd(sock);
#endif
    if( sock_fd < 0 ) {
      LOG_E(ci_log("%s: ERROR: sock_map_fd failed (%d)",
                   __FUNCTION__, sock_fd));
      ep->aflags = 0;
      return sock_fd;
    }
    rc = efab_attach_os_socket(ep, sock_fd);
    if( rc < 0 ) {
      LOG_E(ci_log("%s: ERROR: efab_attach_os_socket failed (%d)",
                   __FUNCTION__, rc));
      efab_linux_sys_close(sock_fd);
      ep->aflags = 0;
      return rc;
    }
    wo->sock.domain = op->domain;
    wo->sock.ino = ep->os_socket->file->f_dentry->d_inode->i_ino;
    wo->sock.uid = ep->os_socket->file->f_dentry->d_inode->i_uid;
  }

  /* Create a new file descriptor to attach the stack to. */
  ci_assert((wo->waitable.state & CI_TCP_STATE_TCP) ||
            wo->waitable.state == CI_TCP_STATE_UDP);
  rc = oo_create_fd(ep, flags,
                    (wo->waitable.state & CI_TCP_STATE_TCP) ?
                    CI_PRIV_TYPE_TCP_EP : CI_PRIV_TYPE_UDP_EP);
  if( rc < 0 ) {
    ci_irqlock_state_t lock_flags;
    ci_irqlock_lock(&ep->thr->lock, &lock_flags);
    if( ep->os_socket != NULL ) {
      oo_file_ref_drop(ep->os_socket);
      ep->os_socket = NULL;
    }
    ci_irqlock_unlock(&ep->thr->lock, &lock_flags);
    ep->aflags = 0;
    return rc;
  }

  op->fd = rc;
#ifdef SOCK_NONBLOCK
  if( op->type & SOCK_NONBLOCK )
    ci_bit_mask_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_O_NONBLOCK);
#endif

  /* Re-read the OS socket buffer size settings.  This ensures we'll use
   * up-to-date values for this new socket.
   */
  efab_get_os_settings(&NI_OPTS_TRS(trs));
  return 0;
}

static int
efab_tcp_helper_pipe_attach(ci_private_t* priv, void *arg)
{
  oo_pipe_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  int rc;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;
  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  if( ci_cas32u_fail(&ep->aflags, 0, OO_THR_EP_AFLAG_ATTACHED ) )
    return -EBUSY;

  rc = oo_create_fd(ep, op->flags, CI_PRIV_TYPE_PIPE_READER);
  if( rc < 0 ) {
    ep->aflags = 0;
    return rc;
  }
  op->rfd = rc;

  rc = oo_create_fd(ep, op->flags, CI_PRIV_TYPE_PIPE_WRITER);
  if( rc < 0 ) {
    efab_linux_sys_close(op->rfd);
    ep->aflags = 0;
    return rc;
  }
  op->wfd = rc;

  return 0;
}


/*--------------------------------------------------------------------
 *!
 * Moves a endpoint state from current TCP helper resource to new
 * TCP helper resource. Moves OS file pointer and redirects state
 * in associated OS file to point to the new state
 *
 * \todo FIXME this is security hole! we should not get new_trs_id
 *             from user space!
 *
 * \param priv            Provate structure of associated OS file
 * \param op              TCP state endpoint id of new and old states;
 *                        id of new TCP resource to move to
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

static int
efab_tcp_helper_move_state(ci_private_t* priv, void *arg)
{
  oo_tcp_move_state_t *op = arg;
  tcp_helper_endpoint_t *new_ep;
  tcp_helper_resource_t * new_trs = NULL;
  ci_netif* ni, *new_ni;
  ci_tcp_state * ts, *new_ts;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->ep_id, &ep);
  if (rc != 0)
    return rc;

  OO_DEBUG_TCPH(ci_log("%s: (trs=%p (%u), priv=%p, ep_id=%u, new_trs_id=%u, "
                       "new_ep_id=%u", __FUNCTION__, priv->thr, priv->thr->id,
                       priv, OO_SP_FMT(op->ep_id), op->new_trs_id,
                       OO_SP_FMT(op->new_ep_id)));
  OO_DEBUG_TCPH(THR_PRIV_DUMP(priv, ""));

  do {
    /* check that the existing id is valid */
    ni = &priv->thr->netif;
    ts = SP_TO_TCP(ni, ep->id);

    /* TODO: check this endpoint belongs to the tcp helper resource of priv and not
     * somewhere else */
    
    /* this function does not change fd_type or fd ops, so it is not able
     * to cope with changing the socket type. We think this only makes sense
     * for TCP, so assert we are taking a TCP endpoint.
     */
    ci_assert_equal(ts->s.pkt.ip.ip_protocol, IPPROTO_TCP);
    ci_assert_equal(priv->fd_type, CI_PRIV_TYPE_TCP_EP);

    /* get pointer to resource from handle - increments ref count */
    rc = efab_thr_table_lookup(NULL, op->new_trs_id,
                               EFAB_THR_TABLE_LOOKUP_CHECK_USER, &new_trs);
    if (rc < 0) {
      OO_DEBUG_ERR( ci_log("%s: invalid new resource handle", __FUNCTION__) );
      break;
    }
    ci_assert(new_trs != NULL);
    /* check valid endpoint in new netif */
    new_ni = &new_trs->netif;
    new_ep = ci_netif_get_valid_ep(new_ni, op->new_ep_id);
    new_ts = SP_TO_TCP(new_ni, new_ep->id);

    /* check the two endpoint states look valid */
    if( (ts->s.pkt.ip.ip_protocol != new_ts->s.pkt.ip.ip_protocol) ||
        (ts->s.b.state != CI_TCP_CLOSED) ||
        (ep->oofilter.sf_local_port != NULL) ) {
      efab_thr_release(new_trs);
      rc = -EINVAL;
      OO_DEBUG_ERR(ci_log("%s: invalid endpoint states", __FUNCTION__));
      break;
    }

    /* should be fine to complete */
    ci_assert(new_trs);
    {
      tcp_helper_resource_t *old_trs;
    again:
      old_trs = priv->thr;
      if (ci_cas_uintptr_fail((ci_uintptr_t *)&priv->thr,
                              (ci_uintptr_t)old_trs, (ci_uintptr_t)new_trs))
        goto again;
      efab_thr_release(old_trs);
    }

    /* move file to hold details of new resource, new endpoint */
    ci_assert(OO_SP_EQ(priv->sock_id, op->ep_id));
    priv->sock_id = new_ep->id;

    OO_DEBUG_TCPH(ci_log("%s: set epid %u", __FUNCTION__,
                         OO_SP_FMT(priv->sock_id)));
    OO_DEBUG_TCPH(THR_PRIV_DUMP(priv, ""));
    
    /* copy across any necessary state */


    ci_assert_equal(new_ep->os_socket, NULL);
    new_ep->os_socket = ep->os_socket;
    ep->os_socket = NULL;

    /* set ORPHAN flag in current as not attached to an FD */
    ci_bit_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
    /* remove ORPHAN flag in new TCP state */
    ci_atomic32_and(&new_ts->s.b.sb_aflags,
		    ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));

    return 0;

  } while (0);

  return rc;

}


/*--------------------------------------------------------------------
 *!
 * Entry point from user-mode when the TCP/IP stack requests
 * filtering of a TCP/UDP endpoint
 *
 * \param trs             tcp helper resource
 * \param op              structure filled in by application
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

static int
efab_ep_filter_set(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_set_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if (rc != 0)
    return rc;

  return tcp_helper_endpoint_set_filters(ep, op->bindto_ifindex,
                                         op->from_tcp_id);
}
static int
efab_ep_filter_clear(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_clear_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if (rc != 0)
    return rc;

  return tcp_helper_endpoint_clear_filters(ep, op->no_sw);
}
static int
efab_ep_filter_mcast_add(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_mcast_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if( rc == 0 )
    rc = oof_socket_mcast_add(efab_tcp_driver.filter_manager,
                              &ep->oofilter, op->addr, op->ifindex);
  return rc;
}
static int
efab_ep_filter_mcast_del(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_mcast_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if( rc == 0 )
    oof_socket_mcast_del(efab_tcp_driver.filter_manager,
                         &ep->oofilter, op->addr, op->ifindex);
  return rc;
}
static int
efab_ep_filter_dump(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_dump_t *op = arg;
  return tcp_helper_endpoint_filter_dump(priv->thr, op->sock_id,
                                         CI_USER_PTR_GET(op->buf),
                                         op->buf_len);
}


/*--------------------------------------------------------------------
 *!
 * Debug function to get information about netids in the driver
 *
 * \param info            copy of user structure
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

static int
efab_tcp_helper_get_info(ci_private_t *unused, void *arg)
{
  ci_netif_info_t *info = arg;
  int index, rc=0;
  tcp_helper_resource_t* thr = NULL;
  ci_netif* ni = NULL;
  int flags = EFAB_THR_TABLE_LOOKUP_CHECK_USER | EFAB_THR_TABLE_LOOKUP_NO_WARN; 

#if CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS
  int j;
  eplock_resource_t* eplock_rs;
#endif

  info->ni_exists = 0;
  info->ni_no_perms_exists = 0;
  if( info->ni_orphan ) {
    flags |= EFAB_THR_TABLE_LOOKUP_NO_UL;
    info->ni_orphan = 0;
  }
  rc = efab_thr_table_lookup(NULL, info->ni_index, flags, &thr);
  if( rc == 0 ) {
    info->ni_exists = 1;
    info->ni_orphan = (thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND);
    ni = &thr->netif;
    info->mmap_bytes = thr->mem_mmap_bytes;
    info->k_ref_count = thr->k_ref_count;
    info->rs_ref_count = oo_atomic_read(&thr->ref_count);
    memcpy(info->ni_name, ni->state->name, sizeof(ni->state->name));
  } else if( rc == -EACCES ) {
    info->ni_no_perms_id = info->ni_index;
    if( efab_thr_get_inaccessible_stack_info(info->ni_index, 
                                             &info->ni_no_perms_uid,
                                             &info->ni_no_perms_euid,
                                             &info->ni_no_perms_share_with,
                                             info->ni_no_perms_name) == 0 )
      info->ni_no_perms_exists = 1;
  }

  /* sub-ops that do not need the netif to exist */
  if( info->ni_subop == CI_DBG_NETIF_INFO_GET_NEXT_NETIF ) {
    tcp_helper_resource_t* next_thr;

    info->u.ni_next_ni.index = -1;
    for( index = info->ni_index + 1;
         index < 10000 /* FIXME: magic! */;
         ++index ) {
      rc = efab_thr_table_lookup(NULL, index, flags, &next_thr);
      if( rc == 0 ) {
        if( next_thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND )
          efab_tcp_helper_k_ref_count_dec(next_thr, 1);
        else
          efab_thr_release(next_thr);
        info->u.ni_next_ni.index = index;
        break;
      }
      if( rc == -EACCES ) {
        info->u.ni_next_ni.index = index;
        break;
      }
    }
    rc = 0;
  }
  else if( info->ni_subop == CI_DBG_NETIF_INFO_NOOP ) {
    rc = 0;
  }

  if (!info->ni_exists)
    return 0;

  /* sub-ops that need the netif to exist */
  switch (info->ni_subop)
  {

    case CI_DBG_NETIF_INFO_GET_ENDPOINT_STATE:
      index = info->u.ni_endpoint.index;
      info->u.ni_endpoint.max = thr->netif.ep_tbl_n;
      if ((index < 0) || (index >= (int)thr->netif.ep_tbl_n)) {
        info->u.ni_endpoint.state = CI_TCP_STATE_FREE;
      }
      else {
        citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, index);

        info->u.ni_endpoint.state = wo->waitable.state;

        if( wo->waitable.state == CI_TCP_STATE_UDP ) {
          ci_udp_state* us = &wo->udp;
          info->u.ni_endpoint.udpstate = us->udpflags;
          info->u.ni_endpoint.rx_pkt_ul = us->recv_q.pkts_delivered;
          info->u.ni_endpoint.rx_pkt_kn = us->stats.n_rx_os;
        }
        else if( wo->waitable.state & CI_TCP_STATE_TCP_CONN ) {
          ci_tcp_state* ts = &wo->tcp;
          info->u.ni_endpoint.tx_pkts_max = ts->send_max;
          info->u.ni_endpoint.tx_pkts_num = ts->send.num;
        }
        if( wo->waitable.state & CI_TCP_STATE_SOCKET ) {
          ci_sock_cmn* s = &wo->sock;
          info->u.ni_endpoint.protocol = (int) sock_protocol(s);
          info->u.ni_endpoint.laddr = sock_laddr_be32(s);
          info->u.ni_endpoint.lport = (int) sock_lport_be16(s);
          info->u.ni_endpoint.raddr = sock_raddr_be32(s);
          info->u.ni_endpoint.rport = (int) sock_rport_be16(s);
        }
      }
      break;

    case CI_DBG_NETIF_INFO_GET_NEXT_NETIF:
      /* If the current netif is found, we need to succeed */
      break;

    case CI_DBG_NETIF_INFO_NOOP:
      /* Always succeeds, rc already set */
      break;

    default:
      rc = -EINVAL;
      break;
  }
  if( thr ) {
    /* Lookup needs a matching efab_thr_release() in case of ordinary
     * stack but just a ref_count_dec in case of orphan
     */
    if( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND )
      efab_tcp_helper_k_ref_count_dec(thr, 1);
    else
      efab_thr_release(thr);
  }
  return rc;
}

static int
efab_tcp_helper_wait_stack_list_update(ci_private_t* priv, void *arg)
{
  struct oo_stacklist_update *param = arg;
  ci_waitq_waiter_t waiter;
  ci_waitq_timeout_t timeout = param->timeout;

  if( param->timeout != 0 ) {
    ci_waitq_waiter_pre(&waiter, &efab_tcp_driver.stack_list_wq);
    while( efab_tcp_driver.stack_list_seq == param->seq &&
           ! ci_waitq_waiter_signalled(&q, &efab_tcp_driver.stack_list_wq) ) {
      ci_waitq_waiter_timedwait(&waiter, &efab_tcp_driver.stack_list_wq,
                                0, &timeout);
    }
    ci_waitq_waiter_post(&waiter, &efab_tcp_driver.stack_list_wq);
  }
  param->seq = efab_tcp_driver.stack_list_seq;
  return 0;
}

static int
efab_tcp_helper_sock_sleep_rsop(ci_private_t* priv, void *op)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_sock_sleep(priv->thr, (oo_tcp_sock_sleep_t *)op);
}

static int
efab_tcp_helper_waitable_wake_rsop(ci_private_t* priv, void* arg)
{
  oo_waitable_wake_t* op = arg;
  if( priv->thr == NULL )
    return -EINVAL;
  tcp_helper_endpoint_wakeup(priv->thr,
                             ci_trs_get_valid_ep(priv->thr, op->sock_id));
  return 0;
}

static int
efab_tcp_helper_bind_os_sock_rsop(ci_private_t* priv, void *arg)
{
  oo_tcp_bind_os_sock_t *op = arg;
  struct sockaddr_storage k_address_buf;
  int addrlen = op->addrlen;
  ci_uint16 port;
  int rc;

  if (priv->thr == NULL)
    return -EINVAL;
  rc = move_addr_to_kernel(CI_USER_PTR_GET(op->address), addrlen,
                           (struct sockaddr *)&k_address_buf);
  if( rc < 0 )
    return rc;
  rc = efab_tcp_helper_bind_os_sock(priv->thr, op->sock_id,
                                    (struct sockaddr *)&k_address_buf,
                                    addrlen, &port);
  if( rc < 0 )
    return rc;
  op->addrlen = port;
  return 0;
}
static int
efab_tcp_helper_listen_os_sock_rsop(ci_private_t* priv, void *p_backlog)
{
  if ( CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type) )
    return efab_tcp_helper_listen_os_sock(priv->thr, priv->sock_id,
                                          *(ci_uint32 *)p_backlog);
  else
    return -EINVAL;
}
static int
tcp_helper_endpoint_shutdown_rsop(ci_private_t* priv, void *arg)
{
  oo_tcp_endpoint_shutdown_t *op = arg;
  if ( CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type) )
    return tcp_helper_endpoint_shutdown(priv->thr, priv->sock_id,
                                        op->how, op->old_state);
  else
    return -EINVAL;
}
static int
efab_tcp_helper_set_tcp_close_os_sock_rsop(ci_private_t* priv, void *arg)
{
  oo_sp *sock_id_p = arg;
  return efab_tcp_helper_set_tcp_close_os_sock(priv->thr, *sock_id_p);
}
static int
efab_tcp_helper_sock_lock_slow_rsop(ci_private_t* priv, void *p_sock_id)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_sock_lock_slow(priv->thr, *(oo_sp *)p_sock_id);
}
static int
efab_tcp_helper_sock_unlock_slow_rsop(ci_private_t* priv, void *p_sock_id)
{
  if (priv->thr == NULL)
    return -EINVAL;
  efab_tcp_helper_sock_unlock_slow(priv->thr, *(oo_sp *)p_sock_id);
  return 0;
}
static int
efab_tcp_helper_pkt_wait_rsop(ci_private_t* priv, void *lock_flags)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_pkt_wait(priv->thr, (int *)lock_flags);
}
static int
efab_tcp_helper_more_bufs_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_more_bufs(priv->thr);
}
static int
efab_tcp_helper_more_socks_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_more_socks(priv->thr);
}
#if CI_CFG_USERSPACE_PIPE
static int
efab_tcp_helper_pipebufs_to_socks_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_pipebufs_to_socks(priv->thr);
}
static int
efab_tcp_helper_more_pipe_bufs_rsop(ci_private_t* priv,
                                    void* req)
{
  oo_tcp_sock_more_pipe_bufs_t* bufs_req =
    (oo_tcp_sock_more_pipe_bufs_t* )req;

  if (priv->thr == NULL)
    return -EINVAL;

  return efab_tcp_helper_more_pipe_bufs(&priv->thr->netif,
                                        bufs_req->bufs_num,
                                        &bufs_req->bufs_start);
}
#endif
static int
cicp_ipif_addr_kind_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_addr_kind_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_ipif_addr_kind(CICP_HANDLE(&priv->thr->netif),
                             op->ip_be32, &op->addr_kind);
}
static int
cicp_ipif_pktinfo_query_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_pktinfo_query_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_ipif_pktinfo_query(CICP_HANDLE(&priv->thr->netif),
                                 &priv->thr->netif,
                                 op->pktid, op->ifindex, &op->out_spec_addr);
}
static int
cicp_ipif_by_ifindex_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_by_ifindex_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_ipif_by_ifindex(CICP_HANDLE(&priv->thr->netif),
                              op->ifindex, &op->out_addr);
}
static int
cicp_llap_find_rsop(ci_private_t *priv, void *arg)
{
  cp_llap_find_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_llap_find(CICP_HANDLE(&priv->thr->netif),
                        &op->ifindex_out, op->hwport, op->vlan_id);
}
static int
cicp_llap_retrieve_rsop(ci_private_t *priv, void *arg)
{
  cp_llap_retrieve_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_llap_retrieve(CICP_HANDLE(&priv->thr->netif),
                            op->ifindex, &op->mtu, &op->hwport, &op->mac,
                            &op->encap, &op->base_ifindex, &op->bond_rowid);
}
static int
cicp_mac_update_rsop(ci_private_t *priv, void *arg)
{
  cp_mac_update_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  cicp_mac_update(&priv->thr->netif, &op->ver, op->ip, 
                  (const ci_mac_addr_t *)&op->mac, op->confirm);
  return 0;
}
static int
cicp_user_defer_send_rsop(ci_private_t *priv, void *arg)
{
  cp_user_defer_send_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  op->rc = cicp_user_defer_send(&priv->thr->netif, op->retrieve_rc,
                                &op->os_rc, op->pkt, op->ifindex);
  /* We ALWAYS want os_rc in the UL, so we always return 0 and ioctl handler
   * copies os_rc to UL. */
  return 0;
}
static int
cicp_user_pkt_dest_ifid_rsop(ci_private_t *priv, void *arg)
{
  cp_user_pkt_dest_ifid_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_user_pkt_dest_ifid(&priv->thr->netif, op->pkt, &op->ifindex);
}
static int
cicp_user_find_home_rsop(ci_private_t *priv, void *arg)
{
  cp_src_addr_checks_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
 return cicp_user_find_home(CICP_HANDLE(&priv->thr->netif), &op->ip_be32,
                            &op->hwport, &op->ifindex,
                            &op->mac, &op->mtu, &op->encap);
}
static int
cicpos_mac_set_rsop(ci_private_t *priv, void *arg)
{
  cp_mac_set_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicpos_mac_set(CICP_HANDLE(&priv->thr->netif), &op->rowinfo,
                        op->ifindex, op->ip_be32,
                        (const ci_mac_addr_t *)op->mac,
                        CI_USER_PTR_GET(op->os_sync_ptr));
}
static int
cicpos_mact_open_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return cicpos_mact_open(CICP_HANDLE(&priv->thr->netif)) ? 0 : -EBUSY;
}
static int
cicpos_mact_close_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_mact_close(CICP_HANDLE(&priv->thr->netif));
  return 0;
}
static int
cicpos_mac_row_seen_rsop(ci_private_t *priv, void *op)
{
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_mac_row_seen(CICP_HANDLE(&priv->thr->netif),
                      (cicp_mib_verinfo_t *)op);
  return 0;
}
static int
cicpos_mac_purge_unseen_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_mac_purge_unseen(CICP_HANDLE(&priv->thr->netif));
  return 0;
}
static int
cicpos_hwport_update_rsop(ci_private_t *priv, void *arg)
{
  cp_hwport_update_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_hwport_update(CICP_HANDLE(&priv->thr->netif),
                       op->hwport, op->max_mtu);
  return 0;
}
static int
cicp_llap_import_rsop(ci_private_t *priv, void *arg)
{
  cp_llap_import_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_llap_import(CICP_HANDLE(&priv->thr->netif), &op->rowid_out,
                          op->ifindex, op->max_mtu, op->up, op->name,
                          &op->mac);
}
static int
cicpos_llap_readrow_rsop(ci_private_t *priv, void *arg)
{
  cp_llap_readrow_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicpos_llap_readrow(CICP_HANDLE(&priv->thr->netif),
                             op->rowinfo_index,
                             &op->table_version, &op->ifindex,
                             &op->up, &op->encap);
}
static int
cicpos_llap_delete_rsop(ci_private_t *priv, void *p_ifindex)
{
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_llap_delete(CICP_HANDLE(&priv->thr->netif), *(ci_ifid_t *)p_ifindex);
  return 0;
}
static int
cicpos_ipif_import_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_import_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicpos_ipif_import(CICP_HANDLE(&priv->thr->netif), &op->rowid,
                            op->ifindex, op->net_ip, op->net_ipset,
                            op->net_bcast, op->scope);
}
static int
cicpos_ipif_readrow_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_readrow_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicpos_ipif_readrow(CICP_HANDLE(&priv->thr->netif),
                             op->rowinfo_index,
                             &op->table_version, &op->ifindex,
                             &op->net_ip, &op->net_ipset, &op->net_bcast);
}
static int
cicpos_ipif_delete_rsop(ci_private_t *priv, void *arg)
{
  cp_ipif_delete_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_ipif_delete(CICP_HANDLE(&priv->thr->netif),
                     op->ifindex, op->net_ip, op->net_ipset);
  return 0;
}
static int
cicp_route_import_rsop(ci_private_t *priv, void *arg)
{
  cp_route_import_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return cicp_route_import(CICP_HANDLE(&priv->thr->netif), &op->rowid,
                           op->dest_ip, op->dest_ipset, op->next_hop_ip,
                           op->tos, op->metric, op->pref_source,
                           op->ifindex, op->mtu);
}
static int
cicpos_route_delete_rsop(ci_private_t *priv, void *arg)
{
  cp_route_delete_t *op = arg;
  if (priv->thr == NULL)
    return -EINVAL;
  cicpos_route_delete(CICP_HANDLE(&priv->thr->netif), 
                      op->dest_ip, op->dest_ipset);
  return 0;
}
static int
efab_eplock_unlock_and_wake_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_eplock_unlock_and_wake(&priv->thr->netif);
}
static int
efab_eplock_lock_wait_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_eplock_lock_wait(&priv->thr->netif);
}
static int
efab_install_stack(ci_private_t *priv, void *arg)
{
  struct oo_op_install_stack* op = arg;
  op->in_name[CI_CFG_STACK_NAME_LEN] = '\0';
  return oo_priv_lookup_and_attach_stack(priv, op->in_name, -1);
}
static int
thr_priv_dump(ci_private_t *priv, void *unused)
{
  THR_PRIV_DUMP(priv, "");
  return 0;
}
static int
oo_cplane_log(ci_private_t *priv, void *unused)
{
  cicp_ipif_cilog(&CI_GLOBAL_CPLANE);
  cicp_llap_cilog(&CI_GLOBAL_CPLANE);
  return 0;
}
static int
oo_ioctl_debug_op(ci_private_t *priv, void *arg)
{
  ci_debug_onload_op_t *op = arg;
  int rc;

  /* First handle ops that can be done without superuser permissions.
   * oo_priv_lookup_and_attach_stack() does its own user ID checking 
   */
  if( op->what == __CI_DEBUG_OP_ON_INSTALL_RESOURCE__ )
    return oo_priv_lookup_and_attach_stack(priv, NULL, op->u.install_id);

  if( !ci_is_sysadmin() )  return -EPERM;

  switch( op->what ) {
  case __CI_DEBUG_OP_DUMP_INODE__:
    rc = efab_linux_dump_inode(op->u.fd);
    break;
  case __CI_DEBUG_OP_TRAMPOLINE__:
    rc = efab_linux_trampoline_debug(&op->u.tramp_debug);
    break;
  case __CI_DEBUG_OP_FDS_DUMP__:
    rc = efab_fds_dump(op->u.fds_dump_pid);
    break;
  case __CI_DEBUG_OP_DUMP_STACK__:
    rc = tcp_helper_dump_stack(op->u.dump_stack.stack_id, 
                               op->u.dump_stack.orphan_only);
    break;
  case __CI_DEBUG_OP_KILL_STACK__:
    rc = tcp_helper_kill_stack(op->u.stack_id);
    break;
  default:
    rc = -EINVAL;
    break;
  }
  return rc;
}
static int
ioctl_ipid_range_alloc(ci_private_t *priv, void *ipid_out)
{
  
  int rc = 0;

  rc = efab_ipid_alloc(&efab_tcp_driver.ipid);
  if( rc >= 0 ) {
    *(ci_int32 *)ipid_out = rc;
    return 0;
  }

  return rc;
}
static int
ioctl_ipid_range_free(ci_private_t *priv, void *p_ipid)
{
  return efab_ipid_free(&efab_tcp_driver.ipid, *(ci_int32 *)p_ipid);
}
static int
ioctl_printk(ci_private_t *priv, void *arg)
{
  char *msg = arg;
  size_t  lvl_len = sizeof KERN_INFO - 1;
  memmove (msg+lvl_len, msg, CI_LOG_MAX_LINE-lvl_len);
  memmove (msg, KERN_INFO, lvl_len);
  msg[CI_LOG_MAX_LINE-1] = 0;
  printk("%s\n", msg);
  return 0;
}
static int
tcp_helper_alloc_rsop(ci_private_t *priv, void *arg)
{
  /* Using lock to serialize multiple processes trying to create
   * stacks with same name.
   */
static DEFINE_MUTEX(ctor_mutex);

  ci_resource_onload_alloc_t *alloc = arg;
  tcp_helper_resource_t* trs;
  int rc;

  mutex_lock(&ctor_mutex);
  rc = tcp_helper_alloc_ul(alloc, NULL, -1, &trs);
  if( rc == 0 ) {
    rc = oo_priv_set_stack(priv, trs);
    if( rc == 0 ) {
      priv->fd_type = CI_PRIV_TYPE_NETIF;
      priv->sock_id = OO_SP_NULL;
    }
    else
      efab_thr_release(trs);
  }
  mutex_unlock(&ctor_mutex);
  return rc;
}
void tcp_helper_pace(tcp_helper_resource_t* trs, int pace_val)
{
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    efrm_pt_pace(trs->nic[intf_i].vi_rs, pace_val);
}
static int ioctl_pace(ci_private_t* priv, void* arg)
{
  struct oo_op_pace* op = arg;
  if( priv->thr == NULL )
    return -EINVAL;
  tcp_helper_pace(priv->thr, op->pace);
  return 0;
}
static int
ioctl_ep_info(ci_private_t *priv, void *arg)
{
  ci_ep_info_t *ep_info = arg;
  ep_info->fd_type = priv->fd_type;
  if (priv->thr != NULL) {
    ep_info->resource_id = priv->thr->id;
    ep_info->sock_id = priv->sock_id;
    ep_info->mem_mmap_bytes = priv->thr->mem_mmap_bytes;
  } else
    ep_info->resource_id = CI_ID_POOL_ID_NONE;

  return 0;
}
static int
ioctl_clone_fd(ci_private_t *priv, void *arg)
{
  ci_clone_fd_t *clone_fd = arg;
  int flags = 0;
  if( clone_fd->flags )
    flags = O_CLOEXEC;
  clone_fd->fd = oo_clone_fd (priv->_filp, 0, flags);
  if (clone_fd->fd < 0) {
    ci_log("clone fd ioctl: get_unused_fd() failed, errno=%d",
           -(int)clone_fd->fd); 
    return clone_fd->fd;
  }
  return 0;
}
static int
ioctl_kill_self(ci_private_t *priv, void *unused)
{
  return send_sig(SIGPIPE, current, 0);
}
extern int ioctl_iscsi_control_op (ci_private_t *priv, void *arg);


/* Move priv file to the alien_ni stack.
 * If rc=0, returns with alien_ni stack locked. */
static int efab_file_move_to_alien_stack(ci_private_t *priv,
                                         ci_netif *alien_ni)
{
  tcp_helper_resource_t *old_thr = priv->thr;
  tcp_helper_resource_t *new_thr = netif2tcp_helper_resource(alien_ni);
  ci_tcp_state *old_ts = SP_TO_TCP(&old_thr->netif, priv->sock_id);
  ci_tcp_state *mid_ts;
  ci_tcp_state *new_ts;
  tcp_helper_endpoint_t *ep;
  struct oo_file_ref *os_socket;
  int rc;

  mid_ts = CI_ALLOC_OBJ(ci_tcp_state);
  if( mid_ts == NULL ) {
    ci_netif_unlock(&old_thr->netif);
    return -ENOMEM;
  }
  *mid_ts = *old_ts;

  /* We are starting with locked "current stack" and finish with
   * locked "current stack".  Change the lock! */
  ci_netif_unlock(&old_thr->netif);
  rc = ci_netif_lock(alien_ni);
  if( rc != 0 ) {
    CI_FREE_OBJ(mid_ts);
    return -EBUSY;
  }

  /* Allocate a socket in the alien_ni stack */
  new_ts = ci_tcp_get_state_buf(alien_ni);
  if( new_ts == NULL ) {
    /* too bad: can't move fd to another stack. */
    ci_netif_unlock(alien_ni);
    CI_FREE_OBJ(mid_ts);
    return -ENOMEM;
  }

  /* Move os_socket from one ep to another */
  ep = ci_trs_ep_get(old_thr, priv->sock_id);
  os_socket = NULL;
  if( ep->os_socket != NULL )
    os_socket = oo_file_ref_add(ep->os_socket);
  ep = ci_trs_ep_get(new_thr, new_ts->s.b.bufid);
  if( ci_cas32u_fail(&ep->aflags, 0, OO_THR_EP_AFLAG_ATTACHED ) ) {
    ci_tcp_state_free(alien_ni, new_ts);
    ci_netif_unlock(alien_ni);
    if( os_socket != NULL )
      oo_file_ref_drop(os_socket);
    CI_FREE_OBJ(mid_ts);
    return -EBUSY;
  }
  ci_assert_equal(ep->os_socket, NULL);
  ep->os_socket = os_socket;

  /* do not copy old_ts->s.b.bufid! */
  new_ts->c = mid_ts->c;
  new_ts->tcpflags = mid_ts->tcpflags;
  new_ts->s.s_flags = mid_ts->s.s_flags;
  new_ts->s.s_aflags = mid_ts->s.s_aflags;
  new_ts->s.domain = mid_ts->s.domain;
  new_ts->s.cp = mid_ts->s.cp;
  new_ts->s.pkt = mid_ts->s.pkt;
  new_ts->s.space_for_hdrs.space_for_tcp_hdr =
          mid_ts->s.space_for_hdrs.space_for_tcp_hdr;
  new_ts->s.uid = mid_ts->s.uid;
  CI_DEBUG(new_ts->s.pid = mid_ts->s.pid);
  new_ts->s.ino = mid_ts->s.ino;
  new_ts->s.cmsg_flags = mid_ts->s.cmsg_flags;
  ci_pmtu_state_init(alien_ni, &new_ts->s, &new_ts->s.pkt.pmtus,
                     CI_IP_TIMER_PMTU_DISCOVER);
  new_ts->s.so = mid_ts->s.so;
  new_ts->s.so_priority = mid_ts->s.so_priority;
  new_ts->s.so_error = mid_ts->s.so_error;
  new_ts->s.tx_errno = mid_ts->s.tx_errno;
  new_ts->s.rx_errno = mid_ts->s.rx_errno;
  new_ts->s.b.state = mid_ts->s.b.state;
  new_ts->s.b.sb_flags = mid_ts->s.b.sb_flags;
  new_ts->s.b.sb_aflags = mid_ts->s.b.sb_aflags;

  /* free temporary mid_ts storage */
  CI_FREE_OBJ(mid_ts);

  /* hack fd to point to the new endpoint */
  oo_move_file(priv, new_thr, new_ts->s.b.bufid);

  /* Free resources from the old endpoint. */
  efab_tcp_helper_close_endpoint(old_thr, old_ts->s.b.bufid);
  efab_thr_release(old_thr);

  return 0;
}

static int
efab_tcp_loopback_connect(ci_private_t *priv, void *arg)
{
  struct oo_op_loopback_connect *carg = arg;
  ci_netif *alien_ni = NULL;
  oo_sp tls_id;

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
        carg->out_rc =
            ci_tcp_connect_lo_toconn(&priv->thr->netif, priv->sock_id,
                                     carg->dst_addr, alien_ni, tls_id);
        efab_thr_release(netif2tcp_helper_resource(alien_ni));
        return 0;

      case CITP_TCP_LOOPBACK_TO_LISTSTACK:
        rc = efab_file_move_to_alien_stack(priv, alien_ni);
        if( rc != 0 ) {
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          /* if we return error, UL will do handover. */
          return rc;
        }

        /* Connect again, using new endpoint */
        carg->out_rc =
            ci_tcp_connect_lo_samestack(alien_ni,
                                        SP_TO_TCP(alien_ni, priv->sock_id),
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
        alloc.in_cpu_khz = IPTIMER_STATE(&priv->thr->netif)->khz;
        strcpy(alloc.in_version, ONLOAD_VERSION);
        strcpy(alloc.in_uk_intf_ver, oo_uk_intf_ver);
        alloc.in_name[0] = '\0';
        alloc.in_flags = 0;
        rc = tcp_helper_alloc_kernel(&alloc, &NI_OPTS(&priv->thr->netif),
                                     NULL/*ifindices*/, 0, &new_thr);
        if( rc != 0 ) {
          ci_log("%s: tcp_helper_rm_alloc failed with %d", __func__, rc);
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          return -ECONNREFUSED;
        }

        /* move connecting socket to the new stack */
        rc = efab_file_move_to_alien_stack(priv, &new_thr->netif);
        if( rc != 0 ) {
          ci_log("%s: efab_file_move_to_alien_stack failed with %d", __func__, rc);
          efab_thr_release(netif2tcp_helper_resource(alien_ni));
          efab_thr_release(new_thr);
          return -ECONNREFUSED;
        }
        carg->out_moved = 1;
        carg->out_rc = -ECONNREFUSED;

        /* now connect via CITP_TCP_LOOPBACK_TO_CONNSTACK */
        carg->out_rc =
            ci_tcp_connect_lo_toconn(&priv->thr->netif, priv->sock_id,
                                     carg->dst_addr, alien_ni, tls_id);
        efab_thr_release(netif2tcp_helper_resource(alien_ni));
        return 0;
      }
      }
    }
  }

  ci_netif_unlock(&priv->thr->netif);
  return -ENOENT;
}

static int
efab_tcp_drop_from_acceptq(ci_private_t *priv, void *arg)
{
  struct oo_op_tcp_drop_from_acceptq *carg = arg;
  tcp_helper_resource_t *thr;
  tcp_helper_endpoint_t *ep;
  citp_waitable *w;
  ci_tcp_state *ts;
  int rc = -EINVAL;

  /* find stack */
  rc = efab_thr_table_lookup(NULL, carg->stack_id,
                                 EFAB_THR_TABLE_LOOKUP_CHECK_USER |
                                 EFAB_THR_TABLE_LOOKUP_NO_UL,
                                 &thr);

  if( rc < 0 )
    return rc;
  ci_assert( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND );

  /* find endpoint and drop OS socket */
  ep = ci_trs_get_valid_ep(thr, carg->sock_id);
  if( ep == NULL )
    goto fail1;

  w = SP_TO_WAITABLE(&thr->netif, carg->sock_id);
  if( !(w->state & CI_TCP_STATE_TCP) || w->state == CI_TCP_LISTEN )
    goto fail2;
  ts = SP_TO_TCP(&thr->netif, carg->sock_id);
  ci_assert(ep->os_port_keeper);
  ci_assert_equal(ep->os_socket, NULL);

  LOG_TV(ci_log("%s: send reset to non-accepted connection", __FUNCTION__));

  /* copy from ci_tcp_listen_shutdown_queues() */
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);
  rc = ci_netif_lock(&thr->netif);
  if( rc != 0 ) {
    ci_assert_equal(rc, -EINTR);
    rc = -ERESTARTSYS;
    goto fail2;
  }
  ci_bit_clear(&ts->s.b.sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
  /* We have no way to close this connection from the other side:
   * there was no RST from peer. */
  ci_assert_nequal(ts->s.b.state, CI_TCP_CLOSED);
  ci_assert_nequal(ts->s.b.state, CI_TCP_TIME_WAIT);
  ci_tcp_send_rst(&thr->netif, ts);
  ci_tcp_drop(&thr->netif, ts, ECONNRESET);
  ci_assert_equal(ep->os_port_keeper, NULL);
  ci_netif_unlock(&thr->netif);
  efab_tcp_helper_k_ref_count_dec(thr, 1);
  return 0;

fail1:
  efab_thr_release(thr);
fail2:
  ci_log("%s: inconsistent ep %d:%d", __func__, carg->stack_id, carg->sock_id);
  return rc;
}

/*************************************************************************
 * ATTENTION! ACHTUNG! ATENCION!                                         *
 * This table MUST be synchronised with enum of OO_OP_* operations!      *
 *************************************************************************/
/*! Table of all supported ioctl handlers */
oo_operations_table_t oo_operations[] = {
#if ! OO_OPS_TABLE_HAS_NAME
# define op(ioc, fn)  { (ioc), (fn) }
#else
# define op(ioc, fn)  { (ioc), (fn), #ioc }
#endif

  op(OO_IOC_DBG_CPLANE_LOG,     oo_cplane_log),
  op(OO_IOC_DBG_GET_STACK_INFO, efab_tcp_helper_get_info),
  op(OO_IOC_DBG_WAIT_STACKLIST_UPDATE, efab_tcp_helper_wait_stack_list_update),

  op(OO_IOC_DEBUG_OP, oo_ioctl_debug_op),

  op(OO_IOC_CFG_SET,   ci_cfg_handle_set_ioctl),
  op(OO_IOC_CFG_UNSET, ci_cfg_handle_unset_ioctl),
  op(OO_IOC_CFG_GET,   ci_cfg_handle_get_ioctl),
  op(OO_IOC_CFG_QUERY, ci_cfg_handle_query_ioctl),

  op(OO_IOC_IPID_RANGE_ALLOC, ioctl_ipid_range_alloc),
  op(OO_IOC_IPID_RANGE_FREE,  ioctl_ipid_range_free),

  op(OO_IOC_PRINTK, ioctl_printk),

  op(OO_IOC_RESOURCE_ONLOAD_ALLOC, tcp_helper_alloc_rsop),
  op(OO_IOC_EP_INFO,               ioctl_ep_info),
  op(OO_IOC_CLONE_FD,              ioctl_clone_fd),
  op(OO_IOC_KILL_SELF_SIGPIPE,     ioctl_kill_self),
  op(OO_IOC_IOCTL_TRAMP_REG,       efab_linux_trampoline_register),
  op(OO_IOC_DIE_SIGNAL,            efab_signal_die),

  op(OO_IOC_ISCSI_CONTROL_OP, ioctl_iscsi_control_op),

  op(OO_IOC_TCP_SOCK_SLEEP,   efab_tcp_helper_sock_sleep_rsop),
  op(OO_IOC_WAITABLE_WAKE,    efab_tcp_helper_waitable_wake_rsop),
#if CI_CFG_FD_CACHING
  op(OO_IOC_TCP_CAN_CACHE_FD, efab_tcp_helper_can_cache_fd),
  op(OO_IOC_TCP_XFER,         efab_tcp_helper_xfer_cached),
#endif

  op(OO_IOC_EP_FILTER_SET,       efab_ep_filter_set),
  op(OO_IOC_EP_FILTER_CLEAR,     efab_ep_filter_clear),
  op(OO_IOC_EP_FILTER_MCAST_ADD, efab_ep_filter_mcast_add),
  op(OO_IOC_EP_FILTER_MCAST_DEL, efab_ep_filter_mcast_del),
  op(OO_IOC_EP_FILTER_DUMP,      efab_ep_filter_dump),

  op(OO_IOC_TCP_MOVE_STATE,     efab_tcp_helper_move_state),
  op(OO_IOC_TCP_SOCK_LOCK,      efab_tcp_helper_sock_lock_slow_rsop),
  op(OO_IOC_TCP_SOCK_UNLOCK,    efab_tcp_helper_sock_unlock_slow_rsop),
  op(OO_IOC_TCP_PKT_WAIT,       efab_tcp_helper_pkt_wait_rsop),
  op(OO_IOC_TCP_MORE_BUFS,      efab_tcp_helper_more_bufs_rsop),
  op(OO_IOC_TCP_MORE_SOCKS,     efab_tcp_helper_more_socks_rsop),
#if CI_CFG_USERSPACE_PIPE
  op(OO_IOC_TCP_PIPEBUFS_TO_SOCKS, efab_tcp_helper_pipebufs_to_socks_rsop),
  op(OO_IOC_TCP_MORE_PIPE_BUFS, efab_tcp_helper_more_pipe_bufs_rsop),
#endif

  op(OO_IOC_STACK_ATTACH,      efab_tcp_helper_stack_attach ),
  op(OO_IOC_SOCK_ATTACH,       efab_tcp_helper_sock_attach ),
#if CI_CFG_USERSPACE_PIPE
  op(OO_IOC_PIPE_ATTACH,       efab_tcp_helper_pipe_attach ),
#endif

  op(OO_IOC_OS_SOCK_FD_GET,        efab_tcp_helper_get_sock_fd),
  op(OO_IOC_OS_SOCK_SENDMSG,       efab_tcp_helper_os_sock_sendmsg),
  op(OO_IOC_OS_SOCK_SENDMSG_RAW,   efab_tcp_helper_os_sock_sendmsg_raw),
  op(OO_IOC_OS_SOCK_RECVMSG,       efab_tcp_helper_os_sock_recvmsg),
  op(OO_IOC_OS_SOCK_ACCEPT,        efab_tcp_helper_os_sock_accept),
  op(OO_IOC_TCP_ENDPOINT_SHUTDOWN, tcp_helper_endpoint_shutdown_rsop),
  op(OO_IOC_TCP_BIND_OS_SOCK,      efab_tcp_helper_bind_os_sock_rsop),
  op(OO_IOC_TCP_LISTEN_OS_SOCK,    efab_tcp_helper_listen_os_sock_rsop),
  op(OO_IOC_TCP_CONNECT_OS_SOCK,   efab_tcp_helper_connect_os_sock),
  op(OO_IOC_TCP_HANDOVER,          efab_tcp_helper_handover),
  op(OO_IOC_TCP_CLOSE_OS_SOCK,     efab_tcp_helper_set_tcp_close_os_sock_rsop),

  op(OO_IOC_CP_IPIF_ADDR_KIND,     cicp_ipif_addr_kind_rsop),
  op(OO_IOC_CP_LLAP_FIND,          cicp_llap_find_rsop),
  op(OO_IOC_CP_LLAP_RETRIEVE,      cicp_llap_retrieve_rsop),
  op(OO_IOC_CP_MAC_UPDATE,         cicp_mac_update_rsop),
  op(OO_IOC_CP_USER_DEFER_SEND,    cicp_user_defer_send_rsop),
  op(OO_IOC_CP_USER_PKT_DEST_IFID, cicp_user_pkt_dest_ifid_rsop),
  op(OO_IOC_CP_SRC_ADDR_CHECKS,    cicp_user_find_home_rsop),
  op(OO_IOC_CP_IPIF_PKTINFO_QUERY, cicp_ipif_pktinfo_query_rsop),
  op(OO_IOC_CP_IPIF_BY_IFINDEX,    cicp_ipif_by_ifindex_rsop),
#if CI_CFG_CONTROL_PLANE_USER_SYNC
  op(OO_IOC_CP_MAC_SET,            cicpos_mac_set_rsop),
  op(OO_IOC_CP_MAC_OPEN,           cicpos_mact_open_rsop),
  op(OO_IOC_CP_MAC_CLOSE,          cicpos_mact_close_rsop),
  op(OO_IOC_CP_MAC_SEEN,           cicpos_mac_row_seen_rsop),
  op(OO_IOC_CP_MAC_PURGE_UNSEEN,   cicpos_mac_purge_unseen_rsop),
  op(OO_IOC_CP_HWPORT_UPDATE,      cicpos_hwport_update_rsop),
  op(OO_IOC_CP_LLAP_IMPORT,        cicp_llap_import_rsop),
  op(OO_IOC_CP_LLAP_DELETE,        cicpos_llap_delete_rsop),
  op(OO_IOC_CP_LLAP_READROW,       cicpos_llap_readrow_rsop),
  op(OO_IOC_CP_IPIF_IMPORT,        cicpos_ipif_import_rsop),
  op(OO_IOC_CP_IPIF_DELETE,        cicpos_ipif_delete_rsop),
  op(OO_IOC_CP_IPIF_READROW,       cicpos_ipif_readrow_rsop),
  op(OO_IOC_CP_ROUTE_IMPORT,       cicp_route_import_rsop),
  op(OO_IOC_CP_ROUTE_DELETE,       cicpos_route_delete_rsop),
#endif /* CI_CFG_CONTROL_PLANE_USER_SYNC */

  op(OO_IOC_EPLOCK_WAKE,      efab_eplock_unlock_and_wake_rsop),
  op(OO_IOC_EPLOCK_LOCK_WAIT, efab_eplock_lock_wait_rsop),

  op(OO_IOC_INSTALL_STACK,    efab_install_stack),
  op(OO_IOC_PACE,             ioctl_pace),
  op(OO_IOC_RSOP_DUMP, thr_priv_dump),
  op(OO_IOC_GET_ONLOADFS_DEV, onloadfs_get_dev_t),
  op(OO_IOC_TCP_LOOPBACK_CONNECT, efab_tcp_loopback_connect),
  op(OO_IOC_TCP_DROP_FROM_ACCEPTQ, efab_tcp_drop_from_acceptq),
#undef op
};
