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
**     Started: 2008/02/20
** Description: Implementation of "ops" invoked by user-level.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>
# include <onload/linux_onload_internal.h>
# include <onload/linux_onload.h>
# include <onload/linux_sock_ops.h>
# include <onload/linux_trampoline.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/efabcfg.h>
#include <onload/oof_interface.h>
#include <onload/cplane_ops.h>
#include <onload/version.h>
#include <onload/dshm.h>
#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif
#include "onload_kernel_compat.h"


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
efab_tcp_helper_lookup_and_attach_stack(ci_private_t* priv, void *arg)
{
  return oo_priv_lookup_and_attach_stack(priv, NULL, *(ci_uint32 *)arg);
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
efab_tcp_helper_sock_attach_setup_flags(int* sock_type_in_out)
{
  int flags;

/* SOCK_CLOEXEC and SOCK_NONBLOCK exist from 2.6.27 both */
#ifdef SOCK_TYPE_MASK
  BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
  flags = *sock_type_in_out & (SOCK_CLOEXEC | SOCK_NONBLOCK);
  *sock_type_in_out &= SOCK_TYPE_MASK;
# ifdef SOCK_NONBLOCK
  if( SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK) )
    flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
# endif
#else
  flags = 0;
#endif

  return flags;
}


static int
efab_tcp_helper_sock_attach_common(tcp_helper_resource_t* trs,
                                   tcp_helper_endpoint_t* ep,
                                   ci_int32 sock_type, int fd_type, int flags)
{
  int rc;
  citp_waitable_obj *wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  (void) wo;

  /* Create a new file descriptor to attach the socket to. */
  rc = oo_create_ep_fd(ep, flags, fd_type);
  if( rc >= 0 ) {
#ifdef SOCK_NONBLOCK
    if( sock_type & SOCK_NONBLOCK )
      ci_bit_mask_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_O_NONBLOCK);
#endif
#ifdef SOCK_CLOEXEC
    if( sock_type & SOCK_CLOEXEC )
      ci_bit_mask_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_O_CLOEXEC);
#endif

    /* Re-read the OS socket buffer size settings.  This ensures we'll use
     * up-to-date values for this new socket.
     */
    efab_get_os_settings(&NI_OPTS_TRS(trs));
  }

  return rc;
}


/* This ioctl may be entered with or without the stack lock.  This has two
 * immediate implications:
 *  - it must not rely on the consistency of nor make atomically inconsistent
 *    modifications to the state protected by the stack lock; and
 *  - it must not block on the stack lock.
 * Trylocks are safe, however.  Also, the caller provides a guarantee that the
 * endpoint whose ep_id is passed in will not change under the ioctl's feet
 * and that the ioctl may modify it freely. */
static int
efab_tcp_helper_sock_attach(ci_private_t* priv, void *arg)
{
  oo_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;
  int flags;
  int sock_type = op->type;
  int fd_type;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);

  ci_assert( (wo->waitable.state == CI_TCP_STATE_UDP) ||
             (wo->waitable.state & CI_TCP_STATE_TCP) );
  fd_type = (wo->waitable.state & CI_TCP_STATE_TCP) ?
            CI_PRIV_TYPE_TCP_EP : CI_PRIV_TYPE_UDP_EP;

  ci_atomic32_and(&wo-> waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));
  wo->sock.domain = op->domain;

  flags = efab_tcp_helper_sock_attach_setup_flags(&sock_type);

  /* We always need an OS socket for UDP endpoints, so grab one here.  In the
   * TCP case we don't want a backing socket for sockets with IP_TRANSPARENT
   * set, but we can't tell that yet, unless we're in a stack configuration
   * that doesn't support IP_TRANSPARENT.
   *
   * We could always defer creation of OS sockets for TCP, as we have to
   * support that for the IP_TRANSPARENT case, but until this feature has
   * matured a bit we'll err on the side of caution and only use it where it
   * might actually be needed.
   */
  if( (NI_OPTS(&trs->netif).scalable_filter_enable !=
       CITP_SCALABLE_FILTERS_ENABLE) ||
      (fd_type == CI_PRIV_TYPE_UDP_EP) ) {
    rc = efab_create_os_socket(trs, ep, op->domain, sock_type, flags);
    if( rc < 0 ) {
      efab_tcp_helper_close_endpoint(trs, ep->id);
      return rc;
    }
  }
  else {
#if CI_CFG_FD_CACHING
    /* There are ways that a cached socket may have had its fd closed.  If
     * that happens we come through this ioctl to get a new one, so update the
     * state to reflect that.
     */
    if( wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD ) {
      ci_assert_flags(wo->waitable.sb_aflags, CI_SB_AFLAG_IN_CACHE);
      ci_assert_flags(wo->waitable.state, CI_TCP_STATE_TCP);

      ci_atomic32_and(&wo->waitable.sb_aflags, ~CI_SB_AFLAG_CACHE_PRESERVE);
      wo->tcp.cached_on_fd = -1;
      wo->tcp.cached_on_pid = -1;
    }
#endif
  }

  rc = efab_tcp_helper_sock_attach_common(trs, ep, op->type, fd_type, flags);
  if( rc < 0 ) {
    efab_tcp_helper_close_endpoint(trs, ep->id);
    return rc;
  }

  op->fd = rc;
  return 0;
}


static int
efab_tcp_helper_tcp_accept_sock_attach(ci_private_t* priv, void *arg)
{
  oo_tcp_accept_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;
  int flags;
  int sock_type = op->type;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  ci_assert(wo->waitable.state & CI_TCP_STATE_TCP);

  ci_atomic32_and(&wo-> waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));

#if CI_CFG_FD_CACHING
  /* There are ways that a cached socket may have had its fd closed.  If
   * that happens we come through this ioctl to get a new one, so update the
   * state to reflect that.
   */
  if( wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD ) {
    ci_assert(wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE);
    ci_atomic32_and(&wo->waitable.sb_aflags, ~CI_SB_AFLAG_CACHE_PRESERVE);
    wo->tcp.cached_on_fd = -1;
    wo->tcp.cached_on_pid = -1;
  }
#endif

  flags = efab_tcp_helper_sock_attach_setup_flags(&sock_type);
  rc = efab_tcp_helper_sock_attach_common(trs, ep, op->type,
                                          CI_PRIV_TYPE_TCP_EP, flags);
  if( rc < 0 ) {
    /* - accept() does not touch the ep - no need to clear it up;
     * - accept() needs the tcp state survive
     */
    ci_atomic32_or(&wo-> waitable.sb_aflags,
                   CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ);
    return rc;
  }
 
  op->fd = rc; 
  return 0;
}


static int
efab_tcp_helper_pipe_attach(ci_private_t* priv, void *arg)
{
  oo_pipe_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
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

  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  ci_atomic32_and(&wo->waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  rc = oo_create_ep_fd(ep, op->flags, CI_PRIV_TYPE_PIPE_READER);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: failed to bind reader [%d:%d] to fd",
                 __func__, trs->id, ep->id));
    tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
    efab_tcp_helper_close_endpoint(trs, ep->id);
    return rc;
  }
  op->rfd = rc;

  rc = oo_create_ep_fd(ep, op->flags, CI_PRIV_TYPE_PIPE_WRITER);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: failed to bind writer [%d:%d] to fd",
                 __func__, trs->id, ep->id));
    efab_linux_sys_close(op->rfd);
    efab_tcp_helper_close_endpoint(trs, ep->id);
    return rc;
  }
  op->wfd = rc;

  return 0;
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
  return tcp_helper_endpoint_clear_filters(ep, 0, op->need_update);
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
static int
efab_cluster_dump(ci_private_t *priv, void *arg)
{
  oo_cluster_dump_t *op = arg;
  return tcp_helper_cluster_dump(priv->thr, CI_USER_PTR_GET(op->buf),
                                 op->buf_len);
}

#ifndef ONLOAD_OFE

static int
efab_ofe_config(ci_private_t *priv, void *arg)
{
  ci_log("%s: ERROR: SolarSecure Filter Engine support not built", __func__);
  return -EOPNOTSUPP;
}

static int
efab_ofe_config_done(ci_private_t *priv, void *arg)
{
  ci_log("%s: ERROR: SolarSecure Filter Engine support not built", __func__);
  return -EOPNOTSUPP;
}

static int
efab_ofe_get_last_error(ci_private_t *priv, void *arg)
{
  ci_log("%s: ERROR: SolarSecure Filter Engine support not built", __func__);
  return -EOPNOTSUPP;
}

#else

static int
efab_ofe_config(ci_private_t *priv, void *arg)
{
  oo_ofe_config_t *op = arg;
  enum ofe_status orc;
  char *str;

  if( priv->thr->netif.ofe == NULL )
    return -EINVAL;

  str = kmalloc(op->len + 1, GFP_KERNEL);
  if( str == NULL )
    return -ENOMEM;
  str[op->len] = '\0';
  if( copy_from_user(str, CI_USER_PTR_GET(op->str), op->len) ) {
    kfree(str);
    return -EFAULT;
  }

  mutex_lock(&priv->thr->ofe_mutex);
  if( priv->thr->ofe_config == NULL ) {
    orc = ofe_config_alloc(&priv->thr->ofe_config, priv->thr->netif.ofe);
    if( orc != OFE_OK ) {
      mutex_unlock(&priv->thr->ofe_mutex);
      return -ofe_rc2errno(orc);
    }
  }
  ci_assert(priv->thr->ofe_config);

  orc = ofe_config_command(priv->thr->ofe_config, NULL, str);
  mutex_unlock(&priv->thr->ofe_mutex);
  kfree(str);
  if( orc != OFE_OK )
    return -ofe_rc2errno(orc);
  return 0;  
}
static int
efab_ofe_config_done(ci_private_t *priv, void *arg)
{
  ci_netif* ni = &(priv->thr->netif);
  enum ofe_status orc;

  if( ni->ofe == NULL )
    return -EINVAL;

  mutex_lock(&priv->thr->ofe_mutex);
  if( priv->thr->ofe_config != NULL ) {
    orc = ofe_config_free(priv->thr->ofe_config);
    priv->thr->ofe_config = NULL;
    if( orc != OFE_OK ) {
      mutex_unlock(&priv->thr->ofe_mutex);
      ci_log("%s: ERROR %s", __func__, ofe_engine_get_last_error(ni->ofe));
      return -(ofe_rc2errno(orc));
    }
    if( ni->ofe_channel == NULL ) {
      ni->ofe_channel = kmalloc(ofe_channel_bytes(ni->ofe), GFP_KERNEL);
      if( ni->ofe_channel == NULL ) {
        mutex_unlock(&priv->thr->ofe_mutex);
        ci_log("ERROR: [%d] failed to allocate SSFE channel", NI_ID(ni));
        return -ENOMEM;
      }
      orc = ofe_channel_init(ni->ofe_channel, ni->ofe, 0);
      if( orc != OFE_OK ) {
        mutex_unlock(&priv->thr->ofe_mutex);
        ci_log("ERROR: [%d] ofe_channel_init failed: %s", NI_ID(ni),
               ofe_engine_get_last_error(ni->ofe));
        kfree(ni->ofe_channel);
        ni->ofe_channel = NULL;
        return -(ofe_rc2errno(orc));
      }
    }
  }
  mutex_unlock(&priv->thr->ofe_mutex);
  return 0;
}
static int
efab_ofe_get_last_error(ci_private_t *priv, void *arg)
{
  const char *msg;

  if( priv->thr->netif.ofe == NULL )
    return -EINVAL;

  msg = ofe_engine_get_last_error(priv->thr->netif.ofe);
  mutex_lock(&priv->thr->ofe_mutex);
  strncpy(arg, msg, CI_LOG_MAX_LINE);
  mutex_unlock(&priv->thr->ofe_mutex);
  return 0;
}

#endif


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
          efab_tcp_helper_k_ref_count_dec(next_thr);
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
          info->u.ni_endpoint.tx_pkts_max = ts->so_sndbuf_pkts;
          info->u.ni_endpoint.tx_pkts_num = ts->send.num;
        }
        if( CI_TCP_STATE_IS_SOCKET(wo->waitable.state) ) {
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
      efab_tcp_helper_k_ref_count_dec(thr);
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


/* This resource op must be called with the stack lock held.  This ensures
 * that we sync a consistent set of state to the OS socket when it is created.
 * All operations that can affect what we sync (setsockopt, ioctl, fcntl) are
 * protected by the stack lock so we know they won't change under our feet.
 */
static int
efab_tcp_helper_os_sock_create_and_set_rsop(ci_private_t* priv, void* arg)
{
  oo_tcp_create_set_t *op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  int rc;

  ci_assert(priv);
  ci_assert(op);

  if (!CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type))
    return -EINVAL;

  ci_assert(priv->thr);
  ci_assert_equal(priv->fd_type, CI_PRIV_TYPE_TCP_EP);
  ep = efab_priv_to_ep(priv);

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, ep->id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  rc = efab_tcp_helper_create_os_sock(priv);
  if( rc < 0 )
    return rc;

  /* If we've been given a socket option to sync, do it now */
  if( op->level >= 0 )
    rc = efab_tcp_helper_setsockopt(trs, ep->id, op->level, op->optname,
                                    CI_USER_PTR_GET(op->optval), op->optlen);

  return rc;
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
efab_tcp_helper_os_pollerr_clear(ci_private_t* priv, void *arg)
{
  oo_sp *sock_id_p = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, *sock_id_p);
  struct file *os_file;
  int rc = oo_os_sock_get_from_ep(ep, &os_file);

  if( rc != 0 )
    return 0;
  oo_os_sock_status_bit_clear_handled(SP_TO_SOCK(&ep->thr->netif, ep->id),
                                      os_file, OO_OS_STATUS_ERR);
  oo_os_sock_put(os_file);
  return 0;
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
#if CI_CFG_FD_CACHING
static int
efab_tcp_helper_clear_epcache_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_clear_epcache(priv->thr);
}
#endif
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
efab_eplock_unlock_and_wake_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  ci_assert_equal(priv->thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT, 0);
  return efab_eplock_unlock_and_wake(&priv->thr->netif, 0);
}
static int
efab_eplock_lock_wait_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_eplock_lock_wait(&priv->thr->netif, 0);
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
  ci_log("OO_IOC_RSOP_DUMP:");
  THR_PRIV_DUMP(priv, "");
  ci_log("OO_IOC_RSOP_DUMP: done");
  return 0;
}
static int
oo_ioctl_debug_op(ci_private_t *priv, void *arg)
{
  ci_debug_onload_op_t *op = arg;
  int rc;

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
                               op->u.dump_stack.orphan_only,
                               CI_USER_PTR_GET(op->u.dump_stack.user_buf),
                               op->u.dump_stack.user_buf_len);
    break;
  case __CI_DEBUG_OP_KILL_STACK__:
    rc = tcp_helper_kill_stack_by_id(op->u.stack_id);
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
  rc = tcp_helper_alloc_ul(alloc, -1, &trs);
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
    efrm_pt_pace(trs->nic[intf_i].thn_vi_rs, pace_val);
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
  ci_clone_fd_t *op = arg;
  op->fd = oo_clone_fd (priv->_filp, op->do_cloexec);
  if (op->fd < 0) {
    ci_log("clone fd ioctl: get_unused_fd() failed, errno=%d",
           -(int)(op->fd)); 
    return op->fd;
  }
  return 0;
}
static int
ioctl_kill_self(ci_private_t *priv, void *unused)
{
  return send_sig(SIGPIPE, current, 0);
}

extern int efab_file_move_to_alien_stack_rsop(ci_private_t *priv, void *arg);
extern int efab_tcp_loopback_connect(ci_private_t *priv, void *arg);
extern int efab_tcp_helper_reuseport_bind(ci_private_t *priv, void *arg);


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
  efab_tcp_helper_k_ref_count_dec(thr);
  return 0;

fail1:
  efab_thr_release(thr);
fail2:
  ci_log("%s: inconsistent ep %d:%d", __func__, carg->stack_id, carg->sock_id);
  return rc;
}


static int oo_get_cpu_khz_rsop(ci_private_t *priv, void *arg)
{
  ci_uint32* cpu_khz = arg;
  oo_timesync_wait_for_cpu_khz_to_stabilize();
  *cpu_khz = oo_timesync_cpu_khz;
  return 0;
}

static int oo_get_cplane_fd(ci_private_t *priv, void *arg)
{
  ci_fixed_descriptor_t* pfd = arg;

  if( priv->thr == NULL || priv->thr->cplane_handle == NULL )
    return -ENOENT;
  
  *pfd = get_unused_fd_flags(O_CLOEXEC);
  if( *pfd < 0 )
    return *pfd;

  fd_install(*pfd, priv->thr->cplane_handle);
  return 0;
}


static int efab_tcp_helper_alloc_active_wild_rsop(ci_private_t *priv,
                                                  void *arg)
{
  tcp_helper_resource_t* trs = priv->thr;

  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  if( trs->netif.state->active_wild_n <
      NI_OPTS(&trs->netif).tcp_shared_local_ports_max )
    tcp_helper_alloc_to_active_wild_pool(trs, 1);

  return 0;
}


/* "Donation" shared memory ioctls. */

static int oo_dshm_register_rsop(ci_private_t *priv, void *arg)
{
  oo_dshm_register_t* params = arg;
  return oo_dshm_register_impl(params->shm_class, params->buffer,
                               params->length, &params->buffer_id,
                               &priv->dshm_list);
}

static int oo_dshm_list_rsop(ci_private_t *priv, void *arg)
{
  oo_dshm_list_t* params = arg;
  return oo_dshm_list_impl(params->shm_class, params->buffer_ids,
                           &params->count);
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

  op(OO_IOC_TCP_SOCK_SLEEP,   efab_tcp_helper_sock_sleep_rsop),
  op(OO_IOC_WAITABLE_WAKE,    efab_tcp_helper_waitable_wake_rsop),

  op(OO_IOC_EP_FILTER_SET,       efab_ep_filter_set),
  op(OO_IOC_EP_FILTER_CLEAR,     efab_ep_filter_clear),
  op(OO_IOC_EP_FILTER_MCAST_ADD, efab_ep_filter_mcast_add),
  op(OO_IOC_EP_FILTER_MCAST_DEL, efab_ep_filter_mcast_del),
  op(OO_IOC_EP_FILTER_DUMP,      efab_ep_filter_dump),

  op(OO_IOC_TCP_SOCK_LOCK,      efab_tcp_helper_sock_lock_slow_rsop),
  op(OO_IOC_TCP_SOCK_UNLOCK,    efab_tcp_helper_sock_unlock_slow_rsop),
  op(OO_IOC_TCP_PKT_WAIT,       efab_tcp_helper_pkt_wait_rsop),
  op(OO_IOC_TCP_MORE_BUFS,      efab_tcp_helper_more_bufs_rsop),
  op(OO_IOC_TCP_MORE_SOCKS,     efab_tcp_helper_more_socks_rsop),
#if CI_CFG_FD_CACHING
  op(OO_IOC_TCP_CLEAR_EPCACHE,  efab_tcp_helper_clear_epcache_rsop),
#endif

  op(OO_IOC_STACK_ATTACH,      efab_tcp_helper_stack_attach ),
  op(OO_IOC_INSTALL_STACK_BY_ID, efab_tcp_helper_lookup_and_attach_stack),
  op(OO_IOC_SOCK_ATTACH,           efab_tcp_helper_sock_attach ),
  op(OO_IOC_TCP_ACCEPT_SOCK_ATTACH,efab_tcp_helper_tcp_accept_sock_attach ),
#if CI_CFG_USERSPACE_PIPE
  op(OO_IOC_PIPE_ATTACH,       efab_tcp_helper_pipe_attach ),
#endif

  op(OO_IOC_OS_SOCK_CREATE_AND_SET,efab_tcp_helper_os_sock_create_and_set_rsop),
  op(OO_IOC_OS_SOCK_FD_GET,        efab_tcp_helper_get_sock_fd),
  op(OO_IOC_OS_SOCK_SENDMSG,       efab_tcp_helper_os_sock_sendmsg),
  op(OO_IOC_OS_SOCK_SENDMSG_RAW,   efab_tcp_helper_os_sock_sendmsg_raw),
  op(OO_IOC_OS_SOCK_RECVMSG,       efab_tcp_helper_os_sock_recvmsg),
  op(OO_IOC_OS_SOCK_ACCEPT,        efab_tcp_helper_os_sock_accept),
  op(OO_IOC_TCP_ENDPOINT_SHUTDOWN, tcp_helper_endpoint_shutdown_rsop),
  op(OO_IOC_TCP_BIND_OS_SOCK,      efab_tcp_helper_bind_os_sock_rsop),
  op(OO_IOC_TCP_LISTEN_OS_SOCK,    efab_tcp_helper_listen_os_sock),
  op(OO_IOC_TCP_CONNECT_OS_SOCK,   efab_tcp_helper_connect_os_sock),
  op(OO_IOC_TCP_HANDOVER,          efab_tcp_helper_handover),
  op(OO_IOC_FILE_MOVED,            oo_file_moved_rsop),
  op(OO_IOC_TCP_CLOSE_OS_SOCK,     efab_tcp_helper_set_tcp_close_os_sock_rsop),
  op(OO_IOC_OS_POLLERR_CLEAR,      efab_tcp_helper_os_pollerr_clear),

  op(OO_IOC_CP_USER_DEFER_SEND,    cicp_user_defer_send_rsop),

  op(OO_IOC_EPLOCK_WAKE,      efab_eplock_unlock_and_wake_rsop),
  op(OO_IOC_EPLOCK_LOCK_WAIT, efab_eplock_lock_wait_rsop),

  op(OO_IOC_INSTALL_STACK,    efab_install_stack),
  op(OO_IOC_PACE,             ioctl_pace),
  op(OO_IOC_RSOP_DUMP, thr_priv_dump),
  op(OO_IOC_GET_ONLOADFS_DEV, onloadfs_get_dev_t),
  op(OO_IOC_TCP_LOOPBACK_CONNECT, efab_tcp_loopback_connect),
  op(OO_IOC_TCP_DROP_FROM_ACCEPTQ, efab_tcp_drop_from_acceptq),
  op(OO_IOC_MOVE_FD, efab_file_move_to_alien_stack_rsop),
  op(OO_IOC_EP_REUSEPORT_BIND, efab_tcp_helper_reuseport_bind),
  op(OO_IOC_CLUSTER_DUMP,      efab_cluster_dump),
  op(OO_IOC_OFE_CONFIG,         efab_ofe_config),
  op(OO_IOC_OFE_CONFIG_DONE,    efab_ofe_config_done),
  op(OO_IOC_OFE_GET_LAST_ERROR, efab_ofe_get_last_error),
  op(OO_IOC_GET_CPU_KHZ, oo_get_cpu_khz_rsop),
  op(OO_IOC_GET_CPLANE_FD, oo_get_cplane_fd),

  op(OO_IOC_DSHM_REGISTER, oo_dshm_register_rsop),
  op(OO_IOC_DSHM_LIST,     oo_dshm_list_rsop),

  op(OO_IOC_ALLOC_ACTIVE_WILD, efab_tcp_helper_alloc_active_wild_rsop),
#undef op
};
