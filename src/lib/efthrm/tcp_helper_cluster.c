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
**      Author: as
**     Started: 2014/03/14
** Description: TCP helper cluster
** </L5_PRIVATE>
\**************************************************************************/


#include <onload/tcp_helper_fns.h>
#include <onload/version.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/oof_interface.h>

#include <ci/efrm/pd.h>
#include <ci/efrm/vi_set.h>
#include <onload/nic.h>
#include <onload/drv/dump_to_user.h>


#define FMT_PROTOCOL(p)    ((p) == IPPROTO_TCP ? "TCP":         \
                            (p) == IPPROTO_UDP ? "UDP" : "???")

#define FMT_PORT(p)        ((int) CI_BSWAP_BE16(p))

#define IP_FMT             CI_IP_PRINTF_FORMAT
#define IP_ARG(ip)         CI_IP_PRINTF_ARGS(&(ip))

#define IPPORT_FMT         IP_FMT":%d"
#define IPPORT_ARG(ip,p)   IP_ARG(ip), FMT_PORT(p)


/* Head of global linked list of clusters */
/* TODO: As all clusters are associated with a oof_local_port, we
 * could iterate over oof_local_port's to get a list of clusters and
 * not need to maintain this list here. */
static tcp_helper_cluster_t* thc_head;

/* You must hold this mutex if you are accessing anything within
 * thc_head
 */
static DEFINE_MUTEX(thc_mutex);
/* This mutex is used to ensure only that consistent state is used to decide
 * whether a new cluster is needed.  It should only be taken without thc_mutex
 * or the netif lock held, and can only be used to protect
 * efab_tcp_helper_reuseport_bind.
 */
static DEFINE_MUTEX(thc_init_mutex);


static int thc_get_sock_protocol(ci_sock_cmn* sock)
{
  return sock->b.state == CI_TCP_STATE_UDP ? IPPROTO_UDP : IPPROTO_TCP;
}


static int thc_is_thr_name_taken(tcp_helper_cluster_t* thc, char* name)
{
  int i = 0;
  tcp_helper_resource_t* thr_walk = thc->thc_thr_head;
  while( thr_walk != NULL && i < thc->thc_cluster_size ) {
    if( strncmp(name, thr_walk->name, CI_CFG_STACK_NAME_LEN) == 0 )
      return 1;
    thr_walk = thr_walk->thc_thr_next;
    ++i;
  }
  ci_assert_le(i, thc->thc_cluster_size);
  return 0;
}


static int thc_get_next_thr_name(tcp_helper_cluster_t* thc, char* name_out)
{
  int i = 0;
  while( i < thc->thc_cluster_size ) {
    snprintf(name_out, CI_CFG_STACK_NAME_LEN, "%s-c%d", thc->thc_name, i);
    if( thc_is_thr_name_taken(thc, name_out) == 0 )
      return 0;
    ++i;
  }
  return -ENOSPC;
}


/* Returns 1 if the stack contains a socket with the match
 * protocol:addr_be32:port_be16 else 0.
 */
static int thc_thr_search_ip_port(tcp_helper_resource_t* thr, int protocol,
                                  unsigned addr_be32, int port_be16)
{
  ci_netif* netif = &thr->netif;
  unsigned id;
  for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
    if( oo_sock_id_is_waitable(netif, id) ) {
      citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, id);
      if( wo->waitable.state != CI_TCP_STATE_FREE ) {
        citp_waitable* w = &wo->waitable;
        ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
        if( thc_get_sock_protocol(s) == protocol &&
            sock_laddr_be32(s) == addr_be32 &&
            sock_lport_be16(s) == port_be16 )
          return 1;
      }
    }
  }
  return 0;
}


/* If the thc has any orphan stacks, return one of them. */
static int thc_get_an_orphan(tcp_helper_cluster_t* thc,
                             tcp_helper_resource_t** thr_out)
{
  tcp_helper_resource_t* thr_walk;
  int rc = -1;
  ci_irqlock_state_t lock_flags;
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  thr_walk = thc->thc_thr_head;
  while( thr_walk ) {
    if( thr_walk->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND ) {
      rc = 0;
      *thr_out = thr_walk;
      break;
    }
    thr_walk = thr_walk->thc_thr_next;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  return rc;
}


/* Returns 1 if the thc has orphaned stacks else 0.
 */
static int thc_has_orphans(tcp_helper_cluster_t* thc)
{
  tcp_helper_resource_t* thr;
  return thc_get_an_orphan(thc, &thr) == 0 ? 1 : 0;
}


/* Allocate a new cluster.
 *
 * You need to hold the thc_mutex before calling this.
 */
static int thc_alloc(const char* cluster_name, int protocol, int port_be16,
                     uid_t euid, int cluster_size, int packet_buffer_mode,
                     tcp_helper_cluster_t** thc_out)
{
  int rc, i;
  struct efrm_pd* pd;
  tcp_helper_cluster_t* thc = kmalloc(sizeof(*thc), GFP_KERNEL);
  if( thc == NULL )
    return -ENOMEM;
  memset(thc, 0, sizeof(*thc));
  ci_dllist_init(&thc->thc_tlos);

  strcpy(thc->thc_name, cluster_name);
  thc->thc_cluster_size = cluster_size;
  thc->thc_euid = euid;

  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i ) {
    if( oo_nics[i].efrm_client == NULL )
      continue;
    if( (rc = efrm_pd_alloc(&pd, oo_nics[i].efrm_client, NULL,
                            packet_buffer_mode != 0)) != 0 )
      goto fail;
    rc = efrm_vi_set_alloc(pd, thc->thc_cluster_size, 0, &thc->thc_vi_set[i]);
    efrm_pd_release(pd);
    if( rc != 0 )
      goto fail;
  }

  thc->thc_next = thc_head;
  thc_head = thc;
  *thc_out = thc;
  return 0;

 fail:
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    if( thc->thc_vi_set[i] != NULL )
      efrm_vi_set_release(thc->thc_vi_set[i]);
  kfree(thc);
  return rc;
}


static int thc_search_by_name(const char* cluster_name, int protocol,
                              int port_be16, uid_t euid,
                              tcp_helper_cluster_t** thc_out)
{
  tcp_helper_cluster_t* thc_walk = thc_head;

  while( thc_walk != NULL ) {
    if( strcmp(cluster_name, thc_walk->thc_name) == 0 ) {
      if( thc_walk->thc_euid != euid )
        return -EPERM;
      *thc_out = thc_walk;
      return 1;
    }
    thc_walk = thc_walk->thc_next;
  }
  return 0;
}


/* Remove the thr from the list of stacks tracked by the thc.
 *
 * You must hold the thc_mutex before calling this function.
 */
static void thc_remove_thr(tcp_helper_cluster_t* thc,
                           tcp_helper_resource_t* thr)
{
  tcp_helper_resource_t* thr_walk = thc->thc_thr_head;
  tcp_helper_resource_t* thr_prev = NULL;

  while( thr_walk != NULL ) {
    if( thr_walk == thr ) {
      if( thr_prev == NULL ) {
        ci_assert_equal(thr_walk, thc->thc_thr_head);
        thc->thc_thr_head = thr_walk->thc_thr_next;
      }
      else {
        thr_prev->thc_thr_next = thr_walk->thc_thr_next;
      }
      thr->thc = NULL;
      return;
    }
    thr_prev = thr_walk;
    thr_walk = thr_walk->thc_thr_next;
  }
  ci_assert(0);
}


/* Kill an orphan stack in the thc
 *
 * You must hold the thc_mutex before calling this function.
 *
 * You cannot hold the THR_TABLE.lock when calling this function.
 */
static void thc_kill_an_orphan(tcp_helper_cluster_t* thc)
{
  tcp_helper_resource_t* thr;
  int rc;

  rc = thc_get_an_orphan(thc, &thr);
  ci_assert_equal(rc, 0);
  /* This is generally called when the stack is being freed.  But as
   * we are holding the thc_mutex, we will deadlock if we took that
   * path.  So we remove thr from the thc now. */
  thc_remove_thr(thc, thr);
  LOG_U(ci_log("Clustering: Killing orphan stack %d", thr->id));
  rc = tcp_helper_kill_stack_by_id(thr->id);
#ifndef NDEBUG
  if( rc != 0 && rc != -EBUSY )
    LOG_U(ci_log("%s: tcp_helper_kill_stack_by_id(%d): failed %d", __FUNCTION__,
                 thr->id, rc));
#endif
}


/* Look for a suitable stack within the cluster and if none found,
 * allocate a new one.
 *
 * You need to efab_thr_release() the stack returned by this function
 * when done.
 *
 * You must hold the thc_mutex before calling this function.
 *
 * You cannot hold the THR_TABLE.lock when calling this function.
 */
static int thc_get_or_alloc_thr(tcp_helper_cluster_t* thc,
                                int cluster_restart_opt, ci_netif* ni,
                                int protocol, unsigned addr_be32, int port_be16,
                                tcp_helper_resource_t** thr_out)
{
  ci_netif_config_opts* opts;
  ci_resource_onload_alloc_t roa;
  tcp_helper_resource_t* thr_walk;
  ci_irqlock_state_t lock_flags;
  int rc;

  /* Search for a suitable stack within the thc.  A suitable stack has
   * the same tid as current and does not have a socket with the same
   * protocol:addr_be32:port_be16
   */
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  thr_walk = thc->thc_thr_head;
  while( thr_walk != NULL ) {
    if( thr_walk->thc_tid == current->pid ) {
      rc = thc_thr_search_ip_port(thr_walk, protocol, addr_be32, port_be16);
      if( rc == 0 ) {
        efab_thr_ref(thr_walk);
        *thr_out = thr_walk;
        ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
        return 0;
      }
    }
    thr_walk = thr_walk->thc_thr_next;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* No suitable stack found, so create a new one */
  if( (rc = thc_get_next_thr_name(thc, roa.in_name)) != 0 ) {
    /* All stack names taken i.e. cluster is full.  Based on setting
     * of cluster_restart_opt, either kill a orphan or return error. */
    if( thc_has_orphans(thc) == 1 ) {
      /* Checking for CITP_CLUSTER_RESTART_TERMINATE_ORPHANS */
      if( cluster_restart_opt == 1 ) {
        thc_kill_an_orphan(thc);
        rc = thc_get_next_thr_name(thc, roa.in_name);
        ci_assert_equal(rc, 0);
      }
      else {
        LOG_E(ci_log("%s: Clustered stack creation failed because of "
                     "orphans.  Either try again later or use "
                     "EF_CLUSTER_RESTART", __FUNCTION__));
        return rc;
      }
    }
    else {
      LOG_E(ci_log("%s: Stack creation failed because all instances in "
                   "cluster already allocated.", __FUNCTION__));
      return rc;
    }
  }
  roa.in_flags = ni->flags;
  strncpy(roa.in_version, ONLOAD_VERSION, sizeof(roa.in_version));
  strncpy(roa.in_uk_intf_ver, oo_uk_intf_ver, sizeof(roa.in_uk_intf_ver));
  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  memcpy(opts, &ni->opts, sizeof(*opts));
  rc = tcp_helper_rm_alloc(&roa, opts, -1, thc, &thr_walk);
  kfree(opts);
  if( rc != 0 )
    return rc;

  thr_walk->thc_tid      = current->pid;
  thr_walk->thc          = thc;
  thr_walk->thc_thr_next = thc->thc_thr_head;
  thc->thc_thr_head      = thr_walk;
  *thr_out = thr_walk;
  return 0;
}


/* Free a thc.
 *
 * You must hold the thc_mutex before calling this function.
 */
static void thc_cluster_free(tcp_helper_cluster_t* thc)
{
  int i;
  tcp_helper_cluster_t *thc_walk, *thc_prev;

  /* Free up resources within the thc */
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    if( thc->thc_vi_set[i] != NULL )
      efrm_vi_set_release(thc->thc_vi_set[i]);

  ci_assert(ci_dllist_is_empty(&thc->thc_tlos));

  /* Remove from the thc_head list */
  thc_walk = thc_head;
  thc_prev = NULL;
  while( thc_walk != NULL ) {
    if( thc_walk == thc ) {
      if( thc_walk == thc_head ) {
        ci_assert_equal(thc_prev, NULL);
        thc_head = thc_walk->thc_next;
      }
      else {
        thc_prev->thc_next = thc_walk->thc_next;
      }
      kfree(thc_walk);
      return;
    }
    thc_prev = thc_walk;
    thc_walk = thc_walk->thc_next;
  }
  ci_assert(0);
}


/* Releases tcp_helper_resource_t on the tcp_helper_cluster_t.  If no
 * more tcp_helper_resource_t's, then frees it.
 *
 * This function will acquire the thc_mutex.
 */
void tcp_helper_cluster_release(tcp_helper_cluster_t* thc,
                                tcp_helper_resource_t* thr)
{
  mutex_lock(&thc_mutex);
  thc_remove_thr(thc, thr);
  if( thc->thc_thr_head == NULL )
    thc_cluster_free(thc);
  mutex_unlock(&thc_mutex);
}


/* Returns 1 if the stack belongs to a cluster or else 0.
 */
int tcp_helper_cluster_from_cluster(tcp_helper_resource_t* thr)
{
  return thr->thc != NULL;
}


static int thc_bind_os_sock(ci_netif* ni, ci_sock_cmn* s,
                            ci_uint32 laddr_be32, ci_uint16 lport_be16)
{
  union ci_sockaddr_u sa_u;

#if CI_CFG_FAKE_IPV6
  ci_assert(s->domain == AF_INET || s->domain == AF_INET6);
  if( s->domain == AF_INET )
    ci_make_sockaddr(&sa_u.sin, s->domain, lport_be16, laddr_be32);
  else
    ci_make_sockaddr6(&sa_u.sin6, s->domain, lport_be16, laddr_be32);
#else
  ci_assert(s->domain == AF_INET);
  ci_make_sockaddr(&sa_u.sin, s->domain, lport_be16, laddr_be32);
#endif

  return efab_tcp_helper_bind_os_sock(netif2tcp_helper_resource(ni),
                                      SC_SP(s), &sa_u.sa, sizeof(sa_u),
                                      &lport_be16);
}


static thc_legacy_os_sock_t*
thc_get_tlos(tcp_helper_cluster_t* thc, ci_uint32 laddr_be32,
             ci_uint16 lport_be16, int protocol)
{
  thc_legacy_os_sock_t* tlos;

  /* Check whether we have an existing tlos for this protocol/port/addr */
  CI_DLLIST_FOR_EACH2(thc_legacy_os_sock_t, tlos, tlos_next, &thc->thc_tlos) {
    if( (tlos->tlos_protocol == protocol) &&
/* Legacy Cluster: Not currently supporting differing laddr
        (tlos->tlos_laddr_be32 == laddr_be32) &&
*/
        (tlos->tlos_lport_be16 == lport_be16) )
      break;
  }

  return tlos;
}


/* This function handles the parts of adding a socket to a cluster that are
 * specific to the case where we're running without kernel support for
 * SO_REUSEPORT.
 *
 * It will:
 * - if this is the first socket for this protocol/addr/port
 *   - bind the os sock
 *   - take a reference to the os sock
 *   - for UDP sockets, flag that this ep will handle os pollwait notification
 * - otherwise
 *   - close the original os sock
 *   - remove any pollwait registration
 *   - add a reference to the existing os socket
 */
static int thc_reuseport_bind_legacy(tcp_helper_cluster_t* thc,
                                     tcp_helper_resource_t* thr, oo_sp sock_id,
                                     ci_uint32 laddr_be32, ci_uint16 lport_be16,
                                     int protocol)
{
  thc_legacy_os_sock_t* tlos;
  int rc = 0;
  tcp_helper_endpoint_t* ep = ci_trs_ep_get(thr, sock_id);
  ci_sock_cmn* sock = SP_TO_SOCK(&thr->netif, sock_id);
  struct oo_file_ref* os_socket;

  /* All fd types that we can get this far with should have an os socket. */
  ci_assert_nequal(ep->os_socket, NULL);

  /* All manipulation of tlos must be done with the thc_mutex held. */
  mutex_lock(&thc_mutex);

  tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_LEGACY_REUSEPORT);

  /* Check whether we have an existing tlos for this protocol/port/addr */
  tlos = thc_get_tlos(thc, laddr_be32, lport_be16, protocol);

  if( tlos == NULL ) {
    tlos = ci_alloc(sizeof(*tlos));
    if( tlos == NULL ) {
      rc = -ENOMEM;
      goto unlock_out;
    }

    tlos->tlos_laddr_be32 = laddr_be32;
    tlos->tlos_lport_be16 = lport_be16;
    tlos->tlos_protocol = protocol;
    tlos->tlos_pollwait_registered = 0;
    tlos->tlos_refs = 1;

    /* Bind the backing socket */
    rc = thc_bind_os_sock(&thr->netif, sock, laddr_be32, lport_be16);

    if( rc < 0 ) {
      ci_free(tlos);
      goto unlock_out;
    }

    /* We maintain a reference to the os socket in the tlos structure so we can
     * avoid ordering issues when sockets drop their os socket ref when
     * closing.
     */
    tlos->tlos_os_sock = oo_file_ref_add(ep->os_socket);
    if( tlos->tlos_os_sock == NULL ) {
      ci_free(tlos);
      rc = -ENOMEM;
      goto unlock_out;
    }

    ci_dllist_push(&thc->thc_tlos, &tlos->tlos_next);

    /* We didn't go via __ci_bind, so have missed setting
     * CI_SOCK_FLAG_PORT_BOUND.  Do so now.
     */
    if( sock->b.state & CI_TCP_STATE_TCP )
      sock->s_flags |= CI_SOCK_FLAG_PORT_BOUND;

    /* We need to ensure that only one endpoint registers for pollwait
     * notifications.  If this is a UDP socket then it will already have been
     * registered, so set the flag to indicate this.  If it's TCP, then the
     * flag will be set by the first endpoint to call listen.
     *
     * We'll use the flag to hand over registration to another endpoint in the
     * cluster if this one is closed.
     */
    if( sock->b.state == CI_TCP_STATE_UDP ) {
      ci_assert_nequal(ep->os_sock_pt.whead, NULL);
      tlos->tlos_pollwait_registered = 1;
      tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_OS_NOTIFIER);
    }
  }
  else {
    ci_assert_nequal(tlos->tlos_os_sock, NULL);

    efab_tcp_helper_os_pollwait_unregister(ep);

    os_socket = ep->os_socket;
    ep->os_socket = oo_file_ref_add(tlos->tlos_os_sock);
    if( ep->os_socket == NULL ) {
      ep->os_socket = os_socket;
      efab_tcp_helper_os_pollwait_register(ep);
      goto unlock_out;
    }

    oo_file_ref_drop(os_socket);
    tlos->tlos_refs++;
  }

 unlock_out:
  mutex_unlock(&thc_mutex);
  return rc;
}


/* This function must be called with netif lock not held and it always
 * returns with the netif lock not held.
 */
int efab_tcp_helper_reuseport_bind(ci_private_t *priv, void *arg)
{
  oo_tcp_reuseport_bind_t* trb = arg;
  ci_netif* ni = &priv->thr->netif;
  tcp_helper_cluster_t* thc;
  tcp_helper_resource_t* thr;
  citp_waitable* waitable;
  ci_sock_cmn* sock = SP_TO_SOCK(ni, priv->sock_id);
  int protocol = thc_get_sock_protocol(sock);
  char name[(CI_CFG_STACK_NAME_LEN >> 1) + 1];
  int rc, rc1;

  if( NI_OPTS(ni).cluster_ignore == 1 ) {
    LOG_NV(ci_log("%s: Ignored attempt to use clusters due to "
                  "EF_CLUSTER_IGNORE option.", __FUNCTION__));
    return 0;
  }

  if( ci_netif_is_locked(ni) ) {
    ci_log("%s: This function can only be used with an unlocked netif.",
           __FUNCTION__);
    return -EINVAL;
  }

  if( trb->port_be16 == 0 ) {
    ci_log("%s: Reuseport on port=0 is not supported", __FUNCTION__);
    return -EINVAL;
  }

  if( trb->cluster_size < 2 ) {
    ci_log("%s: Cluster sizes < 2 are not supported", __FUNCTION__);
    return -EINVAL;
  }

  if( (NI_OPTS(ni).mcast_send & CITP_MCAST_SEND_FLAG_EXT) != 0 ) {
    ci_log("%s: Clustering with HW multicast loopback is not supported.  "
           "Check setting of EF_MCAST_SEND.", __FUNCTION__);
    return -ENOSYS;
  }

  strncpy(name, trb->cluster_name, CI_CFG_STACK_NAME_LEN >> 1);
  name[(CI_CFG_STACK_NAME_LEN >> 1)] = '\0';

  mutex_lock(&thc_init_mutex);
  /* We are going to be iterating over clusters, make sure they don't
   * change.
   */
  mutex_lock(&thc_mutex);

  /* Lookup a suitable cluster to use */
  if( strlen(name) != 0 ) {
    /* user requested a cluster by name.  But we need to make sure
     * that the oof_local_port that the user is interested in is not
     * being used by another cluster.  We search for cluster by name
     * and by oof_local_port and then do some sanity checking on them.
     */
    tcp_helper_cluster_t *named_thc, *ported_thc;
    rc = oof_local_port_thc_search(efab_tcp_driver.filter_manager, protocol,
                                    trb->port_be16, &ported_thc);
    if( rc < 0 )
      goto alloc_fail;
    rc1 = thc_search_by_name(name, protocol, trb->port_be16, ci_geteuid(),
                            &named_thc);
    if( rc1 < 0 ) {
      rc = rc1;
      goto alloc_fail;
    }

    if( rc1 == 0 ) {
      if( rc == 1 ) {
        /* search by oof_local_port found a cluster which search by
         * name didn't find. */
        LOG_E(ci_log("Error: Cluster with requested name %s already "
                     "bound to %s", name, ported_thc->thc_name));
        rc = -EEXIST;
        goto alloc_fail;
      }
      else {
        /* Neither searches found a cluster.  So allocate one below.
         */
      }
    }
    else {
      if( rc == 1 ) {
        /* Both searches found clusters.  Fine if they are the same or
         * else error. */
        if( named_thc != ported_thc ) {
          LOG_E(ci_log("Error: Cluster %s does not handle socket %s:%d.  "
                       "Cluster %s does", name, FMT_PROTOCOL(protocol),
                       trb->port_be16, named_thc->thc_name));
          rc = -EEXIST;
          goto alloc_fail;
        }
        else {
          thc = named_thc;
          goto cont;
        }
      }
      else {
        /* Search by name found a cluster that search by port didn't.
         * This means that the cluster exists but hasn't been
         * associated with the port number yet. */
        thc = named_thc;
        goto cont;
      }
    }

    if( (rc = thc_alloc(name, protocol, trb->port_be16, ci_geteuid(),
                        trb->cluster_size, NI_OPTS(ni).packet_buffer_mode,
                        &thc)) != 0 )
      goto alloc_fail;
  }
  else {
    /* No cluster name requested.  Search for a cluster handling the
     * protocol:port_be16.  If none found, then try to use an existing
     * cluster this process created.  If none found, then allocate one.
     */
    rc = oof_local_port_thc_search(efab_tcp_driver.filter_manager, protocol,
                                   trb->port_be16, &thc);
    /* If rc < 0, then the call failed.  If 0, then we no cluster was
     * found so try to allocate one.  If 1, we found cluster.  Make
     * sure that euids match and continue. */
    if( rc < 0 )
      goto alloc_fail;
    if( rc == 1 ) {
      if( thc->thc_euid != ci_geteuid() ) {
        rc = -EPERM;
        goto alloc_fail;
      }
      goto cont;
    }
    snprintf(name, CI_CFG_STACK_NAME_LEN + 1, "c%d", current->tgid);
    rc = thc_search_by_name(name, protocol, trb->port_be16, ci_geteuid(),
                            &thc);
    if( rc < 0 )
      goto alloc_fail;
    if( rc == 1 )
      goto cont;
    if( (rc = thc_alloc(name, protocol, trb->port_be16, ci_geteuid(),
                        trb->cluster_size, NI_OPTS(ni).packet_buffer_mode,
                        &thc)) != 0 )
      goto alloc_fail;
  }

 cont:
  rc = oof_socket_cluster_add(efab_tcp_driver.filter_manager, thc, protocol,
                              trb->port_be16);
  if( rc != 0 ) {
    if( thc->thc_thr_head == NULL )
      thc_cluster_free(thc);
    goto alloc_fail;
  }

  /* Find a suitable stack within the cluster to use */
  rc = thc_get_or_alloc_thr(thc, trb->cluster_restart_opt, ni, protocol,
                            trb->addr_be32, trb->port_be16, &thr);
  if( rc != 0 ) {
    if( thc->thc_thr_head == NULL )
      thc_cluster_free(thc);
    oof_socket_cluster_del(efab_tcp_driver.filter_manager, thc, protocol,
                           trb->port_be16);
    goto alloc_fail;
  }

  /* At this point, we hold a reference to a stack within a cluster,
   * so the stack and the cluster cannot go away.  We can drop the
   * locks. */
  mutex_unlock(&thc_mutex);

  /* Move the socket into the new stack */
  if( (rc = ci_netif_lock(ni)) != 0 )
    goto drop_and_done;
  waitable = SP_TO_WAITABLE(ni, priv->sock_id);
  rc = ci_sock_lock(ni, waitable);
  if( rc != 0 ) {
    ci_netif_unlock(ni);
    goto drop_and_done;
  }
  efab_thr_ref(thr);
  rc = efab_file_move_to_alien_stack(priv, &thr->netif);
  if( rc != 0 )
    efab_thr_release(thr);
  else {
    ci_netif_unlock(&thr->netif);

    /* Now that the socket's in the clustered stack, set its clustering filter
     * state. */
    oof_socket_set_early_lp(efab_tcp_driver.filter_manager,
                            &ci_trs_ep_get(thr, priv->sock_id)->oofilter,
                            protocol, trb->port_be16);
  }

  /* If this fails we leave the socket in the new stack to avoid a complex
   * error path.
   */
  if( sock->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY )
    rc = thc_reuseport_bind_legacy(thc, thr, priv->sock_id, trb->addr_be32,
                                   trb->port_be16, protocol);

 drop_and_done:
  if( rc != 0 )
    oof_socket_cluster_del(efab_tcp_driver.filter_manager, thc, protocol,
                           trb->port_be16);
  /* Drop the reference we got from thc_get_or_alloc_thr(). */
  efab_thr_release(thr);
  mutex_unlock(&thc_init_mutex);
  return rc;

 alloc_fail:
  mutex_unlock(&thc_mutex);
  mutex_unlock(&thc_init_mutex);
  return rc;
}


static void thc_legacy_sock_set_pollwait(thc_legacy_os_sock_t* tlos,
                                         tcp_helper_endpoint_t* ep)
{
  tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_OS_NOTIFIER);
  efab_tcp_helper_os_pollwait_register(ep);
  tlos->tlos_pollwait_registered = 1;
}


static void thc_legacy_sock_unset_pollwait(thc_legacy_os_sock_t* tlos,
                                           tcp_helper_endpoint_t* ep)
{
  tcp_helper_endpoint_clear_aflags(ep, OO_THR_EP_AFLAG_OS_NOTIFIER);
  efab_tcp_helper_os_pollwait_unregister(ep);
  tlos->tlos_pollwait_registered = 0;
}


/* Returns ep of a legacy reuseport socket in this stack with the match
 * protocol:addr_be32:port_be16, suitable for receiving os notifications.
 */
static oo_sp thc_thr_legacy_sock(tcp_helper_resource_t* thr, int protocol,
                                 unsigned addr_be32, int port_be16)
{
  ci_netif* netif = &thr->netif;
  unsigned id;
  for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
    if( oo_sock_id_is_waitable(netif, id) ) {
      citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, id);
      if( wo->waitable.state != CI_TCP_STATE_FREE ) {
        citp_waitable* w = &wo->waitable;
        ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
        if( thc_get_sock_protocol(s) == protocol &&
/* Legacy Cluster: Not currently supporting differing laddr
            sock_laddr_be32(s) == addr_be32 &&
*/
            sock_lport_be16(s) == port_be16 &&
            sock_raddr_be32(s) == 0 &&
            sock_rport_be16(s) == 0 &&
            (s->b.state == CI_TCP_STATE_UDP || s->b.state == CI_TCP_LISTEN) )
          return OO_SP_FROM_INT(netif, id);
      }
    }
  }
  return OO_SP_INVALID;
}


/* Removes notification responsibility from old_ep, and move it to a new
 * endpoint if one is available.
 * This function should be called with the thc_mutex held.
 */
static void thc_move_legacy_os_notifier(thc_legacy_os_sock_t* tlos,
                                        tcp_helper_endpoint_t* old_ep)
{
  tcp_helper_cluster_t* thc = old_ep->thr->thc;
  tcp_helper_resource_t* thr_walk;
  ci_sock_cmn* s = SP_TO_SOCK(&old_ep->thr->netif, old_ep->id);
  ci_irqlock_state_t lock_flags;
  int protocol = thc_get_sock_protocol(s);
  ci_uint32 addr_be32 = sock_laddr_be32(s);
  ci_uint16 port_be16 = sock_lport_be16(s);
  oo_sp id = OO_SP_INVALID;
  tcp_helper_endpoint_t* new_ep;

  /* Should only be calling this for an endpoint that's in a cluster. */
  ci_assert(thc);

  /* Look for another sock with the same protocol/addr/port in a different
   * stack in the cluster to handover the pollwait registration to.
   */
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  thr_walk = thc->thc_thr_head;
  while( thr_walk != NULL ) {
    /* Only bother looking at different stacks */
    if( thr_walk != old_ep->thr ) {
      id = thc_thr_legacy_sock(thr_walk, protocol, addr_be32, port_be16);
      /* If we're got a valid ep id, then we can use that for notifications. */
      if( id != OO_SP_INVALID ) {
        break;
      }
    }
    thr_walk = thr_walk->thc_thr_next;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  thc_legacy_sock_unset_pollwait(tlos, old_ep);

  if( thr_walk && (id != OO_SP_INVALID) ) {
    new_ep = ci_trs_ep_get(thr_walk, id);
    thc_legacy_sock_set_pollwait(tlos, new_ep);
  }
}


void tcp_helper_cluster_legacy_os_close(tcp_helper_endpoint_t* ep)
{
  thc_legacy_os_sock_t* tlos;
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);

  mutex_lock(&thc_mutex);

  tlos = thc_get_tlos(ep->thr->thc, sock_laddr_be32(s), sock_lport_be16(s),
                      thc_get_sock_protocol(s));
  ci_assert(tlos);

  if( ep->ep_aflags & OO_THR_EP_AFLAG_OS_NOTIFIER ) {
    thc_move_legacy_os_notifier(tlos, ep);
  }

  tlos->tlos_refs--;
  if( tlos->tlos_refs == 0 ) {
    oo_file_ref_drop(tlos->tlos_os_sock);
    ci_dllist_remove(&tlos->tlos_next);
    ci_free(tlos);
  }

  mutex_unlock(&thc_mutex);
}


void tcp_helper_cluster_legacy_os_shutdown(tcp_helper_endpoint_t* ep)
{
  thc_legacy_os_sock_t* tlos;
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);

  /* If this ep was getting the os notifications, then shift that to another
   * ep if one is available.
   */
  if( ep->ep_aflags & OO_THR_EP_AFLAG_OS_NOTIFIER ) {
    mutex_lock(&thc_mutex);
    tlos = thc_get_tlos(ep->thr->thc, sock_laddr_be32(s), sock_lport_be16(s),
                        thc_get_sock_protocol(s));
    ci_assert(tlos);
    thc_move_legacy_os_notifier(tlos, ep);
    mutex_unlock(&thc_mutex);
  }
}


int tcp_helper_cluster_legacy_os_listen(tcp_helper_endpoint_t* ep)
{
  thc_legacy_os_sock_t* tlos;
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int rc = 0;

  ci_assert(ep->thr->thc);

  mutex_lock(&thc_mutex);

  tlos = thc_get_tlos(ep->thr->thc, sock_laddr_be32(s), sock_lport_be16(s),
                      thc_get_sock_protocol(s));

  ci_assert(tlos);
  if( !tlos->tlos_pollwait_registered ) {
    /* We should have removed the notifier if this socket was shutdown
     * previously.
     */
    ci_assert_equal(ep->os_sock_pt.whead, NULL);
    thc_legacy_sock_set_pollwait(tlos, ep);
    rc = 1;
  }

  mutex_unlock(&thc_mutex);
  return rc;
}


/****************************************************************
Cluster dump functions
*****************************************************************/


static const char* citp_waitable_type_str(citp_waitable* w)
{
  if( w->state & CI_TCP_STATE_TCP )         return "TCP";
  else if( w->state == CI_TCP_STATE_UDP )   return "UDP";
  else if( w->state == CI_TCP_STATE_FREE )  return "FREE";
  else if( w->state == CI_TCP_STATE_ALIEN ) return "ALIEN";
#if CI_CFG_USERSPACE_PIPE
  else if( w->state == CI_TCP_STATE_PIPE )  return "PIPE";
#endif
  else return "<unknown-citp_waitable-type>";
}


static void thc_dump_sockets(ci_netif* netif, oo_dump_log_fn_t log,
                             void* log_arg)
{
  unsigned id;
  for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
    if( oo_sock_id_is_waitable(netif, id) ) {
      citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, id);
      if( wo->waitable.state != CI_TCP_STATE_FREE ) {
        citp_waitable* w = &wo->waitable;
        ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
        log(log_arg, "    %s lcl="OOF_IP4PORT" rmt="OOF_IP4PORT,
            citp_waitable_type_str(w),
            OOFA_IP4PORT(sock_laddr_be32(s), sock_lport_be16(s)),
            OOFA_IP4PORT(sock_raddr_be32(s), sock_rport_be16(s)));
      }
    }
  }
}


static void thc_dump_thrs(tcp_helper_cluster_t* thc, oo_dump_log_fn_t log,
                          void* log_arg)
{
  tcp_helper_resource_t* walk;

  walk = thc->thc_thr_head;
  log(log_arg, "stacks:");
  while( walk != NULL ) {
    log(log_arg, "  name=%s  id=%d  tid=%d", walk->name, walk->id,
        walk->thc_tid);
    thc_dump_sockets(&walk->netif, log, log_arg);
    walk = walk->thc_thr_next;
  }
}


static void thc_dump_fn(void* not_used, oo_dump_log_fn_t log, void* log_arg)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_cluster_t* walk;
  int cnt = 0;

  /* Iterating over list of stacks, make sure they don't change. */
  mutex_lock(&thc_mutex);
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  walk = thc_head;
  while( walk != NULL ) {
    log(log_arg, "--------------------------------------------------------");
    log(log_arg, "%d: name=%s  size=%d  euid=%d", cnt++,
        walk->thc_name, walk->thc_cluster_size, walk->thc_euid);
    thc_dump_thrs(walk, log, log_arg);
    walk = walk->thc_next;
  }

  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  mutex_unlock(&thc_mutex);
}


int tcp_helper_cluster_dump(tcp_helper_resource_t* thr, void* buf, int buf_len)
{
  return oo_dump_to_user(thc_dump_fn, NULL, buf, buf_len);
}
