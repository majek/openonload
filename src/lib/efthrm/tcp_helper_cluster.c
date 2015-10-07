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
                     uid_t euid, int cluster_size,
                     unsigned flags,
                     tcp_helper_cluster_t** thc_out)
{
  int rc, i;
  int rss_flags;
  struct efrm_pd* pd;
  int packet_buffer_mode = flags & THC_FLAG_PACKET_BUFFER_MODE;
  int tproxy = flags & THC_FLAG_TPROXY;
  int hw_loopback_enable = flags & THC_FLAG_HW_LOOPBACK_ENABLE;

  tcp_helper_cluster_t* thc = kmalloc(sizeof(*thc), GFP_KERNEL);
  if( thc == NULL )
    return -ENOMEM;
  memset(thc, 0, sizeof(*thc));
  ci_dllist_init(&thc->thc_tlos);

  strcpy(thc->thc_name, cluster_name);
  thc->thc_cluster_size = cluster_size;
  thc->thc_euid = euid;
  thc->thc_flags = flags;

  /* Needed to protect against oo_nics changes */
  rtnl_lock();

  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i ) {
    if( oo_nics[i].efrm_client == NULL ||
        ! oo_check_nic_suitable_for_onload(&(oo_nics[i])) )
      continue;
    if( (rc = efrm_pd_alloc(&pd, oo_nics[i].efrm_client, NULL,
                (packet_buffer_mode ? EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE : 0) |
                (hw_loopback_enable ? EFRM_PD_ALLOC_FLAG_HW_LOOPBACK : 0))) )
      goto fail;
    /*
     * Currently we move on if we fail to get special tproxy RSS_MODE on
     * interface(s) (expect Siena, Huntington old fw, run out of rss contexts).
     */
    rss_flags = tproxy ? EFRM_RSS_MODE_DST | EFRM_RSS_MODE_SRC :
                EFRM_RSS_MODE_DEFAULT;
redo:
    rc = efrm_vi_set_alloc(pd, thc->thc_cluster_size, 0,
                           rss_flags, &thc->thc_vi_set[i]);
    if( rc != 0 && rss_flags ) {
      LOG_E(ci_log("Installing special RSS mode filter failed on hwport %d, "
                   "falling back to default mode.  Transparent proxy will not "
                   "work with this interface.", i));
      rss_flags = 0;
      goto redo;
    }

    efrm_pd_release(pd);
    if( rc != 0 )
      goto fail;
  }

  rtnl_unlock();

  thc->thc_next = thc_head;
  thc_head = thc;
  *thc_out = thc;
  return 0;

 fail:
  rtnl_unlock();
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
  tcp_helper_resource_t* thr = NULL;
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


/* Look for a suitable stack within the cluster.
 *
 * You need to efab_thr_release() the stack returned by this function
 * when done.
 *
 * You must hold the thc_mutex before calling this function.
 *
 * You cannot hold the THR_TABLE.lock when calling this function.
 */
static int thc_get_thr(tcp_helper_cluster_t* thc,
                       struct oof_socket* oofilter,
                       tcp_helper_resource_t** thr_out)
{
  tcp_helper_resource_t* thr_walk;
  ci_irqlock_state_t lock_flags;
  struct oof_manager* fm = efab_tcp_driver.filter_manager;
  /* Search for a suitable stack within the thc.  A suitable stack has
   * the same tid as current and we could associate our filter with it.
   * Or in other words does not have a socket filter installed
   * (dummy or not) with the same protocol:port_be16[:addr_be32]
   */
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  thr_walk = thc->thc_thr_head;
  while( thr_walk != NULL ) {
    if( thr_walk->thc_tid == current->pid ) {
      if( oof_socket_can_update_stack(fm, oofilter, thr_walk) ) {
        efab_thr_ref(thr_walk);
        *thr_out = thr_walk;
        ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
        return 0;
      }
    }
    thr_walk = thr_walk->thc_thr_next;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  return 1;
}


/* Allocates a new stack in thc.
 *
 * You need to efab_thr_release() the stack returned by this function
 * when done.
 *
 * You must hold the thc_mutex before calling this function.
 */
static int thc_alloc_thr(tcp_helper_cluster_t* thc,
                         int cluster_restart_opt,
                         const ci_netif_config_opts* ni_opts,
                         int ni_flags,
                         tcp_helper_resource_t** thr_out)
{
  int rc;
  tcp_helper_resource_t* thr_walk;
  ci_resource_onload_alloc_t roa;
  ci_netif_config_opts* opts;
  ci_netif* netif;

  memset(&roa, 0, sizeof(roa));

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
  roa.in_flags = ni_flags;
  strncpy(roa.in_version, ONLOAD_VERSION, sizeof(roa.in_version));
  strncpy(roa.in_uk_intf_ver, oo_uk_intf_ver, sizeof(roa.in_uk_intf_ver));
  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  memcpy(opts, ni_opts, sizeof(*opts));
  rc = tcp_helper_rm_alloc(&roa, opts, -1, thc, &thr_walk);
  kfree(opts);
  if( rc != 0 )
    return rc;

  /* Do not allow clustered stacks to do TCP loopback. */
  netif = &thr_walk->netif;
  if( NI_OPTS(netif).tcp_server_loopback != CITP_TCP_LOOPBACK_OFF ||
      NI_OPTS(netif).tcp_client_loopback != CITP_TCP_LOOPBACK_OFF )
    ci_log("%s: Disabling Unsupported TCP loopback on clustered stack.",
           __FUNCTION__);
  NI_OPTS(netif).tcp_server_loopback = NI_OPTS(netif).tcp_client_loopback =
    CITP_TCP_LOOPBACK_OFF;

  thr_walk->thc_tid      = current->pid;
  thr_walk->thc          = thc;
  thr_walk->thc_thr_next = thc->thc_thr_head;
  thc->thc_thr_head      = thr_walk;

  if( (thr_walk->thc->thc_flags & THC_FLAG_TPROXY) != 0 )
    netif->state->flags |= CI_NETIF_FLAG_SCALABLE_FILTERS_RSS;

  oo_atomic_inc(&thc->thc_ref_count);
  *thr_out = thr_walk;
  return 0;
}


static int thc_install_tproxy(tcp_helper_cluster_t* thc, int ifindex)
{
  int rc;
  rc = oof_tproxy_install(efab_tcp_driver.filter_manager, NULL, thc, ifindex);
  if( rc == 0 )
    thc->thc_tproxy_ifindex = ifindex;
  return rc;
}


static void thc_uninstall_tproxy(tcp_helper_cluster_t* thc)
{
  if( thc->thc_tproxy_ifindex )
    oof_tproxy_free(efab_tcp_driver.filter_manager, NULL, thc, thc->thc_tproxy_ifindex);
}


/* Free a thc.
 *
 * You must hold the thc_mutex before calling this function.
 */
static void thc_cluster_free(tcp_helper_cluster_t* thc)
{
  int i;
  tcp_helper_cluster_t *thc_walk, *thc_prev;

  thc_uninstall_tproxy(thc);

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


static void tcp_helper_cluster_ref(tcp_helper_cluster_t* thc)
{
  oo_atomic_inc(&thc->thc_ref_count);
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
  if( thr != NULL )
    thc_remove_thr(thc, thr);
  if( oo_atomic_dec_and_test(&thc->thc_ref_count) )
    thc_cluster_free(thc);
  mutex_unlock(&thc_mutex);
}


/* Returns 1 if the stack belongs to a cluster or else 0.
 */
int tcp_helper_cluster_from_cluster(tcp_helper_resource_t* thr)
{
  return thr->thc != NULL;
}


int tcp_helper_cluster_thc_flags(const ci_netif_config_opts* ni_opts)
{
  return
    (ni_opts->packet_buffer_mode ?
     THC_FLAG_PACKET_BUFFER_MODE : 0) |
    (ni_opts->mcast_send & CITP_MCAST_SEND_FLAG_EXT ?
     THC_FLAG_HW_LOOPBACK_ENABLE : 0) |
    (((ni_opts->scalable_filter_enable == CITP_SCALABLE_FILTERS_ENABLE) &&
     (ni_opts->scalable_filter_mode == CITP_SCALABLE_MODE_TPROXY_ACTIVE_RSS)) ?
     THC_FLAG_TPROXY : 0);
}


static int
gen_cluster_name(const char* cname, char* name_out)
{
  int generate = strlen(cname) == 0;
  if( generate )
    snprintf(name_out, CI_CFG_CLUSTER_NAME_LEN + 1, "c%d", current->tgid);
  else
    strncpy(name_out, cname, CI_CFG_CLUSTER_NAME_LEN);
  name_out[CI_CFG_CLUSTER_NAME_LEN] = '\0';
  return generate;
}


int tcp_helper_cluster_alloc_thr(const char* cname,
                                 int cluster_size,
                                 int cluster_restart,
                                 int ni_flags,
                                 const ci_netif_config_opts* ni_opts,
                                 tcp_helper_resource_t** thr_out)
{
  tcp_helper_cluster_t* thc = NULL;
  tcp_helper_resource_t* thr = NULL;
  int alloced = 0;
  int rc = -ENOENT;
  int thc_flags = tcp_helper_cluster_thc_flags(ni_opts);
  char name[CI_CFG_CLUSTER_NAME_LEN + 1];


  mutex_lock(&thc_init_mutex);
  mutex_lock(&thc_mutex);

  gen_cluster_name(cname, name);

  rc = thc_search_by_name(name, 0, 0, ci_geteuid(), &thc);
  if( rc < 0 )
    goto fail;
  if( rc == 1 )
    rc = 0;
  else
    rc = -ENOENT;

  if( rc == -ENOENT ) {
    rc = thc_alloc(name, 0, 0, ci_geteuid(), cluster_size, thc_flags, &thc);
    if( rc < 0 )
      goto fail;
    alloced = 1;
  }
  if( rc == 0 )
    /* Find a suitable stack within the cluster to use */
    rc = thc_alloc_thr(thc, cluster_restart, ni_opts, ni_flags, &thr);
 fail:
  mutex_unlock(&thc_mutex);
  mutex_unlock(&thc_init_mutex);
  if( rc == 0 && alloced && thc_flags & THC_FLAG_TPROXY ) {
    rc = thc_install_tproxy(thc, ni_opts->scalable_filter_ifindex);
    if( rc != 0 ) {
      efab_thr_release(thr);
      /* this should have freed the thc without other references */
      alloced = 0;
    }
  }
  if( rc != 0 && alloced )
    tcp_helper_cluster_release(thc, NULL);
  if( rc == 0 )
   *thr_out = thr;
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
  tcp_helper_resource_t* thr = NULL;
  citp_waitable* waitable;
  ci_sock_cmn* sock = SP_TO_SOCK(ni, priv->sock_id);
  struct oof_manager* fm = efab_tcp_driver.filter_manager;
  struct oof_socket* oofilter;
  struct oof_socket dummy_oofilter;
  int protocol = thc_get_sock_protocol(sock);
  char name[CI_CFG_CLUSTER_NAME_LEN + 1];
  int rc, rc1;
  int flags = 0;
  tcp_helper_cluster_t* named_thc,* ported_thc;
  int alloced = 0;

  /* No clustering on sockets bound to alien addresses */
  if( sock->s_flags & CI_SOCK_FLAG_BOUND_ALIEN )
    return 0;

  if( NI_OPTS(ni).cluster_ignore == 1 ) {
    LOG_NV(ci_log("%s: Ignored attempt to use clusters due to "
                  "EF_CLUSTER_IGNORE option.", __FUNCTION__));
    return 0;
  }

  if( trb->port_be16 == 0 ) {
    ci_log("%s: Reuseport on port=0 is not supported", __FUNCTION__);
    return -EINVAL;
  }

  if( trb->cluster_size < 2 ) {
    ci_log("%s: Cluster sizes < 2 are not supported", __FUNCTION__);
    return -EINVAL;
  }

  if( sock->s_flags & (CI_SOCK_FLAG_TPROXY | CI_SOCK_FLAG_MAC_FILTER) ) {
    ci_log("%s: Scalable filter sockets cannot be clustered",
           __FUNCTION__);
    return -EINVAL;
  }

  oofilter = &ci_trs_ep_get(priv->thr, priv->sock_id)->oofilter;

  if( oofilter->sf_local_port != NULL ) {
    ci_log("%s: Socket that already have filter cannot be clustered",
           __FUNCTION__);
    return -EINVAL;
  }

  if( priv->thr->thc ) {
    /* Reserve proto:port[:ip] until bind (or close)*/
    rc = oof_socket_add(fm, oofilter,
                       OOF_SOCKET_ADD_FLAG_CLUSTERED |
                       OOF_SOCKET_ADD_FLAG_DUMMY,
                       protocol, trb->addr_be32, trb->port_be16, 0, 0,
                       &ported_thc);
    if( rc > 0 )
      rc = 0;
    if( rc == 0 )
      sock->s_flags |= CI_SOCK_FLAG_FILTER;
    return rc;
  }

  mutex_lock(&thc_init_mutex);
  /* We are going to be iterating over clusters, make sure they don't
   * change.
   */
  mutex_lock(&thc_mutex);

  /* Lookup a suitable cluster to use */

  /* We try to add dummy filter to oof to reserve proto:port[:ip] tuple,
   * if there is already a cluster at the tuple we will get reference to it,
   */
  oof_socket_ctor(&dummy_oofilter);
  rc = oof_socket_add(fm, &dummy_oofilter,
                      OOF_SOCKET_ADD_FLAG_CLUSTERED |
                      OOF_SOCKET_ADD_FLAG_DUMMY |
                      OOF_SOCKET_ADD_FLAG_NO_STACK,
                      protocol, trb->addr_be32, trb->port_be16, 0, 0,
                      &ported_thc);
  if( rc < 0 ) /* non-clustered socket on the tuple */
    goto alloc_fail0;

  if( ! gen_cluster_name(trb->cluster_name, name) ) {
    /* user requested a cluster by name.  But we need to make sure
     * that the oof_local_port that the user is interested in is not
     * being used by another cluster.  We search for cluster by name
     * and use results of prior protp:port[:ip] search oof_local_port
     * to then do some sanity checking.
     */
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
      }
      /* Search by name found a cluster no conflict with search by tuple
       * (the ported cluster is either none or the same as named)*/
      thc = named_thc;
      goto cont;
    }
  }
  else {
    /* No cluster name requested.  We have already looked for a cluster handling
     * the tuple.  If none found, then try to use an existing
     * cluster this process created.  If none found, then allocate one.
     */
    /* If rc == 0, then no cluster found - try to allocate one.
     * If rc == 1, we found cluster - make sure that euids match and continue. */
    if( rc == 1 ) {
      thc = ported_thc;
      if( thc->thc_euid != ci_geteuid() ) {
        rc = -EADDRINUSE;
        goto alloc_fail;
      }
      goto cont;
    }
    rc = thc_search_by_name(name, protocol, trb->port_be16, ci_geteuid(),
                            &thc);
    if( rc < 0 )
      goto alloc_fail;
    if( rc == 1 )
      goto cont;
  }
  /* When an interface is in tproxy mode, all clustered listening socket
   * are assumed to be part of tproxy passive side.  This requires
   * rss context to use altered rss hashing based solely on src ip:port.
   */
  flags = tcp_helper_cluster_thc_flags(&NI_OPTS(ni));

  if( (rc = thc_alloc(name, protocol, trb->port_be16, ci_geteuid(),
                      trb->cluster_size, flags, &thc)) != 0 )
      goto alloc_fail;

  alloced = 1;

 cont:
  tcp_helper_cluster_ref(thc);

  /* At this point we have our cluster with one additional reference */

  /* Find a suitable stack within the cluster to use */
  rc = thc_get_thr(thc, &dummy_oofilter, &thr);
  if( rc != 0 )
    rc = thc_alloc_thr(thc, trb->cluster_restart_opt,
                       &ni->opts, ni->flags, &thr);

  /* If get or alloc succeeded thr holds reference to the cluster,
   * so the cluster cannot go away.  We'll drop our reference and also
   * will not be accessing state within the cluster anymore so we can
   * drop the lock. */
  mutex_unlock(&thc_mutex);

  if( alloced && rc == 0 && (flags & THC_FLAG_TPROXY) != 0 ) {
    /* Tproxy filter is allocated as late as here,
     * the reason is that this needs to be preceded by stack allocation
     * (firmware needs initialized vi) */
    rc = thc_install_tproxy(thc, NI_OPTS(ni).scalable_filter_ifindex);
    if( rc != 0 )
      efab_thr_release(thr);
  }

  tcp_helper_cluster_release(thc, NULL);

  if( rc != 0 ) {
    oof_socket_del(fm, &dummy_oofilter);
    goto alloc_fail_unlocked;
  }

  /* We have thr and we hold single reference to it. */

  /* Move the socket into the new stack */
  if( (rc = ci_netif_lock(ni)) != 0 )
    goto drop_and_done;
  waitable = SP_TO_WAITABLE(ni, priv->sock_id);
  rc = ci_sock_lock(ni, waitable);
  if( rc != 0 ) {
    ci_netif_unlock(ni);
    goto drop_and_done;
  }
  /* thr referencing scheme comes from efab_file_move_to_alien_stack_rsop */
  efab_thr_ref(thr);
  rc = efab_file_move_to_alien_stack(priv, &thr->netif, 0);
  if( rc != 0 )
    efab_thr_release(thr);
  else {
    /* beside us, socket now holds its own reference to thr */
    oofilter = &ci_trs_ep_get(thr, sock->b.moved_to_sock_id)->oofilter;
    oof_socket_replace(fm, &dummy_oofilter, oofilter);
    SP_TO_SOCK(&thr->netif, sock->b.moved_to_sock_id)->s_flags |= CI_SOCK_FLAG_FILTER;
    ci_netif_unlock(&thr->netif);
  }

 drop_and_done:
  if( rc != 0 )
    oof_socket_del(fm, &dummy_oofilter);
  /* Drop the reference we got from thc_get_thr or thc_alloc_thr().
   * If things went wrong both stack and cluster might disappear. */
  efab_thr_release(thr);
  oof_socket_dtor(&dummy_oofilter);
  mutex_unlock(&thc_init_mutex);
  return rc;

 alloc_fail:
  oof_socket_del(fm, &dummy_oofilter);
 alloc_fail0:
  mutex_unlock(&thc_mutex);
 alloc_fail_unlocked:
  oof_socket_dtor(&dummy_oofilter);
  mutex_unlock(&thc_init_mutex);
  return rc;
}



/****************************************************************
Cluster dump functions
*****************************************************************/


static void thc_dump_sockets(ci_netif* netif, oo_dump_log_fn_t log,
                             void* log_arg)
{
  unsigned id;
  for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
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
    int hwports = 0;
    int i;
    for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
      if( walk->thc_vi_set[i] != NULL )
        hwports |= (1 << i);
    log(log_arg, "--------------------------------------------------------");
    log(log_arg, "%d: name=%s  size=%d  euid=%d flags=%d hwports=0x%x", cnt++,
        walk->thc_name, walk->thc_cluster_size, walk->thc_euid,
        walk->thc_flags, hwports);
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
