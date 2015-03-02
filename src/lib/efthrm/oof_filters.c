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

/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

/* README!
 *
 * Please do not add any new '#include's here without first talking to
 * David Riddoch.  I want to limit and document dependencies of this module
 * on other parts of Onload.  
 */

#include "onload_kernel_compat.h"

#include "oof_impl.h"
#include <ci/net/ipv4.h>
#include <onload/oof_interface.h>
#include <onload/oof_socket.h>
#include <onload/debug.h>
#include "oo_hw_filter.h"
#include "tcp_filters_internal.h"

#define OOF_SRC_FLAGS_DEFAULT 0
#define OOF_SRC_FLAGS_DEFAULT_MCAST (OO_HW_SRC_FLAG_LOOPBACK)

extern void
tcp_helper_cluster_release(struct tcp_helper_cluster_s* thc,
                           struct tcp_helper_resource_s* trs);
extern void
tcp_helper_cluster_ref(struct tcp_helper_cluster_s* thc);

#ifndef NDEBUG

static void oof_mutex_lock_chk_not_atomic(struct mutex* m)
{
  ci_assert(! in_atomic());
  ci_assert(! in_interrupt());
  mutex_lock(m);
  ci_assert(! in_atomic());
  ci_assert(! in_interrupt());
}

# undef mutex_lock
# define mutex_lock  oof_mutex_lock_chk_not_atomic

#endif


/* If the number of sockets sharing a wild-match filter exceeds this value,
 * then the wild-match filter will be kept even after the socket that
 * created the filter is closed.
 *
 * e.g. Create a listening socket, accept 200 connections, close listening
 * socket.  The accepted sockets will continue to share a single wild-match
 * filter until the number of them drops below [oof_shared_keep_thresh], at
 * which point they will each get their own full-match filter and the wild
 * filter will be freed.
 */
int oof_shared_keep_thresh = 100;

/* If the number of sockets sharing a wild-match filter exceeds this value,
 * then the wild-match filter will be kept even when a new wild-match
 * socket needs the filter to point to a different stack.
 *
 * e.g. Create a listening socket, accept 300 connections, close listening
 * socket, create a new listening socket in a separate app.  The accepted
 * sockets will continue to share use the wild-match filter until the
 * number of them drops below [oof_shared_steal_thresh], at which point
 * they will each get their own full-match filter and the wild filter will
 * be pointed at the new wild socket.
 */
int oof_shared_steal_thresh = 200;


static struct oof_manager* the_manager;


#define IPF_LOG(...)  OO_DEBUG_IPF(ci_log(__VA_ARGS__))
#define ERR_LOG(...)  OO_DEBUG_ERR(ci_log(__VA_ARGS__))

#define SK_FMT             "%d:%d"
#define SK_PRI_ARGS(skf)   oof_cb_stack_id(oof_cb_socket_stack(skf)),   \
                           oof_cb_socket_id(skf)

#define FSK_FMT            "%s: "SK_FMT" "
#define FSK_PRI_ARGS(skf)  __FUNCTION__, SK_PRI_ARGS(skf)

#define TRIPLE_FMT         "%s "IPPORT_FMT
#define TRIPLE_ARGS(proto, ip, port)                    \
    FMT_PROTOCOL(proto), IPPORT_ARG((ip), (port))

#define QUIN_FMT           "%s "IPPORT_FMT" "IPPORT_FMT
#define QUIN_ARGS(proto, ip1, port1, ip2, port2)                        \
    FMT_PROTOCOL(proto), IPPORT_ARG((ip1), (port1)), IPPORT_ARG((ip2), (port2))

#define SK_ADDR_FMT        QUIN_FMT
#define SK_ADDR_ARGS(skf)                                       \
    QUIN_ARGS(skf->sf_local_port->lp_protocol,                  \
              skf->sf_laddr, skf->sf_local_port->lp_lport,      \
              skf->sf_raddr, skf->sf_rport)

#define SK_WILD_ADDR_FMT   TRIPLE_FMT
#define SK_WILD_ADDR_ARGS(skf)                                  \
    TRIPLE_ARGS(skf->sf_local_port->lp_protocol,                \
                skf->sf_laddr, skf->sf_local_port->lp_lport)


static void
oof_mcast_filter_list_free(ci_dllist* mcast_filters);

static int
oof_socket_mcast_install(struct oof_manager* fm, struct oof_socket* skf);

static void
oof_socket_mcast_remove(struct oof_manager* fm, struct oof_socket* skf,
                        ci_dllist* mcast_filters);

static void
oof_socket_mcast_remove_sw(struct oof_manager* fm, struct oof_socket* skf);

static unsigned
oof_mcast_filter_duplicate_hwports(struct oof_mcast_filter* mf,
                                   struct oof_mcast_filter* mf2);

static unsigned
oof_mcast_filter_installable_hwports(struct oof_local_port* lp,
                                      struct oof_mcast_filter* mf);

static unsigned
oof_mcast_filter_hwport_mask(struct oof_manager* fm,
                             struct oof_mcast_filter* mf);

static void
__oof_manager_addr_add(struct oof_manager*, unsigned laddr, unsigned ifindex);

static void
__oof_manager_addr_del(struct oof_manager*, unsigned laddr, unsigned ifindex);

static void
__oof_mcast_update_filters(struct oof_manager* fm, int ifindex);

static void
oof_thc_add_ref(struct oof_local_port* lp);

static int
oof_thc_install_filters(struct oof_manager* fm, struct oof_local_port* lp,
                        unsigned laddr);

static int
oof_thc_alloc(struct oof_manager* fm, struct tcp_helper_cluster_s* thc,
              struct oof_local_port* lp);

static void
oof_thc_remove_filters(struct oof_manager* fm, struct oof_local_port* lp);

static void
oof_thc_do_del(struct oof_thc* thcf);

static int
oof_thc_release(struct oof_manager* fm, struct oof_local_port* lp);


static int oof_is_clustered(struct oof_local_port* lp)
{
  return lp->lp_thcf != NULL;
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static int __oof_hw_filter_set(struct oof_manager* fm,
                               struct oof_socket* skf,
                               struct oo_hw_filter* oofilter,
                               struct tcp_helper_resource_s* trs, int protocol,
                               unsigned saddr, int sport,
                               unsigned daddr, int dport,
                               unsigned hwport_mask,
                               unsigned src_flags,
                               int fail_is_error,
                               const char* caller)
{
  int rc;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  rc = oo_hw_filter_set(oofilter, trs, protocol, saddr, sport,
                            daddr, dport, OO_HW_VLAN_UNSPEC, 0,
                            hwport_mask, src_flags);
  spin_lock_bh(&fm->fm_inner_lock);

  if( rc == 0 ) {
    IPF_LOG(FSK_FMT "FILTER "QUIN_FMT, caller, SK_PRI_ARGS(skf),
            QUIN_ARGS(protocol, daddr, dport, saddr, sport));
    oof_dl_filter_set(oofilter,
                      oof_cb_stack_id(oof_cb_socket_stack(skf)),
                      protocol, saddr, sport, daddr, dport);
  }
  else if( rc == -EACCES ) {
    ERR_LOG(FSK_FMT "FILTER "QUIN_FMT" blocked by firewall", caller,
            SK_PRI_ARGS(skf), QUIN_ARGS(protocol, daddr, dport, saddr, sport));
  }
  else if( fail_is_error ) {
    ERR_LOG(FSK_FMT "ERROR: FILTER "QUIN_FMT" failed (%d)", caller,
            SK_PRI_ARGS(skf), QUIN_ARGS(protocol, daddr, dport, saddr, sport),
            rc);
  }
  else {
    IPF_LOG(FSK_FMT "ERROR: FILTER "QUIN_FMT" failed (%d)", caller,
            SK_PRI_ARGS(skf), QUIN_ARGS(protocol,daddr,dport,saddr,sport), rc);
  }
  return rc;
}


static int oof_hw_thc_filter_set(struct oof_manager* fm,
                                 struct oof_local_port* lp, int la_i,
                                 unsigned laddr)
{
  int rc;
  struct oof_thc* thcf = lp->lp_thcf;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(! in_atomic());
  oo_hw_filter_init(&thcf->tf_filters[la_i]);
  rc = oo_hw_filter_set_thc(&thcf->tf_filters[la_i], thcf->tf_thc,
                            lp->lp_protocol, laddr, lp->lp_lport,
                            fm->fm_hwports_available & fm->fm_hwports_up);
  spin_lock_bh(&fm->fm_inner_lock);
  return rc;
}


static void oof_hw_filter_clear(struct oof_manager* fm,
                                struct oo_hw_filter* oofilter)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  oo_hw_filter_clear(oofilter);
  spin_lock_bh(&fm->fm_inner_lock);
}


static void oof_hw_filter_clear_hwports(struct oof_manager* fm,
                                        struct oo_hw_filter* oofilter,
                                        unsigned hwport_mask)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(oofilter->thc == NULL);

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  oo_hw_filter_clear_hwports(oofilter, hwport_mask);
  spin_lock_bh(&fm->fm_inner_lock);
}


static void __oof_hw_filter_clear_full(struct oof_manager* fm,
                                       struct oof_socket* skf,
                                       const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  oof_dl_filter_del(&skf->sf_full_match_filter);
  oof_hw_filter_clear(fm, &skf->sf_full_match_filter);
  IPF_LOG(FSK_FMT "CLEAR "SK_ADDR_FMT,
          caller, SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
}


static void __oof_hw_filter_clear_wild(struct oof_manager* fm,
                                       struct oof_local_port* lp,
                                       struct oof_local_port_addr* lpa,
                                       unsigned laddr,
                                       const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( lpa->lpa_filter.trs != NULL ) {
    IPF_LOG("%s: CLEAR "TRIPLE_FMT" stack=%d", caller,
            TRIPLE_ARGS(lp->lp_protocol, laddr, lp->lp_lport),
            oof_cb_stack_id(lpa->lpa_filter.trs));
    oof_dl_filter_del(&lpa->lpa_filter);
    oof_hw_filter_clear(fm, &lpa->lpa_filter);
  }
}


static int oof_hw_filter_update(struct oof_manager* fm,
                                struct oo_hw_filter* oofilter,
                                struct tcp_helper_resource_s* new_stack,
                                int protocol,
                                unsigned saddr, int sport,
                                unsigned daddr, int dport,
                                ci_uint16 vlan_id,
                                unsigned hwport_mask,
                                unsigned src_flags)
{
  int rc;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  rc = oo_hw_filter_update(oofilter, new_stack, protocol,
                           saddr, sport, daddr, dport, vlan_id,
                           fm->fm_hwports_vlan_filters & hwport_mask,
                           hwport_mask, src_flags);
  spin_lock_bh(&fm->fm_inner_lock);
  return rc;
}


static void __oof_hw_filter_move(struct oof_manager* fm,
                                 struct oof_socket* skf,
                                 struct oof_local_port* lp,
                                 struct oof_local_port_addr* lpa,
                                 unsigned laddr, unsigned hwport_mask,
                                 const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(! CI_IP_IS_MULTICAST(laddr));

  IPF_LOG(FSK_FMT "MOVE "TRIPLE_FMT" from stack %d", caller, SK_PRI_ARGS(skf),
          TRIPLE_ARGS(lp->lp_protocol, laddr, lp->lp_lport),
          oof_cb_stack_id(lpa->lpa_filter.trs));
  oof_hw_filter_update(fm, &lpa->lpa_filter, oof_cb_socket_stack(skf),
                       lp->lp_protocol, 0, 0, laddr, lp->lp_lport,
                       OO_HW_VLAN_UNSPEC, hwport_mask, OOF_SRC_FLAGS_DEFAULT);
}


static void __oof_hw_filter_transfer(struct oof_manager* fm,
                                     struct oof_mcast_member* mm,
                                     struct oof_mcast_filter* mf_new,
                                     unsigned hwport_mask,
                                     const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  IPF_LOG(FSK_FMT "TRANSFER "TRIPLE_FMT, caller, SK_PRI_ARGS(mm->mm_socket),
          TRIPLE_ARGS(mm->mm_socket->sf_local_port->lp_protocol, mm->mm_maddr,
          mm->mm_socket->sf_local_port->lp_lport));
  oo_hw_filter_transfer(&mm->mm_filter->mf_filter, &mf_new->mf_filter,
                        hwport_mask);
}


#define oof_hw_filter_set(fm, skf, f, s, p, sa, sp, da, dp, pp, sf, fie)     \
  __oof_hw_filter_set((fm), (skf), (f), (s), (p), (sa), (sp), (da),      \
                      (dp), (pp), (sf), (fie),  __FUNCTION__)

#define oof_hw_filter_clear_full(fm, skf)                \
  __oof_hw_filter_clear_full((fm), (skf), __FUNCTION__)

#define oof_hw_filter_clear_wild(fm, lp, lpa, laddr)                     \
  __oof_hw_filter_clear_wild((fm), (lp), (lpa), (laddr), __FUNCTION__)

#define oof_hw_filter_move(fm, skf, lp, lpa, laddr, hwports)            \
  __oof_hw_filter_move((fm), (skf), (lp), (lpa), (laddr), (hwports),    \
                       __FUNCTION__)

#define oof_hw_filter_transfer(fm, mm, mf, hwports)         \
  __oof_hw_filter_transfer((fm), (mm), (mf), (hwports), __FUNCTION__)


static void oof_sw_insert_fail(struct oof_socket* skf,
                               const char* func, int rc)
{
  /* Currently just log and continue in these cases.  Possible responses:
   * (1) Mark the interface for no further acceleration.  (2) Remove some
   * "non-critical" filters such as UDP to make space.
   */
  ERR_LOG(FSK_FMT "ERROR: "SK_ADDR_FMT" could not add s/w filter (%d)",
          func, SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf), rc);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void
oof_local_port_addr_init(struct oof_local_port_addr* lpa)
{
  oo_hw_filter_init(&lpa->lpa_filter);
  ci_dllist_init(&lpa->lpa_semi_wild_socks);
  ci_dllist_init(&lpa->lpa_full_socks);
  lpa->lpa_n_full_sharers = 0;
}




static void
oof_local_port_free(struct oof_manager* fm, struct oof_local_port* lp)
{
  ci_assert(lp->lp_refs == 0);
  ci_assert(ci_dllist_is_empty(&lp->lp_wild_socks));
  ci_assert(ci_dllist_is_empty(&lp->lp_mcast_filters));
  ci_assert(fm->fm_local_addr_n >= 0);

#ifndef NDEBUG
  {
    int la_i;
    spin_lock_bh(&fm->fm_inner_lock);
    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
      struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
      ci_assert(lpa->lpa_filter.trs == NULL);
      ci_assert(ci_dllist_is_empty(&lpa->lpa_semi_wild_socks));
      ci_assert(ci_dllist_is_empty(&lpa->lpa_full_socks));
    }
    spin_unlock_bh(&fm->fm_inner_lock);
  }
#endif
  ci_free(lp->lp_addr);
  ci_free(lp);
}


static struct oof_local_port*
oof_local_port_alloc(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* lp;
  int la_i;

  ci_assert(fm->fm_local_addr_n >= 0);

  lp = CI_ALLOC_OBJ(struct oof_local_port);
  if( lp == NULL ) 
    return NULL;
  lp->lp_addr = CI_ALLOC_ARRAY(struct oof_local_port_addr, 
                               fm->fm_local_addr_max);
  if( lp->lp_addr == NULL ) {
    ci_free(lp);
    return NULL;
  }
  
  lp->lp_lport = lport;
  lp->lp_protocol = protocol;
  lp->lp_refs = 0;
  lp->lp_thcf = NULL;
  ci_dllist_init(&lp->lp_wild_socks);
  ci_dllist_init(&lp->lp_mcast_filters);
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
    oof_local_port_addr_init(&lp->lp_addr[la_i]);
  return lp;
}

/**********************************************************************
***********************************************************************
**********************************************************************/

void
oof_socket_ctor(struct oof_socket* skf)
{
  skf->sf_local_port = NULL;
  skf->sf_early_lp = NULL;
  skf->sf_flags = 0;
  oo_hw_filter_init(&skf->sf_full_match_filter);
  ci_dllist_init(&skf->sf_mcast_memberships);
}


void
oof_socket_dtor(struct oof_socket* skf)
{
  ci_assert(skf->sf_local_port == NULL);
  ci_assert(skf->sf_early_lp == NULL);
  ci_assert(skf->sf_full_match_filter.trs == NULL);
  ci_assert(ci_dllist_is_empty(&skf->sf_mcast_memberships));
}


static struct oof_socket*
oof_socket_at_head(ci_dllist* list)
{
  if( ci_dllist_is_empty(list) )
    return NULL;
  else
    return CI_CONTAINER(struct oof_socket, sf_lp_link, ci_dllist_head(list));
}


static struct oof_socket*
oof_socket_list_find_matching_stack(ci_dllist* list,
                                    struct tcp_helper_resource_s* stack)
{
  struct oof_socket* skf;
  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, list)
    if( oof_cb_socket_stack(skf) == stack )
      return skf;
  return NULL;
}


static int
oof_socket_is_first_in_stack(ci_dllist* list, struct oof_socket* skf,
                             struct tcp_helper_resource_s* stack)
{
  return skf == oof_socket_list_find_matching_stack(list, stack);
}


static int
oof_socket_is_first_in_same_stack(ci_dllist* list, struct oof_socket* skf)
{
  /* Return true if [skf] is the first socket in the list, considering only
   * sockets in the same stack as [skf].
   */
  return oof_socket_is_first_in_stack(list, skf, oof_cb_socket_stack(skf));
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static int
lp_hash(int protocol, int lport)
{
  return (protocol + lport) & OOF_LOCAL_PORT_TBL_MASK;
}


struct oof_manager*
oof_manager_alloc(unsigned local_addr_max, void* owner_private)
{
  struct oof_manager* fm;
  int hash;

  ci_assert(the_manager == NULL);

  fm = CI_ALLOC_OBJ(struct oof_manager);
  if( fm == NULL )
    return NULL;
  fm->fm_local_addrs = CI_ALLOC_ARRAY(struct oof_local_addr, local_addr_max);
  if( fm->fm_local_addrs == NULL ) {
    ci_free(fm);
    return NULL;
  }

  fm->fm_owner_private = owner_private;
  spin_lock_init(&fm->fm_inner_lock);
  mutex_init(&fm->fm_outer_lock);
  spin_lock_init(&fm->fm_cplane_updates_lock);
  fm->fm_local_addr_n = 0;
  fm->fm_local_addr_max = local_addr_max;
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    ci_dllist_init(&fm->fm_local_ports[hash]);
  ci_dllist_init(&fm->fm_mcast_laddr_socks);
  fm->fm_hwports_up = 0;
  fm->fm_hwports_up_new = 0;
  fm->fm_hwports_mcast_replicate_capable = 0;
  fm->fm_hwports_mcast_replicate_capable_new = 0;
  fm->fm_hwports_vlan_filters = 0;
  fm->fm_hwports_vlan_filters_new = 0;
  fm->fm_hwports_available = (unsigned) -1;
  fm->fm_hwports_available_new = (unsigned) -1;
  ci_dllist_init(&fm->fm_cplane_updates);
  the_manager = fm;
  return fm;
}


void
oof_manager_free(struct oof_manager* fm)
{
  int hash;
  ci_assert(ci_dllist_is_empty(&fm->fm_mcast_laddr_socks));
  ci_assert(fm == the_manager);
  the_manager = NULL;
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    ci_assert(ci_dllist_is_empty(&fm->fm_local_ports[hash]));
  mutex_destroy(&fm->fm_outer_lock);
  ci_free(fm->fm_local_addrs);
  ci_free(fm);
}


static void
oof_manager_queue_cplane_update(struct oof_manager* fm,
                                enum oof_cplane_update_type type,
                                unsigned addr, unsigned ifindex)
{
  struct oof_cplane_update* cu;

  cu = CI_ALLOC_OBJ(struct oof_cplane_update);
  if( cu == NULL ) {
    OO_DEBUG_ERR(ci_log("ERROR: out of mem; dropped cplane update type=%d "
                        "addr=%x ifindex=%u", type, addr, ifindex));
    return;
  }
  cu->cu_type = type;
  cu->cu_addr = addr;
  cu->cu_ifindex = ifindex;

  spin_lock_bh(&fm->fm_cplane_updates_lock);
  ci_dllist_put(&fm->fm_cplane_updates, &cu->cu_cplane_updates_link);
  spin_unlock_bh(&fm->fm_cplane_updates_lock);
}


static void
oof_manager_drain_cplane_updates(struct oof_manager* fm)
{
  struct oof_cplane_update* cu;
  ci_dllist list;

  spin_lock_bh(&fm->fm_cplane_updates_lock);
  ci_dllist_rehome(&list, &fm->fm_cplane_updates);
  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  while( ci_dllist_not_empty(&list) ) {
    cu = CI_CONTAINER(struct oof_cplane_update, cu_cplane_updates_link,
                      ci_dllist_get(&list));
    switch( cu->cu_type ) {
    case OOF_CU_ADDR_ADD:
      __oof_manager_addr_add(fm, cu->cu_addr, cu->cu_ifindex);
      break;
    case OOF_CU_ADDR_DEL:
      __oof_manager_addr_del(fm, cu->cu_addr, cu->cu_ifindex);
      break;
    case OOF_CU_UPDATE_FILTERS:
      __oof_mcast_update_filters(fm, cu->cu_ifindex);
      break;
    }
    CI_FREE_OBJ(cu);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static int
oof_manager_addr_find(struct oof_manager* fm, unsigned laddr)
{
  int la_i;

  ci_assert(fm->fm_local_addr_n >= 0);
  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
    if( fm->fm_local_addrs[la_i].la_laddr == laddr )
      return la_i;
  return -1;
}


static void
__oof_manager_addr_add(struct oof_manager* fm, unsigned laddr, unsigned ifindex)
{
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  struct oof_local_interface* li;
  struct oof_socket* skf;
  int hash, la_i, is_new, is_active;

  ci_assert(laddr != 0);
  ci_assert(! CI_IP_IS_MULTICAST(laddr));
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  /* Duplicate? */
  la_i = oof_manager_addr_find(fm, laddr);
  if( la_i >= 0 ) {
    la = &fm->fm_local_addrs[la_i];
    is_active = ci_dllist_not_empty(&la->la_active_ifs);
    CI_DLLIST_FOR_EACH2(struct oof_local_interface, li, li_active_ifs_link, 
                        &la->la_active_ifs)
      if( li->li_ifindex == ifindex )
        break;
    if( li == NULL ) {
      li = CI_ALLOC_OBJ(struct oof_local_interface);
      if( li == NULL ) {
        ERR_LOG("%s: ERROR: "IP_FMT" couldn't allocate space for ifindex %d",
                __FUNCTION__, IP_ARG(laddr), ifindex);
        return; 
      }
      li->li_ifindex = ifindex;
      ci_dllist_push(&la->la_active_ifs, &li->li_active_ifs_link);
    }
    if( is_active )
      /* This local address is already active, nothing further to do. */
      return;
    is_new = 0;
  }
  else {
    /* New entry in local address table. */
    la_i = oof_manager_addr_find(fm, 0);
    if( la_i < 0 ) {
      if( fm->fm_local_addr_n ==  fm->fm_local_addr_max ) {
        ci_log("%s: ERROR: "IP_FMT" overflows local address table",
               __FUNCTION__, IP_ARG(laddr));
        return;
      }
      la_i = fm->fm_local_addr_n;
      ++fm->fm_local_addr_n;
    }
    la = &fm->fm_local_addrs[la_i];
    la->la_laddr = laddr;
    la->la_sockets = 0;
    ci_dllist_init(&la->la_active_ifs);
    li = CI_ALLOC_OBJ(struct oof_local_interface);
    if( li == NULL ) {
      ci_log("%s: ERROR: "IP_FMT" couldn't allocate space for ifindex %d",
             __FUNCTION__, IP_ARG(laddr), ifindex);
      la->la_laddr = 0;
      return; 
    }
    li->li_ifindex = ifindex;
    ci_dllist_push(&la->la_active_ifs, &li->li_active_ifs_link);
    is_new = 1;
  }

  /* Add new filters, and set new filters for wildcard users. */

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      if( is_new )
        oof_local_port_addr_init(lpa);
      /* Add h/w filter for wild sockets. */
      skf = NULL;
      if( ci_dllist_not_empty(&lpa->lpa_semi_wild_socks) ) {
        ci_assert(!is_new);
        skf = oof_socket_at_head(&lpa->lpa_semi_wild_socks);
      }
      else if( ci_dllist_not_empty(&lp->lp_wild_socks) ) {
        skf = oof_socket_at_head(&lp->lp_wild_socks);
      }
      if( skf != NULL && ! oof_is_clustered(lp) )
        oof_hw_filter_set(fm, skf, &lpa->lpa_filter, oof_cb_socket_stack(skf),
                          lp->lp_protocol, 0, 0, laddr, lp->lp_lport,
                          fm->fm_hwports_available & fm->fm_hwports_up,
                          OOF_SRC_FLAGS_DEFAULT, 1);
      /* Add h/w filters for full-match sockets. */
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks) {
        ci_assert(!is_new);
        skf_stack = oof_cb_socket_stack(skf);
        if( lpa->lpa_filter.trs == skf_stack )
          ++lpa->lpa_n_full_sharers;
        else if( ! oof_is_clustered(lp) )
          oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter, skf_stack,
                            lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                            skf->sf_laddr, lp->lp_lport,
                            fm->fm_hwports_available & fm->fm_hwports_up,
                            OOF_SRC_FLAGS_DEFAULT, 1);
      }
      /* Add s/w filters for wild sockets. */
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lp->lp_wild_socks)
        if( oof_socket_is_first_in_same_stack(&lp->lp_wild_socks, skf) ) {
          int rc = oof_cb_sw_filter_insert(skf, laddr, lp->lp_lport, 0, 0,
                                           lp->lp_protocol, 0);
          if( rc != 0 ) {
            oof_sw_insert_fail(skf, __FUNCTION__, rc);
            /* Remove the corresponding hardware filters so that traffic
             * continues to reach the socket, albeit without acceleration.
             * BUT don't do that if existing TCP connections are using the
             * hardware filter.
             */
            if( lp->lp_protocol == IPPROTO_UDP ||
                lpa->lpa_n_full_sharers == 0 )
              oof_hw_filter_clear_wild(fm, lp, lpa, laddr);
          }
        }
      if( oof_is_clustered(lp) ) {
        int rc = oof_hw_thc_filter_set(fm, lp, la_i, laddr);
        if( rc != 0 )
          OO_DEBUG_ERR(ci_log("%s: ERROR: FILTER "TRIPLE_FMT" failed (%d)",
                              __FUNCTION__,
                              TRIPLE_ARGS(lp->lp_protocol, la->la_laddr,
                                          lp->lp_lport), rc));
      }
    }
}


void
oof_manager_addr_add(struct oof_manager* fm, unsigned laddr, unsigned ifindex)
{
  IPF_LOG("%s: addr="IP_FMT" ifindex=%d", __FUNCTION__, IP_ARG(laddr),ifindex);
  oof_manager_queue_cplane_update(fm, OOF_CU_ADDR_ADD, laddr, ifindex);
  oof_cb_defer_work(fm->fm_owner_private);
}


static void
oof_manager_addr_dead(struct oof_manager* fm, struct oof_local_addr* la)
{
  /* Disable/remove table entry.  We can't be bothered to deal with
   * shuffling table entries here, so just mark the entry as free.
   */
  ci_assert(la->la_sockets == 0);
  ci_assert( ci_dllist_is_empty(&la->la_active_ifs) );
  la->la_laddr = 0;
}


static void
__oof_manager_addr_del(struct oof_manager* fm, unsigned laddr, unsigned ifindex)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  struct oof_local_interface* li;
  struct oof_local_interface* li_tmp;
  struct oof_socket* skf;
  int hash, la_i;

  ci_assert(laddr != 0);
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  la_i = oof_manager_addr_find(fm, laddr);
  if( la_i < 0 )
    /* We never added this address, possibly due to overflow. */
    return;
  la = &fm->fm_local_addrs[la_i];

  if( ci_dllist_is_empty(&la->la_active_ifs) ) {
    /* Unused, so don't need do anything */
    return;
  }

  CI_DLLIST_FOR_EACH3(struct oof_local_interface, li, li_active_ifs_link, 
                      &la->la_active_ifs, li_tmp)
    if( li->li_ifindex == ifindex ) {
      ci_dllist_remove(&li->li_active_ifs_link);
      ci_free(li);
    }

  if( ci_dllist_not_empty(&la->la_active_ifs) ) {
    /* Not yet, unused, so don't do anything yet */
    return;
  }

  /* Address is disabled; remove filters. */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      /* Remove h/w filters that use [laddr]. */
      if( ! oof_is_clustered(lp) )
        oof_hw_filter_clear_wild(fm, lp, lpa, la->la_laddr);
      else
        oof_hw_filter_clear(fm, &lp->lp_thcf->tf_filters[la_i]);

      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks)
        oof_hw_filter_clear_full(fm, skf);
      lpa->lpa_n_full_sharers = 0;
      /* Remove s/w filters for wild sockets. */
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lp->lp_wild_socks)
        if( oof_socket_is_first_in_same_stack(&lp->lp_wild_socks, skf) )
          oof_cb_sw_filter_remove(skf, laddr, lp->lp_lport, 0, 0,
                                  lp->lp_protocol, 0);
    }

  if( la->la_sockets )
    return;

  /* Address is no longer in use by any socket. */
#ifndef NDEBUG
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      ci_assert(ci_dllist_is_empty(&lpa->lpa_semi_wild_socks));
      ci_assert(ci_dllist_is_empty(&lpa->lpa_full_socks));
      ci_assert(lpa->lpa_filter.trs == NULL);
    }
#endif

  oof_manager_addr_dead(fm, la);
}


void
oof_manager_addr_del(struct oof_manager* fm, unsigned laddr, unsigned ifindex)
{
  IPF_LOG("%s: addr="IP_FMT" ifindex=%d", __FUNCTION__, IP_ARG(laddr),ifindex);
  oof_manager_queue_cplane_update(fm, OOF_CU_ADDR_DEL, laddr, ifindex);
  oof_cb_defer_work(fm->fm_owner_private);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void
oof_manager_update_all_filters(struct oof_manager* fm)
{
  /* Invoked when physical interfaces come and go.  We add and remove
   * hardware filters to ensure that we don't receive packets through
   * interfaces that are down.  (At time of writing nothing in the net
   * driver or hardware stops packets being delivered when the interface is
   * administratively down).
   */
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf;
  struct oof_local_port* lp;
  struct oof_socket* skf;
  unsigned laddr, hwport_mask;
  int hash, la_i;

  /* Find all filters potentially affected by a change in the set of
   * hwports, and modify the set of ports filtered as needed.
   */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      /* Find and update unicast filters. */
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
        lpa = &lp->lp_addr[la_i];
        laddr = fm->fm_local_addrs[la_i].la_laddr;
        if( lpa->lpa_filter.trs != NULL )
          oof_hw_filter_update(fm, &lpa->lpa_filter, lpa->lpa_filter.trs,
                               lp->lp_protocol, 0, 0, laddr, lp->lp_lport,
                               OO_HW_VLAN_UNSPEC,
                               fm->fm_hwports_available & fm->fm_hwports_up,
                               OOF_SRC_FLAGS_DEFAULT);
        CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                            &lpa->lpa_full_socks)
          if( skf->sf_full_match_filter.trs != NULL )
            oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                                 skf->sf_full_match_filter.trs,
                                 lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                                 skf->sf_laddr, lp->lp_lport,
                                 OO_HW_VLAN_UNSPEC,
                                 fm->fm_hwports_available & fm->fm_hwports_up,
                                 OOF_SRC_FLAGS_DEFAULT);
      }
      /* Find and update multicast filters. */
      CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                          &lp->lp_mcast_filters)
        if( mf->mf_filter.trs != NULL ) {
          hwport_mask = oof_mcast_filter_installable_hwports(lp, mf);
          hwport_mask &= fm->fm_hwports_up & fm->fm_hwports_available;
          oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs,
                               lp->lp_protocol, 0, 0,
                               mf->mf_maddr, lp->lp_lport,
                               mf->mf_vlan_id, hwport_mask,
                               OOF_SRC_FLAGS_DEFAULT_MCAST);
        }
    }
}


void oof_hwport_up_down(int hwport, int up, int mcast_replicate_capable,
                        int vlan_filters)
{
  /* A physical interface has gone up or down. */

  struct oof_manager* fm = the_manager;

  spin_lock_bh(&fm->fm_cplane_updates_lock);
  if( up ) {
    if( mcast_replicate_capable )
      fm->fm_hwports_mcast_replicate_capable_new |= 1 << hwport;

    if( vlan_filters )
      fm->fm_hwports_vlan_filters_new |= 1 << hwport;

    fm->fm_hwports_up_new |= 1 << hwport;
  }
  else {
    fm->fm_hwports_up_new &= ~(1 << hwport);
    fm->fm_hwports_mcast_replicate_capable_new &= ~(1 << hwport);
    fm->fm_hwports_vlan_filters_new &= ~(1 << hwport);
  }
  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  oof_cb_defer_work(fm->fm_owner_private);
}


void oof_hwport_un_available(int hwport, int available)
{
  /* A physical interface is (or isn't) unavailable because it is a member
   * of an unacceleratable bond.  ie. We should(n't) install filters on
   * this hwport.
   */
  struct oof_manager* fm = the_manager;

  spin_lock_bh(&fm->fm_cplane_updates_lock);
  if( available )
    fm->fm_hwports_available_new |= 1 << hwport;
  else
    fm->fm_hwports_available_new &= ~(1 << hwport);
  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  oof_cb_defer_work(fm->fm_owner_private);
}


void oof_do_deferred_work(struct oof_manager* fm)
{
  /* Invoked in a non-atomic context (a workitem on Linux) with no locks
   * held.  We handle control plane changes here.  Reason for deferring to
   * a workitem is so we can grab locks in the right order.
   */
  IPF_LOG("%s:", __FUNCTION__);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  oof_manager_drain_cplane_updates(fm);

  fm->fm_hwports_mcast_replicate_capable =
    fm->fm_hwports_mcast_replicate_capable_new;
  fm->fm_hwports_vlan_filters = fm->fm_hwports_vlan_filters_new;

  if( fm->fm_hwports_up != fm->fm_hwports_up_new ) {
    IPF_LOG("%s: up=%x (mcast replicate=%x vlan filters=%x) down=%x",
            __FUNCTION__,
            fm->fm_hwports_up_new &~ fm->fm_hwports_up,
            fm->fm_hwports_mcast_replicate_capable & 
              fm->fm_hwports_up_new &~ fm->fm_hwports_up,
            fm->fm_hwports_vlan_filters & 
              fm->fm_hwports_up_new &~ fm->fm_hwports_up,
            ~fm->fm_hwports_up_new & fm->fm_hwports_up);
    fm->fm_hwports_up = fm->fm_hwports_up_new;
    oof_manager_update_all_filters(fm);
  }

  if( fm->fm_hwports_available != fm->fm_hwports_available_new ) {
    IPF_LOG("%s: available=%x unavailable=%x", __FUNCTION__,
            fm->fm_hwports_available_new &~ fm->fm_hwports_available,
            ~fm->fm_hwports_available_new & fm->fm_hwports_available);
    fm->fm_hwports_available = fm->fm_hwports_available_new;
    oof_manager_update_all_filters(fm);
  }

  BUG_ON(~fm->fm_hwports_up & fm->fm_hwports_mcast_replicate_capable);
  BUG_ON(~fm->fm_hwports_up & fm->fm_hwports_vlan_filters);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static struct oof_local_port*
oof_local_port_find(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* lp;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                      &fm->fm_local_ports[lp_hash(protocol, lport)])
    if( lp->lp_protocol == protocol && lp->lp_lport == lport )
      return lp;
  return NULL;
}


static struct oof_local_port*
oof_local_port_get(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* new_lp = NULL;
  struct oof_local_port* lp;

  while( 1 ) {
    spin_lock_bh(&fm->fm_inner_lock);
    lp = oof_local_port_find(fm, protocol, lport);
    if( lp == NULL && new_lp ) {
      lp = new_lp;
      ci_dllist_push_tail(&fm->fm_local_ports[lp_hash(protocol, lport)],
                          &lp->lp_manager_link);
      new_lp = NULL;
    }
    if( lp != NULL )
      ++lp->lp_refs;
    spin_unlock_bh(&fm->fm_inner_lock);

    if( lp != NULL )
      break;

    new_lp = oof_local_port_alloc(fm, protocol, lport);
    if( new_lp == NULL ) {
      ERR_LOG("%s: ERROR: out of memory", __FUNCTION__);
      return NULL;
    }
  }

  if( new_lp != NULL )
    oof_local_port_free(fm, new_lp);

  return lp;
}


static struct oof_socket*
oof_wild_socket(struct oof_local_port* lp, struct oof_local_port_addr* lpa)
{
  struct oof_socket* skf;
  skf = oof_socket_at_head(&lpa->lpa_semi_wild_socks);
  if( skf == NULL )
    skf = oof_socket_at_head(&lp->lp_wild_socks);
  return skf;
}


static struct oof_socket*
oof_wild_socket_matching_stack(struct oof_local_port* lp,
                               struct oof_local_port_addr* lpa,
                               struct tcp_helper_resource_s* stack)
{
  struct oof_socket* skf;
  skf = oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks, stack);
  if( skf == NULL )
    skf = oof_socket_list_find_matching_stack(&lp->lp_wild_socks, stack);
  return skf;
}


static void
oof_full_socks_del_hw_filters(struct oof_manager* fm,
                              struct oof_local_port* lp,
                              struct oof_local_port_addr* lpa)
{
  struct tcp_helper_resource_s* stack = lpa->lpa_filter.trs;
  struct oof_socket* skf;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                      &lpa->lpa_full_socks) {
    if( oof_cb_socket_stack(skf) != stack )
      continue;
    if( skf->sf_full_match_filter.trs == NULL )
      continue;
    oof_hw_filter_clear_full(fm, skf);
    ++lpa->lpa_n_full_sharers;
  }
}


static int
oof_full_socks_add_hw_filters(struct oof_manager* fm,
                              struct oof_local_port* lp,
                              struct oof_local_port_addr* lpa)
{
  /* For each full-match socket that is relying on the filter associated
   * with [lpa], try to insert a full-match filter.  Called when the filter
   * associated with [lpa] is about to be removed or pointed at a different
   * stack.
   */
  struct tcp_helper_resource_s* filter_stack = lpa->lpa_filter.trs;
  struct oof_socket* skf_tmp;
  struct oof_socket* skf;
  int rc = 0;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( filter_stack == NULL ) {
    ERR_LOG("%s: ERROR: %s:%d has no filter", __FUNCTION__,
            FMT_PROTOCOL(lp->lp_protocol), FMT_PORT(lp->lp_lport));
    return -EINVAL;
  }

  CI_DLLIST_FOR_EACH3(struct oof_socket, skf, sf_lp_link,
                      &lpa->lpa_full_socks, skf_tmp) {
    if( oof_cb_socket_stack(skf) != filter_stack )
      continue;
    if( skf->sf_full_match_filter.trs != NULL )
      continue;
    rc = oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter, filter_stack,
                           lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                           skf->sf_laddr, lp->lp_lport,
                           fm->fm_hwports_available & fm->fm_hwports_up,
                           OOF_SRC_FLAGS_DEFAULT, 1);
    if( rc < 0 ) {
      oof_full_socks_del_hw_filters(fm, lp, lpa);
      break;
    }
    oof_cb_callback_set_filter(skf);
    ci_assert(lpa->lpa_n_full_sharers > 0);
    --lpa->lpa_n_full_sharers;
  }

  return rc;
}


/* Reasons why fixup_wild() is called. */
enum fixup_wild_why {
  fuw_del_full,
  fuw_del_wild,
  fuw_add_wild,
  fuw_udp_connect,
};


static void
oof_local_port_addr_fixup_wild(struct oof_manager* fm,
                               struct oof_local_port* lp,
                               struct oof_local_port_addr* lpa,
                               unsigned laddr, enum fixup_wild_why why)
{
  struct tcp_helper_resource_s* skf_stack;
  struct oof_socket* skf;
  int rc, skf_has_filter;
  int unshare_full_match;
  int thresh;

  /* Decide whether we need to insert full-match filters for sockets that
   * are currently sharing a wild filter.
   */
  skf = oof_wild_socket(lp, lpa);
  unshare_full_match = lpa->lpa_n_full_sharers > 0;
  if( skf == NULL ) {
    thresh = oof_shared_keep_thresh;
    skf_stack = NULL;
  }
  else {
    thresh = oof_shared_steal_thresh;
    skf_stack = oof_cb_socket_stack(skf);
    if( lpa->lpa_filter.trs == skf_stack )
      /* The existing filter points at the correct stack, so no need to add
       * filters for full-match sockets in that stack.
       */
      unshare_full_match = 0;
  }
  if( unshare_full_match && lpa->lpa_n_full_sharers > thresh ) {
    /* There are lots of sockets still using this wild filter.  We choose
     * not to transfer them all to their own full-match filters, as that
     * would consume lots of h/w resources.  This new socket will have to
     * wait until the filter is freed up.
     *
     * This is not really an error, as user can change
     * oof_shared_[keep|steal]_thresh if they don't like it.  We emit a log
     * message by default (when wild filter is added or removed), as
     * otherwise it can be tricky to see what is going on.
     */
    if( (oo_debug_bits & __OO_DEBUGIPF__) ||
        ((oo_debug_bits & __OO_DEBUGERR__) && why != fuw_del_full) ) {
      ci_log("%s: "TRIPLE_FMT" shared by %d socks in stack %d (thresh=%d "
             "reason=%d)", __FUNCTION__,
             TRIPLE_ARGS(lp->lp_protocol, laddr, lp->lp_lport),
             lpa->lpa_n_full_sharers, oof_cb_stack_id(lpa->lpa_filter.trs),
             thresh, (int) why);
      if( skf != NULL )
        ci_log("%s: WARNING: "SK_FMT" "SK_WILD_ADDR_FMT" will not yet receive "
               "traffic", __FUNCTION__, SK_PRI_ARGS(skf),
               SK_WILD_ADDR_ARGS(skf));
    }
    unshare_full_match = 0;
  }

  if( unshare_full_match ) {
    rc = oof_full_socks_add_hw_filters(fm, lp, lpa);
    if( rc < 0 ) {
      if( (oo_debug_bits & __OO_DEBUGIPF__) ||
          ((oo_debug_bits & __OO_DEBUGERR__) && why != fuw_del_full) ) {
        ci_log("%s: %s"TRIPLE_FMT" unable to free wild filter (%d sharers "
               "in stack %d, rc=%d reason=%d)", __FUNCTION__,
               skf == NULL ? "":"ERROR: ",
               TRIPLE_ARGS(lp->lp_protocol, laddr, lp->lp_lport),
               lpa->lpa_n_full_sharers, oof_cb_stack_id(lpa->lpa_filter.trs),
               rc, (int) why);
        if( skf != NULL )
          ci_log("%s: WARNING: "SK_FMT" "SK_WILD_ADDR_FMT" will not yet "
                 "receive traffic", __FUNCTION__, SK_PRI_ARGS(skf),
                 SK_WILD_ADDR_ARGS(skf));
      }
    }
  }

  if( skf != NULL ) {
    skf_has_filter = 0;
    if( lpa->lpa_filter.trs == NULL ) {
      ci_assert(lpa->lpa_n_full_sharers == 0);
      rc = oof_hw_filter_set(fm, skf, &lpa->lpa_filter, skf_stack,
                             lp->lp_protocol, 0, 0, laddr, lp->lp_lport,
                             fm->fm_hwports_available & fm->fm_hwports_up,
                             OOF_SRC_FLAGS_DEFAULT, 1);
      skf_has_filter = rc == 0;
    }
    else if( lpa->lpa_filter.trs != skf_stack && lpa->lpa_n_full_sharers==0 ) {
      oof_hw_filter_move(fm, skf, lp, lpa, laddr,
                         fm->fm_hwports_available & fm->fm_hwports_up);
      ci_assert(lpa->lpa_filter.trs == skf_stack);
      skf_has_filter = 1;
    }
    if( skf_has_filter )
      oof_full_socks_del_hw_filters(fm, lp, lpa);
  }
  else if( lpa->lpa_n_full_sharers == 0 ) {
    oof_hw_filter_clear_wild(fm, lp, lpa, laddr);
  }
}


static void
oof_local_port_fixup_wild(struct oof_manager* fm, struct oof_local_port* lp,
                          enum fixup_wild_why why)
{
  struct oof_local_addr* la;
  int la_i;
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    if( ci_dllist_not_empty(&la->la_active_ifs) )
      oof_local_port_addr_fixup_wild(fm, lp, &lp->lp_addr[la_i],
                                     la->la_laddr, why);
  }
}


/* Fixme: most callers of oof_cb_sw_filter_insert and
 * oof_socket_add_full_sw do not check rc. */
static int
oof_socket_add_full_sw(struct oof_socket* skf)
{
  return oof_cb_sw_filter_insert(skf, skf->sf_laddr,
                                 skf->sf_local_port->lp_lport,
                                 skf->sf_raddr, skf->sf_rport,
                                 skf->sf_local_port->lp_protocol, 1);
}


static void
oof_socket_del_full_sw(struct oof_socket* skf)
{
  struct oof_local_port* lp = skf->sf_local_port;
  oof_cb_sw_filter_remove(skf, skf->sf_laddr, lp->lp_lport,
                          skf->sf_raddr, skf->sf_rport, lp->lp_protocol, 1);
}


static void
oof_socket_del_wild_sw(struct oof_socket* skf, unsigned laddr)
{
  oof_cb_sw_filter_remove(skf, laddr, skf->sf_local_port->lp_lport,
                          0, 0, skf->sf_local_port->lp_protocol, 1);
}


static void
oof_socket_del_full(struct oof_manager* fm, struct oof_socket* skf,
                    struct oof_local_port_addr* lpa)
{
  ci_dllist_remove(&skf->sf_lp_link);
  oof_socket_del_full_sw(skf);
  if( skf->sf_full_match_filter.trs != NULL ) {
    oof_hw_filter_clear_full(fm, skf);
  }
  else if( oof_cb_socket_stack(skf) == lpa->lpa_filter.trs ) {
    ci_assert(lpa->lpa_n_full_sharers > 0);
    --lpa->lpa_n_full_sharers;
    oof_local_port_addr_fixup_wild(fm, skf->sf_local_port, lpa, skf->sf_laddr,
                                   fuw_del_full);
  }
}


static int
oof_socket_add_full_hw(struct oof_manager* fm, struct oof_socket* skf,
                       struct oof_local_port_addr* lpa)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  int rc;
  if( lpa->lpa_filter.trs != skf_stack ) {
    struct oof_local_port* lp = skf->sf_local_port;
    rc = oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter, skf_stack,
                           lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                           skf->sf_laddr, lp->lp_lport,
                           fm->fm_hwports_available & fm->fm_hwports_up,
                           OOF_SRC_FLAGS_DEFAULT, 1);
    if( rc < 0 ) {
      /* I think there are the following ways this can fail:
       *
       * - Out of memory (ENOMEM).
       * - Out of space in h/w filter table (EBUSY).
       * - Clash in h/w filter table (EEXIST).
       *
       * Is this where we get to if two sockets try to bind/connect to the
       * same 5-tuple?
       *
       * ?? TODO: Handle the various errors elegantly.
       */
      if( rc == -EBUSY )
        return rc;
      else
        return -EADDRNOTAVAIL;
    }
  }
  else {
    /* Share the existing wildcard filter for h/w demux. */
    ++lpa->lpa_n_full_sharers;
    IPF_LOG(FSK_FMT "SHARE "SK_ADDR_FMT, FSK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
  }
  return 0;
}


static int
__oof_socket_add_wild(struct oof_manager* fm, struct oof_socket* skf,
                      struct oof_local_port_addr* lpa, unsigned laddr)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_socket* other_skf;
  int rc;

  other_skf = oof_wild_socket_matching_stack(lp, lpa, skf_stack);
  if( other_skf != NULL )
    oof_cb_sw_filter_remove(other_skf, laddr, lp->lp_lport,
                            0, 0, lp->lp_protocol, 1);
  rc = oof_cb_sw_filter_insert(skf, laddr, lp->lp_lport, 0, 0,
                               lp->lp_protocol, 1);
  if( rc != 0 )
    return rc;

  if( ! oof_is_clustered(lp) ) {
    if( lpa->lpa_filter.trs == NULL ) {
      rc = oof_hw_filter_set(fm, skf, &lpa->lpa_filter, skf_stack,
                             lp->lp_protocol, 0, 0, laddr, lp->lp_lport,
                             fm->fm_hwports_available & fm->fm_hwports_up,
                             OOF_SRC_FLAGS_DEFAULT, 1);
      if( rc != 0 )
        oof_cb_sw_filter_remove(skf, laddr, lp->lp_lport, 0, 0,
                                lp->lp_protocol, 1);
      return rc;
    }
    else if( lpa->lpa_filter.trs != skf_stack ) {
      /* H/w filter already exists but points to a different stack.  This is
       * fixed if necessary in oof_local_port_addr_fixup_wild().
       */
      OO_DEBUG_IPF(other_skf = oof_wild_socket(lp, lpa);
                   if( other_skf != NULL )
                     ci_log(FSK_FMT "STEAL "TRIPLE_FMT" from "SK_FMT,
                            FSK_PRI_ARGS(skf),
                            TRIPLE_ARGS(lp->lp_protocol, laddr, lp->lp_lport),
                            SK_PRI_ARGS(other_skf)));
    }
  }
  return 0;
}


static int
oof_socket_steal_or_add_wild(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int la_i;
  int has_ok = 0;
  int has_fail = 0;
  int rc, saved_rc = 0;

  ci_assert(skf->sf_raddr == 0);
  ci_assert(skf->sf_laddr == 0);

  skf_stack = oof_cb_socket_stack(skf);

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    if( ci_dllist_is_empty(&la->la_active_ifs) )
      /* Entry invalid or address disabled. */
      continue;
    lpa = &lp->lp_addr[la_i];
    if( oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks,
                                            skf_stack) == NULL ) {
      rc = __oof_socket_add_wild(fm, skf, lpa, la->la_laddr);
      if( rc == 0 && ! has_ok )
        has_ok = 1;
      else if( rc != 0 && ! has_fail ) {
        has_fail = 1;
        saved_rc = rc;
      }
    }
  }

  if( ! has_fail )
    return 0;
  else if( has_ok )
    return -EFILTERSSOME;
  else
    return saved_rc;
}


static int
__oof_socket_add(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int rc = 0, la_i;

  if( skf->sf_laddr ) {
    la_i = oof_manager_addr_find(fm, skf->sf_laddr);
    if( la_i < 0 ) {
      if( CI_IP_IS_MULTICAST(skf->sf_laddr) ) {
        /* Local address is bound to multicast address.  We don't insert
         * any filters in this case.  Socket will get accelerated traffic
         * iff it does IP_ADD_MEMBERSHIP.  (NB. In practice this cannot be
         * a full-match add, as that goes via oof_udp_connect()).
         */
        IPF_LOG(FSK_FMT IP_FMT" multicast -- not filtered",
                FSK_PRI_ARGS(skf), IP_ARG(skf->sf_laddr));
        ci_dllist_push(&fm->fm_mcast_laddr_socks, &skf->sf_lp_link);
        return 0;
      }
      ERR_LOG(FSK_FMT "ERROR: laddr="IP_FMT" not local",
              FSK_PRI_ARGS(skf), IP_ARG(skf->sf_laddr));
      return -EINVAL;
    }
    lpa = &lp->lp_addr[la_i];
    la = &fm->fm_local_addrs[la_i];
    if( skf->sf_raddr ) {
      if( oof_is_clustered(lp) ) {
        ci_log("%s: ERROR: Full match filter with reuseport set", __FUNCTION__);
        return -EINVAL;
      }
      if( (rc = oof_socket_add_full_sw(skf)) != 0 )
        return rc;
      if( (rc = oof_socket_add_full_hw(fm, skf, lpa)) != 0 ) {
        oof_socket_del_full_sw(skf);
        return rc;
      }
      ci_dllist_push(&lpa->lpa_full_socks, &skf->sf_lp_link);
    }
    else {
      rc = __oof_socket_add_wild(fm, skf, lpa, skf->sf_laddr);
      if( rc != 0 )
        return rc;
      ci_dllist_push(&lpa->lpa_semi_wild_socks, &skf->sf_lp_link);
      if( ! oof_is_clustered(lp) )
        oof_local_port_addr_fixup_wild(fm, lp, lpa, skf->sf_laddr,
                                       fuw_add_wild);
    }
    ++la->la_sockets;
  }
  else {
    rc = oof_socket_steal_or_add_wild(fm, skf);
    if( rc != 0 && rc != -EFILTERSSOME )
      return rc;
    ci_dllist_push(&lp->lp_wild_socks, &skf->sf_lp_link);
    if( ! oof_is_clustered(lp) )
      oof_local_port_fixup_wild(fm, lp, fuw_add_wild);
  }

  return rc;
}


/* Returns -ve error if oof_local_port exists but no cluster points to it.
 * Returns 0 if oof_local_port does not exist.
 * Returns 1 and sets thc_out if oof_local_port exists and contains a thc.
 */
int oof_local_port_thc_search(struct oof_manager* fm, int protocol, int lport,
                              struct tcp_helper_cluster_s** thc_out)
{
  struct oof_local_port* lp;
  int rc;
  spin_lock_bh(&fm->fm_inner_lock);
  lp = oof_local_port_find(fm, protocol, lport);
  if( lp == NULL ) {
    rc = 0;
  }
  else if( lp->lp_thcf == NULL ) {
    rc = -EADDRINUSE;
  }
  else {
    rc = 1;
    *thc_out = lp->lp_thcf->tf_thc;
  }
  spin_unlock_bh(&fm->fm_inner_lock);
  return rc;
}


/* Add a thc reference to a oof_local_port.  If the oof_local_port
 * does not exist, it is allocated.
 *
 * As we do not do multicast clustering, this function should not be
 * called for multicast addresses. */
int oof_socket_cluster_add(struct oof_manager* fm,
                           struct tcp_helper_cluster_s* thc, int protocol,
                           int lport)
{
  int rc;
  struct oof_local_port* lp = oof_local_port_get(fm, protocol, lport);
  if( lp == NULL ) {
    ERR_LOG("%s: ERROR: out of memory", __FUNCTION__);
    return -ENOMEM;
  }

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);
  if( oof_is_clustered(lp) ) {
    if( lp->lp_thcf->tf_thc != thc ) {
      rc = -EINVAL;
      goto fail;
    }
    /* A reference for this cluster already exists so drop the one
     * oof_local_port_get() took. */
    --lp->lp_refs;
    oof_thc_add_ref(lp);
  }
  else {
    if( (rc = oof_thc_alloc(fm, thc, lp)) != 0 ) {
      goto fail;
    }
  }
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return 0;

 fail:
  if( --lp->lp_refs == 0 )
    ci_dllist_remove(&lp->lp_manager_link);
  else
    lp = NULL;
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( lp != NULL )
    oof_local_port_free(fm, lp);
  return rc;
}


/* This funciton undos what is done in oof_socket_cluster_add().  Only
 * useful when the caller of oof_socket_cluster_add() wants to undo
 * after calling it. */
void oof_socket_cluster_del(struct oof_manager* fm,
                            struct tcp_helper_cluster_s* thc, int protocol,
                            int lport)
{
  struct oof_local_port* lp = oof_local_port_get(fm, protocol, lport);
  if( lp == NULL )
    return;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);
  ci_assert(oof_is_clustered(lp));
  /* Drop reference taken by oof_local_port_get() above. */
  --lp->lp_refs;
  if( --lp->lp_thcf->tf_ref == 0 ) {
    ci_assert(lp->lp_refs == 1);
    --lp->lp_refs;
    ci_dllist_remove(&lp->lp_manager_link);
  }
  else {
    lp = NULL;
  }
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

  if( lp != NULL ) {
    oof_thc_do_del(lp->lp_thcf);
    oof_local_port_free(fm, lp);
  }
}


/* This function should be called on a clustered socket once it's been moved
 * into a clustered stack in order to set the clustering per-socket filter
 * state. */
void oof_socket_set_early_lp(struct oof_manager* fm, struct oof_socket* skf,
                             int protocol, int lport)
{
  struct oof_local_port* lp = oof_local_port_get(fm, protocol, lport);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  ci_assert(oof_is_clustered(lp));
  ci_assert(skf->sf_local_port == NULL);
  skf->sf_early_lp = lp;

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


int
oof_socket_add(struct oof_manager* fm, struct oof_socket* skf,
               int protocol, unsigned laddr, int lport,
               unsigned raddr, int rport)
{
  struct oof_local_port* lp;
  struct tcp_helper_resource_s* skf_stack;
  struct tcp_helper_cluster_s* skf_thc;
  int rc;
  int remove_thc_filters_on_error = 0;

  IPF_LOG(FSK_FMT QUIN_FMT, FSK_PRI_ARGS(skf),
          QUIN_ARGS(protocol, laddr, lport, raddr, rport));

  lp = (skf->sf_early_lp != NULL) ? skf->sf_early_lp :
                                    oof_local_port_get(fm, protocol, lport);
  if( lp == NULL ) {
    ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
    return -ENOMEM;
  }

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  skf_stack = oof_cb_socket_stack(skf);
  skf_thc   = oof_cb_stack_thc(skf_stack);

  rc = -EINVAL;
  if( skf->sf_local_port != NULL ) {
    ERR_LOG(FSK_FMT "ERROR: already bound to "SK_ADDR_FMT,
            FSK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
    goto fail1;
  }
  if( lport == 0 || ((raddr || rport) && ! (raddr && rport)) ) {
    ERR_LOG(FSK_FMT "ERROR: bad "IPPORT_FMT" "IPPORT_FMT,
            FSK_PRI_ARGS(skf), IPPORT_ARG(laddr, lport),
            IPPORT_ARG(raddr, rport));
    goto fail1;
  }

  if( skf_thc != NULL ) {
    /* If the stack is clustered, we better have already associated
     * the lp with a cluster.
     */
    if( ! oof_is_clustered(lp) ) {
      ERR_LOG(FSK_FMT "ERROR: Clustered socket referring to non clustered"
              " oof_local_port.", FSK_PRI_ARGS(skf));
      goto fail1;
    }
    /* We do not cluster on multicast addresses. */
    if( ! CI_IP_IS_MULTICAST(laddr) ) {
      rc = oof_thc_install_filters(fm, lp, laddr);
      if( rc < 0 )
        goto fail1;
      remove_thc_filters_on_error = rc;
    }
  }
  else {
    /* Else the associated lport should not be referring to a oof_thc.
     */
    if( oof_is_clustered(lp) )
      goto fail1;
  }

  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  skf->sf_local_port = lp;
  rc = __oof_socket_add(fm, skf);
  if( rc < 0 && rc != -EFILTERSSOME ) {
    skf->sf_local_port = NULL;
    goto fail0;
  }
  skf->sf_early_lp = NULL;
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( ci_dllist_not_empty(&skf->sf_mcast_memberships) )
    if( oof_socket_mcast_install(fm, skf) != 0 )
      return -EFILTERSSOME;
  return rc;

 fail0:
  if( remove_thc_filters_on_error == 1 )
    oof_thc_remove_filters(fm, lp);
 fail1:
  /* If we have an sf_early_lp, we didn't call oof_local_port_get and so didn't
   * take out an additional reference. */
  if( lp == skf->sf_early_lp || --lp->lp_refs > 0 )
    lp = NULL;
  else
    ci_dllist_remove(&lp->lp_manager_link);
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( lp != NULL )
    oof_local_port_free(fm, lp);
  return rc;
}


/* This function is called to update the remote address and port of a socket.
 * This is needed for sockets which are accepted from the endpoint cache at
 * user level.  These retain the original oof_socket, which should be sharing
 * a wild filter with the listener they were cached on.  However, the raddr
 * and rport on subsequent uses will generally not match that used when the
 * socket was originally added.  This doesn't cause a problem as long as the
 * socket isn't using its own hw filter, but it must be updated before the
 * listening socket's filter is removed.
 */
void
oof_socket_update_sharer_details(struct oof_manager* fm, struct oof_socket* skf,
                                 unsigned raddr, int rport)
{
  /* This must be called while the socket is sharing a wild match filter,
   * otherwise it implies we've been using a hw filter with the wrong details.
   */
#ifndef NDEBUG
  ci_assert(skf->sf_full_match_filter.trs == NULL);
#else
  if( skf->sf_full_match_filter.trs ) {
    ci_log("%s: called for socket with full-match filter", __func__);
  }
#endif

  /* We are not modifying any hw filters, or lists here, just the state that is
   * used to determine them, so just take the inner lock, which allows us to be 
   * called from atomic context.
   */
  spin_lock_bh(&fm->fm_inner_lock);

  skf->sf_raddr = raddr;
  skf->sf_rport = rport;

  spin_unlock_bh(&fm->fm_inner_lock);
}



static int
__oof_socket_share(struct oof_manager* fm, struct oof_socket* skf,
                   struct oof_socket* listen_skf)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  int rc, la_i;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(skf->sf_early_lp == NULL);

  if( skf->sf_local_port != NULL || ! skf->sf_laddr || ! skf->sf_raddr )
    return -EINVAL;
  if( (lp = listen_skf->sf_local_port) == NULL )
    return -EINVAL;
  if( (la_i = oof_manager_addr_find(fm, skf->sf_laddr)) < 0 ) {
    ERR_LOG(FSK_FMT "ERROR: laddr="IP_FMT" not local",
            FSK_PRI_ARGS(skf), IP_ARG(skf->sf_laddr));
    return -EINVAL;
  }

  lpa = &lp->lp_addr[la_i];
  la = &fm->fm_local_addrs[la_i];
  skf->sf_local_port = lp;
  if( (rc = oof_socket_add_full_sw(skf)) != 0 ) {
    skf->sf_local_port = NULL;
    return rc;
  }
  ++lp->lp_refs;
  ci_dllist_push(&lpa->lpa_full_socks, &skf->sf_lp_link);
  ++la->la_sockets;
  ++lpa->lpa_n_full_sharers;
  return 0;
}


int
oof_socket_share(struct oof_manager* fm, struct oof_socket* skf,
                 struct oof_socket* listen_skf, unsigned laddr,
                 unsigned raddr, int rport)
{
  /* This entry point is used when promoting a syn-recv to a new passively
   * opened socket.  oof_socket_add() actually handles that case just fine,
   * but we need a separate entry point because oof_socket_add() cannot be
   * called in atomic context.
   *
   * Note: This is the only entry-point that doesn't grab [fm_outer_lock],
   * which is because it is invoked in atomic context.
   *
   * It is essential that code reached from here does not insert or remove
   * hardware filters, or free any resources, or remove anything items from
   * lists.
   */
  int rc;

  spin_lock_bh(&fm->fm_inner_lock);

  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  if( oof_is_clustered(listen_skf->sf_local_port) )
    oof_thc_add_ref(listen_skf->sf_local_port);
  rc = __oof_socket_share(fm, skf, listen_skf);
  if( rc != 0 && oof_is_clustered(listen_skf->sf_local_port) )
    /* Having just added the reference above 
     * and keeping fm lock since then, we are guaranteed that
     * this will simply decrement the count and nothing more. */
    ci_verify(oof_thc_release(fm, listen_skf->sf_local_port) == 0);

  spin_unlock_bh(&fm->fm_inner_lock);
  return rc;
}


static void
__oof_socket_del_wild(struct oof_socket* skf,
                      struct tcp_helper_resource_s* skf_stack,
                      struct oof_local_port_addr* lpa, unsigned laddr)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_socket* other_skf;

  oof_socket_del_wild_sw(skf, laddr);
  other_skf = oof_wild_socket_matching_stack(lp, lpa, skf_stack);
  if( other_skf != NULL ) {
    int rc = oof_cb_sw_filter_insert(other_skf, laddr, lp->lp_lport,
                                     0, 0, lp->lp_protocol, 1);
    if( rc != 0 )
      oof_sw_insert_fail(other_skf, __FUNCTION__, rc);
  }
}


static void
oof_socket_del_semi_wild(struct oof_manager* fm, struct oof_socket* skf,
                         struct oof_local_port_addr* lpa)
{
  struct tcp_helper_resource_s* skf_stack;
  int hidden;

  skf_stack = oof_cb_socket_stack(skf);
  hidden = ! oof_socket_is_first_in_stack(&lpa->lpa_semi_wild_socks,
                                          skf, skf_stack);
  ci_dllist_remove(&skf->sf_lp_link);
  if( ! hidden ) {
    __oof_socket_del_wild(skf, skf_stack, lpa, skf->sf_laddr);
    if( ! oof_is_clustered(skf->sf_local_port) )
      oof_local_port_addr_fixup_wild(fm, skf->sf_local_port, lpa,
                                     skf->sf_laddr, fuw_del_wild);
  }
}


static void
oof_socket_del_wild(struct oof_manager* fm, struct oof_socket* skf)
{
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int hidden, la_i;

  skf_stack = oof_cb_socket_stack(skf);
  hidden = ! oof_socket_is_first_in_stack(&lp->lp_wild_socks, skf, skf_stack);
  ci_dllist_remove(&skf->sf_lp_link);
  if( hidden )
    return;

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    if(  ci_dllist_is_empty(&la->la_active_ifs) )
      /* Entry invalid or address disabled. */
      continue;
    lpa = &lp->lp_addr[la_i];
    if( oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks,
                                            skf_stack) == NULL )
      __oof_socket_del_wild(skf, skf_stack, lpa, la->la_laddr);
  }
}


void
oof_socket_del(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_local_port* lp;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  ci_dllist mcast_filters;
  int la_i;
  struct oof_thc* thcf = NULL;

  ci_dllist_init(&mcast_filters);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  ci_assert(skf->sf_local_port == NULL || skf->sf_early_lp == NULL);

  if( (lp = skf->sf_local_port) != NULL ) {
    IPF_LOG(FSK_FMT QUIN_FMT, FSK_PRI_ARGS(skf),
            QUIN_ARGS(lp->lp_protocol, skf->sf_laddr, lp->lp_lport,
                      skf->sf_raddr, skf->sf_rport));

    oof_socket_mcast_remove(fm, skf, &mcast_filters);

    if( CI_IP_IS_MULTICAST(skf->sf_laddr) ) {
      ci_dllist_remove(&skf->sf_lp_link);
      if( skf->sf_raddr != 0 ) {
        /* Undo path for oof_udp_connect_mcast_laddr().  It's possible we
         * don't actually have either of these filters, if we haven't joined
         * relevant groups, or don't have hwports that need a full match
         * filter.  However, it's safe to remove these even if we don't have
         * them.
         *
         * Any wild match filters will have been removed already, via the
         * standard path.
         */
        oof_socket_del_full_sw(skf);
        skf->sf_flags &= ~OOF_SOCKET_MCAST_FULL_SW_FILTER;
        oof_hw_filter_clear_full(fm, skf);
      }
    }
    else if( skf->sf_laddr ) {
      la_i = oof_manager_addr_find(fm, skf->sf_laddr);
      ci_assert(la_i >= 0 && la_i < fm->fm_local_addr_n);
      lpa = &lp->lp_addr[la_i];
      la = &fm->fm_local_addrs[la_i];
      if( skf->sf_raddr )
        oof_socket_del_full(fm, skf, lpa);
      else
        oof_socket_del_semi_wild(fm, skf, lpa);
      ci_assert(la->la_sockets > 0);
      if( --la->la_sockets == 0 &&  ci_dllist_is_empty(&la->la_active_ifs) )
        oof_manager_addr_dead(fm, la);
    }
    else {
      oof_socket_del_wild(fm, skf);
      if( ! oof_is_clustered(lp) )
        oof_local_port_fixup_wild(fm, skf->sf_local_port, fuw_del_wild);
    }

    skf->sf_local_port = NULL;
  }
  else {
    lp = skf->sf_early_lp;
    skf->sf_early_lp = NULL;
  }

  /* The remainder of the cleanup must be performed for a local port even if
   * filters haven't been installed yet. */
  if( lp != NULL ) {
    if( oof_is_clustered(lp) )
      if( oof_thc_release(fm, lp) )
        thcf = lp->lp_thcf;

    ci_assert(lp->lp_refs > 0);
    if( --lp->lp_refs == 0 )
      ci_dllist_remove(&lp->lp_manager_link);
    else
      lp = NULL;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

 if( thcf != NULL )
      oof_thc_do_del(thcf);
  if( lp != NULL )
    oof_local_port_free(fm, lp);
  oof_mcast_filter_list_free(&mcast_filters);
}


int
oof_socket_del_sw(struct oof_manager* fm, struct oof_socket* skf)
{
  /* This is a subset of oof_socket_del() that can be invoked in atomic
   * context.  It removes all of the socket's software filter entries.
   *
   * If the socket had only sw filters, then this function will return
   * 0 and no other operations are required.  If the socket has hw
   * filters, then the function returns 1.  In which case, a call to
   * oof_socket_del() a little later (in non-atomic context) is
   * required.  That will try to remove the software filters again,
   * which is not maximally efficient, but is otherwise harmless.
   */
  struct oof_local_port* lp;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int la_i, rc = 1;

  spin_lock_bh(&fm->fm_inner_lock);

  if( (lp = skf->sf_local_port) != NULL ) {
    IPF_LOG(FSK_FMT QUIN_FMT, FSK_PRI_ARGS(skf),
            QUIN_ARGS(lp->lp_protocol, skf->sf_laddr, lp->lp_lport,
                      skf->sf_raddr, skf->sf_rport));

    oof_socket_mcast_remove_sw(fm, skf);

    if( CI_IP_IS_MULTICAST(skf->sf_laddr) ) {
      /* Nothing to do. */
    }
    else if( skf->sf_laddr ) {
      la_i = oof_manager_addr_find(fm, skf->sf_laddr);
      ci_assert(la_i >= 0 && la_i < fm->fm_local_addr_n);
      lpa = &lp->lp_addr[la_i];
      la = &fm->fm_local_addrs[la_i];
      if( skf->sf_raddr ) {
        oof_socket_del_full_sw(skf);
          /* If this endpoint only sharing SW filters and is not the
           * last one to be removed, it is safe to remove the filters
           * in an atomic context.
           *
           * We can't do this if the socket is clustered, as we still need to
           * drop the cluster ref, which is not safe where we have to avoid
           * hw ops.
           */
        if( skf->sf_full_match_filter.trs == NULL &&
            lp->lp_refs > 1 &&
            lpa->lpa_n_full_sharers > 1 &&
            ! oof_is_clustered(lp) ) {
          ci_dllist_remove(&skf->sf_lp_link);
          ci_assert(la->la_sockets > 0);
          --la->la_sockets;
          --lpa->lpa_n_full_sharers;
          skf->sf_local_port = NULL;
          --lp->lp_refs;
          rc = 0;
        }
      }
      else
        oof_socket_del_wild_sw(skf, skf->sf_laddr);
    }
    else {
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
        oof_socket_del_wild_sw(skf, fm->fm_local_addrs[la_i].la_laddr);
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  return rc;
}


static int
oof_udp_connect_mcast_laddr(struct oof_manager* fm, struct oof_socket* skf,
                            unsigned laddr, unsigned raddr, int rport)
{
  /* There are two ways to get here:
   * - a socket bound to local mcast addr is being connected
   * - a socket bound to local mcast addr has joined a group with addr laddr
   * 
   * We defer inserting filters for these socket until they actually join a
   * group with addr laddr to avoid receiving packets before we should.
   *
   * For connected mcast sockets the filters we install depend on the
   * capability of the relevant hwports.
   *
   * For hwports that are capable of multicast replication we use normal
   * wild match filters (specifying a vlan if supported).  This may result
   * in the stack getting extra packets, however the software filter will
   * prevent them from being delivered to the socket.  Because of the
   * replication we aren't preventing packets being delivered to other that
   * are interested in them.  This approach means that on multicast replication
   * capable hwports there is no need for chaining between different filter
   * types, as all multicast filters are IP wild (+ vlan).  Similarly we
   * aren't relying on relative priorities of different filter types.
   *
   * For hwports that aren't capable of multicast replication we can't do
   * this, as we need to be as specific as possible in our filters to avoid
   * taking packets that we don't really want from someone that actually
   * wants those packets.  This means that we will just use a full match
   * filter (no vlan).
   *
   * The wild match hw filters are managed in the same way as for unconnected
   * sockets.  The sw filter is added and removed on the connected path.
   */
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_mcast_member* mm;
  unsigned laddr_old, raddr_old, rport_old;
  unsigned hwports = 0;
  unsigned hwports_full;
  int rc = 0;

  IPF_LOG(FSK_FMT "%s "IPPORT_FMT" => "IPPORT_FMT" "IPPORT_FMT" multicast",
          FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
          IPPORT_ARG(skf->sf_laddr, lp->lp_lport),
          IPPORT_ARG(laddr, lp->lp_lport), IPPORT_ARG(raddr, rport));

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(CI_IP_IS_MULTICAST(skf->sf_laddr));
  ci_assert(CI_IP_IS_MULTICAST(laddr));
  ci_assert(skf->sf_full_match_filter.trs == NULL ||
           (skf->sf_laddr == laddr && skf->sf_raddr == raddr &&
            skf->sf_rport == rport));

  laddr_old = skf->sf_laddr;
  raddr_old = skf->sf_raddr;
  rport_old = skf->sf_rport;
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;

  /* See if we've joined any groups on this laddr, and if so which hwports
   * they're using.
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == laddr )
      hwports |= mm->mm_hwport_mask;


  /* We come through here each time a new group is joined, but only need to
   * add the sw filter the first time.
   */
  if( hwports != 0 && ! (skf->sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER) ) {
    /* Remove the wild filter before installing the full-match one to avoid
     * corrupting the filter table.
     */
    oof_socket_del_wild_sw(skf, laddr);

    rc = oof_socket_add_full_sw(skf);
    if( rc != 0 ) {
      /* Full-match insertion failed and wild has already gone. If this
       * function was called at connect-time, propagation of this failure will
       * result in handover. Otherwise, we must be adding our first membership
       * to this group, and so there are no hardware filters yet; in this case,
       * in response to this failure, the caller should decline to insert any
       * hardware filters so that traffic can go via the kernel.
       */
      oof_sw_insert_fail(skf, __FUNCTION__, rc);
      goto fail1;
    }

    skf->sf_flags |= OOF_SOCKET_MCAST_FULL_SW_FILTER;
  }

  hwports_full = hwports & ~fm->fm_hwports_mcast_replicate_capable;

  if( hwports_full ) {
    /* We only install full match mcast filters on ports that don't support
     * multicast replication, so not specifying a vlan makes no
     * difference on current hw, and simplifies things, so that's what we do.
     */
    rc = oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                              oof_cb_socket_stack(skf), lp->lp_protocol,
                              raddr, rport, laddr, lp->lp_lport,
                              OO_HW_VLAN_UNSPEC, hwports_full,
                              OOF_SRC_FLAGS_DEFAULT);
  }

  return rc;

 fail1:
  skf->sf_laddr = laddr_old;
  skf->sf_raddr = raddr_old;
  skf->sf_rport = rport_old;

  return rc;
}


int
oof_udp_connect(struct oof_manager* fm, struct oof_socket* skf,
                unsigned laddr, unsigned raddr, int rport)
{
  /* Special case for UDP connect().  We don't want to del() then add(), as
   * there may be an interval when there are no filters installed and
   * packets will go to the wrong place.
   */
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  struct oof_local_port* lp;
  unsigned laddr_old;
  int la_i_old = 0;  /* prevent silly compiler warning */
  int rc, la_i_new;
  int hidden;

  if( laddr == 0 || raddr == 0 || rport == 0 ) {
    ERR_LOG(FSK_FMT "ERROR: bad laddr="IP_FMT" raddr="IP_FMT" rport=%d",
            FSK_PRI_ARGS(skf), IP_ARG(laddr), IP_ARG(raddr), FMT_PORT(rport));
    return -EINVAL;
  }

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lp = skf->sf_local_port;
  rc = -EINVAL;
  if( lp == NULL ) {
    ERR_LOG(FSK_FMT "ERROR: no local port", FSK_PRI_ARGS(skf));
    goto unlock_out;
  }
  if( lp->lp_protocol != IPPROTO_UDP || skf->sf_raddr ) {
    ERR_LOG(FSK_FMT "ERROR: protocol=%s remote="IPPORT_FMT,
            FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
            IPPORT_ARG(skf->sf_raddr, skf->sf_rport));
    goto unlock_out;
  }
  la_i_new = oof_manager_addr_find(fm, laddr);
  if( la_i_new < 0 ) {
    if( CI_IP_IS_MULTICAST(laddr) && CI_IP_IS_MULTICAST(skf->sf_laddr) ) {
      rc = oof_udp_connect_mcast_laddr(fm, skf, laddr, raddr, rport);
      if( rc < 0 )
        goto unlock_out;
      else
        goto unlock_mcast_out;
    }
    ERR_LOG(FSK_FMT "ERROR: laddr="IP_FMT" not local",
            FSK_PRI_ARGS(skf), IP_ARG(laddr));
    goto unlock_out;
  }

  IPF_LOG(FSK_FMT "%s "IPPORT_FMT" => "IPPORT_FMT" "IPPORT_FMT,
          FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
          IPPORT_ARG(skf->sf_laddr, lp->lp_lport),
          IPPORT_ARG(laddr, lp->lp_lport), IPPORT_ARG(raddr, rport));

  /* First half of adding as full-match.  May or may not insert full-match
   * h/w filter.  We mustn't install s/w filter until we've removed the
   * existing s/w filter else we can confuse the filter table (which
   * requires that a socket be inserted only once for a given laddr).
   */
  laddr_old = skf->sf_laddr;
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  rc = oof_socket_add_full_hw(fm, skf, &lp->lp_addr[la_i_new]);
  if( rc < 0 )
    goto fail_reset_skf;

  /* Remove wild s/w filters.  May delete or move wild h/w filters, and may
   * insert new full-match h/w filter.  Must not "fixup" the wildcard
   * filters yet as [skf] does not yet look like a full-match socket, so
   * state is not sufficiently consistent.
   */
  skf->sf_laddr = laddr_old;
  skf->sf_raddr = 0;
  skf->sf_rport = 0;
  if( laddr_old ) {
    la_i_old = oof_manager_addr_find(fm, laddr_old);
    ci_assert(la_i_old >= 0 && la_i_old < fm->fm_local_addr_n);
    lpa = &lp->lp_addr[la_i_old];
    skf_stack = oof_cb_socket_stack(skf);
    hidden = ! oof_socket_is_first_in_stack(&lpa->lpa_semi_wild_socks,
                                            skf, skf_stack);
    ci_dllist_remove(&skf->sf_lp_link);
    if( ! hidden )
      __oof_socket_del_wild(skf, skf_stack, lpa, laddr_old);
  }
  else {
    oof_socket_del_wild(fm, skf);
  }

  /* Finish making [skf] into a proper full-match socket. */
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  rc = oof_cb_sw_filter_insert(skf, laddr, lp->lp_lport, raddr, rport,
                               lp->lp_protocol, 1);
  if( rc != 0 ) {
    /* NB. We haven't reset the socket to its previous state here.  We
     * leave it looking like a full-match, but with all filters missing.
     * Calling code should hand socket over to kernel, so this inconsistent
     * state should not matter much.
     */
    oof_sw_insert_fail(skf, __FUNCTION__, rc);
    oof_hw_filter_clear_full(fm, skf);
    goto unlock_out;
  }
  ci_dllist_push(&lp->lp_addr[la_i_new].lpa_full_socks, &skf->sf_lp_link);
  ++fm->fm_local_addrs[la_i_new].la_sockets;

  /* Sort out of the h/w filter(s).  This step may insert a new full-match
   * h/w filter, and may delete or move the wild h/w filter(s).
   */
  if( laddr_old ) {
    oof_local_port_addr_fixup_wild(fm, lp, &lp->lp_addr[la_i_old],
                                   laddr_old, fuw_udp_connect);
    la = &fm->fm_local_addrs[la_i_old];
    if( --la->la_sockets == 0 && ci_dllist_is_empty(&la->la_active_ifs) )
      oof_manager_addr_dead(fm, la);
  }
  else {
    oof_local_port_fixup_wild(fm, lp, fuw_udp_connect);
  }

 unlock_mcast_out:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( ci_dllist_not_empty(&skf->sf_mcast_memberships) )
    oof_socket_mcast_install(fm, skf);
  return 0;

 fail_reset_skf:
  skf->sf_laddr = laddr_old;
  skf->sf_raddr = 0;
  skf->sf_rport = 0;
 unlock_out:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}

/**********************************************************************
***********************************************************************
**********************************************************************/

/* If the socket is connected we only need an mcast (wild match) filter
 * if we have ports that support multicast replication.
 *
 * If local address is bound, then the socket can only receive packets
 * addressed to that local address.
 *
 */
#define OOF_NEED_MCAST_FILTER(fm, skf, mm)                             \
  ((((skf)->sf_raddr == 0) ||                                          \
   ((mm)->mm_hwport_mask & fm->fm_hwports_mcast_replicate_capable)) && \
   ((skf)->sf_laddr == 0 || (skf)->sf_laddr == ((mm)->mm_maddr)))


#define OOF_CONNECTED_MCAST(skf, maddr)                         \
  ((skf)->sf_raddr != 0 && (skf)->sf_laddr == (maddr))


/* Calculate the ports we want to install wild match multicast filters on.
 * For an unconnected socket this is all ports wanted by this oof_mcast_member.
 * For a connected socket we only want wild match on hwports that support
 * multicast replication.
 */
#define OOF_MCAST_WILD_HWPORTS(fm, mm)                                   \
   ( ((mm)->mm_socket->sf_raddr == 0) ?                                  \
     ((mm)->mm_hwport_mask) :                                            \
     ((mm)->mm_hwport_mask & (fm)->fm_hwports_mcast_replicate_capable) )


static struct oof_mcast_member*
oof_mcast_member_list_get(ci_dllist* mm_list)
{
  ci_assert(ci_dllist_not_empty(mm_list));
  return CI_CONTAINER(struct oof_mcast_member, mm_socket_link,
                      ci_dllist_pop(mm_list));
}


static void
oof_mcast_member_list_free(ci_dllist* mm_list)
{
  while( ci_dllist_not_empty(mm_list) )
    ci_free(oof_mcast_member_list_get(mm_list));
}


static struct oof_mcast_filter*
oof_mcast_filter_list_get(ci_dllist* mcast_filters)
{
  ci_assert(ci_dllist_not_empty(mcast_filters));
  return CI_CONTAINER(struct oof_mcast_filter, mf_lp_link,
                      ci_dllist_pop(mcast_filters));
}


static void
oof_mcast_filter_list_free(ci_dllist* mcast_filters)
{
  while( ci_dllist_not_empty(mcast_filters) )
    ci_free(oof_mcast_filter_list_get(mcast_filters));
}


static int
oof_socket_has_maddr_filter(struct oof_socket* skf, unsigned maddr)
{
  struct oof_mcast_member* mm;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_filter != NULL )
      return 1;
  return 0;
}


static struct oof_mcast_member*
oof_mcast_member_alloc(struct oof_socket* skf, unsigned maddr,
                       int ifindex, unsigned hwport_mask, ci_uint16 vlan_id)
{
  struct oof_mcast_member* mm;
  mm = CI_ALLOC_OBJ(struct oof_mcast_member);
  if( mm != NULL ) {
    mm->mm_filter = NULL;
    mm->mm_socket = skf;
    mm->mm_maddr = maddr;
    mm->mm_ifindex = ifindex;
    mm->mm_hwport_mask = hwport_mask;
    mm->mm_vlan_id = vlan_id;
  }
  return mm;
}


static const char*
oof_mcast_member_state(struct oof_mcast_member* mm)
{
  unsigned hwports_got;
  unsigned hwports_want;
  const char* s;
  struct oof_mcast_filter* mf2;
  struct oof_manager* fm = the_manager;

  hwports_got = oo_hw_filter_hwports(&mm->mm_filter->mf_filter);
  hwports_want = OOF_MCAST_WILD_HWPORTS(fm, mm);

  /* Check whether the filter that this oof_mcast_member wanted was installed
   * via another oof_mcast_filter, which can happen on ports that don't
   * support vlans.
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                        &mm->mm_socket->sf_local_port->lp_mcast_filters)
    hwports_got |= oof_mcast_filter_duplicate_hwports(mm->mm_filter, mf2);

  if( hwports_want ) {
    if( (hwports_got & hwports_want) == hwports_want )
      s = "ACCELERATED";
    else if( hwports_got & hwports_want )
      s = "PARTIALLY_ACCELERATED";
    else
      s = "KERNEL";
  }
  else
    s = "NO_ACCELERATABLE_PORTS";
  return s;
}


static void
oof_mcast_filter_init(struct oof_mcast_filter* mf, unsigned maddr,
                      ci_uint16 vlan_id)
{
  oo_hw_filter_init(&mf->mf_filter);
  mf->mf_maddr = maddr;
  mf->mf_vlan_id = vlan_id;
  mf->mf_hwport_mask = 0;
  ci_dllist_init(&mf->mf_memberships);
}


static unsigned
oof_mcast_filter_hwport_mask(struct oof_manager* fm,
                             struct oof_mcast_filter* mf)
{
  struct oof_mcast_member* mm;
  unsigned hwport_mask = 0;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_filter_link,
                      &mf->mf_memberships)
    hwport_mask |= OOF_MCAST_WILD_HWPORTS(fm, mm);
  return hwport_mask;
}


static struct oof_mcast_filter*
oof_local_port_find_mcast_filter(struct oof_local_port* lp,
                                 struct tcp_helper_resource_s* stack,
                                 unsigned maddr, ci_uint16 vlan_id)
{
  struct oof_mcast_filter* mf;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf->mf_filter.trs == stack && mf->mf_maddr == maddr
        && mf->mf_vlan_id == vlan_id )
      break;
  return mf;
}


/* This function returns the mask of ports which would conflict with mf if a 
 * new filter was required with the provided settings, on the same local port
 * as mf.
 */
ci_inline unsigned oof_mcast_conflicted_hwports(struct oof_manager* fm,
                                                struct tcp_helper_resource_s* 
                                                       stack,
                                                unsigned maddr,
                                                unsigned hwport_mask,
                                                ci_uint16 vlan_id,
                                                struct oof_mcast_filter* mf)
{
  /* There can only be a conflict is this is for the same address, but a
   * different stack.
   */
  if( maddr == mf->mf_maddr && stack != mf->mf_filter.trs )
    /* Add to conflict mask ports which appear in both hwport masks */
    return hwport_mask & mf->mf_hwport_mask &
           /* remove from conflict mask ports that support mcast replication */
           ~fm->fm_hwports_mcast_replicate_capable &
           /* If vlan id differs then remove from conflict mask ports which
            * understand vlan filters. If vlan id is the same then don't change
            * conflict mask.
            */
           (vlan_id != mf->mf_vlan_id ?
           ~fm->fm_hwports_vlan_filters : (unsigned)-1);
  else
    return 0;
}


static unsigned
oof_mcast_filter_duplicate_hwports(struct oof_mcast_filter* mf,
                                   struct oof_mcast_filter* mf2)
{
  struct oof_manager* fm = the_manager;
  unsigned hwport_mask = 0;

  /* An oof_mcast_filter is unique per maddr/port/vlan.  However, on hwports
   * that don't support vlan filters that means that the exact filter one
   * oof_mcast_filter wants can already be installed via another
   * oof_mcast_filter.
   *
   * An hwport already has an appropriate filter if:
   * - the stack is the same
   * - the maddr is the same
   * - the port is the same
   * - the hwport does not support vlans
   * - mf2 already has installed a filter on that hwport
   */
  if( (mf->mf_filter.trs == mf2->mf_filter.trs) && 
      (mf->mf_maddr == mf2->mf_maddr) )
    /* The filter matches, now check for hwport overlap on non-vlan hwports */
    hwport_mask = oof_mcast_filter_hwport_mask(fm, mf) &
         (oo_hw_filter_hwports(&mf2->mf_filter) & ~fm->fm_hwports_vlan_filters);

  return hwport_mask;
}


/* Find out whether there are any hwports that [mf] can install filters on.
 * ie. We're looking for hwports that support multicast replication or that
 * no other stack wants to install the same multicast filter on.
 */
static unsigned
oof_mcast_filter_installable_hwports(struct oof_local_port* lp,
                                     struct oof_mcast_filter* mf)
{
  unsigned hwport_mask = mf->mf_hwport_mask;
  struct oof_mcast_filter* mf2;
  struct oof_manager* fm = the_manager;

  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf2 != mf ) {
      hwport_mask &= ~oof_mcast_conflicted_hwports(fm, mf->mf_filter.trs,
                                                   mf->mf_maddr,
                                                   mf->mf_hwport_mask,
                                                   mf->mf_vlan_id, mf2);
      hwport_mask &= ~oof_mcast_filter_duplicate_hwports(mf, mf2);
    }
  return hwport_mask;
}


static int
oof_mcast_install(struct oof_manager* fm, struct oof_mcast_member* mm,
                  ci_dllist* mcast_filters)
{
  struct oof_socket* skf = mm->mm_socket;
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_local_port* lp = skf->sf_local_port;
  unsigned install_hwport_mask;
  unsigned conflicted_port_mask;
  struct oof_mcast_filter* mf;
  int rc;

  ci_assert(lp != NULL);
  ci_assert(OOF_NEED_MCAST_FILTER(fm, skf, mm));
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  /* Install a software filter if this socket doesn't already have a filter
   * for this maddr.  (This happens if the socket joins the same group on
   * more than one interface).
   *
   * In the case of connected sockets the connect path is responsible for
   * managing the sw filter.
   */
  if( (! oof_socket_has_maddr_filter(skf, mm->mm_maddr)) &&
      (! OOF_CONNECTED_MCAST(skf, mm->mm_maddr)) ) {
    rc = oof_cb_sw_filter_insert(skf, mm->mm_maddr, lp->lp_lport,
                                 0, 0, lp->lp_protocol, 1);
    if( rc != 0 )
      return rc; /* SW filter failed: do not insert HW */
  }


  /* Find filters that conflict with the one we want to install.
   *
   * Only bother checking for conflict if this one has any hwports that don't 
   * support multicast replication and this isn't a connected socket.
   * Multicast replication means we can't conflict.  For connected sockets
   * we will only install mcast (wild match) filters on hwports that
   * support multicast replication.
   *
   * Remove hardware filters that conflict.
   */
  if( (mm->mm_hwport_mask & fm->fm_hwports_mcast_replicate_capable)
      != mm->mm_hwport_mask )  {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters) {
     conflicted_port_mask =
       oof_mcast_conflicted_hwports(fm, skf_stack, mm->mm_maddr,
                                    mm->mm_hwport_mask, mm->mm_vlan_id, mf);
     if( conflicted_port_mask ) {
        IPF_LOG(FSK_FMT "CONFLICT: maddr="IPPORT_FMT" if=%d hwports=%x "
                "AND stack=%d hwports=%x AND mcast replicate hwports=%x "
                "AND vlan filter hwports=%x",
                FSK_PRI_ARGS(skf), IPPORT_ARG(mm->mm_maddr, lp->lp_lport),
                mm->mm_ifindex, mm->mm_hwport_mask,
                oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
                fm->fm_hwports_mcast_replicate_capable,
                fm->fm_hwports_vlan_filters);
        ci_assert(mf->mf_filter.thc == NULL);
      oof_hw_filter_clear_hwports(fm, &mf->mf_filter, conflicted_port_mask);
      }
    }
  }

  mf = oof_local_port_find_mcast_filter(lp, skf_stack, mm->mm_maddr,
                                        mm->mm_vlan_id);
  if( mf == NULL ) {
    mf = oof_mcast_filter_list_get(mcast_filters);
    oof_mcast_filter_init(mf, mm->mm_maddr, mm->mm_vlan_id);
    mf->mf_filter.trs = skf_stack;
    ci_dllist_push(&lp->lp_mcast_filters, &mf->mf_lp_link);
  }

  mm->mm_filter = mf;
  ci_dllist_push(&mf->mf_memberships, &mm->mm_filter_link);
  mf->mf_hwport_mask |= OOF_MCAST_WILD_HWPORTS(fm, mm);
  install_hwport_mask = oof_mcast_filter_installable_hwports(lp, mf);
  rc = oof_hw_filter_update(fm, &mf->mf_filter, skf_stack, lp->lp_protocol,
                            0, 0, mf->mf_maddr, lp->lp_lport,
                            mf->mf_vlan_id, install_hwport_mask,
                            OOF_SRC_FLAGS_DEFAULT_MCAST);
  if( rc != 0 )
    /* We didn't get all of the filters we wanted, but traffic should
     * still get there via the kernel stack.
     */
    ERR_LOG(FSK_FMT "mcast hw filter error: maddr="IPPORT_FMT" if=%d "
            "wanted=%x,%x install=%x got=%x rc=%d", FSK_PRI_ARGS(skf),
            IPPORT_ARG(mm->mm_maddr, lp->lp_lport),
            mm->mm_ifindex, mm->mm_hwport_mask, mf->mf_hwport_mask,
            install_hwport_mask, oo_hw_filter_hwports(&mf->mf_filter), rc);

  return rc;
}


static void
oof_mcast_remove(struct oof_manager* fm, struct oof_mcast_member* mm,
                 ci_dllist* mcast_filters)
{
  struct oof_mcast_filter* mf = mm->mm_filter;
  struct oof_socket* skf = mm->mm_socket;
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_mcast_filter* mf2;
  unsigned hwport_mask;
  int rc;

  ci_assert(mm->mm_filter != NULL);
  ci_assert(ci_dllist_not_empty(&mf->mf_memberships));
  ci_assert(mf->mf_maddr == mm->mm_maddr);

  /* It's possible that other oof_mcast_filters may be using a filter
   * installed via this oof_mcast_filter.  That can happen where the
   * oof_mcast_filters differ only in vlan id, and have overlapping hwports
   * that don't support vlan filters.
   *
   * In that case we need to pass ownership of the hwfilter rather than
   * removing it to avoid a gap where there is no filter installed.
   */
  if( mm->mm_hwport_mask & ~fm->fm_hwports_vlan_filters ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                        &lp->lp_mcast_filters)
      if( (mf2 != mf) &&
          (hwport_mask = oof_mcast_filter_duplicate_hwports(mf2, mf)) ) {
        /* mf2 is relying on filtering via mf for hwport_mask.  Pass those
         * filters over to mf2.
         */
        oof_hw_filter_transfer(fm, mm, mf2, hwport_mask);
      }
  }

  mm->mm_filter = NULL;
  ci_dllist_remove(&mm->mm_filter_link);
  if( ci_dllist_is_empty(&mf->mf_memberships) ) {
    oof_hw_filter_clear(fm, &mf->mf_filter);
    IPF_LOG(FSK_FMT "CLEAR "IPPORT_FMT, FSK_PRI_ARGS(skf),
            IPPORT_ARG(mm->mm_maddr, lp->lp_lport));
    ci_dllist_remove(&mf->mf_lp_link);
    ci_dllist_push(mcast_filters, &mf->mf_lp_link);
  }
  else {
    mf->mf_hwport_mask = oof_mcast_filter_hwport_mask(fm, mf);
    hwport_mask = oof_mcast_filter_installable_hwports(lp, mf);
    oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs,
                         lp->lp_protocol, 0, 0, mf->mf_maddr, lp->lp_lport,
                         mf->mf_vlan_id, hwport_mask,
                         OOF_SRC_FLAGS_DEFAULT_MCAST);
  }

  /* Is it now possible to insert filters to accelerate this group for
   * another stack?
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf->mf_maddr == mm->mm_maddr ) {
      unsigned got_hwport_mask;
      got_hwport_mask = oo_hw_filter_hwports(&mf->mf_filter);
      if( mf->mf_hwport_mask != got_hwport_mask ) {
        hwport_mask = oof_mcast_filter_installable_hwports(lp, mf);
        if( hwport_mask != got_hwport_mask ) {
          IPF_LOG(FSK_FMT "maddr="IPPORT_FMT" if=%d MODIFY stack=%d wanted=%x "
                  "had=%x install=%x", FSK_PRI_ARGS(skf),
                  IPPORT_ARG(mm->mm_maddr, lp->lp_lport), mm->mm_ifindex,
                  oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
                  got_hwport_mask, hwport_mask);
          rc = oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs,
                                    lp->lp_protocol, 0, 0, mf->mf_maddr,
                                    lp->lp_lport, mf->mf_vlan_id,
                                    hwport_mask,
                                    OOF_SRC_FLAGS_DEFAULT_MCAST);
          if( rc != 0 )
            ERR_LOG("%s: mcast hw filter error: maddr="IPPORT_FMT" wanted=%x "
                    "install=%x got=%x", __FUNCTION__,
                    IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
                    mf->mf_hwport_mask, hwport_mask,
                    oo_hw_filter_hwports(&mf->mf_filter));
        }
      }
    }

  /* Remove software filter if no filters remain for maddr. */
  if( ! oof_socket_has_maddr_filter(skf, mm->mm_maddr) &&
      ! OOF_CONNECTED_MCAST(skf, mm->mm_maddr) )
    oof_cb_sw_filter_remove(skf, mm->mm_maddr, lp->lp_lport,
                            0, 0, lp->lp_protocol, 1);
}


static void
oof_mcast_update(struct oof_manager* fm, struct oof_local_port *lp,
                 struct oof_mcast_filter* mf, int ifindex)
{
  unsigned install_hwport_mask, before_hwport_mask;
  int rc;

  before_hwport_mask = oo_hw_filter_hwports(&mf->mf_filter);
  install_hwport_mask = oof_mcast_filter_installable_hwports(lp, mf);
  if( install_hwport_mask != before_hwport_mask ) {
    rc = oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs,
                              lp->lp_protocol, 0, 0,
                              mf->mf_maddr, lp->lp_lport,
                              mf->mf_vlan_id, install_hwport_mask,
                              OOF_SRC_FLAGS_DEFAULT_MCAST);
    IPF_LOG("%s: UPDATE "IPPORT_FMT" if=%d hwports before=%x wanted=%x "
            "install=%x after=%x", __FUNCTION__,
            IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
            ifindex, before_hwport_mask, mf->mf_hwport_mask,
            install_hwport_mask, oo_hw_filter_hwports(&mf->mf_filter));
  }
}


static void
__oof_mcast_update_filters(struct oof_manager* fm, int ifindex)
{
  struct oof_local_port* lp;
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  unsigned hwport_mask;
  int rc, hash, touched;

  if( (rc = oof_cb_get_hwport_mask(ifindex, &hwport_mask)) != 0 ) {
    ERR_LOG("%s: ERROR: oof_cb_get_hwport_mask(%d) failed rc=%d",
            __FUNCTION__, ifindex, rc);
    return;
  }

  IPF_LOG("%s: if=%u hwports=%x", __FUNCTION__, ifindex, hwport_mask);

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      /* Need to update mf_hwport_mask in all filters first for
       * oof_mcast_filter_installable_hwports() to give correct results.
       */
      touched = 0;
      CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                          &lp->lp_mcast_filters)
        CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_filter_link,
                            &mf->mf_memberships)
          if( mm->mm_ifindex == ifindex ) {
            mm->mm_hwport_mask = hwport_mask;
            mf->mf_hwport_mask = oof_mcast_filter_hwport_mask(fm, mf);
            touched = 1;
          }
      if( touched )
        CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                            &lp->lp_mcast_filters)
          oof_mcast_update(fm, lp, mf, ifindex);
    }
}


void
oof_mcast_update_filters(struct oof_manager* fm, int ifindex)
{
  /* Caller must hold the CICP_LOCK. */

  oof_manager_queue_cplane_update(fm, OOF_CU_UPDATE_FILTERS, 0, ifindex);
  oof_cb_defer_work(fm->fm_owner_private);
}


int
oof_socket_mcast_add(struct oof_manager* fm, struct oof_socket* skf,
                     unsigned maddr, int ifindex)
{
  struct oof_mcast_member* new_mm;
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  ci_dllist mcast_filters;
  unsigned hwport_mask;
  int rc;
  ci_uint16 vlan_id = OO_HW_VLAN_DEFAULT;

  IPF_LOG(FSK_FMT "maddr="IP_FMT" if=%d",
          FSK_PRI_ARGS(skf), IP_ARG(maddr), ifindex);

  ci_dllist_init(&mcast_filters);
  new_mm = NULL;
  if( ! CI_IP_IS_MULTICAST(maddr) ) {
    ERR_LOG(FSK_FMT "ERROR: maddr="IP_FMT, FSK_PRI_ARGS(skf), IP_ARG(maddr));
    rc = -EINVAL;
    goto out;
  }

  hwport_mask = 0;
  rc = oof_cb_get_hwport_mask(ifindex, &hwport_mask);
  if( rc != 0 || hwport_mask == 0 ) {
    IPF_LOG(FSK_FMT "ERROR: no hwports for if=%d rc=%d",
            FSK_PRI_ARGS(skf), ifindex, rc);
    /* Carry on -- we may get hwports later due to cplane changes. */
  }

  /* We should always succeed unless the interface has gone away.  If it
   * has then no point continuing here.
   */
  if( (rc = oof_cb_get_vlan_id(ifindex, &vlan_id)) != 0 ) {
    IPF_LOG("%s: ERROR: oof_cb_get_vlan_id(%d) failed rc=%d",
            __FUNCTION__, ifindex, rc);
    goto out;
  }

  new_mm = oof_mcast_member_alloc(skf, maddr, ifindex, hwport_mask, vlan_id);
  if( new_mm == NULL )
    goto out_of_memory;
  if( (mf = CI_ALLOC_OBJ(struct oof_mcast_filter)) == NULL )
    goto out_of_memory;
  ci_dllist_push(&mcast_filters, &mf->mf_lp_link);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  rc = 0;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_ifindex == ifindex )
      break;
  if( mm == NULL ) {  /* NB. Ignore duplicates. */
    mm = new_mm;
    new_mm = NULL;
    ci_dllist_push(&skf->sf_mcast_memberships, &mm->mm_socket_link);
    if( skf->sf_local_port != NULL ) {
      /* For connected sockets we install any full match filters and the sw
       * filter via the connect path first.  Then wild match filters are
       * added for all sockets if needed.  If the connect path fails, we don't
       * install hw filters so that traffic can go via the kernel.
       */
      if( OOF_CONNECTED_MCAST(skf, maddr) )
        rc = oof_udp_connect_mcast_laddr(fm, skf, skf->sf_laddr, skf->sf_raddr,
                                         skf->sf_rport);
      if( rc == 0 && OOF_NEED_MCAST_FILTER(fm, skf, mm) )
        rc = oof_mcast_install(fm, mm, &mcast_filters);
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

 out:
  if( new_mm )
    ci_free(new_mm);
  oof_mcast_filter_list_free(&mcast_filters);
  return rc;

 out_of_memory:
  ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
  rc = -ENOMEM;
  goto out;
}


void
oof_socket_mcast_del_connected(struct oof_manager* fm, struct oof_socket* skf,
                               unsigned maddr, int ifindex)
{
  struct oof_mcast_member* mm;
  unsigned hwports = 0;
  unsigned hwports_full;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == skf->sf_laddr )
      hwports |= mm->mm_hwport_mask;

  hwports_full = hwports & ~fm->fm_hwports_mcast_replicate_capable;

  /* Still need a full match filter, update it with the current hwports */
  if( hwports_full ) {
    oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                         oof_cb_socket_stack(skf),
                         skf->sf_local_port->lp_protocol, skf->sf_raddr,
                         skf->sf_rport, skf->sf_laddr,
                         skf->sf_local_port->lp_lport, OO_HW_VLAN_UNSPEC,
                         hwports_full, OOF_SRC_FLAGS_DEFAULT);
  }
  /* If we have no hwports we don't need any filters. */
  else if( hwports == hwports_full ) {
    if( skf->sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER ) {
      oof_socket_del_full_sw(skf);
      skf->sf_flags &= ~OOF_SOCKET_MCAST_FULL_SW_FILTER;
    }
    oof_hw_filter_clear_full(fm, skf);
  }
}


void
oof_socket_mcast_del(struct oof_manager* fm, struct oof_socket* skf,
                     unsigned maddr, int ifindex)
{
  struct oof_mcast_member* mm;
  ci_dllist mcast_filters;

  IPF_LOG(FSK_FMT "maddr="IP_FMT, FSK_PRI_ARGS(skf), IP_ARG(maddr));

  ci_dllist_init(&mcast_filters);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_ifindex == ifindex)
      break;
  if( mm != NULL ) {
    ci_dllist_remove(&mm->mm_socket_link);
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, &mcast_filters);

    if( OOF_CONNECTED_MCAST(skf, maddr) )
      oof_socket_mcast_del_connected(fm, skf, maddr, ifindex);
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

  if( mm != NULL )
    ci_free(mm);
  oof_mcast_filter_list_free(&mcast_filters);
}


void
oof_socket_mcast_del_all(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_mcast_member* mm;
  ci_dllist mf_list, mm_list;

  ci_dllist_init(&mf_list);
  ci_dllist_init(&mm_list);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  while( ci_dllist_not_empty(&skf->sf_mcast_memberships) ) {
    mm = CI_CONTAINER(struct oof_mcast_member, mm_socket_link,
                      ci_dllist_pop(&skf->sf_mcast_memberships));
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, &mf_list);
    ci_dllist_push(&mm_list, &mm->mm_socket_link);
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

  oof_mcast_filter_list_free(&mf_list);
  oof_mcast_member_list_free(&mm_list);
}


static int
oof_socket_mcast_install(struct oof_manager* fm, struct oof_socket* skf)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  struct oof_local_port* lp;
  ci_dllist mcast_filters;
  int mf_needed, mf_n, rc, rc1 = 0;

  /* Calculate how many new filters we'll need to install, and allocate
   * that many.  Slightly complex because we want to allocate with lock
   * dropped.
   *
   * TODO: NB. This can be simplified now that we have fm_outer_lock, which
   * allows non-atomic memory allocation and ensures sf_mcast_memberships
   * won't change.
   */
  ci_dllist_init(&mcast_filters);
  mf_n = 0;
  
  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  while( 1 ) {
    mf_needed = 0;
    if( (lp = skf->sf_local_port) != NULL ) {
      CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                          &skf->sf_mcast_memberships) {
        if( mm->mm_filter == NULL &&
            OOF_NEED_MCAST_FILTER(fm, skf, mm) &&
            oof_local_port_find_mcast_filter(lp, skf_stack, mm->mm_maddr,
                                             mm->mm_vlan_id) == NULL )
          ++mf_needed;
      }
    }
    if( mf_n >= mf_needed )
      break;

    spin_unlock_bh(&fm->fm_inner_lock);
    mutex_unlock(&fm->fm_outer_lock);

    do {
      if( (mf = CI_ALLOC_OBJ(struct oof_mcast_filter)) == NULL )
        goto out_of_memory;
      ci_dllist_push(&mcast_filters, &mf->mf_lp_link);
    } while( ++mf_n < mf_needed );

    mutex_lock(&fm->fm_outer_lock);
    spin_lock_bh(&fm->fm_inner_lock);
  }

  if( lp != NULL ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                        &skf->sf_mcast_memberships) {
      if( mm->mm_filter == NULL ) {
        if( OOF_NEED_MCAST_FILTER(fm, skf, mm) ) {
          rc = oof_mcast_install(fm, mm, &mcast_filters);
          if( rc != 0 && rc1 == 0 )
            rc1 = rc;
        }
      }
      else {
        if( ! OOF_NEED_MCAST_FILTER(fm, skf, mm) )
          oof_mcast_remove(fm, mm, &mcast_filters);
      }
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

 out:
  oof_mcast_filter_list_free(&mcast_filters);
  return rc1;

 out_of_memory:
  ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
  goto out;
}


static void
oof_socket_mcast_remove(struct oof_manager* fm, struct oof_socket* skf,
                        ci_dllist* mcast_filters)
{
  struct oof_mcast_member* mm;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    ci_assert(mm->mm_socket == skf);
    ci_assert(CI_IP_IS_MULTICAST(mm->mm_maddr));
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, mcast_filters);
  }
}


static void
oof_socket_mcast_remove_sw(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_mcast_member* mm;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    ci_assert(mm->mm_socket == skf);
    ci_assert(CI_IP_IS_MULTICAST(mm->mm_maddr));
    if( mm->mm_filter != NULL )
      oof_cb_sw_filter_remove(skf, mm->mm_maddr, skf->sf_local_port->lp_lport,
                              0, 0, skf->sf_local_port->lp_protocol, 1);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/


static void oof_thc_add_ref(struct oof_local_port* lp)
{
  ci_assert(lp);
  ci_assert(lp->lp_thcf);
  ++lp->lp_thcf->tf_ref;
}


/* Install the HW filters for the cluster.  Returns -ve error on
 * failure, 0 if filters already installed, 1 if filters were actually
 * installed.
 */
static int oof_thc_install_filters(struct oof_manager* fm,
                                   struct oof_local_port* lp, unsigned laddr)
{
  struct oof_thc* thcf = lp->lp_thcf;
  struct oof_local_addr* la;
  int la_i, rc;

  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  if( thcf->tf_filters_installed == 1 )
    return 0;

  thcf->tf_laddr = laddr;
  if( thcf->tf_laddr == 0 ) {

    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
      la = &fm->fm_local_addrs[la_i];
      if( ci_dllist_is_empty(&la->la_active_ifs) )
        /* Entry invalid or address disabled. */
        continue;
      if( (rc = oof_hw_thc_filter_set(fm, lp, la_i, la->la_laddr)) != 0 ) {
        OO_DEBUG_ERR(ci_log("%s: ERROR: FILTER "TRIPLE_FMT" failed (%d)",
                            __FUNCTION__,
                            TRIPLE_ARGS(lp->lp_protocol, la->la_laddr,
                                        lp->lp_lport), rc));
        while( --la_i >= 0 )
          oo_hw_filter_clear(&thcf->tf_filters[la_i]);
        return rc;
      }
    }
    thcf->tf_filters_installed = 1;
    return 1;
  }
  else {
    int found = 0;
    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
      if( thcf->tf_laddr == fm->fm_local_addrs[la_i].la_laddr ) {
        found = 1;
        break;
      }
    if( found == 0 )
      return -EINVAL;

    la = &fm->fm_local_addrs[la_i];
    if( ci_dllist_is_empty(&la->la_active_ifs) )
      /* Entry invalid or address disabled. */
      return -EINVAL;
    if( (rc = oof_hw_thc_filter_set(fm, lp, la_i, la->la_laddr)) != 0 )
      if( rc < 0 ) {
      OO_DEBUG_ERR(ci_log("%s: ERROR: FILTER "TRIPLE_FMT" failed (%d)",
                          __FUNCTION__,
                          TRIPLE_ARGS(lp->lp_protocol, la->la_laddr,
                                      lp->lp_lport), rc));
      return rc;
      }
    thcf->tf_filters_installed = 1;
    return 1;
  }
}


static int oof_thc_alloc(struct oof_manager* fm,
                         struct tcp_helper_cluster_s* thc,
                         struct oof_local_port* lp)
{
  struct oof_thc* thcf;
  struct oo_hw_filter* filters;
  int i;
  IPF_LOG("%s: %s lport=%d", __FUNCTION__, FMT_PROTOCOL(lp->lp_protocol),
          lp->lp_lport);

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  spin_unlock_bh(&fm->fm_inner_lock);
  thcf = CI_ALLOC_OBJ(struct oof_thc);
  spin_lock_bh(&fm->fm_inner_lock);
  if( thcf == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  filters = CI_ALLOC_ARRAY(struct oo_hw_filter, fm->fm_local_addr_max);
  spin_lock_bh(&fm->fm_inner_lock);
  if( filters == NULL ) {
    ci_free(thcf);
    OO_DEBUG_ERR(ci_log("%s: ERROR: out of memory", __FUNCTION__));
    return -ENOMEM;
  }
  for( i = 0; i < fm->fm_local_addr_max; ++i )
    oo_hw_filter_init(&filters[i]);

  lp->lp_thcf      = thcf;
  thcf->tf_filters = filters;
  thcf->tf_thc     = thc;
  thcf->tf_ref     = 1;
  thcf->tf_filters_installed = 0;
  tcp_helper_cluster_ref(thc);
  return 0;
}


static void oof_thc_remove_filters(struct oof_manager* fm,
                                   struct oof_local_port* lp)
{
  int la_i;
  struct oof_thc* thcf = lp->lp_thcf;
  thcf->tf_filters_installed = 0;
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
    if( (thcf->tf_laddr == 0 ||
         thcf->tf_laddr == fm->fm_local_addrs[la_i].la_laddr) &&
        ci_dllist_not_empty(&(fm->fm_local_addrs[la_i].la_active_ifs)) ) {
      spin_unlock_bh(&fm->fm_inner_lock);
      oo_hw_filter_clear(&thcf->tf_filters[la_i]);
      spin_lock_bh(&fm->fm_inner_lock);
    }
}


static void oof_thc_do_del(struct oof_thc* thcf)
{
  tcp_helper_cluster_release(thcf->tf_thc, NULL);
  ci_free(thcf->tf_filters);
  ci_free(thcf);
}


static int oof_thc_release(struct oof_manager* fm,
                           struct oof_local_port* lp)
{
  struct oof_thc* thcf = lp->lp_thcf;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(thcf->tf_ref > 0);

  if( --thcf->tf_ref > 0 )
    return 0;
  --lp->lp_refs;
  ci_assert_gt(lp->lp_refs, 0);
  oof_thc_remove_filters(fm, lp);
  return 1; /* all references had been removed */
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void
oof_socket_dump_w_lp(const char* pf, struct oof_manager* fm,
                     struct oof_socket* skf,
                     void (*log)(void* opaque, const char* fmt, ...),
                     void* loga)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf, *mf2;
  const char* state = NULL;
  int n_laddr, n_filter, n_mine;
  int la_i;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(skf->sf_local_port != NULL);

  /* Work out whether the socket can receive any packets. */
  if( lp->lp_thcf != NULL) {
    state = "CLUSTERED";
  }
  else if( skf->sf_full_match_filter.trs != NULL ) {
    state = "ACCELERATED (full)";
  }
  else if( CI_IP_IS_MULTICAST(skf->sf_laddr) ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters)
      if( mf->mf_maddr == skf->sf_laddr && mf->mf_filter.trs == skf_stack ) {
        if( oo_hw_filter_hwports(&mf->mf_filter) )
          state = "ACCELERATED (multicast laddr)";
        else {
          /* See if there's another filter that we're sharing. */
          CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                              &lp->lp_mcast_filters)
            if( (mf != mf2) && (oof_mcast_filter_duplicate_hwports(mf, mf2)) ) {
              state = "ACCELERATED (multicast laddr)";
              break;
            }
          if ( state == NULL )
            state = "KERNEL (multicast laddr)";
        }
        break;
      }
    if( state == NULL )
      /* Not done IP_ADD_MEMBERSHIP, so won't get packets. */
      state = "UNREACHABLE (need IP_ADD_MEMBERSHIP)";
  }
  else if( skf->sf_laddr ) {
    la_i = oof_manager_addr_find(fm, skf->sf_laddr);
    ci_assert(la_i >= 0 && la_i < fm->fm_local_addr_n);
    lpa = &lp->lp_addr[la_i];
    if( skf->sf_raddr ) {
      if( lpa->lpa_filter.trs == skf_stack )
        state = "ACCELERATED (sharing wild)";
      else if( lpa->lpa_filter.trs == NULL )
        state = "ORPHANED (no filter)";
      else
        state = "ORPHANED (filter points elsewhere)";
    }
    else {
      if( oof_wild_socket(lp, lpa) == skf ) {
        if( lpa->lpa_filter.trs == skf_stack )
          state = "ACCELERATED (wild)";
        else if( lpa->lpa_filter.trs == NULL )
          state = "FILTER_MISSING (not accelerated)";
        else
          state = "!! BAD_FILTER !!";
      }
      else
        state = "HIDDEN";
    }
  }
  else {
    n_laddr = n_filter = n_mine = 0;
    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
      if( ci_dllist_not_empty(&fm->fm_local_addrs[la_i].la_active_ifs) ) {
        ++n_laddr;
        lpa = &lp->lp_addr[la_i];
        if( oof_wild_socket(lp, lpa) == skf )
          ++n_mine;
        if( lpa->lpa_filter.trs == skf_stack )
          ++n_filter;
      }
    if( n_laddr == 0 )
      state = "NO_LOCAL_ADDR";
    else if( n_filter < n_mine )
      state = "FILTERS_MISSING (may not be accelerated)";
    else if( n_mine == 0 )
      state = "HIDDEN";
    else if( n_mine < n_laddr )
      state = "PARTIALLY_HIDDEN";
    else
      state = "ACCELERATED";
  }

  log(loga, "%s: "SK_FMT" "SK_ADDR_FMT" %s", pf,
      SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf), state);
}


void
oof_socket_dump(struct oof_manager* fm, struct oof_socket* skf,
                void (*log)(void* opaque, const char* fmt, ...),
                void* loga)
{
  struct oof_mcast_member* mm;
  struct oof_mcast_filter* mf;
  unsigned hwports_got;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  if( skf->sf_local_port != NULL )
    oof_socket_dump_w_lp(__FUNCTION__, fm, skf, log, loga);
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    if( (mf = mm->mm_filter) == NULL ) {
      log(loga, "%s:   maddr="IP_FMT" if=%d hwports=%x NOT_BOUND",
          __FUNCTION__, IP_ARG(mm->mm_maddr), mm->mm_ifindex,
          mm->mm_hwport_mask);
    }
    else {
      hwports_got = oo_hw_filter_hwports(&mf->mf_filter);
      log(loga, "%s:   maddr="IP_FMT" if=%d hwports=%x,%x,%x %s", __FUNCTION__,
          IP_ARG(mm->mm_maddr), mm->mm_ifindex, mm->mm_hwport_mask,
          oof_mcast_filter_installable_hwports(skf->sf_local_port, mf) &
            mm->mm_hwport_mask,
          hwports_got & mm->mm_hwport_mask, oof_mcast_member_state(mm));
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


static void
oof_local_port_dump(struct oof_manager* fm, struct oof_local_port* lp,
                    void (*log)(void* opaque, const char* fmt, ...),
                    void* loga)
{
  unsigned hwports_got, hwports_uc;
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  struct oof_local_addr* la;
  struct oof_socket* skf;
  int la_i;

  log(loga, "%s: %s:%d n_refs=%d %s", __FUNCTION__,
      FMT_PROTOCOL(lp->lp_protocol), FMT_PORT(lp->lp_lport), lp->lp_refs,
      lp->lp_thcf != NULL ? "clustered" : "");

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( ci_dllist_not_empty(&lp->lp_wild_socks) ) {
    log(loga, "  wild sockets:");
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, &lp->lp_wild_socks)
      oof_socket_dump_w_lp("    ", fm, skf, log, loga);
  }

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    lpa = &lp->lp_addr[la_i];
    if( lpa->lpa_filter.trs != NULL )
      log(loga, "  FILTER "IPPORT_FMT" hwports=%x stack=%d",
          IPPORT_ARG(la->la_laddr, lp->lp_lport),
          oo_hw_filter_hwports(&lpa->lpa_filter),
          oof_cb_stack_id(lpa->lpa_filter.trs));
    if( ci_dllist_not_empty(&lpa->lpa_semi_wild_socks) ) {
      log(loga, "  semi-wild sockets:");
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_semi_wild_socks)
        oof_socket_dump_w_lp("    ", fm, skf, log, loga);
    }
    if( ci_dllist_not_empty(&lpa->lpa_full_socks) ) {
      log(loga, "  full-match sockets:");
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks)
        oof_socket_dump_w_lp("    ", fm, skf, log, loga);
    }
  }

  if( ci_dllist_not_empty(&lp->lp_mcast_filters) ) {
    log(loga, "  mcast filters:");
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters) {
      hwports_got = oo_hw_filter_hwports(&mf->mf_filter);
      hwports_uc = oof_mcast_filter_installable_hwports(lp, mf);
      log(loga, "    maddr="IPPORT_FMT" stack=%d hwports=%x,%x,%x",
          IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
          oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
          hwports_uc, hwports_got);
      CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_filter_link,
                          &mf->mf_memberships)
        log(loga, "      "SK_FMT" "SK_ADDR_FMT" if=%d hwports=%x,%x,%x %s",
            SK_PRI_ARGS(mm->mm_socket), SK_ADDR_ARGS(mm->mm_socket),
            mm->mm_ifindex, mm->mm_hwport_mask,
            hwports_uc & mm->mm_hwport_mask, hwports_got & mm->mm_hwport_mask,
            oof_mcast_member_state(mm));
    }
  }
}


void
oof_manager_dump(struct oof_manager* fm,
                void (*log)(void* opaque, const char* fmt, ...),
                void* loga)
{
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  struct oof_socket* skf;
  int la_i, hash;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  log(loga, "%s: hwports up=%x unavailable=%x local_addr_n=%d", __FUNCTION__,
      fm->fm_hwports_up, ~fm->fm_hwports_available, fm->fm_local_addr_n);

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    if( la->la_laddr == 0 )
      continue;
    log(loga, "  "IP_FMT" active=%d sockets=%d", IP_ARG(la->la_laddr),
        ci_dllist_not_empty(&la->la_active_ifs), la->la_sockets);
  }

  if( ci_dllist_not_empty(&fm->fm_mcast_laddr_socks) ) {
    log(loga, "%s: sockets with laddr bound to multicast address:",
        __FUNCTION__);
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                        &fm->fm_mcast_laddr_socks)
      oof_socket_dump_w_lp("  ", fm, skf, log, loga);
  }

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash])
      oof_local_port_dump(fm, lp, log, loga);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}
