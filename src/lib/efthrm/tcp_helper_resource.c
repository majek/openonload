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
**      Author: ctk
**     Started: 2004/03/15
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <ci/internal/transport_config_opt.h>
# include <onload/linux_onload_internal.h>
# include <onload/linux_onload.h>
# include <onload/linux_ip_protocols.h>
#include <ci/efch/mmap.h>
#include <onload/mmap.h>
#include <onload/cplane.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/efabcfg.h>
#include <onload/driverlink_filter.h>
#include <onload/version.h>

#include <etherfabric/timer.h>
#include <etherfabric/init.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_set.h>
#include <ci/driver/efab/hardware.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>
#include <onload/nic.h>
#include <ci/internal/pio_buddy.h>
#include <onload/tmpl.h>


#ifdef NDEBUG
# define DEBUG_STR  ""
#else
# define DEBUG_STR  " debug"
#endif

#if CI_CFG_PKT_BUF_SIZE == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S CI_CFG_PKTS_PER_SET_S
#define PKTS_PER_HW_PAGE 1
#elif CI_CFG_PKT_BUF_SIZE * 2 == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S (CI_CFG_PKTS_PER_SET_S - 1)
#define PKTS_PER_HW_PAGE 2
#elif CI_CFG_PKT_BUF_SIZE * 4 == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S (CI_CFG_PKTS_PER_SET_S - 2)
#define PKTS_PER_HW_PAGE 4
#else
#error "Unkinown value for CI_CFG_PKT_BUF_SIZE"
#endif


#define EFAB_THR_MAX_NUM_INSTANCES  0x00010000

/* Provides upper limit to EF_MAX_PACKETS. default is 512K packets,
 * which equates to roughly 1GB of memory 
 */
static unsigned max_packets_per_stack = 0x80000;
module_param(max_packets_per_stack, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(max_packets_per_stack,
                 "Limit the number of packet buffers that each Onload stack "
                 "can allocate.  This module option places an upper limit "
                 "on the EF_MAX_PACKETS option.  Changes to this module "
                 "option are not applied retrospectively to stacks already "
                 "existing before the change.");

static int allow_insecure_setuid_sharing;
module_param(allow_insecure_setuid_sharing, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(allow_insecure_setuid_sharing,
                 "Override default security rules and allow setuid processes "
                 "to map Onload stacks created by other users.");

/* Global structure for onload driver */
efab_tcp_driver_t efab_tcp_driver;


static void oo_handle_wakeup_int_driven(void*, int is_timeout,
                                        struct efhw_nic*);

static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t*, int can_destroy_now);
static void
efab_tcp_helper_rm_schedule_free(tcp_helper_resource_t*);

static void
oo_handle_wakeup_or_timeout(void*, int is_timeout, struct efhw_nic*);
static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t*);
static void
tcp_helper_stop_periodic_timer(tcp_helper_resource_t*);

static int
efab_tcp_helper_netif_lock_or_set_flags(tcp_helper_resource_t* trs, 
                                        unsigned trusted_flags,
                                        unsigned untrusted_flags,
                                        int in_dl_context);

static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t*);


/*----------------------------------------------------------------------------
 *
 * oo_trusted_lock
 *
 *---------------------------------------------------------------------------*/

ci_inline int
oo_trusted_lock_is_locked(tcp_helper_resource_t* trs)
{
  return trs->trusted_lock & OO_TRUSTED_LOCK_LOCKED;
}


static int
oo_trusted_lock_try_lock(tcp_helper_resource_t* trs)
{
  return trs->trusted_lock == OO_TRUSTED_LOCK_UNLOCKED &&
         ci_cas32u_succeed(&trs->trusted_lock, OO_TRUSTED_LOCK_UNLOCKED, 
                           OO_TRUSTED_LOCK_LOCKED);
}


static void
oo_trusted_lock_drop(tcp_helper_resource_t* trs, int in_dl_context)
{
  unsigned l, new_l, sl_flags;
  ci_netif* ni = &trs->netif;

  /* It is possible to infer in_dl_context from ni->flags,
   * however with in_dl_context argument we can check correctness of the
   * the flag lifetime */
  ci_assert( (! in_dl_context) == (! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT)) );

 again:
  l = trs->trusted_lock;
  ci_assert(l & OO_TRUSTED_LOCK_LOCKED);

  if(CI_UNLIKELY( l & OO_TRUSTED_LOCK_AWAITING_FREE )) {
    /* We may be called from the stack workqueue, so postpone destruction
     * to the point where wq may be flushed */
    efab_tcp_helper_rm_schedule_free(trs);
    if( in_dl_context )
      ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
    return;
  }

  if( l == OO_TRUSTED_LOCK_LOCKED ) {
    if( in_dl_context )
      ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
    if( ci_cas32_fail(&trs->trusted_lock, l, OO_TRUSTED_LOCK_UNLOCKED) ) {
      if( in_dl_context )
        ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
      goto again;
    }
    return;
  }

  if( l & OO_TRUSTED_LOCK_CLOSE_ENDPOINT ) {
    new_l = l & ~OO_TRUSTED_LOCK_CLOSE_ENDPOINT;
    if( ci_cas32_fail(&trs->trusted_lock, l, new_l) )
      goto again;
    if( ef_eplock_lock_or_set_flag(&trs->netif.state->lock,
                                   CI_EPLOCK_NETIF_CLOSE_ENDPOINT) ) {
      /* We've got both locks.  If in non-atomic context, do the work, else
       * defer work and locks to workitem.
       */
      if( in_atomic() ) {
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to workitem",
                             __FUNCTION__, trs->id));
        ci_atomic32_or(&trs->trs_aflags, OO_THR_AFLAG_CLOSE_ENDPOINTS);
        queue_work(trs->wq, &trs->non_atomic_work);
        if( in_dl_context )
          ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
        return;
      }
      OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINT now",
                           __FUNCTION__, trs->id));
      tcp_helper_close_pending_endpoints(trs);
      ci_netif_unlock(&trs->netif);
    }
    else {
      /* Untrusted lock holder now responsible for invoking non-atomic work. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to trusted lock",
                           __FUNCTION__, trs->id));
    }
    goto again;
  }

  sl_flags = 0;
  if( l & OO_TRUSTED_LOCK_NEED_POLL )
    sl_flags |= CI_EPLOCK_NETIF_NEED_POLL;
  if( l & OO_TRUSTED_LOCK_NEED_PRIME )
    sl_flags |= CI_EPLOCK_NETIF_NEED_PRIME;
  if( l & OO_TRUSTED_LOCK_RESET_STACK )
    sl_flags |= CI_EPLOCK_NETIF_RESET_STACK;
  ci_assert(sl_flags != 0);
  if( ci_cas32_succeed(&trs->trusted_lock, l, OO_TRUSTED_LOCK_LOCKED) &&
      ef_eplock_trylock_and_set_flags(&trs->netif.state->lock, sl_flags) )
    ci_netif_unlock(&trs->netif);
  goto again;
}


/* Returns true if flags were set, or false if the lock was not locked.
 * NB. We ignore flags if AWAITING_FREE.
 */
static int
oo_trusted_lock_set_flags_if_locked(tcp_helper_resource_t* trs, unsigned flags)
{
  unsigned l;

  do {
    l = trs->trusted_lock;
    if( ! (l & OO_TRUSTED_LOCK_LOCKED) )
      return 0;
    if( l & OO_TRUSTED_LOCK_AWAITING_FREE )
      /* We must not set flags when AWAITING_FREE. */
      return 1;
  } while( ci_cas32_fail(&trs->trusted_lock, l, l | flags) );

  return 1;
}


/* Returns true if the lock is obtained, or false otherwise.  In the latter
 * case the flags will be set (unless AWAITING_FREE).
 */
static int
oo_trusted_lock_lock_or_set_flags(tcp_helper_resource_t* trs, unsigned flags)
{
  unsigned l, new_l;

  do {
    l = trs->trusted_lock;
    if( l == OO_TRUSTED_LOCK_UNLOCKED )
      new_l = OO_TRUSTED_LOCK_LOCKED;
    else if( l & OO_TRUSTED_LOCK_AWAITING_FREE )
      return 0;
    else
      new_l = l | flags;
  } while( ci_cas32_fail(&trs->trusted_lock, l, new_l) );

  return l == OO_TRUSTED_LOCK_UNLOCKED;
}


/*----------------------------------------------------------------------------
 *
 * efab_tcp_helper_netif_try_lock() etc.
 *
 *---------------------------------------------------------------------------*/

int
efab_tcp_helper_netif_try_lock(tcp_helper_resource_t* trs, int in_dl_context)
{
  if( oo_trusted_lock_try_lock(trs) ) {
    ci_netif* ni = &trs->netif;
    ci_assert( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) );
    if( in_dl_context )
      ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
    if( ci_netif_trylock(&trs->netif) )
      return 1;
    oo_trusted_lock_drop(trs, in_dl_context);
  }
  return 0;
}


void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t* trs, int in_dl_context)
{
  ci_netif_unlock(&trs->netif);
  oo_trusted_lock_drop(trs, in_dl_context);
}


/* Returns 1 if the locks are held, or 0 if not and the flags are set. 
 *   
 * NB if trusted lock has OO_TRUSTED_LOCK_AWAITING_FREE this function
 * will return 0, but the flags will not be set 
 */
static int
efab_tcp_helper_netif_lock_or_set_flags(tcp_helper_resource_t* trs, 
                                        unsigned trusted_flags,
                                        unsigned untrusted_flags,
                                        int in_dl_context)
{
  do {
    if( efab_tcp_helper_netif_try_lock(trs, in_dl_context) )
      return 1;
    if( ef_eplock_set_flags_if_locked(&trs->netif.state->lock, 
                                      untrusted_flags) )
      return 0;
    if( oo_trusted_lock_set_flags_if_locked(trs, trusted_flags) )
       return 0;
  } while( 1 );
}


/*----------------------------------------------------------------------------
 *
 * tcp helpers table implementation
 *
 *---------------------------------------------------------------------------*/

static int thr_table_ctor(tcp_helpers_table_t *table)
{
  ci_dllist_init(&table->all_stacks);
  ci_dllist_init(&table->started_stacks);
  ci_irqlock_ctor(&table->lock);
  ci_id_pool_ctor(&table->instances, EFAB_THR_MAX_NUM_INSTANCES,
                  /* initial size */ 8);
  return 0;
}


static void tcp_helper_kill_stack(tcp_helper_resource_t *thr)
{
  ci_irqlock_state_t lock_flags;
  int n_dec_needed;
  int id;

  if( efab_eplock_lock_timeout(&thr->netif, msecs_to_jiffies(500)) == 0 ) {
    for( id = 0; id < thr->netif.state->n_ep_bufs; ++id ) {
      if( oo_sock_id_is_waitable(&thr->netif, id) ) {
        citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(&thr->netif, id);
        if( wo->waitable.state == CI_TCP_TIME_WAIT ||
            ci_tcp_is_timeout_ophan(&wo->tcp) )
          wo->tcp.t_last_sent = ci_ip_time_now(&thr->netif);
      }
    }
    ci_ip_timer_clear(&thr->netif, &thr->netif.state->timeout_tid);
    ci_netif_timeout_state(&thr->netif);
    ci_netif_unlock(&thr->netif);
  }

  /* If we've got the lock, we have already closed all time-wait sockets.
   * If we fail to get the lock, let's destroy the stack as-is. */

  ci_irqlock_lock(&thr->lock, &lock_flags);
  n_dec_needed = thr->n_ep_closing_refs;
  thr->n_ep_closing_refs = 0;
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  ci_assert_ge(n_dec_needed, 0);
  if( n_dec_needed > 0 ) {
    ci_log("%s: ERROR: force-kill stack [%d]: "
           "leaking %d OS sockets and filters",
           __func__, thr->id, n_dec_needed);
#ifndef NDEBUG
    tcp_helper_dump_stack(thr->id, CI_TRUE);
#endif
  }

  for( ; n_dec_needed > 0; --n_dec_needed )
    efab_tcp_helper_k_ref_count_dec(thr, 0);
}


static void thr_table_dtor(tcp_helpers_table_t *table)
{
  /* Onload is going away, so kill off any remaining stacks. */

  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t* thr;
  ci_dllink* link;
  int rc;

  ci_irqlock_lock(&table->lock, &lock_flags);

  /* Gracefully shutdown all time-wait sockets */
  while( ci_dllist_not_empty(&table->all_stacks) ) {
    link = ci_dllist_pop(&table->all_stacks);
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    ci_dllink_mark_free(&thr->all_stacks_link);

    /* Get a ref to avoid races: thr should not disappear */
    rc = efab_tcp_helper_k_ref_count_inc(thr);
    if( rc != 0 )
      continue;
    ci_irqlock_unlock(&table->lock, &lock_flags);

    if( ! (thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) )
      ci_log("%s: ERROR: non-orphaned stack=%u ref_count=%d k_ref_count=%x",
             __FUNCTION__, thr->id, oo_atomic_read(&thr->ref_count),
             thr->k_ref_count);

    OO_DEBUG_TCPH(ci_log("%s: killing stack %d", __FUNCTION__, thr->id));
    tcp_helper_kill_stack(thr);

    /* The only ref is ours.  Instead of releasing the ref, call dtor
     * directly. */
    tcp_helper_dtor(thr);
    ci_irqlock_lock(&table->lock, &lock_flags);
  }

  ci_irqlock_unlock(&table->lock, &lock_flags);
  ci_id_pool_dtor(&table->instances);
}



static
int efab_thr_table_check_name(const char* name)
{
  /* Check that there is no name collision with already-existing stacks.
   */
  tcp_helpers_table_t* table = &THR_TABLE;
  tcp_helper_resource_t *thr2;
  ci_dllink *link;

  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr2 = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( strncmp(thr2->netif.state->name, name, CI_CFG_STACK_NAME_LEN) == 0 &&
        (thr2->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) == 0 )
      return -EEXIST;
  }
  return 0;
}


int efab_thr_get_inaccessible_stack_info(unsigned id, uid_t* uid, uid_t* euid,
                                         ci_int32* share_with, char* name)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr;
  ci_dllink *link;
  int match;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    match = thr->id == id;

    if( match ) {
      *uid = thr->netif.uid;
      *euid = thr->netif.euid;
      *share_with = NI_OPTS(&thr->netif).share_with;
      memcpy(name, thr->name, sizeof(thr->name));
      ci_irqlock_unlock(&table->lock, &lock_flags);
      return 0;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return -ENODEV;
}


int efab_thr_user_can_access_stack(uid_t uid, uid_t euid,
                                   ci_netif* ni)
{
  if( /* bob and setuid-bob can access stacks created by bob or setuid-bob. */
      euid == ni->euid ||
      /* root can map any stack. */
      uid == 0 )
    return 1;

  if( /* Owner does not allow other users to map this stack. */
      NI_OPTS(ni).share_with == 0 ||
      /* Stack can be shared with another user, but not this user. */
      (NI_OPTS(ni).share_with > 0 && euid != NI_OPTS(ni).share_with) )
    return 0;

  /* By default we don't allow setuid processes to map other users' stacks,
   * because the setuid process could then be compromised.
   */
  return euid == uid || allow_insecure_setuid_sharing;
}

int efab_thr_can_access_stack(tcp_helper_resource_t* thr, int check_user)
{
  /* On entry, [check_user] tells us whether the calling code path requires
   * the user to be checked.  Some paths do not because the call is not
   * being made on behalf of a user.
   */

  if( /* We're not about to give a user access to the stack. */
     ! (check_user & EFAB_THR_TABLE_LOOKUP_CHECK_USER) )
    return 1;

  return efab_thr_user_can_access_stack(ci_getuid(), ci_geteuid(),
                                        &thr->netif);
}

/* 
 * If this returns 0 it will have taken a reference either through:
 * - efab_thr_ref(); or
 * - efab_tcp_helper_k_ref_count_inc() if it is an orphan;
 * 
 * It is up to the caller to drop the appropriate reference when safe
 * to do so.
 *
 * If you call without the EFAB_THR_TABLE_LOOKUP_NO_UL then
 * you only need to consider the efab_thr_ref() as you won't see
 * orphan stacks.  If you call with the EFAB_THR_TABLE_LOOKUP_NO_UL
 * flag then you only need to consider the
 * efab_tcp_helper_k_ref_count_inc() case as you won't see parented
 * stacks.
 */
int efab_thr_table_lookup(const char* name, unsigned id, int flags,
                          tcp_helper_resource_t** thr_p)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr;
  ci_dllink *link;
  int match, rc = -ENODEV;

  ci_assert(thr_p != NULL);
  ci_assert(flags == EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER ||
            (flags & EFAB_THR_TABLE_LOOKUP_CHECK_USER));

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    if( name )
      match = strcmp(thr->name, name) == 0;
    else
      match = thr->id == id;

    if( match ) {
      if( ! efab_thr_can_access_stack(thr, flags) ) {
        if( ! (flags & EFAB_THR_TABLE_LOOKUP_NO_WARN) )
          ci_log("User %d:%d can't share stack %d(%s) owned by %d:%d "
                 "share_with=%d", (int) ci_getuid(), (int) ci_geteuid(),
                 thr->id, thr->name, (int) thr->netif.uid,
                 (int) thr->netif.euid, NI_OPTS(&thr->netif).share_with);
        rc = -EACCES;
      }
      else if( thr->k_ref_count & TCP_HELPER_K_RC_DEAD )
        rc = -EBUSY;
      else if( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND ) {
        /* Orphan stacks */
        if( flags & EFAB_THR_TABLE_LOOKUP_NO_UL ) {
          *thr_p = thr;
          /* do not call efab_thr_ref() */
          efab_tcp_helper_k_ref_count_inc(thr);
          ci_irqlock_unlock(&table->lock, &lock_flags);
          return 0;
        }
        else
          rc = -EBUSY;
      }
      else if( flags & EFAB_THR_TABLE_LOOKUP_NO_UL ) {
        /* Caller has asked for orphan stacks, this one isn't an orphan */ 
        rc = -EBUSY;
      }
      else {
        /* Success */
        efab_thr_ref(thr);
        *thr_p = thr;
        rc = 0;
      }
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return rc;
}


int tcp_helper_dump_stack(unsigned id, unsigned orphan_only)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr = NULL;
  ci_dllink *link;
  int rc = -ENODEV;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( thr->id == id ) {
      if( orphan_only && !(thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) )
        break;
      rc = efab_tcp_helper_k_ref_count_inc(thr);
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);

  if( rc == 0 ) {
    ci_log("============================================================");
    ci_netif_dump(&thr->netif);
    ci_log("============================================================");
    ci_netif_dump_sockets(&thr->netif);
    efab_tcp_helper_k_ref_count_dec(thr, 1);
  }

  return rc;
}


static unsigned rescale(unsigned v, unsigned new_scale, unsigned old_scale)
{
  /* What we want:
   *   return (v * new_scale) / old_scale;
   *
   * Unfortunately we can overflow 32-bits, and 64-bit division is not
   * available in 32-bit x86 kernels.
   */
  while( fls(v) + fls(new_scale) > 32 ) {
    new_scale /= 2;
    old_scale /= 2;
  }
  if( old_scale == 0 )
    /* Breaks assumptions, so don't care that result is dumb. */
    old_scale = 1;
  return v * new_scale / old_scale;
}


static void tcp_helper_reduce_max_packets(ci_netif* ni, int new_max_packets)
{
  ci_assert_lt(new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_rx_packets = rescale(NI_OPTS(ni).max_rx_packets,
                                     new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_tx_packets = rescale(NI_OPTS(ni).max_tx_packets,
                                     new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_packets = new_max_packets;
  ni->state->opts.max_packets = NI_OPTS(ni).max_packets;
  ni->state->opts.max_rx_packets = NI_OPTS(ni).max_rx_packets;
  ni->state->opts.max_tx_packets = NI_OPTS(ni).max_tx_packets;
}


int tcp_helper_kill_stack_by_id(unsigned id)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr = NULL;
  ci_dllink *link;
  int rc = -ENODEV;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( thr->id == id ) {
      if( !(thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) )
        break;
      rc = efab_tcp_helper_k_ref_count_inc(thr);
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  
  if( rc == 0 ) {
    tcp_helper_kill_stack(thr);

    /* Remove reference we took in this function */
    efab_tcp_helper_k_ref_count_dec(thr, 1);
  }

  return rc;
}

void
tcp_helper_resource_assert_valid(tcp_helper_resource_t* thr, int rc_is_zero,
                                 const char *file, int line)
{
  _ci_assert(thr, file, line);
  _ci_assert_nequal(thr->id, CI_ID_POOL_ID_NONE, file, line);
  _ci_assert_equal(thr->id, thr->netif.state->stack_id, file, line);

  if (rc_is_zero >=0) {
    if ((rc_is_zero && oo_atomic_read(&thr->ref_count) > 0) ||
        (!rc_is_zero && oo_atomic_read(&thr->ref_count) == 0)) {
      ci_log("%s %d: %s check %u for %szero ref=%d", file, line,
             __FUNCTION__, thr->id, rc_is_zero ? "" : "non-",
             oo_atomic_read(&thr->ref_count));
    }
    _ci_assert(rc_is_zero || oo_atomic_read(&thr->ref_count), file, line);
  }
}


int tcp_helper_rx_vi_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return EFAB_VI_RESOURCE_INSTANCE(trs->nic[intf_i].vi_rs);
  else
    return -1;
}


int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return efrm_vi_get_hw_stack_id(trs->nic[intf_i].vi_rs);
  else
    return -1;
}


int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                           int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return efrm_vi_is_hw_rx_loopback_supported(trs->nic[intf_i].vi_rs);
  else
    return -1;
}


#if CI_CFG_PIO

# if defined(__PPC__) || !CI_CFG_USE_PIO

/* Although PPC seems to support ioremap_wc(), it's lacking
 * pgprot_writecombine() which is needed later.  So for now just
 * disable altogether on PPC.
 * 
 * PIO also needs to be disabled on 32-bit builds, so also require
 * CI_CFG_USE_PIO
 */ 
static int allocate_pio(tcp_helper_resource_t* trs, int intf_i, 
                        struct efrm_pd *pd, struct efhw_nic* nic,
                        unsigned *pio_buf_offset)
{
  ci_netif* ni = &trs->netif;
  int rc;
  static int printed = 0;

  if( NI_OPTS(ni).pio == 1 ) {
    if( !printed ) {
      ci_log("PIO not supported on this system, will continue without it");
      printed = 1;
    }
    rc = 0;
  }
  else {
    /* EF_PIO == 2 => fail if no PIO */
    ci_log("[%s] ERROR: PIO not supported on this system", 
           ni->state->pretty_name);
    rc = -EINVAL;
  }

  return rc;
}

# else

static int allocate_pio(tcp_helper_resource_t* trs, int intf_i, 
                        struct efrm_pd *pd, struct efhw_nic* nic,
                        unsigned *pio_buf_offset)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
  ci_netif_nic_t *netif_nic = &trs->netif.nic_hw[intf_i];
  struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
  int rc = 0;

  if( trs_nic->pio_rs == NULL ) {
    rc = efrm_pio_alloc(pd, &trs_nic->pio_rs);
    if( rc < 0 ) {
      if( NI_OPTS(ni).pio == 1 ) {
        if( rc == -ENOSPC ) {
          ci_log("[%s]: WARNING: all PIO bufs allocated to other stacks. "
                 "Continuing without PIO.  Use EF_PIO to control this.",
                 ns->pretty_name);
          return 0;
        }
        else {
          ci_log("[%s]: Unable to alloc PIO (%d), will continue without it",
                 ns->pretty_name, rc);
          return 0;
        }
      }
      else {
        OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pio_alloc(%d) failed %d",
                             __FUNCTION__, intf_i, rc));
        return rc;
      }
    }
  }

  /* efrm_pio_alloc() success */
  rc = efrm_pio_link_vi(trs_nic->pio_rs, trs_nic->vi_rs);
  if( rc < 0 ) {
    efrm_pio_release(trs_nic->pio_rs);
    trs_nic->pio_rs = NULL;
    if( NI_OPTS(ni).pio == 1 ) {
      ci_log("[%s]: Unable to link PIO (%d), will continue without it", 
             ns->pretty_name, rc);
      return 0;
    }
    else {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pio_link_vi(%d) failed %d",
                           __FUNCTION__, intf_i, rc));
      return rc;
    }
  }
   
  /* efrm_pio_link_vi() success */
  rc = efrm_pio_map_kernel(nic, trs_nic->vi_rs, 
                           (void**)&netif_nic->pio.pio_io);
  if( rc < 0 ) {
    efrm_pio_unlink_vi(trs_nic->pio_rs, trs_nic->vi_rs);
    efrm_pio_release(trs_nic->pio_rs);
    trs_nic->pio_rs = NULL;
    if( NI_OPTS(ni).pio == 1 ) {
      ci_log("[%s]: Unable to kmap PIO (%d), will continue without it", 
             ns->pretty_name, rc);
      return 0;
    }
    else {
      OO_DEBUG_VM(ci_log("%s: ERROR: efrm_pio_map_kernel(%d) failed %d",
                         __FUNCTION__, intf_i, rc));
      return rc;
    }
  } 

  /* efrm_pio_map_kernel() success */
  /* Set up the pio struct so we can call ef_vi_pio_memcpy */
  netif_nic->pio.pio_buffer = 
    (uint8_t*)ns + ns->pio_bufs_ofs + *pio_buf_offset;
  netif_nic->pio.pio_len = efrm_pio_get_size(trs_nic->pio_rs);
  /* Advertise that PIO can be used on this VI */
  nsn->oo_vi_flags |= OO_VI_FLAGS_PIO_EN;
  /* Advertise how should be mapped for this VI */
  ci_assert_le(netif_nic->pio.pio_len, CI_PAGE_SIZE);
  nsn->pio_io_mmap_bytes = CI_PAGE_SIZE;
  /* and how much of that mapping is usable */
  nsn->pio_io_len = netif_nic->pio.pio_len;
  /* and record a copy that UL can't modify */
  trs_nic->pio_io_mmap_bytes = nsn->pio_io_mmap_bytes;
  netif_nic->vi.linked_pio = &netif_nic->pio;
  trs->pio_mmap_bytes += CI_PAGE_SIZE;
  *pio_buf_offset += efrm_pio_get_size(trs_nic->pio_rs);
  /* Drop original ref to PIO region as linked VI now holds it */ 
  efrm_pio_release(trs_nic->pio_rs);
  /* Initialise the buddy allocator for the PIO region. */
  ci_pio_buddy_ctor(ni, &nsn->pio_buddy);

  return 0;
}

# endif /* PPC / __x86_64__ */

#endif /* CI_CFG_PIO */


/* Evaluates whether timestamping is to be enabled
 * based on respective netif options and NIC architecture.
 */
static int
check_timestamping_support(const char* stack_name, const char* dir,
                           int user_val, int arch,
                           int* out_try_ts, int* out_retry_without)
{
  const int device_supports_ts = arch == EFHW_ARCH_EF10;

  *out_try_ts = (user_val != 0);
  *out_retry_without = 0;
  if( ! device_supports_ts && (user_val == 3) ) {
    ci_log(
        "[%s]: %s timestamping not supported on given interface",
        stack_name, dir);
    return -ENOENT;
  }
  if( ! device_supports_ts && (user_val == 2) ) {
    ci_log(
      "[%s]: %s timestamping not supported on given interface, "
      "continuing with timestamping disabled on this particular interface",
      stack_name, dir);
    *out_try_ts = 0;
  }
  if( user_val == 1 ) {
    *out_retry_without = 1; /* in case alloc fails do retry without ts*/
  }
  return 0;
}

/* Updates value of parameters:
 * ef_vi_flags, efhw_vi_flags, oo_vi_flags
 */
static void
get_timestamping_flags(int rx_ts, int tx_ts,
                       enum ef_vi_flags* ef_vi_flags_out,
                       ci_uint32* efhw_vi_flags_out, int* oo_vi_flags_out)
{
  if( rx_ts ) {
    *ef_vi_flags_out |= EF_VI_RX_TIMESTAMPS;
    *efhw_vi_flags_out |= EFHW_VI_RX_TIMESTAMPS | EFHW_VI_RX_PREFIX;
    *oo_vi_flags_out |= OO_VI_FLAGS_RX_HW_TS_EN;
  } else {
    *ef_vi_flags_out &= ~EF_VI_RX_TIMESTAMPS;
    *efhw_vi_flags_out &= ~(EFHW_VI_RX_TIMESTAMPS | EFHW_VI_RX_PREFIX);
    *oo_vi_flags_out &= ~OO_VI_FLAGS_RX_HW_TS_EN;
  }
  if( tx_ts ) {
    *ef_vi_flags_out |= EF_VI_TX_TIMESTAMPS;
    *efhw_vi_flags_out |= EFHW_VI_TX_TIMESTAMPS;
    *oo_vi_flags_out |= OO_VI_FLAGS_TX_HW_TS_EN;
  } else {
    *ef_vi_flags_out &= ~EF_VI_TX_TIMESTAMPS;
    *efhw_vi_flags_out &= ~EFHW_VI_TX_TIMESTAMPS;
    *oo_vi_flags_out &= ~OO_VI_FLAGS_TX_HW_TS_EN;

  }
}


static int allocate_vi(tcp_helper_resource_t* trs,
                       unsigned evq_sz, ci_resource_onload_alloc_t* alloc,
                       void* vi_state, unsigned vi_state_bytes,
                       tcp_helper_cluster_t* thc)
{
  /* Format is "onload:pretty_name-intf_i"
   * Do not use slash in this name! */
  char vf_name[7 + CI_CFG_STACK_NAME_LEN+8 + 3];
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  enum ef_vi_flags vi_flags;
  ci_uint32 in_flags;
  int rc, intf_i;
  ci_uint32 txq_capacity = 0, rxq_capacity = 0;
  const char* pci_dev_name;
#ifdef CONFIG_SFC_RESOURCE_VF
  struct efrm_vf *first_vf = NULL;
#endif
#if CI_CFG_PIO
  unsigned pio_buf_offset = 0;
#endif

  /* The array of nic_hw is potentially sparse, but the memory mapping
   * is not, so we keep a count to calculate offsets rather than use
   * nic_index */

  vi_flags = 0;
  in_flags = EFHW_VI_JUMBO_EN;

  if( ! NI_OPTS(ni).tx_push )
    vi_flags |= EF_VI_TX_PUSH_DISABLE;

  txq_capacity = NI_OPTS(ni).txq_size;
  rxq_capacity = NI_OPTS(ni).rxq_size;
  ns->vi_mem_mmap_offset = trs->buf_mmap_bytes;
  ns->vi_io_mmap_offset = trs->io_mmap_bytes;
#if CI_CFG_PIO
  ns->pio_io_mmap_offset = trs->pio_mmap_bytes;
#endif

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    trs->nic[intf_i].vi_rs = NULL;
    trs->nic[intf_i].vi_mem_mmap_bytes = 0;
#if CI_CFG_PIO
    trs->nic[intf_i].pio_rs = NULL;
    trs->nic[intf_i].pio_io_mmap_bytes = 0;
#endif
  }

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
    struct efhw_nic* nic = efrm_client_get_nic(trs_nic->oo_nic->efrm_client);
    struct efrm_vi_mappings* vm;
    struct efrm_vf *vf = NULL;
    struct efrm_pd *pd = NULL;
    struct efrm_vi_set* vi_set = NULL;
    struct ef_vi* vi;
    uint32_t* vi_ids;
    int release_pd = 0;
    enum efrm_vi_alloc_failure error_reason;
    int try_rx_ts, try_tx_ts, retry_without_rx_ts, retry_without_tx_ts;

    ci_assert(trs_nic->vi_rs == NULL);
    ci_assert(trs_nic->oo_nic != NULL);
    ci_assert(trs_nic->oo_nic->efrm_client != NULL);

    snprintf(vf_name, sizeof(vf_name), "onload:%s-%d",
             ns->pretty_name, intf_i);

#if CI_CFG_UDP
    if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
        (NI_OPTS(ni).mcast_recv_hw_loop) ) {
      in_flags |= EFHW_VI_RX_LOOPBACK;
    } else {
      in_flags &= ~EFHW_VI_RX_LOOPBACK;
    }
    if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
        (NI_OPTS(ni).mcast_send & CITP_MCAST_SEND_FLAG_EXT) ) {
      vi_flags |= EF_VI_TX_LOOPBACK;
      in_flags |= EFHW_VI_TX_LOOPBACK;
      nsn->oo_vi_flags |= OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
    } else {
      vi_flags &= ~EF_VI_TX_LOOPBACK;
      in_flags &= ~EFHW_VI_TX_LOOPBACK;
      nsn->oo_vi_flags &= ~OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
    }
#endif

    switch( NI_OPTS(ni).packet_buffer_mode ) {
    case 0:
      if( nic->devtype.arch == EFHW_ARCH_EF10 )
        trs->avoid_atomic_allocations = 1;
      break;

    case CITP_PKTBUF_MODE_VF:
    case CITP_PKTBUF_MODE_VF | CITP_PKTBUF_MODE_PHYS:
#ifndef CONFIG_SFC_RESOURCE_VF
      rc = -ENODEV;
      goto error_out;
#else
      rc = efrm_vf_resource_alloc(trs_nic->oo_nic->efrm_client, first_vf,
                                  !(NI_OPTS(ni).packet_buffer_mode &
                                    CITP_PKTBUF_MODE_PHYS),
                                  &vf);
      if( rc < 0 ) {
        OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vf_resource_alloc(%d) failed %d",
                             __FUNCTION__, intf_i, rc));
        goto error_out;
      }
      ci_assert(vf);

      if( first_vf == NULL ) {
        first_vf = vf;
        trs->avoid_atomic_allocations = efrm_vf_avoid_atomic_allocations;
      }

      /* FALLTHROUGH - all VF modes are phys modes from the internal
       * point of view */
#endif

    case CITP_PKTBUF_MODE_PHYS:
      vi_flags |= EF_VI_RX_PHYS_ADDR | EF_VI_TX_PHYS_ADDR;
      break;
    }

    if( thc == NULL ) {
      rc = efrm_pd_alloc(&pd, trs_nic->oo_nic->efrm_client, vf,
                         !!(vi_flags & EF_VI_RX_PHYS_ADDR));
#ifdef CONFIG_SFC_RESOURCE_VF
      if( vf != NULL )
        efrm_vf_resource_release(vf); /* pd keeps a ref to vf */
#endif
      if( rc != 0 ) {
        OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pd_alloc(%d) failed %d",
                           __FUNCTION__, intf_i, rc));
        goto error_out;
      }
      ci_assert(pd);
      release_pd = 1;
      vi_set = NULL;
    }
    else {
      vi_set = thc->thc_vi_set[intf_i];
      release_pd = 0;
      pd = efrm_vi_set_get_pd(vi_set);
    }

    nsn->oo_vi_flags = 0;
    rc = check_timestamping_support(ni->state->pretty_name, "RX",
                                    NI_OPTS(ni).rx_timestamping,
                                    nic->devtype.arch, &try_rx_ts,
                                    &retry_without_rx_ts);
    if( rc != 0 ) {
      efrm_pd_release(pd);
      goto error_out;
    }
    rc = check_timestamping_support(ni->state->pretty_name, "TX",
                                    NI_OPTS(ni).tx_timestamping,
                                    nic->devtype.arch, &try_tx_ts,
                                    &retry_without_tx_ts);
    if( rc != 0 ) {
      efrm_pd_release(pd);
      goto error_out;
    }
again:
    get_timestamping_flags(try_rx_ts, try_tx_ts,
                           &vi_flags, &in_flags, &nsn->oo_vi_flags);
    rc = efrm_vi_resource_alloc(trs_nic->oo_nic->efrm_client,
                                NULL, vi_set, -1, pd, vf_name, in_flags,
                                evq_sz, txq_capacity, rxq_capacity, 0, 0, 
                                NI_OPTS(ni).irq_core, NI_OPTS(ni).irq_channel,
                                &trs_nic->vi_rs, &nsn->vi_io_mmap_bytes,
                                &nsn->vi_mem_mmap_bytes, NULL, NULL,
                                &error_reason);
    if( rc != 0 && try_rx_ts && retry_without_rx_ts &&
        (error_reason == EFRM_VI_ALLOC_RXQ_FAILED ||
         error_reason == EFRM_VI_ALLOC_EVQ_FAILED) ) {
      ci_log(
          "[%s]: enabling RX timestamping on given interface failed, continuing"
          " with RX timestamping disabled on this particular interface",
          ni->state->pretty_name);
      try_rx_ts = 0;
      goto again;
    }
    if( rc != 0 && try_tx_ts && retry_without_tx_ts &&
        (error_reason == EFRM_VI_ALLOC_TXQ_FAILED ||
         error_reason == EFRM_VI_ALLOC_EVQ_FAILED) ) {
      ci_log(
          "[%s]: enabling TX timestamping on given interface failed, continuing"
          " with TX timestamping disabled on this particular interface",
          ni->state->pretty_name);
      try_tx_ts = 0;
      goto again;
    }
    if( rc < 0 ) {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vi_resource_alloc(%d) failed %d",
                           __FUNCTION__, intf_i, rc));
      if( release_pd )
        efrm_pd_release(pd);
      goto error_out;
    }

    nsn->pd_owner = efrm_pd_owner_id(pd);

    pci_dev_name = pci_name(efrm_vi_get_pci_dev(trs_nic->vi_rs));
    strncpy(nsn->pci_dev, pci_dev_name, sizeof(nsn->pci_dev));
    nsn->pci_dev[sizeof(nsn->pci_dev) - 1] = '\0';
    trs_nic->vi_mem_mmap_bytes = nsn->vi_mem_mmap_bytes;
    nsn->vi_instance = (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(trs_nic->vi_rs);
    nsn->vi_arch = (ci_uint8) nic->devtype.arch;
    nsn->vi_variant = (ci_uint8) nic->devtype.variant;
    nsn->vi_revision = (ci_uint8) nic->devtype.revision;

    vi = &(ni->nic_hw[intf_i].vi);
    vi_ids = (void*) ((ef_vi_state*) vi_state + 1);
    BUILD_BUG_ON(sizeof(ni->vi_data) < sizeof(struct efrm_vi_mappings));
    vm = (void*) ni->vi_data;
    efrm_vi_get_mappings(trs_nic->vi_rs, vm);
    ef_vi_init(vi, nsn->vi_arch, nsn->vi_variant,
               nsn->vi_revision, vi_flags, (ef_vi_state*) vi_state);
    nsn->vi_out_flags = (vm->out_flags & EFHW_VI_CLOCK_SYNC_STATUS) ?
                          EF_VI_OUT_CLOCK_SYNC_STATUS : 0;
    ef_vi_init_out_flags( vi, nsn->vi_out_flags);
    ef_vi_init_io(vi, vm->io_page);
    ef_vi_init_timer(vi, vm->timer_quantum_ns);
    ef_vi_init_evq(vi, vm->evq_size, vm->evq_base);
    ef_vi_init_rxq(vi, vm->rxq_size, vm->rxq_descriptors, vi_ids, vm->rxq_prefix_len);
    vi_ids += vm->rxq_size;
    ef_vi_init_txq(vi, vm->txq_size, vm->txq_descriptors, vi_ids);
    ef_vi_init_state(&ni->nic_hw[intf_i].vi);
    ef_vi_set_stats_buf(&ni->nic_hw[intf_i].vi, &ni->state->vi_stats);

#if CI_CFG_PIO
    if( NI_OPTS(ni).pio && (nic->devtype.arch == EFHW_ARCH_EF10) ) {
      rc = allocate_pio(trs, intf_i, pd, nic, &pio_buf_offset);
      if( rc < 0 ) {
        efrm_pd_release(pd);
        goto error_out;
      }
    }
#endif

    if( release_pd )
      efrm_pd_release(pd); /* vi keeps a ref to pd */

    vi_state = (char*) vi_state + vi_state_bytes;
    if( txq_capacity || rxq_capacity )
      ef_vi_add_queue(&ni->nic_hw[intf_i].vi, &ni->nic_hw[intf_i].vi);
    nsn->vi_flags = vi_flags;
    nsn->vi_evq_bytes = efrm_vi_rm_evq_bytes(trs_nic->vi_rs, -1);
    nsn->vi_rxq_size = vm->rxq_size;
    nsn->vi_txq_size = vm->txq_size;
    nsn->timer_quantum_ns = vm->timer_quantum_ns;
    nsn->rx_prefix_len = vm->rxq_prefix_len;
    nsn->rx_ts_correction = vm->rx_ts_correction;
    trs->buf_mmap_bytes += efab_vi_resource_mmap_bytes(trs_nic->vi_rs, 1);
    trs->io_mmap_bytes += efab_vi_resource_mmap_bytes(trs_nic->vi_rs, 0);

    efrm_vi_irq_moderate(trs_nic->vi_rs, NI_OPTS(ni).irq_usec);
    if( NI_OPTS(ni).irq_core >= 0 &&
        (NI_OPTS(ni).packet_buffer_mode & CITP_PKTBUF_MODE_VF) ) {
      rc = efrm_vi_irq_affinity(trs_nic->vi_rs, NI_OPTS(ni).irq_core);
      if( rc < 0 )
        OO_DEBUG_ERR(ci_log("%s: ERROR: failed to set irq affinity to %d "
                            "of %d", __FUNCTION__, (int) NI_OPTS(ni).irq_core,
                            num_online_cpus()));
    }

    if( NI_OPTS(ni).tx_push )
      ef_vi_set_tx_push_threshold(&ni->nic_hw[intf_i].vi, 
                                  NI_OPTS(ni).tx_push_thresh);
  }

  OO_DEBUG_RES(ci_log("%s: done", __FUNCTION__));

  return 0;

error_out:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( trs->nic[intf_i].vi_rs ) {
      efrm_vi_resource_release(trs->nic[intf_i].vi_rs);
      trs->nic[intf_i].vi_rs = NULL;
    }
  return rc;
}


static void vi_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}

static void release_pkts(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  unsigned i;
  int intf_i;

  /* Release packets */
  for (i = 0; i < ni->pkt_sets_n; i++) {
    ci_assert(ni->buf_pages[i]);
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      oo_iobufset_resource_release(ni->nic_hw[intf_i].pkt_rs[i]);
    oo_iobufset_pages_release(ni->buf_pages[i]);
  }

  /* Now release everything allocated in allocate_netif_hw_resources. */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_free(ni->nic_hw[intf_i].pkt_rs);
  ci_free(ni->buf_pages);

#ifdef OO_DO_HUGE_PAGES
  ci_vfree(trs->pkt_shm_id);
#endif
}

static void release_vi(tcp_helper_resource_t* trs)
{
  int intf_i;
  struct completion flush_completion[CI_CFG_MAX_INTERFACES];

  /* Flush vis first to ensure our bufs won't be used any more */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    init_completion(&flush_completion[intf_i]);
    efrm_vi_register_flush_callback(trs->nic[intf_i].vi_rs,
                                    &vi_complete,
                                    &flush_completion[intf_i]);
    efrm_vi_resource_stop_callback(trs->nic[intf_i].vi_rs);
  }
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    wait_for_completion(&flush_completion[intf_i]);

  /* Once all vis are flushed we can release pkt memory */
  release_pkts(trs);

  /* Now do the rest of vi release */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
#if CI_CFG_PIO
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_nic_t *netif_nic = &trs->netif.nic_hw[intf_i];
    if( NI_OPTS(&trs->netif).pio &&
        (efrm_client_get_nic(trs_nic->oo_nic->efrm_client)->devtype.arch ==
         EFHW_ARCH_EF10) && 
        (trs_nic->pio_io_mmap_bytes != 0) ) {
      efrm_pio_unmap_kernel(trs_nic->vi_rs, (void*)netif_nic->pio.pio_io);
      ci_pio_buddy_dtor(&trs->netif, &trs->netif.state->nic[intf_i].pio_buddy);
    }
#endif
    efrm_vi_resource_release_flushed(trs->nic[intf_i].vi_rs);
    trs->nic[intf_i].vi_rs = NULL;
    CI_DEBUG_ZERO(&trs->netif.nic_hw[intf_i].vi);
  }

  if( trs->thc != NULL )
    tcp_helper_cluster_release(trs->thc, trs);
}


static int
allocate_netif_resources(ci_resource_onload_alloc_t* alloc,
                         tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns;
  int i, sz, rc, no_table_entries, synrecv_ofs;
  unsigned vi_state_bytes;
#if CI_CFG_PIO
  unsigned pio_bufs_ofs = 0;
#endif

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  trs->mem_mmap_bytes = 0;
  trs->io_mmap_bytes = 0;
#if CI_CFG_PIO
  trs->pio_mmap_bytes = 0;
#endif
  trs->buf_mmap_bytes = 0;

  no_table_entries = NI_OPTS(ni).max_ep_bufs * 2;

  /* Find size of netif state to allocate. */
  vi_state_bytes = ef_vi_calc_state_bytes(NI_OPTS(ni).rxq_size,
                                          NI_OPTS(ni).txq_size);

  /* allocate shmbuf for netif state */
  ci_assert_le(NI_OPTS(ni).max_ep_bufs, CI_CFG_NETIF_MAX_ENDPOINTS_MAX);
  sz = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n +
    sizeof(ci_netif_filter_table) +
    sizeof(ci_netif_filter_table_entry) * (no_table_entries - 1);

#if CI_CFG_PIO
  /* Allocate shmbuf for pio regions.  We haven't tried to allocate
   * PIOs yet and we don't know how many ef10s we have.  So just
   * reserve space for each available interface and waste the
   * remainder of the memory.
   */
  if( NI_OPTS(ni).pio ) {
    pio_bufs_ofs = sz;
    sz += 2048 * oo_stack_intf_max(ni);
  }
#endif

  /* Allocate the synrecv buffs */
  synrecv_ofs = sz;
  sz += sizeof (ci_tcp_state_synrecv) * NI_OPTS(ni).tcp_backlog_max;

  sz = CI_ROUND_UP(sz, CI_PAGE_SIZE);

  rc = ci_contig_shmbuf_alloc(&ni->state_buf, sz);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to alloc state_buf (%d)", rc));
    goto fail1;
  }
  memset(ci_contig_shmbuf_ptr(&ni->state_buf), 0,
         ci_contig_shmbuf_size(&ni->state_buf));

#ifdef CI_HAVE_OS_NOPAGE
  i = (NI_OPTS(ni).max_ep_bufs + EP_BUF_PER_PAGE - 1) / EP_BUF_PER_PAGE *
    CI_PAGE_SIZE;
  rc = ci_shmbuf_alloc(&ni->pages_buf, i);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to alloc pages buf (%d)", rc));
    goto fail2;
  }
#else
  i = (NI_OPTS(ni).max_ep_bufs + EP_BUF_BLOCKNUM-1) >> EP_BUF_BLOCKSHIFT; 
  ni->k_shmbufs = ci_alloc(sizeof(ci_shmbuf_t *) * i);
  if( ! ni->k_shmbufs ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory at %d", __FUNCTION__, __LINE__));
    rc = -ENOMEM;
    goto fail2;
  }
  memset(ni->k_shmbufs, 0, sizeof(ni->k_shmbufs[0]) * i);
  ni->k_shmbufs_n = 0;
#endif

  ns = ni->state = (ci_netif_state*) ci_contig_shmbuf_ptr(&ni->state_buf);
  memset(ns, 0, synrecv_ofs);
  CI_DEBUG(ns->flags |= CI_NETIF_FLAG_DEBUG);

#ifdef CI_HAVE_OS_NOPAGE
  ns->netif_mmap_bytes =
    ci_contig_shmbuf_size(&ni->state_buf) + ci_shmbuf_size(&ni->pages_buf);
#else
  ns->netif_mmap_bytes =
    ci_contig_shmbuf_size(&ni->state_buf);
#endif

  ns->stack_id = trs->id;
  ns->ep_ofs = ni->ep_ofs = sz;
#if CI_CFG_PIO
  ns->pio_bufs_ofs = pio_bufs_ofs;
#endif
  ns->synrecv_ofs = synrecv_ofs;
  ns->n_ep_bufs = 0;
  ns->nic_n = trs->netif.nic_n;

  /* An entry in intf_i_to_hwport should not be touched if the intf does
   * not exist.  Belt-and-braces: initialise to 0.
   */
  memset(ns->intf_i_to_hwport, 0, sizeof(ns->intf_i_to_hwport));
  memcpy(ns->hwport_to_intf_i, ni->hwport_to_intf_i,
         sizeof(ns->hwport_to_intf_i));
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    if( ns->hwport_to_intf_i[i] >= 0 )
      ns->intf_i_to_hwport[(int) ns->hwport_to_intf_i[i]] = i;

  ns->table_ofs = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n;
  ns->vi_state_bytes = vi_state_bytes;

  ni->filter_table = (void*) ((char*) ns + ns->table_ofs);

  /* Initialize the free list of synrecv bufs */
  ns->free_synrecvs = OO_P_NULL;
  for( i = 0; i < (int) NI_OPTS(ni).tcp_backlog_max; ++i ) {
    ci_tcp_state_synrecv* tsr = (ci_tcp_state_synrecv*)
      ((char*) ns + ns->synrecv_ofs) + i;
    ci_ni_dllist_link_init(ni, &tsr->link,
                           oo_ptr_to_statep(ni, &tsr->link), "fsyn");
    ci_tcp_synrecv_free(ni, tsr);
  }

  /* The shared netif-state buffer and EP buffers are part of the mem mmap */
  trs->mem_mmap_bytes += ns->netif_mmap_bytes;
  OO_DEBUG_MEMSIZE(ci_log(
	"added %d (0x%x) bytes for shared netif state and ep buffers, "
	"reached %d (0x%x)", ns->netif_mmap_bytes, ns->netif_mmap_bytes,
	trs->mem_mmap_bytes, trs->mem_mmap_bytes));

  if( trs->name[0] == '\0' )
    snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d", ns->stack_id);
  else
    snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d,%s",
             ns->stack_id, trs->name);

  /* Allocate an eplock resource. */
  rc = eplock_ctor(ni);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate EPLOCK (%d)", rc));
    goto fail3;
  }
  ni->state->lock.lock = CI_EPLOCK_LOCKED;

  /* Get the initial IP ID range */
  rc = ci_ipid_ctor(ni, (ci_fd_t)-1);
  if (rc < 0) {
    goto fail4;
  }

  ci_waitq_ctor(&trs->pkt_waitq);

  return 0;

 fail4:
  eplock_dtor(ni);
 fail3:
#ifdef CI_HAVE_OS_NOPAGE
  ci_shmbuf_free(&ni->pages_buf);
#else
  /* Can we have allocated these yet?  Let's try to free things anyway */
  for( i = 0; i < (int)ni->k_shmbufs_n; ++i ) {
    ci_shmbuf_free(ni->k_shmbufs[i]);
    ci_free(ni->k_shmbufs[i]);
  }
  ci_free(ni->k_shmbufs);
#endif
 fail2:
  ci_contig_shmbuf_free(&ni->state_buf);
 fail1:
  LOG_NC(ci_log("failed to allocate tcp_helper resources (%d)", rc));
  return rc;
}

static int
allocate_netif_hw_resources(ci_resource_onload_alloc_t* alloc,
                            tcp_helper_cluster_t* thc,
                            tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int sz, rc;
  int intf_i;
  unsigned evq_min, evq_sz;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  /* Choose DMA queue sizes, and calculate suitable size for EVQ. */
  evq_min = NI_OPTS(ni).rxq_size + NI_OPTS(ni).txq_size;
  for( evq_sz = 512; evq_sz <= evq_min; evq_sz *= 2 )
    ;

  rc = allocate_vi(trs, evq_sz, alloc, ns + 1, ns->vi_state_bytes, thc);
  if( rc < 0 )  goto fail1;

  if( NI_OPTS(ni).max_packets > max_packets_per_stack ) {
    OO_DEBUG_ERR(ci_log("WARNING: EF_MAX_PACKETS reduced from %d to %d due to "
                        "max_packets_per_stack module option",
                        NI_OPTS(ni).max_packets, max_packets_per_stack));
    tcp_helper_reduce_max_packets(ni, max_packets_per_stack);
  }

  ni->pkt_sets_n = 0;
  ni->pkt_sets_max =
    (NI_OPTS(ni).max_packets + PKTS_PER_SET - 1) >> CI_CFG_PKTS_PER_SET_S;
  ns->pkt_sets_max = ni->pkt_sets_max;
  ns->pkt_sets_n = 0;
  ns->n_pkts_allocated = 0;

#ifdef OO_DO_HUGE_PAGES
  /* Reserve space for I/O buffers */
  ns->buf_ofs = trs->buf_mmap_bytes;
  ci_assert_equal((ns->buf_ofs & (CI_PAGE_SIZE - 1)), 0);
  sz = ni->pkt_sets_max * sizeof(trs->pkt_shm_id[0]);
  if ( sz & (PAGE_SIZE - 1) )
    sz = ((sz >> PAGE_SHIFT) + 1) << PAGE_SHIFT;
  trs->buf_mmap_bytes += sz;
  trs->pkt_shm_id = ci_vmalloc(sz);
  if( trs->pkt_shm_id == NULL ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate pkt_shm_id"));
    goto fail3;
  }
  memset(trs->pkt_shm_id, 0xff, sz);
#elif CI_CFG_PKTS_AS_HUGE_PAGES
  ns->buf_ofs = (ci_uint32)-1; /* this is our way to tell UL that there are
                                  no huge pages here */
  trs->pkt_shm_id = NULL;
#endif

  sz = sizeof(struct oo_iobufset*) * ni->pkt_sets_max;
  if( (ni->buf_pages = ci_alloc(sz)) == NULL ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate iobufset table"));
    rc = -ENOMEM;
    goto fail4;
  }
  memset(ni->buf_pages, 0, sz);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].pkt_rs = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( (ni->nic_hw[intf_i].pkt_rs = ci_alloc(sz)) == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: failed to allocate iobufset tables",
                          __FUNCTION__));
      goto fail5;
    }
    memset(ni->nic_hw[intf_i].pkt_rs, 0, sz);
  }

  /* initialize NIC from driver data */
  cicp_ni_sethandle(&ni->cplane, &CI_GLOBAL_CPLANE);
  trs->mem_mmap_bytes += cicp_ns_map(&ns->control_mmap,
                                     CICP_HANDLE(ni));
  OO_DEBUG_MEMSIZE(ci_log("added %ld (0x%lx) bytes for global cplane, "
		       "reached %d (0x%x)",
                      (unsigned long) cicp_ns_map(&ns->control_mmap,
						  CICP_HANDLE(ni)),
                      (unsigned long) cicp_ns_map(&ns->control_mmap,
						  CICP_HANDLE(ni)),
		       trs->mem_mmap_bytes, trs->mem_mmap_bytes));

  /* Advertise the size of the IO and buf mmap that needs to be performed. */
  ns->io_mmap_bytes = trs->io_mmap_bytes;
  ns->buf_mmap_bytes = trs->buf_mmap_bytes;
#if CI_CFG_PIO
  ns->pio_mmap_bytes = trs->pio_mmap_bytes;
#endif

  OO_DEBUG_MEMSIZE(ci_log("helper=%u map_bytes=%u (0x%x)",
                          trs->id,
                          trs->mem_mmap_bytes, trs->mem_mmap_bytes));
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    LOG_NC(ci_log("VI=%d", ef_vi_instance(&ni->nic_hw[intf_i].vi)));

  /* Apply pacing value. */
  if( NI_OPTS(ni).tx_min_ipg_cntl != 0 )
    tcp_helper_pace(trs, NI_OPTS(ni).tx_min_ipg_cntl);

  /* This is needed because release_netif_hw_resources() tries to free the ep
  ** table. */
  ni->ep_tbl = 0;

  return 0;

 fail5:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ni->nic_hw[intf_i].pkt_rs )
      ci_free(ni->nic_hw[intf_i].pkt_rs);
  ci_free(ni->buf_pages);
 fail4:
#ifdef OO_DO_HUGE_PAGES
  ci_vfree(trs->pkt_shm_id);
 fail3:
#endif
  release_vi(trs);
 fail1:
  return rc;
}


static void
release_ep_tbl(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;
  if( ni->ep_tbl != NULL ) {
    for( i = 0; i < ni->ep_tbl_n; ++i ) {
#if CI_CFG_USERSPACE_PIPE
      /* skip buffers which were not filled */
      if( ! ni->ep_tbl[i] )
        continue;
#else
      ci_assert(ni->ep_tbl[i]);
#endif
      tcp_helper_endpoint_dtor(ni->ep_tbl[i]);
      ci_free(ni->ep_tbl[i]);
      CI_DEBUG(ni->ep_tbl[i] = 0);
    }
    ci_vfree(ni->ep_tbl);
  }
}


static void
release_netif_resources(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  ci_waitq_dtor(&trs->pkt_waitq);
  ci_ipid_dtor(ni, (ci_fd_t)-1);
  eplock_dtor(ni);

#ifdef CI_HAVE_OS_NOPAGE
  ci_shmbuf_free(&ni->pages_buf);
#else
  for( i = 0; i < ni->k_shmbufs_n; ++i ) {
    ci_shmbuf_free(ni->k_shmbufs[i]);
    ci_free(ni->k_shmbufs[i]);
  }
  ci_free(ni->k_shmbufs);
#endif
  ci_contig_shmbuf_free(&ni->state_buf);
}
static void
release_netif_hw_resources(tcp_helper_resource_t* trs)
{

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  /* do this first because we currently we may find filters still installed
   * - leaving them install doesn't only leak resources, it leaves the NET
   *   driver software filtering open to duplicates
   * - for now we deinstall the filters in the destructor of the TCP EP
   */
  release_ep_tbl(trs);

  release_vi(trs);
}


static int oo_version_check(ci_resource_onload_alloc_t* alloc)
{
  int ver_chk_bad, intf_chk_bad;
  int rc = 0;

  alloc->in_version[sizeof(alloc->in_version) - 1] = '\0';
  ver_chk_bad = strcmp(alloc->in_version, ONLOAD_VERSION);

  alloc->in_uk_intf_ver[sizeof(alloc->in_uk_intf_ver) - 1] = '\0';
  intf_chk_bad = strcmp(alloc->in_uk_intf_ver, oo_uk_intf_ver);

  if( ver_chk_bad ) {
    ci_log("ERROR: user/driver version mismatch");
    ci_log("  user-version: %s", alloc->in_version);
    ci_log("  driver-version: %s", ONLOAD_VERSION);
    rc = -ELIBACC;
  }
  if( intf_chk_bad ) {
    ci_log("ERROR: user/driver interface mismatch");
    ci_log("  user-interface: %s", alloc->in_uk_intf_ver);
    ci_log("  driver-interface: %s", oo_uk_intf_ver);
    rc = -ELIBACC;
  }
  if( rc != 0 )
    ci_log("HINT: Most likely you need to reload the sfc and onload drivers");

  return rc;
}


/* This function is used to retrive the list of currently active SF
 * interfaces.
 *
 * If ifindices_len > 0, the function is not implemented and returns
 * error.
 *
 * If ifindices_len == 0, then the function performs some
 * initialisation and debug checks.  This is useful for creating
 * stacks without HW (e.g. TCP loopback).
 *
 * If ifindices_len < 0, then the function will autodetect all
 * available SF interfaces based on the cplane information.
 */
static int oo_get_nics(tcp_helper_resource_t* trs, int ifindices_len)
{
  ci_netif* ni = &trs->netif;
  struct oo_nic* onic;
  int rc, i, intf_i;

  efrm_nic_set_clear(&ni->nic_set);
  trs->netif.nic_n = 0;

  if( ifindices_len > CI_CFG_MAX_INTERFACES )
    return -E2BIG;

  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    ni->hwport_to_intf_i[i] = (ci_int8) -1;
  
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    ni->intf_i_to_hwport[i] = (ci_int8) -1;

  if( ifindices_len < 0 ) {
    onic = oo_nics;
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      while( onic < oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        if( onic->efrm_client != NULL )
          break;
        else
          ++onic;
      if( onic >= oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        break;
      efrm_nic_set_write(&ni->nic_set, intf_i, CI_TRUE);
      trs->nic[intf_i].intf_i = intf_i;
      trs->nic[intf_i].oo_nic = onic;
      ni->hwport_to_intf_i[onic - oo_nics] = intf_i;
      ni->intf_i_to_hwport[intf_i] = onic - oo_nics;;
      ++trs->netif.nic_n;
      ++onic;
    }
  }
  else if( ifindices_len == 0 ) {
    ci_assert_equal(trs->netif.nic_n, 0);
  }
  else {
    /* This code path is not used yet, but this error message will make it
     * obvious what needs doing if we decide to use it in future...
     */
    ci_log("%s: TODO", __FUNCTION__);
    rc = -EINVAL;
    goto fail;
  }

  if( trs->netif.nic_n == 0 && ifindices_len != 0 ) {
    ci_log("%s: ERROR: No Solarflare network interfaces are active/UP. "
	   "Please check your config with ip addr or ifconfig", __FUNCTION__);
    return -ENODEV;
  }
  return 0;

 fail:
  return rc;
}


ci_inline void efab_notify_stacklist_change(tcp_helper_resource_t *thr)
{
  /* here we should notify tcpdump process that the stack list have
   * changed */
  /*ci_log("add/remove stack %d(%s), refcount %d", thr->id, thr->name,
         oo_atomic_read(&thr->ref_count));*/
  efab_tcp_driver.stack_list_seq++;
  ci_rmb();
  ci_waitq_wakeup(&efab_tcp_driver.stack_list_wq);
}


static void tcp_helper_more_bufs_work(void* context)
{
  tcp_helper_resource_t* trs = context;
  ci_netif* ni = &trs->netif;

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

  if( ci_netif_trylock(ni) ) {
    if( trs->netif.state->n_freepkts <=
        NI_OPTS(&trs->netif).free_packets_low )
      efab_tcp_helper_more_bufs(trs);
    ci_netif_unlock(ni);
    return;
  }

  /* Lock is busy. Are we really out of packets? */
  if( ni->state->n_freepkts > NI_OPTS(ni).free_packets_low / 2 )
    return;

  /* Avoid deadlock with tcp_helper_stop: do not wait forever.
   * From the other side, we must wait for some time, because the atomic
   * process spawned us may be still active and holding the lock.
   * And we can not easily use CI_EPLOCK_NETIF_ flag because a lot of netif
   * unlocks happen in atomic context. */
  if( efab_eplock_lock_timeout(ni, msecs_to_jiffies(10)) == 0 ) {
    if( trs->netif.state->n_freepkts <= NI_OPTS(ni).free_packets_low )
      efab_tcp_helper_more_bufs(trs);
    ci_netif_unlock(ni);
  }
}


static void tcp_helper_do_non_atomic(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            non_atomic_work);
  const unsigned handled_aflags = (OO_THR_EP_AFLAG_CLEAR_FILTERS |
                                   OO_THR_EP_AFLAG_NEED_FREE);
  ci_irqlock_state_t lock_flags;
  tcp_helper_endpoint_t* ep;
  unsigned ep_aflags, new_aflags;
  ci_sllist list;
  ci_sllink* link;

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

  ci_assert(! in_atomic());

  /* Allocate packets in non-atomic mode */
  if( trs->avoid_atomic_allocations &&
      trs->netif.state->n_freepkts <= NI_OPTS(&trs->netif).free_packets_low &&
      NI_OPTS(&trs->netif).max_packets <
      (trs->netif.pkt_sets_n << CI_CFG_PKTS_PER_SET_S))
    tcp_helper_more_bufs_work(trs);

  /* Handle endpoints that have work queued. */
  ci_irqlock_lock(&trs->lock, &lock_flags);
  list = trs->non_atomic_list;
  ci_sllist_init(&trs->non_atomic_list);
  ci_irqlock_unlock(&trs->lock, &lock_flags);
  while( (link = ci_sllist_try_pop(&list)) != NULL ) {
    ep = CI_CONTAINER(tcp_helper_endpoint_t, non_atomic_link , link);
  again:
    do {  /* grab and clear flags telling us what to do */
      ep_aflags = ep->ep_aflags;
      new_aflags = ep_aflags & ~handled_aflags;
    } while( ci_cas32_fail(&ep->ep_aflags, ep_aflags, new_aflags) );
    OO_DEBUG_TCPH(ci_log("%s: [%u:%d] aflags=%x", __FUNCTION__, trs->id,
                         OO_SP_FMT(ep->id), ep_aflags));
    if( ep_aflags & OO_THR_EP_AFLAG_CLEAR_FILTERS )
      tcp_helper_endpoint_clear_filters(ep, 0);
    if( ep_aflags & OO_THR_EP_AFLAG_NEED_FREE )
      citp_waitable_obj_free_nnl(&trs->netif,
                                 SP_TO_WAITABLE(&trs->netif, ep->id));
    /* Clear the NON_ATOMIC flag while checking to see if more work has
     * been requested.  (Done this way to avoid race with
     * citp_waitable_obj_free().
     */
    do {
      if( (ep_aflags = ep->ep_aflags) & handled_aflags )
        goto again;
      new_aflags = ep_aflags & ~OO_THR_EP_AFLAG_NON_ATOMIC;
    } while( ci_cas32_fail(&ep->ep_aflags, ep_aflags, new_aflags) );
  }

  /* Handle the deferred close path. */
  if( trs->trs_aflags & OO_THR_AFLAG_CLOSE_ENDPOINTS ) {
    OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINTS", __FUNCTION__, trs->id));
    ci_assert(ci_netif_is_locked(&trs->netif));
    ci_assert(oo_trusted_lock_is_locked(trs));
    ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_CLOSE_ENDPOINTS);
    tcp_helper_close_pending_endpoints(trs);
    efab_tcp_helper_netif_unlock(trs, 0);
  }
}


void tcp_helper_endpoint_queue_non_atomic(tcp_helper_endpoint_t* ep,
                                          unsigned why_aflag)
{
  ci_irqlock_state_t lock_flags;
  unsigned prev_aflags;

  why_aflag |= OO_THR_EP_AFLAG_NON_ATOMIC;
  ci_irqlock_lock(&ep->thr->lock, &lock_flags);
  prev_aflags = tcp_helper_endpoint_set_aflags(ep, why_aflag);
  if( ! (prev_aflags & OO_THR_EP_AFLAG_NON_ATOMIC) ) {
    ci_sllist_push(&ep->thr->non_atomic_list, &ep->non_atomic_link);
    queue_work(ep->thr->wq, &ep->thr->non_atomic_work);
  }
  ci_irqlock_unlock(&ep->thr->lock, &lock_flags);
}

/* Woritem routine to handle postponed stack destruction. */
static void
tcp_helper_destroy_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            work_item_dtor);

  if( TCP_HELPER_K_RC_REFS(trs->k_ref_count) == 0 ) {
    tcp_helper_dtor(trs);
    return;
  }

  ci_assert(trs->trs_aflags & OO_THR_AFLAG_RM_FREE);
  ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_RM_FREE);
  efab_tcp_helper_rm_free_locked(trs, 1);
}


ci_inline void tcp_helper_init_max_mss(tcp_helper_resource_t* rs)
{
  /* Falcon uses 16, EF10 uses shorter prefixes */
  const int max_prefix = 16;
  int intf_i, min_rx_usr_buf_size;
  ci_netif* ni = &rs->netif;
  struct efhw_nic *nic;

  min_rx_usr_buf_size = FALCON_RX_USR_BUF_SIZE;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    nic = efrm_client_get_nic(rs->nic[intf_i].oo_nic->efrm_client);
    if( nic->rx_usr_buf_size < min_rx_usr_buf_size )
     min_rx_usr_buf_size = nic->rx_usr_buf_size;
  }
  ni->state->max_mss = min_rx_usr_buf_size - max_prefix - ETH_HLEN - 
    ETH_VLAN_HLEN - sizeof(ci_ip4_hdr) - sizeof(ci_tcp_hdr);
}


int tcp_helper_rm_alloc(ci_resource_onload_alloc_t* alloc,
                        const ci_netif_config_opts* opts,
                        int ifindices_len, tcp_helper_cluster_t* thc,
                        tcp_helper_resource_t** rs_out)
{
  tcp_helper_resource_t* rs;
  ci_irqlock_state_t lock_flags;
  struct efhw_nic *nic;
  int rc, intf_i;
  ci_netif* ni;

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0);

  rc = oo_version_check(alloc);
  if( rc < 0 )
    goto fail1;

  oo_timesync_wait_for_cpu_khz_to_stabilize();

  if( (opts->packet_buffer_mode & CITP_PKTBUF_MODE_PHYS) &&
      (phys_mode_gid == -2 ||
       (phys_mode_gid != -1 && ci_getgid() != phys_mode_gid)) ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: EF_PACKET_BUFFER_MODE=%d not permitted "
                        "(phys_mode_gid=%d gid=%d pid=%d)", __FUNCTION__,
                        opts->packet_buffer_mode, phys_mode_gid, ci_getgid(),
                        current->tgid);
                 ci_log("%s: HINT: See the phys_mode_gid onload module "
                        "option.", __FUNCTION__));
    rc = -EPERM;
    goto fail1;
  }

  rs = CI_ALLOC_OBJ(tcp_helper_resource_t);
  if( !rs ) {
    rc = -ENOMEM;
    goto fail1;
  }
  oo_atomic_set(&rs->ref_count, 1);
  ni = &rs->netif;

  rc = oo_get_nics(rs, ifindices_len);
  if( rc < 0 )
    goto fail2;

  /* Allocate an instance number. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  rs->id = ci_id_pool_alloc(&THR_TABLE.instances);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (rs->id == CI_ID_POOL_ID_NONE) {
    OO_DEBUG_ERR(ci_log("%s: out of instances", __FUNCTION__));
    rc = -EBUSY;
    goto fail3;
  }

  rs->trusted_lock = OO_TRUSTED_LOCK_LOCKED;
  rs->k_ref_count = 1;          /* 1 reference for userland */
  rs->n_ep_closing_refs = 0;
  rs->intfs_to_reset = 0;
  rs->avoid_atomic_allocations = 0;
  rs->thc = NULL;
  alloc->in_name[CI_CFG_STACK_NAME_LEN] = '\0';
  strcpy(rs->name, alloc->in_name);

  ni->opts = *opts;
  ci_netif_config_opts_rangecheck(&ni->opts);

  /* Allocate buffers for shared state, etc. */
  rc = allocate_netif_resources(alloc, rs);
  if( rc < 0 ) goto fail4;

  /* Create this lock before adding the stack to started_stacks list,
   * because it is used in reset function. */
  ci_irqlock_ctor(&rs->lock);

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_push(&THR_TABLE.started_stacks, &rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* Allocate hardware resources */
  rc = allocate_netif_hw_resources(alloc, thc, rs);
  if( rc < 0 ) goto fail5;

  /* Prepare per-socket data structures, and allocate the first few socket
  ** buffers. */
  ni->ep_tbl_max = NI_OPTS(ni).max_ep_bufs;
  ni->ep_tbl_n = 0;
  ni->ep_tbl = CI_VMALLOC_ARRAY(tcp_helper_endpoint_t*, ni->ep_tbl_max);
  if( ni->ep_tbl == 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_rm_alloc: failed to allocate ep_tbl"));
    rc = -ENOMEM;
    goto fail6;
  }
#if CI_CFG_USERSPACE_PIPE
  CI_ZERO_ARRAY(ni->ep_tbl, ni->ep_tbl_max);
#endif

  INIT_WORK(&rs->non_atomic_work, tcp_helper_do_non_atomic);
  INIT_WORK(&rs->work_item_dtor, tcp_helper_destroy_work);
  ci_sllist_init(&rs->non_atomic_list);
  ci_sllist_init(&rs->ep_tobe_closed);
  rs->trs_aflags = 0;
  ni->flags = alloc->in_flags;
  ni->uid = ci_getuid();
  ni->euid = ci_geteuid();
  ni->error_flags = 0;
  ci_netif_state_init(&rs->netif, oo_timesync_cpu_khz, alloc->in_name);
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    nic = efrm_client_get_nic(rs->nic[intf_i].oo_nic->efrm_client);
    if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
      ni->state->flags |= CI_NETIF_FLAG_ONLOAD_UNSUPPORTED;
  }

  tcp_helper_init_max_mss(rs);

  efab_tcp_helper_more_socks(rs);

  /* At this point, we are certain that construction of the netif will not
   * fail, so we move out of "Uninitialised" and into "Locked".
   */
  CI_MAGIC_SET(ni, NETIF_MAGIC);

  if( (rc = ci_netif_init_fill_rx_rings(ni)) != 0 )
    goto fail6;

  /* "onload-wq:pretty_name workqueue for non-atomic works */
  snprintf(rs->wq_name, sizeof(rs->wq_name), "onload-wq:%s",
           ni->state->pretty_name);
  rs->wq = create_singlethread_workqueue(rs->wq_name);
  if( rs->wq == NULL )
    goto fail6;

  /* If there aren't any stacks yet force a sync of cplane information, to
   * to help with the case where people create interfaces then immediately
   * launch their app that uses them.
   */
  if( (NI_OPTS(ni).sync_cplane == 2) || ((NI_OPTS(ni).sync_cplane == 1)
        && (ci_dllist_is_empty(&THR_TABLE.all_stacks))) ) {
    cicpos_sync_tables(CICP_HANDLE(&rs->netif));
  }


  /* We're about to expose this stack to other people.  So we should be
   * sufficiently initialised here that other people don't get upset.
   */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_remove_safe(&rs->all_stacks_link);
  if( alloc->in_name[0] ) {
    rc = efab_thr_table_check_name(alloc->in_name);
    if( rc != 0 ) {
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
      goto fail7;
    }
  }
  ci_dllist_push(&THR_TABLE.all_stacks, &rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* This must be set when we are guaranteed that stack creation
   * cannot fail (because stack creation failure calls into stack
   * freeing code which frees the reference to the thc leading us to
   * deadlock with thc creation code).
   */
  rs->thc = thc;
  efab_tcp_helper_netif_unlock(rs, 0);

  efab_notify_stacklist_change(rs);

  /* We deliberately avoid starting periodic timer and callback until now,
   * so we don't have to worry about stopping them if we bomb out early.
   */
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    if( NI_OPTS(ni).int_driven )
      efrm_eventq_register_callback(rs->nic[intf_i].vi_rs,
                                    &oo_handle_wakeup_int_driven,
                                    &rs->nic[intf_i]);
    else
      efrm_eventq_register_callback(rs->nic[intf_i].vi_rs,
                                    &oo_handle_wakeup_or_timeout,
                                    &rs->nic[intf_i]);
  }
  tcp_helper_initialize_and_start_periodic_timer(rs);
  if( NI_OPTS(ni).int_driven )
    tcp_helper_request_wakeup(netif2tcp_helper_resource(ni));

  alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
  alloc->out_nic_set = ni->nic_set;
  *rs_out = rs;
  OO_DEBUG_RES(ci_log("tcp_helper_rm_alloc: allocated %u", rs->id));
  return 0;

 fail7:
  destroy_workqueue(rs->wq);
 fail6:
  release_netif_hw_resources(rs);
 fail5:
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_remove(&rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  release_netif_resources(rs);
 fail4:
  ci_id_pool_free(&THR_TABLE.instances, rs->id, &THR_TABLE.lock);
 fail3:
 fail2:
  CI_FREE_OBJ(rs);
 fail1:
  return rc;
}



int tcp_helper_alloc_ul(ci_resource_onload_alloc_t* alloc,
                        int ifindices_len, tcp_helper_resource_t** rs_out)
{
  ci_netif_config_opts* opts;
  int rc;

  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  rc = -EFAULT;
  if( copy_from_user(opts, CI_USER_PTR_GET(alloc->in_opts), sizeof(*opts)) )
    goto out;

  rc = tcp_helper_rm_alloc(alloc, opts, ifindices_len, NULL, rs_out);
 out:
  kfree(opts);
  return rc;
}



int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                            const ci_netif_config_opts* opts,
                            int ifindices_len, tcp_helper_resource_t** rs_out)
{
  return tcp_helper_rm_alloc(alloc, opts, ifindices_len, NULL, rs_out);
}


static void thr_reset_stack_rx_cb(ef_request_id id, void* arg)
{
  tcp_helper_resource_t* thr = (tcp_helper_resource_t*)arg;
  ci_netif* ni = &thr->netif;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;
  OO_PP_INIT(ni, pp, id);
  pkt = PKT_CHK(ni, pp);
  ci_netif_pkt_release(ni, pkt);
}


struct thr_reset_stack_tx_cb_state {
  int intf_i;
  struct ci_netif_poll_state ps;
  tcp_helper_resource_t* thr;
};


static void thr_reset_stack_tx_cb(ef_request_id id, void* arg)
{
  struct thr_reset_stack_tx_cb_state* cb_state =
    (struct thr_reset_stack_tx_cb_state*)arg;
  ci_netif* ni = &cb_state->thr->netif;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;

  OO_PP_INIT(ni, pp, id);
  pkt = PKT_CHK(ni, pp);
  ++ni->state->nic[cb_state->intf_i].tx_dmaq_done_seq;
  ci_netif_tx_pkt_complete(ni, &cb_state->ps, pkt);
}


static void tcp_helper_reset_stack_locked(tcp_helper_resource_t* thr)
{
  ci_irqlock_state_t lock_flags;
  unsigned intfs_to_reset;
  int intf_i, i, pkt_sets_n;
  ci_netif* ni = &thr->netif;
  ef_vi* vi;
  struct thr_reset_stack_tx_cb_state cb_state;
  uint64_t *hw_addrs;
#if CI_CFG_PIO
  int rc;
  struct efhw_nic* nic;
#endif

  if( thr->thc != NULL ) {
    /* This warning can be removed once Bug43452 is properly addressed */
    ci_log("Stack %s:%d in cluster %s can't restore filters post-NIC-reset.\n"
           "This stack will no longer receive packets",
           thr->name, thr->id, thr->thc->thc_name);
  }

  pkt_sets_n = ni->pkt_sets_n;

  hw_addrs = ci_alloc(sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S));
  if( hw_addrs == NULL ) {
    ci_log("%s: [%d] out of memory", __func__, thr->id);
    return;
  }

  ci_irqlock_lock(&thr->lock, &lock_flags);
  intfs_to_reset = thr->intfs_to_reset;
  thr->intfs_to_reset = 0;
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
    if( intfs_to_reset & (1 << intf_i) ) {
      ci_log("%s: reset stack %d intf %d (0x%x)",
             __FUNCTION__, thr->id, intf_i, intfs_to_reset);

      vi = &ni->nic_hw[intf_i].vi;

#if CI_CFG_PIO
      nic = efrm_client_get_nic(thr->nic[intf_i].oo_nic->efrm_client);
      if( NI_OPTS(ni).pio &&
          (nic->devtype.arch == EFHW_ARCH_EF10) && 
          (thr->nic[intf_i].pio_io_mmap_bytes != 0) ) {
        struct efrm_pd *pd = efrm_vi_get_pd(thr->nic[intf_i].vi_rs);
        OO_DEBUG_TCPH(ci_log("%s: realloc PIO", __FUNCTION__));
        /* Now try to recreate and link the PIO region */
        rc = efrm_pio_realloc(pd, thr->nic[intf_i].pio_rs, 
                              thr->nic[intf_i].vi_rs);
        if( rc < 0 ) {
          OO_DEBUG_TCPH(ci_log("%s: [%d:%d] pio_realloc failed %d, "
                               "removing PIO capability", 
                               __FUNCTION__, thr->id, intf_i, rc));
          thr->nic[intf_i].pio_io_mmap_bytes = 0;
          /* Expose failure to user-level */
          thr->netif.nic_hw[intf_i].pio.pio_buffer = NULL;
          thr->netif.nic_hw[intf_i].pio.pio_len = 0;
          ni->state->nic[intf_i].oo_vi_flags &=~ OO_VI_FLAGS_PIO_EN;
          ni->state->nic[intf_i].pio_io_mmap_bytes = 0;
          ni->state->nic[intf_i].pio_io_len = 0;
          ci_pio_buddy_dtor(ni, &ni->state->nic[intf_i].pio_buddy);
          /* Leave efrm references in place as we can't remove them
           * now - they will get removed as normal when stack
           * destroyed
           */
        }
      }
#endif

      /* Reset sw queues */
      ef_vi_evq_reinit(vi);
      ef_vi_rxq_reinit(vi, thr_reset_stack_rx_cb, thr);

      cb_state.intf_i = intf_i;
      cb_state.thr = thr;
      cb_state.ps.tx_pkt_free_list_insert = &cb_state.ps.tx_pkt_free_list;
      cb_state.ps.tx_pkt_free_list_n = 0;
      ef_vi_txq_reinit(vi, thr_reset_stack_tx_cb, &cb_state);

      /* Reset hw queues.  This must be done after resetting the sw
         queues as the hw will start delivering events after being
         reset. */
      efrm_vi_q_reinit(thr->nic[intf_i].vi_rs, EFHW_EVQ);
      efrm_vi_q_reinit(thr->nic[intf_i].vi_rs, EFHW_TXQ);
      efrm_vi_q_reinit(thr->nic[intf_i].vi_rs, EFHW_RXQ);

      if( cb_state.ps.tx_pkt_free_list_n )
        ci_netif_poll_free_pkts(ni, &cb_state.ps);

      if( OO_PP_NOT_NULL(ni->state->nic[intf_i].rx_frags) ) {
        ci_ip_pkt_fmt* pkt = PKT_CHK(ni, ni->state->nic[intf_i].rx_frags);
        ni->state->nic[intf_i].rx_frags = OO_PP_NULL;
        ci_netif_pkt_release(ni, pkt);
      }

      for( i = 0; i < pkt_sets_n; ++i ) {
        int j, rc;

        rc = oo_iobufset_resource_remap_bt(ni->nic_hw[intf_i].pkt_rs[i],
                                          hw_addrs);
        if( rc == -ENOSYS ) {
          /* This PD does not use buffer table; do not update anything and
           * go away. */
          ci_assert_equal(i, 0);
          break;
        }

        if( rc != 0 ) {
          /* The stack is running, but packet mapping is invalidated.
           * We have no good solution.  Just let's reset all hardware
           * addresses and wait for user to kill the app. */
          ci_log("ERROR [%d]: failed to remap packets after NIC reset",
                 thr->id);
          memset(hw_addrs, 0, sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S));
        }

        for( j = 0; j < PKTS_PER_SET; j++ ) {
          ci_ip_pkt_fmt* pkt;
          int id = (i * PKTS_PER_SET) + j;
          oo_pkt_p pp;
          OO_PP_INIT(ni, pp, id);
          pkt = __PKT(ni, pp);
          pkt->dma_addr[intf_i] = hw_addrs[j / PKTS_PER_HW_PAGE] +
            CI_CFG_PKT_BUF_SIZE * (j % PKTS_PER_HW_PAGE) +
            CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start);
        }
      }

      if( NI_OPTS(ni).timer_usec != 0 ) 
        ef_eventq_timer_prime(vi, NI_OPTS(ni).timer_usec);

      ci_bit_test_and_set(&ni->state->evq_primed, intf_i);
      tcp_helper_request_wakeup_nic(thr, intf_i);
    }
  }

#if CI_CFG_PIO
  /* This should only be done after we have tried to reacquire PIO
   * regions. */
  ci_tcp_tmpl_handle_nic_reset(ni);
#endif

  ci_free(hw_addrs);
}


void tcp_helper_reset_stack(ci_netif* ni, int intf_i)
{
  tcp_helper_resource_t* thr;
  ci_irqlock_state_t lock_flags;

  thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);

  ci_irqlock_lock(&thr->lock, &lock_flags);
  thr->intfs_to_reset |= (1 << intf_i);
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  if( efab_tcp_helper_netif_lock_or_set_flags(thr, 
                                              OO_TRUSTED_LOCK_RESET_STACK,
                                              CI_EPLOCK_NETIF_RESET_STACK,
                                              1) ) {
    tcp_helper_reset_stack_locked(thr);
    efab_tcp_helper_netif_unlock(thr, 1);
  }
}

/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero.
 * The code is arranged so that this happens when the user-mode closes
 * the last efab file - irrespective of whether any TCP connections
 * need to live on
 *
 * At this stage we need to recover from corruption of the shared eplock
 * state - for exmaple, user application may have crashed whilst holding
 * this lock. However, we need to be race free against valid kernel users
 * of this lock - therefore, we proceed only once we have obtained the
 * kernel netif lock
 *
 * \param trs             Efab resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_rm_free(tcp_helper_resource_t* trs)
{
  unsigned l, new_l;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

  do {
    l = trs->trusted_lock;
    /* NB. We clear other flags when setting AWAITING_FREE.
     * tcp_helper_rm_free_locked() will close pending sockets, and other
     * flags are not critical.
     */
    new_l = OO_TRUSTED_LOCK_LOCKED | OO_TRUSTED_LOCK_AWAITING_FREE;
  } while( ci_cas32u_fail(&trs->trusted_lock, l, new_l) );

  if( l & OO_TRUSTED_LOCK_LOCKED )
    /* Lock holder will call efab_tcp_helper_rm_free_locked(). */
    return;

  efab_tcp_helper_rm_free_locked(trs, 1);
  OO_DEBUG_TCPH(ci_log("%s: [%u] done", __FUNCTION__, trs->id));
}


void
efab_thr_release(tcp_helper_resource_t *thr)
{
  ci_irqlock_state_t lock_flags;
  unsigned tmp;
  int is_ref;

  TCP_HELPER_RESOURCE_ASSERT_VALID(thr, 0);


  if( ! oo_atomic_dec_and_test(&thr->ref_count) ) {
    if( oo_atomic_read(&thr->ref_count) == 1 )
      efab_notify_stacklist_change(thr);
    return;
  }
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( (is_ref = oo_atomic_read(&thr->ref_count)) == 0 ) {
    /* Interlock against efab_thr_table_lookup(). */
    do {
      tmp = thr->k_ref_count;
      ci_assert( ! (tmp & TCP_HELPER_K_RC_DEAD) );
      ci_assert( ! (tmp & TCP_HELPER_K_RC_NO_USERLAND) );
    } while( ci_cas32_fail(&thr->k_ref_count, tmp,
                           tmp | TCP_HELPER_K_RC_NO_USERLAND) );
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if( ! is_ref )
    tcp_helper_rm_free(thr);
}

/*--------------------------------------------------------------------
 *!
 * Enqueues a work-item to call tcp_helper_dtor() at a safe time.
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_dtor_schedule(tcp_helper_resource_t * trs)
{
  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));
  ci_verify( queue_work(CI_GLOBAL_WORKQUEUE, &trs->work_item_dtor) != 0);
}


/*--------------------------------------------------------------------
 * Called when [trs->k_ref_count] goes to zero.  This can only happen
 * after all references to the resource have gone, and all sockets have
 * reached closed.
 *
 * \param trs               TCP helper resource
 * \param can_destroy_now   OK to destroy now?  (else schedule work item)
 *--------------------------------------------------------------------*/

static void
efab_tcp_helper_k_ref_count_is_zero(tcp_helper_resource_t* trs,
                                                int can_destroy_now)
{
  /* although we have atomically got to zero we still have to contend
   * with a possible race from the resource manager destruction
   * (which needs the ability to force destruction of orphaned resources)
   * Therefore, we still have to test whether resource is in the list
   */
  ci_irqlock_state_t lock_flags;

  ci_assert(trs);
  ci_assert_equal(TCP_HELPER_K_RC_REFS(trs->k_ref_count), 0);
  ci_assert(trs->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND);
  ci_assert(trs->k_ref_count & TCP_HELPER_K_RC_DEAD);

  OO_DEBUG_TCPH(ci_log("%s: [%u] k_ref_count=%x can_destroy_now=%d",
                       __FUNCTION__, trs->id, trs->k_ref_count,
                       can_destroy_now));

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( !ci_dllink_is_free(&trs->all_stacks_link) ) {
    ci_dllist_remove(&trs->all_stacks_link);
    ci_dllink_mark_free(&trs->all_stacks_link);
  }
  else
    trs = 0;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  if( trs ) {
    if( can_destroy_now )  tcp_helper_dtor(trs);
    else                   tcp_helper_dtor_schedule(trs);
  }
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


/*--------------------------------------------------------------------
 *!
 * Called to release a kernel reference to a stack.  This is called
 * by ci_drop_orphan() when userlevel is no longer around.
 *
 * \param trs             TCP helper resource
 * \param can_destroy_now true if in a context than can call destructor
 *
 *--------------------------------------------------------------------*/

void
efab_tcp_helper_k_ref_count_dec(tcp_helper_resource_t* trs,
                                     int can_destroy_now)
{
  int tmp;

  ci_assert(NULL != trs);

  OO_DEBUG_TCPH(ci_log("%s: [%d] k_ref_count=%x can_destroy_now=%d",
                       __FUNCTION__, trs->id, trs->k_ref_count,
                       can_destroy_now));
  ci_assert(~trs->k_ref_count & TCP_HELPER_K_RC_DEAD);

 again:
  tmp = trs->k_ref_count;
  if( TCP_HELPER_K_RC_REFS(tmp) == 1 ) {
    /* No-one apart from us is referencing this stack any more.  Mark it as
    ** dead to prevent anyone grabbing another reference.
    */
    if( ci_cas32_fail(&trs->k_ref_count, tmp,
                     TCP_HELPER_K_RC_DEAD | TCP_HELPER_K_RC_NO_USERLAND) )
      goto again;
    efab_tcp_helper_k_ref_count_is_zero(trs, can_destroy_now);
  }
  else
    if( ci_cas32_fail(&trs->k_ref_count, tmp, tmp - 1) )
      goto again;
}


/*! Close sockets.  Called with netif lock held.  Kernel netif lock may or
 * may not be held.
 */
static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t* trs)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_endpoint_t* ep;
  ci_sllink* link;

  OO_DEBUG_TCPH(ci_log("%s: [%d]", __FUNCTION__, trs->id));

  ci_assert(ci_netif_is_locked(&trs->netif));
  ci_assert(! in_atomic());

  /* Ensure we're up-to-date so we get an ordered response to all packets.
  ** (eg. ANVL tcp_core 9.18).  Do it once here rather than per-socket.
  ** Also ensure all local packets are delivered before endpoint release.
  */
  ci_netif_poll(&trs->netif);

  while( ci_sllist_not_empty(&trs->ep_tobe_closed) ) {
    ci_irqlock_lock(&trs->lock, &lock_flags);

    /* DEBUG build: we are protected by netif lock, so the ep_tobe_closed
     * list can't be empty.
     * NDEBUG build: we are not protected by kernel netif lock, so
     * we should re-check that ep_tobe_closed is non-empty for security
     * reasons. */
    ci_assert( ci_sllist_not_empty(&trs->ep_tobe_closed) );
    if( ci_sllist_is_empty(&trs->ep_tobe_closed) ) {
      ci_irqlock_unlock(&trs->lock, &lock_flags);
      ci_log("%s: [%d] ERROR: stack lock corrupted", __func__, trs->id);
      break;
    }
    link = ci_sllist_pop(&trs->ep_tobe_closed);
    ci_irqlock_unlock(&trs->lock, &lock_flags);

    ep = CI_CONTAINER(tcp_helper_endpoint_t, tobe_closed , link);
    OO_DEBUG_TCPH(ci_log("%s: [%u:%d] closing",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep->id)));
    tcp_helper_endpoint_clear_aflags(ep, OO_THR_EP_AFLAG_ATTACHED);
    citp_waitable_all_fds_gone(&trs->netif, ep->id);
  }
}


static void
efab_tcp_helper_rm_reset_untrusted(tcp_helper_resource_t* trs)
{
  ci_netif *netif = &trs->netif;
  int i;

  for( i = 0; i < netif->ep_tbl_n; ++i ) {
    tcp_helper_endpoint_t *ep = netif->ep_tbl[i];
    citp_waitable_obj* wo;

    /* this is pipe buffer */
    if( ep == NULL )
      continue;

    /* release OS port keeper */
    if( ep->os_port_keeper )
      oo_file_ref_drop(ep->os_port_keeper);

    /* reset TCP connection */
    wo = ID_TO_WAITABLE_OBJ(netif, i);
    if( (wo->waitable.state & CI_TCP_STATE_TCP_CONN) &&
        wo->waitable.state != CI_TCP_TIME_WAIT )
      ci_tcp_reset_untrusted(netif, &wo->tcp);
  }
}

static void
efab_tcp_helper_rm_schedule_free(tcp_helper_resource_t* trs)
{
  OO_DEBUG_TCPH(ci_log("%s [%u]: defer", __FUNCTION__, trs->id));
  ci_atomic32_or(&trs->trs_aflags, OO_THR_AFLAG_RM_FREE);
  queue_work(CI_GLOBAL_WORKQUEUE, &trs->work_item_dtor);
}

/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero
 * AND we have the kernel netif lock. At this point we are safe to
 * correct any coruption of the netif lock. We either then
 * continue destroying the TCP helper resource OR we leave it around
 * so that it exists for connections that need to close gracefully
 * post application exit
 *
 * \param trs               TCP helper resource
 * \param safe_destroy_now  is it OK to destroy the resource now or
 *                          do we need to schedule for later
 *
 *--------------------------------------------------------------------*/

static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t* trs,
                               int safe_destroy_now)
{
  ci_netif* netif;
  int n_ep_closing;
  int netif_wedged = 0;
  unsigned i;
  int krc_old, krc_new;

  ci_assert(NULL != trs);
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));

  if( in_atomic() ) {
    efab_tcp_helper_rm_schedule_free(trs);
    return;
  }
  /* Make sure all postponed actions are done and endpoints freed */
  flush_workqueue(trs->wq);

  netif = &trs->netif;

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  /* shared user/kernel netif eplock "should" be unlocked at this time */
  if( ! (trs->netif.state->lock.lock & CI_EPLOCK_UNLOCKED) ) {
    if (CI_EPLOCK_UNINITIALISED == trs->netif.state->lock.lock) {
      OO_DEBUG_ERR(ci_log("%s [%u]: "
                          "ERROR netif did not fully initialise (0x%x)",
                          __FUNCTION__, trs->id,
                          trs->netif.state->lock.lock));
    }
    else {
      OO_DEBUG_ERR(ci_log("Stack [%d] released with lock stuck (0x%x)",
                          trs->id, trs->netif.state->lock.lock));
    }
    netif_wedged = 1;
  }

  /* Grab the lock. */
  trs->netif.state->lock.lock = CI_EPLOCK_LOCKED;
  ci_wmb();

  /* Validate shared netif state before we continue
   *  \TODO: for now just clear in_poll flag
   */
  netif->state->in_poll = 0;

  /* If netif is wedged then for now instead of getting netif in
     a valid state we instead try never to touch it again */
#if CI_CFG_DESTROY_WEDGED
  if( netif_wedged ) {
    n_ep_closing = 0;
    goto closeall;
  }
#endif /*CI_CFG_DESTROY_WEDGED*/

  /* purge list of connections waiting to be closed
   *   - ones where we couldn't continue in fop_close because
   *     we didn't have the netif lock
   */
  tcp_helper_close_pending_endpoints(trs);

  for( i=0, n_ep_closing=0; i < netif->ep_tbl_n; i++ ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);
    citp_waitable* w = &wo->waitable;

#if CI_CFG_USERSPACE_PIPE
    if( ! netif->ep_tbl[i] )
      continue;
#endif
    if( w->state == CI_TCP_STATE_FREE )  continue;

    if( w->state == CI_TCP_CLOSED ) {
#if CI_CFG_FD_CACHING
      OO_DEBUG_ERR(ci_log("%s [%u]: ERROR endpoint %d leaked state "
                          "(cached=%d/%d)", __FUNCTION__, trs->id,
                          i, wo->tcp.cached_on_fd, wo->tcp.cached_on_pid));
#else
      OO_DEBUG_ERR(ci_log("%s [%u:%d]: ERROR endpoint leaked",
                          __FUNCTION__, trs->id, i));
#endif
      w->state = CI_TCP_STATE_FREE;
      continue;
    }

    /* All user files are closed; all FINs should be sent.
     * There are some cases when we fail to send FIN to passively-opened
     * connection: reset such connections. */
    if( w->state & CI_TCP_STATE_CAN_FIN ) {
#ifndef NDEBUG
      /* It is normal for EF_TCP_SERVER_LOOPBACK=2 if client closes
       * loopback connection before it is accepted.
       * Do not scare users unless they want to be scared:
       * keep this under #ifndef NDEBUG. */
      OO_DEBUG_ERR(ci_log("%s: %d:%d in %s state when stack is closed",
                   __func__, trs->id, i, ci_tcp_state_str(w->state)));
#endif
      ci_tcp_send_rst(netif, &wo->tcp);
      ci_tcp_drop(netif, &wo->tcp, ECONNRESET);
      continue;
    }

    OO_DEBUG_TCPH(ci_log("%s [%u]: endpoint %d in state %s", __FUNCTION__,
                         trs->id, i, ci_tcp_state_str(w->state)));
    /* \TODO: validate connection,
     *          - do we want to mark as closed or leave to close?
     *          - timers OK ?
     * for now we we just check the ORPHAN flag
     */
    if( ! (w->sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      OO_DEBUG_ERR(ci_log("%s [%u]: ERROR found non-orphaned endpoint %d in"
                          " state %s", __FUNCTION__, trs->id,
                          i, ci_tcp_state_str(w->state) ));
      ci_bit_set(&w->sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
    }
    ++n_ep_closing;
  }

  OO_DEBUG_TCPH(ci_log("%s: [%u] %d socket(s) closing", __FUNCTION__,
                       trs->id, n_ep_closing));

  if( n_ep_closing ) {
    ci_irqlock_state_t lock_flags;
    /* Add in a ref to the stack for each of the closing sockets.  Set
     * CI_NETIF_FLAGS_DROP_SOCK_REFS so that the extra refs are dropped
     * when the sockets close.
     */
    do {
      krc_old = trs->k_ref_count;
      krc_new = krc_old + n_ep_closing;
    } while( ci_cas32_fail(&trs->k_ref_count, krc_old, krc_new) );

    ci_irqlock_lock(&trs->lock, &lock_flags);

    ci_assert_equal(trs->n_ep_closing_refs, 0);
    trs->n_ep_closing_refs = n_ep_closing;

    ci_irqlock_unlock(&trs->lock, &lock_flags);

    netif->flags |= CI_NETIF_FLAGS_DROP_SOCK_REFS;
  }

  /* Drop lock so that sockets can proceed towards close. */
  ci_netif_unlock(&trs->netif);

#if CI_CFG_DESTROY_WEDGED
 closeall:
#endif
  /* Don't need atomics here, because only we are permitted to touch
   * [trusted_lock] when AWAITING_FREE is set.
   */
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));
  trs->trusted_lock = OO_TRUSTED_LOCK_UNLOCKED;
  efab_tcp_helper_k_ref_count_dec(trs, safe_destroy_now);
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


/*--------------------------------------------------------------------
 *!
 * This function stops any async callbacks into the TCP helper resource
 * (waiting for any running callbacks to complete)
 *
 * Split into a separate function from tcp_helper_dtor only to make the
 * protection against potentail race conditions clearer
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

ci_inline void
tcp_helper_stop(tcp_helper_resource_t* trs)
{
  int intf_i;

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  /* stop the periodic timer callbacks*/
  tcp_helper_stop_periodic_timer(trs);

  /* stop callbacks from the event queue
        - wait for any running callback to complete */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    ef_eventq_timer_clear(&(trs->netif.nic_hw[intf_i].vi));
    efrm_eventq_kill_callback(trs->nic[intf_i].vi_rs);
  }

  /* stop postponed packet allocations */
  destroy_workqueue(trs->wq);

  OO_DEBUG_TCPH(ci_log("%s [%d]: finished --- all async processes finished",
                       __FUNCTION__, trs->id));
}


/*--------------------------------------------------------------------
 *!
 * This is the code that was previously called directly when the TCP
 * helper resource ref count reaches zero to destruct the resource.
 * The call is now delayed until all endpoints have closed, or
 * forced when the TCP helper resource manager destructs.
 *
 * By the time we get here all attempts at graceful shutdown of sockets are
 * over.  This function is about releasing resources, and nothing else.  Do
 * not put any code that depends on the shared state in here!
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

void tcp_helper_dtor(tcp_helper_resource_t* trs)
{
  int rc;

  ci_assert(NULL != trs);

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  if( ! (trs->netif.state->lock.lock & CI_EPLOCK_UNLOCKED) )
    /* We're doing this here because we need to be in a context that allows
     * us to block.
     */
    efab_tcp_helper_rm_reset_untrusted(trs);

  /* stop any async callbacks from kernel mode (waiting if necessary)
   *  - as these callbacks are the only events that can take the kernel
   *    netif lock, we know that once these callbacks are stopped the kernel
   *    lock will have been dropped
   *      => tcp_helper_rm_free_locked must have run to completion
   */
  tcp_helper_stop(trs);
#if CI_CFG_SUPPORT_STATS_COLLECTION
  if( trs->netif.state->lock.lock != CI_EPLOCK_UNINITIALISED ) {
    /* Flush statistics gathered for the NETIF to global
     * statistics store before releasing resources of this NETIF.
     */
    ci_ip_stats_update_global(&trs->netif.state->stats_snapshot);
    ci_ip_stats_update_global(&trs->netif.state->stats_cumulative);
  }
#endif

  release_netif_hw_resources(trs);
  release_netif_resources(trs);

  rc = ci_id_pool_free(&THR_TABLE.instances, trs->id, &THR_TABLE.lock);
  OO_DEBUG_ERR(if (rc)
        ci_log("%s [%u]: failed to free instance number",
               __FUNCTION__, trs->id));

  OO_DEBUG_TCPH(ci_log("%s [%u]: finished", __FUNCTION__, trs->id));  
  CI_FREE_OBJ(trs);
}



/*--------------------------------------------------------------------
 *!
 * TCP driver management -- here for now while it needs a NIC to be around
 *
 * TODO: move somewhere more appropriate
 *
 *--------------------------------------------------------------------*/
static void
oo_file_ref_drop_list_work(struct work_struct *data)
{
  oo_file_ref_drop_list_now(NULL);
}

int
efab_tcp_driver_ctor(unsigned max_macs, unsigned max_layer2_interfaces, 
                     unsigned max_routes)
{
  int rc = 0;

  CI_ZERO(&efab_tcp_driver);

  /* Create driverlink filter. */
  if( (efab_tcp_driver.dlfilter = efx_dlfilter_ctor()) == NULL ) {
    rc = -ENOMEM;
    goto fail_dlf;
  }

  /* Create work queue */
  CI_GLOBAL_WORKQUEUE = create_singlethread_workqueue("onload-wqueue");
  if (CI_GLOBAL_WORKQUEUE == NULL)
    goto fail_wq;
  
  /* Create TCP helpers table */
  if ((rc = thr_table_ctor(&efab_tcp_driver.thr_table)) < 0)
    goto fail_thr_table;

  /* Allocate resources & construct the control plane  */
  if ((rc = cicp_ctor(&efab_tcp_driver.cplane_handle, max_macs, 
                      max_layer2_interfaces, max_routes)) < 0)
    goto fail_cicp;

  if( (rc = oof_onload_ctor(&efab_tcp_driver, max_layer2_interfaces)) < 0 )
    goto fail_filter_manager;

  /* Construct the IP ID allocator */
  efab_ipid_ctor(&efab_tcp_driver.ipid);

  ci_atomic_set(&efab_tcp_driver.sendpage_pinpages_n, 0);
  /* This is was (EFHW_BUFFER_TBL_NUM >> 1), but the size is no longer
  ** known at compile time.  But the pinned-page stuff is on its way out,
  ** so no need to fix properly. */
  efab_tcp_driver.sendpage_pinpages_max = 4096;

  efab_tcp_driver.file_refs_to_drop = NULL;
  INIT_WORK(&efab_tcp_driver.file_refs_work_item,
                   oo_file_ref_drop_list_work);

  efab_tcp_driver.stack_list_seq = 0;
  ci_waitq_ctor(&efab_tcp_driver.stack_list_wq);

  return 0;

fail_filter_manager:
  cicp_dtor(&efab_tcp_driver.cplane_handle);
fail_cicp:
  thr_table_dtor(&efab_tcp_driver.thr_table);
fail_thr_table:
  destroy_workqueue(CI_GLOBAL_WORKQUEUE);
fail_wq:
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);
fail_dlf:
  OO_DEBUG_ERR(ci_log("%s: failed rc=%d", __FUNCTION__, rc));
  return rc;
}

void
efab_tcp_driver_dtor(void)
{
  OO_DEBUG_TCPH(ci_log("%s: kill stacks", __FUNCTION__));

  thr_table_dtor(&efab_tcp_driver.thr_table);

  if( efab_tcp_driver.file_refs_to_drop != NULL )
    oo_file_ref_drop_list_now(efab_tcp_driver.file_refs_to_drop);

  flush_workqueue(CI_GLOBAL_WORKQUEUE);



  OO_DEBUG_TCPH(ci_log("%s: free resources", __FUNCTION__));

#ifndef NDEBUG
  if (ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n) != 0) {
    ci_log("%s: ERROR: sendpage_pinpages_n is %d at destruction",
           __FUNCTION__, ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n));
  }
#endif

  efab_ipid_dtor(&efab_tcp_driver.ipid);
  oof_onload_dtor(&efab_tcp_driver);
  cicp_dtor(&efab_tcp_driver.cplane_handle);
  destroy_workqueue(CI_GLOBAL_WORKQUEUE);
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);

  ci_waitq_dtor(&efab_tcp_driver.stack_list_wq);
}


static int
add_ep(tcp_helper_resource_t* trs, unsigned id, tcp_helper_endpoint_t* ep,
       int do_inc)
{
  ci_netif* ni = &trs->netif;
  citp_waitable_obj* wo;

  if( do_inc ) {
    if( id < ni->ep_tbl_n )  return -1;
    ci_assert_equal(id, ni->ep_tbl_n);
  }

  tcp_helper_endpoint_ctor(ep, trs, id);
  ni->ep_tbl[id] = ep;
#if CI_CFG_USERSPACE_PIPE
  oo_bit_array_set(ni->state->ep_buf_is_ep, id);
#endif

  if( do_inc ) {
    /* Only update [ep_tbl_n] once ep is installed. */
    ci_wmb();
    ni->state->n_ep_bufs = ++ni->ep_tbl_n;
  }

  wo = SP_TO_WAITABLE_OBJ(ni, ep->id);
  CI_ZERO(wo);  /* ??fixme */
  citp_waitable_init(ni, &wo->waitable, id);
  citp_waitable_obj_free(ni, &wo->waitable);
  return 0;
}

static int
install_socks(tcp_helper_resource_t* trs, unsigned id, int num, int are_new)
{
  tcp_helper_endpoint_t* eps[EP_BUF_PER_PAGE];
  ci_irqlock_state_t lock_flags;
  int i;

  if( are_new )
    ci_assert_equal(num, EP_BUF_PER_PAGE);
  else
    ci_assert_le(num, EP_BUF_PER_PAGE);

  /* Allocate the kernel state for each socket. */
  for( i = 0; i < num; ++i ) {
    eps[i] = CI_ALLOC_OBJ(tcp_helper_endpoint_t);
    if( ! eps[i] ) {
      OO_DEBUG_ERR(ci_log("%s: allocation failed", __FUNCTION__));
      while( i-- )  ci_free(eps[i]);
      return -ENOMEM;
    }
  }

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  for( i = 0; i < EP_BUF_PER_PAGE; ++i, ++id ){
    OO_DEBUG_SHM(ci_log("%s: add ep %d", __FUNCTION__, id));
    if( add_ep(trs, id, eps[i], are_new) == 0 )
      eps[i] = NULL;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* Prevents leaks! */
  for( i = 0; i < EP_BUF_PER_PAGE; ++i )
    if( eps[i] )
      ci_free(eps[i]);

  return 0;
}


int efab_tcp_helper_more_socks(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int rc;

  if( ni->ep_tbl_n >= ni->ep_tbl_max )  return -ENOSPC;

  rc = ci_shmbuf_demand_page(&ni->pages_buf,
                             (ni->ep_tbl_n * EP_BUF_SIZE) >> CI_PAGE_SHIFT,
                             &THR_TABLE.lock);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: demand failed (%d)", __FUNCTION__, rc));
    return rc;
  }

  return install_socks(trs, ni->ep_tbl_n, EP_BUF_PER_PAGE, CI_TRUE);
}

#if CI_CFG_USERSPACE_PIPE
/* Allocate additional bufs_num buffers. IDs of the buffers should be
 * continous as only beginning of the region is returned to the userspace!
 */
int efab_tcp_helper_more_pipe_bufs(ci_netif* ni,
                                   ci_int32 bufs_num,
                                   ci_int32* bufs_start)
{
  ci_irqlock_state_t lock_flags;
  int i;
  unsigned id;
  int rc;

  ci_assert(ni);
  ci_assert(bufs_start);

  if( bufs_num % EP_BUF_PER_PAGE != 0 )
    bufs_num += EP_BUF_PER_PAGE - (bufs_num % EP_BUF_PER_PAGE);
  ci_assert(bufs_num % EP_BUF_PER_PAGE == 0);

  id = ni->ep_tbl_n;

  /* do we have enough space? */
  if (id + bufs_num - 1 > ni->ep_tbl_max) return -ENOSPC;

  /* allocate new pages */
  for (i = 0; i < bufs_num / EP_BUF_PER_PAGE; i++) {
    rc = ci_shmbuf_demand_page(&ni->pages_buf,
                               ((id * EP_BUF_SIZE) >> CI_PAGE_SHIFT) + i,
                               &THR_TABLE.lock);
    if( rc < 0 ) {
      ci_log("%s: demand failed (%d)", __FUNCTION__, rc);
      return rc;
    }
  }

  *bufs_start = id;

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  /* this modification shoud be done under lock as it's also
   * done from add_ep() function - see below */
  ni->ep_tbl_n += bufs_num;
  ci_wmb();
  ni->state->n_ep_bufs = ni->ep_tbl_n;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  return 0;
}

int efab_tcp_helper_pipebufs_to_socks(tcp_helper_resource_t* trs)
{
  struct oo_pipe_buf* pbuf;
  oo_sp id;
  ci_uint32 len;
  ci_netif *ni = &trs->netif;
  int i;
  
  ci_assert(OO_SP_NOT_NULL(ni->state->free_pipe_bufs));
  ci_assert(ci_netif_is_locked(ni));

  pbuf = SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs);
  ni->state->free_pipe_bufs = pbuf->next;
  id = pbuf->id;
  len = pbuf->length;

  for( i = 0; i * EP_BUF_PER_PAGE < len; i++) {
    int rc = install_socks(trs, id + i * EP_BUF_PER_PAGE,
                    CI_MIN(EP_BUF_PER_PAGE, len - i * EP_BUF_PER_PAGE),
                    CI_FALSE);
    if( rc != 0 )
      return rc;
  }

  return 0;
}
#endif



/*! map offset in shared data to physical page frame number */
static unsigned long
tcp_helper_rm_nopage_mem(tcp_helper_resource_t* trs,
                         void* opaque, unsigned long offset)
{
  ci_netif* ni = &trs->netif;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  /* NB: the order in which offsets are compared against shared memory
         areas must be the same order that is used to allocate those offsets in
         allocate_netif_resources() above
  */

  if( offset < ci_contig_shmbuf_size(&ni->state_buf) ) {
    unsigned rc =  ci_contig_shmbuf_nopage(&ni->state_buf, offset);
    OO_DEBUG_SHM(ci_log("1 ... ci_shmbuf_nopage() = %u", rc));
    return rc;
  }

  offset -= ci_contig_shmbuf_size(&ni->state_buf);

  if( offset < ci_shmbuf_size(&ni->pages_buf) ) {
    unsigned rc =  ci_shmbuf_nopage(&ni->pages_buf, offset);
    OO_DEBUG_SHM(ci_log("2 ... ci_shmbuf_nopage() = %u", rc));
    return rc;
  }

  offset -= ci_shmbuf_size(&ni->pages_buf);

  {
    unsigned int page_frameno;
    if (cicp_nopage_found(&ni->cplane, opaque, &offset, &page_frameno))
      return page_frameno;
  }

  ci_assert(0);
  return (unsigned) -1;
}


static void
efab_tcp_helper_more_bufs_failed(tcp_helper_resource_t* trs, int rc)
{
  /* We've failed to allocate more packet buffers -- we're out of resources
   * (probably buffer table).  We don't want to keep trying to allocate and
   * failing -- that just makes performance yet worse.  So reset the
   * various packet limits, preserving relative sizes.
   */
  ci_netif* ni = &trs->netif;
  int new_max_packets = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;
  ni->pkt_sets_max = ni->pkt_sets_n;
  ni->state->pkt_sets_max = ni->pkt_sets_max;
  tcp_helper_reduce_max_packets(&trs->netif, new_max_packets);
  ci_netif_set_rxq_limit(ni);

  if( ++ni->state->stats.bufset_alloc_fails == 1
#if CI_CFG_PKTS_AS_HUGE_PAGES
      && NI_OPTS(ni).huge_pages != 2
#endif
      )
    OO_DEBUG_ERR(ci_log(FN_FMT "Failed to allocate packet buffers (%d)",
                        FN_PRI_ARGS(&trs->netif), rc);
                 ci_log(FN_FMT "New limits: max_packets=%d rx=%d tx=%d "
                        "rxq_limit=%d", FN_PRI_ARGS(ni),
                        NI_OPTS(ni).max_packets, NI_OPTS(ni).max_rx_packets,
                        NI_OPTS(ni).max_tx_packets, NI_OPTS(ni).rxq_limit));
}


static int 
efab_tcp_helper_iobufset_alloc(tcp_helper_resource_t* trs,
                               struct oo_iobufset** all_out,
                               struct oo_buffer_pages** pages_out,
                               uint64_t* hw_addrs)
{
  ci_netif* ni = &trs->netif;
  int rc, intf_i;
  struct oo_buffer_pages *pages;
  int flags;
  struct efrm_pd *first_pd = NULL;
  struct oo_iobufset *first_iobuf = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    all_out[intf_i] = NULL;
  *pages_out = NULL;

#ifdef OO_DO_HUGE_PAGES
  BUILD_BUG_ON(HW_PAGES_PER_SET_S != HPAGE_SHIFT - PAGE_SHIFT);
#endif
#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( ci_geteuid() == ni->euid )
    flags = ni->huge_pages_flag;
  else
#endif
  flags = 0;
  rc = oo_iobufset_pages_alloc(HW_PAGES_PER_SET_S, &flags, &pages);
  if( rc != 0 )
    return rc;
#if CI_CFG_PKTS_AS_HUGE_PAGES
    if( (flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) &&
        !(ni->huge_pages_flag & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: unable to allocate huge page, using standard pages instead",
             ni->state->pretty_name);
      ni->huge_pages_flag = flags;
    }
#endif

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_pd *pd = efrm_vi_get_pd(trs->nic[intf_i].vi_rs);
    struct oo_iobufset *iobuf;

    if( first_pd != NULL && efrm_pd_share_dma_mapping(first_pd, pd) ) {
      ci_assert(first_iobuf);
      all_out[intf_i] = first_iobuf;
      o_iobufset_resource_ref(first_iobuf);
      memcpy(&hw_addrs[intf_i * (1 << HW_PAGES_PER_SET_S)], hw_addrs,
             sizeof(hw_addrs[0]) * (1 << HW_PAGES_PER_SET_S));
      continue;
    }

    rc = oo_iobufset_resource_alloc(pages, pd, &iobuf,
                        &hw_addrs[intf_i * (1 << HW_PAGES_PER_SET_S)]);
    if( rc < 0 ) {
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        if( all_out[intf_i] != NULL )
          oo_iobufset_resource_release(all_out[intf_i]);
      oo_iobufset_pages_release(pages);
      return rc;
    }
    all_out[intf_i] = iobuf;
    if( first_pd == NULL ) {
      first_pd = pd;
      first_iobuf = iobuf;
    }
  }

  *pages_out = pages;
  return 0;
}


int
efab_tcp_helper_more_bufs(tcp_helper_resource_t* trs)
{
  struct oo_iobufset* iobrs[CI_CFG_MAX_INTERFACES];
  struct oo_buffer_pages* pages;
  uint64_t *hw_addrs;
  ci_irqlock_state_t lock_flags;
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int i, rc, bufset_id, intf_i;

  ci_assert(ci_netif_is_locked(ni));

  if( in_atomic() && trs->avoid_atomic_allocations ) {
    /* this work item may be already in this workqueue,
     * so do not check rc */
    queue_work(trs->wq, &trs->non_atomic_work);
    return -EBUSY;
  }

  hw_addrs = ci_alloc(sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S) *
                      CI_CFG_MAX_INTERFACES);
  if( hw_addrs == NULL ) {
    ci_log("%s: [%d] out of memory", __func__, trs->id);
    return -ENOMEM;
  }

  rc = efab_tcp_helper_iobufset_alloc(trs, iobrs, &pages, hw_addrs);
  if(CI_UNLIKELY( rc < 0 )) {
    /* Fixme: with highly fragmented memory, iobufset_alloc may fail in
     * atomic context but succeed later in non-atomic context.
     * We should somehow differentiate temporary failures (atomic
     * allocation failure) and permanent failure (out of buffer table
     * entries).
     * */
    efab_tcp_helper_more_bufs_failed(trs, rc);
    ci_free(hw_addrs);
    return rc;
  }
  /* check we get the size we are expecting */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_assert(iobrs[intf_i] != NULL);
  ci_assert(pages != NULL);

  /* Install the new buffer allocation, protecting against multi-threads. */
  bufset_id = -1;
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( ni->pkt_sets_n < ni->pkt_sets_max ) {
    bufset_id = ni->pkt_sets_n;
    if( bufset_id < 0 ) {
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
      OO_DEBUG_ERR(ci_log("%s: weirdness n=%d max=%d freepkts=%d", __FUNCTION__,
                          ni->pkt_sets_n, ni->pkt_sets_max,
                          OO_PP_FMT(ni->state->freepkts)));
      ci_free(hw_addrs);
      return -EIO;
    }

    OO_DEBUG_SHM(ci_log("allocated new bufset id %d", bufset_id));
    ++ni->pkt_sets_n;
    ni->buf_pages[bufset_id] = pages;
#ifdef OO_DO_HUGE_PAGES
    trs->pkt_shm_id[bufset_id] = oo_iobufset_get_shmid(pages);
    if( trs->pkt_shm_id[bufset_id] >= 0 )
      CITP_STATS_NETIF_INC(ni, pkt_huge_pages);
#endif
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      ni->nic_hw[intf_i].pkt_rs[bufset_id] = iobrs[intf_i];
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  ni->state->pkt_sets_n = ni->pkt_sets_n;
  ni->state->n_pkts_allocated = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;

  /* Initialise the new buffers. */
  for( i = 0; i < PKTS_PER_SET; i++ ) {
    ci_ip_pkt_fmt* pkt;
    int id = (bufset_id * PKTS_PER_SET) + i;
    oo_pkt_p pp;

    OO_PP_INIT(ni, pp, id);
    pkt = __PKT(ni, pp);
    OO_PKT_PP_INIT(pkt, id);

    pkt->flags = 0;
    __ci_netif_pkt_clean(pkt);
    pkt->refcount = 0;
    pkt->stack_id = trs->id;
    pkt->pio_addr = -1;
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      pkt->dma_addr[intf_i] = hw_addrs[(intf_i) * (1 << HW_PAGES_PER_SET_S) +
                                       i / PKTS_PER_HW_PAGE] +
        CI_CFG_PKT_BUF_SIZE * (i % PKTS_PER_HW_PAGE) +
        CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start);
    }

    pkt->next = ni->state->freepkts;
    ns->freepkts = OO_PKT_P(pkt);
    ++ns->n_freepkts;
  }
  ci_free(hw_addrs);

  CHECK_FREEPKTS(ni);
  return 0;
}


#ifdef CI_HAVE_OS_NOPAGE
static unsigned long
tcp_helper_rm_nopage_iobuf(tcp_helper_resource_t* trs, void* opaque,
                           unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  int intf_i;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

#ifdef OO_DO_HUGE_PAGES
  if( offset < ni->state->buf_ofs ) {
#endif
    /* VIs (descriptor rings and event queues). */
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
      if( offset + CI_PAGE_SIZE <= trs_nic->vi_mem_mmap_bytes )
        return efab_vi_resource_nopage(trs_nic->vi_rs, opaque,
                                       offset, trs_nic->vi_mem_mmap_bytes);
      else
        offset -= trs_nic->vi_mem_mmap_bytes;
    }
#ifdef OO_DO_HUGE_PAGES
  }
  else if( offset < ni->state->buf_ofs +
           ni->pkt_sets_max * sizeof(trs->pkt_shm_id[0]) ) {
    offset -= ni->state->buf_ofs;
    return vmalloc_to_pfn((char *)trs->pkt_shm_id + offset);
  }
#endif
  OO_DEBUG_SHM(ci_log("%s: %u offset %ld too great",
                      __FUNCTION__, trs->id, offset));
  return (unsigned) -1;
}

static unsigned long
tcp_helper_rm_nopage_pkts(tcp_helper_resource_t* trs, void* opaque,
                          unsigned long offset)
{
  int bufset_id = offset / (CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
  ci_netif* ni = &trs->netif;

  if( ! ni->buf_pages[bufset_id] ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD offset=%lx bufset_id=%d",
                        __FUNCTION__, trs->id, offset, bufset_id));
    return (unsigned) -1;
  }

  offset -= bufset_id * CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET;
  return oo_iobufset_pfn(ni->buf_pages[bufset_id], offset);
}

unsigned long
tcp_helper_rm_nopage(tcp_helper_resource_t* trs, void* opaque,
                     int map_id, unsigned long offset)
{

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      return tcp_helper_rm_nopage_mem(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_IOBUFS:
      return tcp_helper_rm_nopage_iobuf(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_IO:
      ci_log("%s: map_id:%d", __FUNCTION__, map_id);
      ci_assert(0);
      return (unsigned) -1;
    default:
      return tcp_helper_rm_nopage_pkts(trs, opaque,
                                       offset +
                                       (map_id - CI_NETIF_MMAP_ID_PKTS) *
                                       CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
  }

  /* We currently provide no nopage support for dynamic ep_bufs or
   * pkt_bufs.  In theory, all that would have to be done is iterrate
   * through the unmapped but allocated bufs looking for the address.  Note
   * that this routine gives us the offset, so it will need to be changed!
   * FIXME
   */
}

#endif	/* CI_HAVE_OS_NOPAGE */


void
tcp_helper_rm_dump(int fd_type, oo_sp sock_id,
                   tcp_helper_resource_t* trs, const char *line_prefix) 
{
  ci_netif* ni;
  int intf_i;
  unsigned i;

  if( trs == NULL ) {
    ci_dllink *link;
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.all_stacks) {
      trs = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      tcp_helper_rm_dump(CI_PRIV_TYPE_NETIF, OO_SP_NULL, trs, line_prefix);
      for( i = 0; i < trs->netif.ep_tbl_n; ++i )
        if (trs->netif.ep_tbl[i]) {
          ci_sock_cmn *s = ID_TO_SOCK(&trs->netif, i);
          if (s->b.state == CI_TCP_STATE_FREE || s->b.state == CI_TCP_CLOSED)
            continue;
          tcp_helper_rm_dump(s->b.state == CI_TCP_STATE_UDP ?
                             CI_PRIV_TYPE_UDP_EP : CI_PRIV_TYPE_TCP_EP,
                             OO_SP_FROM_INT(&trs->netif, i), trs, line_prefix);
        }
    }
    return;
  }

  ni = &trs->netif;

  switch (fd_type) {
  case CI_PRIV_TYPE_NETIF: 
    ci_log("%stcp helper used as a NETIF mmap_bytes=%x", 
           line_prefix, trs->mem_mmap_bytes); 
    break;
  case CI_PRIV_TYPE_NONE:
    ci_log("%stcp helper, unspecialized (?!)", line_prefix);
    break;
  case CI_PRIV_TYPE_TCP_EP:
  case CI_PRIV_TYPE_UDP_EP:
    ci_log("%stcp helper specialized as %s endpoint with id=%u", 
           line_prefix, fd_type == CI_PRIV_TYPE_TCP_EP ? "TCP":"UDP", 
           OO_SP_FMT(sock_id));
    citp_waitable_dump(ni, SP_TO_WAITABLE(ni, sock_id), line_prefix);
    break;
#if CI_CFG_USERSPACE_PIPE
  case CI_PRIV_TYPE_PIPE_READER:
  case CI_PRIV_TYPE_PIPE_WRITER:
    ci_log("%stcp_helper specialized as PIPE-%s endpoint with id=%u",
           line_prefix,
           fd_type == CI_PRIV_TYPE_PIPE_WRITER ? "WR" : "RD",
           OO_SP_FMT(sock_id));
    citp_waitable_dump(ni, SP_TO_WAITABLE(ni, sock_id), line_prefix);
    break;
#endif
  default:
    ci_log("%sUNKNOWN fd_type (%d)", line_prefix, fd_type);
  }

  ci_log("%sref_count=%d k_ref_count=%d", line_prefix,
         oo_atomic_read(&trs->ref_count), trs->k_ref_count);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_log("%svi[%d]: %d", line_prefix, intf_i,
           ef_vi_instance(&ni->nic_hw[intf_i].vi));
}


/**********************************************************************
 * Callbacks (timers, interrupts)
 */


/*--------------------------------------------------------------------
 *!
 * Eventq callback
 *    - call OS dependent code to try and poll the stack
 *    - reprime timer and/of request wakeup if needed
 *
 *--------------------------------------------------------------------*/

static void tcp_helper_wakeup(tcp_helper_resource_t* trs, int intf_i)
{
  ci_netif* ni = &trs->netif;
  int n, prime_async;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Must clear this before the poll rather than waiting till later */
  ci_bit_clear(&ni->state->evq_primed, intf_i);

  /* Don't reprime if someone is spinning -- let them poll the stack. */
  prime_async = ! ci_netif_is_spinner(ni);

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
      CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
      ni->state->poll_did_wake = 0;
      n = ci_netif_poll(ni);
      CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
      if( ni->state->poll_did_wake ) {
        prime_async = 0;
        CITP_STATS_NETIF_INC(ni, interrupt_wakes);
      }
      efab_tcp_helper_netif_unlock(trs, 1);
    }
    else {
      /* Couldn't get the lock.  We take this as evidence that another thread
       * is alive and doing stuff, so no need to re-enable interrupts.  The
       * EF_INT_REPRIME option overrides.
       */
      CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
      if( ! NI_OPTS(ni).int_reprime )
        prime_async = 0;
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, interrupt_no_events);
  }

  if( prime_async )
    if( ni->state->last_spin_poll_frc > ni->state->last_sleep_frc )
      /* A spinning thread has polled the stack more recently than a thread
       * has gone to sleep.  We assume the spinning thread will handle
       * network events (or enable interrupts at some point), so no need to
       * enable interrupts here.
       */
      prime_async = 0;

  if( prime_async ) {
    if( ci_bit_test(&ni->state->evq_primed, intf_i) )
      tcp_helper_request_wakeup_nic(trs, intf_i);
    else if( ! ci_bit_test_and_set(&ni->state->evq_primed, intf_i) )
      tcp_helper_request_wakeup_nic(trs, intf_i);
    CITP_STATS_NETIF_INC(ni, interrupt_primes);
  }
}


static void tcp_helper_timeout(tcp_helper_resource_t* trs, int intf_i)
{
#if CI_CFG_HW_TIMER
  ci_netif* ni = &trs->netif;
  int i, n;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, timeout_interrupts);

  /* Re-prime the timer here to ensure it is re-primed even if we don't
   * call ci_netif_poll() below.  Updating [evq_last_prime] ensures we
   * won't re-prime it again in ci_netif_poll().
   */
  ci_frc64(&ni->state->evq_last_prime);
  if( NI_OPTS(ni).timer_usec != 0 )
    OO_STACK_FOR_EACH_INTF_I(ni, i)
      ef_eventq_timer_prime(&ni->nic_hw[i].vi, NI_OPTS(ni).timer_usec);

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
      CITP_STATS_NETIF(++ni->state->stats.timeout_interrupt_polls);
      ni->state->poll_did_wake = 0;
      if( (n = ci_netif_poll(ni)) ) {
        CITP_STATS_NETIF(ni->state->stats.timeout_interrupt_evs += n;
                         ni->state->stats.timeout_interrupt_wakes +=
                         ni->state->poll_did_wake);
      }
      efab_tcp_helper_netif_unlock(trs, 1);
    }
    else {
      CITP_STATS_NETIF_INC(ni, timeout_interrupt_lock_contends);
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, timeout_interrupt_no_events);
  }
#endif
}


static void oo_handle_wakeup_or_timeout(void* context, int is_timeout,
                                        struct efhw_nic* nic)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->intf_i], tcph_nic);

  if( ! CI_CFG_HW_TIMER || ! is_timeout )
    tcp_helper_wakeup(trs, tcph_nic->intf_i);
  else
    tcp_helper_timeout(trs, tcph_nic->intf_i);
}



static void oo_handle_wakeup_int_driven(void* context, int is_timeout,
                                        struct efhw_nic* nic_)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  ci_netif* ni;
  int n;

  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->intf_i], tcph_nic);
  ni = &trs->netif;

  ci_assert( ! is_timeout );
  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Grab lock and poll, or set bit so that lock holder will poll.  (Or if
   * stack is being destroyed, do nothing).
   */
  while( 1 ) {
    if( ci_netif_intf_has_event(ni, tcph_nic->intf_i) ) {
      if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
        CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
        ci_assert( ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT);
        ni->state->poll_did_wake = 0;
        n = ci_netif_poll(ni);
        CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
        if( ni->state->poll_did_wake )
          CITP_STATS_NETIF_INC(ni, interrupt_wakes);
        tcp_helper_request_wakeup_nic(trs, tcph_nic->intf_i);
        efab_tcp_helper_netif_unlock(trs, 1);
        break;
      }
      else {
        CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
      }
    }
    else {
      CITP_STATS_NETIF_INC(ni, interrupt_no_events);
      if( efab_tcp_helper_netif_lock_or_set_flags(trs,
                                               OO_TRUSTED_LOCK_NEED_PRIME,
                                               CI_EPLOCK_NETIF_NEED_PRIME,
                                               1) ) {
        tcp_helper_request_wakeup_nic(trs, tcph_nic->intf_i);
        efab_tcp_helper_netif_unlock(trs, 1);
      }
      break;
    }

    if( ef_eplock_set_flags_if_locked(&ni->state->lock,
                                      CI_EPLOCK_NETIF_NEED_POLL |
                                      CI_EPLOCK_NETIF_NEED_PRIME) ) {
      break;
    }
    else if( oo_trusted_lock_set_flags_if_locked(trs,
                                        OO_TRUSTED_LOCK_NEED_POLL |
                                        OO_TRUSTED_LOCK_NEED_PRIME) ) {
      break;
    }
  }
}


/*--------------------------------------------------------------------
 *!
 * TCP helper timer implementation 
 *
 *--------------------------------------------------------------------*/

/*** Linux ***/


static int 
linux_set_periodic_timer_tasklet(tcp_helper_resource_t* rs) 
{
  unsigned long t = ci_net_random() % CI_TCP_HELPER_PERIODIC_FLOAT_T;

  if (atomic_read(&rs->timer_running) == 0) 
    return 0;

  return mod_timer(&rs->timer,
                   jiffies + (CI_TCP_HELPER_PERIODIC_BASE_T) + t);
}

static void
linux_tcp_timer_do(tcp_helper_resource_t* rs)
{
  ci_netif* ni = &rs->netif;
  ci_uint64 now_frc;
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(rs, -1);
  OO_DEBUG_VERB(ci_log("%s: running", __FUNCTION__));

  oo_timesync_update(CICP_HANDLE(ni));

  /* Avoid interfering if stack has been active recently.  This code path
   * is only for handling time-related events that have not been handled in
   * the normal course of things because we've not had any network events.
   */
  ci_frc64(&now_frc);
  if( now_frc - ni->state->evq_last_prime >
      ni->state->timer_prime_cycles * 5 ) {
    if( efab_tcp_helper_netif_try_lock(rs, 1) ) {
      /* We can't safely do MCDI in this context.  We are running in a
       * softirq which can prevent the netdriver from handling the MCDI
       * completion on certain realtime kernels (more details in bug42745).
       */
      ci_assert( (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) );
      rc = ci_netif_poll(ni);
      efab_tcp_helper_netif_unlock(rs, 1);
      CITP_STATS_NETIF_INC(ni, periodic_polls);
      if( rc > 0 )
        CITP_STATS_NETIF_ADD(ni, periodic_evs, rc);
    }
    else {
      CITP_STATS_NETIF_INC(ni, periodic_lock_contends);
    }
  }

  /* Monitor number of free packets  */
  if( rs->avoid_atomic_allocations &&
      NI_OPTS(ni).max_packets > (ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S) &&
      ni->state->n_freepkts < NI_OPTS(ni).free_packets_low /2 ) {
    queue_work(rs->wq, &rs->non_atomic_work);
  }
}

static void
linux_tcp_timer_tasklet(unsigned long l)
{
  tcp_helper_resource_t* rs = (tcp_helper_resource_t*)l;
  linux_tcp_timer_do(rs);
}

static void
linux_tcp_helper_periodic_timer(unsigned long l)
{
  tcp_helper_resource_t* rs = (tcp_helper_resource_t*)l;

  ci_assert(NULL != rs);

  OO_DEBUG_VERB(ci_log("linux_tcp_helper_periodic_timer: fired"));

  tasklet_schedule(&rs->tasklet);
  linux_set_periodic_timer_tasklet(rs);
}

static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t* rs)
{
  atomic_set(&rs->timer_running, 1);

  init_timer(&rs->timer);
  rs->timer.function = &linux_tcp_helper_periodic_timer;
  rs->timer.data = (unsigned long) rs;
  tasklet_init(&rs->tasklet, &linux_tcp_timer_tasklet,
               (unsigned long)rs);

  linux_set_periodic_timer_tasklet(rs);
}


static void
tcp_helper_stop_periodic_timer(tcp_helper_resource_t* rs)
{
  atomic_set(&rs->timer_running, 0);

  del_timer_sync(&rs->timer);
  tasklet_kill(&rs->tasklet);
}

/*--------------------------------------------------------------------*/

/** Solaris **/

/*--------------------------------------------------------------------
 *!
 * End of TCP helper timer implementation
 *
 *--------------------------------------------------------------------*/


void
efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs, oo_sp ep_id)
{
  ci_netif* ni;
  tcp_helper_endpoint_t* tep_p;
  ci_irqlock_state_t lock_flags;

  ni = &trs->netif;
  tep_p = ci_trs_ep_get(trs, ep_id);

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] k_ref_count=%d", __FUNCTION__,
                       trs->id, OO_SP_FMT(ep_id), trs->k_ref_count));

  ci_assert(!(SP_TO_WAITABLE(ni, ep_id)->sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(! in_atomic());

  /* Drop ref to the OS socket.  Won't necessarily be the last reference to it;
   * there may also be one from the filter, and others from dup'd or forked
   * processes.  This needs to be done here rather since fput can block.
   */
  if( tep_p->os_socket != NULL ) {
    ci_irqlock_state_t lock_flags;
    struct oo_file_ref* os_socket;
    ci_assert( !(SP_TO_WAITABLE(ni, ep_id)->sb_flags & CI_SB_FLAG_MOVED) );

    /* Shutdown() the os_socket.  This needs to be done in a blocking
     * context.
     */
    if( SP_TO_WAITABLE(ni, ep_id)->state == CI_TCP_LISTEN )
      efab_tcp_helper_shutdown_os_sock(tep_p, SHUT_RDWR);
    efab_tcp_helper_os_pollwait_unregister(tep_p);

    ci_irqlock_lock(&trs->lock, &lock_flags);
    os_socket = tep_p->os_socket;
    tep_p->os_socket = NULL;
    ci_irqlock_unlock(&trs->lock, &lock_flags);
    if( os_socket != NULL )
      oo_file_ref_drop(os_socket);
  }

  /* Legacy Clustering: where we do this needs consideration in conjunction
   * with what we decide about orphans and re-using clusters.
   */
  if( tep_p->ep_aflags & OO_THR_EP_AFLAG_LEGACY_REUSEPORT )
    tcp_helper_cluster_legacy_os_close(tep_p);

  /*! Add ep to the list in tcp_helper_resource_t for closing
    *   - we don't increment the ref count - as we need it to reach 0 when
    * the application exits i.e. crashes (even if its holding the netif lock)
    */
  ci_irqlock_lock(&trs->lock, &lock_flags);
  ci_sllist_push(&trs->ep_tobe_closed, &tep_p->tobe_closed);
  ci_irqlock_unlock(&trs->lock, &lock_flags);

  /* set flag in eplock to signify callback needed when netif unlocked
   * 
   * It is fine to pass 0 value as in_dl_context parameter to the function
   * for in the driverlink context the trusted lock is already held and
   * effectively the following clause only sets a flag, no lock
   * gets obtained and the inner clause is skipped.
   */

  if( efab_tcp_helper_netif_lock_or_set_flags(trs,
                                            OO_TRUSTED_LOCK_CLOSE_ENDPOINT,
                                            CI_EPLOCK_NETIF_CLOSE_ENDPOINT,
                                            0) ) {
    OO_DEBUG_TCPH(ci_log("%s: [%d:%d] closing now",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep_id)));
    ci_assert(! in_atomic());
    tcp_helper_close_pending_endpoints(trs);
    efab_tcp_helper_netif_unlock(trs, 0);
  }
  else {
    OO_DEBUG_TCPH(ci_log("%s: [%d:%d] closing deferred to lock holder",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep_id)));
  }

  if( efab_tcp_driver.file_refs_to_drop != NULL )
    oo_file_ref_drop_list_now(NULL);
}


void generic_tcp_helper_close(ci_private_t* priv)
{
  tcp_helper_resource_t* trs;
  tcp_helper_endpoint_t* ep;

  ci_assert(CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type));
  trs = efab_priv_to_thr(priv);
  ep = ci_trs_ep_get(trs, priv->sock_id);


  if (ep->fasync_queue) {
    OO_DEBUG_SHM(ci_log("generic_tcp_helper_close removing fasync helper"));
    linux_tcp_helper_fop_fasync(-1, ci_privf(priv), 0);
  }

 efab_tcp_helper_close_endpoint(trs, ep->id);
}


/**********************************************************************
 * CI_RESOURCE_OPs.
 */

int
efab_attach_os_socket(tcp_helper_endpoint_t* ep, struct file* os_file)
{
  int rc;
  struct oo_file_ref* os_socket;

  ci_assert(ep);
  ci_assert(os_file);
  ci_assert_equal(ep->os_socket, NULL);

  rc = oo_file_ref_lookup(os_file, &os_socket);
  if( rc < 0 ) {
    fput(os_file);
    OO_DEBUG_ERR(ci_log("%s: %d:%d os_file=%p lookup failed (%d)",
                        __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
                        os_file, rc));
    return rc;
  }

  /* Check that this os_socket is really a socket. */
  if( !S_ISSOCK(os_file->f_dentry->d_inode->i_mode) ||
      SOCKET_I(os_file->f_dentry->d_inode)->file != os_file) {
    oo_file_ref_drop(os_socket);
    OO_DEBUG_ERR(ci_log("%s: %d:%d os_file=%p is not a socket",
                        __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
                        os_file));
    return -EBUSY;
  }
  
  ep->os_socket = os_socket;
  if( SP_TO_WAITABLE(&ep->thr->netif, ep->id)->state == CI_TCP_STATE_UDP )
    efab_tcp_helper_os_pollwait_register(ep);
  return 0;
}



/**********************************************************************
***************** Wakeups, callbacks, signals, events. ****************
**********************************************************************/

void tcp_helper_endpoint_wakeup(tcp_helper_resource_t* thr,
                                tcp_helper_endpoint_t* ep)
{
  citp_waitable* w = SP_TO_WAITABLE(&thr->netif, ep->id);
  int wq_active;
  w->wake_request = 0;
  wq_active = ci_waitable_active(&ep->waitq);
  ci_waitable_wakeup_all(&ep->waitq);
  if( wq_active ) {
    thr->netif.state->poll_did_wake = 1;
    if( w->sb_flags & CI_SB_FLAG_WAKE_RX )
      CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_rx);
    if( w->sb_flags & CI_SB_FLAG_WAKE_TX )
      CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_tx);
  }
  w->sb_flags = 0;
  /* Check to see if application has requested ASYNC notification */
  if( ep->fasync_queue ) {
    LOG_TV(ci_log(NWS_FMT "async notification sigown=%d",
                  NWS_PRI_ARGS(&thr->netif, w), w->sigown));
    kill_fasync(&ep->fasync_queue, SIGIO, POLL_IN);
    CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_signal);
    if( w->sigown )
      /* Ensure we keep getting notified. */
      ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_RX_B);
  }
}


static void
wakeup_post_poll_list(tcp_helper_resource_t* thr)
{
  ci_netif* ni = &thr->netif;
  tcp_helper_endpoint_t* ep;
  int n = ni->ep_tbl_n;
  ci_ni_dllist_link* lnk;
  citp_waitable* w;

  LOG_TV(if( ci_ni_dllist_is_empty(ni, &ni->state->post_poll_list) )
           ci_log("netif_lock_callback: need_wake but empty"));

  /* [n] ensures the loop will terminate in reasonable time no matter how
  ** badly u/l behaves.
  */
  while( n-- > 0 && ci_ni_dllist_not_empty(ni, &ni->state->post_poll_list) ) {
    lnk = ci_ni_dllist_head(ni, &ni->state->post_poll_list);
    w = CI_CONTAINER(citp_waitable, post_poll_link, lnk);
    ci_ni_dllist_remove_safe(ni, &w->post_poll_link);
    ep = ci_netif_get_valid_ep(ni, W_SP(w));
    tcp_helper_endpoint_wakeup(thr, ep);
  }
}


/*--------------------------------------------------------------------
 *!
 * Callback installed with the netif (kernel/user mode shared) eplock
 * so we can get notified when the lock is dropped
 *
 * This code is either called with the kernel netif lock held (if the
 * common eplock is dropped from kernel mode). It can also be called
 * when user mode drops the eplock with the kernel lock not held.
 * However in this case we know the user mode still exists and has a
 * file open on efab. Therefore, we know that this cannot race with
 * efab_tcp_helper_rm_free_locked which is called whilst holding the kernel
 * lock once user mode has closed all efab file handles
 *
 * \param arg             TCP helper resource
 * \param lock_val        lock value
 *
 * \return                final lock value just before unlock
 *
 *--------------------------------------------------------------------*/

unsigned
efab_tcp_helper_netif_lock_callback(eplock_helper_t* epl, ci_uint32 lock_val)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t,
                                            netif.eplock_helper, epl);
  const unsigned all_after_unlock_flags = (CI_EPLOCK_NETIF_NEED_PRIME |
                                           CI_EPLOCK_NETIF_PKT_WAKE);
  ci_netif* ni = &thr->netif;
  unsigned flags_set, clear_flags;
  unsigned after_unlock_flags = 0;
  int intf_i;
  int in_dl_context = ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT;

  ci_assert(ci_netif_is_locked(ni));


  do {
    clear_flags = 0;

    if( lock_val & CI_EPLOCK_NETIF_IS_PKT_WAITER )
      if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
        clear_flags |= CI_EPLOCK_NETIF_IS_PKT_WAITER;
        after_unlock_flags |= CI_EPLOCK_NETIF_PKT_WAKE;
        lock_val = ni->state->lock.lock;
        CITP_STATS_NETIF_INC(ni, unlock_slow_pkt_waiter);
      }

    /* Do this first as it might request another address space */
    if( lock_val & CI_EPLOCK_NETIF_SOCKET_LIST ) {
      CITP_STATS_NETIF_INC(ni, unlock_slow_socket_list);
      lock_val = ci_netif_purge_deferred_socket_list(ni);
    }
    /* Get flags set and clear them.  NB. Its possible no flags were set
    ** e.g. we tried to unlock the eplock (bottom of loop) but found
    ** someone had tried to lock it and therefore set the "need wake" bit.
    */
    flags_set = lock_val & CI_EPLOCK_NETIF_UNLOCK_FLAGS;
    ef_eplock_clear_flags(&ni->state->lock, clear_flags | flags_set);
    after_unlock_flags |= flags_set;

    /* All code between here and the bottom of the loop should use
    ** [flags_set], and must not touch [lock_val].  If any flags
    ** subsequently get re-set, then we'll come round the loop again.
    */

    if( flags_set & CI_EPLOCK_NETIF_NEED_POLL ) {
      CITP_STATS_NETIF(++ni->state->stats.deferred_polls);
      ci_netif_poll(ni);
    }

    if( flags_set & CI_EPLOCK_NETIF_NEED_WAKE ) {
      wakeup_post_poll_list(thr);
      CITP_STATS_NETIF(++ni->state->stats.unlock_slow_wake);
    }

    if( flags_set & CI_EPLOCK_NETIF_RESET_STACK )
      tcp_helper_reset_stack_locked(thr);

    if( flags_set & CI_EPLOCK_NETIF_CLOSE_ENDPOINT ) {
      if( oo_trusted_lock_lock_or_set_flags(thr,
                                            OO_TRUSTED_LOCK_CLOSE_ENDPOINT) ) {
        /* We've got both locks.  If in non-atomic context, do the work,
         * else defer work and locks to workitem.
         */
        if( in_atomic() ) {
          OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to workitem",
                               __FUNCTION__, thr->id));
          ci_atomic32_or(&thr->trs_aflags, OO_THR_AFLAG_CLOSE_ENDPOINTS);
          queue_work(thr->wq, &thr->non_atomic_work);
          if( after_unlock_flags & all_after_unlock_flags )
            ef_eplock_holder_set_flags(&ni->state->lock,
                                 after_unlock_flags & all_after_unlock_flags);
          return 0;
        }
        OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINT now",
                             __FUNCTION__, thr->id));
        tcp_helper_close_pending_endpoints(thr);
        oo_trusted_lock_drop(thr, in_dl_context);
        CITP_STATS_NETIF(++ni->state->stats.unlock_slow_close);
      }
      else {
        /* Trusted lock holder now responsible for non-atomic work. */
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to trusted lock",
                             __FUNCTION__, thr->id));
      }
    }

  } while ( !ef_eplock_try_unlock(&ni->state->lock, &lock_val,
                                  CI_EPLOCK_NETIF_UNLOCK_FLAGS |
                                  CI_EPLOCK_NETIF_SOCKET_LIST) );

  /* Its important that we clear [defer_work_count] after dropping the
   * lock.  Otherwise it won't stop us from continuing to do deferred work
   * forever!
   */
  ni->state->defer_work_count = 0;

  if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME ) {
    CITP_STATS_NETIF_INC(&thr->netif, unlock_slow_need_prime);
    if( NI_OPTS(ni).int_driven ) {
      /* TODO: When interrupt driven, evq_primed is never cleared, so we
       * don't know here which subset of interfaces needs to be primed.
       * Would be more efficient if we did.
       */
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        tcp_helper_request_wakeup_nic(thr, intf_i);
    }
    else {
      tcp_helper_request_wakeup(thr);
    }
  }

  if( after_unlock_flags & CI_EPLOCK_NETIF_PKT_WAKE ) {
    CITP_STATS_NETIF_INC(&thr->netif, pkt_wakes);
    ci_waitq_wakeup(&thr->pkt_waitq);
  }

  /* ALERT!  If [after_unlock_flags] is used for any more flags, they must
   * be included in all_after_unlock_flags above!
   */

  return lock_val;
}


/**********************************************************************
***************** Iterators to find netifs ***************************
**********************************************************************/

/*--------------------------------------------------------------------
 *!
 * Called to iterate through all the various netifs, where we feel
 * safe to continue with an unlocked netif. This function guareetees
 * the netif pointer will remain valid BUT callees need to be aware
 * that other contexts could be changing the netif state.
 *
 * If the caller wants to stop iteration before the function returns
 * non-zero, he should drop the netif reference by calling
 * iterate_netifs_unlocked_dropref().
 *
 * Usage:
 *   netif = NULL;
 *   while (iterate_netifs_unlocked(&netif) == 0) {
 *     do_something_useful_with_each_netif;
 *     if (going_to_stop) {
 *       iterate_netifs_unlocked_dropref(netif);
 *       break;
 *     }
 *     do_something;
 *   }
 *
 * \param p_ni       IN: previous netif (NULL to start)
 *                   OUT: next netif
 *
 * \return either an unlocked netif or NULL if no more netifs
 *
 *--------------------------------------------------------------------*/

extern int
iterate_netifs_unlocked(ci_netif **p_ni)
{
  ci_netif *ni_prev = *p_ni;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t * thr_prev = NULL;
  ci_dllink *link = NULL;
  int rc = -ENOENT;

  if (ni_prev) {
    thr_prev = CI_CONTAINER(tcp_helper_resource_t, netif, ni_prev);
    TCP_HELPER_RESOURCE_ASSERT_VALID(thr_prev, -1);
  }

  /* We need a lock to protect the link and thr from removing 
   * after we've got the link and before taking refcount */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  if (ni_prev != NULL) {
    link = thr_prev->all_stacks_link.next;
    if (ci_dllist_end(&THR_TABLE.all_stacks) == link)
      link = NULL;
  } else if (ci_dllist_not_empty(&THR_TABLE.all_stacks))
    link = ci_dllist_start(&THR_TABLE.all_stacks);

  if (link) {
    int ref_count;
    tcp_helper_resource_t * thr;

    /* Skip dead thr's */
again:
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    /* get a kernel refcount */
    do {
      ref_count = thr->k_ref_count;
      if (ref_count & TCP_HELPER_K_RC_DEAD) {
        link = link->next;
        if (ci_dllist_end(&THR_TABLE.all_stacks) == link) {
          *p_ni = NULL;
          goto out;
        }
        goto again;
      }
    } while (ci_cas32_fail(&thr->k_ref_count, ref_count, ref_count + 1));

    rc = 0;
    *p_ni = &thr->netif;
  }

out:
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (ni_prev != NULL)
    efab_tcp_helper_k_ref_count_dec(thr_prev, 0);
  return rc;
}



extern int efab_ipid_alloc(efab_ipid_cb_t* ipid)
{
  int i;
  int rv;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );
  ci_irqlock_lock( &ipid->lock, &lock_flags );

  /* go find an unused block */
  i = ipid->last_block_used;
  do {
    i = (i + 1) % CI_IPID_BLOCK_COUNT;
    if( i == ipid->last_block_used )
      break;
    if( !ipid->range[i] ) {
      ipid->range[i]++;
      rv = CI_IPID_MIN + (i << CI_IPID_BLOCK_SHIFT);
      ci_assert((rv >= CI_IPID_MIN) && 
                (rv <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));
      ipid->last_block_used = i;
      goto alloc_exit;
    } else {
      ci_assert( ipid->range[i] == 1 );
    }
  } while(1);
  /* !!Out of blocks!! */
  rv = -ENOMEM;

 alloc_exit:
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return rv;
}


int
efab_ipid_free(efab_ipid_cb_t* ipid, int base )
{
  int i;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );

  if(  (base & CI_IPID_BLOCK_MASK) != 0 )
    return -EINVAL;  /* not actually on a block boundary */

  ci_assert((base >= CI_IPID_MIN) && 
            (base <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));

  ci_irqlock_lock( &ipid->lock, &lock_flags );
  i = (base - CI_IPID_MIN) >> CI_IPID_BLOCK_SHIFT;
  ci_assert( ipid->range[i] == 1 );
  ipid->range[i] = 0;
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return 0;
}

/*! \cidoxg_end */
