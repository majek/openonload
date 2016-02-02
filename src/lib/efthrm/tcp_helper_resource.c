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
**      Author: ctk
**     Started: 2004/03/15
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <ci/internal/transport_config_opt.h>
# include <onload_kernel_compat.h>
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
#include <etherfabric/internal/internal.h>
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
#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif
#include "tcp_helper_resource.h"


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

#ifdef EFRM_DO_NAMESPACES
static void (*my_free_nsproxy)(struct nsproxy *ns);
static inline void my_put_nsproxy(struct nsproxy *ns)
{
	if (atomic_dec_and_test(&ns->count)) {
		my_free_nsproxy(ns);
	}
}

#define put_nsproxy my_put_nsproxy
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

#ifdef CONFIG_PREEMPT
unsigned long oo_avoid_wakeup_under_pressure = 1;
#else
unsigned long oo_avoid_wakeup_under_pressure = 0;
#endif
module_param(oo_avoid_wakeup_under_pressure, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_avoid_wakeup_under_pressure,
                 "Avoid endpoint wakeups for this number of jiffies after "
                 "NAPI budget limited interrupt handler.  This is typically "
                 "needed on realtime kernels, where you can see "
                 "\"stall on CPU\" messages when this value is set to 0.");
DEFINE_PER_CPU(unsigned long, oo_budget_limit_last_ts);

/* Global structure for onload driver */
efab_tcp_driver_t efab_tcp_driver;


static int oo_handle_wakeup_int_driven(void*, int is_timeout,
                                        struct efhw_nic*, int budget);

static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t*, int can_destroy_now);
static void
efab_tcp_helper_rm_schedule_free(tcp_helper_resource_t*);

static int
oo_handle_wakeup_or_timeout(void*, int is_timeout,
                            struct efhw_nic*, int budget);
static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t*);
static void
tcp_helper_stop_periodic_work(tcp_helper_resource_t*);

static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t*);

static void
tcp_helper_purge_txq_work(struct work_struct *data);

static void
tcp_helper_reset_stack_work(struct work_struct *data);

static void
get_os_ready_list(tcp_helper_resource_t* thr, int ready_list);


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
  unsigned l, new_l;
  ci_uint64 sl_flags;
  ci_netif* ni = &trs->netif;
  int i;

 again:
  l = trs->trusted_lock;
  ci_assert(l & OO_TRUSTED_LOCK_LOCKED);

  if(CI_UNLIKELY( l & OO_TRUSTED_LOCK_AWAITING_FREE )) {
    /* We may be called from the stack workqueue, so postpone destruction
     * to the point where wq may be flushed */
    efab_tcp_helper_rm_schedule_free(trs);
    return;
  }

  if( l == OO_TRUSTED_LOCK_LOCKED ) {
    if( ci_cas32_fail(&trs->trusted_lock, l, OO_TRUSTED_LOCK_UNLOCKED) ) {
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
      /* We've got both locks.  If in non-dl context, do the work, else
       * defer work and locks to workitem.
       */
      if( in_dl_context ) {
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to workitem",
                             __FUNCTION__, trs->id));
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_CLOSE_ENDPOINTS);
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

  if( l & OO_TRUSTED_LOCK_OS_READY ) {
    new_l = l & ~OO_TRUSTED_LOCK_OS_READY;
    if( ci_cas32_fail(&trs->trusted_lock, l, new_l) )
      goto again;
    if( ef_eplock_lock_or_set_flag(&trs->netif.state->lock,
                                   CI_EPLOCK_NETIF_NEED_WAKE) ) {
      /* We've got both locks, do the work now. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] OS READY now",
                           __FUNCTION__, trs->id));
      for( i = 1; i < CI_CFG_N_READY_LISTS; i++ ) {
        if( trs->netif.state->ready_lists_in_use & (1 << i) ) {
          get_os_ready_list(trs, i);
          if( ci_ni_dllist_not_empty(&trs->netif,
                                     &trs->netif.state->ready_lists[i]))
            ci_waitable_wakeup_all(&trs->ready_list_waitqs[i]);
        }
      }
      ci_netif_unlock(&trs->netif);
    }
    else {
      /* Untrusted lock holder now responsible for invoking work. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] defer OS READY WAKE to trusted lock",
                           __FUNCTION__, trs->id));
    }
    goto again;
  }

  sl_flags = 0;
  if( l & OO_TRUSTED_LOCK_NEED_POLL )
    sl_flags |= CI_EPLOCK_NETIF_NEED_POLL;
  if( l & OO_TRUSTED_LOCK_NEED_PRIME )
    sl_flags |= CI_EPLOCK_NETIF_NEED_PRIME;
  if( l & OO_TRUSTED_LOCK_SWF_UPDATE )
    sl_flags |= CI_EPLOCK_NETIF_SWF_UPDATE;
  if( l & OO_TRUSTED_LOCK_PURGE_TXQS )
    sl_flags |= CI_EPLOCK_NETIF_PURGE_TXQS;
  ci_assert(sl_flags != 0);
  if( ci_cas32_succeed(&trs->trusted_lock, l, OO_TRUSTED_LOCK_LOCKED) &&
      ef_eplock_trylock_and_set_flags(&trs->netif.state->lock, sl_flags) ) {
    if( in_dl_context )
      ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
    ci_netif_unlock(&trs->netif);
  }
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
    if( ci_netif_trylock(&trs->netif) ) {
      ci_assert( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) );
      if( in_dl_context )
        ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
      return 1;
    }
    oo_trusted_lock_drop(trs, in_dl_context);
  }
  return 0;
}


void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t* trs, int in_dl_context)
{
  ci_assert_equiv(in_dl_context, trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT);
  ci_netif_unlock(&trs->netif);
  oo_trusted_lock_drop(trs, in_dl_context);
}


/* Returns 1 if the locks are held, or 0 if not and the flags are set. 
 *   
 * NB if trusted lock has OO_TRUSTED_LOCK_AWAITING_FREE this function
 * will return 0, but the flags will not be set 
 */
int
efab_tcp_helper_netif_lock_or_set_flags(tcp_helper_resource_t* trs, 
                                        unsigned trusted_flags,
                                        ci_uint64 untrusted_flags,
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


static void dump_stack_to_logger(void* netif, oo_dump_log_fn_t logger,
                                 void* log_arg)
{
    logger(log_arg,
           "============================================================");
    ci_netif_dump_to_logger(netif, logger, log_arg);
    logger(log_arg,
           "============================================================");
    ci_netif_dump_sockets_to_logger(netif, logger, log_arg);
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
  table->stack_count = 0;
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

  ci_assert( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND );

  /* Fixme: timeout is not appropriate here.  We should not leak OS socket
   * and filters. */
  if( efab_eplock_lock_timeout(&thr->netif, msecs_to_jiffies(500)) == 0 ) {
    for( id = 0; id < thr->netif.state->n_ep_bufs; ++id ) {
      citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(&thr->netif, id);
      if( wo->waitable.state == CI_TCP_TIME_WAIT ||
          ci_tcp_is_timeout_orphan(&wo->tcp) )
        wo->tcp.t_last_sent = ci_ip_time_now(&thr->netif);
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
    dump_stack_to_logger(&thr->netif, ci_log_dump_fn, NULL);
#endif
  }

  for( ; n_dec_needed > 0; --n_dec_needed )
    efab_tcp_helper_k_ref_count_dec(thr);
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


int tcp_helper_dump_stack(unsigned id, unsigned orphan_only,
                          void* user_buf, int user_buf_len)
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
    if ( user_buf != NULL )
      rc = oo_dump_to_user(dump_stack_to_logger, &thr->netif, user_buf,
                           user_buf_len);
    else
      dump_stack_to_logger(&thr->netif, ci_log_dump_fn, NULL);

    efab_tcp_helper_k_ref_count_dec(thr);
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
  if( ni->state != NULL ) {
    ni->state->opts.max_packets = NI_OPTS(ni).max_packets;
    ni->state->opts.max_rx_packets = NI_OPTS(ni).max_rx_packets;
    ni->state->opts.max_tx_packets = NI_OPTS(ni).max_tx_packets;
  }
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
    efab_tcp_helper_k_ref_count_dec(thr);
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
    return EFAB_VI_RESOURCE_INSTANCE(trs->nic[intf_i].thn_vi_rs);
  else
    return -1;
}


#if CI_CFG_SEPARATE_UDP_RXQ
int tcp_helper_udp_rxq_rx_vi_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_netif* ni = &trs->netif;
  if( NI_OPTS(ni).separate_udp_rxq ) {
    ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
    if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
      return EFAB_VI_RESOURCE_INSTANCE(trs->nic[intf_i].thn_udp_rxq_vi_rs);
  }
  return -1;
}
#endif


int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 ) {
    struct efrm_vi* vi = trs->nic[intf_i].thn_vi_rs;
    struct efrm_pd* pd = efrm_vi_pd_get(vi);
    return efrm_pd_stack_id_get(pd);
  }
  else
    return -1;
}


int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport)
{
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( thc->thc_vi_set[hwport] != NULL ) {
    struct efrm_pd* pd = efrm_vi_set_get_pd(thc->thc_vi_set[hwport]);
    return efrm_pd_stack_id_get(pd);
  }
  else
    return -1;
}


int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport)
{
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( thc->thc_vi_set[hwport] != NULL )
    return efrm_vi_set_get_base(thc->thc_vi_set[hwport]);
  else
    return -1;
}


int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                           int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return efrm_vi_is_hw_rx_loopback_supported(trs->nic[intf_i].thn_vi_rs);
  else
    return -1;
}


#if CI_CFG_PIO

# if ! CI_CFG_USE_PIO

/* PIO should not be used: Check whether we should continue and emit
 * warning.
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
    rc = -EOPNOTSUPP;
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

  if( trs_nic->thn_pio_rs == NULL ) {
    rc = efrm_pio_alloc(pd, &trs_nic->thn_pio_rs);
    if( rc < 0 ) {
      if( NI_OPTS(ni).pio == 1 ) {
        if( rc == -ENOSPC ) {
          ci_log("[%s]: WARNING: all PIO bufs allocated to other stacks. "
                 "Continuing without PIO.  Use EF_PIO to control this.",
                 ns->pretty_name);
          return 0;
        }
        else {
          CI_NDEBUG( if( rc != -ENETDOWN ) )
            /* ENETDOWN means absent hardware, so this failure is
             * expected, and we should not warn about it in NDEBUG
             * builds 
             */
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
  rc = efrm_pio_link_vi(trs_nic->thn_pio_rs, trs_nic->thn_vi_rs);
  if( rc < 0 ) {
    efrm_pio_release(trs_nic->thn_pio_rs);
    trs_nic->thn_pio_rs = NULL;
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
  rc = efrm_pio_map_kernel(nic, trs_nic->thn_vi_rs, 
                           (void**)&netif_nic->pio.pio_io);
  if( rc < 0 ) {
    efrm_pio_unlink_vi(trs_nic->thn_pio_rs, trs_nic->thn_vi_rs);
    efrm_pio_release(trs_nic->thn_pio_rs);
    trs_nic->thn_pio_rs = NULL;
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
  netif_nic->pio.pio_len = efrm_pio_get_size(trs_nic->thn_pio_rs);
  /* Advertise that PIO can be used on this VI */
  nsn->oo_vi_flags |= OO_VI_FLAGS_PIO_EN;
  /* Advertise how should be mapped for this VI */
  ci_assert_le(netif_nic->pio.pio_len, CI_PAGE_SIZE);
  nsn->pio_io_mmap_bytes = CI_PAGE_SIZE;
  /* and how much of that mapping is usable */
  nsn->pio_io_len = netif_nic->pio.pio_len;
  /* and record a copy that UL can't modify */
  trs_nic->thn_pio_io_mmap_bytes = nsn->pio_io_mmap_bytes;
  netif_nic->vi.linked_pio = &netif_nic->pio;
  trs->pio_mmap_bytes += CI_PAGE_SIZE;
  *pio_buf_offset += efrm_pio_get_size(trs_nic->thn_pio_rs);
  /* Drop original ref to PIO region as linked VI now holds it */ 
  efrm_pio_release(trs_nic->thn_pio_rs);
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


static int allocate_pd(ci_netif* ni, struct vi_allocate_info* info,
                       struct efhw_nic* nic)
{
  int rc = 0;
#ifdef CONFIG_SFC_RESOURCE_VF
  struct efrm_vf *first_vf = NULL;
#endif

  switch( NI_OPTS(ni).packet_buffer_mode ) {
  case 0:
    if( nic->devtype.arch == EFHW_ARCH_EF10 )
      ni->flags |= CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION;
    break;

  case CITP_PKTBUF_MODE_VF:
  case CITP_PKTBUF_MODE_VF | CITP_PKTBUF_MODE_PHYS:
#ifndef CONFIG_SFC_RESOURCE_VF
    rc = -ENODEV;
    return rc;
#else
    rc = efrm_vf_resource_alloc(info->client, first_vf,
                                !(NI_OPTS(ni).packet_buffer_mode &
                                  CITP_PKTBUF_MODE_PHYS),
                                &info->vf);
    if( rc < 0 ) {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vf_resource_alloc(%d) failed %d",
                           __FUNCTION__, info->intf_i, rc));
      return rc;
    }
    ci_assert(info->vf);

    if( first_vf == NULL ) {
      first_vf = info->vf;
      if( efrm_vf_avoid_atomic_allocations )
        ni->flags |= CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION;
    }

    /* FALLTHROUGH - all VF modes are phys modes from the internal
     * point of view */
#endif

  case CITP_PKTBUF_MODE_PHYS:
    info->ef_vi_flags |= EF_VI_RX_PHYS_ADDR | EF_VI_TX_PHYS_ADDR;
    break;
  }

  if( info->cluster == NULL ) {
    rc = efrm_pd_alloc(&info->pd, info->client, info->vf,
        ((info->ef_vi_flags & EF_VI_RX_PHYS_ADDR) ?
            EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE : 0) |
        ((info->oo_vi_flags & OO_VI_FLAGS_TX_HW_LOOPBACK_EN) ?
            EFRM_PD_ALLOC_FLAG_HW_LOOPBACK : 0) );
#ifdef CONFIG_SFC_RESOURCE_VF
    if( info->vf != NULL )
      efrm_vf_resource_release(info->vf); /* pd keeps a ref to vf */
#endif
    if( rc != 0 ) {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pd_alloc(%d) failed %d",
                         __FUNCTION__, info->intf_i, rc));
      return rc;
    }
    ci_assert(info->pd);
    info->release_pd = 1;
    info->vi_set = NULL;
  }
  else {
    int hwport = ni->intf_i_to_hwport[info->intf_i];
    ci_assert_ge(hwport, 0);
    info->vi_set = info->cluster->thc_vi_set[hwport];
    info->release_pd = 0;
    info->pd = efrm_vi_set_get_pd(info->vi_set);
  }

  return rc;
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


static int
get_vi_settings(ci_netif* ni, struct efhw_nic* nic,
                struct vi_allocate_info* info)
{
  int rc;

  info->wakeup_cpu_core = NI_OPTS(ni).irq_core;
  info->log_resource_warnings = NI_OPTS(ni).log_category &
                              (1 << (EF_LOG_RESOURCE_WARNINGS));
  if( NI_OPTS(ni).irq_core < 0 && NI_OPTS(ni).irq_channel < 0 ) {
    info->wakeup_cpu_core = raw_smp_processor_id();
    info->log_resource_warnings = 0;
  }

#if CI_CFG_UDP
  if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
      (NI_OPTS(ni).mcast_recv_hw_loop) ) {
    info->efhw_flags |= EFHW_VI_RX_LOOPBACK;
  } else {
    info->efhw_flags &= ~EFHW_VI_RX_LOOPBACK;
  }
  if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
      (NI_OPTS(ni).mcast_send & CITP_MCAST_SEND_FLAG_EXT) ) {
    info->efhw_flags |= EFHW_VI_TX_LOOPBACK;
    info->oo_vi_flags |= OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
  } else {
    info->efhw_flags &= ~EFHW_VI_TX_LOOPBACK;
    info->oo_vi_flags &= ~OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
  }
#endif

  rc = check_timestamping_support(ni->state->pretty_name, "RX",
                                  NI_OPTS(ni).rx_timestamping,
                                  nic->devtype.arch, &info->try_rx_ts,
                                  &info->retry_without_rx_ts);

  if( rc == 0 )
    rc = check_timestamping_support(ni->state->pretty_name, "TX",
                                    NI_OPTS(ni).tx_timestamping,
                                    nic->devtype.arch, &info->try_tx_ts,
                                    &info->retry_without_tx_ts);

  return rc;
}


static int allocate_vi(ci_netif* ni, struct vi_allocate_info* info)
{
  int rc;
  enum efrm_vi_alloc_failure error_reason;
  unsigned evq_min;

  /* Choose DMA queue sizes, and calculate suitable size for EVQ. */
  evq_min = info->rxq_capacity + info->txq_capacity;
  for( info->evq_capacity = 512; info->evq_capacity <= evq_min;
       info->evq_capacity *= 2 )
    ;

again:
  get_timestamping_flags(info->try_rx_ts, info->try_tx_ts,
                         &info->ef_vi_flags, &info->efhw_flags,
                         &info->oo_vi_flags);
  rc = efrm_vi_resource_alloc(info->client, NULL, info->vi_set, -1, info->pd,
                              info->name, info->efhw_flags,
                              info->evq_capacity, info->txq_capacity,
                              info->rxq_capacity, 0, 0, info->wakeup_cpu_core,
                              info->wakeup_channel, info->virs,
                              &info->vi_io_mmap_bytes,
                              &info->vi_mem_mmap_bytes, NULL, NULL,
                              info->log_resource_warnings,
                              &error_reason);

  if( rc != 0 && info->try_rx_ts && info->retry_without_rx_ts &&
      (error_reason == EFRM_VI_ALLOC_RXQ_FAILED ||
       error_reason == EFRM_VI_ALLOC_EVQ_FAILED) ) {
    ci_log(
        "[%s]: enabling RX timestamping on given interface failed, continuing"
        " with RX timestamping disabled on this particular interface",
        ni->state->pretty_name);
    info->try_rx_ts = 0;
    goto again;
  }
  if( rc != 0 && info->try_tx_ts && info->retry_without_tx_ts &&
      (error_reason == EFRM_VI_ALLOC_TXQ_FAILED ||
       error_reason == EFRM_VI_ALLOC_EVQ_FAILED) ) {
    ci_log(
        "[%s]: enabling TX timestamping on given interface failed, continuing"
        " with TX timestamping disabled on this particular interface",
        ni->state->pretty_name);
    info->try_tx_ts = 0;
    goto again;
  }
  if( rc < 0 && info->wakeup_cpu_core != NI_OPTS(ni).irq_core ) {
    info->wakeup_cpu_core = NI_OPTS(ni).irq_core;
    info->log_resource_warnings = NI_OPTS(ni).log_category &
                                (1 << (EF_LOG_RESOURCE_WARNINGS));
    goto again;
  }
  if( rc < 0 ) {
    OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vi_resource_alloc(%d) failed %d",
                         __FUNCTION__, info->intf_i, rc));
    if( info->release_pd )
      efrm_pd_release(info->pd);
  }

  return rc;
}


static void initialise_vi(ci_netif* ni, struct ef_vi* vi, struct efrm_vi* vi_rs,
                          struct efrm_vi_mappings* vm, void* vi_state,
                          int vi_arch, int vi_variant, int vi_revision,
                          unsigned ef_vi_flags, unsigned* vi_out_flags,
                          ef_vi_stats* vi_stats)
{
  int rc = 0;
  uint32_t* vi_ids = (void*) ((ef_vi_state*) vi_state + 1);

  efrm_vi_get_mappings(vi_rs, vm);

  ef_vi_init(vi, vi_arch, vi_variant, vi_revision, ef_vi_flags,
             (ef_vi_state*) vi_state);
  *vi_out_flags = (vm->out_flags & EFHW_VI_CLOCK_SYNC_STATUS) ?
                        EF_VI_OUT_CLOCK_SYNC_STATUS : 0;

  ef_vi_init_out_flags( vi, *vi_out_flags);
  ef_vi_init_io(vi, vm->io_page);
  ef_vi_init_timer(vi, vm->timer_quantum_ns);
  ef_vi_init_evq(vi, vm->evq_size, vm->evq_base);
  ef_vi_init_rxq(vi, vm->rxq_size, vm->rxq_descriptors, vi_ids,
                 vm->rxq_prefix_len);
  vi_ids += vm->rxq_size;
  if( vm->txq_size > 0 )
    ef_vi_init_txq(vi, vm->txq_size, vm->txq_descriptors, vi_ids);
  vi->vi_i = EFAB_VI_RESOURCE_INSTANCE(vi_rs);
  ef_vi_init_state(vi);
  ef_vi_set_stats_buf(vi, vi_stats);
  if( vm->txq_size || vm->rxq_size )
    ef_vi_add_queue(vi, vi);

  efrm_vi_irq_moderate(vi_rs, NI_OPTS(ni).irq_usec);
  if( NI_OPTS(ni).irq_core >= 0 &&
      (NI_OPTS(ni).packet_buffer_mode & CITP_PKTBUF_MODE_VF) ) {
    rc = efrm_vi_irq_affinity(vi_rs, NI_OPTS(ni).irq_core);
    if( rc < 0 )
      OO_DEBUG_ERR(ci_log("%s: ERROR: failed to set irq affinity to %d "
                          "of %d", __FUNCTION__, (int) NI_OPTS(ni).irq_core,
                          num_online_cpus()));
  }

  if( NI_OPTS(ni).tx_push )
    ef_vi_set_tx_push_threshold(vi, NI_OPTS(ni).tx_push_thresh);
  ef_vi_init_rx_timestamping(vi, vm->rx_ts_correction);
  ef_vi_init_tx_timestamping(vi, vm->tx_ts_correction);
}


static int allocate_vis(tcp_helper_resource_t* trs,
                        ci_resource_onload_alloc_t* alloc,
                        void* vi_state, tcp_helper_cluster_t* thc)
{
  /* Format is "onload:pretty_name-intf_i"
   * Do not use slash in this name! */
  char vf_name[7 + CI_CFG_STACK_NAME_LEN+8 + 3];
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int rc, intf_i;
  const char* pci_dev_name;
#if CI_CFG_PIO
  unsigned pio_buf_offset = 0;
#endif
  /* vi allocation is done in several stages.  We build up the information
   * needed in this structure, and pass it to helper functions that use and
   * update the information as needed.
   */
  struct vi_allocate_info alloc_info;

  /* The user level netif build function calculates mapping offsets based on
   * the vi information.  If these values are non-zero here, that implies
   * something before vi creation is adding to these mappings, so the
   * netif build function will need updating.
   */
  ci_assert_equal(trs->buf_mmap_bytes, 0);
  ci_assert_equal(trs->io_mmap_bytes, 0);
#if CI_CFG_PIO
  ci_assert_equal(trs->pio_mmap_bytes, 0);
#endif

  /* Outside the per-interface loop we initialise some values that are common
   * across all interfaces.
   */
  alloc_info.wakeup_channel = NI_OPTS(ni).irq_channel,
  alloc_info.ef_vi_flags = 0;
  alloc_info.efhw_flags = EFHW_VI_JUMBO_EN;
  alloc_info.name = vf_name;
  alloc_info.cluster = thc;
  alloc_info.rxq_capacity = NI_OPTS(ni).rxq_size;

  if( ! NI_OPTS(ni).tx_push )
    alloc_info.ef_vi_flags |= EF_VI_TX_PUSH_DISABLE;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    trs->nic[intf_i].thn_vi_rs = NULL;
    trs->nic[intf_i].thn_vi_mmap_bytes = 0;
#if CI_CFG_SEPARATE_UDP_RXQ
    trs->nic[intf_i].thn_udp_rxq_vi_rs = NULL;
    trs->nic[intf_i].thn_udp_rxq_vi_mmap_bytes = 0;
#endif
#if CI_CFG_PIO
    trs->nic[intf_i].thn_pio_rs = NULL;
    trs->nic[intf_i].thn_pio_io_mmap_bytes = 0;
#endif
  }

  /* This loop does the work of allocating a vi, using the information built
   * up in the alloc_info structure.  It then updates the nsn structure with
   * the resultant resource information.
   */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
    struct efhw_nic* nic =
      efrm_client_get_nic(trs_nic->thn_oo_nic->efrm_client);
    struct efrm_vi_mappings* vm = (void*) ni->vi_data;
    unsigned vi_out_flags = 0;
    struct pci_dev* dev;

    BUILD_BUG_ON(sizeof(ni->vi_data) < sizeof(struct efrm_vi_mappings));

    alloc_info.client = trs_nic->thn_oo_nic->efrm_client;
    alloc_info.vf = NULL;
    alloc_info.pd = NULL;
    alloc_info.vi_set = NULL;
    alloc_info.release_pd = 0;
    alloc_info.intf_i = intf_i;
    alloc_info.oo_vi_flags = 0;

    ci_assert(trs_nic->thn_vi_rs == NULL);
    ci_assert(trs_nic->thn_oo_nic != NULL);
    ci_assert(alloc_info.client != NULL);

    snprintf(vf_name, sizeof(vf_name), "onload:%s-%d",
             ns->pretty_name, intf_i);

    rc = get_vi_settings(ni, nic, &alloc_info);
    if( rc != 0 )
      goto error_out;

    rc = allocate_pd(ni, &alloc_info, nic);
    if( rc != 0 )
      goto error_out;
    nsn->pd_owner = efrm_pd_owner_id(alloc_info.pd);

    alloc_info.virs = &trs_nic->thn_vi_rs;
    alloc_info.txq_capacity = NI_OPTS(ni).txq_size;
    rc = allocate_vi(ni, &alloc_info);
    if( rc != 0 )
      goto error_out;

    initialise_vi(ni, &(ni->nic_hw[intf_i].vi), trs_nic->thn_vi_rs, vm,
                  vi_state, nic->devtype.arch, nic->devtype.variant,
                  nic->devtype.revision, alloc_info.ef_vi_flags, &vi_out_flags,
                  &ni->state->vi_stats);

    nsn->oo_vi_flags = alloc_info.oo_vi_flags;
    nsn->vi_io_mmap_bytes = alloc_info.vi_io_mmap_bytes;
    dev = efrm_vi_get_pci_dev(trs_nic->thn_vi_rs);
    pci_dev_name = pci_name(dev);
    pci_dev_put(dev);
    strncpy(nsn->pci_dev, pci_dev_name, sizeof(nsn->pci_dev));
    nsn->pci_dev[sizeof(nsn->pci_dev) - 1] = '\0';
    nsn->vi_instance =
      (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(trs_nic->thn_vi_rs);
    nsn->vi_arch = (ci_uint8) nic->devtype.arch;
    nsn->vi_variant = (ci_uint8) nic->devtype.variant;
    nsn->vi_revision = (ci_uint8) nic->devtype.revision;
    nsn->vi_channel = (ci_uint8)efrm_vi_get_channel(trs_nic->thn_vi_rs);
    nsn->vi_flags = alloc_info.ef_vi_flags;
    nsn->vi_out_flags = vi_out_flags;
    nsn->vi_evq_bytes = efrm_vi_rm_evq_bytes(trs_nic->thn_vi_rs, -1);
    nsn->vi_rxq_size = vm->rxq_size;
    nsn->vi_txq_size = vm->txq_size;
    nsn->timer_quantum_ns = vm->timer_quantum_ns;
    nsn->rx_prefix_len = vm->rxq_prefix_len;
    nsn->rx_ts_correction = vm->rx_ts_correction;
    nsn->tx_ts_correction = vm->tx_ts_correction;

    trs_nic->thn_vi_mmap_bytes = alloc_info.vi_mem_mmap_bytes;
    trs->buf_mmap_bytes += alloc_info.vi_mem_mmap_bytes;
    trs->io_mmap_bytes += alloc_info.vi_io_mmap_bytes;
    vi_state = (char*) vi_state +
               ef_vi_calc_state_bytes(vm->rxq_size, vm->txq_size);

    /* We used the info we were told - check that's consistent with what someone
     * else would get if they checked separately.
     */
    ci_assert_equal(trs_nic->thn_vi_mmap_bytes,
                    efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs, 1));
    ci_assert_equal(nsn->vi_io_mmap_bytes,
                    efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs, 0));

#if CI_CFG_SEPARATE_UDP_RXQ
    if( NI_OPTS(ni).separate_udp_rxq ) {
      if( alloc_info.cluster ) {
        ci_log("%s: ERROR EF_SEPARATE_UDP_RXQ=1 not supported when clustering"
               "(SO_REUSEPORT) is being used", __FUNCTION__);
        rc = -EINVAL;
        efrm_pd_release(alloc_info.pd);
        goto error_out;
      }
      alloc_info.txq_capacity = 0;
      alloc_info.virs = &trs_nic->thn_udp_rxq_vi_rs;
      rc = allocate_vi(ni, &alloc_info);
      if( rc != 0 ) {
        efrm_pd_release(alloc_info.pd);
        goto error_out;
      }

      initialise_vi(ni, &(ni->nic_hw[intf_i].udp_rxq_vi),
                    trs_nic->thn_udp_rxq_vi_rs, vm, vi_state,
                    nic->devtype.arch, nic->devtype.variant,
                    nic->devtype.revision, alloc_info.ef_vi_flags,
                    &vi_out_flags, &ni->state->udp_rxq_vi_stats);

      nsn->udp_rxq_vi_evq_bytes =
        efrm_vi_rm_evq_bytes(trs_nic->thn_udp_rxq_vi_rs, -1);
      nsn->udp_rxq_vi_instance =
        (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(trs_nic->thn_udp_rxq_vi_rs);

      trs_nic->thn_udp_rxq_vi_mmap_bytes = alloc_info.vi_mem_mmap_bytes;
      trs->buf_mmap_bytes += alloc_info.vi_mem_mmap_bytes;
      trs->io_mmap_bytes += alloc_info.vi_io_mmap_bytes;
      vi_state = (char*) vi_state +
                 ef_vi_calc_state_bytes(vm->rxq_size, vm->txq_size);

      /* We used the info we were told - check that's consistent with what
       * someone else would get if they checked separately.
       */
      ci_assert_equal(trs_nic->thn_udp_rxq_vi_mmap_bytes,
                    efab_vi_resource_mmap_bytes(trs_nic->thn_udp_rxq_vi_rs, 1));
      ci_assert_equal(nsn->vi_io_mmap_bytes,
                    efab_vi_resource_mmap_bytes(trs_nic->thn_udp_rxq_vi_rs, 0));

      /* We only store one copy of information that's guaranteed to be the
       * same for both the normal and udp_rxq vi.  Let's do some double
       * checking!
       */
      ci_assert_equal(efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs, 0),
                      efab_vi_resource_mmap_bytes(trs_nic->thn_udp_rxq_vi_rs,
                      0));
      ci_assert_equal(nsn->vi_rxq_size, vm->rxq_size);
    }
#endif


#if CI_CFG_PIO
    if( NI_OPTS(ni).pio && (nic->devtype.arch == EFHW_ARCH_EF10) ) {
      rc = allocate_pio(trs, intf_i, alloc_info.pd, nic, &pio_buf_offset);
      if( rc < 0 ) {
        efrm_pd_release(alloc_info.pd);
        goto error_out;
      }
    }
#endif

    if( alloc_info.release_pd )
      efrm_pd_release(alloc_info.pd); /* vi keeps a ref to pd */
  }

  OO_DEBUG_RES(ci_log("%s: done", __FUNCTION__));

  return 0;

error_out:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( trs->nic[intf_i].thn_vi_rs ) {
      efrm_vi_resource_release(trs->nic[intf_i].thn_vi_rs);
      trs->nic[intf_i].thn_vi_rs = NULL;
    }
#if CI_CFG_SEPARATE_UDP_RXQ
    if( trs->nic[intf_i].thn_udp_rxq_vi_rs ) {
      efrm_vi_resource_release(trs->nic[intf_i].thn_udp_rxq_vi_rs);
      trs->nic[intf_i].thn_udp_rxq_vi_rs = NULL;
    }
#endif
  }
  return rc;
}


static void vi_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}

static void release_pkts_pages(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            non_atomic_work);
  int i;
  ci_netif* ni = &trs->netif;

  for (i = 0; i < ni->pkt_sets_n; i++)
    oo_iobufset_pages_release(ni->pkt_bufs[i]);

  complete(&trs->complete);
}

static void release_pkts(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  unsigned i;
  int intf_i;
#ifndef NDEBUG
  int n_free = 0;
#endif

  for (i = 0; i < ni->pkt_sets_n; i++) {
    ci_assert(ni->pkt_bufs[i]);
#ifndef NDEBUG
    n_free += ni->packets->set[i].n_free;
#endif
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      oo_iobufset_resource_release(ni->nic_hw[intf_i].pkt_rs[i],
                                   trs->intfs_suspended & (1 << intf_i));
  }
#ifndef NDEBUG
  ci_assert_equal(ni->packets->n_free, n_free);
#endif

  /* Now release everything allocated in allocate_netif_hw_resources. */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_free(ni->nic_hw[intf_i].pkt_rs);

  /* Release the packet pages from the stack workq only!
   * Only here we have a guarantee of using the correct IPC namespace for
   * huge pages. */
  INIT_WORK(&trs->non_atomic_work, release_pkts_pages);
  reinit_completion(&trs->complete);
  queue_work(trs->wq, &trs->non_atomic_work);
  wait_for_completion(&trs->complete);
  ci_free(ni->pkt_bufs);
}

static void release_vi(tcp_helper_resource_t* trs)
{
  int intf_i;

  /* Flush vis first to ensure our bufs won't be used any more */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    reinit_completion(&trs->complete);
    efrm_vi_register_flush_callback(trs->nic[intf_i].thn_vi_rs,
                                    &vi_complete,
                                    &trs->complete);
    efrm_vi_resource_stop_callback(trs->nic[intf_i].thn_vi_rs);
    wait_for_completion(&trs->complete);

#if CI_CFG_SEPARATE_UDP_RXQ
    if( trs->nic[intf_i].thn_udp_rxq_vi_rs ) {
      reinit_completion(&trs->complete);
      efrm_vi_register_flush_callback(trs->nic[intf_i].thn_udp_rxq_vi_rs,
                                      &vi_complete, &trs->complete);
      efrm_vi_resource_stop_callback(trs->nic[intf_i].thn_udp_rxq_vi_rs);
      wait_for_completion(&trs->complete);
    }
#endif
  }

  /* Now do the rest of vi release */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
#if CI_CFG_PIO
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_nic_t *netif_nic = &trs->netif.nic_hw[intf_i];
    if( NI_OPTS(&trs->netif).pio &&
        (efrm_client_get_nic(trs_nic->thn_oo_nic->efrm_client)->devtype.arch ==
         EFHW_ARCH_EF10) && 
        (trs_nic->thn_pio_io_mmap_bytes != 0) ) {
      efrm_pio_unmap_kernel(trs_nic->thn_vi_rs, (void*)netif_nic->pio.pio_io);
      ci_pio_buddy_dtor(&trs->netif,
                        &trs->netif.state->nic[intf_i].pio_buddy);
    }
#endif
    efrm_vi_resource_release_flushed(trs->nic[intf_i].thn_vi_rs);
    trs->nic[intf_i].thn_vi_rs = NULL;
    CI_DEBUG_ZERO(&trs->netif.nic_hw[intf_i].vi);

#if CI_CFG_SEPARATE_UDP_RXQ
    if( trs->nic[intf_i].thn_udp_rxq_vi_rs ) {
      efrm_vi_resource_release_flushed(trs->nic[intf_i].thn_udp_rxq_vi_rs);
      trs->nic[intf_i].thn_udp_rxq_vi_rs = NULL;
      CI_DEBUG_ZERO(&trs->netif.nic_hw[intf_i].udp_rxq_vi);
    }
#endif
  }

  if( trs->thc != NULL )
    tcp_helper_cluster_release(trs->thc, trs);
}


static void tcp_helper_gracious_dtor(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;

  /* We are not going to send any more packets.  Ensure that all the
   * packets get the corresponding TX complete event. */
  if( ! ni->error_flags ) {
    int intf_i;
    int has_bad_intf;
    unsigned long start_jiffies = jiffies;
    unsigned intf_is_good = 0;

    do {
      has_bad_intf = 0;
      reinit_completion(&trs->complete);
      ci_wmb();

      /* If we have some events or wait for TX complete events, we should
       * wait for interrupt handler to process them all.
       * In theory, we can process them here, but we do not want to go
       * through lock complexities. */
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
        ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
        if( ci_netif_intf_has_event(ni, intf_i) || 
             nic->tx_dmaq_insert_seq != nic->tx_dmaq_done_seq ) {
          has_bad_intf = 1;
          tcp_helper_request_wakeup_nic(trs, intf_i);
        }
        else
          intf_is_good |= 1 << intf_i;
      }

      if( ! has_bad_intf || jiffies - start_jiffies > HZ )
        break;

      wait_for_completion_timeout(&trs->complete, HZ);
    } while( 1 );

    /* Merge atomic counter if they were messed up somehow */
    ci_netif_merge_atomic_counters(ni);

    /* Check for packet leak */
    ci_assert_equal(ni->packets->n_pkts_allocated,
                    ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S);
    if( has_bad_intf )
      ci_log("%s: WARNING: [%d] Failed to get TX complete events "
             "for some packets", __func__, trs->id);
    else {
      ci_assert_equal(ni->packets->n_free + ni->state->n_rx_pkts +
                      ni->state->n_async_pkts,
                      ni->packets->n_pkts_allocated);
    }
  }

  /* Check that all aux buffers have been freed before the stack
   * destruction. */
  ci_assert_equal(ni->state->n_free_aux_bufs, ni->state->n_aux_bufs);
  if( ni->state->n_free_aux_bufs != ni->state->n_aux_bufs )
    ci_log("%s[%d]: leaked %d aux bufs from %d", __func__, NI_ID(ni),
           ni->state->n_aux_bufs - ni->state->n_free_aux_bufs,
           ni->state->n_aux_bufs);
}


static int
allocate_netif_resources(ci_resource_onload_alloc_t* alloc,
                         tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns;
  int i, sz, rc, no_table_entries;
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

  /* Fixme: max_ep_bufs is the number of ep states including the states
   * used for aux buffers and pipe endpoints.  How many real sockets are
   * we going to create?  Do we need a separate option? */
  no_table_entries = NI_OPTS(ni).max_ep_bufs * 2;

  /* pkt_sets_n should be zeroed before possible NIC reset */
  if( NI_OPTS(ni).max_packets > max_packets_per_stack ) {
    OO_DEBUG_ERR(ci_log("WARNING: EF_MAX_PACKETS reduced from %d to %d due to "
                        "max_packets_per_stack module option",
                        NI_OPTS(ni).max_packets, max_packets_per_stack));
    ni->state = NULL;
    tcp_helper_reduce_max_packets(ni, max_packets_per_stack);
  }
  ni->pkt_sets_n = 0;
  ni->pkt_sets_max =
    (NI_OPTS(ni).max_packets + PKTS_PER_SET - 1) >> CI_CFG_PKTS_PER_SET_S;

  /* Find size of netif state to allocate. */
  vi_state_bytes = ef_vi_calc_state_bytes(NI_OPTS(ni).rxq_size,
                                          NI_OPTS(ni).txq_size);
#if CI_CFG_SEPARATE_UDP_RXQ
  if( NI_OPTS(ni).separate_udp_rxq )
    vi_state_bytes += ef_vi_calc_state_bytes(NI_OPTS(ni).rxq_size, 0);
#endif

  /* allocate shmbuf for netif state */
  ci_assert_le(NI_OPTS(ni).max_ep_bufs, CI_CFG_NETIF_MAX_ENDPOINTS_MAX);
  sz = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n +
    sizeof(oo_pktbuf_manager) + sizeof(oo_pktbuf_set) * ni->pkt_sets_max +
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
  memset(ns, 0, sz);
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

  ns->buf_ofs = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n;
  ns->table_ofs = ns->buf_ofs + sizeof(oo_pktbuf_manager) +
    sizeof(oo_pktbuf_set) * ni->pkt_sets_max;
  ns->vi_state_bytes = vi_state_bytes;

  ni->packets = (void*) ((char*) ns + ns->buf_ofs);
  ni->filter_table = (void*) ((char*) ns + ns->table_ofs);

  ni->packets->sets_max = ni->pkt_sets_max;
  ni->packets->sets_n = 0;
  ni->packets->n_pkts_allocated = 0;

  /* Initialize the free list of synrecv/aux bufs */
  ni->state->free_aux_mem = OO_P_NULL;
  ni->state->n_free_aux_bufs = ni->state->n_aux_bufs = 0;

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

  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ ) {
    ci_dllist_init(&trs->os_ready_lists[i]);
    ci_waitable_ctor(&trs->ready_list_waitqs[i]);
  }
  spin_lock_init(&trs->os_ready_list_lock);

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

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  rc = allocate_vis(trs, alloc, ns + 1, thc);
  if( rc < 0 )  goto fail1;

  sz = sizeof(ci_pkt_bufs) * ni->pkt_sets_max;
  if( (ni->pkt_bufs = ci_alloc(sz)) == NULL ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate iobufset table"));
    rc = -ENOMEM;
    goto fail4;
  }
  memset(ni->pkt_bufs, 0, sz);

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
  ns->cplane_bytes = cicp_ns_map(&ns->control_mmap, CICP_HANDLE(ni));
  OO_DEBUG_MEMSIZE(ci_log("%d (0x%x) bytes for global cplane",
                          ns->cplane_bytes, ns->cplane_bytes));

  /* Advertise the size of the IO and buf mmap that needs to be performed. */
  ns->io_mmap_bytes = trs->io_mmap_bytes;
  ns->buf_mmap_bytes = trs->buf_mmap_bytes;
#if CI_CFG_PIO
  ns->pio_mmap_bytes = trs->pio_mmap_bytes;
#endif

  OO_DEBUG_MEMSIZE(ci_log("helper=%u map_bytes=%u (0x%x)",
                          trs->id,
                          trs->mem_mmap_bytes, trs->mem_mmap_bytes));
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    LOG_NC(ci_log("VI=%d", ef_vi_instance(&ni->nic_hw[intf_i].vi)));
#if CI_CFG_SEPARATE_UDP_RXQ
    if( NI_OPTS(ni).separate_udp_rxq )
      LOG_NC(ci_log("RXQ_VI=%d",
                    ef_vi_instance(&ni->nic_hw[intf_i].udp_rxq_vi)));
#endif
  }

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
  ci_free(ni->pkt_bufs);
 fail4:
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
      ci_assert(ni->ep_tbl[i]);
      tcp_helper_endpoint_dtor(ni->ep_tbl[i]);
      ci_free(ni->ep_tbl[i]);
      CI_DEBUG(ni->ep_tbl[i] = 0);
    }
    ci_vfree(ni->ep_tbl);
    ni->ep_tbl = NULL;
  }
}

static void
release_netif_resources(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  ci_waitq_dtor(&trs->pkt_waitq);
  ci_ipid_dtor(ni, (ci_fd_t)-1);
  eplock_dtor(ni);
  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ )
    ci_waitable_dtor(&trs->ready_list_waitqs[i]);

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

  release_vi(trs);

  /* Once all vis are flushed we can release pkt memory */
  release_pkts(trs);
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
    /* Needed to protect against oo_nics changes */
    rtnl_lock();

    onic = oo_nics;
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      while( onic < oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        if( onic->efrm_client != NULL &&
            /* VIs are created regardless interface is up, down or
             * unplugged,
             * OO_NIC_UNPLUGGED is the "create ghost VIs" case. */
            oo_check_nic_suitable_for_onload(onic) )
          break;
        else
          ++onic;
      if( onic >= oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        break;
      efrm_nic_set_write(&ni->nic_set, intf_i, CI_TRUE);
      trs->nic[intf_i].thn_intf_i = intf_i;
      trs->nic[intf_i].thn_oo_nic = onic;
      ni->hwport_to_intf_i[onic - oo_nics] = intf_i;
      ni->intf_i_to_hwport[intf_i] = onic - oo_nics;;
      ++trs->netif.nic_n;
      ++onic;
    }

    rtnl_unlock();
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
    ci_log("%s: ERROR: No Solarflare network interfaces are active/UP,\n"
           "or they are configured with packed stream firmware, disabled,\n"
	   "or unlicensed for Onload. Please check your configuration.",
           __FUNCTION__);
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


static int tcp_helper_reprime_is_needed(ci_netif* ni)
{
  ci_assert_equal( NI_OPTS(ni).int_driven, 0);

  if( ci_netif_is_spinner(ni) )
    /* Don't reprime if someone is spinning -- let them poll the stack. */
    return 0;
  if( ni->state->last_spin_poll_frc > ni->state->last_sleep_frc )
    /* A spinning thread has polled the stack more recently than a thread
     * has gone to sleep.  We assume the spinning thread will handle
     * network events (or enable interrupts at some point), so no need to
     * enable interrupts here.
     */
    return 0;
  return 1;
}


/* Defer some task from a driverlink context to non-atomic work item.
 * The caller should hold the shared lock in case of
 * OO_THR_AFLAG_UNLOCK_UNTRUSTED and both shared and trusted locks
 * otherwise.  The caller should not assume that it has the locks after
 * this function is called, because non-atomic work item might be already
 * running and using the locks.
 */
void
tcp_helper_defer_dl2work(tcp_helper_resource_t* trs, ci_uint32 flag)
{
  OO_DEBUG_TCPH(ci_log("%s: [%u] defer locks with flag=%x",
                       __FUNCTION__, trs->id, flag));
  ci_assert(ci_netif_is_locked(&trs->netif));
  CITP_STATS_NETIF_INC(&trs->netif, stack_locks_deferred);
  trs->netif.flags &=~ CI_NETIF_FLAG_IN_DL_CONTEXT;
  /* We need write memory barrier here.  However, both x86 and ppc
   * implementations of ci_atomic32_or() include  a sort of write memory
   * barrier at the beginning.
   * On the flip side, ci_wmb+ci_atomic32_or on ppc result in 2 lwsync
   * instructions one afther another, which is harmful for performance. */
  ci_atomic32_or(&trs->trs_aflags, flag);
  /* And we really need write memory barrier here.  It is harmless on x86:
   * ci_atomic32_or-x86 implementation provides such a barrier but
   * ci_atomic32_or+ci_wmb do not create any additional barrier in the
   * asm code.  But this barrier is really needed on ppc. */
  ci_wmb();
  queue_work(trs->wq, &trs->non_atomic_work);
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
  int need_unlock_shared = 0;

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

  ci_assert(! in_atomic());

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
      tcp_helper_endpoint_clear_filters(ep, 0, 0);
    if( ep_aflags & OO_THR_EP_AFLAG_NEED_FREE ) {
      /* make sure that the filters are released: */
      tcp_helper_endpoint_clear_filters(ep, 0, 0);
      citp_waitable_obj_free_nnl(&trs->netif,
                                 SP_TO_WAITABLE(&trs->netif, ep->id));
    }
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

  /* Handle the deferred actions with stolen locks: shared lock. */
  if( trs->trs_aflags & OO_THR_AFLAG_UNLOCK_UNTRUSTED ) {
    ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_UNLOCK_UNTRUSTED);
    need_unlock_shared = 1;
  }

  /* Handle the deferred actions with stolen locks: both shared and trusted
   * lock. */
  if( trs->trs_aflags & OO_THR_AFLAG_DEFERRED_TRUSTED ) {
    ci_uint32 trs_aflags;
    OO_DEBUG_TCPH(ci_log("%s: [%u] deferred locks trs_aflags=%d",
                         __FUNCTION__, trs->id, trs->trs_aflags));
    ci_assert(ci_netif_is_locked(&trs->netif));
    ci_assert(oo_trusted_lock_is_locked(trs));

    /* We have the trusted lock, so no one could set new
     * OO_THR_AFLAG_DEFERRED_TRUSTED flags before we handle them.
     * So, it is safe to remove them all at once.
     *
     * From the other hand, we should remove POLL_AND_PRIME flag
     * before it is handled, because event callbacks check for the presence
     * of this flag.  If POLL_AND_PRIME is present, event callbacks assume
     * that poll-and-prime is going to happen soon. */
    trs_aflags = trs->trs_aflags;
    ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_DEFERRED_TRUSTED);

    if( trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
      int intf_i;

      OO_DEBUG_TCPH(ci_log("%s: [%u] deferred POLL_AND_PRIME",
                           __FUNCTION__, trs->id));
      ci_netif_poll(&trs->netif);
      if( NI_OPTS(&trs->netif).int_driven ) {
        OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
          tcp_helper_request_wakeup_nic(trs, intf_i);
      }
      else if( ! trs->netif.state->poll_did_wake &&
               tcp_helper_reprime_is_needed(&trs->netif) ) {
        tcp_helper_request_wakeup(trs);
        CITP_STATS_NETIF_INC(&trs->netif, interrupt_primes);
      }
    }
    if( trs_aflags & OO_THR_AFLAG_CLOSE_ENDPOINTS ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] deferred CLOSE_ENDPOINTS",
                           __FUNCTION__, trs->id));
      tcp_helper_close_pending_endpoints(trs);
    }

    efab_tcp_helper_netif_unlock(trs, 0);
  }
  else if( need_unlock_shared )
    ci_netif_unlock(&trs->netif);
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

/* Woritem routine to handle postponed stack destruction.
 * Should be run in global workqueue only, not in the stack workqueue
 * because these functions flush and destroy the stack workqueue. */
static void
tcp_helper_destroy_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            work_item_dtor);

  if( TCP_HELPER_K_RC_REFS(trs->k_ref_count) == 0 ) {
    tcp_helper_dtor(trs);
    return;
  }

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
    nic = efrm_client_get_nic(rs->nic[intf_i].thn_oo_nic->efrm_client);
    if( nic->rx_usr_buf_size < min_rx_usr_buf_size )
     min_rx_usr_buf_size = nic->rx_usr_buf_size;
  }
  ni->state->max_mss = min_rx_usr_buf_size - max_prefix - ETH_HLEN - 
    ETH_VLAN_HLEN - sizeof(ci_ip4_hdr) - sizeof(ci_tcp_hdr);
}


#ifdef ONLOAD_OFE
static void tcp_helper_rm_alloc_ofe(tcp_helper_resource_t* trs)
{
  enum ofe_status orc;
  ci_netif* ni = &(trs->netif);
  ni->ofe = NULL;
  ni->ofe_channel = NULL;
  mutex_init(&trs->ofe_mutex);
  trs->ofe_config = NULL;
  if( ni->opts.ofe_size == 0 )
    return;
  orc = ofe_engine_alloc(&(ni->opts.ofe_size),
                         ci_ip_time_ms2ticks_slow(ni, 1000),
                         trs->nic[0].thn_vi_rs, &(ni->ofe));
  if( orc != OFE_OK ) {
    ci_log("ERROR: [%d] failed to allocate filter engine size=%d (orc=%d)",
           NI_ID(ni), ni->opts.ofe_size, (int) orc);
    goto fail1;
  }
  ni->state->opts.ofe_size = ni->opts.ofe_size;
  return;

 fail1:
  ni->opts.ofe_size = 0;
  ni->state->opts.ofe_size = 0;
  /* ?? FIXME: option to fail stack creation */
  return;
}
#endif


int tcp_helper_rm_alloc_proxy(ci_resource_onload_alloc_t* alloc,
                              const ci_netif_config_opts* opts,
                              int ifindices_len,
                              tcp_helper_resource_t** rs_out)
{
  tcp_helper_resource_t* rs;
  int rc;
  ci_netif* ni;

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0);

  rc = oo_version_check(alloc);
  if( rc < 0 )
    return rc;

  oo_timesync_wait_for_cpu_khz_to_stabilize();

  if( alloc->in_flags & CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS ) {
    /* Create stack that will be part of a cluster,
     * Cluster will be created if needed.
     */
    alloc->in_flags &= ~CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS;
    rc = tcp_helper_cluster_alloc_thr(alloc->in_name,
                                      alloc->in_cluster_size,
                                      alloc->in_cluster_restart,
                                      alloc->in_flags,
                                      opts,
                                      &rs);
    if ( rc != 0 )
      return rc;
    ni = &rs->netif;
    ci_assert_equal(rs->id, rs->netif.state->stack_id);
    alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
    alloc->out_nic_set = ni->nic_set;
    *rs_out = rs;
    return 0;
  }
  else {
    return tcp_helper_rm_alloc(alloc, opts, ifindices_len,
                               NULL, rs_out);
  }
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
  int hw_resources_allocated = 0;

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0);

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

  /* Mark that there is a stack present.
   * This will prevent interfaces going down. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ++THR_TABLE.stack_count;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

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
  rs->intfs_suspended = 0;
  rs->thc = NULL;
  alloc->in_name[CI_CFG_STACK_NAME_LEN] = '\0';
  strcpy(rs->name, alloc->in_name);

  ni->opts = *opts;
  ci_netif_config_opts_rangecheck(&ni->opts);
  spin_lock_init(&ni->swf_update_lock);
  ni->swf_update_last =  ni->swf_update_first = NULL;

  /* Allocate buffers for shared state, etc. */
  rc = allocate_netif_resources(alloc, rs);
  if( rc < 0 ) goto fail4;

  /* Initialise work items.
   * Some of them are used in reset handler and in error path. */
  INIT_WORK(&rs->non_atomic_work, tcp_helper_do_non_atomic);
  INIT_WORK(&rs->work_item_dtor, tcp_helper_destroy_work);
  INIT_DELAYED_WORK(&rs->purge_txq_work, tcp_helper_purge_txq_work);
  INIT_WORK(&rs->reset_work, tcp_helper_reset_stack_work);
  ci_sllist_init(&rs->non_atomic_list);
  ci_sllist_init(&rs->ep_tobe_closed);
  ci_irqlock_ctor(&rs->lock);
  init_completion(&rs->complete);

  /* "onload-wq:pretty_name workqueue for non-atomic works */
  snprintf(rs->wq_name, sizeof(rs->wq_name), "onload-wq:%s",
           ni->state->pretty_name);
  /* This workqueue is used to poll NIC => WQ_CPU_INTENSIVE
   * This workqueue is used to postpone IRQ hanlder when we are out of NAPI
   * budget => WQ_HIGHPRI
   * EF10 postpones packet allocation => WQ_HIGHPRI
   * Users want to set cpu affinity => WQ_SYSFS
   * Long running CPU intensive workloads which can be better
   * managed by the system scheduler => WQ_UNBOUND
   */
  rs->wq = efrm_alloc_workqueue(rs->wq_name,
                                WQ_UNBOUND | WQ_CPU_INTENSIVE |
                                WQ_HIGHPRI | WQ_SYSFS);
  if( rs->wq == NULL )
    goto fail5;

  /* "onload-wq-reset:pretty_name workqueue for handling resets */
  snprintf(rs->reset_wq_name, sizeof(rs->reset_wq_name), ONLOAD_RESET_WQ_NAME,
           ni->state->pretty_name);
  /* Until we've handled a reset, other activities are pointless => WQ_HIGHPRI
   * Users may want to set cpu affinity => WQ_SYSFS
   */
  rs->reset_wq = efrm_alloc_workqueue(rs->reset_wq_name, WQ_UNBOUND |
                                      WQ_HIGHPRI | WQ_SYSFS);
  if( rs->reset_wq == NULL )
    goto fail5a;

  /* Ready for possible reset: after workqueue is ready, but before any hw
   * resources are allocated. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_push(&THR_TABLE.started_stacks, &rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* Allocate hardware resources */
  ni->ep_tbl = NULL;
  ni->flags = alloc->in_flags;
  rc = allocate_netif_hw_resources(alloc, thc, rs);
  if( rc < 0 ) goto fail6;

  /* Prepare per-socket data structures, and allocate the first few socket
  ** buffers. */
  ni->ep_tbl_max = NI_OPTS(ni).max_ep_bufs;
  ni->ep_tbl_n = 0;
  ni->ep_tbl = CI_VMALLOC_ARRAY(tcp_helper_endpoint_t*, ni->ep_tbl_max);
  if( ni->ep_tbl == 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_rm_alloc: failed to allocate ep_tbl"));
    rc = -ENOMEM;
    goto fail7;
  }

  rs->trs_aflags = 0;
  ni->uid = ci_getuid();
  ni->euid = ci_geteuid();
  ni->error_flags = 0;
  ci_netif_state_init(&rs->netif, oo_timesync_cpu_khz, alloc->in_name);
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    nic = efrm_client_get_nic(rs->nic[intf_i].thn_oo_nic->efrm_client);
    if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
      ni->state->flags |= CI_NETIF_FLAG_ONLOAD_UNSUPPORTED;
    if( nic->resetting )
      tcp_helper_suspend_interface(ni, intf_i);
  }

  tcp_helper_init_max_mss(rs);

  efab_tcp_helper_more_socks(rs);

#ifdef ONLOAD_OFE
  tcp_helper_rm_alloc_ofe(rs);
#endif

  CI_MAGIC_SET(ni, NETIF_MAGIC);

#ifdef EFRM_DO_NAMESPACES
  /* Initialise nsproxy field */
  rs->nsproxy = task_nsproxy_start(current);
  ci_assert(rs->nsproxy);
  get_nsproxy(rs->nsproxy);
  task_nsproxy_done(current);
#endif

  if( (rc = ci_netif_init_fill_rx_rings(ni)) != 0 )
    goto fail8;

  /* If there aren't any stacks yet force a sync of cplane information, to
   * to help with the case where people create interfaces then immediately
   * launch their app that uses them.
   */
  if( (NI_OPTS(ni).sync_cplane == 2) || ((NI_OPTS(ni).sync_cplane == 1)
        && (ci_dllist_is_empty(&THR_TABLE.all_stacks))) ) {
    cicpos_sync_tables(CICP_HANDLE(&rs->netif));
  }


  /* When requested set up tproxy mode on selected interface(s) */
  if( (NI_OPTS(ni).scalable_filter_enable == CITP_SCALABLE_FILTERS_ENABLE) &&
      ((NI_OPTS(ni).scalable_filter_mode & CITP_SCALABLE_MODE_RSS) == 0) &&
      thc == NULL ) {
    int ifindex = NI_OPTS(ni).scalable_filter_ifindex;
    rc = oof_tproxy_install(efab_tcp_driver.filter_manager, rs, NULL, ifindex);
    if( rc != 0 ) {
      OO_DEBUG_ERR(ci_log("%s: [%d] Failed to set ifindex %d as tproxy rc=%d.",
                          __func__, NI_ID(ni), ifindex, rc));
      goto fail9;
    }
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
      goto fail10;
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
      efrm_eventq_register_callback(rs->nic[intf_i].thn_vi_rs,
                                    &oo_handle_wakeup_int_driven,
                                    &rs->nic[intf_i]);
    else
      efrm_eventq_register_callback(rs->nic[intf_i].thn_vi_rs,
                                    &oo_handle_wakeup_or_timeout,
                                    &rs->nic[intf_i]);
  }
  tcp_helper_initialize_and_start_periodic_timer(rs);
  if( NI_OPTS(ni).int_driven )
    tcp_helper_request_wakeup(netif2tcp_helper_resource(ni));

#ifdef ONLOAD_OFE
#endif

  alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
  alloc->out_nic_set = ni->nic_set;
  *rs_out = rs;
  OO_DEBUG_RES(ci_log("tcp_helper_rm_alloc: allocated %u", rs->id));
  return 0;

 fail10:
 fail9:
 fail8:
#ifdef EFRM_DO_NAMESPACES
  put_nsproxy(rs->nsproxy);
#endif
#ifdef ONLOAD_OFE
  ofe_engine_free(ni->ofe);
#endif
  release_ep_tbl(rs);
 fail7:
  /* Do not call release_netif_hw_resources() now - do it later, after
   * we're out of THR_TABLE. */
  hw_resources_allocated = 1;
 fail6:

  /* Remove from the THR_TABLE and handle possible reset
   * before trying to remove VIs. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_remove(&rs->all_stacks_link);
  ci_dllink_mark_free(&rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* We might have been reset.
   * Provide a lock for potential waiter.
   * No one else could be accessing this stack!
   * Pretend to be in dl context to avoid proactive packet buffer
   * allocation. */
  ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
  efab_tcp_helper_netif_unlock(rs, 1);
  flush_workqueue(rs->reset_wq);
  efab_tcp_helper_netif_try_lock(rs, 0);

  if( hw_resources_allocated )
    release_netif_hw_resources(rs);

  destroy_workqueue(rs->reset_wq);
 fail5a:
  flush_workqueue(rs->wq);
  destroy_workqueue(rs->wq);
 fail5:
  release_netif_resources(rs);
 fail4:
  ci_id_pool_free(&THR_TABLE.instances, rs->id, &THR_TABLE.lock);
 fail3:
 fail2:
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert(THR_TABLE.stack_count > 0);
  --THR_TABLE.stack_count;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
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

  rc = tcp_helper_rm_alloc_proxy(alloc, opts, ifindices_len, rs_out);
 out:
  kfree(opts);
  return rc;
}



int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                            const ci_netif_config_opts* opts,
                            int ifindices_len, tcp_helper_resource_t** rs_out)
{
  return tcp_helper_rm_alloc_proxy(alloc, opts, ifindices_len, rs_out);
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

static void
thr_reset_stack_tx_cb_state_init(struct thr_reset_stack_tx_cb_state* cb_state,
                                 tcp_helper_resource_t* thr, int intf_i)
{
  cb_state->intf_i = intf_i;
  cb_state->thr = thr;
  cb_state->ps.tx_pkt_free_list_insert = &cb_state->ps.tx_pkt_free_list;
  cb_state->ps.tx_pkt_free_list_n = 0;
}

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


#define TXQ_PURGE_PERIOD (HZ / 10)
static void tcp_helper_purge_txq_locked(tcp_helper_resource_t* thr)
{
  /* We want to purge the TXQs of any interfaces which have been unplugged but
   * have not returned yet.  This is only safe if the hardware is actually
   * gone, as opposed merely to having been suspended in anticipation of a
   * reset.  The former implies that the suspension has also happened, though,
   * so for now we record the mask of suspended interfaces and will check later
   * whether in fact the hardware has gone. */
  unsigned intfs_suspended = OO_ACCESS_ONCE(thr->intfs_suspended);
  ci_netif* ni = &thr->netif;
  int intf_i;
  int reschedule = 0;

  OO_DEBUG_VERB(ci_log("%s: [%d] Purging TXQs for suspended interfaces %08x",
                       __FUNCTION__, thr->id, intfs_suspended));

  ci_assert(ci_netif_is_locked(ni));

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i )
    if( intfs_suspended & (1 << intf_i) ) {
      struct efhw_nic* nic;
      nic = efrm_client_get_nic(thr->nic[intf_i].thn_oo_nic->efrm_client);
      /* Purge the TXQ only if the hardware has been removed, to avoid races
       * against subsequent TX completions.  The flag that we check can change
       * asynchronously, but races against such changes are harmless; the full
       * reset work will always be done precisely once and after any purging
       * that we do here, and that's what matters. */
      if( nic->resetting & NIC_RESETTING_FLAG_UNPLUGGED ) {
        struct thr_reset_stack_tx_cb_state cb_state;
        ef_vi* vi = &ni->nic_hw[intf_i].vi;
        thr_reset_stack_tx_cb_state_init(&cb_state, thr, intf_i);
        ef_vi_txq_reinit(vi, thr_reset_stack_tx_cb, &cb_state);
        /* Purge the eventq as well, to get rid of any references to TX
         * descriptors that we just purged. */
        ef_vi_evq_reinit(vi);

        /* We will continue to reschedule this work item for as long as there
         * are defunct queues to purge. */
        reschedule = 1;
      }
    }

  if( reschedule )
    queue_delayed_work(thr->wq, &thr->purge_txq_work, TXQ_PURGE_PERIOD);
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
  struct efhw_nic* nic;
#if CI_CFG_PIO
  int rc;
#endif

  ci_assert(ci_netif_is_locked(ni));

  /* We walked this link to find this stack to reset in the first place, but
   * it might have been invalidated while we were waiting for the lock. */
  if( ci_dllink_is_free(&thr->all_stacks_link) ) {
    OO_DEBUG_TCPH(ci_log("%s: [%d] Stack is being destroyed; not resetting",
                         __FUNCTION__, thr->id));
    return;
  }

  ci_irqlock_lock(&thr->lock, &lock_flags);
  intfs_to_reset = thr->intfs_to_reset;
  thr->intfs_to_reset = 0;
  /* Prevent any further periodic TXQ-purges, since we're about to bring the
   * TXQ back up. */
  thr->intfs_suspended &=~ intfs_to_reset;
  ci_irqlock_unlock(&thr->lock, &lock_flags);

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

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
    if( intfs_to_reset & (1 << intf_i) ) {
      ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
      ci_uint32 old_errors = nsn->nic_error_flags;
      vi = &ni->nic_hw[intf_i].vi;

      ci_log("%s: reset stack %d intf %d (0x%x)",
             __FUNCTION__, thr->id, intf_i, intfs_to_reset);

#if CI_CFG_PIO
      nic = efrm_client_get_nic(thr->nic[intf_i].thn_oo_nic->efrm_client);
      if( NI_OPTS(ni).pio &&
          (nic->devtype.arch == EFHW_ARCH_EF10) && 
          (thr->nic[intf_i].thn_pio_io_mmap_bytes != 0) ) {
        struct efrm_pd *pd = efrm_vi_get_pd(thr->nic[intf_i].thn_vi_rs);
        OO_DEBUG_TCPH(ci_log("%s: realloc PIO", __FUNCTION__));
        /* Now try to recreate and link the PIO region */
        rc = efrm_pio_realloc(pd, thr->nic[intf_i].thn_pio_rs, 
                              thr->nic[intf_i].thn_vi_rs);
        if( rc < 0 ) {
          OO_DEBUG_TCPH(ci_log("%s: [%d:%d] pio_realloc failed %d, "
                               "removing PIO capability", 
                               __FUNCTION__, thr->id, intf_i, rc));
          thr->pio_mmap_bytes -= thr->nic[intf_i].thn_pio_io_mmap_bytes;
          /* Expose failure to user-level */
          ni->state->pio_mmap_bytes -= thr->nic[intf_i].thn_pio_io_mmap_bytes;
          thr->nic[intf_i].thn_pio_io_mmap_bytes = 0;
          thr->netif.nic_hw[intf_i].pio.pio_buffer = NULL;
          thr->netif.nic_hw[intf_i].pio.pio_len = 0;
          nsn->oo_vi_flags &=~ OO_VI_FLAGS_PIO_EN;
          nsn->pio_io_mmap_bytes = 0;
          nsn->pio_io_len = 0;
          ci_pio_buddy_dtor(ni, &nsn->pio_buddy);
          /* Leave efrm references in place as we can't remove them
           * now - they will get removed as normal when stack
           * destroyed
           */
        }
      }
#endif

      /* Remap packets before using them in RX q */
      nsn->nic_error_flags &=~ CI_NETIF_NIC_ERROR_REMAP;
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
          /* The stack is running, but packet mapping is invalidated.  We have
           * no good solution.  Just let's reset all hardware addresses and
           * wait for user to kill the app, or for another reset to attempt
           * to recover things. */
          ci_log("ERROR [%d]: failed to remap packet set %d after NIC reset",
                 thr->id, i);
          memset(hw_addrs, 0, sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S));
          nsn->nic_error_flags |= CI_NETIF_NIC_ERROR_REMAP;
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
      if( ~nsn->nic_error_flags & CI_NETIF_NIC_ERROR_REMAP ) {
        if( old_errors & CI_NETIF_NIC_ERROR_REMAP )
          ci_log("[%d]: packets remapped successfully on intf %d", thr->id,
                 intf_i);
      }

      /* Reset sw queues */
      ef_vi_evq_reinit(vi);
      ef_vi_rxq_reinit(vi, thr_reset_stack_rx_cb, thr);

      thr_reset_stack_tx_cb_state_init(&cb_state, thr, intf_i);
      ef_vi_txq_reinit(vi, thr_reset_stack_tx_cb, &cb_state);

      /* Reset hw queues.  This must be done after resetting the sw
         queues as the hw will start delivering events after being reset.  If
         we failed to map packet buffers, we don't bring the hw queues back up
         to ensure that we don't attempt to DMA to an invalid address. */
      if( ~nsn->nic_error_flags & CI_NETIF_NIC_ERROR_REMAP )
        efrm_vi_qs_reinit(thr->nic[intf_i].thn_vi_rs);
      else
        efrm_vi_resource_mark_shut_down(thr->nic[intf_i].thn_vi_rs);

      if( cb_state.ps.tx_pkt_free_list_n )
        ci_netif_poll_free_pkts(ni, &cb_state.ps);

      if( OO_PP_NOT_NULL(nsn->rx_frags) ) {
        ci_ip_pkt_fmt* pkt = PKT_CHK(ni, nsn->rx_frags);
        nsn->rx_frags = OO_PP_NULL;
        ci_netif_pkt_release(ni, pkt);
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

void tcp_helper_suspend_interface(ci_netif* ni, int intf_i)
{
  tcp_helper_resource_t* thr;
  ci_irqlock_state_t lock_flags;

  thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);

  ci_irqlock_lock(&thr->lock, &lock_flags);
  thr->intfs_suspended |= (1 << intf_i);
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  /* If a bonded interface is hot-unplugged, we fail over to another slave.
   * There is potentially a considerable interval between an interface going
   * away and the failover actually happening, during which time Onload will
   * merrily post packets to the defunct NIC's TXQ.  Naturally no completion
   * will be generated for such packets, and so they are not eligible for
   * retransmission.  If these packets are left there, any TCP connections to
   * which they belong will stall, and will be reset if the hardware does not
   * reappear quickly enough.  To avoid this problem, we purge defunct TXQs
   * periodically.  (In non-bonded scenarios there is no benefit to this, but
   * no harm either).
   */
  queue_delayed_work(thr->wq, &thr->purge_txq_work, 0);
}

void tcp_helper_reset_stack(ci_netif* ni, int intf_i)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);
  ci_irqlock_state_t lock_flags;

  ci_irqlock_lock(&thr->lock, &lock_flags);
  /* We would like to assert that the corresponding bit in thr->intfs_suspended
   * is already set, but a race against stack-allocation means that's not quite
   * necessarily true. */
  thr->intfs_to_reset |= (1 << intf_i);
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  /* Call tcp_helper_reset_stack_locked from non-dl context only.
   * todo: net driver should tell us if it is dl context */
  queue_work(thr->reset_wq, &thr->reset_work);
}

static void tcp_helper_purge_txq_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs;

#ifdef EFX_NEED_WORK_API_WRAPPERS
  trs = container_of(data, tcp_helper_resource_t, purge_txq_work);
#else
  trs = container_of(data, tcp_helper_resource_t, purge_txq_work.work);
#endif

  /* If we can get the lock, we purge the queues now; if not, we defer to the
   * lock-holder. */
  if( efab_tcp_helper_netif_lock_or_set_flags(trs, OO_TRUSTED_LOCK_PURGE_TXQS,
                                              CI_EPLOCK_NETIF_PURGE_TXQS, 0) ) {
    tcp_helper_purge_txq_locked(trs);
    efab_tcp_helper_netif_unlock(trs, 0);
  }
}

static void tcp_helper_reset_stack_work(struct work_struct *data)
{
  int rc;
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            reset_work);

  /* Before tcp_helper_reset_stack_locked is called,
   * any stack activity is just silly.  So we agressively wait for
   * the stack lock to reset the stack as early as possible.
   *
   * However, we have to cope with the possibility that we're blocked waiting
   * for a wedged lock.  If we know the lock may already be wedged we can
   * just trylock here.  Otherwise block, but allow interruption by a wakeup.
   */
  if( !(trs->trs_aflags & OO_THR_AFLAG_DONT_BLOCK_SHARED) ) {
    rc = ci_netif_lock_maybe_wedged(&trs->netif);
    /* At this point we have either got the lock without blocking, or we had
     * to block and have been woken up.  That might mean the lock's been
     * released, or it might mean the stack's being destructed, so we
     * check the OO_TRUSTED_LOCK_DONT_BLOCK_SHARED flag, and if it's not set
     * we try and grab the lock again.
     */
    while( (rc == -ECANCELED) &&
           !(trs->trs_aflags & OO_THR_AFLAG_DONT_BLOCK_SHARED) )
      rc = ci_netif_lock_maybe_wedged(&trs->netif);
  }
  else {
    rc = !ci_netif_trylock(&trs->netif);
  }

  if( rc ) {
    /* We've been interrupted by a signal.  In workqueue. */
    ci_assert(trs->trusted_lock & OO_TRUSTED_LOCK_AWAITING_FREE);
    return;
  }

  tcp_helper_reset_stack_locked(trs);
  ci_netif_unlock(&trs->netif);
}

/* Shuts down hardware queues for a VI. This is an exceptional operation:
 * normally the queues will be shut down after the last VI reference has been
 * dropped and the queues have been flushed. */
void tcp_helper_shutdown_vi(ci_netif* ni, int hwport)
{
  int intf_i;
  if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 ) {
    tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);
    efrm_vi_resource_shutdown(thr->nic[intf_i].thn_vi_rs);
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

  efab_tcp_helper_rm_free_locked(trs, 0);
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
    if( can_destroy_now
#if defined(PF_KTHREAD) && defined(PF_WQ_WORKER)
        /* We can safely destroy the stack from the UL process or
         * from the global workqueue.  Global workqueue is undetectable;
         * UL process is non-atomic non-kthread non-workqueue. */
        || ( ! in_atomic() &&
             (current->flags & (PF_KTHREAD | PF_WQ_WORKER)) == 0 )
#endif
        
        ) {
      tcp_helper_dtor(trs);
    }
    else {
      tcp_helper_dtor_schedule(trs);
    }
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
__efab_tcp_helper_k_ref_count_dec(tcp_helper_resource_t* trs,
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
  ci_assert( ~trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );

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
    tcp_helper_endpoint_clear_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
    if( ep->alien_ref != NULL ) {
      fput(ep->alien_ref->_filp);
      ep->alien_ref = NULL;
    }
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
efab_tcp_helper_flush_reset_wq(tcp_helper_resource_t* trs)
{
  /* There may be both work running and work pending.  We can wake up the
   * work currently blocked on the lock, but we don't want a queued
   * work item to block subsequently so set a flag.
   */
  ci_atomic32_or(&trs->trs_aflags, OO_THR_AFLAG_DONT_BLOCK_SHARED);
  wake_up_interruptible(&trs->netif.eplock_helper.wq);
  flush_workqueue(trs->reset_wq);
  ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_DONT_BLOCK_SHARED);
}

void tcp_helper_flush_resets(ci_netif* ni)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);
  efab_tcp_helper_flush_reset_wq(thr);
}


static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t* trs,
                               int safe_destroy_now)
{
  ci_netif* netif;
  int n_ep_closing;
  unsigned i;
  int krc_old, krc_new;

  ci_assert(NULL != trs);
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));

  netif = &trs->netif;
  if( netif->flags & CI_NETIF_FLAG_IN_DL_CONTEXT ) {
    /* It is extremely bad idea to flush workqueue from the driverlink
     * context blocking napi thread, even if it is non-atomic. */
    efab_tcp_helper_rm_schedule_free(trs);
    return;
  }
  ci_assert(!in_atomic());
  /* Make sure all postponed actions are done and endpoints freed */
  flush_workqueue(trs->wq);


  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  /* At this point we need to determine the state of the shared lock.  There
   * is still potentially reset work running, which also uses the lock.
   *
   * The following are the possible cases:
   *
   * 1. Wedged with reset work pending
   * 2. Wedged without reset work pending
   * 3. Not wedged with reset work ongoing
   * 4. Not wedged with no reset work
   * 5. Stack did not initialise fully
   *
   * We must ensure that the reset work is not running before we continue.
   * That means that we need to hold the lock.  We get to this state in the
   * same way in cases 1, 2 and 3, by dinging the lock waitqueue then waiting
   * for the reset-wq to flush.
   *
   * In case 1 the ding wakes the reset work, which simply returns, leaving
   * the lock locked.
   *
   * In case 2 there's no work pending, so the lock is still locked.
   *
   * In case 3 the ding doesn't achieve anything because there are no waiters,
   * but the reset work carries on and releases the lock on completion.
   *
   * In case 4 we can aquire the lock.
   *
   * In case 5 the lock value is set to CI_EPLOCK_UNINITIALISED.
   *
   * This allows us to distinguish all cases, and so appropriately set the
   * CI_NETIF_FLAG_WEDGED flag to handle the rest of the cleanup appropriately.
   */
  if( ! ci_netif_trylock(&trs->netif) ) {
    if (CI_EPLOCK_UNINITIALISED == trs->netif.state->lock.lock) {
      /* Case 5 */
      OO_DEBUG_ERR(ci_log("%s [%u]: "
                          "ERROR netif did not fully initialise (0x%llx)",
                          __FUNCTION__, trs->id,
                          (unsigned long long)trs->netif.state->lock.lock));
      /* We have the trusted lock, and there is effectively no shared state.
       * So, we do not care about taking the shared lock when modofying the
       * flags. */
      netif->flags |= CI_NETIF_FLAG_WEDGED;
    }
    else {
      /* Cases 1, 2 and 3 */
      efab_tcp_helper_flush_reset_wq(trs);

      /* There's a potential race here.  We're still on the all stacks list
       * at this point so additional reset work could potentially be queued
       * and take the lock between the flush and this trylock.  This leads us
       * to think that the stack is wedged, and perform an ungraceful
       * stack release, but we shouldn't encounter more serious consequences.
       * As we deem the stack wedged we won't be touching the shared state,
       * and we'll wait for the work to complete as we flush the workqueue
       * again on tcp_helper_stop.
       */
      if( !ci_netif_trylock(&trs->netif) ) {
        /* Cases 1 and 2 */
        OO_DEBUG_ERR(ci_log("Stack [%d] released with lock stuck (0x%llx)",
                     trs->id,
                     (unsigned long long)trs->netif.state->lock.lock));
        netif->flags |= CI_NETIF_FLAG_WEDGED;
      }
    }
  }
  /* else case 4 */

  /* Validate shared netif state before we continue
   *  \TODO: for now just clear in_poll flag
   */
  netif->state->in_poll = 0;

  /* If netif is wedged then for now instead of getting netif in
   * a valid state we instead try never to touch it again.  For most of our
   * resources this is fine, they'll just be released gracelessly.  In the
   * case of socket caching we potentially have fds which won't be.  However,
   * socket caching doesn't play nicely with stack sharing, so it's likely
   * that if this stack is going away it means the process has died and so
   * the fds will be released.
   */
#if CI_CFG_DESTROY_WEDGED
  if( netif->flags & CI_NETIF_FLAG_WEDGED ) {
    n_ep_closing = 0;
    goto closeall;
  }
#endif /*CI_CFG_DESTROY_WEDGED*/

#if CI_CFG_FD_CACHING
  ci_tcp_active_cache_drop_cache(netif);
#endif

  /* purge list of connections waiting to be closed
   *   - ones where we couldn't continue in fop_close because
   *     we didn't have the netif lock
   */
  tcp_helper_close_pending_endpoints(trs);

  for( i=0, n_ep_closing=0; i < netif->ep_tbl_n; i++ ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);
    citp_waitable* w = &wo->waitable;

    if( w->state == CI_TCP_STATE_FREE || w->state == CI_TCP_STATE_AUXBUF )
      continue;

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
    if( w->state & CI_TCP_STATE_TCP_CONN && wo->sock.tx_errno == 0 ) {
      if( OO_SP_IS_NULL(wo->tcp.local_peer) ||
          (~w->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ) ) {
        /* It is normal for EF_TCP_SERVER_LOOPBACK=2,4 if client closes
         * loopback connection before it is accepted. */
        OO_DEBUG_ERR(ci_log("%s: %d:%d in %s state when stack is closed",
                     __func__, trs->id, i, ci_tcp_state_str(w->state)));
      }
      /* Make sure the receive queue is freed,
       * to avoid packet leak warning: */
      ci_bit_clear(&w->sb_aflags, CI_SB_AFLAG_TCP_IN_ACCEPTQ_BIT);
      ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
      ci_tcp_send_rst(netif, &wo->tcp);
      ci_tcp_drop(netif, &wo->tcp, ECONNRESET);
      if( OO_SP_NOT_NULL(wo->tcp.local_peer) )
        ci_netif_poll(netif); /* push RST through the stack */
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
  __efab_tcp_helper_k_ref_count_dec(trs, safe_destroy_now);
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

  /* stop the periodic timer callbacks and TXQ-purges. */
  tcp_helper_stop_periodic_work(trs);

  /* stop callbacks from the event queue
        - wait for any running callback to complete */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    ef_eventq_timer_clear(&(trs->netif.nic_hw[intf_i].vi));
    efrm_eventq_kill_callback(trs->nic[intf_i].thn_vi_rs);
  }

  /* stop postponed packet allocations: we are the only thread using this
   * thr, so nobody can scedule anything new */
  flush_workqueue(trs->wq);
  efab_tcp_helper_flush_reset_wq(trs);

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
  ci_irqlock_state_t lock_flags;

  ci_assert(NULL != trs);

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting %s", __FUNCTION__, trs->id,
                       trs->netif.flags & CI_NETIF_FLAG_WEDGED ?
                       "wedged" : "gracious"));

  if( trs->netif.flags & CI_NETIF_FLAG_WEDGED )
    /* We're doing this here because we need to be in a context that allows
     * us to block.
     */
    efab_tcp_helper_rm_reset_untrusted(trs);

  /* Remove all filters - and make sure we do not send anything, while
   * closing socket or as a reply to a network packet. */
  release_ep_tbl(trs);

  /* Make sure we receive all TX complete events */
  if( ~trs->netif.flags & CI_NETIF_FLAG_WEDGED )
    tcp_helper_gracious_dtor(trs);

  /* stop any async callbacks from kernel mode (waiting if necessary)
   *  - as these callbacks are the only events that can take the kernel
   *    netif lock, we know that once these callbacks are stopped the kernel
   *    lock will have been dropped
   *      => tcp_helper_rm_free_locked must have run to completion
   */
  tcp_helper_stop(trs);

  if( (NI_OPTS(&trs->netif).scalable_filter_enable ==
       CITP_SCALABLE_FILTERS_ENABLE) &&
      ((NI_OPTS(&trs->netif).scalable_filter_mode &
       CITP_SCALABLE_MODE_RSS) == 0) &&
      trs->thc == NULL ) {
    int ifindex = NI_OPTS(&trs->netif).scalable_filter_ifindex;
    rc = oof_tproxy_free(efab_tcp_driver.filter_manager, trs, NULL, ifindex);
    if( rc !=0 )
      OO_DEBUG_ERR(ci_log("%s: [%d] Failed to remove tproxy on ifindex %d.",
                          __func__, NI_ID(&trs->netif), ifindex));
  }

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

  destroy_workqueue(trs->wq);
  destroy_workqueue(trs->reset_wq);
#ifdef EFRM_DO_NAMESPACES
  put_nsproxy(trs->nsproxy);
#endif

#ifdef ONLOAD_OFE
  if( trs->netif.ofe != NULL )
    ofe_engine_free(trs->netif.ofe);
#endif

  rc = ci_id_pool_free(&THR_TABLE.instances, trs->id, &THR_TABLE.lock);
  OO_DEBUG_ERR(if (rc)
        ci_log("%s [%u]: failed to free instance number",
               __FUNCTION__, trs->id));

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert(THR_TABLE.stack_count > 0);
  --THR_TABLE.stack_count;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

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

#ifdef EFRM_DO_NAMESPACES
  my_free_nsproxy = efrm_find_ksym("free_nsproxy");
  if( my_free_nsproxy == NULL ) {
    ci_log("Failed to find free_nsproxy() function in the running kernel.");
    return -EINVAL;
  }
#endif

  CI_ZERO(&efab_tcp_driver);

  /* Create driverlink filter. */
  if( (efab_tcp_driver.dlfilter = efx_dlfilter_ctor()) == NULL ) {
    rc = -ENOMEM;
    goto fail_dlf;
  }

  /* Create work queue */
  /* Cplane lacks proper locking(?) => __WQ_ORDERED
   * XXX Is it true?
   * WQ_SYSFS is not compatible with __WQ_ORDERED (linux-4.0)
   */
  CI_GLOBAL_WORKQUEUE = efrm_alloc_workqueue("onload-wqueue",
                                             WQ_SYSFS
                                             );
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

  efab_tcp_driver.load_numa_node = numa_node_id();

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

  trs->netif.state->sock_alloc_numa_nodes |= 1 << numa_node_id();
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


#if CI_CFG_FD_CACHING
int efab_tcp_helper_clear_epcache(tcp_helper_resource_t* trs)
{
  ci_tcp_epcache_drop_cache(&trs->netif);
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

  ci_shmbuf_size(&ni->pages_buf);

  ci_assert(0);
  return (unsigned) -1;
}


static unsigned long
tcp_helper_rm_nopage_cplane(tcp_helper_resource_t* trs,
                            void* opaque, unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  unsigned int page_frameno;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  if (cicp_nopage_found(&ni->cplane, opaque, &offset, &page_frameno))
    return page_frameno;

  ci_assert(0);
  return (unsigned) -1;
}


static void
efab_tcp_helper_no_more_bufs(tcp_helper_resource_t* trs)
{
  /* We've failed to allocate more packet buffers -- we're out of resources
   * (probably buffer table).  We don't want to keep trying to allocate and
   * failing -- that just makes performance yet worse.  So reset the
   * various packet limits, preserving relative sizes.
   */
  ci_netif* ni = &trs->netif;
  int new_max_packets = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;
  ni->pkt_sets_max = ni->pkt_sets_n;
  ni->packets->sets_max = ni->pkt_sets_max;
  tcp_helper_reduce_max_packets(&trs->netif, new_max_packets);
  ci_netif_set_rxq_limit(ni);

  if( ++ni->state->stats.bufset_alloc_nospace == 1 )
    OO_DEBUG_ERR(ci_log(FN_FMT "Failed to allocate packet buffers: "
                        "no more buffer table entries. ",
                        FN_PRI_ARGS(&trs->netif));
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

  flags = NI_OPTS(ni).compound_pages << OO_IOBUFSET_FLAG_COMPOUND_SHIFT;
#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* If there is a possibility to get huge pages, copy the flags.
   * Otherwise, we'll avoid them. */
  if( ni->flags & CI_NETIF_FLAG_HUGE_PAGES_FAILED )
    flags |= OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED;
  if( !in_atomic() && current->mm != NULL ) {
#ifdef EFRM_DO_NAMESPACES
    struct nsproxy *ns;
    ns = task_nsproxy_start(current);
    /* Use huge pages if we are in the same namespace only.
     * ipc_ns has a pointer to user_ns, so we may compare uids
     * if ipc namespaces match. */
    if( ns != NULL && ns->ipc_ns == trs->nsproxy->ipc_ns
        && ci_geteuid() == ni->euid ) {
      flags |= NI_OPTS(ni).huge_pages;
    }
    task_nsproxy_done(current);
#else
    if( ci_geteuid() == ni->euid )
      flags |= NI_OPTS(ni).huge_pages;
#endif
  }
#endif
  rc = oo_iobufset_pages_alloc(HW_PAGES_PER_SET_S, &flags, &pages);
  if( rc != 0 )
    return rc;
#if CI_CFG_PKTS_AS_HUGE_PAGES
    if( (flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) &&
        !(ni->flags & CI_NETIF_FLAG_HUGE_PAGES_FAILED) ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: unable to allocate huge page, using standard pages instead",
             ni->state->pretty_name);
      ni->flags |= CI_NETIF_FLAG_HUGE_PAGES_FAILED;
    }
#endif

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_pd *pd = efrm_vi_get_pd(trs->nic[intf_i].thn_vi_rs);
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
                        &hw_addrs[intf_i * (1 << HW_PAGES_PER_SET_S)],
                        trs->intfs_suspended & (1 << intf_i));
    if( rc < 0 ) {
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        if( all_out[intf_i] != NULL )
          oo_iobufset_resource_release(all_out[intf_i], 0);
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
  int i, rc, bufset_id, intf_i;

  ci_assert(ci_netif_is_locked(ni));

  if( (ni->flags & (CI_NETIF_FLAG_IN_DL_CONTEXT |
                    CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION) ) ==
       (CI_NETIF_FLAG_IN_DL_CONTEXT |
        CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION) ) {
    ef_eplock_holder_set_flag(&ni->state->lock,
                              CI_EPLOCK_NETIF_NEED_PKT_SET);
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
    /* With highly fragmented memory, iobufset_alloc may fail in
     * atomic context but succeed later in non-atomic context.
     * We should somehow differentiate temporary failures (atomic
     * allocation failure) and permanent failure (out of buffer table
     * entries).
     */
    if( rc == -ENOSPC )
      efab_tcp_helper_no_more_bufs(trs);
    else {
      ++ni->state->stats.bufset_alloc_fails;
      NI_LOG(ni, RESOURCE_WARNINGS,
             FN_FMT "Failed to allocate packet buffers (%d)",
             FN_PRI_ARGS(&trs->netif), rc);

      /* We've got ENOMEM.  If we are in atomic context, it is possible
       * that memory is available in non-atomic mode.
       * efab_tcp_helper_netif_lock_callback() will kick off packet
       * allocation via workqueue without
       * CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION flag check, so we'll
       * retry from non-atomic context immediately.
       *
       * For all other errors (ENOMEM & non-atomic or other rc values),
       * there is no obvious benefit in re-trying the same operation
       * immediately. */
      if( rc == -ENOMEM && ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT ) {
        ef_eplock_holder_set_flag(&ni->state->lock,
                                  CI_EPLOCK_NETIF_NEED_PKT_SET);
      }
    }
    ci_free(hw_addrs);
    return rc;
  }
  /* check we get the size we are expecting */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_assert(iobrs[intf_i] != NULL);
  ci_assert(pages != NULL);

  /* Install the new buffer allocation, protecting against multi-threads. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert_le(ni->pkt_sets_n, ni->pkt_sets_max);
  ci_assert_ge(ni->pkt_sets_n, 0);
  if( ni->pkt_sets_n == ni->pkt_sets_max ) {
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      oo_iobufset_resource_release(iobrs[intf_i], 0);
    oo_iobufset_pages_release(pages);
    ci_free(hw_addrs);
    return -ENOSPC;
  }
  bufset_id = ni->pkt_sets_n;
  ci_assert_ge(bufset_id, 0);

  ++ni->pkt_sets_n;
  ni->pkt_bufs[bufset_id] = pages;
#ifdef OO_DO_HUGE_PAGES
  if( oo_iobufset_get_shmid(pages) >= 0 )
    CITP_STATS_NETIF_INC(ni, pkt_huge_pages);
#endif
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].pkt_rs[bufset_id] = iobrs[intf_i];
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  OO_DEBUG_SHM({
    int i;
    ci_log("[%d] allocated new bufset id %d, current=%d n_freepkts=%d",
           NI_ID(ni), bufset_id, ni->packets->id,
           ni->packets->n_free);
    for( i = 0; i < bufset_id; i++ )
      ci_log("\tpkt_set[%i]: n_free=%d", i, ni->packets->set[i].n_free);
  });

  ni->packets->sets_n = ni->pkt_sets_n;
  ni->packets->n_pkts_allocated = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;

  ni->packets->set[bufset_id].free = OO_PP_NULL;
  ni->packets->set[bufset_id].n_free = PKTS_PER_SET;
#ifdef OO_DO_HUGE_PAGES
  ni->packets->set[bufset_id].shm_id = oo_iobufset_get_shmid(pages);
#else
  ni->packets->set[bufset_id].shm_id = -1;
#endif
  ni->packets->n_free += PKTS_PER_SET;

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

    pkt->next = ni->packets->set[bufset_id].free;
    ni->packets->set[bufset_id].free = OO_PKT_P(pkt);
  }
  ci_free(hw_addrs);

  trs->netif.state->packet_alloc_numa_nodes |= 1 << numa_node_id();
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

  /* VIs (descriptor rings and event queues). */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    if( offset + CI_PAGE_SIZE <= trs_nic->thn_vi_mmap_bytes ) {
      return efab_vi_resource_nopage(trs_nic->thn_vi_rs, opaque,
                                     offset, trs_nic->thn_vi_mmap_bytes);
    }
#if CI_CFG_SEPARATE_UDP_RXQ
    else if( offset + CI_PAGE_SIZE <= trs_nic->thn_vi_mmap_bytes +
             trs_nic->thn_udp_rxq_vi_mmap_bytes) {
      offset -= trs_nic->thn_vi_mmap_bytes;
      return efab_vi_resource_nopage(trs_nic->thn_udp_rxq_vi_rs, opaque,
                                     offset,
                                     trs_nic->thn_udp_rxq_vi_mmap_bytes);
    }
#endif
    else {
#if CI_CFG_SEPARATE_UDP_RXQ
       offset -= trs_nic->thn_vi_mmap_bytes
                 + trs_nic->thn_udp_rxq_vi_mmap_bytes;
#else
       offset -= trs_nic->thn_vi_mmap_bytes;
#endif
    }
  }
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

  if( ! ni->pkt_bufs[bufset_id] ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD offset=%lx bufset_id=%d",
                        __FUNCTION__, trs->id, offset, bufset_id));
    return (unsigned) -1;
  }

  offset -= bufset_id * CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET;
  return oo_iobufset_pfn(ni->pkt_bufs[bufset_id], offset);
}

#ifdef ONLOAD_OFE
static unsigned long
tcp_helper_rm_nopage_ofe(tcp_helper_resource_t* trs, void* opaque,
                         unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  if( ni->ofe == NULL )
    return (unsigned) -1;
  return vmalloc_to_pfn((char *)ni->ofe + offset);
}
static unsigned long
tcp_helper_rm_nopage_ofe_rw(tcp_helper_resource_t* trs, void* opaque,
                            unsigned long offset)
{
  ci_netif* ni = &trs->netif;
  struct ofe_stats_usage stat;
  enum ofe_status orc;
  
  if( ni->ofe == NULL )
    return (unsigned) -1;
  orc = ofe_stats_rw_mem(ni->ofe, &stat);
  if( orc != OFE_OK )
    return (unsigned) -1;
  ci_assert_le(offset, stat.max);
  return vmalloc_to_pfn((char *)ni->ofe + offset +
                        NI_OPTS(&trs->netif).ofe_size - stat.max);
}
#endif

unsigned long
tcp_helper_rm_nopage(tcp_helper_resource_t* trs, void* opaque,
                     int map_id, unsigned long offset)
{

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      return tcp_helper_rm_nopage_mem(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_CPLANE:
      return tcp_helper_rm_nopage_cplane(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_IOBUFS:
      return tcp_helper_rm_nopage_iobuf(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_IO:
      ci_log("%s: map_id:%d", __FUNCTION__, map_id);
      ci_assert(0);
      return (unsigned) -1;
#ifdef ONLOAD_OFE
    case CI_NETIF_MMAP_ID_OFE_RO:
      return tcp_helper_rm_nopage_ofe(trs, opaque, offset);
    case CI_NETIF_MMAP_ID_OFE_RW:
      return tcp_helper_rm_nopage_ofe_rw(trs, opaque, offset);
#endif
    default:
      ci_assert_ge(map_id, CI_NETIF_MMAP_ID_PKTS);
      return tcp_helper_rm_nopage_pkts(trs, opaque,
                                       offset +
                                       (map_id - CI_NETIF_MMAP_ID_PKTS) *
                                       CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
  }

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

static int tcp_helper_wakeup(tcp_helper_resource_t* trs, int intf_i, int budget)
{
  ci_netif* ni = &trs->netif;
  int n = 0, prime_async;

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
      n = ci_netif_poll_n(ni, budget);
      CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
      trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();

      /* If we've exceeded budget, and have woken up user - we trust to user
       * to poll the rest of events.  But if there is no such a user - we
       * defer the poll-and-prime action to workqueue. */
      if( n >= budget && ! ni->state->poll_did_wake &&
          ci_netif_intf_has_event(ni, intf_i) ) {
        CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
        raw_cpu_write(oo_budget_limit_last_ts, jiffies);
        /* Steal the locks and exit */
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
        return n;
      }

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

  if( prime_async && tcp_helper_reprime_is_needed(ni) ) {
    tcp_helper_request_wakeup_nic_if_needed(trs, intf_i);
    CITP_STATS_NETIF_INC(ni, interrupt_primes);
  }

  return n;
}


static int tcp_helper_timeout(tcp_helper_resource_t* trs, int intf_i, int budget)
{
  int n = 0;
#if CI_CFG_HW_TIMER
  ci_netif* ni = &trs->netif;
  int i;

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
      trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();
      if( (n = ci_netif_poll_n(ni, budget)) ) {
        CITP_STATS_NETIF(ni->state->stats.timeout_interrupt_evs += n;
                         ni->state->stats.timeout_interrupt_wakes +=
                         ni->state->poll_did_wake);
        if( n >= budget && ci_netif_intf_has_event(ni, intf_i) ) {
          ni->state->poll_did_wake = 1; /* avoid re-priming */
          CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
          raw_cpu_write(oo_budget_limit_last_ts, jiffies);
          /* Steal the locks and exit */
          tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
          return n;
        }
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
  return n;
}


static int oo_handle_wakeup_or_timeout(void* context, int is_timeout,
                                        struct efhw_nic* nic, int budget)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->thn_intf_i],
                     tcph_nic);
  if( trs->trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
    /* OO_THR_AFLAG_POLL_AND_PRIME is set - i.e. in some sense the
     * previous interrupt handler is already running.
     * Workqueue will handle new events if any and will prime if needed. */
    return 0;
  }

  if( ! CI_CFG_HW_TIMER || ! is_timeout )
    return tcp_helper_wakeup(trs, tcph_nic->thn_intf_i, budget);
  else
    return tcp_helper_timeout(trs, tcph_nic->thn_intf_i, budget);
}



static int oo_handle_wakeup_int_driven(void* context, int is_timeout,
                                        struct efhw_nic* nic_, int budget)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  ci_netif* ni;
  int n = 0;

  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->thn_intf_i],
                     tcph_nic);
  if( trs->trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
    /* OO_THR_AFLAG_POLL_AND_PRIME is set - i.e. in some sense the
     * previous interrupt handler is already running.
     * Workqueue will handle new events if any and will prime if needed. */
    return 0;
  }

  ni = &trs->netif;

  ci_assert( ! is_timeout );
  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Grab lock and poll, or set bit so that lock holder will poll.  (Or if
   * stack is being destroyed, do nothing).
   */
  while( 1 ) {
    if( ci_netif_intf_has_event(ni, tcph_nic->thn_intf_i) ) {
      if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
        CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
        ci_assert( ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT);
        ni->state->poll_did_wake = 0;
        n = ci_netif_poll_n(ni, budget);
        CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
        if( ni->state->poll_did_wake )
          CITP_STATS_NETIF_INC(ni, interrupt_wakes);
        trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();

        if( n >= budget &&
            ci_netif_intf_has_event(ni, tcph_nic->thn_intf_i) ) {
          CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
          raw_cpu_write(oo_budget_limit_last_ts, jiffies);
          /* Steal the locks and exit */
          tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
          return n;
        }
        tcp_helper_request_wakeup_nic(trs, tcph_nic->thn_intf_i);
        efab_tcp_helper_netif_unlock(trs, 1);
        break;
      }
      else {
        CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
        /* Drop through to set lock flags or try again... */
      }
    }
    else {
      CITP_STATS_NETIF_INC(ni, interrupt_no_events);

      /* Requesting wakeup is tricky here.  Don't want to take the
       * lock if avoidable as results in user-level seeing lock
       * contention, but need an accurate value of the evq_ptr to
       * write to request the wakeup.
       * 
       * First attempt to set the flags to request lock holder request
       * wakeup.  If this fails, then lock is not held, so evq_ptr is
       * likely consistent.  In case where we get it wrong it will
       * result in immediate wakeup and we'll try again, but won't get
       * into the feedback loop of repeated wakeups seen in bug42745.
       */
      if( ef_eplock_set_flag_if_locked(&ni->state->lock,
                                       CI_EPLOCK_NETIF_NEED_PRIME) ) {
        break;
      }
      else if( oo_trusted_lock_set_flags_if_locked
               (trs, OO_TRUSTED_LOCK_NEED_PRIME) ) {
        break;
      }
      tcp_helper_request_wakeup_nic(trs, tcph_nic->thn_intf_i);
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
  return n;
}


/*--------------------------------------------------------------------
 *!
 * TCP helper timer implementation 
 *
 *--------------------------------------------------------------------*/

/*** Linux ***/


static void
linux_set_periodic_timer_restart(tcp_helper_resource_t* rs) 
{
  unsigned long t = ci_net_random() % CI_TCP_HELPER_PERIODIC_FLOAT_T;

  if (atomic_read(&rs->timer_running) == 0) 
    return;

  queue_delayed_work(rs->wq, &rs->timer, CI_TCP_HELPER_PERIODIC_BASE_T + t);
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
    if( efab_tcp_helper_netif_try_lock(rs, 0) ) {
      rc = ci_netif_poll(ni);
      efab_tcp_helper_netif_unlock(rs, 0);
      CITP_STATS_NETIF_INC(ni, periodic_polls);
      if( rc > 0 )
        CITP_STATS_NETIF_ADD(ni, periodic_evs, rc);
    }
    else {
      CITP_STATS_NETIF_INC(ni, periodic_lock_contends);
    }
  }
}

static void
linux_tcp_helper_periodic_timer(struct work_struct *work)
{
  tcp_helper_resource_t* rs = container_of(work, tcp_helper_resource_t,
                                           timer
#ifndef EFX_NEED_WORK_API_WRAPPERS
                                                .work
#endif
                                          );

  ci_assert(NULL != rs);

  OO_DEBUG_VERB(ci_log("linux_tcp_helper_periodic_timer: fired"));

  linux_tcp_timer_do(rs);
  linux_set_periodic_timer_restart(rs);
}

static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t* rs)
{
  atomic_set(&rs->timer_running, 1);

  INIT_DELAYED_WORK(&rs->timer, linux_tcp_helper_periodic_timer);

  linux_set_periodic_timer_restart(rs);
}


static void
tcp_helper_stop_periodic_work(tcp_helper_resource_t* rs)
{
  ci_irqlock_state_t lock_flags;

  /* Prevent timers from rescheduling themselves. */
  atomic_set(&rs->timer_running, 0);

  /* Prevent TXQ-purge for rescheduling itself. */
  ci_irqlock_lock(&rs->lock, &lock_flags);
  rs->intfs_suspended = 0;
  ci_irqlock_unlock(&rs->lock, &lock_flags);

  /* cancel already-scheduled workitems */
  cancel_delayed_work(&rs->timer);
  cancel_delayed_work(&rs->purge_txq_work);
  /* wait for running timer workqitem */
  flush_workqueue(rs->wq);
  /* the running workitems might haved kicked off some more before the flags
   * were cleared earlier - let's cancel them. */
  cancel_delayed_work(&rs->timer);
  cancel_delayed_work(&rs->purge_txq_work);
  /* and flush, just in case the second workitem have started
   * before we cancelled it */
  flush_workqueue(rs->wq);
}

/*--------------------------------------------------------------------*/

/** Solaris **/

/*--------------------------------------------------------------------
 *!
 * End of TCP helper timer implementation
 *
 *--------------------------------------------------------------------*/

/* efab_tcp_helper_close_endpoint() must be called in non-atomic
 * non-driverlink context.
 * (1) There might be postponed works for this ep, and we must process
 *     them before closing.
 * (2) tcp_helper_endpoint_clear_filters() will postpone hw filter removal.
 *     See (1) for the result.
 */
void
efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs, oo_sp ep_id)
{
  ci_netif* ni;
  tcp_helper_endpoint_t* tep_p;
  ci_irqlock_state_t lock_flags;
  citp_waitable_obj* wo;

  ni = &trs->netif;
  tep_p = ci_trs_ep_get(trs, ep_id);

  wo = SP_TO_WAITABLE_OBJ(&trs->netif, tep_p->id);
  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] k_ref_count=%d %s", __FUNCTION__,
                       trs->id, OO_SP_FMT(ep_id), trs->k_ref_count,
                       ci_tcp_state_str(wo->waitable.state)));

  ci_assert(!(wo->waitable.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(! in_atomic());

  /* Drop ref to the OS socket.  Won't necessarily be the last reference to it;
   * there may also be one from the filter, and others from dup'd or forked
   * processes.  This needs to be done here rather since fput can block.
   */
  if( tep_p->os_socket != NULL ) {
    unsigned long flags;
    struct oo_file_ref* os_socket;
    ci_assert( !(wo->waitable.sb_flags & CI_SB_FLAG_MOVED) );

    /* Shutdown() the os_socket.  This needs to be done in a blocking
     * context.
     */
    if( wo->waitable.state == CI_TCP_LISTEN )
      efab_tcp_helper_shutdown_os_sock(tep_p, SHUT_RDWR);

    spin_lock_irqsave(&tep_p->lock, flags);

    os_socket = tep_p->os_socket;
    tep_p->os_socket = NULL;
    spin_unlock_irqrestore(&tep_p->lock, flags);
    oo_os_sock_poll_register(&tep_p->os_sock_poll, NULL);
    if( os_socket != NULL )
      oo_file_ref_drop(os_socket);
  }

  /* SO_LINGER should be handled
   * (i) when we close the last reference to the file;
   * (ii) not postponed to any lock holder;
   * (iii) not under the trusted lock.
   */
  if( ! (current->flags & PF_EXITING) &&
      (wo->waitable.state & CI_TCP_STATE_TCP) &&
      wo->waitable.state !=  CI_TCP_LISTEN &&
      (wo->sock.s_flags & CI_SOCK_FLAG_LINGER) && wo->sock.so.linger != 0 &&
      ci_netif_lock(&trs->netif) == 0 ) {
    __ci_tcp_shutdown(&trs->netif, &wo->tcp, SHUT_WR);
    ci_tcp_linger(&trs->netif, &wo->tcp);
    /* ci_tcp_linger exits unlocked */
  }

#if CI_CFG_FD_CACHING
  if( SP_TO_WAITABLE(ni, ep_id)->state == CI_TCP_LISTEN )
    ci_tcp_listen_uncache_fds(ni, SP_TO_TCP_LISTEN(ni, ep_id));
#endif

  /*! Add ep to the list in tcp_helper_resource_t for closing
    *   - we don't increment the ref count - as we need it to reach 0 when
    * the application exits i.e. crashes (even if its holding the netif lock)
    */
  ci_irqlock_lock(&trs->lock, &lock_flags);
  if( ! ci_sllink_busy(&tep_p->tobe_closed) )
    ci_sllist_push(&trs->ep_tobe_closed, &tep_p->tobe_closed);
  else {
    ci_irqlock_unlock(&trs->lock, &lock_flags);
    ci_log("%s: [%d:%d] is already closing", __FUNCTION__,
           trs->id, OO_SP_FMT(ep_id));
    return;
  }
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
#if CI_CFG_FD_CACHING
  citp_waitable_obj* wo;
#endif

  ci_assert(CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type));
  trs = efab_priv_to_thr(priv);
  ep = ci_trs_ep_get(trs, priv->sock_id);
#if CI_CFG_FD_CACHING
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
#endif


  if (ep->fasync_queue) {
    OO_DEBUG_SHM(ci_log("generic_tcp_helper_close removing fasync helper"));
    linux_tcp_helper_fop_fasync(-1, ci_privf(priv), 0);
  }

 if( priv->fd_type == CI_PRIV_TYPE_ALIEN_EP )
    fput(priv->_filp);

#if CI_CFG_FD_CACHING
  /* We don't close the endpoint for something in the cache.  The socket will
   * either be accepted, then freed as normal, or freed on removal from the
   * cache or acceptq on listening socket shutdown.
   *
   * The IN_CACHE flag is set with the netif lock held before adding to the
   * pending cache queue when deciding to cache.  At that point we still have
   * an fdtable entry preventing any close from the app getting here. This
   * means we should be safe to assume that responsibility for endpoint free
   * has been passed to the listening socket as long as Onload prevents
   * termination of threads that are holding the stack lock.  If this is not
   * the case there is the potential to leak the endpoint if the thread is
   * killed between setting the flag and adding the socket to the pending
   * queue.
   *
   * The NO_FD flag is required to be accurate when a socket is being pulled
   * off the acceptq.  This can be done by the app on accept, or on listen
   * socket shutdown.  It is also required to be accurate if the socket is
   * freed directly from cache on listen socket shutdown.
   *
   * There is some peril here if the app does a dup2/3 onto the cached fd
   * before we've put an entry in the fdtable.  The code at user level is
   * responsible for avoiding this.
   *
   * This is tricky on listening socket shutdown.  The fd can have changed
   * identity, but we might not know about it yet.  At the moment we don't
   * cope properly with this, just logging that it occurred.
   */
  if( (priv->fd_type == CI_PRIV_TYPE_TCP_EP) &&
      (wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE) )  {
    ci_atomic32_or(&wo->waitable.sb_aflags, CI_SB_AFLAG_IN_CACHE_NO_FD);
    LOG_EP(ci_log("%s: %d:%d fd close while cached - not freeing endpoint",
                  __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id)));
  }
  else {
#endif
    efab_tcp_helper_close_endpoint(trs, ep->id);
#if CI_CFG_FD_CACHING
  }
#endif
}


/**********************************************************************
 * CI_RESOURCE_OPs.
 */

int
efab_attach_os_socket(tcp_helper_endpoint_t* ep, struct file* os_file)
{
  int rc;
  struct oo_file_ref* old_os_socket;
  struct oo_file_ref* new_os_socket;
  unsigned long lock_flags;

  ci_assert(ep);
  ci_assert(os_file);
  ci_assert_equal(ep->os_socket, NULL);

  rc = oo_file_ref_lookup(os_file, &new_os_socket);
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
    oo_file_ref_drop(new_os_socket);
    OO_DEBUG_ERR(ci_log("%s: %d:%d os_file=%p is not a socket",
                        __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
                        os_file));
    return -EBUSY;
  }
  
  spin_lock_irqsave(&ep->lock, lock_flags);
  old_os_socket = oo_file_ref_xchg(&ep->os_socket, new_os_socket);
  new_os_socket = oo_file_ref_add(new_os_socket);
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  if( SP_TO_WAITABLE(&ep->thr->netif, ep->id)->state == CI_TCP_STATE_UDP )
    oo_os_sock_poll_register(&ep->os_sock_poll, new_os_socket->file);
  else
    oo_os_sock_poll_register(&ep->os_sock_poll, NULL);

  oo_file_ref_drop(new_os_socket);
  if( old_os_socket != NULL )
    oo_file_ref_drop(old_os_socket);

  return 0;
}


int
efab_create_os_socket(tcp_helper_endpoint_t* ep, ci_int32 domain,
                      ci_int32 type, int flags)
{
  int rc;
  struct file *os_file;
  struct socket* sock;
  citp_waitable_obj *wo = SP_TO_WAITABLE_OBJ(&ep->thr->netif, ep->id);

  rc = sock_create(domain, type, 0, &sock);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: sock_create(%d, %d, 0) failed (%d)",
                 __FUNCTION__, domain, type, rc));
    return rc;
  }
  os_file = sock_alloc_file(sock, flags, NULL);
  if( IS_ERR(os_file) ) {
    LOG_E(ci_log("%s: ERROR: sock_alloc_file failed (%ld)",
                 __FUNCTION__, PTR_ERR(os_file)));
    sock_release(sock);
    return PTR_ERR(os_file);
  }         

  wo->sock.ino = os_file->f_dentry->d_inode->i_ino;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
  wo->sock.uid = os_file->f_dentry->d_inode->i_uid;
#else
  wo->sock.uid = __kuid_val(os_file->f_dentry->d_inode->i_uid);
#endif

  rc = efab_attach_os_socket(ep, os_file);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: efab_attach_os_socket failed (%d)",
                 __FUNCTION__, rc));
    /* NB. efab_attach_os_socket() consumes [os_file] even on error. */
    return rc;
  }

  /* Advertise the existence of the backing socket to user-level. */
  ci_atomic32_or(&wo->waitable.sb_aflags, CI_SB_AFLAG_OS_BACKED);

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
get_os_ready_list(tcp_helper_resource_t* thr, int ready_list)
{
  ci_netif* ni = &thr->netif;
  tcp_helper_endpoint_t* ep;
  ci_dllink* lnk;
  citp_waitable* w;
  unsigned long lock_flags;

  spin_lock_irqsave(&thr->os_ready_list_lock, lock_flags);
  while( ci_dllist_not_empty(&thr->os_ready_lists[ready_list]) ) {
    lnk = ci_dllist_head(&thr->os_ready_lists[ready_list]);
    ep = CI_CONTAINER(tcp_helper_endpoint_t, os_ready_link, lnk);
    ci_dllist_remove_safe(&ep->os_ready_link);

    w = SP_TO_WAITABLE(ni, ep->id);
    ci_ni_dllist_remove(ni, &w->ready_link);
    ci_ni_dllist_put(ni, &ni->state->ready_lists[ready_list],
                     &w->ready_link);
  }
  spin_unlock_irqrestore(&thr->os_ready_list_lock, lock_flags);
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

  for( n = 1; n < CI_CFG_N_READY_LISTS; n++ ) {
    if( ni->state->ready_lists_in_use & (1 << n) ) {
      get_os_ready_list(thr, n);
      if( ci_ni_dllist_not_empty(ni, &ni->state->ready_lists[n]))
        efab_tcp_helper_ready_list_wakeup(thr, n);
    }
  }
}

ci_inline int want_proactive_packet_allocation(ci_netif* ni)
{
  ci_uint32 current_free = ni->packets->set[NI_PKT_SET(ni)].n_free;

  /* All the packets allocated */
  if( ni->pkt_sets_n == ni->pkt_sets_max )
    return 0;

  /* We need to have a decent number of free packets. */
  if( ni->packets->n_free > NI_OPTS(ni).free_packets_low ) {
    /* But these free packets may be distributed between sets in
     * unfortunate way, so we do additional checks. */

    /* Good if the packets are underused */
    if( ni->packets->n_free > ni->packets->n_pkts_allocated / 3 )
      return 0;

    /* Good: a lot of packets in the current set and also some packets in
     * non-current sets, so it'll be possible to switch to another set when
     * this one is empty. */
    if( current_free > PKTS_PER_SET / 2 &&
        ni->packets->n_free > PKTS_PER_SET * 3 / 4 )
      return 0;

    /* Good: a lot of packets in non-current sets, and
     * some of them have at least CI_CFG_RX_DESC_BATCH packets. */
    if( ni->packets->n_free - current_free >
        CI_MAX(PKTS_PER_SET / 2, CI_CFG_RX_DESC_BATCH * (ni->pkt_sets_n - 1)) )
      return 0;
  }

  CITP_STATS_NETIF_INC(ni, proactive_packet_allocation);
  OO_DEBUG_TCPH(ci_log("%s: [%d] proactive packet allocation: "
                       "%d sets n_freepkts=%d free_packets_low=%d "
                       "current_set.n_free=%d",
                       __func__, NI_ID(ni), ni->pkt_sets_n,
                       ni->packets->n_free, NI_OPTS(ni).free_packets_low,
                       current_free));
  return 1;
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
efab_tcp_helper_netif_lock_callback(eplock_helper_t* epl, ci_uint64 lock_val,
                                    int in_dl_context)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t,
                                            netif.eplock_helper, epl);
  const ci_uint64 all_after_unlock_flags = (CI_EPLOCK_NETIF_NEED_PRIME |
                                           CI_EPLOCK_NETIF_PKT_WAKE);
  ci_netif* ni = &thr->netif;
  ci_uint64 flags_set, clear_flags;
  ci_uint64 after_unlock_flags = 0;
  int intf_i;

  ci_assert(ci_netif_is_locked(ni));


  do {
    clear_flags = 0;
    if( in_dl_context )
      ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;

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
      flags_set &=~ CI_EPLOCK_NETIF_NEED_POLL;
    }

    if( flags_set & CI_EPLOCK_NETIF_SWF_UPDATE ) {
      oof_cb_sw_filter_apply(ni);
      CITP_STATS_NETIF(++ni->state->stats.unlock_slow_swf_update);
      flags_set &=~ CI_EPLOCK_NETIF_SWF_UPDATE;
    }

    if( flags_set & CI_EPLOCK_NETIF_NEED_WAKE ) {
      if( in_dl_context && oo_avoid_wakeup_from_dl() ) {
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer endpoint wakeup to workitem",
                             __FUNCTION__, thr->id));
        ef_eplock_holder_set_flags(
          &ni->state->lock,
          (after_unlock_flags & all_after_unlock_flags) | flags_set);
        ci_assert(ni->state->lock.lock & CI_EPLOCK_NETIF_NEED_WAKE);
        tcp_helper_defer_dl2work(thr, OO_THR_AFLAG_UNLOCK_UNTRUSTED);
        return 0;
      }
      OO_DEBUG_TCPH(ci_log("%s: [%u] wake up endpoints",
                           __FUNCTION__, thr->id));
      wakeup_post_poll_list(thr);
      CITP_STATS_NETIF(++ni->state->stats.unlock_slow_wake);
      flags_set &=~ CI_EPLOCK_NETIF_NEED_WAKE;
    }

    /* Monitor the number of free packets: pretend that
    ** CI_EPLOCK_NETIF_NEED_PKT_SET was set if non-current packet sets are
    ** short of packets.
    */
    if( (flags_set & CI_EPLOCK_NETIF_NEED_PKT_SET) ||
        want_proactive_packet_allocation(ni) ) {
      if( in_dl_context ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] NEED_PKT_SET to workitem",
                           __FUNCTION__, thr->id));
        ef_eplock_holder_set_flags(
          &ni->state->lock,
          (after_unlock_flags & all_after_unlock_flags) | flags_set);
        tcp_helper_defer_dl2work(thr, OO_THR_AFLAG_UNLOCK_UNTRUSTED);
        return 0;
      }
      OO_DEBUG_TCPH(ci_log("%s: [%u] NEED_PKT_SET now",
                           __FUNCTION__, thr->id));
      efab_tcp_helper_more_bufs(thr);
      flags_set &=~ CI_EPLOCK_NETIF_NEED_PKT_SET;
    }

    if( flags_set & CI_EPLOCK_NETIF_CLOSE_ENDPOINT ) {
      if( oo_trusted_lock_lock_or_set_flags(thr,
                                            OO_TRUSTED_LOCK_CLOSE_ENDPOINT) ) {
        /* We've got both locks.  If in non-atomic context, do the work,
         * else defer work and locks to workitem.
         */
        if( in_dl_context ) {
          OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to workitem",
                               __FUNCTION__, thr->id));
          if( after_unlock_flags & all_after_unlock_flags )
            ef_eplock_holder_set_flags(&ni->state->lock,
                                 after_unlock_flags & all_after_unlock_flags);
          tcp_helper_defer_dl2work(thr, OO_THR_AFLAG_CLOSE_ENDPOINTS);
          return 0;
        }
        OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINT now",
                             __FUNCTION__, thr->id));
        tcp_helper_close_pending_endpoints(thr);
        oo_trusted_lock_drop(thr, 0/*in_dl_context==0*/);
        CITP_STATS_NETIF(++ni->state->stats.unlock_slow_close);
      }
      else {
        /* Trusted lock holder now responsible for non-atomic work. */
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to trusted lock",
                             __FUNCTION__, thr->id));
      }
    }

    if( flags_set & CI_EPLOCK_NETIF_PURGE_TXQS )
      tcp_helper_purge_txq_locked(thr);

    /* IN_DL_CONTEXT flag should be removed under the stack lock - so we
     * remove it inside the "while" loop here and set back if necessary at
     * the beginning of the loop. */
    if( in_dl_context )
      ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;

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
    efab_tcp_helper_k_ref_count_dec(thr_prev);
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
