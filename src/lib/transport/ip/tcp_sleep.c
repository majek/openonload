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
** \author  djr
**  \brief  Support for blocking.
**   \date  2004/07/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"


#if defined(__unix__) && !defined(__KERNEL__)
# include <ci/internal/ip_signal.h>
# define HANDLE_SIGNALS 1
#else
# define HANDLE_SIGNALS 0
#endif


/**********************************************************************
 *
 * ci_sock_sleep()
 *
 */

#ifndef __KERNEL__

int ci_sock_sleep(ci_netif* ni, citp_waitable* w, ci_bits why,
                  unsigned lock_flags, ci_uint64 sleep_seq,
                  ci_uint32 *timeout_ms_p)
{
#if HANDLE_SIGNALS
  citp_signal_info* si;
#endif
  oo_tcp_sock_sleep_t op;
  int rc;

  LOG_TV(ci_log("%d:%d SLEEP why=%s%s flags=%s%s%s%s sleep_seq=%"CI_PRIu64,
                NI_ID(ni), W_FMT(w),
                (why & CI_SB_FLAG_WAKE_RX) ? "R":"",
                (why & CI_SB_FLAG_WAKE_TX) ? "T":"",
                (lock_flags & CI_SLEEP_NETIF_LOCKED) ? "NetifLocked":"",
                (lock_flags & CI_SLEEP_SOCK_LOCKED) ? "SockLocked":"",
                (lock_flags & CI_SLEEP_NETIF_RQ) ? "NetifRq":"",
                (lock_flags & CI_SLEEP_SOCK_RQ) ? "SockRq":"",
                sleep_seq));

  ci_assert(why);
  ci_assert(!(why &~ (CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX)));
  ci_assert(!(lock_flags & CI_SLEEP_NETIF_LOCKED) || ci_netif_is_locked(ni));
  ci_assert(!(lock_flags & CI_SLEEP_SOCK_LOCKED) || ci_sock_is_locked(ni, w));

  op.sock_id = W_SP(w);
  op.why = why;
  op.sleep_seq = sleep_seq;
  op.lock_flags = lock_flags;
  if( timeout_ms_p == NULL )
    op.timeout_ms = 0;
  else
    op.timeout_ms = *timeout_ms_p;
#if HANDLE_SIGNALS
  si = citp_signal_get_specific_inited();
  CI_USER_PTR_SET(op.sig_state, si);
  ci_assert(si->inside_lib != 0);
 again:
  /* Danger: "again" label must immediately precede the blocking call. */
#endif

  rc = oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_TCP_SOCK_SLEEP,
                      &op);
#if HANDLE_SIGNALS
  ci_assert(si->inside_lib == 0);
  if(CI_UNLIKELY( rc == -EBUSY )) {
    if( si->run_pending )
      citp_signal_run_pending(si);
    ci_assert(si->run_pending == 0);
    op.lock_flags &= ~(CI_SLEEP_NETIF_LOCKED | CI_SLEEP_SOCK_LOCKED);
    goto again;
  }
  si->inside_lib = 1;
#endif
  if( timeout_ms_p != NULL )
    *timeout_ms_p = op.timeout_ms;

  LOG_TV(ci_log("%d:%d AWAKE why=%s%s sleep=%"CI_PRIu64",%"CI_PRIu64" rc=%d",
                NI_ID(ni), W_FMT(w),
                (why & CI_SB_FLAG_WAKE_RX) ? "R":"",
                (why & CI_SB_FLAG_WAKE_TX) ? "T":"", sleep_seq,
                w->sleep_seq.all, rc));

  return rc;
}


#else  /* __KERNEL__ */

int ci_sock_sleep(ci_netif* ni, citp_waitable* w, ci_bits why,
                  unsigned lock_flags, ci_uint64 sleep_seq,
                  ci_uint32 *timeout_ms_p)
{
  oo_tcp_sock_sleep_t op;
  int rc;

  LOG_TV(ci_log("%d:%d SLEEP why=%s%s flags=%s%s%s%s sleep_seq=%"CI_PRIu64,
                NI_ID(ni), W_FMT(w),
                (why & CI_SB_FLAG_WAKE_RX) ? "R":"",
                (why & CI_SB_FLAG_WAKE_TX) ? "T":"",
                (lock_flags & CI_SLEEP_NETIF_LOCKED) ? "NetifLocked":"",
                (lock_flags & CI_SLEEP_SOCK_LOCKED) ? "SockLocked":"",
                (lock_flags & CI_SLEEP_NETIF_RQ) ? "NetifRq":"",
                (lock_flags & CI_SLEEP_SOCK_RQ) ? "SockRq":"",
                sleep_seq));

  ci_assert(why);
  ci_assert(!(why &~ (CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX)));
  ci_assert(!(lock_flags & CI_SLEEP_NETIF_LOCKED) || ci_netif_is_locked(ni));
  ci_assert(!(lock_flags & CI_SLEEP_SOCK_LOCKED) || ci_sock_is_locked(ni, w));

  op.sock_id = W_SP(w);
  op.why = why;
  op.sleep_seq = sleep_seq;
  op.lock_flags = lock_flags;
  if( timeout_ms_p == NULL )
    op.timeout_ms = 0;
  else
    op.timeout_ms = *timeout_ms_p;
  CI_USER_PTR_SET(op.sig_state, NULL);

  rc = efab_tcp_helper_sock_sleep(netif2tcp_helper_resource(ni), &op
                           CI_BLOCKING_CTX_ARG(ci_blocking_ctx_arg_needed()));
  ci_assert((op.lock_flags & (CI_SLEEP_NETIF_LOCKED |
                              CI_SLEEP_SOCK_LOCKED)) == 0);
  if( timeout_ms_p != NULL )
    *timeout_ms_p = op.timeout_ms;

  LOG_TV(ci_log("%d:%d AWAKE why=%s%s sleep=%"CI_PRIu64",%"CI_PRIu64" rc=%d",
                NI_ID(ni), W_FMT(w),
                (why & CI_SB_FLAG_WAKE_RX) ? "R":"",
                (why & CI_SB_FLAG_WAKE_TX) ? "T":"", sleep_seq,
                w->sleep_seq.all, rc));

  return rc;
}

#endif  /* __KERNEL__ */


/**********************************************************************
 *
 * ci_sock_lock_slow(), ci_sock_unlock_slow()
 *
 */

#ifdef __KERNEL__

static int ci_sock_lock_block(ci_netif* ni, citp_waitable* w)
{
  return efab_tcp_helper_sock_lock_slow(netif2tcp_helper_resource(ni),
                                        W_SP(w)
                           CI_BLOCKING_CTX_ARG(ci_blocking_ctx_arg_needed()));
}

#else

static int ci_sock_lock_block(ci_netif* ni, citp_waitable* w)
{
  oo_sp w_sp = W_SP(w);
  return oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_TCP_SOCK_LOCK,
                        &w_sp);
}

#endif


int ci_sock_lock_slow(ci_netif* ni, citp_waitable* w)
{
#ifndef __KERNEL__
  ci_uint64 start_frc, now_frc;
#endif
  unsigned old, new;
  int rc;

  if( ci_sock_trylock(ni, w) )
    return 0;

#ifndef __KERNEL__
  /* Limit to user-level for now.  Could allow spinning in kernel if we did
   * not rely on user-level accessible state for spin timeout.
   */
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SOCK_LOCK) ) {
    CITP_STATS_NETIF(++ni->state->stats.sock_lock_buzz);
    ci_frc64(&now_frc);
    start_frc = now_frc;
    while( now_frc - start_frc < ni->state->buzz_cycles ) {
      ci_frc64(&now_frc);
      if( ci_sock_trylock(ni, w) )
        return 0;
      ci_spinloop_pause();
    }
  }
#endif

  while( 1 ) {
    if( (rc = ci_sock_lock_block(ni, w)) < 0 ) {
#ifndef __KERNEL__
      if( rc == -EINTR )
        /* Keep waiting.  See __ef_eplock_lock_slow() for explaination of
         * why this is okay.
         */
        continue;
      LOG_E(ci_log("%s: ERROR: rc=%d", __FUNCTION__, rc));
      CI_TEST(0);
#else
      /* There is nothing we can do expect propagate the error. */
      LOG_E(ci_log("%s: ERROR: rc=%d", __FUNCTION__, rc));
      return rc;
#endif
    }
  again:
    /* NB. This is better than using ci_sock_trylock(), because we avoid
     * the sys-call in the case that the cas fails.
     */
    old = w->lock.wl_val;
    if( ! (old & OO_WAITABLE_LK_LOCKED) ) {
      new = old | OO_WAITABLE_LK_LOCKED;
      if( ci_cas32u_succeed(&w->lock.wl_val, old, new) )
        return 0;
      else
        goto again;
    }
  }
}


void ci_sock_unlock_slow(ci_netif* ni, citp_waitable* w)
{
  unsigned l;

  ci_assert(ci_sock_is_locked(ni, w));

 again:
  l = w->lock.wl_val;
  if( ! (l & OO_WAITABLE_LK_NEED_WAKE) ) {
    if(CI_LIKELY( ci_cas32u_succeed(&w->lock.wl_val, l,
                                    (l & ~OO_WAITABLE_LK_LOCKED)) ))
      return;
    goto again;
  }

#ifdef __KERNEL__
  efab_tcp_helper_sock_unlock_slow(netif2tcp_helper_resource(ni), W_SP(w));
#else
  {
    oo_sp w_sp = W_SP(w);
    CI_DEBUG_TRY(oo_resource_op(ci_netif_get_driver_handle(ni),
                                OO_IOC_TCP_SOCK_UNLOCK, &w_sp));
  }
#endif
}


/**********************************************************************
 *
 * ci_netif_pkt_wait()
 *
 */

#ifndef __KERNEL__

static int ci_netif_pkt_wait_spin(ci_netif* ni, int* lock_flags, int* done)
{
  ci_uint64 start_frc, now_frc;
  int rc = 1;

  ci_frc64(&start_frc);
  now_frc = start_frc;
  ni->state->is_spinner = 1;
  CITP_STATS_NETIF(++ni->state->stats.pkt_wait_spin);

  do {
    if( ci_netif_may_poll(ni) && ci_netif_need_poll_spinning(ni, now_frc) &&
        ((*lock_flags & CI_SLEEP_NETIF_LOCKED) || ci_netif_trylock(ni)) ) {
      *lock_flags |= CI_SLEEP_NETIF_LOCKED;
      ci_netif_poll(ni);
    }
    if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
      rc = 0;
      *done = 1;
      if( *lock_flags & CI_SLEEP_NETIF_RQ ) {
        if( ! (*lock_flags & CI_SLEEP_NETIF_LOCKED) )
          rc = ci_netif_lock(ni);  /* NB. Don't care about lock_flags now */
      }
      else if( *lock_flags & CI_SLEEP_NETIF_LOCKED )
        ci_netif_unlock(ni);  /* NB. Don't care about lock_flags now */
      break;
    }
    if( *lock_flags & CI_SLEEP_NETIF_LOCKED ) {
      ci_netif_unlock(ni);
      *lock_flags &=~ CI_SLEEP_NETIF_LOCKED;
    }
    ci_frc64(&now_frc);
    ci_spinloop_pause();
    /* NB: we do not handle signals here, since memory allocation is
     * considered non-interruptible. */
  } while( now_frc - start_frc < ni->state->spin_cycles );

  ni->state->is_spinner = 0;
  return rc;
}

#endif


int ci_netif_pkt_wait(ci_netif* ni, int lock_flags)
{
  int rc;

  ci_assert(!(lock_flags & CI_SLEEP_NETIF_LOCKED) || ci_netif_is_locked(ni));

#ifndef __KERNEL__
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_PKT_WAIT) ) {
    int done = 0;
    rc = ci_netif_pkt_wait_spin(ni, &lock_flags, &done);
    if( done )
      return rc;
  }
  else
#endif
  if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) )
    if( (lock_flags & CI_SLEEP_NETIF_LOCKED) || ci_netif_trylock(ni) ) {
      lock_flags |= CI_SLEEP_NETIF_LOCKED;
      ci_netif_poll(ni);
      if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
        if( ! (lock_flags & CI_SLEEP_NETIF_RQ) )
          ci_netif_unlock(ni);
        return 0;
      }
    }

  do {
    /* The PKT_WAIT ioctl used to be able to drop the stack lock, but I've
     * purged that feature for now.
     */
    if( lock_flags & CI_SLEEP_NETIF_LOCKED ) {
      ci_netif_unlock(ni);
      lock_flags &= ~CI_SLEEP_NETIF_LOCKED;
    }
#ifdef __KERNEL__
    rc = efab_tcp_helper_pkt_wait(netif2tcp_helper_resource(ni),
                                  &lock_flags
                            CI_BLOCKING_CTX_ARG(ci_blocking_ctx_arg_needed()));
#else
    rc = oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_TCP_PKT_WAIT,
                        &lock_flags);
    /* We treat allocation of memory (inc. packet buffers) as being
     * non-interruptible, because that is how the kernel behaves. */
    if( rc == -EINTR )
      continue;
#endif /* __KERNEL__ */

    /* If caller doesn't want the netif lock held, then there is not really
     * any point in checking can_alloc either (as it can change between now
     * and when caller acts).
     */
    if( rc < 0 || ! (lock_flags & CI_SLEEP_NETIF_RQ) )
      return rc;

    rc = ci_netif_lock(ni);
    if( rc < 0 )  return rc;
    lock_flags |= CI_SLEEP_NETIF_LOCKED;
  }
  while( ! ci_netif_pkt_tx_can_alloc_now(ni) );

  return 0;
}

/*! \cidoxg_end */
