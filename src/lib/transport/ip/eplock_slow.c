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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Slow path for eplocks.  (Lock contended case).
**   \date  2003/02/14
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>

#ifndef __KERNEL__
# include <onload/ul.h>
# include "ip_internal.h"
#endif


static int __ef_eplock_lock_wait(ci_netif *ni)
{
#ifndef __KERNEL__
  return oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_EPLOCK_LOCK_WAIT,
                        NULL);
#else
  return efab_eplock_lock_wait(ni
		       CI_BLOCKING_CTX_ARG(ci_blocking_ctx_arg_needed()));
#endif
}


int __ef_eplock_lock_slow(ci_netif *ni)
{
#ifndef __KERNEL__
  ci_uint64 start_frc, now_frc;
#endif
  int rc, l, n;

  if( ef_eplock_trylock(&ni->state->lock) )
    return 0;

#ifndef __KERNEL__
  /* Limit to user-level for now.  Could allow spinning in kernel if we did
   * not rely on user-level accessible state for spin timeout.
   */
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_STACK_LOCK) ) {
    CITP_STATS_NETIF(++ni->state->stats.stack_lock_buzz);
    ci_frc64(&now_frc);
    start_frc = now_frc;
    while( now_frc - start_frc < ni->state->buzz_cycles ) {
      ci_spinloop_pause();
      ci_frc64(&now_frc);
      if( ef_eplock_trylock(&ni->state->lock) )
        return 0;
    }
  }
#endif

  while( 1 ) {
    if( (rc = __ef_eplock_lock_wait(ni)) < 0 ) {
#ifndef __KERNEL__
      if( rc == -EINTR )
        /* Keep waiting if interrupted by a signal.  I think this is okay:
         * If the outer call blocks, we'll handle the signal before
         * blocking, and behave as if the signal arrived before the outer
         * call.  If the outer call does not block, then we'll handle the
         * signal on return, and behave as if the signal arrived after the
         * outer call.
         */
        continue;
      /* This should never happen. */
      LOG_E(ci_log("%s: ERROR: rc=%d", __FUNCTION__, rc));
      CI_TEST(0);
#else
      /* There is nothing we can do except propagate the error.  Caller
       * must handle it.
       */
      if( rc == -ERESTARTSYS )
        /* Actually it would probably be better to just return -ERESTARTSYS
         * here, as I suspect most callers will want to propagate that.
         * But we'll need to audit all the callers first.
         */
        return -EINTR;
      LOG_E(ci_log("%s: ERROR: rc=%d", __FUNCTION__, rc));
      return rc;
#endif
    }

    /* NB. This is better than using trylock, because we avoid the sys-call
     * in the case that the cas fails.
     */
  again:
    l = ni->state->lock.lock;
    if( l & CI_EPLOCK_UNLOCKED ) {
      n = (l &~ CI_EPLOCK_UNLOCKED) | CI_EPLOCK_LOCKED;
      if( ci_cas32_succeed(&ni->state->lock.lock, l, n) )
	return 0;
      else
	goto again;
    }
  }

  /* Can't get here. */
  ci_assert(0);
  return 0;
}

/*! \cidoxg_end */
