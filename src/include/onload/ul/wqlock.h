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

/**************************************************************************\
*//*! \file wqlock.c
** <L5_PRIVATE L5_HEADER >
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  oo_wqlock interface.
**   \date  2012/01/09
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_WQLOCK_H__
#define __ONLOAD_UL_WQLOCK_H__

#include <ci/tools.h>
#include <stdint.h>
#include <assert.h>
#include <pthread.h>


#define OO_WQLOCK_LOCKED     ((uintptr_t) 0x1)
#define OO_WQLOCK_NEED_WAKE  ((uintptr_t) 0x2)

#define OO_WQLOCK_LOCK_BITS  ((uintptr_t) 0x3)
#define OO_WQLOCK_WORK_BITS  (~OO_WQLOCK_LOCK_BITS)


struct oo_wqlock {
  volatile uintptr_t  lock;
  pthread_mutex_t     mutex;
  pthread_cond_t      cond;
};


extern void oo_wqlock_init(struct oo_wqlock* wql);

extern void oo_wqlock_lock_slow(struct oo_wqlock* wql) CI_HF;

extern void oo_wqlock_unlock_slow(struct oo_wqlock* wql,
                                  void (*cb)(void* cb_arg, void* work),
                                  void* cb_arg) CI_HF;


static inline int oo_wqlock_try_lock(struct oo_wqlock* wql)
{
  return wql->lock == 0 &&
    ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED);
}


static inline int oo_wqlock_try_queue(struct oo_wqlock* wql,
                                      void* work, void** p_next)
{
  uintptr_t new_v, v = wql->lock;
  if( v & OO_WQLOCK_LOCKED ) {
    *p_next = (void*) (v & OO_WQLOCK_WORK_BITS);
    new_v = (v & OO_WQLOCK_LOCK_BITS) | (uintptr_t) work;
    if( ci_cas_uintptr_succeed(&wql->lock, v, new_v) )
      return 1;
  }
  return 0;
}


static inline void oo_wqlock_lock(struct oo_wqlock* wql)
{
  if( wql->lock == 0 &&
      ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED) )
    return;
  oo_wqlock_lock_slow(wql);
}


static inline int oo_wqlock_lock_or_queue(struct oo_wqlock* wql,
                                          void* work, void** p_next)
{
  while( 1 )
    if( oo_wqlock_try_queue(wql, work, p_next) )
      return 0;
    else if( oo_wqlock_try_lock(wql) )
      return 1;
}


static inline void oo_wqlock_try_drain_work(struct oo_wqlock* wql,
                                         void (*cb)(void* cb_arg, void* work),
                                         void* cb_arg)
{
  uintptr_t v = wql->lock;
  assert(v & OO_WQLOCK_LOCKED);
  if( v & OO_WQLOCK_WORK_BITS )
    if( ci_cas_uintptr_succeed(&wql->lock, v, v & OO_WQLOCK_LOCK_BITS) )
      cb(cb_arg, (void*) (v & OO_WQLOCK_WORK_BITS));
}


static inline void oo_wqlock_unlock(struct oo_wqlock* wql,
                                    void (*cb)(void* cb_arg, void* work),
                                    void* cb_arg)
{
  if( wql->lock == OO_WQLOCK_LOCKED &&
      ci_cas_uintptr_succeed(&wql->lock, OO_WQLOCK_LOCKED, 0) )
    return;
  oo_wqlock_unlock_slow(wql, cb, cb_arg);
}

#endif  /* __ONLOAD_UL_WQLOCK_H__ */
