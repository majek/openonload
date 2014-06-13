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
**  \brief  Implementation of oo_wqlock.
**   \date  2012/01/10
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/ul/wqlock.h>


void oo_wqlock_init(struct oo_wqlock* wql)
{
  wql->lock = 0;
  pthread_mutex_init(&wql->mutex, NULL);
  pthread_cond_init(&wql->cond, NULL);
}


void oo_wqlock_lock_slow(struct oo_wqlock* wql)
{
  pthread_mutex_lock(&wql->mutex);
  while( 1 ) {
    uintptr_t v = wql->lock;
    if( v == 0 ) {
      if( ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED) )
        break;
    }
    else {
      if( ! (v & OO_WQLOCK_NEED_WAKE) )
        ci_cas_uintptr_succeed(&wql->lock, v, v | OO_WQLOCK_NEED_WAKE);
      else
        pthread_cond_wait(&wql->cond, &wql->mutex);
    }
  }
  pthread_mutex_unlock(&wql->mutex);
}


void oo_wqlock_unlock_slow(struct oo_wqlock* wql,
                           void (*cb)(void* cb_arg, void* work),
                           void* cb_arg)
{
  uintptr_t v;
  while( 1 ) {
    v = wql->lock;
    assert(v & OO_WQLOCK_LOCKED);
    if( (v & OO_WQLOCK_WORK_BITS) == 0 )
      if( ci_cas_uintptr_succeed(&wql->lock, v, 0) )
        break;
    oo_wqlock_try_drain_work(wql, cb, cb_arg);
  }
  if( v & OO_WQLOCK_NEED_WAKE ) {
    pthread_mutex_lock(&wql->mutex);
    pthread_mutex_unlock(&wql->mutex);
    pthread_cond_broadcast(&wql->cond);
  }
}
