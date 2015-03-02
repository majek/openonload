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
** <L5_PRIVATE L5_HEADER >
** \author  gel
**  \brief  Low-overhead un-shared user-space reader-writer locks.
**   \date  2004/01/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __ONLOAD_UL_RWLOCK_H__
#define __ONLOAD_UL_RWLOCK_H__


#include <ci/tools.h>
#include <pthread.h>

/* If lock mode is:
 * CI_RWLOCK_WRITE: tests for lock being held in write mode
 * CI_RWLOCK_READ: tests for lock being held in read mode
 * CI_RWLOCK_ANY: tests for lock being held in either mode
 */
enum lock_mode {CI_RWLOCK_WRITE, CI_RWLOCK_READ, CI_RWLOCK_ANY};

typedef struct {
  pthread_rwlock_t rw;
} oo_rwlock;

ci_inline int oo_rwlock_ctor(oo_rwlock *l)
{
  return pthread_rwlock_init(&l->rw, NULL);
}
ci_inline void oo_rwlock_dtor(oo_rwlock *l)
{
  (void) pthread_rwlock_destroy(&l->rw);
}

ci_inline void oo_rwlock_lock_read(oo_rwlock* l)
{
  while( pthread_rwlock_rdlock(&l->rw) );
}
ci_inline int oo_rwlock_try_read(oo_rwlock *l)
{
  return pthread_rwlock_tryrdlock(&l->rw);
}
ci_inline void oo_rwlock_unlock_read(oo_rwlock *l) {
  while( pthread_rwlock_unlock(&l->rw) );
}

/* oo_rwlock write is (i) rwlock and (ii) mutex (locked in this order,
 * unlocked in reverse order). */
ci_inline void oo_rwlock_lock_write(oo_rwlock* l) {
  while( pthread_rwlock_wrlock(&l->rw) );
}
ci_inline int oo_rwlock_try_write (oo_rwlock *l)
{
  return pthread_rwlock_trywrlock(&l->rw);
}

ci_inline void oo_rwlock_unlock_write(oo_rwlock *l)
{
  while( pthread_rwlock_unlock(&l->rw) );
}



typedef struct {
  pthread_mutex_t m;
  pthread_cond_t  c;
} oo_rwlock_cond;


ci_inline int oo_rwlock_cond_init(oo_rwlock_cond *cond)
{
  int rc = pthread_mutex_init(&cond->m, NULL);
  if( rc != 0 )
    return rc;
  return pthread_cond_init(&cond->c, NULL);
}
ci_inline void oo_rwlock_cond_destroy(oo_rwlock_cond *cond) {
  int rc = pthread_mutex_destroy(&cond->m);
  (void) rc;
  ci_assert_equal(rc, 0);
  rc = pthread_cond_destroy(&cond->c);
  ci_assert_equal(rc, 0);
}

ci_inline void
oo_rwlock_cond_lock(oo_rwlock_cond *cond)
{
  while( pthread_mutex_lock(&cond->m) );
}
ci_inline void
oo_rwlock_cond_unlock(oo_rwlock_cond *cond)
{
  pthread_mutex_unlock(&cond->m);
}
 
ci_inline int
oo_rwlock_cond_wait(oo_rwlock_cond *cond)
{
  return pthread_cond_wait(&cond->c, &cond->m);
}
ci_inline int
oo_rwlock_cond_broadcast(oo_rwlock_cond *cond)
{
  return pthread_cond_broadcast(&cond->c);
}


#endif  /* __ONLOAD_UL_RWLOCK_H__ */
