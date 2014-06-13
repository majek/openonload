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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Greg Law
**  \brief  Reader-writer lock slow-paths (fast-paths inlined in header)
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <ci/compat.h>
#include <onload/ul/rwlock.h>


/**********************************************************************/
/**********************************************************************/

ci_inline int rwlock_internal_ctor(oo_rwlock *l)
{
  int r;
  r = pthread_mutex_init(&l->m, NULL);
  if( r )  goto fail1;
  r = pthread_cond_init(&l->write_cond, NULL);
  if( r )  goto fail2;
  r = pthread_cond_init(&l->read_cond, NULL);
  if( r )  goto fail3;
  return 0;
 fail3:	/* tough luck if these fail...nothing we can do */
  pthread_cond_destroy (&l->write_cond);
 fail2:
  pthread_mutex_destroy(&l->m);
 fail1:
  return -r;
}


ci_inline void rwlock_internal_dtor(oo_rwlock* l)
{
   /* NB: We assume the destrunction of the pthreads primitives will succeed.
   * We can't deal with failure in the case that we end up with a rwlock
   * half-destroyed, and according to the pthreads spec there is no way for
   * these ops to fail if the rwlock has been used accourding to our rules
   * (specifically, don't destroy one that a thread maybe waiting on)/
   */
  CI_TRY(pthread_mutex_destroy(&l->m));

  CI_TRY(pthread_cond_destroy(&l->read_cond));

  CI_TRY(pthread_cond_destroy(&l->write_cond));
}

ci_inline int rwlock_internal_cond_wait(rwlock_cond_t* cond, oo_rwlock* l)
{ return pthread_cond_wait (cond, &l->m); }

ci_inline int rwlock_internal_mutex_lock(oo_rwlock* l)
{ return pthread_mutex_lock (&l->m); }

ci_inline int rwlock_internal_mutex_unlock(oo_rwlock* l)
{ return pthread_mutex_unlock (&l->m); }

ci_inline int rwlock_internal_signal_writer (rwlock_cond_t* cond)
{ return pthread_cond_signal (cond); }

ci_inline int rwlock_internal_broadcast_writer (rwlock_cond_t* cond)
{ return pthread_cond_broadcast (cond); }

ci_inline int rwlock_internal_signal_readers(rwlock_cond_t* cond) 
{ return pthread_cond_broadcast (cond); }



/**********************************************************************/


/**********************************************************************
***********************************************************************
**********************************************************************/

int
oo_rwlock_ctor(oo_rwlock *l)
{
  int r;
  ci_assert(l);

  l->state.val = 0;

#if OO_RWLOCK_STATS
  ci_atomic_set(&l->n_lock_read_contends, 0);
  ci_atomic_set(&l->n_unlock_read_contends, 0);
  ci_atomic_set(&l->n_lock_write_contends, 0);
  ci_atomic_set(&l->n_unlock_write_contends, 0);
#endif

  /* According to the man pages, pthread_[mutex|cond]_init() *always*
  ** return 0.  However, this is ONLY FOR LinuxThreads; the POSIX 1003.4
  ** spec (and NPTL) make no such guarnatee!
  */
  r=rwlock_internal_ctor(l);
  if (r) return r;

  return 0;
}


void
oo_rwlock_dtor(oo_rwlock* l)
{
  ci_assert(l);
  rwlock_internal_dtor(l);
}


int
oo_rwlock_cond_init (oo_rwlock_cond *cond)
{
  return pthread_cond_init (&cond->c, 0);
}


int
oo_rwlock_cond_destroy (oo_rwlock_cond *cond)
{
  return pthread_cond_destroy (&cond->c);
}


/* Exactly analagous to pthread_cond_wait, except that the c.v. is synchronized
 * by a rwlock (held in write mode) as opposed to a pthreads mutex.
 * This implementation may appear at first glance as though it is vulnerable to
 * lost wake-ups since we go:
 *  1. Take rwlock in write mode (before this is called)
 *  2. Take rwlock's underlying mutex
 *  3. Release rwlock state
 *  4. Wait
 * Why isn't there a lost wake-up race between steps 3 and 4?  It's because we
 * take the pthreads mutex at step 2, and also because the signal code takes
 * the pthread mutex before signalling.  Which means that there is no way the
 * signal can come in between steps 3 and 4 (since we have the mutex).
 */
int
oo_rwlock_cond_wait (oo_rwlock_cond *cond, oo_rwlock *l) {
  int rc;

  ci_assert(l);
  ci_assert(oo_rwlock_is_locked (l, CI_RWLOCK_WRITE));
  CI_TRY(rwlock_internal_mutex_lock(l));

  /* Let the lock go.  From this point on other threads will be able to take
   * the lock.  This is OK, but we must be careful to guard against lost
   * wake-up races with the condition variable.  This is OK, because we insist
   * that the cond-var is signalled only via oo_rwlock_cond_signal, which will
   * also take the mutex.
   */
  __oo_rwlock_unlock_write_slow (l, 1);

  rc = rwlock_internal_cond_wait (&cond->c, l);

  /* Now we need to take the lock again.  We know we hold l->m, but other
   * threads can take the lock in write or read mode without holding l->m,
   * so we need to go through the full locking process
   */
  __oo_rwlock_lock_write_slow (l, 1);

  CI_TRY(rwlock_internal_mutex_unlock (l));

  return rc;
}


int oo_rwlock_cond_signal (oo_rwlock_cond *cond, oo_rwlock *l,
			   int l_is_locked)
{
  int rc;
  ci_assert(! l_is_locked || oo_rwlock_is_locked (l, CI_RWLOCK_WRITE));

  /* Race breaker. */

  if( ! l_is_locked && l->state.s.write_held ) {
    oo_rwlock_lock_write(l);
    oo_rwlock_unlock_write(l);
  }

  CI_TRY(rwlock_internal_mutex_lock (l));
  CI_TRY(rwlock_internal_mutex_unlock (l));

  rc = rwlock_internal_signal_writer (&cond->c);

  return rc;
}


int oo_rwlock_cond_broadcast (oo_rwlock_cond *cond, oo_rwlock *l,
			      int l_is_locked)
{
  int rc;
  ci_assert(! l_is_locked || oo_rwlock_is_locked (l, CI_RWLOCK_WRITE));

  /* Race breaker. */

  if( ! l_is_locked && l->state.s.write_held ) {
    oo_rwlock_lock_write(l);
    oo_rwlock_unlock_write(l);
  }

  CI_TRY(rwlock_internal_mutex_lock (l));
  CI_TRY(rwlock_internal_mutex_unlock (l));

  rc = rwlock_internal_broadcast_writer (&cond->c);

  return rc;
}


/* The slow path for locking a reader-writer lock.  Called when someone tried
 * to take a lock in read mode, but it was already held in write mode, and so
 * we need to block.  This should never be called directly.
 * Note that we need to be aware that by the time we get here, the lock may
 * have been released.  Either we regsiter our interest in it by decrementing
 * the number of readers, or we take it by incrementing the reader count.
 *
 * We also need to pay attention to the "lost wakeup race".  We prevent this by
 * surrounding the whole thing with a mutex, so that we are synchronized
 * between waiting on the condvar and being woken from it.  Note however that
 * even though we have the mutex, the lock can still change state under our
 * feet because the fast path operations do not take the mutex.
 */
void
__oo_rwlock_lock_read_slow (oo_rwlock *l) {
  union rw_lock_state old_state, new_state;

  ci_assert(l);

#if OO_RWLOCK_STATS
  ci_atomic_inc(&l->n_lock_read_contends);
#endif

  CI_TRY(rwlock_internal_mutex_lock (l));

  do {
    old_state = new_state = l->state;

    if (new_state.s.write_held) {
      /* Still held in write-mode.  We need to register that we need to be
       * woken when whoever own it releases it, and we'll block below
       */ 
      ci_assert_le(new_state.s.n_readers, 0);
      new_state.s.n_readers--;
    }
    else {
      /* In the mean time it has become available, try again to take it. */
      ci_assert_ge(new_state.s.n_readers, 0);
      new_state.s.n_readers++;
    }
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));

  /* When we get here either we've taken the lock in read mode, or registered
   * our interest in it.  Wait until it becomes taken in read mode.
   */
  ci_assert(new_state.s.n_readers);  /* Either have it or waiting for it */
  while (l->state.s.n_readers < 0)
    CI_TRY(rwlock_internal_cond_wait (&l->read_cond, l));

  CI_TRY(rwlock_internal_mutex_unlock (l));
}



/* Slow path for unlocking a reader lock.  Called when we unlock a lock from
 * read mode, and detect that someone else is waiting to take it in write mode.
 * Which means we need to wake that person up if and only if we are the last
 * thread to hold it in reader mode.  Note that the lock cannot have changed
 * state to write mode, but we need to pay attention to the race that we are
 * the last thread to hold in read mode, but concurrently someone else comes
 * and takes it in write mode.
 */
void
__oo_rwlock_unlock_read_slow (oo_rwlock *l) {
  int do_wake;
  union rw_lock_state old_state, new_state;
  
  ci_assert(l);

#if OO_RWLOCK_STATS
  ci_atomic_inc(&l->n_unlock_read_contends);
#endif

  CI_TRY(rwlock_internal_mutex_lock(l));

  do {
    do_wake = 0;
    new_state = old_state = l->state; 
 
    /* Have lock in read-mode, hence no one can have it in write mode */
    ci_assert_ge(l->state.s.n_readers, 1);
    ci_assert_equal(l->state.s.write_held, 0);
 
    new_state.s.n_readers--;
 
    if ((!new_state.s.n_readers) && new_state.s.n_writers_waiting) {
      /* No more readers, writers were queued: wake one of them up. */
      do_wake = 1;
    }
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));

  CI_TRY(rwlock_internal_mutex_unlock(l));

  if (do_wake)
    CI_TRY(rwlock_internal_signal_writer (&l->write_cond));
}


void __oo_rwlock_lock_write_slow(oo_rwlock* l, int mutex_held)
{
  union rw_lock_state old_state, new_state;
  int got_it, waiting = 0;

  ci_assert(l);

#if OO_RWLOCK_STATS
  ci_atomic_inc(&l->n_lock_write_contends);
#endif

  if (!mutex_held)
    CI_TRY(rwlock_internal_mutex_lock(l));

  while( 1 ) {
    do {
      old_state = new_state = l->state;
      got_it = 0;

      if( (new_state.s.n_readers > 0) | new_state.s.write_held ) {
        /* There are readers or writers; need to block */
        if( ! waiting )  ++new_state.s.n_writers_waiting;
      }
      else {
        /* Has been freed in the mean-time; we can take it */
        got_it = 1;
        new_state.s.write_held = 1;
        if( waiting ) {
          ci_assert_gt(new_state.s.n_writers_waiting, 0);
          --new_state.s.n_writers_waiting;
        }
      }
    }
    while( ci_cas32_fail (&l->state.val, old_state.val, new_state.val) );

    /* Either we took the lock in write mode, or we registered interest in
    ** it. */
    ci_assert(l->state.s.n_writers_waiting | new_state.s.write_held);

    if( got_it ) {
      /* We successfully took the lock */
      ci_assert(l->state.s.write_held);
      ci_assert_le(l->state.s.n_readers, 0);
      if( ! mutex_held )
        CI_TRY(rwlock_internal_mutex_unlock (l));
      return;
    }

    /* If we get here we didn't get the lock; wait */
    waiting = 1;
    CI_TRY(rwlock_internal_cond_wait (&l->write_cond, l));
  }
}


void
__oo_rwlock_unlock_write_slow (oo_rwlock *l, int mutex_held) {
  union rw_lock_state old_state, new_state;
  int wake_readers, wake_writers;

  ci_assert(l);

#if OO_RWLOCK_STATS
  ci_atomic_inc(&l->n_unlock_write_contends);
#endif

  if (!mutex_held) {
    /* Strictly speaking we probably don't need this lock -- there should
     * only ever be one thread unlocking from write mode, because this
     * function should only be called by a thread that owns the lock in
     * write mode, and there can only be one of those.  Keep things simple
     * for now however...
     */
    CI_TRY(rwlock_internal_mutex_lock(l));
  }

  do {
    wake_readers = wake_writers = 0;
    old_state = new_state = l->state;

    ci_assert(new_state.s.write_held);
    ci_assert_le(new_state.s.n_readers, 0);

    if (new_state.s.n_readers) {
      /* Strong reader, so wake all readers in preference.  This is slightly
       * confusing because we "hand over" ownership of the lock when waking
       * readers, but not when waking writers.  This is because from a single
       * point we wake all readers, so it makes sense to do it here, but when
       * waking a writer we don't know who we're waking, so we take ownership
       * of the lock in __oo_rwlock_lock_write (necessary for correctness as
       * well as good for performance :-)
       */
      wake_readers = 1;
      new_state.s.n_readers = -new_state.s.n_readers;
    }
    else if (new_state.s.n_writers_waiting)
      wake_writers = 1;

    new_state.s.write_held = 0;
    
  } 
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
    
  if (!mutex_held)
    CI_TRY(rwlock_internal_mutex_unlock (l));

  ci_assert(!(wake_writers && wake_readers));
  if (wake_writers)
    CI_TRY(rwlock_internal_signal_writer (&l->write_cond));
  if (wake_readers)
    CI_TRY(rwlock_internal_signal_readers (&l->read_cond));
}



/*! \cidoxg_end */
