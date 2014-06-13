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


#define OO_RWLOCK_STATS 1


#include <ci/tools.h>
#include <pthread.h>


typedef pthread_mutex_t rwlock_mutex_t;
typedef pthread_cond_t rwlock_cond_t;



union rw_lock_state {
  struct {
    /* The +ve number of readers, or the -ve # of threads waiting to read */
    int n_readers : 16;

    /* Number of writers waiting */
    unsigned n_writers_waiting : 15;

    /* Non-zero if the lock is held in write (exclusive) mode. */
    unsigned write_held : 1;
  } s;
  ci_int32 val;
};


/* A reader-writer lock (strong reader) */
typedef struct {
  volatile union rw_lock_state state;
  rwlock_mutex_t  m;
  rwlock_cond_t   write_cond;
  rwlock_cond_t   read_cond;

#if OO_RWLOCK_STATS
  ci_atomic_t      n_lock_read_contends;
  ci_atomic_t      n_unlock_read_contends;
  ci_atomic_t      n_lock_write_contends;
  ci_atomic_t      n_unlock_write_contends;
#endif
} oo_rwlock;


/* ctor and dtor -- use in obvious way */
extern int oo_rwlock_ctor(oo_rwlock *l) CI_HF;
extern void oo_rwlock_dtor (oo_rwlock *l) CI_HF;


/*****************************************************************************
 * The following provides a condition variable that is synchronized with a
 * rw-lock rather than a mutex.  Note however that the rw lock must be take
 * in write mode to be used with oo_rwlock_cond_wait.
 */
typedef struct {
  pthread_cond_t c;
} oo_rwlock_cond;


extern int oo_rwlock_cond_init (oo_rwlock_cond *cond);
extern int oo_rwlock_cond_destroy (oo_rwlock_cond *cond);
extern int oo_rwlock_cond_wait (oo_rwlock_cond *cond, oo_rwlock *l) CI_HF;
extern int oo_rwlock_cond_signal (oo_rwlock_cond *cond, oo_rwlock *l,
				  int l_is_locked) CI_HF;
extern int oo_rwlock_cond_broadcast (oo_rwlock_cond *cond, oo_rwlock *l,
				     int l_is_locked) CI_HF;

/* Private functions, for use only by the inlines defined in this header */
extern void __oo_rwlock_lock_read_slow (oo_rwlock *l) CI_HF;
extern void __oo_rwlock_unlock_read_slow (oo_rwlock *l) CI_HF;
extern void __oo_rwlock_lock_write_slow (oo_rwlock *l, int mutex_held) CI_HF;
extern void __oo_rwlock_unlock_write_slow (oo_rwlock *l, int mutex_held) CI_HF;

  /*! Lock a rwlock in read mode. */
ci_inline void
oo_rwlock_lock_read (oo_rwlock* l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);
  do {
    new_state = old_state = l->state;
    if (new_state.s.write_held) {
      /* Someone has it in write mode; slow path. */
      __oo_rwlock_lock_read_slow (l);
      return;
    }
    new_state.s.n_readers++;
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
}

  /*! Try to lock a rwlock in read mode (i.e. don't block) */
ci_inline int
oo_rwlock_try_read (oo_rwlock *l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);
  do {
    new_state = old_state = l->state;
    if (new_state.s.write_held) {
      /* Someone has it in write mode; failure */
      return 0;
    }
    new_state.s.n_readers++;
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
  return 1;
}

  /*! Unlock a rwlock from read mode. */
ci_inline void
oo_rwlock_unlock_read (oo_rwlock *l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);
  do {
    new_state = old_state = l->state;
    /* Have the lock in read mode; can't be held in write mode, and there can't
     * be readers waiting on it, and at lest one thread (us) holds it.
     */
    ci_assert (!l->state.s.write_held);
    ci_assert (l->state.s.n_readers > 0);

    new_state.s.n_readers--;

    if ((new_state.s.n_readers == 0) && new_state.s.n_writers_waiting) {
      /* We are the last reader, and writers are waiting; drop to slow path. */
      __oo_rwlock_unlock_read_slow (l);
      return;
    }
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
}


  /*! Lock a rwlock for writing */
ci_inline void
oo_rwlock_lock_write (oo_rwlock *l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);
  do {
    new_state = old_state = l->state;
    if (new_state.s.write_held | (new_state.s.n_readers > 0)) {
      /* Note: We can't just say (new_state.val != 0) above, because this means
       * in the case that there are readers waiting or writers waiting, but
       * none of them actually have it, then we block waiting with no one to
       * wake us.  The only time this can actually happen however is when a
       * thread has relenquished the lock, but not yet woken people up.  So in
       * this case it is probably OK, because then whoever was waiting will be
       * woken eventually, who will wake us when they release it.  By induction
       * this is OK.  All very difficult to reason about however, so for now we
       * keep it simple.  Also avoids us blocking when we might not really need
       * to, although this in turn could possibly lead to starvation??
       *
       * Anyway,
       *
       * Someone has it in read or write mode; slow path.
       */
      __oo_rwlock_lock_write_slow (l, 0);
      ci_assert (l->state.s.write_held);
      return;
    }
    new_state.s.write_held = 1;
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
  ci_assert (l->state.s.write_held);
}

  /*! Try to lock a rwlock for writing */
ci_inline int
oo_rwlock_try_write (oo_rwlock *l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);
  do {
    new_state = old_state = l->state;
    if (new_state.s.write_held | (new_state.s.n_readers > 0)) {
      /* Someone else has it.  Don't block but return zero */
      return 0;
    }
    new_state.s.write_held = 1;
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
  ci_assert (l->state.s.write_held);
  return 1;
}

  /*! Unlock a rwlock from writing */
ci_inline void
oo_rwlock_unlock_write (oo_rwlock *l) {

  union rw_lock_state new_state, old_state;
  ci_assert (l);

  do {
    new_state = old_state = l->state;

    /* Must be held in write mode */
    ci_assert (new_state.s.write_held);
    ci_assert (new_state.s.n_readers <= 0);

    if (new_state.s.n_readers | new_state.s.n_writers_waiting) {
      /* Threads waiting for read and/or write; slow path. */
      __oo_rwlock_unlock_write_slow (l, 0);
      return;
    }
    new_state.s.write_held = 0;
  }
  while (ci_cas32_fail (&l->state.val, old_state.val, new_state.val));
}

  /*! Unlock a rwlock from either writer mode of read mode */
ci_inline void
oo_rwlock_unlock (oo_rwlock *l) {

  ci_assert (l);
  ci_assert (l->state.s.write_held | l->state.s.n_readers);
  if (l->state.s.write_held == 1)
    oo_rwlock_unlock_write (l);
  else
    oo_rwlock_unlock_read (l);

}

   /*! Return non-zero if lock held (useful for assertions).  If mode is:
    *  CI_RWLOCK_WRITE: tests for lock being held in write mode
    *  CI_RWLOCK_READ: tests for lock being held in read mode
    *  CI_RWLOCK_ANY: tests for lock being held in either mode
    */
enum lock_mode {CI_RWLOCK_WRITE, CI_RWLOCK_READ, CI_RWLOCK_ANY};

ci_inline int
oo_rwlock_is_locked (oo_rwlock *l, enum lock_mode mode) {
  ci_assert (l);

  switch (mode) {
    case CI_RWLOCK_ANY:
      return (l->state.val != 0);
    case CI_RWLOCK_READ:
      return (l->state.s.n_readers > 0);
    case CI_RWLOCK_WRITE:
      return (l->state.s.write_held);
  }

  /* We were passed an invalid mode -- fail! */
  ci_assert (0);
  return 0;
}


#endif  /* __ONLOAD_UL_RWLOCK_H__ */
