/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/kcompat.h>
#include <ci/tools.h>
#include <onload/common.h>
#include <onload/atomics.h>

void test_lock_init(pthread_mutex_t* m)
{
  int rc = pthread_mutex_init(m, NULL);
  ci_assert(rc == 0);
  (void) rc;
}

void test_lock_lock(pthread_mutex_t* m)
{
  int rc = pthread_mutex_lock(m);
  ci_assert(rc == 0);
  (void) rc;
}

void test_lock_unlock(pthread_mutex_t* m)
{
  int rc = pthread_mutex_unlock(m);
  ci_assert(rc == 0);
  (void) rc;
}

int test_lock_is_locked(pthread_mutex_t* m)
{
  int rc = pthread_mutex_trylock(m);
  if(rc == 0) {
    pthread_mutex_unlock(m);
    return 0;
  }
  else {
    return 1;
  }
}

void test_lock_destroy(pthread_mutex_t* m)
{
  int rc = pthread_mutex_destroy(m);
  ci_assert(rc == 0);
  (void) rc;
}

void mutex_lock(struct mutex* m) {
  test_lock_lock(&m->mutex);
}

void mutex_unlock(struct mutex* m) {
  test_lock_unlock(&m->mutex);
}

void mutex_init(struct mutex* m) {
  test_lock_init(&m->mutex);
}

int mutex_is_locked(struct mutex* m) {
  return test_lock_is_locked(&m->mutex);
}

void mutex_destroy(struct mutex* m) {
  test_lock_destroy(&m->mutex);
}

/* The spinlock implementation currently uses the pthread mutex, however,
 * this requires a destroy() function be called, which the oof code does not
 * call, so should probably be replaced.
 */
void spin_lock_init(spinlock_t* s) {
  test_lock_init(&s->spin);
}

int spin_is_locked(spinlock_t* s) {
  return test_lock_is_locked(&s->spin);
}

void spin_lock_bh(spinlock_t* s) {
  test_lock_lock(&s->spin);
}

void spin_unlock_bh(spinlock_t* s) {
  test_lock_unlock(&s->spin);
}

void atomic_add(int i, atomic_t *v)
{
  oo_atomic_add(v, i);
}

void atomic_set(atomic_t *v, int i)
{
  oo_atomic_set(v, i);
}

long atomic_long_add_return(long i, atomic_long_t *l)
{
  return __sync_add_and_fetch(&l->counter, i);
}

void atomic_long_sub(long i, atomic_long_t *l)
{
  __sync_sub_and_fetch(&l->counter, i);
}

