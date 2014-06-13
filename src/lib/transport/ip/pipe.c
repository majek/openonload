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
** \author  djr/ctk/stg
**  \brief  PIPE routines
**   \date  2003/06/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#if CI_CFG_USERSPACE_PIPE

#include <onload/common.h>
#include <onload/oo_pipe.h>
#include <onload/sleep.h>

#define LPF "ci_pipe_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF

/* Lockless implememntation in case of single reader/writer */
#define OO_PIPE_LOCKLESS          0
/* Many-many logging messages */
#define OO_PIPE_VERBOSE           0

#define OO_PIPE_DUMP              0

#if OO_PIPE_VERBOSE
# define LOG_PIPE(x...) ci_log(x)
#else
# define LOG_PIPE(x...)
#endif


void pipe_dump(struct oo_pipe* p)
{
  if( OO_PIPE_DUMP ) {
    int i;
    ci_log("Pipe: p=%d", p->b.bufid);
    ci_log("  read_ptr: %u %u", p->read_ptr.bufid, p->read_ptr.offset);
    ci_log("  write_ptr: %u %u", p->write_ptr.bufid, p->write_ptr.offset);
    ci_log("  aflags=%x ", p->aflags);
    ci_log("  bufs_num=%u", p->bufs_num);
    ci_log("  bytes_added=%u bytes_removed=%u",
           p->bytes_added, p->bytes_removed);
    for( i = 0; i < p->bufs_num; i++ )
      ci_log("  buf[%d]=%u", i, p->buffer_idxs[i]);
  }
}


#if OO_PIPE_LOCKLESS

static int oo_pipe_trylock(ci_netif* ni, struct oo_pipe* p, int lock)
{
  ci_uint32 l = p->b.lock.wl_val;

  /* lock is already taken - we're loosers */
  if( l & lock ) return 0;

  return ci_cas32u_succeed(&p->b.lock.wl_val, l, l | lock);
}


static int oo_pipe_tryunlock(ci_netif* ni, struct oo_pipe* p, int lock)
{
  ci_uint32 l = p->b.lock.wl_val;

  /* no lock taken - very very bad */
  ci_assert(l & lock);

  return ci_cas32u_succeed(&p->b.lock.wl_val, l, l & (~ lock));
}


static int oo_pipe_is_locked(ci_netif* ni, struct oo_pipe* p, int lock)
{
  return ( p->b.lock.wl_val & lock );
}


static int oo_pipe_lock(ci_netif* ni, struct oo_pipe* p, int lock, int wake)
{
  LOG_PIPE("%s: called for ni=%d p=%d lock=%s wake=%d",
           __FUNCTION__, ni->state->stack_id, p->b.bufid,
           lock == OO_WAITABLE_LK_PIPE_RX ? "RX" : "TX", wake);
  
  ci_assert( lock == OO_WAITABLE_LK_PIPE_RX ||
             lock == OO_WAITABLE_LK_PIPE_TX );
  ci_assert( wake == CI_SB_FLAG_WAKE_RX ||
             wake == CI_SB_FLAG_WAKE_TX );

  while ( 1 ) {
    if( ! ci_sock_is_locked(ni, &p->b) ) {
      LOG_PIPE("%s: p=%d sock is unlocked", __FUNCTION__,
               p->b.bufid);
      if( ! oo_pipe_is_locked(ni, p, lock) ) {
        LOG_PIPE("%s: p=%d pipe is unlocked", __FUNCTION__, p->b.bufid);
        if( oo_pipe_trylock(ni, p, lock) ) {
          ci_assert(oo_pipe_is_locked(ni, p, lock));
          /* this is fastpath */
          return 0;
        }
        LOG_PIPE("%s: p=%d pipe lock failed", __FUNCTION__, p->b.bufid);
      }
      else {
        int rc;
        ci_uint64 sleep_seq = p->b.sleep_seq.all;

        LOG_PIPE("slowpath - sleeping");
        ci_log("entering slowpath: probably you have 2 readers or "
               "2 writers - this is very bad for performance and "
               "may lead to data mix");

        ci_rmb();
        /* something has changed - retry */
        if( ! oo_pipe_is_locked(ni, p, lock) )
          continue;

        /* sleep here */
        rc = ci_sock_sleep(ni, &p->b, wake, 0, sleep_seq, 0);
        if (rc < 0)
          CI_TEST(0);
        LOG_PIPE("woke up to take the lock");
      }
    }
    else {
      /* should we log here? it's slowpath... */
      LOG_PIPE("slowpath - taking socklock");

      /* sleep till socket is unlocked - this is cheaper then
       * ci_sock_sleep() as wake does not require netif lock
       */
      ci_sock_lock(ni, &p->b);
      if( oo_pipe_trylock(ni, p, lock) ) {
        ci_sock_unlock(ni, &p->b);
        return 0;
      }
      ci_sock_unlock(ni, &p->b);
    }
  } /* main */

  /* should not reach */
  CI_TEST(0);

  return -1;
}


static int oo_pipe_unlock(ci_netif* ni, struct oo_pipe* p, int lock, int wake)
{
  LOG_PIPE("%s: called for ni=%p p=%d lock=%s wake=%d",
           __FUNCTION__, ni, p->b.bufid,
           lock == OO_WAITABLE_LK_PIPE_RX ? "RX" : "TX", wake);

  ci_assert( lock == OO_WAITABLE_LK_PIPE_RX ||
             lock == OO_WAITABLE_LK_PIPE_TX );
  ci_assert( wake == CI_SB_FLAG_WAKE_RX ||
             wake == CI_SB_FLAG_WAKE_TX );

  while( 1 ) {
    if( ! ci_sock_is_locked(ni, &p->b) ) {
      LOG_PIPE("%s: p=%d sock is unlocked", __FUNCTION__,
               p->b.bufid);
      if( oo_pipe_tryunlock(ni, p, lock) )
        break;
      /* this can happen in case lock for _other_ end was changed,
       * not because somebody removed _our_ lock */
      LOG_PIPE("%s: p=%d unlock failed", __FUNCTION__,
               p->b.bufid);
      continue;
    }

    ci_sock_lock(ni, &p->b);
    if ( oo_pipe_tryunlock(ni, p, lock) ) {
      ci_sock_unlock(ni, &p->b);
      break;
    }

    ci_sock_unlock(ni, &p->b);
  }
  /* wake! */
  oo_pipe_wake_peer(p, ni, wake);
  return 0;
}


/* this should be updated to separate locks */
#define oo_pipe_lock_read(_ni, _p) \
  oo_pipe_lock(_ni, _p, OO_WAITABLE_LK_PIPE_RX, CI_SB_FLAG_WAKE_RX)
#define oo_pipe_unlock_read(_ni, _p) \
  oo_pipe_unlock(_ni, _p, OO_WAITABLE_LK_PIPE_RX, CI_SB_FLAG_WAKE_RX)
#define oo_pipe_is_read_locked(_ni, _p) \
  oo_pipe_is_locked(_ni, _p, OO_WAITABLE_LK_PIPE_RX)

#define oo_pipe_lock_write(_ni, _p)   \
  oo_pipe_lock(_ni, _p, OO_WAITABLE_LK_PIPE_TX, CI_SB_FLAG_WAKE_TX)
#define oo_pipe_unlock_write(_ni, _p) \
  oo_pipe_unlock(_ni, _p, OO_WAITABLE_LK_PIPE_TX, CI_SB_FLAG_WAKE_TX)
#define oo_pipe_is_write_locked(_ni, _p)  \
  oo_pipe_is_locked(_ni, _p, OO_WAITABLE_LK_PIPE_TX)

#else  /* OO_PIPE_LOCKLESS */

#define oo_pipe_is_read_locked(_ni, _p) ci_sock_is_locked(_ni, &(_p)->b)
#define oo_pipe_is_write_locked(_ni, _p) ci_sock_is_locked(_ni, &(_p)->b)

#endif /* OO_PIPE_LOCKLESS */


/* Amount of space left in the pipe for writing. */
#define oo_pipe_space(p)                                        \
  (OO_PIPE_BUF_SIZE * (p)->bufs_num - oo_pipe_data_len(p))


/* Update 'offset' of the _op pointer and may be shift to the new buffer idx */
/* question kostik: should we write all with expressions w/o if */
#define pipe_buf_next(_ni, _p, _op, _offset)                            \
  do {                                                                  \
    LOG_PIPE("%s: %s buf id=%d offset=%d, move_offset=%d", __FUNCTION__, \
             #_op, _p->_op##_ptr.bufid, _p->_op##_ptr.offset, (_offset)); \
    ci_assert(oo_pipe_is_##_op##_locked((_ni), (_p)));                  \
    _p->_op##_ptr.offset += (_offset);                                  \
    if( _p->_op##_ptr.offset == OO_PIPE_BUF_SIZE ) {                    \
      _p->_op##_ptr.offset = 0;                                         \
      _p->_op##_ptr.bufid = (_p->_op##_ptr.bufid + 1) % p->bufs_num;    \
    }                                                                   \
    LOG_PIPE("%s: new buf id=%d offset=%d", __FUNCTION__,               \
             _p->_op##_ptr.bufid, _p->_op##_ptr.offset);                \
  } while (0)


ci_inline void __oo_pipe_wake_peer(ci_netif* ni, struct oo_pipe* p,
                                   unsigned wake)
{
  ci_wmb();
  if( wake & CI_SB_FLAG_WAKE_RX )
    ++p->b.sleep_seq.rw.rx;
  if( wake & CI_SB_FLAG_WAKE_TX )
    ++p->b.sleep_seq.rw.tx;
  ci_mb();
  if( p->b.wake_request & wake ) {
    p->b.sb_flags |= wake;
    citp_waitable_wakeup(ni, &p->b);
  }
}


#ifdef __KERNEL__
void oo_pipe_wake_peer(ci_netif* ni, struct oo_pipe* p, unsigned wake)
{
  __oo_pipe_wake_peer(ni, p, wake);
}
#endif


ci_inline char* pipe_get_point(struct oo_pipe *p, ci_netif* ni,
                               ci_uint32 bufid, ci_uint32 offset)
{
  oo_sp buf_id;

  ci_assert(p);
  ci_assert_lt(bufid, p->bufs_num);

  buf_id = OO_SP_FROM_INT(ni, p->buffer_idxs[bufid]);

  return oo_sockp_to_ptr(ni, buf_id) + offset;
}


ci_inline int do_copy_read(void* to, const void* from, int n_bytes)
{
#ifdef __KERNEL__
  return copy_to_user(to, from, n_bytes) != 0;
#else
  memcpy(to, from, n_bytes);
  return 0;
#endif
}


ci_inline int do_copy_write(void* to, const void* from, int n_bytes)
{
#ifdef __KERNEL__
  return copy_from_user(to, from, n_bytes) != 0;
#else
  memcpy(to, from, n_bytes);
  return 0;
#endif
}


static int oo_pipe_read_wait(ci_netif* ni, struct oo_pipe* p)
{
  ci_uint64 sleep_seq;
  int rc;

  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) ) {
  closed_double_check:
    ci_mb();
    return oo_pipe_data_len(p) ? 1 : 0;
  }

  LOG_PIPE("%s: not enough data in the pipe",
           __FUNCTION__);

  if( p->aflags & (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_READER_SHIFT) ) {
    LOG_PIPE("%s: O_NONBLOCK is set so exit", __FUNCTION__);
    CI_SET_ERROR(rc, EAGAIN);
    return rc;
  }

#ifndef __KERNEL__
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_PIPE_RECV) ) {
    ci_uint64 now_frc, start_frc;
    ci_uint64 schedule_frc;
    citp_signal_info* si = citp_signal_get_specific_inited();

    ci_frc64(&now_frc);
    start_frc = now_frc;
    schedule_frc = now_frc;
    do {
      rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                           false, NULL, si);
      if( rc < 0 ) {
        CI_SET_ERROR(rc, -rc);
        return rc;
      }
      if( oo_pipe_data_len(p) )
        return 1;
      if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
        goto closed_double_check;
      ci_frc64(&now_frc);
    } while( now_frc - start_frc < ni->state->spin_cycles );
  }
#endif

  while( 1 ) {
    sleep_seq = p->b.sleep_seq.all;
    ci_rmb();
    if( oo_pipe_data_len(p) )
      return 1;
    if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
      goto closed_double_check;

    LOG_PIPE("%s [%u]: going to sleep seq=(%u, %u) data_len=%d aflags=%x",
             __FUNCTION__, p->b.bufid,
             ((ci_sleep_seq_t *)(&sleep_seq))->rw.rx,
             ((ci_sleep_seq_t *)(&sleep_seq))->rw.tx,
             oo_pipe_data_len(p), p->aflags);
    rc = ci_sock_sleep(ni, &p->b, CI_SB_FLAG_WAKE_RX, 0, sleep_seq, 0);
    LOG_PIPE("%s[%u]: woke up: rc=%d data_len=%d aflags=%x", __FUNCTION__,
             p->b.bufid, rc, (int)oo_pipe_data_len(p), p->aflags);
    if( rc < 0 ) {
      LOG_PIPE("%s: sleep rc = %d", __FUNCTION__, rc);
      CI_SET_ERROR(rc, -rc);
      return rc;
    }
    if( oo_pipe_data_len(p) )
      return 1;
  }
}


int ci_pipe_read(ci_netif* ni, struct oo_pipe* p,
                 const struct iovec *iov, size_t iovlen)
{
  int bytes_available;
  int rc;
  int i;

  ci_assert(p);
  ci_assert(ni);
  ci_assert(iov);
  ci_assert_gt(iovlen, 0);

  LOG_PIPE("%s[%u]: ENTER data_len=%d aflags=%x",
           __FUNCTION__, p->b.bufid, oo_pipe_data_len(p), p->aflags);
  pipe_dump(p);

  bytes_available = oo_pipe_data_len(p);
  if( bytes_available == 0 ) {
    if( (rc = oo_pipe_read_wait(ni, p)) != 1 )
      goto out;
    bytes_available = oo_pipe_data_len(p);
  }

  rc = ci_sock_lock(ni, &p->b);
#ifdef __KERNEL__
  if( rc < 0 )
    return -ERESTARTSYS;
#endif

  rc = 0;
  for( i = 0; i < iovlen; i++ ) {
    char* start = iov[i].iov_base;
    char* end = start + iov[i].iov_len;
    while ( end - start ) {
      char* read_point = pipe_get_point(p, ni, p->read_ptr.bufid,
                                        p->read_ptr.offset);
      int burst = CI_MIN(OO_PIPE_BUF_SIZE - p->read_ptr.offset,
                         end - start);
      burst = CI_MIN(burst, bytes_available - rc);
      if(CI_UNLIKELY( do_copy_read(start, read_point, burst) != 0 )) {
        rc = -EFAULT;
        goto wake_and_unlock_out;
      }

      rc += burst;
      start += burst;
      pipe_buf_next(ni, p, read, burst);

      if( bytes_available == rc )
        goto read;
    }
  }

read:
  ci_wmb();
  p->bytes_removed += rc;
wake_and_unlock_out:
  __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_TX);
  ci_sock_unlock(ni, &p->b);
out:
  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;
}


ci_inline void oo_pipe_signal(ci_netif* ni)
{
#ifndef __KERNEL__
  (void)ci_sys_ioctl(ci_netif_get_driver_handle(ni),
                     OO_IOC_KILL_SELF_SIGPIPE,
                     NULL);
#else
  (void)send_sig(SIGPIPE, current, 0);
#endif
}


static int oo_pipe_wait_write(ci_netif* ni, struct oo_pipe* p)
{
  ci_uint64 sleep_seq;
  int rc = 0;

#ifndef __KERNEL__
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_PIPE_SEND) ) {
    ci_uint64 now_frc, start_frc;
    ci_uint64 schedule_frc;
    citp_signal_info* si = citp_signal_get_specific_inited();

    ci_frc64(&now_frc);
    start_frc = now_frc;
    schedule_frc = now_frc;

    do {
      rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                           false, NULL, si);
      if( rc < 0 ) {
        CI_SET_ERROR(rc, -rc);
        return rc;
      }

      if ( oo_pipe_is_writable(p) )
        return 0;

      if ( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) ) {
        CI_SET_ERROR(rc, EPIPE);
        oo_pipe_signal(ni);
        return rc;
      }

      ci_frc64(&now_frc);

    } while( now_frc - start_frc < ni->state->spin_cycles );
  }
#endif /* spin code end */

  do {
    sleep_seq = p->b.sleep_seq.all;
    ci_rmb();

    /* if we have enough space at this moment - just exit */
    if( oo_pipe_is_writable(p) )
      break;

    /* we should sleep here */
    LOG_PIPE("%s: going to sleep", __FUNCTION__);
    rc = ci_sock_sleep(ni, &p->b, CI_SB_FLAG_WAKE_TX, 0, sleep_seq, 0);
    if ( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) ) {
      CI_SET_ERROR(rc, EPIPE);
      oo_pipe_signal(ni);
      return rc;
    }

    LOG_PIPE("%s[%u]: woke up - %d %d", __FUNCTION__,
             p->b.bufid, rc, (int)oo_pipe_space(p));

    if( rc < 0 ) {
      LOG_PIPE("%s: sleep rc = %d", __FUNCTION__, rc);
      CI_SET_ERROR(rc, -rc);
      return rc;
    }
  } while( ! oo_pipe_is_writable(p) );

  /* we have some space! */
  return 0;
}


/* Called when we want more space to write data into.  Returns >0 if more
 * space was allocated, 0 if we've already got the max and -ENOMEM if we
 * can't get more memory.
 *
 * When called in kernel may return -EINTR or -ERESTARTSYS if interrupted
 * while waiting for a lock.
 *
 * Warning!  Grabs the stack lock and possibly socket lock).
 */
static int oo_pipe_maybe_claim_buffers(ci_netif* ni, struct oo_pipe* p,
                                       int pipe_lock_required)
{
  int rc;

  LOG_PIPE("%s: called for ni=%d p=%d lock_req=%d wr=%d rd=%d",
           __FUNCTION__, ni->state->stack_id, p->b.bufid,
           pipe_lock_required, p->write_ptr.bufid, p->read_ptr.bufid);

  if( p->bufs_num >= OO_PIPE_MAX_BUFS )
    return 0;
  if( pipe_lock_required && (rc = ci_sock_lock(ni, &p->b)) < 0 )
    return rc;
  rc = 0;
  if( p->bufs_num < OO_PIPE_MAX_BUFS ) {
    if( (rc = ci_netif_lock(ni)) == 0 ) {
      rc = oo_pipe_alloc_bufs(ni, p, CI_MIN(OO_PIPE_BURST_BUFS,
                                            OO_PIPE_MAX_BUFS - p->bufs_num));
      rc = (rc < 0) ? -ENOMEM : 1;
      ci_netif_unlock(ni);
    }
  }
  if( pipe_lock_required )
    ci_sock_unlock(ni, &p->b);
  return rc;
}


int ci_pipe_write(ci_netif* ni, struct oo_pipe* p,
                  const struct iovec *iov,
                  size_t iovlen)
{
  int total_bytes = 0, rc;
  int i;
  int add = 0;

  ci_assert(p);
  ci_assert(ni);
  ci_assert(iov);
  ci_assert_gt(iovlen, 0);

  LOG_PIPE("%s[%u]: ENTER space=%d nonblock=%s bufs=%d wr=%d rd=%d",
           __FUNCTION__,
           p->b.bufid,
           (int)oo_pipe_space(p),
           (p->aflags &
            (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT)) ?
           "true" : "false",
           p->bufs_num,
           p->write_ptr.bufid, p->read_ptr.bufid);

  pipe_dump(p);

rewrite:
  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT)) {
    /* send sigpipe: not sure if anything can be done
     * in case of failure*/
    CI_SET_ERROR(rc, EPIPE);
    oo_pipe_signal(ni);
    goto out;
  }

  /* fast exit in case of problems */
  if( ! oo_pipe_is_writable(p) ) {
    if( total_bytes )
      __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);

    rc = oo_pipe_maybe_claim_buffers(ni, p, 1);
    if( rc > 0 )
      goto rewrite;
#ifdef __KERNEL__
    else if( rc == -ERESTARTSYS || rc == -EINTR )
      return -ERESTARTSYS;
#endif
    /* We didn't allocate more buffer space. */
    if( p->aflags & (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT)) {
      LOG_PIPE("%s: O_NONBLOCK is set so exit", __FUNCTION__);
      CI_SET_ERROR(rc, EAGAIN);
      goto out;
    }
    else {
      rc = oo_pipe_wait_write(ni, p);
      if (rc != 0)
        goto out;
    }
  }

  rc = ci_sock_lock(ni, &p->b);
#ifdef __KERNEL__
  if( rc < 0 )
    return -ERESTARTSYS;
#endif

  for( i = 0; i < iovlen; i++ ) {
    char* start = iov[i].iov_base;
    char* end = start + iov[i].iov_len;

    for (;;) {
      char* write_point = pipe_get_point(p, ni, p->write_ptr.bufid,
                                         p->write_ptr.offset);
      /* don't write more than left from the buffer */
      int burst = CI_MIN(OO_PIPE_BUF_SIZE - p->write_ptr.offset,
                         end - start);

      /* as we don't update bytes_added and bytes_removed
       * every time we need to check burst agains the actual
       * amount of space in the pipe
       */
      burst = CI_MIN(burst, oo_pipe_space(p) - add - OO_PIPE_BUF_SIZE);
      LOG_PIPE("%s: ->%d+%d %d %d %d",
               __FUNCTION__, p->write_ptr.bufid, p->write_ptr.offset,
               (int)(OO_PIPE_BUF_SIZE - p->write_ptr.offset),
               (int)(end - start),
               (int)(oo_pipe_space(p) - add) - OO_PIPE_BUF_SIZE);
      if( burst ) {
        if(CI_UNLIKELY( do_copy_write(write_point, start, burst) != 0 )) {
          rc = -EFAULT;
          goto wake_and_unlock_out;
        }

        /* local move */
        add += burst;
        start += burst;
        pipe_buf_next(ni, p, write, burst);

        LOG_PIPE("%s: end-start=%d burst=%d add=%d space=%d",
                 __FUNCTION__, (int)(end - start),
               burst, add, oo_pipe_space(p));
      }

      if( ! ( end - start ) ) {
        /* written all of this segment */
        break;
      }
      else if( burst && oo_pipe_is_writable(p) ) {
        /* still more space available */
        continue;
      }
      else if( (rc = oo_pipe_maybe_claim_buffers(ni, p, 0)) > 0 ) {
        /* allocated more space -- keep trying */
        continue;
      }
#ifdef __KERNEL__
      else if( rc == -ERESTARTSYS || rc == -EINTR ) {
        /* interrupted while waiting for lock */
        if( total_bytes + add )
          goto sent_locked;
        ci_sock_unlock(ni, &p->b);
        rc = -ERESTARTSYS;
        goto out;
      }
#endif
      else if( p->aflags &
               (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT) ) {
        goto sent_locked;
      }

      /* loosers! no space and have plenty of data to write! */
      total_bytes += add;
      ci_wmb();
      p->bytes_added += add;
      add = 0;

      if( total_bytes )
        __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
      ci_sock_unlock(ni, &p->b);
      rc = oo_pipe_wait_write(ni, p);
      if (rc != 0) {
        if( total_bytes ) {
          goto sent_not_locked;
        }
        goto out;
      }
      rc = ci_sock_lock(ni, &p->b);
#ifdef __KERNEL__
      if( rc < 0 ) {
        if( total_bytes )
          goto sent_not_locked;
        else
          return -ERESTARTSYS;
      }
#endif
    }
  }

 sent_locked:
  total_bytes += add;
  ci_wmb();
  p->bytes_added += add;
  rc = total_bytes;
 wake_and_unlock_out:
  __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
  ci_sock_unlock(ni, &p->b);

out:
  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;

 sent_not_locked:
  __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
  rc = total_bytes;
  goto out;
}


/* add 'number' of buffers to the pipe buffers list
 * and update corresponding counters. bufs_start - starting id
 * index of the assigned buffers (it's assumed that they are
 * allocated as a continous chunk
 */
static void oo_pipe_assign_buffers(struct oo_pipe* p,
                                   int num, ci_uint32 bufs_start)
{
  int i;
  ci_uint32 insert_bufid;

  ci_assert(p->bufs_num + num <= OO_PIPE_MAX_BUFS);

  pipe_dump(p);

  /* A bit of black magic: write_ptr.bufid == read_ptr.bufid iff we are
   * creating this pipe; later, we always keep read and write pointers
   * different. */
  if( p->write_ptr.bufid == 0 && p->read_ptr.bufid == 0 ) {
    insert_bufid = p->bufs_num;
  }
  else {
    ci_assert_nequal(p->write_ptr.bufid, p->read_ptr.bufid);
    insert_bufid = p->write_ptr.bufid + 1;
  }


  LOG_PIPE("%s: %d: bufs_num=%d write_ptr.bufid=%d insert_bufid=%d "
           "add %d bufs", __FUNCTION__, W_ID(&p->b),
           p->bufs_num, p->write_ptr.bufid, insert_bufid, num);

  if( insert_bufid != p->bufs_num ) {
    /* insert_bufid has some content to be preserved.
     * we should move all buffers [insert_bufid..bufs_num[
     * to the end of the buffer list */
    LOG_PIPE("%s: %d: reassign [%d..%d[ -> [%d..%d[",
             __FUNCTION__, W_ID(&p->b), insert_bufid, p->bufs_num,
             insert_bufid + num, p->bufs_num + num);
    for( i = p->bufs_num - 1; i >= insert_bufid; i-- )
      p->buffer_idxs[i + num] =  p->buffer_idxs[i];
    if( p->read_ptr.bufid >= insert_bufid )
      p->read_ptr.bufid += num;
  }

  LOG_PIPE("%s: %d: %d + [0..%d[ -> %d + i", __FUNCTION__, W_ID(&p->b),
           insert_bufid, num, bufs_start);
  for( i = 0; i < num; i++ )
    p->buffer_idxs[insert_bufid + i] = bufs_start + i;
  ci_wmb();
  p->bufs_num += num;

  pipe_dump(p);
}


ci_inline void oo_pipe_free_buffers(ci_netif* ni, struct oo_pipe* p,
                                    oo_sp buf_id, ci_uint32 len)
{
  struct oo_pipe_buf* pbuf;

  ci_assert(ni);
  ci_assert(p);
  ci_assert(len > 0);

  LOG_PIPE("%s: %d: adding chunk (id=%d, len=%d) next=%d",
           __FUNCTION__, W_ID(&p->b), OO_SP_TO_INT(buf_id),
           len,
           OO_SP_IS_NULL(ni->state->free_pipe_bufs) ?
           -1 : (SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs))->id);

  if( OO_SP_NOT_NULL(ni->state->free_pipe_bufs) )
    ci_assert_nequal(SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs)->id,
                     OO_SP_TO_INT(buf_id));

  pbuf = SP_TO_PIPE_BUF(ni, buf_id);
  pbuf->id = buf_id;
  pbuf->next = ni->state->free_pipe_bufs;
  pbuf->length = len;
  ci_wmb();
  ni->state->free_pipe_bufs = PIPE_BUF_SP(pbuf);
}


int oo_pipe_alloc_bufs(ci_netif* ni, struct oo_pipe* p, ci_uint32 num)
{
  int len;
  ci_uint32 bufs_start;

  /* check that we don't exceed the maximum number of buffers */
  ci_assert_le(num + p->bufs_num, OO_PIPE_MAX_BUFS);
  ci_assert(ci_netif_is_locked(ni));

  pipe_dump(p);

  LOG_PIPE("%s: ni=%d p=%d trying to alloc %d buffers (current amount %d)",
           __FUNCTION__, ni->state->stack_id, p->b.bufid, num, p->bufs_num);

  while ( ! OO_SP_IS_NULL(ni->state->free_pipe_bufs) &&
          num > 0) {
    struct oo_pipe_buf* pbuf;

    pbuf = SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs);
    /* remove buffer from the list */
    ni->state->free_pipe_bufs = pbuf->next;
    bufs_start = OO_SP_TO_INT(pbuf->id);
    len = pbuf->length;

    ci_assert(len > 0);

    LOG_PIPE("%s: got %d buffers from free_pipe_bufs list, start=%d len=%d, "
             "left:(id=%d,len=%d)",
             __FUNCTION__, len, bufs_start, len,
             OO_SP_IS_NULL(ni->state->free_pipe_bufs) ?
             -1 : (SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs))->id,
             OO_SP_IS_NULL(ni->state->free_pipe_bufs) ?
             -1 :(SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs))->length);

    if (len > num)
    {
      unsigned buf_num = bufs_start + num;
      oo_sp buf_id = OO_SP_FROM_INT(ni, buf_num);

      LOG_PIPE("%s: big chunk (%u>%u), truncate it", __FUNCTION__,
               len, num);
      /* we should take what we need and don't touch the rest */

      oo_pipe_free_buffers(ni, p, buf_id, len - num);
      len = num;
    }

    oo_pipe_assign_buffers(p, len, bufs_start);
    num -= len;
  }
  if ( num != 0 ) {
    LOG_PIPE("%s: need to allocate some more (%d) from the kernel",
             __FUNCTION__, num);
    /* we did not have enough  */
#ifndef __KERNEL__
    if( ci_tcp_helper_more_pipe_bufs(ni, num, &bufs_start) ) {
      LOG_E (ci_log ("Failed to alloc pipe data buffers") );
      return -1;
    }
#else
    if( efab_tcp_helper_more_pipe_bufs(ni, num, &bufs_start) ) {
      LOG_E (ci_log ("Failed to alloc pipe data buffers") );
      return -1;
    }
#endif
    LOG_PIPE("%s: buffers allocated, buffer start = %d",
             __FUNCTION__, bufs_start);

    oo_pipe_assign_buffers(p, num, bufs_start);
  }

  return 0;
}


#ifdef __ci_driver__

/* Current implementation assumes that we free a sequence of
 * buffers (OO_PIPE_BUFS number of them). */
static void oo_pipe_free_bufs(ci_netif* ni, struct oo_pipe* p)
{
  ci_uint32 id = p->buffer_idxs[0];
  int length = 1;
  int i;

  for( i = 1; i < p->bufs_num; i++ ) {
    if( p->buffer_idxs[i] == id + length )
      /* continue building the region */
      length++;

    if( p->buffer_idxs[i] != id + length - 1 ||
        i == p->bufs_num - 1) {
      oo_sp buf_id = OO_SP_FROM_INT(ni, id);
      /* region is finished - has lenght 'length' and
       * starts with buffer id 'id' */
      oo_pipe_free_buffers(ni, p, buf_id, length);

      /* start building new sequence */
      id = p->buffer_idxs[i];
      length = 1;
    }
  }
}


static void oo_pipe_free(ci_netif* ni, struct oo_pipe* p)
{
  ci_assert(ci_netif_is_locked(ni));

  LOG_PIPE("%s: free pipe waitable id=%d", __FUNCTION__,
           p->b.bufid);
  /* fixme kostik: no async ops */

  citp_waitable_obj_free(ni, &p->b);
}


void ci_pipe_all_fds_gone(ci_netif* ni, struct oo_pipe* p)
{
  ci_assert(p);
  ci_assert(ni);
  ci_assert(ci_netif_is_locked(ni));

  pipe_dump(p);

  oo_pipe_free_bufs(ni, p);
  oo_pipe_free(ni, p);

  LOG_PIPE("%s: done", __FUNCTION__);
}


#endif /* __ci_driver__ */


void oo_pipe_dump(ci_netif* ni, struct oo_pipe* p, const char* pf)
{
  log("%s  read_p=%u:%u bytes=%u flags=%x", pf,
      p->read_ptr.bufid, p->read_ptr.offset, p->bytes_removed,
      (p->aflags & CI_PFD_AFLAG_READER_MASK ) >> CI_PFD_AFLAG_READER_SHIFT);
  log("%s  writ_p=%u:%u bytes=%u flags=%x", pf,
      p->write_ptr.bufid, p->write_ptr.offset, p->bytes_added,
      (p->aflags & CI_PFD_AFLAG_WRITER_MASK ) >> CI_PFD_AFLAG_WRITER_SHIFT);
  log("%s  num_bufs=%d", pf, p->bufs_num);
}

#endif /* CI_CFG_USERSPACE_PIPE */
