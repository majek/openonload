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
*//*! \file epoll_fd_b.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  epoll implementation - first approach
**   \date  2010/03/04
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <ci/internal/transport_config_opt.h>


#define LPF      "citp_epoll:"

#if CI_CFG_USERSPACE_EPOLL

#include <ci/internal/transport_common.h>
#include <onload/ul/tcp_helper.h>
#include "ul_epoll.h"


/***************************************************************
                       Epoll implementation details
                       ----------------------------

There is no /dev/onload fd associated with epoll fd.  All the
implementation is userspace-only.  After exec(), user receives just
normal kernel epoll fd, loosing all userspace acceleration.

Known problems:

Edge-triggering & EPOLLONESHOT
==============================
With EPOLLET, every event is reported no more than twice.
For OO socket, it is polled via oo_sockets list and via the main epfd.
For kernel fd, it is polled via epfd_os and via the main epfd.
Each of them reports each event only once, so it is possible that
the entire epoll_wait() call reports the same event twice regardless
on EPOLLET.
Similar problem exists with EPOLLONESHOT

2 types of fds
==============
We have 3 types of fds: kernel and onload.

fork()+exec() bug in epoll
==========================
User has onload epfd in app1.  Using fork+exec, he gets the same epfd in
non-accelerated app2 (even if app2 is really accelerated, epfd is
non-accelerated).  From proc2, user calls epoll_ctl().  As proc1 knows
nothing about it, oo_sockets list and epfd_os are not changed.  Now, app2
receives incorrect results for epoll_wait().
- If app2 have added new fd to the polling set, app1 will receive these
events only when it blocks.  Not so bad.
- If app2 have modified fd parameters (events or data), app1 will receive
incorrect events.
- If app2 have removed fd from the polling set, app1 will receive events
for this fd even after removal.
I do not think the scenarios above can really happen with any real-world
applications, so I'm not going to fix it.  See also some discussions about
epoll+exec() in LKML: http://www.mail-archive.com/search?q=epoll (exec OR
shared)&l=linux-kernel@vger.kernel.org



Missing features:

exec()
======
Restore onload epoll fd after exec.  Currently, we get kernel epoll fd
in the exec'ed app.

epoll_pwait()
=============
epoll_pwait(), ppoll() and pselect() are not accelerated.

multi-level poll
================
If an application uses poll/epoll/select on onload epoll fd, we can
accelerate it.  Currently, onload epoll fd will be used as kernel fd.

Unification of poll/epoll/select code
=====================================
We have 3 copy of more-or-less the same code.  May be, it is good, as
the code is not identical.

Lazy update of the main epoll fd
================================
Waiting on the main epoll fd is rare thing, especially with EF_POLL_SPIN.
We can avoid calling epoll_ctl(main fd, ...) as long as it is not really
necessary.  It is not clear if such approach makes things faster.


 ***************************************************************/


#define EITEM_FROM_DLLINK(lnk)                          \
  CI_CONTAINER(struct citp_epoll_member, dllink, (lnk))


#define EP_NOT_REGISTERED  ((unsigned) -1)


/* In the same namespace as EPOLLIN etc.  Assumed not to collide with any
 * useful events!
 */
#define OO_EPOLL_FORCE_SYNC  (1 << 27)


#define EPOLL_CTL_FMT  "%d, %s, %d, %x, %llx"
#define EPOLL_CTL_ARGS(epoll_fd, op, fd, event)                 \
  (epoll_fd), citp_epoll_op_str(op), (fd),                      \
  (event) ? (event)->events : -1,                               \
    (unsigned long long) ((event) ? (event)->data.u64 : 0llu)


#define CITP_EPOLL_EP_LOCK(ep)                  \
  do {                                          \
    if( (ep)->not_mt_safe )                     \
      oo_wqlock_lock(&(ep)->lock);              \
  } while( 0 )

#define CITP_EPOLL_EP_UNLOCK(ep, fdt_locked)                    \
  do {                                                          \
    if( (ep)->not_mt_safe )                                     \
      oo_wqlock_unlock(&(ep)->lock, citp_epoll_unlock_cb,       \
                       (void*)(uintptr_t) (fdt_locked));        \
  } while( 0 )


#ifndef NDEBUG
static const char* citp_epoll_op_str(int op)
{
  switch( op ) {
  case EPOLL_CTL_ADD:  return "ADD";
  case EPOLL_CTL_MOD:  return "MOD";
  case EPOLL_CTL_DEL:  return "DEL";
  default:             return "BAD_OP";
  }
}
#endif


static void citp_epoll_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);

  if (!oo_atomic_dec_and_test(&ep->refcount))
    return;

  CITP_FDTABLE_LOCK();
  ci_tcp_helper_close_no_trampoline(ep->shared->epfd);
  __citp_fdtable_reserve(ep->shared->epfd, 0);
  munmap(ep->shared, sizeof(*ep->shared));

  ci_tcp_helper_close_no_trampoline(ep->epfd_os);
  __citp_fdtable_reserve(ep->epfd_os, 0);
  CITP_FDTABLE_UNLOCK();

  CI_FREE_OBJ(ep);
}
static int citp_epoll_close(citp_fdinfo *fdi, int may_cache)
{
  return 0;
}

static citp_fdinfo* citp_epoll_dup(citp_fdinfo* orig_fdi)
{
  citp_fdinfo    *fdi;
  citp_epoll_fdi *epi;
  struct citp_epoll_fd* ep = fdi_to_epoll(orig_fdi);

  epi = CI_ALLOC_OBJ(citp_epoll_fdi);
  if (!epi)
    return NULL;

  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_epoll_protocol_impl);
  epi->epoll = ep;
  oo_atomic_inc(&ep->refcount);
  return fdi;
}

static int citp_epoll_ioctl(citp_fdinfo *fdi, int cmd, void *arg)
{
  return ci_sys_ioctl(fdi->fd, cmd, arg);
}


citp_protocol_impl citp_epoll_protocol_impl = {
  .type     = CITP_EPOLL_FD,
  .ops      = {
    /* Important members -- users will realy call it. */
    .dup         = citp_epoll_dup,
    .dtor        = citp_epoll_dtor,
    .close       = citp_epoll_close,
    .fcntl       = citp_epoll_fcntl,
    /* Poll/select for epollfd is done via kernel. */
    .select      = citp_epoll_select,
    .poll        = citp_epoll_poll,

    /* "Invalid" members; normal user should not call it and should not
     * expect good behaviour */
    .socket      = citp_closedfd_socket,
    .bind        = citp_epoll_bind,
    .listen      = citp_epoll_listen,
    .accept      = citp_epoll_accept,
    .connect     = citp_epoll_connect,
    .shutdown    = citp_epoll_shutdown,
    .getsockname = citp_epoll_getsockname,
    .getpeername = citp_epoll_getpeername,
    .getsockopt  = citp_epoll_getsockopt,
    .setsockopt  = citp_epoll_setsockopt,
    .recv        = citp_epoll_recv,
#if CI_CFG_RECVMMSG
    .recvmmsg    = citp_nosock_recvmmsg,
#endif
    .send        = citp_epoll_send,
#if CI_CFG_SENDMMSG
    .sendmmsg    = citp_nosock_sendmmsg,
#endif
    .ioctl       = citp_epoll_ioctl,
    .zc_send     = citp_epoll_zc_send,
    .zc_recv     = citp_epoll_zc_recv,
    .zc_recv_filter = citp_epoll_zc_recv_filter,
    .recvmsg_kernel = citp_epoll_recvmsg_kernel,
  }
};


int citp_epoll_create(int size, int flags)
{
  citp_fdinfo    *fdi;
  citp_epoll_fdi *epi;
  struct citp_epoll_fd* ep;
  int            fd;

  if( (epi = CI_ALLOC_OBJ(citp_epoll_fdi)) == NULL )
    goto fail0;
  if( (ep = CI_ALLOC_OBJ(struct citp_epoll_fd)) == NULL )
    goto fail1;
  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_epoll_protocol_impl);

  /* Create the epoll fd. */
  CITP_FDTABLE_LOCK();
  if( (fd = ci_sys_epoll_create_compat(size, flags, 0)) < 0 )
    goto fail2;
  citp_fdtable_new_fd_set(fd, fdip_busy, TRUE);

  /* Init epfd_os */
#ifdef O_CLOEXEC
  ep->epfd_os = ci_sys_open(OO_EPOLL_DEV, O_RDWR | O_CLOEXEC);
#else
  ep->epfd_os = ci_sys_open(OO_EPOLL_DEV, O_RDWR);
  if( ep->epfd_os >= 0 )
    ci_sys_fcntl(ep->epfd_os, F_SETFD, FD_CLOEXEC);
#endif
  if( ep->epfd_os < 0 ) {
    Log_E(ci_log("%s: ERROR: failed to open(%s) errno=%d",
                 __FUNCTION__, OO_EPOLL_DEV, errno));
    goto fail3;
  }
  __citp_fdtable_reserve(ep->epfd_os, 1);
  ep->shared = mmap(NULL, sizeof(*ep->shared), PROT_READ, MAP_SHARED,
                     ep->epfd_os, 0);
  if( ep->shared == MAP_FAILED ) {
    Log_E(ci_log("%s: ERROR: failed to mmap shared segment errno=%d",
                 __FUNCTION__, errno));
    goto fail4;
  }
  __citp_fdtable_reserve(ep->shared->epfd, 1);
  CITP_FDTABLE_UNLOCK();

  epi->epoll = ep;
  ep->size = size;
  oo_wqlock_init(&ep->lock);
  ep->not_mt_safe = ! CITP_OPTS.ul_epoll_mt_safe;
  ci_dllist_init(&ep->oo_sockets);
  ci_dllist_init(&ep->dead_sockets);
  oo_atomic_set(&ep->refcount, 1);
  ep->epfd_syncs_needed = 0;
  ep->blocking = 0;
  citp_fdtable_insert(fdi, fd, 0);
  Log_POLL(ci_log("%s: fd=%d driver_fd=%d epfd=%d", __FUNCTION__,
                  fd, ep->epfd_os, (int) ep->shared->epfd));
  return fd;

 fail4:
  __citp_fdtable_reserve(ep->epfd_os, 0);
  ci_sys_close(ep->epfd_os);
 fail3:
  ci_sys_close(fd);
  citp_fdtable_busy_clear(fd, fdip_unknown, 1);
 fail2:
  CITP_FDTABLE_UNLOCK();
  CI_FREE_OBJ(ep);
 fail1:
  CI_FREE_OBJ(epi);
 fail0:
  return -1;
}


/* Reset edge-triggering status of the eitem */
ci_inline void citp_eitem_reset_epollet(struct citp_epoll_member* eitem)
{
  if( eitem->epoll_data.events & (EPOLLET | EPOLLONESHOT) ) {
    /* Only needed for EPOLLET and harmless otherwise.
     *
     * FIXME: We should really initialise these to the underlying sleep_seq
     * minus 1.  If very unlucky the current sleep_seq could match these
     * values...
     */
    eitem->reported_sleep_seq.rw.rx = 0;
    eitem->reported_sleep_seq.rw.tx = CI_SLEEP_SEQ_NEVER;
    /* User is arming or re-arming ET or ONESHOT.  If not adding, we have
     * no idea whether these are still armed in the kernel set, so we must
     * re-sync before doing a wait.
     */
    eitem->epoll_data.events |= OO_EPOLL_FORCE_SYNC;
  }
}


ci_inline int epoll_event_eq(const struct epoll_event*__restrict__ a,
                             const struct epoll_event*__restrict__ b)
{
  return memcmp(a, b, sizeof(*a)) == 0;
}


/* Return true if kernel has up-to-date state for this eitem. */
ci_inline int citp_eitem_is_synced(const struct citp_epoll_member* eitem)
{
  return epoll_event_eq(&eitem->epoll_data, &eitem->epfd_event);
}


ci_inline struct citp_epoll_member*
citp_epoll_find(struct citp_epoll_fd* ep, const citp_fdinfo* fd_fdi)
{
  struct citp_epoll_member* eitem;
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets)
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      break;
  return eitem;
}


ci_inline struct citp_epoll_member*
citp_epoll_find_dead(struct citp_epoll_fd* ep, const citp_fdinfo* fd_fdi)
{
  struct citp_epoll_member* eitem;
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->dead_sockets)
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      break;
  return eitem;
}


static int citp_epoll_ctl_onload2(struct citp_epoll_fd* ep, int op,
                                  struct epoll_event* event,
                                  citp_fdinfo* fd_fdi, int epoll_fd,
                                  ci_uint64 epoll_fd_seq)
{
  struct citp_epoll_member* eitem;
  int sync_kernel, rc = 0;
  int sync_op = op;

  /* Should we sync this op to the kernel?
   *
   * We try defer this step when EF_EPOLL_CTL_FAST=1 because we hope to
   * avoid a sys-call, or at least delay the sys-call until we're about to
   * block.
   *
   * If a thread is blocking in epoll_wait(), then we must sync to kernel
   * now, as this op may wake the epoll_wait().
   */
  sync_kernel = ! CITP_OPTS.ul_epoll_ctl_fast || ep->blocking;

  eitem = citp_epoll_find(ep, fd_fdi);

  switch( op ) {
  case EPOLL_CTL_ADD:
    if( eitem == NULL ) {
      eitem = citp_epoll_find_dead(ep, fd_fdi);
      if( eitem == NULL ) {
        eitem = CI_ALLOC_OBJ(struct citp_epoll_member);
        eitem->epoll_data = *event;
        eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
        citp_eitem_reset_epollet(eitem);
        if( ! sync_kernel ) {
          eitem->epfd_event.events = EP_NOT_REGISTERED;
          ++ep->epfd_syncs_needed;
        }
        eitem->fd = fd_fdi->fd;
        eitem->fdi_seq = fd_fdi->seq;
      }
      else {
        /* Re-added having previously been deleted (but delete did not
         * yet make it as far as the kernel).
         */
        eitem->epoll_data = *event;
        eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
        citp_eitem_reset_epollet(eitem);
        if( sync_kernel )
          sync_op = EPOLL_CTL_MOD;
        else if( ! citp_eitem_is_synced(eitem) )
          ++ep->epfd_syncs_needed;
        ci_dllist_remove(&eitem->dllink);
      }
      ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
      /* Remember that this fd has been added to this epoll set.  This
       * is needed to handle accelerated fds being handed over to
       * kernel.
       */
      fd_fdi->epoll_fd = epoll_fd;
      fd_fdi->epoll_fd_seq = epoll_fd_seq;
    }
    else {
      errno = EEXIST;
      rc = -1;
    }
    break;
  case EPOLL_CTL_MOD:
    if(CI_LIKELY( eitem != NULL )) {
      eitem->epoll_data = *event;
      eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
      citp_eitem_reset_epollet(eitem);
      if( sync_kernel ) {
        if( eitem->epfd_event.events == EP_NOT_REGISTERED )
          sync_op = EPOLL_CTL_ADD;
      }
      else if( ! citp_eitem_is_synced(eitem) )
        ++ep->epfd_syncs_needed;
      /* Reinsert at front to exploit locality of reference if there
       * are many sockets and EPOLL_CTL_MOD is frequent.
       */
      ci_dllist_remove(&eitem->dllink);
      ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
    }
    else {
      errno = ENOENT;
      rc = -1;
    }
    break;
  case EPOLL_CTL_DEL:
    fd_fdi->epoll_fd = -1;
    if(CI_LIKELY( eitem != NULL )) {
      ci_dllist_remove(&eitem->dllink);
      if( eitem->epfd_event.events == EP_NOT_REGISTERED )
        sync_kernel = 0;
      if( sync_kernel || eitem->epfd_event.events == EP_NOT_REGISTERED ) {
        CI_FREE_OBJ(eitem);
      }
      else {
        ci_dllist_push(&ep->dead_sockets, &eitem->dllink);
        ++ep->epfd_syncs_needed;
      }
    }
    else {
      errno = ENOENT;
      rc = -1;
    }
    break;
  default:
    errno = EINVAL;
    rc = -1;
    break;
  }

  /* Apply epoll_ctl() to the kernel. */
  if( sync_kernel && rc == 0 ) {
    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): SYNC_KERNEL", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event)));
    rc = ci_sys_epoll_ctl(epoll_fd, sync_op, fd_fdi->fd, event);
    if( rc < 0 )
      Log_E(ci_log("%s("EPOLL_CTL_FMT"): ERROR: sys_epoll_ctl(%s) failed (%d)",
                   __FUNCTION__,
                   EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event),
                   citp_epoll_op_str(sync_op), errno));
    eitem->epoll_data.events &= ~OO_EPOLL_FORCE_SYNC;
    eitem->epfd_event = eitem->epoll_data;
  }
  else {
    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): rc=%d errno=%d", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event),
                    rc, errno));
  }

  return rc;
}


struct deferred_epoll_ctl {
  void* next;
  struct citp_epoll_fd* ep;
  int op;
  struct epoll_event event;
  citp_fdinfo* fd_fdi;
  int epoll_fd;
  ci_uint64 epoll_fd_seq;
};


static void citp_epoll_unlock_cb(void* cb_arg, void* work_list)
{
  struct deferred_epoll_ctl* dec_list = NULL;
  struct deferred_epoll_ctl* dec = NULL;
  int fdt_locked = (int)(uintptr_t) cb_arg;
  int rc;

  Log_POLL(ci_log("%s:", __FUNCTION__));

  /* Reverse the list. */
  do {
    dec = work_list;
    work_list = dec->next;
    dec->next = dec_list;
    dec_list = dec;
  } while( work_list != NULL );

  do {
    dec = dec_list;
    dec_list = dec_list->next;
    Log_POLL(ci_log("%s: epoll_ctl("EPOLL_CTL_FMT")", __FUNCTION__,
                    EPOLL_CTL_ARGS(dec->epoll_fd, dec->op, dec->fd_fdi->fd,
                                   &dec->event)));
    rc = citp_epoll_ctl_onload2(dec->ep, dec->op, &dec->event, dec->fd_fdi,
                                dec->epoll_fd, dec->epoll_fd_seq);
    if( rc != 0 ) {
      /* If you see this error message then the optimisation that passes an
       * epoll_ctl() call from one thread to another has hidden an error
       * return from the application.  This may or may not be a problem.
       * Set EF_EPOLL_CTL_FAST=0 to prevent this from happening.
       */
      Log_E(ci_log("%s: ERROR: epoll_ctl("EPOLL_CTL_FMT") returned (%d,%d)",
                   __FUNCTION__,
                   EPOLL_CTL_ARGS(dec->epoll_fd, dec->op, dec->fd_fdi->fd,
                                  &dec->event), rc, errno));
    }
    citp_fdinfo_release_ref(dec->fd_fdi, fdt_locked);
    free(dec);
  } while( dec_list != NULL );

  Log_POLL(ci_log("%s: done", __FUNCTION__));
}


static int
citp_epoll_ctl_try_defer_to_lock_holder(struct citp_epoll_fd* ep, int op,
                                        const struct epoll_event* event,
                                        citp_fdinfo* fd_fdi, int epoll_fd,
                                        ci_uint64 epoll_fd_seq)
{
  struct deferred_epoll_ctl* dec;

  if( (dec = malloc(sizeof(*dec))) == NULL ) {
    oo_wqlock_lock(&ep->lock);
    return 0;
  }
  dec->ep = ep;
  dec->op = op;
  if( event != NULL )  /* NB. We've already checked op... */
    dec->event = *event;
  dec->fd_fdi = fd_fdi;
  citp_fdinfo_ref(fd_fdi);
  dec->epoll_fd = epoll_fd;
  dec->epoll_fd_seq = epoll_fd_seq;
  if( oo_wqlock_lock_or_queue(&ep->lock, dec, &dec->next) ) {
    /* We got the lock after all. */
    citp_fdinfo_release_ref(fd_fdi, 0);
    free(dec);
    return 0;
  }
  else {
    return 1;
  }
}


static int citp_epoll_ctl_onload(citp_fdinfo* fdi, int op,
                                 struct epoll_event* event,
                                 citp_fdinfo* fd_fdi)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  int rc;

  if( event == NULL && (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) ) {
    errno = EFAULT;
    return -1;
  }

  if( ep->not_mt_safe ) {
    if( CITP_OPTS.ul_epoll_ctl_handoff ) {
      /* We need the lock, but epoll_wait() holds it while spinning.  We
       * don't want to do a blocking lock, as we could be held-up
       * indefinitely, and even deadlock the app.  So if the lock is held
       * we pass the epoll_ctl() op to the lock holder.
       */
      if( ! oo_wqlock_try_lock(&ep->lock) &&
          citp_epoll_ctl_try_defer_to_lock_holder(ep, op, event, fd_fdi,
                                                  fdi->fd, fdi->seq) ) {
        /* The thread holding [ep->lock] will apply this op for us.  We just
         * hope it doesn't fail!
         */
        Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): QUEUED", __FUNCTION__,
                        EPOLL_CTL_ARGS(fdi->fd, op, fd_fdi->fd, event)));
        return 0;
      }
    }
    else {
      CITP_EPOLL_EP_LOCK(ep);
    }
  }

  rc = citp_epoll_ctl_onload2(ep, op, event, fd_fdi, fdi->fd, fdi->seq);
  CITP_EPOLL_EP_UNLOCK(ep, 0);
  return rc;
}


static int citp_epoll_ctl_os(citp_fdinfo* fdi, int op, int fd,
                             struct epoll_event *event)
{
  /* Apply this epoll_ctl() to both epoll fds (the one containing
   * everything, and the one containing just non-accelerated fds).
   *
   * To avoid doing two syscalls, we do this via an internal ioctl().
   */
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct oo_epoll1_action_arg oop;
  struct oo_epoll_item ev;
  int rc;

  ev.op = op;
  ev.fd = fd;
  if( event == NULL ) {
    if(CI_UNLIKELY( op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD )) {
      errno = EFAULT;
      return -1;
    }
  }
  else {
    ev.event = *event;
  }
  CI_USER_PTR_SET(oop.epoll_ctl, &ev);
  oop.epoll_ctl_n = 1;
  oop.maxevents = 0;
  oop.epfd = fdi->fd;
  rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_ACTION, &oop);
  Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): rc=%d errno=%d op_rc=%d", __FUNCTION__,
                  EPOLL_CTL_ARGS(fdi->fd, op, fd, event), rc, errno, oop.rc));
  if( rc < 0 )
    return rc;
  if( oop.rc == 0 )
    return 0;
  ci_assert_lt(oop.rc, 0);
  errno = -oop.rc;
  return -1;
}


int citp_epoll_ctl(citp_fdinfo* fdi, int op, int fd, struct epoll_event *event)
{
  citp_fdinfo* fd_fdi;

  if( (fd_fdi = citp_fdtable_lookup(fd)) != NULL ) {
    int rc = CITP_NOT_HANDLED;
    if( citp_fdinfo_get_ops(fd_fdi)->epoll != NULL )
      rc = citp_epoll_ctl_onload(fdi, op, event, fd_fdi);
    citp_fdinfo_release_ref(fd_fdi, 0);
    if( rc != CITP_NOT_HANDLED )
      return rc;
  }

  return citp_epoll_ctl_os(fdi, op, fd, event);
}


static void citp_ul_epoll_ctl_sync_fd(int epfd,
                                      struct citp_epoll_member* eitem)
{
  int rc, op;

  if( eitem->epfd_event.events == EP_NOT_REGISTERED ) {
    if( (eitem->epfd_event.events & OO_EPOLL_ALL_EVENTS) == 0 )
      /* No events to register, so don't bother to sync for now.  (In
       * EPOLLONESHOT case this is important, else kernel could report one
       * of the always-on events).
       */
      return;
    op = EPOLL_CTL_ADD;
  }
  else {
    op = EPOLL_CTL_MOD;
  }
  Log_POLL(ci_log("%s: sys_epoll_ctl("EPOLL_CTL_FMT") old_evs=%x",
                  __FUNCTION__,
                  EPOLL_CTL_ARGS(epfd, op, eitem->fd, &eitem->epoll_data),
                  eitem->epfd_event.events));
  eitem->epoll_data.events &= ~OO_EPOLL_FORCE_SYNC;
  eitem->epfd_event = eitem->epoll_data;
  rc = ci_sys_epoll_ctl(epfd, op, eitem->fd, &eitem->epoll_data);
  if( rc < 0 )
    Log_E(ci_log("%s: ERROR: sys_epoll_ctl("EPOLL_CTL_FMT") failed (%d,%d)",
                 __FUNCTION__,
                 EPOLL_CTL_ARGS(epfd, op, eitem->fd, &eitem->epoll_data),
                 rc, errno));
}

static inline citp_fdinfo * 
citp_ul_epoll_member_to_fdi(struct citp_epoll_member* eitem)
{
  citp_fdinfo* fdi = NULL;
  do {
    citp_fdinfo_p fdip = citp_fdtable.table[eitem->fd].fdip;
    if( fdip_is_busy(fdip) ) {
      /* Wait: We cannot draw any conclusion about a busy entry.  (NB. We
       * cannot call citp_fdtable_busy_wait() because we're holding the
       * fdtable lock).
       */
      ci_spinloop_pause();
      continue;
    }
    if( !fdip_is_normal(fdip) )
      return NULL;
    fdi = fdip_to_fdi(fdip);
    if( fdi->seq != eitem->fdi_seq )
      return NULL;
    break;
  } while(1);
  return fdi;
}

static void citp_ul_epoll_ctl_sync(struct citp_epoll_fd* ep, int epfd)
{
  struct citp_epoll_member* eitem;
  int rc;

  while( ci_dllist_not_empty(&ep->dead_sockets) ) {
    eitem = EITEM_FROM_DLLINK(ci_dllist_pop(&ep->dead_sockets));

    /* Check that this fd was not replaced by another file */
    if( citp_ul_epoll_member_to_fdi(eitem) ) {
      Log_POLL(ci_log("%s(%d): DEL %d", __FUNCTION__, epfd, eitem->fd));
      rc = ci_sys_epoll_ctl(epfd, EPOLL_CTL_DEL,
                            eitem->fd, &eitem->epoll_data);
      if( rc < 0 )
        Log_E(ci_log("%s: ERROR: sys_epoll_ctl(%d, DEL, %d) failed (%d,%d)",
                     __FUNCTION__, epfd, eitem->fd, rc, errno));
    }
    CI_FREE_OBJ(eitem);
  }

  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets)
    if( ! citp_eitem_is_synced(eitem) ) {
      if( citp_ul_epoll_member_to_fdi(eitem) )
        citp_ul_epoll_ctl_sync_fd(epfd, eitem);
      else {
        ci_dllist_remove(&eitem->dllink);
        CI_FREE_OBJ(eitem);
      }
      if( --ep->epfd_syncs_needed == 0 )
        /* This early exit may help us avoid iterating over the whole list. */
        break;
    }

  /* epfd_syncs_needed can be an overestimate, because changes can cancel
   * and members can be removed.
   */
  ep->epfd_syncs_needed = 0;
}


static void citp_ul_epoll_one(struct oo_ul_epoll_state*__restrict__ eps,
                              struct citp_epoll_member*__restrict__ eitem)
{
  citp_fdinfo* fdi = NULL;

  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);

  if(CI_LIKELY( (fdi = citp_ul_epoll_member_to_fdi(eitem)) != NULL )) {
    if( (eitem->epoll_data.events & OO_EPOLL_ALL_EVENTS) != 0 )
      citp_fdinfo_get_ops(fdi)->epoll(fdi, eitem, eps);
    return;
  }

  /* [fdip] is special, or the seq check failed, so this fd has changed
   * identity.  Best we can do at userlevel is assume the file descriptor
   * was closed, and remove it from the set.
   */
  Log_POLL(ci_log("%s: auto remove fd %d from epoll set",
                  __FUNCTION__, eitem->fd));
  ci_dllist_remove(&eitem->dllink);
  CI_FREE_OBJ(eitem);
}


static void citp_epoll_poll_ul(struct oo_ul_epoll_state*__restrict__ eps)
{
  /* Poll accelerated sockets for events. */

  struct citp_epoll_member* eitem;
  ci_dllink *next, *last;

  if( ci_dllist_not_empty(&eps->ep->oo_sockets) ) {
    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    last = ci_dllist_last(&eps->ep->oo_sockets);
    next = ci_dllist_start(&eps->ep->oo_sockets);
    do {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, next);
      next = next->next;
      citp_ul_epoll_one(eps, eitem);
    } while( eps->events < eps->events_top && &eitem->dllink != last );

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  FDTABLE_ASSERT_VALID();
}


ci_inline int citp_epoll_os_fds(citp_epoll_fdi *efdi,
                                struct epoll_event* events, int maxevents)
{
  struct oo_epoll1_action_arg op;
  struct citp_epoll_fd* ep = efdi->epoll;
  int rc;

  ci_assert(__oo_per_thread_get()->sig.inside_lib);

  if( (ep->shared->flag & OO_EPOLL1_FLAG_EVENT) == 0 )
    return 0;

  Log_POLL(ci_log("%s(%d): poll os fds", __FUNCTION__, efdi->fdinfo.fd));

  op.epoll_ctl_n = 0;
  op.epfd = efdi->fdinfo.fd;
  op.maxevents = maxevents;
  CI_USER_PTR_SET(op.events, events);
  rc = ci_sys_ioctl(efdi->epoll->epfd_os, OO_EPOLL1_IOC_ACTION, &op);
  return rc < 0 ? rc : op.rc;
}


int citp_epoll_wait(citp_fdinfo* fdi, struct epoll_event*__restrict__ events,
                    int maxevents, int timeout, const sigset_t *sigmask,
                    citp_lib_context_t *lib_context)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct oo_ul_epoll_state eps;
  ci_uint64 poll_start_frc;
  int rc = 0, rc_os;
#if CI_LIBC_HAS_epoll_pwait
  sigset_t sigsaved;
  int pwait_was_spinning = 0;
#endif

  Log_POLL(ci_log("%s(%d, max_ev=%d, timeout=%d) ul=%d dead=%d syncs=%d",
                  __FUNCTION__, fdi->fd, maxevents, timeout,
                  ! ci_dllist_is_empty(&ep->oo_sockets),
                  ! ci_dllist_is_empty(&ep->dead_sockets),
                  ep->epfd_syncs_needed));

  CITP_EPOLL_EP_LOCK(ep);

  if( (ci_dllist_is_empty(&ep->oo_sockets) && !ep->epfd_syncs_needed) ||
      maxevents <= 0 || timeout < -1 || events == NULL ) {
    /* No accelerated fds or invalid parameters). */
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    citp_exit_lib(lib_context, FALSE);
    if( timeout )
      ep->blocking = 1;
    Log_POLL(ci_log("%s(%d, ..): passthrough", __FUNCTION__, fdi->fd));
#if CI_LIBC_HAS_epoll_pwait
    if( sigmask != NULL )
      rc = ci_sys_epoll_pwait(fdi->fd, events, maxevents, timeout, sigmask);
    else
#endif
      rc = ci_sys_epoll_wait(fdi->fd, events, maxevents, timeout);
    ep->blocking = 0;
    return rc;
  }

  /* Set up epoll state */
  ci_frc64(&poll_start_frc);
  eps.this_poll_frc = poll_start_frc;
  eps.ep = ep;
  eps.events = events;
  eps.events_top = events + maxevents;
  eps.has_epollet = 0;
  /* NB. We do need to call oo_per_thread_get() here (despite having
   * [lib_context] in scope) to ensure [spinstate] is initialised.
   */
  eps.ul_epoll_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_EPOLL_WAIT);

 poll_again:
  citp_epoll_poll_ul(&eps);

  if( eps.events != events ) {
    /* We have userlevel sockets ready.  So just need to do a non-blocking
     * poll of kernel sockets (at most) and we're done.
     */
    rc = eps.events - events;
    ci_assert_le(rc, maxevents);
    rc_os = 0;
    if(CI_UNLIKELY( ep->shared->flag & OO_EPOLL1_FLAG_EVENT )) {
      if(CI_LIKELY( rc < maxevents )) {
        rc_os = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi),
                                  events + rc, maxevents - rc);
        if( rc_os > 0 )
          rc += rc_os;
      }
    }
    Log_POLL(ci_log("%s(%d): return %d ul + %d kernel",
                    __FUNCTION__, fdi->fd, rc, rc_os));
    goto unlock_release_exit_ret;
  }
  /* eps.n == 0 */

  if( timeout == 0 ) {
    Log_POLL(ci_log("%s: No UL evs && timeout=0, poll OS fds", __FUNCTION__));
    rc = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi), events, maxevents);
    goto unlock_release_exit_ret;
  }

  /* Blocking.  Shall we spin? */
  if( KEEP_POLLING(eps.ul_epoll_spin, eps.this_poll_frc, poll_start_frc) ) {
#if CI_LIBC_HAS_epoll_pwait
    if( !pwait_was_spinning && sigmask != NULL) {
      if( ep->avoid_spin_once ) {
        eps.ul_epoll_spin = 0;
        ep->avoid_spin_once = 0;
        goto passthrough;
      }
      citp_exit_lib(lib_context, CI_FALSE);
      rc = citp_ul_pwait_spin_pre(lib_context, sigmask, &sigsaved);
      if( rc != 0 ) {
        CITP_EPOLL_EP_UNLOCK(ep, 0);
        citp_exit_lib(lib_context, CI_FALSE);
        return rc;
      }
      pwait_was_spinning = 1;
    }
#endif

    /* We need to keep an eye on the kernel fds when polling.  We
     * don't need to citp_exit_lib() here because we're not blocking.
     */
    rc = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi), events, maxevents);
    if( rc ) {
      Log_POLL(ci_log("%s(%d): %d kernel events", __FUNCTION__, fdi->fd, rc));
      goto unlock_release_exit_ret;
    }

    /* See if another thread has queued any epoll_ctl requests. */
    oo_wqlock_try_drain_work(&ep->lock, citp_epoll_unlock_cb,
                             (void*)(uintptr_t) 0);

    /* Timeout while spinning? */
    if( timeout > 0 && (eps.this_poll_frc - poll_start_frc >=
                        (ci_uint64) timeout * ci_cpu_khz) ) {
      Log_POLL(ci_log("%s(%d): timeout during spin", __FUNCTION__, fdi->fd));
      rc = 0;
      timeout = 0;
      goto unlock_release_exit_ret;
    }

    if(CI_UNLIKELY( lib_context->thread->sig.run_pending )) {
      errno = EINTR;
      rc = -1;
      goto unlock_release_exit_ret;
    }

    goto poll_again;
  } /* endif ul_epoll_spin spinning*/

  /* Re-calculate timeout.  We should do it if we were spinning a lot. */
  if( eps.ul_epoll_spin && timeout > 0 ) {
    timeout -= (eps.this_poll_frc - poll_start_frc) / ci_cpu_khz;
    timeout = CI_MAX(timeout, 0);
    Log_POLL(ci_log("%s: blocking timeout reduced to %d",
                    __FUNCTION__, timeout));
  }

#if CI_LIBC_HAS_epoll_pwait
 passthrough:
#endif
  /* Synchronise state to kernel (if necessary) and block. */
  if( ep->epfd_syncs_needed )
    citp_ul_epoll_ctl_sync(ep, fdi->fd);
 unlock_release_exit_ret:
  CITP_EPOLL_EP_UNLOCK(ep, 0);
  Log_POLL(ci_log("%s(%d): to kernel", __FUNCTION__, fdi->fd));


#if CI_LIBC_HAS_epoll_pwait
  if( pwait_was_spinning) {
    /* Fixme:
     * if we've got both signal and event, we can't return both to user.
     * As signal will be processed anyway (in exit_lib), we MUST
     * tell the user about it with -1(EINTR).  User will get events with
     * the next epoll_pwait call.
     *
     * The problem is, if some events are with EPOLLET or EPOLLONESHOT,
     * they are lost.  Ideally, we should un-mark them as "reported" in our
     * internal oo_sockets list.
     *
     * Workaround is to disable spinning for one next epoll_pwait call,
     * because we report EPOLLET events twice in such a way.
     */
    citp_ul_pwait_spin_done(lib_context, &sigsaved, &rc);
    if( rc < 0 ) {
      if( eps.has_epollet )
        ep->avoid_spin_once = 1;
      return rc;
    }
  }
  else
#endif
    citp_exit_lib(lib_context, FALSE);

  if( rc == 0 && (timeout != 0
#if CI_LIBC_HAS_epoll_pwait
                  || sigmask != NULL
#endif
                  ) ) {
    if( timeout != 0 )
      ep->blocking = 1;
#if CI_LIBC_HAS_epoll_pwait
    if( sigmask != NULL )
      rc = ci_sys_epoll_pwait(fdi->fd, events, maxevents, timeout, sigmask);
    else
#endif
      rc = ci_sys_epoll_wait(fdi->fd, events, maxevents, timeout);
    ep->blocking = 0;
  }

  Log_POLL(ci_log("%s(%d): to kernel => %d (%d)", __FUNCTION__, fdi->fd,
                  rc, errno));
  return rc;
}


void citp_epoll_on_handover(citp_fdinfo* fd_fdi, int fdt_locked)
{
  /* We've handed [fd_fdi->fd] over to the kernel, but it may be registered
   * in an epoll set.  The handover (probably) caused the underlying file
   * object in the kernel to be freed, which will have removed this fd from
   * the epoll set.  We need to add it back.
   */
  struct citp_epoll_member* eitem;
  struct citp_epoll_fd* ep;
  citp_fdinfo* epoll_fdi;
#if !CI_CFG_EPOLL_HANDOVER_WORKAROUND
  int rc;
#endif

  if( (epoll_fdi = citp_fdtable_lookup(fd_fdi->epoll_fd)) == NULL ) {
    Log_POLL(ci_log("%s: epoll_fd=%d not found (fd=%d)", __FUNCTION__,
                    fd_fdi->epoll_fd, fd_fdi->fd));
    return;
  }

  if( epoll_fdi->protocol->type == CITP_EPOLL_FD &&
      epoll_fdi->seq == fd_fdi->epoll_fd_seq ) {
    ep = fdi_to_epoll(epoll_fdi);
    CITP_EPOLL_EP_LOCK(ep);
    CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                        dllink, &ep->oo_sockets)
      if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
        break;
    if( eitem != NULL ) {
      Log_POLL(ci_log("%s: epoll_fd=%d fd=%d events=%x data=%llx",
                      __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd,
                      eitem->epoll_data.events,
                      (unsigned long long) eitem->epoll_data.data.u64));
      ci_dllist_remove(&eitem->dllink);
      CITP_EPOLL_EP_UNLOCK(ep, fdt_locked);
#if !CI_CFG_EPOLL_HANDOVER_WORKAROUND
      rc =
#endif
          citp_epoll_ctl(epoll_fdi, EPOLL_CTL_ADD, fd_fdi->fd,
                          &eitem->epoll_data);
#if !CI_CFG_EPOLL_HANDOVER_WORKAROUND
      /* Error is OK: it means this fd is already in the kernel epoll set,
       * and kernel workaround is used */
      if( rc != 0 )
        Log_E(ci_log("%s: ERROR: epoll_ctl(%d, ADD, %d, ev) failed (%d)",
                     __FUNCTION__, epoll_fdi->fd, fd_fdi->fd, errno));
#endif
      CI_FREE_OBJ(eitem);
    }
    else {
      Log_POLL(ci_log("%s: epoll_fd=%d fd=%d not in epoll u/l set",
                      __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd));
      CITP_EPOLL_EP_UNLOCK(ep, fdt_locked);
    }
  }
  else {
    Log_POLL(ci_log("%s: epoll_fd=%d changed (type=%d seq=%llx,%llx fd=%d)",
                    __FUNCTION__, fd_fdi->epoll_fd, epoll_fdi->protocol->type,
                    (unsigned long long) epoll_fdi->seq,
                    (unsigned long long) fd_fdi->epoll_fd_seq, fd_fdi->fd));
  }
  citp_fdinfo_release_ref(epoll_fdi, fdt_locked);
}


ci_inline void
citp_ul_epoll_store_event(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events)
{
  Log_POLL(ci_log("%s: member=%llx events=%x", __FUNCTION__,
                  (long long) eitem->epoll_data.data.u64, events));

  ci_assert(eps->events_top - eps->events > 0);
  eps->events[0].events = events;
  eps->events[0].data = eitem->epoll_data.data;
  ++eps->events;

  ci_dllist_remove(&eitem->dllink);
  if( eitem->epoll_data.events & (EPOLLONESHOT | EPOLLET) )
    eps->has_epollet = 1;
  if( eitem->epoll_data.events & EPOLLONESHOT ) {
    eitem->epoll_data.events = 0;
    if( ! citp_eitem_is_synced(eitem) )
      ++(eps->ep->epfd_syncs_needed);
  }
  ci_dllist_push_tail(&eps->ep->oo_sockets, &eitem->dllink);
}


int
citp_ul_epoll_find_events(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq)
{
  if( eitem->epoll_data.events & EPOLLET ) {
    ci_sleep_seq_t polled_sleep_seq;
    polled_sleep_seq.all = sleep_seq;
    Log_POLL(ci_log("%s: EPOLLET rx_seq=%d,%d tx_seq=%d,%d",
                    __FUNCTION__,
                    eitem->reported_sleep_seq.rw.rx, polled_sleep_seq.rw.rx,
                    eitem->reported_sleep_seq.rw.tx, polled_sleep_seq.rw.tx));
    if( polled_sleep_seq.all == eitem->reported_sleep_seq.all )
      events = 0;
    else if( polled_sleep_seq.rw.rx == eitem->reported_sleep_seq.rw.rx )
      events &=~ OO_EPOLL_READ_EVENTS;
    else if( polled_sleep_seq.rw.tx == eitem->reported_sleep_seq.rw.tx )
      events &=~ OO_EPOLL_WRITE_EVENTS;
    eitem->reported_sleep_seq = polled_sleep_seq;
  }

  if( events != 0 ) {
    citp_ul_epoll_store_event(eps, eitem, events);
    return 1;
  }
  else {
    return 0;
  }
}

#endif  /* CI_CFG_USERSPACE_EPOLL */
