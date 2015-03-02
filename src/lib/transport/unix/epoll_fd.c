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
#include <onload/extensions.h>
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
#define EITEM_FROM_DEADLINK(lnk)                          \
  CI_CONTAINER(struct citp_epoll_member, dead_stack_link, (lnk))


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

static void citp_epoll_unlock_cb(void* cb_arg, void* work_list);


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


static void citp_epoll_last_stack_socket_gone(struct citp_epoll_fd* epoll_fd)
{
  /* Release the ready list.  We don't bother to sync this to the kernel. */
  ci_assert(ci_dllist_is_empty(&epoll_fd->oo_stack_sockets));
  ci_assert(ci_dllist_is_empty(&epoll_fd->oo_stack_not_ready_sockets));
  ci_assert(ci_dllist_is_empty(&epoll_fd->dead_stack_sockets));
  ci_netif_put_ready_list(epoll_fd->home_stack, epoll_fd->ready_list);
  citp_netif_release_ref(epoll_fd->home_stack, 1);
  epoll_fd->home_stack = NULL;
  epoll_fd->ready_list = 0;
}


/* This function does the full monty cleanup.  It assumes that:
 * - a reference to fd_fdi is held
 * - the epoll lock is held (or we know we don't need it)
 * - the home stack netif lock is not held
 * For cases where we can't guarantee the above
 *
 * It tidies up all state, but does not free the eitem.
 */
static void citp_remove_home_member(struct citp_epoll_fd* epoll_fd,
                                  struct citp_epoll_member* eitem,
                                  citp_fdinfo* fd_fdi)
{
  ci_netif* ni;
  citp_socket* sock;

  ci_assert(eitem);
  ci_assert_gt(eitem->ready_list_id, 0);
  ci_assert(epoll_fd->home_stack);

  ci_dllist_remove_safe(&eitem->dllink);
  epoll_fd->oo_stack_sockets_n--;

  sock = fdi_to_socket(fd_fdi);
  ni = sock->netif;
  fd_fdi->epoll_fd = -1;
  sock->s->b.eitem_pid = 0;

  /* Before we release this we need to reset the ready list and unqueue it.
   * As soon as we don't claim this, someone else might add it to another set.
   */
  ci_netif_lock(ni);
  sock->s->b.ready_list_id = 0;
  ci_ni_dllist_remove_safe(ni, &sock->s->b.ready_link);
  ci_netif_unlock(ni);

  /* We can happily furtle the eitem field without the stack lock because we
   * know that the socket buffer can't have been freed yet, and we're only
   * allowed to fiddle with it from the epoll side, it's opaque to the stack.
   */
  CI_USER_PTR_SET(sock->s->b.eitem, NULL);

  if( epoll_fd->oo_stack_sockets_n == 0 )
    citp_epoll_last_stack_socket_gone(epoll_fd);
}


/* This function requires that the epoll lock is held, or we know that we
 * don't need it.
 */
static void citp_epoll_cleanup_dead_home_socks(struct citp_epoll_fd* ep)
{
  struct citp_epoll_member* eitem;

  oo_wqlock_lock(&ep->dead_stack_lock);
  while( ci_dllist_not_empty(&ep->dead_stack_sockets) ) {
    eitem = EITEM_FROM_DEADLINK(ci_dllist_head(&ep->dead_stack_sockets));

    /* For dead sockets the associated socket state has (potentiall) been
     * freed, so we have nothing to do (and can't touch) the associated fdinfo
     * or socket buffer.
     *
     * We just need to remove this eitem from any other queue it's on, and
     * free it.
     */
    ci_dllist_remove(&eitem->dllink);
    ci_dllist_remove(&eitem->dead_stack_link);
    CI_FREE_OBJ(eitem);
    ci_assert_gt(ep->oo_stack_sockets_n, 0);
    if( --ep->oo_stack_sockets_n == 0 )
      citp_epoll_last_stack_socket_gone(ep);
  }
  oo_wqlock_unlock(&ep->dead_stack_lock, NULL, NULL);
}


static void citp_epoll_cleanup_home_sock_list(struct citp_epoll_fd* ep,
                                              ci_dllist* list)
{
  struct citp_epoll_member* eitem;
  citp_fdinfo* fd_fdi;
  /* Can only call this for lists that use the dllink field */
  ci_assert((list == &ep->oo_stack_sockets) ||
            (list == &ep->oo_stack_not_ready_sockets));

  while( ci_dllist_not_empty(list) ) {
    eitem = EITEM_FROM_DLLINK(ci_dllist_head(list));
    oo_wqlock_lock(&ep->dead_stack_lock);
    /* The socket could be being closed at the same time as we are, so need
     * to take dead_stack_lock and check whether it's on the list.
     */
    if( ci_dllink_is_self_linked(&eitem->dead_stack_link) ) {
      fd_fdi = citp_fdtable_lookup(eitem->fd);

      /* We know that the fd must still exist and not have changed identity -
       * if it was closed from user level we would have been prompted to remove
       * it, and if it was closed via the kernel we wouldn't be coming through
       * here (we don't restore epoll state after exec).
       */
      ci_assert( fd_fdi && (fd_fdi->seq == eitem->fdi_seq) );
      ci_assert( ci_dllink_is_self_linked(&eitem->dead_stack_link) );
  
      /* Last reference to this epoll_fd is about to go => we don't need to
       * take epoll lock here.
       */
      citp_remove_home_member(ep, eitem, fd_fdi);
      CI_FREE_OBJ(eitem);
      citp_fdinfo_release_ref(fd_fdi, 0);
    }
    oo_wqlock_unlock(&ep->dead_stack_lock, NULL, NULL);
  }
}


static void citp_epoll_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);

  if (!oo_atomic_dec_and_test(&ep->refcount))
    return;

  if( ep->home_stack ) {
    /* Cleaning up the dead sockets must be done first, to ensure that they're
     * removed from the other lists before we process them.
     */
    citp_epoll_cleanup_dead_home_socks(ep);
    citp_epoll_cleanup_home_sock_list(ep, &ep->oo_stack_sockets);
    citp_epoll_cleanup_home_sock_list(ep, &ep->oo_stack_not_ready_sockets);
    citp_epoll_cleanup_dead_home_socks(ep);
    ci_assert_equal(ep->home_stack, NULL);
  }
  ci_assert(ci_dllist_is_empty(&ep->oo_stack_sockets));
  ci_assert(ci_dllist_is_empty(&ep->oo_stack_not_ready_sockets));
  ci_assert(ci_dllist_is_empty(&ep->dead_stack_sockets));

  if( ! fdt_locked )  CITP_FDTABLE_LOCK();
  ci_tcp_helper_close_no_trampoline(ep->shared->epfd);
  __citp_fdtable_reserve(ep->shared->epfd, 0);
  munmap(ep->shared, sizeof(*ep->shared));

  ci_tcp_helper_close_no_trampoline(ep->epfd_os);
  __citp_fdtable_reserve(ep->epfd_os, 0);
  if( ! fdt_locked )  CITP_FDTABLE_UNLOCK();

  CI_FREE_OBJ(ep);
}


static int citp_epoll_close(citp_fdinfo *fdi)
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
    .ioctl       = citp_epoll_ioctl,

    /* Poll/select for epollfd is done via kernel. */
    .select      = citp_passthrough_select,
    .poll        = citp_passthrough_poll,
    .fcntl       = citp_passthrough_fcntl,

    /* "Invalid" members; normal user should not call it and should not
     * expect good behaviour */
    .socket      = NULL,        /* nobody should ever call this */
    .recv        = citp_nonsock_recv,
    .send        = citp_nonsock_send,
    .bind        = citp_nonsock_bind,
    .listen      = citp_nonsock_listen,
    .accept      = citp_nonsock_accept,
    .connect     = citp_nonsock_connect,
    .shutdown    = citp_nonsock_shutdown,
    .getsockname = citp_nonsock_getsockname,
    .getpeername = citp_nonsock_getpeername,
    .getsockopt  = citp_nonsock_getsockopt,
    .setsockopt  = citp_nonsock_setsockopt,
#if CI_CFG_RECVMMSG
    .recvmmsg    = citp_nonsock_recvmmsg,
#endif
#if CI_CFG_SENDMMSG
    .sendmmsg    = citp_nonsock_sendmmsg,
#endif
    .zc_send     = citp_nonsock_zc_send,
    .zc_recv     = citp_nonsock_zc_recv,
    .zc_recv_filter = citp_nonsock_zc_recv_filter,
    .recvmsg_kernel = citp_nonsock_recvmsg_kernel,
    .tmpl_alloc     = citp_nonsock_tmpl_alloc,
    .tmpl_update    = citp_nonsock_tmpl_update,
    .tmpl_abort     = citp_nonsock_tmpl_abort,
#if CI_CFG_USERSPACE_EPOLL
    .ordered_data   = citp_nonsock_ordered_data,
#endif
    .is_spinning    = citp_nonsock_is_spinning,
#if CI_CFG_FD_CACHING
    .cache          = citp_nonsock_cache,
#endif
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
  if( ef_onload_driver_open(&ep->epfd_os, OO_EPOLL_DEV, 1) < 0 ) {
    Log_E(ci_log("%s: ERROR: failed to open(%s) errno=%d",
                 __FUNCTION__, oo_device_name[OO_EPOLL_DEV], errno));
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
  oo_wqlock_init(&ep->dead_stack_lock);
  ep->not_mt_safe = ! CITP_OPTS.ul_epoll_mt_safe;
  ci_dllist_init(&ep->oo_stack_sockets);
  ep->oo_stack_sockets_n = 0;
  ci_dllist_init(&ep->oo_stack_not_ready_sockets);
  ci_dllist_init(&ep->oo_sockets);
  ep->oo_sockets_n = 0;
  ci_dllist_init(&ep->dead_sockets);
  ci_dllist_init(&ep->dead_stack_sockets);
  oo_atomic_set(&ep->refcount, 1);
  ep->epfd_syncs_needed = 0;
  ep->blocking = 0;
  ep->home_stack = NULL;
  ep->ready_list = 0;
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
  return -2;
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


ci_inline int
citp_epoll_find(struct citp_epoll_fd* ep, const citp_fdinfo* fd_fdi,
                struct citp_epoll_member** eitem_out, int epoll_fd)
{
  int fdi_epoll_fd;
  citp_socket* sock;

  /* We don't know how long ago the fdi was aquired - although we know it's
   * still valid because we hold a reference.  All sorts of things could have
   * happened to it in the meantime.
   *
   * Firstly we check to see if it's a home socket.  In this case the referred
   * to socket will have it's eitem field set, and the fd_fdi->epoll_fd will
   * provide us with the required epoll information.  These would have been
   * unset
   */

  if( citp_fdinfo_is_socket(fd_fdi) ) {
    sock = fdi_to_socket((citp_fdinfo*)fd_fdi);
    /* We need to get a consistent view of fd_fdi - it might be in the process
     * of being closed.
     *
     * We also need to be certain that we actually own this eitem.
     */
    oo_wqlock_lock(&ep->dead_stack_lock);
    *eitem_out = CI_USER_PTR_GET(sock->s->b.eitem);
    fdi_epoll_fd = fd_fdi->epoll_fd;
    oo_wqlock_unlock(&ep->dead_stack_lock, NULL, NULL);
    if( *eitem_out && (sock->s->b.eitem_pid == getpid()) &&
        (fdi_epoll_fd == epoll_fd) ) {
      /* We know that the fd must still exist and not have changed identity -
       * if it was closed from user level we would have been prompted to remove
       * it, and if it was closed via the kernel we wouldn't be coming through
       * here (we don't restore epoll state after exec).
       *
       * We can only assert this for home sockets, as we don't remove non-home
       * sockets on close.
       */
      ci_assert( fd_fdi && (fd_fdi->seq == (*eitem_out)->fdi_seq) );
      return EPOLL_STACK_EITEM;
    }
  }

  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, *eitem_out,
                      dllink, &ep->oo_sockets)
    if( (*eitem_out)->fd == fd_fdi->fd && (*eitem_out)->fdi_seq == fd_fdi->seq )
      return EPOLL_NON_STACK_EITEM;

  *eitem_out = NULL;
  return -1;
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


static void citp_eitem_init(struct citp_epoll_member* eitem,
                            citp_fdinfo* fd_fdi, struct epoll_event* event)
{
  eitem->epoll_data = *event;
  eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
  citp_eitem_reset_epollet(eitem);
  eitem->fd = fd_fdi->fd;
  eitem->fdi_seq = fd_fdi->seq;
  eitem->ready_list_id = 0;
  ci_dllink_self_link(&eitem->dead_stack_link);
}


static void citp_epoll_ctl_onload_add_home(struct citp_epoll_member* eitem,
                                           struct citp_epoll_fd* ep,
                                           citp_socket* sock,
                                           citp_fdinfo* fd_fdi, int epoll_fd,
                                           ci_uint64 epoll_fd_seq)
{
  sock->s->b.ready_list_id = ep->ready_list;
  eitem->item_list = &ep->oo_stack_sockets;
  eitem->ready_list_id = ep->ready_list;
  ep->oo_stack_sockets_n++;

  /* We start it out on the ready list - if it's already ready it won't be
   * on the stack ready list.
   */
  ci_dllist_push(&ep->oo_stack_sockets, &eitem->dllink);

  fd_fdi->epoll_fd = epoll_fd;
  fd_fdi->epoll_fd_seq = epoll_fd_seq;
}


static void citp_epoll_ctl_onload_add_other(struct citp_epoll_member* eitem,
                                            struct citp_epoll_fd* ep,
                                            int* sync_kernel,
                                            citp_fdinfo* fd_fdi, int epoll_fd,
                                            ci_uint64 epoll_fd_seq)
{
  eitem->item_list = &ep->oo_sockets;
  ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
  ep->oo_sockets_n++;

  /* We need to be able to autopop at user level if we want to cache, and that
   * means we can only cache stuff added as home sockets.
   */
  /* FIXME SCJ want a stat to pick this up - probably want to be more
   * specific about why uncacheable - set flags?
   */
  fd_fdi->can_cache = 0;

  if( ! *sync_kernel ) {
    eitem->epfd_event.events = EP_NOT_REGISTERED;
    ++ep->epfd_syncs_needed;
  }

  /* At the moment only one epoll set can be associated with an fdinfo.  This
   * is used on handover, stack move, and in the home stack case it's also
   * needed on close.  Because everything gets closed, but move or handover
   * are more unusual I'm making the non-broken set the home stack set.
   * FIXME SCJ this is skanky anyway - maybe we should just prohibit adding to
   * more than one set with epoll1 - it works ok with epoll2.
   */
  if( ci_cas32_succeed(&fd_fdi->epoll_fd, -1, epoll_fd) )
    fd_fdi->epoll_fd_seq = epoll_fd_seq;
}


static int citp_epoll_ctl_onload_add_new(struct citp_epoll_member** eitem_out,
                                         struct citp_epoll_fd* ep,
                                         citp_fdinfo* fd_fdi, int* sync_kernel,
                                         struct epoll_event* event,
                                         int epoll_fd, ci_uint64 epoll_fd_seq)
{
  citp_socket* sock = NULL;
  ci_netif* ni = fdi_to_socket(fd_fdi)->netif;
  struct oo_epoll1_set_home_arg op;
  int rc;

  *eitem_out = CI_ALLOC_OBJ(struct citp_epoll_member);
  if( *eitem_out == NULL ) {
    errno = ENOMEM;
    return -1;
  }

  citp_eitem_init(*eitem_out, fd_fdi, event);

  if( citp_fdinfo_is_socket(fd_fdi) )
    sock = fdi_to_socket(fd_fdi);

  /* If we don't already have a home stack, then see if we can get a ready
   * list for this socket's stack, and if so use that.
   *
   * There's a gap here between deciding to use this socket's stack for our
   * home stack, and actually claiming this socket as ours, but I'm deeming
   * the chance of this socket being added to another socket in parallel
   * sufficiently low that the cost of locking more widely to avoid it isn't
   * worth it.  Things will work fine, we just potentially won't end up with
   * any sockets in our home stack, but currently home stack selection is not
   * guaranteed to be in any way optimal anyway.
   */
  if( (CITP_OPTS.ul_epoll == 3) && CI_UNLIKELY(!ep->home_stack) && sock &&
      CI_USER_PTR_GET(sock->s->b.eitem) == NULL ) {
    ep->ready_list = ci_netif_get_ready_list(ni);
    Log_POLL(ci_log("%s: Set home stack for set %d using ready list %d",
                    __FUNCTION__, epoll_fd, ep->ready_list));

    if( ep->ready_list > 0 ) {
      op.sockfd = fd_fdi->fd;
      op.ready_list = ep->ready_list;
      rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_SET_HOME_STACK, &op);
      if( rc == 0 ) {
        citp_netif_add_ref(ni);
        ep->home_stack = ni;
      }
      else {
        ci_netif_put_ready_list(ni, ep->ready_list);
        ep->ready_list = 0;
      }
    }
  }

  /* If we have a home stack then need to check if this fd lives there.
   * If so we can add it to our cool sockets list, if not we'll do it the old
   * school way.
   */
  if( ep->home_stack == ni ) {
    /* Once we've set the eitem this socket is claimed by this epoll set */
    ci_sock_lock(ni, &sock->s->b);
    if( CI_USER_PTR_GET(sock->s->b.eitem) == NULL ) {
      sock->s->b.eitem_pid = getpid();
      CI_USER_PTR_SET(sock->s->b.eitem, *eitem_out);
      ci_sock_unlock(ni, &sock->s->b);

      citp_epoll_ctl_onload_add_home(*eitem_out, ep, sock, fd_fdi, epoll_fd,
                                     epoll_fd_seq);
      *sync_kernel = 0;
    }
    else {
      ci_sock_unlock(ni, &sock->s->b);
      citp_epoll_ctl_onload_add_other(*eitem_out, ep, sync_kernel, fd_fdi,
                                      epoll_fd, epoll_fd_seq);
    }
  }
  else {
    citp_epoll_ctl_onload_add_other(*eitem_out, ep, sync_kernel, fd_fdi,
                                    epoll_fd, epoll_fd_seq);
  }

  return 0;
}


static void citp_epoll_ctl_onload_readd(struct citp_epoll_member* eitem,
                                        struct citp_epoll_fd* ep,
                                        int* sync_kernel, int* sync_op,
                                        struct epoll_event* event,
                                        citp_fdinfo* fd_fdi, int epoll_fd,
                                        ci_uint64 epoll_fd_seq)
{
  /* Sockets in the home stack don't hang around after EPOLL_CTL_DEL */
  ci_assert_equal(eitem->ready_list_id, 0);

  /* Re-added having previously been deleted (but delete did not
   * yet make it as far as the kernel).
   */
  eitem->epoll_data = *event;
  eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
  citp_eitem_reset_epollet(eitem);
  if( *sync_kernel )
    *sync_op = EPOLL_CTL_MOD;
  else if( ! citp_eitem_is_synced(eitem) )
    ++ep->epfd_syncs_needed;
  ci_dllist_remove(&eitem->dllink);

  ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
  ep->oo_sockets_n++;

  if( ci_cas32_succeed(&fd_fdi->epoll_fd, -1, epoll_fd) )
    fd_fdi->epoll_fd_seq = epoll_fd_seq;
}


static int citp_epoll_ctl_onload_add(struct citp_epoll_member** eitem_out,
                                     struct citp_epoll_fd* ep,
                                     citp_fdinfo* fd_fdi, int* sync_kernel,
                                     int* sync_op, struct epoll_event* event,
                                     int epoll_fd, ci_uint64 epoll_fd_seq)
{
  int rc = 0;
  if( *eitem_out == NULL ) {
    *eitem_out = citp_epoll_find_dead(ep, fd_fdi);
    if( *eitem_out == NULL ) {
      rc = citp_epoll_ctl_onload_add_new(eitem_out, ep, fd_fdi, sync_kernel,
                                         event, epoll_fd, epoll_fd_seq);
    }
    else {
      citp_epoll_ctl_onload_readd(*eitem_out, ep, sync_kernel, sync_op, event,
                                  fd_fdi, epoll_fd, epoll_fd_seq);
    }
  }
  else {
    errno = EEXIST;
    rc = -1;
  }
  return rc;
}


static int citp_epoll_ctl_onload_mod(struct citp_epoll_member* eitem,
                                     struct citp_epoll_fd* ep,
                                     int* sync_kernel, int* sync_op,
                                     struct epoll_event* event)
{
  int rc = 0;
  if(CI_LIKELY( eitem != NULL )) {
    eitem->epoll_data = *event;
    eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
    citp_eitem_reset_epollet(eitem);
    if( *sync_kernel ) {
      if( eitem->epfd_event.events == EP_NOT_REGISTERED )
        *sync_op = EPOLL_CTL_ADD;
    }
    else if( (eitem->ready_list_id == 0) && !citp_eitem_is_synced(eitem) )
      ++ep->epfd_syncs_needed;

    /* Reinsert at front to exploit locality of reference if there
     * are many sockets and EPOLL_CTL_MOD is frequent.
     */
    ci_dllist_remove(&eitem->dllink);
    ci_dllist_push(eitem->item_list, &eitem->dllink);
  }
  else {
    errno = ENOENT;
    rc = -1;
  }
  return rc;
}

static int citp_epoll_ctl_onload_del(struct citp_epoll_member* eitem,
                                     struct citp_epoll_fd* ep,
                                     int* sync_kernel, citp_fdinfo* fd_fdi,
                                     int epoll_fd)
{
  int rc = 0;
  if(CI_LIKELY( eitem != NULL )) {
    if( eitem->ready_list_id > 0 ) {
      /* This may already be being, or have been, removed via close of the
       * socket, so need to check.
       */
      oo_wqlock_lock(&ep->dead_stack_lock);
      if( ci_dllink_is_self_linked(&eitem->dead_stack_link) ) {
        /* Not been closed yet, can cleanup now. */
        citp_remove_home_member(ep, eitem, fd_fdi);
        CI_FREE_OBJ(eitem);
      }
      ci_assert_equal(fd_fdi->epoll_fd, -1);
      oo_wqlock_unlock(&ep->dead_stack_lock, NULL, NULL);
    }
    else {
      ci_dllist_remove(&eitem->dllink);
      ep->oo_sockets_n--;
      if( eitem->epfd_event.events == EP_NOT_REGISTERED )
        *sync_kernel = 0;
      if( *sync_kernel || eitem->epfd_event.events == EP_NOT_REGISTERED ) {
        CI_FREE_OBJ(eitem);
      }
      else {
        ci_dllist_push(&ep->dead_sockets, &eitem->dllink);
        ++ep->epfd_syncs_needed;
      }
      ci_cas32_succeed(&fd_fdi->epoll_fd, epoll_fd, -1);
    }
  }
  else {
    errno = ENOENT;
    rc = -1;
  }
  return rc;
}


static int citp_epoll_ctl_onload2(struct citp_epoll_fd* ep, int op,
                                  struct epoll_event* event,
                                  citp_fdinfo* fd_fdi, int epoll_fd,
                                  ci_uint64 epoll_fd_seq)
{
  struct citp_epoll_member* eitem;
  int sync_kernel, rc = 0;
  int sync_op = op;
  int type = citp_epoll_find(ep, fd_fdi, &eitem, epoll_fd);

  /* Should we sync this op to the kernel?
   *
   * We try defer this step when EF_EPOLL_CTL_FAST=1 because we hope to
   * avoid a sys-call, or at least delay the sys-call until we're about to
   * block.
   *
   * If a thread is blocking in epoll_wait(), then we must sync to kernel
   * now, as this op may wake the epoll_wait().
   *
   * If the relevant eitem is in our home stack we don't have any kernel
   * state to be kept in sync.
   */
  sync_kernel = (type != EPOLL_STACK_EITEM) &&
                (! CITP_OPTS.ul_epoll_ctl_fast || ep->blocking);


  switch( op ) {
  case EPOLL_CTL_ADD:
    rc = citp_epoll_ctl_onload_add(&eitem, ep, fd_fdi, &sync_kernel, &sync_op,
                                   event, epoll_fd, epoll_fd_seq);
    break;
  case EPOLL_CTL_MOD:
    rc = citp_epoll_ctl_onload_mod(eitem, ep, &sync_kernel, &sync_op, event);
    break;
  case EPOLL_CTL_DEL:
    rc = citp_epoll_ctl_onload_del(eitem, ep, &sync_kernel, fd_fdi, epoll_fd);
    break;
  default:
    errno = EINVAL;
    rc = -1;
    break;
  }

  /* Apply epoll_ctl() to the kernel. */
  if( sync_kernel && rc == 0 ) {
    /* We don't sync home sockets to the kernel */
    ci_assert(eitem->ready_list_id == 0);

    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): SYNC_KERNEL", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event)));
    if( sync_op == EPOLL_CTL_ADD ) {
      ci_fixed_descriptor_t fd = fd_fdi->fd;
      int saved_errno = errno;
      ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_ADD_STACK, &fd);
      /* We ignore rc: we do not care if ioctl failed.
       * So, we should restore errno. */
      errno = saved_errno;
    }
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
    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): %s rc=%d errno=%d", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event),
                    eitem && eitem->ready_list_id > 0 ? "HOME":"OTHER",
                    rc, errno));
  }

  if( ci_dllist_not_empty(&ep->dead_stack_sockets) )
    citp_epoll_cleanup_dead_home_socks(ep);

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
  struct oo_epoll1_ctl_arg oop;
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
  oop.fd = ev.fd;
  CI_USER_PTR_SET(oop.event, &ev.event);
  oop.op = ev.op;
  oop.epfd = fdi->fd;
  rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_CTL, &oop);
  Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): rc=%d errno=%d", __FUNCTION__,
                  EPOLL_CTL_ARGS(fdi->fd, op, fd, event), rc, errno));
  return rc;
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


static void citp_ul_epoll_ctl_sync_fd(int epfd, struct citp_epoll_fd* ep,
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
  if( op == EPOLL_CTL_ADD ) {
    ci_fixed_descriptor_t fd = eitem->fd;
    int saved_errno = errno;
    ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_ADD_STACK, &fd);
    /* We ignore rc: we do not care if ioctl failed.
     * So, we should restore errno. */
    errno = saved_errno;
  }
  rc = ci_sys_epoll_ctl(epfd, op, eitem->fd, &eitem->epoll_data);
  if( rc < 0 )
    Log_E(ci_log("%s: ERROR: sys_epoll_ctl("EPOLL_CTL_FMT") failed (%d,%d)",
                 __FUNCTION__,
                 EPOLL_CTL_ARGS(epfd, op, eitem->fd, &eitem->epoll_data),
                 rc, errno));
}

static inline citp_fdinfo_p
citp_ul_epoll_member_to_fdip(struct citp_epoll_member* eitem)
{
  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);
  return citp_fdtable.table[eitem->fd].fdip;
}

static inline citp_fdinfo * 
citp_ul_epoll_member_to_fdi(struct citp_epoll_member* eitem)
{
  citp_fdinfo* fdi = NULL;
  do {
    citp_fdinfo_p fdip = citp_ul_epoll_member_to_fdip(eitem);
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
  struct citp_epoll_member* eitem_tmp;
  int rc;

  Log_POLL(ci_log("%s(%d)", __FUNCTION__, epfd));

  while( ci_dllist_not_empty(&ep->dead_sockets) ) {
    eitem = EITEM_FROM_DLLINK(ci_dllist_pop(&ep->dead_sockets));
    ci_assert_equal(eitem->ready_list_id, 0);

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

  CI_DLLIST_FOR_EACH3(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets, eitem_tmp)
    if( ! citp_eitem_is_synced(eitem) ) {
      if( citp_ul_epoll_member_to_fdi(eitem) )
        citp_ul_epoll_ctl_sync_fd(epfd, ep, eitem);
      else {
        ci_dllist_remove(&eitem->dllink);
        ep->oo_sockets_n--;
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


/* Number of retries: avoid false edge-triggered events if the sleep
 * sequence number is changing while the event is processed. */
#define OO_EPOLLET_SLEEP_SEQ_MISMATCH_RETRIES 3

static int citp_ul_epoll_one(struct oo_ul_epoll_state*__restrict__ eps,
                             struct citp_epoll_member*__restrict__ eitem)
{
  citp_fdinfo* fdi = NULL;
  int stored_event = 0;

  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);

  if(CI_LIKELY( (fdi = citp_ul_epoll_member_to_fdi(eitem)) != NULL )) {
    if( (eitem->epoll_data.events & OO_EPOLL_ALL_EVENTS) != 0 ) {
      int i = 0;

      /* If SO_BUSY_POLL behaviour requested need to check if there is
       * a spinning socket in the set, and remove flag to enable spinning
       * if it is found */
      if( ( eps->ul_epoll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) ) &&
          citp_fdinfo_get_ops(fdi)->is_spinning(fdi) ) {
        eps->ul_epoll_spin &= ~(1 << ONLOAD_SPIN_SO_BUSY_POLL);
      }

      /* In most cases, it is not a loop - ->epoll() usually returns 0.
       * ->epoll() returns non-zero if user asked for EPOLLET and
       * the sequence number is changing under our feet.
       * In such a case, we retry a few times. */
      while( citp_fdinfo_get_ops(fdi)->epoll(fdi, eitem, eps, &stored_event) &&
             i++ < OO_EPOLLET_SLEEP_SEQ_MISMATCH_RETRIES )
        ;
    }
    return stored_event;
  }

  /* [fdip] is special, or the seq check failed, so this fd has changed
   * identity.  Best we can do at userlevel is assume the file descriptor
   * was closed, and remove it from the set.
   *
   *   Home sockets are cleaned up via the close hook, and so must not be
   * cleaned up here.  If the fdi we've looked up is closing, then we can't
   * currently tell whether this is a home socket, so don't do anything yet.
   * If it's not closing then we should be able to tell by looking at whether
   * it's on the dead list - home sockets are bunged here when they're closed.
   */
  if( !fdip_is_closing(citp_ul_epoll_member_to_fdip(eitem)) &&
      ci_dllink_is_self_linked(&eitem->dead_stack_link) &&
      eitem->ready_list_id == 0) {
    Log_POLL(ci_log("%s: auto remove fd %d from epoll set",
                    __FUNCTION__, eitem->fd));

    ci_dllist_remove(&eitem->dllink);
    eps->ep->oo_sockets_n--;
    CI_FREE_OBJ(eitem);
  }

  return stored_event;
}


static void citp_epoll_get_ready_list(struct oo_ul_epoll_state*
                                      __restrict__ eps)
{
  ci_ni_dllist_link* lnk;
  citp_waitable* sb;
  ci_netif* ni = eps->ep->home_stack;
  ci_ni_dllist_t* ready_list =
                         &ni->state->ready_lists[eps->ep->ready_list];
  struct citp_epoll_member* eitem;

  ci_atomic32_and(&ni->state->ready_list_flags[eps->ep->ready_list],
                  ~CI_NI_READY_LIST_FLAG_RESCAN);
  citp_poll_if_needed(ni, eps->this_poll_frc, eps->ul_epoll_spin);

  ci_netif_lock(ni);
  lnk = ci_ni_dllist_start(ni, ready_list);
  while (lnk != ci_ni_dllist_end(ni, ready_list)) {
    sb = CI_CONTAINER(citp_waitable, ready_link, lnk);
    eitem = CI_USER_PTR_GET(sb->eitem);
    ci_ni_dllist_iter(ni, lnk);
    ci_ni_dllist_remove_safe(ni, &sb->ready_link);
    ci_assert(eitem);
    ci_assert_equal(sb->ready_list_id, eps->ep->ready_list);
    ci_dllist_remove(&((struct citp_epoll_member*)eitem)->dllink);
    ci_dllist_push(&eps->ep->oo_stack_sockets,
                   &((struct citp_epoll_member*)eitem)->dllink);
  }
  ci_netif_unlock(ni);
}


static void citp_epoll_poll_home_socks(struct oo_ul_epoll_state*
                                       __restrict__ eps)
{
  struct citp_epoll_member* eitem;
  ci_dllink *next, *last;
  int stored_event;

  if( ci_dllist_not_empty(&eps->ep->oo_stack_sockets) ) {
    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    last = ci_dllist_last(&eps->ep->oo_stack_sockets);
    next = ci_dllist_start(&eps->ep->oo_stack_sockets);
    do {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, next);
      next = next->next;
      stored_event = citp_ul_epoll_one(eps, eitem);
      if( !stored_event ) {
        ci_dllist_remove(&eitem->dllink);
        ci_dllist_push(&eps->ep->oo_stack_not_ready_sockets, &eitem->dllink);
      }

    } while( eps->events < eps->events_top && &eitem->dllink != last );

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  FDTABLE_ASSERT_VALID();
}


static void citp_epoll_poll_ul_home_stack(struct oo_ul_epoll_state*
                                          __restrict__ eps)
{
  ci_assert( eps->events < eps->events_top );

  /* Move all potentially ready socks onto our internal potential ready list.
   * If they turn out not to be ready later on, then they'll go onto the not
   * ready list then.
   *
   * We always get the ready list, so that we don't need to remember what socks
   * we've already got events for.  We could be cleverer here, and avoid a poll
   * and stack lock grab.
   */
  citp_epoll_get_ready_list(eps);

  citp_epoll_poll_home_socks(eps);
}


static void citp_epoll_poll_ul_other(struct oo_ul_epoll_state* __restrict__ eps)
{
  struct citp_epoll_member* eitem;
  ci_dllink *next, *last;

  ci_assert( eps->events < eps->events_top );

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


static void citp_epoll_poll_ul(struct oo_ul_epoll_state*__restrict__ eps)
{
  /* First check any sockets in our home stack */
  if( eps->ep->home_stack )
    citp_epoll_poll_ul_home_stack(eps);

  /* Then check any other accelerated sockets if we still have space */
  if( eps->events < eps->events_top )
    citp_epoll_poll_ul_other(eps);

  /* If we'd like to spin for spinning socket only, and we've failed to
   * find any - remove spinning flags. */
  if( eps->ul_epoll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) )
    eps->ul_epoll_spin = 0;
}


ci_inline int citp_epoll_os_fds(citp_epoll_fdi *efdi,
                                struct epoll_event* events, int maxevents)
{
  struct oo_epoll1_wait_arg op;
  struct citp_epoll_fd* ep = efdi->epoll;
  int rc;

  ci_assert(__oo_per_thread_get()->sig.inside_lib);

  if( (ep->shared->flag & OO_EPOLL1_FLAG_EVENT) == 0 )
    return 0;

  Log_POLL(ci_log("%s(%d): poll os fds", __FUNCTION__, efdi->fdinfo.fd));

  op.epfd = efdi->fdinfo.fd;
  op.maxevents = maxevents;
  CI_USER_PTR_SET(op.events, events);
  rc = ci_sys_ioctl(efdi->epoll->epfd_os, OO_EPOLL1_IOC_WAIT, &op);
  return rc < 0 ? rc : op.rc;
}



static inline int
citp_epoll_find_timeout(ci_int64* timeout_hr, ci_uint64* poll_start_frc)
{
  ci_uint64 now_frc;
  ci_frc64(&now_frc);
  *timeout_hr -= now_frc - *poll_start_frc;
  *poll_start_frc = now_frc;
  *timeout_hr = CI_MAX(*timeout_hr, 0);
  return *timeout_hr / citp.cpu_khz;
}

/* Sanity check: we use ppoll() to implement epoll_pwait() */
#if CI_LIBC_HAS_epoll_pwait && ! CI_LIBC_HAS_ppoll
#error "Can not implement epoll_pwait() without ppoll()"
#endif

int citp_epoll_wait(citp_fdinfo* fdi, struct epoll_event*__restrict__ events,
                    struct citp_ordered_wait* ordering,
                    int maxevents, int timeout, const sigset_t *sigmask,
                    citp_lib_context_t *lib_context)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct oo_ul_epoll_state eps;
  ci_uint64 poll_start_frc;
  ci_int64 timeout_hr = (ci_int64) timeout * citp.cpu_khz;
  int rc = 0, rc_os;
#if CI_LIBC_HAS_epoll_pwait
  sigset_t sigsaved;
  int pwait_was_spinning = 0;
#endif
  int have_spin = 0;

  Log_POLL(ci_log("%s(%d, max_ev=%d, timeout=%d) ul=%d dead=%d syncs=%d",
                  __FUNCTION__, fdi->fd, maxevents, timeout,
                  ! ci_dllist_is_empty(&ep->oo_sockets),
                  ! ci_dllist_is_empty(&ep->dead_sockets),
                  ep->epfd_syncs_needed));

  CITP_EPOLL_EP_LOCK(ep);

  if( ((CITP_OPTS.ul_epoll == 1 || ! ep->not_mt_safe) &&
       ci_dllist_is_empty(&ep->oo_stack_sockets) &&
       ci_dllist_is_empty(&ep->oo_stack_not_ready_sockets) &&
       ci_dllist_is_empty(&ep->oo_sockets)) ||
      maxevents <= 0 || timeout < -1 || events == NULL ) {
    /* No accelerated fds or invalid parameters). */
    if( ep->epfd_syncs_needed )
      citp_ul_epoll_ctl_sync(ep, fdi->fd);
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
  eps.ordering_info = ordering ? ordering->ordering_info : NULL;
  eps.has_epollet = 0;
  /* NB. We do need to call oo_per_thread_get() here (despite having
   * [lib_context] in scope) to ensure [spinstate] is initialised.
   */
  eps.ul_epoll_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_EPOLL_WAIT);
  if( eps.ul_epoll_spin ) {
    eps.ul_epoll_spin |=
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SO_BUSY_POLL);
  }

 poll_again:
#if CI_CFG_SPIN_STATS
  eps.stat_incremented = 0;
#endif
  ci_assert( eps.events_top == (eps.events + maxevents) );
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

    /* If we've been spinning for some time before getting events, then any
     * events are probably past the limit being used for ordering.  Tell caller
     * that it would be worth polling again.
     */
    if( have_spin && ordering ) {
      ordering->poll_again = 1;
      ordering->next_timeout = citp_epoll_find_timeout(&timeout_hr,
                                                       &poll_start_frc);
    }

    Log_POLL(ci_log("%s(%d): return %d ul + %d kernel",
                    __FUNCTION__, fdi->fd, rc, rc_os));
    goto unlock_release_exit_ret;
  }
  /* eps.events == events */

  /* poll OS fds: */
  rc = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi), events, maxevents);
  if( rc != 0 || timeout == 0 ) {
    Log_POLL(ci_log("%s(%d): %d kernel events", __FUNCTION__, fdi->fd, rc));
    goto unlock_release_exit_ret;
  }

  /* Blocking.  Shall we spin? */
  if( KEEP_POLLING(eps.ul_epoll_spin, eps.this_poll_frc, poll_start_frc) ) {
#if CI_LIBC_HAS_epoll_pwait
    if( !pwait_was_spinning && sigmask != NULL) {
      if( ep->avoid_spin_once ) {
        eps.ul_epoll_spin = 0;
        ep->avoid_spin_once = 0;
        goto unlock_release_exit_ret;
      }
      rc = citp_ul_pwait_spin_pre(lib_context, sigmask, &sigsaved);
      if( rc != 0 ) {
        CITP_EPOLL_EP_UNLOCK(ep, 0);
        citp_exit_lib(lib_context, CI_FALSE);
        return rc;
      }
      pwait_was_spinning = 1;
    }
#endif

    /* See if another thread has queued any epoll_ctl requests. */
    oo_wqlock_try_drain_work(&ep->lock, citp_epoll_unlock_cb,
                             (void*)(uintptr_t) 0);

    /* Timeout while spinning? */
    if( timeout > 0 && (eps.this_poll_frc - poll_start_frc >= timeout_hr) ) {
      Log_POLL(ci_log("%s(%d): timeout during spin", __FUNCTION__, fdi->fd));
      rc = 0;
      timeout = 0;
      goto unlock_release_exit_ret;
    }

    if(CI_UNLIKELY( lib_context->thread->sig.aflags &
                    OO_SIGNAL_FLAG_HAVE_PENDING )) {
      errno = EINTR;
      rc = -1;
      goto unlock_release_exit_ret;
    }

    have_spin = 1;

    /* give a chance to close fd from this epoll set */
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    CITP_EPOLL_EP_LOCK(ep);

    goto poll_again;
  } /* endif ul_epoll_spin spinning*/

  /* Re-calculate timeout.  We should do it if we were spinning a lot. */
  if( eps.ul_epoll_spin && timeout > 0 ) {
    timeout_hr -= eps.this_poll_frc - poll_start_frc;
    timeout_hr = CI_MAX(timeout_hr, 0);
    timeout = timeout_hr / citp.cpu_khz;
    Log_POLL(ci_log("%s: blocking timeout reduced to %d",
                    __FUNCTION__, timeout));
  }

 unlock_release_exit_ret:
  /* Synchronise state to kernel (if necessary) and block. */
  if( ep->epfd_syncs_needed &&
      rc == 0 && (timeout != 0
#if CI_LIBC_HAS_epoll_pwait
                  || sigmask != NULL
#endif
                  ) )
    citp_ul_epoll_ctl_sync(ep, fdi->fd);
  CITP_EPOLL_EP_UNLOCK(ep, 0);
  Log_POLL(ci_log("%s(%d): to kernel", __FUNCTION__, fdi->fd));

#if CI_LIBC_HAS_epoll_pwait
  if( pwait_was_spinning) {
    Log_POLL(ci_log("%s(%d): pwait_was_spinning", __FUNCTION__, fdi->fd));
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

  if( rc != 0 || timeout == 0 )
    return rc;

  Log_POLL(ci_log("%s(%d): rc=0 timeout=%d sigmask=%p", __FUNCTION__,
                  fdi->fd, timeout, sigmask));
  ci_assert( eps.events_top == (eps.events + maxevents) );

  /* Fixme:
   * - interrupt-driven stacks do not need to be primed at all;
   * - home stack is primed by oo_epoll1_poll() function.
   * We need to prime all other stacks if there are any - in the most
   * cases, there are no other stacks.
   */
  ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_PRIME);

  ep->blocking = 1;

  if( ! ep->home_stack &&
      ( CITP_OPTS.ul_epoll == 1 || ! ep->not_mt_safe ) ) {
    /* If there is no home stack and it can not be created while we are
     * blocked, we can block on epoll_wait() */
#if CI_LIBC_HAS_epoll_pwait
    if( sigmask != NULL )
      rc = ci_sys_epoll_pwait(fdi->fd, events, maxevents, timeout, sigmask);
    else
#endif
      rc = ci_sys_epoll_wait(fdi->fd, events, maxevents, timeout);
    ep->blocking = 0;
  }
  else {
    struct pollfd pollfds[2];
    /* Do a poll so we can monitor both the epoll set containing our home stack
     * sockets, and the other accelerated + kernel set.
     */
    pollfds[0].fd = fdi->fd;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = ep->epfd_os;
    pollfds[1].events = POLLIN;

   block_again:
#if CI_LIBC_HAS_epoll_pwait
    if( sigmask != NULL ) {
      struct timespec timeout_ts;
      ms2timespec(timeout, 0, &timeout_ts);
      rc = ci_sys_ppoll(&pollfds[0], 2, &timeout_ts, sigmask);
    }
    else
#endif
      rc = ci_sys_poll(&pollfds[0], 2, timeout);

    ep->blocking = 0;
    if( rc > 0 && !ordering ) {
      /* We've got some events.  We MUST call epoll_wait to get the real
       * events - it is the only way to reset EPOLLET event. */
      if( pollfds[0].revents ) {
        rc = ci_sys_epoll_wait(fdi->fd, events, maxevents, 0);
        if( rc < 0 )
          return rc;
        eps.events += rc;
      }

      /* Are there any events in the home stack? */
      if( pollfds[1].revents ) {
        citp_reenter_lib(lib_context);

        CITP_EPOLL_EP_LOCK(ep);
        /* We MUST check that home stack has not disappeared while we were
         * waiting. */
        if( eps.ep->home_stack )
          citp_epoll_poll_ul_home_stack(&eps);
        CITP_EPOLL_EP_UNLOCK(ep, 0);

        citp_exit_lib(lib_context, FALSE);
        rc = eps.events - events;
      }

      if( rc == 0 ) {
        /* False alarm. Let's block again.  */
        timeout = citp_epoll_find_timeout(&timeout_hr, &poll_start_frc);
        if( timeout > 0 ) {
          ep->blocking = 1;
          goto block_again;
        }
      }
    }
  }

  if( rc && ordering ) {
    ordering->poll_again = 1;
    ordering->next_timeout = citp_epoll_find_timeout(&timeout_hr,
                                                     &poll_start_frc);
  }

  Log_POLL(ci_log("%s(%d): to kernel => %d (%d)", __FUNCTION__, fdi->fd,
                  rc, errno));
  return rc;
}

/* Caller must call CITP_EPOLL_EP_UNLOCK in case of success */
static int
citp_epoll_hook_start(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                      int fdt_locked,
                      struct citp_epoll_member** eitem_out)
{
  struct citp_epoll_member* eitem;
  struct citp_epoll_fd* ep;

  ep = fdi_to_epoll(epoll_fdi);
  CITP_EPOLL_EP_LOCK(ep);

  /* This hook may be called after a completed handover, ie after the socket
   * buffer has been released, so we need to search through our list, rather
   * than going through the fdi.
   */
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_stack_sockets) {
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq ) {
      *eitem_out = eitem;
      return 0;
    }
  }

  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets) {
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq ) {
      *eitem_out = eitem;
      return 0;
    }
  }

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d not in epoll u/l set",
                  __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd));
  CITP_EPOLL_EP_UNLOCK(ep, fdt_locked);
  return -ENOENT;

}

void citp_epoll_on_move(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                        citp_fdinfo* new_fdi, int fdt_locked)
{
  struct citp_epoll_member* eitem;
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);
  int rc;

  rc = citp_epoll_hook_start(epoll_fdi, fd_fdi, fdt_locked, &eitem);
  if( rc != 0 )
    return;

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d %s", __FUNCTION__, fd_fdi->epoll_fd,
                  fd_fdi->fd, eitem->ready_list_id > 0 ? "HOME":"OTHER"));

  if( eitem->ready_list_id == 0 ) {
    /* Would be nice to move into the home stack if that's where we're moved
     * to, but not bothering for now.
     */
    eitem->fdi_seq = new_fdi->seq;
  }
  else {
    /* This was in our home stack, but now isn't.  Need to update the eitem
     * state to be appropriate for a non-home sock.
     */
    ci_dllist_remove(&eitem->dllink);
    ep->oo_stack_sockets_n--;
    eitem->ready_list_id = 0;

    eitem->item_list = &ep->oo_sockets;
    ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
    ep->oo_sockets_n++;

    eitem->fdi_seq = new_fdi->seq;
    eitem->epfd_event.events = EP_NOT_REGISTERED;
    ++ep->epfd_syncs_needed;
  }

  CITP_EPOLL_EP_UNLOCK(fdi_to_epoll(epoll_fdi), fdt_locked);
}

void citp_epoll_on_handover(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                            int fdt_locked)
{
  /* We've handed [fd_fdi->fd] over to the kernel, but it may be registered
   * in an epoll set.  The handover (probably) caused the underlying file
   * object in the kernel to be freed, which will have removed this fd from
   * the epoll set.  We need to add it back.
   */
  struct citp_epoll_member* eitem;
  struct citp_epoll_fd* ep;
  int rc;

  rc = citp_epoll_hook_start(epoll_fdi, fd_fdi, fdt_locked, &eitem);
  if( rc != 0 )
    return;

  ep = fdi_to_epoll(epoll_fdi);

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d events=%x data=%llx",
                  __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd,
                  eitem->epoll_data.events,
                  (unsigned long long) eitem->epoll_data.data.u64));

  if( eitem->ready_list_id == 0 ) {
    ep->oo_sockets_n--;
    ci_dllist_remove(&eitem->dllink);
  }
  else {
    citp_remove_home_member(ep, eitem, fd_fdi);
  }

  CITP_EPOLL_EP_UNLOCK(ep, fdt_locked);
  if( fd_fdi->protocol->type == CITP_PASSTHROUGH_FD )
    rc = citp_epoll_ctl(epoll_fdi, EPOLL_CTL_ADD,
                        fdi_to_alien_fdi(fd_fdi)->os_socket,
                        &eitem->epoll_data);
  else
    rc = citp_epoll_ctl(epoll_fdi, EPOLL_CTL_ADD, fd_fdi->fd,
                        &eitem->epoll_data);
  /* Error is OK: it means this fd is already in the kernel epoll set,
   * and kernel workaround is used */
  if( rc != 0 )
    Log_E(ci_log("%s: ERROR: epoll_ctl(%d, ADD, %d, ev) failed (%d)",
                 __FUNCTION__, epoll_fdi->fd, fd_fdi->fd, errno));
  CI_FREE_OBJ(eitem);

  if( ep->epfd_syncs_needed )
    citp_ul_epoll_ctl_sync(ep, epoll_fdi->fd);
}


void citp_epoll_on_close(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                         int fdt_locked)
{
  struct citp_epoll_member* eitem = NULL;
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);
  citp_socket* sock;
  ci_netif* ni;

  if( citp_fdinfo_is_socket(fd_fdi) ) {
    sock = fdi_to_socket(fd_fdi);

    oo_wqlock_lock(&ep->dead_stack_lock);
    eitem = CI_USER_PTR_GET(sock->s->b.eitem);

    /* Only remove home members from the set here, because this hook is only
     * guaranteed to be called for home sockets as we only remember one epoll
     * set we've been added to.
     */
    if( eitem && (sock->s->b.eitem_pid == getpid()) &&
        (eitem->ready_list_id > 0) ) {
      Log_POLL(ci_log("%s: epoll_fd=%d fd=%d",
                      __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd));
      /* At this point any of the eitem, sock buf, or fdinfo may still be in
       * use. As such we just add the socket to the dead sockets list here.
       * We can only free the eitem at a point where we hold the epoll lock,
       * if needed.  For now we just bung this on the dead list, to be
       * processed later.
       */
      fd_fdi->epoll_fd = -1;
      sock->s->b.eitem_pid = 0;

      ni = sock->netif;
      ci_netif_lock(ni);
      sock->s->b.ready_list_id = 0;
      ci_ni_dllist_remove_safe(ni, &sock->s->b.ready_link);
      ci_netif_unlock(ni);

      CI_USER_PTR_SET(sock->s->b.eitem, NULL);
      ci_dllist_push(&ep->dead_stack_sockets, &eitem->dead_stack_link);
    }
    oo_wqlock_unlock(&ep->dead_stack_lock, NULL, NULL);
  }
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
  if( eps->ordering_info ) {
    citp_fdinfo* fdi = citp_ul_epoll_member_to_fdi(eitem);
    struct timespec zero = {0, 0};
    ci_assert(fdi);
    eps->ordering_info[0].fdi = fdi;
    if( events & EPOLLIN )
      /* Grab the timestamp of the first data available. */
      citp_fdinfo_get_ops(fdi)->ordered_data(fdi, &zero,
                                        &eps->ordering_info[0].oo_event.ts,
                                        &eps->ordering_info[0].oo_event.bytes);
    ++eps->ordering_info;
  }

  ci_assert(eitem->item_list == &eps->ep->oo_sockets ||
            eitem->item_list == &eps->ep->oo_stack_sockets);
  ci_dllist_remove_safe(&eitem->dllink);
  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);
  if( eitem->epoll_data.events & (EPOLLONESHOT | EPOLLET) )
    eps->has_epollet = 1;
  if( eitem->epoll_data.events & EPOLLONESHOT ) {
    eitem->epoll_data.events = 0;
    if( ! citp_eitem_is_synced(eitem) )
      ++(eps->ep->epfd_syncs_needed);
  }
  ci_dllist_push_tail(eitem->item_list, &eitem->dllink);
}


int
citp_ul_epoll_find_events(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq,
                          volatile ci_uint64* sleep_seq_p,
                          int* seq_mismatch)
{
  if( eitem->epoll_data.events & EPOLLET ) {
    ci_sleep_seq_t polled_sleep_seq;
    if( sleep_seq != *sleep_seq_p ) {
      *seq_mismatch = 1;
      return 0;
    }
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


/* Gets the limiting timestamp for a netif, the earliest if the earliest
 * parameter is true, else the latest.
 */
static void citp_epoll_netif_limit(ci_netif* ni, struct timespec* ts_out,
                                   int earliest)
{
  ci_netif_state_nic_t* nsn = &ni->state->nic[0];
  int intf_i;
  int check = earliest ? -1 : 1;

  ts_out->tv_sec = nsn->last_rx_timestamp.tv_sec;
  ts_out->tv_nsec = nsn->last_rx_timestamp.tv_nsec;
  for( intf_i = 1; intf_i < oo_stack_intf_max(ni); ++intf_i ) {
    nsn = &ni->state->nic[intf_i];

    if( citp_oo_timespec_compare(&nsn->last_rx_timestamp, ts_out) == check ) {
      ts_out->tv_sec = nsn->last_rx_timestamp.tv_sec;
      ts_out->tv_nsec = nsn->last_rx_timestamp.tv_nsec;
    }
  }
}


static void citp_epoll_latest_rx(ci_netif* ni, struct timespec* ts_out)
{
  citp_epoll_netif_limit(ni, ts_out, 0);
}

static void citp_epoll_earliest_rx(ci_netif* ni, struct timespec* ts_out)
{
  citp_epoll_netif_limit(ni, ts_out, 1);
}


static void citp_epoll_get_ordering_limit(ci_netif* ni,
                                          struct timespec* limit_out)
{
  struct timespec base_ts;

  ci_netif_lock(ni);
  citp_epoll_latest_rx(ni, &base_ts);
  ci_netif_poll(ni);
  citp_epoll_earliest_rx(ni, limit_out);
  ci_netif_unlock(ni);

  if( citp_timespec_compare(&base_ts, limit_out) > 0 ) {
    limit_out->tv_sec = base_ts.tv_sec;
    limit_out->tv_nsec = base_ts.tv_nsec;
  }

  Log_POLL(ci_log("%s: poll limit %lu:%09lu", __FUNCTION__,
                  limit_out->tv_sec, limit_out->tv_nsec));
}


int citp_epoll_ordering_compare(const void* a, const void* b)
{
  return citp_timespec_compare(
                          &((const struct citp_ordering_info*)a)->oo_event.ts,
                          &((const struct citp_ordering_info*)b)->oo_event.ts);
}


int citp_epoll_sort_results(struct epoll_event*__restrict__ events,
                            struct epoll_event*__restrict__ wait_events,
                            struct onload_ordered_epoll_event* oo_events,
                            struct citp_ordering_info* ordering_info,
                            int ready_socks, int maxevents,
                            struct timespec* limit)
{
  int i;
  int ordered_events = 0;
  struct timespec next;
  struct timespec* next_data_limit;
  if( ready_socks < maxevents )
    maxevents = ready_socks;

  /* Update ordering info to point at the corresponding event, so that we know
   * which event it corresponds to after sorting.
   */
  for( i = 0; i < ready_socks; i++ )
    ordering_info[i].event = &wait_events[i];

  /* Sort list of ready sockets based on timestamp of next available data. */
  qsort(ordering_info, ready_socks, sizeof(*ordering_info),
        citp_epoll_ordering_compare);

  /* Working from head of list, copy ordered data into output array, stopping
   * when any of the following conditions are true:
   * - we have filled the output event array (i == maxevents)
   * - the timestamp for the current event is after the limit
   * - a ready socket has additional data that is earlier than the next socket's
   *
   * If a socket has additional data that is after the next socket's, but
   * still earlier than the limit, then reduce the limit to that timestamp.
   */
  for( i = 0; i < maxevents; i++ ) {
    /* If this event has a valid timestamp, then get ordering data for it. */
    if( ordering_info[i].oo_event.ts.tv_sec != 0 ) {
      /* If this event is after the limit, stop here. */
      if( citp_timespec_compare(limit, &ordering_info[i].oo_event.ts) < 0 )
        break;

      /* If there is another ready socket then use the start of their data
       * to bound the amount we claim as available from this socket.
       */
      if( (i + 1) < ready_socks && ordering_info[i + 1].oo_event.ts.tv_sec &&
          citp_timespec_compare(&ordering_info[i + 1].oo_event.ts, limit) < 0 )
        next_data_limit = &ordering_info[i + 1].oo_event.ts;
      else
        next_data_limit = limit;

      /* Get the number of bytes available in order, and the timestamp of the
       * first data that is after that.
       */
      if( ordering_info[i].fdi )
        citp_fdinfo_get_ops(ordering_info[i].fdi)->ordered_data(
                                       ordering_info[i].fdi, next_data_limit,
                                       &next, &ordering_info[i].oo_event.bytes);

      /* If we have more data then don't let us return anything beyond that. */
      if( next.tv_sec && citp_timespec_compare(&next, limit) < 0 )
        *limit = next;
    }

    memcpy(&events[i], ordering_info[i].event, sizeof(struct epoll_event));
    memcpy(&oo_events[i], &ordering_info[i].oo_event,
           sizeof(struct onload_ordered_epoll_event));
    ordered_events++;
  }
  Log_POLL(ci_log("%s: got %d ordered events", __FUNCTION__, ordered_events));

  return ordered_events;
}

int citp_epoll_ordered_wait(citp_fdinfo* fdi,
                            struct epoll_event*__restrict__ events,
                            struct onload_ordered_epoll_event* oo_events,
                            int maxevents, int timeout, const sigset_t *sigmask,
                            citp_lib_context_t *lib_context)
{
  int rc;
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct citp_epoll_member* eitem;
  citp_fdinfo* sock_fdi = NULL;
  citp_sock_fdi* sock_epi = fdi_to_sock_fdi(fdi);
  ci_netif* ni = NULL;
  struct timespec limit_ts = {0, 0};
  struct citp_ordering_info* ordering_info = NULL;
  struct epoll_event* wait_events = NULL;
  struct citp_ordered_wait wait;
  int n_socks;

  Log_POLL(ci_log("%s(%d, max_ev=%d, timeout=%d) ul=%d dead=%d syncs=%d",
                  __FUNCTION__, fdi->fd, maxevents, timeout,
                  ! ci_dllist_is_empty(&ep->oo_sockets),
                  ! ci_dllist_is_empty(&ep->dead_sockets),
                  ep->epfd_syncs_needed));

  CITP_EPOLL_EP_LOCK(ep);

  /* We need to consider all accelerated sockets in the set.  We drop the lock
   * before polling the sockets, so it's possible to increase the size of the
   * set during this call, and not have all sockets considered.
   *
   * It's possible that the set also contains un-accelerated fds, so if
   * maxevents is bigger than the number of accelerated fds then we'll use
   * that value.
   */
  n_socks = CI_MAX(maxevents,
                   ep->home_stack ? ep->oo_stack_sockets_n : ep->oo_sockets_n);
  ordering_info = ci_calloc(n_socks, sizeof(*ordering_info));
  wait_events = ci_calloc(n_socks, sizeof(*wait_events));

  if( !ordering_info || !wait_events ) {
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    citp_exit_lib(lib_context, FALSE);
    free(ordering_info);
    free(wait_events);
    errno = ENOMEM;
    return -1;
  }

  if( ep->home_stack ) {
    ni = ep->home_stack;
  }
  else if( ci_dllist_not_empty(&ep->oo_sockets) ) {
    ci_dllink *link;
    ci_assert(ep->oo_sockets_n);

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    CI_DLLIST_FOR_EACH(link, &ep->oo_sockets) {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, link);

      ci_assert_lt(eitem->fd, citp_fdtable.inited_count);

      /* Use the first orderable socket we find to select the netif to use
       * for ordering.
       */
      if(CI_LIKELY( (sock_fdi = citp_ul_epoll_member_to_fdi(eitem)) != NULL )) {
        if( citp_fdinfo_is_socket(sock_fdi) ) {
          sock_epi = fdi_to_sock_fdi(sock_fdi);
          ni = sock_epi->sock.netif;
          break;
        }
      }
    }

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  FDTABLE_ASSERT_VALID();

  CITP_EPOLL_EP_UNLOCK(ep, 0);

  if( ni )
    citp_epoll_get_ordering_limit(ni, &limit_ts);

  wait.poll_again = 0;
  wait.ordering_info = ordering_info;
  /* citp_epoll_wait will do citp_exit_lib */
  rc = citp_epoll_wait(fdi, wait_events, ni ? &wait : NULL,
                       n_socks, timeout, sigmask, lib_context);
  if( rc < 0 )
    goto out;

  /* If we ended up going via the kernel we won't have the info we need for
   * the ordering - but the fds will be ready next time the user does a wait.
   */
  if( wait.poll_again ) {
    ci_assert( ni );
    Log_POLL(ci_log("%s: need repoll at user level", __FUNCTION__));
    citp_epoll_get_ordering_limit(ni, &limit_ts);

    citp_reenter_lib(lib_context);
    rc = citp_epoll_wait(fdi, wait_events, &wait, n_socks,
                         wait.next_timeout, sigmask, lib_context);
  }

  if( rc > 0 )
    rc = citp_epoll_sort_results(events, wait_events, oo_events, ordering_info,
                                 rc, maxevents, &limit_ts);

out:
  ci_free(ordering_info);
  ci_free(wait_events);
  return rc;
}


#endif  /* CI_CFG_USERSPACE_EPOLL */
