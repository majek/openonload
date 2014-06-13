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

#ifndef __UNIX_UL_EPOLL_H__
#define __UNIX_UL_EPOLL_H__

#if !CI_CFG_USERSPACE_EPOLL
#error "Do not include onload/epoll.h when epoll is not enabled"
#endif

#include <sys/epoll.h>
#include <onload/ul/wqlock.h>
#include "internal.h"
#include "ul_poll.h"


/*************************************************************************
 **************** Common general epoll-related code **********************
 *************************************************************************/

extern
int citp_epoll_fcntl(citp_fdinfo *fdi, int cmd, long arg);
extern
int citp_epoll_select(citp_fdinfo* fdinfo, int* n, int rd, int wr, int ex,
                      struct oo_ul_select_state*);
extern
int citp_epoll_poll(citp_fdinfo* fdinfo, struct pollfd* pfd,
                           struct oo_ul_poll_state* ps);
extern int citp_closedfd_socket(int domain, int type, int protocol);
extern
int citp_epoll_bind(citp_fdinfo* fdinfo,
                    const struct sockaddr* sa, socklen_t sa_len);
extern
int citp_epoll_listen(citp_fdinfo* fdinfo, int backlog);
extern
int citp_epoll_accept(citp_fdinfo* fdinfo,
                      struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                      citp_lib_context_t* lib_context);
extern
int citp_epoll_connect(citp_fdinfo* fdinfo,
                       const struct sockaddr* sa, socklen_t sa_len,
                       citp_lib_context_t* lib_context);
extern
int citp_epoll_connect(citp_fdinfo* fdinfo,
                       const struct sockaddr* sa, socklen_t sa_len,
                       citp_lib_context_t* lib_context);
extern
int citp_epoll_shutdown(citp_fdinfo* fdinfo, int how);
extern
int citp_epoll_getsockname(citp_fdinfo* fdinfo,
                           struct sockaddr* sa, socklen_t* p_sa_len);
extern
int citp_epoll_getpeername(citp_fdinfo* fdinfo,
                           struct sockaddr* sa, socklen_t* p_sa_len);
extern
int citp_epoll_getsockopt(citp_fdinfo* fdinfo, int level,
                          int optname, void* optval, socklen_t* optlen);
extern
int citp_epoll_setsockopt(citp_fdinfo* fdinfo, int level, int optname,
                          const void* optval, socklen_t optlen);
extern
int citp_epoll_recv(citp_fdinfo* fdinfo, struct msghdr* msg, int flags);
extern
int citp_epoll_send(citp_fdinfo* fdinfo, const struct msghdr* msg, int flags);
#if CI_CFG_RECVMMSG
extern
int citp_nosock_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg,
                         unsigned vlen, int flags,
                         const struct timespec *timeout);
#endif
#if CI_CFG_SENDMMSG
extern
int citp_nosock_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg,
                         unsigned vlen, int flags);
#endif
extern
int citp_epoll_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg,
                       int flags);
extern
int citp_epoll_zc_recv(citp_fdinfo* fdi,
                       struct onload_zc_recv_args* args);
extern
int citp_epoll_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg,
                              int flags);
extern
int citp_epoll_zc_recv_filter(citp_fdinfo* fdi,
                              onload_zc_recv_filter_callback filter,
                              void* cb_arg, int flags);
extern
int citp_epoll_tmpl_alloc(citp_fdinfo* fdi, struct iovec* initial_msg,
                          int mlen, struct oo_msg_template** omt_pp,
                          unsigned flags);
extern
int citp_epoll_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                           struct onload_template_msg_update_iovec* updates,
                           int ulen, unsigned flags);
extern
int citp_epoll_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt);


static inline int ci_sys_epoll_create_compat(int size, int flags, int cloexec)
{
  int rc;
  int fd;

#ifdef EPOLL_CLOEXEC
  if( cloexec )
    flags |= EPOLL_CLOEXEC;

  /* Yes, it is VERY likely.  But if you compile with new libc, but run
   * with the old one, you get assert in citp_enter_lib. */
  if( flags && CI_LIKELY( ci_sys_epoll_create1 != epoll_create1 ) ) {
    rc = ci_sys_epoll_create1(flags);

    /* ENOSYS means that kernel is older than libc; fall through
     * to the old epoll_create(). */
    if( rc >=0 || errno != ENOSYS )
      return rc;
  }

  /* EPOLL_CLOEXEC is known, but it failed somehow. */
  cloexec |= flags & EPOLL_CLOEXEC;
#endif

  fd = ci_sys_epoll_create(size);
  if( fd < 0 )
    return fd;
  if( ! cloexec )
    return fd;
  rc = ci_sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
  if( rc < 0 ) {
    Log_E(log("%s: fcntl(F_SETFD, FD_CLOEXEC) failed errno=%d",
              __FUNCTION__, errno));
    ci_sys_close(fd);
    return -1;
  }
  return fd;
}



/*************************************************************************
 **************** The first EPOLL implementation *************************
 *************************************************************************/

/* We rely on the fact that EPOLLxxx == POLLxxx.  Check it at build time! */
CI_BUILD_ASSERT(EPOLLOUT == POLLOUT);
CI_BUILD_ASSERT(EPOLLIN == POLLIN);


/*! Per-fd structure to keep in epoll file. */
struct citp_epoll_member {
  ci_dllink             dllink;     /*!< Double-linked list links */
  struct epoll_event    epoll_data;
  struct epoll_event    epfd_event; /*!< event synchronised to kernel */
  ci_uint64             fdi_seq;    /*!< fdi->seq */
  int                   fd;         /*!< Onload fd */
  ci_sleep_seq_t        reported_sleep_seq;
};


/*! Data associated with each epoll epfd.  */
struct citp_epoll_fd {
  /* epoll_create() parameter */
  int     size;

  /* Os file descriptor for alien (kernel) fds */
  int     epfd_os;
  struct oo_epoll1_shared *shared;

  /* Lock for [oo_sockets] and [dead_sockets].  fdtable lock must be taken
   * after this one to avoid deadlock.
   */
  struct oo_wqlock      lock;
  int                   not_mt_safe;

  /* List of onload sockets (struct citp_epoll_member) */
  ci_dllist             oo_sockets;

  /* List of deleted sockets (struct citp_epoll_member) */
  ci_dllist             dead_sockets;

  /* Refcount to increment at dup() time. */
  oo_atomic_t refcount;

  /* Number of changes to u/l members not yet synchronised with kernel. */
  int         epfd_syncs_needed;

  /* Is a thread in a blocking call to sys_epoll_wait() ?  This is used to
   * decide whether epoll_ctl() should be allowed to delay update of kernel
   * state (EF_EPOLL_CTL_FAST).
   */
  int         blocking;

  /* Avoid spinning in next epoll_pwait call */
  int avoid_spin_once;
};


typedef struct {
  citp_fdinfo           fdinfo;
  struct citp_epoll_fd* epoll;
} citp_epoll_fdi;

#define fdi_to_epoll_fdi(fdi)  CI_CONTAINER(citp_epoll_fdi, fdinfo, (fdi))
#define fdi_to_epoll(fdi)      (fdi_to_epoll_fdi(fdi)->epoll)


/* Epoll state in user-land poll.  Copied from oo_ul_poll_state */
struct oo_ul_epoll_state {
  /* Parameters of this epoll fd */
  struct citp_epoll_fd*__restrict__ ep;

  /* Where to store events. */
  struct epoll_event*__restrict__ events;

  /* End of the [events] array. */
  struct epoll_event*__restrict__ events_top;

  /* Timestamp for the beginning of the current poll.  Used to avoid doing
   * ci_netif_poll() on stacks too frequently.
   */
  ci_uint64             this_poll_frc;

  /* Whether or not this call should spin */
  unsigned              ul_epoll_spin;

  /* We have found some EPOLLET or EPOLLONESHOT events, and they can not be
   * dropped. */
  int                   has_epollet;
};


extern int citp_epoll_create(int size, int flags) CI_HF;
extern int citp_epoll_ctl(citp_fdinfo* fdi, int op, int fd,
                          struct epoll_event *event) CI_HF;
extern int citp_epoll_wait(citp_fdinfo*, struct epoll_event*,
                           int maxev, int timeout, const sigset_t *sigmask,
                           citp_lib_context_t*) CI_HF;
extern void citp_epoll_on_handover(citp_fdinfo*, int fdt_locked) CI_HF;


/* At time of writing, we never generate the following epoll events:
 *
 *  EPOLLRDHUP
 *  EPOLLRDBAND
 *  EPOLLMSG
 */
#define OO_EPOLL_READ_EVENTS   (EPOLLIN | EPOLLRDNORM | EPOLLPRI)
#define OO_EPOLL_WRITE_EVENTS  (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)
#define OO_EPOLL_HUP_EVENTS    (EPOLLHUP | EPOLLERR)

#define OO_EPOLL_ALL_EVENTS    (OO_EPOLL_READ_EVENTS  | \
                                OO_EPOLL_WRITE_EVENTS | \
                                OO_EPOLL_HUP_EVENTS)


int
citp_ul_epoll_find_events(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq);

/* Function to be called at the end of citp_protocol_impl->epoll()
 * function, when UL reports events "mask".
 *
 * Returns true if an event was stored, else false.
 */
ci_inline int
citp_ul_epoll_set_ul_events(struct oo_ul_epoll_state*__restrict__ eps,
                            struct citp_epoll_member*__restrict__ eitem,
                            unsigned events, ci_uint64 sleep_seq)
{
  Log_POLL(ci_log("%s: member=%llx mask=%x events=%x report=%x",
                  __FUNCTION__, (long long) eitem->epoll_data.data.u64,
                  eitem->epoll_data.events, events,
                  eitem->epoll_data.events & events));
  events &= eitem->epoll_data.events;
  return events ? citp_ul_epoll_find_events(eps, eitem, events, sleep_seq) : 0;
}


/*************************************************************************
 ******************* The EPOLL implementation B **************************
 *************************************************************************/

extern int citp_epollb_create(int size, int flags) CI_HF;
extern int citp_epollb_ctl(citp_fdinfo* fdi, int op, int fd,
                    struct epoll_event *event) CI_HF;
extern int citp_epollb_wait(citp_fdinfo* fdi, struct epoll_event *events,
                     int maxevents, int timeout, const sigset_t *sigmask,
                     citp_lib_context_t* lib_context) CI_HF;

extern void citp_epollb_on_handover(citp_fdinfo* fd_fdi) CI_HF;

#endif /* __UNIX_UL_EPOLL_H__ */
