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

#ifndef __UNIX_UL_EPOLL_H__
#define __UNIX_UL_EPOLL_H__

#if !CI_CFG_USERSPACE_EPOLL
#error "Do not include onload/epoll.h when epoll is not enabled"
#endif

#include <sys/epoll.h>
#include <onload/ul/wqlock.h>
#include "internal.h"
#include "ul_poll.h"
#include "nonsock.h"


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

ci_inline citp_fdinfo*
citp_epoll_fdi_from_member(citp_fdinfo* fd_fdi, int fdt_locked)
{
  citp_fdinfo* epoll_fdi = citp_fdtable_lookup_noprobe(fd_fdi->epoll_fd);
  if( epoll_fdi == NULL ) {
    Log_POLL(ci_log("%s: epoll_fd=%d not found (fd=%d)", __FUNCTION__,
                    fd_fdi->epoll_fd, fd_fdi->fd));
    return NULL;
  }
  if( epoll_fdi->seq != fd_fdi->epoll_fd_seq ||
      ( epoll_fdi->protocol->type != CITP_EPOLL_FD &&
        epoll_fdi->protocol->type != CITP_EPOLLB_FD ) ) {
    Log_POLL(ci_log("%s: epoll_fd=%d changed (type=%d seq=%llx,%llx fd=%d)",
                    __FUNCTION__, fd_fdi->epoll_fd, epoll_fdi->protocol->type,
                    (unsigned long long) epoll_fdi->seq,
                    (unsigned long long) fd_fdi->epoll_fd_seq, fd_fdi->fd));
    citp_fdinfo_release_ref(epoll_fdi, fdt_locked);
    return NULL;
  }

  return epoll_fdi;
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
  ci_dllink             dead_stack_link; /*!< Link for dead stack list */
  ci_dllist*            item_list;  /*!< The list this member belong on */
  int                   ready_list_id;
  struct epoll_event    epoll_data;
  struct epoll_event    epfd_event; /*!< event synchronised to kernel */
  ci_uint64             fdi_seq;    /*!< fdi->seq */
  int                   fd;         /*!< Onload fd */
  ci_sleep_seq_t        reported_sleep_seq;
};


#define EPOLL_STACK_EITEM 1
#define EPOLL_NON_STACK_EITEM 2
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

  /* Lock for and [dead_stack_sockets].  fdtable lock must be taken
   * after this one to avoid deadlock.
   */
  struct oo_wqlock      dead_stack_lock;

  /* List of onload sockets in home stack (struct citp_epoll_member) */
  ci_dllist             oo_stack_sockets;
  ci_dllist             oo_stack_not_ready_sockets;
  int                   oo_stack_sockets_n;

  /* List of onload sockets in non-home stack (struct citp_epoll_member) */
  ci_dllist             oo_sockets;
  int                   oo_sockets_n;

  /* List of deleted sockets (struct citp_epoll_member) */
  ci_dllist             dead_sockets;
  ci_dllist             dead_stack_sockets;

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

  ci_netif* home_stack;
  int ready_list;
};


typedef struct {
  citp_fdinfo           fdinfo;
  struct citp_epoll_fd* epoll;
} citp_epoll_fdi;

#define fdi_to_epoll_fdi(fdi)  CI_CONTAINER(citp_epoll_fdi, fdinfo, (fdi))
#define fdi_to_epoll(fdi)      (fdi_to_epoll_fdi(fdi)->epoll)

struct citp_ordering_info {
  struct epoll_event* event;
  struct onload_ordered_epoll_event oo_event;
  struct timespec next_rx_ts;
  citp_fdinfo* fdi;
};

struct citp_ordered_wait {
  struct citp_ordering_info* ordering_info;
  int poll_again;
  int next_timeout;
};

/* Epoll state in user-land poll.  Copied from oo_ul_poll_state */
struct oo_ul_epoll_state {
  /* Parameters of this epoll fd */
  struct citp_epoll_fd*__restrict__ ep;

  /* Where to store events. */
  struct epoll_event*__restrict__ events;

  /* End of the [events] array. */
  struct epoll_event*__restrict__ events_top;

  /* Information associated with ordering. */
  struct citp_ordering_info* ordering_info;

  /* Timestamp for the beginning of the current poll.  Used to avoid doing
   * ci_netif_poll() on stacks too frequently.
   */
  ci_uint64             this_poll_frc;

  /* Whether or not this call should spin */
  unsigned              ul_epoll_spin;

  /* We have found some EPOLLET or EPOLLONESHOT events, and they can not be
   * dropped. */
  int                   has_epollet;

#if CI_CFG_SPIN_STATS
  /* Have we incremented statistics for this spin round? */
  int stat_incremented;
#endif
};


extern int citp_epoll_create(int size, int flags) CI_HF;
extern int citp_epoll_ctl(citp_fdinfo* fdi, int op, int fd,
                          struct epoll_event *event) CI_HF;
extern int citp_epoll_wait(citp_fdinfo*, struct epoll_event*,
                           struct citp_ordered_wait* ordering,
                           int maxev, int timeout, const sigset_t *sigmask,
                           citp_lib_context_t*) CI_HF;
extern void citp_epoll_on_move(citp_fdinfo*, citp_fdinfo*, citp_fdinfo*,
                               int fdt_locked) CI_HF;
extern void citp_epoll_on_handover(citp_fdinfo*, citp_fdinfo*,
                                   int fdt_locked) CI_HF;
extern void citp_epoll_on_close(citp_fdinfo*, citp_fdinfo*,
                                int fdt_locked) CI_HF;

struct onload_ordered_epoll_event;
extern int citp_epoll_ordered_wait(citp_fdinfo* fdi,
                                   struct epoll_event*__restrict__ events,
                                   struct onload_ordered_epoll_event* oo_events,
                                   int maxevents, int timeout,
                                   const sigset_t *sigmask,
                                   citp_lib_context_t *lib_context);
extern void citp_epoll_remove_if_not_ready(struct oo_ul_epoll_state* eps,
                                           struct citp_epoll_member* eitem,
                                           ci_netif* ni, citp_waitable* w);


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
citp_ul_epoll_find_events(struct oo_ul_epoll_state* eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq,
                          volatile ci_uint64* sleep_seq_p, int* seq_mismatch);

/* Function to be called at the end of citp_protocol_impl->epoll()
 * function, when UL reports events "mask".
 *
 * sleep_seq should be the value of *sleep_seq_p taken _before_
 * looking for events.
 *
 * Returns true if an event was stored, else false.
 */
ci_inline int
citp_ul_epoll_set_ul_events(struct oo_ul_epoll_state*__restrict__ eps,
                            struct citp_epoll_member*__restrict__ eitem,
                            unsigned events, ci_uint64 sleep_seq,
                            volatile ci_uint64* sleep_seq_p,
                            int* seq_mismatch)
{
  Log_POLL(
    if( events )
      ci_log("%s: member=%llx mask=%x events=%x report=%x",
               __FUNCTION__, (long long) eitem->epoll_data.data.u64,
                 eitem->epoll_data.events, events,
                   eitem->epoll_data.events & events)
          );
  events &= eitem->epoll_data.events;
  return events ?
      citp_ul_epoll_find_events(eps, eitem, events,
                                sleep_seq, sleep_seq_p, seq_mismatch) : 0;
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

extern void citp_epollb_on_handover(citp_fdinfo*, citp_fdinfo*) CI_HF;

#endif /* __UNIX_UL_EPOLL_H__ */
