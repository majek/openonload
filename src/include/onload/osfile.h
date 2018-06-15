/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
** \author  djr/cgg
**  \brief  Abstraction of type used by operating system to represent a file
**   \date  2006/11/15
**    \cop  (c) 2003-2005 Level 5 Networks Limited.
**              2006 Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef _CI_DRIVER_EFAB_OSFILE_H_
#define _CI_DRIVER_EFAB_OSFILE_H_

#include <onload/sock_p.h>


/* This file contains the definition of types - not operations */


/* Used to hold a reference to an O/S socket.  It is needed because we
 * sometimes need to drop a reference when in atomic context, and fput()
 * (on Linux at least) cannot be done at such times, so we need to defer.
 * This gives us a "next" field so we can put it on a list.
 */
struct oo_file_ref {
  struct file*        file;
  struct oo_file_ref* next;
};


#ifdef __KERNEL__

#  include <ci/driver/internal.h>
#  define CI_OS_FILE_BAD ((struct file *)NULL)
   typedef struct file * ci_os_file;



#endif


#ifndef __KERNEL__
# define CI_OS_FILE_BAD ((ci_uintptr_t)0)
  typedef int ci_os_file;
#endif


typedef ci_os_file oo_os_file;


#ifdef __KERNEL__
struct tcp_helper_endpoint_s;
extern int oo_os_sock_get_from_ep(struct tcp_helper_endpoint_s* ep,
                                  oo_os_file* os_sock_out) CI_HF;
static inline void oo_os_sock_put(oo_os_file os_sock)
{
  ci_assert(!in_atomic());
  fput(os_sock);
}
#define OO_OS_SOCKET_FOP(ep, os_sock, rc, fop, ...) \
  do {                                              \
    rc = oo_os_sock_get_from_ep(ep, &os_sock);      \
    if( rc == 0 ) {                                 \
      rc = os_sock->f_op->fop(os_sock, __VA_ARGS__);\
      oo_os_sock_put(os_sock);                      \
    }                                               \
  } while(0)

#endif
extern int  oo_os_sock_get(struct ci_netif_s*, oo_sp, oo_os_file* out) CI_HF;

extern int oo_os_sock_sendmsg(struct ci_netif_s*, oo_sp,
                              const struct msghdr*, int flags) CI_HF;
extern int oo_os_sock_sendmsg_raw(ci_netif* ni, oo_sp sock_p,
                                  const struct msghdr* msg, int flags) CI_HF;
extern int oo_os_sock_recvmsg(struct ci_netif_s*, oo_sp,
                              struct msghdr*, int flags) CI_HF;

extern int oo_os_sock_accept(ci_netif* ni, oo_sp sock_p,
                             struct sockaddr *addr, socklen_t *addrlen,
                             int flags);

/* Invoke ioctl() on the os socket.  If [ioctl_rc_opt] is not null, then
 * the result of the ioctl() call is stored there, and the return value of
 * the function reflects any errors returned by oo_os_sock_get().
 * Otherwise the result of the ioctl() call is returned.
 */
extern int oo_os_sock_ioctl(ci_netif*, oo_sp, int request, void* arg,
                            int* ioctl_rc_opt) CI_HF;


#ifdef __KERNEL__
extern struct oo_file_ref* oo_file_ref_add(struct oo_file_ref*);
extern void oo_file_ref_drop(struct oo_file_ref*);
extern int  oo_file_ref_lookup(struct file*, struct oo_file_ref**);
extern void oo_file_ref_drop_list_now(struct oo_file_ref*);
#define oo_file_ref_xchg(pp, fr)                        \
  ((struct oo_file_ref*) ci_xchg_uintptr((pp), (ci_uintptr_t) (fr)))
#endif

#if defined(__KERNEL__) && defined(__linux__)
/* Used to poll OS socket for OS events. */
struct oo_os_sock_poll {
  wait_queue_entry_t wait;
  struct file *file;
  spinlock_t lock;
};
static inline wait_queue_head_t *
oo_os_sock_to_wait_queue_head(struct file *os_file)
{
#ifdef EFRM_HAVE_SK_SLEEP_FUNC
  return sk_sleep(SOCKET_I(os_file->f_dentry->d_inode)->sk);
#else
  return SOCKET_I(os_file->f_dentry->d_inode)->sk->sk_sleep;
#endif
}
static inline void
oo_os_sock_poll_register(struct oo_os_sock_poll *sock_poll,
                         struct file *os_file)
{
  struct file *old_file = NULL;

  if( os_file )
    get_file(os_file);
  spin_lock_bh(&sock_poll->lock);
  if( sock_poll->file != NULL ) {
    remove_wait_queue(oo_os_sock_to_wait_queue_head(sock_poll->file),
                      &sock_poll->wait);
    old_file = sock_poll->file;
  }
  sock_poll->file = os_file;
  if( os_file )
    add_wait_queue(oo_os_sock_to_wait_queue_head(os_file), &sock_poll->wait);
  spin_unlock_bh(&sock_poll->lock);

  if( old_file )
    fput(old_file);
}
static inline void
oo_os_sock_poll_ctor(struct oo_os_sock_poll *sock_poll)
{
  spin_lock_init(&sock_poll->lock);
}

#endif

#endif /* _CI_DRIVER_EFAB_OSFILE_H_ */
