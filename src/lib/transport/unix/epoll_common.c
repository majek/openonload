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
*//*! \file epoll_common.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  epoll-related functions common for different epoll implementations
**   \date  2011/02/14
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <ci/internal/transport_config_opt.h>


#define LPF      "citp_epoll:"

#if CI_CFG_USERSPACE_EPOLL

#include <ci/internal/transport_common.h>
#include "ul_epoll.h"

int citp_epoll_fcntl(citp_fdinfo *fdi, int cmd, long arg)
{
  switch( cmd ) {

  case F_DUPFD:
    return citp_ep_dup(fdi->fd, citp_ep_dup_fcntl_dup, arg);
#ifdef F_DUPFD_CLOEXEC
  case F_DUPFD_CLOEXEC:
    return citp_ep_dup(fdi->fd, citp_ep_dup_fcntl_dup_cloexec, arg);
#endif

  /* F_GETFL/F_SETFL, F_GETOWN/F_SETOWN, F_GETFD/F_SETFD,
   * F_GETLK/F_SETLK/F_SETLKW
   * have no effect on epoll fd, let's kernel report it together with
   * unknown fcntl cmds. */
  default:
    return ci_sys_fcntl(fdi->fd, cmd, arg);
  }
  /*UNREACHABLE*/
}

/* Poll/select via kernel */
int citp_epoll_select(citp_fdinfo* fdinfo, int* n, int rd, int wr, int ex,
                      struct oo_ul_select_state* ss)
{
  return 0;
}
int citp_epoll_poll(citp_fdinfo* fdinfo, struct pollfd* pfd,
                           struct oo_ul_poll_state* ps)
{
  return 0;
}

/* File operations which are "invalid" -- just pass them to OS in
 * appropriate way. */
int citp_epoll_bind(citp_fdinfo* fdinfo,
                    const struct sockaddr* sa, socklen_t sa_len)
{
  int rc = ci_sys_bind(fdinfo->fd, sa, sa_len);
  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}
int citp_epoll_listen(citp_fdinfo* fdinfo, int backlog)
{
  int rc = ci_sys_listen(fdinfo->fd, backlog);
  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}
int citp_epoll_accept(citp_fdinfo* fdinfo,
                      struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                      citp_lib_context_t* lib_context)
{
  return ci_sys_accept(fdinfo->fd, sa, p_sa_len);
}
int citp_epoll_connect(citp_fdinfo* fdinfo,
                       const struct sockaddr* sa, socklen_t sa_len,
                       citp_lib_context_t* lib_context)
{
  int rc = ci_sys_connect(fdinfo->fd, sa, sa_len);
  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}
int citp_epoll_shutdown(citp_fdinfo* fdinfo, int how)
{
  return ci_sys_shutdown(fdinfo->fd, how);
}
int citp_epoll_getsockname(citp_fdinfo* fdinfo,
                           struct sockaddr* sa, socklen_t* p_sa_len)
{
  return ci_sys_getsockname(fdinfo->fd, sa, p_sa_len);
}
int citp_epoll_getpeername(citp_fdinfo* fdinfo,
                           struct sockaddr* sa, socklen_t* p_sa_len)
{
  return ci_sys_getpeername(fdinfo->fd, sa, p_sa_len);
}
int citp_epoll_getsockopt(citp_fdinfo* fdinfo, int level,
                          int optname, void* optval, socklen_t* optlen)
{
  return ci_sys_getsockopt(fdinfo->fd, level, optname, optval, optlen);
}
int citp_epoll_setsockopt(citp_fdinfo* fdinfo, int level, int optname,
                          const void* optval, socklen_t optlen)
{
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
int citp_epoll_recv(citp_fdinfo* fdinfo, struct msghdr* msg, int flags)
{
  return ci_sys_recvmsg(fdinfo->fd, msg, flags);
}
int citp_epoll_send(citp_fdinfo* fdinfo, const struct msghdr* msg, int flags)
{
  return ci_sys_sendmsg(fdinfo->fd, msg, flags);
}
int citp_epoll_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg, 
                       int flags)
{
  msg->rc = -ENOTSOCK;
  return 1;
}
int citp_epoll_zc_recv(citp_fdinfo* fdi, 
                       struct onload_zc_recv_args* args)
{
  return -ENOTSOCK;
}
int citp_epoll_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg, 
                              int flags)
{
  return -ENOTSOCK;
}
int citp_epoll_zc_recv_filter(citp_fdinfo* fdi, 
                              onload_zc_recv_filter_callback filter,
                              void* cb_arg, int flags)
{
# if CI_CFG_ZC_RECV_FILTER
  return -ENOTSOCK;
# else
  return -ENOSYS;
# endif
}

int citp_epoll_tmpl_alloc(citp_fdinfo* fdi, struct iovec* initial_msg,
                         int mlen, struct oo_msg_template** omt_pp,
                         unsigned flags)
{
  return -EOPNOTSUPP;
}


int citp_epoll_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                          struct onload_template_msg_update_iovec* updates,
                          int ulen, unsigned flags)
{
  return -EOPNOTSUPP;
}


int citp_epoll_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt)
{
  return -EOPNOTSUPP;
}

#endif /* CI_CFG_USERSPACE_EPOLL */


#if CI_CFG_USERSPACE_EPOLL || CI_CFG_USERSPACE_PIPE

#if CI_CFG_RECVMMSG || CI_CFG_SENDMMSG
#include "internal.h"
#endif

#if CI_CFG_RECVMMSG
int citp_nosock_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                         unsigned vlen, int flags, 
                         const struct timespec *timeout)
{
  errno = ENOTSOCK;
  return -1;
}
#endif

#if CI_CFG_SENDMMSG
int citp_nosock_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                         unsigned vlen, int flags)
{
  errno = ENOTSOCK;
  return -1;
}
#endif
#endif

