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
** \author  djr/ctk
**  \brief  Sockets interface to user level TCP
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <internal.h>
#include <netinet/in.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/ul/tcp_helper.h>


#define VERB(x)


int apply_fcntl_to_os_sock(citp_sock_fdi* epi, int fd,
                           int cmd, int arg, int *fcntl_result)
{
  /* If we have an OS sock associated with this socket, then apply
  ** fcntl() to it and return the result in fcntl_result.  The rc of
  ** the function is the os_sock or error.
  */
  int rc;

  if( (epi->sock.s->b.state & CI_TCP_STATE_TCP_CONN) &&
      (SOCK_TO_TCP(epi->sock.s)->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED) ) {
    *fcntl_result = 0;
    return 0;
  }

  rc = ci_get_os_sock_fd(&epi->sock, fd);
  if( CI_IS_VALID_SOCKET(rc)) {
    *fcntl_result = ci_sys_fcntl(rc, cmd, arg);
    ci_rel_os_sock_fd(rc);
  }
  else {
    /* Only errors that are possible are:
     *   i) There is no OS socket (handled above)
     *  ii) There are no more file-descriptors available (ENFILE)
     * We wouldn't expect ii normally, though i can happen on some apps
     */
    ci_assert_equal(rc, -ENFILE);
  }
  return rc;
}


static unsigned fd_flags_to_sbflags(int fd_flags)
{
  unsigned sbflags = 0;
  if( fd_flags & O_ASYNC    )  sbflags |= CI_SB_AFLAG_O_ASYNC;
  if( fd_flags & O_APPEND   )  sbflags |= CI_SB_AFLAG_O_APPEND;
  if( fd_flags & O_NONBLOCK )  sbflags |= CI_SB_AFLAG_O_NONBLOCK;
  if( fd_flags & O_NDELAY   )  sbflags |= CI_SB_AFLAG_O_NDELAY;
  return sbflags;
}


static int sbflags_to_fd_flags(unsigned sbflags)
{
  int fd_flags = 0;
  if( sbflags & CI_SB_AFLAG_O_ASYNC    )  fd_flags |= O_ASYNC;
  if( sbflags & CI_SB_AFLAG_O_APPEND   )  fd_flags |= O_APPEND;
  if( sbflags & CI_SB_AFLAG_O_NONBLOCK )  fd_flags |= O_NONBLOCK;
  if( sbflags & CI_SB_AFLAG_O_NDELAY   )  fd_flags |= O_NDELAY;
  return fd_flags;
}


int citp_sock_fcntl(citp_sock_fdi *epi, int fd, int cmd, long arg)
{
  ci_sock_cmn* s = epi->sock.s;
  int rc = 0, fcntl_result;

  Log_VSC(log("%s("EF_FMT", %#x, %#lx)", __FUNCTION__, EF_PRI_ARGS(epi,fd),
              (unsigned)cmd, (unsigned long)arg));

  switch( cmd ) {

  case F_GETFL: {
    rc = sbflags_to_fd_flags(s->b.sb_aflags) | O_RDWR;
    break;
  }

  case F_SETFL: {
    /* Set the descriptor's flags.  Only O_APPEND, O_NONBLOCK, O_ASYNC
    ** (linux only) can be set.  O_DIRECT provokes EINVAL, whereas other
    ** flags are ignored silently.
    */
    ci_uint32 mask = (CI_SB_AFLAG_O_APPEND | CI_SB_AFLAG_O_NONBLOCK |
                      CI_SB_AFLAG_O_NDELAY);
    mask |= CI_SB_AFLAG_O_ASYNC;
    if( arg & O_DIRECT ) {
      CI_SET_ERROR(rc, EINVAL);
      break;
    }
    ci_atomic32_merge(&s->b.sb_aflags, fd_flags_to_sbflags(arg), mask);
    /* Apply to this fd and also the OS socket.  NB. Listening OS socket
     * must always be non-blocking.
     */
    ci_sys_fcntl(fd, cmd, arg);
    if( s->b.state == CI_TCP_LISTEN )
      arg |= O_NONBLOCK | O_NDELAY;
    apply_fcntl_to_os_sock(epi, fd, cmd, arg, &fcntl_result);
    break;
  }

  case F_GETOWN:
    /* get the process ID/group that is receiving signals for this fd */
    rc = s->b.sigown;
    break;

  case F_SETOWN:
    /* On Solaris, fcntl(fd, F_SETOWN, arg) returns error
     * for non-socket fd's */
    rc = ci_sys_fcntl(fd, cmd, arg);
    if( rc != 0 )
        break;
    s->b.sigown = arg;
    /* Keep O/S socket up-to-date. */
    apply_fcntl_to_os_sock(epi, fd, cmd, arg, &fcntl_result);
    if( s->b.sigown && (s->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;

  case F_GETSIG:
    rc = s->b.sigsig;
    break;

  case F_SETSIG:
    if( (rc = ci_sys_fcntl(fd, cmd, arg)) != 0 )
      break;
    s->b.sigsig = arg;
    apply_fcntl_to_os_sock(epi, fd, cmd, arg, &fcntl_result);
    break;

  case F_DUPFD:
    rc = citp_ep_dup(fd, citp_ep_dup_fcntl_dup, arg);
    break;
#ifdef F_DUPFD_CLOEXEC
  case F_DUPFD_CLOEXEC:
    rc = citp_ep_dup(fd, citp_ep_dup_fcntl_dup_cloexec, arg);
    break;
#endif

  case F_GETFD:
  case F_SETFD:
    rc = ci_sys_fcntl(fd, cmd, arg);
    break;

  case F_GETLK:
  case F_SETLK:
  case F_SETLKW:
    /* File locks not supported on sockets */
    Log_U(ci_log("%s: "EF_FMT" cmd %d not supported on sockets!",__FUNCTION__,
                 EF_PRI_ARGS(epi, fd), cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;

  default:
    Log_U(ci_log("%s: "EF_FMT" unknown cmd %d", __FUNCTION__,
                 EF_PRI_ARGS(epi, fd), cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;
  }

  Log_VSC(log("%s(%d, %d, %ld) = %d  (errno=%d)",
	      __FUNCTION__, fd, cmd, arg, rc, errno));

  return rc;
}

/*! \cidoxg_end */
