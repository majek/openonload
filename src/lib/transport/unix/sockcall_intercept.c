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
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#define _GNU_SOURCE

#include "internal.h"
#if CI_CFG_USERSPACE_PIPE
#include "ul_pipe.h"
#endif
#include <onload/syscalls.h>

#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h> /* for getpid() */
#include <aio.h>
#include <alloca.h>


/*
** Other stuff to think about: sockatmark()
**
** Strong or weak symbols?  Some have to be strong (eg. __read, __write).
** What about the rest?  When does it matter?  (Possibly it only matters if
** there is another strong definition of the symbol somewhere in the symbol
** search space.)
**
** I believe that the linker will link with a strong symbol in preference
** to a weak one.  ie. It will choose to link with the first strong
** definition in the link search order.  If there are none, it will link
** with the first weak definition.
**
** Do we need more aliases?
**
** We probably ought to have some pthread_testcancel()s.  See
** valgrind/vg_libpthread.c.
*/

/*
** Convertion of send/receive calls to 'struct msghdr' rules.
**
** 1. Conversion must be lite weight as must as it possible:
**    If some parameter(s) may be kept uninitialized, do it.
**
** 2. Prepared messages may be forwarded to OS Socket layer.
**    OS (e.g. Linux) considers messages with NULL pointer parameter
**    and non-zero length parametes as invalid and returns EFAULT or
**    EINVAL. It works fine, if pointer is uninitialized and length
**    is equal to zero.
**
** 3. Uninitialized pointers must be intentionally initialized to
**    not NULL value in debugging build.
*/

#define CI_NOT_NULL     ((void *)-1)


#ifdef __GNUC__

# define strong_alias(name, aliasname) \
  extern __typeof (name) aliasname __attribute__ ((alias (#name)));

# define OO_INTERCEPT(ret, name, args)    ret onload_##name args

# define CI_MK_DECL(ret, fn, args)        strong_alias(onload_##fn, fn)
# include <onload/declare_syscalls.h.tmpl>

#else

# error Need support for this compiler.

#endif


/* Bug 22074: we use address space for purposes which application do not
 * expect.  Add following value to RLIMIT_AS:
 *
 * CI_PAGE_SIZE << ci_log2_le(ci_cfg_opts.netif_opts.max_ep_bufs) -
 * endpoint space.
 * sizeof(ci_netif) - ignore.
 * citp_fdtable.size * sizeof(citp_fdtable_entry) - citp_fdtable.
 * CI_CFG_PKT_BUF_SIZE * max_packets - packet buffers.
 *
 * Obviously, it is possible that the app uses multiple netifs...
 * From the other side, rare netif uses all endpoint and all packet spaces.
 * If we see such a problem, we'll think about it.
 */
#define OO_RLIMIT_AS_FIX(user_rlim, oo_rlim, rlim_inf, kind, format, \
                         format_cast) \
  do {                                                                  \
    oo_rlim = user_rlim +                                               \
      citp_fdtable.size * sizeof(citp_fdtable_entry) +                  \
      (CI_PAGE_SIZE << ci_log2_le(ci_cfg_opts.netif_opts.max_ep_bufs)) + \
      CI_CFG_PKT_BUF_SIZE * ci_cfg_opts.netif_opts.max_packets;         \
    if( oo_rlim < user_rlim ) /* Check for overflow */                  \
      oo_rlim = rlim_inf;                                               \
    ci_log("%s: RLIMIT_AS: "kind" limit requested "format               \
           ", but set to "format, __FUNCTION__,                         \
           (format_cast)user_rlim, (format_cast)oo_rlim);               \
    user_rlim = oo_rlim;                                                \
  } while(0)

OO_INTERCEPT(int, setrlimit,
             (__rlimit_resource_t resource, const struct rlimit* rlim))
{
  int rc;
  struct rlimit rl = *rlim;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_setrlimit(resource, rlim);
  }

  Log_CALL(ci_log("%s(%d, {cur %lx, max %lx})", __FUNCTION__, 
                  resource, rlim->rlim_cur, rlim->rlim_max));

  switch( resource) {
  case RLIMIT_NOFILE:
    if( rl.rlim_max > citp_fdtable.size ) {
      ci_log("%s: RLIMIT_NOFILE: hard limit requested %lu, but set to %u",
             __FUNCTION__, rl.rlim_max, citp_fdtable.size);
      rl.rlim_max = citp_fdtable.size;
    }
    if( rl.rlim_cur > rl.rlim_max ) {
      ci_log("%s: RLIMIT_NOFILE: soft limit requested %lu, but set to %lu",
             __FUNCTION__, rl.rlim_cur, rl.rlim_max);
      rl.rlim_cur = rl.rlim_max;
    }
    break;

  case RLIMIT_AS:
  {
    rlim_t lim;
    if( rl.rlim_max != RLIM_INFINITY ) {
      OO_RLIMIT_AS_FIX(rl.rlim_max, lim, RLIM_INFINITY, "hard", "%lu",
                       unsigned long);
    }
    if( rl.rlim_cur != RLIM_INFINITY ) {
      OO_RLIMIT_AS_FIX(rl.rlim_cur, lim, RLIM_INFINITY, "soft", "%lu",
                       unsigned long);
    }
    break;
  }

  default:
    /* Do nothing */
    break;
  }

  rc = ci_sys_setrlimit(resource, &rl);

  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(int, setrlimit64,
             (__rlimit_resource_t resource, const struct rlimit64* rlim))
{
  int rc;
  struct rlimit64 rl = *rlim;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_setrlimit64(resource, rlim);
  }

  Log_CALL(ci_log("%s(%d, {cur %llx, max %llx})", __FUNCTION__, 
                  resource, (unsigned long long) rlim->rlim_cur,
                  (unsigned long long) rlim->rlim_max));

  switch( resource) {
  case RLIMIT_NOFILE:
    if( rl.rlim_max > citp_fdtable.size ) {
      ci_log("%s: RLIMIT_NOFILE: hard limit requested %llu, but set to %u",
             __FUNCTION__, (unsigned long long) rl.rlim_max,
             citp_fdtable.size);
      rl.rlim_max = citp_fdtable.size;
    }
    if( rl.rlim_cur > rl.rlim_max ) {
      ci_log("%s: RLIMIT_NOFILE: soft limit requested %llu, but set to %llu",
             __FUNCTION__, (unsigned long long) rl.rlim_cur,
             (unsigned long long) rl.rlim_max);
      rl.rlim_cur = rl.rlim_max;
    }
    break;

  case RLIMIT_AS:
  {
    rlim64_t lim;
    if( rl.rlim_max != RLIM_INFINITY ) {
      OO_RLIMIT_AS_FIX(rl.rlim_max, lim, RLIM64_INFINITY, "hard", "%llu",
                       unsigned long long);
    }
    if( rl.rlim_cur != RLIM_INFINITY ) {
      OO_RLIMIT_AS_FIX(rl.rlim_cur, lim, RLIM64_INFINITY, "soft", "%llu",
                       unsigned long long);
    }
    break;
  }

  default:
    /* Do nothing */
    break;
  }

  rc = ci_sys_setrlimit64(resource, &rl);

  Log_CALL_RESULT(rc);
  return rc;
}
#endif
#undef OO_RLIMIT_AS_FIX


OO_INTERCEPT(int, socket,
             (int domain, int type, int protocol))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_socket(domain, type, protocol);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%s, %s, %d)", __FUNCTION__, domain_str(domain),
		  type_str(type), protocol));

  rc = citp_protocol_manager_create_socket(domain, type, protocol);
  
  if( rc == CITP_NOT_HANDLED ) {
    rc = ci_sys_socket(domain, type, protocol); /* NOTE: done inside ENTER_LIB
                                                   because of later operations
                                                   that may lock */
    citp_fdtable_passthru(rc, 0);
    Log_PT(log("PT: sys_socket(%d, %d, %d) = %d", domain, type, protocol, rc));
  }

  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, bind,
             (int fd, const struct sockaddr* sa, socklen_t sa_len))
{
  int rc;
  citp_fdinfo* fdi;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_bind(fd, sa, sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %p, %u)", __FUNCTION__, fd, sa, sa_len));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    /* NOTE
     * 1. All protocol handlers MUST do their own call to
     * citp_fdinfo_release_ref()
     * 2. After the call to the protocol bind handler the fd
     * and all associated resources may have been deleted
     */
    rc = citp_fdinfo_get_ops(fdi)->bind(fdi, sa, sa_len);
  }
  else {
    Log_PT(log("PT: sys_bind(%d, sa, %d)", fd, sa_len));
    rc = ci_sys_bind(fd, sa, sa_len); /* NOTE: done inside ENTER_LIB because
                                         of the FDTABLE_ASSERT_VALID*/
  }
  FDTABLE_ASSERT_VALID(); /* needs lock */
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, listen,
             (int fd, int backlog))
{
  int rc;
  citp_fdinfo* fdi;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_listen(fd, backlog);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %d)", __FUNCTION__, fd, backlog));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    /* NOTE
     * 1. All protocol handlers MUST do their own call to
     * citp_fdinfo_release_ref()
     * 2. After the call to the protocol listen handler the fd
     * and all associated resources may have been deleted
     */
    rc = citp_fdinfo_get_ops(fdi)->listen(fdi, backlog);
  }
  else {
    Log_PT(log("PT: sys_listen(%d, %d)", fd, backlog));
    rc = ci_sys_listen(fd, backlog); /* NOTE: done inside ENTER_LIB
                                        because of the FDTABLE_ASSERT_VALID
                                        that will lock */
  }

  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


static void oo_accept_os_hack_inheritance(int lfd, int afd)
{
  /* the following accept() inheritance options, which are provided   */
  /* in our library, also need to be emulated in the system socket    */
  /* calls - for consistency                                          */
#if !CI_CFG_ACCEPT_INHERITS_NONBLOCK
  if (CITP_OPTS.accept_force_inherit_nonblock) {
    int pflags = ci_sys_fcntl(lfd, F_GETFL);
    int flags = ((pflags & O_NONBLOCK) ? O_NONBLOCK : 0) |
                ((pflags & O_NDELAY) ? O_NDELAY : 0);
    int tmp = ci_sys_fcntl(afd, F_GETFL);

    if ((tmp & flags) == 0)
      CI_TRY(ci_sys_fcntl(afd, F_SETFL, tmp | flags));
  }
#endif

  /* No-delay */
#if !CI_CFG_ACCEPT_INHERITS_NODELAY
  /* no-delay will not have been inherited so we may need to turn it on */
  if (CITP_OPTS.accept_force_inherit_nodelay) {
    int nodelay;
    int size;

    CI_TRY(ci_sys_getsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &nodelay,
                             &size));
    CI_TEST(size == sizeof(nodelay));

    if (nodelay != 0)
      CI_TRY(ci_sys_setsockopt(afd, IPPROTO_TCP, TCP_NODELAY,
                               &nodelay, size));
  }
#endif

}

OO_INTERCEPT(int, accept,
             (int fd, struct sockaddr* sa, socklen_t* p_sa_len))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_accept(fd, sa, p_sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%p,%p)", __FUNCTION__, fd, sa, p_sa_len));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->accept(fdi, sa, p_sa_len, 0, &lib_context);
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    /* May block for a long time - stop deferring signals during syscall */
    citp_exit_lib(&lib_context, FALSE);
    rc = ci_sys_accept(fd, sa, p_sa_len);
    citp_reenter_lib(&lib_context);
    if( rc >= 0 ) {
      citp_fdtable_passthru(rc, 0);
      oo_accept_os_hack_inheritance(fd, rc);
    }
    Log_PT(log("PT: sys_accept(%d, , ) = %d", fd, rc >= 0));
  }
  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);

  Log_CALL_RESULT(rc);
  return rc;
}

#if CI_LIBC_HAS_accept4
OO_INTERCEPT(int, accept4,
             (int fd, struct sockaddr* sa, socklen_t* p_sa_len, int flags))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_accept(fd, sa, p_sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%p,%p,0x%x)", __FUNCTION__, fd, sa, p_sa_len, flags));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->accept(fdi, sa, p_sa_len, flags,
                                          &lib_context);
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    /* May block for a long time - stop deferring signals during syscall */
    citp_exit_lib(&lib_context, FALSE);
    rc = ci_sys_accept4(fd, sa, p_sa_len, flags);
    citp_reenter_lib(&lib_context);
    if( rc >= 0 ) {
      citp_fdtable_passthru(rc, 0);
      oo_accept_os_hack_inheritance(fd, rc);
    }
    Log_PT(log("PT: sys_accept(%d, , ) = %d", fd, rc >= 0));
  }
  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);

  Log_CALL_RESULT(rc);
  return rc;
}
#endif


OO_INTERCEPT(int, connect,
             (int fd, const struct sockaddr* sa, socklen_t sa_len))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_connect(fd, sa, sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(
     if( sa && sa_len >= sizeof(struct sockaddr_in) &&
         sa->sa_family == AF_INET )
       ci_log("%s(%d,AF_INET %s:%u,%u)", __FUNCTION__, fd,
              ip_addr_str(((struct sockaddr_in*)sa)->sin_addr.s_addr),
              CI_BSWAP_BE16(((struct sockaddr_in*)sa)->sin_port), sa_len);
     else
       ci_log("%s(%d,%p,%u)", __FUNCTION__, fd, sa, sa_len)
     );

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    {
      /* NOTE
       * 1. All protocol handlers MUST do their own call to
       * citp_fdinfo_release_ref()
       * 2. After the call to the protocol connect handler the fd
       * and all associated resources may have been deleted
       */
      rc = citp_fdinfo_get_ops(fdi)->connect(fdi, sa, sa_len, &lib_context);
    }
  }
  else {
    Log_PT(log("PT: sys_connect(%d, , %d)", fd, sa_len));
    /* May block for a long time - stop deferring signals during syscall */
    citp_exit_lib(&lib_context, FALSE);
    rc = ci_sys_connect(fd, sa, sa_len);
    citp_reenter_lib(&lib_context);
  }
  FDTABLE_ASSERT_VALID(); /* acquires lock, needs to be insider ENTER_LIB */

  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, shutdown,
             (int fd, int how))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_shutdown(fd, how);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%d)", __FUNCTION__, fd, how));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    /* Validate 'how' parameter at first. 
     * Solaris validates it after validation of the socket state. */
    if (!citp_shutdown_how_is_valid(how)) {
      errno = EINVAL;
      citp_fdinfo_release_ref(fdi, 0);
      citp_exit_lib(&lib_context, FALSE);
      Log_CALL_RESULT(-1);
      return -1;
    }

    rc = citp_fdinfo_get_ops(fdi)->shutdown(fdi, how);
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_shutdown(%d, %d)", fd, how));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_shutdown(fd, how);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, getsockname,
             (int fd, struct sockaddr* sa, socklen_t* p_sa_len))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_getsockname(fd, sa, p_sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %p, %p)", __FUNCTION__, fd, sa, p_sa_len));

  /* make sure we've been given a valid buffer: */
  if( !sa || !p_sa_len ) {
    errno = EFAULT;
    citp_exit_lib(&lib_context, FALSE);
    rc = -1;
  } else {
    if( (fdi = citp_fdtable_lookup(fd)) ) {
      {
        rc = citp_fdinfo_get_ops(fdi)->getsockname(fdi, sa, p_sa_len);
      }
      citp_fdinfo_release_ref(fdi, 0);
      citp_exit_lib(&lib_context, rc == 0);
    } else {
      Log_PT(log("PT: sys_getsockname(%d)", fd));
      citp_exit_lib(&lib_context, TRUE);
      rc = ci_sys_getsockname(fd, sa, p_sa_len);
    }
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, getpeername,
             (int fd, struct sockaddr* sa, socklen_t* p_sa_len))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_getpeername(fd, sa, p_sa_len);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%p,%p)", __FUNCTION__, fd, sa, p_sa_len));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    {
      rc = citp_fdinfo_get_ops(fdi)->getpeername(fdi, sa, p_sa_len);
    }
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_getpeername(%d)", fd));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_getpeername(fd, sa, p_sa_len);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, getsockopt,
             (int fd, int level, int optname, void* optval, socklen_t* optlen))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_getsockopt(fd, level, optname, optval, optlen);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %d, %d, %p, %p(%d))", __FUNCTION__, fd, level,
                  optname, optval, optlen, *(socklen_t *)optlen));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    if( CI_UNLIKELY((optlen == NULL) || (*(int *)optlen > 0 && optval == NULL)) ) {
      errno = EFAULT;
      rc = -1;
    } else {
      rc = citp_fdinfo_get_ops(fdi)->getsockopt(fdi,level,optname,optval,
                                                optlen);
    }
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_getsockopt(%d, %d, %d)", fd, level, optname));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_getsockopt(fd, level, optname, optval, optlen);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, setsockopt,
             (int fd, int level, int optname,
              const void* optval, socklen_t optlen))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_setsockopt(fd, level, optname, optval, optlen);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %d, %d, %p, %d)", __FUNCTION__, fd, level, optname,
                  optval, optlen));

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    /* ATTENTION: All protocol handlers MUST do their
     * own call to citp_fdinfo_release_ref(). */
    rc = citp_fdinfo_get_ops(fdi)->setsockopt(fdi,level,optname,optval,optlen);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_setsockopt(%d, %d, %d)", fd, level, optname));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_setsockopt(fd, level, optname, optval, optlen);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(ssize_t, recv,
             (int fd, void* buf, size_t len, int flags))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_recv(fd, buf, len, flags);
  }

  Log_CALL(ci_log("%s(%d, %p, %u, 0x%x)", __FUNCTION__, fd, buf, (unsigned)len, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = buf;
    iov[0].iov_len = len;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_name = CI_NOT_NULL);
    m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    /* msg_flags is output only */
    rc = citp_fdinfo_get_ops(fdi)->recv(fdi, &m, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_recv(%d, buf, %d, 0x%x)", fd, (int) len,
               (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_recv(fd, buf, len, flags);
  }
  Log_CALL_RESULT(rc);
  return rc;
}

#if CI_LIBC_HAS___recv_chk
OO_INTERCEPT(ssize_t, __recv_chk,
             (int fd, void* buf, size_t count, size_t buflen, int flags))
{
  if (count > buflen)
    ci_sys___read_chk(fd, buf, count, buflen);
  return onload_recv(fd, buf, count, flags);
}
#endif

OO_INTERCEPT(ssize_t, recvfrom,
             (int fd, void* buf, size_t len, int flags,
              struct sockaddr* from, socklen_t* fromlen))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_recvfrom(fd, buf, len, flags, from, fromlen);
  }

  Log_CALL(ci_log("%s(%d,%p,%u,0x%x,%p,%p)", __FUNCTION__,
                  fd, buf, (unsigned)len, flags, from, fromlen));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = buf;
    iov[0].iov_len = len;
    m.msg_name = from;
    /* if both parameters are zero then we shouldn't segfault here */
    if(CI_LIKELY( fromlen != NULL ))
      m.msg_namelen = *fromlen;
    else
      m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    /* msg_flags is output only */
    rc = citp_fdinfo_get_ops(fdi)->recv(fdi, &m, flags);
    if (fromlen != NULL && from != NULL) {
      *fromlen = m.msg_namelen;
    } else if (CI_UNLIKELY(rc >= 0 && fromlen == NULL && from != NULL)) {
      /* Socket tester "func_recvfrom_addr_null_(dgram|stream)" 
       * Linux errors *after* receipt with EFAULT when from!=NULL && 
       * fromlen==NULL */
      errno = EFAULT;
      rc = CI_SOCKET_ERROR;
    }
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_recvfrom(%d, buf, %d, 0x%x)", fd, (int) len,
               (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_recvfrom(fd, buf, len, flags, from, fromlen);
  }
  Log_CALL_RESULT(rc);
  return rc;
}

#if CI_LIBC_HAS___recvfrom_chk
OO_INTERCEPT(ssize_t, __recvfrom_chk,
             (int fd, void* buf, size_t count, size_t buflen, int flags,
              struct sockaddr* addr, socklen_t* addrlen))
{
  if (count > buflen)
    ci_sys___read_chk(fd, buf, count, buflen);
  return onload_recvfrom(fd, buf, count, flags, addr, addrlen);
}
#endif

OO_INTERCEPT(ssize_t, recvmsg,
             (int fd, struct msghdr* msg, int flags))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_recvmsg(fd, msg, flags);
  }

  Log_CALL(ci_log("%s(%d, %p, 0x%x)", __FUNCTION__, fd,msg,flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    if( msg->msg_iov == NULL && msg->msg_iovlen != 0 )
      CI_SET_ERROR(rc, EFAULT);
    else
      rc = citp_fdinfo_get_ops(fdi)->recv(fdi, msg, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_recvmsg(%d, msg, 0x%x)", fd, (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_recvmsg(fd, msg, flags);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


#if CI_CFG_RECVMMSG

# ifdef OO_RECVMMSG_NOT_IN_LIBC
int ci_sys_recvmmsg(int fd, struct mmsghdr* mmsg, unsigned vlen,
                    int flags, const struct timespec* timeout)
{
  static int (*sys_recvmmsg)(int, struct mmsghdr*, unsigned, int,
                             const struct timespec*);

  if( sys_recvmmsg == NULL )
    if( (sys_recvmmsg = dlsym(RTLD_NEXT, "recvmmsg")) == NULL ) {
      errno = ENOSYS;
      return -1;
    }

  return sys_recvmmsg(fd, mmsg, vlen, flags, timeout);
}
# endif


OO_INTERCEPT(int, recvmmsg, 
             (int fd, struct mmsghdr* msg, unsigned vlen,
              int flags, const struct timespec* timeout))
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int rc, i;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_recvmmsg(fd, msg, vlen, flags, timeout);
  }

  Log_CALL(ci_log("%s(%d, %p, %u, 0x%x)", __FUNCTION__, fd, msg, vlen, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    if(CI_UNLIKELY( msg == NULL && vlen != 0 )) {
      CI_SET_ERROR(rc, EFAULT);
    }
    else if(CI_UNLIKELY( timeout != NULL &&
                         (timeout->tv_sec < 0 || timeout->tv_nsec < 0) )) {
      CI_SET_ERROR(rc, EINVAL);
    }
    else {
      for( i = 0; i < vlen; ++i )
        if(CI_UNLIKELY( msg[i].msg_hdr.msg_iov == NULL && 
                        msg[i].msg_hdr.msg_iovlen != 0 )) {
          CI_SET_ERROR(rc, EFAULT);
          goto release_and_exit;
        }
      rc = citp_fdinfo_get_ops(fdi)->recvmmsg(fdi, msg, vlen, flags, timeout);
    }
  release_and_exit:
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_recvmmsg(%d, msg, %u, 0x%x)", fd, vlen,
               (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_recvmmsg(fd, msg, vlen, flags, timeout);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


# ifdef OO_RECVMMSG_NOT_IN_LIBC
strong_alias(onload_recvmmsg, recvmmsg);
# endif

#endif


OO_INTERCEPT(ssize_t, send,
             (int fd, const void* msg, size_t len, int flags))
{
  citp_fdinfo* fdi=0;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_send(fd, msg, len, flags);
  }

  Log_CALL(log("%s(%d, %p, %u, %x)", __FUNCTION__, fd, msg, (unsigned)len, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = (void*) msg;
    iov[0].iov_len = len;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_name = CI_NOT_NULL);
    m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    /* msg_flags is output only */
    rc = citp_fdinfo_get_ops(fdi)->send(fdi, &m, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_send(%d, msg, %d, 0x%x)", fd, (int) len,
               (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_send(fd, msg, len, flags);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(ssize_t, sendto,
             (int fd, const void* msg, size_t len, int flags,
              const struct sockaddr* to, socklen_t tolen))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendto(fd, msg, len, flags, to, tolen);
  }

  Log_CALL(ci_log("%s(%d, %p, %u, %d, %p, %u)", __FUNCTION__,
                  fd,msg,(unsigned)len,flags,to,tolen));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = (void*) msg;
    iov[0].iov_len = len;
    m.msg_name = (void*) to;
    /* Linux ignores length of address if the address is NULL. I do not know
     * *BSD or any other system behaviour. */
    m.msg_namelen = (to != NULL) ? tolen : 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    m.msg_flags = 0;
    rc = citp_fdinfo_get_ops(fdi)->send(fdi, &m, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_sendto(%d, msg, %d, 0x%x)", fd, (int) len,
               (unsigned)flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_sendto(fd, msg, len, flags, to, tolen);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(ssize_t, sendmsg,
             (int fd, const struct msghdr* msg, int flags))
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int rc;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendmsg(fd, msg, flags);
  }

  Log_CALL(ci_log("%s(%d, %p, 0x%x)", __FUNCTION__, fd, msg, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    if(CI_LIKELY( msg != NULL ))
      rc = citp_fdinfo_get_ops(fdi)->send(fdi, msg, flags);
    else
      CI_SET_ERROR(rc, EFAULT);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_sendmsg(%d, msg, 0x%x)", fd, (unsigned) flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_sendmsg(fd, msg, flags);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


#if CI_CFG_SENDMMSG

# ifdef OO_SENDMMSG_NOT_IN_LIBC
int ci_sys_sendmmsg(int fd, struct mmsghdr* mmsg, unsigned vlen,
                    int flags)
{
  static int (*sys_sendmmsg)(int, struct mmsghdr*, unsigned, int);

  if( sys_sendmmsg == NULL )
    if( (sys_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg")) == NULL ) {
      errno = ENOSYS;
      return -1;
    }

  return sys_sendmmsg(fd, mmsg, vlen, flags);
}
# endif


OO_INTERCEPT(int, sendmmsg, 
             (int fd, struct mmsghdr* msg, unsigned vlen, int flags))
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int rc, i;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendmmsg(fd, msg, vlen, flags);
  }

  Log_CALL(ci_log("%s(%d, %p, %u, 0x%x)", __FUNCTION__, fd, msg, vlen, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    if(CI_UNLIKELY( msg == NULL && vlen != 0 )) {
      CI_SET_ERROR(rc, EFAULT);
    }
    else {
      for( i = 0; i < vlen; ++i )
        if(CI_UNLIKELY( msg[i].msg_hdr.msg_iov == NULL && 
                        msg[i].msg_hdr.msg_iovlen != 0 )) {
          CI_SET_ERROR(rc, EFAULT);
          goto release_and_exit;
        }
      rc = citp_fdinfo_get_ops(fdi)->sendmmsg(fdi, msg, vlen, flags);
    }
  release_and_exit:
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_sendmmsg(%d, msg, %u, 0x%x)", fd, vlen, flags));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_sendmmsg(fd, msg, vlen, flags);
  }
  Log_CALL_RESULT(rc);
  return rc;
}

# ifdef OO_SENDMMSG_NOT_IN_LIBC
strong_alias(onload_sendmmsg, sendmmsg);
# endif

#endif /* CI_CFG_SENDMMSG */


#if CI_CFG_USERSPACE_SELECT

/* Internal poll/select timeout is calculated in milliseconds,
 * and in citp_ul_do_select/citp_ul_do_poll this value is multiplied by
 * ci_cpu_khz, assuming it not to overflow.
 * So we are dividing by 10GHz here.
 * This does limit us to maximum timeout of about 58 years.
 */
#define MAX_POLL_SELECT_MILLISEC ((ci_uint64) -1 / 10000000)
static inline ci_uint64
timespec2ms(const struct timespec* tv)
{
  ci_uint64 ms;

  if( tv == NULL )
    return MAX_POLL_SELECT_MILLISEC;
  ms = (ci_uint64)tv->tv_sec * 1000 +
       (tv->tv_nsec + 500000) / 1000000;

  /* If spinning is enabled, user expects us to spin a bit
   * even with extra-small timeout. */
  if( ms == 0 && tv->tv_nsec != 0 )
    ms = 1;
  if( ms >= MAX_POLL_SELECT_MILLISEC )
    return MAX_POLL_SELECT_MILLISEC;
  return ms;
}
static inline ci_uint64
timeval2ms(const struct timeval* tv)
{
  ci_uint64 ms;

  if( tv == NULL )
    return MAX_POLL_SELECT_MILLISEC;
  ms = (ci_uint64)tv->tv_sec * 1000 +
    (tv->tv_usec + 500) / 1000;

  /* If spinning is enabled, user expects us to spin a bit
   * even with extra-small timeout. */
  if( ms == 0 && tv->tv_usec != 0 )
    ms = 1;
  if( ms >= MAX_POLL_SELECT_MILLISEC )
    return MAX_POLL_SELECT_MILLISEC;
  return ms;
}
static inline void
ms2timeval(ci_uint64 timeout, ci_uint64 spent, struct timeval* tv)
{
  if( timeout > spent ) {
    tv->tv_sec = (timeout - spent) / 1000;
    tv->tv_usec = ((timeout - spent) % 1000) * 1000;
  }
  else {
    tv->tv_sec = tv->tv_usec = 0;
  }
}
static inline void
ms2timespec(ci_uint64 timeout, ci_uint64 spent, struct timespec* tv)
{
  if( timeout > spent ) {
    tv->tv_sec = (timeout - spent) / 1000;
    tv->tv_nsec = ((timeout - spent) % 1000) * 1000000;
  }
  else {
    tv->tv_sec = tv->tv_nsec = 0;
  }
}


OO_INTERCEPT(int, select,
             (int nfds, fd_set* rds, fd_set* wrs, fd_set* exs,
              struct timeval* timeout))
{
  citp_lib_context_t lib_context;
  ci_uint64 timeout_ms, used_ms = 0;
  int rc;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_select(nfds, rds, wrs, exs, timeout);
  }

  Log_CALL(ci_log("%s(%d, %p, %p, %p, {%d,%d})", __FUNCTION__,
                  nfds, rds, wrs, exs,
                  timeout ? (int)timeout->tv_sec : -1,
                  timeout ? (int)timeout->tv_usec : -1));

  if(CI_UNLIKELY( (!CITP_OPTS.ul_select) || (nfds <= 0) ||
                  (timeout != NULL &&
                   (timeout->tv_sec < 0 || timeout->tv_usec < 0)))) {
    rc = ci_sys_select(nfds, rds, wrs, exs, timeout);
    goto out;
  }

  timeout_ms = timeval2ms(timeout);

  citp_enter_lib(&lib_context);
  rc = citp_ul_do_select(nfds, rds, wrs, exs, timeout_ms, &used_ms,
                         &lib_context, NULL, NULL);

  /* Linux-specific behaviour: change timeout parameter. */
  if( timeout != NULL && used_ms != 0 ) {
    if( timeout_ms > used_ms )
      ms2timeval(timeout_ms, used_ms, timeout);
    else
      timeout->tv_sec = timeout->tv_usec = 0;
  }
  if( rc == CI_SOCKET_HANDOVER )
    rc = ci_sys_select(nfds, rds, wrs, exs, timeout);

out:
  Log_CALL_RESULT(rc);
  return rc;
}

OO_INTERCEPT(int, pselect,
             (int nfds, fd_set* rds, fd_set* wrs, fd_set* exs,
              const struct timespec *timeout_ts, const sigset_t *sigmask))
{
  citp_lib_context_t lib_context;
  sigset_t sigsaved;
  ci_uint64 timeout_ms, used_ms = 0;
  int rc = 0;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_pselect(nfds, rds, wrs, exs, timeout_ts, sigmask);
  }

  Log_CALL(ci_log("%s(%d, %p, %p, %p, {%d,%d}, %p)", __FUNCTION__, nfds,
                  rds, wrs, exs,
                  timeout_ts ? (int)timeout_ts->tv_sec : -1,
                  timeout_ts ? (int)timeout_ts->tv_nsec : -1,
                  sigmask));

  if( ! CITP_OPTS.ul_poll || nfds <= 0 ||
      (timeout_ts != NULL &&
       (timeout_ts->tv_sec < 0 || timeout_ts->tv_nsec < 0 ))) {
    rc = ci_sys_pselect(nfds, rds, wrs, exs, timeout_ts, sigmask);
    goto out;
  }

  timeout_ms = timespec2ms(timeout_ts);

  /* Set up signal mask and spin */
  citp_enter_lib(&lib_context);
  rc = citp_ul_do_select(nfds, rds, wrs, exs, timeout_ms, &used_ms,
                         &lib_context, sigmask, &sigsaved);

  /* we should not return 0 without signal check; do it now: */
  if( rc == CI_SOCKET_HANDOVER || (rc == 0 && sigmask != NULL) ) {
    if( timeout_ts != NULL && used_ms != 0 ) {
      struct timespec ts;
      ms2timespec(timeout_ms, used_ms, &ts);
      rc = ci_sys_pselect(nfds, rds, wrs, exs, &ts, sigmask);
    }
    else
      rc = ci_sys_pselect(nfds, rds, wrs, exs, timeout_ts, sigmask);
  }

out:
  Log_CALL_RESULT(rc);
  return rc;
}

OO_INTERCEPT(int, poll,
             (struct pollfd*__restrict__ fds, nfds_t nfds, int timeout))
{
  citp_lib_context_t lib_context;
  int rc;
  ci_uint64 used_ms = 0;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_poll(fds, nfds, timeout);
  }

  if( ! CITP_OPTS.ul_poll || nfds <= 0 )
    return ci_sys_poll(fds, nfds, timeout);

  Log_CALL(ci_log("%s(%p, %ld, %d)", __FUNCTION__, fds, nfds, timeout));

  citp_enter_lib(&lib_context);
  rc = citp_ul_do_poll(fds, nfds, timeout, &used_ms, &lib_context);

  /* fixme: signals may come after spin but before ci_sys_select(); we'll
   * handle them but do not return -1(EINTR). */
  citp_exit_lib(&lib_context, rc >= 0);
  if( timeout != used_ms && rc == 0 )
    rc = ci_sys_poll(fds, nfds, timeout - used_ms);

  Log_CALL_RESULT(rc);
  return rc;
}

#if CI_LIBC_HAS_ppoll
OO_INTERCEPT(int, ppoll,
             (struct pollfd*__restrict__ fds, nfds_t nfds,
              const struct timespec *timeout_ts, const sigset_t *sigmask))
{
  citp_lib_context_t lib_context;
  sigset_t sigsaved;
  ci_uint64 timeout_ms, used_ms = 0;
  int rc = 0;
  int was_spinning = 0;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_ppoll(fds, nfds, timeout_ts, sigmask);
  }

  Log_CALL(ci_log("%s(%p, %ld, {%d,%d}, %p)", __FUNCTION__, fds, nfds,
                  timeout_ts ? (int)timeout_ts->tv_sec : -1,
                  timeout_ts ? (int)timeout_ts->tv_nsec : -1,
                  sigmask));

  if( ! CITP_OPTS.ul_poll || nfds <= 0 ||
      (timeout_ts != NULL &&
       (timeout_ts->tv_sec < 0 || timeout_ts->tv_nsec < 0 ))) {
    rc = ci_sys_ppoll(fds, nfds, timeout_ts, sigmask);
    goto out;
  }

  /* Non-blocking check: do we have anything ready? */
  citp_enter_lib(&lib_context);
  rc = citp_ul_do_poll(fds, nfds, 0, &used_ms, &lib_context);
  citp_exit_lib(&lib_context, rc >=0);
  if( rc != 0)
    goto out;

  timeout_ms = timespec2ms(timeout_ts);

  /* Set up signal mask and spin */
  /* Fixme: move sigmask handling into citp_ul_do_poll, after we've
   * checked if any socket is already available. */
  if( timeout_ms != 0 &&
      (oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_POLL)) ) {
    was_spinning = 1;
    rc = citp_ul_pwait_spin_pre(&lib_context, sigmask, &sigsaved);
    if( rc < 0 ) {
      citp_exit_lib(&lib_context, rc >=0);
      goto out;
    }

    rc = citp_ul_do_poll(fds, nfds, timeout_ms, &used_ms, &lib_context);

    citp_ul_pwait_spin_done(&lib_context, &sigsaved, &rc);
    if( rc != 0 )
      goto out;
  }

  /* Block in the OS */
  if( (timeout_ms != used_ms || !was_spinning) && rc == 0 ) {
    if( used_ms == 0 || timeout_ts == NULL )
      rc = ci_sys_ppoll(fds, nfds, timeout_ts, sigmask);
    else {
      struct timespec ts;
      ms2timespec(timeout_ms, used_ms, &ts);
      rc = ci_sys_ppoll(fds, nfds, &ts, sigmask);
    }
  }

out:
  Log_CALL_RESULT(rc);
  return rc;
}
#endif


#if CI_CFG_USERSPACE_EPOLL
# include "ul_epoll.h"


#ifdef EPOLL_CLOEXEC
OO_INTERCEPT(int, epoll_create1,
             (int flags))
{
  int rc = 0;
  citp_lib_context_t lib_context;

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_ALL )) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_epoll_create1(flags);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d)", __FUNCTION__, flags));
  if( ! CITP_OPTS.ul_epoll )
    goto pass_through;
  if( CITP_OPTS.ul_epoll == 1 )
    rc = citp_epoll_create(1, flags);
  else
    rc = citp_epollb_create(1, flags);
  if( rc == CITP_NOT_HANDLED )
    goto pass_through;
  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;

 pass_through:
  rc = ci_sys_epoll_create1(flags);
  if( rc >= 0 )
    citp_fdtable_passthru(rc, 0);
  citp_exit_lib(&lib_context, rc >= 0);
  Log_PT(log("PT: sys_epoll_create1(%x) = %d", flags, rc));
  return rc;
}
#endif


OO_INTERCEPT(int, epoll_create,
             (int size))
{
  int rc = 0;
  citp_lib_context_t lib_context;

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_ALL )) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_epoll_create(size);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d)", __FUNCTION__, size));
  if( ! CITP_OPTS.ul_epoll )
    goto pass_through;
  if( CITP_OPTS.ul_epoll == 1 )
    rc = citp_epoll_create(size, 0);
  else
    rc = citp_epollb_create(size, 0);
  if( rc == CITP_NOT_HANDLED )
    goto pass_through;
  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;

 pass_through:
  rc = ci_sys_epoll_create(size);
  if( rc >= 0 )
    citp_fdtable_passthru(rc, 0);
  citp_exit_lib(&lib_context, rc >= 0);
  Log_PT(log("PT: sys_epoll_create(%d) = %d", size, rc));
  return rc;
}


OO_INTERCEPT(int, epoll_ctl,
             (int epfd, int op, int fd, struct epoll_event *event))
{
  citp_fdinfo* fdi;
  citp_lib_context_t lib_context;

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_ALL )) {
    citp_do_init(CITP_INIT_SYSCALLS);
    goto pass_through;
  }
  if( ! CITP_OPTS.ul_epoll )
    goto pass_through;

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %d, %d, %p)", __FUNCTION__, epfd, op, fd, event));

  if( (fdi = citp_fdtable_lookup(epfd)) ) {
    int rc;
    if( fdi->protocol->type == CITP_EPOLL_FD )
      rc = citp_epoll_ctl(fdi, op, fd, event);
    else if (fdi->protocol->type == CITP_EPOLLB_FD )
      rc = citp_epollb_ctl(fdi, op, fd, event);
    else {
      citp_fdinfo_release_ref(fdi, 0);
      goto error;
    }
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
    Log_CALL_RESULT(rc);
    return rc;
  }

error:
  citp_exit_lib(&lib_context, TRUE);
  Log_PT(log("PT: sys_epoll_ctl(%d, %d, %d, %p)", epfd, op, fd, event));
 pass_through:
  return ci_sys_epoll_ctl(epfd, op, fd, event);
}


OO_INTERCEPT(int, epoll_wait,
             (int epfd, struct epoll_event*events, int maxevents, int timeout))
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_ALL )) {
    citp_do_init(CITP_INIT_SYSCALLS);
    goto pass_through;
  }
  if( ! CITP_OPTS.ul_epoll )
    goto pass_through;

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %p, %d, %d)", __FUNCTION__, epfd, events,
                  maxevents, timeout));

  if( (fdi=citp_fdtable_lookup(epfd)) ) {
    int rc;
    if( fdi->protocol->type == CITP_EPOLL_FD )
      /* NB. citp_epoll_wait() calls citp_exit_lib(). */
      rc = citp_epoll_wait(fdi, events, NULL, maxevents, timeout, NULL,
                           &lib_context);
    else if (fdi->protocol->type == CITP_EPOLLB_FD ) {
      rc = citp_epollb_wait(fdi, events, maxevents, timeout, NULL,
                            &lib_context);
      citp_exit_lib(&lib_context, rc >= 0);
    }
    else {
      citp_fdinfo_release_ref(fdi, 0);
      goto error;
    }
    citp_fdinfo_release_ref(fdi, 0);
    Log_CALL_RESULT(rc);
    return rc;
  }

error:
  citp_exit_lib(&lib_context, TRUE);
  Log_PT(log("PT: sys_epoll_wait(%d, %p, %d, %d)", epfd, events,
             maxevents, timeout));
 pass_through:
  return ci_sys_epoll_wait(epfd, events, maxevents, timeout);
}

#if CI_LIBC_HAS_epoll_pwait
OO_INTERCEPT(int, epoll_pwait,
             (int epfd, struct epoll_event*events, int maxevents, int timeout,
              const sigset_t *sigmask))
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_ALL )) {
    citp_do_init(CITP_INIT_SYSCALLS);
    goto pass_through;
  }
  if( ! CITP_OPTS.ul_epoll )
    goto pass_through;

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d, %p, %d, %d, %p)", __FUNCTION__, epfd, events,
                  maxevents, timeout, sigmask));

  if( (fdi=citp_fdtable_lookup(epfd)) ) {
    int rc;
    if( fdi->protocol->type == CITP_EPOLL_FD ) {
      /* NB. citp_epoll_wait() calls citp_exit_lib(). */
      rc = citp_epoll_wait(fdi, events, NULL, maxevents, timeout, sigmask,
                           &lib_context);
    }
    else if (fdi->protocol->type == CITP_EPOLLB_FD ) {
      rc = citp_epollb_wait(fdi, events, maxevents, timeout, sigmask,
                            &lib_context);
      citp_exit_lib(&lib_context, rc >= 0);
    }
    else {
      citp_fdinfo_release_ref(fdi, 0);
      goto error;
    }
    citp_fdinfo_release_ref(fdi, 0);
    Log_CALL_RESULT(rc);
    return rc;
  }

error:
  citp_exit_lib(&lib_context, TRUE);
  Log_PT(log("PT: sys_epoll_pwait(%d, %p, %d, %d, %p)", epfd, events,
             maxevents, timeout, sigmask));
 pass_through:
  return ci_sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}
#endif /*CI_LIBC_HAS_epoll_pwait*/
#endif /*CI_CFG_USERSPACE_EPOLL*/
#endif /*CI_CFG_USERSPACE_SELECT*/


#if CI_CFG_SENDFILE

#ifdef CI_IOCTL_SENDFILE
OO_INTERCEPT(ssize_t, sendfile,
             (int out_fd, int in_fd, off_t* offset, size_t count))
{
  ssize_t        rc;
  ci_sendfilev_t cs;
  citp_fdinfo   *out_fdi;
  void          (*post_hook)(citp_fdinfo *);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendfile(out_fd, in_fd, offset, count);
  }

  Log_CALL(ci_log("%s(%d, %d, %p, %u)", __FUNCTION__, out_fd, in_fd, offset,
                  (unsigned)count));
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);
  if (!(out_fdi = citp_fdtable_lookup(out_fd))) {
    rc = ci_sys_sendfile(out_fd, in_fd, offset, count);
  } else {
    if (out_fdi->protocol->type == CITP_TCP_SOCKET) {
      post_hook = citp_fdinfo_get_ops(out_fdi)->sendfile_post_hook;

      cs.cs_sfv[0].sfv_fd = in_fd;
      cs.cs_sfv[0].sfv_flag = 0;
      cs.cs_sfv[0].sfv_off = *offset;
      cs.cs_sfv[0].sfv_len = count;
      cs.cs_nelem = 1;

      Log_V( {
           ci_sfv_t * sp;

           for (sp = cs.cs_sfv; sp < cs.cs_sfv+cs.cs_nelem; sp++)
              ci_log("%s: idx %ld fd %lld len %lld", __FUNCTION__,
                      (long)(sp - cs.cs_sfv),
                      (long long)sp->sfv_fd, (long long)sp->sfv_len);
             } )

      rc = ci_sys_ioctl(out_fd, CI_SENDFILEV, &cs);
      *offset += cs.cs_xferred;

      if( post_hook ) {
        post_hook(out_fdi);
      }
    } else
      CI_SET_ERROR(rc, EOPNOTSUPP);

    citp_fdinfo_release_ref(out_fdi, 0);
  }

  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT((int)rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(ssize_t, sendfile64,
             (int out_fd, int in_fd, off64_t* offset, size_t count))
{
  ssize_t        rc;
  ci_sendfilev_t cs;
  citp_fdinfo   *out_fdi;
  void          (*post_hook)(citp_fdinfo *);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendfile64(out_fd, in_fd, offset, count);
  }

  Log_CALL(ci_log("%s(%d, %d, %p, %u)", __FUNCTION__, out_fd, in_fd, offset,
                  (unsigned)count));
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);
  if (!(out_fdi = citp_fdtable_lookup(out_fd))) {
    rc = ci_sys_sendfile64(out_fd, in_fd, offset, count);
  } else {
    post_hook = citp_fdinfo_get_ops(out_fdi)->sendfile_post_hook;

    cs.cs_sfv[0].sfv_fd = in_fd;
    cs.cs_sfv[0].sfv_flag = 0;
    cs.cs_sfv[0].sfv_off = *offset;
    cs.cs_sfv[0].sfv_len = count;
    cs.cs_nelem = 1;

    Log_V( {
           ci_sfv_t * sp;

           for (sp = cs.cs_sfv; sp < cs.cs_sfv+cs.cs_nelem; sp++)
              ci_log("%s: idx %ld fd %lld len %lld", __FUNCTION__,
                      (long)(sp - cs.cs_sfv),
                      (long long)sp->sfv_fd, (long long)sp->sfv_len);
           } )

    if ((rc = ci_sys_ioctl(out_fd, CI_SENDFILEV, &cs)) >= 0)
      *offset += cs.cs_xferred;

    if( post_hook ) {
      post_hook(out_fdi);
    }
  }

  citp_fdinfo_release_ref(out_fdi, 0);
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT((int)rc);
  return rc;
}
#endif /* _LP64 */
#else


OO_INTERCEPT(ssize_t, sendfile,
             (int out_fd, int in_fd, off_t* offset, size_t count))
{
  ssize_t       rc;
  citp_fdinfo   *out_fdi;
  void          (*post_hook)(citp_fdinfo *);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendfile(out_fd, in_fd, offset, count);
  }

  Log_CALL(ci_log("%s(%d, %d, %p, %u)", __FUNCTION__, out_fd, in_fd, offset,
                  (unsigned)count));
  Log_V(log("sys_sendfile(%d, %d, offset, %lu)", out_fd, in_fd, (ulong)count));

  /* NB: our code will be used inside this system call... */
  rc = ci_sys_sendfile(out_fd, in_fd, offset, count);

  if( (out_fdi = citp_fdtable_lookup(out_fd)) ) {
    post_hook = citp_fdinfo_get_ops(out_fdi)->sendfile_post_hook;
    if( post_hook ) {
      citp_lib_context_t lib_context;
      citp_enter_lib(&lib_context);

      post_hook(out_fdi);
      citp_exit_lib(&lib_context, rc >= 0);
    }
    citp_fdinfo_release_ref(out_fdi, 0);
  }

  Log_CALL_RESULT((int)rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(ssize_t, sendfile64,
             (int out_fd, int in_fd, off64_t* offset, size_t count))
{
  ssize_t       rc;
  citp_fdinfo   *out_fdi;
  void          (*post_hook)(citp_fdinfo *);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendfile64(out_fd, in_fd, offset, count);
  }

  Log_CALL(ci_log("%s(%d, %d, %p, %u)", __FUNCTION__, out_fd, in_fd, offset,
                  (unsigned)count));

  Log_V(log("sys_sendfile64(%d, %d, offset, %lu)", out_fd,in_fd,(ulong)count));

  /* NB: our code will be used inside this system call... */
  rc = ci_sys_sendfile64(out_fd, in_fd, offset, count);

  if( (out_fdi = citp_fdtable_lookup(out_fd)) ) {
    post_hook = citp_fdinfo_get_ops(out_fdi)->sendfile_post_hook;
    if( post_hook ) {
      citp_lib_context_t lib_context;
      citp_enter_lib(&lib_context);

      post_hook(out_fdi);
      citp_exit_lib(&lib_context, rc >= 0);
    }
    citp_fdinfo_release_ref(out_fdi, 0);
  }

  Log_CALL_RESULT((int)rc);
  return rc;
}
#endif /* _LP64 */
#endif /* CI_IOCTL_SENDFILE */
#endif /*CI_CFG_SENDFILE*/


#if CI_CFG_SENDFILEV
OO_INTERCEPT(ssize_t, sendfilev,
             (int out_fd, const struct sendfilevec *vec,
              int sfvcnt, size_t *xferred))
{
  ssize_t                    rc;
  ci_sendfilev_t             cs;
  const struct sendfilevec * vp;
  citp_fdinfo              * out_fdi;
  void                     (*post_hook)(citp_fdinfo *);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_sendfilev(out_fd, vec, sfvcnt, xferred);
  }

  Log_CALL(ci_log("%s(%d, %p, %d, %p)", __FUNCTION__, out_fd, vec, sfvcnt,
			xferred));
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);

  if (!(out_fdi = citp_fdtable_lookup(out_fd))) {
    rc = ci_sys_sendfilev(out_fd, vec, sfvcnt, xferred);
  } else {
    post_hook = citp_fdinfo_get_ops(out_fdi)->sendfile_post_hook;

    for (rc = 0, vp = vec; rc < sfvcnt; rc++, vp++ ) {
      cs.cs_sfv[rc].sfv_fd =   vp->sfv_fd;
      cs.cs_sfv[rc].sfv_flag = vp->sfv_flag;
      cs.cs_sfv[rc].sfv_off =  vp->sfv_off;
      cs.cs_sfv[rc].sfv_len =  vp->sfv_len;
    }
    cs.cs_nelem = sfvcnt;

    Log_V( {
             ci_sfv_t * sp;

             for (sp = cs.cs_sfv; sp < cs.cs_sfv+cs.cs_nelem; sp++)
                ci_log("%s: idx %ld fd %lld len %lld", __FUNCTION__,
                        (long)(sp - cs.cs_sfv),
                        (long long)sp->sfv_fd, (long long)sp->sfv_len);
           } )

    rc = ci_sys_ioctl(out_fd, CI_SENDFILEV, &cs);
    *xferred = cs.cs_xferred;

    if( post_hook )
      post_hook(out_fdi);		  
  }

  citp_fdinfo_release_ref(out_fdi, 0);
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT((int)rc);
  return rc;
}
#endif	/*CI_CFG_SENDFILEV*/


OO_INTERCEPT(ssize_t, read,
             (int fd, void* buf, size_t count))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_read(fd, buf, count);
  }

  Log_CALL(ci_log("%s(%d, %p, %u)", __FUNCTION__, fd, buf, (unsigned)count));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = buf;
    iov[0].iov_len = count;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_name = CI_NOT_NULL);
    m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    /* msg_flags is output only */
    if( count == 0 )
      rc = 0;
    else
    rc = citp_fdinfo_get_ops(fdi)->recv(fdi, &m, 0);
    citp_fdinfo_release_ref_fast(fdi);
    FDTABLE_ASSERT_VALID();
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_read(%d, buf, %d)", fd, (int) count));
    FDTABLE_ASSERT_VALID();
    citp_exit_lib_if(&lib_context, TRUE);
    rc =  ci_sys_read(fd, buf, count);
  }

  Log_CALL_RESULT(rc);
  return rc;
}

#if CI_LIBC_HAS___read_chk
OO_INTERCEPT(ssize_t, __read_chk,
             (int fd, void* buf, size_t count, size_t buflen))
{
  if (count > buflen)
    ci_sys___read_chk(fd, buf, count, buflen);
  return onload_read(fd, buf, count);
}
#endif

OO_INTERCEPT(ssize_t, write,
             (int fd, const void* buf, size_t count))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  struct iovec iov[1];
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_write(fd, buf, count);
  }

  Log_CALL(ci_log("%s(%d, %p, %u)", __FUNCTION__, fd, buf, (unsigned)count));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    iov[0].iov_base = (void*) buf;
    iov[0].iov_len = count;
    /* See note about convertions above in this file */
    CI_DEBUG(m.msg_name = CI_NOT_NULL);
    m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    CI_DEBUG(m.msg_control = CI_NOT_NULL);
    m.msg_controllen = 0;
    /* msg_flags is output only */
    rc = citp_fdinfo_get_ops(fdi)->send(fdi, &m, 0);
    citp_fdinfo_release_ref_fast(fdi);
    FDTABLE_ASSERT_VALID();
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_write(%d, buf, %d)", fd, (int) count));
    FDTABLE_ASSERT_VALID();
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_write(fd, buf, count);
  }

  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(ssize_t, readv,
             (int fd, const struct iovec* vector, int count))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_readv(fd, vector, count);
  }

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, vector, count));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    {
      int len_is_zero = 1;
      int i;
      for( i = 0; i < count; i++ ) {
        if( vector[i].iov_len ) {
          len_is_zero = 0;
          break;
        }
      }
      /* See note about convertions above in this file */
      CI_DEBUG(m.msg_name = CI_NOT_NULL);
      m.msg_namelen = 0;
      m.msg_iov = (struct iovec*) vector;
      m.msg_iovlen = count;
      CI_DEBUG(m.msg_control = CI_NOT_NULL);
      m.msg_controllen = 0;
      /* msg_flags is output only */
      if( len_is_zero )
        rc = 0;
      else
      rc = citp_fdinfo_get_ops(fdi)->recv(fdi, &m, 0);
    }
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_readv(%d, vector, %d)", fd, count));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_readv(fd, vector, count);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(ssize_t, writev,
             (int fd, const struct iovec* vector, int count))
{
  citp_fdinfo* fdi;
  struct msghdr m;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_writev(fd, vector, count);
  }

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, vector, count));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    {
      /* See note about convertions above in this file */
      CI_DEBUG(m.msg_name = CI_NOT_NULL);
      m.msg_namelen = 0;
      m.msg_iov = (struct iovec*) vector;
      m.msg_iovlen = count;
      CI_DEBUG(m.msg_control = CI_NOT_NULL);
      m.msg_controllen = 0;
      /* msg_flags is output only */
      rc = citp_fdinfo_get_ops(fdi)->send(fdi, &m, 0);
    }
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  }
  else {
    Log_PT(log("PT: sys_writev(%d, vector, %d)", fd, count));
    citp_exit_lib_if(&lib_context, TRUE);
    rc = ci_sys_writev(fd, vector, count);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, close,
             (int fd))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_close(fd);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d)", __FUNCTION__, fd));

  rc = citp_ep_close(fd);

  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, fcntl,
             (int fd, int cmd, ...))
{
  citp_fdinfo* fdi;
  long arg;
  va_list va;
  int rc;
  citp_lib_context_t lib_context;

  va_start(va, cmd);
  arg = va_arg(va, long);
  va_end(va);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_fcntl(fd, cmd, arg);
  }

  Log_CALL(ci_log("%s(%d, %d, %ld)", __FUNCTION__, fd, cmd, arg));

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    ci_assert (citp_fdinfo_get_ops (fdi)->fcntl);
    rc = citp_fdinfo_get_ops(fdi)->fcntl(fdi, cmd, arg);
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_fcntl(%d, %d, ...)", fd, cmd));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_fcntl(fd, cmd, arg);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __GLIBC__
OO_INTERCEPT(int, ioctl,
             (int fd, unsigned long request, ...))
#else
OO_INTERCEPT(int, ioctl,
             (int fd, int request, ...))
#endif
{
  citp_fdinfo* fdi;
  void* arg;
  va_list va;
  int rc;
  citp_lib_context_t lib_context;

  va_start(va, request);
  arg = (void*)va_arg(va, long);
  va_end(va);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_ioctl(fd, request, arg);
  }

  citp_enter_lib(&lib_context);
#ifdef  __GLIBC__
  Log_CALL(ci_log("%s(%d, %ld, ...)", __FUNCTION__, fd, request));
#else
  Log_CALL(ci_log("%s(%d, %d, ...)", __FUNCTION__, fd, request));
#endif

  if( (fdi = citp_fdtable_lookup(fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->ioctl(fdi, request, arg);
    citp_fdinfo_release_ref(fdi, 0);
    citp_exit_lib(&lib_context, rc == 0);
  } else {
    Log_PT(log("PT: sys_ioctl(%d, %lu, ...)", fd, (unsigned long) request));
    citp_exit_lib(&lib_context, TRUE);
    rc = ci_sys_ioctl(fd, request, arg);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, dup,
             (int fd))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_dup(fd);
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d)", __FUNCTION__, fd));

  if( fd >= 0 )
    rc = citp_ep_dup(fd, citp_ep_dup_dup, 0 /*unused*/);
  else {
    errno = EBADF;
    rc = -1;
  }

  Log_V(log("dup(%d) = %d", fd, rc));
  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}


OO_INTERCEPT(int, dup2,
             (int oldfd, int newfd))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_dup2(oldfd, newfd);
  }
  if( oldfd < 0 || newfd < 0 ) {
    CI_SET_ERROR(rc, EBADF);
    return rc;
  }
  if( oldfd == newfd )
    /* fixme: This is the wrong thing to do because oldfd might be bad. */
    return oldfd;

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%d)", __FUNCTION__, oldfd, newfd));

  rc = citp_ep_dup3(oldfd, newfd, 0);
  Log_V(log("dup2(%d, %d) = %d", oldfd, newfd, rc));

  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}


#if CI_LIBC_HAS_dup3
OO_INTERCEPT(int, dup3,
             (int oldfd, int newfd, int flags))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_dup3(oldfd, newfd, flags);
  }
  if( oldfd < 0 || newfd < 0 ) {
    CI_SET_ERROR(rc, oldfd == newfd ? EINVAL : EBADF);
    return rc;
  }
  if( (flags & ~O_CLOEXEC) != 0 || oldfd == newfd ) {
    CI_SET_ERROR(rc, EINVAL);
    return rc;
  }

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(%d,%d,%x)", __FUNCTION__, oldfd, newfd, flags));

  rc = citp_ep_dup3(oldfd, newfd, flags);
  Log_V(log("dup3(%d, %d, %x) = %d", oldfd, newfd, flags, rc));

  FDTABLE_ASSERT_VALID();
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}
#endif

void *onload___vfork_rtaddr = NULL;
#ifdef __i386__
ci_uint32 onload___vfork_ebx = 0;
#endif
#ifdef __powerpc__
#ifdef __powerpc64__
ci_uint64 onload___vfork_r31 = 0;
#else
ci_uint32 onload___vfork_r31 = 0;
ci_uint32 onload___vfork_r3  = 0;
#endif
#endif

OO_INTERCEPT(int, __vfork_is_vfork, (void))
{
  return CITP_OPTS.vfork_mode == 2;
}

OO_INTERCEPT(pid_t, __vfork_as_fork,
             (void))
{
  int rc;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_LOGGING) )
    citp_do_init(CITP_INIT_LOGGING);

  Log_CALL(ci_log("%s()", __FUNCTION__));

  ci_assert_nequal( CITP_OPTS.vfork_mode, 2 ); 
  if( CITP_OPTS.vfork_mode == 1 ) {
    int pipefd[2];
    uint8_t buf;

#if defined(SYS_pipe2) && CI_LIBC_HAS_pipe2
    rc = ci_sys_pipe2(pipefd, O_CLOEXEC);
    if( rc ) {
      Log_V(log("Warning: Calling pipe2() in vfork() failed (%d).  "
                "Trying pipe().", rc));
    }
    else
      goto fork;
#endif

    /* Pipe is less prefered because we race to open the pipe and set
     * FD_CLOEXEC on the fd.  There isn't anything we can do about
     * this race.
     */
    rc = ci_sys_pipe(pipefd);
    if( rc ) {
      log("ERROR: Calling pipe() in vfork() failed (%d)", rc);
      return rc;
    }

    rc = ci_sys_fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    if( rc ) {
      log("ERROR: Calling fcntl() in vfork() failed (%d)", rc);
      close(pipefd[0]);
      close(pipefd[1]);
      return rc;
    }

#if defined(SYS_pipe2) && CI_LIBC_HAS_pipe2
  fork:
#endif
    rc = fork();
    if( rc == -1 ) {
      log("ERROR: Calling fork() in vfork() failed (%d)", rc);
      close(pipefd[0]);
      close(pipefd[1]);
      return rc;
    }

    if( rc ) { /* Parent.  Block till child exits */
      Log_V(log("fork() [in place of vfork()] = %d", rc));
      close(pipefd[1]);
      ci_sys_read(pipefd[0], &buf, 1);
      close(pipefd[0]);
    }
    else /* child.  pipefd[1] closed when child exits */
      close(pipefd[0]);
  }
  else {
    ci_assert_equal(CITP_OPTS.vfork_mode, 0);
    rc = fork();
    Log_V(if( rc )  log("fork() [in place of vfork()] = %d", rc));
  }
  return rc;
}


OO_INTERCEPT(int, open,
             (const char* pathname, int flags, ...))
{
  mode_t mode;
  int rc;
  va_list va;

  va_start(va, flags);
  mode = va_arg(va, mode_t);
  va_end(va);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_open(pathname, flags, mode);
  }

  Log_CALL(ci_log("%s(\"%s\", %d, ...)", __FUNCTION__, pathname, flags));

  {
    citp_lib_context_t lib_context;

    rc = ci_sys_open(pathname, flags, mode);
    citp_enter_lib(&lib_context);
    citp_fdtable_passthru(rc, 0);
    Log_PT(log("PT: sys_open(%s, %x, %x) = %d", pathname,
               (unsigned) flags, (unsigned) mode, rc));
    citp_exit_lib(&lib_context, rc >= 0);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(int, open64,
             (const char* pathname, int flags, ...))
{
  mode_t mode;
  int rc;
  va_list va;

  va_start(va, flags);
  mode = va_arg(va, mode_t);
  va_end(va);

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_open(pathname, flags, mode);
  }

  Log_CALL(ci_log("%s(\"%s\", %d, ...)", __FUNCTION__, pathname, flags));

  {
    citp_lib_context_t lib_context;
    
    rc = ci_sys_open64(pathname, flags, mode);
    
    citp_enter_lib(&lib_context);
    citp_fdtable_passthru(rc, 0);
    Log_PT(log("PT: sys_open64(%s, %x, %x) = %d", pathname,
               (unsigned) flags, (unsigned) mode, rc));
    citp_exit_lib(&lib_context, rc >= 0);
  }
  Log_CALL_RESULT(rc);
  return rc;
}
#endif


OO_INTERCEPT(int, creat,
             (const char* pathname, mode_t mode))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_creat(pathname, mode);
  }

  Log_CALL(ci_log("%s(\"%s\", 0x%x)", __FUNCTION__, pathname,
                  (unsigned) mode));

  rc = ci_sys_creat(pathname, mode);
  citp_enter_lib(&lib_context);
  citp_fdtable_passthru(rc, 0);
  Log_PT(log("PT: sys_creat(%s, %x) = %d", pathname, (unsigned) mode, rc));
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(int, creat64,
             (const char* pathname, mode_t mode))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_creat64(pathname, mode);
  }

  Log_CALL(ci_log("%s(\"%s\", 0x%x)", __FUNCTION__, pathname,
                  (unsigned) mode));

  rc = ci_sys_creat64(pathname, mode);
  citp_enter_lib(&lib_context);
  citp_fdtable_passthru(rc, 0);
  Log_PT(log("PT: sys_creat64(%s, %x) = %d", pathname, (unsigned) mode, rc));
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}
#endif


OO_INTERCEPT(int, socketpair,
             (int d, int type, int protocol, int sv[2]))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_socketpair(d, type, protocol, sv);
  }

  Log_CALL(ci_log("%s(%d, %d, %d, [%d, %d])", __FUNCTION__,d,type,protocol,
                  sv ? sv[0] : -1, sv ? sv[1] : -1));

  rc = ci_sys_socketpair(d, type, protocol, sv);
  citp_enter_lib(&lib_context);
  if( rc == 0 ) {
    citp_fdtable_passthru(sv[0], 0);
    citp_fdtable_passthru(sv[1], 0);
  }
  Log_PT(log("PT: sys_socketpair(%d, %d, %d, sv) = %d  sv={%d,%d}",
             d, type, protocol, rc, sv ? sv[0]:-1, sv ? sv[1]:-1));
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL(ci_log("%s returning %d, [%d,%d] (errno %d)",__FUNCTION__,
                  rc,sv[0],sv[1],errno));
  return rc;
}


OO_INTERCEPT(int, pipe,
             (int fd[2]))
{
  int rc = CITP_NOT_HANDLED;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_pipe(fd);
  }
  if( fd == NULL ) {
    errno = EFAULT;
    return -1;
  }

  Log_CALL(ci_log("%s([%d],[%d])", __FUNCTION__, fd[0], fd[1]));
  citp_enter_lib(&lib_context);

#if CI_CFG_USERSPACE_PIPE
  if( CITP_OPTS.ul_pipe ) {
      rc = citp_pipe_create(fd, 0);
  }
#endif
  if( rc == CITP_NOT_HANDLED ) {
      rc = ci_sys_pipe(fd);
      if( rc == 0 ) {
          citp_fdtable_passthru(fd[0], 0);
          citp_fdtable_passthru(fd[1], 0);
      }
      Log_PT(log("PT: sys_pipe(filedes) = %d  filedes={%d,%d}",
                 rc, fd ? fd[0]:-1, fd ? fd[1]:-1));
  }

  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL(ci_log("%s returning %d, [%d,%d] (errno %d)",__FUNCTION__,
                  rc,fd[0],fd[1],errno));
  return rc;
}
#if defined(SYS_pipe2) && CI_LIBC_HAS_pipe2
OO_INTERCEPT(int, pipe2,
             (int fd[2], int flags))
{
  int rc = CITP_NOT_HANDLED;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_pipe2(fd, flags);
  }
  if( fd == NULL || (flags & ~O_CLOEXEC) != 0)
    return ci_sys_pipe2(fd, flags);

  Log_CALL(ci_log("%s([%d],[%d], %x)", __FUNCTION__, fd[0], fd[1], flags));
  citp_enter_lib(&lib_context);

#if CI_CFG_USERSPACE_PIPE
  if( CITP_OPTS.ul_pipe ) {
      rc = citp_pipe_create(fd, flags);
  }
#endif
  if( rc == CITP_NOT_HANDLED ) {
      rc = ci_sys_pipe2(fd, flags);
      if( rc == 0 ) {
          citp_fdtable_passthru(fd[0], 0);
          citp_fdtable_passthru(fd[1], 0);
      }
      Log_PT(log("PT: sys_pipe(filedes) = %d  filedes={%d,%d}",
                 rc, fd ? fd[0]:-1, fd ? fd[1]:-1));
  }

  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL(ci_log("%s returning %d, [%d,%d] (errno %d)",__FUNCTION__,
                  rc,fd[0],fd[1],errno));
  return rc;
}
#endif


OO_INTERCEPT(int, setuid, (uid_t uid))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_setuid(uid);
  }
  Log_CALL(ci_log("%s(%d)", __FUNCTION__, uid));
  rc = ci_sys_setuid(uid);
  citp_enter_lib(&lib_context);
  if( rc == 0 ) {
    CITP_LOCK(&citp_ul_lock);
    oo_stackname_update(NULL);
    CITP_UNLOCK(&citp_ul_lock);
  }
  Log_PT(log("PT: setuid(%d) = %d", uid, rc));
  citp_exit_lib(&lib_context, rc >= 0);
  Log_CALL_RESULT(rc);
  return rc;
}



/* On linux, this interception is necessary:
 * - for kernel<=2.6.21, since onloadfs files do not have proper i_mode;
 * - for epoll, since it is a char device. */
OO_INTERCEPT(int, __fxstat,
             (int ver, int fd, struct stat *stat_buf))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys___fxstat(ver, fd, stat_buf);
  }

  Log_CALL(ci_log("%s(%d, %d, %p)", __FUNCTION__, ver, fd, stat_buf));

  rc = ci_sys___fxstat(ver, fd, stat_buf);
  citp_enter_lib(&lib_context);
  if( rc == 0 && (fdi = citp_fdtable_lookup(fd))) {
    if( fdi != &citp_the_closed_fd ) {
      stat_buf->st_mode &= ~S_IFMT;
#if CI_CFG_USERSPACE_PIPE
      if( fdi->protocol->type == CITP_PIPE_FD ) {
        stat_buf->st_mode |= S_IFIFO;
        stat_buf->st_mode &= ~0177;
      }
      else
#endif
#if CI_CFG_USERSPACE_EPOLL
      if( fdi->protocol->type == CITP_EPOLLB_FD ||
          fdi->protocol->type == CITP_EPOLL_FD )
        stat_buf->st_mode = 0600;
      else
#endif
        stat_buf->st_mode |= S_IFSOCK;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __USE_LARGEFILE64
OO_INTERCEPT(int, __fxstat64,
             (int ver, int fd, struct stat64 *stat_buf))
{
  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys___fxstat64(ver, fd, stat_buf);
  }

  Log_CALL(ci_log("%s(%d, %d, %p)", __FUNCTION__, ver, fd, stat_buf));

  rc = ci_sys___fxstat64(ver, fd, stat_buf);
  citp_enter_lib(&lib_context);
  if( rc == 0 && (fdi = citp_fdtable_lookup(fd)) ) {
    if( fdi != &citp_the_closed_fd ) {
      stat_buf->st_mode &= ~S_IFMT;
#if CI_CFG_USERSPACE_PIPE
      if( fdi->protocol->type == CITP_PIPE_FD ) {
        stat_buf->st_mode |= S_IFIFO;
        stat_buf->st_mode &= ~0177;
      }
      else
#endif
#if CI_CFG_USERSPACE_EPOLL
      if( fdi->protocol->type == CITP_EPOLLB_FD ||
          fdi->protocol->type == CITP_EPOLL_FD )
        stat_buf->st_mode = 0600;
      else
#endif
        stat_buf->st_mode |= S_IFSOCK;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}
#endif




OO_INTERCEPT(int, chroot,
             (const char* path))
{
  int rc;
  citp_lib_context_t lib_context;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    return ci_sys_chroot(path);
  }

  /* Do nothing if we are not going to accelerate anything. */
  if (CITP_OPTS.ul_udp == 0 && CITP_OPTS.ul_tcp == 0)
    return ci_sys_chroot(path);

  citp_enter_lib(&lib_context);
  Log_CALL(ci_log("%s(\"%s\")", __FUNCTION__, path));

  Log_V(log("chroot intercepted"));
  (void) citp_onload_dev_major();/* ensure the major dev ID has been cached */
  ci_setup_ipstack_params();     /* save values from /proc */
  ef_driver_save_fd();
  rc = ci_sys_chroot(path);
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);
  return rc;
}


# define dump_args(a)

typedef int exec_fn_t(const char *filename, char *const argv[],
                      char *const envp[]);

static int onload_exec(const char *path, char *const argv[],
                       char *const envp[], int resolve_path,
                       const char *fname)
{
  int rc;
  char **new_env;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) )
    citp_do_init(CITP_INIT_ENVIRON);

  new_env = citp_environ_check_preload((char **)envp);

  /* No citp_enter_lib() / citp_exit_lib() needed here */
  Log_CALL(ci_log("%s(\"%s\", %p, %p)", fname, path,argv,envp));
  if (new_env == NULL) {
    Log_E(log("%s: no memory for modified environment", __FUNCTION__));
    errno = ENOMEM;
    rc =  -1;
  } else if (!resolve_path) {
    Log_V(log("execve: %s", path));
    rc = ci_sys_execve(path, argv, new_env);
  } else {
    ci_assert_equal(envp, __environ);
    __environ = new_env;
    Log_V(log("execvp: %s", path));
    rc = ci_sys_execvp(path, argv);
  }
  Log_CALL(ci_log("%s returning %d (errno %d)", fname, rc, errno))
  return rc;
}

OO_INTERCEPT(int, execve,
             (const char *path, char *const argv[], char *const envp[]))
{
  return onload_exec(path, argv, envp, CI_FALSE, __FUNCTION__);
}


OO_INTERCEPT(int, execv,
             (const char *path, char *const argv[]))
{
  return onload_exec(path, argv, __environ, CI_FALSE, __FUNCTION__);
}


OO_INTERCEPT(int, execl,
             (const char *path, const char *arg, ...))
{
  va_list args;
  char **argv;

  va_start(args, arg);
  argv = citp_environ_handle_args(arg, args, NULL);
  va_end(args);
  if (argv == NULL) {
    Log_E(log("%s: no memory for aruments", __FUNCTION__));
    errno = ENOMEM;
    return -1;
  }
  return onload_exec(path, argv, __environ, CI_FALSE, __FUNCTION__);
}


OO_INTERCEPT(int, execlp,
             (const char *file, const char *arg, ...))
{
  va_list args;
  char **argv;

  va_start(args, arg);
  argv = citp_environ_handle_args(arg, args, NULL);
  va_end(args);
  if (argv == NULL) {
    Log_E(log("%s: no memory for aruments", __FUNCTION__));
    errno = ENOMEM;
    return -1;
  }
  return onload_exec(file, argv, __environ, CI_TRUE, __FUNCTION__);
}


OO_INTERCEPT(int, execle,
             (const char *path, const char *arg, ...))
{
  va_list args;
  char **argv, **new_env;

  va_start(args, arg);
  argv = citp_environ_handle_args(arg, args, &new_env);
  va_end(args);
  if (argv == NULL) {
    Log_E(log("%s: no memory for aruments", __FUNCTION__));
    errno = ENOMEM;
    return -1;
  }
  return onload_exec(path, argv, new_env, CI_FALSE, __FUNCTION__);
}


OO_INTERCEPT(int, execvp,
             (const char *file, char *const argv[]))
{
  return onload_exec(file, argv, __environ, CI_TRUE, __FUNCTION__);
}


OO_INTERCEPT(int, bproc_move,
             (int node))
{
  static int (*sys_bproc_move)(int) = 0;
  int fd;
  citp_fdinfo* fdinfo;
  int old_citp_log_fd = -1;
  int rc;

  if( CI_UNLIKELY(citp.init_level < CITP_INIT_ALL) ) {
    citp_do_init(CITP_INIT_SYSCALLS);
    sys_bproc_move = dlsym(RTLD_NEXT, "bproc_move");
    if (!sys_bproc_move)
      RET_WITH_ERRNO(EINVAL);
    return sys_bproc_move(node);
  }

  Log_CALL(ci_log("%s(%d)", __FUNCTION__, node));

  if (!sys_bproc_move)
    sys_bproc_move = dlsym(RTLD_NEXT, "bproc_move");

  if (sys_bproc_move) {
    /* Flush out the FD table, closing all user-level sockets.
    ** This is safe because the process after migration loses all open file
    ** descriptors, we are just removing everything before the move.
    **
    ** \TODO To turn this from a hack into a solution, we need to handle ther
    **  case if the move fails, ideally we need to be able to move with
    **  everything in place and tidy up afterwards.
    */
    for (fd = 0; fd < citp_fdtable.inited_count; fd++) {
      /* This is slow (taking and releasing the FD table lock lots) but it
      ** works.
      */
      fdinfo = citp_fdtable_lookup_noprobe(fd);
      if (fdinfo) {
        close(fd);
        citp_fdinfo_release_ref(fdinfo, 0);
      }
    }

    /* Close and destruct any remaining netifs */
    citp_netif_pre_bproc_move_hook();

    CITP_LOCK(&citp_ul_lock);

    /* Stop the logging, we won't be abole to continue logging to a file
    ** descriptor after migration.
    */
    if ((!CITP_OPTS.log_via_ioctl) && (citp.log_fd >= 0)) {
      old_citp_log_fd = citp.log_fd;
      citp.log_fd = -1;
      __citp_fdtable_reserve(old_citp_log_fd, 0);
    }

    /* Force the complete FD table space to be reprobed */
    citp_fdtable.inited_count = 0;

    CITP_UNLOCK(&citp_ul_lock);

    /* Close the old logging FD */
    if (old_citp_log_fd >= 0)
      close(old_citp_log_fd);

    rc = sys_bproc_move(node);
  }
  else
    CI_SET_ERROR(rc, EINVAL);

  Log_CALL_RESULT(rc);
  return rc;
}



#ifdef __GLIBC__
/**********************************************************************
 * Aliases
 */

/* We define these so we can intercept I/O calls from within GLIBC.
**
** For example: fprintf(fd, "Hello")
** will call __write within glibc hence we need to catch this here
** because fd might be a socket.
**
** Note: this doesn't work with more recent versions of glibc, because it is
** compiled with "hidden plt" which makes it go slightly faster, at the cost
** of not correctly handling the overriding of weak symbols :-(  To cope with
** that we intercept fdopen and in such cases pass all handling down to the
** kernel.
**
** ?? FIXME: I suspect these are no longer needed.
*/
strong_alias(onload_read, __read)
strong_alias(onload_write, __write)
#endif

/*
 * vi: sw=2:ai:aw
 * vim: et:ul=0
 */
/*! \cidoxg_end */
