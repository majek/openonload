/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Wrapper for recvmmsg to allow transparent usage on older systems
**   \date  2011/01/17
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_RECVMMSG_H__

#include <dlfcn.h>

#include "libc_compat.h" /* for CI_HAVE_RECVMMSG_CONST_TIMESPEC */

#include <linux/socket.h>

#ifdef MSG_WAITFORONE
# define RECVMMSG_AVAILABLE
#endif


#ifndef RECVMMSG_AVAILABLE
# define MSG_WAITFORONE  0x10000
struct mmsghdr {
  struct msghdr  msg_hdr;
  unsigned       msg_len;
};
#endif


#ifdef __NR_recvmmsg
#ifdef __GNUC__
__attribute__((unused))
#endif
static int sc_recvmmsg(int fd, struct mmsghdr* mmsg, unsigned vlen,
                       int flags,
#if ! CI_HAVE_RECVMMSG_NOCONST_TIMESPEC
                       const
#endif
                       struct timespec* timeout)
{
  return syscall(__NR_recvmmsg, fd, mmsg, vlen, flags, timeout);
}
#endif


#ifndef RECVMMSG_AVAILABLE
#ifdef __GNUC__
__attribute__((unused))
#endif
static int recvmmsg(int fd, struct mmsghdr* mmsg, unsigned vlen,
                    int flags, const struct timespec* timeout)
{
  static int (*p_recvmmsg)(int, struct mmsghdr*, unsigned, int,
                           const struct timespec*);
  if( p_recvmmsg == NULL ) {
    p_recvmmsg = (int (*)(int, struct mmsghdr*, unsigned int, 
                          int, const struct timespec*))
      dlsym(RTLD_NEXT, "recvmmsg");
#ifdef __NR_recvmmsg
    if( p_recvmmsg == NULL )
      p_recvmmsg = sc_recvmmsg;
#endif
    if( p_recvmmsg == NULL ) {
      fprintf(stderr, "recvmmsg not linked and don't know value of"
              " __NR_recvmmsg\n");
      errno = ENOSYS;
      return -1;
    }
  }
  return p_recvmmsg(fd, mmsg, vlen, flags, timeout);
}
#endif

#endif /* __CI_APP_RECVMMSG_H__ */
/*! \cidoxg_end */
