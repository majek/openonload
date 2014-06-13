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
**  \brief  Sockets interface to user level pipe
**   \date  2004/06/02 (pipe version)
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "internal.h"
#if CI_CFG_USERSPACE_PIPE
#include "ul_pipe.h"
#include "ul_poll.h"
#include "ul_select.h"
#include "ul_epoll.h"
#include <ci/internal/cplane_ops.h>
#include <ci/internal/cplane_handle.h>
#include <onload/ul/tcp_helper.h>
#include <onload/oo_pipe.h>
#include <onload/tcp_poll.h>


#define VERB(x) Log_VTC(x)

# define LOG_PIPE(x...)

#define LPF "citp_pipe_"

#define fdi_to_pipe(_fdi) (fdi_to_pipe_fdi(_fdi))->pipe
#define fdi_is_reader(_fdi) ((_fdi)->protocol == &citp_pipe_read_protocol_impl)


static void citp_pipe_dtor(citp_fdinfo* fdinfo, int fdt_locked)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  LOG_PIPE("%s: fdinfo=%p epi=%p", __FUNCTION__, fdinfo, epi);

  citp_netif_release_ref(epi->ni, fdt_locked);
  LOG_PIPE("%s: done", __FUNCTION__);
}

static int citp_pipe_close(citp_fdinfo *fdi, int may_cache)
{
  return 0;
}

static citp_fdinfo* citp_pipe_dup(citp_fdinfo* orig_fdi)
{
  citp_fdinfo*   fdi;
  citp_pipe_fdi* epi;
  struct oo_pipe*       p = fdi_to_pipe(orig_fdi);

  epi = CI_ALLOC_OBJ(citp_pipe_fdi);
  if (!epi)
    return NULL;

  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, orig_fdi->protocol);
  epi->ni = (fdi_to_pipe_fdi(orig_fdi))->ni;
  epi->pipe = p;

  /* we use pages_buf from netif - don't want it to be gone too fast */
  citp_netif_add_ref(epi->ni);
  return fdi;
}

static int citp_pipe_recv(citp_fdinfo* fdinfo,
                          struct msghdr* msg, int flags)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  ci_assert_equal(flags, 0);
  ci_assert(msg);
  ci_assert(msg->msg_iov);

  return ci_pipe_read(epi->ni, epi->pipe, msg->msg_iov, msg->msg_iovlen);
}


static int citp_pipe_send(citp_fdinfo* fdinfo,
                          const struct msghdr* msg, int flags)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  ci_assert_equal(flags, 0);
  ci_assert(msg);
  ci_assert(msg->msg_iov);

  return ci_pipe_write(epi->ni, epi->pipe, msg->msg_iov, msg->msg_iovlen);
}

#if CI_CFG_USERSPACE_SELECT


static int citp_pipe_select_reader(citp_fdinfo* fdinfo, int* n,
                                   int rd, int wr, int ex,
                                   struct oo_ul_select_state* ss)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask = 0;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

  /* set mask */
  mask = oo_pipe_poll_read_events(p);

  if( rd && (mask & SELECT_RD_SET) ) {
    FD_SET(fdinfo->fd, ss->rdu);
    ++*n;
  }

  return 1;
}

static int citp_pipe_select_writer(citp_fdinfo* fdinfo, int* n,
                                   int rd, int wr, int ex,
                                   struct oo_ul_select_state* ss)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

  /* set mask */
  mask = oo_pipe_poll_write_events(p);

  if( wr && (mask & SELECT_WR_SET) ) {
    FD_SET(fdinfo->fd, ss->wru);
    ++*n;
  }

  return 1;
}

static int citp_pipe_poll_reader(citp_fdinfo* fdinfo, struct pollfd* pfd,
                                 struct oo_ul_poll_state* ps)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

  /* set mask */
  mask = oo_pipe_poll_read_events(p);

  /* set revents */
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);

  return 1;
}


static int citp_pipe_poll_writer(citp_fdinfo* fdinfo, struct pollfd* pfd,
                                 struct oo_ul_poll_state* ps)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

  /* set mask */
  mask = oo_pipe_poll_write_events(p);

  /* set revents */
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);

  return 1;
}


#endif  /* CI_CFG_USERSPACE_SELECT */

#ifdef CI_CFG_USERSPACE_EPOLL

static void citp_pipe_epoll_reader(citp_fdinfo* fdinfo,
                                   struct citp_epoll_member* eitem,
                                   struct oo_ul_epoll_state* eps)
{
  unsigned mask;
  struct oo_pipe* pipe = fdi_to_pipe_fdi(fdinfo)->pipe;
  ci_uint64 sleep_seq = pipe->b.sleep_seq.all;
  mask = oo_pipe_poll_read_events(pipe);
  citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq);
}


static void citp_pipe_epoll_writer(citp_fdinfo* fdinfo,
                                   struct citp_epoll_member* eitem,
                                   struct oo_ul_epoll_state* eps)
{
  unsigned mask;
  struct oo_pipe* pipe = fdi_to_pipe_fdi(fdinfo)->pipe;
  ci_uint64 sleep_seq = pipe->b.sleep_seq.all;
  mask = oo_pipe_poll_write_events(pipe);
  citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq);
}

#endif

/* fixme kostik: this is partially copy-paste from citp_sock_fcntl */
static int citp_pipe_fcntl(citp_fdinfo* fdinfo, int cmd, long arg)
{
  int rc = 0;
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);
  struct oo_pipe* p = epi->pipe;

  switch ( cmd ) {
  case F_GETFL: {
    ci_uint32 flag_nonb = CI_PFD_AFLAG_NONBLOCK;
    if( ! fdi_is_reader(fdinfo) ) {
      rc = O_WRONLY;
      flag_nonb <<= CI_PFD_AFLAG_WRITER_SHIFT;
    }
    else
      flag_nonb <<= CI_PFD_AFLAG_READER_SHIFT;
    if ( p->aflags & flag_nonb ) rc |= O_NONBLOCK;
    break;
  }
  case F_SETFL: {
    ci_uint32 bit;

    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    if( rc < 0 )
      break;

    bit = CI_PFD_AFLAG_NONBLOCK <<
                (fdi_is_reader(fdinfo) ? CI_PFD_AFLAG_READER_SHIFT :
                 CI_PFD_AFLAG_WRITER_SHIFT);
    if( arg & (O_NONBLOCK | O_NDELAY) )
      ci_bit_mask_set(&p->aflags, bit);
    else
      ci_bit_mask_clear(&p->aflags, bit);
    break;
  }
  case F_DUPFD:
    rc = citp_ep_dup(fdinfo->fd, citp_ep_dup_fcntl_dup, arg);
    break;
#ifdef F_DUPFD_CLOEXEC
  case F_DUPFD_CLOEXEC:
    rc = citp_ep_dup(fdinfo->fd, citp_ep_dup_fcntl_dup_cloexec, arg);
    break;
#endif
  case F_GETFD:
  case F_SETFD:
    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    break;
  case F_GETLK:
  case F_SETLK:
  case F_SETLKW:
    /* File locks not supported on sockets */
    Log_U(ci_log("%s: cmd %d not supported on sockets!",__FUNCTION__,
                 cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;
  case F_GETOWN:
  case F_SETOWN:
#ifdef F_GETOWN_EX
  case F_GETOWN_EX:
#endif
#ifdef F_SETOWN_EX
  case F_SETOWN_EX:
#endif
    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    if( rc != 0 )
        break;
    p->b.sigown = arg;
    if( p->b.sigown && (p->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&p->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;
  default:
    /* fixme kostik: logging should include some pipe identification */
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
  }

  Log_VSC(log("%s(%d, %d, %ld) = %d  (errno=%d)",
              __FUNCTION__, fdinfo->fd, cmd, arg, rc, errno));

  return rc;
}

/* handler for io operations on _wrong_ side of the pipe */
static int citp_pipe_send_none(citp_fdinfo* fdinfo,
                               const struct msghdr* msg, int flags)
{
  errno = EBADF;
  return -1;
}

/* handler for io operations on _wrong_ side of the pipe */
static int citp_pipe_recv_none(citp_fdinfo* fdinfo,
                               struct msghdr* msg, int flags)
{
  errno = EBADF;
  return -1;
}

static int citp_pipe_bind(citp_fdinfo* fdinfo,
                          const struct sockaddr* sa, socklen_t sa_len)
{
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}

static int citp_pipe_listen(citp_fdinfo* fdinfo, int backlog)
{
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_accept(citp_fdinfo* fdinfo,
                             struct sockaddr* sa, socklen_t* p_sa_len,
                             int flags,
                             citp_lib_context_t* lib_context)
{
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_connect(citp_fdinfo* fdinfo,
                              const struct sockaddr* sa, socklen_t sa_len,
                              citp_lib_context_t* lib_context)
{
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_shutdown(citp_fdinfo* fdinfo, int how)
{
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_getsockname(citp_fdinfo* fdinfo,
                                  struct sockaddr* sa, socklen_t* p_sa_len)
{
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_getpeername(citp_fdinfo* fdinfo,
                                  struct sockaddr* sa, socklen_t* p_sa_len)
{
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_getsockopt(citp_fdinfo* fdinfo, int level,
                                 int optname, void* optval, socklen_t* optlen)
{
  errno = ENOTSOCK;
  return -1;
}
static int citp_pipe_setsockopt(citp_fdinfo* fdinfo, int level, int optname,
                                 const void* optval, socklen_t optlen)
{
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}

static int citp_pipe_ioctl(citp_fdinfo *fdinfo, int cmd, void *arg)
{
  int rc = 0;
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);
  struct oo_pipe* p = epi->pipe;

  switch( cmd ) {
  case FIONBIO:
  {
    int b = *(int* )arg;
    ci_uint32 bit = CI_PFD_AFLAG_NONBLOCK <<
                      (fdi_is_reader(fdinfo) ? CI_PFD_AFLAG_READER_SHIFT :
                       CI_PFD_AFLAG_WRITER_SHIFT);

    LOG_PIPE("%s: set non-blocking mode '%s'",
             __FUNCTION__, b ? "ON" : "OFF");

    if( b )
      ci_bit_mask_set(&p->aflags, bit);
    else
      ci_bit_mask_clear(&p->aflags, bit);

    break;
  }
  case FIONREAD:
  {
    /* NOTE: a normal user would expect that FIONREAD returns zero or
     * even an error when called on 'write' end of the pipe. But Linux
     * thinks it's reasonable to return 'correct' amount of data in the pipe
     * regardless of the actul fd. */
    int *r = (int* )arg;

    /* we don't need any lock here as actual 'read' of the variable is atomic */
    *r = p->bytes_added - p->bytes_removed;
    break;
  }
  default:
    errno = ENOSYS;
    rc = -1;
    break;
  }
  /* fixme kostik : support of ioctl should be added */
  return rc;
}


static int citp_pipe_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg,
                                 int flags)
{
  msg->rc = -ENOTSOCK;
  return 1;
}


static int citp_pipe_zc_recv(citp_fdinfo* fdi,
                                 struct onload_zc_recv_args* args)
{
  return -ENOTSOCK;
}


static int citp_pipe_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg,
                                        int flags)
{
  return -ENOTSOCK;
}


static int citp_pipe_zc_recv_filter(citp_fdinfo* fdi,
                                        onload_zc_recv_filter_callback filter,
                                        void* cb_arg, int flags)
{
#if CI_CFG_ZC_RECV_FILTER
  return -ENOTSOCK;
#else
  return -ENOSYS;
#endif
}


int citp_pipe_tmpl_alloc(citp_fdinfo* fdi, struct iovec* initial_msg,
                         int mlen, struct oo_msg_template** omt_pp,
                         unsigned flags)
{
  return -EOPNOTSUPP;
}


int citp_pipe_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                          struct onload_template_msg_update_iovec* updates,
                          int ulen, unsigned flags)
{
  return -EOPNOTSUPP;
}


int citp_pipe_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt)
{
  return -EOPNOTSUPP;
}


/* Read and write ends of the pipe have different protocol implementations in the same
 * manner as they have them separate in linux kernel. All io-unrelated hooks are common,
 * reader has no write/send support of any kind, writer has no read/recv support.
 */
citp_protocol_impl citp_pipe_read_protocol_impl = {
  .type        = CITP_PIPE_FD,
  .ops         = {
    .socket      = NULL,        /* nobody should ever call this */
    .dtor        = citp_pipe_dtor,
    .dup         = citp_pipe_dup,
    .bind        = citp_pipe_bind,
    .listen      = citp_pipe_listen,
    .accept      = citp_pipe_accept,
    .connect     = citp_pipe_connect,
    .close       = citp_pipe_close,
    .shutdown    = citp_pipe_shutdown,
    .getsockname = citp_pipe_getsockname,
    .getpeername = citp_pipe_getpeername,
    .getsockopt  = citp_pipe_getsockopt,
    .setsockopt  = citp_pipe_setsockopt,
    .recv        = citp_pipe_recv,
#if CI_CFG_RECVMMSG
    .recvmmsg    = citp_nosock_recvmmsg,
#endif
    .send        = citp_pipe_send_none,
#if CI_CFG_SENDMMSG
    .sendmmsg    = citp_nosock_sendmmsg,
#endif
    .fcntl       = citp_pipe_fcntl,
    .ioctl       = citp_pipe_ioctl,
#if CI_CFG_USERSPACE_SELECT
    .select	 = citp_pipe_select_reader,
    .poll	 = citp_pipe_poll_reader,
#if CI_CFG_USERSPACE_EPOLL
    .epoll       = citp_pipe_epoll_reader,
#endif
#endif
    .zc_send     = citp_pipe_zc_send,
    .zc_recv     = citp_pipe_zc_recv,
    .zc_recv_filter = citp_pipe_zc_recv_filter,
    .recvmsg_kernel = citp_pipe_recvmsg_kernel,
#if CI_CFG_SENDFILE
    /* qustion kostik: will we ever ever need this??? */
    .sendfile_post_hook = NULL,
#endif
    .tmpl_alloc    = citp_pipe_tmpl_alloc,
    .tmpl_update   = citp_pipe_tmpl_update,
    .tmpl_abort    = citp_pipe_tmpl_abort,
  }
};

citp_protocol_impl citp_pipe_write_protocol_impl = {
  .type        = CITP_PIPE_FD,
  .ops         = {
    .socket      = NULL,        /* nobody should ever call this */
    .dtor        = citp_pipe_dtor,
    .dup         = citp_pipe_dup,
    .bind        = citp_pipe_bind,
    .listen      = citp_pipe_listen,
    .accept      = citp_pipe_accept,
    .connect     = citp_pipe_connect,
    .close       = citp_pipe_close,
    .shutdown    = citp_pipe_shutdown,
    .getsockname = citp_pipe_getsockname,
    .getpeername = citp_pipe_getpeername,
    .getsockopt  = citp_pipe_getsockopt,
    .setsockopt  = citp_pipe_setsockopt,
    .recv        = citp_pipe_recv_none,
#if CI_CFG_RECVMMSG
    .recvmmsg    = citp_nosock_recvmmsg,
#endif
    .send        = citp_pipe_send,
#if CI_CFG_SENDMMSG
    .sendmmsg    = citp_nosock_sendmmsg,
#endif
    .fcntl       = citp_pipe_fcntl,
    .ioctl       = citp_pipe_ioctl,
#if CI_CFG_USERSPACE_SELECT
    .select	 = citp_pipe_select_writer,
    .poll	 = citp_pipe_poll_writer,
#if CI_CFG_USERSPACE_EPOLL
    .epoll       = citp_pipe_epoll_writer,
#endif
#endif
    .zc_send     = citp_pipe_zc_send,
    .zc_recv     = citp_pipe_zc_recv,
    .zc_recv_filter = citp_pipe_zc_recv_filter,
    .recvmsg_kernel = citp_pipe_recvmsg_kernel,
#if CI_CFG_SENDFILE
    /* qustion kostik: will we ever ever need this??? */
    .sendfile_post_hook = NULL,
#endif
    .tmpl_alloc    = citp_pipe_tmpl_alloc,
    .tmpl_update   = citp_pipe_tmpl_update,
    .tmpl_abort    = citp_pipe_tmpl_abort,
  }
};

static citp_pipe_fdi *citp_pipe_epi_alloc(ci_netif *ni, int flags)
{
  citp_pipe_fdi* epi;

  epi = CI_ALLOC_OBJ(citp_pipe_fdi);
  if( ! epi ) {
    Log_U(ci_log(LPF "pipe: failed to allocate epi"));
    errno = ENOMEM;
    return NULL;
  }
  if( flags == O_WRONLY )
    citp_fdinfo_init(&epi->fdinfo, &citp_pipe_write_protocol_impl);
  else
    citp_fdinfo_init(&epi->fdinfo, &citp_pipe_read_protocol_impl);
  epi->ni = ni;

  return epi;
}

/* Should be called when netif is locked */
static int oo_pipe_init(ci_netif* ni, struct oo_pipe* p)
{
  int rc;

  ci_assert(ni);
  ci_assert(p);

  /* init waitable */
  citp_waitable_reinit(ni, &p->b);

  p->b.state = CI_TCP_STATE_PIPE;

  p->bytes_added = 0;
  p->bytes_removed = 0;

  p->read_ptr.bufid = 0;
  p->read_ptr.offset = 0;

  p->write_ptr.bufid = 0;
  p->write_ptr.offset = 0;

  p->aflags = 0;

  /* will be set to proper value later */
  p->bufs_num = 0;

  rc = oo_pipe_alloc_bufs(ni, p, OO_PIPE_INITIAL_BUFS);
  if( rc < 0 )
    return -1;


  return 0;
}

static struct oo_pipe* oo_pipe_buf_get(ci_netif* netif)
{
  citp_waitable_obj *wo;
  int rc = -1;

  wo = citp_waitable_obj_alloc(netif);
  if( ! wo )
    return NULL;

  rc = oo_pipe_init(netif, &wo->pipe);
  if( rc != 0 ) {
    citp_waitable_obj_free(netif, &wo->waitable);

    return NULL;
  }

  return &wo->pipe;
}

static int oo_pipe_ctor(ci_netif* netif, struct oo_pipe** out_pipe,
                        int fds[2], int flags)
{
  struct oo_pipe* p;
  int rc;

  ci_assert(netif);

  ci_netif_lock(netif);
  p = oo_pipe_buf_get(netif);
  if( !p ) {
    rc = -1;
    /* in fact it's ENOSPC, but pipe specification allows only EFAULT */
    errno = EFAULT;
    goto out;
  }

  if( flags & O_NONBLOCK ) {
    p->aflags = (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_READER_SHIFT) |
        (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT);
  }

  /* attach */
  rc = ci_tcp_helper_pipe_attach(ci_netif_get_driver_handle(netif),
                                 W_SP(&p->b), flags, fds);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ci_tcp_helper_pipe_attach %d", __FUNCTION__, rc));
    /* fixme kostik: cleanup */
    CI_TEST(0);
    goto out;
  }

  *out_pipe = p;

out:
  ci_netif_unlock(netif);

  return rc;
}

/* we don't register protocol impl */
int citp_pipe_create(int fds[2], int flags)
{
  citp_pipe_fdi* epi_read;
  citp_pipe_fdi* epi_write;
  struct oo_pipe* p = NULL;         /* make compiler happy */
  ci_netif* ni;
  int rc = -1;
  ef_driver_handle fd = -1;

  Log_V(log(LPF "pipe()"));

  CITP_LOCK(&citp_ul_lock);
  if( CITP_OPTS.ul_pipe == CI_UNIX_PIPE_ACCELERATE_IF_NETIF &&
      ! citp_netif_exists() ) {
    CITP_UNLOCK(&citp_ul_lock);
    return CITP_NOT_HANDLED;
  }
  CITP_UNLOCK(&citp_ul_lock);

  rc = citp_netif_alloc_and_init(&fd, &ni);
  if( rc != 0 ) {
    if( rc == CI_SOCKET_HANDOVER ) {
      /* This implies EF_DONT_ACCELERATE is set, so we handover
       * regardless of CITP_OPTS.no_fail */
      return CITP_NOT_HANDLED;
    }
    /* may be lib mismatch - errno will be ELIBACC */
    goto fail1;
  }
  rc = -1;

  CI_MAGIC_CHECK(ni, NETIF_MAGIC);

  /* add another reference as we have 2 fdis */
  citp_netif_add_ref(ni);

  epi_read = citp_pipe_epi_alloc(ni, O_RDONLY);
  if( epi_read == NULL )
    goto fail2;
  epi_write = citp_pipe_epi_alloc(ni, O_WRONLY);
  if( epi_write == NULL )
    goto fail3;

  /* oo_pipe init code */
  if( fdtable_strict() )  CITP_FDTABLE_LOCK();
  rc = oo_pipe_ctor(ni, &p, fds, flags);
  if( rc < 0 )
      goto fail4;
  citp_fdtable_new_fd_set(fds[0], fdip_busy, fdtable_strict());
  citp_fdtable_new_fd_set(fds[1], fdip_busy, fdtable_strict());
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();

  LOG_PIPE("%s: pipe=%p id=%d", __FUNCTION__, p, p->b.bufid);

  /* as pipe is created it should be attached to the end-points */
  epi_read->pipe = p;
  epi_write->pipe = p;

  /* We're ready.  Unleash us onto the world! */
  ci_assert(epi_read->pipe->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_assert(epi_write->pipe->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&epi_read->pipe->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&epi_read->pipe->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  citp_fdtable_insert(&epi_read->fdinfo, fds[0], 0);
  citp_fdtable_insert(&epi_write->fdinfo, fds[1], 0);

  CI_MAGIC_CHECK(ni, NETIF_MAGIC);

  return 0;

fail4:
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
fail3:
  CI_FREE_OBJ(epi_write);
fail2:
  CI_FREE_OBJ(epi_read);
  citp_netif_release_ref(ni, 0);
  citp_netif_release_ref(ni, 0);
fail1:
  if( CITP_OPTS.no_fail && errno != ELIBACC ) {
    Log_U(ci_log("%s: failed (errno:%d) - PASSING TO OS", __FUNCTION__, errno));
    return CITP_NOT_HANDLED;
  }

  return rc;
}
#endif
