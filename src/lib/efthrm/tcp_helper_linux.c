/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2006/06/16
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <ci/internal/ip.h>
#include <onload/tcp_helper_fns.h>
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_poll.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <driver/linux_affinity/autocompat.h>



/* file_operations might have readv/writev, aio_read/aio_write,
 * read_iter/write_iter members.  To support this variety, we define one
 * simple handler and derive whatever this kernel needs from it. */
#ifdef EFRM_HAVE_FOP_READV
#define DEFINE_FOP_RW_V(base_handler, rw_v_handler) \
  static ssize_t rw_v_handler(struct file *filp, const struct iovec *iov,   \
                              unsigned long iovlen, loff_t *off)            \
  { return base_handler(filp, iov, iovlen); }
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
#define DEFINE_FOP_AIO_RW(base_handler, aio_rw_handler) \
  static ssize_t aio_rw_handler(struct kiocb *iocb, const struct iovec *iov,\
                                unsigned long iovlen, loff_t pos)           \
  { if (!is_sync_kiocb(iocb))                                               \
      return -EOPNOTSUPP;                                                   \
    return base_handler(iocb->ki_filp, iov, iovlen); }
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
#define DEFINE_FOP_RW_ITER(base_handler, rw_iter_handler) \
  static ssize_t rw_iter_handler(struct kiocb *iocb, struct iov_iter *v)    \
  { if (!is_sync_kiocb(iocb))                                               \
      return -EOPNOTSUPP;                                                   \
    if( ~v->type & ITER_IOVEC )                                             \
      return -EOPNOTSUPP;                                                   \
    return base_handler(iocb->ki_filp, v->iov, v->nr_segs); }
#endif



#ifndef EFRM_HAVE___VFS_READ_EXPORTED
static inline ssize_t oo___vfs_read(struct file *file, char __user *buf,
                                 size_t count, loff_t *pos)
{
  if( file->f_op->read )
    return file->f_op->read(file, buf, count, pos);
  else
    return do_sync_read(file, buf, count, pos);
}
#define __vfs_read oo___vfs_read
static inline ssize_t oo___vfs_write(struct file *file, const char __user *buf,
                                  size_t count, loff_t *pos)
{
  if( file->f_op->write )
    return file->f_op->write(file, buf, count, pos);
  else
    return do_sync_write(file, buf, count, pos);
}
#define __vfs_write oo___vfs_write
#endif



/* poll_requested_events_max(): user is not interested in other events */
#ifdef EFRM_HAVE_POLL_REQUESTED_EVENTS
#define poll_requested_events_max(p) \
    (poll_requested_events(p) | POLLERR | POLLHUP)
#else
#define poll_requested_events_max(p) ~0UL
#endif

/* poll_requested_events_min(): user will not block if got one of these */

#ifdef EFRM_POLL_TABLE_HAS_OLD_KEY
static inline unsigned long poll_requested_events_min(const poll_table *p)
{
  return p && p->key != 0UL ? p->key : (POLLERR | POLLHUP);
}
#elif defined(EFRM_HAVE_POLL_REQUESTED_EVENTS)
static inline unsigned long poll_requested_events_min(const poll_table *p)
{
  return p && p->_key != 0UL ? p->_key : (POLLERR | POLLHUP);
}
#else
#define poll_requested_events_min(p) (POLLERR | POLLHUP)
#endif

#define POLL_CAN_NOT_BLOCK(mask, wait) \
  ( (poll_requested_events_min(wait) & (mask)) )

/* Is it possible for a thread polling the socket to block and later be
 * woken, given the mask value provided?
 *
 * NB. No assumptions can be made if these return false.
 *
 * There are crazy cases when sys_poll() blocks waiting for POLLHUP or
 * something like that (POLLPRI).  In such a case, we are not awaiting any
 * events from network and do not enable interrupts.
 */
#define SOCK_POLL_AWAITING_EVENTS(mask, wait)                       \
  ( ! POLL_CAN_NOT_BLOCK((mask), (wait)) &&                         \
    ( ((mask) & (POLLIN | POLLOUT)) !=                              \
      (poll_requested_events_max(wait) & (POLLIN | POLLOUT)) ) )


static inline int
efab_fop_poll__poll_if_needed(tcp_helper_resource_t* trs, citp_waitable* w)
{
  ci_netif* ni = &trs->netif;

  if(CI_UNLIKELY( ! (w->sb_aflags & CI_SB_AFLAG_AVOID_INTERRUPTS) &&
                  ! ci_netif_is_spinner(ni) && ci_netif_not_primed(ni) )) {
    /* No-one is spinning, and interrupts are not primed.  So (a) we need
     * to bring this stack up-to-date and (b) we should enable interrupts
     * if we're going to block.
     *
     * NB. This is deliberately after setting the [wake_request] bits so
     * that if poll does make this socket "ready" then we won't leave the
     * [wake_request] bits set unnecessarily (which might incur significant
     * expense later).
     */
    if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) &&
        efab_tcp_helper_netif_try_lock(trs, 0) ) {
      ci_netif_poll(ni);
      efab_tcp_helper_netif_unlock(trs, 0);
    }
    return 1;
  }
  return 0;
}


static inline void
efab_fop_poll__prime_if_needed(tcp_helper_resource_t* trs,
                               tcp_helper_endpoint_t* ep,
                               int mask_awaiting_events,
                               int enable_interrupts)
{
  OO_DEBUG_ASYNC(ci_log("%s: [%d:%d] mask_awaiting_events=%d waitq_active=%d "
                        "enable_interrupts=%d", __FUNCTION__,
                        trs->id, ep->id, mask_awaiting_events,
                        waitqueue_active(&ep->waitq.wq), enable_interrupts));
  if( mask_awaiting_events && waitqueue_active(&ep->waitq.wq)
      ) {
    /* This thread looks likely to block on this socket. */
    ci_frc64(&trs->netif.state->last_sleep_frc);
    if( enable_interrupts ) {
      OO_DEBUG_ASYNC(ci_log("%s: [%d:%d] enable interrupts",
                            __FUNCTION__, trs->id, ep->id));
      tcp_helper_request_wakeup(trs);
      CITP_STATS_NETIF_INC(&trs->netif, select_primes);
    }
  }
}


#if CI_CFG_USERSPACE_PIPE
static ssize_t linux_tcp_helper_fop_read_pipe(struct file *filp, char *buf,
                                              size_t len, loff_t *off)
{
  ci_private_t *priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct iovec iov[1];

  iov[0].iov_base = buf;
  iov[0].iov_len = len;

  return ci_pipe_read(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                      iov, 1);
}
static ssize_t linux_tcp_helper_fop_write_pipe(struct file *filp,
                                               const char *buf,
                                               size_t len, loff_t *off)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct iovec iov[1];

  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = len;

  return ci_pipe_write(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                       iov, 1);
}

static ssize_t linux_tcp_helper_fop_read_iov_pipe(struct file *filp,
                                                  const struct iovec *iov,
                                                  unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);

  return ci_pipe_read(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                      iov, iovlen);
}
static ssize_t linux_tcp_helper_fop_write_iov_pipe(struct file *filp,
                                                   const struct iovec *iov,
                                                   unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);

  return ci_pipe_write(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                       iov, iovlen);
}
#ifdef EFRM_HAVE_FOP_READV
DEFINE_FOP_RW_V(linux_tcp_helper_fop_read_iov_pipe, \
                linux_tcp_helper_fop_readv_pipe)
DEFINE_FOP_RW_V(linux_tcp_helper_fop_write_iov_pipe, \
                linux_tcp_helper_fop_writev_pipe)
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_read_iov_pipe, \
                  linux_tcp_helper_fop_aio_read_pipe)
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_write_iov_pipe, \
                  linux_tcp_helper_fop_aio_write_pipe)
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_read_iov_pipe, \
                   linux_tcp_helper_fop_read_iter_pipe)
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_write_iov_pipe, \
                   linux_tcp_helper_fop_write_iter_pipe)
#endif


static ssize_t linux_tcp_helper_fop_read_notsupp(struct file *filp, char *buf,
                                                 size_t len, loff_t *off)
{
  return -EOPNOTSUPP;
}
static ssize_t linux_tcp_helper_fop_write_notsupp(struct file *filp,
                                                  const char *buf,
                                                  size_t len, loff_t *off)
{
  return -EOPNOTSUPP;
}
#ifdef EFRM_HAVE_FOP_READV
static ssize_t linux_tcp_helper_fop_rw_v_notsupp(struct file *filp,
                                          const struct iovec *iov,
                                          unsigned long iovlen, loff_t *off)
{
  return -EOPNOTSUPP;
}
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
static ssize_t linux_tcp_helper_fop_aio_rw_notsupp(struct kiocb *iocb, 
                                             const struct iovec *iov, 
                                             unsigned long iovlen, loff_t pos)
{
  return -EOPNOTSUPP;
}
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
static ssize_t linux_tcp_helper_fop_rw_iter_notsupp(struct kiocb *iocb,
                                                      struct iov_iter *tofrom)
{
  return -EOPNOTSUPP;
}
#endif



static unsigned linux_tcp_helper_fop_poll_pipe_reader(struct file* filp,
                                                      poll_table* wait)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct oo_pipe* pipe = SP_TO_PIPE(&trs->netif, priv->sock_id);

  poll_wait(filp, &TCP_HELPER_WAITQ(trs, priv->sock_id)->wq, wait);
  ci_atomic32_or(&pipe->b.wake_request, CI_SB_FLAG_WAKE_RX);
  return oo_pipe_poll_read_events(pipe);
}


static unsigned linux_tcp_helper_fop_poll_pipe_writer(struct file* filp,
                                                      poll_table* wait)
{
  ci_private_t *priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct oo_pipe* pipe = SP_TO_PIPE(&trs->netif, priv->sock_id);

  poll_wait(filp, &TCP_HELPER_WAITQ(trs, priv->sock_id)->wq, wait);
  ci_atomic32_or(&pipe->b.wake_request, CI_SB_FLAG_WAKE_TX);
  return oo_pipe_poll_write_events(pipe);
}
#endif


static unsigned efab_linux_tcp_helper_fop_poll_tcp(struct file* filp,
					    tcp_helper_resource_t* trs,
					    oo_sp id,
					    poll_table* wait)
{
  tcp_helper_endpoint_t* tep_p;
  int enable_interrupts = 0;
  unsigned mask = 0;
  ci_sock_cmn* s;
  ci_netif* ni;

  ci_assert(filp);
  ci_assert(trs);
  ni = &trs->netif;
  s = SP_TO_SOCK(ni, id);

  OO_DEBUG_ASYNC(ci_log("efab_linux_tcp_helper_fop_poll_tcp: "NSS_FMT
                        " wait=%p", NSS_PRI_ARGS(ni, s), wait));

  /* Register the wait queue.  This needs to happen before we set the
   * [wake_request] bits, which in turn need to happen before we test any
   * state.
   */
  poll_wait(filp, &TCP_HELPER_WAITQ(trs, id)->wq, wait);
  ci_atomic32_or(&s->b.wake_request, CI_SB_FLAG_WAKE_TX | CI_SB_FLAG_WAKE_RX);
  enable_interrupts = efab_fop_poll__poll_if_needed(trs, &s->b);
  tep_p = ci_trs_ep_get(trs, id);

  mask = ci_tcp_poll_events(ni, s);
  efab_fop_poll__prime_if_needed(trs, tep_p,
                                 SOCK_POLL_AWAITING_EVENTS(mask, wait),
                                 enable_interrupts);
  if( ! poll_does_not_wait(wait) && s->b.state == CI_TCP_CLOSED &&
      tep_p->os_socket  != NULL) {
    /* From the closed state, handover is possible.  We should add OS
     * socket waitqueue to the poll table.
     */
    struct file *os_sock;
    int drop_rc;
    OO_OS_SOCKET_FOP(tep_p, os_sock, drop_rc, poll, wait);
  }

  OO_DEBUG_ASYNC(ci_log("%s: return 0x%x, enable_interrupts=%d",
                        __FUNCTION__, mask, enable_interrupts));
  return mask;
}


static unsigned linux_tcp_helper_fop_poll_tcp(struct file* filp,
                                              poll_table* wait)
{
  ci_private_t *priv;

  priv = filp->private_data;
  return efab_linux_tcp_helper_fop_poll_tcp(filp, efab_priv_to_thr(priv), 
					    priv->sock_id, wait);
}

static unsigned linux_tcp_helper_fop_poll_udp(struct file* filp,
                                              poll_table* wait)
{
  ci_private_t* priv;
  tcp_helper_endpoint_t* tep_p;
  tcp_helper_resource_t* trs;
  int enable_interrupts;
  ci_udp_state* us;
  ci_netif* ni;
  unsigned mask;
  oo_sp id;

  priv = filp->private_data;
  if( filp->f_op != &linux_tcp_helper_fops_udp)
    return POLLERR;

  trs = efab_priv_to_thr(priv);
  ni = &trs->netif;
  id = priv->sock_id;
  us = SP_TO_UDP(ni, id);
  tep_p = ci_trs_ep_get(trs, id);

  OO_DEBUG_ASYNC(ci_log("%s: %d:%d %s:%d wait=%p", __FUNCTION__,
                        NI_ID(ni), OO_SP_FMT(id),
                        ip_addr_str(sock_laddr_be32(&us->s)),
                        (unsigned) CI_BSWAP_BE16(sock_lport_be16(&us->s)),
                        wait));

  /* NB. We cannot do an early return here like we do for TCP, because the
   * only mask values that guarantee we can't block must include POLLERR or
   * POLLHUP, and those are rarely set.  So not worth a special case.
   */

  /* Register the wait queue.  This needs to happen before we set the
   * [wake_request] bits, which in turn need to happen before we test any
   * state.
   */
  poll_wait(filp, &TCP_HELPER_WAITQ(trs, id)->wq, wait);
  ci_atomic32_or(&us->s.b.wake_request, CI_SB_FLAG_WAKE_TX|CI_SB_FLAG_WAKE_RX);
  enable_interrupts = efab_fop_poll__poll_if_needed(trs, &us->s.b);

  mask = ci_udp_poll_events(ni, us);
  efab_fop_poll__prime_if_needed(trs, tep_p,
                                 SOCK_POLL_AWAITING_EVENTS(mask, wait),
                                 enable_interrupts);

  return mask;
}


static int linux_tcp_helper_fop_close(struct inode* inode, struct file* filp)
{
  ci_private_t* priv = filp->private_data;
  int rc;
  OO_DEBUG_TCPH(ci_log("%s:", __FUNCTION__));
  generic_tcp_helper_close(priv);
  rc = oo_fop_release(inode, filp);
  OO_DEBUG_TCPH(ci_log("%s: done", __FUNCTION__));
  return rc;
}

#if CI_CFG_USERSPACE_PIPE
static int linux_tcp_helper_fop_close_pipe(struct inode* inode,
                                           struct file* filp)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  tcp_helper_endpoint_t* ep = ci_trs_ep_get(trs, priv->sock_id);
  unsigned ep_aflags;
  int rc;

  OO_DEBUG_TCPH(ci_log("%s:", __FUNCTION__));
  ci_assert_equal(SP_TO_WAITABLE(&trs->netif, ep->id)->state,
                  CI_TCP_STATE_PIPE);

  /* Set flag to indicate that we've closed one end of the pipe. */
  ep_aflags = tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);

  if( ! (ep_aflags & OO_THR_EP_AFLAG_PEER_CLOSED) ) {
    /* Other end is still open -- signal it. */
    struct oo_pipe* p = SP_TO_PIPE(&trs->netif, ep->id);
    ci_atomic32_or(&p->aflags,
                   CI_PFD_AFLAG_CLOSED <<
                   (priv->fd_type == CI_PRIV_TYPE_PIPE_READER ?
                    CI_PFD_AFLAG_READER_SHIFT : CI_PFD_AFLAG_WRITER_SHIFT));
    oo_pipe_wake_peer(&trs->netif, p, CI_SB_FLAG_WAKE_RX | CI_SB_FLAG_WAKE_TX);
  }
  else {
    /* Both ends now closed. */
    generic_tcp_helper_close(priv);
  }

  rc = oo_fop_release(inode, filp);
  OO_DEBUG_TCPH(ci_log("%s: rc=%d", __FUNCTION__, rc));
  return rc;
}
#endif

int linux_tcp_helper_fop_fasync_no_os(int fd, struct file *filp, int mode)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  tcp_helper_endpoint_t* ep = ci_trs_ep_get(trs, priv->sock_id);
  citp_waitable* w = SP_TO_WAITABLE(&trs->netif, ep->id);
  int rc;

  OO_DEBUG_ASYNC(ci_log("%s: %d:%d fd=%d mode=%d sigown=%d", __FUNCTION__,
                        N_PRI_ARGS(&trs->netif), W_FMT(w), fd, mode,
                        w->sigown));

  if( mode )
    ci_bit_mask_set(&w->sb_aflags, CI_SB_AFLAG_O_ASYNC);
  else
    ci_bit_mask_clear(&w->sb_aflags, CI_SB_AFLAG_O_ASYNC);
  if( mode && w->sigown )
    ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_RX_B);

  rc = fasync_helper(fd, filp, mode, &ep->fasync_queue);

  return rc < 0 ? rc : 0;
}

int linux_tcp_helper_fop_fasync(int fd, struct file *filp, int mode)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  tcp_helper_endpoint_t* ep = ci_trs_ep_get(trs, priv->sock_id);
  int rc;

  OO_DEBUG_ASYNC(ci_log("%s: %d:%d fd=%d mode=%d sigown=%d", __FUNCTION__,
                        N_PRI_ARGS(&trs->netif), ep->id, fd, mode,
                        SP_TO_WAITABLE(&trs->netif, ep->id)->sigown));

  rc = linux_tcp_helper_fop_fasync_no_os(fd, filp, mode);
  if( rc == 0 && ep->os_socket != NULL) {
    struct file *os_sock;
    if( oo_os_sock_get_from_ep(ep, &os_sock) == 0 ) {
      if( os_sock->f_op->fasync(fd, os_sock, mode) != 0 )
        linux_tcp_helper_fop_fasync_no_os(fd, filp, !mode);
      oo_os_sock_put(os_sock);
    }
  }
  return rc < 0 ? rc : 0;
}


CI_BUILD_ASSERT(CI_SB_AFLAG_O_NONBLOCK == MSG_DONTWAIT);


/* Onload fcntl always sets OS flags, but not vice-versa.  So, in case of
 * mismatch the last was an OS call. */
static void
fix_nonblock_flag(struct file *filp, ci_sock_cmn* s)
{
  if( ! (filp->f_flags & O_NONBLOCK) !=
      ! (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK) ) {
    if( filp->f_flags & O_NONBLOCK )
      ci_atomic32_or(&s->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK);
    else
      ci_atomic32_and(&s->b.sb_aflags, ~CI_SB_AFLAG_O_NONBLOCK);
  }
}


/*!
 * write() file operation implementation.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_write_tcp(struct file *filp, const char *buf,
                                              size_t len, loff_t *off)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct iovec iov[1];
  ci_sock_cmn* s;
  int rc;

  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = len;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN )
    return ci_tcp_sendmsg(&trs->netif, SOCK_TO_TCP(s), iov, 1,
                          (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK),
                          CI_ADDR_SPC_CURRENT);

  CI_SET_ERROR(rc, s->tx_errno);
  return rc;
}


/*!
 * writev() file operation implementation.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_write_iov_tcp(struct file *filp,
                                                  const struct iovec *iov,
                                                  unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_sock_cmn* s;
  int rc;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN )
    return ci_tcp_sendmsg(&trs->netif, SOCK_TO_TCP(s), iov, iovlen,
                          (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK),
                          CI_ADDR_SPC_CURRENT);

  CI_SET_ERROR(rc, s->tx_errno);
  return rc;
}
#ifdef EFRM_HAVE_FOP_READV
DEFINE_FOP_RW_V(linux_tcp_helper_fop_write_iov_tcp, \
                linux_tcp_helper_fop_writev_tcp)
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_write_iov_tcp, \
                  linux_tcp_helper_fop_aio_write_tcp)
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_write_iov_tcp, \
                   linux_tcp_helper_fop_write_iter_tcp)
#endif

/*!
 * write() file operation implementation for UDP case.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_write_udp(struct file *filp, const char *buf,
                                              size_t len, loff_t *off)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  ci_msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;

  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = len;
  m.msg_iov = iov;
  m.msg_iovlen = 1;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);
  /* no init for fd and ep in case of kernel space */

  return ci_udp_sendmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}

/*!
 * writev() file operation implementation for UDP case.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_write_iov_udp(struct file *filp,
                                                  const struct iovec *iov,
                                                  unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  ci_msghdr m;
  ci_sock_cmn* s;

  m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
  m.msg_iovlen = iovlen;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);

  return ci_udp_sendmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}
#ifdef EFRM_HAVE_FOP_READV
DEFINE_FOP_RW_V(linux_tcp_helper_fop_write_iov_udp, \
                linux_tcp_helper_fop_writev_udp)
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_write_iov_udp, \
                  linux_tcp_helper_fop_aio_write_udp)
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_write_iov_udp, \
                   linux_tcp_helper_fop_write_iter_udp)
#endif

/*!
 * read() file operation implementation.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_read_tcp(struct file *filp, char *buf,
                                             size_t len, loff_t *off)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_tcp_recvmsg_args a;
  ci_msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;
  int rc;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN ) {
    iov[0].iov_base = buf;
    iov[0].iov_len = len;
    m.msg_iov = iov;
    m.msg_iovlen = 1;

    /* NB. Depends on (CI_SB_AFLAG_O_NONBLOCK == MSG_DONTWAIT), which is
     * checked in a build assert above.
     */
    a.flags = s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK;
    ci_tcp_recvmsg_args_init(&a, &trs->netif, SOCK_TO_TCP(s), &m, a.flags);
    return ci_tcp_recvmsg(&a);
  }

  CI_SET_ERROR(rc, ENOTCONN);
  return rc;
}


/*!
 * readv() file operation implementation.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_read_iov_tcp(struct file *filp,
                                                 const struct iovec *iov,
                                                 unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_tcp_recvmsg_args a;
  ci_msghdr m;
  ci_sock_cmn* s;
  int rc;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN ) {
    m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
    m.msg_iovlen = iovlen;

    /* NB. Depends on (CI_SB_AFLAG_O_NONBLOCK == MSG_DONTWAIT), which is
     * checked in a build assert above.
     */
    a.flags = s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK;
    ci_tcp_recvmsg_args_init(&a, &trs->netif, SOCK_TO_TCP(s), &m, a.flags);
    return ci_tcp_recvmsg(&a);
  }

  CI_SET_ERROR(rc, ENOTCONN);
  return rc;
}
#ifdef EFRM_HAVE_FOP_READV
DEFINE_FOP_RW_V(linux_tcp_helper_fop_read_iov_tcp, \
                linux_tcp_helper_fop_readv_tcp)
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_read_iov_tcp, \
                  linux_tcp_helper_fop_aio_read_tcp)
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_read_iov_tcp, \
                   linux_tcp_helper_fop_read_iter_tcp)
#endif

/*!
 * read() file operation implementation for UDP case.
 *
 * This will get called in certain circumstances when the interposing library
 * doesn't intercept write.  Notably if libc calls write via streams
 * operations (which the interposing library doesn't get a chance to
 * intercept).
 */
static ssize_t linux_tcp_helper_fop_read_udp(struct file *filp, char *buf,
                                             size_t len, loff_t *off)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  ci_msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  iov[0].iov_base = buf;
  iov[0].iov_len = len;
  m.msg_iov = iov;
  m.msg_iovlen = 1;

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);
  a.filp = filp;

  return ci_udp_recvmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}

static ssize_t linux_tcp_helper_fop_read_iov_udp(struct file *filp,
                                                 const struct iovec *iov,
                                                 unsigned long iovlen)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  ci_msghdr m;
  ci_sock_cmn* s;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
  m.msg_iovlen = iovlen;

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);
  a.filp = filp;

  return ci_udp_recvmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}
#ifdef EFRM_HAVE_FOP_READV
DEFINE_FOP_RW_V(linux_tcp_helper_fop_read_iov_udp, \
                linux_tcp_helper_fop_readv_udp)
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
DEFINE_FOP_AIO_RW(linux_tcp_helper_fop_read_iov_udp, \
                  linux_tcp_helper_fop_aio_read_udp)
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
DEFINE_FOP_RW_ITER(linux_tcp_helper_fop_read_iov_udp, \
                   linux_tcp_helper_fop_read_iter_udp)
#endif


static ssize_t
linux_tcp_helper_fop_read_passthrough(struct file *filp, char *buf,
                                      size_t len, loff_t *off)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  rc = __vfs_read(os_file, buf, len, off);
  oo_os_sock_put(os_file);

  return rc;
}
static ssize_t
linux_tcp_helper_fop_write_passthrough(struct file *filp, const char *buf,
                                       size_t len, loff_t *off)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  rc = __vfs_write(os_file, buf, len, off);
  oo_os_sock_put(os_file);

  return rc;
}
#ifdef EFRM_HAVE_FOP_READV
static ssize_t
linux_tcp_helper_fop_readv_passthrough(struct file *filp,
                                       const struct iovec *iov,
                                       unsigned long iovlen, loff_t *off)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(filp->private_data);
  struct file *os_file;
  int rc;

  OO_OS_SOCKET_FOP(ep, os_file, rc, readv, iov, iovlen, off);
  return rc;
}
static ssize_t
linux_tcp_helper_fop_writev_passthrough(struct file *filp,
                                        const struct iovec *iov,
                                        unsigned long iovlen, loff_t *off)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(filp->private_data);
  struct file *os_file;
  int rc;

  OO_OS_SOCKET_FOP(ep, os_file, rc, writev, iov, iovlen, off);
  return rc;
}
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
static ssize_t
linux_tcp_helper_fop_aio_read_passthrough(struct kiocb *iocb, 
                                          const struct iovec *iov, 
                                          unsigned long iovlen, loff_t pos)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(iocb->ki_filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  iocb->ki_filp = os_file;
  rc = os_file->f_op->aio_read(iocb, iov, iovlen, pos);
  oo_os_sock_put(os_file);

  return rc;
}
static ssize_t
linux_tcp_helper_fop_aio_write_passthrough(struct kiocb *iocb, 
                                           const struct iovec *iov, 
                                           unsigned long iovlen, loff_t pos)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(iocb->ki_filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  iocb->ki_filp = os_file;
  rc = os_file->f_op->aio_write(iocb, iov, iovlen, pos);
  oo_os_sock_put(os_file);

  return rc;
}
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
static ssize_t
linux_tcp_helper_fop_read_iter_passthrough(struct kiocb *iocb,
                                           struct iov_iter *to)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(iocb->ki_filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  iocb->ki_filp = os_file;
  rc = os_file->f_op->read_iter(iocb, to); 
  oo_os_sock_put(os_file);

  return rc;
}
static ssize_t
linux_tcp_helper_fop_write_iter_passthrough(struct kiocb *iocb,
                                            struct iov_iter *from)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(iocb->ki_filp->private_data);
  struct file *os_file;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 )
    return rc;
  iocb->ki_filp = os_file;
  rc = os_file->f_op->write_iter(iocb, from); 
  oo_os_sock_put(os_file);

  return rc;
}
#endif

static unsigned linux_tcp_helper_fop_poll_passthrough(struct file* filp,
                                                      poll_table* wait)
{
  tcp_helper_endpoint_t* ep = efab_priv_to_ep(filp->private_data);
  struct file *os_file;
  int rc;

  OO_OS_SOCKET_FOP(ep, os_file, rc, poll, wait);
  return rc;
}

static ssize_t
linux_tcp_helper_fop_read_alien(struct file *filp, char *buf,
                                      size_t len, loff_t *off)
{
  struct file *alien_file = efab_priv_to_ep(filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->read(alien_file, buf, len, off);
}
static ssize_t
linux_tcp_helper_fop_write_alien(struct file *filp, const char *buf,
                                       size_t len, loff_t *off)
{
  struct file *alien_file = efab_priv_to_ep(filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->write(alien_file, buf, len, off);
}
#ifdef EFRM_HAVE_FOP_READV
static ssize_t
linux_tcp_helper_fop_readv_alien(struct file *filp,
                                       const struct iovec *iov,
                                       unsigned long iovlen, loff_t *off)
{
  struct file *alien_file = efab_priv_to_ep(filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->readv(alien_file, iov, iovlen, off);
}
static ssize_t
linux_tcp_helper_fop_writev_alien(struct file *filp,
                                        const struct iovec *iov,
                                        unsigned long iovlen, loff_t *off)
{
  struct file *alien_file = efab_priv_to_ep(filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->writev(alien_file, iov, iovlen, off);
}
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
static ssize_t
linux_tcp_helper_fop_aio_read_alien(struct kiocb *iocb, 
                                          const struct iovec *iov, 
                                          unsigned long iovlen, loff_t pos)
{
  struct file *alien_file = efab_priv_to_ep(iocb->ki_filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->aio_read(iocb, iov, iovlen, pos);
}
static ssize_t
linux_tcp_helper_fop_aio_write_alien(struct kiocb *iocb, 
                                           const struct iovec *iov, 
                                           unsigned long iovlen, loff_t pos)
{
  struct file *alien_file = efab_priv_to_ep(iocb->ki_filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->aio_write(iocb, iov, iovlen, pos);
}
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
static ssize_t
linux_tcp_helper_fop_read_iter_alien(struct kiocb *iocb, 
                                     struct iov_iter *to)
{
  struct file *alien_file = efab_priv_to_ep(iocb->ki_filp->private_data)->
                                                           alien_ref->_filp;
  iocb->ki_filp = alien_file;
  return alien_file->f_op->read_iter(iocb, to);
}
static ssize_t
linux_tcp_helper_fop_write_iter_alien(struct kiocb *iocb, 
                                      struct iov_iter *from)
{
  struct file *alien_file = efab_priv_to_ep(iocb->ki_filp->private_data)->
                                                           alien_ref->_filp;
  iocb->ki_filp = alien_file;
  return alien_file->f_op->write_iter(iocb, from);
}
#endif

static unsigned linux_tcp_helper_fop_poll_alien(struct file* filp,
                                                      poll_table* wait)
{
  struct file *alien_file = efab_priv_to_ep(filp->private_data)->
                                                           alien_ref->_filp;
  return alien_file->f_op->poll(alien_file, wait);
}


/* Linux file operations for TCP and UDP.
*/
struct file_operations linux_tcp_helper_fops_tcp =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_tcp),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_tcp),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_tcp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_tcp),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_tcp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_tcp),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_read_iter_tcp),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_write_iter_tcp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_tcp),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release, linux_tcp_helper_fop_close),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
  CI_STRUCT_MBR(sendpage, linux_tcp_helper_fop_sendpage),
#ifdef fop_has_splice
  CI_STRUCT_MBR(splice_write, generic_splice_sendpage)
#endif
};


struct file_operations linux_tcp_helper_fops_udp =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_udp),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_udp),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_udp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_udp),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_udp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_udp),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_read_iter_udp),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_write_iter_udp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_udp),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release, linux_tcp_helper_fop_close),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
  CI_STRUCT_MBR(sendpage, linux_tcp_helper_fop_sendpage_udp),
#ifdef fop_has_splice
  CI_STRUCT_MBR(splice_write, generic_splice_sendpage)
#endif
};

struct file_operations linux_tcp_helper_fops_passthrough =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_passthrough),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_passthrough),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_passthrough),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_passthrough),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_passthrough),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_passthrough),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_read_iter_passthrough),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_write_iter_passthrough),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_passthrough),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release, linux_tcp_helper_fop_close),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
#ifdef fop_has_splice
  CI_STRUCT_MBR(splice_write, generic_splice_sendpage)
#endif
};

struct file_operations linux_tcp_helper_fops_alien =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_alien),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_alien),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_alien),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_alien),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_alien),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_alien),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_read_iter_alien),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_write_iter_alien),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_alien),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release, linux_tcp_helper_fop_close),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
#ifdef fop_has_splice
  CI_STRUCT_MBR(splice_write, generic_splice_sendpage)
#endif
};

#if CI_CFG_USERSPACE_PIPE
struct file_operations linux_tcp_helper_fops_pipe_reader =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_pipe),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_notsupp),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_pipe),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_rw_v_notsupp),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_pipe),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_rw_notsupp),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_read_iter_pipe),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_rw_iter_notsupp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_pipe_reader),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release,  linux_tcp_helper_fop_close_pipe),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
};

struct file_operations linux_tcp_helper_fops_pipe_writer =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_notsupp),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_pipe),
#ifdef EFRM_HAVE_FOP_READV
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_rw_v_notsupp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_pipe),
#endif
#ifdef EFRM_HAVE_FOP_AIO_READ
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_rw_notsupp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_pipe),
#endif
#ifdef EFRM_HAVE_FOP_READ_ITER
  CI_STRUCT_MBR(read_iter, linux_tcp_helper_fop_rw_iter_notsupp),
  CI_STRUCT_MBR(write_iter, linux_tcp_helper_fop_write_iter_pipe),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_pipe_writer),
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release,  linux_tcp_helper_fop_close_pipe),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
};
#endif

/**********************************************************************
 * oo_file_ref operations.
 */

struct oo_file_ref* oo_file_ref_add(struct oo_file_ref* fr)
{
  struct oo_file_ref* new_fr;

  ci_assert(fr != NULL);
  ci_assert(fr->file != NULL);

  new_fr = kmalloc(sizeof(*new_fr),
                   (in_atomic() || in_interrupt()) ? GFP_ATOMIC : 0);
  if( new_fr != NULL ) {
    new_fr->file = fr->file;
    get_file(new_fr->file);
  }
  return new_fr;
}


void oo_file_ref_drop(struct oo_file_ref* fr)
{
  ci_assert(fr != NULL);
  ci_assert(fr->file != NULL);

  /* Caveat: On some kernels, this check does not detect the case where the
   * caller is holding a spinlock, so calling this function while holding a
   * spinlock is not safe. */
  if( ! (in_atomic() || in_interrupt()) ) {
    fput(fr->file);
    kfree(fr);
  }
  else {
    /* We're not in a context where we can do fput(), so defer. */
    unsigned long lock_flags;
    spin_lock_irqsave(&efab_tcp_driver.file_refs_lock, lock_flags);
    fr->next = efab_tcp_driver.file_refs_to_drop;
    efab_tcp_driver.file_refs_to_drop = fr;
    spin_unlock_irqrestore(&efab_tcp_driver.file_refs_lock, lock_flags);
    queue_work(CI_GLOBAL_WORKQUEUE, &efab_tcp_driver.file_refs_work_item);
  }
}


int oo_file_ref_lookup(struct file* file, struct oo_file_ref** fr_out)
{
  struct oo_file_ref* fr;

  ci_assert(file);
  fr = kmalloc(sizeof(*fr), (in_atomic() || in_interrupt()) ? GFP_ATOMIC : 0);
  if( fr == NULL )
    return -ENOMEM;
  fr->file = file;
  *fr_out = fr;
  return 0;
}


void oo_file_ref_drop_list_now(struct oo_file_ref* fr_next)
{
  struct oo_file_ref* fr;

  ci_assert(! in_interrupt());
  ci_assert(! in_atomic());

  if( fr_next == NULL ) {
    unsigned long lock_flags;
    spin_lock_irqsave(&efab_tcp_driver.file_refs_lock, lock_flags);
    fr_next = efab_tcp_driver.file_refs_to_drop;
    efab_tcp_driver.file_refs_to_drop = NULL;
    spin_unlock_irqrestore(&efab_tcp_driver.file_refs_lock, lock_flags);
  }

  while( (fr = fr_next) != NULL ) {
    fr_next = fr->next;
    fput(fr->file);
    kfree(fr);
  }
}


/* fixme: function should be optimized for >= 2.6.32 kernel to use
 * poll_schedule_timeout() function. */

int efab_tcp_helper_poll_udp(struct file *filp, int *mask,
                             s64 *timeout)
{
  /* At this point we allocate poll_wqueues structure on the stack.
   * It is pretty big because of ->inline_entires array which stores
   * several poll_table_entry structures. Number of structures stored
   * is determined basing on N_INLINE_POLL_ENTRIES define in poll.h
   * header file. So in fact we do allocate ~600 bytes on the stack.
   *
   * From one point of view it's not a good idea to store it on the
   * stack. However, there are several excuses.
   *
   * 1) poll_wqueues structure is allocated for instance in do_select(),
   * do_sys_poll, kernel functions which means that kernel developers think
   * that it's safe to allocate it on stack.
   *
   * 2) efab_tcp_helper_poll_udp() function is called currently only from
   * ci_udp_recvmsg() which is itself called from ..fop_read_udp() - call
   * stack is very short and is very close (from logical point of view) to
   * the one for do_select and do_sys_poll. It's just a syscall.
   *
   * 3) Unfortunately poll_wqueues structure differ from kernel to kernel
   * and it's not possible/safe to redefine it locally or redefine
   * N_INLINE_POLL_ENTRIES macro prior to poll.h file include.
   *
   * 4) Althoug it may seem that we don't use entire poll_wqueues structure
   * in the code - it's not true. In poll_initwait() we set callback for
   * poll wait to __pollwait which using container_of() gets poll_wqueues
   * structure by given poll_table (as it's .pt field).
   */
  struct poll_wqueues table;
  int remask, rc = 0;
  poll_table *pt;
  long __timeout;

  ci_assert(timeout);

  poll_initwait(&table);
  pt = &table.pt;

  /* check that it's our poll function */
  ci_assert(filp->f_op && filp->f_op->poll);
  ci_assert(filp->f_op->poll == linux_tcp_helper_fop_poll_udp);

  for (;;) {
    __set_current_state(TASK_INTERRUPTIBLE);
    remask = filp->f_op->poll(filp, pt);
    pt = NULL;
    /* mask out unnecessary events */
    remask &= (*mask | POLLERR | POLLHUP);
    if (remask)
      break;

    rc = table.error;
    if (signal_pending(current)) {
      __set_current_state(TASK_RUNNING);
      poll_freewait(&table);
      return -ERESTARTSYS;
    }

    /* in case it's an instant check (timeout is zero) */
    if( rc || !*timeout )
      break;
    if (*timeout < 0) {
      /* Wait indefinitely */
      __timeout = MAX_SCHEDULE_TIMEOUT;
    } else if (unlikely(*timeout >= (s64)MAX_SCHEDULE_TIMEOUT-1)) {
      __timeout = MAX_SCHEDULE_TIMEOUT - 1;
      *timeout -= __timeout;
    } else {
      __timeout = *timeout;
      *timeout = 0;
    }
    __timeout = schedule_timeout(__timeout);
    if (*timeout >= 0)
      *timeout += __timeout;
  }

  __set_current_state(TASK_RUNNING);

  poll_freewait(&table);

  *mask = remask;

  return rc;
}


/****** OS socket callback *****/

/* Returns the fixed "mask" for OS socket events.
 * This is really linux-specific function. */
static short efab_os_wakup_fix_mask(tcp_helper_endpoint_t *ep, short mask,
                                    ci_int32 *so_error_out)
{
  struct file *file;
  struct socket *sock;
  unsigned long lock_flags;
  struct oo_file_ref *kref;

  spin_lock_irqsave(&ep->lock, lock_flags);
  if( ep->os_socket == NULL ) {
    spin_unlock_irqrestore(&ep->lock, lock_flags);
    return 0;
  }
  kref = oo_file_ref_add(ep->os_socket);
  spin_unlock_irqrestore(&ep->lock, lock_flags);
  file = kref->file;
  ci_assert(file);

  sock = SOCKET_I(file->f_dentry->d_inode);
  ci_assert(sock);

  *so_error_out = -sock_error(sock->sk);

  /* Normally, we know the mask.  But: linux<2.6.30 uses 0, and some events
   * on modern kernel also use 0.
   * So, we find the current mask if necessary.
   * These 2 masks are not the same: key is the _event_just_happened_,
   * while poll returns the _events_ever_happened_. */
  if( mask == 0 || mask == (short)0xffff ) {
    /* We'd like to call file->f_op->poll() in all cases, but
     * datagram_poll() is so much faster than udp_poll();
     * and on some kernels udp_poll() function does not like
     * arbitrary context we can be running on. */
    if( sock->type == SOCK_DGRAM )
      mask = datagram_poll(file, sock, NULL);
    else
      mask = file->f_op->poll(file, NULL);
  }
  else if( *so_error_out || ((mask & POLLIN) && sock->type == SOCK_DGRAM) ) {
    /* In some cases, we should drop the flagged event.
     * - If so_error was non-zero, we've just zeroed it.  POLLERR event was
     *   flagged, but we've "handled" it - and is not shown by the OS
     *   socket any more.
     * - Some kernels (2.6.32) send POLLIN wakeup to UDP socket when ICMP
     *   error is received, but poll() does not show this event.
     */
    mask &= datagram_poll(file, sock, NULL);
  }

  oo_file_ref_drop(kref);

  return mask;
}

/* Tell any waiters that there is an OS event.  This function is not
 * Linux-specific and should be moved to tcp_helper_endpoint.c. */
static void efab_os_wakeup_event(tcp_helper_endpoint_t *ep,
                                 short mask, ci_int32 so_error)
{
  ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int wq_active;
  unsigned long flags;
  tcp_helper_resource_t* trs = ep->thr;
  ci_uint32 os_sock_status;

  OO_DEBUG_ASYNC(ci_log("%s: updated mask=%hx so_error=%d os_sock_status=%x",
                        __FUNCTION__, mask, so_error, s->os_sock_status));

  if( so_error )
    SP_TO_SOCK(&ep->thr->netif, ep->id)->so_error = so_error;
  os_sock_status = oo_os_sock_status_from_mask(mask);
  if( os_sock_status == 0 && so_error == 0 )
    return;


  /* Set os_sock_status field in the socket. */
  if( os_sock_status != 0 &&
      (s->os_sock_status & os_sock_status) != os_sock_status ) {
    oo_os_sock_status_bit_set(s, os_sock_status);
  }

  /* Wake up endpoint if someone is waiting on poll().
   * wq_active here is unreliable: it could change either way before the
   * actual call to ci_waitable_wakeup_all().  So, it is used to update
   * statistics only. */
  wq_active = ci_waitable_active(&ep->waitq);
  if( (os_sock_status & (OO_OS_STATUS_RX | OO_OS_STATUS_ERR))
      || so_error ) {
    ++s->b.sleep_seq.rw.rx;
    if( wq_active )
      CITP_STATS_NETIF_INC(&ep->thr->netif, sock_wakes_rx_os);
  }
  if( (os_sock_status & (OO_OS_STATUS_TX | OO_OS_STATUS_ERR))
      || so_error ) {
    ++s->b.sleep_seq.rw.tx;
    if( wq_active )
      CITP_STATS_NETIF_INC(&ep->thr->netif, sock_wakes_tx_os);
  }
  ci_waitable_wakeup_all(&ep->waitq);

  /* Epoll3 support: */

  /* It's safe to check the id before we decide whether to put stuff on the
   * ready list, as the epoll code will always start off assuming that things
   * may be ready, and this check is after we've set the os ready status.
   */
  if( s->b.ready_list_id > 0 ) {
    /* The best thing is if we can just get the lock - in that case we can
     * just bung this socket straight on the ready list.
     */
    if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
      ci_ni_dllist_remove(&trs->netif, &s->b.ready_link);
      ci_ni_dllist_put(&trs->netif,
                       &trs->netif.state->ready_lists[s->b.ready_list_id],
                       &s->b.ready_link);
      ci_waitable_wakeup_all(&trs->ready_list_waitqs[s->b.ready_list_id]);
      tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_UNLOCK_TRUSTED);
      /* do not insert anything here - we should return immediately */
    }
    else {
      /* If we couldn't get the lock straight away then we need to set a
       * flag so this can be handled by the lock holder.  We can't set the
       * flag though until we've got the work ready to do, ie queued it on
       * the os ready list.
       */
      spin_lock_irqsave(&trs->os_ready_list_lock, flags);
      ci_dllist_remove(&ep->os_ready_link);
      ci_dllist_put(&trs->os_ready_lists[s->b.ready_list_id],
                    &ep->os_ready_link);
      spin_unlock_irqrestore(&trs->os_ready_list_lock, flags);

      if( efab_tcp_helper_netif_lock_or_set_flags(trs,
                                                  OO_TRUSTED_LOCK_OS_READY,
                                                  CI_EPLOCK_NETIF_NEED_WAKE,
                                                  1) ) {
        spin_lock_irqsave(&trs->os_ready_list_lock, flags);
        ci_dllist_remove_safe(&ep->os_ready_link);
        spin_unlock_irqrestore(&trs->os_ready_list_lock, flags);

        ci_ni_dllist_remove(&trs->netif, &s->b.ready_link);
        ci_ni_dllist_put(&trs->netif,
                         &trs->netif.state->ready_lists[s->b.ready_list_id],
                         &s->b.ready_link);
        ci_waitable_wakeup_all(&trs->ready_list_waitqs[s->b.ready_list_id]);
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_UNLOCK_TRUSTED);
        /* do not insert anything here - we should return immediately */
      }
    }
  }
}


/* This function is a handler for events on the OS socket.  It is called by
 * Linux function __wake_up after spin_lock_irqsave(), so all this code
 * should be ready to work with the interrupts turned off. */
int efab_os_sock_callback(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
  tcp_helper_endpoint_t *ep = container_of(wait,
                                           tcp_helper_endpoint_t,
                                           os_sock_poll.wait);
  unsigned long mask = (unsigned long)key;
  short fixed_mask;
  ci_int32 so_error = 0;

  fixed_mask = efab_os_wakup_fix_mask(ep, mask, &so_error);
  OO_DEBUG_ASYNC(ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
                 ci_log("%s: %d:%d %s:%d mask=%lx fixed_mask=%hx so_error=%d",
                        __FUNCTION__,
                         ep->thr->id, OO_SP_FMT(ep->id),
                         ip_addr_str(sock_laddr_be32(s)),
                        (unsigned) CI_BSWAP_BE16(sock_lport_be16(s)),
                        mask, fixed_mask, so_error));

  if( fixed_mask || so_error )
    efab_os_wakeup_event(ep, fixed_mask, so_error);

  return 1; /* nobody is really interested in the return value */
}

/*! \cidoxg_end */
