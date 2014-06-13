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
#include <linux/poll.h>



/* Is it possible for a thread polling the socket to block and later be
 * woken, given the mask value provided?
 *
 * NB. No assumptions can be made if these return false.
 */
#define TCP_POLL_MASK_CAN_BLOCK(mask)                   \
  (((mask) & (POLLIN | POLLOUT)) != (POLLIN | POLLOUT))

#define TCP_LISTEN_POLL_MASK_CAN_BLOCK(mask)    \
  ((mask) == 0)

#define UDP_POLL_MASK_CAN_BLOCK(mask)                           \
  ((((mask) & (POLLIN | POLLOUT)) != (POLLIN | POLLOUT)) &&     \
   ! ((mask) & (POLLERR | POLLHUP)))


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
        efab_tcp_helper_netif_try_lock(trs) ) {
      ci_netif_poll(ni);
      efab_tcp_helper_netif_unlock(trs);
    }
    return 1;
  }
  return 0;
}


static inline void
efab_fop_poll__prime_if_needed(tcp_helper_resource_t* trs,
                               tcp_helper_endpoint_t* ep,
                               int mask_permits_block,
                               int enable_interrupts)
{
  OO_DEBUG_ASYNC(ci_log("%s: [%d:%d] mask_permits_block=%d waitq_active=%d "
                        "enable_interrupts=%d", __FUNCTION__,
                        trs->id, ep->id, mask_permits_block,
                        waitqueue_active(&ep->waitq.wq), enable_interrupts));
  if( mask_permits_block && waitqueue_active(&ep->waitq.wq) ) {
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

#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_readv_pipe(struct file *filp,
                                          const struct iovec *iov,
                                          unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_read_pipe(struct kiocb *iocb, 
                                             const struct iovec *iov, 
                                             unsigned long iovlen, loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);

  return ci_pipe_read(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                      iov, iovlen);
}

static ssize_t linux_tcp_helper_fop_read_notsupp(struct file *filp, char *buf,
                                                 size_t len, loff_t *off)
{
  return -EOPNOTSUPP;
}
#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_readv_notsupp(struct file *filp,
                                          const struct iovec *iov,
                                          unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_read_notsupp(struct kiocb *iocb, 
                                             const struct iovec *iov, 
                                             unsigned long iovlen, loff_t pos)
#endif
{
  return -EOPNOTSUPP;
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

#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_writev_pipe(struct file *filp,
                                    const struct iovec *iov,
                                    unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_write_pipe(struct kiocb *iocb, 
                                    const struct iovec *iov, 
                                    unsigned long iovlen, loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);

  return ci_pipe_write(&trs->netif, SP_TO_PIPE(&trs->netif, priv->sock_id),
                       iov, iovlen);
}

static ssize_t linux_tcp_helper_fop_write_notsupp(struct file *filp,
                                                  const char *buf,
                                                  size_t len, loff_t *off)
{
  return -EOPNOTSUPP;
}
#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_writev_notsupp(struct file *filp,
                                    const struct iovec *iov,
                                    unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_write_notsupp(struct kiocb *iocb, 
                                    const struct iovec *iov, 
                                    unsigned long iovlen, loff_t pos)
#endif
{
  return -EOPNOTSUPP;
}


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

  if( s->b.state != CI_TCP_LISTEN ) {
    mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
    if( wait != NULL ) {
      efab_fop_poll__prime_if_needed(trs, tep_p, TCP_POLL_MASK_CAN_BLOCK(mask),
                                     enable_interrupts);
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
      /* From the closed state, handover is possible.  We should add OS
       * socket waitqueue to the poll table.
       */
      if( s->b.state == CI_TCP_CLOSED && tep_p->os_socket  != NULL ) {
        struct file *os_sock = tep_p->os_socket->file;
        ci_assert(os_sock->f_op != NULL);
        ci_assert(os_sock->f_op->poll != NULL);
        os_sock->f_op->poll(os_sock, wait); /* drop results */
      }
#endif
    }
  }
  else {
    mask = ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s));
    efab_fop_poll__prime_if_needed(trs, tep_p,
                                   TCP_LISTEN_POLL_MASK_CAN_BLOCK(mask),
                                   enable_interrupts);
  }

  OO_DEBUG_ASYNC(ci_log("%s: return 0x%x, enable_interrupts=%d",
                        __FUNCTION__, mask, enable_interrupts));
  return mask;
}


static unsigned linux_tcp_helper_fop_poll_tcp(struct file* filp,
                                              poll_table* wait)
{
  ci_private_t *priv;
  int rc = POLLERR;

  /* bug34448: we should check f_op AFTER getting private data
   * to ensure it is our file.  Also, epoll does not increment refcount,
   * so we should lock here to prevent handover process from endpoint
   * desruction. */
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  down_read(&handover_rwlock);
#endif
  priv = filp->private_data;
  if( filp->f_op == &linux_tcp_helper_fops_tcp)
    rc = efab_linux_tcp_helper_fop_poll_tcp(filp, efab_priv_to_thr(priv), 
					    priv->sock_id, wait);
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  up_read(&handover_rwlock);
#endif
  return rc;
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

  /* bug34448: see comments in linux_tcp_helper_fop_poll_tcp */
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  down_read(&handover_rwlock);
#endif
  priv = filp->private_data;
  if( filp->f_op != &linux_tcp_helper_fops_udp) {
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
    up_read(&handover_rwlock);
#endif
    return POLLERR;
  }

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

#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  /* For non-connected socket handover is possible.  We should add OS
   * socket waitqueue to the poll table.  And connected socket may be
   * disconnected and connected-to-OS again, so no guarantee here.  Let's
   * be safe.
   *
   * ?? FIXME: I really don't believe this logic...
   */
  if( wait != NULL &&
      (NI_OPTS(ni).udp_connect_handover || sock_lport_be16(&us->s) == 0) ) {
    struct file* os_sock = tep_p->os_socket->file;
    ci_assert(os_sock->f_op != NULL);
    ci_assert(os_sock->f_op->poll != NULL);
    if( os_sock != NULL )  /* belt and braces */
      (void) os_sock->f_op->poll(os_sock, wait);
  }
#endif

  mask = ci_udp_poll_events(ni, us);
  efab_fop_poll__prime_if_needed(trs, tep_p, UDP_POLL_MASK_CAN_BLOCK(mask),
                                 enable_interrupts);

#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  up_read(&handover_rwlock);
#endif
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
    tcp_helper_endpoint_clear_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
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
    rc = ep->os_socket->file->f_op->fasync(fd, ep->os_socket->file, mode);
    if( rc != 0 )
      linux_tcp_helper_fop_fasync_no_os(fd, filp, !mode);
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
  struct msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;
  int rc;

  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = len;
  m.msg_namelen = 0;
  m.msg_iov = iov;
  m.msg_iovlen = 1;
  m.msg_controllen = 0;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN )
    return ci_tcp_sendmsg(&trs->netif, SOCK_TO_TCP(s), &m,
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
#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_writev_tcp(struct file *filp,
                                               const struct iovec *iov,
                                               unsigned long iovlen,
                                               loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_write_tcp(struct kiocb *iocb, 
                                                  const struct iovec *iov, 
                                                  unsigned long iovlen,
                                                  loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  struct msghdr m;
  ci_sock_cmn* s;
  int rc;

#ifndef fop_has_readv
  if (!is_sync_kiocb(iocb))
    return -EINVAL;
#endif
  m.msg_namelen = 0;
  m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
  m.msg_iovlen = iovlen;
  m.msg_controllen = 0;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN )
    return ci_tcp_sendmsg(&trs->netif, SOCK_TO_TCP(s), &m,
                          (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK),
                          CI_ADDR_SPC_CURRENT);

  CI_SET_ERROR(rc, s->tx_errno);
  return rc;
}

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
  struct msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;

  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = len;
  m.msg_namelen = 0;
  m.msg_iov = iov;
  m.msg_iovlen = 1;
  m.msg_controllen = 0;

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
#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_writev_udp(struct file *filp,
                                    const struct iovec *iov,
                                    unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_write_udp(struct kiocb *iocb, 
                                    const struct iovec *iov, 
                                    unsigned long iovlen, loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  struct msghdr m;
  ci_sock_cmn* s;

#ifndef fop_has_readv
  if (!is_sync_kiocb(iocb))
    return -EINVAL;
#endif
  m.msg_namelen = 0;
  m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
  m.msg_iovlen = iovlen;
  m.msg_controllen = 0;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);

  return ci_udp_sendmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}

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
  struct msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;
  int rc;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN ) {
    iov[0].iov_base = buf;
    iov[0].iov_len = len;
    m.msg_namelen = 0;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    m.msg_controllen = 0;

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
#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_readv_tcp(struct file *filp,
                                              const struct iovec *iov,
                                              unsigned long iovlen,
                                              loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_read_tcp(struct kiocb *iocb, 
                                                 const struct iovec *iov, 
                                                 unsigned long iovlen,
                                                 loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_tcp_recvmsg_args a;
  struct msghdr m;
  ci_sock_cmn* s;
  int rc;

#ifndef fop_has_readv
  if (!is_sync_kiocb(iocb))
    return -EINVAL;
#endif
  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  if( s->b.state != CI_TCP_LISTEN ) {
    m.msg_namelen = 0;
    m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
    m.msg_iovlen = iovlen;
    m.msg_controllen = 0;

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
  struct msghdr m;
  struct iovec iov[1];
  ci_sock_cmn* s;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  iov[0].iov_base = buf;
  iov[0].iov_len = len;
  m.msg_name = NULL;
  m.msg_namelen = 0;
  m.msg_iov = iov;
  m.msg_iovlen = 1;
  m.msg_controllen = 0;

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);
  a.filp = filp;

  return ci_udp_recvmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}

#ifdef fop_has_readv
static ssize_t linux_tcp_helper_fop_readv_udp(struct file *filp,
                                          const struct iovec *iov,
                                          unsigned long iovlen, loff_t *off)
#else
static ssize_t linux_tcp_helper_fop_aio_read_udp(struct kiocb *iocb, 
                                             const struct iovec *iov, 
                                             unsigned long iovlen, loff_t pos)
#endif
{
#ifndef fop_has_readv
  struct file *filp = iocb->ki_filp;
#endif
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_udp_iomsg_args a;
  struct msghdr m;
  ci_sock_cmn* s;

#ifndef fop_has_readv
  if (!is_sync_kiocb(iocb))
    return -EINVAL;
#endif
  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  fix_nonblock_flag(filp, s);

  m.msg_name = NULL;
  m.msg_namelen = 0;
  m.msg_iov = (struct iovec *)iov; /* FIXME: remove const qualifier */
  m.msg_iovlen = iovlen;
  m.msg_controllen = 0;

  a.ni = &trs->netif;
  a.us = SOCK_TO_UDP(s);
  a.filp = filp;

  return ci_udp_recvmsg(&a, &m, (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK));
}


/* Linux file operations for TCP and UDP.
*/
struct file_operations linux_tcp_helper_fops_tcp =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(read, linux_tcp_helper_fop_read_tcp),
  CI_STRUCT_MBR(write, linux_tcp_helper_fop_write_tcp),
#ifdef fop_has_readv
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_tcp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_tcp),
#else
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_tcp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_tcp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_tcp),
#if HAVE_UNLOCKED_IOCTL
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
#else
  CI_STRUCT_MBR(ioctl, oo_fop_ioctl),
#endif
#if HAVE_COMPAT_IOCTL
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
#endif
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
#ifdef fop_has_readv
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_udp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_udp),
#else
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_udp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_udp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_udp),
#if HAVE_UNLOCKED_IOCTL
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
#else
  CI_STRUCT_MBR(ioctl, oo_fop_ioctl),
#endif
#if HAVE_COMPAT_IOCTL
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
#endif
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release, linux_tcp_helper_fop_close),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
  CI_STRUCT_MBR(sendpage, linux_tcp_helper_fop_sendpage_udp),
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
#ifdef fop_has_readv
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_pipe),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_notsupp),
#else
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_pipe),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_notsupp),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_pipe_reader),
#if HAVE_UNLOCKED_IOCTL
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
#else
  CI_STRUCT_MBR(ioctl, oo_fop_ioctl),
#endif
#if HAVE_COMPAT_IOCTL
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
#endif
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
#ifdef fop_has_readv
  CI_STRUCT_MBR(readv, linux_tcp_helper_fop_readv_notsupp),
  CI_STRUCT_MBR(writev, linux_tcp_helper_fop_writev_pipe),
#else
  CI_STRUCT_MBR(aio_read, linux_tcp_helper_fop_aio_read_notsupp),
  CI_STRUCT_MBR(aio_write, linux_tcp_helper_fop_aio_write_pipe),
#endif
  CI_STRUCT_MBR(poll, linux_tcp_helper_fop_poll_pipe_writer),
#if HAVE_UNLOCKED_IOCTL
  CI_STRUCT_MBR(unlocked_ioctl, oo_fop_unlocked_ioctl),
#else
  CI_STRUCT_MBR(ioctl, oo_fop_ioctl),
#endif
#if HAVE_COMPAT_IOCTL
  CI_STRUCT_MBR(compat_ioctl, oo_fop_compat_ioctl),
#endif
  CI_STRUCT_MBR(mmap, oo_fop_mmap),
  CI_STRUCT_MBR(open, oo_fop_open),
  CI_STRUCT_MBR(release,  linux_tcp_helper_fop_close_pipe),
  CI_STRUCT_MBR(fasync, linux_tcp_helper_fop_fasync),
};
#endif

#if CI_CFG_FD_CACHING
int efab_tcp_helper_can_cache_fd(ci_private_t *priv_ni, void *arg)
{
  unsigned fd = (unsigned)(ci_uintptr_t)arg;
  struct file *fp;
  ci_private_t *priv;
  int rc = -ENOENT;

  ci_assert(priv_ni);
  if (priv_ni->thr == NULL)
    return rc;
  ci_assert_ge(fd, 0);
  if ((fp = fget(fd)) == NULL)
    return rc;

  priv = (ci_private_t *)fp->private_data;
  if (priv == NULL)
    goto done;


  if (!CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type))
    goto done;

  if (file_count(fp) == 1) {
    tcp_helper_endpoint_t* ep = ci_trs_ep_get(priv_ni->thr, priv->sock_id);

    if (ep->fasync_queue)
      linux_tcp_helper_fop_fasync(-1, ci_privf(priv), 0);

    rc = 0;
  }

done:
  fput(fp);
  return rc;
}


static int efab_tcp_helper_xfer_cached_verify(ci_private_t *other_priv,
                                              void *arg)
{
  tcp_helper_resource_t *trs, *alt_trs;
  int rc;

  /* As a security measure, ensure we're xfering fds within single netif. */
  trs = (tcp_helper_resource_t*)arg;
  rc = efab_get_tcp_helper_of_priv(other_priv, &alt_trs, __FUNCTION__);
  if(rc<0 || alt_trs != trs) {
    /* Different TCP helper resource, means different netif.  Which means this
     * is not a valid thing to try and do!
     */
    LOG_E (ci_log ("Error: attempt to xfer cache from other netif!"));
    return -EPERM;
  }

  return 0;
}


/* This is the low-level part of efab_tcp_helper_xfer_cached */
static int
ci_xfer_cached(struct task_struct *t, int other_fd,
               tcp_helper_resource_t *trs)
{
  struct file * other_filp;
  struct files_struct *other_files;
  ci_private_t *other_priv;
  int rc = 0;
  ci_fdtable *fdt;

  /* Now get at the filp for the other fd */
  other_files = t->files;

  LOG_EP (ci_log ("xfer: take files lock on %p", other_files));
  spin_lock(&other_files->file_lock);
  fdt = ci_files_fdtable(other_files);

  if (other_fd >= fdt->max_fds) {
    LOG_E (ci_log ("Error: attempt to xfer out-of-range fd (%d)", other_fd));
    rc = -EBADF;
    goto out_unlock;
  }
  LOG_EP (ci_log ("xfer: get other files on fdtable %p", fdt->fd));
  other_filp = fdt->fd[other_fd];
  if (!other_filp) {
    LOG_E (ci_log ("Error: attempt to xfer invalid fd (%d)", other_fd));
    rc = -EBADF;
    goto out_unlock;
  }

  /* This is only a valid thing to do on TCP EPs */
  if( other_filp->f_op != &linux_tcp_helper_fops_tcp ) {
    LOG_E (ci_log ("Attempt to xfer invalid FD"));
    rc = -EINVAL;
    goto out_unlock;
  }

  /* This assertion because we checked the file-ops above */
  other_priv = other_filp->private_data;
  ci_assert_equal(other_priv->fd_type, CI_PRIV_TYPE_TCP_EP);

  rc = efab_tcp_helper_xfer_cached_verify(other_priv, trs);
  if (rc<0) {
    goto out_unlock;
  }


  LOG_EP (ci_log ("xfer: close other fd"));
  /* Now we need to 'close' the other fd.  We need to do this before the
   * attach, because otherwise we need to keep the files lock held across the
   * attach, and this will give potential deadlock (should two processes
   * mutually and concurrently xfer cached FDs from each other)
   */
  ci_fdtable_set_fd(fdt, other_fd, NULL);
  efx_clear_close_on_exec(other_fd, fdt);
  efx_clear_open_fd(other_fd, fdt);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
  if (other_fd < fdt->next_fd)
    fdt->next_fd = other_fd;
#else
  if (other_fd < other_files->next_fd)
    other_files->next_fd = other_fd;
#endif
  get_file (other_filp);              /* Take a reference from this process */
  rc = filp_close(other_filp, other_files);    /* Close FD in other process */
  spin_unlock(&other_files->file_lock);
  if (rc < 0) {
    /* TODO: Unpick by undo-ing the attach done above */
    LOG_E (ci_log ("Error %d when closing on cache xfer", rc));
    return rc;
  }

  /* Finnaly, allocate a new fd in this process and link it to the cached EP */
  LOG_EP (ci_log ("xfer: get unused fd"));
  rc = get_unused_fd();
  if (rc >= 0)
    fd_install(rc, other_filp);
  else {
    ci_log ("ERROR: out of fds!!\n");
    ci_assert (0);
  }

  return rc;

out_unlock:
  /* This is the error path */
  ci_assert (rc < 0);
  spin_unlock(&other_files->file_lock);
  return rc;
}

/* EPs are cached for performance reasons, based on a netif.  This is fine,
 * until a netif is shared between two processes, such that a socket is cached
 * on one process, and then pulled out of the cache on another process' accept.
 * When the user-level detects such a case (in accept), it will call this
 * function in order to transfer the cached socket to the correct process.
 * This essentially means closing the file-descriptor in the original process,
 * and creating a new file-descriptor in the calling process, and attach the
 * TCP state to the new fd in this process.
 */
int efab_tcp_helper_xfer_cached(ci_private_t *priv, void *arg)
{
  oo_tcp_xfer_t *op = arg;
  struct task_struct *t;
  int rc;

  LOG_EP (ci_log ("xfering cached from pid=%d, fd=%d to pid=%d",
                  op->other_pid, op->other_fd, current->tgid));
  ci_assert(priv);
  if (priv->thr == NULL)
    return -EINVAL;

  /* Get at the task structure for the requested pid */
  t = ci_lock_task_by_pid(op->other_pid); /* Handles the locking for us. */

  if (!t) {
    /* Can't find pid.  This can happen when the other process is being
     * destroyed.  It'll clean up its own cached state itself, so we don't
     * need to close any FD
     */
    LOG_U (ci_log ("WARNING: invalid pid on cached xfer (pid=%d)",
                   op->other_pid));
    return -ESRCH;
  }

  /* The low-level mangling of file tables happens here. */
  rc = ci_xfer_cached(t, op->other_fd, priv->thr);

  ci_unlock_task();
  return rc;
}
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
  if( ! (in_atomic() || in_interrupt()) ) {
    fput(fr->file);
    kfree(fr);
  }
  else {
    /* We're not in a context where we can do fput(), so defer. */
    ci_irqlock_state_t lock_flags;
    ci_irqlock_lock(&efab_tcp_driver.thr_table.lock, &lock_flags);
    fr->next = efab_tcp_driver.file_refs_to_drop;
    efab_tcp_driver.file_refs_to_drop = fr;
    ci_irqlock_unlock(&efab_tcp_driver.thr_table.lock, &lock_flags);
    ci_workqueue_add(&CI_GLOBAL_WORKQUEUE,
                     &efab_tcp_driver.file_refs_work_item);
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


void oo_file_ref_drop_list_now(void *context)
{
  struct oo_file_ref* fr_next = context;
  struct oo_file_ref* fr;

  ci_assert(! in_interrupt());
  ci_assert(! in_atomic());

  if( fr_next == NULL ) {
    ci_irqlock_state_t lock_flags;
    ci_irqlock_lock(&efab_tcp_driver.thr_table.lock, &lock_flags);
    fr_next = efab_tcp_driver.file_refs_to_drop;
    efab_tcp_driver.file_refs_to_drop = NULL;
    ci_irqlock_unlock(&efab_tcp_driver.thr_table.lock, &lock_flags);
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

static int efab_os_callback(wait_queue_t *wait, unsigned mode, int sync,
                            void *key)
{
  struct oo_os_sock_poll *os_sock_pt = container_of(wait,
                                                    struct oo_os_sock_poll,
                                                    wait);
  tcp_helper_endpoint_t *ep = container_of(os_sock_pt,
                                           tcp_helper_endpoint_t,
                                           os_sock_pt);
  struct file *file = ep->os_socket->file;
  struct socket *sock = SOCKET_I(file->f_dentry->d_inode);
  ci_int32 so_error;
  unsigned long mask = (unsigned long)key;
  ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int wq_active, do_wakeup = 0;

  OO_DEBUG_ASYNC(ci_log("%s: %d:%d %s:%d key=%lx", __FUNCTION__,
                         ep->thr->id, OO_SP_FMT(ep->id),
                         ip_addr_str(sock_laddr_be32(s)),
                        (unsigned) CI_BSWAP_BE16(sock_lport_be16(s)),
                        mask));

  ci_assert(sock);

  so_error = -sock_error(sock->sk);
  if( so_error ) {
    SP_TO_SOCK(&ep->thr->netif, ep->id)->so_error = so_error;
    do_wakeup = 1;
  }

  /* Normally, we know the mask.  But: linux<2.6.30 uses 0, and some events
   * on modern kernel also use 0.
   * So, we find the current mask if necessary.
   * These 2 masks are not the same: key is the _event_just_happened_,
   * while poll returns the _events_ever_happened_.
   *
   * We'd like to call f_op->poll(), but udp_poll does not like this
   * context (see bug25557, bug25311).
   */
  if( !mask ) {
    if( sock->type == SOCK_DGRAM )
      mask = datagram_poll(file, sock, NULL);
    else
      mask = file->f_op->poll(file, NULL);
  }
  else if( (mask & POLLIN) && sock->type == SOCK_DGRAM ) {
    /* This suck, but it is necessary: we have to re-check that we
     * really have POLLIN event.
     * 2.6.32 sends POLLIN wakeup when ICMP error is received
     * (it also sends POLLERR later). */
    mask &= datagram_poll(ep->os_socket->file, sock, NULL);
  }

  /* oo_os_sock_status_bit_set is better to be called once, so
   * we use if-elseif instead of two ifs. */
  if( (mask & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT) ) {
    oo_os_sock_status_bit_set(s, OO_OS_STATUS_RX | OO_OS_STATUS_TX);
    ++s->b.sleep_seq.rw.rx;
    ++s->b.sleep_seq.rw.tx;
    do_wakeup = 1;
  }
  else if( mask & POLLIN ) {
    oo_os_sock_status_bit_set(s, OO_OS_STATUS_RX);
    ++s->b.sleep_seq.rw.rx;
    do_wakeup = 1;
  }
  else if( mask & POLLOUT ) {
    oo_os_sock_status_bit_set(s, OO_OS_STATUS_TX);
    ++s->b.sleep_seq.rw.tx;
    do_wakeup = 1;

  }
  else if( mask & (POLLHUP | POLLERR) )
    do_wakeup = 1;
  OO_DEBUG_ASYNC(ci_log("%s: updated mask=%lx, do_wakeup=%d", __FUNCTION__,
                        mask, do_wakeup));

  /* Wake up endpoint if someone is waiting on poll() */
  if( do_wakeup
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
      /* Double wakeups are bad things: no real use, additional lock
       * contention.  So, we avoid wakeup if OS socket is already in the
       * waitq. */
      && ( s->b.state != CI_TCP_STATE_UDP ||
           NI_OPTS(&ep->thr->netif).udp_connect_handover )
#endif
      ) {
    wq_active = ci_waitable_active(&ep->waitq);
    ci_waitable_wakeup_all(&ep->waitq);
    if( wq_active ) {
      if( mask & POLLIN )
        CITP_STATS_NETIF_INC(&ep->thr->netif, sock_wakes_rx_os);
      if( mask & POLLOUT )
        CITP_STATS_NETIF_INC(&ep->thr->netif, sock_wakes_tx_os);
    }
  }

  return 1;
}

static void efab_ptable_queue_proc(struct file *file,
                                   wait_queue_head_t *whead,
                                   poll_table *pt)
{
  struct oo_os_sock_poll *os_sock_pt = container_of(pt,
                                                    struct oo_os_sock_poll,
                                                    pt);
  init_waitqueue_func_entry(&os_sock_pt->wait, efab_os_callback);
  os_sock_pt->whead = whead;
  add_wait_queue(whead, &os_sock_pt->wait);
}

/* connect to os_sock->f_op->poll() to get error messages */
void efab_tcp_helper_os_pollwait_register(tcp_helper_endpoint_t* ep)
{
  OO_DEBUG_ASYNC(ci_log("%s: %d:%d", __FUNCTION__, ep->thr->id,
                        OO_SP_FMT(ep->id)));
  ci_assert_equal(ep->os_sock_pt.whead, NULL);
  init_poll_funcptr(&ep->os_sock_pt.pt, efab_ptable_queue_proc);
  ep->os_socket->file->f_op->poll(ep->os_socket->file, &ep->os_sock_pt.pt);
}

void efab_tcp_helper_os_pollwait_unregister(tcp_helper_endpoint_t* ep)
{
  if( ep->os_sock_pt.whead ) {
    remove_wait_queue(ep->os_sock_pt.whead, &ep->os_sock_pt.wait);
    ep->os_sock_pt.whead = NULL;
  }
}
/*! \cidoxg_end */
