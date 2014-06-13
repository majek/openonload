/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  djr
**  \brief  UDP recvmsg() etc.
**   \date  2003/12/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#define _GNU_SOURCE  /* for recvmmsg */

#include "ip_internal.h"
#include <onload/osfile.h>
#if defined(__unix__) && !defined(__KERNEL__)
# include <ci/internal/ip_signal.h>
#endif

#if !defined(__KERNEL__)
#include <sys/socket.h>
#include <onload/extensions_zc.h>
#endif

#define VERB(x)

#define LPF "ci_udp_"
#define LPFIN LPF
#define LPFOUT LPF


/* Implementation:
**  MSG_PEEK         supported
**  MSG_ERRQUEUE     supported (Linux only)
**  MSG_OOB          not supported (ignored)
**  MSG_WAITALL      supported (as is O_NONBLOCK through fcntl)
**  MSG_NOSIGNAL     not UDP
**  MSG_TRUNC        supported
**
**  Fragmentation is not supported (by netif_event.c functions)
*/


/* Set [MSG_OOB_CHK] to [MSG_OOB] if it should be rejected, or to [0] if it
** should be ignored in UDP recv*() functions.
**
** On Linux, MSG_OOB is ignored.
*/
#define MSG_OOB_CHK	0

#ifdef MSG_ERRQUEUE
# define MSG_ERRQUEUE_CHK	MSG_ERRQUEUE
#else
# define MSG_ERRQUEUE_CHK	0
#endif

# define HAVE_MSG_FLAGS		1
# define LOCAL_MSG_TRUNC	MSG_TRUNC



ci_inline void ci_udp_recvmsg_fill_msghdr(ci_netif* ni, struct msghdr* msg,
					  const ci_ip_pkt_fmt* pkt,
					  ci_sock_cmn* s)
{
  const ci_udp_hdr* udp;
  const ci_ip4_hdr* ip;

  if( msg != NULL ) {
    if( msg->msg_name != NULL ) {
      if( pkt->flags & CI_PKT_FLAG_RX_INDIRECT )
        pkt = PKT_CHK_NNL(ni, pkt->frag_next);
      ip = oo_ip_hdr(pkt);
      udp = (const ci_udp_hdr*) ((char*) ip + CI_IP4_IHL(ip));
      ci_addr_to_user(CI_SA(msg->msg_name), &msg->msg_namelen,
                      s->domain, udp->udp_source_be16, ip->ip_saddr_be32);
    }
  }
}


ci_inline int do_copy(void* to, const void* from, int n_bytes
                      CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
#ifdef __KERNEL__
  if( addr_spc != CI_ADDR_SPC_KERNEL )
    return copy_to_user(to, from, n_bytes) != 0;
#endif
  memcpy(to, from, n_bytes);
  return 0;
}


static int
oo_copy_pkt_to_iovec_no_adv(ci_netif* ni, const ci_ip_pkt_fmt* pkt,
                            ci_iovec_ptr* piov, int bytes_to_copy
                            CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  /* Copy data from [pkt] to [piov], following [pkt->frag_next] as
   * necessary.  Does not modify [pkt].  May or may not advance [piov].
   * The packet must contain at least [bytes_to_copy] of data in the
   * [pkt->buf].  [piov] may contain an arbitrary amount of space.
   *
   * Returns number of bytes copied on success, or -EFAULT otherwise.
   */
  int n, pkt_left, pkt_off = 0;
  int bytes_copied = 0;

  while( 1 ) {
    pkt_left = oo_offbuf_left(&pkt->buf) - pkt_off;
    n = CI_MIN(pkt_left, CI_IOVEC_LEN(&piov->io));
    n = CI_MIN(n, bytes_to_copy);
    if(CI_UNLIKELY( do_copy(CI_IOVEC_BASE(&piov->io),
                            oo_offbuf_ptr(&pkt->buf) + pkt_off, n
                            CI_KERNEL_ARG(addr_spc)) != 0 ))
      return -EFAULT;

    bytes_copied += n;
    pkt_off += n;
    if( n == bytes_to_copy )
      return bytes_copied;

    bytes_to_copy -= n;
    if( n == pkt_left ) {
      /* Caller guarantees that packet contains at least [bytes_to_copy]. */
      ci_assert(OO_PP_NOT_NULL(pkt->frag_next));
      ci_iovec_ptr_advance(piov, n);
      pkt = PKT_CHK_NNL(ni, pkt->frag_next);
      pkt_off = 0;
      /* We're unlikely to hit end-of-pkt-buf and end-of-iovec at the same
       * time, and if we do, just go round the loop again.
       */
      continue;
    }

    ci_assert_equal(n, CI_IOVEC_LEN(&piov->io));
    if( piov->iovlen == 0 )
      return bytes_copied;
    piov->io = *piov->iov++;
    --piov->iovlen;
  }
}


#ifndef __KERNEL__
/* Max number of iovecs needed:
 * = max_datagram / (min_mtu - udp_header)
 * = 65536 / (576 - 28) 
 * = 120
 */
#define CI_UDP_ZC_IOVEC_MAX 120

static void ci_udp_pkt_to_zc_msg(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                 struct onload_zc_msg* zc_msg)
{
  int i, bytes_left = pkt->pay_len;
  ci_ip_pkt_fmt* frag;
  ci_ip_pkt_fmt* handle_frag;

  handle_frag = frag = pkt;
  i = 0;
  ci_assert_nequal(zc_msg->iov, NULL);

  /* Ignore first frag if zero length and there is another frag, but
   * still pass the zero-length buffer as the onload_zc_handle so it
   * will get freed correctly
   */
  if( oo_offbuf_left(&frag->buf) == 0 && OO_PP_NOT_NULL(frag->frag_next) )
    frag = PKT_CHK_NNL(ni, frag->frag_next);

  do {
    zc_msg->iov[i].iov_len = CI_MIN(oo_offbuf_left(&frag->buf), 
                                    bytes_left);
    zc_msg->iov[i].iov_base = oo_offbuf_ptr(&frag->buf);
    zc_msg->iov[i].buf = (onload_zc_handle)handle_frag;
    zc_msg->iov[i].iov_flags = 0;
    bytes_left -= zc_msg->iov[i].iov_len;
    ++i;
    if( OO_PP_IS_NULL(frag->frag_next) || 
        (i == CI_UDP_ZC_IOVEC_MAX) ||
        (bytes_left == 0) )
      break;
    frag = PKT_CHK_NNL(ni, frag->frag_next);
    handle_frag = frag;
  } while( 1 );
  zc_msg->msghdr.msg_iovlen = i;
}


# if CI_CFG_ZC_RECV_FILTER
static int ci_zc_msg_to_udp_pkt(ci_netif* ni, 
                                struct onload_zc_msg* zc_msg,
                                ci_ip_pkt_fmt* pkt)
{
  int i, n_buffers = pkt->n_buffers, dropped_bytes = 0;
  ci_ip_pkt_fmt* frag;
  ci_ip_pkt_fmt* prev_frag = NULL;
  frag = pkt;
  i = 0;
  ci_assert_nequal(zc_msg->iov, NULL);

  /* Ignore first frag if zero length and there is another frag */
  if( oo_offbuf_left(&frag->buf) == 0 && OO_PP_NOT_NULL(frag->frag_next) ) {
    frag = PKT_CHK_NNL(ni, frag->frag_next);
    --n_buffers;
  }

  CI_TEST(zc_msg->msghdr.msg_iovlen <= n_buffers);
  CI_TEST(zc_msg->msghdr.msg_iovlen > 0);

  do {
    CI_TEST(zc_msg->iov[i].buf == (onload_zc_handle)frag);
    CI_TEST(zc_msg->iov[i].iov_len != 0);
    if( i < zc_msg->msghdr.msg_iovlen ) {
      if( zc_msg->iov[i].iov_base != oo_offbuf_ptr(&frag->buf) ) {
        ci_assert_gt((char*)zc_msg->iov[i].iov_base, 
                     oo_offbuf_ptr(&frag->buf));
        dropped_bytes += ((char*)zc_msg->iov[i].iov_base - 
                          oo_offbuf_ptr(&frag->buf) );
        oo_offbuf_set_start(&frag->buf, (char*)zc_msg->iov[i].iov_base);
      }
      if( zc_msg->iov[i].iov_len != oo_offbuf_left(&frag->buf) ) {
        ci_assert_lt(zc_msg->iov[i].iov_len, oo_offbuf_left(&frag->buf));
        dropped_bytes += (oo_offbuf_left(&frag->buf) - zc_msg->iov[i].iov_len);
        oo_offbuf_set_len(&frag->buf, zc_msg->iov[i].iov_len);
      }
    }
    else {
      /* All remaining fragments should be discarded.  Should not get
       * here on first frag as msg_iovlen > 0
       */
      ci_assert(prev_frag != NULL);
      prev_frag->frag_next = OO_PP_NULL;
      /* remember frag so we can release it after counting dropped bytes */
      prev_frag = frag;
      do {
        dropped_bytes += oo_offbuf_left(&frag->buf);
        if( ++i == n_buffers )
          break;
        frag = PKT_CHK_NNL(ni, frag->frag_next);
      } while( 1 );
      ci_netif_pkt_release(ni, prev_frag);
      pkt->n_buffers -= (n_buffers - zc_msg->msghdr.msg_iovlen);
      return dropped_bytes;
    }

    ci_assert_lt(oo_offbuf_offset(&frag->buf) + oo_offbuf_left(&frag->buf),
                 CI_CFG_PKT_BUF_SIZE);

    if( ++i == n_buffers )
      break;
    prev_frag = frag;
    frag = PKT_CHK_NNL(ni, frag->frag_next);
  } while( 1 );

  return dropped_bytes;
}


int ci_udp_filter_recved_pkts(ci_netif* ni, ci_udp_state* us)
{
  enum onload_zc_callback_rc rc;
  struct onload_zc_msg zc_msg;
  struct onload_zc_iovec zc_iovec[CI_UDP_ZC_IOVEC_MAX];
  ci_ip_pkt_fmt* pkt;
  unsigned cb_flags;
  int dropped_bytes;

  ci_assert(ci_sock_is_locked(ni, &us->s.b));

  zc_msg.iov = zc_iovec;
  zc_msg.msghdr.msg_controllen = 0;
  zc_msg.msghdr.msg_flags = 0;

  while( us->recv_q.pkts_added != 
         us->recv_q.pkts_filter_passed + us->recv_q.pkts_filter_dropped ) {
    ci_rmb();
    pkt = PKT_CHK_NNL(ni, us->recv_q.filter);
    if( pkt->pf.udp.rx_flags & 
        (CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED |
         CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED) ) {
      /* We know this can't go past tail because of the while loop condition */
      us->recv_q.filter = pkt->next;
      pkt = PKT_CHK_NNL(ni, us->recv_q.filter);
      ci_assert( !(pkt->pf.udp.rx_flags & 
                   (CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED |
                    CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED)) );
    }

    ci_udp_pkt_to_zc_msg(ni, pkt, &zc_msg);

    cb_flags = CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ? 
      ONLOAD_ZC_MSG_SHARED : 0;
    rc = (*(onload_zc_recv_filter_callback)((ci_uintptr_t)us->recv_q_filter))
      (&zc_msg, (void *)((ci_uintptr_t)us->recv_q_filter_arg), cb_flags);

    ci_assert(!(rc & ONLOAD_ZC_KEEP));

    if( rc & ONLOAD_ZC_TERMINATE ) {
      us->recv_q.bytes_filter_dropped += pkt->pay_len;
      pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED;
      ++us->recv_q.pkts_filter_dropped;
    }
    else {
      pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED;
      ++us->recv_q.pkts_filter_passed;
      if( rc & ONLOAD_ZC_MODIFIED ) {
        ci_assert(!(cb_flags & ONLOAD_ZC_MSG_SHARED));
        dropped_bytes = ci_zc_msg_to_udp_pkt(ni, &zc_msg, pkt);
        ci_assert_gt(dropped_bytes, 0);
        ci_assert_lt(dropped_bytes, pkt->pay_len);
        pkt->pay_len -= dropped_bytes;
        us->recv_q.bytes_filter_dropped += dropped_bytes;
      }
      us->recv_q.bytes_filter_passed += pkt->pay_len;
      return 1;
    }
  }

  return us->recv_q.pkts_filter_passed != us->recv_q.pkts_delivered;
}


static int ci_udp_filter_kernel_pkt(ci_netif* ni, ci_udp_state* us, 
                                    struct msghdr* msg, int *bytes)
{
  enum onload_zc_callback_rc rc;
  struct onload_zc_msg zc_msg;
  struct onload_zc_iovec zc_iovec[CI_UDP_ZC_IOVEC_MAX];
  unsigned cb_flags = 0;
  int i = 0, bytes_remaining = *bytes;

  if( msg->msg_iovlen > CI_UDP_ZC_IOVEC_MAX ) {
    LOG_U(log("%s: too many fragments (%d), passing packet unfiltered", 
              __FUNCTION__, (int)msg->msg_iovlen));
    return 1;
  }

  zc_msg.iov = zc_iovec;
  zc_msg.msghdr = *msg;
  zc_msg.msghdr.msg_iov = NULL;

  ci_assert_gt(msg->msg_iovlen, 0);

  do { 
    zc_msg.iov[i].iov_base = msg->msg_iov[i].iov_base;
    zc_msg.iov[i].iov_len = msg->msg_iov[i].iov_len > bytes_remaining ? 
      bytes_remaining : msg->msg_iov[i].iov_len;
    zc_msg.iov[i].buf = ONLOAD_ZC_HANDLE_NONZC;
    zc_msg.iov[i].iov_flags = 0;
    bytes_remaining -= zc_msg.iov[i].iov_len;
  } while(++i < msg->msg_iovlen && bytes_remaining);

  zc_msg.msghdr.msg_iovlen = i;

  rc = (*(onload_zc_recv_filter_callback)((ci_uintptr_t)us->recv_q_filter))
    (&zc_msg, (void *)((ci_uintptr_t)us->recv_q_filter_arg), cb_flags);

  ci_assert(!(rc & ONLOAD_ZC_KEEP));

  if( rc & ONLOAD_ZC_TERMINATE ) 
    return 0;
  else {
    if( rc & ONLOAD_ZC_MODIFIED ) {
      int new_len = 0;
#ifndef NDEBUG
      int found_shortened_iov = 0;
#endif
      for( i = 0; i < zc_msg.msghdr.msg_iovlen; ++i ) {
        new_len += zc_msg.iov[i].iov_len;
#ifndef NDEBUG
        if( found_shortened_iov )
          ci_assert_equal(zc_msg.iov[i].iov_len, 0);
        ci_assert_equal(zc_msg.iov[i].iov_base, msg->msg_iov[i].iov_base);
        if( zc_msg.iov[i].iov_len != msg->msg_iov[i].iov_len ) {
          ci_assert_lt(zc_msg.iov[i].iov_len, msg->msg_iov[i].iov_len);
          found_shortened_iov = 1;
        }
#endif
      }
#ifndef NDEBUG
      if( found_shortened_iov )
        ci_assert_lt(new_len, *bytes);
      else
        ci_assert_equal(new_len, *bytes);
#endif
      *bytes = new_len;
    }
  }
  return 1;
}
# endif
#endif

static int ci_udp_recvmsg_get(ci_netif* ni, ci_udp_state* us,
                              ci_iovec_ptr* piov, 
                              struct msghdr* msg, int flags
                              CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_ip_pkt_fmt* pkt;
  int rc;

  /* NB. [msg] can be NULL for async recv. */

  if( ci_udp_recv_q_not_readable(ni, us) )
    goto recv_q_is_empty;

  ci_rmb();

  pkt = PKT_CHK_NNL(ni, us->recv_q.extract);
  if( pkt->pf.udp.rx_flags & CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED ) {
    /* We know that the receive queue is not empty and if a filter is
     * involved that there are some that have passed the filter, so if
     * this pkt is already consumed, the next one must be OK to
     * receive (and already have been filtered)
     */
    us->recv_q.extract = pkt->next;
    pkt = PKT_CHK_NNL(ni, us->recv_q.extract);
    ci_assert( !(pkt->pf.udp.rx_flags & 
                 CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED) );
#if CI_CFG_ZC_RECV_FILTER
    if( us->recv_q_filter )
      /* Filter should have run on this packet and marked it */
      ci_assert( (pkt->pf.udp.rx_flags & 
                  (CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED | 
                   CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED)) ); 
    else
      /* Bump this along as we don't have a filter installed, but want
       * to keep the filter pointer in a sane place
       */
      us->recv_q.filter = us->recv_q.extract;
#endif
  }

#if CI_CFG_ZC_RECV_FILTER
  /* Skip any that the filter has dropped.  This must terminate before
   * hitting the tail because we know the queue is readable.
   */
  while( pkt->pf.udp.rx_flags & CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED ) {
    us->recv_q.extract = pkt->next;
    pkt = PKT_CHK_NNL(ni, us->recv_q.extract);
  }
#endif

  if( msg != NULL && msg->msg_controllen != 0 ) {
#ifdef __KERNEL__
    /* We currently don't need to do any cmsg recvmsg stuff in-kernel
     * as calls are all via recv/read 
     */
    CI_TEST(0);
#else
    if( CI_UNLIKELY(us->s.cmsg_flags != 0 ) )
      ci_ip_cmsg_recv(ni, us, pkt, msg, 0);
    else
      msg->msg_controllen = 0;
#endif
  }
  us->stamp = pkt->pf.udp.rx_stamp;

  rc = oo_copy_pkt_to_iovec_no_adv(ni, pkt, piov, pkt->pay_len
                                   CI_KERNEL_ARG(addr_spc));

  if(CI_LIKELY( rc >= 0 )) {
#if HAVE_MSG_FLAGS
    if(CI_UNLIKELY( rc < pkt->pay_len && msg != NULL ))
      msg->msg_flags |= LOCAL_MSG_TRUNC;
#endif
    ci_udp_recvmsg_fill_msghdr(ni, msg, pkt, &us->s);
    if( ! (flags & MSG_PEEK) ) {
      us->recv_q.bytes_delivered += pkt->pay_len;
      us->recv_q.pkts_delivered  += 1;
      pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED;
#if CI_CFG_ZC_RECV_FILTER
      if( !us->recv_q_filter ) {
        /* Pretend this packet passed the filter, to keep state consistent */
        ++us->recv_q.pkts_filter_passed;
        us->recv_q.bytes_filter_passed += pkt->pay_len;
        pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_PASSED;
      }
#endif
    }
    us->udpflags |= CI_UDPF_LAST_RECV_ON;
  }

  return rc;

 recv_q_is_empty:
  return -EAGAIN;
}


#ifndef __KERNEL__

static int __ci_udp_recvmsg_try_os(ci_netif *ni, ci_udp_state *us,
                                   struct msghdr* msg, int flags, int* prc)
{
  int rc;

  rc = oo_os_sock_recvmsg(ni, SC_SP(&us->s), msg, flags | MSG_DONTWAIT);

  if( rc >= 0 ) {
    ++us->stats.n_rx_os;
    us->udpflags &= ~CI_UDPF_LAST_RECV_ON;
    if( ! (flags & MSG_PEEK) )
      us->udpflags &=~ CI_UDPF_PEEK_FROM_OS;
    else
      us->udpflags |=  CI_UDPF_PEEK_FROM_OS;
  }
  else {
    if( rc == -EAGAIN )
      return 0;
    ci_assert(-rc == errno);
    rc = -1;
    ++us->stats.n_rx_os_error;
  }

  *prc = rc;
  return 1;
}

#else  /* __KERNEL__ */

static int __ci_udp_recvmsg_try_os(ci_netif *ni, ci_udp_state *us,
                                   struct msghdr* msg, int flags, int* prc)
{
  int rc, total_bytes, i;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;
  struct file *os_sock;

  total_bytes = 0;
  for( i = 0; i < msg->msg_iovlen; ++i )
    total_bytes += msg->msg_iov[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    return -EINVAL;

  ep = ci_netif_ep_get(ni, SC_SP(&us->s));
  os_sock = ep->os_socket->file;
  ci_assert(S_ISSOCK(os_sock->f_dentry->d_inode->i_mode));
  sock = SOCKET_I(os_sock->f_dentry->d_inode);

  rc = sock_recvmsg(sock, msg, total_bytes, flags | MSG_DONTWAIT);
  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear(&us->s, OO_OS_STATUS_RX,
                              os_sock->f_op->poll(os_sock, NULL) & POLLIN);
  if( rc >= 0 ) {
    ++us->stats.n_rx_os;
  }
  else {
    if( rc == -EAGAIN )
      return 0;
    ++us->stats.n_rx_os_error;
  }

  if( rc >= 0 ) {
    us->udpflags &= ~CI_UDPF_LAST_RECV_ON;
    if( ! (flags & MSG_PEEK) )
      us->udpflags &=~ CI_UDPF_PEEK_FROM_OS;
    else
      us->udpflags |=  CI_UDPF_PEEK_FROM_OS;
  }
  *prc = rc;
  return 1;
}

#endif  /* __KERNEL__ */

static int ci_udp_recvmsg_try_os(ci_udp_iomsg_args *a,
                                 struct msghdr* msg, int flags, int* prc)
{
  int rc;
  ci_udp_state *us = a->us;
#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER 
  struct msghdr saved_msg;
# endif
#endif

  if( !(us->s.os_sock_status & OO_OS_STATUS_RX) )
    return 0;

#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER 
  if( us->recv_q_filter )
    saved_msg = *msg;
# endif
#endif

  rc = __ci_udp_recvmsg_try_os(a->ni, us, msg, flags, prc);

#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER 
  if( us->recv_q_filter && rc == 1 && *prc >= 0) {
    rc = ci_udp_filter_kernel_pkt(a->ni, us, msg, prc);
    /* If we've dropped the pkt we need to restore the msghdr to
     * before calling sock_recvmsg so that future calls see the
     * user-supplied values 
     */
    if( rc == 0 )
      *msg = saved_msg;
  }
# endif
#endif
  return rc;
}


static int ci_udp_recvmsg_socklocked_slowpath(ci_udp_iomsg_args* a, 
                                              struct msghdr* msg,
                                              ci_iovec_ptr *piov, int flags)
{
  int rc = 0;
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;

  if(CI_UNLIKELY( ni->state->rxq_low ))
    ci_netif_rxq_low_on_recv(ni, &us->s,
                             1 /* assume at least one pkt freed */);
  /* In the kernel recv() with flags is not called.
   * only read(). So flags may only contain MSG_DONTWAIT */
#ifndef __KERNEL__
  if( flags & MSG_ERRQUEUE_CHK ) {
    /* ICMP is handled via OS, so get OS error */
    rc = oo_os_sock_recvmsg(ni, SC_SP(&us->s), msg, flags);
    if( rc < 0 ) {
      ci_assert(-rc == errno);
      return -1;
    }
    else
      return rc;
  }
#endif
  if( (rc = ci_get_so_error(&us->s)) != 0 ) {
    CI_SET_ERROR(rc, rc);
    return rc;
  }
  if( msg->msg_iovlen > 0 && msg->msg_iov == NULL ) {
    CI_SET_ERROR(rc, EFAULT);
    return rc;
  }
#if MSG_OOB_CHK
  if( flags & MSG_OOB_CHK ) {
    CI_SET_ERROR(rc, EOPNOTSUPP);
    return rc;
  }
#endif
#if CI_CFG_POSIX_RECV  
  if( ! udp_lport_be16(us)) {
    LOG_UV(log("%s: -1 (ENOTCONN)", __FUNCTION__));
    CI_SET_ERROR(rc, ENOTCONN);
    return rc;
  }
#endif
  if( msg->msg_iovlen == 0 ) {
    /* We have a difference in behaviour from the Linux stack here.  When
    ** msg_iovlen is 0 Linux 2.4.21-15.EL does not set MSG_TRUNC when a
    ** datagram has non-zero length.  We do. */
    CI_IOVEC_LEN(&piov->io) = piov->iovlen = 0;
    return 1;
  }
  return 0;
}


struct recvmsg_spinstate {
  ci_uint64 start_frc;
  ci_uint64 schedule_frc;
  ci_uint64 max_spin;
  int do_spin;
  int spin_limit_by_so;
  ci_uint32 timeout;
#ifndef __KERNEL__
  citp_signal_info* si;
#endif
};


static int 
ci_udp_recvmsg_block(ci_udp_iomsg_args* a, ci_netif* ni, ci_udp_state* us,
                     int timeout)
{
  int rc;

#ifndef __KERNEL__
  {
    citp_signal_info* si;
    struct pollfd pfd;
#if !CI_CFG_CITP_INSIDE_LIB_IS_FLAG
    int inside_lib;
#endif
    pfd.fd = a->fd;
    pfd.events = POLLIN;

    if( timeout == 0 )
      timeout = -1;

    /* Ideally, we should do the same as in citp_tcp_accept(), but since
     * we do not have lib_context and citp_exit_lib() out of unix/
     * subdirectory, we copy it contents. */
    si = citp_signal_get_specific_inited();
  continue_to_block:
#if !CI_CFG_CITP_INSIDE_LIB_IS_FLAG
    inside_lib = si->inside_lib;
    ci_assert_gt(inside_lib, 0);
#endif
    si->inside_lib = 0;
    ci_compiler_barrier();
    if(CI_UNLIKELY( si->run_pending ))
      citp_signal_run_pending(si);
    si->need_restart = 1;

    rc = ci_sys_poll(&pfd, 1, timeout);

#if CI_CFG_CITP_INSIDE_LIB_IS_FLAG
    si->inside_lib = 1;
#else
    si->inside_lib = inside_lib;
#endif

    if( rc > 0 )
      return 0;
    else if( rc == 0 )
      rc = -EAGAIN;
    else if( errno == EINTR && si->need_restart && timeout == -1 ) {
      /* Blocking recv() should only be restarted if there is no timeout. */
      goto continue_to_block;
    } else 
      rc = -errno;

    return rc;
  }
#else  /* __KERNEL__ */
  {
    int mask;
    s64 t;

    if( timeout == 0 )
      t = -1;
    else
      t = msecs_to_jiffies(timeout);

    mask = POLLIN;
    rc = efab_tcp_helper_poll_udp(a->filp, &mask, &t);
    if( rc == 0 ) {
      if( mask ) {
        return 0;
      }
      else
        rc = -EAGAIN;
    }
    else if( rc == -ERESTARTSYS &&  us->s.so.rcvtimeo_msec )
      rc = -EINTR;
  }
  return rc;
#endif /* __KERNEL__ */
}


ci_inline int
ci_udp_recvmsg_socklocked_spin(ci_udp_iomsg_args* a,
                               ci_netif* ni, ci_udp_state* us,
                               struct recvmsg_spinstate* spin_state)
{
  ci_uint64 now_frc;
  int intf_i;

  ci_frc64(&now_frc);
  if( now_frc - spin_state->start_frc < spin_state->max_spin ) {
    if( ci_netif_may_poll(ni) ) {
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        if( ci_netif_intf_has_event(ni, intf_i) && ci_netif_trylock(ni) ) {
          ci_netif_poll_intf_fast(ni, intf_i, now_frc);
          ci_netif_unlock(ni);
          if( ci_udp_recv_q_readable(ni, us) )
            return 0;
        }
      if( ni->state->poll_work_outstanding ||
          ci_netif_need_timer_prime(ni, now_frc) )
        if( ci_netif_trylock(ni) ) {
          ci_netif_poll(ni);
          ci_netif_unlock(ni);
        }
      if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
    }
    return OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, 
                                           &spin_state->schedule_frc,
                                           us->s.so.rcvtimeo_msec,
                                           &us->s.b, spin_state->si);
  }
  else {
    if( spin_state->spin_limit_by_so ) {
      ++us->stats.n_rx_eagain;
      return -EAGAIN;
    }

    if( spin_state->timeout ) {
      ci_uint32 spin_ms = NI_OPTS(ni).spin_usec >> 10;
      if( spin_ms < spin_state->timeout )
        spin_state->timeout -= spin_ms;
      else {
        ++us->stats.n_rx_eagain;
        return -EAGAIN;
      }
    }
    spin_state->do_spin = 0;
  }

  ni->state->is_spinner = 0;
  return 1;
}


static int 
ci_udp_recvmsg_socklocked(ci_udp_iomsg_args *a, struct msghdr* msg, 
                          int flags CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  int have_polled = 0;
  ci_iovec_ptr  piov = {NULL,0, {NULL, 0}};
  int rc = 0, slow;
  struct recvmsg_spinstate spin_state = {0};

#ifndef __KERNEL__
  spin_state.do_spin = -1;
  spin_state.si = citp_signal_get_specific_inited();
#endif
  spin_state.timeout = us->s.so.rcvtimeo_msec;

  slow = ((flags & (MSG_OOB_CHK | MSG_ERRQUEUE_CHK)) |
	  (msg->msg_iovlen == 0                    ) |
	  (msg->msg_iov == NULL                    ) |
	  (ni->state->rxq_low                      ) |
#if CI_CFG_POSIX_RECV  
	  (udp_lport_be16(us) == 0                 ) |
#endif
	  (us->s.so_error                          ));
  if( slow )
    goto slow_path;

 back_to_fast_path:
  ci_iovec_ptr_init_nz(&piov, msg->msg_iov, msg->msg_iovlen);
  
 piov_inited:
#if HAVE_MSG_FLAGS
  msg->msg_flags = 0;
#endif

  if(CI_UNLIKELY( us->udpflags & CI_UDPF_PEEK_FROM_OS ))
    goto peek_from_os;

 check_ul_recv_q:
  rc = ci_udp_recvmsg_get(ni, us, &piov, msg, flags CI_KERNEL_ARG(addr_spc));
  if( rc >= 0 )
    goto out;

  /* User-level receive queue is empty. */

  if( ! have_polled ) {
    have_polled = 1;
    ci_frc64(&spin_state.start_frc);

    if( ci_netif_may_poll(ni) &&
        ci_netif_need_poll_spinning(ni, spin_state.start_frc) &&
        ci_netif_trylock(ni) ) {
      int any_evs = ci_netif_poll_n(ni, NI_OPTS(ni).evs_per_poll);
      if( ci_udp_recv_q_is_empty(us) && any_evs )
        ci_netif_poll(ni);
      ci_netif_unlock(ni);
      if( ci_udp_recv_q_readable(ni, us) )
        goto check_ul_recv_q;
    }
  }

  if(CI_UNLIKELY( (rc = UDP_RX_ERRNO(us)) )) {
    CI_SET_ERROR(rc, rc);
    us->s.rx_errno = us->s.rx_errno & 0xf0000000;
    goto out;
  }
  if(CI_UNLIKELY( us->s.so_error )) {
    int rc1 = ci_get_so_error(&us->s);
    if( rc1 != 0 ) {
      CI_SET_ERROR(rc, rc1);
      goto out;
    }
  }

  /* Nothing doing at userlevel.  Need to check the O/S socket. */
  if( ci_udp_recvmsg_try_os(a, msg, flags, &rc) )
    goto out;

  if( ((flags | us->s.b.sb_aflags) & MSG_DONTWAIT)) {
    /* UDP returns EAGAIN when non-blocking even when shutdown. */
    CI_SET_ERROR(rc, EAGAIN);
    ++us->stats.n_rx_eagain;
    goto out;
  }
  else if (UDP_IS_SHUT_RD(us)) {
    /* Blocking and shutdowned */
    rc = 0;
    goto out;
  }

  /* We need to block (optionally spinning first). */

#ifndef __KERNEL__    
  /* -1 is special value for uninitialised */
  if( spin_state.do_spin == -1 ) {
    spin_state.do_spin = 
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_RECV);

    if( spin_state.do_spin ) {
      spin_state.schedule_frc = spin_state.start_frc;
      spin_state.max_spin = ni->state->spin_cycles;
      if( us->s.so.rcvtimeo_msec ) {
        ci_uint64 max_so_spin = (ci_uint64)us->s.so.rcvtimeo_msec *
            IPTIMER_STATE(ni)->khz;
        if( max_so_spin <= spin_state.max_spin ) {
          spin_state.max_spin = max_so_spin;
          spin_state.spin_limit_by_so = 1;
        }
      }
    }
  }

  if( spin_state.do_spin ) {
    rc = ci_udp_recvmsg_socklocked_spin(a, ni, us, &spin_state);
    if( rc == 0 )
      goto check_ul_recv_q;
    else if( rc < 0 ) {
      CI_SET_ERROR(rc, -rc);
      goto out;
    }
  }
#endif

  ci_sock_unlock(ni, &us->s.b);
  rc = ci_udp_recvmsg_block(a, ni, us, spin_state.timeout);
  ci_sock_lock_fixme(ni, &us->s.b);
  if( rc == 0 )
    goto check_ul_recv_q;
  CI_SET_ERROR(rc, -rc);

 out:
  ni->state->is_spinner = 0;
  return rc;

 slow_path:
  rc = ci_udp_recvmsg_socklocked_slowpath(a, msg, &piov, flags);
  if( rc == 0 ) 
    goto back_to_fast_path;
  else if( rc == 1 )
    goto piov_inited;
  else
    goto out;

 peek_from_os:
  if( ci_udp_recvmsg_try_os(a, msg, flags, &rc) )
    goto out;
  
  goto check_ul_recv_q;
}


int ci_udp_recvmsg(ci_udp_iomsg_args *a, struct msghdr* msg, 
                   int flags CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  int rc;

  /* Grab the per-socket lock so we can access the receive queue. */
  rc = ci_sock_lock(ni, &us->s.b);
  if(CI_UNLIKELY( rc != 0 )) {
    CI_SET_ERROR(rc, -rc);
    return rc;
  }
  rc = ci_udp_recvmsg_socklocked(a, msg, flags CI_KERNEL_ARG(addr_spc));
  ci_sock_unlock(ni, &us->s.b);

  return rc;
}


#if CI_CFG_RECVMMSG && !defined(__KERNEL__)
int ci_udp_recvmmsg(ci_udp_iomsg_args *a, struct mmsghdr* mmsg, 
                    unsigned int vlen, int flags, 
                    const struct timespec* timeout 
                    CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  int rc, i;
  struct timeval tv_before;
  int timeout_msec = -1;

  if( timeout ) {
    timeout_msec = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
    gettimeofday(&tv_before, NULL);
  }

  rc = ci_sock_lock(ni, &us->s.b);
  if(CI_UNLIKELY( rc != 0 )) {
    CI_SET_ERROR(rc, -rc);
    return rc;
  }

  i = 0;
  while( i < vlen && timeout_msec != 0 ) { 
    rc = ci_udp_recvmsg_socklocked(a, &mmsg[i].msg_hdr, flags
                                   CI_KERNEL_ARG(addr_spc));
    if( rc >= 0 )
      mmsg[i].msg_len = rc;
    else {
      if( i != 0 && errno != EAGAIN )
        us->s.so_error = errno;
      ci_sock_unlock(ni, &us->s.b);
      if( i != 0 )
        return i;
      else
        return rc;
    }

    if( ( flags & MSG_DONTWAIT ) && rc == 0 )
      break;

    if( flags & MSG_WAITFORONE )
      flags |= MSG_DONTWAIT;
    
    if( timeout_msec > 0 ) {
      struct timeval tv_after, tv_sub;
      gettimeofday(&tv_after, NULL);
      timersub(&tv_after, &tv_before, &tv_sub);
      tv_before = tv_after;
      timeout_msec -= tv_sub.tv_sec * 1000 + tv_sub.tv_usec / 1000;
      if( timeout_msec < 0 ) {
        timeout_msec = 0;
        flags |= MSG_DONTWAIT;
      }
    }
    ++i;
  }

  ci_sock_unlock(ni, &us->s.b);
  
  return i;
}
#endif


#ifndef __KERNEL__

static int ci_udp_zc_recv_from_os(ci_netif* ni, ci_udp_state* us,
                                  struct onload_zc_recv_args* args, 
                                  enum onload_zc_callback_rc* cb_rc)
{
#define ZC_BUFFERS_FOR_64K_DATAGRAM ((0x10000 / (CI_CFG_PKT_BUF_SIZE - \
                                                 PKT_START_OFF())) + 1)
  int rc, i, cb_flags;
  struct msghdr msg;
  struct iovec iov[ZC_BUFFERS_FOR_64K_DATAGRAM];
  struct onload_zc_iovec zc_iov[ZC_BUFFERS_FOR_64K_DATAGRAM];
  oo_pkt_p pkt_p, first_pkt_p;
  ci_ip_pkt_fmt* pkt;

  if( us->zc_kernel_datagram_count < ZC_BUFFERS_FOR_64K_DATAGRAM) {
    /* We've not come this way before, so allocate enough packet bufs
     * to hold max size UDP datagram 
     */
    ci_netif_lock(ni);
    while( us->zc_kernel_datagram_count < ZC_BUFFERS_FOR_64K_DATAGRAM ) {
      pkt = ci_netif_pkt_alloc(ni);
      if( !pkt ) {
        ci_netif_unlock(ni);
        return -ENOBUFS;
      }
      pkt->frag_next = us->zc_kernel_datagram;
      us->zc_kernel_datagram = OO_PKT_P(pkt);
      ++us->zc_kernel_datagram_count;
    }
    ci_netif_unlock(ni);
  }

  pkt_p = us->zc_kernel_datagram;
  i = 0;
  while( OO_PP_NOT_NULL(pkt_p) ) {
#ifndef NDEBUG
    ci_assert_lt(i, us->zc_kernel_datagram_count);
#endif
    pkt = PKT_CHK_NNL(ni, pkt_p);
    iov[i].iov_base = PKT_START(pkt);
    iov[i].iov_len = (CI_CFG_PKT_BUF_SIZE - (PKT_START(pkt) - (char*)pkt));
    ++i;
    pkt_p = pkt->frag_next;
  }

  msg.msg_iov = iov;
  msg.msg_iovlen = i;
  msg.msg_control = args->msg.msghdr.msg_control;
  msg.msg_controllen = args->msg.msghdr.msg_controllen;
  msg.msg_name = args->msg.msghdr.msg_name;
  msg.msg_namelen = args->msg.msghdr.msg_namelen;
  msg.msg_flags = 0;

  ci_assert(us->s.os_sock_status & OO_OS_STATUS_RX);
  i = __ci_udp_recvmsg_try_os(ni, us, &msg, 
                              args->flags & ONLOAD_ZC_RECV_FLAGS_PTHRU_MASK,
                              &rc);
  ci_assert_equal(i, 1);
  ci_assert_gt(rc, 0);

  /* We now have to translate the result from OS recvmsg - stored as
   * an iovec - into something we can pass to the callback, stored in
   * the caller's onload_zc_iovec 
   */
  
  i = 0;
  pkt_p = us->zc_kernel_datagram;
  while( rc > 0 ) {
#ifndef NDEBUG
    ci_assert_lt(i, us->zc_kernel_datagram_count);
#endif
    pkt = PKT_CHK_NNL(ni, pkt_p);
    zc_iov[i].iov_len = rc > iov[i].iov_len ? iov[i].iov_len : rc;
    zc_iov[i].iov_base = iov[i].iov_base;
    zc_iov[i].buf = (onload_zc_handle)pkt;

    rc -= zc_iov[i].iov_len;
    ++i;
    pkt_p = pkt->frag_next;
  }

  /* Clear last packet's frag_next in chain we're passing to callback.
   * We'll restore it later if they don't keep the buffers  
   */
  pkt->frag_next = OO_PP_NULL;
  /* pkt_p handily points to the buffer after the last one used for
   * this datagram, and i is the number of buffers we used.  Remove
   * them from the zc_kernel_datagram list
   */
  first_pkt_p = us->zc_kernel_datagram;
  us->zc_kernel_datagram = pkt_p;
#ifndef NDEBUG
  ci_assert_ge(us->zc_kernel_datagram_count, i);
#endif
  us->zc_kernel_datagram_count -= i;

  args->msg.iov = zc_iov;
  args->msg.msghdr.msg_iovlen = i;
  args->msg.msghdr.msg_control = msg.msg_control;
  args->msg.msghdr.msg_controllen = msg.msg_controllen;
  args->msg.msghdr.msg_name = msg.msg_name;
  args->msg.msghdr.msg_namelen = msg.msg_namelen;
  args->msg.msghdr.msg_flags = msg.msg_flags;

  cb_flags = 0;
  if( (ci_udp_recv_q_pkts(&us->recv_q) == 0) && 
      (us->s.os_sock_status & OO_OS_STATUS_RX) == 0 )
    cb_flags |= ONLOAD_ZC_END_OF_BURST;

  /* Beware - as soon as we provide the pkts to the callback we can't 
   * touch them anymore as we don't know what the app might be doing with
   * them, such as releasing them.
   */
  *cb_rc = (*args->cb)(args, cb_flags);

  if( !((*cb_rc) & ONLOAD_ZC_KEEP) ) {
    /* Put the buffers back on the zc_kernel_datagram list */
    pkt->frag_next = us->zc_kernel_datagram;
    us->zc_kernel_datagram = first_pkt_p;
    us->zc_kernel_datagram_count += i;
  }

  if( cb_flags & ONLOAD_ZC_END_OF_BURST ) {
    /* If we've advertised an end of burst, we should return to match
     * receive-via-Onload behaviour.  Note this assumes that setting
     * ONLOAD_ZC_TERMINATE clears ONLOAD_ZC_CONTINUE, and that
     * done_big_poll = 1 and done_kernel_poll = 1 in calling function
     */
    (*cb_rc) |= ONLOAD_ZC_TERMINATE;
    ci_assert(((*cb_rc) & ONLOAD_ZC_CONTINUE) == 0);
  }

  return 0;
}


int ci_udp_zc_recv(ci_udp_iomsg_args* a, struct onload_zc_recv_args* args)
{
  int rc, done_big_poll = 0, done_kernel_poll = 0, done_callback = 0;
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  enum onload_zc_callback_rc cb_rc = ONLOAD_ZC_CONTINUE;
  struct recvmsg_spinstate spin_state = {0};
  size_t supplied_controllen = args->msg.msghdr.msg_controllen;
  void* supplied_control = args->msg.msghdr.msg_control;
  socklen_t supplied_namelen = args->msg.msghdr.msg_namelen;
  void* supplied_name = args->msg.msghdr.msg_name;
  struct onload_zc_iovec iovec[CI_UDP_ZC_IOVEC_MAX];
  unsigned cb_flags;

  spin_state.do_spin = -1;
  spin_state.si = citp_signal_get_specific_inited();
  spin_state.timeout = us->s.so.rcvtimeo_msec;

  rc = ci_sock_lock(ni, &us->s.b);
  if(CI_UNLIKELY( rc != 0 ))
    return rc;

#if CI_CFG_ZC_RECV_FILTER
  ci_assert(!us->recv_q_filter);
#endif

  if( CI_UNLIKELY(us->s.so_error) ) {
    if( (rc = ci_get_so_error(&us->s)) != 0 )
      return -rc;
  }

  if( ci_udp_recv_q_is_empty(us) )
    goto empty;

  while( 1 ) {
  not_empty:
    args->msg.iov = iovec;
    cb_flags = 0;

    while( ci_udp_recv_q_not_empty(us) ) {
      ci_ip_pkt_fmt* pkt;
      ci_rmb();

      pkt = PKT_CHK_NNL(ni, us->recv_q.extract);
      if( pkt->pf.udp.rx_flags & CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED ) {
        us->recv_q.extract = pkt->next;
#if CI_CFG_ZC_RECV_FILTER
        /* Bump this along as we don't have a filter installed, but want
         * to keep the filter pointer in a sane place
         */
        us->recv_q.filter = us->recv_q.extract;
#endif
        pkt = PKT_CHK_NNL(ni, us->recv_q.extract);
        ci_assert( !(pkt->pf.udp.rx_flags
                     & CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED) );
      }

#if CI_CFG_ZC_RECV_FILTER
      ci_assert( !(pkt->pf.udp.rx_flags & 
                   (CI_IP_PKT_FMT_PREFIX_UDP_RX_FILTER_DROPPED)) );
#endif

      args->msg.msghdr.msg_name = supplied_name;
      args->msg.msghdr.msg_namelen = supplied_namelen;
      args->msg.msghdr.msg_flags = 0;

      if( CI_UNLIKELY(us->s.cmsg_flags != 0 ) ) {
        args->msg.msghdr.msg_controllen = supplied_controllen;
        args->msg.msghdr.msg_control = supplied_control;
        ci_ip_cmsg_recv(ni, us, pkt, &args->msg.msghdr, 0);
      }
      else
        args->msg.msghdr.msg_controllen = 0;

      ci_udp_recvmsg_fill_msghdr(ni, &args->msg.msghdr, pkt, 
                                 &us->s);

      ci_udp_pkt_to_zc_msg(ni, pkt, &args->msg);

      us->stamp = pkt->pf.udp.rx_stamp;
      us->udpflags |= CI_UDPF_LAST_RECV_ON;
    
      cb_flags = CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ? 
        ONLOAD_ZC_MSG_SHARED : 0;
      if( (ci_udp_recv_q_pkts(&us->recv_q) == 1) &&
          ((us->s.os_sock_status & OO_OS_STATUS_RX) == 0) )
        cb_flags |= ONLOAD_ZC_END_OF_BURST;

      /* Add KEEP flag before calling callback, and remove it after
       * if not needed.  This prevents races where the app releases
       * the pkt before we've added the flag.
       */
      pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_KEEP;

      cb_rc = (*args->cb)(args, cb_flags);

      if( ! (cb_rc & ONLOAD_ZC_KEEP) ) {
        /* indicate need for ref to prevent it being reaped */
        pkt->pf.udp.rx_flags &=~ CI_IP_PKT_FMT_PREFIX_UDP_RX_KEEP;
      }

      us->recv_q.bytes_delivered += pkt->pay_len;
      us->recv_q.pkts_delivered  += 1;
      pkt->pf.udp.rx_flags |= CI_IP_PKT_FMT_PREFIX_UDP_RX_CONSUMED;
#if CI_CFG_ZC_RECV_FILTER
      /* Pretend it passed the filter to keep state consistent */
      us->recv_q.bytes_filter_passed += pkt->pay_len;
      ++us->recv_q.pkts_filter_passed;
#endif

      done_callback = 1;

      if( cb_rc & ONLOAD_ZC_TERMINATE )
        goto out;
    }

    if( done_big_poll && done_kernel_poll && 
        (cb_flags & ONLOAD_ZC_END_OF_BURST) )
      goto out;

    goto empty;
  }

 out:
  ni->state->is_spinner = 0;
  ci_sock_unlock(ni, &us->s.b);
  
  return rc;

 empty:
  if( spin_state.start_frc == 0 )
    ci_frc64(&spin_state.start_frc);

  if( ci_netif_may_poll(ni) &&
      ci_netif_need_poll_spinning(ni, spin_state.start_frc) && 
      ci_netif_trylock(ni) ) {
    /* If only a few events, we don't need to bother with the full poll */
    if( ci_netif_poll_n(ni, NI_OPTS(ni).evs_per_poll) < 
        NI_OPTS(ni).evs_per_poll )
      done_big_poll = 1;

    /* If polling a few events didn't get us anything, do a full poll */
    if( !done_big_poll && ci_udp_recv_q_is_empty(us) ) {
      done_big_poll = 1;
      ci_netif_poll(ni);
    }

    ci_netif_unlock(ni);

    if( ci_udp_recv_q_not_empty(us) )
      goto not_empty;

  } else 
    done_big_poll = 1; /* pretend we did if we can't poll */

 spin_loop:
  if(CI_UNLIKELY( (rc = UDP_RX_ERRNO(us)) )) {
    rc = -rc;
    us->s.rx_errno = us->s.rx_errno & 0xf0000000;
    goto out;
  }
  if(CI_UNLIKELY( us->s.so_error )) {
    int rc1 = ci_get_so_error(&us->s);
    if( rc1 != 0 ) {
      rc = -rc1;
      goto out;
    }
  }

  done_kernel_poll = 1;
  if( us->s.os_sock_status & OO_OS_STATUS_RX ) {
    if( args->flags & ONLOAD_MSG_RECV_OS_INLINE ) {
      do {
        /* Restore these just in case they are needed */
        args->msg.msghdr.msg_controllen = supplied_controllen;
        args->msg.msghdr.msg_control = supplied_control;
        args->msg.msghdr.msg_name = supplied_name;
        args->msg.msghdr.msg_namelen = supplied_namelen;
        rc = ci_udp_zc_recv_from_os(ni, us, args, &cb_rc);
        done_callback = 1;
        if( rc != 0 || cb_rc & ONLOAD_ZC_TERMINATE ) {
          ci_assert(done_big_poll);
          goto out;
        }
        if( ci_udp_recv_q_not_empty(us) )
          goto not_empty;
      } while( us->s.os_sock_status & OO_OS_STATUS_RX );
    }
    else {
      /* Return error */
      rc = -ENOTEMPTY;
      goto out;
    }
  }

  /* If we've done some callbacks, and checked everywhere for data,
   * we're at the end of a burst and should return without spinning
   * and blocking
   */
  if( done_callback ) {
    ci_assert(done_big_poll);
    ci_assert(done_kernel_poll);
    rc = 0;
    goto out;
  }

  if( ((args->flags | us->s.b.sb_aflags) & MSG_DONTWAIT)) {
    /* UDP returns EAGAIN when non-blocking even when shutdown. */
    rc = -EAGAIN;
    ++us->stats.n_rx_eagain;
    goto out;
  }
  else if (UDP_IS_SHUT_RD(us)) {
    /* Blocking and shutdowned */
    rc = 0;
    goto out;
  }

  /* We need to block (optionally spinning first). */

  /* -1 is special value that means uninitialised */
  if( spin_state.do_spin == -1 ) {
    spin_state.do_spin = 
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_RECV);
  
    if( spin_state.do_spin ) {
      spin_state.si = citp_signal_get_specific_inited();
      spin_state.max_spin = ni->state->spin_cycles;

      if( us->s.so.rcvtimeo_msec ) {
        ci_uint64 max_so_spin = (ci_uint64)us->s.so.rcvtimeo_msec *
            IPTIMER_STATE(ni)->khz;
        if( max_so_spin <= spin_state.max_spin ) {
          spin_state.max_spin = max_so_spin;
          spin_state.spin_limit_by_so = 1;
        }
      }
    }
  }

  if( spin_state.do_spin ) {
    rc = ci_udp_recvmsg_socklocked_spin(a, ni, us, &spin_state);
    /* 0 => ul maybe readable 
     * 1 => spin complete 
     * -ve => error 
     */
    if( rc == 0 ) {
      if( ci_udp_recv_q_not_empty(us) )
        goto not_empty;
      goto spin_loop;
    }
    else if( rc < 0 )
      goto out;
  }

  ci_sock_unlock(ni, &us->s.b);
  rc = ci_udp_recvmsg_block(a, ni, us, spin_state.timeout);
  ci_sock_lock(ni, &us->s.b);
  if( rc == 0 ) {
    if( ci_udp_recv_q_not_empty(us) )
      goto not_empty;
    else
      goto empty;
  }
  else
    goto out;
}
#endif

/*! \cidoxg_end */


int ci_udp_recvmsg_kernel(int fd, ci_netif* ni, ci_udp_state* us,
                          struct msghdr* msg, int flags)
{
  int rc = 0;
  int rc1;

  if( us->s.os_sock_status & OO_OS_STATUS_RX ) {
    rc1 = __ci_udp_recvmsg_try_os(ni, us, msg, flags, &rc);
    if( rc1 != 1 ) {
      if( rc1 == 0 )
        rc = -EAGAIN;
      else
        rc = rc1;
    }

    if( rc < 0 )
      CI_SET_ERROR(rc, -rc);
  }

  return rc;
}
