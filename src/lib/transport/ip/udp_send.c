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
** \author  djr/stg
**  \brief  UDP sendmsg() etc.
**   \date  2003/12/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "udp_internal.h"
#include "ip_tx.h"
#include <ci/tools/pktdump.h>
#include <onload/osfile.h>
#include <onload/pkt_filler.h>
#include <onload/sleep.h>


#define VERB(x)

#define LPF "ci_udp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


/* This just avoids some ugly #ifdef.  This val is not used at userlevel. */
#ifndef __KERNEL__
# define ERESTARTSYS 0
#endif


#define TXQ_LEVEL(us)                                           \
  ((us)->tx_count + oo_atomic_read(&(us)->tx_async_q_level))

/* If not locked then trylock, and if successful set locked flag and (in
 * some cases) increment the counter.  Return true if lock held, else
 * false.  si_ variants take a [struct udp_send_info*].
 */
#define trylock(ni, locked)                                     \
  ((locked) || (ci_netif_trylock(ni) && ((locked) = 1)))
#define si_trylock(ni, sinf)                    \
  trylock((ni), (sinf)->stack_locked)
#define trylock_and_inc(ni, locked, cntr)                               \
  ((locked) || (ci_netif_trylock(ni) && (++(cntr), (locked) = 1)))
#define si_trylock_and_inc(ni, sinf, cntr)              \
  trylock_and_inc((ni), (sinf)->stack_locked, (cntr))

# define msg_namelen_ok(namelen)  ((namelen) >= sizeof(struct sockaddr_in))

#define oo_tx_udp_hdr(pkt)  ((ci_udp_hdr*) oo_tx_ip_data(pkt))


struct udp_send_info {
  int                   rc;
  ci_ip_cached_hdrs     ipcache;
  int                   used_ipcache;
  int                   stack_locked;
  ci_uint32             timeout;
};


ci_noinline void ci_udp_sendmsg_chksum(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                       ci_ip4_hdr* first_ip)
{
  /* 1400*50 = 70000, i.e. in normal situation there are <50 fragments */
#define MAX_IP_FRAGMENTS 50
  struct iovec iov[MAX_IP_FRAGMENTS];
  int n = -1;
  ci_udp_hdr* udp = TX_PKT_UDP(pkt);
  ci_ip_pkt_fmt* p = pkt;
  int first_frag = 1;

  /* iterate all IP fragments */
  while( OO_PP_NOT_NULL(p->next) ) {
    int frag_len;
    char *frag_start;
    int max_sg_len;

    /* When too many fragments, let's send it without checksum */
    if( ++n == MAX_IP_FRAGMENTS )
      return;

    if( first_frag ) {
      frag_start = (char *)(udp + 1);
      frag_len = CI_BSWAP_BE16(first_ip->ip_tot_len_be16) -
        CI_IP4_IHL(first_ip) - sizeof(ci_udp_hdr);
      first_frag = 0;
    }
    else {
      ci_ip4_hdr *p_ip;
      p = PKT_CHK(ni, p->next);
      p_ip = oo_tx_ip_hdr(p);
      frag_len = CI_BSWAP_BE16(p_ip->ip_tot_len_be16) - CI_IP4_IHL(p_ip);
      frag_start = (char *)(p_ip + 1);
    }

    iov[n].iov_base = frag_start;
    iov[n].iov_len = frag_len;
    max_sg_len = CI_PTR_ALIGN_FWD(PKT_START(p), CI_CFG_PKT_BUF_SIZE) -
        frag_start;
    if( frag_len > max_sg_len ) {
      iov[n].iov_len = max_sg_len;
      frag_len -= max_sg_len;
    }

    /* do we have scatte-gather for this IP fragment? */
    if( p->frag_next != p->next ) {
      ci_ip_pkt_fmt* sg_pkt = p;
      while( sg_pkt->frag_next != p->next ) {
        ci_assert(frag_len);
        sg_pkt = PKT_CHK(ni, sg_pkt->frag_next);
        ++n;
        ci_assert_le(n, MAX_IP_FRAGMENTS);

        iov[n].iov_base = PKT_START(sg_pkt);
        iov[n].iov_len = frag_len;
        max_sg_len = CI_PTR_ALIGN_FWD(PKT_START(sg_pkt),
                                      CI_CFG_PKT_BUF_SIZE) -
                     PKT_START(sg_pkt);
        if( frag_len > max_sg_len ) {
          iov[n].iov_len = max_sg_len;
          frag_len -= max_sg_len;
        }
        else
          frag_len = 0;
      }
      ci_assert_equal(frag_len, 0);
    }
  }
  
  udp->udp_check_be16 = ci_udp_checksum(first_ip, udp, iov, n+1);
}


static void ci_ip_send_udp_slow(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                ci_ip_cached_hdrs* ipcache)
{
  int os_rc = 0;

  ci_assert_equal(oo_ether_type_get(pkt), CI_ETHERTYPE_IP);
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(pkt)), sizeof(ci_ip4_hdr));

  /* Mark the fact that there was traffic sent on this socket (pmtu
   * related).
   */
  ipcache->pmtus.traffic = 1;

  cicp_user_defer_send(ni, retrrc_nomac, &os_rc, OO_PKT_P(pkt), 
                       ipcache->ifindex);


  /* Update size of transmit queue now, because we do not have any callback
   * when the packet will go out or dropped.
   */
  ci_udp_dec_tx_count(SP_TO_UDP(ni, pkt->pf.udp.tx_sock_id), pkt);
}


static int ci_udp_sendmsg_loop(ci_sock_cmn* s, void* opaque_arg)
{
  struct ci_udp_rx_deliver_state* state = opaque_arg;
  ci_ip_pkt_fmt* frag_head;
  ci_ip_pkt_fmt* buf_pkt;
  int seg_i, buf_len;
  ci_udp_hdr* udp;
  void* buf_start;

  if( ! state->delivered ) {
    /* Setup the fields that are expected in an RX packet.  The UDP
     * datagram consists of a sequence of one or more IP fragments.  Each
     * fragment may be split over multiple buffers.  The whole lot are
     * chained together by the [frag_next] field.
     */
    frag_head = state->pkt;
    udp = (ci_udp_hdr*) (oo_ip_hdr(frag_head) + 1);
    frag_head->pf.udp.rx_stamp  = IPTIMER_STATE(state->ni)->frc;
    frag_head->pay_len = CI_BSWAP_BE16(udp->udp_len_be16) - sizeof(*udp);
    buf_pkt = frag_head;
    seg_i = 0;
    while( 1 ) {
      ++state->ni->state->n_rx_pkts;
      ci_assert(!(buf_pkt->flags & CI_PKT_FLAG_RX));
      buf_pkt->flags |= CI_PKT_FLAG_RX;
      if( buf_pkt == state->pkt )
        /* First IP fragment, move past IP+UDP header */
        buf_start = udp + 1;
      else if( seg_i == 0 )
        /* Subsequent IP fragment, move past IP header */
        buf_start = oo_ip_hdr(buf_pkt) + 1;
      else
        /* Internal (jumbo) fragment, no header to move past */ 
        buf_start = PKT_START(buf_pkt);
      buf_len = buf_pkt->buf_len;
      buf_len -= (char*) buf_start - PKT_START(buf_pkt);
      oo_offbuf_init(&buf_pkt->buf, buf_start, buf_len);
      if( OO_PP_IS_NULL(buf_pkt->frag_next) )
        break;
      buf_pkt = PKT_CHK(state->ni, buf_pkt->frag_next);
      if( ++seg_i == frag_head->n_buffers ) {
        seg_i = 0;
        frag_head = buf_pkt;
      }
    }
  }

  CITP_STATS_NETIF_INC(state->ni, udp_send_mcast_loop);
  ci_udp_rx_deliver(s, opaque_arg);
  citp_waitable_wake_not_in_poll(state->ni, &s->b, CI_SB_FLAG_WAKE_RX);

  return 0;  /* continue delivering to other sockets */
}


static void ci_udp_sendmsg_mcast(ci_netif* ni, ci_udp_state* us,
                                 ci_ip_cached_hdrs* ipcache,
                                 ci_ip_pkt_fmt* pkt)
{
  /* NB. We don't deliver multicast packets directly to local sockets if
   * sending via the control plane (below) as they'll get there via the
   * OS socket.
   *
   * FIXME: Problem is, they'll get there even if IP_MULTICAST_LOOP is
   * disabled.  Fix would be to send via the OS socket instead of the
   * control plane route and find an alternative way to keep neighbour
   * entries alive.
   */
  struct ci_udp_rx_deliver_state state;
  const ci_udp_hdr* udp;

  if( ! (us->udpflags & CI_UDPF_MCAST_LOOP) || NI_OPTS(ni).multicast_loop_off )
    return;
  if(CI_UNLIKELY( ni->state->n_rx_pkts >= NI_OPTS(ni).max_rx_packets )) {
    ci_netif_try_to_reap(ni, 100);
    if( ni->state->n_rx_pkts >= NI_OPTS(ni).max_rx_packets ) {
      CITP_STATS_NETIF_INC(ni, udp_send_mcast_loop_drop);
      return;
    }
  }

  state.ni = ni;
  state.pkt = pkt;
  state.queued = 0;
  state.delivered = 0;

  udp = TX_PKT_UDP(pkt);

  ci_netif_filter_for_each_match(ni,
                                 oo_ip_hdr(pkt)->ip_daddr_be32,
                                 udp->udp_dest_be16,
                                 oo_ip_hdr(pkt)->ip_saddr_be32,
                                 udp->udp_source_be16,
                                 IPPROTO_UDP, ipcache->intf_i,
                                 ipcache->encap.vlan_id,
                                 ci_udp_sendmsg_loop, &state);
  ci_netif_filter_for_each_match(ni,
                                 oo_ip_hdr(pkt)->ip_daddr_be32,
                                 udp->udp_dest_be16,
                                 0, 0, IPPROTO_UDP, ipcache->intf_i,
                                 ipcache->encap.vlan_id,
                                 ci_udp_sendmsg_loop, &state);
}


/* Pass prepared packet to ip_send(), release our ref & and update stats */
ci_inline void prep_send_pkt(ci_netif* ni, ci_udp_state* us,
                             ci_ip_pkt_fmt* pkt, ci_ip_cached_hdrs* ipcache)
{
  ci_ip4_hdr *ip = oo_tx_ip_hdr(pkt);
  ni->state->n_async_pkts -= pkt->n_buffers;

  ip->ip_saddr_be32 = ipcache->ip_saddr_be32;
  ip->ip_daddr_be32 = ipcache->ip.ip_daddr_be32;
  ip->ip_ttl = ipcache->ip.ip_ttl;
  ci_ip_set_mac_and_port(ni, ipcache, pkt);
  us->tx_count += pkt->pf.udp.tx_length;
  pkt->flags |= CI_PKT_FLAG_UDP;
  pkt->pf.udp.tx_sock_id = S_SP(us);
  CI_UDP_STATS_INC_OUT_DGRAMS( ni );

  if( (ip->ip_frag_off_be16 & (CI_IP4_FRAG_MORE | CI_IP4_OFFSET_MASK))
      == CI_IP4_FRAG_MORE )
    /* First fragmented chunk: calculate UDP checksum. */
    ci_udp_sendmsg_chksum(ni, pkt, ip);
}


#ifdef __KERNEL__

static int do_sys_sendmsg(ci_sock_cmn *s, oo_os_file os_sock,
                          const struct msghdr* msg,
                          int flags, int user_buffers, int atomic)
{
  struct socket* sock;
  int i, bytes;

  ci_assert(S_ISSOCK(os_sock->f_dentry->d_inode->i_mode));
  sock = SOCKET_I(os_sock->f_dentry->d_inode);
  ci_assert(! user_buffers || ! atomic);

  ci_log("%s: user_buffers=%d atomic=%d sk_allocation=%x ATOMIC=%x",
         __FUNCTION__, user_buffers, atomic,
         sock->sk->sk_allocation, GFP_ATOMIC);

  if( atomic && sock->sk->sk_allocation != GFP_ATOMIC ) {
    ci_log("%s: cannot proceed", __FUNCTION__);
    return -EINVAL;
  }

  for( i = 0, bytes = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;

  if( user_buffers )
    bytes = sock_sendmsg(sock, (struct msghdr*) msg, bytes);
  else
    bytes = kernel_sendmsg(sock, (struct msghdr*) msg,
                           (struct kvec*) msg->msg_iov, msg->msg_iovlen,
                           bytes);
  /* Clear OS TX flag if necessary  */
  oo_os_sock_status_bit_clear(s, OO_OS_STATUS_TX,
                              os_sock->f_op->poll(os_sock, NULL) & POLLOUT);
  return bytes;
}

static int ci_udp_sendmsg_os(ci_netif* ni, ci_udp_state* us,
                             const struct msghdr* msg, int flags,
                             int user_buffers, int atomic)
{
  int rc;
  oo_os_file os_sock;

  ++us->stats.n_tx_os;

  rc = oo_os_sock_get(ni, S_ID(us), &os_sock);
  if( rc == 0 )
    rc = do_sys_sendmsg(&us->s, os_sock, msg, flags, user_buffers, atomic);
  return rc;
}


#else

ci_inline int ci_udp_sendmsg_os(ci_netif* ni, ci_udp_state* us,
                             const struct msghdr* msg, int flags,
                             int user_buffers, int atomic)
{
  int rc;

  ++us->stats.n_tx_os;

#ifdef __i386__
  /* We do not handle compat cmsg in normal oo_os_sock_sendmsg */
  if( msg->msg_controllen != 0 )
    rc = oo_os_sock_sendmsg_raw(ni, S_SP(us), msg, flags);
  else
#endif
    rc = oo_os_sock_sendmsg(ni, S_SP(us), msg, flags);
  return rc >= 0 ? rc : -1;
}

#endif


#ifndef __KERNEL__
/* Send the data using the OS backing socket and updates the efab binding
 * information appropriately.  Must only be called with the local port
 * set to 0 (default).
 *
 * TODO: wrap it into ioctl: sendmsg+getsockname.
 * */
static int ci_udp_sendmsg_os_get_binding(citp_socket *ep, ci_fd_t fd,
                                         const struct msghdr * msg, int flags)
{
  ci_netif* ni = ep->netif;
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  int ret, rc, err;
  struct sockaddr_in sa;
  socklen_t salen = sizeof(sa);
  ci_fd_t os_sock = (ci_fd_t)ci_get_os_sock_fd ( ep, fd);

  ci_assert( !udp_lport_be16(us));

  if ( !CI_IS_VALID_SOCKET(os_sock) ) {
    LOG_U( log("%s: "NT_FMT" can't get OS socket (%d)", __FUNCTION__, 
		NT_PRI_ARGS(ni,us), os_sock));
    RET_WITH_ERRNO((int)os_sock); /*! \todo FIXME remvoce cast */
  }

  /* Not bound.  Probably not connected & sending for the first time,
   * therefore we let the OS do it & record the ephemeral port on
   * return from the sys_sendmsg. */

  /* We're not actually sending over the ef stack! :-) */
  UDP_CLR_FLAG(us, CI_UDPF_EF_SEND);

  /* ret/err are what we'll tell the caller - any errors after here
    * are just between us & the kernel */
  ++us->stats.n_tx_os;
  ++us->stats.n_tx_os_slow;
  ret = ci_sys_sendmsg(os_sock, msg, flags);
  /* In theory, we should poll() os_sock and find POLLOUT state, removing
   * OO_OS_STATUS_TX flag if necessary.  In practice, it costs us another
   * syscall (or implementation of just-another-ioctl), with very low
   * probability of full sendq.
   *
   * To get full sendq now, there should be following:
   * - non-blocking sendmsg;
   * - small sndbuf, large datagram
   * or
   * - a lot of parallel sendmsg from different threads at start-of-day.
   *
   * If application developer is crazy, we should not solve his problem.
   * And there is no much harm in indicating POLLOUT when sendq is full -
   * user should be always ready to block or get EAGAIN.
   */
  err = CI_GET_ERROR(ret);

  /* see what the kernel did - we'll do just the same */
  rc = ci_sys_getsockname( os_sock, (struct sockaddr*)&sa, &salen);
  /* get out if getsockname fails or returns a non INET family
    * or a sockaddr struct that's too darned small */
  if( CI_UNLIKELY( rc || (!rc &&
			  ( sa.sin_family != AF_INET || 
			    salen < sizeof(struct sockaddr_in))))) {
    LOG_UV(log("%s: "NT_FMT" sys_getsockname prob. (rc:%d err:%d, fam:%d, "
		"len:%d - exp %u)",
		__FUNCTION__, NT_PRI_ARGS(ni,us), rc, errno, sa.sin_family, 
		salen, (unsigned)sizeof(struct sockaddr_in)));
    ci_rel_os_sock_fd( os_sock );
    errno = err;
    return ret;
  }

  ci_netif_lock(ni);
  if( udp_lport_be16(us) == 0 ) {
    us->udpflags |= CI_UDPF_IMPLICIT_BIND;
    ci_udp_set_laddr(ep, sa.sin_addr.s_addr, sa.sin_port);

    /* Add a filter if the local addressing is appropriate. */
    if( sa.sin_port != 0 &&
        (sa.sin_addr.s_addr == INADDR_ANY ||
         cicp_user_addr_is_local_efab(CICP_HANDLE(ni),&sa.sin_addr.s_addr)) ) {
      ci_assert( ! (us->udpflags & CI_UDPF_FILTERED) );
      rc = ci_tcp_ep_set_filters(ni, S_SP(us), us->s.cp.so_bindtodevice,
                                 OO_SP_NULL);
      if( rc ) {
        LOG_U(log("%s: FILTER ADD FAIL %d", __FUNCTION__, -rc));
      }
      else {
        UDP_SET_FLAG(us, CI_UDPF_FILTERED);
      }
    }
  }
  ci_netif_unlock(ni);

  LOG_UV(ci_log("%s: "NT_FMT"Unbound: first send via OS got L:[%s:%u]",
		__FUNCTION__, NT_PRI_ARGS(ni,us), 
		ip_addr_str( udp_laddr_be32(us)), udp_lport_be16(us)));
  ci_rel_os_sock_fd( os_sock );
  errno = err;
  return ret;
}
#endif


static void ci_udp_sendmsg_send_pkt_via_os(ci_netif* ni, ci_udp_state* us,
                                           ci_ip_pkt_fmt* pkt, int flags,
                                           struct udp_send_info* sinf)
{
  int rc, seg_i, buf_len, iov_i;
  ci_ip_pkt_fmt* frag_head;
  ci_ip_pkt_fmt* buf_pkt;
  struct iovec iov[30];
  ci_udp_hdr* udp;
  void* buf_start;

#ifndef __KERNEL__
  struct sockaddr_in sin;
  struct msghdr m;

  if( oo_tx_ip_hdr(pkt)->ip_daddr_be32 != 0 ) {
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = oo_tx_ip_hdr(pkt)->ip_daddr_be32;
    sin.sin_port = TX_PKT_UDP(pkt)->udp_dest_be16;
    m.msg_name = &sin;
    m.msg_namelen = sizeof(struct sockaddr_in);
  }
  else {
    m.msg_name = NULL;
    m.msg_namelen = 0;
  }
  m.msg_iov = iov;
  m.msg_iovlen = 0;
  m.msg_controllen = 0;
#endif /* __KERNEL__ */

  frag_head = pkt;
  udp = (ci_udp_hdr*) (oo_tx_ip_hdr(frag_head) + 1);
  buf_pkt = frag_head;
  seg_i = 0;
  iov_i = 0;
  while( 1 ) {
    if( buf_pkt == pkt )
      /* First IP fragment, move past IP+UDP header */
      buf_start = udp + 1;
    else if( seg_i == 0 )
      /* Subsequent IP fragment, move past IP header */
      buf_start = oo_tx_ip_hdr(buf_pkt) + 1;
    else
      /* Internal (jumbo) fragment, no header to move past */ 
      buf_start = PKT_START(buf_pkt);
    buf_len = buf_pkt->buf_len;
    buf_len -= (char*) buf_start - PKT_START(buf_pkt);
    iov[iov_i].iov_base = buf_start;
    iov[iov_i].iov_len = buf_len;
    if( OO_PP_IS_NULL(buf_pkt->frag_next) )
      break;
    if( ++iov_i == sizeof(iov) / sizeof(iov[0]) ) {
      /* We're out of iovec space; MTU must be very small.  You have to be
       * pretty unlucky to hit this path, so bomb.
       */
      return;
    }
    buf_pkt = PKT_CHK(ni, buf_pkt->frag_next);
    if( ++seg_i == frag_head->n_buffers ) {
      seg_i = 0;
      frag_head = buf_pkt;
    }
  }

#ifdef __KERNEL__
  if( sinf == NULL ) {
    /* We're not in the context of the thread that invoked sendmsg(), so we
     * mustn't block this thread.
     */
    ci_assert(flags == 0 || flags == MSG_CONFIRM);
    flags |= MSG_DONTWAIT;
  }
#endif

  /* ?? TODO: Need to do some testing before we allow this to be called in
   * the kernel.  Not at all obvious at this stage that it is legal and
   * won't panic.
   */
#ifndef __KERNEL__
  m.msg_iovlen = iov_i + 1;
  rc = ci_udp_sendmsg_os(ni, us, &m, flags, 0, sinf == NULL);
  if( rc < 0 ) {
    /* ?? TODO: count 'em */
    ci_log("%s: failed rc=%d", __FUNCTION__, rc);
  }
#else
  (void) rc;
  (void) ci_udp_sendmsg_os;
#endif
}


static void fixup_n_async_pkts(ci_netif *ni, ci_ip_pkt_fmt* pkt)
{
  ci_assert(ci_netif_is_locked(ni));
  while( 1 ) {
    ci_assert_gt(pkt->n_buffers, 0);
    ni->state->n_async_pkts -= pkt->n_buffers;
    if( OO_PP_IS_NULL(pkt->next) )
      break;
    pkt = PKT_CHK(ni, pkt->next);
  }
}


static void ci_udp_sendmsg_send(ci_netif* ni, ci_udp_state* us,
                                ci_ip_pkt_fmt* pkt, int flags,
				struct udp_send_info* sinf)
{
  ci_ip_pkt_fmt* first_pkt = pkt;
  ci_ip_cached_hdrs* ipcache;
  int ipcache_onloadable;

  ci_assert(ci_netif_is_locked(ni));

  if( oo_tx_ip_hdr(pkt)->ip_daddr_be32 != 0 ) {
    /**********************************************************************
     * Unconnected send -- dest IP and port provided.  First packet
     * contains correct remote IP and port.
     */
    ++us->stats.n_tx_onload_uc;
    ipcache = &us->ephemeral_pkt;
    if( oo_tx_ip_hdr(pkt)->ip_daddr_be32 == ipcache->ip.ip_daddr_be32 &&
        oo_tx_udp_hdr(pkt)->udp_dest_be16 == ipcache->dport_be16 ) {
      if( cicp_ip_cache_is_valid(CICP_HANDLE(ni), ipcache) )
        goto done_hdr_update;
    }
    else {
      ipcache->ip.ip_daddr_be32 = oo_tx_ip_hdr(pkt)->ip_daddr_be32;
      ipcache->dport_be16 = oo_tx_udp_hdr(pkt)->udp_dest_be16;
      if( sinf != NULL && sinf->used_ipcache &&
          cicp_ip_cache_is_valid(CICP_HANDLE(ni), &sinf->ipcache) ) {
        /* Caller did control plane lookup earlier, and it is still
         * valid.
         */
        cicp_ip_cache_update_from(ni, ipcache, &sinf->ipcache);
        goto done_hdr_update;
      }
    }

    ++us->stats.n_tx_cp_uc_lookup;
    cicp_user_retrieve(ni, ipcache, &us->s.cp);
  }
  else {
    /**********************************************************************
     * Connected send.
     */
    ++us->stats.n_tx_onload_c;
    if(CI_UNLIKELY( ! udp_raddr_be32(us) ))
      goto no_longer_connected;
    ipcache = &us->s.pkt;
    if(CI_UNLIKELY( ! cicp_ip_cache_is_valid(CICP_HANDLE(ni), ipcache) )) {
      ++us->stats.n_tx_cp_c_lookup;
      cicp_user_retrieve(ni, ipcache, &us->s.cp);
    }

    /* Set IP and port now we know we're not going to send_pkt_via_os. */
    oo_tx_ip_hdr(pkt)->ip_daddr_be32 = udp_raddr_be32(us);
    TX_PKT_UDP(pkt)->udp_dest_be16 = udp_rport_be16(us);

  }

 done_hdr_update:
  switch( ipcache->status ) {
  case retrrc_success:
    ipcache_onloadable = 1;
    break;
  case retrrc_nomac:
    ipcache_onloadable = 0;
    break;
  default:
    goto send_pkt_via_os;
  }

  if(CI_UNLIKELY( CI_BSWAP_BE16(oo_tx_ip_hdr(pkt)->ip_tot_len_be16) >
                  ipcache->mtu ))
    /* Oh dear -- we've fragmented the packet with too large an MTU.
     * Either the MTU has recently changed, or we are unconnected and
     * sampled the MTU from the cached value at a bad time.
     *
     * ?? TODO: We either need to fragment again, or send via the OS
     * socket.
     *
     * For now just carry on regardless...
     */
    ci_log("%s: pkt mtu=%d exceeds path mtu=%d", __FUNCTION__,
           CI_BSWAP_BE16(oo_tx_ip_hdr(pkt)->ip_tot_len_be16), ipcache->mtu);

  ci_assert_equal(ni->state->send_may_poll, 0);
  ni->state->send_may_poll = ci_netif_may_poll(ni);

  if( ipcache->ip.ip_ttl ) {
    if(CI_LIKELY( ipcache_onloadable )) {
      /* TODO: Hit the doorbell just once. */
      while( 1 ) {
        prep_send_pkt(ni, us, pkt, ipcache);
        ci_netif_send(ni, pkt);
        if( OO_PP_IS_NULL(pkt->next) )
          break;
        pkt = PKT_CHK(ni, pkt->next);
      }
      cicp_ip_cache_mac_update(ni, ipcache, flags & MSG_CONFIRM);

      if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) )
        ci_udp_sendmsg_mcast(ni, us, ipcache, first_pkt);
    }
     else {
      /* Packet should go via an onload interface, but ipcache is not valid.
       * Could be that we don't have a mac, or could be that we need to drop
       * into the kernel to keep the mac entry alive.
       *
       * ?? FIXME: Currently this will end up sending the packet via the
       * kernel stack.  This is very bad because it can result in
       * out-of-orderness (which, although technically allowed for unreliable
       * datagram sockets, is undesirable as it provokes some apps to perform
       * poorly or even misbehave).  If mac exists, we need to ensure we send
       * via onload.  (And make sure we get the multicast case right).
       */
      ++us->stats.n_tx_cp_no_mac;
      while( 1 ) {
        prep_send_pkt(ni, us, pkt, ipcache);
        ci_ip_send_udp_slow(ni, pkt, ipcache);
        if( OO_PP_IS_NULL(pkt->next) )
          break;
        pkt = PKT_CHK(ni, pkt->next);
      }
    }
  }
  else if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) )
    ci_udp_sendmsg_mcast(ni, us, ipcache, first_pkt);
  else
    LOG_U(ci_log("%s: do not send UDP packet because IP TTL = 0",
                 __FUNCTION__));

  ni->state->send_may_poll = 0;
  return;

 send_pkt_via_os:
  ++us->stats.n_tx_os_late;
  fixup_n_async_pkts(ni, pkt);
  ci_udp_sendmsg_send_pkt_via_os(ni, us, pkt, flags, sinf);
  return;

 no_longer_connected:
  /* We were connected when we entered ci_udp_sendmsg(), but we're not now.
   * If not draining tx_async_q, return error to caller.  Otherwise just
   * drop this datagram.
   */
  if( sinf != NULL )
    sinf->rc = -EDESTADDRREQ;
  else
    /* We're draining [tx_async_q], so too late to return an error to the
     * thread that invoked sendmsg().  Silent drop is only option available
     * to us.  This is not so bad -- can only happen if one thread is doing
     * sendmsg() and another is doing connect() concurrently (which is an
     * odd thing to do).
     */
    ++us->stats.n_tx_unconnect_late;
  fixup_n_async_pkts(ni, pkt);
  return;
}


static int ci_udp_tx_datagram_level(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                    ci_boolean_t ni_locked)
{
  /* Sum the contributions from each IP fragment. */
  int level = 0;
  for( ; ; pkt = PKT_CHK_NML(ni, pkt->next, ni_locked) ) {
    level += pkt->pf.udp.tx_length;
    if( OO_PP_IS_NULL(pkt->next) )
      return level;
  }
}


void ci_udp_sendmsg_send_async_q(ci_netif* ni, ci_udp_state* us)
{
  oo_pkt_p pp, send_list;
  ci_ip_pkt_fmt* pkt;
  int flags, level = 0;

  /* Grab the contents of [tx_async_q]. */
  do {
    OO_PP_INIT(ni, pp, us->tx_async_q);
    if( OO_PP_IS_NULL(pp) )  return;
  } while( ci_cas32_fail(&us->tx_async_q, OO_PP_ID(pp), OO_PP_ID_NULL) );

  /* Reverse the list. */
  send_list = OO_PP_NULL;
  do {
    pkt = PKT_CHK(ni, pp);
    level += ci_udp_tx_datagram_level(ni, pkt, CI_TRUE);
    pp = pkt->netif.tx.dmaq_next;
    pkt->netif.tx.dmaq_next = send_list;
    send_list = OO_PKT_P(pkt);
  }
  while( OO_PP_NOT_NULL(pp) );

  oo_atomic_add(&us->tx_async_q_level, -level);

  /* Send each datagram. */
  while( 1 ) {
    pp = pkt->netif.tx.dmaq_next;
    if( pkt->flags & CI_PKT_FLAG_MSG_CONFIRM )
      flags = MSG_CONFIRM;
    else
      flags = 0;
    ++us->stats.n_tx_lock_defer;
    ci_udp_sendmsg_send(ni, us, pkt, flags, NULL);
    ci_netif_pkt_release(ni, pkt);
    if( OO_PP_IS_NULL(pp) )  break;
    pkt = PKT_CHK(ni, pp);
  }
}

static void ci_udp_sendmsg_async_q_enqueue(ci_netif* ni, ci_udp_state* us,
                                           ci_ip_pkt_fmt* pkt, int flags)
{
  if( flags & MSG_CONFIRM )
    /* Only setting this for first IP fragment -- that should be fine. */
    pkt->flags |= CI_PKT_FLAG_MSG_CONFIRM;

  oo_atomic_add(&us->tx_async_q_level, 
                ci_udp_tx_datagram_level(ni, pkt, CI_FALSE));
  do
    OO_PP_INIT(ni, pkt->netif.tx.dmaq_next, us->tx_async_q);
  while( ci_cas32_fail(&us->tx_async_q,
                       OO_PP_ID(pkt->netif.tx.dmaq_next), OO_PKT_ID(pkt)) );

  if( ci_netif_lock_or_defer_work(ni, &us->s.b) )
    ci_netif_unlock(ni);
}


/* Check if provided address struct/content is OK for us. */
static int ci_udp_name_is_ok(ci_udp_state* us, const struct msghdr* msg)
{
  ci_assert(us);
  ci_assert(msg != NULL);
  ci_assert(msg->msg_namelen > 0);

  /* name ptr must be valid if len != 0 */
  if( msg->msg_name == NULL )
    return 0;

#if CI_CFG_FAKE_IPV6
  if( us->s.domain == AF_INET6 ) {
    return msg->msg_namelen >= SIN6_LEN_RFC2133 && 
      CI_SIN6(msg->msg_name)->sin6_family == AF_INET6 &&
      ci_tcp_ipv6_is_ipv4((struct sockaddr*) msg->msg_name);
  }
#endif


  return msg->msg_namelen >= sizeof(struct sockaddr_in) && 
    CI_SIN(msg->msg_name)->sin_family == AF_INET;
}


#define OO_TIMEVAL_UNINITIALISED  ((struct oo_timeval*) 1)


static int ci_udp_sendmsg_may_send(ci_udp_state* us, int bytes_to_send)
{
  int sndbuf = us->s.so.sndbuf;

  if( bytes_to_send > sndbuf / 2 )
    /* Datagrams are large: Send at least two before blocking.  Otherwise
     * we risk allowing the link to go idle because we'll not get any
     * pipelining.
     */
    if( TXQ_LEVEL(us) < sndbuf )
      return 1;

  if( ci_udp_tx_advertise_space(us) )
    /* App may have been told by select/poll that there is space in the
     * sendq, and so may have called us expecting to not block (or get
     * EAGAIN).  So don't disappoint them...
     */
    return 1;

  return sndbuf >= (int) (TXQ_LEVEL(us) + bytes_to_send);
}


static int ci_udp_sendmsg_wait(ci_netif* ni, ci_udp_state* us,
                               unsigned bytes_to_send, int flags,
                               struct udp_send_info* sinf)
{
  ci_uint64 start_frc = 0, now_frc = 0;
  ci_uint64 schedule_frc = 0;
#ifndef __KERNEL__
  citp_signal_info* si = citp_signal_get_specific_inited();
#endif
  ci_uint64 max_spin = 0;
  int spin_limit_by_so = 0;
  ci_uint64 sleep_seq;
  int rc, first_time = 1;
  unsigned udp_send_spin;

  if( ci_udp_sendmsg_may_send(us, bytes_to_send) )
    return 0;

#ifndef __KERNEL__
  udp_send_spin = oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_SEND);
#else
  udp_send_spin = 0;
#endif

  /* Processing events may free space. */
  if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) )
    if( si_trylock_and_inc(ni, sinf, us->stats.n_tx_lock_poll) )
      ci_netif_poll(ni);

 no_error:
  while( 1 ) {
    sleep_seq = us->s.b.sleep_seq.all;
    ci_rmb();
    if(CI_UNLIKELY( (rc = ci_get_so_error(&us->s)) != 0 || us->s.tx_errno ))
      goto so_error;
    if( ci_udp_sendmsg_may_send(us, bytes_to_send) ) {
      us->stats.n_tx_poll_avoids_full += first_time;
      if( udp_send_spin )
        ni->state->is_spinner = 0;
      return 0;
    }
    if( (flags & MSG_DONTWAIT) ||
        (us->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK|CI_SB_AFLAG_O_NDELAY)) ) {
      ++us->stats.n_tx_eagain;
      RET_WITH_ERRNO(EAGAIN);
    }
    if( first_time ) {
      first_time = 0;
      if( udp_send_spin ) {
        max_spin = ni->state->spin_cycles;
        if( us->s.so.sndtimeo_msec ) {
          ci_uint64 max_so_spin = sinf->timeout * IPTIMER_STATE(ni)->khz;
          if( max_so_spin <= max_spin ) {
            max_spin = max_so_spin;
            spin_limit_by_so = 1;
          }
        }
        ++us->stats.n_tx_spin;
        ci_frc64(&start_frc);
        now_frc = start_frc;
        schedule_frc = start_frc;
      }
    }
    if( udp_send_spin ) {
      if( now_frc - start_frc < max_spin ) {
        if( ci_netif_may_poll(ni) ) {
          if( ci_netif_need_poll_spinning(ni, now_frc) ) {
            if( si_trylock(ni, sinf) )
              ci_netif_poll_n(ni, NI_OPTS(ni).evs_per_poll);
          }
          else if( ! ni->state->is_spinner )
            ni->state->is_spinner = 1;
        }
        if( sinf->stack_locked ) {
          ci_netif_unlock(ni);
          sinf->stack_locked = 0;
        }
        rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc,
                                             us->s.so.sndtimeo_msec,
                                             NULL, si);
        if( rc != 0 ) {
          ni->state->is_spinner = 0;
          return rc;
        }
      }
      else if( spin_limit_by_so ) {
        ++us->stats.n_tx_eagain;
        RET_WITH_ERRNO(EAGAIN);
      }
    }
    else {
      if( sinf->timeout && udp_send_spin ) {
        ci_uint32 spin_ms = NI_OPTS(ni).spin_usec >> 10;
        if( spin_ms < sinf->timeout )
          sinf->timeout -= spin_ms;
        else {
          ++us->stats.n_tx_eagain;
          RET_WITH_ERRNO(EAGAIN);
        }
      }
      ++us->stats.n_tx_block;
      rc = ci_sock_sleep(ni, &us->s.b, CI_SB_FLAG_WAKE_TX,
                         sinf->stack_locked ? CI_SLEEP_NETIF_LOCKED : 0,
                         sleep_seq, &sinf->timeout);
      sinf->stack_locked = 0;
      if( rc < 0 )
        return rc;
    }
  }

 so_error:
  if( udp_send_spin )
    ni->state->is_spinner = 0;
  if( rc == 0 )
    rc = -us->s.tx_errno;
  if( rc == 0 )
    goto no_error;
  return rc;
}
  

ci_inline ci_udp_hdr* udp_init(ci_udp_state* us, ci_ip_pkt_fmt* pkt,
                               unsigned payload_bytes)
{
  ci_udp_hdr* udp = TX_PKT_UDP(pkt);
  udp->udp_len_be16 = (ci_uint16) (payload_bytes + sizeof(ci_udp_hdr));
  udp->udp_len_be16 = CI_BSWAP_BE16(udp->udp_len_be16);
  udp->udp_check_be16 = 0;
  udp->udp_source_be16 = udp_lport_be16(us);
  return udp;
}


/* put in the def. eth hdr, IP hdr then update the address
 * and IP ID fields. */
ci_inline ci_ip4_hdr* eth_ip_init(ci_netif* ni, ci_udp_state* us, 
				  ci_ip_pkt_fmt* pkt)
{
  ci_ip4_hdr* ip;

  ip = oo_tx_ip_hdr(pkt);

  ip->ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(*ip));
  ip->ip_tos = UDP_IP_HDR(us)->ip_tos;
  /* ip_tot_len_be16 */
  /* ip_id_be16 */
  ip->ip_frag_off_be16 = CI_IP4_FRAG_DONT;
  ip->ip_protocol = IPPROTO_UDP;
  ip->ip_check_be16 = 0;
  return ip;
}


/* Allocate packet buffers and fill them with the payload.
 *
 * Returns [bytes_to_send] on success.  Always succeeds (or segfaults) when
 * called at userlevel.  In kernel can return -EFAULT or -ERESTARTSYS.
 */
static
int ci_udp_sendmsg_fill(ci_netif* ni, ci_udp_state* us,
                        int pmtu, ci_iovec_ptr* piov, int bytes_to_send,
                        struct oo_pkt_filler* pf,
                        struct udp_send_info* sinf)
{
  ci_ip_pkt_fmt* first_pkt;
  ci_ip_pkt_fmt* new_pkt;
  int rc, frag_bytes, payload_bytes;
  int bytes_left, frag_off;
  ci_uint16 ip_id;
  ci_ip4_hdr* ip;

  ci_assert(pmtu > 0);

  frag_off = 0;
  bytes_left = bytes_to_send;

  /* Grab lock early, if options allow.  This reduces overhead and latency
   * because we avoid the cost of atomic ops to allocate packet buffers.
   */
  if( bytes_to_send < NI_OPTS(ni).udp_send_unlock_thresh &&
      ! sinf->stack_locked )
    sinf->stack_locked = ci_netif_trylock(ni);

  first_pkt = ci_netif_pkt_alloc_block(ni, &sinf->stack_locked);
  if(CI_UNLIKELY( ci_netif_pkt_alloc_block_was_interrupted(first_pkt) ))
    return -ERESTARTSYS;
  oo_pkt_layout_set(first_pkt, CI_PKT_LAYOUT_TX_SIMPLE);

  ip_id = NEXT_IP_ID(ni);
  ip_id = CI_BSWAP_BE16(ip_id);

  udp_init(us, first_pkt, bytes_to_send);

  oo_pkt_filler_init(pf, first_pkt,
                     oo_tx_ip_data(first_pkt) + sizeof(ci_udp_hdr));
  first_pkt->tx_pkt_len = 
    (oo_tx_ip_data(first_pkt) + sizeof(ci_udp_hdr)) - PKT_START(first_pkt);

  payload_bytes = pmtu - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr);
  if( payload_bytes >= bytes_left ) {
    payload_bytes = bytes_left;
    bytes_left = 0;
  }
  else {
    payload_bytes = UDP_PAYLOAD1_SPACE_PMTU(pmtu);
    bytes_left -= payload_bytes;
  }
  frag_bytes = payload_bytes + sizeof(ci_udp_hdr);

  while( 1 ) {
    pf->pkt->pf.udp.tx_length = payload_bytes + sizeof(ci_udp_hdr) +
        sizeof(ci_ip4_hdr) + sizeof(ci_ether_hdr);
    ip = eth_ip_init(ni, us, pf->pkt);
    ip->ip_tot_len_be16 = frag_bytes + sizeof(ci_ip4_hdr);
    ip->ip_tot_len_be16 = CI_BSWAP_BE16(ip->ip_tot_len_be16);
    ip->ip_frag_off_be16 = frag_off >> 3u;
    ip->ip_frag_off_be16 = CI_BSWAP_BE16(ip->ip_frag_off_be16);
    if( bytes_left > 0 )
      ip->ip_frag_off_be16 |= CI_IP4_FRAG_MORE;
    frag_off += frag_bytes;
    ip->ip_id_be16 = ip_id;

    rc = oo_pkt_fill(ni, &sinf->stack_locked, pf, piov,
                     payload_bytes CI_KERNEL_ARG(CI_ADDR_SPC_CURRENT));
    if(CI_UNLIKELY( oo_pkt_fill_failed(rc) ))
      goto fill_failed;

    if( bytes_left == 0 )
      break;

    /* This counts the number of fragments not including the first. */
    ++us->stats.n_tx_fragments;

    new_pkt = ci_netif_pkt_alloc_block(ni, &sinf->stack_locked);
    if(CI_UNLIKELY( ci_netif_pkt_alloc_block_was_interrupted(new_pkt) )) {
      rc = -ERESTARTSYS;
      goto fill_failed;
    }
    oo_pkt_layout_set(new_pkt, CI_PKT_LAYOUT_TX_SIMPLE);

    pf->pkt->next = OO_PKT_P(new_pkt);
    pf->last_pkt->frag_next = OO_PKT_P(new_pkt);
    oo_pkt_filler_init(pf, new_pkt, oo_tx_ip_data(new_pkt));
    new_pkt->tx_pkt_len = oo_tx_ip_data(new_pkt) - PKT_START(new_pkt);

    payload_bytes = UDP_PAYLOAD2_SPACE_PMTU(pmtu);
    payload_bytes = CI_MIN(payload_bytes, bytes_left);
    bytes_left -= payload_bytes;
    frag_bytes = payload_bytes;
  }

  pf->pkt->next = OO_PP_NULL;
  pf->last_pkt = pf->pkt;
  pf->pkt = first_pkt;

  return bytes_to_send;

 fill_failed:
#ifdef __KERNEL__
  /* ?? FIXME: We'll leak a packet buffer here if we can't get the stack
   * lock.  We need a generic function for freeing a packet whether or not
   * we have the lock.
   */
  if( ! sinf->stack_locked && ci_netif_lock(ni) == 0 )
    sinf->stack_locked = 1;
  if( sinf->stack_locked )
    ci_netif_pkt_release(ni, first_pkt);

  switch( rc ) {
  case -EFAULT:
  case -ERESTARTSYS:
    /* Waiting for packet was interrupted by a signal.  To match kernel
     * semantics we should really do an uninterruptible wait for packet
     * buffers.  However, if the packet pool becomes permanently depleted
     * (which at time of writing is possible) then we wouldn't be able to
     * kill the app, which would be very unfriendly.
     *
     * Instead we return -ERESTARTSYS so that the signal is handled and we
     * try again.
     */
    return rc;
  default:
    /* Not possible. */
    CI_TEST(0);
  }
#endif
  return 0;
}


static
void ci_udp_sendmsg_onload(ci_netif* ni, ci_udp_state* us,
                           const struct msghdr* msg, int flags,
                           struct udp_send_info* sinf)
{
  int rc, i, bytes_to_send;
  struct oo_pkt_filler pf;
  ci_iovec_ptr piov;
  int was_locked;

  /* Caller should guarantee the following: */
  ci_assert(ni);
  ci_assert(us);
  ci_assert(msg != NULL);

  /* Find total amount of payload, and validate pointers. */
  bytes_to_send = 0;
  if( msg->msg_iovlen > 0 ) {
    i = msg->msg_iovlen - 1;
    do {
      if( CI_IOVEC_BASE(&msg->msg_iov[i]) != NULL )
        bytes_to_send += CI_IOVEC_LEN(&msg->msg_iov[i]);
      else if( CI_IOVEC_LEN(&msg->msg_iov[i]) > 0 )
        goto efault;
    } while( --i >= 0 );
    ci_iovec_ptr_init_nz(&piov, msg->msg_iov, msg->msg_iovlen);
  }
  else {
    ci_iovec_ptr_init(&piov, NULL, 0);
  }

  /* For now we don't allocate packets in advance, so init to NULL */
  pf.alloc_pkt = NULL;

  if( ! UDP_HAS_SENDQ_SPACE(us, bytes_to_send)         |
      (bytes_to_send > (int) CI_UDP_MAX_PAYLOAD_BYTES) )
    goto no_space_or_too_big;

 back_to_fast_path:
  was_locked = sinf->stack_locked;
  rc = ci_udp_sendmsg_fill(ni, us, sinf->ipcache.mtu, &piov,
                           bytes_to_send, &pf, sinf);
  if( sinf->stack_locked && ! was_locked )
    ++us->stats.n_tx_lock_pkt;
  if(CI_LIKELY( rc >= 0 )) {
    sinf->rc = bytes_to_send;
    oo_tx_ip_hdr(pf.pkt)->ip_daddr_be32 = sinf->ipcache.ip.ip_daddr_be32;
    oo_tx_udp_hdr(pf.pkt)->udp_dest_be16 = sinf->ipcache.dport_be16;
    if( si_trylock_and_inc(ni, sinf, us->stats.n_tx_lock_snd) ) {
      ci_udp_sendmsg_send(ni, us, pf.pkt, flags, sinf);
      ci_netif_pkt_release(ni, pf.pkt);
      ci_netif_unlock(ni);
    }
    else {
      ci_udp_sendmsg_async_q_enqueue(ni, us, pf.pkt, flags);
    }
  }
  else {
    sinf->rc = rc;
    if( sinf->stack_locked )
      ci_netif_unlock(ni);
  }
  return;


  /* *********************** */
 efault:
  sinf->rc = -EFAULT;
  return;

 no_space_or_too_big:
  /* TODO: If we implement IP options we'll have to calculate
   * CI_UDP_MAX_PAYLOAD_BYTES depending on them.
   */
  if( bytes_to_send > CI_UDP_MAX_PAYLOAD_BYTES ) {
    sinf->rc = -EMSGSIZE;
    return;
  }

  /* There may be insufficient room in the sendq. */
  rc = ci_udp_sendmsg_wait(ni, us, bytes_to_send, flags, sinf);
  if(CI_UNLIKELY( rc != 0 )) {
    if( sinf->stack_locked )
      ci_netif_unlock(ni);
    sinf->rc = rc;
    return;
  }

  LOG_UV(ci_log("%s: "NT_FMT"back to fast path", __FUNCTION__,
		NT_PRI_ARGS(ni,us)));
  goto back_to_fast_path;
}


int ci_udp_sendmsg(ci_udp_iomsg_args *a,
                   const struct msghdr* msg, int flags)
{
  ci_netif *ni = a->ni;
  ci_udp_state *us = a->us;
  struct udp_send_info sinf;
  int rc;

  /* Caller should have checked this. */
  ci_assert(msg != NULL);

  /* Init sinf to properly unlock netif on exit */
  sinf.rc = 0;
  sinf.stack_locked = 0;
  sinf.used_ipcache = 0;
  sinf.timeout = us->s.so.sndtimeo_msec;

  if(CI_UNLIKELY( CMSG_FIRSTHDR(msg) != NULL )) {
    struct in_pktinfo* info = NULL;
    if( ci_ip_cmsg_send(msg, &info) != 0 || info != NULL )
      goto send_via_os;
  }

  if(CI_UNLIKELY( flags & MSG_MORE )) {
    LOG_E(ci_log("%s: MSG_MORE not yet supported", __FUNCTION__));
    CI_SET_ERROR(rc, EOPNOTSUPP);
    return rc;
  }

  if(CI_UNLIKELY( flags & MSG_OOB ))
    /* This returns an error, so very unlikely! */
    goto send_via_os;

  if(CI_UNLIKELY( us->s.so_error | us->s.tx_errno ))
    goto so_error;
 no_error:

#if CI_CFG_UDP_SEND_UNLOCK_OPT
  if( ! NI_OPTS(ni).udp_send_unlocked ) {
# ifndef __KERNEL__
    ci_netif_lock(ni);
# else
    if( (rc = ci_netif_lock(ni)) < 0 ) {
      rc = -ERESTARTSYS;
      goto error;
    }
# endif
    sinf.stack_locked = 1;
  }
#endif

  if( msg->msg_namelen == 0 ) {
    /**********************************************************************
     * Connected send.
     */
    if(CI_UNLIKELY( ! udp_raddr_be32(us) )) {
      /* Linux kernel <= 2.4.20 returns ENOTCONN in this case, but we don't
       * care about such old kernels.
       */
      rc = -EDESTADDRREQ;
      goto error;
    }

    sinf.ipcache.ip.ip_daddr_be32 = 0;

    if( us->s.pkt.status == retrrc_success ) {
      /* All good -- was accelerated last time we looked, so we'll work on
       * the assumption we still are.  We'll check again before sending.
       */
      /* ?? TODO: put some code here to avoid conditional branch forward on
       * fast path.
       */
    }
    else {
      /* In the case of a control plane change and stack lock contention we
       * may use old info here.  Worst case is that we'll send via OS when
       * we could have accelerated (and that can only happen if the control
       * plane change affected this connection).
       */
      if(CI_UNLIKELY( ! cicp_ip_cache_is_valid(CICP_HANDLE(ni),&us->s.pkt) )) {
        if( si_trylock_and_inc(ni, &sinf, us->stats.n_tx_lock_cp) ) {
          ++us->stats.n_tx_cp_c_lookup;
          cicp_user_retrieve(ni, &us->s.pkt, &us->s.cp);
        }
      }
      if( us->s.pkt.status != retrrc_success &&
          us->s.pkt.status != retrrc_nomac )
        goto send_via_os;
    }
    sinf.ipcache.mtu = us->s.pkt.mtu;
  }
  else if(CI_UNLIKELY( msg->msg_name == NULL )) {
    rc = -EFAULT;
    goto error;
  }
  else {
    /**********************************************************************
     * Unconnected send -- dest IP and port provided.
     */
    if( msg->msg_name != NULL && msg_namelen_ok(msg->msg_namelen) &&
        (! CI_CFG_FAKE_IPV6 || us->s.domain == AF_INET) &&
        CI_SIN(msg->msg_name)->sin_family == AF_INET ) {
      /* Fast check -- we're okay. */
    }
    else if( ! ci_udp_name_is_ok(us, msg) )
      /* Fast check and more detailed check failed. */
      goto send_via_os;
    if( ! CI_CFG_FAKE_IPV6 || CI_SA(msg->msg_name)->sa_family == AF_INET ) {
      sinf.ipcache.ip.ip_daddr_be32 = CI_SIN(msg->msg_name)->sin_addr.s_addr;
      sinf.ipcache.dport_be16 = CI_SIN(msg->msg_name)->sin_port;
    }
#if CI_CFG_FAKE_IPV6
    else {
      sinf.ipcache.ip.ip_daddr_be32 = ci_get_ip4_addr(AF_INET6,
                                                      CI_SA(msg->msg_name));
      sinf.ipcache.dport_be16 = CI_SIN6(msg->msg_name)->sin6_port;
    }
#endif

    if(CI_UNLIKELY( sinf.ipcache.ip.ip_daddr_be32 == INADDR_ANY ))
      goto send_via_os;

#ifndef __KERNEL__
    if(CI_UNLIKELY( udp_lport_be16(us) == 0 )) {
      /* We haven't yet allocated a local port.  So send this packet using
       * the OS, which will allocate an ephemeral local port, which we'll
       * use for subsequent sends.
       */
      if( sinf.stack_locked )
        ci_netif_unlock(ni);
      return ci_udp_sendmsg_os_get_binding(a->ep, a->fd, msg, flags);
    }
#endif

    if( sinf.ipcache.dport_be16 == us->ephemeral_pkt.dport_be16 &&
        sinf.ipcache.ip.ip_daddr_be32 ==
          us->ephemeral_pkt.ip.ip_daddr_be32 &&
        cicp_ip_cache_is_valid(CICP_HANDLE(ni), &us->ephemeral_pkt) ) {
      /* Looks like [us->ephemeral_pkt] has up-to-date info for this
       * destination, so go with it.  This is racey if another thread is
       * sending on the same socket concurrently (and happens to be
       * modifying [us->ephemeral_pkt]), but we'll check again before
       * finally sending.  Worst case is we use the wrong MTU and send via
       * OS when we could have accelerated.
       *
       * ?? TODO: cache is not valid when status is retrrc_nomac -- do we
       * care?  prob not -- expect that to be relatively uncommon
       */
      if( us->ephemeral_pkt.status != retrrc_success &&
          us->ephemeral_pkt.status != retrrc_nomac )
        goto send_via_os;
      sinf.ipcache.mtu = us->ephemeral_pkt.mtu;
      ++us->stats.n_tx_cp_match;
    }
    else if( si_trylock_and_inc(ni, &sinf, us->stats.n_tx_lock_cp) ) {
      if( sinf.ipcache.dport_be16 != us->ephemeral_pkt.dport_be16 ||
          sinf.ipcache.ip.ip_daddr_be32 !=
            us->ephemeral_pkt.ip.ip_daddr_be32 ) {
        us->ephemeral_pkt.ip.ip_daddr_be32 = sinf.ipcache.ip.ip_daddr_be32;
        us->ephemeral_pkt.dport_be16 = sinf.ipcache.dport_be16;
        ci_ip_cache_invalidate(&us->ephemeral_pkt);
      }
      if(CI_UNLIKELY( ! cicp_ip_cache_is_valid(CICP_HANDLE(ni),
                                               &us->ephemeral_pkt) )) {
        ++us->stats.n_tx_cp_uc_lookup;
        cicp_user_retrieve(ni, &us->ephemeral_pkt, &us->s.cp);
      }
      if( us->ephemeral_pkt.status != retrrc_success &&
          us->ephemeral_pkt.status != retrrc_nomac )
        goto send_via_os;
      sinf.ipcache.mtu = us->ephemeral_pkt.mtu;
    }
    else {
      /* Need control plane lookup and could not grab stack lock; so do
       * lookup with temporary ipcache [sinf.ipcache].
       */
      sinf.used_ipcache = 1;
      ++us->stats.n_tx_cp_a_lookup;
      sinf.ipcache.mac_integrity.row_index = 0;
      cicp_user_retrieve(ni, &sinf.ipcache, &us->s.cp);
      if( sinf.ipcache.status != retrrc_success &&
          sinf.ipcache.status != retrrc_nomac )
        goto send_via_os;
    }
  }

  ci_assert_gt(sinf.ipcache.mtu, 0);
  ci_udp_sendmsg_onload(ni, us, msg, flags, &sinf);
  if( sinf.rc < 0 )
      CI_SET_ERROR(sinf.rc, -sinf.rc);
  return sinf.rc;

 so_error:
  if( (rc = -ci_get_so_error(&us->s)) == 0 && (rc = -us->s.tx_errno) == 0 )
    goto no_error;
  goto error;

 error:
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  CI_SET_ERROR(rc, -rc);
  return rc;

 send_via_os:
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  return ci_udp_sendmsg_os(ni, us, msg, flags, 1, 0);
}

/*! \cidoxg_end */
