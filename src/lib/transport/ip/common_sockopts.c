/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** \author  stg
**  \brief  getsockopt & setsockopt code commont to all protocols
**   \date  2005/07/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_stats.h>
#include <ci/net/sockopts.h>
#ifndef __KERNEL__
# include <limits.h>
# include <net/if.h>
#endif


/* 
 * IP_MTU
 * ------
 *
 * NOTE: This is a linux only sockopt but we have already included the
 *       netinet/in.h header so we cannot blindly include linux/in.h.
 *       Hence we have little choice but to duplicate the definition here.
 */
#define IP_MTU  14

#define VERB(x)

#ifndef NDEBUG
#define STG_VERB(x) x
#else
#define STG_VERB(x)
#endif

#define REPORT_CASE(sym) case sym:

/* Emulate Linux mapping between priority and TOS field */
#include <linux/types.h>
#include <linux/pkt_sched.h>

static unsigned ci_tos2priority[] = {
    /*  0 */ TC_PRIO_BESTEFFORT,
    /*  1 */ TC_PRIO_FILLER,
    /*  2 */ TC_PRIO_BESTEFFORT,
    /*  3 */ TC_PRIO_BESTEFFORT,
    /*  4 */ TC_PRIO_BULK,
    /*  5 */ TC_PRIO_BULK,
    /*  6 */ TC_PRIO_BULK,
    /*  7 */ TC_PRIO_BULK,
    /*  8 */ TC_PRIO_INTERACTIVE,
    /*  9 */ TC_PRIO_INTERACTIVE,
    /* 10 */ TC_PRIO_INTERACTIVE,
    /* 11 */ TC_PRIO_INTERACTIVE,
    /* 12 */ TC_PRIO_INTERACTIVE_BULK,
    /* 13 */ TC_PRIO_INTERACTIVE_BULK,
    /* 14 */ TC_PRIO_INTERACTIVE_BULK,
    /* 15 */ TC_PRIO_INTERACTIVE_BULK
};


#ifndef __KERNEL__
int ci_sock_rx_bind2dev(ci_netif* ni, ci_sock_cmn* s, ci_ifid_t ifindex)
{
  ci_ifid_t base_ifindex;
  ci_hwport_id_t hwport;
  cicp_encap_t encap;
  int rc;

  /* Can we accelerate this interface?  If not, best to handover now. */
  rc = cicp_llap_retrieve(CICP_HANDLE(ni), ifindex, NULL/*mtu*/, &hwport,
                          NULL/*mac*/, &encap, &base_ifindex, NULL);
  if( rc != 0 ) {
    /* non-Ethernet interface */
    return CI_SOCKET_HANDOVER;
  }
  if( (unsigned) hwport >= CI_CFG_MAX_REGISTER_INTERFACES )
    return CI_SOCKET_HANDOVER;
  if( __ci_hwport_to_intf_i(ni, hwport) < 0 )
    /* ?? FIXME: We should really be checking whether *all* slaves in the
     * bond are onloadable (for bonds).
     */
    return CI_SOCKET_HANDOVER;

  s->rx_bind2dev_ifindex = ifindex;
  s->rx_bind2dev_base_ifindex = base_ifindex;
  s->rx_bind2dev_vlan = encap.vlan_id;
  ci_ip_cache_invalidate(&s->pkt);
  if( s->b.state == CI_TCP_STATE_UDP )
    /* ?? TODO: replace w ci_udp_invalidate_ip_caches(); */
    ci_ip_cache_invalidate(&SOCK_TO_UDP(s)->ephemeral_pkt);
  return 0;
}


static int ci_sock_bindtodevice(ci_netif* ni, ci_sock_cmn* s,
                                const void* optval, socklen_t optlen)
{
  ci_ifid_t ifindex;
  struct ifreq ifr;
  int rc;

  if( optlen == 0 || ((char*)optval)[0] == '\0' ) {
    /* Unbind. */
    s->cp.so_bindtodevice = CI_IFID_BAD;
    s->rx_bind2dev_ifindex = CI_IFID_BAD;
    /* These don't really need to be initialised, as only significant when
     * rx_bind2dev_ifindex != CI_IFID_BAD.  But makes stackdump output
     * cleaner this way...
     */
    s->rx_bind2dev_base_ifindex = 0;
    s->rx_bind2dev_vlan = 0;
    return 0;
  }

  if( NI_OPTS(ni).bindtodevice_handover )
    goto handover;

  /* Find the ifindex of the interface. */
  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, optval, CI_MIN(optlen, sizeof(ifr.ifr_name)));
  ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
  ifindex = if_nametoindex(ifr.ifr_name);
  if( ifindex == 0 ) {
    /* Unexpected, because it worked when we applied this sockopt to the
     * kernel socket.  (Although don't forget that some sockets do not have
     * a kernel socket).
     */
    LOG_E(ci_log("%s: ERROR: if_nametoindex(%s) failed",
                 __FUNCTION__, ifr.ifr_name));
    return -ENODEV;
  }

  rc = ci_sock_rx_bind2dev(ni, s, ifindex);
  if( rc == 0 )
    s->cp.so_bindtodevice = ifindex;
  return rc;

 handover:
  /* You might be tempted to think "Handing a connected TCP socket to the
   * kernel is a bad idea, because we'll remove filters, so the kernel
   * stack will see packets for a socket it doesn't know about and reply
   * with RST."
   *
   * True, but that is exactly what will happen if we keep this socket in
   * Onload.  If packets arrive at an Onload interface, Onload will reply
   * with RST.  If packets arrive at a non-Onload interface, kernel will
   * reply with RST.  There is nothing we can do to improve on this.
   */
  return CI_SOCKET_HANDOVER;
}
#else
static int ci_sock_bindtodevice(ci_netif* ni, ci_sock_cmn* s,
                                const void* optval, socklen_t optlen)
{
  /* ?? TODO: -- need kernel version of if_nametoindex() */
  return CI_SOCKET_HANDOVER;
}
#endif


#if defined(__KERNEL__) && defined(__linux__)
int ci_khelper_getsockopt(ci_netif* ni,  oo_sp sock_p, int level, 
			  int optname, char* optval, int* optlen )
{
  tcp_helper_endpoint_t* ep;
  struct file* file;
  struct inode* inode;
  int rc = -EINVAL;

  ci_assert(ni != NULL);

  ep = ci_netif_get_valid_ep(ni, sock_p);
  if( ep->os_socket == NULL )
    return -EINVAL;
  file = ep->os_socket->file;
  inode = file->f_dentry->d_inode;
  if( inode != NULL ) {
    struct socket* sock = SOCKET_I(inode);
    if( sock != NULL ) {
      ci_assert(sock->file == file);
      rc = sock->ops->getsockopt(sock, level, optname, optval, optlen);
      LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));
    }
  }
  return rc;
}


int ci_khelper_setsockopt(ci_netif* ni, oo_sp sock_p, int level, 
			  int optname, const void* optval, int optlen )
{
  tcp_helper_endpoint_t* ep;
  struct file* file;
  struct inode* inode;
  int rc = -EINVAL;

  ci_assert(ni != NULL);

  ep = ci_netif_get_valid_ep(ni, sock_p);
  if( ep->os_socket == NULL )
    return -EINVAL;
  file = ep->os_socket->file;
  inode = file->f_dentry->d_inode;
  if( inode != NULL ) {
    struct socket* sock = SOCKET_I(inode);
    if( sock != NULL ) {
      ci_assert(sock->file == file);
      rc = sock->ops->setsockopt(sock, level, optname, (char*) optval, optlen);
      LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));
    }
  }
  return rc;
}
#endif

#ifndef __KERNEL__
/* Get OS socket option value */
ci_inline int
ci_get_os_sockopt(citp_socket *ep, ci_fd_t fd, int level, int optname, 
                  void *optval, socklen_t *optlen )
{
  int rc;
  ci_fd_t os_sock = ci_get_os_sock_fd(ep, fd);

  if (CI_IS_VALID_SOCKET(os_sock) ) { 
    rc = ci_sys_getsockopt(os_sock, level, optname, optval, optlen);
    ci_rel_os_sock_fd(os_sock);
    if (rc != 0)
      RET_WITH_ERRNO(errno);
    return 0;
  } else {
    /* Caller should care about this case if necessary. */
    RET_WITH_ERRNO(ENOPROTOOPT); 
  }
}
#else
/* Get OS socket option value 
 * [fd] is unused
 */
ci_inline int
ci_get_os_sockopt(citp_socket *ep, ci_fd_t fd, int level, int optname, 
                  void *optval, socklen_t *optlen )
{
  int rc;
  
  rc = ci_khelper_getsockopt( ep->netif,SC_SP(ep->s), level, optname, optval, 
			      optlen );
  return rc;
}
#endif

/*
 * The handlers in this module must conform to the following:
 * 1. Be common to all protocols
 * 2. Not be performance critical
 *
 * Performance-critical and protocol-unique handlers must be handled from
 * the switch block in ci_xxx_getsockopt() & ci_xxx_setsockopt().
 */

/* Handler for common getsockopt:SOL_IP options. */
int ci_get_sol_ip( citp_socket* ep, ci_sock_cmn* s, ci_fd_t fd,
                   int optname, void *optval, socklen_t *optlen )
{
  unsigned u;

  /* NOTE: "break" from this switch block will exit through code
   * that passes the value in [u] back to the caller.  */

  switch(optname) {
  case IP_OPTIONS:
    /* gets the IP options to be sent with every packet from this socket */
    LOG_U(ci_log("%s: "NS_FMT" unhandled IP_OPTIONS", __FUNCTION__,
                 NS_PRI_ARGS(ep->netif, s)));
    goto fail_unsup;

  case IP_TOS:
    /* gets the IP ToS options sent with every packet from this socket */
    ci_assert((s->b.state & CI_TCP_STATE_TCP) ||
	      s->b.state == CI_TCP_STATE_UDP);

    u = s->pkt.ip.ip_tos;
    break;

  case IP_TTL:
    /* gets the IP TTL set in every packet sent on this socket */
    ci_assert((s->b.state & CI_TCP_STATE_TCP) ||
	      s->b.state == CI_TCP_STATE_UDP);

    u = s->cp.ip_ttl;
    break;

  case IP_MTU:
    /* gets the current known path MTU of the current socket */
    /*! \todo Can we improve on the flagging here (other than
     * purging udp_state with extreme prejudice :-) ) */
    if( ((s->b.state & CI_TCP_STATE_TCP) &&
         ((s->b.state < CI_TCP_ESTABLISHED) ||
         (s->b.state >= CI_TCP_TIME_WAIT))) ||
        (s->b.state == CI_TCP_STATE_UDP &&
	 /*??fixme*/
         sock_raddr_be32(s) == 0) )  {
      /* The socket is not connected */
      RET_WITH_ERRNO(ENOTCONN);
    }
    u = s->pkt.pmtus.pmtu;
    break;

  case IP_MTU_DISCOVER:
    /* gets the status of Path MTU discovery on this socket */
    u = s->pkt.pmtus.state;
    break;

  case IP_RECVTOS:
    u = !!(s->cmsg_flags & CI_IP_CMSG_TOS);
    break;

  case IP_PKTOPTIONS:
    {
      struct msghdr msg;
      struct cmsg_state cmsg_state;

      /* On Linux, IP_PKTOPTIONS is stream-only */
      if( s->b.state == CI_TCP_STATE_UDP )
        RET_WITH_ERRNO(ENOPROTOOPT);
      /* ci_put_cmsg checks that optval is long enough */

      /* set all cmsg_len fields to 0 */
      memset(optval, 0, *optlen);

      msg.msg_control = optval;
      msg.msg_controllen = *optlen;
      msg.msg_flags = 0;
      cmsg_state.msg = &msg;
      cmsg_state.cm = CMSG_FIRSTHDR(&msg);
      cmsg_state.cmsg_bytes_used = 0;

      if (s->cmsg_flags & CI_IP_CMSG_PKTINFO) {
        struct in_pktinfo info;
        info.ipi_addr.s_addr = info.ipi_spec_dst.s_addr = sock_laddr_be32(s);

        info.ipi_ifindex = s->cp.ip_multicast_if < 0 ?
            0 : s->cp.ip_multicast_if;
        ci_put_cmsg(&cmsg_state, IPPROTO_IP, IP_PKTINFO, sizeof(info), &info);
        if(msg.msg_flags & MSG_CTRUNC)
          goto fail_inval;
      }

      if (s->cmsg_flags & CI_IP_CMSG_TTL) {
        int ttl = s->cp.ip_mcast_ttl;
        ci_put_cmsg(&cmsg_state, IPPROTO_IP, IP_TTL, sizeof(ttl), &ttl);
        if(msg.msg_flags & MSG_CTRUNC)
          goto fail_inval;
      }

      *optlen = cmsg_state.cmsg_bytes_used;
      return 0;
    }

  case IP_RECVERR:
    u = !!(s->so.so_debug & CI_SOCKOPT_FLAG_IP_RECVERR);
    break;


  case IP_RECVTTL:
    u = !!(s->cmsg_flags & CI_IP_CMSG_TTL);
    break;

  case IP_RECVOPTS:
    u = !!(s->cmsg_flags & CI_IP_CMSG_RECVOPTS);
    break;

  case IP_RETOPTS:
    u = !!(s->cmsg_flags & CI_IP_CMSG_RETOPTS);
    break;

  /* UDP is handled in UDP-specific functions. */
  REPORT_CASE(IP_MULTICAST_IF)
  REPORT_CASE(IP_MULTICAST_LOOP)
  REPORT_CASE(IP_MULTICAST_TTL)
    return ci_get_os_sockopt(ep, fd, IPPROTO_IP, optname, optval, optlen);

  case IP_PKTINFO:
    u = !!(s->cmsg_flags & CI_IP_CMSG_PKTINFO);
    break;


  default:
    goto fail_noopt;
  }

  return ci_getsockopt_final(optval, optlen, SOL_IP, &u, sizeof(u));

 fail_inval:
  LOG_SC( log("%s: "NS_FMT" invalid option: %i (EINVAL)",
             __FUNCTION__, NS_PRI_ARGS(ep->netif, s), optname));
  RET_WITH_ERRNO(EINVAL);

 fail_noopt:
  LOG_SC( log("%s: "NS_FMT" unimplemented/bad option: %i (ENOPROTOOPT)",
             __FUNCTION__, NS_PRI_ARGS(ep->netif, s), optname));

 fail_unsup:
  RET_WITH_ERRNO(ENOPROTOOPT);
}

#if CI_CFG_FAKE_IPV6
# ifndef __KERNEL__ 
/* Handler for common getsockopt:SOL_IPV6 options. */
int ci_get_sol_ip6( citp_socket* ep, ci_sock_cmn* s, ci_fd_t fd,
                    int optname, void *optval, socklen_t *optlen )
{
  int rc;
  ci_fd_t os_sock = ci_get_os_sock_fd (ep, fd);

  if (CI_IS_VALID_SOCKET(os_sock) ) { 
    rc = ci_sys_getsockopt( os_sock, IPPROTO_IPV6, optname, optval, optlen);
    ci_rel_os_sock_fd( os_sock );
    if (rc != 0)
      RET_WITH_ERRNO(errno);
    return 0;
  } else {
    /* Do not really support IPv6 options */
    RET_WITH_ERRNO(ENOPROTOOPT); 
  }
}
# else /* is kernel */
/* Get OS socket option value 
 * [fd] is unused
 */
int ci_get_sol_ip6( citp_socket* ep, ci_sock_cmn* s, ci_fd_t fd,
		    int optname, void *optval, socklen_t *optlen )
{
  int rc;
  
  rc = ci_khelper_getsockopt( ep->netif, SC_SP(ep->s), IPPROTO_IPV6, 
			      optname, optval, optlen );
  return rc;
}
# endif
#endif

/* Handler for common getsockopt:SOL_SOCKET options. */
int ci_get_sol_socket( ci_netif* netif, ci_sock_cmn* s,
                       int optname, void *optval, socklen_t *optlen )
{
  int u;

  switch(optname) {
#if CI_CFG_TCP_SOCK_STATS
  case CI_SO_L5_GET_SOCK_STATS:
    /* Way to get access to our socket statistics data
     * optval is a pointer to memory & optval should be at least
     * 2 * sizeof(ci_ip_sock_stats)
     */
    if(*optlen < (sizeof(ci_ip_sock_stats)<<1) )
      goto fail_inval;
    ci_tcp_stats_action(netif, (ci_tcp_state*) s, CI_IP_STATS_REPORT,
                        CI_IP_STATS_OUTPUT_NONE, optval, optlen );
    break;

  case CI_SO_L5_DUMP_SOCK_STATS:
# if CI_CFG_SEND_STATS_TO_LOG==0
    /* TODO check that optval is long enough? */
    if(*optlen == 0)
      goto fail_inval;
# endif
    if( ! (s->b.state & CI_TCP_STATE_TCP_CONN) )
      goto fail_inval;
    ci_tcp_stats_action(netif, SOCK_TO_TCP(s), CI_IP_STATS_REPORT,
                        CI_IP_STATS_OUTPUT_NONE, optval, optlen );
    break;
#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION
  case CI_SO_L5_GET_NETIF_STATS:
    /* Way to get access to our netif statistics data
     * optval is a pointer to memory & optval should be at least
     * 2 * sizeof(ci_ip_stats)
     */
    if(*optlen < (sizeof(ci_ip_stats)<<1) )
      goto fail_inval;

    ci_netif_stats_action(netif, CI_IP_STATS_REPORT,
                          CI_IP_STATS_OUTPUT_NONE, optval, optlen );
    break;

  case CI_SO_L5_DUMP_NETIF_STATS:
# if CI_CFG_SEND_STATS_TO_LOG==0
    /* TODO check that optval is long enough? */
    if(*optlen == 0)
      goto fail_inval;
# endif
    /* Get the report in text or xml format */
    ci_netif_stats_action(netif, CI_IP_STATS_REPORT,
                          CI_IP_STATS_OUTPUT_NONE, optval, optlen );
    break;
#endif

  case SO_KEEPALIVE:
    u = !!(s->s_flags & CI_SOCK_FLAG_KALIVE);
    goto u_out;

  case SO_OOBINLINE:
    /* if enabled out-of-band data is directly placed in receive stream */

    u = !!(s->s_flags & CI_SOCK_FLAG_OOBINLINE);
    goto u_out;

  case SO_RCVLOWAT:
    u = s->so.rcvlowat;
    goto u_out;

  case SO_SNDLOWAT:
    /* unchangable on always set to 1 byte */
    u = 1u;
    goto u_out;

  case SO_RCVTIMEO: {
    /* BUG2725: Windows isn't BSD compatible at all! */
    struct timeval tv;
    tv.tv_sec = s->so.rcvtimeo_msec / 1000;
    tv.tv_usec = (s->so.rcvtimeo_msec - (tv.tv_sec * 1000ULL)) * 1000ULL;
    return ci_getsockopt_final(optval, optlen, SOL_SOCKET, &tv, sizeof(tv));
  }

  case SO_SNDTIMEO: {
    /* BUG2725: Windows isn't BSD compatible at all! */
    struct timeval tv;
    tv.tv_sec = s->so.sndtimeo_msec / 1000;
    tv.tv_usec = (s->so.sndtimeo_msec - (tv.tv_sec * 1000ULL)) * 1000ULL;
    return ci_getsockopt_final(optval, optlen, SOL_SOCKET, &tv, sizeof(tv));
  }

  case SO_REUSEADDR:
    /* Allow bind to reuse local addresses */
    u = !!(s->s_flags & CI_SOCK_FLAG_REUSEADDR);
    goto u_out;

  case SO_TYPE:
    /* get socket type */
    ci_assert((s->b.state & CI_TCP_STATE_TCP) ||
	      s->b.state == CI_TCP_STATE_UDP);
    u = (s->b.state & CI_TCP_STATE_TCP) ? SOCK_STREAM : SOCK_DGRAM;
    goto u_out;


  case SO_DONTROUTE:
    /* don't send via gateway, only directly connected machine */
    /*! ?? \TODO */
    goto fail_noopt;

  case SO_BROADCAST:
    /* get current broadcast rx state */
    /* Note: while this is unused by TCP it's always accessible */
    u = !!(s->s_flags & CI_SOCK_FLAG_BROADCAST);
    goto u_out;

  case SO_SNDBUF:
    /* gets the maximum socket send buffer in bytes */
    u = s->so.sndbuf;
    goto u_out;

  case SO_RCVBUF:
    /* gets the maximum socket receive buffer in bytes */
    u = s->so.rcvbuf;
    goto u_out;

  case SO_LINGER:
    {
      struct linger l;
      memset(&l, 0, sizeof(l));


      if( s->s_flags & CI_SOCK_FLAG_LINGER ) {
        l.l_onoff = 1;
        l.l_linger = s->so.linger;
      } else {
        l.l_onoff = 0;
      }
      VERB(ci_log("%s: onoff:%d fl:%x", __FUNCTION__,
                  l.l_onoff, s->s_flags));
      return ci_getsockopt_final(optval, optlen, SOL_SOCKET, &l, sizeof(l));
    }

  case SO_PRIORITY:
    u = (unsigned) s->so_priority;
    goto u_out;

  case SO_ERROR:
    /* Gets the pending socket error and reset the pending error */
    u = ci_get_so_error(s);
    goto u_out;

  case SO_ACCEPTCONN:
    u = (s->b.state == CI_TCP_LISTEN);
    goto u_out;

  case SO_DEBUG:
    u = !!(s->so.so_debug & CI_SOCKOPT_FLAG_SO_DEBUG);
    goto u_out;


  default: /* Unexpected & known invalid options end up here */
    goto fail_noopt;
  }

  return 0;

 u_out:
  if( (int)*optlen >= 0 ) {
    int minlen = CI_MIN(sizeof(u), (int)*optlen);
    memcpy(optval, (char*)&u, minlen);
    *optlen = minlen;
    return 0;
  } 
  /* deliberate drop through */ 

 fail_inval:
  LOG_SC(log("%s: "NS_FMT" option %i ptr/len error (EINVAL or EFAULT)",
             __FUNCTION__, NS_PRI_ARGS(netif, s), optname));
  RET_WITH_ERRNO(EINVAL);

 fail_noopt:
  LOG_SC(log("%s: "NS_FMT" unimplemented/bad option %i (ENOPROTOOPT)",
            __FUNCTION__, NS_PRI_ARGS(netif, s), optname));
  RET_WITH_ERRNO(ENOPROTOOPT);
}

/* Handler for common setsockopt:SOL_IP handlers */
int ci_set_sol_ip( ci_netif* netif, ci_sock_cmn* s,
                   int optname, const void *optval, socklen_t optlen)
{
  int rc = 0; /* Shut up compiler warning */

  ci_assert(netif);

  /* IP level options valid for TCP */
  switch(optname) {
  case IP_OPTIONS:
    /* sets the IP options to be sent with every packet from this socket */
    /*! ?? \TODO is this possible ? */
    LOG_U(ci_log("%s: "NS_FMT" unhandled IP_OPTIONS", __FUNCTION__,
                 NS_PRI_ARGS(netif, s)));
    goto fail_unhan;

  case IP_TOS:
  {
    unsigned val;

    /* sets the IP ToS options sent with every packet from this socket   */
    /* Note: currently we do not interpret this value in determining our */
    /*       delivery strategy                                           */
    if( (rc = opt_not_ok( optval, optlen, char)) ) {
      if( optlen == 0 )
        return 0;
      goto fail_fault;
    }
    val = ci_get_optval(optval, optlen);


    if( s->b.state & CI_TCP_STATE_TCP ) {
      /* Bug3172: do not allow to change 2 and 1 bits of TOS for TCP socket. */
      val &= ~3;
      val |= s->pkt.ip.ip_tos & 3;
    }
    val = CI_MIN(val, CI_IP_MAX_TOS);
    s->pkt.ip.ip_tos = (ci_uint8)val;
    if( s->b.state == CI_TCP_STATE_UDP )
      SOCK_TO_UDP(s)->ephemeral_pkt.ip.ip_tos = (ci_uint8)val;

    LOG_TV(log("%s: "NS_FMT" TCP IP_TOS = %u", __FUNCTION__,
               NS_PRI_ARGS(netif, s), s->pkt.ip.ip_tos));

    /* Set SO_PRIORITY */
    s->so_priority = ci_tos2priority[(((val)>>1) & 0xf)];
    break;
  }

  case IP_TTL: {
    int v;
    /* Set the TTL on this socket */
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;
    v = ci_get_optval(optval, optlen);

    if( 
      v == 0 || 
      v > CI_IP_MAX_TTL ) {
      rc = -EINVAL;
      goto fail_fault;
    }

    s->cp.ip_ttl = (ci_uint8) v;
    if( ! CI_IP_IS_MULTICAST(s->pkt.ip.ip_daddr_be32) )
      s->pkt.ip.ip_ttl = s->cp.ip_ttl;
    if( s->b.state == CI_TCP_STATE_UDP) {
      ci_udp_state* us = SOCK_TO_UDP(s);
      if (! CI_IP_IS_MULTICAST(us->ephemeral_pkt.ip.ip_daddr_be32) )
        us->ephemeral_pkt.ip.ip_ttl = s->cp.ip_ttl;
    }
    LOG_TV(log("%s: "NS_FMT" IP_TTL = %u", __FUNCTION__,
               NS_PRI_ARGS(netif, s), s->cp.ip_ttl));
    break;
  }

    /* Bug 5644 */
  case IP_PKTINFO:
    if( (rc = opt_not_ok(optval, optlen, char)) ) {
      if( optlen == 0 )
        return 0;
      goto fail_fault;
    }

    if (ci_get_optval(optval, optlen))
      s->cmsg_flags |= CI_IP_CMSG_PKTINFO;
    else
      s->cmsg_flags &= ~CI_IP_CMSG_PKTINFO;
    break;

  case IP_MTU_DISCOVER:
  {
    unsigned val;
    /* sets the Path MTU discovery on this socket */
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;
    val = ci_get_optval(optval, optlen);

    if(val < CI_PMTU_DISCOVER_DISABLE ||
       val > CI_PMTU_DISCOVER_ENABLE_AND_CHECK_SENDS) {
      rc = -EINVAL;
      goto fail_fault;
    }

    s->pkt.pmtus.state = val;
    break;
  }

   case IP_RECVTOS:
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;

    if (ci_get_optval(optval, optlen))
      s->cmsg_flags |= CI_IP_CMSG_TOS;
    else
      s->cmsg_flags &= ~CI_IP_CMSG_TOS;
    break;

  case IP_RECVERR:
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;
    if (ci_get_optval(optval, optlen))
      s->so.so_debug |= CI_SOCKOPT_FLAG_IP_RECVERR;
    else
      s->so.so_debug &= ~CI_SOCKOPT_FLAG_IP_RECVERR;
    break;


  case IP_RECVTTL:
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;

    if (ci_get_optval(optval, optlen))
      s->cmsg_flags |= CI_IP_CMSG_TTL;
    else
      s->cmsg_flags &= ~CI_IP_CMSG_TTL;
    break;

   case IP_RECVOPTS:
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;

    if (ci_get_optval(optval, optlen))
      s->cmsg_flags |= CI_IP_CMSG_RECVOPTS;
    else
      s->cmsg_flags &= ~CI_IP_CMSG_RECVOPTS;
    break;

  case IP_RETOPTS:
    if( (rc = opt_not_ok(optval, optlen, char)) )
      goto fail_fault;

    if (ci_get_optval(optval, optlen))
      s->cmsg_flags |= CI_IP_CMSG_RETOPTS;
    else
      s->cmsg_flags &= ~CI_IP_CMSG_RETOPTS;
    break;


  REPORT_CASE(IP_ADD_MEMBERSHIP)
  REPORT_CASE(IP_DROP_MEMBERSHIP)
#ifdef MCAST_JOIN_GROUP
  REPORT_CASE(MCAST_JOIN_GROUP)
  REPORT_CASE(MCAST_LEAVE_GROUP)
#endif
  REPORT_CASE(IP_MULTICAST_IF)
  REPORT_CASE(IP_MULTICAST_LOOP)
  REPORT_CASE(IP_MULTICAST_TTL)
    /* When real work is necessary, it is already done in UDP-specific
     * functions or by OS . */
    break;


  default:
    goto fail_noopt;
  }

  return 0;

 fail_fault:
  LOG_SC(log("%s: "NS_FMT" option %i ptr/len error (EFAULT or EINVAL)", __FUNCTION__,
             NS_PRI_ARGS(netif, s), optname));
  RET_WITH_ERRNO( -rc );

 fail_noopt:
  LOG_SC(log("%s: "NS_FMT" unimplemented/bad option %i (ENOPROTOOPT)",
             __FUNCTION__, NS_PRI_ARGS(netif, s), optname));
 fail_unhan:
  RET_WITH_ERRNO( ENOPROTOOPT );
}

#if CI_CFG_FAKE_IPV6
/* Handler for common getsockopt:SOL_IPV6 options. */
int ci_set_sol_ip6( ci_netif* netif, ci_sock_cmn* s,
                    int optname, const void *optval, socklen_t optlen )
{
#ifdef  IPV6_V6ONLY
  if (optname == IPV6_V6ONLY && 
      (opt_not_ok(optval, optlen, unsigned) || *(unsigned *)optval)) {
    return CI_SOCKET_HANDOVER;
  }
#endif
  /* All socket options are already set for system socket, and we do not
   * handle IPv6 option natively. */
  return 0;
}
#endif

/* Handler for common setsockopt:SOL_SOCKET handlers */
int ci_set_sol_socket(ci_netif* netif, ci_sock_cmn* s,
                      int optname, const void* optval, socklen_t optlen)
{
  int v;
  int rc;

  ci_assert(netif);

  switch(optname) {
#if CI_CFG_TCP_SOCK_STATS
    /* Our proprietary socket options for collecting stats */
  case CI_SO_L5_CONFIG_SOCK_STATS:
    {
      ci_tcp_state* ts = (ci_tcp_state*) s;
      ci_ip_stats_config *tcp_config;
      if( (rc = opt_not_ok(optval, optlen, ci_ip_stats_config)) )
        goto fail_inval;

      tcp_config = (ci_ip_stats_config *) optval;

      NI_CONF(netif).tconst_stats =
        ci_tcp_time_ms2ticks(netif, tcp_config->timeout);

      ts->stats_fmt = tcp_config->output_fmt;
      /* (Re)start the collection - will dump right now */
      ci_tcp_stats_action( netif, ts,
                           tcp_config->action_type,
                           tcp_config->output_fmt,
                           NULL, NULL);
      break;
    }
#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION
  case CI_SO_L5_CONFIG_NETIF_STATS:
    {
      ci_ip_stats_config *netif_config;

      if( (rc =opt_not_ok(optval, optlen, ci_ip_stats_config)) )
        goto fail_inval;

      netif_config = (ci_ip_stats_config *) optval;

      NI_CONF(netif).tconst_stats =
        ci_tcp_time_ms2ticks(netif, netif_config->timeout);

      netif->state->stats_fmt = netif_config->output_fmt;
      /* (Re)start the collection - will dump right now */
      ci_netif_stats_action( netif,
                             netif_config->action_type,
                             netif_config->output_fmt,
                             NULL, NULL);
      break;
    }
#endif

  case SO_KEEPALIVE:
    /* Default Keepalive handler - use ONLY for protocols that do not
     * do keepalives */
    if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      goto fail_inval;

    if(*(unsigned*)optval)
      s->s_flags |= CI_SOCK_FLAG_KALIVE;
    else
      s->s_flags &= ~CI_SOCK_FLAG_KALIVE;
    break;

  case SO_OOBINLINE:
    /* If enabled, out-of-band data is directly placed in receive stream.
     * While this has no effect in UDP, setsockopt() still stores the flag. */
    if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      goto fail_inval;


    s->s_flags = ( *((unsigned*)optval) )
      ? s->s_flags | CI_SOCK_FLAG_OOBINLINE
      : s->s_flags & (~CI_SOCK_FLAG_OOBINLINE);
    break;

  case SO_RCVLOWAT: {
    int val;
    if( (rc = opt_not_ok(optval, optlen, int)) )
      goto fail_inval;
    val = *(int*) optval;

    if( val < 0)
      val = INT_MAX;
    /* In Linux (2.4, 2.6) 0 means 1. */
    s->so.rcvlowat = val ? val : 1;
    break;
  }

  case SO_DONTROUTE:
    /* don't send via gateway, only directly connected machine */
    /*! ?? \TODO */
      LOG_U(ci_log("%s: "NS_FMT" SO_DONTROUTE seen (not supported)",
                   __FUNCTION__, NS_PRI_ARGS(netif, s)));
      goto fail_noopt;

  case SO_BROADCAST:
    /* Allow broadcasts (no effect on TCP) */
    if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      goto fail_inval;

    if(*(unsigned*)optval)
      s->s_flags |= CI_SOCK_FLAG_BROADCAST;
    else
      s->s_flags &= ~CI_SOCK_FLAG_BROADCAST;
    break;

  case SO_REUSEADDR:
    if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      goto fail_inval;
    if( *(unsigned*) optval )
      s->s_flags |= CI_SOCK_FLAG_REUSEADDR;
    else
      s->s_flags &= ~CI_SOCK_FLAG_REUSEADDR;
    break;

  case SO_SNDBUF:
    /* Sets the maximum socket send buffer in bytes. */
    if( (rc = opt_not_ok(optval, optlen, int)) )
      goto fail_inval;
    v = *(int*) optval;
    if( s->b.state & CI_TCP_STATE_TCP ) {
      v = CI_MAX(v, (int) NI_OPTS(netif).tcp_sndbuf_min);
      v = CI_MIN(v, (int) NI_OPTS(netif).tcp_sndbuf_max);
      s->so.sndbuf = oo_adjust_SO_XBUF(v);
      /* only recalculate sndbuf, if the socket is already connected, if not,
       * then eff_mss is probably rubbish and we also know that the sndbuf
       * will have to be set when the socket is promoted to established
       */
      if( ! (s->b.state & CI_TCP_STATE_NOT_CONNECTED) )
        ci_tcp_set_sndbuf(SOCK_TO_TCP(s));
    }
    else {
      v = CI_MAX(v, (int) NI_OPTS(netif).udp_sndbuf_min);
      v = CI_MIN(v, (int) NI_OPTS(netif).udp_sndbuf_max);
      s->so.sndbuf = oo_adjust_SO_XBUF(v);
    }
    s->s_flags |= CI_SOCK_FLAG_SET_SNDBUF;
    break;

  case SO_RCVBUF:
    /* Sets the maximum socket receive buffer in bytes. */
    if( (rc = opt_not_ok(optval, optlen, int)) )
      goto fail_inval;
    v = *(int*) optval;
    if( s->b.state & CI_TCP_STATE_TCP ) {
      v = CI_MAX(v, (int) NI_OPTS(netif).tcp_rcvbuf_min);
      v = CI_MIN(v, (int) NI_OPTS(netif).tcp_rcvbuf_max);
    }
    else {
      v = CI_MAX(v, (int) NI_OPTS(netif).udp_rcvbuf_min);
      v = CI_MIN(v, (int) NI_OPTS(netif).udp_rcvbuf_max);
    }
    s->so.rcvbuf = oo_adjust_SO_XBUF(v);
    s->s_flags |= CI_SOCK_FLAG_SET_RCVBUF;
    break;

  case SO_LINGER:
    {
      struct linger *l = (struct linger*)optval;

      /* sets linger status */
      if( (rc = opt_not_ok(optval, optlen, struct linger)) )
        goto fail_inval;

      if( l->l_onoff ) {
        s->s_flags |= CI_SOCK_FLAG_LINGER;
        s->so.linger = l->l_linger;
      } else {
        s->s_flags &= ~CI_SOCK_FLAG_LINGER;
      }
      VERB(ci_log("%s: onoff:%d fl:%x", __FUNCTION__,
                  l->l_onoff, s->s_flags));
      break;
    }

  case SO_PRIORITY:
      if( (rc = opt_not_ok(optval, optlen, ci_pkt_priority_t)) )
        goto fail_inval;

      /* Linux stores/returns the precise priority value set */
      s->so_priority = *(ci_pkt_priority_t *)optval;
      break;

  case SO_BINDTODEVICE:
      rc = ci_sock_bindtodevice(netif, s, optval, optlen);
      if( rc == 0 || rc == CI_SOCKET_HANDOVER )
        return rc;
      else
        goto fail_other;
      break;

  case SO_DEBUG:
    if( (rc = opt_not_ok(optval, optlen, unsigned)) )
      goto fail_inval;

    if (*(unsigned*)optval)
      s->so.so_debug |= CI_SOCKOPT_FLAG_SO_DEBUG;
    else
      s->so.so_debug &= ~CI_SOCKOPT_FLAG_SO_DEBUG;
    break;


  default:
    /* SOL_SOCKET options that are defined to fail with ENOPROTOOPT:
     *  SO_TYPE,  CI_SOSNDLOWAT,
     *  SO_ERROR, SO_ACCEPTCONN
     */
    goto fail_noopt;
  }

  /* Success */
  return 0;

 fail_inval:
  LOG_SC(log("%s: "NS_FMT" option %i ptr/len error (EINVAL or EFAULT)",
             __FUNCTION__, NS_PRI_ARGS(netif, s), optname));
  RET_WITH_ERRNO( -rc );

 fail_noopt:
  LOG_SC(log("%s: "NS_FMT" unimplemented/bad option %i (ENOPROTOOPT)",
             __FUNCTION__, NS_PRI_ARGS(netif, s), optname));
  RET_WITH_ERRNO( ENOPROTOOPT );

 fail_other:
  RET_WITH_ERRNO(-rc);
}


int ci_set_sol_socket_nolock(ci_netif* ni, ci_sock_cmn* s, int optname,
			     const void* optval, socklen_t optlen)
{
  int rc = 1;  /* This means "not handled". */

  switch( optname ) {
  case SO_RCVTIMEO: {
    struct timeval *tv = (struct timeval *)optval;
    ci_uint64 timeo_usec;
    if( (rc = opt_not_ok(optval, optlen, struct timeval)) )
      goto fail_inval;
    timeo_usec = tv->tv_sec * 1000000ULL + tv->tv_usec;
    if( timeo_usec == 0 )
      s->so.sndtimeo_msec = 0;
    else if( timeo_usec > 0xffffffffULL * 1000 )
      s->so.rcvtimeo_msec = -1; /* some weeks = MAX_UINT */
    else if( timeo_usec < 1000 )
      s->so.rcvtimeo_msec = 1; /* small timeout = 1 */
    else
      s->so.rcvtimeo_msec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
    rc = 0;
    break;
  }

  case SO_SNDTIMEO: {
    struct timeval *tv = (struct timeval *)optval;
    ci_uint64 timeo_usec;
    if( (rc = opt_not_ok(optval, optlen, struct timeval)) )
      goto fail_inval;
    timeo_usec = tv->tv_sec * 1000000ULL + tv->tv_usec;
    if( timeo_usec == 0 )
      s->so.sndtimeo_msec = 0;
    else if( timeo_usec > 0xffffffffULL * 1000 )
      s->so.sndtimeo_msec = -1; /* some weeks = MAX_UINT */
    else if( timeo_usec < 1000 )
      s->so.sndtimeo_msec = 1; /* small timeout = 1 */
    else
      s->so.sndtimeo_msec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
    rc = 0;
    break;
  }

  }
  return rc;

 fail_inval:
  RET_WITH_ERRNO(-rc);
}

/*! \cidoxg_end */
