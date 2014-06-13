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
** \author  ctk, stg
**  \brief  UDP socket option control; getsockopt, setsockopt
**   \date  2005/05/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/cplane_ops.h>

# include <netinet/udp.h>


#define LPF "UDP SOCKOPTS "


static void ci_mcast_opts_updated(ci_netif* ni, ci_udp_state* us)
{
  if( CI_IP_IS_MULTICAST(us->ephemeral_pkt.ip.ip_daddr_be32) )
    ci_ip_cache_invalidate(&us->ephemeral_pkt);
  if( CI_IP_IS_MULTICAST(us->s.pkt.ip.ip_daddr_be32) )
    ci_ip_cache_invalidate(&us->s.pkt);
}


static void ci_mcast_set_outgoing_if(ci_netif* ni, ci_udp_state* us,
                                     int ifindex, ci_uint32 laddr)
{
  int rc;

  us->s.cp.ip_multicast_if_laddr_be32 = laddr;
  if( ifindex == 0 ) {
    if( laddr == INADDR_ANY ) {
      us->s.cp.ip_multicast_if = CI_IFID_BAD;
      return;
    }
    rc = cicp_user_find_home(CICP_HANDLE(ni), &laddr,
                             NULL/*hwport*/, &us->s.cp.ip_multicast_if,
                             NULL/*smac*/, NULL/*mtu*/, NULL/*encap*/);
    if(CI_UNLIKELY( rc != 0 ))
      /* Unlikely because when we invoked this on the kernel socket, it
       * thought that given ifindex does exist.
       *
       * ?? FIXME: We should return error to the caller in this case.
       */
      LOG_E(ci_log("%s: cicp_user_find_home %s failed (%d)",
                   __FUNCTION__, ip_addr_str(laddr), rc));
  }
  else {
    us->s.cp.ip_multicast_if = ifindex;
  }
}


static int ci_mcast_join_leave(ci_netif* ni, ci_udp_state* us,
                               ci_ifid_t ifindex, ci_uint32 laddr,
                               ci_uint32 maddr, int /*bool*/ add)
{
  ci_hwport_id_t hwport = CI_HWPORT_ID_BAD;
  cicp_encap_t encap = {CICP_LLAP_TYPE_NONE, 0}; /* Shut up gcc */
  int rc;

  if( add )
    us->udpflags |= CI_UDPF_MCAST_JOIN;

  if( NI_OPTS(ni).mcast_join_handover == 2 )
    return CI_SOCKET_HANDOVER;
  if( ! NI_OPTS(ni).mcast_recv )
    return 0;

  if( ifindex != 0 )
    rc = cicp_llap_retrieve(CICP_HANDLE(ni), ifindex, NULL, &hwport, NULL,
                            &encap, NULL/*base_ifindex*/, NULL);
  else if( laddr != 0 )
    rc = cicp_user_find_home(CICP_HANDLE(ni), &laddr, &hwport, &ifindex,
                             NULL, NULL, &encap);
  else {
    ci_ip_cached_hdrs ipcache;
    ci_ip_cache_init(&ipcache);
    ipcache.ip.ip_daddr_be32 = maddr;
    ipcache.dport_be16 = 0;
    cicp_user_retrieve(ni, &ipcache, &us->s.cp);
    hwport = ipcache.hwport;
    encap = ipcache.encap;
    ifindex = ipcache.ifindex;
    switch( ipcache.status ) {
    case retrrc_success:
    case retrrc_nomac:
      rc = 0;
      break;
    default:
      rc = 1;
      break;
    }
  }

  /* Use ci_hwport_check_onload() rather than testing CI_HWPORT_ID_BAD
   * because we should support this on a bond with no slaves.
   */
  if( rc != 0 || ! ci_hwport_check_onload(hwport, &encap) )
    /* Not acceleratable.  NB. The mcast_join_handover takes effect even if
     * this socket has joined a group that is accelerated.  This is
     * deliberate.
     */
    return NI_OPTS(ni).mcast_join_handover ? CI_SOCKET_HANDOVER : 0;

  rc = ci_tcp_ep_mcast_add_del(ni, S_SP(us), ifindex, maddr, add);
  if( rc != 0 ) {
    /* NB. We ignore the error because the kernel stack will handle it. */
    LOG_E(log(FNS_FMT "%s ifindex=%d maddr="CI_IP_PRINTF_FORMAT" failed "
              "(%d,%d)", FNS_PRI_ARGS(ni, &us->s), add ? "ADD" : "DROP",
              (int) ifindex, CI_IP_PRINTF_ARGS(&maddr), rc, errno));
    return 0;
  }

  LOG_UC(log(FNS_FMT "ci_tcp_ep_mcast_add_del(%s, %d, "CI_IP_PRINTF_FORMAT")",
             FNS_PRI_ARGS(ni, &us->s), add ? "ADD" : "DROP", 
             (int) ifindex, CI_IP_PRINTF_ARGS(&maddr)));

  if( add )
    us->udpflags |= CI_UDPF_MCAST_FILTER;

  if( add && NI_OPTS(ni).mcast_join_bindtodevice &&
      ! (us->udpflags & CI_UDPF_NO_MCAST_B2D) &&
      us->s.cp.so_bindtodevice == CI_IFID_BAD ) {
    /* When app does IP_ADD_MEMBERSHIP, automatically bind the socket to
     * the device that the multicast join was on.
     */
    if( us->s.rx_bind2dev_ifindex == CI_IFID_BAD ) {
      if( (rc = ci_sock_rx_bind2dev(ni, &us->s, ifindex)) == 0 ) {
        LOG_UC(log(FNS_FMT "bound rx to ifindex=%d",
                   FNS_PRI_ARGS(ni, &us->s), ifindex));
        us->udpflags |= CI_UDPF_MCAST_B2D;
      }
      else {
        LOG_E(log(FNS_FMT "ERROR: joined on ifindex=%d but bind failed (%d)",
                  FNS_PRI_ARGS(ni, &us->s), ifindex, rc));
      }
    }
    else if( us->s.rx_bind2dev_ifindex != ifindex ) {
      LOG_UC(log(FNS_FMT "unbinding socket from ifindex=%d",
                 FNS_PRI_ARGS(ni, &us->s), us->s.rx_bind2dev_ifindex));
      us->udpflags |= CI_UDPF_NO_MCAST_B2D;
      us->s.rx_bind2dev_ifindex = CI_IFID_BAD;
      us->s.rx_bind2dev_base_ifindex = 0;
      us->s.rx_bind2dev_vlan = 0;
    }
  }

  return 0;
}


ci_inline int __get_socket_opt(citp_socket* ep, ci_fd_t sock, int level, 
                               int name, void* v, socklen_t* len )
{
  return CI_IS_VALID_SOCKET(sock) ? 
    ci_sys_getsockopt(sock, level, name, v, len) : -1;
}



/* BUG1439: pass in [fd] so we can go ask the OS for it's SO_ERROR */
int ci_udp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, void *optval, socklen_t *optlen )
{
  ci_netif* netif;
  ci_udp_state* us;
  unsigned u = 0;

  ci_assert(ep);
  netif = ep->netif;
  us = SOCK_TO_UDP(ep->s);

  /* ?? what to do about optval and optlen checking
  ** Kernel can raise EFAULT, here we are a little in the dark.
  */

  if(level == SOL_SOCKET) {
    if(optname == SO_ERROR) {
      /* Allow OS errors to be passed-up to app.  Our own error
       * takes priority. Usually, our own errors are just copied from OS. */
      u = 0;
      if(  us->s.so_error ) {
      	u = ci_get_so_error(&us->s);
      } else {
	ci_fd_t os_sock = ci_get_os_sock_fd (ep, fd);
        if( !__get_socket_opt(ep, os_sock, level, optname, optval, optlen) )
	  u = *(int*)optval;
        ci_rel_os_sock_fd( os_sock );
      }
      goto u_out;
    }
    else {
      /* Common SOL_SOCKET option handler */
      return ci_get_sol_socket(netif, &us->s, optname, optval, optlen);
    }
  } else if (level ==  IPPROTO_IP) {
    /* IP level options valid for UDP */
    switch (optname) {
    case IP_RECVERR:
      {
	ci_fd_t os_sock = ci_get_os_sock_fd (ep, fd);
        if( !__get_socket_opt(ep, os_sock, level, optname, optval, optlen) )
	  u = *(int*)optval;
        ci_rel_os_sock_fd( os_sock );
      }
      goto u_out;

    case IP_MULTICAST_IF:
      u = us->s.cp.ip_multicast_if_laddr_be32;
      /* Hack: multicast options are not handled in the same way as other
       * opts in SOL_IP level in Linux. */
      return ci_getsockopt_final(optval, optlen, SOL_UDP, &u, sizeof(u));

    case IP_MULTICAST_LOOP:
      u = (us->udpflags & CI_UDPF_MCAST_LOOP) != 0;
      goto u_out_char;

    case IP_MULTICAST_TTL:
      u = us->s.cp.ip_mcast_ttl;
      goto u_out_char;

    default:
      return ci_get_sol_ip(ep, &us->s, fd, optname, optval, optlen);
    }

#if CI_CFG_FAKE_IPV6
  } else if (level ==  IPPROTO_IPV6 && us->s.domain == AF_INET6) {
    /* IP6 level options valid for TCP */
    return ci_get_sol_ip6(ep, &us->s, fd, optname, optval, optlen);
#endif

  } else if (level == IPPROTO_UDP) {
    /* We definitely don't support this */
    RET_WITH_ERRNO(ENOPROTOOPT);
  } else {
    SOCKOPT_RET_INVALID_LEVEL(&us->s);
  }

 u_out_char:
 u_out:
  return ci_getsockopt_final(optval, optlen, SOL_IP, &u, sizeof(u));
}


static int ci_udp_setsockopt_lk(citp_socket* ep, ci_fd_t fd, ci_fd_t os_sock,
				int level, int optname, const void* optval,
				socklen_t optlen)
{
  ci_netif* netif;
  ci_udp_state* us;
  int rc, v;

  ci_assert(ep);
  netif = ep->netif;
  us = SOCK_TO_UDP(ep->s);

  /* Note that the OS backing socket [os_sock] is expected to be available
   * in the following code. */
  ci_assert( CI_IS_VALID_SOCKET( os_sock ) );

  if(level == SOL_SOCKET) {
    /* socket level options valid for UDP */
    switch(optname) {
    case SO_SNDBUF:
      /* sets the maximum socket send buffer in bytes */
      if( (rc = opt_not_ok(optval,optlen,int)) )
        goto fail_inval;

      /* Since we keep both a user-level and an OS socket around and can send
      ** via either it is extremely important we keep both in sync.  Where
      ** possible we read back the effective send buffer size set above.
      */
      if( __get_socket_opt(ep, os_sock, SOL_SOCKET, SO_SNDBUF, &v, &optlen)) {
        /* We don't have an OS socket or we can't read the buffer size back.
        ** Emulate the OS behaviour. */
        v = *(int*) optval;
        v = CI_MAX(v, (int)NI_OPTS(netif).udp_sndbuf_min);
        v = CI_MIN(v, (int)NI_OPTS(netif).udp_sndbuf_max);
        v = oo_adjust_SO_XBUF(v);
      }
      else if( NI_OPTS(netif).udp_sndbuf_user ) {
        v = oo_adjust_SO_XBUF(NI_OPTS(netif).udp_sndbuf_user);
      }

      us->s.so.sndbuf = v;
      break;

    case SO_RCVBUF:
      /* sets the maximum socket receive buffer in bytes */
      if( (rc = opt_not_ok(optval,optlen,int)) )
        goto fail_inval;

      /* Since we keep both a user-level and an OS socket around and can
      ** receive via either it is extremely important we keep both in sync.
      ** Where possible we read back the effective receive buffer size set
      ** above.
      */
      if( __get_socket_opt(ep, os_sock, SOL_SOCKET, SO_RCVBUF, &v, &optlen)) {
        /* We don't have an OS socket or we can't read the buffer size back.
        ** Emulate the OS behaviour. */
        v = *(int*) optval;
        v = CI_MAX(v, (int)NI_OPTS(netif).udp_rcvbuf_min);
        v = CI_MIN(v, (int)NI_OPTS(netif).udp_rcvbuf_max);
        v = oo_adjust_SO_XBUF(v);
      }
      else if( NI_OPTS(netif).udp_rcvbuf_user ) {
        v = oo_adjust_SO_XBUF(NI_OPTS(netif).udp_rcvbuf_user);
      }

      us->s.so.rcvbuf = v;
      /* It is essential that [max_recvq_depth] be <= SO_RCVBUF, else
       * SO_RCVBUF has no effect (see ci_udp_rx_deliver()).  Simplest thing
       * is to reset it to zero.
       */
      us->stats.max_recvq_depth = 0;
      break;

    case SO_TIMESTAMP:
    case SO_TIMESTAMPNS:
      /* Make sure the siocgstamp returns correct value until
       * SO_TIMESTAMP[NS] is turned off again
       */
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      if( (us->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP_ANY) == 0 ) {
          /* Make sure the siocgstamp returns correct value until
           * SO_TIMESTAMP[NS] is turned off again
           */
          if( ci_get_optval(optval, optlen) )
            us->stamp_pre_sots = us->stamp;
          else
            us->stamp = us->stamp_pre_sots;
      }
      /* Then use the common path */
      return ci_set_sol_socket(netif, &us->s, optname, optval, optlen);
      break;

    default:
      /* Common socket level options */
      return ci_set_sol_socket(netif, &us->s, optname, optval, optlen);
    }
  } else if (level == IPPROTO_IP) {
    /* IP level options valid for UDP */
    switch(optname) {
    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
    {
      const struct ip_mreqn *mreqn = (void *)optval;
      const struct ip_mreq *mreq = (void *)optval;

      if( optlen >= sizeof(struct ip_mreqn) ) {
        rc = ci_mcast_join_leave(netif, us, (ci_ifid_t)mreqn->imr_ifindex,
                                 mreqn->imr_address.s_addr,
                                 mreqn->imr_multiaddr.s_addr,
                                 optname == IP_ADD_MEMBERSHIP);
      }
      else 
      if( optlen >= sizeof(struct ip_mreq) ) {
        rc = ci_mcast_join_leave(netif, us, 0, mreq->imr_interface.s_addr,
                                 mreq->imr_multiaddr.s_addr,
                                 optname == IP_ADD_MEMBERSHIP);
      }
      else
        RET_WITH_ERRNO(EFAULT);
      if( rc )
        return rc;
      break;
    }

#ifdef IP_ADD_SOURCE_MEMBERSHIP
    case IP_ADD_SOURCE_MEMBERSHIP:
    case IP_DROP_SOURCE_MEMBERSHIP:
    {
      /* NB. We are treating this just like IP_ADD_MEMBERSHIP.  ie. The
       * hardware filters we insert are not source specific.  The kernel
       * will still take account of the source for igmp purposes.
       *
       * I think this should be okay, because joining a group controls the
       * delivery of packets to the host.  It does not in any way limit the
       * packets that can arrive at a particular socket.
       */
      const struct ip_mreq_source *mreqs = (void *)optval;

      if( optlen >= sizeof(struct ip_mreq_source) ) {
        rc = ci_mcast_join_leave(netif, us, 0, mreqs->imr_interface.s_addr,
                                 mreqs->imr_multiaddr.s_addr,
                                 optname == IP_ADD_SOURCE_MEMBERSHIP);
      }
      else
        RET_WITH_ERRNO(EFAULT);
      if( rc )
        return rc;
      break;
    }
#endif

#ifdef MCAST_JOIN_GROUP
    case MCAST_JOIN_GROUP:
    case MCAST_LEAVE_GROUP:
    {
      struct group_req *greq = (void *)optval;

      if( optlen < sizeof(struct group_req) )
        RET_WITH_ERRNO(EFAULT);
      if( greq->gr_group.ss_family != AF_INET )
        return CI_SOCKET_HANDOVER;
      rc = ci_mcast_join_leave(netif, us, greq->gr_interface, 0,
                CI_SIN(&greq->gr_group)->sin_addr.s_addr,
                optname == MCAST_JOIN_GROUP);
      if( rc )
        return rc;
      break;
    }
#endif

#ifdef MCAST_JOIN_SOURCE_GROUP
    case MCAST_JOIN_SOURCE_GROUP:
    case MCAST_LEAVE_SOURCE_GROUP:
    {
      /* NB. We are treating this just like IP_ADD_MEMBERSHIP.  ie. The
       * hardware filters we insert are not source specific.  The kernel
       * will still take account of the source for igmp purposes.
       *
       * I think this should be okay, because joining a group controls the
       * delivery of packets to the host.  It does not in any way limit the
       * packets that can arrive at a particular socket.
       */
      struct group_source_req *gsreq = (void *)optval;

      if( optlen < sizeof(struct group_source_req) )
        RET_WITH_ERRNO(EFAULT);
      if( gsreq->gsr_group.ss_family != AF_INET )
        return CI_SOCKET_HANDOVER;
      rc = ci_mcast_join_leave(netif, us, gsreq->gsr_interface, 0,
                CI_SIN(&gsreq->gsr_group)->sin_addr.s_addr,
                optname == MCAST_JOIN_SOURCE_GROUP);
      if( rc )
        return rc;
      break;
    }
#endif

    case IP_MULTICAST_IF:
    {
      const struct ip_mreqn *mreqn = (void *)optval;

      if( optlen >= sizeof(struct ip_mreqn) )
        ci_mcast_set_outgoing_if(netif, us, mreqn->imr_ifindex,
                                 mreqn->imr_address.s_addr);
      else
      if( optlen >= sizeof(struct in_addr) )
        ci_mcast_set_outgoing_if(netif, us, 0, *(ci_uint32 *)optval);
      else
        us->s.cp.ip_multicast_if = CI_IFID_BAD;
      ci_mcast_opts_updated(netif, us);
      break;
    }

    case IP_MULTICAST_LOOP:
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      if( ci_get_optval(optval, optlen) ) {
        us->udpflags |= CI_UDPF_MCAST_LOOP;
        if( NI_OPTS(netif).force_send_multicast )
          /* Options say accelerate mcast sends anyway. */
          us->s.cp.sock_cp_flags &= ~OO_SCP_NO_MULTICAST;
        else
          us->s.cp.sock_cp_flags |= OO_SCP_NO_MULTICAST;
      }
      else {
        /* Can accelerate when no loopback. */
        us->udpflags &= ~CI_UDPF_MCAST_LOOP;
        us->s.cp.sock_cp_flags &= ~OO_SCP_NO_MULTICAST;
      }
      ci_mcast_opts_updated(netif, us);
      break;

    case IP_MULTICAST_TTL:
    {
      int ttl;
      if( (rc = opt_not_ok(optval, optlen, char)) )
        goto fail_inval;
      ttl = (int) ci_get_optval(optval, optlen);
      /* On linux, -1 for IP_MULTICAST_TTL means reset to default. */
      us->s.cp.ip_mcast_ttl = ttl == -1 ? 1 : ttl;
      ci_mcast_opts_updated(netif, us);
      break;
    }
    default:
      /* Common SOL_IP option handler */
      return ci_set_sol_ip( netif, &us->s, optname, optval, optlen );
    }

#if CI_CFG_FAKE_IPV6
  } else if (level ==  IPPROTO_IPV6) {
    /* IP6 level options valid for TCP */
    return ci_set_sol_ip6( netif, &us->s, optname, optval, optlen);
#endif

  } else if (level == IPPROTO_UDP) {
    RET_WITH_ERRNO(ENOPROTOOPT);
  }
  else {
    LOG_U(log(FNS_FMT "unknown level=%d optname=%d accepted by O/S",
              FNS_PRI_ARGS(netif, ep->s), level, optname));
  }

  return 0;

 fail_inval:
  LOG_UC(log("%s: "SF_FMT" option %i ptr/len error (EINVAL or EFAULT)",
             __FUNCTION__, SF_PRI_ARGS(ep,fd), optname));
  RET_WITH_ERRNO(-rc);

}

ci_inline int __set_socket_opt(citp_socket* ep, ci_fd_t sock, int level, 
                               int name, const void* v, socklen_t len )
{
  return CI_IS_VALID_SOCKET(sock) ? 
    ci_sys_setsockopt(sock, level, name, v, len) : -1;
}

int ci_udp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		      int optname, const void *optval, socklen_t optlen )
{
  ci_fd_t os_sock;
  int rc;

  /* Keep the OS socket in sync so we can move freely between efab & OS fds
  ** on a per-call basis if necessary. */
  os_sock = ci_get_os_sock_fd(ep, fd);
  ci_assert(CI_IS_VALID_SOCKET(os_sock));
  rc = __set_socket_opt(ep, os_sock, level, optname, optval, optlen);
  if( rc == CI_SOCKET_ERROR )  goto out;

  if( level == SOL_SOCKET ) {
    rc = ci_set_sol_socket_nolock(ep->netif, ep->s, optname, optval, optlen);
    if( rc <= 0 )  goto out;
  }

  /* Otherwise we need to grab the netif lock. */
  ci_netif_lock_id(ep->netif, SC_SP(ep->s));
  rc = ci_udp_setsockopt_lk(ep, fd, os_sock, level, optname, optval, optlen);
  ci_netif_unlock(ep->netif);
 out:
  ci_rel_os_sock_fd(os_sock);
  return rc;
}

/*! \cidoxg_end */
