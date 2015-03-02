/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
**  \brief  TCP connection routines:
**          accept, bind, close, connect, shutdown, getpeername
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include <onload/common.h>
#include <onload/sleep.h>

#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif

#ifndef __KERNEL__
#include <ci/internal/efabcfg.h>
#endif

#define VERB(x)

#define LPF "tcp_connect: "

#ifndef __KERNEL__
/*!
 * Tests for valid sockaddr & sockaddr length & AF_INET or AF_INET6.
 */
static int ci_tcp_validate_sa( sa_family_t domain, 
                               const struct sockaddr* sa, socklen_t sa_len )
{
  /*
   * Linux deviates from documented behaviour here;
   * On Linux we return EINVAL if sa and sa_len are NULL and 0 respectively,
   *      and we return EFAULT if sa is NULL and sa_len != 0....
   */
  if( !sa ) {
    LOG_U(ci_log(LPF "invalid sockaddr : sa = %lx, sa_len = %d",
	      (long) sa, sa_len));
    if( sa_len == 0 )
      RET_WITH_ERRNO( EINVAL );
    else
      RET_WITH_ERRNO( EFAULT );
  }

  if( sa_len < sizeof(struct sockaddr_in) 
#if CI_CFG_FAKE_IPV6
      || (domain == AF_INET6 && sa_len < SIN6_LEN_RFC2133)
#endif
      ) {
    LOG_U( ci_log(LPF "struct too short to be sockaddr_in(6)" ));
    RET_WITH_ERRNO( EINVAL );
  }

  /* It should be sa->sa_family, but MS wdm does not understand it,
   * so let's use CI_SIN(sa)->sin_family. */
  if (CI_SIN(sa)->sin_family != domain 
#if !CI_CFG_REQUIRE_SOCKADDR_FAM
      && CI_SIN(sa)->sin_family != AF_UNSPEC
#endif
      ) {
    LOG_U(ci_log(LPF "address family %d does not match "
                  "with socket domain %d", CI_SIN(sa)->sin_family, domain));
    RET_WITH_ERRNO(EAFNOSUPPORT);
  }

#if CI_CFG_FAKE_IPV6
  if (sa->sa_family == AF_INET6 && !ci_tcp_ipv6_is_ipv4(sa)) {
    LOG_TC(ci_log(LPF "Pure IPv6 address is not supported"));
    RET_WITH_ERRNO(EAFNOSUPPORT);
  }
#endif 
  return 0;
}
#endif

/* These bind routine may be common to TCP & UDP, but is used in TCP only */
/*! Perform system bind on the OS backing socket.
 * \param ep       Endpoint context
 * \param fd       Callers FD
 * \param ip_addr_be32  Local address to which to bind
 * \param port_be16     [in] requested port [out] assigned port
 * \return         0 - success & [port_be16] updated
 *                 CI_SOCKET_HANDOVER, Pass to OS, OS bound ok, (no error)
 *                 CI_SOCKET_ERROR & errno set
 */
ci_inline int __ci_bind(ci_netif *ni, ci_sock_cmn *s,
                        ci_uint32 ip_addr_be32, ci_uint16* port_be16 )
{
  int rc;
  ci_uint16 user_port; /* Port number specified by user, not by OS.
                        * See bug 4015 for details */
  union ci_sockaddr_u sa_u;

  ci_assert(s->domain == AF_INET || s->domain == AF_INET6);

  ci_assert( port_be16 );

  user_port = *port_be16;
#if CI_CFG_FAKE_IPV6
  ci_assert(s->domain == AF_INET || s->domain == AF_INET6);
  if( s->domain == AF_INET )
    ci_make_sockaddr(&sa_u.sin, s->domain, user_port, ip_addr_be32);
  else
    ci_make_sockaddr6(&sa_u.sin6, s->domain, user_port, ip_addr_be32);
#else
  ci_assert(s->domain == AF_INET);
  ci_make_sockaddr(&sa_u.sin, s->domain, user_port, ip_addr_be32);
#endif

#ifdef __ci_driver__
  rc = efab_tcp_helper_bind_os_sock(netif2tcp_helper_resource(ni),
                                    SC_SP(s),
                                    &sa_u.sa, sizeof(sa_u), port_be16);
#else
  rc = ci_tcp_helper_bind_os_sock(ni, SC_SP(s), &sa_u.sa,
                                  sizeof(sa_u), port_be16);
#endif

  /* bug1781: only do this if the earlier bind succeeded. 
   * check if we can handle this socket */
  if( rc != 0 )
    return rc;
  if( user_port != 0 )
    s->s_flags |= CI_SOCK_FLAG_PORT_BOUND;
  if( ip_addr_be32 != INADDR_ANY )
    s->s_flags |= CI_SOCK_FLAG_ADDR_BOUND;
  s->s_flags &= ~CI_SOCK_FLAG_CONNECT_MUST_BIND;

#ifndef __ci_driver__
  /* We do not call bind() to alien address from in-kernel code */
  if( ip_addr_be32 != INADDR_ANY &&
      !cicp_user_addr_is_local_efab(CICP_HANDLE(ni), &ip_addr_be32) )
    s->s_flags |= CI_SOCK_FLAG_BOUND_ALIEN;
#endif
  
  return rc;
}


oo_sp ci_tcp_connect_find_local_peer(ci_netif *ni,
                                     ci_ip_addr_t dst_be32, int dport_be16)
{
  int i;

  for( i = 0; i < (int)ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, i);
    ci_tcp_socket_listen* tls;
    if( wo->waitable.state != CI_TCP_LISTEN ) continue;
    if( wo->waitable.sb_aflags & CI_SB_AFLAG_ORPHAN ) continue;
    tls = SOCK_TO_TCP_LISTEN(&wo->sock);
    if( tls->s.cp.lport_be16 != dport_be16 ) continue;
    if( tls->s.cp.ip_laddr_be32 != INADDR_ANY &&
        tls->s.cp.ip_laddr_be32 != dst_be32) continue;
    if( tls->s.cp.so_bindtodevice != CI_IFID_BAD ) continue;

    /* this is our tls - connect to it! */
    if( (int)ci_tcp_acceptq_n(tls) < tls->acceptq_max )
      return tls->s.b.bufid;
    else
      return OO_SP_INVALID;
  }
  return OO_SP_NULL;
}




#ifndef __KERNEL__
/* check that we can handle this destination */
static int ci_tcp_connect_check_dest(citp_socket* ep, ci_ip_addr_t dst_be32,
                                     int dport_be16)
{
  ci_ip_cached_hdrs* ipcache = &ep->s->pkt;

  ipcache->ip.ip_daddr_be32 = dst_be32;
  ipcache->dport_be16 = dport_be16;
  cicp_user_retrieve(ep->netif, ipcache, &ep->s->cp);

  if(CI_LIKELY( ipcache->status == retrrc_success ||
                ipcache->status == retrrc_nomac   ||
                ipcache->status < 0 )) {
    /* Onloadable. */
    if( ipcache->encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER4 )
      /* We don't yet have a local port number, so the result of that
       * lookup may be wrong.
       */
      ci_ip_cache_invalidate(ipcache);
    if( ipcache->ip.ip_saddr_be32 == 0 ) {
      /* Control plane has selected a source address for us -- remember it. */
      ipcache->ip.ip_saddr_be32 = ipcache->ip_saddr_be32;
      ep->s->cp.ip_laddr_be32 = ipcache->ip_saddr_be32;
    }
    return 0;
  }
  else if( ipcache->status == retrrc_localroute ) {
    ci_tcp_state* ts = SOCK_TO_TCP(ep->s);

    if( NI_OPTS(ep->netif).tcp_client_loopback == CITP_TCP_LOOPBACK_OFF)
      return CI_SOCKET_HANDOVER;

    ep->s->s_flags |= CI_SOCK_FLAG_BOUND_ALIEN;
    if( NI_OPTS(ep->netif).tcp_server_loopback != CITP_TCP_LOOPBACK_OFF )
      ts->local_peer = ci_tcp_connect_find_local_peer(ep->netif, dst_be32,
                                                      dport_be16);
    else
      ts->local_peer = OO_SP_NULL;

    if( OO_SP_NOT_NULL(ts->local_peer) ||
        NI_OPTS(ep->netif).tcp_client_loopback !=
        CITP_TCP_LOOPBACK_SAMESTACK ) {
      ipcache->flags |= CI_IP_CACHE_IS_LOCALROUTE;
      if( ipcache->ip.ip_saddr_be32 == 0 ) {
        ipcache->ip.ip_saddr_be32 = dst_be32;
        ep->s->cp.ip_laddr_be32 = dst_be32;
      }
      ipcache->ether_offset = 4; /* lo is non-VLAN */
      ipcache->ip_saddr_be32 = dst_be32;
      ipcache->dport_be16 = dport_be16;
      return 0;
    }
    return CI_SOCKET_HANDOVER;
  }

  return CI_SOCKET_HANDOVER;
}
#endif



/* Return codes from ci_tcp_connect_ul_start(). */
#define CI_CONNECT_UL_OK                0
#define CI_CONNECT_UL_FAIL              -1
#define CI_CONNECT_UL_START_AGAIN	-2
#define CI_CONNECT_UL_LOCK_DROPPED	-3

static int ci_tcp_connect_ul_start(ci_netif *ni, ci_tcp_state* ts,
				   ci_uint32 dst_be32, unsigned dport_be16,
                                   int* fail_rc)
{
  ci_ip_pkt_fmt* pkt;
  int rc = 0;

  ci_assert(ts->s.pkt.mtu);

  /* Now that we know the outgoing route, set the MTU related values.
   * Note, even these values are speculative since the real MTU
   * could change between now and passing the packet to the lower layers
   */
  ts->amss = ts->s.pkt.mtu - sizeof(ci_tcp_hdr) - sizeof(ci_ip4_hdr);
#if CI_CFG_LIMIT_AMSS
  ts->amss = ci_tcp_limit_mss(ts->amss, ni, __FUNCTION__);
#endif

  /* Default smss until discovered by MSS option in SYN - RFC1122 4.2.2.6 */
  ts->smss = CI_CFG_TCP_DEFAULT_MSS;

  /* set pmtu, eff_mss, snd_buf and adjust windows */
  ci_pmtu_set(ni, &ts->pmtus, ts->s.pkt.mtu);
  ci_tcp_set_eff_mss(ni, ts);
  ci_tcp_set_initialcwnd(ni, ts);

  /* Send buffer adjusted by ci_tcp_set_eff_mss(), but we want it to stay
   * zero until the connection is established.
   */
  ts->so_sndbuf_pkts = 0;

  /* 
   * 3. State and address are OK. It's address routed through our NIC.
   *    Do connect().
   */
  ci_assert_nequal(ts->s.pkt.ip.ip_saddr_be32, INADDR_ANY);

  if( ts->s.s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND ) {
    ci_sock_cmn* s = &ts->s;
    ci_uint16 source_be16 = 0;

    if( s->s_flags & CI_SOCK_FLAG_ADDR_BOUND )
      rc = __ci_bind(ni, &ts->s, ts->s.pkt.ip.ip_saddr_be32, &source_be16);
    else 
      rc = __ci_bind(ni, &ts->s, INADDR_ANY, &source_be16);
    if(CI_LIKELY( rc == 0 )) {
      TS_TCP(ts)->tcp_source_be16 = source_be16;
      ts->s.cp.lport_be16 = source_be16;
      LOG_TC(log(LNT_FMT "connect: our bind returned %s:%u", 
                 LNT_PRI_ARGS(ni, ts),
                 ip_addr_str(INADDR_ANY),
                 (unsigned) CI_BSWAP_BE16(TS_TCP(ts)->tcp_source_be16)));
    }
    else {
      LOG_U(ci_log("__ci_bind returned %d at %s:%d", CI_GET_ERROR(rc),
                   __FILE__, __LINE__));
      *fail_rc = rc;
      return CI_CONNECT_UL_FAIL;
    }
    if(CI_UNLIKELY( ts->s.pkt.ip.ip_saddr_be32 == 0 )) {
      CI_SET_ERROR(*fail_rc, EINVAL);
      return CI_CONNECT_UL_FAIL;
    }
  }

  ci_tcp_set_peer(ts, dst_be32, dport_be16);

  /* Make sure we can get a buffer before we change state. */
  pkt = ci_netif_pkt_tx_tcp_alloc(ni);
  if( CI_UNLIKELY(! pkt) ) {
    /* NB. We've already done a poll above. */
    rc = ci_netif_pkt_wait(ni, &ts->s, CI_SLEEP_NETIF_LOCKED|CI_SLEEP_NETIF_RQ);
    if( ci_netif_pkt_wait_was_interrupted(rc) ) {
      CI_SET_ERROR(*fail_rc, -rc);
      return CI_CONNECT_UL_LOCK_DROPPED;
    }
    /* OK, there are (probably) packets available - go try again.  Note we
     * jump back to the top of the function because someone may have
     * connected this socket in the mean-time, so we need to check the
     * state once more.
     */
    return CI_CONNECT_UL_START_AGAIN;
  }

#ifdef ONLOAD_OFE
    if( ni->ofe != NULL )
      ts->s.ofe_code_start = ofe_socktbl_find(
                        ni->ofe, OFE_SOCKTYPE_TCP_ACTIVE,
                        tcp_laddr_be32(ts), tcp_raddr_be32(ts),
                        tcp_lport_be16(ts), tcp_rport_be16(ts));
#endif

  rc = ci_tcp_ep_set_filters(ni, S_SP(ts), ts->s.cp.so_bindtodevice,
                             OO_SP_NULL);
  if( rc < 0 ) {
    /* Perhaps we've run out of filters?  See if we can push a socket out
     * of timewait and steal its filter.
     */
    ci_assert_nequal(rc, -EFILTERSSOME);
    if( rc != -EBUSY || ! ci_netif_timewait_try_to_free_filter(ni) ||
        (rc = ci_tcp_ep_set_filters(ni, S_SP(ts),
                                    ts->s.cp.so_bindtodevice,
                                    OO_SP_NULL)) < 0 ) {
      ci_assert_nequal(rc, -EFILTERSSOME);
      /* Either a different error, or our efforts to free a filter did not
       * work.
       */
      if( ! (ts->s.s_flags & CI_SOCK_FLAG_ADDR_BOUND) ) {
        ts->s.pkt.ip.ip_saddr_be32 = 0;
        ts->s.cp.ip_laddr_be32 = 0;
      }
      ci_netif_pkt_release(ni, pkt);
      CI_SET_ERROR(*fail_rc, -rc);
      return CI_CONNECT_UL_FAIL;
    }
  }

  LOG_TC(log(LNT_FMT "CONNECT %s:%u->%s:%u", LNT_PRI_ARGS(ni, ts),
	     ip_addr_str(ts->s.pkt.ip.ip_saddr_be32),
	     (unsigned) CI_BSWAP_BE16(TS_TCP(ts)->tcp_source_be16),
	     ip_addr_str(ts->s.pkt.ip.ip_daddr_be32),
	     (unsigned) CI_BSWAP_BE16(TS_TCP(ts)->tcp_dest_be16)));

  /* We are going to send the SYN - set states appropriately */
  tcp_snd_una(ts) = tcp_snd_nxt(ts) = tcp_enq_nxt(ts) = tcp_snd_up(ts) =
    ci_tcp_initial_seqno(ni);
  ts->snd_max = tcp_snd_nxt(ts) + 1;

  /* Must be after initialising snd_una. */
  ci_tcp_clear_rtt_timing(ts);
  ci_tcp_set_flags(ts, CI_TCP_FLAG_SYN);
  ts->tcpflags &=~ CI_TCPT_FLAG_OPT_MASK;
  ts->tcpflags |= NI_OPTS(ni).syn_opts;

  if( (ts->tcpflags & CI_TCPT_FLAG_WSCL) ) {
    ts->rcv_wscl = ci_tcp_wscl_by_buff(ni, ci_tcp_rcvbuf_established(ni, &ts->s));
    CI_IP_SOCK_STATS_VAL_RXWSCL(ts, ts->rcv_wscl);
  }
  else {
    ts->rcv_wscl = 0;
    CI_IP_SOCK_STATS_VAL_RXWSCL(ts, 0);
  }
  ci_tcp_set_rcvbuf(ni, ts);
  ci_tcp_init_rcv_wnd(ts, "CONNECT");

  /* outgoing_hdrs_len is initialised to include timestamp option. */
  if( ! (ts->tcpflags & CI_TCPT_FLAG_TSO) )
    ts->outgoing_hdrs_len = sizeof(ci_ip4_hdr)+sizeof(ci_tcp_hdr);
  if( ci_tcp_can_stripe(ni, ts->s.pkt.ip.ip_saddr_be32,
			ts->s.pkt.ip.ip_daddr_be32) )
    ts->tcpflags |= CI_TCPT_FLAG_STRIPE;
  ci_tcp_set_slow_state(ni, ts, CI_TCP_SYN_SENT);

  /* If the app trys to send data on a socket in SYN_SENT state
  ** then the data is queued for send until the SYN gets ACKed.
  ** (rfc793 p56)
  **
  ** Receive calls on the socket should block until data arrives
  ** (rfc793 p58)
  **
  ** Clearing tx_errno and rx_errno acheive this. The transmit window
  ** is set to 1 byte which ensures that only the SYN packet gets
  ** sent until the ACK is received with more window. 
  */
  ci_assert(ts->snd_max == tcp_snd_nxt(ts) + 1);
  ts->s.rx_errno = 0;
  ts->s.tx_errno = 0; 
  ci_tcp_enqueue_no_data(ts, ni, pkt);
  ci_tcp_set_flags(ts, CI_TCP_FLAG_ACK);  

  if( ts->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY) ) {
    ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
    LOG_TC(log( LNT_FMT "Non-blocking connect - return EINPROGRESS",
		LNT_PRI_ARGS(ni, ts)));
    CI_SET_ERROR(*fail_rc, EINPROGRESS);
    return CI_CONNECT_UL_FAIL;
  }

  return CI_CONNECT_UL_OK;
}

ci_inline int ci_tcp_connect_handle_so_error(ci_sock_cmn *s)
{
  ci_int32 rc = ci_get_so_error(s);
  if( rc == 0 )
    return 0;
  s->rx_errno = ENOTCONN;
  return rc;
}

static int ci_tcp_connect_ul_syn_sent(ci_netif *ni, ci_tcp_state *ts)
{
  int rc = 0;

  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    ci_netif_poll(ni);
    if( OO_SP_NOT_NULL(ts->local_peer) ) {
      /* No reason to sleep.  Obviously, listener have dropped our syn
       * because of some reason.  Go away! */
      ci_tcp_drop(ni, ts, EBUSY);
      RET_WITH_ERRNO(EBUSY);
    }
    CI_TCP_SLEEP_WHILE(ni, ts, CI_SB_FLAG_WAKE_RX,
                       ts->s.so.sndtimeo_msec,
                       ts->s.b.state == CI_TCP_SYN_SENT, &rc); 
  }

  if( rc == -EAGAIN ) {
    LOG_TC(log( LNT_FMT "timeout on sleep: %d",
		LNT_PRI_ARGS(ni, ts), -rc));
    if( ! (ts->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT) ) {
      ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
      CI_SET_ERROR(rc, EINPROGRESS);
    }
    else
      CI_SET_ERROR(rc, EALREADY);
    return rc;
  }
  else if( rc == -EINTR ) {
    LOG_TC(log(LNT_FMT "connect() was interrupted by a signal", 
               LNT_PRI_ARGS(ni, ts)));
    ts->tcpflags |= CI_TCPT_FLAG_NONBLOCK_CONNECT;
    CI_SET_ERROR(rc, EINTR);
    return rc;
  }

  /*! \TODO propagate the correct error code: CONNREFUSED, NOROUTE, etc. */

  if( ts->s.b.state == CI_TCP_CLOSED ) {
    /* Bug 3558: 
     * Set OS socket state to allow/disallow next bind().
     * It is Linux hack. */
#ifdef __ci_driver__
    CI_TRY(efab_tcp_helper_set_tcp_close_os_sock(netif2tcp_helper_resource(ni),
                                                 S_SP(ts)));
#else
    CI_TRY(ci_tcp_helper_set_tcp_close_os_sock(ni, S_SP(ts)));
#endif

    /* We should re-bind socket on the next use if the port was determined by
     * OS.
     */
    if( ! (ts->s.s_flags & CI_SOCK_FLAG_PORT_BOUND) )
      ts->s.s_flags |= CI_SOCK_FLAG_CONNECT_MUST_BIND;

    /* - if SO_ERROR is set, handle it and return this value;
     * - else if rx_errno is set, return it;
     * - else (TCP_RX_ERRNO==0, socket is CI_SHUT_RD) return ECONNABORTED */
    if( (rc = ci_tcp_connect_handle_so_error(&ts->s)) == 0)
        rc = TCP_RX_ERRNO(ts) ? TCP_RX_ERRNO(ts) : ECONNABORTED;
    CI_SET_ERROR(rc, rc);

    if( ! (ts->s.s_flags & CI_SOCK_FLAG_ADDR_BOUND) ) {
      ts->s.pkt.ip.ip_saddr_be32 = 0;
      ts->s.cp.ip_laddr_be32 = 0;
    }
    return rc;
  }

  return 0;
}


#ifndef __KERNEL__
/* Returns:
 *          0                  on success
 *          
 *          CI_SOCKET_ERROR (and errno set)
 *                             this is a normal error that is returned to the
 *                             the application
 *
 *          CI_SOCKET_HANDOVER we tell the upper layers to handover, no need
 *                             to set errno since it isn't a real error
 */
int ci_tcp_connect(citp_socket* ep, const struct sockaddr* serv_addr,
		   socklen_t addrlen, ci_fd_t fd, int *p_moved)
{
  /* Address family is validated earlier. */
  struct sockaddr_in* inaddr = (struct sockaddr_in*) serv_addr;
  ci_sock_cmn* s = ep->s;
  ci_tcp_state* ts = &SOCK_TO_WAITABLE_OBJ(s)->tcp;
  int rc = 0, crc;
  ci_uint32 dst_be32;

  if( NI_OPTS(ep->netif).tcp_connect_handover )
    return CI_SOCKET_HANDOVER;

  /* Make sure we're up-to-date. */
  ci_netif_lock(ep->netif);
  CHECK_TEP(ep);
  ci_netif_poll(ep->netif);

  /*
   * 1. Check if state of the socket is OK for connect operation.
   */

 start_again:

  if( (rc = ci_tcp_connect_handle_so_error(s)) != 0) {
    CI_SET_ERROR(rc, rc);
    goto unlock_out;
  }

  if( s->b.state != CI_TCP_CLOSED ) {
    /* see if progress can be made on this socket before
    ** determining status  (e.g. non-blocking connect and connect poll)*/
    if( s->b.state & CI_TCP_STATE_SYNCHRONISED ) {
      if( ts->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT ) {
        ts->tcpflags &= ~CI_TCPT_FLAG_NONBLOCK_CONNECT;
	rc = 0;
	goto unlock_out;
      }
      if( serv_addr->sa_family == AF_UNSPEC )
        LOG_E(ci_log("Onload does not support TCP disconnect via "

                     "connect(addr->sa_family==AF_UNSPEC)"));
      CI_SET_ERROR(rc, EISCONN);
    }
    else if( s->b.state == CI_TCP_LISTEN ) {
#if CI_CFG_POSIX_CONNECT_AFTER_LISTEN
      CI_SET_ERROR(rc, EOPNOTSUPP);
#else
      if( ci_tcp_validate_sa(s->domain, serv_addr, addrlen) ) {
        /* Request should be forwarded to OS */
        rc = CI_SOCKET_HANDOVER;
	goto unlock_out;
      }
      if( serv_addr->sa_family == AF_UNSPEC ) {
        /* Linux does listen shutdown on disconnect (AF_UNSPEC) */
        ci_netif_unlock(ep->netif);
        rc = ci_tcp_shutdown(ep, SHUT_RD, fd);
	goto out;
      } else {
        /* Linux has curious error reporting in this case */
        CI_SET_ERROR(rc, EISCONN);
      }
#endif
    }
    else {
      /* Socket is in SYN-SENT state. Let's block for receiving SYN-ACK */
      ci_assert_equal(s->b.state, CI_TCP_SYN_SENT);
      if( s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY) )
        CI_SET_ERROR(rc, EALREADY);
      else
        goto syn_sent;
    }
    goto unlock_out;
  }

  /* Check if we've ever been connected. */
  if( ts->tcpflags & CI_TCPT_FLAG_WAS_ESTAB ) {
    CI_SET_ERROR(rc, EISCONN);
    goto unlock_out;
  }

  /* 
   * 2. Check address parameter, if it's inappropriate for handover
   *    decision or handover should be done, try to to call OS and
   *    do handover on success.
   */

  if (
    /* Af first, check that address family and length is OK. */
    ci_tcp_validate_sa(s->domain, serv_addr, addrlen)
    /* rfc793 p54 if the foreign socket is unspecified return          */
    /* "error: foreign socket unspecified" (EINVAL), but keep it to OS */
    || (dst_be32 = ci_get_ip4_addr(inaddr->sin_family, serv_addr)) == 0
    /* Zero destination port is tricky as well, keep it to OS */
    || inaddr->sin_port == 0 )
  {
    rc = CI_SOCKET_HANDOVER;
    goto unlock_out;
  }
  
  /* is this a socket that we can handle? */
  rc = ci_tcp_connect_check_dest(ep, dst_be32, inaddr->sin_port);
  if( rc )  goto unlock_out;

  if( (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE) &&
      OO_SP_IS_NULL(ts->local_peer) ) {
    /* Try to connect to another stack; handover if can't */
    struct oo_op_loopback_connect op;
    op.dst_port = inaddr->sin_port;
    op.dst_addr = dst_be32;
    /* this operation unlocks netif */
    rc = oo_resource_op(fd, OO_IOC_TCP_LOOPBACK_CONNECT, &op);
    if( rc < 0)
      return CI_SOCKET_HANDOVER;
    if( op.out_moved )
      *p_moved = 1;
    if( op.out_rc == -EINPROGRESS )
      RET_WITH_ERRNO( EINPROGRESS );
    else if( op.out_rc == -EAGAIN )
      return -EAGAIN;
    else if( op.out_rc != 0 )
      return CI_SOCKET_HANDOVER;
    return 0;
  }

  /* filters can't handle alien source address */
  if( (s->s_flags & CI_SOCK_FLAG_BOUND_ALIEN) &&
      ! (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE) ) {
    rc = CI_SOCKET_HANDOVER;
    goto unlock_out;
  }

  crc = ci_tcp_connect_ul_start(ep->netif, ts, dst_be32, inaddr->sin_port, &rc);
  if( crc != CI_CONNECT_UL_OK ) {
    switch( crc ) {
    case CI_CONNECT_UL_FAIL:
      goto unlock_out;
    case CI_CONNECT_UL_LOCK_DROPPED:
      goto out;
    case CI_CONNECT_UL_START_AGAIN:
      goto start_again;
    }
  }
  CI_TCP_STATS_INC_ACTIVE_OPENS( ep->netif );

 syn_sent:
  rc = ci_tcp_connect_ul_syn_sent(ep->netif, ts);

 unlock_out:
  ci_netif_unlock(ep->netif);
 out:
  return rc;
}
#endif

static int ci_tcp_listen_init(ci_netif *ni, ci_tcp_socket_listen *tls)
{
  int i;
  oo_p sp;

  tls->acceptq_n_in = tls->acceptq_n_out = 0;
  tls->acceptq_put = CI_ILL_END;
  tls->acceptq_get = OO_SP_NULL;
  tls->n_listenq = 0;
  tls->n_listenq_new = 0;

  /* Allocate and initialise the listen bucket */
  if( OO_P_IS_NULL(ni->state->free_aux_mem) )
    return -ENOBUFS;
  tls->bucket = ni->state->free_aux_mem;
  ci_tcp_bucket_alloc(ni);

  /* Initialise the listenQ. */
  for( i = 0; i <= CI_CFG_TCP_SYNACK_RETRANS_MAX; ++i ) {
    sp = TS_OFF(ni, tls);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, listenq[i]));
    ci_ni_dllist_init(ni, &tls->listenq[i], sp, "lstq");
  }

  /* Initialize the cache and pending lists for the EP-cache.
   * See comment at definition for details
   */
  LOG_EP (log ("Initialise cache and pending list for id %d",
	       S_FMT(tls)));

#if CI_CFG_FD_CACHING
  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache_cache));
  ci_ni_dllist_init(ni, &tls->epcache_cache, sp, "epch");

  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache_pending));
  ci_ni_dllist_init(ni, &tls->epcache_pending, sp, "eppd");

  sp = TS_OFF(ni, tls);
  OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, epcache_connected));
  ci_ni_dllist_init(ni, &tls->epcache_connected, sp, "epco");

  tls->cache_avail_sock = ni->state->opts.per_sock_cache_max;
#endif

  return 0;
}


#ifdef __KERNEL__
int ci_tcp_connect_lo_samestack(ci_netif *ni, ci_tcp_state *ts, oo_sp tls_id)
{
  int crc, rc = 0;

  ci_assert(ci_netif_is_locked(ni));

  ts->local_peer = tls_id;
  crc = ci_tcp_connect_ul_start(ni, ts, ts->s.pkt.ip_saddr_be32,
                                ts->s.pkt.dport_be16, &rc);

  /* The connect is really finished, but we should return EINPROGRESS
   * for non-blocking connect and 0 for normal. */
  if( crc == CI_CONNECT_UL_OK )
    rc = ci_tcp_connect_ul_syn_sent(ni, ts);
  return rc;
}

/* c_ni is assumed to be locked on enterance and is always unlocked on
 * exit. */
int ci_tcp_connect_lo_toconn(ci_netif *c_ni, oo_sp c_id, ci_uint32 dst,
                             ci_netif *l_ni, oo_sp l_id)
{
  ci_tcp_state *ts;
  ci_tcp_socket_listen *tls, *alien_tls;
  citp_waitable_obj *wo;
  citp_waitable *w;
  int rc;

  ci_assert(ci_netif_is_locked(c_ni));
  ci_assert(OO_SP_NOT_NULL(c_id));
  ci_assert(OO_SP_NOT_NULL(l_id));

  LOG_TC(log("%s: connect %d:%d to %d:%d", __FUNCTION__,
             c_ni->state->stack_id, OO_SP_TO_INT(c_id),
             l_ni->state->stack_id, OO_SP_TO_INT(l_id)));

  alien_tls = SP_TO_TCP_LISTEN(l_ni, l_id);
  if( (int)ci_tcp_acceptq_n(alien_tls) >= alien_tls->acceptq_max ) {
    ci_netif_unlock(c_ni);
    return -EBUSY;
  }

  /* In c_ni, create shadow listening socket tls (copy l_id) */
  ts = ci_tcp_get_state_buf(c_ni);
  if( ts == NULL ) {
    ci_netif_unlock(c_ni);
    LOG_E(ci_log("%s: [%d] out of socket buffers", __FUNCTION__, NI_ID(c_ni)));
    return -ENOMEM;
  }

  /* init common tcp fields */
  ts->s.so = alien_tls->s.so;
  ts->s.cp.ip_ttl = alien_tls->s.cp.ip_ttl;
  S_TCP_HDR(&ts->s)->tcp_source_be16 =
      S_TCP_HDR(&alien_tls->s)->tcp_source_be16;
  ts->s.domain = alien_tls->s.domain;
  ts->c = alien_tls->c;
  ts->c.tcp_defer_accept = OO_TCP_DEFER_ACCEPT_OFF;

  /* make sure nobody will ever connect to our "shadow" socket
   * except us */
  ci_bit_set(&ts->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);

  ci_tcp_set_slow_state(c_ni, ts, CI_TCP_LISTEN);
  tls = SOCK_TO_TCP_LISTEN(&ts->s);
  /* no timer: */
  tls->s.s_flags = alien_tls->s.s_flags | CI_SOCK_FLAG_BOUND_ALIEN;

  tls->acceptq_max = 1;
  rc = ci_tcp_listen_init(c_ni, tls);
  if( rc != 0 ) {
    citp_waitable_obj_free(c_ni, &tls->s.b);
    return rc;
  }

  /* Connect c_id to tls */
  ts = SP_TO_TCP(c_ni, c_id);
  rc = ci_tcp_connect_lo_samestack(c_ni, ts, tls->s.b.bufid);

  /* Accept as from tls */
  if( !ci_tcp_acceptq_not_empty(tls) ) {
    /* it is possible, for example, if ci_tcp_listenq_try_promote() failed
     * because there are no endpoints */
    citp_waitable_obj_free(c_ni, &tls->s.b);
    ci_netif_unlock(c_ni);
    return -EBUSY;
  }
  w = ci_tcp_acceptq_get(c_ni, tls);
  ci_assert(w);
  LOG_TV(ci_log("%s: %d:%d to %d:%d shadow %d:%d accepted %d:%d",
                __FUNCTION__,
                c_ni->state->stack_id, OO_SP_TO_INT(c_id),
                l_ni->state->stack_id, OO_SP_TO_INT(l_id),
                c_ni->state->stack_id, tls->s.b.bufid,
                c_ni->state->stack_id, w->bufid));

  ci_assert(w->state & CI_TCP_STATE_TCP);
  ci_assert(w->state != CI_TCP_LISTEN);

  /* Destroy tls.
   * NB: nobody could possibly connect to it, so no need to do proper
   * shutdown.
   */
  ci_assert_equal(ci_tcp_acceptq_n(tls), 0);
  citp_waitable_obj_free(c_ni, &tls->s.b);
  ci_netif_unlock(c_ni);

  /* Keep a port reference */
  {
    tcp_helper_endpoint_t *l_ep, *a_ep;
    struct oo_file_ref* os_sock_ref;
    ci_irqlock_state_t lock_flags;

    l_ep = ci_trs_ep_get(netif2tcp_helper_resource(l_ni), l_id);
    a_ep = ci_trs_ep_get(netif2tcp_helper_resource(c_ni), W_SP(w));
    ci_irqlock_lock(&l_ep->thr->lock, &lock_flags);
    os_sock_ref = l_ep->os_socket;
    ci_assert_equal(a_ep->os_port_keeper, NULL);
    if( os_sock_ref != NULL ) {
      os_sock_ref = oo_file_ref_add(os_sock_ref);
      os_sock_ref = oo_file_ref_xchg(&a_ep->os_port_keeper, os_sock_ref);
      ci_irqlock_unlock(&l_ep->thr->lock, &lock_flags);
      if( os_sock_ref != NULL )
        oo_file_ref_drop(os_sock_ref);
    }
    else {
      ci_irqlock_unlock(&l_ep->thr->lock, &lock_flags);
      goto cleanup;
    }
  }

  /* lock l_ni: Check that l_id is the same socket it used to be */
  /* create ref-sock in l_ni, put it into acc q */
  if( ci_netif_lock(l_ni) != 0 )
    goto cleanup;
  if( alien_tls->s.b.state != CI_TCP_LISTEN ||
      (alien_tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ||
      S_TCP_HDR(&alien_tls->s)->tcp_source_be16 != TS_TCP(ts)->tcp_dest_be16 ||
      (alien_tls->s.pkt.ip.ip_saddr_be32 != INADDR_ANY &&
       alien_tls->s.pkt.ip.ip_saddr_be32 != ts->s.pkt.ip.ip_daddr_be32) ) {
    ci_netif_unlock(l_ni);
    goto cleanup;
  }

  ci_bit_mask_set(&w->sb_aflags,
                  CI_SB_AFLAG_TCP_IN_ACCEPTQ | CI_SB_AFLAG_ORPHAN);

  wo = citp_waitable_obj_alloc(l_ni);
  if( wo == NULL ) {
    ci_netif_unlock(l_ni);
    goto cleanup;
  }
  wo->waitable.state = CI_TCP_CLOSED;
  wo->waitable.sb_aflags |= CI_SB_AFLAG_MOVED_AWAY;
  wo->waitable.moved_to_stack_id = c_ni->state->stack_id;
  wo->waitable.moved_to_sock_id = W_SP(w);
  LOG_TC(log("%s: put to acceptq %d:%d referencing %d:%d", __func__,
             l_ni->state->stack_id, OO_SP_TO_INT(W_SP(&wo->waitable)),
             c_ni->state->stack_id, OO_SP_TO_INT(W_SP(w))));

  ci_tcp_acceptq_put(l_ni, alien_tls, &wo->waitable);
  citp_waitable_wake_not_in_poll(l_ni, &alien_tls->s.b, CI_SB_FLAG_WAKE_RX);
  ci_netif_unlock(l_ni);

  return rc;

cleanup:
  ci_assert(w->sb_aflags & CI_SB_AFLAG_ORPHAN);
  ci_bit_mask_clear(&w->sb_aflags,
                    CI_SB_AFLAG_TCP_IN_ACCEPTQ | CI_SB_AFLAG_ORPHAN);
  efab_tcp_helper_close_endpoint(netif2tcp_helper_resource(c_ni), w->bufid);
  /* we can not guarantee c_ni lock, so we can' call
   * ci_tcp_drop(c_ni, ts).  So, we return error; UL will handover
   * and close ts endpoint. */
  return -EBUSY;
}
#endif


 
#ifndef  __KERNEL__

/* Set a reuseport bind on a socket.
 */
int ci_tcp_reuseport_bind(ci_sock_cmn* sock, ci_fd_t fd)
{
  int rc;
  /* With legacy reuseport we delay the __ci_bind actions to avoid errors
   * when trying to re-use a port for the os socket, so won't have set the
   * PORT_BOUND flag yet.
   */
  ci_assert(((sock->s_flags & CI_SOCK_FLAG_PORT_BOUND) != 0) ||
            ((sock->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY) != 0));
  ci_assert_nequal(sock->s_flags & CI_SOCK_FLAG_REUSEPORT, 0);
  if ( (rc = ci_tcp_ep_reuseport_bind(fd, CITP_OPTS.cluster_name,
                                      CITP_OPTS.cluster_size,
                                      CITP_OPTS.cluster_restart_opt,
                                      sock_laddr_be32(sock), 
                                      sock_lport_be16(sock))) != 0 ) {
    errno = -rc;
    return -1;
  }
  return 0;
}

/* In this bind handler we just check that the address to which
 * are binding is either "any" or one of ours. 
 * In the Linux kernel version [fd] is unused.
 */
int ci_tcp_bind(citp_socket* ep, const struct sockaddr* my_addr,
                socklen_t addrlen, ci_fd_t fd )
{
  struct sockaddr_in* my_addr_in;
  ci_uint16 new_port;
  ci_uint32 addr_be32;
  ci_sock_cmn* s = ep->s;
  ci_tcp_state* c = &SOCK_TO_WAITABLE_OBJ(s)->tcp;
  int rc;

  CHECK_TEP(ep);

  my_addr_in = (struct sockaddr_in*) my_addr;

  /* Check if state of the socket is OK for bind operation. */
  /* \todo Earlier (TS_TCP( epi->tcpep.state )->tcp_source_be16) is used.
   *       What is better? */
  if (my_addr == NULL)
    RET_WITH_ERRNO( EINVAL );


  if (s->b.state != CI_TCP_CLOSED)
    RET_WITH_ERRNO( EINVAL );

  if (c->tcpflags & CI_TCPT_FLAG_WAS_ESTAB)
    RET_WITH_ERRNO( EINVAL );

  if( my_addr->sa_family != s->domain )
    RET_WITH_ERRNO( s->domain == PF_INET ? EAFNOSUPPORT : EINVAL );

  /* Bug 4884: Windows regularly uses addrlen > sizeof(struct sockaddr_in) 
   * Linux is also relaxed about overlength data areas. */
  if (s->domain == PF_INET && addrlen < sizeof(struct sockaddr_in))
    RET_WITH_ERRNO( EINVAL );

#if CI_CFG_FAKE_IPV6
  if (s->domain == PF_INET6 && addrlen < SIN6_LEN_RFC2133)
    RET_WITH_ERRNO( EINVAL );

  if( s->domain == PF_INET6 && !ci_tcp_ipv6_is_ipv4(my_addr) )
    return CI_SOCKET_HANDOVER;
#endif
  addr_be32 = ci_get_ip4_addr(s->domain, my_addr);
 
  /* Using the port number provided, see if we can do this bind */
  new_port = my_addr_in->sin_port;

  if( CITP_OPTS.tcp_reuseports != 0 && new_port != 0 ) {
    struct ci_port_list *force_reuseport;
    CI_DLLIST_FOR_EACH2(struct ci_port_list, force_reuseport, link,
                        (ci_dllist*)(ci_uintptr_t)CITP_OPTS.tcp_reuseports) {
      if( force_reuseport->port == new_port ) {
        int one = 1;
        ci_fd_t os_sock = ci_get_os_sock_fd(ep, fd);
        ci_assert(CI_IS_VALID_SOCKET(os_sock));
        rc = ci_sys_setsockopt(os_sock, SOL_SOCKET, SO_REUSEPORT, &one,
                               sizeof(one));
        ci_rel_os_sock_fd(os_sock);
        if( rc != 0 && errno == ENOPROTOOPT )
          ep->s->s_flags |= CI_SOCK_FLAG_REUSEPORT_LEGACY;
        ep->s->s_flags |= CI_SOCK_FLAG_REUSEPORT;
        LOG_TC(log("%s "SF_FMT", applied legacy SO_REUSEPORT flag for port %u",
                   __FUNCTION__, SF_PRI_ARGS(ep, fd), new_port));
      }
    }
  }

  if( !(ep->s->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY) ) 
    CI_LOGLEVEL_TRY_RET(LOG_TV,
		        __ci_bind(ep->netif, ep->s, addr_be32, &new_port));
  ep->s->s_flags |= CI_SOCK_FLAG_BOUND;
  sock_lport_be16(s) = new_port; 
  sock_laddr_be32(s) = addr_be32;
  if( CI_IP_IS_MULTICAST(addr_be32) )
    s->cp.ip_laddr_be32 = 0;
  else
    s->cp.ip_laddr_be32 = addr_be32;
  s->cp.lport_be16 = new_port;
  sock_rport_be16(s) = sock_raddr_be32(s) = 0;

  LOG_TC(log(LPF "bind to %s:%u n_p:%u lp:%u", ip_addr_str(addr_be32),
	     (unsigned) CI_BSWAP_BE16(my_addr_in->sin_port),
	     CI_BSWAP_BE16(new_port), CI_BSWAP_BE16(sock_lport_be16(s)))); 

  return 0;
}


/* Set the socket to listen, the reorder buffer and txq become
** the listen state, and it is initialised
** \todo split this overlong function up!
**
** NOTE: [fd] is unused in the kernel version
*/

int ci_tcp_listen(citp_socket* ep, ci_fd_t fd, int backlog)
{
  /* 
  ** ?? error handling on possible fails not handled robustly...
  ** ?? Need to check port number is valid TODO
  */

  /*! \todo If not bound then we have to be listening on all interfaces.
   * It's likely that we won't be coming through here as we have to
   * listen on the OS socket too! */
  ci_tcp_state* ts;
  ci_tcp_socket_listen* tls;
  ci_netif* netif = ep->netif;
  ci_sock_cmn* s = ep->s;
  unsigned ul_backlog = backlog;
  int rc;
  oo_p sp;

  LOG_TC(log("%s "SK_FMT" listen backlog=%d", __FUNCTION__, SK_PRI_ARGS(ep), 
             backlog));
  CHECK_TEP(ep);

  if( NI_OPTS(netif).tcp_listen_handover )
    return CI_SOCKET_HANDOVER;
  if( !NI_OPTS(netif).tcp_server_loopback) {
    /* We should handover if the socket is bound to alien address. */
    if( s->s_flags & CI_SOCK_FLAG_BOUND_ALIEN )
      return CI_SOCKET_HANDOVER;
  }

  if( ul_backlog < 0 )
    ul_backlog = NI_OPTS(netif).max_ep_bufs;
  else if( ul_backlog < NI_OPTS(netif).acceptq_min_backlog )
    ul_backlog = NI_OPTS(netif).acceptq_min_backlog;

  if( s->b.state == CI_TCP_LISTEN ) {
    tls = SOCK_TO_TCP_LISTEN(s);
    tls->acceptq_max = ul_backlog;
    ci_tcp_helper_listen_os_sock(fd, ul_backlog);
    return 0;
  }

  if( s->b.state != CI_TCP_CLOSED ) {
    CI_SET_ERROR(rc, EINVAL);
    return rc;
  }


  ts = SOCK_TO_TCP(s);

  /* Bug 3376: if socket used for a previous, failed, connect then the error
   * numbers will not be as expected.  Only seen when not using listening
   * netifs (as moving the EP to the new netif resets them). 
   */

  ts->s.tx_errno = EPIPE;



  ts->s.rx_errno = ENOTCONN;

  /* fill in address/ports and all TCP state */
  if( !(ts->s.s_flags & CI_SOCK_FLAG_BOUND) ) {
    ci_uint16 source_be16;

    /* They haven't previously done a bind, so we need to choose 
     * a port.  As we haven't been given a hint we let the OS choose. */

    source_be16 = 0;
    rc = __ci_bind(ep->netif, ep->s, ts->s.pkt.ip.ip_saddr_be32, &source_be16);
    if (CI_LIKELY( rc==0 )) {
      TS_TCP(ts)->tcp_source_be16 = source_be16;
      ts->s.cp.lport_be16 = source_be16;
      LOG_TC(log(LNT_FMT "listen: our bind returned %s:%u", 
                 LNT_PRI_ARGS(ep->netif, ts),
                 ip_addr_str(ts->s.pkt.ip.ip_saddr_be32),
                 (unsigned) CI_BSWAP_BE16(TS_TCP(ts)->tcp_source_be16)));

    } else {
      LOG_U(ci_log("__ci_bind returned %d at %s:%d", CI_GET_ERROR(rc),
                   __FILE__, __LINE__));
      return rc;
    }
  } 

  ci_tcp_set_slow_state(netif, ts, CI_TCP_LISTEN);
  tls = SOCK_TO_TCP_LISTEN(&ts->s);

  tcp_raddr_be32(tls) = 0u;
  tcp_rport_be16(tls) = 0u;

  ci_assert_equal(tls->s.tx_errno, EPIPE);



  ci_assert_equal(tls->s.rx_errno, ENOTCONN);

  /* setup listen timer - do it before the first return statement,
   * because __ci_tcp_listen_to_normal() will be called on error path. */
  if( ~tls->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN ) {
    sp = TS_OFF(netif, tls);
    OO_P_ADD(sp, CI_MEMBER_OFFSET(ci_tcp_socket_listen, listenq_tid));
    ci_ip_timer_init(netif, &tls->listenq_tid, sp, "lstq");
    tls->listenq_tid.param1 = S_SP(tls);
    tls->listenq_tid.fn = CI_IP_TIMER_TCP_LISTEN;
  }

  rc = ci_tcp_listen_init(netif, tls);
  if( rc != 0 ) {
    CI_SET_ERROR(rc, -rc);
    goto listen_fail;
  }
  tls->acceptq_max = ul_backlog;

  CITP_STATS_TCP_LISTEN(CI_ZERO(&tls->stats));

  /* install all the filters needed for this connection 
   *    - tcp_laddr_be32(ts) = 0 for IPADDR_ANY
   *
   *  TODO: handle BINDTODEVICE by setting phys_port paramter to correct 
   *        physical L5 port index
   *  TODO: handle REUSEADDR by setting last paramter to TRUE
   */
  if( ~s->s_flags & CI_SOCK_FLAG_BOUND_ALIEN ) {
#ifdef ONLOAD_OFE
    if( netif->ofe != NULL ) {
      tls->s.ofe_code_start = ofe_socktbl_find(
                        netif->ofe, OFE_SOCKTYPE_TCP_LISTEN,
                        tcp_laddr_be32(tls), INADDR_ANY,
                        tcp_lport_be16(ts), 0);
      tls->ofe_promote = ofe_socktbl_find(
                        netif->ofe, OFE_SOCKTYPE_TCP_PASSIVE,
                        tcp_laddr_be32(tls), INADDR_ANY,
                        tcp_lport_be16(ts), 0);
    }
#endif
    rc = ci_tcp_ep_set_filters(netif, S_SP(tls), tls->s.cp.so_bindtodevice,
                               OO_SP_NULL);
    if( rc == -EFILTERSSOME ) {
      if( CITP_OPTS.no_fail )
        rc = 0;
      else {
        ci_tcp_ep_clear_filters(netif, S_SP(tls), 0);
        rc = -ENOBUFS;
      }
    }
    ci_assert_nequal(rc, -EFILTERSSOME);
    VERB(ci_log("%s: set_filters  returned %d", __FUNCTION__, rc));
    if (rc < 0) {
      CI_SET_ERROR(rc, -rc);
      goto listen_fail;
    }
  }


  /* 
   * Call of system listen() is required for listen any, local host
   * communications server and multi-homed server (to accept connections
   * to L5 assigned address(es), but incoming from other interfaces).
   */
#ifdef __ci_driver__
  {
    rc = efab_tcp_helper_listen_os_sock( netif2tcp_helper_resource(netif),
					 S_SP(tls), backlog);
  }
#else
  rc = ci_tcp_helper_listen_os_sock(fd, backlog);
#endif
  if ( rc < 0 ) {
    /* clear the filter we've just set */
    ci_tcp_ep_clear_filters(netif, S_SP(tls), 0);
    goto listen_fail;
  }
  return 0;

 listen_fail:
  /* revert TCP state to a non-listening socket format */
  __ci_tcp_listen_to_normal(netif, tls);
  /* Above function sets orphan flag but we are attached to an FD. */
  ci_bit_clear(&tls->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
#ifdef __ci_driver__
  return rc;
#else
  return CI_SOCKET_ERROR;
#endif
}


static int ci_tcp_shutdown_listen(citp_socket* ep, int how, ci_fd_t fd)
{
  ci_tcp_socket_listen* tls = SOCK_TO_TCP_LISTEN(ep->s);

  if( how == SHUT_WR )
    return 0;

  ci_sock_lock(ep->netif, &tls->s.b);
  ci_netif_lock(ep->netif);
  LOG_TC(ci_log(SK_FMT" shutdown(SHUT_RD)", SK_PRI_ARGS(ep)));
  __ci_tcp_listen_shutdown(ep->netif, tls, fd);
  __ci_tcp_listen_to_normal(ep->netif, tls);
  {
    ci_fd_t os_sock = ci_get_os_sock_fd(ep, fd);
    int flags = ci_sys_fcntl(os_sock, F_GETFL);
    flags &= (~O_NONBLOCK);
    CI_TRY(ci_sys_fcntl(os_sock, F_SETFL, flags));
    ci_rel_os_sock_fd(os_sock);
  }
  ci_netif_unlock(ep->netif);
  ci_sock_unlock(ep->netif, &tls->s.b);
  return 0;
}


#ifndef __KERNEL__
int ci_tcp_shutdown(citp_socket* ep, int how, ci_fd_t fd)
{
  ci_sock_cmn* s = ep->s;
  int rc;

  if( s->b.state == CI_TCP_LISTEN )
    return ci_tcp_shutdown_listen(ep, how, fd);

  if( SOCK_TO_TCP(s)->snd_delegated ) {
    /* We do not know which seq number to use.  Call
     * onload_delegated_send_cancel(). */
    CI_SET_ERROR(rc, -EBUSY);
    return rc;
  }

  if( ! ci_netif_trylock(ep->netif) ) {
    /* Can't get lock, so try to defer shutdown to the lock holder. */
    unsigned flags = 0;
    switch( s->b.state ) {
    case CI_TCP_CLOSED:
    case CI_TCP_TIME_WAIT:
      CI_SET_ERROR(rc, ENOTCONN);
      return rc;
    }
    if( how == SHUT_RD || how == SHUT_RDWR )
      flags |= CI_SOCK_AFLAG_NEED_SHUT_RD;
    if( how == SHUT_WR || how == SHUT_RDWR )
      flags |= CI_SOCK_AFLAG_NEED_SHUT_WR;
    ci_atomic32_or(&s->s_aflags, flags);
    if( ! ci_netif_lock_or_defer_work(ep->netif, &s->b) )
      return 0;
    ci_atomic32_and(&s->s_aflags, ~flags);
  }

  if( 0 ) {
    /* Poll to get up-to-date.  This is slightly spurious but done to ensure
     * ordered response to all packets preceding this FIN (e.g. ANVL tcp_core
     * 9.18)
     *
     * DJR: I've disabled this because it can hurt performance for
     * high-connection-rate apps.  May consider adding back (as option?) if
     * needed.
     */
    ci_netif_poll(ep->netif);
  }
  rc = __ci_tcp_shutdown(ep->netif, SOCK_TO_TCP(s), how);
  if( rc < 0 )
    CI_SET_ERROR(rc, -rc);
  ci_netif_unlock(ep->netif);
  return rc;
}
#endif


void ci_tcp_linger(ci_netif* ni, ci_tcp_state* ts)
{
  /* This is called at user-level when a socket is closed if linger is
  ** enabled and has a timeout, and there is TX data outstanding.
  **
  ** Our job is to block until all data is successfully sent and acked, or
  ** until timeout.
  */
  ci_uint64 sleep_seq;
  int rc = 0;
  ci_uint32 timeout = ts->s.so.linger * 1000;

  LOG_TC(log("%s: "NTS_FMT, __FUNCTION__, NTS_PRI_ARGS(ni, ts)));

  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
  ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_SO_LINGER);
  ci_assert(ts->s.s_flags & CI_SOCK_FLAG_LINGER);
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  while( 1 ) {
    sleep_seq = ts->s.b.sleep_seq.all;
    ci_rmb();
    if( SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts)) )
      return;
    rc = ci_sock_sleep(ni, &ts->s.b, CI_SB_FLAG_WAKE_TX, 0, sleep_seq,
                       &timeout);
    if( rc )
      break;
  }

  if( ! SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts)) ) {
    ci_netif_lock(ni);
    /* check we are working with the same socket, and it was not closed and
     * dropped under our feet. */
    if( ! SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_una(ts)) &&
        (ts->s.b.sb_aflags & CI_SB_AFLAG_IN_SO_LINGER) )
      ci_tcp_drop(ni, ts, 0);
    ci_netif_unlock(ni);
  }
}


int ci_tcp_getpeername(citp_socket* ep, struct sockaddr* name,
		       socklen_t* namelen)
{
  ci_sock_cmn* s = ep->s;
  int rc;

  CHECK_TEP_NNL(ep);

  /* If we're not connected... */
  if( ! (s->b.state & CI_TCP_STATE_SYNCHRONISED) ||
      s->b.state == CI_TCP_TIME_WAIT )
    CI_SET_ERROR(rc, ENOTCONN);
  else if( name == NULL || namelen == NULL )
    CI_SET_ERROR(rc, EFAULT);
  else {
    ci_addr_to_user(name, namelen, s->domain, 
                    S_TCP_HDR(s)->tcp_dest_be16, s->pkt.ip.ip_daddr_be32);
    rc = 0;
  }

  return rc;
}


#endif


/*! \cidoxg_end */
