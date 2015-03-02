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
** \author  djr/ctk/stg
**  \brief  UDP connection routines:
**          accept, bind, close, connect, shutdown, getpeername
**   \date  2003/06/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <onload/common.h>

#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif

#ifndef __KERNEL__
#include <ci/internal/efabcfg.h>
#endif

#define LPF "ci_udp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF

#define INADDR_ANY_BE32 (CI_BSWAPC_BE32(INADDR_ANY))

#ifndef __ci_driver__

#ifndef NDEBUG
static char * ci_udp_addr_str( ci_udp_state* us )
{
  static char buf[128];

  ci_assert(us);
  sprintf( buf, "L[%s:%d] R[%s:%d]",
	   ip_addr_str( udp_laddr_be32(us)), 
	   CI_BSWAP_BE16(udp_lport_be16(us)),
	   ip_addr_str( udp_raddr_be32(us)), 
	   CI_BSWAP_BE16(udp_rport_be16(us)) );
  return buf;
}
#define CI_UDP_EP_ADDR_STR(ep) \
  ci_udp_addr_str((ep)->state)

# define CI_UDPSTATE_SHOW(us) \
      LOG_UV(log( "%s: %d UDP %s Fl[%s]", \
        __FUNCTION__, S_FMT(us), \
        ci_udp_addr_str((us)), \
        UDP_GET_FLAG((us), CI_UDPF_FILTERED) ? "Flt " : "" \
      ))

#define CI_UDPSTATE_SHOW_EP(ep) \
    CI_UDPSTATE_SHOW( SOCK_TO_UDP((ep)->s) )

#else

# define CI_UDPSTATE_SHOW(us)
# define CI_UDPSTATE_SHOW_EP(ep)

#endif


/* Encapsulation of sys_getsockname for UDP EPs */
static int ci_udp_sys_getsockname( ci_fd_t sock, citp_socket* ep )
{
  socklen_t salen;
  int rc;
  union ci_sockaddr_u sa_u;

  ci_assert(ep);
#if CI_CFG_FAKE_IPV6
  ci_assert(ep->s->domain == AF_INET || ep->s->domain == AF_INET6);
#else
  ci_assert(ep->s->domain == AF_INET);
#endif

  salen = sizeof(sa_u);

  rc = ci_sys_getsockname( sock, &sa_u.sa, &salen );
  if( rc )
    return rc;

  if( sa_u.sa.sa_family != ep->s->domain || salen < sizeof(struct sockaddr_in)
#if CI_CFG_FAKE_IPV6
      || (ep->s->domain == AF_INET6 && salen < sizeof(struct sockaddr_in6) )
#endif
      ) {
    LOG_UV(log("%s: OS sock domain %d != expected domain %d or "
               "sys_getsockname struct small (%d exp %d)",
               __FUNCTION__, sa_u.sa.sa_family, ep->s->domain,
               salen, 
               (int)(ep->s->domain == AF_INET ? sizeof(struct sockaddr_in) :
                sizeof(struct sockaddr_in6))));
    return -1;
  }

#if CI_CFG_FAKE_IPV6
  if( ep->s->domain == AF_INET ) {
    ci_udp_set_laddr( ep, ci_get_ip4_addr(sa_u.sa.sa_family, &sa_u.sa), 
                      sa_u.sin.sin_port );
  }
  else {
    ci_udp_set_laddr( ep, ci_get_ip4_addr(sa_u.sa.sa_family, &sa_u.sa), 
                      sa_u.sin6.sin6_port );
  }
#else
  ci_udp_set_laddr( ep, ci_get_ip4_addr(sa_u.sa.sa_family, &sa_u.sa), 
                    sa_u.sin.sin_port );
#endif
  return 0;
}

/* Wrapper for call down to OS disconnect. */
ci_inline int ci_udp_sys_disconnect( ci_fd_t sock, citp_socket* ep )
{
  struct sockaddr_in sin;
  
  sin.sin_family = AF_UNSPEC;
  return ci_sys_connect( sock, (struct sockaddr*)&sin, sizeof(sin) );
}


static void ci_udp_clr_filters(citp_socket* ep)
{
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  if( UDP_GET_FLAG(us, CI_UDPF_FILTERED) ) {
    ci_tcp_ep_clear_filters(ep->netif, S_SP(us), 0);
    UDP_CLR_FLAG(us, CI_UDPF_FILTERED);
  }
}


static int ci_udp_set_filters(citp_socket* ep, ci_udp_state* us)
{
  int rc;

  ci_assert(ep);
  ci_assert(us);

  if( udp_lport_be16(us) == 0 )
    return 0;

  rc = ci_tcp_ep_set_filters(ep->netif, S_SP(us), us->s.cp.so_bindtodevice, 
                             OO_SP_NULL);
  if( rc == -EFILTERSSOME ) {
    if( CITP_OPTS.no_fail )
      rc = 0;
    else {
      ci_tcp_ep_clear_filters(ep->netif, S_SP(us), 0);
      rc = -ENOBUFS;
    }
  }
  if( rc < 0 ) {
    LOG_UC(log(FNS_FMT "ci_tcp_ep_set_filters failed (%d)",
               FNS_PRI_ARGS(ep->netif, ep->s), -rc));
    CI_SET_ERROR(rc, -rc);
    return rc;
  }
  UDP_SET_FLAG(us, CI_UDPF_FILTERED);
  return 0;
}


/* ******************************************************************
 * Interface
 */

int ci_udp_should_handover(citp_socket* ep, const struct sockaddr* addr,
                           ci_uint16 lport)
{
  ci_uint32 addr_be32;

#if CI_CFG_FAKE_IPV6
  if( ep->s->domain == AF_INET6 && ! ci_tcp_ipv6_is_ipv4(addr) )
    goto handover;
#endif

  if( (CI_BSWAP_BE16(lport) >= NI_OPTS(ep->netif).udp_port_handover_min &&
       CI_BSWAP_BE16(lport) <= NI_OPTS(ep->netif).udp_port_handover_max) ||
      (CI_BSWAP_BE16(lport) >= NI_OPTS(ep->netif).udp_port_handover2_min &&
       CI_BSWAP_BE16(lport) <= NI_OPTS(ep->netif).udp_port_handover2_max) ||
      (CI_BSWAP_BE16(lport) >= NI_OPTS(ep->netif).udp_port_handover3_min &&
       CI_BSWAP_BE16(lport) <= NI_OPTS(ep->netif).udp_port_handover3_max) ) {
    LOG_UC(log(FNS_FMT "HANDOVER (%d <= %d <= %d)",
               FNS_PRI_ARGS(ep->netif, ep->s),
               NI_OPTS(ep->netif).udp_port_handover_min,
               CI_BSWAP_BE16(lport),
               NI_OPTS(ep->netif).udp_port_handover_max));
    goto handover;
  }

  addr_be32 = ci_get_ip4_addr(ep->s->domain, addr);
  if( addr_be32 != CI_BSWAPC_BE32(INADDR_ANY) &&
      ! cicp_user_addr_is_local_efab(CICP_HANDLE(ep->netif), &addr_be32) && 
      ! CI_IP_IS_MULTICAST(addr_be32) ) {
    /* Either the bind/getsockname indicated that we need to let the OS
      * take this or the local address is not one of ours - so we can safely
      * hand-over as bind to a non-ANY addr cannot be revoked.
      * The filters (if any) have already been removed, so we just get out. */
    goto handover;
  }

  return 0;
 handover:
  return 1;
}

/* Conclude the EP's binding.  This function is abstracted from the
 * main bind code to allow implicit binds that occur when sendto() is
 * called on an OS socket.  [lport] and CI_SIN(addr)->sin_port do not
 * have to be the same value. */
static int ci_udp_bind_conclude(citp_socket* ep, const struct sockaddr* addr,
                                ci_uint16 lport )
{
  ci_udp_state* us;
  ci_uint32 addr_be32;
  int rc;

  CHECK_UEP(ep);
  ci_assert(addr != NULL);

  if( ci_udp_should_handover(ep, addr, lport) )
    goto handover;

  addr_be32 = ci_get_ip4_addr(ep->s->domain, addr);

  ci_udp_set_laddr(ep, addr_be32, lport);
  us = SOCK_TO_UDP(ep->s);
  if( addr_be32 != 0 )
    us->s.cp.sock_cp_flags |= OO_SCP_LADDR_BOUND;
  /* reset any rx/tx that have taken place already */
  UDP_CLR_FLAG(us, CI_UDPF_EF_SEND);

#ifdef ONLOAD_OFE
    if( ep->netif->ofe != NULL )
      us->s.ofe_code_start = ofe_socktbl_find(
                        ep->netif->ofe, OFE_SOCKTYPE_UDP,
                        udp_laddr_be32(us), udp_raddr_be32(us),
                        udp_lport_be16(us), udp_rport_be16(us));
#endif

  /* OS source addrs have already been handed-over, so this must be one of
   * our src addresses.
   */
  rc = ci_udp_set_filters( ep, us);
  ci_assert( !UDP_GET_FLAG(us, CI_UDPF_EF_BIND) );
  /*! \todo FIXME isn't the port the thing to be testing here? */
  if( udp_laddr_be32(us) != INADDR_ANY_BE32 )
    UDP_SET_FLAG(us, CI_UDPF_EF_BIND);
  CI_UDPSTATE_SHOW_EP( ep );
  if( rc == CI_SOCKET_ERROR && CITP_OPTS.no_fail) {
    CITP_STATS_NETIF(++ep->netif->state->stats.udp_bind_no_filter);
    goto handover;
  }
  return rc;

 handover:
  LOG_UV(log("%s: "SK_FMT" HANDOVER", __FUNCTION__, SK_PRI_ARGS(ep)));
  return CI_SOCKET_HANDOVER;
}


void ci_udp_handle_force_reuseport(ci_fd_t fd, citp_socket* ep,
                                   const struct sockaddr* sa, socklen_t sa_len)
{
  int rc;

  if( CITP_OPTS.udp_reuseports != 0 &&
      ((struct sockaddr_in*)sa)->sin_port != 0 ) {
    struct ci_port_list *force_reuseport;
    CI_DLLIST_FOR_EACH2(struct ci_port_list, force_reuseport, link,
                        (ci_dllist*)(ci_uintptr_t)CITP_OPTS.udp_reuseports) {
      if( force_reuseport->port == ((struct sockaddr_in*)sa)->sin_port ) {
        int one = 1;
        ci_fd_t os_sock = ci_get_os_sock_fd(ep, fd);
        ci_assert(CI_IS_VALID_SOCKET(os_sock));
        rc = ci_sys_setsockopt(os_sock, SOL_SOCKET, SO_REUSEPORT, &one,
                               sizeof(one));
        ci_rel_os_sock_fd(os_sock);
        if( rc != 0 && errno == ENOPROTOOPT )
          ep->s->s_flags |= CI_SOCK_FLAG_REUSEPORT_LEGACY;
        ep->s->s_flags |= CI_SOCK_FLAG_REUSEPORT;
        LOG_UC(log("%s "SF_FMT", applied legacy SO_REUSEPORT flag for port %u",
                   __FUNCTION__, SF_PRI_ARGS(ep, fd), force_reuseport->port));
      }
    }
  }
}


/* Set a reuseport bind on a socket.
 */
int ci_udp_reuseport_bind(citp_socket* ep, ci_fd_t fd,
                          const struct sockaddr* sa, socklen_t sa_len)
{
  int rc;
  ci_uint32 laddr_be32 = ci_get_ip4_addr(ep->s->domain, sa);
  int lport_be16 = ((struct sockaddr_in*)sa)->sin_port;
  ci_assert_nequal(ep->s->s_flags & CI_SOCK_FLAG_REUSEPORT, 0);

  /* We cannot support binding to port 0 as the kernel would assign
   * the socket a port number.  We must move the socket before binding
   * the OS socket and we don't have a port number to look up
   * clusters.
   */
  if( lport_be16 == 0 ) {
    LOG_UC(ci_log("%s: Binding to port 0 with reuseport set not supported",
                  __FUNCTION__));
    RET_WITH_ERRNO(ENOSYS);
  }

  /* If we don't have SO_REUSEPORT support in the kernel then we can't allow
   * clustered sockets to be handed over - they're sharing an os socket.
   * We don't allow implicit reuseport bind, so we can see now whether we'd
   * have to handover.
   *
   * Legacy reuseport: This could still change before bind conclusion.
   */
  if( (ep->s->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY) &&
      ci_udp_should_handover(ep, sa, lport_be16) ) {
    LOG_U(ci_log("%s: Binding would result in handover, which is not supported"
                 " on kernels that do not support SO_REUSEPORT", __FUNCTION__));
    RET_WITH_ERRNO(ENOSYS);
  }

  if( (rc = ci_tcp_ep_reuseport_bind(fd, CITP_OPTS.cluster_name,
                                     CITP_OPTS.cluster_size,
                                     CITP_OPTS.cluster_restart_opt, laddr_be32,
                                     lport_be16)) != 0 ) {
    errno = -rc;
    return -1;
  }
  return rc;
}


/* To handle bind we just let the underlying OS socket make all
 * of the decisions for us.  If The bind leaves things such that
 * the source address is not one of ours then we hand it over to the
 * OS (by returning CI_SOCKET_HANDOVER) - in which case the OS socket 
 * will be bound as expected. */
int ci_udp_bind(citp_socket* ep, ci_fd_t fd, const struct sockaddr* addr,
		socklen_t addrlen)
{
  int rc;
  ci_uint16 local_port;

  CHECK_UEP(ep);
  LOG_UC(log("%s("SF_FMT", addrlen=%d)", __FUNCTION__,
             SF_PRI_ARGS(ep,fd), addrlen));

  /* Make sure we have no filters.
   *
   * ?? TODO: Under what circumstances could we possibly have filters here?
   * _WIN32 only perhaps?
   */
  ci_udp_clr_filters(ep);

  /* If the OS doesn't support reuseport we need to allow the clustering code
   * to decide whether to bind the OS socket.
   */
  if( ! (ep->s->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY) ) {
    rc = ci_tcp_helper_bind_os_sock(ep->netif, SC_SP(ep->s), addr,
                                    addrlen, &local_port);
  }
  else {
    local_port = ((struct sockaddr_in*)addr)->sin_port;
    rc = 0;
  }

  if( rc == CI_SOCKET_ERROR )
    return rc;
  return ci_udp_bind_conclude(ep, addr, local_port );
}


static void ci_udp_set_raddr(ci_udp_state* us, unsigned raddr_be32,
                             int rport_be16)
{
  ci_ip_cache_invalidate(&us->s.pkt);
  udp_raddr_be32(us) = raddr_be32;
  udp_rport_be16(us) = (ci_uint16) rport_be16; 
  us->s.pkt.dport_be16 = (ci_uint16) rport_be16;
}


# define IS_DISCONNECTING(sin)  ( (sin)->sin_family == AF_UNSPEC )


static int
ci_udp_disconnect(citp_socket* ep, ci_udp_state* us, ci_fd_t os_sock)
{
  int rc;

  if( (rc = ci_udp_sys_getsockname(os_sock, ep)) != 0 ) {
    LOG_E(log(FNS_FMT "ERROR: sys_getsockname failed (%d)",
              FNS_PRI_ARGS(ep->netif, ep->s), errno));
    return rc;
  }
  ci_udp_set_raddr(us, 0, 0);
  /* TODO: We shouldn't really clear then set here; instead we should
   * insert wildcard filters before removing the full-match ones.  ie. The
   * reverse of what we do in connect().  But probably not worth worrying
   * about in this case.
   */
  ci_udp_clr_filters(ep);

#ifdef ONLOAD_OFE
    if( ep->netif->ofe != NULL )
      us->s.ofe_code_start = ofe_socktbl_find(
                        ep->netif->ofe, OFE_SOCKTYPE_UDP,
                        udp_laddr_be32(us), udp_raddr_be32(us),
                        udp_lport_be16(us), udp_rport_be16(us));
#endif

  if( (rc = ci_udp_set_filters(ep, us)) != 0 )
    /* Not too bad -- should still get packets via OS socket. */
    LOG_U(log(FNS_FMT "ERROR: ci_udp_set_filters failed (%d)",
              FNS_PRI_ARGS(ep->netif, ep->s), errno));
  us->s.cp.sock_cp_flags &= ~OO_SCP_CONNECTED;
  return 0;
}


/* Complete a UDP U/L connect.  The sys connect() call must have been made
 * (and succeeded) before calling this function.  So if anything goes wrong
 * in here, then it can be consider an internal error or failing of onload.
 */
int ci_udp_connect_conclude(citp_socket* ep, ci_fd_t fd,
                            const struct sockaddr* serv_addr, 
                            socklen_t addrlen, ci_fd_t os_sock)
{
  const struct sockaddr_in* serv_sin = (const struct sockaddr_in*) serv_addr;
  ci_uint32 dst_be32;
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  int onloadable;
  int rc = 0;

  CHECK_UEP(ep);

  UDP_CLR_FLAG(us, CI_UDPF_EF_SEND);
  us->s.rx_errno = 0;
  us->s.tx_errno = 0;           

  if( IS_DISCONNECTING(serv_sin) ) {
    rc = ci_udp_disconnect(ep, us, os_sock);
    goto out;
  }
#if CI_CFG_FAKE_IPV6
  if( us->s.domain == PF_INET6 && !ci_tcp_ipv6_is_ipv4(serv_addr) ) {
    LOG_UC(log(FNT_FMT "HANDOVER not IPv4", FNT_PRI_ARGS(ep->netif, us)));
    goto handover;
  }
#endif

  dst_be32 = ci_get_ip4_addr(serv_sin->sin_family, serv_addr);
  if( (rc = ci_udp_sys_getsockname(os_sock, ep)) != 0 ) {
    LOG_E(log(FNT_FMT "ERROR: (%s:%d) sys_getsockname failed (%d)",
              FNT_PRI_ARGS(ep->netif, us), ip_addr_str(dst_be32),
              CI_BSWAP_BE16(serv_sin->sin_port), errno));
    goto out;
  }

  us->s.cp.sock_cp_flags |= OO_SCP_CONNECTED;
  ci_udp_set_raddr(us, dst_be32, serv_sin->sin_port);
  cicp_user_retrieve(ep->netif, &us->s.pkt, &us->s.cp);

  switch( us->s.pkt.status ) {
  case retrrc_success:
  case retrrc_nomac:
    onloadable = 1;
    break;
  default:
    onloadable = 0;
    if( NI_OPTS(ep->netif).udp_connect_handover ) {
      LOG_UC(log(FNT_FMT "HANDOVER %s:%d", FNT_PRI_ARGS(ep->netif, us),
                 ip_addr_str(dst_be32), CI_BSWAP_BE16(serv_sin->sin_port)));
      goto handover;
    }
    break;
  }

  if( dst_be32 == INADDR_ANY_BE32 || serv_sin->sin_port == 0 ) {
    LOG_UC(log(FNT_FMT "%s:%d - route via OS socket",
               FNT_PRI_ARGS(ep->netif, us), ip_addr_str(dst_be32),
               CI_BSWAP_BE16(serv_sin->sin_port)));
    ci_udp_clr_filters(ep);
    return 0;
  }
  if( CI_IP_IS_LOOPBACK(dst_be32) ) {
    /* After connecting via loopback it is not possible to connect anywhere
     * else.
     */
    LOG_UC(log(FNT_FMT "HANDOVER %s:%d", FNT_PRI_ARGS(ep->netif, us),
               ip_addr_str(dst_be32), CI_BSWAP_BE16(serv_sin->sin_port)));
    goto handover;
  }

  if( onloadable ) {
#ifdef ONLOAD_OFE
    if( ep->netif->ofe != NULL )
      us->s.ofe_code_start = ofe_socktbl_find(
                        ep->netif->ofe, OFE_SOCKTYPE_UDP,
                        udp_laddr_be32(us), udp_raddr_be32(us),
                        udp_lport_be16(us), udp_rport_be16(us));
#endif

    if( (rc = ci_udp_set_filters(ep, us)) != 0 ) {
      /* Failed to set filters.  Most likely we've run out of h/w filters.
       * Handover to O/S to avoid breaking the app.
       *
       * TODO: Actually we probably won't break the app if we don't
       * handover, as packets will still get delivered via the kernel
       * stack.  Might be worth having a runtime option to choose whether
       * or not to handover in such cases.
       */
      LOG_U(log(FNT_FMT "ERROR: (%s:%d) ci_udp_set_filters failed (%d)",
                FNT_PRI_ARGS(ep->netif, us), ip_addr_str(dst_be32),
                CI_BSWAP_BE16(serv_sin->sin_port), rc));
      CITP_STATS_NETIF(++ep->netif->state->stats.udp_connect_no_filter);
      goto out;
    }
  }
  else {
    ci_udp_clr_filters(ep);
  }

  LOG_UC(log(LPF "connect: "SF_FMT" %sCONNECTED L:%s:%u R:%s:%u (err:%d)",
	     SF_PRI_ARGS(ep,fd), udp_raddr_be32(us) ? "" : "DIS",
	     ip_addr_str(udp_laddr_be32(us)),
	     (unsigned) CI_BSWAP_BE16(udp_lport_be16(us)),
	     ip_addr_str(udp_raddr_be32(us)),
	     (unsigned) CI_BSWAP_BE16(udp_rport_be16(us)), errno));
  return 0;

 out:
  if( rc < 0 && CITP_OPTS.no_fail )
    goto handover;
  return rc;

 handover:
  ci_udp_clr_filters(ep);
  return CI_SOCKET_HANDOVER;
}


/* create a pt->pt association with a server
 * This uses the OS to do all the work so that we don't have to emulate
 * some of the more unpleasant "tricks" of Linux.
 *
 * When we're either handing-over OS-dest connects or when we're "no 
 * failing" connects we may return -2 (unhandled). In this case the
 * OS socket _has_ been connected & we therefore are handing-over to
 * a socket in the right state.
 *
 * NOTE: WINDOWS the WSPConnect() API is quite a lot more complex than
 * the BSD one.  Therefore, to stop polluting the core code with masses
 * of Windows frippery, the backing socket connection is successfully 
 * established _before_ this function is called.  This function will use 
 * the state of the backing socket to configure the Efab socket - so the 
 * end result is the same (right down to the race between the OS socket 
 * connection being established and our filters being inserted).
 */
int ci_udp_connect(citp_socket* ep, ci_fd_t fd,
		   const struct sockaddr* serv_addr, socklen_t addrlen )
{
  int rc;
  ci_fd_t  os_sock;

  CHECK_UEP(ep);
  LOG_UC(log("%s("SF_FMT", addrlen=%d)", __FUNCTION__,
             SF_PRI_ARGS(ep,fd), addrlen));

  if( ep->s->s_flags & CI_SOCK_FLAG_REUSEPORT_LEGACY ) {
    ci_log("%s: Connecting a UDP socket with SO_REUSEPORT set is not supported"
           " where the kernel does not support SO_REUSEPORT.", __FUNCTION__);
    return -1;
  }

  os_sock = ci_get_os_sock_fd (ep, fd);
  if( !CI_IS_VALID_SOCKET( os_sock ) ) {
    LOG_U(ci_log("%s: no backing socket", __FUNCTION__));
    return -1;
  }

  /* Because we have not handed over the fd to the OS all calls to bind()
   * and connect() will have been seen by us - therefore our copies of
   * the local/remote address & port will be accurate. */

  /* Let the OS do the connection - it'll also do the data validation
   * for free. On failure the OS changes nothing - therefore we
   * need to leave the filters in place (if such they were).
   * Because the OS socket and our socket are socket-options-synchronized,
   * the following call will also check the supplied address according to
   * the SO_BROADCAST socket option settings. */
  rc = ci_sys_connect(os_sock, serv_addr, addrlen);
  if( rc != 0 ) {
    LOG_U(log("%s: sys_connect failed errno:%d", __FUNCTION__, errno));
    ci_rel_os_sock_fd(os_sock);
    return -1;
  }

  rc = ci_udp_connect_conclude( ep, fd, serv_addr, addrlen, os_sock);
  ci_rel_os_sock_fd(os_sock);
  return rc;
}


int __ci_udp_shutdown(ci_netif* netif, ci_udp_state* us, int how)
{
  ci_assert(netif);
  ci_assert(us);
  
  /* On Windows you can shutdown socket even if it is not connected */
  if( udp_raddr_be32(us) == 0 )
    return -ENOTCONN;
  /* Maybe ESHUTDOWN is suitable, but Linux returns EPIPE */
  switch( how ) {
  case SHUT_RD:
    us->s.rx_errno |= CI_SHUT_RD;
    break;
  case SHUT_WR:
    us->s.rx_errno |= CI_SHUT_WR;
    us->s.tx_errno = EPIPE;
    break;
  case SHUT_RDWR:
    us->s.rx_errno |= (CI_SHUT_RD | CI_SHUT_WR);
    us->s.tx_errno = EPIPE;
    ci_assert(UDP_IS_SHUT_RDWR(us));
    break;
  default:
    ci_fail(("'how' parameter of shutdown() must be verified earlier"));
    return -EINVAL;
  }
  /* shutdown() must not disconnect */
  return 0;  
}

#endif /* !__ci_driver__ */


#ifndef __ci_driver__

int ci_udp_shutdown(citp_socket* ep, ci_fd_t fd, int how)
{
  ci_fd_t  os_sock;
  int rc;

  CHECK_UEP(ep);
  LOG_UV(log(LPF "shutdown("SF_FMT", %d)", SF_PRI_ARGS(ep,fd), how));

  os_sock = ci_get_os_sock_fd (ep, fd);

  if( CI_IS_VALID_SOCKET( os_sock ) ) {
    rc = ci_sys_shutdown(os_sock, how);
    ci_rel_os_sock_fd( os_sock );
    if( rc < 0 )
      return CI_SOCKET_ERROR;
  }

  rc = __ci_udp_shutdown(ep->netif, SOCK_TO_UDP(ep->s), how);
  
  if( rc < 0 ) {
    CI_SET_ERROR(rc, -rc);
    return rc;
  }
  return 0;
}


/*! \todo we can simplify this a lot by letting the kernel have it! */
int ci_udp_getpeername(citp_socket*ep, struct sockaddr* name, socklen_t* namelen)
{
  ci_udp_state* us;
  
  CHECK_UEP(ep);
  
  us = SOCK_TO_UDP(ep->s);

  /*
   * At first, it's necessary to check whether socket is connected or
   * not, since we can return ENOTCONN even if name and/or namelen are
   * not valid.
   */
  if( udp_raddr_be32(us) == 0 ) {
    RET_WITH_ERRNO(ENOTCONN);
  } else if( name == NULL || namelen == NULL ) {
    RET_WITH_ERRNO(EFAULT);
  } else {
    ci_addr_to_user(name, namelen, ep->s->domain, 
                    udp_rport_be16(us), udp_raddr_be32(us));
    return 0;
  }
}

#endif /* !__ci_driver__*/


#ifdef __ci_driver__

void ci_udp_all_fds_gone(ci_netif* netif, oo_sp sock_id, int do_free)
{
  /* All process references to this socket have gone.  So we should
   * shutdown() if necessary, and arrange for all resources to eventually
   * get cleaned up.
   *
   * This is called by the driver only.  [sock_id] is trusted.
   */
  ci_udp_state* us = SP_TO_UDP(netif, sock_id);

  ci_assert(ci_netif_is_locked(netif));
  ci_assert(us->s.b.state == CI_TCP_STATE_UDP);

  LOG_UC(ci_log("ci_udp_all_fds_gone: "NTS_FMT, 
		NTS_PRI_ARGS(netif, us)));

  if( UDP_GET_FLAG(us, CI_UDPF_FILTERED) ) {
    UDP_CLR_FLAG(us, CI_UDPF_FILTERED);
    ci_tcp_ep_clear_filters(netif, S_SP(us), 0);
  }
  ci_udp_recv_q_drop(netif, &us->recv_q);
  ci_ni_dllist_remove(netif, &us->s.reap_link);

  if( OO_PP_NOT_NULL(us->zc_kernel_datagram) ) {
    ci_netif_pkt_release_rx(netif, PKT_CHK(netif, us->zc_kernel_datagram));
    us->zc_kernel_datagram = OO_PP_NULL;
    us->zc_kernel_datagram_count = 0;
  }

  /* Only free state if no outstanding tx packets: otherwise it'll get
   * freed by the tx completion event.
   */
  if( do_free ) {
    if( us->tx_count == 0 )
      ci_udp_state_free(netif, us);
    else
      CITP_STATS_NETIF_INC(netif, udp_free_with_tx_active);
  }
}

#endif /* __ci_driver__ */
