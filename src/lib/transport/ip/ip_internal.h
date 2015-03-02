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
** \author  ctk
**  \brief  Decls & defs for IP library internal to our libraries.
**   \date  2004/02/02
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#ifndef __CI_LIB_IP_INTERNAL_H__
#define __CI_LIB_IP_INTERNAL_H__

#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>
#include <ci/net/ethernet.h>
#include <onload/ul/tcp_helper.h>
#ifdef __KERNEL__
# include <onload/oof_interface.h>
#endif
#ifndef __KERNEL__
#include <ci/internal/cplane_handle.h>
#endif
#include <ci/internal/cplane_ops.h>


#ifdef __KERNEL__
/* These types of messages can only be sent in user space and will
 * never be queued up to be sent at a later point or potentially by
 * the driver.  However, the driver compiles code that uses this
 * definition so just define it to 0.
 */
#define ONLOAD_MSG_WARM 0
#endif


/**********************************************************************
**************************** Logging etc. *****************************
**********************************************************************/

extern unsigned ci_tp_log CI_HV;
extern unsigned ci_tp_max_dump CI_HV;


#define log  ci_log


ci_inline unsigned ip_pkt_dump_len(unsigned len) {
  len += ETH_HLEN; /* ?? Cout VLAN tag as well ?? */
  if( len > ETH_FRAME_LEN )   len = 80;
#if defined(__ci_driver__)
  if( len > 80 ) len = 80;
#else
  if( len > ci_tp_max_dump )  len = ci_tp_max_dump;
#endif
  return len;
}


#ifdef __ci_driver__
/* definitions for installing/removing IP filters */
# include <onload/tcp_helper_endpoint.h>
# include <onload/tcp_helper_fns.h>
#endif


/*
** called with an RTT estimate to update SRTT, RTTVAR, RTO as in RFC2988
**
** We use Jacobson's SIGCOMM 88 convention with ts->sa holding SRTT
** scaled by 8 and ts->sv holding RTTVAR scaled by 4. ts->rto is the
** real number of ticks.
*/
ci_inline void ci_tcp_update_rtt(ci_netif* netif, ci_tcp_state* ts, int m)
{
  /* ?? Jacobson's algorithm assumes a signed number which might not
  ** be the same as ci_iptime_t, hmmm... what to do? */
  ci_assert_ge(m, 0);
  m = CI_MAX(1, m);

  if( CI_LIKELY(ts->sa) ) {
    /* See Jacobson's SIGCOMM 88 algorithm to calculate (2.3) of
    ** RFC2988
    */
    m -= (ts->sa >> 3u);
    ts->sa += m;          /* SRTT <- SRTT + 0.125*(M-SRTT)  */
    if( m < 0 ) m = -m;
    m -= (ts->sv >> 2u);
    ts->sv += m;          /* RTTVAR <- 0.75*RTTVAR + 0.25*|M-SRTT| */
    ts->rto = tcp_srtt(ts) + ts->sv;   /* RTO <- SRTT + 4*RTTVAR */
  }
  else {
    /* first rtt estimate so follow (2.2) of RFC2988 */
    ts->sa = (m << 3u);
    ts->sv = (m << 1u);
    ts->rto = m + ts->sv;
  }

  ci_tcp_rto_bound(netif, ts);

  CI_IP_SOCK_STATS_VAL_RTT_SRTT_RTO( ts, ts->sv >> 2, ts->sa >> 3, ts->rto );
  LOG_TR(ci_log("TCP RX %d UPDATE RTT sa=%u sv=%u SRTT=%u RTTVAR=%u RTO=%u",
	        S_FMT(ts), ts->sa, ts->sv,
	        tcp_srtt(ts), tcp_rttvar(ts), ts->rto));
}

/*
** Turn timestamps into cmsg entries.
*/
void ip_cmsg_recv_timestamp(ci_netif *ni, ci_uint64 timestamp, 
                                      struct cmsg_state *cmsg_state);
void ip_cmsg_recv_timestampns(ci_netif *ni, ci_uint64 timestamp, 
                                        struct cmsg_state *cmsg_state);
void ip_cmsg_recv_timestamping(ci_netif *ni,
      ci_uint64 sys_timestamp, struct timespec* hw_timestamp,
      int flags, struct cmsg_state *cmsg_state);


/**********************************************************************
******************************* Sleeping ******************************
**********************************************************************/

/* Macro for sleeping until [cond] is not true (or timeout, or error). */
/* TODO timeout should be re-calculated when looping */
#define CITP_WAITABLE_SLEEP_WHILE(ni, w, why, timeout, cond, prc) \
  do {								\
    ci_uint64 __sleep_seq;					\
    ci_uint32 t = (timeout);					\
    *(prc) = 0;							\
    while( 1 ) {						\
      __sleep_seq = (w)->sleep_seq.all;				\
      ci_rmb();							\
      if( !(cond) ) break;					\
      (*prc) = ci_sock_sleep((ni), (w), (why),			\
			     CI_SLEEP_NETIF_LOCKED |		\
			     CI_SLEEP_NETIF_RQ,			\
			     __sleep_seq, &t);		\
      /* TODO (Bug24547) handle case where netif lock fails */  \
      CI_TEST(ci_netif_lock(ni) == 0);                          \
      if( *(prc) )  break;					\
      ci_netif_poll(ni);					\
    }								\
  } while(0)


#define CI_TCP_SLEEP_WHILE(ni, ts, why, timeout, cond, prc)     \
  CITP_WAITABLE_SLEEP_WHILE((ni), &(ts)->s.b, (why), (timeout), (cond), (prc))


/**********************************************************************
******************************* Filters *******************************
**********************************************************************/

/*--------------------------------------------------------------------
 *!
 * Set all the filters needed for a TCP/UDP endpoint. This includes
 *    - hardware filters
 *    - filters in the software connection hash table
 *    - driverlink filters
 *
 * \param ni              ci_netif structure
 * \param sock_id         socket id
 * \param bindto_ifindex  ifindex from SO_BINDTODEVICE
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

ci_inline int
ci_tcp_ep_set_filters(ci_netif *        ni,
                      oo_sp             sock_id,
                      ci_ifid_t         bindto_ifindex,
                      oo_sp             from_tcp_id)
{
  int rc;

  ci_assert(ni);

  LOG_TC(ci_log("%s: %d:%d bindto_ifindex=%d port_sock=%d",
                __FUNCTION__, NI_ID(ni), OO_SP_FMT(sock_id),
                (int) bindto_ifindex, OO_SP_FMT(from_tcp_id)));

#ifdef __ci_driver__
  rc = tcp_helper_endpoint_set_filters(ci_netif_get_valid_ep(ni, sock_id),
                                       bindto_ifindex, from_tcp_id);

#else
  rc = ci_tcp_helper_ep_set_filters(ci_netif_get_driver_handle(ni), sock_id,
                                    bindto_ifindex, from_tcp_id);
#endif

  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}

#ifndef __ci_driver__
ci_inline int
ci_tcp_ep_reuseport_bind(ci_fd_t fd, const char* cluster_name,
                         ci_int32 cluster_size, ci_uint32 cluster_restart_opt,
                         ci_uint32 addr_be32, ci_uint16 port_be16)
{
  int rc;

  LOG_TC(ci_log("%s: %d addr_be32: %d port: %d", __FUNCTION__, fd, addr_be32,
                port_be16));
  rc = ci_tcp_helper_ep_reuseport_bind(fd, cluster_name, cluster_size,
                                       cluster_restart_opt, addr_be32,
                                       port_be16);
  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}
#endif

/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param ni              ci_netif structure
 * \param sock_id         id of socket
 * \param no_sw           non-zero if the s/w filter has already been removed
 *                        (e.g. if the EP was cached)
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

ci_inline int
ci_tcp_ep_clear_filters(ci_netif*         ni,
                        oo_sp             sock_id,
                        int               need_update)
{
  int rc;
#ifdef __ci_driver__
  int supress_hw_ops = ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT;
#endif
  ci_assert(ni);

  LOG_TC(ci_log("%s: %d:%d (%d)", __FUNCTION__,
                ni->state->stack_id, OO_SP_FMT(sock_id), need_update));
  ci_assert(ci_netif_is_locked(ni));

#ifdef __ci_driver__
  rc = tcp_helper_endpoint_clear_filters(ci_netif_get_valid_ep(ni, sock_id),
                                         supress_hw_ops, need_update);
#else
  rc = ci_tcp_helper_ep_clear_filters(ci_netif_get_driver_handle(ni), sock_id,
                                      need_update);
#endif

  LOG_TC( if (rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * Add multicast address to a socket list of multicast addresses. If the
 * socket is already bound, this function installs filters for this
 * address. If the socket is not bound, the function just add multicast
 * address to the list, and bind() should install the filter.
 * or
 * Delete a multicast address from a socket list of multicast addresses. 
 * If the socket is already bound, this function removes filters for this
 * address. If the socket is not bound, the function just deletes multicast
 * address from the list.
 *
 * \param ni              ci_netif structure
 * \param sock_id         socket id
 * \param sock_fd         OS socket file descriptor
 * \param phys_port       L5 physcial port index to use when joining the
 *                        group
 * \param mcast_addr      Multicast address to add to the socket list
 * \param add             add or delete multicast entry?
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

ci_inline int
ci_tcp_ep_mcast_add_del(ci_netif*         ni,
                        oo_sp             sock_id,
                        ci_ifid_t         ifindex,
                        ci_uint32         mcast_addr,
                        int               add)
{
  int rc;

  ci_assert(ni);

  LOG_TC(ci_log("%s: id=%d (ifid=%d, maddr=%s)",
                __FUNCTION__, OO_SP_FMT(sock_id), ifindex,
                ip_addr_str(mcast_addr)));

#ifdef __ci_driver__
  {
    tcp_helper_endpoint_t* ep = ci_netif_get_valid_ep(ni, sock_id);
    if( add )
      rc = oof_socket_mcast_add(efab_tcp_driver.filter_manager,
                                &ep->oofilter, mcast_addr, ifindex);
    else {
      oof_socket_mcast_del(efab_tcp_driver.filter_manager,
                           &ep->oofilter, mcast_addr, ifindex);
      rc = 0;
    }
  }
#else
  rc = ci_tcp_helper_ep_mcast_add_del(ci_netif_get_driver_handle(ni),
                                      sock_id, mcast_addr, ifindex, add);
#endif

  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}


/*********************************************************************
**************************** Debug support ***************************
*********************************************************************/

#ifdef __KERNEL__
# define verify_fail()  return
#else
# define verify_fail()  ci_fail(("STOP."))
#endif

#define verify(exp)							  \
  do{									  \
    if( CI_UNLIKELY(!(exp)) ) {						  \
      ci_log("********** verify(%s) at %s:%d", #exp, __FILE__, __LINE__); \
      ci_log("********** from %s:%d", file?file:"", line);		  \
      verify_fail();							  \
    }									  \
  }while(0)

#undef verify
#define verify(exp)  ci_assert(exp)


/*********************************************************************
**************************** Socket options **************************
*********************************************************************/

#ifndef SO_TIMESTAMPNS
# define SO_TIMESTAMPNS 35
#endif

#ifndef SO_REUSEPORT
# define SO_REUSEPORT   15
#endif

/* The following value needs to match its counterpart
 * in kernel headers.
 */
#define ONLOAD_SO_TIMESTAMPING 37
#define ONLOAD_SCM_TIMESTAMPING ONLOAD_SO_TIMESTAMPING

/* The following values need to match their counterparts in
 * linux kernel header linux/net_tstamp.h
 */
enum {
	ONLOAD_SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
	ONLOAD_SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
	ONLOAD_SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
	ONLOAD_SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
	ONLOAD_SOF_TIMESTAMPING_SOFTWARE = (1<<4),
	ONLOAD_SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
	ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
	ONLOAD_SOF_TIMESTAMPING_MASK =
	( (ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE << 1) - 1 )
};

/* The following value needs to match its counterpart
 * in kernel headers.
 */
#define ONLOAD_SO_BUSY_POLL 46

/* check [ov] is a non-NULL ptr & [ol] indicates the right space for
 * type [ty] */
#define opt_ok(ov,ol,ty)     ((ov) && (ol) >= sizeof(ty))
#define opt_not_ok(ov,ol,ty) \
    ((ol) < sizeof(ty) ? -EINVAL : (ov) ? 0 : -EFAULT)

#if defined(__KERNEL__) && defined(__linux__)
extern int ci_khelper_getsockopt(ci_netif* ni,  oo_sp sock_id, int level, 
				 int optname, char* optval, int* optlen ) CI_HF;
extern int ci_khelper_setsockopt(ci_netif* ni, oo_sp sock_id, int level, 
				 int optname, const void* optval, 
				 int optlen ) CI_HF;
#endif

ci_inline unsigned 
ci_get_optval(const void *optval, socklen_t optlen)
{
  if (optlen >= sizeof(unsigned))
    return (*(unsigned*)optval);
  else return (unsigned)(*(unsigned char*)optval);
}

/*! Do not call it, use ci_getsockopt_final(). */
ci_inline int
ci_getsockopt_final_pre(void *optval, socklen_t *optlen, int level,
                        void *val, size_t val_size)
{
  if( *optlen > 0 )
    memcpy(optval, val, CI_MIN(*optlen, val_size));
  if( *optlen > val_size )
    *optlen = val_size;
  /* TODO AFAIK, Solaris returns error if *optlen < val_size. */
  return 0;  
}

/*! Common getsockopt() part - push value to the user according to the
 * particular OS expectations. Return -1 with errno being set or 0.  */
ci_inline int
ci_getsockopt_final(void *optval, socklen_t *optlen, int level,
                    void *val, size_t val_size)
{
  if( (level == SOL_SOCKET || level == SOL_IP) &&
      val_size == sizeof(int) && 
      *optlen >= sizeof(char) && *optlen < sizeof(int) ) {
    int ival = *((int *)val);
    unsigned char ucval = (unsigned char)ival;
    if( ival >=0 && ival <= 255)
      return ci_getsockopt_final_pre(optval, optlen, level,
                                     &ucval, sizeof(ucval));
  }
  return ci_getsockopt_final_pre(optval, optlen, level,
                                 val, val_size);
}

/*! Handler for common getsockopt:SOL_IP options. The handlers here will
 * cope with both TCP & UDP.
 * \param netif   [in] Netif context
 * \param ts      [in] TCP state context
 * \param fd      [in] File descriptor
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_ip( citp_socket* netif, ci_sock_cmn* s, ci_fd_t fd,
			  int optname, void *optval,
			  socklen_t *optlen ) CI_HF;

#if CI_CFG_FAKE_IPV6
/*! Handler for common getsockopt:SOL_IPV6 options. The handlers here will
 * cope with both TCP & UDP.
 * \param ep      [in] Endpoint handle
 * \param ts      [in] TCP state context
 * \param fd      [in] File descriptor
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_ip6( citp_socket* ep, ci_sock_cmn* s, ci_fd_t fd,
                           int optname, void *optval, 
                           socklen_t *optlen ) CI_HF;
#endif

/*! Handler for common getsockopt:SOL_SOCKET options.
 * \param ni      [in] Netif context
 * \param ts      [in] TCP state context (regardless of the actual protocol)
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_socket( ci_netif* netif, ci_sock_cmn* s,
			      int optname, void *optval,
			      socklen_t *optlen ) CI_HF;

/*! Handler for common setsockopt:SOL_IP handlers.
 * \param netif   [in] Netif context
 * \param ts      [in] TCP state context
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_ip( ci_netif* netif, ci_sock_cmn* s,
	       int optname, const void *optval, socklen_t optlen) CI_HF;

#if CI_CFG_FAKE_IPV6
/*! Handler for common setsockopt:SOL_IPV6 handlers.
 * \param netif   [in] Netif context
 * \param ts      [in] TCP state context
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_ip6( ci_netif* netif, ci_sock_cmn* s,
	        int optname, const void *optval, socklen_t optlen) CI_HF;
#endif

/*! Handler for common setsockopt:SOL_SOCKET handlers.
 * \param netif   [in] Netif context
 * \param ts      [in] TCP state context (regardless of protocol)
 * \param os_rc   [in] Return code from callers setsockopt() on OS backing sock
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_socket( ci_netif* netif, ci_sock_cmn* s,
		   int optname, const void *optval, socklen_t optlen) CI_HF;

/*! Handles socket options that don't require the netif lock. */
extern int 
ci_set_sol_socket_nolock(ci_netif*, ci_sock_cmn* s, int optname,
			 const void *optval, socklen_t optlen) CI_HF;

/*********************************************************************
 ******************************* Ioctls ******************************
*********************************************************************/


#ifdef __KERNEL__
#define CI_IOCTL_ARG_OK(t,a) ({t _v; int _rc = get_user(_v, (t*)(a)); (void)_v; _rc==0;})
#define CI_IOCTL_SETARG(a,v) do { put_user(v,a); } while(0)
#define CI_IOCTL_GETARG(t,a) ({t _v; get_user(_v, (t*)(a)); _v; })
#else
#define CI_IOCTL_ARG_OK(t,a) ((a) != 0)
#define CI_IOCTL_SETARG(a,v) do { *(a)=(v); } while(0)
#define CI_IOCTL_GETARG(t,v) (*(t*)(v))
#endif

#if defined(__KERNEL) /* Bug 18959: should be __KERNEL__ */
/* Common handler for FIONBIO - called in per-protocol handler to 
 * keep the request efficient */
#define CI_CMN_IOCTL_FIONBIO(s, arg) do {                             \
  int v, _rc = get_user(v, arg);                                      \
  if( v ) {                                                           \
      LOG_SV( ci_log("%s: set non-blocking mode", __FUNCTION__ ) );   \
      ci_bit_set(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);      \
    } else {                                                          \
      LOG_SV( ci_log("%s: clear non-blocking mode", __FUNCTION__ ) ); \
      ci_bit_clear(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);    \
    } } while (0) 
#else
/* Common handler for FIONBIO - called in per-protocol handler to 
 * keep the request efficient */
#define CI_CMN_IOCTL_FIONBIO(s, arg) do {                             \
  if( *(int*)(arg) ) {                                                \
      LOG_SV( ci_log("%s: set non-blocking mode", __FUNCTION__ ) );   \
      ci_bit_set(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);      \
    } else {                                                          \
      LOG_SV( ci_log("%s: clear non-blocking mode", __FUNCTION__ ) ); \
      ci_bit_clear(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);    \
    } } while (0) 
#endif

/*! Common handler for IOCTL calls.
 * \param  netif    Context
 * \param  s        ci_sock_cmn context
 * \param  request  Ioctl request code from ioctl() intercept
 * \param  arg      Ioctl arg ptr from ioctl() intercept
 * \param  os_rc    Return from call-down to ioctl() for backing OS socket
 * \param  os_socket_exists Non-zero if OS socket extsts
 * \return          As for ioctl()
 */
extern int ci_cmn_ioctl(ci_netif* netif, ci_sock_cmn* s, int request, 
			void* arg, int os_rc, int os_socket_exists);

/*! Compute the time stamp delta for the given packet time stamp and
 *  return in in ts
 */
extern void ci_udp_compute_stamp(ci_netif *netif, ci_uint64 stamp,
                                 struct timespec *ts);




/* Return from getsockopt(level=SOL_INVALID) with appropriate errno */
# define SOCKOPT_RET_INVALID_LEVEL(s) \
    if ((s)->domain == AF_INET6 )   \
      RET_WITH_ERRNO(ENOPROTOOPT);  \
    else                            \
      RET_WITH_ERRNO(EOPNOTSUPP)

/*********************************************************************
 ***************************** Async IO ******************************
 *********************************************************************/


/* XXX find a better way to do this lot */

#if defined(__linux__) && !defined(ECANCELED)
#define ECANCELED 125
#endif


#if defined(__KERNEL__)
extern void ci_ip_queue_enqueue_nnl(ci_netif* netif, ci_ip_pkt_queue*qu,
				    ci_ip_pkt_fmt* pkt) CI_HF;
#endif
extern ci_ip_pkt_fmt* ci_pkt_alloc_n(ci_netif* ni, int n) CI_HF;
extern ci_ip_pkt_fmt* ci_pkt_alloc_n_nnl(ci_netif* ni, int n) CI_HF;



/*********************************************************************
 ******************************** UDP ********************************
 *********************************************************************/

/* The following two macros cope with Path MTU constraints and fragmentation
 * boundary requirements (multiple of 64 bits) */

/* How much payload space in a first fragment packet */
#define UDP_PAYLOAD1_SPACE_PMTU(pmtu)			\
  (((pmtu)-sizeof(ci_ip4_hdr)- sizeof(ci_udp_hdr))&0xfff8)

/* How much space in a second fragment packet */
#define UDP_PAYLOAD2_SPACE_PMTU(pmtu) (((pmtu)-sizeof(ci_ip4_hdr))&0xfff8)

#define UDP_HAS_SENDQ_SPACE(us,l) \
  ((us)->s.so.sndbuf >= (int)((us)->tx_count + (l)))


/* Linux sets twice the buffer size that the application requests. */
# define oo_adjust_SO_XBUF(v)  ((v) * 2)


/**********************************************************************
 * OO_SPINLOOP_PAUSE_CHECK_SIGNALS()
 */

#ifdef __KERNEL__

ci_inline int
oo_spinloop_pause_check_signals(ci_netif* ni, ci_uint64 now_frc,
                                ci_uint64* schedule_frc, int have_timeout)
{
  if(CI_UNLIKELY( signal_pending(current) ))
    return have_timeout ? -EINTR : -ERESTARTSYS;
  if( now_frc - *schedule_frc > IPTIMER_STATE(ni)->khz ) {
    schedule();                  /* schedule() every 1ms */
    *schedule_frc = now_frc;
  }
  return 0;
}

#define OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, schedule_frc,      \
                                        have_timeout, w, si)            \
  oo_spinloop_pause_check_signals(ni, now_frc, schedule_frc, have_timeout)

#else

#include "ci/internal/ip_signal.h"
extern int oo_spinloop_run_pending_sigs(ci_netif*, citp_waitable*,
                                        citp_signal_info*, int) CI_HF;

ci_inline int
oo_spinloop_pause_check_signals(ci_netif* ni, ci_uint64 now_frc,
                                ci_uint64* schedule_frc /*unused*/,
                                int have_timeout,
                                citp_waitable* w, citp_signal_info* si)
{
  ci_assert_gt(si->inside_lib, 0);
  ci_assert(~si->aflags & OO_SIGNAL_FLAG_FDTABLE_LOCKED);

  if(CI_LIKELY( ~si->aflags & OO_SIGNAL_FLAG_HAVE_PENDING )) {
    ci_spinloop_pause();
    return 0;
  }
  return oo_spinloop_run_pending_sigs(ni, w, si, have_timeout);
}

#define OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, schedule_frc,      \
                                        have_timeout, w, si)            \
  oo_spinloop_pause_check_signals(ni, now_frc, schedule_frc,            \
                                  have_timeout, w, si)

#endif


/*********************************************************************
 ******************************** Per-Thread *************************
 *********************************************************************/

#ifndef __KERNEL__
extern citp_init_thread_callback init_thread_callback CI_HV;
#endif


/*********************************************************************
 ******************************* Post Stripe *************************
 *********************************************************************/

#if CI_CFG_PORT_STRIPING
#define ci_ts_port_swap(seq, ts) ((seq / tcp_eff_mss(ts)) & 1)
#endif

ci_inline int ci_netif_intf_i_to_base_ifindex(ci_netif* ni, int intf_i)
{
  ci_hwport_id_t hwport;
  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  hwport = ni->state->intf_i_to_hwport[intf_i];
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  return cicp_fwd_hwport_to_base_ifindex(&CICP_MIBS(CICP_HANDLE(ni))->user,
                                         hwport);
}

#endif /* __CI_LIB_IP_INTERNAL_H__ */
/*! \cidoxg_end */
