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
**  \brief  UDP socket initialisation & and cached data update utils.
**   \date  2003/12/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/cplane_ops.h> /* for ip.h ci_ip_cache_init */


#define LPF "ci_udp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF

#define VERB(x)


#ifndef __KERNEL__

/* Set up ip4/udp headers.  The dest addr and ports are not set and 
 * there are no IP options.  The source port is defaulted to port 0 
 */
static void ci_udp_hdrs_init(ci_ip_cached_hdrs* ipcache)
{
  /* Caller should already have done ci_ip_cache_init(). */
  ci_ip_hdr_init_fixed(&ipcache->ip, IPPROTO_UDP,
                       CI_IP_DFLT_TTL, CI_IP_DFLT_TOS);
  ipcache->ip.ip_saddr_be32 = 0;
  ipcache->ip.ip_daddr_be32 = 0;
}


/* initialise all the fields that we can in the UDP state structure.  
** There are no IP options, no destination addresses, no ports */
static void ci_udp_state_init(ci_netif* netif, ci_udp_state* us)
{
  ci_sock_cmn_init(netif, &us->s);

  /* IP_MULTICAST_LOOP is 1 by default, so we should not send multicast
   * unless specially permitted */
  if( ! NI_OPTS(netif).force_send_multicast )
    us->s.cp.sock_cp_flags |= OO_SCP_NO_MULTICAST;

  /* Poison. */
  CI_DEBUG(memset(&us->s + 1, 0xf0, (char*) (us + 1) - (char*) (&us->s + 1)));

  /*! \todo This should be part of sock_cmn reinit, but the comment to that
   * function suggests that it's possibly not a good plan to move it there */

  /*! \todo These two should really be handled in ci_sock_cmn_init() */

  /* Make sure we don't hit any state assertions. Can use
   *  UDP_STATE_FROM_SOCKET_EPINFO() after this. */
  us->s.b.state = CI_TCP_STATE_UDP;

  us->s.so.sndbuf = NI_OPTS(netif).udp_sndbuf_def;
  us->s.so.rcvbuf = NI_OPTS(netif).udp_rcvbuf_def;

  /* Init the ip-caches (packet header templates). */
  ci_udp_hdrs_init(&us->s.pkt);
  ci_ip_cache_init(&us->ephemeral_pkt);
  ci_udp_hdrs_init(&us->ephemeral_pkt);
  udp_lport_be16(us) = 0;
  udp_rport_be16(us) = 0;

#if CI_CFG_ZC_RECV_FILTER
  us->recv_q_filter = 0;
  us->recv_q_filter_arg = 0;
#endif
  ci_udp_recv_q_init(&us->recv_q);
  us->zc_kernel_datagram = OO_PP_NULL;
  us->zc_kernel_datagram_count = 0;
  us->tx_async_q = CI_ILL_END;
  oo_atomic_set(&us->tx_async_q_level, 0);
  us->tx_count = 0;
  us->udpflags = CI_UDPF_MCAST_LOOP;
  us->stamp = 0;
  memset(&us->stats, 0, sizeof(us->stats));

  /* initialise the emphemeral ip cache */
  ci_pmtu_state_init(netif, &us->s, &us->ephemeral_pkt.pmtus,
                     CI_IP_TIMER_PMTU_DISCOVER_2);
}


static ci_udp_state* ci_udp_get_state_buf(ci_netif* netif)
{
  citp_waitable_obj* wo;

  ci_assert(netif);

  wo = citp_waitable_obj_alloc(netif);
  if( wo ) {
    ci_udp_state_init(netif, &wo->udp);
    return &wo->udp;
  }
  return NULL;
}

/* *******************************
** Public interface
*/

#ifndef __ci_driver__
ci_fd_t ci_udp_ep_ctor(citp_socket* ep, ci_netif* netif, int domain, int type)
{
  ci_udp_state* us;
  ci_fd_t fd;

  VERB( log(LPFIN "ctor( )" ) );

  ci_assert(ep);
  ci_assert(netif);

  ci_netif_lock(netif);
  us = ci_udp_get_state_buf(netif);
  if (!us) {
    ci_netif_unlock(netif);
    LOG_E(ci_log("%s: [%d] out of socket buffers", __FUNCTION__,NI_ID(netif)));
    return -ENOMEM;
  }

  /* It's required to set protocol before ci_tcp_helper_sock_attach()
   * since it's used to determine if TCP or UDP file operations should be
   * attached to the file descriptor in kernel. */
  sock_protocol(&us->s) = IPPROTO_UDP;

  /* NB: this attach will close the os_sock_fd */
  fd = ci_tcp_helper_sock_attach(ci_netif_get_driver_handle(netif),  
                                 SC_SP(&us->s), domain, type);
  if( fd < 0 ) {
    LOG_E(ci_log("%s: ci_tcp_helper_sock_attach(domain=%d, type=%d) failed %d",
                 __FUNCTION__, domain, type, fd));
    ci_udp_state_free(netif, us);
    ci_netif_unlock(netif);
    return fd;
  }

  ci_assert(~us->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);

  us->s.rx_errno = 0;
  us->s.tx_errno = 0;
  us->s.so_error = 0;

  ep->s = &us->s;
  ep->netif = netif;
  CHECK_UEP(ep);
  ci_netif_unlock(netif);
  return fd;
}
#endif


void ci_udp_set_laddr(citp_socket* ep, unsigned laddr_be32, int lport_be16)
{
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  udp_laddr_be32(us) = laddr_be32;
  udp_lport_be16(us) = (ci_uint16) lport_be16;
  if( CI_IP_IS_MULTICAST(laddr_be32) )
    us->s.cp.ip_laddr_be32 = 0;
  else
    us->s.cp.ip_laddr_be32 = laddr_be32;
  us->s.cp.lport_be16 = lport_be16;
}


/* Get the IP TOS */
ci_uint8 ci_udp_get_tos( ci_udp_state* us )
{
  return UDP_IP_HDR(us)->ip_tos;
}

/* Set the IP TOS */
void ci_udp_set_tos( ci_udp_state* us, ci_uint32 tos )
{
  ci_ip_hdr_init_fixed(UDP_IP_HDR(us), IPPROTO_UDP, UDP_IP_HDR(us)->ip_ttl,
		       CI_MIN(tos, CI_IP_MAX_TOS));
}

#endif	/* #ifndef __KERNEL__ */

/* **********************
** Debugging
*/

#ifndef NDEBUG

void ci_udp_state_assert_valid(ci_netif* netif, ci_udp_state* us,
			       const char* file, int line)
{
  ci_assert(us);

}


void ci_udp_ep_assert_valid(citp_socket* ep, const char* file, int line)
{
  ci_netif* netif;
  ci_udp_state* us;

  ci_assert(ep);
  netif = ep->netif;

  ci_netif_assert_valid(netif, file, line);

  _ci_assert_equal(ep->s->b.state, CI_TCP_STATE_UDP, file, line);
  us = SOCK_TO_UDP(ep->s);

  ci_udp_state_assert_valid(netif, us, file, line);
}

#endif	/* #ifndef NDEBUG */


#undef percent
static int
percent (uint64_t a, unsigned b)
{
#if defined(__KERNEL__) && (CI_WORD_SIZE == 4)
   /* Sorry -- can't do 64-bit division in kernel. */
   (void)a;
   (void)b;
   return 0;
#else
   return  ((unsigned) ((b) ? (uint64_t) (a) * 100 / (b) : 0));
#endif
}

void ci_udp_state_dump(ci_netif* ni, ci_udp_state* us, const char* pf)
{
  ci_udp_socket_stats uss = us->stats;
  unsigned rx_added = us->recv_q.pkts_added;
  unsigned rx_os = uss.n_rx_os + uss.n_rx_os_slow;
  unsigned rx_total = rx_added + uss.n_rx_mem_drop + uss.n_rx_overflow + rx_os;
  unsigned n_tx_onload = uss.n_tx_onload_uc + uss.n_tx_onload_c;
  unsigned tx_total = n_tx_onload + uss.n_tx_os;
  ci_ip_cached_hdrs* ipcache;

  (void) rx_total;  /* unused on 32-bit builds in kernel */
  (void) tx_total;

  /* General. */
  log("%s  udpflags: "CI_UDP_STATE_FLAGS_FMT, pf,
      CI_UDP_STATE_FLAGS_PRI_ARG(us));

  /* Receive path. */
  log("%s  rcv: q_bytes=%d q_pkts=%d reap=%d tot_bytes=%u tot_pkts=%u", pf,
      ci_udp_recv_q_bytes(&us->recv_q), ci_udp_recv_q_pkts(&us->recv_q),
      ci_udp_recv_q_reapable(&us->recv_q),
      (unsigned) us->recv_q.bytes_added, rx_added);
#if CI_CFG_ZC_RECV_FILTER
  log("%s  rcv: filtered=%d unfiltered=%d tot_filt_rej=%d tot_filt_pass=%d ", pf,
      us->recv_q.pkts_filter_passed - us->recv_q.pkts_delivered,
      us->recv_q.pkts_added - us->recv_q.pkts_filter_passed - 
      us->recv_q.pkts_filter_dropped,
      us->recv_q.pkts_filter_dropped, us->recv_q.pkts_filter_passed);
#endif
  log("%s  rcv: oflow_drop=%u(%u%%) mem_drop=%u eagain=%u pktinfo=%u "
      "q_max=%u", pf, uss.n_rx_overflow, percent(uss.n_rx_overflow, rx_total),
      uss.n_rx_mem_drop, uss.n_rx_eagain, uss.n_rx_pktinfo, 
      uss.max_recvq_depth);
  log("%s  rcv: os=%u(%u%%) os_slow=%u os_error=%u", pf,
      rx_os, percent(rx_os, rx_total), uss.n_rx_os_slow, uss.n_rx_os_error);

  /* Send path. */
  log("%s  snd: q=%u+%u ul=%u os=%u(%u%%)", pf,
      us->tx_count, oo_atomic_read(&us->tx_async_q_level),
      n_tx_onload, uss.n_tx_os, percent(uss.n_tx_os, tx_total));
  log("%s  snd: LOCK cp=%u(%u%%) pkt=%u(%u%%) snd=%u(%u%%) poll=%u(%u%%) "
      "defer=%u(%u%%)", pf,
      uss.n_tx_lock_cp,  percent(uss.n_tx_lock_cp,  n_tx_onload),
      uss.n_tx_lock_pkt,  percent(uss.n_tx_lock_pkt,  n_tx_onload),
      uss.n_tx_lock_snd,  percent(uss.n_tx_lock_snd,  n_tx_onload),
      uss.n_tx_lock_poll, percent(uss.n_tx_lock_poll, n_tx_onload),
      uss.n_tx_lock_defer, percent(uss.n_tx_lock_defer, n_tx_onload));

  log("%s  snd: MCAST if=%d src="OOF_IP4" ttl=%d", pf,
      us->s.cp.ip_multicast_if,
      OOFA_IP4(us->s.cp.ip_multicast_if_laddr_be32),
      (int) us->s.cp.ip_mcast_ttl);

  /* State relating to unconnected sends. */
  ipcache = &us->ephemeral_pkt;
  log("%s  snd: TO n=%u match=%u(%u%%) lookup=%u+%u(%u%%) "OOF_IPCACHE_STATE,
      pf, uss.n_tx_onload_uc,
      uss.n_tx_cp_match, percent(uss.n_tx_cp_match, uss.n_tx_onload_uc),
      uss.n_tx_cp_uc_lookup, uss.n_tx_cp_a_lookup,
      percent(uss.n_tx_cp_uc_lookup + uss.n_tx_cp_a_lookup,
              uss.n_tx_onload_uc),
      OOFA_IPCACHE_STATE(ni, ipcache));
  log("%s  snd: TO "OOF_IPCACHE_DETAIL, pf,
      OOFA_IPCACHE_DETAIL(ipcache));
  log("%s  snd: TO "OOF_IP4PORT" => "OOF_IP4PORT, pf,
      OOFA_IP4PORT(ipcache->ip_saddr_be32, udp_lport_be16(us)),
      OOFA_IP4PORT(ipcache->ip.ip_daddr_be32, ipcache->dport_be16));

  /* State relating to connected sends. */
  ipcache = &us->s.pkt;
  log("%s  snd: CON n=%d lookup=%d "OOF_IPCACHE_STATE, pf,
      uss.n_tx_onload_c, uss.n_tx_cp_c_lookup, OOFA_IPCACHE_STATE(ni,ipcache));
  log("%s  snd: CON "OOF_IPCACHE_DETAIL, pf,
      OOFA_IPCACHE_DETAIL(ipcache));

  log("%s  snd: eagain=%d spin=%d block=%d", pf,
      uss.n_tx_eagain, uss.n_tx_spin, uss.n_tx_block);
  log("%s  snd: poll_avoids_full=%d fragments=%d confirm=%d", pf,
      uss.n_tx_poll_avoids_full, uss.n_tx_fragments, uss.n_tx_msg_confirm);
  log("%s  snd: os_slow=%d os_late=%d unconnect_late=%d nomac=%u(%u%%)", pf,
      uss.n_tx_os_slow, uss.n_tx_os_late, uss.n_tx_unconnect_late,
      uss.n_tx_cp_no_mac, percent(uss.n_tx_cp_no_mac, tx_total));
}

/*! \cidoxg_end */
