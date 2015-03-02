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
** \author  djr
**  \brief  Event handling
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "netif_tx.h"
#include "tcp_rx.h"
#include <ci/tools/pktdump.h>
#include <etherfabric/timer.h>
#include <etherfabric/vi.h>
#include <ci/internal/pio_buddy.h>

#ifdef __KERNEL__
#include <linux/time.h>
#else
#include <time.h>
#endif

#define SAMPLE(n) (n)

#define LPF "netif: "


struct oo_rx_state {
  ci_ip_pkt_fmt* rx_pkt;
  ci_ip_pkt_fmt* frag_pkt;
  int            frag_bytes;
};


static int ci_ip_csum_correct(ci_ip4_hdr* ip, int max_ip_len)
{
  unsigned csum;
  int ip_len;

  if( max_ip_len < CI_IP4_IHL(ip) )
    return 0;
  ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  if( max_ip_len < ip_len )
    return 0;

  csum = ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip));
  csum = ci_ip_hdr_csum_finish(csum);
  return csum == 0;
}


static int ci_tcp_csum_correct(ci_ip_pkt_fmt* pkt, int ip_paylen)
{
  ci_ip4_pseudo_hdr ph;
  ci_tcp_hdr* tcp;
  unsigned csum;
  int tcp_hlen;

  tcp = PKT_TCP_HDR(pkt);
  tcp_hlen = CI_TCP_HDR_LEN(tcp);

  if( tcp_hlen < sizeof(ci_tcp_hdr) )
    return 0;
  if( ip_paylen < tcp_hlen )
    return 0;

  ph.ip_saddr_be32 = oo_ip_hdr(pkt)->ip_saddr_be32;
  ph.ip_daddr_be32 = oo_ip_hdr(pkt)->ip_daddr_be32;
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_TCP;
  ph.length_be16 = CI_BSWAP_BE16((ci_uint16) ip_paylen);

  csum = ci_ip_csum_partial(0, &ph, sizeof(ph));
  csum = ci_ip_csum_partial(csum, tcp, ip_paylen);
  csum = ci_ip_hdr_csum_finish(csum);
  return csum == 0;
}


static void ci_parse_rx_vlan(ci_ip_pkt_fmt* pkt)
{
  uint16_t* p_ether_type;

  ci_assert_nequal((ci_uint8) pkt->pkt_start_off, 0xff);
  ci_assert_equal(pkt->pkt_eth_payload_off, 0xff);

  p_ether_type = &(oo_ether_hdr(pkt)->ether_type);
  if( *p_ether_type != CI_ETHERTYPE_8021Q ) {
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN;
    pkt->vlan = 0;
  }
  else {
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN + ETH_VLAN_HLEN;
    pkt->vlan = CI_BSWAP_BE16(p_ether_type[1]) & 0xfff;
  }
}


static void handle_rx_pkt(ci_netif* netif, struct ci_netif_poll_state* ps,
                          ci_ip_pkt_fmt* pkt)
{
  /* On entry: [pkt] may be a whole packet, or a linked list of scatter
   * fragments linked by [pkt->frag_next].  [pkt->pay_len] contains the
   * length of the whole frame.  Each scatter fragment has its [buf] field
   * initialised with the delivered frame payload.
   */
  int not_fast, ip_paylen, ip_tot_len;
  ci_ip4_hdr *ip;

  ci_assert_nequal(pkt->pkt_eth_payload_off, 0xff);

  ip = oo_ip_hdr(pkt);
  LOG_NR(log(LPF "RX id=%d ether_type=0x%04x ip_proto=0x%x", OO_PKT_FMT(pkt),
             (unsigned) CI_BSWAP_BE16(oo_ether_type_get(pkt)),
             (unsigned) ip->ip_protocol));
  LOG_AR(ci_analyse_pkt(PKT_START(pkt), pkt->pay_len));

#if CI_CFG_RANDOM_DROP && !defined(__KERNEL__)
  if( CI_UNLIKELY(rand() < NI_OPTS(netif).rx_drop_rate) )  goto drop;
#endif

  /* Is this an IP packet?  Yes -- hardware only delivers us IPv4 at time
  ** of writing. */
  if(CI_LIKELY( 1 || oo_ether_type_get(pkt) == CI_ETHERTYPE_IP )) {
    CI_IPV4_STATS_INC_IN_RECVS( netif );

    /* Do the byte-swap just once! */
    ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);

    LOG_DR(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(ip_tot_len), 0));

    if( oo_tcpdump_check(netif, pkt, pkt->intf_i) )
      oo_tcpdump_dump_pkt(netif, pkt);

    /* Hardware will not deliver us fragments.  Check for IP options and
    ** valid IP length. */
    not_fast = ((ip->ip_ihl_version-CI_IP4_IHL_VERSION(sizeof(*ip))) |
                (ip_tot_len > pkt->pay_len - oo_ether_hdr_size(pkt)));
    /* NB. If you want to check for fragments, add this:
    **
    **  (ip->ip_frag_off_be16 & ~CI_IP4_FRAG_DONT)
    */

    /* We are not checking for certain other illegalities here (invalid
    ** source address and short IP length).  That's because in some cases
    ** they can be checked for free in the transport.  It is the
    ** transport's responsibility to check these as necessary.
    */

    if( CI_LIKELY(not_fast == 0) ) {
      char* payload = (char*) ip + sizeof(ci_ip4_hdr);
      ci_netif_state_nic_t* nsn = &netif->state->nic[pkt->intf_i];
      struct timespec stamp;

      ip_paylen = (int) ip_tot_len - sizeof(ci_ip4_hdr);
      /* This will go negative if the ip_tot_len was too small even
      ** for the IP header.  The ULP is expected to notice...
      */

      if( nsn->oo_vi_flags & OO_VI_FLAGS_RX_HW_TS_EN ) {
        unsigned sync_flags;
        int rc = ef_vi_receive_get_timestamp_with_sync_flags
          (&netif->nic_hw[pkt->intf_i].vi,
           PKT_START(pkt) - nsn->rx_prefix_len, &stamp, &sync_flags);
        if( rc == 0 ) {
          int tsf = (NI_OPTS(netif).timestamping_reporting &
                     CITP_TIMESTAMPING_RECORDING_FLAG_CHECK_SYNC) ?
                    EF_VI_SYNC_FLAG_CLOCK_IN_SYNC :
                    EF_VI_SYNC_FLAG_CLOCK_SET;
          stamp.tv_nsec =
                    (stamp.tv_nsec & ~CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC) |
                    ((sync_flags & tsf) ? CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC : 0);
          nsn->last_rx_timestamp.tv_sec = stamp.tv_sec;
          nsn->last_rx_timestamp.tv_nsec = stamp.tv_nsec;

          LOG_NR(log(LPF "RX id=%d timestamp: %lu.%09lu sync %d",
              OO_PKT_FMT(pkt), stamp.tv_sec, stamp.tv_nsec, sync_flags));
        } else {
          LOG_NR(log(LPF "RX id=%d missing timestamp", OO_PKT_FMT(pkt)));
          stamp.tv_sec = 0;
        }
      }
      else
        stamp.tv_sec = 0;
        /* no need to set tv_nsec to 0 here as socket layer ignores
         * timestamps when tv_sec is 0
         */

      /* Demux to appropriate protocol. */
      if( ip->ip_protocol == IPPROTO_TCP ) {
        pkt->pf.tcp_rx.rx_hw_stamp.tv_sec = stamp.tv_sec;
        pkt->pf.tcp_rx.rx_hw_stamp.tv_nsec = stamp.tv_nsec;
        ci_tcp_handle_rx(netif, ps, pkt, (ci_tcp_hdr*) payload, ip_paylen);
        CI_IPV4_STATS_INC_IN_DELIVERS( netif );
        return;
      }
#if CI_CFG_UDP
      else if(CI_LIKELY( ip->ip_protocol == IPPROTO_UDP )) {
        pkt->pf.udp.rx_hw_stamp.tv_sec = stamp.tv_sec;
        pkt->pf.udp.rx_hw_stamp.tv_nsec = stamp.tv_nsec;
        ci_udp_handle_rx(netif, pkt, (ci_udp_hdr*) payload, ip_paylen);
        CI_IPV4_STATS_INC_IN_DELIVERS( netif );
        return;
      }
#endif

      LOG_U(log(LPF "IGNORE IP protocol=%d", (int) ip->ip_protocol));
      return;
    }

    /*! \todo IP slow path.  Don't want to deal with this yet. */
    LOG_U(log(LPF "[%d] IP HARD "
              "(ihl_ver=%x ihl=%d frag=%x ip_len=%d frame_len=%d)"
              PKT_DBG_FMT,
              netif->state->stack_id,
              (int) ip->ip_ihl_version, (int) CI_IP4_IHL(ip),
              (unsigned) ip->ip_frag_off_be16,
              ip_tot_len, pkt->pay_len, PKT_DBG_ARGS(pkt)));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
    ci_netif_pkt_release_rx_1ref(netif, pkt);
    return;
  }

  LOG_U(log(LPF "UNEXPECTED ether_type=%04x"PKT_DBG_FMT,
            (unsigned) CI_BSWAP_BE16(oo_ether_type_get(pkt)),
            PKT_DBG_ARGS(pkt));
        ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
  ci_netif_pkt_release_rx_1ref(netif, pkt);
  return;

#if CI_CFG_RANDOM_DROP && !defined(__ci_driver__)
 drop:
  LOG_NR(log(LPF "DROP"));
  LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
  ci_netif_pkt_release_rx_1ref(netif, pkt);
  return;
#endif
}


static void handle_rx_scatter(ci_netif* ni, struct oo_rx_state* s,
                              ci_ip_pkt_fmt* pkt, int frame_bytes,
                              unsigned flags)
{
  s->rx_pkt = NULL;

  if( flags & EF_EVENT_FLAG_SOP ) {
    /* First fragment. */
    ci_assert(s->frag_pkt == NULL);
    ci_assert_le(frame_bytes,
                 (int) (CI_CFG_PKT_BUF_SIZE -
                        CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start)));
    s->frag_pkt = pkt;
    pkt->buf_len = s->frag_bytes = frame_bytes;
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), s->frag_bytes);
  }
  else {
    ci_assert(s->frag_pkt != NULL);
    ci_assert_gt(s->frag_bytes, 0);
    ci_assert_gt(frame_bytes, s->frag_bytes);
    pkt->buf_len = frame_bytes - s->frag_bytes;
    oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
    s->frag_bytes = frame_bytes;
    CI_DEBUG(pkt->pay_len = -1);
    if( flags & EF_EVENT_FLAG_CONT ) {
      /* Middle fragment. */
      pkt->frag_next = OO_PKT_P(s->frag_pkt);
      s->frag_pkt = pkt;
    }
    else {
      /* Last fragment. */
      oo_pkt_p next_p;
      ci_assert(OO_PP_IS_NULL(pkt->frag_next));
      pkt->n_buffers = 1;
      while( 1 ) {  /* reverse the chain of fragments */
        next_p = s->frag_pkt->frag_next;
        s->frag_pkt->frag_next = OO_PKT_P(pkt);
        s->frag_pkt->n_buffers = pkt->n_buffers + 1;
        if( OO_PP_IS_NULL(next_p) )
          break;
        pkt = s->frag_pkt;
        s->frag_pkt = PKT(ni, next_p);
      }
      s->rx_pkt = s->frag_pkt;
      s->rx_pkt->pay_len = s->frag_bytes;
      s->frag_pkt = NULL;
      ASSERT_VALID_PKT(ni, s->rx_pkt);
    }
  }
}


static int handle_rx_csum_bad(ci_netif* ni, struct ci_netif_poll_state* ps,
                              ci_ip_pkt_fmt* pkt, int frame_len)
{
  ci_ip4_hdr *ip;
  int ip_paylen;
  int ip_len;

  ci_parse_rx_vlan(pkt);

  /* Packet reached onload -- so must be IP and must at least reach the TCP
   * or UDP header.
   */
  ci_assert_equal(oo_ether_type_get(pkt), CI_ETHERTYPE_IP);

  pkt->pay_len = frame_len;
  oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
  if( pkt->pay_len <=
      sizeof(ci_tcp_hdr) + sizeof(ci_ip4_hdr) + oo_ether_hdr_size(pkt) ) {
    CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
    LOG_U(log(FN_FMT "BAD frame_len=%d",
              FN_PRI_ARGS(ni), pkt->pay_len));
    goto drop;
  }
  
  ip = oo_ip_hdr(pkt);
  ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  ip_paylen = ip_len - sizeof(ci_ip4_hdr);
  if( pkt->pay_len < oo_ether_hdr_size(pkt) + ip_len ||
      ip_paylen < sizeof(ci_tcp_hdr) ) {
    CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
    LOG_U(log(FN_FMT "BAD ip_len=%d frame_len=%d",
              FN_PRI_ARGS(ni), ip_len, pkt->pay_len));
    goto drop;
  }

  if( ! ci_ip_csum_correct(ip, pkt->pay_len - oo_ether_hdr_size(pkt)) ) {
    CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
    LOG_U(log(FN_FMT "IP BAD CHECKSUM", FN_PRI_ARGS(ni)));
    goto drop;
  }


  if( ip->ip_protocol == IPPROTO_TCP ) {
    if( ci_tcp_csum_correct(pkt, ip_paylen) ) {
      handle_rx_pkt(ni, ps, pkt);
      return 1;
    }
    else {
      LOG_U(log(FN_FMT "BAD TCP CHECKSUM %04x "PKT_DBG_FMT, FN_PRI_ARGS(ni),
                (unsigned) PKT_TCP_HDR(pkt)->tcp_check_be16,
                PKT_DBG_ARGS(pkt)));
      goto drop;
    }
  }
#if CI_CFG_UDP
  else if( ip->ip_protocol == IPPROTO_UDP ) {
    ci_udp_hdr* udp = PKT_UDP_HDR(pkt);
    pkt->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16);
    if( ci_udp_csum_correct(pkt, udp) ) {
      handle_rx_pkt(ni, ps, pkt);
      return 1;
    }
    else {
      CI_UDP_STATS_INC_IN_ERRS(ni);
      LOG_U(log(FN_FMT "BAD UDP CHECKSUM %04x", FN_PRI_ARGS(ni),
                (unsigned) udp->udp_check_be16));
      goto drop;
    }
  }
#endif

drop:
  LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), frame_len, 0));
  LOG_NR(log(LPF "DROP"));
  LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
  return 0;
}


static void handle_rx_no_desc_trunc(ci_netif* ni,
                                    struct ci_netif_poll_state* ps,
                                    int intf_i,
                                    struct oo_rx_state* s, ef_event ev)
{
  LOG_U(log(LPF "[%d] intf %d RX_NO_DESC_TRUNC "EF_EVENT_FMT,
            NI_ID(ni), intf_i, EF_EVENT_PRI_ARG(ev)));

  if( s->rx_pkt != NULL ) {
    ci_parse_rx_vlan(s->rx_pkt);
    handle_rx_pkt(ni, ps, s->rx_pkt);
    s->rx_pkt = NULL;
  }
  ci_assert(s->frag_pkt != NULL);
  if( s->frag_pkt != NULL ) {  /* belt and braces! */
    ci_netif_pkt_release_rx_1ref(ni, s->frag_pkt);
    s->frag_pkt = NULL;
  }
}


static void handle_rx_discard(ci_netif* ni, struct ci_netif_poll_state* ps,
                              int intf_i, struct oo_rx_state* s, ef_event ev)
{
  int discard_type = EF_EVENT_RX_DISCARD_TYPE(ev), is_frag;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;
  int handled = 0;
  int frame_len;

  LOG_U(log(LPF "[%d] intf %d RX_DISCARD %d "EF_EVENT_FMT,
            NI_ID(ni), intf_i,
            (int) discard_type, EF_EVENT_PRI_ARG(ev)));

  if( s->rx_pkt != NULL ) {
    ci_parse_rx_vlan(s->rx_pkt);
    handle_rx_pkt(ni, ps, s->rx_pkt);
    s->rx_pkt = NULL;
  }

  /* For now bin any fragments as (i) they would only be useful in the
   * CSUM_BAD case; (ii) the hardware is probably right about the
   * checksum (especially so for packets long enough to fragment); and
   * (iii) validating the hardware's decision in the multiple
   * fragments case would require significantly more code
   */
  if( (is_frag = (s->frag_pkt != NULL)) ) {
    ci_netif_pkt_release_rx_1ref(ni, s->frag_pkt);
    s->frag_pkt = NULL;
  }

  OO_PP_INIT(ni, pp, EF_EVENT_RX_DISCARD_RQ_ID(ev));
  pkt = PKT_CHK(ni, pp);

  frame_len = EF_EVENT_RX_DISCARD_BYTES(ev) - 
    ni->nic_hw[intf_i].vi.rx_prefix_len;

  if( EF_EVENT_RX_DISCARD_TYPE(ev) == EF_EVENT_RX_DISCARD_CSUM_BAD && 
      !is_frag )
    handled = handle_rx_csum_bad(ni, ps, pkt, frame_len);
  
  switch( discard_type ) {
  case EF_EVENT_RX_DISCARD_CSUM_BAD:
    CITP_STATS_NETIF_INC(ni, rx_discard_csum_bad);
    break;
  case EF_EVENT_RX_DISCARD_MCAST_MISMATCH:
    CITP_STATS_NETIF_INC(ni, rx_discard_mcast_mismatch);
    break;
  case EF_EVENT_RX_DISCARD_CRC_BAD:
    CITP_STATS_NETIF_INC(ni, rx_discard_crc_bad);
    break;
  case EF_EVENT_RX_DISCARD_TRUNC:
    CITP_STATS_NETIF_INC(ni, rx_discard_trunc);
    break;
  case EF_EVENT_RX_DISCARD_RIGHTS:
    CITP_STATS_NETIF_INC(ni, rx_discard_rights);
    break;
  case EF_EVENT_RX_DISCARD_OTHER:
    CITP_STATS_NETIF_INC(ni, rx_discard_other);
    break;
  }

  if( !handled ) {
    if( (discard_type == EF_EVENT_RX_DISCARD_CSUM_BAD ||
         discard_type == EF_EVENT_RX_DISCARD_MCAST_MISMATCH ||
         discard_type == EF_EVENT_RX_DISCARD_CRC_BAD ||
         discard_type == EF_EVENT_RX_DISCARD_TRUNC) &&
        oo_tcpdump_check(ni, pkt, pkt->intf_i) ) {
        pkt->pay_len = frame_len;
        oo_tcpdump_dump_pkt(ni, pkt);
    }

    ci_netif_pkt_release_rx_1ref(ni, pkt);
  }
}


static void ci_sock_put_on_reap_list(ci_netif* ni, ci_sock_cmn* s)
{
  ci_ni_dllist_remove(ni, &s->reap_link);
  ci_ni_dllist_put(ni, &ni->state->reap_list, &s->reap_link);
  s->b.sb_flags &= ~CI_SB_FLAG_RX_DELIVERED;
}


static void process_post_poll_list(ci_netif* ni)
{
  ci_ni_dllist_link* lnk;
  int i, need_wake = 0;
  citp_waitable* sb;
  int lists_need_wake = 0;

  (void) i;  /* prevent warning; effectively unused at userlevel */

  for( i = 0, lnk = ci_ni_dllist_start(ni, &ni->state->post_poll_list);
       lnk != ci_ni_dllist_end(ni, &ni->state->post_poll_list); ) {

#ifdef __KERNEL__
    if(CI_UNLIKELY( i++ > ni->ep_tbl_n )) {
      ci_netif_error_detected(ni, CI_NETIF_ERROR_POST_POLL_LIST, __FUNCTION__);
      return;
    }
#endif

    sb = CI_CONTAINER(citp_waitable, post_poll_link, lnk);
    lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next);

    if( sb->sb_flags & CI_SB_FLAG_TCP_POST_POLL )
      ci_tcp_rx_post_poll(ni, CI_CONTAINER(ci_tcp_state, s.b, sb));
    if( sb->sb_flags & CI_SB_FLAG_RX_DELIVERED )
      ci_sock_put_on_reap_list(ni, CI_CONTAINER(ci_sock_cmn, b, sb));

    if( sb->sb_flags ) {
      if( sb->sb_flags & CI_SB_FLAG_WAKE_RX )
        ++sb->sleep_seq.rw.rx;
      if( sb->sb_flags & CI_SB_FLAG_WAKE_TX )
        ++sb->sleep_seq.rw.tx;
      ci_mb();

      lists_need_wake |= 1 << sb->ready_list_id;
#ifdef __KERNEL__
      if( (sb->sb_flags & sb->wake_request) )
        citp_waitable_wakeup(ni, sb);
      else
        sb->sb_flags = 0;
#else
      /* Leave endpoints that need waking on the post-poll list so they can
       * be woken in the driver with a single syscall when we drop the
       * lock.
       */
      if( ! (sb->sb_flags & sb->wake_request) ) {
	sb->sb_flags = 0;
      }
      else {
        /* NB. Important to leave [sb_flags] set here, as we may run
         * process_post_poll_list() multiple times before dropping the
         * lock.  If we cleared [sb_flags] this endpoint could be dropped
         * from the list.
         */
        need_wake = 1;
        continue;
      }
#endif
    }
    ci_ni_dllist_remove_safe(ni, &sb->post_poll_link);
  }

  CHECK_NI(ni);

#ifndef __KERNEL__
  /* See if any of the ready lists need a wake.  We only bother checking if
   * we're not going to do a wake anyway, and we don't check list 0, as that's
   * just a dummy list, for things that aren't on a real one.
   */
  if( need_wake == 0 ) {
    for( i = 1; i < CI_CFG_N_READY_LISTS; i++ ) {
      if( (lists_need_wake & (1 << i)) &&
          (ni->state->ready_list_flags[i] & CI_NI_READY_LIST_FLAG_WAKE) ) {
        need_wake = 1;
        break;
      }
    }
  }
#endif

  if( need_wake )
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_WAKE);

  /* Shouldn't have had a wake for a list we don't think exists */
  ci_assert_equal(lists_need_wake & ~((1 << (CI_CFG_N_READY_LISTS + 1))-1), 0);

#ifdef __KERNEL__
  /* Check whether any ready lists associated with a set need to be woken.
   * We don't check ready list 0 as that is the dummy list, used for all socks
   * that aren't associated with a specific set, so never needs a wakeup.
   */
  for( i = 1; i < CI_CFG_N_READY_LISTS; i++ )
    if( (lists_need_wake & (1 << i)) &&
        (ni->state->ready_list_flags[i] & CI_NI_READY_LIST_FLAG_WAKE) )
      efab_tcp_helper_ready_list_wakeup(netif2tcp_helper_resource(ni), i);
#endif
}


#if CI_CFG_UDP

# define UDP_CAN_FREE(us)  ((us)->tx_count == 0)

#define CI_NETIF_TX_VI(ni, nic_i, label)  (&(ni)->nic_hw[nic_i].vi)


static void ci_netif_tx_pkt_complete_udp(ci_netif* netif,
                                         struct ci_netif_poll_state* ps,
                                         ci_ip_pkt_fmt* pkt)
{
  ci_udp_state* us;
  oo_pkt_p frag_next;
  int n_buffers = pkt->n_buffers;

  ci_assert(oo_ip_hdr(pkt)->ip_protocol == IPPROTO_UDP);

  us = SP_TO_UDP(netif, pkt->pf.udp.tx_sock_id);

  ci_udp_dec_tx_count(us, pkt);

  if( ci_udp_tx_advertise_space(us) ) {
    if( ! (us->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      /* Linux wakes up with event= POLLOUT on each TX,
       * and we do the same. */
      ci_udp_wake_possibly_not_in_poll(netif, us, CI_SB_FLAG_WAKE_TX);
      ci_netif_put_on_post_poll(netif, &us->s.b);
    }
    else if( UDP_CAN_FREE(us) ) {
      ci_ni_dllist_remove_safe(netif, &us->s.b.post_poll_link);
      ci_udp_state_free(netif, us);
    }
  }

  /* linux/Documentation/networking/timestamping.txt:
   * If the outgoing packet has to be fragmented, then only the first
   * fragment is time stamped and returned to the sending socket. */
  if( pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED ) {
    pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
    frag_next = ci_udp_timestamp_q_enqueue(netif, us, pkt);
    goto next_fragment;
  }

  /* Free this packet and all the fragments if possible. */
  while( 1 ) {
    if( pkt->refcount == 1 ) {
      frag_next = pkt->frag_next;

      pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
      pkt->refcount = 0;
      if( pkt->flags & CI_PKT_FLAG_RX )
        --netif->state->n_rx_pkts;
      __ci_netif_pkt_clean(pkt);
      if( pkt->flags & CI_PKT_FLAG_NONB_POOL ) {
        *ps->tx_pkt_free_list_insert = OO_PKT_P(pkt);
        ps->tx_pkt_free_list_insert = &pkt->next;
        ++ps->tx_pkt_free_list_n;
      }
      else {
        pkt->next = netif->state->freepkts;
        netif->state->freepkts = OO_PKT_P(pkt);
        ++netif->state->n_freepkts;
      }

next_fragment:
      /* is there any next fragment? */
      if( OO_PP_IS_NULL(frag_next) )
        break;
      pkt = PKT_CHK(netif, frag_next);
      /* Is it next IP fragment? */
      if( n_buffers == 1 ) {
        /* have we started with it? */
        if( ~pkt->flags & CI_PKT_FLAG_TX_PENDING )
          return;
        n_buffers = pkt->n_buffers;
      }
      else
        n_buffers--;
    }
    else {
      ci_assert_gt(pkt->refcount, 1);
      --pkt->refcount;
      break;
    }
  }
}

#endif


ci_inline void __ci_netif_tx_pkt_complete(ci_netif* ni,
                                          struct ci_netif_poll_state* ps,
                                          ci_ip_pkt_fmt* pkt, ef_event* ev)
{
  ci_netif_state_nic_t* nic = &ni->state->nic[pkt->intf_i];
  /* debug check - take back ownership of buffer from NIC */
  ci_assert(pkt->flags & CI_PKT_FLAG_TX_PENDING);
  nic->tx_bytes_removed += TX_PKT_LEN(pkt);
  ci_assert((int) (nic->tx_bytes_added - nic->tx_bytes_removed) >=0);
  if( pkt->pio_addr >= 0 ) {
    ci_pio_buddy_free(ni, &nic->pio_buddy, pkt->pio_addr, pkt->pio_order);
    pkt->pio_addr = -1;
  }

  if( pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED ) {
    if( ev != NULL && EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP ) {
      int opt_tsf = ((NI_OPTS(ni).timestamping_reporting) &
                     CITP_TIMESTAMPING_RECORDING_FLAG_CHECK_SYNC) ?
                    EF_VI_SYNC_FLAG_CLOCK_IN_SYNC :
                    EF_VI_SYNC_FLAG_CLOCK_SET;
      int pkt_tsf = EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(*ev);

      pkt->tx_hw_stamp.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(*ev);
      pkt->tx_hw_stamp.tv_nsec =
                    (EF_EVENT_TX_WITH_TIMESTAMP_NSEC(*ev) &
                     (~CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC)) |
                    ((pkt_tsf & opt_tsf) ?
                     CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC : 0);
    }
    else {
      /* Fixme: suppress this message if ev=NULL as a result of reset? */
      if( CI_NETIF_TX_VI(ni, pkt->intf_i, ev->tx_timestamp.q_id)->vi_flags &
          EF_VI_TX_TIMESTAMPS ) {
        ci_log("ERROR: TX timestamp requested, but non-timestamped "
                "TX complete event received.");
      }
      pkt->flags &= ~CI_PKT_FLAG_TX_TIMESTAMPED;
    }

  }


#if CI_CFG_UDP
  if( pkt->flags & CI_PKT_FLAG_UDP )
    ci_netif_tx_pkt_complete_udp(ni, ps, pkt);
  else
#endif
  {
    pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
    ci_netif_pkt_release(ni, pkt);
  }

}


void ci_netif_tx_pkt_complete(ci_netif* ni, struct ci_netif_poll_state* ps,
                              ci_ip_pkt_fmt* pkt)
{
  __ci_netif_tx_pkt_complete(ni, ps, pkt, NULL);
}



static int ci_netif_poll_evq(ci_netif* ni, struct ci_netif_poll_state* ps,
                             int intf_i)
{
  struct oo_rx_state s;
  ef_vi* evq = &ni->nic_hw[intf_i].vi;
  unsigned total_evs = 0;
  ci_ip_pkt_fmt* pkt;
  ef_event *ev = ni->events;
  int i, n_evs;
  oo_pkt_p pp;

  s.frag_pkt = NULL;
  s.frag_bytes = 0;  /*??*/

  if( OO_PP_NOT_NULL(ni->state->nic[intf_i].rx_frags) ) {
    pkt = PKT_CHK(ni, ni->state->nic[intf_i].rx_frags);
    ni->state->nic[intf_i].rx_frags = OO_PP_NULL;
    s.frag_pkt = pkt;
    s.frag_bytes = pkt->pay_len;
    CI_DEBUG(pkt->pay_len = -1);
  }

  do {
    n_evs = ef_eventq_poll(evq, ev, sizeof(ni->events) / sizeof(ev[0]));
    if( n_evs == 0 )
      break;

    s.rx_pkt = NULL;
    for( i = 0; i < n_evs; ++i ) {
      /* Look for RX events first to minimise latency. */
      if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX ) {
        CITP_STATS_NETIF_INC(ni, rx_evs);
        OO_PP_INIT(ni, pp, EF_EVENT_RX_RQ_ID(ev[i]));
        pkt = PKT_CHK(ni, pp);
        ci_prefetch(pkt->dma_start);
        ci_prefetch(pkt);
        ci_assert_equal(pkt->intf_i, intf_i);
        if( s.rx_pkt != NULL ) {
          ci_parse_rx_vlan(s.rx_pkt);
          handle_rx_pkt(ni, ps, s.rx_pkt);
        }
        if( (ev[i].rx.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                       == EF_EVENT_FLAG_SOP ) {
          /* Whole packet in a single buffer. */
          pkt->pay_len = EF_EVENT_RX_BYTES(ev[i]) - evq->rx_prefix_len;
          oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
          s.rx_pkt = pkt;
        }
        else {
          handle_rx_scatter(ni, &s, pkt,
                            EF_EVENT_RX_BYTES(ev[i]) - evq->rx_prefix_len,
                            ev[i].rx.flags);
        }
      }

      else if(CI_LIKELY( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX )) {
        ef_request_id *ids = ni->tx_events;
        int n_ids, j;
        ef_vi* vi = CI_NETIF_TX_VI(ni, intf_i, ev[i].tx.q_id);
        CITP_STATS_NETIF_INC(ni, tx_evs);
        n_ids = ef_vi_transmit_unbundle(vi, &ev[i], ids);
        ci_assert_ge(n_ids, 0);
        ci_assert_le(n_ids, sizeof(ni->tx_events) / sizeof(ids[0]));
        for( j = 0; j < n_ids; ++j ) {
          OO_PP_INIT(ni, pp, ids[j]);
          pkt = PKT_CHK(ni, pp);
          ++ni->state->nic[intf_i].tx_dmaq_done_seq;
          __ci_netif_tx_pkt_complete(ni, ps, pkt, &ev[i]);
        }
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP ) {
        CITP_STATS_NETIF_INC(ni, tx_evs);
        OO_PP_INIT(ni, pp, ev[i].tx_timestamp.rq_id);
        pkt = PKT_CHK(ni, pp);
        ++ni->state->nic[intf_i].tx_dmaq_done_seq;
        __ci_netif_tx_pkt_complete(ni, ps, pkt, &ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_NO_DESC_TRUNC ) {
        handle_rx_no_desc_trunc(ni, ps, intf_i, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_DISCARD ) {
        handle_rx_discard(ni, ps, intf_i, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX_ERROR ) {
        LOG_U(log(LPF "[%d] intf %d TX_ERROR %d "EF_EVENT_FMT,
                  NI_ID(ni), intf_i,
                  (int) EF_EVENT_TX_ERROR_TYPE(ev[i]),
                  EF_EVENT_PRI_ARG(ev[i])));
        CITP_STATS_NETIF_INC(ni, tx_error_events);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_OFLOW ) {
        LOG_E(log(LPF "***** EVENT QUEUE OVERFLOW *****"));
        return 0;
      }

      else {
        /* NB. If you see this for an RX event, then perhaps some code
         * which I thought was obsolete is needed. */
        ci_assert( EF_EVENT_TYPE(ev[i]) != EF_EVENT_TYPE_RX );
        LOG_E(log(LPF "***** UNKNOWN EVENT "EF_EVENT_FMT" (abstracted type:%d)"
                  " *****",
                  EF_EVENT_PRI_ARG(ev[i]), EF_EVENT_TYPE(ev[i])));
      }
    }

#ifndef NDEBUG
    {
      ef_vi* vi = CI_NETIF_TX_VI(ni, intf_i, ev[i].tx_timestamp.q_id);
      ci_assert_equiv((ef_vi_transmit_fill_level(vi) == 0 &&
                       ni->state->nic[intf_i].dmaq.num == 0),
                      (ni->state->nic[intf_i].tx_dmaq_insert_seq ==
                       ni->state->nic[intf_i].tx_dmaq_done_seq));
    }
#endif

    if( s.rx_pkt != NULL ) {
      ci_parse_rx_vlan(s.rx_pkt);
      handle_rx_pkt(ni, ps, s.rx_pkt);
    }

    total_evs += n_evs;
  } while( total_evs < NI_OPTS(ni).evs_per_poll );

  if( s.frag_pkt != NULL ) {
    s.frag_pkt->pay_len = s.frag_bytes;
    ni->state->nic[intf_i].rx_frags = OO_PKT_P(s.frag_pkt);
  }

  return total_evs;
}


static void ci_netif_tx_progress(ci_netif* ni, int intf_i)
{
  ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
  ci_tcp_state* ts;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ci_ni_dllist_not_empty(ni, &nic->tx_ready_list));

  if( nic->tx_bytes_added - nic->tx_bytes_removed > NI_OPTS(ni).txq_restart )
    return;

  do {
    ts = CI_CONTAINER(ci_tcp_state, tx_ready_link,
                      ci_ni_dllist_head(ni, &nic->tx_ready_list));
    LOG_TT(ci_log(FNT_FMT, FNT_PRI_ARGS(ni, ts)));
    ci_tcp_tx_advance(ts, ni);
    if( ci_ni_dllist_is_empty(ni, &nic->tx_ready_list) )
      break;
  } while( nic->tx_bytes_added - nic->tx_bytes_removed
           < NI_OPTS(ni).txq_limit );
}


static int ci_netif_poll_intf(ci_netif* ni, int intf_i, int max_evs)
{
  struct ci_netif_poll_state ps;
  int total_evs = 0;
  int rc;

  ci_assert(ci_netif_is_locked(ni));
  ps.tx_pkt_free_list_insert = &ps.tx_pkt_free_list;
  ps.tx_pkt_free_list_n = 0;

  do {
    rc = ci_netif_poll_evq(ni, &ps, intf_i);
    if( rc > 0 ) {
      total_evs += rc;
      process_post_poll_list(ni);
    }
    else
      break;
  } while( total_evs < max_evs );

  if( ps.tx_pkt_free_list_n )
    ci_netif_poll_free_pkts(ni, &ps);

  /* The following steps probably aren't needed if we haven't handled any
   * events, but that is a rare case and so not worth testing for.
   */
  if( ci_netif_rx_vi_space(ni, ci_netif_rx_vi(ni, intf_i))
      >= CI_CFG_RX_DESC_BATCH )
    ci_netif_rx_post(ni, intf_i);

  if( ci_ni_dllist_not_empty(ni, &ni->state->nic[intf_i].tx_ready_list) )
    ci_netif_tx_progress(ni, intf_i);
  if( ci_netif_dmaq_not_empty(ni, intf_i) )
    ci_netif_dmaq_shove1(ni, intf_i);

  return total_evs;
}


int ci_netif_poll_intf_fast(ci_netif* ni, int intf_i, ci_uint64 now_frc)
{
  struct ci_netif_poll_state ps;
  int rc;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ni->state->in_poll == 0);

  if(CI_LIKELY( ni->state->poll_work_outstanding == 0 )) {
    ci_ip_time_update(IPTIMER_STATE(ni), now_frc);
    ps.tx_pkt_free_list_insert = &ps.tx_pkt_free_list;
    ps.tx_pkt_free_list_n = 0;
    ++ni->state->in_poll;
    if( (rc = ci_netif_poll_evq(ni, &ps, intf_i)) ) {
      process_post_poll_list(ni);
      ni->state->poll_work_outstanding = 1;
    }
    --ni->state->in_poll;
    if( ps.tx_pkt_free_list_n )
      ci_netif_poll_free_pkts(ni, &ps);
    return rc;
  }
  /* We don't want to just be calling ci_netif_poll_intf_fast(), since
   * we'll never refill the RX rings.  So we ensure that a full poll
   * interleaves each fast one.
   */
  return ci_netif_poll_n(ni, NI_OPTS(ni).evs_per_poll);
}


static void ci_netif_loopback_pkts_send(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p send_list = OO_PP_ID_NULL;
  ci_ip4_hdr* ip;
#ifdef __KERNEL__
  int i = 0;
#endif

  CI_BUILD_ASSERT(
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_tx.lo.rx_sock) ==
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_rx.lo.rx_sock) );
  CI_BUILD_ASSERT(
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_tx.lo.tx_sock) ==
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_rx.lo.tx_sock) );

  while( OO_PP_NOT_NULL(ni->state->looppkts) ) {
#ifdef __KERNEL__
    if(CI_UNLIKELY( i++ > ni->pkt_sets_n * PKTS_PER_SET )) {
      ci_netif_error_detected(ni, CI_NETIF_ERROR_LOOP_PKTS_LIST, __FUNCTION__);
      return;
    }
#endif
    pkt = PKT_CHK(ni, ni->state->looppkts);
    ni->state->looppkts = pkt->next;
    pkt->next = send_list;
    send_list = OO_PKT_ID(pkt);
  }

  while( OO_PP_NOT_NULL(send_list) ) {
    pkt = PKT_CHK(ni, send_list);
    send_list = pkt->next;
    ni->state->n_looppkts--;

    LOG_NR(ci_log(N_FMT "loopback RX pkt %d: %d->%d", N_PRI_ARGS(ni),
                  OO_PKT_FMT(pkt),
                  OO_SP_FMT(pkt->pf.tcp_tx.lo.tx_sock),
                  OO_SP_FMT(pkt->pf.tcp_tx.lo.rx_sock)));

    ip = oo_ip_hdr(pkt);
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->buf_len);
    pkt->intf_i = OO_INTF_I_LOOPBACK;
    pkt->flags &= CI_PKT_FLAG_NONB_POOL;
    if( oo_tcpdump_check(ni, pkt, OO_INTF_I_LOOPBACK) )
      oo_tcpdump_dump_pkt(ni, pkt);
    pkt->next = OO_PP_NULL;
    ci_tcp_handle_rx(ni, NULL, pkt, (ci_tcp_hdr*)(ip + 1),
                     CI_BSWAP_BE16(ip->ip_tot_len_be16) - sizeof(ci_ip4_hdr));
  }
}


int ci_netif_poll_n(ci_netif* netif, int max_evs)
{
  int intf_i, n_evs_handled = 0;

#if defined(__KERNEL__) || ! defined(NDEBUG)
  if( netif->error_flags )
    return 0;
#endif

  ci_assert(ci_netif_is_locked(netif));
  CHECK_NI(netif);

#ifdef __KERNEL__
  CITP_STATS_NETIF_INC(netif, k_polls);
#else
  CITP_STATS_NETIF_INC(netif, u_polls);
#endif

  ci_ip_time_resync(IPTIMER_STATE(netif));

#if CI_CFG_HW_TIMER
  if( ci_netif_need_timer_prime(netif, IPTIMER_STATE(netif)->frc) ) {
    if( NI_OPTS(netif).timer_usec != 0 )
      OO_STACK_FOR_EACH_INTF_I(netif, intf_i)
        ef_eventq_timer_prime(&netif->nic_hw[intf_i].vi,
                              NI_OPTS(netif).timer_usec);
    netif->state->evq_last_prime = IPTIMER_STATE(netif)->frc;
  }
#endif

  ci_assert(netif->state->in_poll == 0);
  ++netif->state->in_poll;
  OO_STACK_FOR_EACH_INTF_I(netif, intf_i) {
    int n = ci_netif_poll_intf(netif, intf_i, max_evs);
    ci_assert(n >= 0);
    n_evs_handled += n;
  }

  while( OO_PP_NOT_NULL(netif->state->looppkts) ) {
    ci_netif_loopback_pkts_send(netif);
    process_post_poll_list(netif);
  }
  ci_assert_equal(netif->state->n_looppkts, 0);
  --netif->state->in_poll;

  /* Timer code can't use in-poll wakeup, since endpoints are out of
   * post-poll list.  So, poll timers after --in_poll. */
  ci_ip_timer_poll(netif);

  /* Timers MUST NOT send via loopback. */
  ci_assert(OO_PP_IS_NULL(netif->state->looppkts));

  if(CI_LIKELY( netif->state->rxq_low <= 1 ))
    netif->state->mem_pressure &= ~OO_MEM_PRESSURE_LOW;
  else
    netif->state->mem_pressure |= OO_MEM_PRESSURE_LOW;

  /* ?? TODO: move this into an unlock flag. */
  if(CI_UNLIKELY( netif->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL ))
    if( ci_netif_mem_pressure_try_exit(netif) )
      CITP_STATS_NETIF_INC(netif, memory_pressure_exit_poll);

  netif->state->poll_work_outstanding = 0;

  /* returns the number of events handled */
  return n_evs_handled;
}

/*! \cidoxg_end */
