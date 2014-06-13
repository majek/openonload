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
  const ci_uint8* type_ptr = pkt->ether_base + 2 * ETH_ALEN;
  ci_assert_equal(pkt->pkt_layout, CI_PKT_LAYOUT_INVALID);
  if( *((const ci_uint16*)type_ptr) != CI_ETHERTYPE_8021Q ) {
    pkt->pkt_layout = CI_PKT_LAYOUT_RX_SIMPLE;
    pkt->vlan = 0;
  }
  else {
    const ci_uint8* vlan_ptr = pkt->ether_base + ETH_HLEN;
    pkt->pkt_layout = CI_PKT_LAYOUT_RX_VLAN;
    pkt->vlan = CI_BSWAP_BE16(*((const ci_uint16*)vlan_ptr)) & 0xfff;
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

  ci_assert_nequal(pkt->pkt_layout, CI_PKT_LAYOUT_INVALID);
  ci_assert(pkt->pkt_layout == CI_PKT_LAYOUT_RX_SIMPLE ||
            pkt->pkt_layout == CI_PKT_LAYOUT_RX_VLAN);
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
      ip_paylen = (int) ip_tot_len - sizeof(ci_ip4_hdr);
      /* This will go negative if the ip_tot_len was too small even
      ** for the IP header.  The ULP is expected to notice...
      */
      pkt->pay_len = ip_paylen;

      /* Demux to appropriate protocol. */
      if( ip->ip_protocol == IPPROTO_TCP ) {
        ci_tcp_handle_rx(netif, ps, pkt, (ci_tcp_hdr*) payload, ip_paylen);
        CI_IPV4_STATS_INC_IN_DELIVERS( netif );
        return;
      }
#if CI_CFG_UDP
      else if(CI_LIKELY( ip->ip_protocol == IPPROTO_UDP )) {
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
                        CI_MEMBER_OFFSET(ci_ip_pkt_fmt, ether_base)));
    s->frag_pkt = pkt;
    pkt->buf_len = s->frag_bytes = frame_bytes;
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), s->frag_bytes);
  }
  else {
    ci_assert(s->frag_pkt != NULL);
    ci_assert_gt(s->frag_bytes, 0);
    ci_assert_gt(frame_bytes, s->frag_bytes);
    pkt->buf_len = frame_bytes - s->frag_bytes;
    oo_offbuf_init(&pkt->buf, pkt->ether_base - (CI_CFG_RSS_HASH * 16),
                   pkt->buf_len);
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
        s->frag_pkt = PKT_CHK(ni, next_p);
      }
      s->rx_pkt = s->frag_pkt;
      s->rx_pkt->pay_len = s->frag_bytes;
      s->frag_pkt = NULL;
    }
  }
}


static void handle_rx_csum_bad(ci_netif* ni, struct ci_netif_poll_state* ps,
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

  ip = oo_ip_hdr(pkt);
  pkt->pay_len = frame_len;
  oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
  ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  ip_paylen = ip_len - sizeof(ci_ip4_hdr);

  if( ci_ip_csum_correct(ip, pkt->pay_len - oo_ether_hdr_size(pkt)) ) {
    if( pkt->pay_len < oo_ether_hdr_size(pkt) + ip_len ) {
      LOG_U(log(FN_FMT "BAD ip_len=%d frame_len=%d",
                FN_PRI_ARGS(ni), ip_len, pkt->pay_len));
    }
    else if( ip->ip_protocol == IPPROTO_TCP ) {
      if( ci_tcp_csum_correct(pkt, ip_paylen) ) {
        handle_rx_pkt(ni, ps, pkt);
        return;
      }
      else {
        LOG_U(log(FN_FMT "BAD TCP CHECKSUM %04x "PKT_DBG_FMT, FN_PRI_ARGS(ni),
                  (unsigned) PKT_TCP_HDR(pkt)->tcp_check_be16,
                  PKT_DBG_ARGS(pkt)));
        LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), frame_len, 0));
      }
    }
#if CI_CFG_UDP
    else if( ip->ip_protocol == IPPROTO_UDP ) {
      if( ci_udp_csum_correct(pkt, PKT_UDP_HDR(pkt)) ) {
        handle_rx_pkt(ni, ps, pkt);
        return;
      }
      else {
        CI_UDP_STATS_INC_IN_ERRS(ni);
        LOG_U(log(FN_FMT "BAD UDP CHECKSUM %04x", FN_PRI_ARGS(ni),
                  (unsigned) PKT_UDP_HDR(pkt)->udp_check_be16));
        LOG_U(ci_hex_dump(ci_log_fn, PKT_START(pkt), frame_len, 0));
      }
    }
#endif
  }
  else {
    CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
    LOG_U(log(FN_FMT "IP BAD CHECKSUM", FN_PRI_ARGS(ni)));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), frame_len, 0));
  }

  LOG_NR(log(LPF "DROP"));
  LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
  ci_netif_pkt_release_rx_1ref(ni, pkt);
}


static void handle_rx_no_desc_trunc(ci_netif* ni,
                                    struct ci_netif_poll_state* ps,
                                    struct oo_rx_state* s, ef_event ev)
{
  LOG_U(log(LPF "RX_NO_DESC_TRUNC "EF_EVENT_FMT, EF_EVENT_PRI_ARG(ev)));

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

  LOG_U(log(LPF "RX_DISCARD %d "EF_EVENT_FMT,
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
  if( EF_EVENT_RX_DISCARD_TYPE(ev) == EF_EVENT_RX_DISCARD_CSUM_BAD && 
      !is_frag )
    handle_rx_csum_bad(ni, ps, pkt,
                       EF_EVENT_RX_DISCARD_BYTES(ev) - (CI_CFG_RSS_HASH * 16));
  else
    ci_netif_pkt_release_rx_1ref(ni, pkt);

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

  if( need_wake )
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_WAKE);
}


#if CI_CFG_UDP

# define UDP_CAN_FREE(us)  ((us)->tx_count == 0)


void ci_netif_tx_pkt_complete_udp(ci_netif* netif,
                                  struct ci_netif_poll_state* ps,
                                  ci_ip_pkt_fmt* pkt)
{
  ci_udp_state* us;
  oo_pkt_p frag_next;

  ci_assert(oo_ip_hdr(pkt)->ip_protocol == IPPROTO_UDP);

  us = SP_TO_UDP(netif, pkt->pf.udp.tx_sock_id);

  ci_udp_dec_tx_count(us, pkt);

  if( ci_udp_tx_advertise_space(us) ) {
    if( ! (us->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      ci_udp_wake(netif, us, CI_SB_FLAG_WAKE_TX);
      ci_netif_put_on_post_poll(netif, &us->s.b);
    }
    else if( UDP_CAN_FREE(us) ) {
      ci_ni_dllist_remove_safe(netif, &us->s.b.post_poll_link);
      ci_udp_state_free(netif, us);
    }
  }

  while( 1 ) {
    if( pkt->refcount == 1 ) {
      frag_next = pkt->frag_next;

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
      if( OO_PP_IS_NULL(frag_next) )
        break;
      pkt = PKT_CHK(netif, frag_next);
    }
    else {
      ci_assert_gt(pkt->refcount, 1);
      --pkt->refcount;
      break;
    }
  }
}

#endif


#define CI_NETIF_TX_VI(ni, nic_i, label)  (&(ni)->nic_hw[nic_i].vi)


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

  s.rx_pkt = NULL;
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

    for( i = 0; i < n_evs; ++i ) {
      /* Look for RX events first to minimise latency. */
      if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX ) {
        CITP_STATS_NETIF_INC(ni, rx_evs);
        OO_PP_INIT(ni, pp, EF_EVENT_RX_RQ_ID(ev[i]));
        pkt = PKT_CHK(ni, pp);
        ci_prefetch(pkt->ether_base);
        ci_prefetch(pkt);
        ci_assert_equal(pkt->intf_i, intf_i);
        if( s.rx_pkt != NULL ) {
          ci_parse_rx_vlan(s.rx_pkt);
          handle_rx_pkt(ni, ps, s.rx_pkt);
        }
        if( (ev[i].rx.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                       == EF_EVENT_FLAG_SOP ) {
          /* Whole packet in a single buffer. */
          pkt->pay_len = EF_EVENT_RX_BYTES(ev[i]) - (CI_CFG_RSS_HASH * 16);
          oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
          s.rx_pkt = pkt;
        }
        else {
          handle_rx_scatter(ni, &s, pkt,
                            EF_EVENT_RX_BYTES(ev[i]) - (CI_CFG_RSS_HASH * 16),
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
          ci_netif_tx_pkt_complete(ni, ps, pkt);
        }
        ci_assert_equiv((ef_vi_transmit_fill_level(vi) == 0 &&
                         ni->state->nic[intf_i].dmaq.num == 0),
                        (ni->state->nic[intf_i].tx_dmaq_insert_seq ==
                         ni->state->nic[intf_i].tx_dmaq_done_seq));
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_NO_DESC_TRUNC ) {
        handle_rx_no_desc_trunc(ni, ps, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_DISCARD ) {
        handle_rx_discard(ni, ps, intf_i, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX_ERROR ) {
        LOG_U(log(LPF "TX_ERROR %d "EF_EVENT_FMT,
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

    total_evs += n_evs;
  } while( total_evs < NI_OPTS(ni).evs_per_poll );

  if( s.rx_pkt != NULL ) {
    ci_parse_rx_vlan(s.rx_pkt);
    handle_rx_pkt(ni, ps, s.rx_pkt);
  }

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
    if( ci_tcp_tx_advertise_space(ts) )
      ci_tcp_wake_not_in_poll(ni, ts, CI_SB_FLAG_WAKE_TX);
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

    LOG_NR(ci_log(N_FMT "loopback RX pkt %d: %d->%d", N_PRI_ARGS(ni),
                  OO_PKT_FMT(pkt),
                  OO_SP_FMT(pkt->pf.lo.tx_sock),
                  OO_SP_FMT(pkt->pf.lo.rx_sock)));

    ip = oo_ip_hdr(pkt);
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->buf_len);
    pkt->pay_len = CI_BSWAP_BE16(ip->ip_tot_len_be16) - sizeof(ci_ip4_hdr);
    pkt->intf_i = OO_INTF_I_LOOPBACK;
    pkt->flags &= CI_PKT_FLAG_NONB_POOL;
    pkt->flags |= CI_PKT_FLAG_RX;
    if( oo_tcpdump_check(ni, pkt, OO_INTF_I_LOOPBACK) )
      oo_tcpdump_dump_pkt(ni, pkt);
    pkt->next = OO_PP_NULL;
    /* ci_tcp_handle_rx will decrease n_rx_pkts, so increase it here */
    ++ni->state->n_rx_pkts;
    ci_tcp_handle_rx(ni, NULL, pkt, (ci_tcp_hdr*)(ip + 1), pkt->pay_len);
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
  --netif->state->in_poll;

  /* Timer code can't use in-poll wakeup, since endpoints are out of
   * post-poll list.  So, poll timers after --in_poll. */
  ci_ip_timer_poll(netif);

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
