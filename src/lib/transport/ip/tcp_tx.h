/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#ifndef __TCP_TX_H__
#define __TCP_TX_H__


/*
** Fill out the timestamp option on a given packet
*/
ci_inline int ci_tcp_tx_opt_tso(ci_uint8** opt,
                                ci_uint32 tsval, ci_uint32 tsecr)
{
  *(ci_uint32*)(*opt) = CI_TCP_TSO_WORD;
  *(ci_uint32*)(*opt + 4) = CI_BSWAP_BE32(tsval);
  *(ci_uint32*)(*opt + 8) = CI_BSWAP_BE32(tsecr);
  *opt += 12;
  return 12;
}


/* finish off a transmitted data segment by:
**   - snarfing a timestamp for RTT measurement
**   - timestamps
** could be a place to deal with ECN.
** We could not deal with outgoing SACK here, because it will change packet
** length.
*/
ci_inline void ci_tcp_tx_finish(ci_netif* netif, ci_tcp_state* ts,
                                ci_ip_pkt_fmt* pkt)
{
  ci_tcp_hdr* tcp = TX_PKT_TCP(pkt);
  ci_uint8* opt = CI_TCP_HDR_OPTS(tcp);
  int seq = pkt->pf.tcp_tx.start_seq;

  /* Decrement the faststart counter by the number of bytes acked */
  ci_tcp_reduce_faststart(ts, SEQ_SUB(tcp_rcv_nxt(ts),ts->tslastack));

  /* put in the TSO & SACK options if needed */
  ts->tslastack = tcp_rcv_nxt(ts); /* also used for faststart */
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    unsigned now =  ci_tcp_time_now(netif);
    ci_tcp_tx_opt_tso(&opt, now, ts->tsrecent);
  } else {
    /* do snarf for RTT timing if not using timestamps */
    if( CI_LIKELY((ts->congstate == CI_TCP_CONG_OPEN) |
                  (ts->congstate == CI_TCP_CONG_NOTIFIED)) ) {
      /* setup new timestamp off this packet
      ** if we are not measuring already */
      if( !SEQ_LE(tcp_snd_una(ts), ts->timed_seq) ) {
        ci_tcp_set_rtt_timing(netif, ts, seq);
      }
    } else {
      /* congested use Karn's algorithm and only measure segments
      ** after the congrecover, anything else must be a retransmit
      */
      if( SEQ_LE(ts->congrecover, seq) &&
          !SEQ_LE(tcp_snd_una(ts), ts->timed_seq) ) {
        /* forward transmission while in recovery so timing possible */
        ci_tcp_set_rtt_timing(netif, ts, seq);
      }
    }
  }

  tcp->tcp_seq_be32 = CI_BSWAP_BE32(seq);
}


ci_inline void ci_tcp_ip_hdr_init(ci_ip4_hdr* ip, unsigned len)
{
  ci_assert_equal(CI_IP4_IHL(ip), sizeof(ci_ip4_hdr));
  ip->ip_tot_len_be16 = CI_BSWAP_BE16((ci_uint16) len);
  ci_assert_equal(ip->ip_check_be16, 0);
  ci_assert_equal(ip->ip_id_be16, 0);
}


ci_inline void __ci_tcp_calc_rcv_wnd(ci_tcp_state* ts)
{
  /* Calculate receive window, avoiding silly windows and snap-back. */

  int new_window;
  unsigned new_rhs;
  ci_uint16 tmp;

  new_window = CI_MIN(ts->rcv_window_max,
                      ts->s.so.rcvbuf -
                        SEQ_SUB(tcp_rcv_nxt(ts), ts->rcv_delivered));
  new_rhs = tcp_rcv_nxt(ts) + new_window;

  /* Check that the right window edge moves forward by at least the AMSS,
   * as required by RFC1122 silly window avoidance.
   *
   * Do not apply silly window avoidance when we have nothing to read:
   * probably, rcvbuff is too small.
   */
  if( CI_LIKELY( SEQ_GE(new_rhs, ts->rcv_wnd_right_edge_sent + ts->amss) )
      || tcp_rcv_usr(ts) == 0 ) {
    /* We are ready to move on the window right edge. */
    ts->rcv_wnd_advertised = new_window;
    tcp_rcv_wnd_right_edge_sent(ts) = new_rhs;
  }
  else {
    /* Snapback and silly window avoidance mode: Work out a new window
     * value that keeps the right hand edge constant given the current
     * value of tcp_rcv_nxt.
     */
    new_window = ts->rcv_wnd_right_edge_sent - tcp_rcv_nxt(ts);
    ts->rcv_wnd_advertised = CI_MIN(new_window,
                                    CI_CFG_TCP_MAX_WINDOW << ts->rcv_wscl);
  }

  tmp = ts->rcv_wnd_advertised >> ts->rcv_wscl;
  TS_TCP(ts)->tcp_window_be16 = CI_BSWAP_BE16(tmp);
  CI_IP_SOCK_STATS_VAL_RXWIN(ts, ts->rcv_wnd_advertised);
}


#define ci_tcp_calc_rcv_wnd(ts, caller)  __ci_tcp_calc_rcv_wnd(ts)


ci_inline void ci_tcp_tx_maybe_do_striping(ci_ip_pkt_fmt* pkt,
                                           ci_tcp_state* ts) {
#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
    pkt->netif.tx.intf_swap = ci_ts_port_swap(pkt->pf.tcp_tx.start_seq, ts);
#endif
}

#endif  /* __TCP_TX_H__ */
