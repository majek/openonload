/*
** Copyright 2005-2018  Solarflare Communications Inc.
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


#define MORE_STATS_DERIVED_DESC "derived statistic"

/* TCP states need to come first to match more_stats_t
 * and in the following order to match CI_TCP_STATE_NUM(state) index */
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_CLOSED, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_LISTEN, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_SYN_SENT, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_ESTABLISHED, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_CLOSE_WAIT, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_LAST_ACK, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_FIN_WAIT1, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_FIN_WAIT2, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_CLOSING, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_TIME_WAIT, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_STATE_FREE, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_STATE_UDP, val)
/* PIPE needs to be kept even for
 * non-PIPE builds */
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_STATE_PIPE, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_STATE_AUXBUF, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, TCP_STATE_ACTIVE_WILD, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, BAD_STATE, val)

OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, sock_orphans, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, sock_wake_needed_rx, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, sock_wake_needed_tx, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_has_recvq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_recvq_bytes, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_recvq_pkts, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_has_recv_reorder, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_recv_reorder_pkts, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_has_sendq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_sendq_bytes, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_sendq_pkts, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_has_inflight, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_inflight_bytes, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_inflight_pkts, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_n_in_listenq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, tcp_n_in_acceptq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_has_recvq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_recvq_pkts, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_has_sendq, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_sendq_bytes, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_tot_recv_pkts_ul, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_tot_recv_drops_ul, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_tot_recv_pkts_os, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_tot_send_pkts_ul, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, udp_tot_send_pkts_os, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_rx_ev_lost, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_rx_ev_bad_desc_i, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_rx_ev_bad_q_label, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_evq_gap, count)

#if CI_CFG_SEPARATE_UDP_RXQ
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_udp_rxq_rx_ev_lost, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_udp_rxq_rx_ev_bad_desc_i, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_udp_rxq_rx_ev_bad_q_label, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_udp_rxq_evq_gap, count)
#endif
