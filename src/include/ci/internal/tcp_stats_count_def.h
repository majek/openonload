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


OO_STAT("Number of times TCP connections have made a direct "
        "transition to the SYN-SENT state from the CLOSED state.",
        CI_IP_STATS_TYPE, tcp_active_opens, count)
OO_STAT("Number of times TCP connections have made a direct "
        "transition to the SYN-RCVD state from the LISTEN state.",
        CI_IP_STATS_TYPE, tcp_passive_opens, count)
OO_STAT("Number of times TCP connection have made a direct "
        "transition to the CLOSED state from the SYN-SENT state or the "
        "SYN-RCVD state, plus the number of times TCP connections have "
        "made a direct transition to the LISTEN state from "
        "the SYN-RCVD state.",
        CI_IP_STATS_TYPE, tcp_attempt_fails, count)
OO_STAT("Number of times TCP connections have made a direct transition to "
        "the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT "
        "state.",
        CI_IP_STATS_TYPE, tcp_estab_resets, count)
OO_STAT("Number of TCP connections for which the current state is either "
        "ESTABLISHED or CLOSE-WAIT.",
        CI_IP_STATS_TYPE, tcp_curr_estab, count)
OO_STAT("Total number of segments received, including those "
        "received in error.",
        CI_IP_STATS_TYPE, tcp_in_segs, count)
OO_STAT("Total number of segments sent, including those on current "
        "connections but excluding those containing only retransmitted octets .",
        CI_IP_STATS_TYPE, tcp_out_segs, count)
OO_STAT("Total number of segments retransmitted.",
        CI_IP_STATS_TYPE, tcp_retran_segs, count)
OO_STAT("Number of erroneous segments received.",
        CI_IP_STATS_TYPE, tcp_in_errs, count)
OO_STAT("Number of RST segments sent.",
        CI_IP_STATS_TYPE, tcp_out_rsts, count)
