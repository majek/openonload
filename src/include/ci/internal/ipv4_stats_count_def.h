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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  jmj
**  \brief  Definition of ipv4 stack statistics
**   \date  2018/07/03
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/


OO_STAT("Total number of recieved datagrams.",
        CI_IP_STATS_TYPE, in_recvs,count)

OO_STAT("Number of datagrams discarded due to errors in their IP headers.",
        CI_IP_STATS_TYPE, in_hdr_errs,count)

OO_STAT("Number of datagrams discarded due to value of IP destination adress.",
        CI_IP_STATS_TYPE, in_addr_errs,count)

OO_STAT("Number of forwarded datagrams.",
        CI_IP_STATS_TYPE, forw_dgrams,count)

OO_STAT("Number of datagrams destined to unknown or unsupported protocols.",
        CI_IP_STATS_TYPE, in_unknown_protos,count)

OO_STAT("Number of input IP datagrams for which no problems were "
        "encountered to prevent their continued processing, but which "
        "were discarded (e.g., for lack of buffer space).",
        CI_IP_STATS_TYPE, in_discards,count)

OO_STAT("Total number of input datagrams successfully delivered to IP "
        "user-protocols.",
        CI_IP_STATS_TYPE, in_delivers,count)

OO_STAT("Total number of IP datagrams which local IP user-protocols "
        "(including ICMP) supplied to IP in request for transmission.",
        CI_IP_STATS_TYPE,out_requests,count)

OO_STAT("Number of output IP datagrams for which no problems "
        "were ecountered to prevent their countinued processing, but "
        "which were discarded (e.g., for lack of buffer space.",
        CI_IP_STATS_TYPE, out_discards,count)

OO_STAT("Number of IP datagrams discarded because no route could "
        "be found to transmit them to their destination.",
        CI_IP_STATS_TYPE, out_no_routes,count)

  /** this set of counters deal with IP fragmentation, which is not
   * supported, so they should be zero [RFC1213]*/
OO_STAT("Maximum number of seconds which received "
        "fragments are held while they are awaiting "
        "reassembly at this entity.(Not Supported)",
        CI_IP_STATS_TYPE, reasm_timeout,val)
OO_STAT("Number of IP fragments received which needed "
        "to be reassembled at this entity.(Not Supported)",
        CI_IP_STATS_TYPE, reasm_reqds,count)
OO_STAT("Number of IP datagrams successfully re-assembled.(Not Supported) ",
        CI_IP_STATS_TYPE, reasm_oks,count)
OO_STAT("Number of failures detected by the IP re-assembly algorithm."
        "(Not Supported)",
        CI_IP_STATS_TYPE, reasm_fails,count)
OO_STAT("Number of IP datagrams that have been "
        "successfully fragmented at this entity.(Not Supported)",
        CI_IP_STATS_TYPE, frag_oks,count)
OO_STAT("Number of IP datagrams that have been "
        "discarded because they needed to be fragmented at "
        "this entity but could not be.(Not Supported)",
        CI_IP_STATS_TYPE, frag_fails,count)
OO_STAT("The number of IP datagram fragments that have been generated "
        "as a result of fragmentation at this entity.(Not Supported)",
        CI_IP_STATS_TYPE, frag_creates,count)
