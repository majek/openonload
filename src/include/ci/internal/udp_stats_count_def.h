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
**  \brief  Definition of udp stack statistics
**   \date  2018/07/03
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

OO_STAT("Total number of UDP datagrams delivered to UDP users.",
        CI_IP_STATS_TYPE, udp_in_dgrams, count)

OO_STAT("Total number of received UDP datagrams for which "
        "there was no application at the destination port.",
        CI_IP_STATS_TYPE, udp_no_ports, count)

OO_STAT("Number of received UDP datagrams that could not be delivered "
        "for reason other than the lack of an application at the destination "
        "port.",
        CI_IP_STATS_TYPE, udp_in_errs, count)

OO_STAT("Total number of UDP datagrams sent from this entity.",
        CI_IP_STATS_TYPE, udp_out_dgrams, count)
