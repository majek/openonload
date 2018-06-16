/*
** Copyright 2005-2018  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Checksum utility functions.
** \date      2017/11/17
** \copyright Copyright &copy; 2017 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_CHECKSUM_H__
#define __EFAB_CHECKSUM_H__

#include <etherfabric/base.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Calculate the checksum for an IP header
**
** \param ip The IP header to use.
**
** \return The checksum of the IP header.
**
** Calculate the checksum for an IP header.
*/
extern uint32_t ef_ip_checksum(const struct iphdr* ip);

/*! \brief Calculate the checksum for a UDP packet
**
** \param ip     The IP header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the UDP packet.
**
** Calculate the checksum for a UDP packet.
*/
extern uint32_t
ef_udp_checksum(const struct iphdr* ip, const struct udphdr* udp,
                const struct iovec* iov, int iovlen);
                
/*! \brief Calculate the checksum for a TCP packet
**
** \param ip     The IP header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the TCP packet.
**
** Calculate the checksum for a TCP packet.
*/
extern uint32_t
ef_tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp,
                const struct iovec* iov, int iovlen);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_CHECKSUM_H__ */
