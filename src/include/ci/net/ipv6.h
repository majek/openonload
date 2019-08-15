/*
** Copyright 2005-2019  Solarflare Communications Inc.
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
** \author  kjm
**  \brief  Internet protocol definitions.
**   \date  2009/03
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_IPV6_H__
#define __CI_NET_IPV6_H__

/**********************************************************************
 ** IP
 */

typedef ci_uint8 ci_ip6_addr_t[16];

typedef struct ci_ip6_hdr_s {
  ci_uint8  prio_version;
  ci_uint8  flow[3];
  ci_uint16 payload_len;
  ci_uint8  next_hdr;
  ci_uint8  hop_limit;
  ci_ip6_addr_t saddr;
  ci_ip6_addr_t daddr;
} ci_ip6_hdr;

#define CI_IP6_PRIORITY(ip) ((ip)->prio_version & 0xf)
#define CI_IP6_VERSION(ip)  ((ip)->prio_version >> 4u)

#define CI_IP6_PRINTF_FORMAT \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

#define CI_IP6_PRINTF_ARGS(ip) \
    ip[0], ip[1], ip[2], ip[3], \
    ip[4], ip[5], ip[6], ip[7], \
    ip[8], ip[9], ip[10], ip[11], \
    ip[12], ip[13], ip[14], ip[15]

#define CI_INET6_ADDRSTRLEN 46

#define CI_IP6_IS_MULTICAST(a) (((const ci_uint8 *) (a))[0] == 0xff)

#define CI_IP6_ADDR_CMP(addr1, addr2) memcmp((addr1), (addr2), \
    sizeof(ci_ip6_addr_t))

#endif /* __CI_NET_IPV6_H__ */
