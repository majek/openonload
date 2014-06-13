/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

typedef struct ci_ip6_hdr_s {
  ci_uint8  prio_version;
  ci_uint8  flow[3];
  ci_uint16 payload_len;
  ci_uint8  next_hdr;
  ci_uint8  hop_limit;
  ci_uint32 saddr[4];
  ci_uint32 daddr[4];
} ci_ip6_hdr;

#define CI_IP6_PRIORITY(ip) ((ip)->prio_version & 0xf)
#define CI_IP6_VERSION(ip)  ((ip)->prio_version >> 4u)

#endif /* __CI_NET_IPV6_H__ */
