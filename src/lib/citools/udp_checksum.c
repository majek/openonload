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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Compute Internet checksums.
**   \date  2003/01/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>

unsigned ci_udp_checksum(const ci_ip4_hdr* ip, const ci_udp_hdr* udp,
			 const ci_iovec *iov, int iovlen)
{
  ci_ip4_pseudo_hdr ph;
  unsigned paylen, csum;
  int n;

  ci_assert(ip);
  ci_assert(udp);
  ci_assert_ge(CI_BSWAP_BE16(ip->ip_tot_len_be16),
	       (int)(CI_IP4_IHL(ip) + sizeof(ci_udp_hdr)));

  ph.ip_saddr_be32 = ip->ip_saddr_be32;
  ph.ip_daddr_be32 = ip->ip_daddr_be32;
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_UDP;
  paylen = sizeof(ci_udp_hdr);
  for( n = 0; n < iovlen; n++ )
    paylen += CI_IOVEC_LEN(&iov[n]);
  ph.length_be16 = CI_BSWAP_BE16((ci_uint16) paylen);

  csum = ci_ip_csum_partial(0, &ph, sizeof(ph));
  csum = ci_ip_csum_partial(csum, udp, 6); /* omit udp_check_be16 */
  for( n = 0; n < iovlen; n++ )
    csum = ci_ip_csum_partial(csum, CI_IOVEC_BASE(&iov[n]),
                              CI_IOVEC_LEN(&iov[n]));
  return ci_udp_csum_finish(csum);
}

/*! \cidoxg_end */
