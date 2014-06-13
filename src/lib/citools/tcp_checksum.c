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

/* 0xffff is an impossible checksum for TCP and IP (special case for UDP)
** This is because you would need the partial checksum when folded to be
** 0 (so it inverts to ffff). The checksum is additive so you can only
** add to the next multiple of 0x10000 and that will always get folded
** back again
*/

unsigned ci_tcp_checksum(const ci_ip4_hdr* ip, const ci_tcp_hdr* tcp,
			 const void* payload)
{
  ci_ip4_pseudo_hdr ph;
  unsigned paylen, csum; /* csum is a BE value */

  /* NB: csum can be maintained as BE value even with LE addition operations
   * because all inputs are BE values and the folding of overflow means
   * that carry going the "wrong way" between the bytes doesn't matter
   * after folding as the scheme is somewhat "symmetrical"
   */

  ci_assert(ip);
  ci_assert(tcp);
  ci_assert(CI_BSWAP_BE16(ip->ip_tot_len_be16) >=
	    CI_IP4_IHL(ip) + CI_TCP_HDR_LEN(tcp));
  ci_assert(payload || (CI_BSWAP_BE16(ip->ip_tot_len_be16) ==
			CI_IP4_IHL(ip) + CI_TCP_HDR_LEN(tcp)));

  paylen = CI_BSWAP_BE16(ip->ip_tot_len_be16) - CI_IP4_IHL(ip);

  ph.ip_saddr_be32 = ip->ip_saddr_be32;
  ph.ip_daddr_be32 = ip->ip_daddr_be32;
  ph.zero = 0;
  ph.ip_protocol = (ci_uint8)IPPROTO_TCP;
  ph.length_be16 = CI_BSWAP_BE16((ci_uint16) paylen);

  csum = ci_ip_csum_partial(0, &ph, sizeof(ph));
  csum = ci_ip_csum_partial(csum, tcp, CI_TCP_HDR_LEN(tcp));
  csum -= tcp->tcp_check_be16;
  csum = ci_ip_csum_partial(csum, payload, paylen - CI_TCP_HDR_LEN(tcp));

  /* BE value */
  return ci_tcp_csum_finish(csum);
}

/*! \cidoxg_end */
