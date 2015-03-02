/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** \author  djr/stg
**  \brief  Compute Internet checksums.
**   \date  2004/10/26
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_icmp_checksum(const ci_ip4_hdr* ip, const ci_icmp_hdr* icmp)
{
  unsigned csum;

  ci_assert(ip);
  ci_assert(icmp);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);
  ci_assert(CI_PTR_OFFSET(icmp, 4) == 0);
  ci_assert(sizeof(ci_icmp_hdr) == 4);
  ci_assert(CI_BSWAP_BE16(ip->ip_tot_len_be16) >=
	    (int) (CI_IP4_IHL(ip) + sizeof(ci_icmp_hdr)));

  /* This gets the [type] and [code] fields. */
  csum = *(ci_uint16*) icmp;
  /* Omit the [check] field and sum the rest. */
  csum = ci_ip_csum_partial(csum, icmp, (CI_BSWAP_BE16(ip->ip_tot_len_be16)
					 - CI_IP4_IHL(ip)
					 - sizeof(ci_icmp_hdr)));
  return ci_icmp_csum_finish(csum);
}

/*! \cidoxg_end */
