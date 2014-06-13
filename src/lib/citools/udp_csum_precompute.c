/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
**  \brief  Precompute partial checksum for UDP packet.
**   \date  2004/01/21
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_udp_csum_precompute(const ci_ip4_hdr* ip, const ci_udp_hdr* udp)
{
  ci_ip4_pseudo_hdr ph;
  const ci_uint16* p;
  unsigned csum;

  ci_assert(ip);
  ci_assert(udp);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);
  ci_assert(CI_PTR_OFFSET(udp, 4) == 0);

  p = (const ci_uint16*) ip;
  csum  = p[6];	/* ip_saddr_be32	  */
  csum += p[7];
  csum += p[8];	/* ip_daddr_be32	  */
  csum += p[9];
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_UDP;
  p = (const ci_uint16*) &ph;
  csum += p[4];	/* zero, ip_protocol */

  csum += udp->udp_source_be16;
  csum += udp->udp_dest_be16;

  return csum;
}

/*! \cidoxg_end */
