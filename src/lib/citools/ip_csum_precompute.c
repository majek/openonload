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
 **  \brief  Precompute partial checksum for IP header.
 **   \date  2004/01/21
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/
  
 /*! \cidoxg_lib_citools */
  
#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_ip_csum_precompute(const ci_ip4_hdr* ip)
{
  const ci_uint16* p = (const ci_uint16*) ip;
  unsigned csum;

  ci_assert(ip);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);

  csum  = p[0];	/* ip_ihl_version, ip_tos */
  csum += p[3];	/* ip_frag_off_be16	  */
  csum += p[4];	/* ip_ttl, ip_protocol	  */
  csum += p[6];	/* ip_saddr_be32	  */
  csum += p[7];
  csum += p[8];	/* ip_daddr_be32	  */
  csum += p[9];
  return csum;
}

/*! \cidoxg_end */
