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
**  \brief  Compute Internet checksums.
**   \date  2003/01/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
 
/*! \cidoxg_lib_citools */
 
#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_ip_csum_partial(unsigned sum, const volatile void* in_buf,
			    int bytes)
{
  const ci_uint16* buf = (const ci_uint16*) in_buf;

  ci_assert(in_buf || bytes == 0);
  ci_assert(bytes >= 0);

  while( bytes > 1 ) {
    sum += *buf++;
    bytes -= 2;
  }

  /* If there's a lone final byte, it needs to be treated as if it was
   * padded by an extra zero byte.  Casting to ci_uint8* introduces an
   * implicit CI_BSWAP_LE16 which needs to be reversed. */
  sum += bytes ? CI_BSWAP_LE16(*(ci_uint8*) buf) : 0;

  return sum;
}

/*! \cidoxg_end */
