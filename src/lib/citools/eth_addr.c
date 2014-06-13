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
 ** \author  
 **  \brief  
 **   \date  
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/
 
 /*! \cidoxg_lib_citools */
 
#include "citools_internal.h"


int ci_format_eth_addr(char* buf, const void* eth_mac_addr, char sep)
{
  const unsigned char* p;
  p = (const unsigned char*) eth_mac_addr;

  ci_assert(buf);
  ci_assert(eth_mac_addr);

  if( sep == 0 )  sep = ':';

  return ci_sprintf(buf, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
		 (unsigned) p[0], sep, (unsigned) p[1], sep, 
		 (unsigned) p[2], sep, (unsigned) p[3], sep,
		 (unsigned) p[4], sep, (unsigned) p[5]);
}

/*! \cidoxg_end */
