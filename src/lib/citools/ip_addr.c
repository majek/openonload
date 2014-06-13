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
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
 
/*! \cidoxg_lib_citools */
 
#include "citools_internal.h"


int ci_format_ip4_addr(char* buf, unsigned addr_be32)
{
  const unsigned char* p;
  p = (const unsigned char*) &addr_be32;

  ci_assert(buf);

  return ci_sprintf(buf, "%u.%u.%u.%u",
		 (unsigned) p[0], (unsigned) p[1],
		 (unsigned) p[2], (unsigned) p[3]);
}

/*! \cidoxg_end */
