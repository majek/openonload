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


int  ci_hex_dump_to_raw(const char* src_hex, void* buf,
			unsigned* addr_out_opt, int* skip)
{
  unsigned u[16];
  unsigned *up = &u[0];
  unsigned addr;
  ci_uint8* p;
  unsigned i, tot=0;
  int pos;

  ci_assert(src_hex);
  ci_assert(buf);
  ci_assert_equal(*skip % 1, 0);

  if (ci_sscanf(src_hex, " %x%n  ", &addr, &pos) < 1)
    return -1;


  for (i = 0 ; i < 16 ; i++) {    
    /* match whitespace */
    while (*(src_hex + pos) == ' ') pos++;

    /* match xx's to be skipped */
    if (*skip) {
      if (memcmp(src_hex + pos, "xx", 2) != 0) {
	ci_log("asked to drop data but it was not xx");
	return -1;
      }
      pos += 2;
      *skip -= 1;

    } else {
      /* match hex data */
      int n, used=0;

      n = ci_sscanf(src_hex + pos, "%2x%n", up, &used);
      if (n == 0) {
	if (!tot && memcmp(src_hex + pos, "xx", 2) == 0) {
	  ci_log("xx's detected in input. Try using the -d option?");
	  return -1;
	}
      }
      if (n > 0) {
	up += 1;
	pos += used;
	tot += n;
      }
    }
  }


  if( addr_out_opt )  *addr_out_opt = addr;

  p = (ci_uint8*) buf;
  for( i = 0; i < tot; ++i )
    *p++ = (ci_uint8) u[i];

  return tot;
}

/*! \cidoxg_end */
