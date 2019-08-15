/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


void ci_iarray_mode(const int* start, const int* end, int* mode_out)
{
  int current_v, mode, current_n, mode_n;
  const int* i;

  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);
  ci_assert(mode_out);

  current_v = mode = *start;
  current_n = mode_n = 1;

  for( i = start + 1; i != end; ++i ) {
    if( *i != current_v ) {
      if( current_n > mode_n ) {
	mode_n = current_n;
	mode = current_v;
      }
      current_v = *i;
      current_n = 0;
    }
    ++current_n;
  }
  if( current_n > mode_n ) {
    mode_n = current_n;
    mode = current_v;
  }

  *mode_out = mode;
}

/*! \cidoxg_end */
