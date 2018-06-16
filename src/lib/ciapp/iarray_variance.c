/*
** Copyright 2005-2018  Solarflare Communications Inc.
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


void ci_iarray_variance(const int* start, const int* end,
			 int mean, ci_int64* variance_out)
{
  ci_int64 sumsq, diff;
  const int* i;

  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);
  ci_assert(variance_out);

  if( end - start < 2 ) {
    *variance_out = 0;
    return;
  }

  sumsq = 0;

  for( i = start; i != end; ++i ) {
    diff = *i - mean;
    sumsq += diff * diff;
  }

  *variance_out = sumsq / (end - start - 1);
}

/*! \cidoxg_end */
