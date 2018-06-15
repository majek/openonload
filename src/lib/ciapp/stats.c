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


#if CI_INCLUDE_ASSERT_VALID
void ci_iarray_assert_valid(const int* start, const int* end)
{
  ci_assert(start);
  ci_assert(end);
  ci_assert((((char*) end - (char*) start) & (sizeof(*start) - 1)) == 0);
}


void ci_iarray_assert_sorted(const int* start, const int* end)
{
  while( start + 1 != end )
    ci_assert(start[0] <= start[1]);
}
#endif

/*! \cidoxg_end */
