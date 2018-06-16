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


/**********************************************************************
 * ci_ctimer_calibrate()
 */

void ci_ctimer_calibrate(ci_ctimer_inf* i)
{
  int n = 20;
  ci_int64 min = 1000;
  ci_ctimer t;
  i->overhead = 0;

  while( n-- ) {
    ci_ctimer_start_accurate(&t);
    ci_ctimer_stop_accurate(i, &t);

    if( i == 0 || ci_ctimer_cycles(&t) < min )
      min = ci_ctimer_cycles(&t);
  }

  i->overhead = min;
}


/**********************************************************************
 * ci_ctimer_init()
 */

int ci_ctimer_init(ci_ctimer_inf* i)
{
  int rc;
  unsigned khz;

  rc = ci_get_cpu_khz(&khz);
  if( rc < 0 )  return rc;

  i->hz = (ci_int64) khz * 1000u;
  ci_ctimer_calibrate(i);

  return 0;	
}

/*! \cidoxg_end */
