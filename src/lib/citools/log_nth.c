/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

#ifndef  CI_LOG_FN_DEFAULT
# define CI_LOG_FN_DEFAULT  ci_log_stderr
#endif

void (*__ci_log_nth_fn)(const char* msg) = CI_LOG_FN_DEFAULT;
int  ci_log_nth_n = 100;


void __ci_log_nth(const char* msg)
{
  static int n = 0;

  /* Avoid the obvious loop.  Other loops possible though... */
  if( __ci_log_nth_fn == ci_log_fn )  return;

  if( n % ci_log_nth_n == 0 )  __ci_log_nth_fn(msg);
  ++n;
}

/*! \cidoxg_end */
