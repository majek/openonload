/*
** Copyright 2005-2015  Solarflare Communications Inc.
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


void __ci_sys_fail(const char* fn, int rc, const char* file, int line)
{
  ci_log("*** UNEXPECTED ERROR ***");
  ci_log("        what: %s", fn);
  ci_log(" called from: %s:%d", file, line);
  ci_log(" return code: %d", rc);
#ifndef __KERNEL__
  ci_log("       errno: %d", errno);
  ci_log("    strerror: %s", strerror(errno));
#endif
  ci_fail((" "));
}

/*! \cidoxg_end */
