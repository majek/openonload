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
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Code to ensure the CPU has all the features required by this build.
**   \date  2003/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_CPU_FEATURES_H__
#define __CI_TOOLS_CPU_FEATURES_H__

#define CI_CPU_OK 	(0)  /* CPU checked out ok */
#define CI_CPU_OLD 	(-1) /* CPU didn't respond to the cpuid instruction */
#define CI_CPU_ERROR	(-2) /* CPU cannot run this build */
#define CI_CPU_WARNING	(-3) /* CPU can run this build but performance could
				be impacted */

/*! Comment? */
extern int ci_cpu_features_check(int verbose);

#endif  /* __CI_TOOLS_CPU_FEATURES_H__ */

/*! \cidoxg_end */
