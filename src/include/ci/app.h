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
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci */

#ifndef __CI_APP_H__
#define __CI_APP_H__

#ifdef __KERNEL__
# error This header should not be included in __KERNEL__ builds.
#endif

#ifndef __CI_TOOLS_H__
# include <ci/tools.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

# include <ci/app/platform/unix.h>

#include <ci/app/utils.h>
#include <ci/app/testapp.h>
#include <ci/app/net.h>
#include <ci/app/ctimer.h>
#include <ci/app/stats.h>
#include <ci/app/testpattern.h>

#ifdef __cplusplus
}
#endif

#endif  /* __CI_APP_H__ */

/*! \cidoxg_end */
