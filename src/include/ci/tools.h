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
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci */

#ifndef __CI_TOOLS_H__
#define __CI_TOOLS_H__

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>
#include <ci/tools/sysdep.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <ci/tools/memleak_debug.h>
#include <ci/tools/config.h>
#include <ci/tools/utils.h>
#include <ci/tools/buffer.h>
#include <ci/tools/bufrange.h>
#include <ci/tools/sllist.h>
#include <ci/tools/dllist.h>
#include <ci/tools/spinlock.h>
#include <ci/tools/buddy.h>
#include <ci/tools/stacks.h>
#include <ci/tools/fifo.h>
#include <ci/tools/fifos.h>
#include <ci/tools/magic.h>
#include <ci/tools/iovec.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/ipcsum.h>
#include <ci/tools/cpu_features.h>

#ifdef __cplusplus
}
#endif

#endif  /* __CI_TOOLS_H__ */

/*! \cidoxg_end */
