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


#ifndef __CI_EFHW_DEBUG_CI2LINUX_H__
#define __CI_EFHW_DEBUG_CI2LINUX_H__

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>

#define printk    ci_log
#define printk_nl ""

#define KERN_ERR        "ERR>"
#define KERN_WARNING    "WARN>"
#define KERN_NOTICE     "NOTICE>"
#define KERN_DEBUG      "DBG>"

# define BUG_ON(cond) ci_assert((cond) == 0)
# define BUG() ci_assert(0)

#endif /* __CI_EFHW_DEBUG_CI2LINUX_H__ */
