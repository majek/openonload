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


#ifndef __CI_EFHW_HARDWARE_CI2LINUX_H__
#define __CI_EFHW_HARDWARE_CI2LINUX_H__

#include <ci/compat.h>

#define __iomem

#if CI_MY_BYTE_ORDER == CI_LITTLE_ENDIAN
#define EFHW_IS_LITTLE_ENDIAN
#else
#define EFHW_IS_BIG_ENDIAN
#endif


#ifndef PAGE_SIZE
#define PAGE_SIZE CI_PAGE_SIZE
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT CI_PAGE_SHIFT
#endif


#define mmiowb()
#define rmb ci_rmb
#define wmb ci_wmb


#endif /* __CI_EFHW_HARDWARE_CI2LINUX_H__ */
