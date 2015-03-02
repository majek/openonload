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

#ifndef __CI_EFCH_MMAP_H__
#define __CI_EFCH_MMAP_H__

#include <ci/tools.h>  /* for CI_HAVE_OS_NOPAGE */
#include <ci/efch/mmap_id.h>

struct efrm_vi;


extern int
efab_vi_resource_mmap(struct efrm_vi *virs, unsigned long *bytes, void *opaque,
                      int *map_num, unsigned long *offset, int map_type);

extern int
efab_vi_resource_mmap_bytes(struct efrm_vi* virs, int map_type);

#ifdef CI_HAVE_OS_NOPAGE
extern unsigned long
efab_vi_resource_nopage(struct efrm_vi *virs, void *opaque,
                        unsigned long offset, unsigned long map_size);
#endif


#endif /* __CI_EFCH_MMAP_H__ */
