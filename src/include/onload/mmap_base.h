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

#ifndef __ONLOAD_MMAP_BASE_H__
#define __ONLOAD_MMAP_BASE_H__

/*********************************************************************
***************************** Memory maps ****************************
*********************************************************************/

/* Mmap offset is multiple of PAGE_SIZE.  Mmaps with different offsets may
 * "virtually overlap", i.e. the "offset" number can be considered as
 * opaque ID for a given memory area.
 *
 * High bits of the offset is used to define "mapping type"
 * and the rest is parsed depending on the "type".
 */

/* Mapping types.  The low OO_MMAP_TYPE_SHIFT bits are available for use by
 * each mapping type. */
#define OO_MMAP_TYPE_NETIF        0
#define OO_MMAP_TYPE_CPLANE       1
#ifdef __x86_64__
# define OO_MMAP_TYPE_DSHM        2
#endif

#define OO_MMAP_TYPE_MASK        0x3
#define OO_MMAP_TYPE_WIDTH       2
#define OO_MMAP_TYPE_SHIFT       CI_PAGE_SHIFT
#define OO_MMAP_ID_SHIFT         (OO_MMAP_TYPE_WIDTH + OO_MMAP_TYPE_SHIFT)
#define OO_MMAP_TYPE(offset) \
    (((offset) >> OO_MMAP_TYPE_SHIFT) & OO_MMAP_TYPE_MASK)
#define OO_MMAP_ID(offset)       ((offset) >> OO_MMAP_ID_SHIFT)


#endif /* __ONLOAD_MMAP_BASE_H__ */
