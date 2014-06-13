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
** \author  ok_sasha
**  \brief  Char driver operations API
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_efrm  */

#ifndef __CI_DRIVER_EFAB_OPERATIONS_H__
#define __CI_DRIVER_EFAB_OPERATIONS_H__

#include <ci/tools/sysdep.h>
#include <ci/tools/timeval.h>
#include <ci/efhw/common.h>
#include <ci/driver/efab/efch_id.h>
#include <ci/efrm/resource_id.h>


#if 1 && defined(__ONLOAD_COMMON_H__)
#error "You should select one driver to talk with -- char or onload"
#endif


/*----------------------------------------------------------------------------
 *
 *  Mmap-related macros
 *
 *---------------------------------------------------------------------------*/

/* TODO: considering moving OS specific mmap stuff somewhere else */
/* mmap offsets must be page aligned, hence the bottom PAGE_SHIFT bits must
** be zero.  To be conservative we should assume 8k pages and 32-bit
** offset.  That leaves is with 19 bits to play with.  We current use 5 for
** the resource id, and 12 for the map_id (total 17).
*/
#define EFAB_MMAP_OFFSET_MAP_ID_BITS  (19u - EFRM_RESOURCE_MAX_PER_FD_BITS)
#define EFAB_MMAP_OFFSET_MAP_ID_MASK  ((1u << EFAB_MMAP_OFFSET_MAP_ID_BITS)-1u)
#define EFAB_MMAP_OFFSET_ID_MASK      (EFRM_RESOURCE_MAX_PER_FD - 1u)

ci_inline off_t
EFAB_MMAP_OFFSET_MAKE(efch_resource_id_t id, unsigned map_id) {
  return (id.index | (map_id << EFRM_RESOURCE_MAX_PER_FD_BITS))
         << CI_PAGE_SHIFT;
}

ci_inline efch_resource_id_t
EFAB_MMAP_OFFSET_TO_RESOURCE_ID(off_t offset) {
  efch_resource_id_t id;
  id.index = (offset >> CI_PAGE_SHIFT) & EFAB_MMAP_OFFSET_ID_MASK;
  return id;
}

ci_inline unsigned
EFAB_MMAP_OFFSET_TO_MAP_ID(off_t offset)
{ return offset >> (CI_PAGE_SHIFT + EFRM_RESOURCE_MAX_PER_FD_BITS); }


/*--------------------------------------------------------------------
 *
 * Driver entry points
 *
 *--------------------------------------------------------------------*/

/* Worth changing this base whenever you change an ioctl in an incompatible
** way, so we can catch the error more easily...
*/
#define CI_IOC_CHAR_BASE       81

#define CI_RESOURCE_OP      (CI_IOC_CHAR_BASE+ 0)  /* ioctls for resources */
#define CI_RESOURCE_ALLOC   (CI_IOC_CHAR_BASE+ 1)  /* allocate resources   */
#define CI_IOC_CHAR_MAX     (CI_IOC_CHAR_BASE+ 2)


#endif /* __CI_DRIVER_EFAB_OPERATIONS_H__ */
/*! \cidoxg_end */
