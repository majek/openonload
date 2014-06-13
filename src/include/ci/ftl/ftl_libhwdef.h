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
** \author  cgg
**  \brief  ftl_libhwdef.h      FTL library for libhwdef access
**   \date  2008/09
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* Inclusion of this headers must be preceded by one for ftl.h */
   
/*! \cidoxg_tests_nic */

#ifndef _FTL_LIBHWDEF_H
#define _FTL_LIBHWDEF_H

#include <ci/driver/efab/hardware/hwd.h> /*< for HWD_* map IDs */

#ifdef __cplusplus
extern "C" {
#endif

/*! Create an FTL directory (c.f. struct) representing information about a
 *  register field
 */
extern dir_t *
dir_field_new(hwd_deffieldobj_t* field, int access_group);

/*! Create an FTL directory (c.f. dictionary) representing a list of named
 * fields
 */
extern dir_t *
dir_fieldlist_new(hwd_defobj_t* fielddef, ci_uint8 regwidth, int access_group,
                  hwd_version_t version);

/*! Create an FTL directory (c.f. struct) representing information about a 
 *  register
 */
extern dir_t *
dir_reg_new(hwd_ifmaptblobj_t* reg, int access_group, hwd_version_t version);

/*! Create an FTL directory (c.f. dictionary) representing information about
 *  an address space (a list of named regisers)
 */
extern dir_t *
dir_map_new(hwd_ifmaptblobj_t* mapbase, size_t entries, int access_group,
            hwd_version_t version, int rtlblock);
/*! Create an FTL directory (c.f. dictionary) representing information about
 *  a NIC with a given version (a list of named bars)
 */
extern dir_t *
dir_maplist_new(hwd_version_t version, int rtlblock);

#endif /* _FTL_LIBHWDEF_H */

