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
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Definition of user-specific options/restrictions
**   \date  2005/12/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


/* For a detailed explanation of how this macro system works, look at
 * <ci/internal/opts_netif_def.h>
 *
 *     CI_CFG_OPT(type, type_modifider, name, group, default,
 *                minimum, maximum, presentation)
 */

#ifdef CI_CFG_OPTFILE_VERSION
CI_CFG_OPTFILE_VERSION(100)
#endif

