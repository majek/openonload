/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
**  \brief  EtherFabric NIC FD private info for driver
**   \date  2006/08/25
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_FDPRIVATE_H__
#define __CI_DRIVER_EFAB_FDPRIVATE_H__

/*--------------------------------------------------------------------
 *
 * headers for type dependencies 
 *
 *--------------------------------------------------------------------*/

#include <onload/tcp_helper.h>
#include <onload/osfile.h>

/*--------------------------------------------------------------------
 *
 * ci_private_t - holds the per file descriptor private state - private.c
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct ci_private_s {
  tcp_helper_resource_t *thr; /* Keep it first! */

  /* A [ci_private_t] may be specialised so it can handle certain O/S
  ** interfaces.  For example, to handle read, write or select system
  ** calls.  (On Linux this is done by replacing the file_operations.  The
  ** following fields (prefixed with spec_) relate to specialised
  ** endpoints:
  */
  char			fd_type;
  /*! See common.h CI_PRIV_TYPE_* for type definitions. */
  oo_sp                 sock_id;	/*! id of ep */

  ci_os_file  _filp;
} ci_private_t;

#endif  /* __CI_DRIVER_EFAB_FDPRIVATE_H__ */

/*! \cidoxg_end */
