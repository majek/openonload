/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
*//*! \file pcap.c
** <L5_PRIVATE L5_SOURCE>
** \author  ak
**  \brief  Interface to common transport logging functions
**   \date  2005/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_common */

#include <ci/internal/transport_common.h>

/* ***************************
 * Global vars
 */

/*! Current logging level/mask */
unsigned citp_log_level = CI_UL_LOG_E | CI_UL_LOG_U;


/*! \cidoxg_end */
