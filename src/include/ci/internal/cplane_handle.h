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


#ifndef __CI_INTERNAL_CPLANE_HANDLE_H__
#define __CI_INTERNAL_CPLANE_HANDLE_H__

/*----------------------------------------------------------------------------
 * Control Plane Handle
 *---------------------------------------------------------------------------*/

/* We define cicp_handle_t as the chosen type to represent access to the
   control plane in either the user mode or the driver.
   In code that may execute in either user or kernel mode the macro
   
       CICP_HANDLE(netif) : returns cicp_handle_t
       
   will always deliver a value of that type.
   This handle can always be used with

       CICP_MIBS(handle) : returns cicp_mibs_kern_t in kernel (read-write), or
                         : returns cicp_mibs_user_t in user mode (read-only)
       
   to return a pointer to the (available) table definitions
*/

/* can't yet handle this in Windows user-level driver builds */
#if defined(__ci_driver__)
#include <onload/tcp_driver.h>

#define CICP_HANDLE(netif) (&CI_GLOBAL_CPLANE)

#else

#define CICP_HANDLE(netif) (netif)

#endif


#endif /* __CI_INTERNAL_CPLANE_HANDLE_H__ */
