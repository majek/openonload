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
 ** \author  djr
 **  \brief  TCP helper dependent driver / kernel specifics for libef.
 **   \date  2006/06/13
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
\**************************************************************************/

/*! \cidoxg_lib_ef */

#include <ci/internal/ip.h>
#include <onload/tcp_driver.h>
#include <onload/tcp_helper_fns.h>

#ifndef __KERNEL__
# error "kernel-only source file"
#endif

int ci_tcp_helper_more_bufs(ci_netif* ni)
{
  return efab_tcp_helper_more_bufs(netif2tcp_helper_resource(ni));
}

int ci_tcp_helper_more_socks(ci_netif* ni)
{
  return efab_tcp_helper_more_socks(netif2tcp_helper_resource(ni));
}

#if CI_CFG_USERSPACE_PIPE
int ci_tcp_helper_pipebufs_to_socks(ci_netif* ni)
{
  return efab_tcp_helper_more_socks(netif2tcp_helper_resource(ni));
}
#endif

/*! \cidoxg_end */
