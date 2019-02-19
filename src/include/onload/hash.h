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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mjp
**  \brief  Hash functions for implementing lookup tables
**   \date  2017/07/14
**    \cop  (c) 2017 Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_HASH_H__
#define __ONLOAD_HASH_H__

#include <ci/internal/transport_config_opt.h>

/*
 * There are hash_ipv4.h and hash_ipv6.h header files which are included
 * depending on CI_CFG_IPV6 parameter defined in transport_config_opt.h.
 * hash_ipv4.h contains IPv4-specific onload_addr_xor function, and
 * hash_ipv6.h - onload_addr_xor corresponding to both IPv4 and IPv6.
 */
#if CI_CFG_IPV6
#include <onload/hash_ipv6.h>
#else
#include <onload/hash_ipv4.h>
#endif

#endif /* __ONLOAD_HASH_H__ */
