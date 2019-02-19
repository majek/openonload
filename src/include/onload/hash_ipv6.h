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

#ifndef __ONLOAD_HASH_IPV6_H__
#define __ONLOAD_HASH_IPV6_H__

#ifdef __ONLOAD_HASH_IPV_ANY_H__
#error "Both hash_ipv4.h and hash_ipv6.h should not be included"
#else
#define __ONLOAD_HASH_IPV_ANY_H__

#include <ci/tools/sysdep.h>

ci_inline unsigned onload_addr_xor(int af, const void* addr) {
  unsigned addr_xor = *(unsigned*)addr;

  if ( af == AF_INET6 ) {
    int i;

    for( i = 1; i < 4; i++ )
      addr_xor ^= *((unsigned*)addr + i);
  }

  return addr_xor;
}

#include <onload/hash_common.h>

#endif /* __ONLOAD_HASH_IPV_ANY_H__ */

#endif /* __ONLOAD_HASH_IPV6_H__ */
