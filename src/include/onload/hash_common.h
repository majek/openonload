/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

#ifndef __ONLOAD_HASH_COMMON_H__
#define __ONLOAD_HASH_COMMON_H__

#include <ci/tools/byteorder.h>
#include <ci/tools/log2.h>
#include <ci/compat.h>

/*!
** Hashing alternatives:
**
**  linear hashing  (good cache performance, but get clustering)
**  quadratic hashing  (try positions 1, 4, 9 away...)
**  double-hashing
**  re-hashing  (resize table or use different hash fn)
**
** Double-hashing: h(k,i) = (h1(k) + i*h2(k)) mod n    for i=0,1,2...
**   Require h2(k) be relatively prime in n.  eg. n is power 2, and h2(k)
**   is odd.
**
** Note that you get better cache performance w linear hashing, so it might
** be best on the host.
**
** Resources:
**  http://www.sci.csuhayward.edu/~billard/cs3240/node23.html
**  http://ciips.ee.uwa.edu.au/~morris/Year2/PLDS210/hash_tables.html
**  http://algorithm.myrice.com/resources/technical_artile/hashing_rehashed/hashing_rehashed.htm
**  http://www.cs.nyu.edu/courses/summer03/G22.1170-001/5-Hashing.pdf
**  http://uiorean.cluj.astral.ro/cursuri/dsa/6_Sda.pdf
*/

ci_inline unsigned onload_hash3(int af,
                                const void* laddr, unsigned lport,
                                const void* raddr, unsigned rport,
                                unsigned protocol) {
  unsigned laddr_xor = onload_addr_xor(af, laddr);
  unsigned raddr_xor = onload_addr_xor(af, raddr);
  unsigned h = CI_BSWAP_BE32(raddr_xor) ^ CI_BSWAP_LE32(laddr_xor) ^
               (rport << 16 | lport) ^ protocol;
  h ^= h >> 16;
  h ^= h >> 8;
  return h;
}

ci_inline unsigned onload_hash1(int af, unsigned size_mask,
                                const void* laddr, unsigned lport,
                                const void* raddr, unsigned rport,
                                unsigned protocol)
{
  ci_assert(CI_IS_POW2(size_mask + 1));
  return onload_hash3(af, laddr, lport, raddr, rport, protocol) & size_mask;
}

ci_inline unsigned onload_hash2(int af,
                                const void* laddr, unsigned lport,
                                const void* raddr, unsigned rport,
                                unsigned protocol) {
  unsigned laddr_xor = onload_addr_xor(af, laddr);
  unsigned raddr_xor = onload_addr_xor(af, raddr);

  /* N.B. rport and lport are in opposite words with respect to the calculation
   * in onload_hash1. */
  return (CI_BSWAP_LE32(laddr_xor ^ raddr_xor)
         ^ (lport << 16 | rport) ^ protocol) | 1u;
}

/* This variant of onload_hash2() has a better distribution when the
 * low bits of the addresses are zero, such as when they've been
 * masked off because the prefix length is less than 32. */
ci_inline unsigned cplane_hash2(int af,
                                const void* laddr, unsigned ifindex,
                                const void* raddr, unsigned tos) {
  unsigned laddr_xor = onload_addr_xor(af, laddr);
  unsigned raddr_xor = onload_addr_xor(af, raddr);

  /* N.B. ifindex and tos are in opposite words with respect to the
   * calculation in onload_hash1. */
  unsigned h = CI_BSWAP_LE32(raddr_xor) ^ CI_BSWAP_BE32(laddr_xor + raddr_xor) ^
               (ifindex << 16 | tos);
  h ^= h >> 16;
  h ^= h >> 8;
  return h | 1u;
}

#endif /* __ONLOAD_HASH_COMMON_H__ */
