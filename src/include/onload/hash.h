/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/* Top-level file must define CI_CFG_IPV6 in some way */

#include <ci/net/ipvx.h>

/* onload_addr_xor() DOES NOT returns the same result for IPv4 address
 * in natural form (!CI_CFG_IPV6) and in IPv6-mapped form.
 * However it us harmless for all the existing use-cases:
 * - All the Onload code is compiled in the same way;
 * - All the Cplane code is always compiled with CI_CFG_IPV6.
 *
 * If you are writing more cplane code, in particular cplane library linked
 * with Onload, ensure that your code is always compiled with CI_CFG_IPV6.
 */
ci_inline unsigned onload_addr_xor(const ci_addr_t addr)
{
#if CI_CFG_IPV6
  unsigned addr_xor = 0;
  int i;
  for( i = 0; i < 4; i++ )
    addr_xor ^= addr.u32[i];
  return addr_xor;
#else
  return addr.ip4;
#endif
}


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

ci_inline unsigned __onload_hash3(unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  unsigned h = CI_BSWAP_BE32(raddr) ^ CI_BSWAP_LE32(laddr) ^
               (rport << 16 | lport) ^ protocol;
  h ^= h >> 16;
  h ^= h >> 8;
  return h;
}
ci_inline unsigned onload_hash3(const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash3(onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}

ci_inline unsigned __onload_hash1(unsigned size_mask,
                                  unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  ci_assert(CI_IS_POW2(size_mask + 1));
  return __onload_hash3(laddr, lport, raddr, rport, protocol) & size_mask;
}
ci_inline unsigned onload_hash1(unsigned size_mask,
                                const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash1(size_mask, onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}

ci_inline unsigned __onload_hash2(unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  /* N.B. rport and lport are in opposite words with respect to the calculation
   * in onload_hash1. */
  return (CI_BSWAP_LE32(laddr ^ raddr)
         ^ (lport << 16 | rport) ^ protocol) | 1u;
}
ci_inline unsigned onload_hash2(const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash2(onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}


/* This variant of onload_hash2() has a better distribution when the
 * low bits of the addresses are zero, such as when they've been
 * masked off because the prefix length is less than 32. */
ci_inline unsigned cplane_hash2(const ci_addr_t laddr, unsigned ifindex,
                                const ci_addr_t raddr, unsigned tos,
                                unsigned iif_ifindex)
{
  unsigned laddr_xor = onload_addr_xor(laddr);
  unsigned raddr_xor = onload_addr_xor(raddr);

  /* N.B. ifindex and tos are in opposite words with respect to the
   * calculation in onload_hash1. */
  unsigned h = CI_BSWAP_LE32(raddr_xor) ^ CI_BSWAP_BE32(laddr_xor + raddr_xor) ^
               (ifindex << 16 | (iif_ifindex + tos));
  h ^= h >> 16;
  h ^= h >> 8;
  return h | 1u;
}

#endif /* __ONLOAD_HASH_H__ */
