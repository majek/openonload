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

#ifndef __CI_NET_IPVX_H__
#define __CI_NET_IPVX_H__

#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>

typedef union {
  struct {
#if CI_CFG_IPV6
      ci_uint8 pad[12];
#endif
      ci_ip_addr_t ip4;
  };
#if CI_CFG_IPV6
  ci_ip6_addr_t ip6;
#endif
} ci_addr_t;

static const ci_addr_t addr_any;
#if CI_CFG_IPV6
static const ci_addr_t ip4_addr_any = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}}};
#else
static const ci_addr_t ip4_addr_any;
#endif

#if CI_CFG_IPV6
#define CI_ADDR_FROM_IP4(ip) ({ ci_addr_t a = {}; a.ip4 = (ip); \
    a.pad[10] = 0xff; a.pad[11] = 0xff; a; })
#else
#define CI_ADDR_FROM_IP4(ip) ({ ci_addr_t a = {}; a.ip4 = (ip); a; })
#endif

#if CI_CFG_IPV6
#define CI_IPX_ADDR_SIZE(af) ((af) == AF_INET6 ? sizeof(ci_ip6_addr_t) \
        : sizeof(ci_ip_addr_t))
#else
#define CI_IPX_ADDR_SIZE(af) sizeof(ci_ip_addr_t)
#endif

#if CI_CFG_IPV6
#define CI_IS_ADDR_IP6(addr) \
    (memcmp((addr).pad, ip4_addr_any.pad, sizeof((addr).pad)))
#else
    #define CI_IS_ADDR_IP6(addr) 0
#endif

#if CI_CFG_IPV6
#define CI_IPX_IS_MULTICAST(addr) \
    (CI_IS_ADDR_IP6(addr) ? CI_IP6_IS_MULTICAST((addr).ip6) : \
    CI_IP_IS_MULTICAST((addr).ip4))
#else
#define CI_IPX_IS_MULTICAST(addr) CI_IP_IS_MULTICAST((addr).ip4)
#endif

#if CI_CFG_IPV6
#define CI_IPX_ADDR_CMP(addr1, addr2) CI_IP6_ADDR_CMP((addr1).ip6, (addr2).ip6)
#else
#define CI_IPX_ADDR_CMP(addr1, addr2) CI_IP_ADDR_CMP((addr1).ip4, (addr2).ip4)
#endif

#if CI_CFG_IPV6
#define CI_IPX_ADDR_CMP_ANY(addr) \
    (CI_IS_ADDR_IP6(addr) ? CI_IP6_ADDR_CMP((addr).ip6, addr_any.ip6) : \
    CI_IP_ADDR_CMP((addr).ip4, addr_any.ip4))
#else
#define CI_IPX_ADDR_CMP_ANY(addr) CI_IP_ADDR_CMP((addr).ip4, addr_any.ip4)
#endif

typedef enum {
  AF_SPACE_FLAG_IP4=1,
  AF_SPACE_FLAG_IP6=2,
} ci_af_space_t;

#ifdef CI_CFG_IPV6
#define IS_AF_SPACE_IP6(af_space) ((af_space) & AF_SPACE_FLAG_IP6)
#else
#define IS_AF_SPACE_IP6(af_space) 0
#endif

#ifdef CI_CFG_IPV6
#define IS_AF_INET6(af) ((af) == AF_INET6)
#else
#define IS_AF_INET6(af) 0
#endif

ci_inline char *ci_get_ip_str(const ci_addr_t src, char *dst, size_t size)
{
#ifndef NDEBUG
  int n = 0;
#endif

#if CI_CFG_IPV6
  ci_addr_t a = {};

  a.pad[10] = 0xff;
  a.pad[11] = 0xff;

  if( memcmp(&src.pad, &a.pad, sizeof(src.pad)) ) {
#ifndef NDEBUG
    n =
#endif
    ci_snprintf(dst, size, CI_IP6_PRINTF_FORMAT,
                CI_IP6_PRINTF_ARGS(src.ip6));
  }
  else
#endif
  {
 #ifndef NDEBUG
    n =
 #endif
    ci_snprintf(dst, size, CI_IP_PRINTF_FORMAT,
                CI_IP_PRINTF_ARGS(&src.ip4));

  }

  ci_assert_gt(size, n);
  return dst;
}

#if CI_CFG_IPV6
#define IPX_FMT            "%s"
#define IPX_ARG(ip)        (ip)
#define IPX_PORT_FMT       "%s:%d"
#define AF_IP(ip)          ( &({ \
    struct { char buf[CI_INET6_ADDRSTRLEN]; } str; \
    ci_get_ip_str(ip, str.buf, sizeof(str.buf)); \
    str; }).buf[0] )
#else
#define IPX_FMT            CI_IP_PRINTF_FORMAT
#define IPX_ARG(ip)        CI_IP_PRINTF_ARGS(&(ip.ip4))
#define IPX_PORT_FMT       IPX_FMT":%d"
#define AF_IP(ip)          (ip)
#endif

#ifdef CI_CFG_IPV6
#define IPX_SOCKADDR_SIZE(af) ((af) == AF_INET ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#else
#define IPX_SOCKADDR_SIZE(af) (sizeof(struct sockaddr_in))
#endif

#endif /* __CI_NET_IPVX_H__ */
