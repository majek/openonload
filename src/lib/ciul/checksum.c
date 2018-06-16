/*
** Copyright 2005-2018  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "ef_vi_internal.h"

/* The pseudo-header used for TCP and UDP checksum calculation. */
typedef struct {
  uint32_t  ip_saddr_be32;
  uint32_t  ip_daddr_be32;
  uint8_t   zero;
  uint8_t   ip_protocol;
  uint16_t  length_be16;  /* udp hdr + payload */
} ip4_pseudo_hdr;


/* NB: csum can be maintained as BE value even with LE addition operations
 * because all inputs are BE values and the folding of overflow means that
 * carry going the "wrong way" between the bytes doesn't matter after folding
 * as the scheme is somewhat "symmetrical".
 */

ef_vi_inline uint64_t
ip_csum64_partial(uint64_t csum64, const void*__restrict__ buf, size_t bytes)
{
  EF_VI_ASSERT(buf || bytes == 0);
  EF_VI_ASSERT(bytes >= 0);
  EF_VI_ASSERT((bytes & 1) == 0);

  while( bytes >= 4 ) {
    uint32_t bounce;
    memcpy(&bounce, buf, sizeof(bounce));
    csum64 += bounce;
    buf = (char*) buf + sizeof(bounce);
    bytes -= sizeof(bounce);
  }
  if( bytes ) {
    uint16_t bounce;
    memcpy(&bounce, buf, sizeof(bounce));
    csum64 += bounce;
  }

  return csum64;
}


static uint64_t
ip_csum64_partialv(uint64_t csum64, const struct iovec* iov, int iovlen)
{
  int n, carry = 0;
  union {
    uint8_t u8[2];
    uint16_t u16;
  } carried;
  carried.u8[0] = 0;  /* avoid compiler warning */

  for( n = 0; n < iovlen; n++ ) {
    uint8_t* data = (uint8_t*)iov[n].iov_base;
    int bytes = iov[n].iov_len;
    if( bytes == 0 )
      continue;
    if( carry ) {
      carried.u8[1] = data[0];
      csum64 += carried.u16;
      data++;
      bytes--;
    }
    csum64 = ip_csum64_partial(csum64, data, bytes & ~1);
    if( (bytes & 1) == 0 ) {
      carry = 0;
    }
    else {
      carry = 1;
      carried.u8[0] = data[bytes - 1];
    }
  }
  if( carry )
    csum64 += carried.u8[0];
  return csum64;
}


ef_vi_inline uint32_t ip_proto_csum64_finish(uint64_t csum64)
{
  /* The top 16bits of csum64 will be zero because we're only summing IP
   * datagrams (so total length is < 64KiB).
   */
  EF_VI_ASSERT((csum64 >> 48) == 0);
  {
    unsigned sum = ( ((csum64 >> 32) & 0xffff) + ((csum64 >> 16) & 0xffff)
                     + (csum64 & 0xffff) );
    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = ~sum & 0xffff;
    return sum ? sum : 0xffff;
  }
}


ef_vi_inline uint32_t ip_hdr_csum32_finish(uint32_t csum32)
{
  unsigned sum =  (csum32 >> 16u) + (csum32 & 0xffff);
  sum += (sum >> 16u);
  return ~sum & 0xffff;
}


uint32_t ef_ip_checksum(const struct iphdr* ip)
{
  const uint16_t*__restrict__ p = (const uint16_t*) ip;
  uint32_t csum32;
  int bytes;

  csum32  = p[0];
  csum32 += p[1];
  csum32 += p[2];
  csum32 += p[3];
  csum32 += p[4];
  /* omit ip_check_be16 */
  csum32 += p[6];
  csum32 += p[7];
  csum32 += p[8];
  csum32 += p[9];

  bytes = ip->ihl * 4;
  if(CI_UNLIKELY( bytes > 20 )) {
    p += 10;
    bytes -= 20;
    do {
      csum32 += *p++;
      bytes -= 2;
    } while( bytes );
  }

  return ip_hdr_csum32_finish(csum32);
}


uint32_t ef_udp_checksum(const struct iphdr* ip, const struct udphdr* udp,
			 const struct iovec* iov, int iovlen)
{
  ip4_pseudo_hdr ph;
  uint64_t csum64;

  ph.ip_saddr_be32 = ip->saddr;
  ph.ip_daddr_be32 = ip->daddr;
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_UDP;
  ph.length_be16 = udp->len;

  csum64 = ip_csum64_partial(0, &ph, sizeof(ph));
  csum64 = ip_csum64_partial(csum64, udp, 6); /* omit udp_check_be16 */
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  return ip_proto_csum64_finish(csum64);
}


uint32_t ef_tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp,
                         const struct iovec* iov, int iovlen)
{
  ip4_pseudo_hdr ph;
  uint16_t paylen;
  uint64_t csum64;

  paylen = ntohs(ip->tot_len) - (ip->ihl * 4);

  ph.ip_saddr_be32 = ip->saddr;
  ph.ip_daddr_be32 = ip->daddr;
  ph.zero = 0;
  ph.ip_protocol = IPPROTO_TCP;
  ph.length_be16 = htons(paylen);

  csum64 = ip_csum64_partial(0, &ph, sizeof(ph));
  csum64 = ip_csum64_partial(csum64, tcp, (tcp->doff * 4));
  csum64 -= tcp->check;
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  return ip_proto_csum64_finish(csum64);
}
