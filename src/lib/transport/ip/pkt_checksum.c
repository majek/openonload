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

/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Solarflare Communications Inc.
**      Author: mjp
**     Started: 2018/02/22
** Description: Fill in packet checksum fields.
** </L5_PRIVATE>
\**************************************************************************/

#include <etherfabric/checksum.h>
#include "ip_internal.h"
#include "netif_tx.h"

void oo_pkt_calc_checksums(ci_netif* netif, ci_ip_pkt_fmt* pkt,
                           struct iovec* host_iov)
{
  struct iphdr* ip = oo_l3_hdr(pkt);

  /* The packet must contain at least one buffer. */
  ci_assert_ge(pkt->n_buffers, 1);

  /* The IP header must be contained entirely in the first buffer. */
  ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
               pkt->pkt_eth_payload_off + sizeof(*ip));
  /* N.B.: [buf_len] measures the length of the packet starting from [dma_start
   * + pkt_start_off], but [pkt_eth_payload_off] is relative to [dma_start],
   * without regard to [pkt_start_off].  Furthermore, in practice, if
   * [pkt_start_off] is not zero then it is equal to -4 (!) because VLAN tags
   * cause the start of the packet to come _before_ [dma_start]. */

  ip->check = ef_ip_checksum(ip);

  if( ip->protocol == IPPROTO_TCP ) {
    struct tcphdr* tcp = (struct tcphdr*) (ip+1);
    size_t tcp_hlen;

    /* The TCP header must be contained entirely in the first buffer. */
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + sizeof(*ip) + sizeof(*tcp));
    tcp_hlen = 4 * tcp->doff;
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + sizeof(*ip) + tcp_hlen);

    struct iovec tmp_iov = host_iov[0];

    /* Advance the first one past the TCP header. */
    uint8_t* new_base = (uint8_t*) tcp + tcp_hlen;
    host_iov[0].iov_len -= (new_base - (uint8_t*) host_iov[0].iov_base);
    host_iov[0].iov_base = (void*) new_base;

    /* Now we can fill in the checksum. */
    tcp->check = ef_tcp_checksum(ip, tcp, host_iov, pkt->n_buffers);

    host_iov[0] = tmp_iov;
  }
  else if( ip->protocol == IPPROTO_UDP ) {
    struct udphdr* udp = (struct udphdr*) (ip+1);

    /* If the UDP datagram is fragmented, then the UDP checksum has already
     * been computed.
     *
     * Logically this should go before the protocol check, but in practice
     * Onload never fragments TCP, so good to avoid this check for the TCP
     * case.
     */
    if( ip->frag_off & htons(IP_OFFMASK | IP_MF) )
      return;

    /* The UDP header must be contained entirely in the first buffer. */
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + sizeof(*ip) + sizeof(*udp));

    struct iovec tmp_iov = host_iov[0];

    /* Advance the first one past the UDP header. */
    uint8_t* new_base = (uint8_t*) udp + sizeof(*udp);
    host_iov[0].iov_len -= (new_base - (uint8_t*) host_iov[0].iov_base);
    host_iov[0].iov_base = (void*) new_base;

    /* Now we can fill in the checksum. */
    udp->check = ef_udp_checksum(ip, udp, host_iov, pkt->n_buffers);

    host_iov[0] = tmp_iov;
  }
  else {
    /* Unrecognised protocol. */
    ci_assert(0);
  }
}
