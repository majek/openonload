/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
  int af = ci_ethertype2af(oo_tx_ether_type_get(pkt));
  ci_ipx_hdr_t* ipx = oo_ipx_hdr(pkt);
  ci_uint8 protocol = ipx_hdr_protocol(af, ipx);

  /* The packet must contain at least one buffer. */
  ci_assert_ge(pkt->n_buffers, 1);

  /* The IP header must be contained entirely in the first buffer. */
  ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
               pkt->pkt_eth_payload_off + CI_IPX_HDR_SIZE(af));
  /* N.B.: [buf_len] measures the length of the packet starting from [dma_start
   * + pkt_start_off], but [pkt_eth_payload_off] is relative to [dma_start],
   * without regard to [pkt_start_off].  Furthermore, in practice, if
   * [pkt_start_off] is not zero then it is equal to -4 (!) because VLAN tags
   * cause the start of the packet to come _before_ [dma_start]. */

  if( af == AF_INET )
    ipx->ip4.ip_check_be16 = ef_ip_checksum((struct iphdr*)&ipx->ip4);

  if( protocol == IPPROTO_TCP ) {
    struct tcphdr* tcp = (struct tcphdr*) oo_ipx_data(af, pkt);
    size_t tcp_hlen;

    /* The TCP header must be contained entirely in the first buffer. */
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + CI_IPX_HDR_SIZE(af) + sizeof(*tcp));
    tcp_hlen = 4 * tcp->doff;
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + CI_IPX_HDR_SIZE(af) + tcp_hlen);

    struct iovec tmp_iov = host_iov[0];

    /* Advance the first one past the TCP header. */
    uint8_t* new_base = (uint8_t*) tcp + tcp_hlen;
    host_iov[0].iov_len -= (new_base - (uint8_t*) host_iov[0].iov_base);
    host_iov[0].iov_base = (void*) new_base;

    /* Now we can fill in the checksum. */
    tcp->check = ef_tcp_checksum_ipx(af, ipx, tcp, host_iov, pkt->n_buffers);

    host_iov[0] = tmp_iov;
  }
  else if( protocol == IPPROTO_UDP ) {
    struct udphdr* udp = (struct udphdr*) oo_ipx_data(af, pkt);

    /* If the UDP datagram is fragmented, then the UDP checksum has already
     * been computed.
     *
     * Logically this should go before the protocol check, but in practice
     * Onload never fragments TCP, so good to avoid this check for the TCP
     * case.
     */
    /* FIXIT: process properly IPv6-fragmented UDP datagram case */
    if( af == AF_INET &&
        (ipx->ip4.ip_frag_off_be16 & htons(IP_OFFMASK | IP_MF)) )
      return;

    /* The UDP header must be contained entirely in the first buffer. */
    ci_assert_ge(pkt->buf_len + pkt->pkt_start_off,
                 pkt->pkt_eth_payload_off + CI_IPX_HDR_SIZE(af) + sizeof(*udp));

    struct iovec tmp_iov = host_iov[0];

    /* Advance the first one past the UDP header. */
    uint8_t* new_base = (uint8_t*) udp + sizeof(*udp);
    host_iov[0].iov_len -= (new_base - (uint8_t*) host_iov[0].iov_base);
    host_iov[0].iov_base = (void*) new_base;

    /* Now we can fill in the checksum. */
    udp->check = ef_udp_checksum_ipx(af, ipx, udp, host_iov, pkt->n_buffers);

    host_iov[0] = tmp_iov;
  }
  else {
    /* Unrecognised protocol. */
    ci_assert(0);
  }
}
