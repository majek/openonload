/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
**  \brief  UDP internals
**   \date  2008/09/26
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
#ifndef __UDP_INTERNAL_H__
#define __UDP_INTERNAL_H__


/* On Linux (at least) the space taken in the recvq is calculated as frame
 * size + some skb overhead.  Value used here was measured on kernel
 * 2.6.24.7-65.el5rt using "udp_rcvbuf".
 */
#define OO_UDP_RX_PER_PKT_OVERHEAD  350


struct ci_udp_rx_deliver_state {
  ci_netif*      ni;
  ci_ip_pkt_fmt* pkt;
  int            delivered;
  int            queued;
};


/*! Calculate multicast MAC address from multicast IP address. */
ci_inline void
ci_mcast_ipcache_set_mac(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                         unsigned daddr_be32)
{
  char *dhost = ci_ip_cache_ether_dhost(ipcache);
  dhost[0] = 1;
  dhost[1] = 0;
  dhost[2] = 0x5e;
  dhost[3] = (daddr_be32 >> 8) & 0x7f;
  dhost[4] = (daddr_be32 >> 16) & 0xff;
  dhost[5] = (daddr_be32 >> 24) & 0xff;
  cicp_mac_set_mostly_valid(CICP_MIBS(CICP_HANDLE(ni))->user.mac_utable,
                            &ipcache->mac_integrity);
}


extern int ci_udp_rx_deliver(ci_sock_cmn*, void*) CI_HF;


#endif  /* __UDP_INTERNAL_H__ */
