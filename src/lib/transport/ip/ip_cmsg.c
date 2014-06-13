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
** \author  Evgeniy Vladimirovich Bobkov <kavri@oktetlabs.ru>
**  \brief  Control messages / ancillary data.
**   \date  2004/12/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include <ci/internal/cplane_ops.h>


#define LPF "IP CMSG "



/**
 * Put a portion of ancillary data into msg ancillary data buffer.
 *
 * man cmsg says: Use CMSG_FIRSTHDR() on the msghdr to get the first
 * control message and CMSG_NEXTHDR() to get all subsequent ones.  In
 * each control message, initialize cmsg_len (with CMSG_LEN()), the
 * other cmsghdr header fields, and the data portion using
 * CMSG_DATA().  Finally, the msg_controllen field of the msghdr
 * should be set to the sum of the CMSG_SPACE() of the length of all
 * control messages in the buffer.
 */
void ci_put_cmsg(struct cmsg_state *cmsg_state,
                 int level, int type, socklen_t len, const void* data)
{

  int data_space, data_len = len;

  /* Calls to CMSG_FIRSTHDR and CMSG_NEXTHDR already check that there
   * is enough space for the cmsghdr itself, so just need to check
   * that it is != NULL here
   */
  if( cmsg_state->cm == NULL ) {
    cmsg_state->msg->msg_flags |= MSG_CTRUNC;
    return;
  }

  data_space = ((unsigned char*)cmsg_state->msg->msg_control + 
                cmsg_state->msg->msg_controllen) - 
    (unsigned char*)CMSG_DATA(cmsg_state->cm);
  if( data_space < 0 ) {
    cmsg_state->msg->msg_flags |= MSG_CTRUNC;
    return;
  }
  
  if( data_len > data_space ) {
    cmsg_state->msg->msg_flags |= MSG_CTRUNC;
    data_len = data_space;
  }

  cmsg_state->cm->cmsg_len   = CMSG_LEN(data_len);
  cmsg_state->cm->cmsg_level = level;
  cmsg_state->cm->cmsg_type  = type;

  memcpy(CMSG_DATA(cmsg_state->cm), data, data_len);

  cmsg_state->cmsg_bytes_used += CMSG_SPACE(data_len);
  cmsg_state->cm = CMSG_NXTHDR(cmsg_state->msg, cmsg_state->cm);
}


#ifndef __KERNEL__

/**
 * Put an IP_PKTINFO control message into msg ancillary data buffer.
 */
static void ip_cmsg_recv_pktinfo(ci_netif* netif, const ci_ip_pkt_fmt* pkt,
                                 struct cmsg_state *cmsg_state)
{
  /* TODO: This is horribly inefficient -- two system calls.  Could be made
   * cheap with a user-level llap table.
   */
  struct in_pktinfo info;
  ci_uint32 addr;
  int hwport;

  addr = oo_ip_hdr(pkt)->ip_daddr_be32;
  info.ipi_addr.s_addr = addr;

  /* Set the ifindex the pkt was received at. */
  {
    ci_ifid_t ifindex = 0;
    int rc = 0;
    ci_uint16 vlan_id = 0;

    if( pkt->pkt_layout == CI_PKT_LAYOUT_RX_VLAN ) {
      vlan_id = *(ci_uint16*) (pkt->ether_base + ETH_HLEN);
      vlan_id = CI_BSWAP_BE16(vlan_id) & 0xfff;
    }

    hwport = netif->state->intf_i_to_hwport[pkt->intf_i];
    rc = cicp_llap_find(CICP_HANDLE(netif), &ifindex,
                        CI_HWPORT_ID(hwport), vlan_id);
    if( rc != 0 )
      LOG_E(ci_log("%s: cicp_llap_find(intf_i=%d, hwport=%d) failed rc=%d",
                   __FUNCTION__, pkt->intf_i, hwport, rc));
    info.ipi_ifindex = ifindex;
  }

  /* RFC1122: The specific-destination address is defined to be the
   * destination address in the IP header unless the header contains a
   * broadcast or multicast address, in which case the specific-destination
   * is an IP address assigned to the physical interface on which the
   * datagram arrived. */
  /*\ FIXME: we should drop the packet if this call fails */
  cicp_ipif_pktinfo_query(CICP_HANDLE(netif), netif, OO_PKT_P(pkt),
                          info.ipi_ifindex, 
                          &info.ipi_spec_dst.s_addr
                          );

  ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_PKTINFO, sizeof(info), &info);
}

/**
 * Put an IP_RECVTTL control message into msg ancillary data buffer.
 */
ci_inline void ip_cmsg_recv_ttl(const ci_ip_pkt_fmt *pkt, 
                                struct cmsg_state *cmsg_state)
{
  int ttl = oo_ip_hdr(pkt)->ip_ttl;

  ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_TTL, sizeof(ttl), &ttl);
}

/**
 * Put an IP_RECVTOS control message into msg ancillary data buffer.
 */
ci_inline void ip_cmsg_recv_tos(const ci_ip_pkt_fmt *pkt, 
                                struct cmsg_state *cmsg_state)
{
  int tos = oo_ip_hdr(pkt)->ip_tos;

  ci_put_cmsg(cmsg_state, IPPROTO_IP, IP_TOS, sizeof(tos), &tos);
}

/**
 * Put a SO_TIMESTAMP control message into msg ancillary data buffer.
 */
ci_inline void ip_cmsg_recv_timestamp(ci_netif *ni, const ci_ip_pkt_fmt *pkt, 
                                      struct cmsg_state *cmsg_state)
{
  struct timespec ts;
  struct timeval tv;

  ci_udp_compute_stamp(ni, pkt->pf.udp.rx_stamp, &ts);
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = ts.tv_nsec / 1000;

  ci_put_cmsg(cmsg_state, SOL_SOCKET, SO_TIMESTAMP, sizeof(tv), &tv);
}

/**
 * Put a SO_TIMESTAMPNS control message into msg ancillary data buffer.
 */
ci_inline void ip_cmsg_recv_timestampns(ci_netif *ni, const ci_ip_pkt_fmt *pkt, 
                                        struct cmsg_state *cmsg_state)
{
  struct timespec ts;

  ci_udp_compute_stamp(ni, pkt->pf.udp.rx_stamp, &ts);

  ci_put_cmsg(cmsg_state, SOL_SOCKET, SO_TIMESTAMPNS, sizeof(ts), &ts);
}


/**
 * Fill in the msg ancillary data buffer with all control messages
 * according to cmsg_flags the user has set beforehand.
 */
void ci_ip_cmsg_recv(ci_netif* ni, ci_udp_state* us, const ci_ip_pkt_fmt *pkt,
                     struct msghdr *msg, int netif_locked)
{
  unsigned flags = us->s.cmsg_flags;
  struct cmsg_state cmsg_state;

  cmsg_state.msg = msg;
  cmsg_state.cmsg_bytes_used = 0;
  cmsg_state.cm = CMSG_FIRSTHDR(msg);

  if( pkt->flags & CI_PKT_FLAG_RX_INDIRECT )
    pkt = PKT_CHK_NML(ni, pkt->frag_next, netif_locked);

  if (flags & CI_IP_CMSG_PKTINFO) {
    ++us->stats.n_rx_pktinfo;
    ip_cmsg_recv_pktinfo(ni, pkt, &cmsg_state);
  }

  if (flags & CI_IP_CMSG_TTL)
    ip_cmsg_recv_ttl(pkt, &cmsg_state);

  if (flags & CI_IP_CMSG_TOS)
    ip_cmsg_recv_tos(pkt, &cmsg_state);

  if( flags & CI_IP_CMSG_TIMESTAMP )
    ip_cmsg_recv_timestamp(ni, pkt, &cmsg_state);

  if( flags & CI_IP_CMSG_TIMESTAMPNS )
    ip_cmsg_recv_timestampns(ni, pkt, &cmsg_state);

  msg->msg_controllen = cmsg_state.cmsg_bytes_used;
}

#endif /* !__KERNEL__ */


/**
 * Find out all control messages the user has provided with msg.
 *
 * \param info_out    Must be a valid pointer.
 */
int ci_ip_cmsg_send(const struct msghdr* msg, struct in_pktinfo** info_out)
{
  struct cmsghdr *cmsg;

  /* NB. I don't think CMSG_NXTHDR() modifies [*msg], but for some
   * reason it takes a non-const arg.
   */
  for( cmsg = CMSG_FIRSTHDR(msg); cmsg;
       cmsg = CMSG_NXTHDR((struct msghdr*) msg, cmsg) ) {

    if( cmsg->cmsg_len < sizeof(struct cmsghdr) ||
        (socklen_t)(((char*)cmsg - (char*)msg->msg_control)
                    + cmsg->cmsg_len) > msg->msg_controllen )
      return -EINVAL;

    if( cmsg->cmsg_level != IPPROTO_IP )
      continue;

    switch( cmsg->cmsg_type ) {
    case IP_RETOPTS:
      /* TODO: implementation required */
      return -ENOPROTOOPT;

    case IP_PKTINFO:
      if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo)))
        return -EINVAL;
      *info_out = (struct in_pktinfo *)CMSG_DATA(cmsg);
      break;

    default:
      return -EINVAL;
    }
  }

  return 0;
}

/*! \cidoxg_end */
