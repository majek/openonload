/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  stg
**  \brief  ICMP utility functions for sending errors
**   \date  2003/12/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "ip_tx.h"


#define LPF "ci_icmp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


/* STATS */
/*! \todo Temporary stats in ICMP tx module need replacing */
typedef struct {
  ci_uint32 nobuf;
  ci_uint32 nospace;
  ci_uint32 sentok;
} ci_icmp_tx_stats;

static ci_icmp_tx_stats icmp_tx_stats = {0,0,0};

#define CI_ICMP_TX_STAT_NOBUF(ni) (icmp_tx_stats.nobuf++)
#define CI_ICMP_TX_STAT_NOSPACE(ni) (icmp_tx_stats.nospace++)
#define CI_ICMP_TX_STAT_SENT(ni) (icmp_tx_stats.sentok++)

/* IP header + 8 bytes is largest possible ICMP error payload */
#define CI_ICMP_MAX_PAYLOAD ( 60 + 8 )

/* Largest possible ICMP message that we're likely to send */
#define CI_ICMP_MAX_MSG_LEN \
  (sizeof(ci_ip4_hdr) + sizeof(ci_icmp_hdr) + 4 + CI_ICMP_MAX_PAYLOAD)

/**
 * Send an ICMP packet
 */
extern int
ci_icmp_send(ci_netif *ni, ci_ip_pkt_fmt *tx_pkt,
	     const ci_ip_addr_t *ref_ip_source,
	     const ci_ip_addr_t *ref_ip_dest,
	     const ci_mac_addr_t *mac_dest,
	     ci_uint8 type, ci_uint8 code, ci_uint16 data_len)
{
  struct oo_eth_hdr *tx_eth;
  ci_ip4_hdr *tx_ip;
  ci_icmp_hdr *icmp;
  ci_uint16 ipid;
  unsigned csum;

  ci_assert(ni);
  
  tx_ip = oo_tx_ip_hdr(tx_pkt);
  tx_eth = oo_ether_hdr(tx_pkt);
  icmp = (ci_icmp_hdr*) (tx_ip + 1);

  /* Skip space for the IP4 hdr, ICMP hdr */
  ci_assert(sizeof(ci_icmp_hdr) == 4);
  oo_offbuf_init(&tx_pkt->buf, 
		 (char*)tx_ip+sizeof(ci_ip4_hdr) + sizeof(ci_icmp_hdr) + 4, 
		 CI_ICMP_MAX_PAYLOAD);

  /* How much space free in the buffer?  */
  if (oo_offbuf_left(&tx_pkt->buf) < CI_ICMP_MAX_PAYLOAD) {
    LOG_IPP( log(LPF "send_error: Buffer too short for an ICMP msg (%d)!",
		 oo_offbuf_left(&tx_pkt->buf)));
    ci_netif_pkt_release(ni, tx_pkt);	
    CI_ICMP_TX_STAT_NOSPACE(ni);
    CI_ICMP_STATS_INC_OUT_ERRS( ni );
    return -1;
  }

  /* Sort out the eth hdr, the ip_send call will deal with our MAC  */
  memcpy( tx_eth->ether_dhost, mac_dest, ETH_ALEN );
  tx_eth->ether_type = CI_ETHERTYPE_IP;

  /* do the IP hdr, we trust the IP addresses in the rx pkt as they
   * managed to get the message thus far  */
  memset( tx_ip, 0, sizeof(ci_ip4_hdr));
  tx_ip->ip_ihl_version = CI_IP4_IHL_VERSION( sizeof(ci_ip4_hdr));
  ipid = NEXT_IP_ID( ni );
  tx_ip->ip_id_be16 = CI_BSWAP_BE16( ipid );
  tx_ip->ip_frag_off_be16 = CI_IP4_FRAG_DONT;
  tx_ip->ip_ttl = CI_IP_DFLT_TTL;
  tx_ip->ip_protocol = IPPROTO_ICMP;
  tx_ip->ip_saddr_be32 = *ref_ip_source;
  tx_ip->ip_daddr_be32 = *ref_ip_dest;

  /* do the ICMP hdr */
  icmp->type = type;
  icmp->code = code;
  icmp->check = 0;
  ci_assert( sizeof(ci_icmp_hdr) == 4 );
  /* set ICMP checksum */
  csum = ci_ip_csum_partial(0, icmp, sizeof(ci_icmp_hdr) + 4 + data_len );
  icmp->check = (ci_uint16)ci_icmp_csum_finish(csum);

  tx_ip->ip_tot_len_be16 = CI_BSWAP_BE16( sizeof(ci_ip4_hdr)
      + sizeof(ci_icmp_hdr) + 4 + data_len );
  tx_ip->ip_check_be16 = (ci_uint16)ci_ip_checksum(tx_ip);
  
  tx_pkt->buf_len = tx_pkt->pay_len = 
    CI_BSWAP_BE16(tx_ip->ip_tot_len_be16) + oo_ether_hdr_size(tx_pkt);

  /* ?? FIXME: This will lookup the dest IP in the route table to choose
   * the interface to send on, but really we should reply back through the
   * same interface that we received on.
   */
  ci_ip_send_pkt(ni, NULL, tx_pkt);

  /* NB: (bug?) this will fill in the destination MAC addresses based on
         the first hop to the destination IP address (despite assigning
	 it above) - really we should send the reply back through the same
	 interface that is was received on - no matter what our routing table
	 says.
	 Note that if we do fill in a different MAC address it will
	 invalidate the ICMP checksum!
  */

  CI_ICMP_STATS_INC_OUT_MSGS(ni);
  ci_netif_pkt_release(ni, tx_pkt);
  CI_ICMP_TX_STAT_SENT(ni);
  LOG_IPP(log(LPF "send_error: sent %d/%d to %s",
	      code, type, ip_addr_str( *ref_ip_dest )));

#if CI_CFG_SUPPORT_STATS_COLLECTION
  CI_ICMP_OUT_STATS_COLLECT(ni, icmp);
#endif

  return 0;
}




/**
 * Generate an ICMP error in the context of the netif and the given 
 * received packet. The outbound error will use type/code and contain
 * the IP hdr & first 8 bytes of the payload of pkt.
 */
extern int __ci_icmp_send_error(ci_netif *ni,
				ci_ip4_hdr* rx_ip,
				struct oo_eth_hdr* rx_eth,
	                        ci_uint8 type, ci_uint8 code)
{
  ci_assert(ni);
  ci_assert(rx_ip);
  ci_assert(rx_eth);

  /* Bug1729, Bug1731: LAND attack sets source addr=dest addr, thus our "trust"
   * mentioned below is utterly misplaced ...
   */
  if( cicp_user_is_local_addr(CICP_HANDLE(ni), &rx_ip->ip_saddr_be32) ) {
    char buf[32];
    if( rx_ip->ip_protocol == IPPROTO_TCP )
      strcpy(buf, "TCP packet");
    else if ( rx_ip->ip_protocol == IPPROTO_UDP )
      strcpy(buf, "UDP packet");
    else
    {
      snprintf(buf, sizeof(buf), "packet with protocol=%u", rx_ip->ip_protocol);
    }
    if( rx_ip->ip_saddr_be32 == rx_ip->ip_daddr_be32 ) {
      LOG_U(ci_log("WARNING: Unexpected receipt of a %s with source IP\n"
                   "address = dest IP address (%s). Possible LAND attack.\n"
                   "Not sending ICMP type=%u code=%u", buf,
                   ip_addr_str( rx_ip->ip_saddr_be32 ), type, code));
    } else {
      /*! \todo We could reply from here using a raw socket given that we're happy
       * that the received packet isn't some kind of vulnerability attack */
      LOG_U(ci_log("Unexpected receipt of a %s packet from a local IP\n"
                   "address (%s). Not sending ICMP type=%u code=%u", buf,
                   ip_addr_str( rx_ip->ip_saddr_be32 ), type, code));
    }
    return -1;
    
  } else
  { ci_ip_pkt_fmt *tx_pkt = ci_netif_pkt_alloc(ni);
    
    if (NULL == tx_pkt) {
      LOG_IPP( log(LPF "send-error: !!No buff, yet expected at least one!!")); 
      CI_ICMP_TX_STAT_NOBUF( ni );
      CI_ICMP_STATS_INC_OUT_ERRS( ni );
      return -1;
      
    } else
    { ci_uint16 data_len = CI_MIN( CI_IP4_IHL(rx_ip) + 8,
				   rx_ip->ip_tot_len_be16 );
      ci_icmp_hdr *icmp;

      oo_tx_pkt_layout_init(tx_pkt);
      oo_tx_ether_type_set(tx_pkt, CI_ETHERTYPE_IP);
      icmp = (ci_icmp_hdr*) (oo_tx_ip_hdr(tx_pkt) + 1);

      *(ci_uint32*)&icmp[1] = 0;
      memcpy( &icmp[2], rx_ip, data_len );
      
      return ci_icmp_send(ni, tx_pkt,
			  /*ip_src*/&rx_ip->ip_daddr_be32,
			  /*ip_dest*/&rx_ip->ip_saddr_be32,
			  /*mac_dest*/(const ci_mac_addr_t *)
			      &rx_eth->ether_shost,
			  type, code, data_len);
    }
  }
}



/*! \cidoxg_end */
