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
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Char driver support for ICMP, IGMP
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <onload/linux_ip_protocols.h>
#include <ci/internal/ip.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>

#ifndef NDEBUG
# define __ENTRY OO_DEBUG_IPP(ci_log("-> %s", __FUNCTION__))
# define __EXIT(s) OO_DEBUG_IPP(ci_log("<- %s %s", __FUNCTION__, (s) ? (s) : ""))
#else
# define __ENTRY
# define __EXIT(s)
#endif

#define DEBUGPMTU OO_DEBUG_IPP

#define VERB(x)

/* ****************************************** 
 * Packet enqueue functions
 */

ci_inline int ci_ipp_ip_csum_ok(ci_ip4_hdr* ip)
{
  unsigned csum;
  ci_uint16 pkt_csum;

  __ENTRY;
  ci_assert( ip );

  pkt_csum = ip->ip_check_be16;
  ip->ip_check_be16 = 0;
  csum = ci_ip_hdr_csum_finish(ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip)));
  ip->ip_check_be16 = pkt_csum;
#ifndef NDEBUG
  if( csum != pkt_csum )
    OO_DEBUG_IPP(ci_log("%s: pkt sum:%x we get:%x", __FUNCTION__, pkt_csum, csum));
#endif
  __EXIT(0);
  return csum == pkt_csum;
}

/* Sum the ICMP hdr/payload 
 * \return 0 if csum failed
 */
int ci_ipp_icmp_csum_ok( ci_icmp_hdr* icmp, int icmp_total_len)
{
  unsigned csum;
  ci_uint16 csum_pkt;

  __ENTRY;
  ci_assert(icmp);
  ci_assert( icmp_total_len > 0 );
  ci_assert( icmp_total_len < 0x10000 );

  csum_pkt = icmp->check;
  icmp->check = 0;

  csum = ci_ip_csum_partial(0, icmp, icmp_total_len);
  csum = ci_icmp_csum_finish(csum);

  icmp->check = csum_pkt;
#ifndef NDEBUG
  if( csum != csum_pkt )
    OO_DEBUG_IPP(ci_log("%s: pkt len %d, sum:%x we get:%x", __FUNCTION__, 
		    icmp_total_len, csum_pkt, csum));
#endif
  __EXIT(0);
  return csum == csum_pkt;
}


/*! efab_ipp_icmp_parse -
 * Get the important info out of the ICMP hdr & it's payload
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 * \param  ip  pointer to IP header - if [dta_only] != 0 then this is 
 *  the *data* IP address (i.e. the failing packet hdr)
 * \param  ip_len length of *ip
 * \param  addr   output: addressing data parsed from *[ip]
 * \param  data_only  [ip] points to data IP rather than ICMP IP hdr
 *
 * \return 1 - ok, 0 - failed.  If [data_only] != 0 then on success
 * addr->ip & addr->icmp will both be 0.  If [data_only] == 0 then
 * on success both addr->ip and addr->icmp will be valid pointers.
 */
extern int
efab_ipp_icmp_parse(const ci_ip4_hdr *ip, int ip_len, efab_ipp_addr* addr,
		    int data_only )
{
  const ci_ip4_hdr* data_ip;
  ci_icmp_hdr* icmp;
  ci_tcp_hdr* data_tcp;
  ci_udp_hdr* data_udp;
  int ip_paylen;

  __ENTRY;
  ci_assert( ip );
  ci_assert( addr );

  ip_paylen = (int)CI_BSWAP_BE16(ip->ip_tot_len_be16);

  if( !data_only ) {
    /* remotely generated (ICMP) errors */
    addr->ip = ip;
    addr->icmp = icmp = (ci_icmp_hdr*)((char*)ip + CI_IP4_IHL(ip));

    if( ip_paylen > ip_len ) {
      /* ?? how do I record this in the ICMP stats */
      OO_DEBUG_IPP(ci_log("%s: truncated packet %d %d", __FUNCTION__, 
		      ip_paylen, ip_len));
      return 0;
    }
    /* uncount the ICMP message IP hdr & ICMP hdr */
    ci_assert( sizeof(ci_icmp_hdr) == 4 );
    ip_paylen -= (int)CI_IP4_IHL(ip) + sizeof(ci_icmp_hdr) + 4;
    data_ip = (ci_ip4_hdr*)((char*)icmp + sizeof(ci_icmp_hdr) + 4);
  } else { 
    /* Locally generated errors */
    addr->ip = 0;
    addr->icmp = icmp = 0;
    data_ip = ip;
  }


  /* note that we swap the source/dest addr:port info - this means
   * that the sense of the addresses is correct for the lookup */
  if( data_ip->ip_protocol == IPPROTO_IP || 
      data_ip->ip_protocol == IPPROTO_TCP ) {
    data_tcp = (ci_tcp_hdr*)((char*)data_ip + CI_IP4_IHL(data_ip));
    addr->protocol = IPPROTO_TCP;
    addr->sport_be16 = data_tcp->tcp_dest_be16;
    addr->dport_be16 = data_tcp->tcp_source_be16;
  } else if ( data_ip->ip_protocol == IPPROTO_UDP ) {
    data_udp = (ci_udp_hdr*)((char*)data_ip + CI_IP4_IHL(data_ip));
    addr->protocol = IPPROTO_UDP;
    addr->sport_be16 = data_udp->udp_dest_be16;
    addr->dport_be16 = data_udp->udp_source_be16;
  } else {
    OO_DEBUG_IPP(ci_log("%s: Unknown protocol %d", __FUNCTION__, 
		    data_ip->ip_protocol));
    return 0;
  }

  addr->data = (ci_uint8*)data_ip;
  addr->data_len =  ip_paylen;
  addr->saddr_be32 = data_ip->ip_daddr_be32;
  addr->daddr_be32 = data_ip->ip_saddr_be32;
  __EXIT(0);
  return 1;
}

/*! efab_ipp_icmp_validate -
 * Check to see if the ICMP pkt is one we want to handle and is 
 * well-formed. We don't check the sums as there should only be one
 * copy passed-in.
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 *
 * \return 1 - ok, 0 - failed
 */
extern int 
efab_ipp_icmp_validate( tcp_helper_resource_t* thr, ci_ip4_hdr *ip)
{
  ci_icmp_hdr* icmp;
  int ip_paylen, ip_tot_len;

  __ENTRY;
  ci_assert( thr );
  ci_assert( ip );
   
  icmp = (ci_icmp_hdr*)((char*)ip + CI_IP4_IHL(ip));
  ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  ip_paylen = ip_tot_len - CI_IP4_IHL(ip);

  OO_DEBUG_IPP( ci_log("%s: ip: tot len:%u, pay_len:%u", 
		   __FUNCTION__, ip_tot_len, ip_paylen ));

  CI_ICMP_IN_STATS_COLLECT( &(thr->netif), icmp );

  /* Done in net driver */

  /* as we may be making more than one copy of this ICMP message we
   * may be saving time by doing the sum just once. Or maybe not. */
  if( CI_UNLIKELY( !ci_ipp_icmp_csum_ok( icmp, ip_paylen))) {
    CI_ICMP_STATS_INC_IN_ERRS( &(thr->netif));
    __EXIT("bad ICMP sum");
    return 0;
  }

  CI_ICMP_STATS_INC_IN_MSGS( &(thr->netif) );
  __EXIT(0);
  return 1;
}

/*!
 * Mapping of ICMP code field of destination unreachable message to errno.
 * The mapping is based on linux sources.
 */
static struct icmp_error {
  int errno;
  ci_uint8 hard;  /* Hard errors will be reported by so_error
                   * even if error queue is disabled. */
} icmp_du_code2errno[CI_ICMP_DU_CODE_MAX] = {
  { ENETUNREACH,  0 },   /* ICMP_NET_UNREACH   */
  { EHOSTUNREACH, 0 },   /* ICMP_HOST_UNREACH  */
  { ENOPROTOOPT,  1 },   /* ICMP_PROT_UNREACH  */
  { ECONNREFUSED, 1 },   /* ICMP_PORT_UNREACH  */
  { EMSGSIZE,     1 },   /* ICMP_FRAG_NEEDED   */
  { EOPNOTSUPP,   0 },   /* ICMP_SR_FAILED     */
  { ENETUNREACH,  1 },   /* ICMP_NET_UNKNOWN   */
  { EHOSTDOWN,    1 },   /* ICMP_HOST_UNKNOWN  */
  { ENONET,       1 },   /* ICMP_HOST_ISOLATED */
  { ENETUNREACH,  1 },   /* ICMP_NET_ANO       */
  { EHOSTUNREACH, 1 },   /* ICMP_HOST_ANO      */
  { ENETUNREACH,  0 },   /* ICMP_NET_UNR_TOS   */
  { EHOSTUNREACH, 0 }    /* ICMP_HOST_UNR_TOS  */
};

/*!
 * Maps received ICMP message type and code fields to host errno value
 * according to STEVENS, section 25.7
 *
 * \param type  ICMP type
 * \param code  ICMP code
 * \param err   errno that corresponds to ICMP type/code
 * \param hard  whether the error is hard
 */
static void get_errno(ci_uint8 type, ci_uint8 code,
                      int *err, ci_uint8 *hard)
{
  switch (type) {
  case CI_ICMP_DEST_UNREACH:
    if (code < CI_ICMP_DU_CODE_MAX) {
      *err = icmp_du_code2errno[code].errno;
      *hard = icmp_du_code2errno[code].hard;
    }
    else {  
      *err = EHOSTUNREACH;
      *hard = 1;
    }
    break;

  case CI_ICMP_SOURCE_QUENCH:
    *err = 0;
    *hard  = 0;
    break;
    
  case CI_ICMP_TIME_EXCEEDED:
    *err = EHOSTUNREACH;
    *hard = 0;
    break;

  case CI_ICMP_PARAMETERPROB:
    *err = EPROTO;
    *hard = 1;
    break;

  default:
    *err = EHOSTUNREACH;
    *hard = 0;
  }
}

typedef struct {
  ci_icmp_hdr hdr;
  ci_uint16   unused;
  ci_uint16   next_hop_mtu_be16;
} ci_icmp_too_big_t;


#define CI_PMTU_PRINTF_SOCKET_FORMAT \
  CI_IP_PRINTF_FORMAT ":%d->" CI_IP_PRINTF_FORMAT ":%d"

#define CI_PMTU_PRINTF_SOCKET_ARGS(ipp_addr) \
  CI_IP_PRINTF_ARGS(&ipp_addr->saddr_be32),  \
  CI_BSWAP_BE16(addr->sport_be16),           \
  CI_IP_PRINTF_ARGS(&addr->daddr_be32),      \
  CI_BSWAP_BE16(addr->dport_be16)
                                                                                  

static void 
ci_ipp_pmtu_rx(ci_netif *netif, ci_ip_cached_hdrs *ipcache,
               efab_ipp_addr* addr, ci_uint32 traffic)
{
  const ci_uint16 plateau[] = CI_PMTU_PLATEAU_ENTRIES;
  ci_ip4_hdr* ip;        /* hdr of failing packet */
  ci_uint16 len;         /* length of failing packet */
  ci_icmp_too_big_t *tb = (ci_icmp_too_big_t*)addr->icmp;
  ci_pmtu_state_t *pmtus = &ipcache->pmtus;
  int ctr;

  if( ipcache->ip.ip_daddr_be32 != addr->saddr_be32 ) {
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " addresses don't match",
                     __FUNCTION__, CI_PMTU_PRINTF_SOCKET_ARGS(addr)));
    return;
  }
  
  if ( pmtus->state == CI_PMTU_DISCOVER_DISABLE ) {
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " pmtu discovery disabled",
                     __FUNCTION__, CI_PMTU_PRINTF_SOCKET_ARGS(addr)));
    return;
  }

  /* rfc1191 provides for this icmp message to have zero in the field
   * as defined in rfc792 */
  len = CI_BSWAP_BE16(tb->next_hop_mtu_be16);
  if( len == 0 ) {
    ci_assert( sizeof(*tb) == (sizeof(ci_icmp_hdr) + 4) );
    ip = (ci_ip4_hdr*)(&tb[1]);	
    len = CI_BSWAP_BE16( ip->ip_tot_len_be16 );
    ctr = CI_PMTU_PLATEAU_ENTRY_MAX;
    while( ctr >= 0 && len <= plateau[ctr] )
      --ctr;
    DEBUGPMTU(ci_log("%s: (legacy icmp) pmtu=%u(%d) ip_tot_len=%d",
	             __FUNCTION__, plateau[ctr], ctr, len));
    len = plateau[ctr];
  } else {
    DEBUGPMTU(ci_log("%s: (rfc1191) next hop mtu = %d", __FUNCTION__, len));
  }
  
  /* must have been delayed as we're already below the reported len */
  if( CI_UNLIKELY(len >= pmtus->pmtu) ) {
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " ignoring, current_pmtu=%d pkt_pmtu=%d", __FUNCTION__,
                     CI_PMTU_PRINTF_SOCKET_ARGS(addr), pmtus->pmtu, len));
    return;
  }
  
  /* hardly a worth-while dos attack, however ... */
  /* ... (proof that i'm not great at predictions) by april 2005 it was picked
   *  up by the media as part of a world-spanning problem :-) */
  if( CI_UNLIKELY(len < plateau[0]) ) {
    int i = 4;
    ci_uint16 npl;
    ci_assert(i < CI_PMTU_PLATEAU_ENTRY_MAX);
    npl = plateau[i];
    /* see bug 3667 where ANVL requires us to reduce the PMTU a bit
       from default; this matches the Linux behaviour, and also
       prevents the DoS attack */
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " warning, below minimum (l:%d) dos?"
		     " using maximum plateua %d", 
		     __FUNCTION__,
                     CI_PMTU_PRINTF_SOCKET_ARGS(addr), len, npl));
    len = npl;
  }
  
  DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                   " curr_pmtu=%d, pkt_pmtu=%d", __FUNCTION__,
                   CI_PMTU_PRINTF_SOCKET_ARGS(addr), pmtus->pmtu, len));

  /* if we're already at index 0 we just get out - there should be a timer
   * in the system & if we re-trigger it we may never actually get back to 
   * a sensible value (we probably won't anyway - this is probably occurring
   * because of a dos attack) */
  /*! \todo sort out a better way to handle malicious messages - for example
   * we could ignore pmtu for some time if we cannot get away from the min. */
  ci_assert_ge(pmtus->pmtu, CI_CFG_TCP_MINIMUM_MSS);
  if( CI_UNLIKELY(pmtus->pmtu == plateau[0]) ) {
    DEBUGPMTU(ci_log("%s: icmp too big and at min pmtu. dos?", __FUNCTION__));
    return;
  }

  ci_pmtu_update_slow(netif, ipcache, len);

#if CI_CFG_FAST_RECOVER_PMTU_AT_MIN
  if( CI_UNLIKELY(s->pmtus.pmtu == plateau[0]) ) {
    DEBUGPMTU(ci_log("%s: min pmtu! (recover timer)", __FUNCTION__));
    ci_pmtu_discover_timer(&thr->netif, &s->pmtus,
                           &thr->netif.tconst_pmtu_discover_recover);
  }
#endif
  
  /* record last_tx, so we can detect TCP progress from now on */
  pmtus->traffic = traffic;
}


/* ci_ipp_pmtu_rx_tcp -
 * handler for the receipt of "datagram too big" icmp messages - 
 * just extracts the most likely plateau to use.
 */
static void 
ci_ipp_pmtu_rx_tcp(tcp_helper_resource_t* thr, 
                   ci_tcp_state* ts, efab_ipp_addr* addr)
{
  ci_assert( thr );
  ci_assert( ts );
  ci_assert( addr );
  ci_assert( addr->icmp );
  ci_assert( sizeof(ci_icmp_hdr) == 4 );

  if (ts->s.b.state == CI_TCP_LISTEN) {
    DEBUGPMTU(ci_log("%s: "CI_IP_PRINTF_FORMAT":%d->"
                     CI_IP_PRINTF_FORMAT":%d listening socket - aborting", 
                     __FUNCTION__,
                     CI_IP_PRINTF_ARGS(&addr->saddr_be32), 
                     CI_BSWAP_BE16(addr->sport_be16),
                     CI_IP_PRINTF_ARGS(&addr->daddr_be32), 
                     CI_BSWAP_BE16(addr->dport_be16)));
    return;
  }

  ci_ipp_pmtu_rx(&thr->netif, &ts->s.pkt, addr, tcp_snd_nxt(ts));

  DEBUGPMTU(ci_log("%s: set eff_mss & change tx q to match", __FUNCTION__));
  ci_tcp_tx_change_mss(&thr->netif, ts);
}


/* ci_ipp_pmtu_rx_tcp -
 * handler for the receipt of "datagram too big" icmp messages - 
 * just extracts the most likely plateau to use.
 */
static void 
ci_ipp_pmtu_rx_udp(tcp_helper_resource_t* thr, 
                   ci_udp_state* us, efab_ipp_addr* addr)
{
}


/* efab_ipp_icmp_for_thr -
 * Is this ICMP message destined for this netif 
 *
 * MUST NOT make use of addr->ip & addr->icmp fields without
 * checking as they can both be 0 
 */
ci_sock_cmn* efab_ipp_icmp_for_thr( tcp_helper_resource_t* thr, 
				    efab_ipp_addr* addr )
{
  ci_assert( thr );
  ci_assert( addr );
  ci_assert( addr->data );

  return  __ci_netif_filter_lookup(&thr->netif, addr->daddr_be32, 
				   addr->dport_be16, addr->saddr_be32, 
				   addr->sport_be16, addr->protocol);
}

/* efab_ipp_icmp_qpkt -
 * Enqueue an ICMP packet into the TCP helper's netif. 
 * This function is assumed to be called within a lock on the 
 * tcp_helper_resource's ep.
 */
extern void
efab_ipp_icmp_qpkt(tcp_helper_resource_t* thr, 
		   ci_sock_cmn* s, efab_ipp_addr* addr)
{
  ci_uint8 icmp_type, icmp_code, hard;
  int err;
  ci_netif* ni = &thr->netif;

  ci_assert(thr);
  ci_assert(thr->netif.state);
  ci_assert(s);
  ci_assert(addr);
  ci_assert(addr->data);
  /* If the address was created without an
   * IP/ICMP hdr then these will be 0 */
  ci_assert(addr->ip);
  ci_assert(addr->icmp);

  ci_assert( ci_netif_is_locked(ni) );

  icmp_type = addr->icmp->type;
  icmp_code = addr->icmp->code;

  /* Path MTU interception */
  if ((icmp_type == CI_ICMP_DEST_UNREACH) && 
       (icmp_code == CI_ICMP_DU_FRAG_NEEDED))
  {
    if (addr->protocol == IPPROTO_UDP)
      ci_ipp_pmtu_rx_udp(thr, SOCK_TO_UDP(s), addr);
    else {
      ci_assert_equal(addr->protocol, IPPROTO_TCP);
      ci_ipp_pmtu_rx_tcp(thr, SOCK_TO_TCP(s), addr);
    }
    
    if (s->pkt.pmtus.state == CI_PMTU_DISCOVER_DISABLE) return;
  }

  /* \TODO: should I write into connected socket error queue for ephemeral tx */
  
  get_errno(icmp_type, icmp_code, &err, &hard);

  /* We handle ICMP for TCP only. */
  ci_assert_equal(addr->protocol, IPPROTO_TCP);
  if( s->b.state == CI_TCP_SYN_SENT ) 
      /* \todo we should handle tsr from listening sockets as well */
  {
    ci_tcp_state* ts = SOCK_TO_TCP(s);

    OO_DEBUG_IPP(ci_log("%s: TCP", __FUNCTION__));

    s->so_error = err;
    ci_tcp_drop(ni, ts, 0);
  }
}

/*! \cidoxg_end */
