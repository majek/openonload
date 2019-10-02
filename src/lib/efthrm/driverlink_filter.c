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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_efab */

/*! \todo The removal of the UDP fragmentation code has made this module a
 *   lot less complex, but it has also forced the UL library to poll the OS
 *   socket - with inherent overheads.  Maybe we need to think again about
 *   ditching the UDP fragment handling - in concert with the tunnelled UDP 
 *   mechanism it may be that we will again benefit from avoiding the OS 
 *   socket calls.
 */

/*! \todo  With the removal of the UDP fragmentation code the filtering
 * mechanism in this module became way too complex for the job of filtering
 * ICMP messages for the char driver.
 *
 * We need to:
 * 1) remove the "local address" (it was useful for fragment caching but is 
 *    now just adding overhead and complexity)
 * 2) find a better filtering mechanism that will allow us to reduce the amount
 *    of filter traffic from the char driver.
 */ 

#define LPF "efx_dlfilter "
 
#include <ci/internal/ip.h>
#include <onload/linux_ip_protocols.h>
#include <onload/driverlink_filter.h>
#include <onload/debug.h>
#include <onload/driverlink_filter_private.h>
#include <onload/id_pool.h> /* for CI_ID_POOL_ID_NONE */

/* *************************************************************
 * Compilation control
 */

/* Define this to get a lot more debug info */
#define VERB(x)


/* *************************************************************
 * Local prototypes
 */

#ifndef NDEBUG
  static void
  dlfilter_dump_entry( efx_dlfilter_cb_t* fcb, const char * pfx, 
		       int idx, efx_dlfilt_entry_t* ent );
#endif

/* dlfilter_lookup will lookup the exact set of parameters provided. */
static int dlfilter_lookup(efx_dlfilter_cb_t*, ci_uint32 laddr,
                           ci_uint16 lport, ci_uint32 raddr,
                           ci_uint16 rport, ci_uint8 protocol, int* thr_id);
/* dlfilter_full_lookup will first try an exact parameter lookup, but if that
 * fails it will fall back to a wild match lookup, ignoring the raddr/rport.
 */
static int dlfilter_full_lookup(efx_dlfilter_cb_t* fcb,
                                ci_uint32 laddr, ci_uint16 lport,
                                ci_uint32 raddr, ci_uint16 rport,
                                ci_uint8 protocol, int* thr_id );

#define EFAB_DLFILT_ENTRY_MASK (EFAB_DLFILT_ENTRY_COUNT-1)

#define EFAB_DLFILT_ENTRY_STATE(e) \
  ((e)->state & EFAB_DLFILT_STATE_MASK)
#define EFAB_DLFILT_ENTRY_ROUTE(e) \
  ((e)->state & ~EFAB_DLFILT_STATE_MASK)
#define EFAB_DLFILT_ENTRY_IN_USE(e) \
  (EFAB_DLFILT_ENTRY_STATE(e)==EFAB_DLFILT_INUSE) 
#define EFAB_DLFILT_ENTRY_EMPTY(e) \
  (EFAB_DLFILT_ENTRY_STATE(e)==EFAB_DLFILT_EMPTY) 


static const char* dlfilt_addr_str(ci_uint32 addr_be32)
{
  static char strbuf[2][16];
  static int strbuf_i;

  strbuf_i = !strbuf_i;
  ci_format_ip4_addr(strbuf[strbuf_i], addr_be32);
  return strbuf[strbuf_i];
}


/* ************************************************************
 * Helpers
 */
void
efx_dlfilter_count_stats(efx_dlfilter_cb_t* fcb,
                         int *n_empty, int *n_tomp, int *n_used)
{
  int ctr;
  int no_empty=0;
  int no_tomb=0;
  int no_used=0;

  ci_assert(fcb);

  for( ctr = 0; ctr < EFAB_DLFILT_ENTRY_COUNT; ctr++ ) 
  {
    if ( EFAB_DLFILT_ENTRY_STATE(&fcb->table[ctr]) == EFAB_DLFILT_EMPTY )
      no_empty++;
    else if ( EFAB_DLFILT_ENTRY_STATE(&fcb->table[ctr]) == EFAB_DLFILT_TOMBSTONE )
      no_tomb++;
    else
      no_used++;
  }

  *n_empty = no_empty;
  *n_tomp = no_tomb;
  *n_used = no_used;
}

#ifndef NDEBUG

static void
dlfilter_dump_on_error(efx_dlfilter_cb_t* fcb)
{
  static int dump_on_error=0;

  ci_assert(fcb);

  if (!dump_on_error) {
    int no_empty, no_tomb, no_used;
    efx_dlfilter_count_stats(fcb, &no_empty, &no_tomb, &no_used);
    ci_log("%s: ****************************************", __FUNCTION__);
    ci_log("%s: ERROR ERROR - empty=%d, tomb=%d, used=%d", 
         __FUNCTION__, no_empty, no_tomb, no_used);
    ci_log("%s: ****************************************", __FUNCTION__);
    dump_on_error=1;
  }
}
#endif

ci_inline int 
dlfilter_icmp_checks(const ci_ip4_hdr* ip)
{
  /* ?? FIXME: should not modify packet contents */
  ci_ip4_hdr* ipbad = (ci_ip4_hdr*) ip;
  ci_uint16 csum, pkt_csum = ipbad->ip_check_be16;
  ipbad->ip_check_be16 = 0;
  csum = (ci_uint16) ci_icmp_csum_finish(ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip)));
  ipbad->ip_check_be16 = pkt_csum;
  if( csum != pkt_csum ) {
    OO_DEBUG_DLF(ci_log( LPF "*** ICMP CSUM fail" ));
    return 0;
  }
  return 1;
}

/* ************************************************************
 * ICMP handling
 */

/* one entry per ICMP type (matches table in char driver)
 * b0 : Pass to char driver
 * b1 : notify routing module (not used in net driver)
 *
 * NOTE NOTE NOTE
 * If you change the entries in this table MAKE VERY SURE that the
 * message you're enabling (assuming you're enabling!) has a 32-bit
 * data area after the **32 BIT** ICMP header & before the offending 
 * IP header (which must be present in the ICMP payload).
 *
 * If this is NOT the case then you will have to put in a special case
 * in dlfilter_handle_icmp() or dlfilter_ipp_icmp_parse()
 * 
 */
#define CI_ICMP_PASS_UP 1
#define CI_ICMP_ROUTE 2
static int icmp_handled[ CI_ICMP_TYPE_MAX ] = {
  0,                      /* Echo reply */ 
  0, 
  0, 
  CI_ICMP_PASS_UP,        /* Dest unreachable (RFC792) */
  CI_ICMP_PASS_UP,        /* Source quench  (RFC792) */
  0 /*CI_ICMP_PASS_UP*/,  /* Redirect (RFC792) - enable if the routing
			   *  module in char driver requires this. */ 
  0, 
  0,  
  0,                      /* Echo (RFC792) */
  0, 
  0, 
  CI_ICMP_PASS_UP,        /* Time exceeded (RFC792) */
  CI_ICMP_PASS_UP,        /* Parameter problem (RFC792) */
  0,                      /* Timestamp (RFC792) */
  0,                      /* Timestamp reply (RFC792) */
  0,                      /* Info request (RFC792) */  
  0,                      /* Info reply (RFC792) */
  0,                      /* Address mask (RFC950) */ 
  0                       /* Address mask reply (RFC950) */
};

/*! efab_ipp_icmp_parse -
 * Get the important info out of the ICMP hdr & it's payload.  This function
 * assumes that we've already filtered the ICMP messages we're planning to
 * handle in the char driver AND it knows that all of the ones we (currently)
 * handle have 32-bits of data between the ICMP header & original IP header
 * (in the ICMP payload area).
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 *
 * \return 1 - ok, 0 - failed
 */
static int
dlfilter_ipp_icmp_parse(const ci_ip4_hdr *ip, int ip_len, efab_ipp_addr* addr)
{
  ci_ip4_hdr* data_ip;
  ci_icmp_msg* icmpl;
  ci_tcp_hdr* data_tcp;

  ci_assert( ip );
  ci_assert( addr );

  CI_ASSERT_ICMP_TYPES_VALID;
  icmpl = (ci_icmp_msg*)((char*)ip + CI_IP4_IHL(ip));

  /* SEE WARNING IN FUNCTION COMMENT ABOVE */
  data_ip = (ci_ip4_hdr*)(icmpl + 1);

  if( data_ip->ip_protocol == IPPROTO_IP || 
      data_ip->ip_protocol == IPPROTO_TCP ) {
    addr->protocol = IPPROTO_TCP;
  } else if ( data_ip->ip_protocol == IPPROTO_UDP ) {
    addr->protocol = IPPROTO_UDP;
  } else {
    OO_DEBUG_DLF(ci_log("%s: Unknown protocol %d", __FUNCTION__, 
		    data_ip->ip_protocol));
    return 0;
  }

  data_tcp = (ci_tcp_hdr*)((char*)data_ip + CI_IP4_IHL(data_ip));

  ci_assert( CI_MEMBER_OFFSET(ci_tcp_hdr, tcp_source_be16) ==
	     CI_MEMBER_OFFSET(ci_udp_hdr, udp_source_be16));

  ci_assert( CI_MEMBER_OFFSET(ci_tcp_hdr, tcp_dest_be16) ==
	     CI_MEMBER_OFFSET(ci_udp_hdr, udp_dest_be16));

  /* note that we swap the source/dest addr:port info - this means
   * that the sense of the addresses is correct for the lookup */
  addr->sport_be16 = data_tcp->tcp_dest_be16;
  addr->dport_be16 = data_tcp->tcp_source_be16;
  addr->saddr_be32 = data_ip->ip_daddr_be32;
  addr->daddr_be32 = data_ip->ip_saddr_be32;
  return 1;
}


/*! dlfilter_handle_icmp -
 * Check to see if the ICMP pkt is one we want to handle
 *
 * NOTE: please refer to comments above thre ICMP type check table before
 *       making changes to supported ICMP codes!!
 *
 * The device might not be a Onload-enabled device; this needs to be
 * verified.
 *
 * returns 0 : not for us
 *         1 : want to pass this over the link
 */
static int dlfilter_handle_icmp(struct net* netns, int ifindex,
                                efx_dlfilter_cb_t* fcb,
                                const ci_ip4_hdr *ip, int len, int* thr_id )
{
  ci_icmp_hdr* icmp;
  efab_ipp_addr addr;

  ci_assert(fcb);
  ci_assert(ip);
  
  CI_ASSERT_ICMP_TYPES_VALID;
  ci_assert_ge(len, CI_IP4_IHL(ip) + sizeof(ci_icmp_msg));

  /* Reject request codes we don't do (the kernel can do it for us) */
  icmp = (ci_icmp_hdr *)((char *)ip + CI_IP4_IHL(ip));
  if( ( icmp->type >= CI_ICMP_TYPE_MAX) || 
      !(icmp_handled[icmp->type] & CI_ICMP_PASS_UP) ) {
    OO_DEBUG_DLF(ci_log(LPF "handle_icmp: not interested in ICMP type:%d",
		    icmp->type));
    return 0;
  }

  /* Parse the message to get the addressing info.  Note that ONLY
   * the source & dest addr/ports & protocol are filled in [addr] */
  if( !dlfilter_ipp_icmp_parse( ip, len, &addr ) ) {
    OO_DEBUG_DLF(ci_log(LPF "handle_icmp: couldn't parse ICMP pkt"));
    return 0;
  }

  /* sums etc? */
  if( !dlfilter_icmp_checks(ip) ) {
    OO_DEBUG_DLF(ci_log(LPF "handle_icmp: ICMP sums fail etc."));
    return 0;
  }

  /* Did it arrive on an Onload-enabled device? */
  {
    ci_assert_nequal(fcb->is_onloaded, NULL);
    if( ! fcb->is_onloaded(fcb->ctx, netns, ifindex) ) {
      OO_DEBUG_DLF(ci_log(LPF "handle_icmp: not our netns or device"));
      return 0;
    }
  }

  /* Finally, do we have a filter?
   * NOTE: this is the point at which the char driver's TCP helper
   *       resource handle is picked up */
  if( dlfilter_full_lookup(fcb, addr.daddr_be32, 
                           addr.dport_be16, addr.saddr_be32, 
                           addr.sport_be16, addr.protocol, thr_id) < 0 ) {
    OO_DEBUG_DLF( ci_log( LPF "handle_icmp: no filter"));
    return 0;
  }

  ci_assert_nequal(*thr_id, CI_ID_POOL_ID_NONE);
  OO_DEBUG_DLF(ci_log(LPF "handle_icmp: Interested type:%d code:%d",
		    icmp->type, icmp->code));
  return 1;
}


/* *************************************************************
 * Filter management
 */

/* These hash funcs mimic those in the char driver's addr table */
ci_inline ci_uint32
dlfilter_hash1( ci_uint32 laddr, ci_uint16 lport,
		ci_uint32 raddr, ci_uint16 rport, ci_uint8 prot)
{
  ci_uint32 h = laddr ^ (ci_uint32)lport ^ raddr ^ (ci_uint32)rport ^ 
    (ci_uint32)prot;
  h ^= h >> 16;
  h ^= h >> 8;
  return h & EFAB_DLFILT_ENTRY_MASK;

}

ci_inline ci_uint32
dlfilter_hash2( ci_uint32 laddr, ci_uint16 lport,
		ci_uint32 raddr, ci_uint16 rport, ci_uint8 prot)
{
  return ( laddr  ^ (ci_uint32)lport  ^ raddr ^ (ci_uint32)rport ^ 
	   (ci_uint32)prot) | 1u;
}

/* returns 0 on a match.  Will match on the protocol, the local address
 * and port and optionally on the remote addr/port if both are not 0 */
ci_inline int 
dlfilter_match( efx_dlfilter_cb_t* fcb, efx_dlfilt_entry_t* ent, 
		ci_uint32 laddr, ci_uint16 lport, ci_uint32 raddr,
		ci_uint32 rport, ci_uint8 protocol )
{
  ci_assert(fcb);
  ci_assert(ent);

  if( !EFAB_DLFILT_ENTRY_IN_USE(ent) )
    return -1;

  if( rport | raddr ) {
    /* not wildcard */
    return (int)((raddr - ent->raddr_be32) |
                 (laddr - ent->laddr_be32)   |
                 (rport - ent->rport_be16) |
                 (lport - ent->lport_be16) |
                 (protocol - ent->ip_protocol));
  }
  else {
    return (int)( (laddr - ent->laddr_be32)   |
                  (lport - ent->lport_be16) |
                  (protocol - ent->ip_protocol));
  }
}


static int 
dlfilter_lookup( efx_dlfilter_cb_t* fcb, ci_uint32 laddr, ci_uint16 lport,  
		 ci_uint32 raddr, ci_uint16 rport, ci_uint8 protocol, 
		 int* thr_id)  
{
  unsigned hash1, hash2, first;
#ifndef NDEBUG
  int hops = 0;
#endif

  ci_assert(fcb);
  ci_assert( protocol == IPPROTO_UDP || protocol == IPPROTO_TCP );
  ci_assert(thr_id);

  hash1 = first = dlfilter_hash1(laddr, lport, raddr, rport, protocol);
  hash2 = dlfilter_hash2(laddr, lport, raddr, rport, protocol);

  VERB(ci_log(LPF " dlfilter_lookup %s R:%s:%u L:%s:%u hash=%u:%u",
	      protocol != IPPROTO_UDP ? "TCP" : "UDP",
	      dlfilt_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	      dlfilt_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	      hash1, hash2));

  while( 1 ) {
    int id = fcb->table[hash1].state;
    if( CI_LIKELY(id >= 0) ) {
      if( !dlfilter_match( fcb, &fcb->table[hash1],
			   laddr, lport, raddr, rport, protocol )){
	*thr_id = fcb->table[hash1].thr_id;
      	return hash1;
      }
    }
    if( id == EFAB_DLFILT_EMPTY )
      break;
    hash1 = (hash1 + hash2) & EFAB_DLFILT_ENTRY_MASK;
#ifndef NDEBUG
    ++hops;
    if( hash1 == first ) {
      ci_log(LPF " dlfilter_lookup: Got into a loop");
      ci_log(LPF "lookup: LOOP R:%s:%u L:%s:%u hash=%x:%x hops=%d",
		   dlfilt_addr_str(raddr), rport,
		   dlfilt_addr_str(laddr), lport, hash1, hash2, hops);
      return -ELOOP;
    }
#endif
  }

  return -ENOENT;
}


static int
dlfilter_full_lookup(efx_dlfilter_cb_t* fcb, ci_uint32 laddr, ci_uint16 lport,
                     ci_uint32 raddr, ci_uint16 rport, ci_uint8 protocol,
                     int* thr_id )
{
  int rc;

  ci_assert( thr_id );
  ci_assert(fcb);

  if( 0 > (rc = dlfilter_lookup(fcb, laddr, lport, raddr, rport, protocol,
                                thr_id)))
    rc = dlfilter_lookup( fcb, laddr, lport,  0, 0, protocol, thr_id );
  VERB(ci_log("%s: rc:%d thr_id:%x", __FUNCTION__, rc, *thr_id));
  return rc;
}


/* Insert a new entry in the hash table & the index table */
static int
dlfilter_insert(efx_dlfilter_cb_t* fcb, ci_uint32 laddr, ci_uint16 lport,
                ci_uint32 raddr, ci_uint16 rport, ci_uint8 protocol,
                int thr_id, unsigned* handle_out)
{
  unsigned first, hash1, hash2, h1, h2;
#ifndef NDEBUG
  unsigned located;
#endif

  ci_assert(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
  ci_assert_nequal(thr_id, CI_ID_POOL_ID_NONE);

  h1= hash1= first= dlfilter_hash1( laddr, lport, raddr, rport, protocol);
  h2= hash2= dlfilter_hash2( laddr, lport, raddr, rport, protocol);

  /* First find a free slot (and check for duplicates). */
  while( 1 ) {
    if( !EFAB_DLFILT_ENTRY_IN_USE(&fcb->table[hash1]) ) {
#ifndef NDEBUG
      located = hash1;
#endif
      break;
    }

    if(!dlfilter_match( fcb, &fcb->table[hash1], laddr, lport, 
			raddr, rport, protocol)) {
      OO_DEBUG_DLF( ci_log(LPF " DUP %s R:%s:%u L:%s:%u",
		       protocol != IPPROTO_UDP ? "TCP" : "UDP",
		       dlfilt_addr_str(raddr),
		       (unsigned) CI_BSWAP_BE16(rport), 
		       dlfilt_addr_str(laddr),
		       (unsigned) CI_BSWAP_BE16(lport)));
      return -ESRCH;
    }
    hash1 = (hash1 + hash2) & EFAB_DLFILT_ENTRY_MASK;
    if( hash1 == first ) {
      ci_log(LPF " INSERT LOOP %sP R:%s:%u L:%s:%u", 
	     protocol != IPPROTO_UDP ? "TC" : "UD",
	     dlfilt_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     dlfilt_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport));
#ifndef NDEBUG
      dlfilter_dump_on_error(fcb);
#endif
      return -ELOOP;
    }
  }

  /* Not a duplicate & space available - so we can add it, up the
   * route counts along the way (may be nothing to do here) */
  hash1 = h1;  hash2 = h2;
  while ( EFAB_DLFILT_ENTRY_IN_USE(&fcb->table[hash1]) ) {
    fcb->table[hash1].state++;
    hash1 = (hash1 + hash2) &  EFAB_DLFILT_ENTRY_MASK;
  }

  /* insert the new entry. */
  OO_DEBUG_DLF(ci_log(LPF " INS thr:%d %sP R:%s:%u L:%s:%u hash=%u:%u",
                      thr_id, protocol != IPPROTO_UDP ? "TC" : "UD",
                      dlfilt_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
                      dlfilt_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                      hash1, hash2));

  /* Now being used, gets a route count INCREMENT of 1 (this entry) 
      - needs to be an increment because if a tombstone it could
      already have a non-zero reference count */
  ci_assert( located == hash1 );
  ci_assert( !EFAB_DLFILT_ENTRY_IN_USE(&fcb->table[hash1]) );
  fcb->table[hash1].state = EFAB_DLFILT_INUSE + 1
            + EFAB_DLFILT_ENTRY_ROUTE(&fcb->table[hash1]);
  fcb->table[hash1].raddr_be32 = raddr;
  fcb->table[hash1].rport_be16 = rport;
  fcb->table[hash1].laddr_be32 = laddr;
  fcb->table[hash1].lport_be16 = lport;
  fcb->table[hash1].ip_protocol = protocol;
  fcb->table[hash1].thr_id = thr_id;
  fcb->used_slots++;
  *handle_out = hash1;

  return 0;
}


void efx_dlfilter_remove(efx_dlfilter_cb_t* fcb, unsigned handle)
{
  efx_dlfilt_entry_t *ent;
  unsigned hash1, hash2, first;

  ci_assert(handle != EFX_DLFILTER_HANDLE_BAD);
  ci_assert(fcb);

  ent = &fcb->table[handle];
  ci_assert( EFAB_DLFILT_ENTRY_IN_USE(ent) );

  hash1 = first = dlfilter_hash1(ent->laddr_be32, ent->lport_be16,
				 ent->raddr_be32, ent->rport_be16, 
				 ent->ip_protocol );
  hash2 = dlfilter_hash2(ent->laddr_be32, ent->lport_be16,
			 ent->raddr_be32, ent->rport_be16, 
			 ent->ip_protocol );
  while( 1 ) {
    
    ent = &fcb->table[hash1];
    /* st gets the state, must not be EMPTY */
    ci_assert( !EFAB_DLFILT_ENTRY_EMPTY(ent) );
    ci_assert( EFAB_DLFILT_ENTRY_ROUTE(ent) );
    --ent->state;

    if( hash1 == handle )
      /* We've found the right entry. */
      break;

#ifndef NDEBUG
    /* The entry's not the one we're after. If the route count gets
     * to 0 then the entry must have been tombstoned previously (because
     * the route count is initialised to 1 at insertion & decremented
     * at removal) */
    if( !EFAB_DLFILT_ENTRY_ROUTE(ent)) {
      if( EFAB_DLFILT_ENTRY_STATE(ent) != EFAB_DLFILT_TOMBSTONE ) {
	dlfilter_dump_entry( fcb, "ERROR", hash1, ent );
	ci_log( "ERROR state = %#x", ent->state );
	ci_assert( EFAB_DLFILT_ENTRY_STATE(ent) == EFAB_DLFILT_TOMBSTONE );
      }
    }
#endif
    /* if now an unused tombstone */
    if( ent->state == EFAB_DLFILT_TOMBSTONE ) {
      /* A filter that has been previously removed can finally be
       * freed-up */
      ent->state = EFAB_DLFILT_EMPTY;
      fcb->used_slots--;
    }
    hash1 = (hash1 + hash2) & EFAB_DLFILT_ENTRY_MASK;
    /* If we do a full check of the table then we're in trouble 
     * as it means that it's probably very full and our entry's 
     * definitely escaped! */
    ci_assert(hash1 != first);
  }

  ci_assert(hash1 == handle);

  OO_DEBUG_DLF(ci_log(LPF " REM %s R:%s:%u L:%s:%u St:%x h:%u:%u", 
                      ent->ip_protocol != IPPROTO_UDP ? "TCP" : "UDP",
                      dlfilt_addr_str(ent->raddr_be32), 
                      (unsigned) CI_BSWAP_BE16(ent->rport_be16),
                      dlfilt_addr_str(ent->laddr_be32),
                      (unsigned) CI_BSWAP_BE16(ent->lport_be16),
                      ent->state, hash1, hash2));

  ci_assert( EFAB_DLFILT_ENTRY_IN_USE(ent) );
  if( EFAB_DLFILT_ENTRY_ROUTE(ent) ) {
    ent->state |= EFAB_DLFILT_TOMBSTONE;
  } else {
    ent->state = EFAB_DLFILT_EMPTY;
    fcb->used_slots--;
  }
}


void efx_dlfilter_add(efx_dlfilter_cb_t* fcb, unsigned protocol,
                      unsigned laddr, ci_uint16 lport,
                      unsigned raddr, ci_uint16 rport, int thr_id,
                      unsigned* handle_out)
{
  ci_assert(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);

  *handle_out = EFX_DLFILTER_HANDLE_BAD;
  dlfilter_insert(fcb, laddr, lport,  raddr, rport,
                  protocol, thr_id, handle_out);
}


static void
dlfilter_init(efx_dlfilter_cb_t* fcb, void* ctx,
              efx_dlfilter_is_onloaded_t is_onloaded)
{
  int ctr;

  ci_assert(fcb);

  memset(fcb, 0, sizeof(*fcb));

  /* set up the main control block */
#ifndef NDEBUG
  if( !CI_IS_POW2( EFAB_DLFILT_ENTRY_COUNT )) {
    ci_log( LPF "init: EFAB_DLFILT_ENTRY_COUNT (%u) must be pow 2",
	    EFAB_DLFILT_ENTRY_COUNT );
    ci_assert(0);
  }
#endif

  for( ctr = 0; ctr < EFAB_DLFILT_ENTRY_COUNT; ctr++ )
    fcb->table[ctr].state = EFAB_DLFILT_EMPTY;

  /* no filters yet */
  fcb->used_slots = 0;

  fcb->ctx = ctx;
  fcb->is_onloaded = is_onloaded;
}


/* Construct a driverlink filter object.
 * Return     ptr to object or NULL if failed
 */
struct efx_dlfilt_cb_s*
efx_dlfilter_ctor(void* ctx, efx_dlfilter_is_onloaded_t is_onloaded)
{
  efx_dlfilter_cb_t* cb = ci_vmalloc(sizeof(efx_dlfilter_cb_t));
  if( cb != NULL )
    dlfilter_init(cb, ctx, is_onloaded);
  return cb;
}


/* Clean-up object created through efx_dlfilter_ctor() */
void efx_dlfilter_dtor( efx_dlfilter_cb_t* cb )
{
  ci_assert( cb );
  OO_DEBUG_DLF(ci_log("%s()", __FUNCTION__));
#ifndef NDEBUG
  {
    int no_empty, no_tomb, no_used;
    efx_dlfilter_count_stats(cb, &no_empty, &no_tomb, &no_used);
    if( no_used )
      ci_log("ERROR ERROR driverlink filters at unload: %d", no_used);
  }
#endif
  ci_vfree( cb );
}


#ifndef NDEBUG
/* compile time assert: EFAB_DLFILT_ENTRY_COUNT too small for h/w! */
CI_BUILD_ASSERT(EFAB_DLFILT_ENTRY_COUNT >= EFHW_IP_FILTER_NUM);
#endif




/* *************************************************************
 * THE MAIN ENTRY POINT
 * 
 * Data-passing entry point.
 * The device might not be a Onload-enabled device; this needs to be
 * verified for some types of filtering.
 *
 * Returns: 0 - carry on as normal
 *          else - discard SKB etc.
 */
int efx_dlfilter_handler(struct net* netns, int ifindex, efx_dlfilter_cb_t* fcb,
                         const ci_ether_hdr* hdr, const void* ip_hdr, int len)
{
  const ci_ip4_hdr* ip;
  int thr_id;
  int ip_hlen, ip_paylen;

  /* ASSUMED: IP4, IHL sensible */
  if( CI_UNLIKELY(len < sizeof(ci_ip4_hdr)) )
    return 0;
  ip = (const ci_ip4_hdr*) ip_hdr;
  ip_paylen = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  ip_hlen = CI_IP4_IHL(ip);
  if( len < ip_hlen || len < ip_paylen || ip_hlen >= ip_paylen )
    return 0;
  ip_paylen -= ip_hlen;

  /* At this point, we know we have valid IP packet with
   * ip_hlen < ip_len <= hw_len.  ip_paylen is the length of the IP
   * payload. */

  /* We do not handle fragmented packets. */
  if( CI_UNLIKELY( CI_IP4_FRAG_OFFSET(ip) ))
    return 0;

  /* ICMP only, no fragments */
  if( ip->ip_protocol == IPPROTO_ICMP ) {
    if(CI_UNLIKELY( ip->ip_frag_off_be16 & CI_BSWAPC_BE16(0xafff) ))
      return 0;
    if( CI_UNLIKELY(ip_paylen < sizeof(ci_icmp_hdr)) )
      return 0;

    if( dlfilter_handle_icmp(netns, ifindex, fcb, ip, len, &thr_id) ) {
      if( thr_id != -1 ) {
        OO_DEBUG_DLF(ci_log(LPF "handler: pass ICMP len:%d thr:%d", 
                            len, thr_id));
        efab_handle_ipp_pkt_task(thr_id, ifindex, ip, len);
      }
      else {
        OO_DEBUG_DLF(ci_log(LPF "handler: reject ICMP, INVALID THR ID %d",
                            thr_id));
      }
    }
    return 0;
  }

  return 0;
}


/* ******************************************************************
 * Debug stuff
 */

#ifndef NDEBUG

#define __DLF_ENT_DUMP_HDR \
  "  Idx   St Rt R.Addr    RPort L.Addr         LPort Pr THR"
#define __DLF_ENT_DUMP_FMT \
  "%s %5d %2d %2d %8s %4u %15s %5u %2d %08x"

static void dlfilter_dump_entry( efx_dlfilter_cb_t* fcb, const char * pfx, 
				 int idx, efx_dlfilt_entry_t* ent )
{
  ci_assert(fcb);
  ci_assert(ent);
  ci_log(__DLF_ENT_DUMP_FMT, pfx ? pfx : "", idx,
         ent->state >> EFAB_DLFILT_STATE_SHIFT, 
         ent->state & ~EFAB_DLFILT_STATE_MASK,
         dlfilt_addr_str(ent->raddr_be32), CI_BSWAP_BE16(ent->rport_be16),
         dlfilt_addr_str(ent->laddr_be32), CI_BSWAP_BE16(ent->lport_be16),
         ent->ip_protocol, ent->thr_id);
}


void efx_dlfilter_dump(efx_dlfilter_cb_t* fcb)
{
  int ctr;
  ci_assert(fcb);

  ci_log("Master CB");
  ci_log("Used slots:%d", fcb->used_slots);
  ci_log("Filter table");
  ci_log( __DLF_ENT_DUMP_HDR);
  for( ctr = 0; ctr < EFAB_DLFILT_ENTRY_COUNT; ctr++ ) {
    if( fcb->table[ctr].state != EFAB_DLFILT_EMPTY )
      dlfilter_dump_entry(fcb, 0, ctr, &fcb->table[ctr]);
  }
}
#endif

/*! \cidoxg_end */
