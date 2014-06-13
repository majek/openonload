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
** \author  djr
**  \brief  Software implemented endpoint lookup.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"


#define LPF "tcp_table: "
#define LPFU "udp_table: "


#define TOMBSTONE  -1
#define EMPTY      -2

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

ci_inline unsigned tcp_hash1(ci_netif_filter_table* tbl,
			     unsigned laddr, unsigned lport,
			     unsigned raddr, unsigned rport, 
			     unsigned protocol) {
  unsigned h = raddr ^ laddr ^ lport ^ rport ^ protocol;
  h ^= h >> 16;
  h ^= h >> 8;
  return h & tbl->table_size_mask;
}

ci_inline unsigned tcp_hash2(ci_netif_filter_table* tbl,
			     unsigned laddr, unsigned lport,
			     unsigned raddr, unsigned rport, 
			     unsigned protocol ) {
  return (laddr ^ raddr ^ lport ^ rport ^ protocol) | 1u;
}


int ci_netif_filter_lookup(ci_netif* netif, unsigned laddr, unsigned lport,
			   unsigned raddr, unsigned rport, unsigned protocol)
{
  unsigned hash1, hash2;
  ci_netif_filter_table* tbl;
  unsigned first;

  ci_assert(netif);
  ci_assert(netif->filter_table);

  tbl = netif->filter_table;
  hash1 = tcp_hash1(tbl, laddr, lport, raddr, rport, protocol);
  first = hash1;

  LOG_NV(log("tbl_lookup: %s %s:%u->%s:%u hash=%u:%u at=%u",
	     CI_IP_PROTOCOL_STR(protocol),
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     first, tcp_hash2(tbl, laddr, lport, raddr, rport, protocol),
	     hash1));

  while( 1 ) {
    int id = tbl->table[hash1].id;
    if( CI_LIKELY(id >= 0) ) {
      ci_sock_cmn* s = ID_TO_SOCK(netif, id);
      if( ((laddr    - tbl->table[hash1].laddr) |
	   (lport    - sock_lport_be16(s)     ) |
	   (raddr    - sock_raddr_be32(s)     ) |
	   (rport    - sock_rport_be16(s)     ) |
	   (protocol - sock_protocol(s)       )) == 0 )
      	return hash1;
    }
    if( id == EMPTY )  break;
    /* We defer calculating hash2 until its needed, just to make the fast
    ** case that little bit faster.  This means we may calculate hash2
    ** multiple times, but its not that expensive, so probably worth it.
    */
    hash2 = tcp_hash2(tbl, laddr, lport, raddr, rport, protocol);
    hash1 = (hash1 + hash2) & tbl->table_size_mask;
    if( hash1 == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP %s:%u->%s:%u hash=%x:%x",
                   FN_PRI_ARGS(netif), ip_addr_str(laddr), lport,
		   ip_addr_str(raddr), rport, hash1, hash2));
      return -ELOOP;
    }
  }

  return -ENOENT;
}


ci_inline int ci_netif_intf_i_to_base_ifindex(ci_netif* ni, int intf_i)
{
  ci_hwport_id_t hwport;
  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  hwport = ni->state->intf_i_to_hwport[intf_i];
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_REGISTER_INTERFACES);
  return cicp_fwd_hwport_to_base_ifindex(&CICP_MIBS(CICP_HANDLE(ni))->user,
                                         hwport);
}


ci_inline int ci_sock_intf_check(ci_netif* ni, ci_sock_cmn* s,
                                 int intf_i, int vlan)
{
  return ((s->rx_bind2dev_base_ifindex ==
           ci_netif_intf_i_to_base_ifindex(ni, intf_i)) &&
          s->rx_bind2dev_vlan == vlan);
}


void ci_netif_filter_for_each_match(ci_netif* ni, unsigned laddr,
                                    unsigned lport, unsigned raddr,
                                    unsigned rport, unsigned protocol,
                                    int intf_i, int vlan,
                                    int (*callback)(ci_sock_cmn*, void*),
                                    void* callback_arg)
{
  ci_netif_filter_table* tbl;
  unsigned hash1, hash2;
  unsigned first;

  tbl = ni->filter_table;
  hash1 = tcp_hash1(tbl, laddr, lport, raddr, rport, protocol);
  first = hash1;

  LOG_NV(log("%s: %s %s:%u->%s:%u hash=%u:%u at=%u",
             __FUNCTION__, CI_IP_PROTOCOL_STR(protocol),
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     first, tcp_hash2(tbl, laddr, lport, raddr, rport, protocol),
	     hash1));

  while( 1 ) {
    int id = tbl->table[hash1].id;
    if(CI_LIKELY( id >= 0 )) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
      if( ((laddr    - tbl->table[hash1].laddr) |
	   (lport    - sock_lport_be16(s)     ) |
	   (raddr    - sock_raddr_be32(s)     ) |
	   (rport    - sock_rport_be16(s)     ) |
	   (protocol - sock_protocol(s)       )) == 0 )
        if(CI_LIKELY( s->rx_bind2dev_ifindex == CI_IFID_BAD ||
                      ci_sock_intf_check(ni, s, intf_i, vlan) ))
          if( callback(s, callback_arg) != 0 )
            return;
    }
    else if( id == EMPTY )
      break;
    /* We defer calculating hash2 until its needed, just to make the fast
    ** case that little bit faster.  This means we may calculate hash2
    ** multiple times, but its not that expensive, so probably worth it.
    */
    hash2 = tcp_hash2(tbl, laddr, lport, raddr, rport, protocol);
    hash1 = (hash1 + hash2) & tbl->table_size_mask;
    if( hash1 == first ) {
      LOG_NV(ci_log(FN_FMT "ITERATE FULL %s:%u->%s:%u hash=%x:%x",
                   FN_PRI_ARGS(ni), ip_addr_str(laddr), lport,
		   ip_addr_str(raddr), rport, hash1, hash2));
      break;
    }
  }
}


/* Insert for either TCP or UDP */
int ci_netif_filter_insert(ci_netif* netif, oo_sp tcp_id,
			   unsigned laddr, unsigned lport,
			   unsigned raddr, unsigned rport, unsigned protocol)
{
  ci_netif_filter_table_entry* entry;
  unsigned hash1, hash2;
  ci_netif_filter_table* tbl;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
  unsigned hops = 1;
#endif
  unsigned first;

  ci_assert(netif);
  ci_assert(netif->filter_table);
  tbl = netif->filter_table;

  hash1 = tcp_hash1(tbl, laddr, lport, raddr, rport, protocol);
  hash2 = tcp_hash2(tbl, laddr, lport, raddr, rport, protocol);
  first = hash1;

  /* Find a free slot. */
  while( 1 ) {
    entry = &tbl->table[hash1];
    if( entry->id < 0 )  break;

    ++entry->route_count;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
    ++hops;
#endif

    /* A socket can only have multiple entries in the filter table if each
     * entry has a different [laddr].
     */
    if( (entry->id == OO_SP_TO_INT(tcp_id)) && (laddr == entry->laddr) ) {
      /* Multicast 224.0.0.1 is added for all interfaces when necessary. */
      ci_assert_equal(laddr, CI_IP_ALL_HOSTS);
      return 0;
    }

    hash1 = (hash1 + hash2) & tbl->table_size_mask;

    if( hash1 == first ) {
      ci_sock_cmn *s = SP_TO_SOCK_CMN(netif, tcp_id);
      if( ! (s->s_flags & CI_SOCK_FLAG_SW_FILTER_FULL) ) {
        LOG_E(ci_log(FN_FMT "%d FULL %s %s:%u->%s:%u hops=%u",
                     FN_PRI_ARGS(netif),
                     OO_SP_FMT(tcp_id), CI_IP_PROTOCOL_STR(protocol),
                     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
                     hops));
        s->s_flags |= CI_SOCK_FLAG_SW_FILTER_FULL;
      }

      CITP_STATS_NETIF_INC(netif, sw_filter_insert_table_full);
      return -ENOBUFS;
    }
  }

  /* Now insert the new entry. */
  LOG_TC(ci_log(FN_FMT "%d INSERT %s %s:%u->%s:%u hash=%u:%u at=%u "
		"over=%d hops=%u", FN_PRI_ARGS(netif), OO_SP_FMT(tcp_id),
                CI_IP_PROTOCOL_STR(protocol),
		ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
		ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
		first, hash2, hash1, entry->id, hops));

#if CI_CFG_STATS_NETIF
  if( hops > netif->state->stats.table_max_hops )
    netif->state->stats.table_max_hops = hops;
  /* Keep a rolling average of the number of hops per entry. */
  if( netif->state->stats.table_mean_hops == 0 )
    netif->state->stats.table_mean_hops = 1;
  netif->state->stats.table_mean_hops =
    (netif->state->stats.table_mean_hops * 9 + hops) / 10;

  if( entry->id == EMPTY )
    ++netif->state->stats.table_n_slots;
  ++netif->state->stats.table_n_entries;
#endif

  entry->id = (ci_int16) OO_SP_TO_INT(tcp_id);
  entry->laddr = laddr;
  return 0;
}


static void
__ci_netif_filter_remove(ci_netif* ni, unsigned hash1,
                         unsigned hash2, int hops, unsigned last_tbl_i)
{
  ci_netif_filter_table* tbl = ni->filter_table;
  ci_netif_filter_table_entry* entry;
  unsigned tbl_i;
  int i;

  tbl_i = hash1;
  for( i = 0; i < hops; ++i ) {
    entry = &tbl->table[tbl_i];
    ci_assert(entry->id != EMPTY);
    ci_assert(entry->route_count > 0);
    if( --entry->route_count == 0 && entry->id == TOMBSTONE ) {
      CITP_STATS_NETIF(--ni->state->stats.table_n_slots);
      entry->id = EMPTY;
    }
    tbl_i = (tbl_i + hash2) & tbl->table_size_mask;
  }
  ci_assert(tbl_i == last_tbl_i);

  CITP_STATS_NETIF(--ni->state->stats.table_n_entries);
  entry = &tbl->table[tbl_i];
  if( entry->route_count == 0 ) {
    CITP_STATS_NETIF(--ni->state->stats.table_n_slots);
    entry->id = EMPTY;
  }
  else {
    entry->id = TOMBSTONE;
  }
}


void
ci_netif_filter_remove(ci_netif* netif, oo_sp sock_p,
		       unsigned laddr, unsigned lport,
		       unsigned raddr, unsigned rport, unsigned protocol)
{
  ci_netif_filter_table_entry* entry;
  unsigned hash1, hash2, tbl_i;
  ci_netif_filter_table* tbl;
  int hops = 0;
  unsigned first;

  tbl = netif->filter_table;
  hash1 = tcp_hash1(tbl, laddr, lport, raddr, rport, protocol);
  hash2 = tcp_hash2(tbl, laddr, lport, raddr, rport, protocol);
  first = hash1;

  LOG_TC(ci_log("%s: [%d:%d] REMOVE %s %s:%u->%s:%u hash=%u:%u",
                __FUNCTION__, NI_ID(netif), OO_SP_FMT(sock_p),
                CI_IP_PROTOCOL_STR(protocol),
		ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
		ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
		hash1, hash2));

  tbl_i = hash1;
  while( 1 ) {
    entry = &tbl->table[tbl_i];
    if( entry->id == OO_SP_TO_INT(sock_p) ) {
      if( laddr == entry->laddr )
        break;
    }
    else if( entry->id == EMPTY ) {
      if( laddr != CI_IP_ALL_HOSTS) {
        /* See ci_netif_filter_insert() comment for CI_IP_ALL_HOSTS.
         * With CI_IP_ALL_HOSTS we can't unbind from one interface only,
         * so we are just removing all filters. */
        LOG_E(ci_log("%s: ERROR: [%d:%d] REMOVE %s %s:%u->%s:%u NOT FOUND",
                     __FUNCTION__, NI_ID(netif), OO_SP_FMT(sock_p),
                     CI_IP_PROTOCOL_STR(protocol),
                     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport)));
      }
      return;
    }
    ci_assert(entry->route_count > 0);
    tbl_i = (tbl_i + hash2) & tbl->table_size_mask;
    ++hops;
    if( tbl_i == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP [%d] %s %s:%u->%s:%u",
                   FN_PRI_ARGS(netif), OO_SP_FMT(sock_p),
                   CI_IP_PROTOCOL_STR(protocol),
                   ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                   ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport)));
      return /*-ENOENT*/;
    }
  }

  __ci_netif_filter_remove(netif, hash1, hash2, hops, tbl_i);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

#ifdef __ci_driver__

void ci_netif_filter_init(ci_netif_filter_table* tbl, int size_lg2)
{
  unsigned i;
  unsigned size = ci_pow2(size_lg2);

  ci_assert(tbl);
  ci_assert(size_lg2 > 0);
  ci_assert(size_lg2 < 32);

  tbl->table_size_mask = size - 1;

  for( i = 0; i < size; ++i ) {
    tbl->table[i].id = EMPTY;
    tbl->table[i].route_count = 0;
    tbl->table[i].laddr = 0;
  }
}

#endif

ci_sock_cmn* __ci_netif_filter_lookup(ci_netif* netif, unsigned laddr, 
				      unsigned lport, unsigned raddr, 
				      unsigned rport, unsigned protocol)
{
  int rc;

  /* try full lookup */
  rc = ci_netif_filter_lookup(netif, laddr, lport,  raddr, rport, protocol);
  LOG_NV(log(LPF "FULL LOOKUP %s:%u->%s:%u\n" 
	     "     hash=%u rc=%d",
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     tcp_hash1(netif->filter_table, 
		       laddr, lport, raddr, rport, 
		       protocol ),
	     rc));    

  if(CI_LIKELY( rc >= 0 ))
    return ID_TO_SOCK(netif, netif->filter_table->table[rc].id);

  /* try wildcard lookup */
  raddr = rport = 0;
  rc = ci_netif_filter_lookup(netif, laddr, lport, raddr, rport, protocol);
  LOG_NV(log(LPF "WILD LOOKUP %s:%u->%s:%u\n"
	    "     hash=%u rc=%d",
	    ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	    ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	    tcp_hash1(netif->filter_table, 
		      laddr, lport, raddr, rport, protocol ),
	     rc));

  if(CI_LIKELY( rc >= 0 ))
    return ID_TO_SOCK(netif, netif->filter_table->table[rc].id);
 
  return 0;
}


int ci_netif_filter_check(ci_netif* netif,
			  unsigned laddr, unsigned lport,
			  unsigned raddr, unsigned rport,
			  unsigned protocol)
{
  return ci_netif_filter_lookup(netif, laddr, lport,  raddr, rport, protocol);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

void ci_netif_filter_dump(ci_netif* ni)
{
  int id;
  unsigned i;
  ci_netif_filter_table* tbl;

  ci_assert(ni);
  tbl = ni->filter_table;

  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#if CI_CFG_STATS_NETIF
  log(FN_FMT "size=%d n_entries=%i n_slots=%i max=%i mean=%i", FN_PRI_ARGS(ni),
      tbl->table_size_mask + 1, ni->state->stats.table_n_entries,
      ni->state->stats.table_n_slots, ni->state->stats.table_max_hops,
      ni->state->stats.table_mean_hops);
#endif

  for( i = 0; i <= tbl->table_size_mask; ++i ) {
    id = tbl->table[i].id;
    if( CI_LIKELY(id >= 0) ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
      unsigned laddr = tbl->table[i].laddr;
      int lport = sock_lport_be16(s);
      unsigned raddr = sock_raddr_be32(s);
      int rport = sock_rport_be16(s);
      int protocol = sock_protocol(s);
      unsigned hash1 = tcp_hash1(tbl, laddr, lport, raddr, rport, protocol);
      log("%04d id=%-4d rt_ct=%d %s "CI_IP_PRINTF_FORMAT":%d "
          CI_IP_PRINTF_FORMAT":%d %04d",
	  i, id, tbl->table[i].route_count, CI_IP_PROTOCOL_STR(protocol),
          CI_IP_PRINTF_ARGS(&laddr), CI_BSWAP_BE16(lport),
	  CI_IP_PRINTF_ARGS(&raddr), CI_BSWAP_BE16(rport), hash1);
    }
  }
  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
}

/*! \cidoxg_end */
