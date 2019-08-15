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
** \author  djr
**  \brief  Software implemented endpoint lookup.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include <ci/internal/transport_config_opt.h>
#include <onload/hash.h>
#include "ip_internal.h"
#include "netif_table.h"


int ci_netif_filter_lookup(ci_netif* netif, unsigned laddr, unsigned lport,
			   unsigned raddr, unsigned rport, unsigned protocol)
{
  unsigned hash1, hash2 = 0;
  ci_netif_filter_table* tbl;
  unsigned first;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(netif->filter_table);

  tbl = netif->filter_table;
  hash1 = onload_hash1(AF_INET, tbl->table_size_mask, &laddr, lport,
                       &raddr, rport, protocol);
  first = hash1;

  LOG_NV(log("tbl_lookup: %s %s:%u->%s:%u hash=%u:%u at=%u",
	     CI_IP_PROTOCOL_STR(protocol),
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     first, onload_hash2(AF_INET, &laddr, lport, &raddr, rport, protocol),
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
    /* We defer calculating hash2 until it's needed, just to make the fast
     * case that little bit faster. */
    if( hash1 == first )
      hash2 = onload_hash2(AF_INET, &laddr, lport, &raddr, rport, protocol);
    hash1 = (hash1 + hash2) & tbl->table_size_mask;
    if( hash1 == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP %s:%u->%s:%u hash=%u:%u",
                   FN_PRI_ARGS(netif), ip_addr_str(laddr), lport,
		   ip_addr_str(raddr), rport, hash1, hash2));
      return -ELOOP;
    }
  }

  return -ENOENT;
}


int ci_netif_listener_lookup(ci_netif* netif, unsigned laddr, unsigned lport)
{
  int rc = ci_netif_filter_lookup(netif, laddr, lport, 0, 0, IPPROTO_TCP);
  if( rc < 0 )
    rc = ci_netif_filter_lookup(netif, 0, lport, 0, 0, IPPROTO_TCP);
  return rc;
}


ci_uint32
ci_netif_filter_hash(ci_netif* ni, unsigned laddr, unsigned lport,
                     unsigned raddr, unsigned rport, unsigned protocol)
{
  return onload_hash3(AF_INET, &laddr, lport, &raddr, rport, protocol);
}


ci_inline int ci_sock_intf_check(ci_netif* ni, ci_sock_cmn* s,
                                 int intf_i, int vlan)
{
  ci_hwport_id_t hwport = ni->state->intf_i_to_hwport[intf_i];
  return ((s->rx_bind2dev_hwports & (1ull << hwport)) != 0 &&
          s->rx_bind2dev_vlan == vlan);
}


static int
for_each_match_common(ci_netif* ni,
                      ci_addr_t laddr, unsigned lport,
                      ci_addr_t raddr, unsigned rport,
                      unsigned protocol, int intf_i, int vlan,
                      int (*callback)(ci_sock_cmn*, void*),
                      void* callback_arg, ci_uint32* hash_out)
{
  ci_netif_filter_table* tbl = NULL;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_tbl = NULL;
#endif
  unsigned hash1, hash2 = 0;
  unsigned first, table_size_mask;
  int af;
  void *laddr_ptr, *raddr_ptr;

  tbl = ni->filter_table;

#if CI_CFG_IPV6
  if ( CI_IS_ADDR_IP6(laddr) ) {
    af = AF_INET6;
    ip6_tbl = ni->ip6_filter_table;
    table_size_mask = ip6_tbl->table_size_mask;
    laddr_ptr = laddr.ip6;
    raddr_ptr = raddr.ip6;
  } else
#endif
  {
    af = AF_INET;
    tbl = ni->filter_table;
    table_size_mask = tbl->table_size_mask;
    laddr_ptr = &laddr.ip4;
    raddr_ptr = &raddr.ip4;
  }

  if( hash_out != NULL )
    *hash_out = onload_hash3(af, laddr_ptr, lport, raddr_ptr, rport, protocol);
  hash1 = onload_hash1(af, table_size_mask, laddr_ptr, lport,
                       raddr_ptr, rport, protocol);
  first = hash1;

  LOG_NV(log("%s: %s " IPX_PORT_FMT "->" IPX_PORT_FMT " hash=%u:%u at=%u",
             __FUNCTION__, CI_IP_PROTOCOL_STR(protocol),
	     IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
	     IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
	     first, onload_hash2(af, laddr_ptr, lport, raddr_ptr, rport, protocol),
	     hash1));

  while( 1 ) {
    int id;

#if CI_CFG_IPV6
    if ( af == AF_INET6 ) {
      id = ip6_tbl->table[hash1].id;
    }
    else
#endif
    {
      id = tbl->table[hash1].id;
    }
    if(CI_LIKELY( id >= 0 )) {
      int is_match = 0;

      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
#if CI_CFG_IPV6
      if ( af == AF_INET6 ) {
        if( !memcmp(laddr.ip6, ip6_tbl->table[hash1].laddr, sizeof(ci_ip6_addr_t)) &&
            !memcmp(raddr.ip6, sock_ip6_raddr(s), sizeof(ci_ip6_addr_t)) &&
            lport == sock_lport_be16(s) && rport == sock_rport_be16(s) &&
            protocol == sock_protocol(s)) {
          is_match = 1;

          LOG_NV(ci_log("match %s: %s " IPX_PORT_FMT "->"
                        IPX_PORT_FMT " hash=%u:%u at=%u",
                        __FUNCTION__, CI_IP_PROTOCOL_STR(protocol),
                        IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
                        IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
                        first, onload_hash2(af, laddr_ptr, lport, raddr_ptr,
                        rport, protocol), hash1));
        }
      } else
#endif
      {
        if( ((laddr.ip4 - tbl->table[hash1].laddr) |
            (lport      - sock_lport_be16(s)     ) |
            (raddr.ip4  - sock_raddr_be32(s)     ) |
            (rport      - sock_rport_be16(s)     ) |
            (protocol   - sock_protocol(s)       )) == 0 )
          is_match = 1;
      }
      if(is_match && CI_LIKELY( (s->rx_bind2dev_ifindex == CI_IFID_BAD ||
                     ci_sock_intf_check(ni, s, intf_i, vlan)) ))
        if( callback(s, callback_arg) != 0 )
          return 1;
    }
    else if( id == EMPTY )
      break;
    /* We defer calculating hash2 until it's needed, just to make the fast
    ** case that little bit faster. */
    if( hash1 == first )
      hash2 = onload_hash2(af, laddr_ptr, lport, raddr_ptr, rport, protocol);
    hash1 = (hash1 + hash2) & table_size_mask;
    if( hash1 == first ) {
      LOG_NV(ci_log(FN_FMT "ITERATE FULL " IPX_PORT_FMT "->"
                    IPX_PORT_FMT " hash=%u:%u",
                    FN_PRI_ARGS(ni), IPX_ARG(AF_IP(laddr)), lport,
                    IPX_ARG(AF_IP(raddr)), rport, hash1, hash2));
      break;
    }
  }
  return 0;
}


int
ci_netif_filter_for_each_match(ci_netif* ni,
                               unsigned laddr, unsigned lport,
                               unsigned raddr, unsigned rport,
                               unsigned protocol, int intf_i, int vlan,
                               int (*callback)(ci_sock_cmn*, void*),
                               void* callback_arg, ci_uint32* hash_out)
{
  return for_each_match_common(ni, CI_ADDR_FROM_IP4(laddr), lport,
                               CI_ADDR_FROM_IP4(raddr), rport, protocol, intf_i,
                               vlan, callback, callback_arg, hash_out);
}


int
ci_netif_filter_for_each_match_ip6(ci_netif* ni,
                                   ci_addr_t laddr, unsigned lport,
                                   ci_addr_t raddr, unsigned rport,
                                   unsigned protocol, int intf_i, int vlan,
                                   int (*callback)(ci_sock_cmn*, void*),
                                   void* callback_arg, ci_uint32* hash_out)
{
  return for_each_match_common(ni, laddr, lport, raddr, rport, protocol, intf_i,
                               vlan, callback, callback_arg, hash_out);
}


/* Insert for either TCP or UDP */
static int
ci_ip4_netif_filter_insert(ci_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp tcp_id,
                           unsigned laddr, unsigned lport,
                           unsigned raddr, unsigned rport,
                           unsigned protocol)
{
  ci_netif_filter_table_entry* entry;
  unsigned hash1, hash2;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
  unsigned hops = 1;
#endif
  unsigned first;

  hash1 = onload_hash1(AF_INET, tbl->table_size_mask, &laddr, lport,
                       &raddr, rport, protocol);
  hash2 = onload_hash2(AF_INET, &laddr, lport, &raddr, rport, protocol);
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
    ci_assert(
      !((entry->id == OO_SP_TO_INT(tcp_id)) && (laddr == entry->laddr)) );

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

  entry->id = OO_SP_TO_INT(tcp_id);
  entry->laddr = laddr;
  return 0;
}


static void
__ci_ip4_netif_filter_remove(ci_netif_filter_table* tbl, ci_netif* ni,
                             unsigned hash1, unsigned hash2,
                             int hops, unsigned last_tbl_i)
{
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


static void
ci_ip4_netif_filter_remove(ci_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp sock_p,
                           unsigned laddr, unsigned lport,
                           unsigned raddr, unsigned rport,
                           unsigned protocol)
{
  ci_netif_filter_table_entry* entry;
  unsigned hash1, hash2, tbl_i;
  int hops = 0;
  unsigned first;

  ci_assert(ci_netif_is_locked(netif)
#ifdef __KERNEL__
            /* release_ep_tbl might be called without the stack lock.
             * Do not complain about this. */
            || (netif2tcp_helper_resource(netif)->k_ref_count &
                TCP_HELPER_K_RC_DEAD)
#endif
            );

  hash1 = onload_hash1(AF_INET, tbl->table_size_mask, &laddr, lport,
                       &raddr, rport, protocol);
  hash2 = onload_hash2(AF_INET, &laddr, lport, &raddr, rport, protocol);
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
      /* We allow multiple removes of the same filter -- helps avoid some
       * complexity in the filter module.
       */
      return;
    }
    tbl_i = (tbl_i + hash2) & tbl->table_size_mask;
    ++hops;
    if( tbl_i == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP [%d] %s %s:%u->%s:%u",
                   FN_PRI_ARGS(netif), OO_SP_FMT(sock_p),
                   CI_IP_PROTOCOL_STR(protocol),
                   ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                   ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport)));
      return;
    }
  }

  __ci_ip4_netif_filter_remove(tbl, netif, hash1, hash2, hops, tbl_i);
}

int
ci_netif_filter_insert(ci_netif* netif, oo_sp tcp_id, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport,
                       unsigned protocol)
{
  ci_netif_filter_table* ip4_tbl;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_tbl;
#endif

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    ci_assert(netif->ip6_filter_table);
    ip6_tbl = netif->ip6_filter_table;

    return ci_ip6_netif_filter_insert(ip6_tbl, netif, tcp_id, laddr, lport,
                                      raddr, rport, protocol);
  }
  else
#endif
  {
    ci_assert(netif->filter_table);
    ip4_tbl = netif->filter_table;

    return ci_ip4_netif_filter_insert(ip4_tbl, netif, tcp_id, laddr.ip4, lport,
                                      raddr.ip4, rport, protocol);
  }
}

void
ci_netif_filter_remove(ci_netif* netif, oo_sp sock_p, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport,
                       unsigned protocol)
{
  ci_netif_filter_table* ip4_tbl;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_tbl;
#endif

  ci_assert(netif);

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    ci_assert(netif->ip6_filter_table);
    ip6_tbl = netif->ip6_filter_table;

    return ci_ip6_netif_filter_remove(ip6_tbl, netif, sock_p, laddr, lport,
                                      raddr, rport, protocol);
  }
  else
#endif
  {
    ci_assert(netif->filter_table);
    ip4_tbl = netif->filter_table;

    return ci_ip4_netif_filter_remove(ip4_tbl, netif, sock_p, laddr.ip4, lport,
                                      raddr.ip4, rport, protocol);
  }
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
  ci_assert_gt(size_lg2, 0);
  ci_assert_le(size_lg2, 32);

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
  LOG_NV(log(LPF "FULL LOOKUP %s:%u->%s:%u rc=%d",
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     rc));    

  if(CI_LIKELY( rc >= 0 ))
    return ID_TO_SOCK(netif, netif->filter_table->table[rc].id);

  /* try wildcard lookup */
  raddr = rport = 0;
  rc = ci_netif_filter_lookup(netif, laddr, lport, raddr, rport, protocol);
  LOG_NV(log(LPF "WILD LOOKUP %s:%u->%s:%u rc=%d",
	    ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	    ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
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
      unsigned hash1 = onload_hash1(AF_INET, tbl->table_size_mask, &laddr, lport,
                                    &raddr, rport, protocol);
      unsigned hash2 = onload_hash2(AF_INET, &laddr, lport, &raddr, rport, protocol);
      log("%010d id=%-10d rt_ct=%d %s "CI_IP_PRINTF_FORMAT":%d "
          CI_IP_PRINTF_FORMAT":%d %010d:%010d",
	  i, id, tbl->table[i].route_count, CI_IP_PROTOCOL_STR(protocol),
          CI_IP_PRINTF_ARGS(&laddr), CI_BSWAP_BE16(lport),
	  CI_IP_PRINTF_ARGS(&raddr), CI_BSWAP_BE16(rport), hash1, hash2);
    }
  }
#if CI_CFG_IPV6
  ci_ip6_netif_filter_dump(ni);
#endif
  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
}

/*! \cidoxg_end */
