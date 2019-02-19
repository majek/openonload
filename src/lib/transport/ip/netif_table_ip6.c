/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#include <ci/internal/transport_config_opt.h>
#include <onload/hash.h>
#include "ip_internal.h"
#include "netif_table.h"

#if CI_CFG_IPV6

int
ci_ip6_netif_filter_insert(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp tcp_id,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned hash1, hash2;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
  unsigned hops = 1;
#endif
  unsigned first, table_size_mask;
  char laddr_str[CI_INET6_ADDRSTRLEN], raddr_str[CI_INET6_ADDRSTRLEN];
  int af = AF_INET6;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));

  table_size_mask = tbl->table_size_mask;

  ci_get_ip_str(laddr, laddr_str, sizeof(laddr_str));
  ci_get_ip_str(raddr, raddr_str, sizeof(raddr_str));

  hash1 = onload_hash1(af, table_size_mask, laddr.ip6, lport,
                       raddr.ip6, rport, protocol);
  hash2 = onload_hash2(af, laddr.ip6, lport, raddr.ip6, rport, protocol);
  first = hash1;

  /* Find a free slot. */
  while( 1 ) {
    entry = &tbl->table[hash1];
    if( entry->id < 0 )  break;

    ++entry->route_count;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
    ++hops;
#endif

    hash1 = (hash1 + hash2) & table_size_mask;

    if( hash1 == first ) {
      ci_sock_cmn *s = SP_TO_SOCK_CMN(netif, tcp_id);
      if( ! (s->s_flags & CI_SOCK_FLAG_SW_FILTER_FULL) ) {
        LOG_E(ci_log(FN_FMT "%d FULL %s %s:%u->%s:%u hops=%u",
                     FN_PRI_ARGS(netif),
                     OO_SP_FMT(tcp_id), CI_IP_PROTOCOL_STR(protocol),
                     laddr_str, (unsigned) CI_BSWAP_BE16(lport),
                     raddr_str, (unsigned) CI_BSWAP_BE16(rport),
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
		laddr_str, (unsigned) CI_BSWAP_BE16(lport),
		raddr_str, (unsigned) CI_BSWAP_BE16(rport),
		first, hash2, hash1, entry->id, hops));

  entry->id = OO_SP_TO_INT(tcp_id);
  memcpy(entry->laddr, laddr.ip6, sizeof(entry->laddr));
  return 0;
}

static void
__ci_ip6_netif_filter_remove(ci_ip6_netif_filter_table* tbl,
                             unsigned hash1, unsigned hash2,
                             int hops, unsigned last_tbl_i)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned tbl_i, table_size_mask;
  int i;

  table_size_mask = tbl->table_size_mask;

  tbl_i = hash1;
  for( i = 0; i < hops; ++i ) {
    entry = &tbl->table[tbl_i];
    ci_assert(entry->id != EMPTY);
    ci_assert(entry->route_count > 0);
    if( --entry->route_count == 0 && entry->id == TOMBSTONE ) {
      entry->id = EMPTY;
    }
    tbl_i = (tbl_i + hash2) & table_size_mask;
  }
  ci_assert(tbl_i == last_tbl_i);

  entry = &tbl->table[tbl_i];
  entry->id = ( entry->route_count == 0 ) ? EMPTY : TOMBSTONE;
}

void
ci_ip6_netif_filter_remove(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp sock_p,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned hash1, hash2, tbl_i;
  int hops = 0, af = AF_INET6;
  unsigned first, table_size_mask;
  char laddr_str[CI_INET6_ADDRSTRLEN], raddr_str[CI_INET6_ADDRSTRLEN];

  ci_assert(ci_netif_is_locked(netif)
#ifdef __KERNEL__
            /* release_ep_tbl might be called without the stack lock.
             * Do not complain about this. */
            || (netif2tcp_helper_resource(netif)->k_ref_count &
                TCP_HELPER_K_RC_DEAD)
#endif
            );

  table_size_mask = tbl->table_size_mask;

  hash1 = onload_hash1(af, table_size_mask, laddr.ip6, lport,
                       raddr.ip6, rport, protocol);
  hash2 = onload_hash2(af, laddr.ip6, lport, raddr.ip6, rport, protocol);
  first = hash1;

  ci_get_ip_str(laddr, laddr_str, sizeof(laddr_str));
  ci_get_ip_str(raddr, raddr_str, sizeof(raddr_str));

  LOG_TC(ci_log("%s: [%d:%d] REMOVE %s %s:%u->%s:%u hash=%u:%u",
                __FUNCTION__, NI_ID(netif), OO_SP_FMT(sock_p),
                CI_IP_PROTOCOL_STR(protocol),
		            laddr_str, (unsigned) CI_BSWAP_BE16(lport),
		            raddr_str, (unsigned) CI_BSWAP_BE16(rport),
		            hash1, hash2));

  tbl_i = hash1;
  while( 1 ) {
    entry = &tbl->table[tbl_i];
    if( entry->id == OO_SP_TO_INT(sock_p) ) {
      if( !memcmp(laddr.ip6, entry->laddr, sizeof(entry->laddr)) )
        break;
    }
    else if( entry->id == EMPTY ) {
      /* We allow multiple removes of the same filter -- helps avoid some
       * complexity in the filter module.
       */
      return;
    }
    tbl_i = (tbl_i + hash2) & table_size_mask;
    ++hops;
    if( tbl_i == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP [%d] %s %s:%u->%s:%u",
                   FN_PRI_ARGS(netif), OO_SP_FMT(sock_p),
                   CI_IP_PROTOCOL_STR(protocol),
                   laddr_str, (unsigned) CI_BSWAP_BE16(lport),
                   raddr_str, (unsigned) CI_BSWAP_BE16(rport)));
      return;
    }
  }

  __ci_ip6_netif_filter_remove(tbl, hash1, hash2, hops, tbl_i);
}

#ifdef __ci_driver__

void ci_ip6_netif_filter_init(ci_ip6_netif_filter_table* tbl, int size_lg2)
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
    memset(tbl->table[i].laddr, 0, sizeof(tbl->table[i].laddr));
  }
}

#endif /* __ci_driver__ */

void ci_ip6_netif_filter_dump(ci_netif* ni)
{
  int id;
  unsigned i;
  ci_ip6_netif_filter_table* ip6_tbl;

  ci_assert(ni);
  ip6_tbl = ni->ip6_filter_table;

  for( i = 0; i <= ip6_tbl->table_size_mask; ++i ) {
    id = ip6_tbl->table[i].id;
    if( CI_LIKELY(id >= 0) ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
      ci_ip6_addr_t *laddr_ip6 = &ip6_tbl->table[i].laddr;
      int lport = sock_lport_be16(s);
      ci_ip6_addr_t *raddr_ip6 = &sock_ip6_raddr(s);
      int rport = sock_rport_be16(s);
      int protocol = sock_protocol(s);
      unsigned hash1 = onload_hash1(AF_INET6, ip6_tbl->table_size_mask,
                                    laddr_ip6, lport, raddr_ip6, rport,
                                    protocol);
      unsigned hash2 = onload_hash2(AF_INET6, laddr_ip6, lport,
                                    raddr_ip6, rport, protocol);
      ci_addr_t laddr, raddr;

      memcpy(laddr.ip6, laddr_ip6, sizeof(laddr.ip6));
      memcpy(raddr.ip6, raddr_ip6, sizeof(raddr.ip6));

      log("%010d id=%-10d rt_ct=%d %s %s:%d %s:%d %010u:%010u",
          i, id, ip6_tbl->table[i].route_count, CI_IP_PROTOCOL_STR(protocol),
          AF_IP(laddr), CI_BSWAP_BE16(lport), AF_IP(raddr),
          CI_BSWAP_BE16(rport), hash1, hash2);
    }
  }
}

#endif /* CI_CFG_IPV6 */
