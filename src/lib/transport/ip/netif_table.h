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

#ifndef __NETIF_TABLE_H__
#define __NETIF_TABLE_H__

#define LPF "tcp_table: "
#define LPFU "udp_table: "


#define TOMBSTONE  -1
#define EMPTY      -2

#if CI_CFG_IPV6
int
ci_ip6_netif_filter_insert(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp tcp_id,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol) CI_HF;

void
ci_ip6_netif_filter_remove(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp sock_p,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol) CI_HF;

void ci_ip6_netif_filter_dump(ci_netif* ni);

#endif

#endif /* __NETIF_TABLE_H__ */
