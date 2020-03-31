/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
