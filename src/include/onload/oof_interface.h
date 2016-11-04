/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#ifndef __ONLOAD_OOF_INTERFACE_H__
#define __ONLOAD_OOF_INTERFACE_H__

#include <cplane/shared_types.h> /* for ci_hwport_id_t */

struct tcp_helper_resource_s;
struct oof_socket;
struct oof_manager;
struct oo_hw_filter;
struct tcp_helper_cluster_s;


#define OO_IFID_ALL (-2)


/**********************************************************************
 * The oof module interface.
 */

extern int oof_shared_keep_thresh;
extern int oof_shared_steal_thresh;
extern int oof_all_ports_required;

extern struct oof_manager*
oof_manager_alloc(unsigned local_addr_max, void* owner_private);

extern void
oof_manager_free(struct oof_manager*);

extern void
oof_manager_addr_add(struct oof_manager*, unsigned laddr, unsigned ifindex);

extern void
oof_manager_addr_del(struct oof_manager*, unsigned laddr, unsigned ifindex);

extern void
oof_hwport_up_down(int hwport, int up, int mcast_replicate_capable,
                   int vlan_filters, int sync);

extern void
oof_hwport_removed(int hwport);

extern void
oof_hwport_un_available(ci_hwport_id_t hwport, int available, int tag,
                        void *arg);

extern void
oof_do_deferred_work(struct oof_manager*);

extern void
oof_socket_ctor(struct oof_socket*);

extern void
oof_socket_dtor(struct oof_socket*);


extern int
oof_socket_is_armed(struct oof_socket* skf);

#define OOF_SOCKET_ADD_FLAG_CLUSTERED 0x1
#define OOF_SOCKET_ADD_FLAG_DUMMY     0x2
#define OOF_SOCKET_ADD_FLAG_NO_STACK  0x4
extern int
oof_socket_add(struct oof_manager*, struct oof_socket*,
               int flags, int protocol, unsigned laddr, int lport,
               unsigned raddr, int rport,
               struct tcp_helper_cluster_s** thc_out);

extern int
oof_socket_replace(struct oof_manager* fm,
                   struct oof_socket* old_skf, struct oof_socket* skf);

extern int
oof_socket_can_update_stack(struct oof_manager* fm, struct oof_socket* skf,
                            struct tcp_helper_resource_s* thr);

extern void
oof_socket_update_sharer_details(struct oof_manager*, struct oof_socket*,
                                 unsigned raddr, int rport);

extern int
oof_socket_share(struct oof_manager*, struct oof_socket* skf,
                 struct oof_socket* listen_skf, unsigned laddr,
                 unsigned raddr, int rport);

extern void
oof_socket_del(struct oof_manager*, struct oof_socket*);

extern int
oof_socket_del_sw(struct oof_manager*, struct oof_socket*);

extern int
oof_udp_connect(struct oof_manager*, struct oof_socket*,
                unsigned laddr, unsigned raddr, int rport);

extern int
oof_socket_mcast_add(struct oof_manager*, struct oof_socket*,
                     unsigned maddr, int ifindex);

extern void
oof_socket_mcast_del(struct oof_manager*, struct oof_socket*,
                     unsigned maddr, int ifindex);

extern void
oof_socket_mcast_del_all(struct oof_manager*, struct oof_socket*);

extern void
oof_mcast_update_filters(ci_ifid_t ifindex, void *arg);

extern int
oof_tproxy_install(struct oof_manager* fm,
                   struct tcp_helper_resource_s* trs,
                   struct tcp_helper_cluster_s* thc,
                   int ifindex);

extern int
oof_tproxy_free(struct oof_manager* fm,
                struct tcp_helper_resource_s* trs,
                struct tcp_helper_cluster_s* thc,
                int ifindex);

extern int
oof_tproxy_update_filters(struct oof_manager* fm, int ifindex);

extern void
oof_socket_dump(struct oof_manager*, struct oof_socket*,
                void (*dump_fn)(void* opaque, const char* fmt, ...),
                void* opaque);

extern void
oof_manager_dump(struct oof_manager*,
                 void (*dump_fn)(void* opaque, const char* fmt, ...),
                 void* opaque);

/**********************************************************************
 * Callbacks.  These are invoked by the oof module.
 */

extern struct tcp_helper_resource_s*
oof_cb_socket_stack(struct oof_socket* skf);

extern struct tcp_helper_cluster_s*
oof_cb_stack_thc(struct tcp_helper_resource_s* skf_stack);

extern const char*
oof_cb_thc_name(struct tcp_helper_cluster_s* thc);

extern int
oof_cb_socket_id(struct oof_socket* skf);

extern int
oof_cb_stack_id(struct tcp_helper_resource_s*);

extern void
oof_cb_callback_set_filter(struct oof_socket* skf);

extern int
oof_cb_sw_filter_insert(struct oof_socket*, unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol,
                        int stack_locked);

extern void
oof_cb_sw_filter_remove(struct oof_socket*, unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol,
                        int stack_locked);

struct ci_netif_s;
extern void oof_cb_sw_filter_apply(struct ci_netif_s* ni);

extern struct oof_socket*
oof_cb_sw_filter_lookup(struct tcp_helper_resource_s*,
                        unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol);

extern void
oof_dl_filter_set(struct oo_hw_filter* filter, int stack_id, int protocol,
                  unsigned saddr, int sport, unsigned daddr, int dport);

extern void
oof_dl_filter_del(struct oo_hw_filter* filter);

extern int 
oof_cb_get_hwport_mask(int ifindex, unsigned *hwport_mask);

extern int 
oof_cb_get_vlan_id(int ifindex, unsigned short *vlan_id);

extern int
oof_cb_get_mac(int ifindex, unsigned char mac[6]);

extern void
oof_cb_defer_work(void* owner_private);

extern int
oof_hwports_list(struct oof_manager* fm, struct seq_file* seq);
extern int
oof_ipaddrs_list(struct oof_manager* fm, struct seq_file* seq);

#endif  /* __ONLOAD_OOF_INTERFACE_H__ */
