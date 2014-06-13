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

#ifndef __ONLOAD_OOF_INTERFACE_H__
#define __ONLOAD_OOF_INTERFACE_H__


struct tcp_helper_resource_s;
struct oof_socket;
struct oof_manager;
struct oof_port_ref;

#define OO_IFID_ALL (-2)

/**********************************************************************
 * The oof module interface.
 */

extern int oof_shared_keep_thresh;
extern int oof_shared_steal_thresh;


extern struct oof_manager*
oof_manager_alloc(unsigned local_addr_max);

extern void
oof_manager_free(struct oof_manager*);

extern void
oof_manager_addr_add(struct oof_manager*, unsigned laddr, unsigned ifindex);

extern void
oof_manager_addr_del(struct oof_manager*, unsigned laddr, unsigned ifindex);

extern void
oof_socket_ctor(struct oof_socket*);

extern void
oof_socket_dtor(struct oof_socket*);

extern int
oof_socket_add(struct oof_manager*, struct oof_socket*,
               int protocol, unsigned laddr, int lport,
               unsigned raddr, int rport);

extern void
oof_socket_del(struct oof_manager*, struct oof_socket*);

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
oof_mcast_update_filters(struct oof_manager* fm, int ifindex);

extern void
oof_socket_dump(struct oof_manager*, struct oof_socket*,
                void (*dump_fn)(void* opaque, const char* fmt, ...),
                void* opaque);

extern void
oof_manager_dump(struct oof_manager*,
                 void (*dump_fn)(void* opaque, const char* fmt, ...),
                 void* opaque);

extern void oof_update_available_hwports(int hwport, int add);


/**********************************************************************
 * Callbacks.  These are invoked by the oof module.
 */

extern struct tcp_helper_resource_s*
oof_cb_socket_stack(struct oof_socket* skf);

extern int
oof_cb_socket_id(struct oof_socket* skf);

extern int
oof_cb_stack_id(struct tcp_helper_resource_s*);

extern int
oof_cb_sw_filter_insert(struct oof_socket*, unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol);

extern void
oof_cb_sw_filter_remove(struct oof_socket*, unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol);

extern struct oof_socket*
oof_cb_sw_filter_lookup(struct tcp_helper_resource_s*,
                        unsigned laddr, int lport,
                        unsigned raddr, int rport, int protocol);

extern void
oof_cb_port_ref_release(struct oof_port_ref*);


struct oo_hw_filter;

extern void
oof_dl_filter_set(struct oo_hw_filter* filter, int stack_id, int protocol,
                  unsigned saddr, int sport, unsigned daddr, int dport);

extern void
oof_dl_filter_del(struct oo_hw_filter* filter);

extern int 
oof_cb_get_hwport_mask(int ifindex, unsigned *hwport_mask);

extern void
oof_cb_cicp_lock(unsigned long *lock_state);

extern void
oof_cb_cicp_unlock(unsigned long *lock_state);

#endif  /* __ONLOAD_OOF_INTERFACE_H__ */
