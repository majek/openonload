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

/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2003/08/18
** Description: CIUL TCP helper interface
** </L5_PRIVATE>
\**************************************************************************/

#ifndef __CI_UL_TCP_HELPER_H__
#define __CI_UL_TCP_HELPER_H__


/*! Comment? */
extern int ci_tcp_helper_more_socks(struct ci_netif_s*) CI_HF;

                               
/*! Comment? */
extern int ci_tcp_helper_more_bufs(struct ci_netif_s* ni) CI_HF;

/* Allocate fd for a stack; attach the stack from [from_fd] to thie new fd;
 * specialise it as a netif-fd. */
extern int ci_tcp_helper_stack_attach(ci_fd_t from_fd,
                                      efrm_nic_set_t *out_ptr_nic_set,
                                      ci_uint32 *out_map_size);

/*! Allocate fd for socket ep_id and create OS socket for UDP socks */
extern int ci_tcp_helper_sock_attach(ci_fd_t stack_fd, oo_sp ep_id,
                                     int domain, int type);
/*! Allocate fd for accepted tcp socket ep_id */
extern int ci_tcp_helper_tcp_accept_sock_attach(ci_fd_t stack_fd, oo_sp ep_id,
                                               int type);
extern int ci_tcp_helper_pipe_attach(ci_fd_t stack_fd, oo_sp ep_id,
                                     int flags, int fds[2]);

#if CI_CFG_FD_CACHING
extern int ci_tcp_helper_clear_epcache(struct ci_netif_s*);
#endif

#if defined(__unix__) && ! defined(__ci_driver__)
extern int ci_tcp_helper_close_no_trampoline(int) CI_HF;
extern void ci_tcp_helper_close_no_trampoline_retaddr(void) CI_HF;

extern ci_fd_t ci_tcp_helper_get_sock_fd(ci_fd_t fd) CI_HF;

extern int ci_tcp_helper_rel_sock_fd (ci_fd_t fd) CI_HF;


struct sockaddr;
extern int ci_tcp_helper_bind_os_sock(ci_fd_t fd, const struct sockaddr* addr,
                                      size_t addrlen,
                                      ci_uint16* out_port) CI_HF;

extern int ci_tcp_helper_listen_os_sock(ci_fd_t fd, int backlog) CI_HF;

extern int ci_tcp_helper_endpoint_shutdown(ci_fd_t fd, int how,
                                           ci_uint32 old_state) CI_HF;

extern int ci_tcp_helper_connect_os_sock(ci_fd_t, const struct sockaddr*,
                                         size_t addrlen) CI_HF;

extern int ci_tcp_helper_os_sock_create_and_set(ci_netif *ni, ci_fd_t fd,
                                                ci_sock_cmn *s, int level,
                                                int optname, const void* optval,
                                                int optlen) CI_HF;
#endif

extern int ciul_can_handle_addr(struct ci_netif_s *netif, ci_uint32 ip_be32,
                                unsigned int proto,
                                ci_uint32 *src_ip_be32_out,
                                unsigned *nic_i_out, unsigned *mtu_out) CI_HF;


/*--------------------------------------------------------------------
 *!
 * Set the corresponding filters for an endpoint. This includes
 *    - hardware IP filters
 *    - filters in the software connection hash table
 *    - filters for NET to CHAR driver comms to support fragments
 *
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param phys_port       L5 physcial port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

extern int
ci_tcp_helper_ep_set_filters(ci_fd_t           fd,
                             oo_sp             ep,
                             ci_ifid_t         bindto_ifindex,
                             oo_sp             from_tcp_id) CI_HF;

extern int
ci_tcp_helper_ep_reuseport_bind(ci_fd_t           fd,
                                const char*       cluster_name,
                                ci_int32          cluster_size,
                                ci_uint32         cluster_restart_opt,
                                ci_uint32         addr_be32,
                                ci_uint16         port_be16) CI_HF;


/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param need_update     Whether the filter details must be updated before
 *                        removal (for sockets accepted from cache, which have
 *                        outdated filter info)
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

extern int
ci_tcp_helper_ep_clear_filters(ci_fd_t fd, oo_sp, int need_update) CI_HF;

/*--------------------------------------------------------------------
 *!
 * Dump filter or clustering state.  For the former, if oo_sp is
 * OO_SP_NULL, then dump all filters.
 *
 * If return is -ve, then error, don't try again.  Otherwise > 0 and
 * gives length of buffer required.  If <= buf_len, then you're good,
 * otherwise try again with a bigger buffer.
 *
 * The functions' signatures must match that of oo_dump_request_fn_t.
 *
 *--------------------------------------------------------------------*/

typedef struct {
  ci_fd_t fd;
  oo_sp   sock_id;
} filter_dump_args;

extern int
ci_tcp_helper_ep_filter_dump(void* opaque, void* buf, int buf_len) CI_HF;

typedef struct {
  ci_fd_t fd;
} cluster_dump_args;

extern int
ci_tcp_helper_cluster_dump(void* opaque, void* buf, int buf_len) CI_HF;

/*--------------------------------------------------------------------
 *!
 * Adds or deletes multicast address to/from socket list.
 * 
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param phys_port       L5 physcial port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param mcast_addr      Multicast address to add to the socket list
 * \param add             Add or delete?
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/
extern int
ci_tcp_helper_ep_mcast_add_del(ci_fd_t           fd,
                               oo_sp             ep,
                               ci_uint32         mcast_addr,
                               ci_ifid_t         ifindex,
                               int               add);

/*--------------------------------------------------------------------
 *!
 * Setup event triggering mechanism
 *--------------------------------------------------------------------*/
extern
int ci_tcp_helper_setup_event_trigger(ci_netif *ni, ci_fd_t fd,
                                        ci_uint32 ep_id, ci_uint32 trigger_idx,
                                        ci_fixed_descriptor_t event_descriptor,
                                        ci_uint32 trigger_mask);

/*--------------------------------------------------------------------
 *!
 * Fire an event trigger
 *--------------------------------------------------------------------*/
extern
int ci_tcp_helper_fire_event_trigger(ci_netif *ni, ci_fd_t fd,
                                       ci_uint32 ep_id, ci_uint32 trigger_idx);

/*--------------------------------------------------------------------
 *!
 * Open an event for a trigger that will be common/shared across
 * processes.
 *--------------------------------------------------------------------*/
extern
int ci_tcp_helper_open_shared_event(ci_netif *ni, ci_fd_t fd,
                                      ci_uint32 ep_id, ci_uint32 event_idx,
                                      ci_fixed_descriptor_t *event_descriptor);

extern int ci_tcp_helper_set_tcp_close_os_sock(ci_netif *ni,
                                               oo_sp sock_id) CI_HF;

/*--------------------------------------------------------------------
 *!
 * Try and expand the active wild pool
 *--------------------------------------------------------------------*/
extern int ci_tcp_helper_alloc_active_wild(ci_netif *ni);

#endif /* __CI_UL_TCP_HELPER_H__ */

