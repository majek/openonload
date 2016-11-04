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

#ifndef __ONLOAD_IOCTL_H__
#define __ONLOAD_IOCTL_H__

#include <ci/internal/transport_config_opt.h>
#include <linux/version.h>


#define ONLOADFS_MAGIC 0xefab010d

/* Worth changing this base whenever you change an ioctl in an incompatible
** way, so we can catch the error more easily...
*/
# define OO_LINUX_IOC_BASE  90
# if OO_LINUX_IOC_BASE > 254
# error "OO_LINUX_IOC_BASE should be one byte"
# endif

# define OO_IOC_NONE(XXX)   _IO(OO_LINUX_IOC_BASE, OO_OP_##XXX)
# define OO_IOC_R(XXX, t)   _IOR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_W(XXX, t)   _IOW(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_RW(XXX, t)  _IOWR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)



/*************************************************************************
 * ATTENTION! ACHTUNG! ATENCION!                                         *
 * This enum MUST be synchronised with the oo_operations table!          *
 *************************************************************************/

/* OS-independent operations enum */
enum {
  /* Debug ops */
  OO_OP_DBG_GET_STACK_INFO,
#define OO_IOC_DBG_GET_STACK_INFO   OO_IOC_RW(DBG_GET_STACK_INFO, \
                                              ci_netif_info_t)
  OO_OP_DBG_WAIT_STACKLIST_UPDATE,
#define OO_IOC_DBG_WAIT_STACKLIST_UPDATE \
                                OO_IOC_RW(DBG_WAIT_STACKLIST_UPDATE, \
                                          struct oo_stacklist_update)
  OO_OP_DEBUG_OP,
#define OO_IOC_DEBUG_OP         OO_IOC_RW(DEBUG_OP, ci_debug_onload_op_t)

  /* cfg; ci_cfg_ioctl_desc_t in/out */
  OO_OP_CFG_SET,         /*< Set the config database */
#define OO_IOC_CFG_SET          OO_IOC_RW(CFG_SET, ci_cfg_ioctl_desc_t)
  OO_OP_CFG_UNSET,       /*< Delete config database */
#define OO_IOC_CFG_UNSET        OO_IOC_RW(CFG_UNSET, ci_cfg_ioctl_desc_t)
  OO_OP_CFG_GET,         /*< Get the config database */
#define OO_IOC_CFG_GET          OO_IOC_RW(CFG_GET, ci_cfg_ioctl_desc_t)
  OO_OP_CFG_QUERY,       /*< Get the config database */
#define OO_IOC_CFG_QUERY        OO_IOC_RW(CFG_QUERY, ci_cfg_ioctl_desc_t)

  /* IPv4 Id number handling */
  OO_OP_IPID_RANGE_ALLOC,      /*< Alloc range of IPIDs; ci_int32 out */
#define OO_IOC_IPID_RANGE_ALLOC OO_IOC_R(IPID_RANGE_ALLOC, ci_int32)
  OO_OP_IPID_RANGE_FREE,       /*< Free range of IPIDs; ci_int32 in */
#define OO_IOC_IPID_RANGE_FREE  OO_IOC_W(IPID_RANGE_FREE, ci_int32)

  /* Logging */
  OO_OP_PRINTK,
#define OO_IOC_PRINTK           OO_IOC_W(PRINTK, char[CI_LOG_MAX_LINE])

  /* netif & EP handling */
  OO_OP_RESOURCE_ONLOAD_ALLOC, /*< allocate resources for netif;
                                ci_resource_onload_alloc_t in/out */
#define OO_IOC_RESOURCE_ONLOAD_ALLOC    OO_IOC_RW(RESOURCE_ONLOAD_ALLOC, \
                                                  ci_resource_onload_alloc_t)
  OO_OP_EP_INFO,   /*< Get endpoint information: TCP Helper handle and endpoint
                    identifier; ci_ep_info_t out */
#define OO_IOC_EP_INFO          OO_IOC_R(EP_INFO, ci_ep_info_t)
  OO_OP_CLONE_FD,              /*< Clone onload device fd; int out */
#define OO_IOC_CLONE_FD         OO_IOC_RW(CLONE_FD, ci_clone_fd_t)
  OO_OP_KILL_SELF_SIGPIPE,      /*< Send a signal to self */
#define OO_IOC_KILL_SELF_SIGPIPE    OO_IOC_NONE(KILL_SELF_SIGPIPE)

  OO_OP_IOCTL_TRAMP_REG,       /*< Register tramp handler;
                              ci_tramp_reg_args_t in */
#define OO_IOC_IOCTL_TRAMP_REG  OO_IOC_W(IOCTL_TRAMP_REG, ci_tramp_reg_args_t)

  OO_OP_DIE_SIGNAL,           /*< Die because unhandled signal is received */
#define OO_IOC_DIE_SIGNAL       OO_IOC_W(DIE_SIGNAL, ci_int32)

  /* TCP helper operations */
  OO_OP_TCP_SOCK_SLEEP,
#define OO_IOC_TCP_SOCK_SLEEP   OO_IOC_RW(TCP_SOCK_SLEEP, oo_tcp_sock_sleep_t)
  OO_OP_WAITABLE_WAKE,
#define OO_IOC_WAITABLE_WAKE    OO_IOC_W(WAITABLE_WAKE, oo_waitable_wake_t)

  /* Filter operations */
  OO_OP_EP_FILTER_SET,
#define OO_IOC_EP_FILTER_SET    OO_IOC_W(EP_FILTER_SET, oo_tcp_filter_set_t)
  OO_OP_EP_FILTER_CLEAR,
#define OO_IOC_EP_FILTER_CLEAR  OO_IOC_W(EP_FILTER_CLEAR, oo_tcp_filter_clear_t)
  OO_OP_EP_FILTER_MCAST_ADD,
#define OO_IOC_EP_FILTER_MCAST_ADD  OO_IOC_W(EP_FILTER_MCAST_ADD, \
                                             oo_tcp_filter_mcast_t)
  OO_OP_EP_FILTER_MCAST_DEL,
#define OO_IOC_EP_FILTER_MCAST_DEL  OO_IOC_W(EP_FILTER_MCAST_DEL, \
                                             oo_tcp_filter_mcast_t)
  OO_OP_EP_FILTER_DUMP,
#define OO_IOC_EP_FILTER_DUMP       OO_IOC_W(EP_FILTER_DUMP,            \
                                             oo_tcp_filter_dump_t)

  OO_OP_TCP_SOCK_LOCK,
#define OO_IOC_TCP_SOCK_LOCK        OO_IOC_W(TCP_SOCK_LOCK, ci_int32)
  OO_OP_TCP_SOCK_UNLOCK,
#define OO_IOC_TCP_SOCK_UNLOCK      OO_IOC_W(TCP_SOCK_UNLOCK, ci_int32)
  OO_OP_TCP_PKT_WAIT,
#define OO_IOC_TCP_PKT_WAIT         OO_IOC_W(TCP_PKT_WAIT, ci_int32)
  OO_OP_TCP_MORE_BUFS,
#define OO_IOC_TCP_MORE_BUFS        OO_IOC_NONE(TCP_MORE_BUFS)
  OO_OP_TCP_MORE_SOCKS,
#define OO_IOC_TCP_MORE_SOCKS       OO_IOC_NONE(TCP_MORE_SOCKS)

#if CI_CFG_FD_CACHING
  OO_OP_TCP_CLEAR_EPCACHE,
#define OO_IOC_TCP_CLEAR_EPCACHE  OO_IOC_NONE(TCP_CLEAR_EPCACHE)
#endif

  OO_OP_STACK_ATTACH,
#define OO_IOC_STACK_ATTACH         OO_IOC_RW(STACK_ATTACH, \
                                              oo_stack_attach_t)
  OO_OP_INSTALL_STACK_BY_ID,
#define OO_IOC_INSTALL_STACK_BY_ID  OO_IOC_W(INSTALL_STACK_BY_ID, ci_uint32)

  OO_OP_SOCK_ATTACH,
#define OO_IOC_SOCK_ATTACH          OO_IOC_RW(SOCK_ATTACH, \
                                              oo_sock_attach_t)

  OO_OP_TCP_ACCEPT_SOCK_ATTACH,
#define OO_IOC_TCP_ACCEPT_SOCK_ATTACH   OO_IOC_RW(TCP_ACCEPT_SOCK_ATTACH, \
                                              oo_tcp_accept_sock_attach_t)

#if CI_CFG_USERSPACE_PIPE
  OO_OP_PIPE_ATTACH,
#define OO_IOC_PIPE_ATTACH          OO_IOC_RW(PIPE_ATTACH, \
                                              oo_pipe_attach_t)
#endif

  /* OS-specific TCP helper operations */

  OO_OP_OS_SOCK_CREATE_AND_SET,
#define OO_IOC_OS_SOCK_CREATE_AND_SET OO_IOC_W(OS_SOCK_CREATE_AND_SET,  \
                                              oo_tcp_create_set_t)
  OO_OP_OS_SOCK_FD_GET,
#define OO_IOC_OS_SOCK_FD_GET       OO_IOC_RW(OS_SOCK_FD_GET,           \
                                              oo_os_sock_fd_get_t)
  OO_OP_OS_SOCK_SENDMSG,
#define OO_IOC_OS_SOCK_SENDMSG      OO_IOC_W(OS_SOCK_SENDMSG,           \
                                             oo_os_sock_sendmsg_t)
  OO_OP_OS_SOCK_SENDMSG_RAW,
#define OO_IOC_OS_SOCK_SENDMSG_RAW  OO_IOC_W(OS_SOCK_SENDMSG_RAW,       \
                                             oo_os_sock_sendmsg_raw_t)
  OO_OP_OS_SOCK_RECVMSG,
#define OO_IOC_OS_SOCK_RECVMSG      OO_IOC_RW(OS_SOCK_RECVMSG,          \
                                              oo_os_sock_recvmsg_t)
  OO_OP_OS_SOCK_ACCEPT,
#define OO_IOC_OS_SOCK_ACCEPT       OO_IOC_RW(OS_SOCK_ACCEPT,           \
                                              oo_os_sock_accept_t)
  OO_OP_TCP_ENDPOINT_SHUTDOWN,
#define OO_IOC_TCP_ENDPOINT_SHUTDOWN    OO_IOC_W(TCP_ENDPOINT_SHUTDOWN, \
                                                 oo_tcp_endpoint_shutdown_t)
  OO_OP_TCP_BIND_OS_SOCK,
#define OO_IOC_TCP_BIND_OS_SOCK     OO_IOC_RW(TCP_BIND_OS_SOCK, \
                                              oo_tcp_bind_os_sock_t)
  OO_OP_TCP_LISTEN_OS_SOCK,
#define OO_IOC_TCP_LISTEN_OS_SOCK   OO_IOC_W(TCP_LISTEN_OS_SOCK, ci_int32)
  OO_OP_TCP_CONNECT_OS_SOCK,
#define OO_IOC_TCP_CONNECT_OS_SOCK  OO_IOC_W(TCP_CONNECT_OS_SOCK, \
                                             oo_tcp_sockaddr_with_len_t)
  OO_OP_TCP_HANDOVER,
#define OO_IOC_TCP_HANDOVER         OO_IOC_RW(TCP_HANDOVER, ci_int32)

  OO_OP_FILE_MOVED,
#define OO_IOC_FILE_MOVED           OO_IOC_RW(FILE_MOVED, ci_int32)

  OO_OP_TCP_CLOSE_OS_SOCK,
#define OO_IOC_TCP_CLOSE_OS_SOCK    OO_IOC_W(TCP_CLOSE_OS_SOCK, oo_sp)

  OO_OP_OS_POLLERR_CLEAR,
#define OO_IOC_OS_POLLERR_CLEAR     OO_IOC_W(OS_POLLERR_CLEAR, oo_sp)



  /* Cplane operations */
  OO_OP_CP_USER_DEFER_SEND,
#define OO_IOC_CP_USER_DEFER_SEND   OO_IOC_RW(CP_USER_DEFER_SEND, \
                                              cp_user_defer_send_t)

  OO_OP_EPLOCK_WAKE,
#define OO_IOC_EPLOCK_WAKE          OO_IOC_NONE(EPLOCK_WAKE)
  OO_OP_EPLOCK_LOCK_WAIT,
#define OO_IOC_EPLOCK_LOCK_WAIT     OO_IOC_NONE(EPLOCK_LOCK_WAIT)
  
  OO_OP_INSTALL_STACK,
#define OO_IOC_INSTALL_STACK        OO_IOC_W(INSTALL_STACK,             \
                                             struct oo_op_install_stack)
  OO_OP_PACE,
#define OO_IOC_PACE                 OO_IOC_W(PACE, struct oo_op_pace)

  OO_OP_RSOP_DUMP,
#define OO_IOC_RSOP_DUMP            OO_IOC_NONE(RSOP_DUMP)

  OO_OP_GET_ONLOADFS_DEV,
#define OO_IOC_GET_ONLOADFS_DEV     OO_IOC_R(GET_ONLOADFS_DEV, ci_uint32)

  OO_OP_TCP_LOOPBACK_CONNECT,
#define OO_IOC_TCP_LOOPBACK_CONNECT OO_IOC_RW(TCP_LOOPBACK_CONNECT, \
                                              struct oo_op_loopback_connect)
  OO_OP_TCP_DROP_FROM_ACCEPTQ,
#define OO_IOC_TCP_DROP_FROM_ACCEPTQ OO_IOC_W(TCP_DROP_FROM_ACCEPTQ, \
                                          struct oo_op_tcp_drop_from_acceptq)

  OO_OP_MOVE_FD,
#define OO_IOC_MOVE_FD              OO_IOC_W(MOVE_FD, \
                                             ci_fixed_descriptor_t)

  OO_OP_EP_REUSEPORT_BIND,
#define OO_IOC_EP_REUSEPORT_BIND                        \
  OO_IOC_W(EP_REUSEPORT_BIND, oo_tcp_reuseport_bind_t)
  OO_OP_CLUSTER_DUMP,
#define OO_IOC_CLUSTER_DUMP       OO_IOC_W(CLUSTER_DUMP,            \
                                             oo_cluster_dump_t)

#define OO_IOC_OFE_CONFIG         OO_IOC_W(OFE_CONFIG, oo_ofe_config_t)
  OO_OP_OFE_CONFIG,
#define OO_IOC_OFE_CONFIG_DONE    OO_IOC_NONE(OFE_CONFIG_DONE)
  OO_OP_OFE_CONFIG_DONE,
#define OO_IOC_OFE_GET_LAST_ERROR OO_IOC_R(OFE_GET_LAST_ERROR, \
                                           char[CI_LOG_MAX_LINE])
  OO_OP_OFE_GET_LAST_ERROR,

  OO_OP_GET_CPU_KHZ,
#define OO_IOC_GET_CPU_KHZ        OO_IOC_R(GET_CPU_KHZ, ci_uint32)

  OO_OP_GET_CPLANE_FD,
#define OO_IOC_GET_CPLANE_FD      OO_IOC_R(GET_CPLANE_FD, \
                                           ci_fixed_descriptor_t)

  OO_OP_DSHM_REGISTER,
#define OO_IOC_DSHM_REGISTER      OO_IOC_RW(DSHM_REGISTER, oo_dshm_register_t)

  OO_OP_DSHM_LIST,
#define OO_IOC_DSHM_LIST          OO_IOC_RW(DSHM_LIST, oo_dshm_list_t)

  OO_OP_ALLOC_ACTIVE_WILD,
#define OO_IOC_ALLOC_ACTIVE_WILD  OO_IOC_NONE(ALLOC_ACTIVE_WILD)

  OO_OP_END  /* This had better be last! */
};


#endif  /* __ONLOAD_IOCTL_H__ */
