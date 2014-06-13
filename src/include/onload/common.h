/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Interface for invoking misc ops on resources.
**   \date  2003/01/17
**    \cop  (c) 2003-2005 Level 5 Networks Limited.
**              2006 Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_onload  */

#ifndef __ONLOAD_COMMON_H__
#define __ONLOAD_COMMON_H__

#if 1 && defined(__CI_DRIVER_EFAB_OPERATIONS_H__)
#error "You should select one driver to talk with -- char or onload"
#endif

#include <ci/tools/sysdep.h> /* for memset */
#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/efrm/nic_set.h>
#include <ci/net/ethernet.h>
#include <ci/internal/cplane_types.h>
#include <onload/signals.h> /* for OO_SIGHANGLER_DFL_MAX */



/**********************************************************************
********************** Identifying address space **********************
**********************************************************************/

#define ci_addr_spc_id_set(p, v)                        \
  ((*(p)) = (ci_addr_spc_id_t)(ci_uintptr_t) (v))


/*----------------------------------------------------------------------------
 *
 *  OS device name used e.g registered unix char special device /dev/onload
 *
 *---------------------------------------------------------------------------*/


# define EFAB_DEV_NAME  "onload"  
# define EFAB_DEV       "/dev/" EFAB_DEV_NAME

# define OO_EPOLL_DEV_NAME "onload_epoll"
# define OO_EPOLL_DEV      "/dev/" OO_EPOLL_DEV_NAME



/* Max length of version string used for version skew checking. */
enum { OO_VER_STR_LEN = 40 };

/* We use an md5sum over certain headers to ensure that userland and kernel
 * drivers are built against a compatible interface.
 */
enum { CI_CHSUM_STR_LEN = 32 };



/*! This data structure contains the arguments required to create a new
 *  tcp helper resource and the results that the allocation operation
 *  subsequently returns.
 */
typedef struct ci_resource_onload_alloc_s {
  ci_user_ptr_t           in_opts  CI_ALIGN(8);
  ci_uint16               in_flags;
  char                    in_version[OO_VER_STR_LEN + 1];
  char                    in_uk_intf_ver[CI_CHSUM_STR_LEN + 1];
  char                    in_name[CI_CFG_STACK_NAME_LEN + 1];
  efrm_nic_set_t          out_nic_set;
  ci_uint32               out_netif_mmap_bytes;
} ci_resource_onload_alloc_t;


/*--------------------------------------------------------------------
 *
 * ci_user_context_t - u/l context saved with fd
 *
 *       int ci_save_user_context(ci_fd_t, ci_user_context_t*)
 *       int ci_get_user_context(ci_fd_t, ci_user_context_t*)
 *
 * Save a context of length 0 to delete a saved context.  Currently only
 * one context may be saved with any fd.
 *
 *--------------------------------------------------------------------*/

#define CI_MAX_SAVE_CONTEXT_LEN  1024

/*--------------------------------------------------------------------
 *
 * resource operations (ioctl for resources)
 *
 *--------------------------------------------------------------------*/

typedef struct {
  oo_sp         sock_id;
  ci_bits       why;  /* 32 bits */
  ci_uint64     sleep_seq;
  ci_int32      lock_flags;
  ci_uint32     timeout_ms; /* IN/OUT */
  ci_user_ptr_t sig_state;
} oo_tcp_sock_sleep_t;

typedef struct {
  oo_sp         sock_id;
} oo_waitable_wake_t;

typedef struct {
  oo_sp             tcp_id;
  oo_sp             from_tcp_id;
  ci_ifid_t         bindto_ifindex;
} oo_tcp_filter_set_t;

typedef struct {
  char      cluster_name[(CI_CFG_STACK_NAME_LEN >> 1) + 1];
  ci_int32  cluster_size;
  ci_uint32 cluster_restart_opt;
  ci_uint32 addr_be32;
  ci_uint16 port_be16;
} oo_tcp_reuseport_bind_t;

typedef struct {
  oo_sp             tcp_id;
} oo_tcp_filter_clear_t;

typedef struct {
  oo_sp             tcp_id;
  ci_int32          addr;
  ci_ifid_t         ifindex;
} oo_tcp_filter_mcast_t;

typedef struct {
  ci_user_ptr_t buf;
  ci_int32      buf_len;
} oo_cluster_dump_t;

typedef struct {
  oo_sp         sock_id;
  ci_user_ptr_t buf;
  ci_int32      buf_len;
} oo_tcp_filter_dump_t;

typedef struct {
  oo_sp         	ep_id;
  ci_uint32		new_trs_id;
  oo_sp         	new_ep_id;
} oo_tcp_move_state_t;

typedef struct {
  oo_sp         sock_id;
  ci_user_ptr_t address; /* const struct sockaddr */
  ci_uint32     addrlen; /* IN: addrlen OUT: port */
} oo_tcp_bind_os_sock_t;

typedef struct {
  ci_user_ptr_t address; /* const struct sockaddr */
  ci_uint32     addrlen;
} oo_tcp_sockaddr_with_len_t;

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  efrm_nic_set_t        out_nic_set;
  ci_uint32             out_map_size;
} oo_stack_attach_t;

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  oo_sp                 ep_id;
  ci_int32              domain;
  ci_int32              type;
  ci_int32              padding;
} oo_sock_attach_t;

#if CI_CFG_USERSPACE_PIPE
typedef struct {
  ci_fixed_descriptor_t rfd, wfd;   /* OUT for Unix */
  oo_sp                 ep_id;
  ci_int32              flags;
} oo_pipe_attach_t;

typedef struct {
  ci_int32      bufs_num;
  ci_int32      bufs_start;
} oo_tcp_sock_more_pipe_bufs_t;
#endif

typedef struct {
  ci_int32          other_fd;
  ci_int32          other_pid;
  oo_sp             ep_id;
} oo_tcp_xfer_t;

typedef struct {
  ci_int32  sock_id;
  ci_int32  fd_out;
} oo_os_sock_fd_get_t;

typedef struct {
  ci_int32      sock_id;
  ci_int32      flags;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg_iov;
  ci_user_ptr_t msg_name;
  ci_user_ptr_t msg_control;
  ci_uint32     msg_iovlen;
  ci_uint32     msg_namelen;
  ci_uint32     msg_controllen;
} oo_os_sock_sendmsg_t;

typedef struct {
  ci_int32      sock_id;
  ci_int32      flags;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg;
  ci_user_ptr_t socketcall_args;
} oo_os_sock_sendmsg_raw_t;

typedef struct {
  ci_int32      sock_id;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg_iov;
  ci_user_ptr_t msg_name;
  ci_user_ptr_t msg_control;
  ci_uint32     msg_iovlen;
  ci_uint32     msg_namelen;
  ci_uint32     msg_controllen;
  ci_int32      flags;
  ci_int32      rc;
} oo_os_sock_recvmsg_t;

typedef struct {
  ci_int32      sock_id;
  ci_user_ptr_t addr;
  ci_user_ptr_t addrlen;
  ci_int32      flags;
  ci_int32      rc;
} oo_os_sock_accept_t;

typedef struct {
  ci_uint32 how;
  ci_uint32 old_state;
} oo_tcp_endpoint_shutdown_t;



/* Cplane ioctl structures */
typedef struct {
  ci_ip_addr_t      ip_be32;
  ci_ip_addr_kind_t addr_kind;
} cp_ipif_addr_kind_t;

typedef struct { /* do not reorder fields if you're not sure about alignment */
  ci_ifid_t      ifindex_out;
  ci_uint16      vlan_id;
  ci_hwport_id_t hwport;
} cp_llap_find_t;

typedef struct {
  ci_ifid_t      ifindex; /* IN */
  ci_mtu_t       mtu;
  ci_hwport_id_t hwport;
  ci_mac_addr_t  mac;
  cicp_encap_t   encap;
  ci_ifid_t      base_ifindex;
  ci_int16       bond_rowid;
} cp_llap_retrieve_t;

typedef struct {
  cicp_mac_verinfo_t ver;
  ci_ip_addr_t ip;
  ci_mac_addr_t mac;
  ci_int32 /*bool*/  confirm;
} cp_mac_update_t;

typedef struct {
  oo_pkt_p	pkt;
  ci_uint32	retrieve_rc;
  ci_uerr_t	os_rc;
  ci_uerr_t	rc;
  ci_ifid_t     ifindex;
} cp_user_defer_send_t;

typedef struct {
  ci_uint32	pkt;
  ci_ifid_t	ifindex;
} cp_user_pkt_dest_ifid_t;

typedef struct {
  ci_ip_addr_t   ip_be32; /* IN */
  ci_ifid_t      ifindex;
  ci_hwport_id_t hwport;
  ci_mac_addr_t  mac;
  ci_mtu_t       mtu;
  cicp_encap_t   encap;
} cp_src_addr_checks_t;

#if CI_CFG_CONTROL_PLANE_USER_SYNC
/* the control plane synchronization operations are made available
   to the user in Windows but only optionally in Linux */
typedef struct {
  ci_user_ptr_t         os_sync_ptr;
  ci_ip_addr_t          ip_be32;
  cicp_mib_verinfo_t    rowinfo;
  ci_ifid_t             ifindex;
  ci_mac_addr_t         mac;
} cp_mac_set_t;

typedef struct {
  ci_mtu_t      max_mtu;
  ci_hwport_id_t hwport;
} cp_hwport_update_t;

typedef struct {
  ci_ifid_t         ifindex;
  ci_mtu_t          max_mtu;
  ci_uint8          up;
  char              name[CICP_LLAP_NAME_MAX];
  ci_mac_addr_t     mac;
  cicp_llap_rowid_t rowid_out CI_ALIGN(8);
} cp_llap_import_t;

typedef struct {
  ci_verlock_value_t    table_version;
  cicp_encap_t          encap;
  ci_ifid_t             ifindex;
  ci_uint8              up;
  cicp_llap_rowid_t     rowinfo_index; /* IN */
} cp_llap_readrow_t;

typedef struct {
  cicp_ipif_rowid_t rowid; /* OUT */
  ci_ip_addr_net_t  net_ip;
  ci_ip_addrset_t   net_ipset;
  ci_ip_addr_net_t  net_bcast;
  ci_ifid_t         ifindex;
  ci_uint8          scope;
} cp_ipif_import_t;

typedef struct {
    ci_ip_addr_net_t    net_ip;
    ci_ip_addrset_t     net_ipset;
    ci_ifid_t           ifindex;
} cp_ipif_delete_t;

typedef struct {
  ci_verlock_value_t    table_version;
  ci_ip_addr_t          net_ip;
  ci_ip_addrset_t       net_ipset;
  ci_ip_addr_t          net_bcast;
  ci_ifid_t             ifindex;
  cicp_ipif_rowid_t     rowinfo_index; /* IN */
} cp_ipif_readrow_t;

typedef struct {
  ci_ip_addr_t    dest_ip;
  ci_ip_addrset_t dest_ipset;
  ci_ip_addr_t    next_hop_ip;
  ci_ip_addr_t    pref_source;
  cicp_ip_tos_t   tos;
  cicp_metric_t   metric;
  ci_ifid_t       ifindex;
  ci_mtu_t        mtu;
  cicp_route_rowid_t  rowid; /* OUT */
} cp_route_import_t;

typedef struct {
  ci_ip_addr_t      dest_ip;
  ci_ip_addrset_t   dest_ipset;
} cp_route_delete_t;
#endif

typedef struct {
  oo_pkt_p     pktid;
  ci_ifid_t    ifindex;
  ci_ip_addr_t out_spec_addr;
} cp_ipif_pktinfo_query_t;

typedef struct {
  ci_ifid_t    ifindex;
  ci_ip_addr_t out_addr;
} cp_ipif_by_ifindex_t;


/* This is shared structure. It should not use "int", "long", etc because
 * kernel and userland may have different size for such types. */
typedef struct {
  ci_int16               fd_type;
# define CI_PRIV_TYPE_NONE      0
# define CI_PRIV_TYPE_TCP_EP    1
# define CI_PRIV_TYPE_UDP_EP    2
# define CI_PRIV_TYPE_NETIF     3
# define CI_PRIV_TYPE_PASSTHROUGH_EP 4
#if CI_CFG_USERSPACE_PIPE
# define CI_PRIV_TYPE_PIPE_READER 5
# define CI_PRIV_TYPE_PIPE_WRITER 6
#endif
#if CI_CFG_USERSPACE_PIPE
# define CI_PRIV_TYPE_IS_ENDPOINT(t)                                \
    ((t) == CI_PRIV_TYPE_TCP_EP || (t) == CI_PRIV_TYPE_UDP_EP ||    \
     (t) == CI_PRIV_TYPE_PASSTHROUGH_EP ||                          \
     (t) == CI_PRIV_TYPE_PIPE_READER || (t) == CI_PRIV_TYPE_PIPE_WRITER)
#else
# define CI_PRIV_TYPE_IS_ENDPOINT(t)                                \
    ((t) == CI_PRIV_TYPE_TCP_EP || (t) == CI_PRIV_TYPE_UDP_EP ||    \
     (t) == I_PRIV_TYPE_PASSTHROUGH_EP)
#endif

  ci_uint32              resource_id;
  ci_uint32              mem_mmap_bytes;
  oo_sp                  sock_id;
} ci_ep_info_t;

typedef struct {
  ci_uint64             flags; /* it's u8 really, but we need to be compat */
  ci_fixed_descriptor_t fd;
} ci_clone_fd_t;


typedef ci_uint32 ci_cfg_ioctl_desc_err_t;

/*! Data structure used by the CI_IOCTL_(GET|SET|QUERY) ioctls. */
typedef struct ci_cfg_ioctl_desc_s {
  /*! During set  : Ptr to database blob
   *  During get  : Ptr to a buffer where the database blob can be written
   *  During query: Ptr to a memory location of type ci_ioctl_cfg_query_t.
   *                On the way down, this data struct holds the uid and process
   *                name to be used for the query, if any of the uid or
   *                proc_name pointers aren't set then they are automatically
   *                retrieved from the current context.
   *                On the way up it holds the data for the data structures
   *                citp_opts_t and ci_netif_config_opts.
   */
  ci_user_ptr_t ptr CI_ALIGN(8);
  
  /*! length of the database blob (during set operation) or size of the buffer
   *  where the database blob is to be written (during get operation)
   *  TODO: explain query????
   */
  ci_uint32 len CI_ALIGN(4);

  /*! return code, 0 is good */
  ci_cfg_ioctl_desc_err_t err CI_ALIGN(4);
#define CICFG_DESC_ENOTINST   1 /* database not installed */
#define CICFG_DESC_ETOOSMALL  2 /* descriptor too small */
#define CICFG_DESC_EPROCEXCL  3 /* process is excluded */
#define CICFG_DESC_EBADUID    4 /* bad uid or uid descriptor */
#define CICFG_DESC_EBADPNAME  5 /* bad process id or process id descriptor */
#define CICFG_DESC_EFAULT     6 /* bad pointer in pdesc */
#define CICFG_DESC_EBADCMD    7 /* bad ioctl cmd value */
#define CICFG_DESC_EPERM      8 /* not authorised to install database */
#define CICFG_DESC_ENOMEM     9 /* not enough memory */
#define CICFG_DESC_EINVAL    10 /* database not valid */
#define CICFG_DESC_EAGAIN    11 /* retry the operation */
} ci_cfg_ioctl_desc_t;

/*--------------------------------------------------------------------
 *
 * Platform dependent IOCTLS
 *
 *--------------------------------------------------------------------*/





/* struct contains arguments for the trampoline register ioctl */
typedef struct ci_tramp_reg_args {
  ci_user_ptr_t trampoline_entry;
  ci_user_ptr_t trampoline_exclude;
  ci_user_ptr_t trampoline_ul_fail;

  ci_user_ptr_t signal_handler_postpone;
  ci_user_ptr_t signal_handlers[OO_SIGHANGLER_DFL_MAX+1];
  ci_user_ptr_t signal_sarestorer;
  ci_user_ptr_t signal_data;
  ci_int32 max_signum;
  ci_int32/*bool*/ sa_onstack_intercept;

   /* Used by PPC64 and other architectures for TOC and
    *  user fixup pointers.
    */
  ci_user_ptr_t trampoline_toc;
  ci_user_ptr_t trampoline_user_fixup;
} ci_tramp_reg_args_t;


struct oo_op_install_stack {
  char in_name[CI_CFG_STACK_NAME_LEN + 1];
};

struct oo_op_pace {
  ci_int32 pace;
};

struct oo_op_sigaction {
  ci_int32 sig;
  ci_user_ptr_t new_sa;   /*!< struct sigaction */
  ci_user_ptr_t old_sa;   /*!< struct sigaction */
};

struct oo_op_loopback_connect {
  ci_uint32 dst_addr;   /*!< destination address to connect to */
  ci_uint16 dst_port;   /*!< destination port to connect to */
  ci_uint8 out_moved;   /*!< have we moved socket to another stack? */
  ci_int8  out_rc;      /*!< rc of connect() */
};

struct oo_op_tcp_drop_from_acceptq {
  ci_uint32 stack_id;
  oo_sp sock_id;
};

/*----------------------------------------------------------------------------
 *
 *  Optional debug interface for resources
 *
 *---------------------------------------------------------------------------*/

#include <onload/debug_intf.h>   


/*--------------------------------------------------------------------
 *
 * Driver entry points
 *
 *--------------------------------------------------------------------*/

#include <ci/iscsi/sis_interface.h> /* to get ci_iscsi_control_params type */
#include <onload/ioctl.h>

#endif /* __ONLOAD_COMMON_H__ */
/*! \cidoxg_end */
