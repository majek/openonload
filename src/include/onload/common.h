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
#include <onload/signals.h> /* for OO_SIGHANGLER_DFL_MAX */
#include <cplane/cplane.h>



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

enum oo_device_type {
  OO_STACK_DEV,
  OO_EPOLL_DEV,
  OO_MAX_DEV /* not a device type */
};

# define EFAB_DEV_NAME  "onload"  

# define OO_EPOLL_DEV_NAME "onload_epoll"


/* Max length of version string used for version skew checking. */
enum { OO_VER_STR_LEN = 40 };

/* We use an md5sum over certain headers to ensure that userland and kernel
 * drivers are built against a compatible interface.
 */
enum { CI_CHSUM_STR_LEN = 32 };


typedef struct oo_version_check_s {
  char                    in_version[OO_VER_STR_LEN + 1];
  char                    in_uk_intf_ver[CI_CHSUM_STR_LEN + 1];
  int32_t                 debug;
} oo_version_check_t;

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
  int                     in_cluster_size;
  int                     in_cluster_restart;
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
  char      cluster_name[CI_CFG_CLUSTER_NAME_LEN + 1];
  ci_int32  cluster_size;
  ci_uint32 cluster_restart_opt;
  ci_uint32 cluster_hot_restart_opt;
  ci_uint32 addr_be32;
  ci_uint16 port_be16;
} oo_tcp_reuseport_bind_t;

typedef struct {
  oo_sp             tcp_id;
  ci_int32          need_update;
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
  ci_int32      level;
  ci_int32      optname;
  ci_user_ptr_t optval;
  ci_int32      optlen;
} oo_tcp_create_set_t;

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

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  oo_sp                 ep_id;
  ci_int32              type;
} oo_tcp_accept_sock_attach_t;

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

typedef struct {
  ci_uint32 len;
  ci_user_ptr_t str;
} oo_ofe_config_t;


typedef struct {
  oo_pkt_p	pkt;
  ci_uint32	retrieve_rc;
  ci_uerr_t	os_rc;
  ci_uerr_t	rc;
  ci_ifid_t     ifindex;
  ci_uint32     next_hop;
} cp_user_defer_send_t;

typedef struct {
  ci_uint32	pkt;
  ci_ifid_t	ifindex;
} cp_user_pkt_dest_ifid_t;

/* This is shared structure. It should not use "int", "long", etc because
 * kernel and userland may have different size for such types. */
typedef struct {
  ci_int16               fd_type;
# define CI_PRIV_TYPE_NONE      0
# define CI_PRIV_TYPE_TCP_EP    1
# define CI_PRIV_TYPE_UDP_EP    2
# define CI_PRIV_TYPE_NETIF     3
# define CI_PRIV_TYPE_PASSTHROUGH_EP 4
# define CI_PRIV_TYPE_ALIEN_EP   5
#if CI_CFG_USERSPACE_PIPE
# define CI_PRIV_TYPE_PIPE_READER 6
# define CI_PRIV_TYPE_PIPE_WRITER 7
#endif
#if CI_CFG_USERSPACE_PIPE
# define CI_PRIV_TYPE_IS_ENDPOINT(t)                                \
    ((t) == CI_PRIV_TYPE_TCP_EP || (t) == CI_PRIV_TYPE_UDP_EP ||    \
     (t) == CI_PRIV_TYPE_PASSTHROUGH_EP ||                          \
     (t) == CI_PRIV_TYPE_ALIEN_EP ||                                \
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
  ci_user_ptr_t stats_data;
  ci_uint32 intf_i;
  ci_uint32 data_len;
  ci_uint8 do_reset;
} ci_vi_stats_query_t;


typedef struct {
  ci_uint64             do_cloexec; /* it's u8 really, but we need to be compat */
  ci_fixed_descriptor_t fd;
} ci_clone_fd_t;


/* "Donation" shared memory ioctl structures. */

typedef struct {
  ci_int32       shm_class;
  ci_user_ptr_t  buffer;
  ci_uint32      length;
  ci_int32       buffer_id;
} oo_dshm_register_t;

typedef struct {
  ci_int32       shm_class;
  ci_user_ptr_t  buffer_ids;
  ci_uint32      count;
} oo_dshm_list_t;

typedef struct {
  ci_int32       laddr_be32;
} oo_alloc_active_wild_t;

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


/*----------------------------------------------------------------------------
 *
 *  Driver entry points used from the Control Plane
 *
 *---------------------------------------------------------------------------*/

#include <cplane/ioctl.h>

/*--------------------------------------------------------------------
 *
 * Driver entry points
 *
 *--------------------------------------------------------------------*/

#include <onload/ioctl.h>

#endif /* __ONLOAD_COMMON_H__ */
/*! \cidoxg_end */
