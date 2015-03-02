/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
**  \brief  Definition of ci_netif etc.
**   \date  2006/06/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_IP_TYPES_H__
#define __CI_INTERNAL_IP_TYPES_H__

/*
** READ ME FIRST please.
**
** This header contains type definitions for the Etherfabric TCP/IP stack
** that do not form part of the state of the stack.  ie. These types are
** part of the support and infrastructure.
**
** The only stuff that may appear here is types and data structures,
** constants associated with fields in those data structures and
** documentation.
**
** NO CODE IN THIS FILE PLEASE.
*/



/*!
** ci_netif_nic_t
**
** The portion of a netif that corresponds to H/W resources and must be
** replicated per NIC.
*/
typedef struct ci_netif_nic_s {
  ef_vi                      vi;
#if CI_CFG_PIO
  ef_pio                     pio;
#endif // CI_CFG_PIO
#ifdef __KERNEL__
  struct oo_iobufset** pkt_rs;
#endif
} ci_netif_nic_t;


#ifdef __KERNEL__
struct tcp_helper_endpoint_s;
struct oof_cb_sw_filter_op;
#endif


/*!
** ci_netif
**
** This is the top-level representation of an Etherfabric stack.  It is the
** key-stone that provides access to the state of the stack.
**
** This data-structure is not shared: There is one copy per userlevel
** address space, and one in the kernel.  Therefore it does not contain any
** of the "state" of the stack, merely description of whether that state
** is.
*/
struct ci_netif_s {
  ci_magic_t           magic;
  efrm_nic_set_t       nic_set; 
  int                  nic_n;
  /* resources */
  ci_netif_nic_t       nic_hw[CI_CFG_MAX_INTERFACES];

  ci_netif_state*      state;

#ifndef __KERNEL__
  /* Use ci_netif_get_driver_handle() rather than this directly. */
  ef_driver_handle     driver_handle;
  unsigned             mmap_bytes;
  char*                cplane_ptr;
  char*                io_ptr;
#if CI_CFG_PIO
  uint8_t*             pio_ptr;
#endif
  char*                buf_ptr;
#endif

#ifdef __ci_driver__
  ci_int8              hwport_to_intf_i[CI_CFG_MAX_REGISTER_INTERFACES];
  ci_int8              intf_i_to_hwport[CI_CFG_MAX_INTERFACES];
  uid_t                uid;
  uid_t                euid;
# ifdef CI_HAVE_OS_NOPAGE
  ci_shmbuf_t          pages_buf;
# else
  ci_shmbuf_t**        k_shmbufs;
  unsigned             k_shmbufs_n;
# endif
#else
# ifndef CI_HAVE_OS_NOPAGE
  void **              u_shmbufs;
# endif
#endif


  cicp_ni_t            cplane;
    
#ifdef __KERNEL__
  /** eplock resource. Note that this has the SAME lifetime as [lock]. 
   *  The reference on this object is taken when the lock is created -
   *  and no other reference is taken. */
  eplock_helper_t      eplock_helper;
#endif

  ci_netif_filter_table* filter_table;

#ifdef __KERNEL__
  /** pkt resources, 1:1 mapping with [pkt_rs]. Note that these have
   *  the SAME lifetime as [pkt_rs]. Entry in this array MUST NOT be
   *  taken to imply that a ref. has been taken; it hasn't! */
  struct oo_buffer_pages** buf_pages;
# if CI_CFG_PKTS_AS_HUGE_PAGES
  int                   huge_pages_flag;
# endif
#else
# if CI_CFG_PKTS_AS_HUGE_PAGES
  ci_int32             *pkt_shm_id;
# endif
  char**                pkt_sets; /* array of mmaped pkt sets */
#endif

#ifdef __ci_driver__
  ci_contig_shmbuf_t   state_buf;
  unsigned             pkt_sets_n;
  unsigned             pkt_sets_max;
  ci_uint32            ep_ofs;           /**< Copy from ci_netif_state_s */

  /*! Trusted per-socket state. */
  struct tcp_helper_endpoint_s**  ep_tbl;
  unsigned                        ep_tbl_n;
  unsigned                        ep_tbl_max;
#endif

#ifndef __ci_driver__
  /* for table of active UL netifs (unix/netif_init.c) */
  ci_dllink            link;
  
  /* Number of active endpoints this process has in this UL netif.  Used as a
  ** reference count to govern the lifetime of the UL netif.
  */
  oo_atomic_t          ref_count;
#endif /* __ci_driver__ */

  /* General flags */  
  /* This field must be protected by the netif lock.
   */
  unsigned             flags;
  /* Sending ONLOAD_MSG_WARM */
# define CI_NETIF_FLAG_MSG_WARM          0x1

#ifndef __KERNEL__
  /* netif was once (and maybe still is) shared between multiple processes */
# define CI_NETIF_FLAGS_SHARED           0x10
  /* netif is protected from destruction with an extra ref_count */
# define CI_NETIF_FLAGS_DTOR_PROTECTED   0x20
  /* Don't use this stack for new sockets unless name says otherwise */
# define CI_NETIF_FLAGS_DONT_USE_ANON    0x40
#else
  /* netif is a kernel-only stack and thus is trusted */
# define CI_NETIF_FLAGS_IS_TRUSTED       0x100
  /* Stack [k_ref_count] to be decremented when sockets close. */
# define CI_NETIF_FLAGS_DROP_SOCK_REFS   0x200
  /* Currently being used from a driverlink context */
# define CI_NETIF_FLAG_IN_DL_CONTEXT     0x400
  /* Should not allocate packets in atomic/driverlink context */
# define CI_NETIF_FLAG_AVOID_ATOMIC_ALLOCATION 0x800
  /* Packet allocation postponed */
#define CI_NETIF_FLAG_NO_PACKET_BUFFERS  0x1000
#endif

#ifndef __KERNEL__
  double    ci_ip_time_tick2ms;     /* time for 1 tick in ms */
#endif

#ifdef __KERNEL__
  ci_netif_config_opts opts;

  /* Stack overflow avoidance, used from allocate_vi(). */
  ci_uint64 vi_data[10];

  /* List of postponed sw filter updates and its lock */
  /* It is the innermost lock - no other locks, no kfree(), etc
   * could be used under it. */
  spinlock_t swf_update_lock; /* innermost lock */
  /* The first and the last entry in the postponed
   * sw filter update list. */
  struct oof_cb_sw_filter_op *swf_update_first, *swf_update_last;
#endif

  /* Used from ci_netif_poll_evq() only.  Moved here to avoid stack
   * overflow. */
  ef_event      events[16];
  ef_request_id tx_events[EF_VI_TRANSMIT_BATCH];
  /* See also copy in ci_netif_state. */
  unsigned      error_flags;

#ifdef ONLOAD_OFE
  struct ofe_engine* ofe;
#endif
};


/*!
** citp_socket
**
** This is the keystone that provides access to a socket.  It provides
** access to the stack the socket lies in, and identifies the socket within
** that stack.
*/
struct citp_socket_s {
  ci_netif*            netif;
  ci_sock_cmn*         s;

  /* When SO_LINGER is used, this value checks that the endpoint was not
   * re-used for another socket. */
  ci_uint64            so_linger_hash;

};


/* To avoid complicated compat code, use simplified msghdr when
 * compiling in-kernel  */
#ifndef __KERNEL__
typedef struct msghdr ci_msghdr;
#else
typedef struct {
  ci_iovec*     msg_iov;
  unsigned long msg_iovlen;
} ci_msghdr;
#endif


/* Arguments to ci_tcp_recvmsg(). */
typedef struct ci_tcp_recvmsg_args {
  ci_netif*      ni;
  ci_tcp_state*  ts;
  ci_msghdr*     msg;
  int            flags;
} ci_tcp_recvmsg_args;

/* Arguments to ci_udp_sendmsg and ci_udp_recvmsg */
typedef struct ci_udp_iomsg_args {
  ci_udp_state  *us;
  ci_netif      *ni;
#ifndef __KERNEL__
  citp_socket   *ep;
  ci_fd_t        fd;
#else
  /* This one is required to call poll on filp from
   * recv */
  struct file   *filp;
  /* stored to speed up os socket recv */
#endif
} ci_udp_iomsg_args;

struct ci_netif_poll_state {
  oo_pkt_p  tx_pkt_free_list;
  oo_pkt_p* tx_pkt_free_list_insert;
  int       tx_pkt_free_list_n;
};



#endif  /* __CI_INTERNAL_IP_TYPES_H__ */
/*! \cidoxg_end */
