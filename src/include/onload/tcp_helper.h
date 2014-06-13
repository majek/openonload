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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/03/23
** Description: User level TCP helper interface.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_HELPER_H__
#define __CI_DRIVER_EFAB_TCP_HELPER_H__


#include <ci/compat.h>
#include <ci/internal/ip.h>
#include <onload/osfile.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_socket.h>


/* Forwards. */
typedef struct tcp_helper_endpoint_s tcp_helper_endpoint_t;


struct tcp_helper_nic {
  int                  intf_i;
  struct oo_nic*       oo_nic;
  struct efrm_vi*      vi_rs;
  unsigned             vi_mem_mmap_bytes;
#if CI_CFG_PIO
  struct efrm_pio*     pio_rs;
  unsigned             pio_io_mmap_bytes;
#endif
};


struct tcp_helper_resource_s;

typedef struct thc_legacy_os_sock_s {
    ci_uint32                    tlos_laddr_be32;
    ci_uint16                    tlos_lport_be16;
    int                          tlos_protocol;
    int                          tlos_pollwait_registered;
    struct oo_file_ref*          tlos_os_sock;
    int                          tlos_refs;
    ci_dllink                    tlos_next;
} thc_legacy_os_sock_t;

typedef struct tcp_helper_cluster_s {
  struct efrm_vi_set*           thc_vi_set[CI_CFG_MAX_REGISTER_INTERFACES];
  struct oof_thc*               thc_oof_head;
  struct tcp_helper_resource_s* thc_thr_head;
  char                          thc_name[(CI_CFG_STACK_NAME_LEN >> 1) + 1];
  int                           thc_cluster_size;
  uid_t                         thc_euid;
  ci_dllist                     thc_tlos;
  struct tcp_helper_cluster_s*  thc_next;
} tcp_helper_cluster_t;


 /*--------------------------------------------------------------------
 *
 * tcp_helper_resource_t
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct tcp_helper_resource_s {
  /* A number of fields here duplicate fields in ci_netif_state.  This is
   * deliberate, and is because we do not trusted the contents of the
   * shared state.
   */
  unsigned               id;
  char                   name[CI_CFG_STACK_NAME_LEN + 1];
  oo_atomic_t            ref_count;

  ci_netif               netif;

  /*! Kernel side stack lock. Needed so we can determine who "owns" the
   *   netif lock (kernel or user).
   *
   * The flags can only be set when the lock is LOCKED.  ie. This must be
   * UNLOCKED, or LOCKED possibly in combination with the other flags.  If
   * AWAITING_FREE is set, other flags must not be.
   */
#define OO_TRUSTED_LOCK_UNLOCKED          0x0
#define OO_TRUSTED_LOCK_LOCKED            0x1
#define OO_TRUSTED_LOCK_AWAITING_FREE     0x2
#define OO_TRUSTED_LOCK_NEED_POLL         0x4
#define OO_TRUSTED_LOCK_CLOSE_ENDPOINT    0x8
#define OO_TRUSTED_LOCK_RESET_STACK       0x10
#define OO_TRUSTED_LOCK_NEED_PRIME        0x20
  volatile unsigned      trusted_lock;

  /*! Link for global list of stacks. */
  ci_dllink              all_stacks_link;

  /*! A count of kernel references to this stack.  Normally there is one
   * reference to indicate that this stack is still referenced by userland.
   * Some other bits of code may hold a reference.
   *
   * Once the userland reference has gone away we set
   * TCP_HELPER_K_RC_NO_USERLAND to prevent new user-level references being
   * taken.
   *
   * When the ref count goes to zero we set TCP_HELPER_K_RC_DEAD to ensure
   * other code won't grab another ref to this stack.
   */
  volatile int           k_ref_count;
# define TCP_HELPER_K_RC_NO_USERLAND    0x10000000
# define TCP_HELPER_K_RC_DEAD           0x20000000
# define TCP_HELPER_K_RC_REFS(krc)      ((krc) & 0xffffff)

  /* A count of the refs added to k_ref_count for closing endpoints in
   * efab_tcp_helper_rm_free_locked().  Protected by thr->lock *not*
   * ci_netif lock */
  int n_ep_closing_refs;

  /*! this is used so we can schedule destruction at task time */
  struct work_struct work_item_dtor;

  /* For deferring work to a non-atomic context. */
  char wq_name[11 + CI_CFG_STACK_NAME_LEN];
  struct workqueue_struct *wq;
  struct work_struct non_atomic_work;
  /* List of endpoints requiring work in non-atomic context. */
  ci_sllist     non_atomic_list;

#ifdef  __KERNEL__
  /*! clear to indicate that timer should not restart itself */
  atomic_t                 timer_running;
  /*! timer tasklet */
  struct tasklet_struct  tasklet;
  /*! timer tasklet timer */
  struct timer_list      timer;

#  if HZ < 100
#   error FIXME: Not able to cope with low HZ at the moment.
#  endif
  /* Periodic timer fires roughly 100 times per sec. */
# define CI_TCP_HELPER_PERIODIC_BASE_T  ((unsigned long)(HZ*9/100))
# define CI_TCP_HELPER_PERIODIC_FLOAT_T ((unsigned long)(HZ*1/100))



#endif  /* __KERNEL__ */

  /*! tcp_helper endpoint(s) to be closed at next calling of
   * linux_tcp_helper_fop_close() or if tcp_helper_resource is released
   */
  ci_sllist             ep_tobe_closed;

  volatile ci_uint32    trs_aflags;
  /* We've deferred locks to non-atomic handler.  Must close endpoints. */
# define OO_THR_AFLAG_CLOSE_ENDPOINTS     0x1
  /* Defer efab_tcp_helper_rm_free_locked() to non-atomic handler. */
# define OO_THR_AFLAG_RM_FREE             0x2

  /*! Spinlock.  Protects:
   *    - ep_tobe_closed
   *    - non_atomic_list
   *    - wakeup_list
   *    - n_ep_closing_refs
   *    - intfs_to_reset 
   */
  ci_irqlock_t          lock;

  /* Bit mask of intf_i that need resetting by the lock holder */
  unsigned              intfs_to_reset;

  unsigned              mem_mmap_bytes;
  unsigned              io_mmap_bytes;
  unsigned              buf_mmap_bytes;
#if CI_CFG_PIO
  /* Length of the PIO mapping.  There is typically a page for each VI */
  unsigned              pio_mmap_bytes;
#endif

  /* Used to block threads that are waiting for free pkt buffers. */
  ci_waitq_t            pkt_waitq;
  
  struct tcp_helper_nic      nic[CI_CFG_MAX_INTERFACES];

#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* shmid of packet set */
  ci_int32             *pkt_shm_id;
#endif

  /* bool: avoid packet allocations when in atomic mode */
  int avoid_atomic_allocations;

  /* The cluster this stack is associated with if any */
  tcp_helper_cluster_t*         thc;
  /* TID of thread that created this stack within the cluster */
  pid_t                         thc_tid;
  /* Track list of stacks associated with a single thc */
  struct tcp_helper_resource_s* thc_thr_next;
} tcp_helper_resource_t;


#define NI_OPTS_TRS(trs) (NI_OPTS(&(trs)->netif))

#define netif2tcp_helper_resource(ni)                   \
  CI_CONTAINER(tcp_helper_resource_t, netif, (ni))

#ifdef NDEBUG
#define TCP_HELPER_RESOURCE_ASSERT_VALID(trs, rc_mbz)
#else
extern void tcp_helper_resource_assert_valid(tcp_helper_resource_t*,
                                             int rc_is_zero,
                                             const char *file, int line);
#define TCP_HELPER_RESOURCE_ASSERT_VALID(trs, rc_mbz) \
    tcp_helper_resource_assert_valid(trs, rc_mbz, __FILE__, __LINE__)
#endif


 /*--------------------------------------------------------------------
 *
 * tcp_helper_endpoint_t
 *
 *--------------------------------------------------------------------*/

/*! Information about endpoint accessible to kernel only */
struct tcp_helper_endpoint_s {

  /*! TCP helper resource we are a part of */
  tcp_helper_resource_t * thr;

  /*! Endpoint ID */
  oo_sp id;

  /*! Per-socket state for the filter manager. */
  struct oof_socket oofilter;

  /*! OS socket responsible for port reservation; may differ from os_socket
   * (for accepted socket) and is set/cleared together with filters.
   * Concurrency control is via atomic exchange (oo_file_ref_xchg()).
   */
  struct oo_file_ref* os_port_keeper;

  /*! link so we can be in the list of endpoints to be closed in the future */
  ci_sllink tobe_closed;

  /* Link field when queued for non-atomic work. */
  ci_sllink non_atomic_link;

  /*! Links of the list with endpoints with pinned pages */
  ci_dllink ep_with_pinned_pages;
  /*! List of pinned pages */
  ci_dllist pinned_pages;
  /*! Number of pinned pages */
  unsigned int n_pinned_pages;

  /*! Head of the waitqueue */
  ci_waitable_t waitq;			

  /*!< OS socket that backs this user-level socket.  May be NULL (not all
   * socket types have an OS socket).
   * os_socket should be set only when aflags & OO_THR_EP_AFLAG_ATTACHED
   */
  struct oo_file_ref* os_socket;

  /*!< OS socket poll table to get OS errors */
  struct oo_os_sock_poll os_sock_pt;

  struct fasync_struct* fasync_queue;

  /*! Link for the wakeup list.  This *must* be reset to zero when not in
  ** use.
  */
  tcp_helper_endpoint_t* wakeup_next;

  /*! Atomic endpoint flags not visible for UL. */
  volatile ci_uint32 ep_aflags;
#define OO_THR_EP_AFLAG_ATTACHED       0x1
#define OO_THR_EP_AFLAG_PEER_CLOSED    0x2  /* Used for pipe */
#define OO_THR_EP_AFLAG_NON_ATOMIC     0x4  /* On the non-atomic list */
#define OO_THR_EP_AFLAG_CLEAR_FILTERS  0x8  /* Needs filters clearing */
#define OO_THR_EP_AFLAG_NEED_FREE      0x10 /* Endpoint to be freed */
#define OO_THR_EP_AFLAG_OS_NOTIFIER    0x20 /* Pollwait registration for os
                                             * sock used by cluster without
                                             * kernel reuseport support is
                                             * owned by this endpoint.
                                             */
#define OO_THR_EP_AFLAG_LEGACY_REUSEPORT    0x40



};


#endif /* __CI_DRIVER_EFAB_TCP_HELPER_H__ */
/*! \cidoxg_end */
