/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  slp
**  \brief  Interface for invoking debug ops on resources.
**   \date  2004/08/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_onload  */

#ifndef __ONLOAD_DEBUG_INTF_H__
#define __ONLOAD_DEBUG_INTF_H__

#include <ci/internal/transport_config_opt.h>
#include <ci/tools/config.h>


/*--------------------------------------------------------------------
 *
 * ci_get_netif_info - get information about various netifs
 *
 *--------------------------------------------------------------------*/

typedef struct {
  /*! OUT:  Select/Poll maxima */
  ci_uint16		poll_l5_max[2];
  ci_uint16		poll_os_max[2];
  ci_uint16		select_l5_max[2];
  ci_uint16		select_os_max[2];
} ci_netif_dbg_max_t;

typedef struct {
  /*! IN:   index of thread we asking for information on */
  ci_int32          index;
  /*! OUT:  thread id - negative value indicates no thread */
  ci_int32          id;
#define NETIF_INFO_MAX_EPS_PER_THREAD  4
  /* ids of the endpoints this thread is using */
  ci_int32          ep_id[NETIF_INFO_MAX_EPS_PER_THREAD];
#define NETIF_INFO_UNLOCKED_NETIF   0
#define NETIF_INFO_AWATING_NETIF    1
#define NETIF_INFO_LOCKED_NETIF     2
#define NETIF_INFO_HOLDER_IS_SELF     4   /* pseudo-state created
					   * when "get state" called */
  /*! OUT:  is this thread currently waiting for the lock */
  ci_int32          lock_status;
  /*! OUT:  number of times this thread waited for eplock */
  ci_int32          no_lock_contentions;
  /*! OUT:  number of times this thread called fork, select,
   *        exec and poll */
  ci_int32          no_select;
  ci_int32          no_poll;
  ci_int32          no_fork;
  ci_int32          no_exec;
  ci_int32          no_accept;
  /*! OUT:  number of contentions on fdtable lock */
  ci_int32          no_fini;
  /*! OUT:  maxima for poll/select calls */
  ci_netif_dbg_max_t max;
} ci_netif_thrd_info_t;


/*! Comment? */
typedef struct {
 
#define CI_DBG_NETIF_INFO_MAX_ENDPOINTS 40
  /*! IN:   index of netif */
  ci_uint32             ni_index;              
  /*! IN/OUT: orphans should be included, stack is an orphan */
  ci_uint32             ni_orphan;
  /*! OUT:  does netif exist at this index? */
  ci_int32              ni_exists; 
  /*! OUT: name of the current netif, if ni_exists==1 */
  char                  ni_name[CI_CFG_STACK_NAME_LEN + 1];

  ci_uint32		mmap_bytes;
  ci_int32		k_ref_count;
  ci_int32		rs_ref_count;

  /*! OUT: netif exists but not sufficient permissions to access it */
  ci_int32              ni_no_perms_exists;
  unsigned              ni_no_perms_id;
  char                  ni_no_perms_name[CI_CFG_STACK_NAME_LEN + 1];
  uid_t                 ni_no_perms_uid;
  uid_t                 ni_no_perms_euid;
  ci_int32              ni_no_perms_share_with;

#define CI_DBG_NETIF_INFO_NOOP                    0
#define CI_DBG_NETIF_INFO_GET_NEXT_NETIF          1
#define CI_DBG_NETIF_INFO_GET_ENDPOINT_STATE      2
          
  /*! IN: subcode of operation required */
  ci_uint32		ni_subop;
  union {

    struct {
      /*! OUT: index of next netif - -1 if no more */
      ci_int32		index;
    } ni_next_ni;

    /* Thread-specific info - this struct is also present in
     * ci_netif_state */
    ci_netif_thrd_info_t ni_thread;

    struct {
      /*! IN:   index of endpoint we asking for information on */
      ci_int32		index;
      /*! OUT:  endpoint state */
      ci_int32		state;
      /*! OUT:  n ep bufs */
      ci_int32		max;
      /*! OUT:  TCP tx queue stats */
      ci_int32		tx_pkts_max;
      ci_int32		tx_pkts_num;
      ci_int32		tx_pkts_len;
      /*! OUT:  Protocol info */
      ci_int32		protocol;
      ci_int32		laddr;
      ci_int32		lport;
      ci_int32		raddr;
      ci_int32		rport;
      ci_uint32		udpstate;
      /*! OUT:  Select/Poll maxima */
      ci_netif_dbg_max_t maxima;
      ci_uint32		rx_pkt_ul;
      ci_uint32		rx_pkt_kn;
    } ni_endpoint;

    /* Conditionally included history log */
    struct {
      /*! IN:   Index being sought
       *  OUT:  Index being returned (-1 if none) */
      ci_int32		index;
    } ni_ep_history;
  } u;

} ci_netif_info_t;

struct oo_stacklist_update {
  ci_uint32 seq;        /**< Sequence number of stack list */
  ci_int32  timeout;    /**< Timeout; we really need only 0 and -1 */
};

/*! Comment? */
typedef struct {

#define __CI_DEBUG_OP_DUMP_INODE__	(1)
#define __CI_DEBUG_OP_TRAMPOLINE__	(2)
#define __CI_DEBUG_OP_FDS_DUMP__	(3)
#define __CI_DEBUG_OP_DUMP_STACK__	(5)
#define __CI_DEBUG_OP_KILL_STACK__	(6)

  ci_uint32			what;		/* which operation */

  union { 
    ci_uint32			fd;
    ci_uintptr_t		tramp_debug;	/* ci_debug_trampoline */
    ci_uint32			fds_dump_pid;
    struct {
      ci_uint32			stack_id;
      ci_uint32                 orphan_only;
    } dump_stack;
    ci_uint32                   stack_id;       /* kill stack */
  } u CI_ALIGN(8);
} ci_debug_onload_op_t;

#endif /* __ONLOAD_DEBUG_INTF_H__ */
/*! \cidoxg_end */
