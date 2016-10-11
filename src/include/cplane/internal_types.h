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
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane kernel type definitions
**   \date  2005/07/13
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane_types */

#ifndef __CI_DRIVER_EFAB_CPLANE_TYPES_H__
#define __CI_DRIVER_EFAB_CPLANE_TYPES_H__


/*----------------------------------------------------------------------------
 *
 * Types - all together 
 *
 *---------------------------------------------------------------------------*/
#ifndef __ci_driver__
#error "driver-only header"
#endif


#if defined(__KERNEL__) && !defined(__oo_standalone__)
#include "driver/linux_net/kernel_compat.h" /* for uintptr_t in linux<2.6.24 */
#endif
#include <cplane/shared_types.h>
#include <cplane/driver_types.h>
#include <ci/tools/dllist.h>


/*! Type required for user-mode operating system synchronization
 */
typedef struct cicpos_mac_row_sync_s cicpos_mac_row_sync_t;

#include <cplane/linux_sync.h> /* O/S synchronization */


#include <cplane/prot_types.h>
 

/*----------------------------------------------------------------------------
 * Control Plane Statistics
 *---------------------------------------------------------------------------*/
typedef struct cicp_stat_s {

  ci_uint32 dropped_ip;        /*!< # of IP pkts dropped                  */
  ci_uint32 tbl_full;          /*!< times ARP table found full            */
  ci_uint32 tbl_clashes;       /*!< # of ARP table clashes                */
  ci_uint32 unsupported;       /*!< unsupported pkts received e.g. RARP   */
  ci_uint32 pkt_reject;        /*!< # of rejected arp pkts                */
  ci_uint32 nl_msg_reject;     /*!< # of rejected netlink neighbor msgs   */
  ci_uint32 retrans;           /*!< # of ARP req pkt retransmissions      */
  ci_uint32 timeouts;          /*!< # of ARP transaction timeouts         */
  ci_uint32 req_sent;          /*!< # of ARP pkt requests sent            */
  ci_uint32 req_recv;          /*!< # of ARP pkt requests received        */
  ci_uint32 repl_recv;         /*!< # of ARP pkt replies received         */
  ci_uint32 reinforcements;    /*!< # of ARP reinforcements(netlink)      */
  ci_uint32 fifo_overflow;     /*|< times ARP FIFO was full(pkt dropped)  */
  ci_uint32 dl_c2n_tx_err;     /*!< driverlink tx char to net errors      */
  ci_uint32 other_errors;      /*!< other ARP related  errors             */
  oo_os_timestamp_t last_poll_bgn;  /*|< last time poller was started     */
  oo_os_timestamp_t last_poll_end;  /*!< last time poller ended           */
  oo_os_timestamp_t pkt_last_recv;  /*!< time of last ARP pkt recv        */
  uintptr_t         alloc_cookie;   /*!< cookie from oo_os_alloc()        */
} cicp_stat_t;



/*----------------------------------------------------------------------------
 * Sets
 *---------------------------------------------------------------------------*/


/* For use in the O/S synchronization routines */


#define _CI_BITSET_SIZE(elements) (((elements)+0x1f)>>5)

#define CI_BITSET_SIZE(elements) (sizeof(ci_uint32)*_CI_BITSET_SIZE(elements))

#define _CI_BITSET_INDEX(index) ((index)>>5)

#define _CI_BITSET_BIT(index) (1 << ((index) & 0x1f))

#define CI_BITSET(name, elements) ci_uint32 name[_CI_BITSET_SIZE(elements)]

#define CI_BITSET_REF(name) &name[0]

/* use in declaration e.g. CI_BITSET(myset, 42); */

typedef ci_uint32 *ci_bitset_ref_t;

ci_inline void
ci_bitset_clear(ci_bitset_ref_t set, size_t elements)
{   unsigned int i;
    for (i=0; i<_CI_BITSET_SIZE(elements); i++)
	set[i] = 0;
}

/*! NB: bounds checking is the responsibility of the caller */
ci_inline int /* bool */
ci_bitset_in(ci_bitset_ref_t set, int element)
{   return 0 != (set[_CI_BITSET_INDEX(element)] & _CI_BITSET_BIT(element));
}


/*! NB: bounds checking is the responsibility of the caller */
ci_inline void
ci_bitset_add(ci_bitset_ref_t set, int element)
{   set[_CI_BITSET_INDEX(element)] |= _CI_BITSET_BIT(element);
}



/*! NB: bounds checking is the responsibility of the caller */
ci_inline void
ci_bitset_remove(ci_bitset_ref_t set, int element)
{   set[_CI_BITSET_INDEX(element)] &= ~_CI_BITSET_BIT(element);
}



/*----------------------------------------------------------------------------
 * Address Resolution MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

/* Note: this is used in conjunction with the user-visible mac MIB table */

typedef struct
{   cicpos_mac_row_t sync;    /*< O/S synchronization info */
    cicppl_mac_row_t prot;    /*< fields for ARP/ICMPv6/.. protocol support */
} cicp_mac_kernrow_t;


typedef struct cicp_mac_kmib_s
{
    uintptr_t          alloc_cookie;
    ci_verlock_t       version;      /*< incremented whenever table changed */
    ci_uint32          sync_claimed; /*< synchronizer instance active */
    cicpos_mac_mib_t   sync;         /*< fields for O/S synch support */
    cicppl_mac_mib_t   prot;         /*< fields for protocol support */
    /* ci_mac_stat_t      stat; */      /*< Address resolution statistics */
    cicp_mac_kernrow_t entry[1];     /*< no. of rows varies with allocation */
} cicp_mac_kmib_t;




/* constant-preserving macro for determining size of kernel MAC MIB */ 
#define CICP_MAC_KMIB_SIZE(_kmact, _n) \
        (sizeof(*_kmact)+((_n)-1)*sizeof((_kmact)->entry[0]))

/*! emulate sizeof() for a kernel mac mib - using entries of user mac mib */
ci_inline size_t
cicp_mac_kmib_size(const cicp_mac_mib_t *mact, const cicp_mac_kmib_t *kmact)
{   return CICP_MAC_KMIB_SIZE(kmact, cicp_mac_mib_rows(mact));
}



/*----------------------------------------------------------------------------
 * kernel IP interface MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

typedef struct
{   ci_ip_addr_net_t bcast_ip;  /*< broadcast IP address, 0 if not set */
    ci_ip_addr_net_t net_ip;    /*< network own address */
    ci_ip_addrset_t  net_ipset; /*< network IP address set specification */
    ci_ifid_t        ifindex;   /*< O/S index of link layer interface */
    cicp_rowid_t     bond_rowid; /*< Bond table rowid if onloadable bond */
    ci_uint8         scope;     /*< Scope - 0 is global, more is worse */
    /* no O/S synchronization information required? */
} cicp_ipif_row_t;


/*! emulating an "allocated" field in a ipif row: set it to "unallocated" */
ci_inline void
cicp_ipif_row_free(cicp_ipif_row_t *row)
{
   row->net_ipset = CI_IP_ADDRSET_BAD;
}

/*! emulating an "allocated" field in a ipif row: read whether allocated */
ci_inline int /* bool */
cicp_ipif_row_allocated(const cicp_ipif_row_t *row)
{
   return row->net_ipset != CI_IP_ADDRSET_BAD;
}


typedef struct cicpos_callback_registration_s
{   cicpos_ipif_event_fn_t   *add_fn;
    cicpos_ipif_event_fn_t   *delete_fn;
    cicpos_llap_event_fn_t   *llap_fn;
    cicpos_hwport_event_fn_t *hwport_fn;
    void                     *arg;
    uintptr_t                 alloc_cookie;
} cicpos_callback_registration_t;

ci_inline int /* bool */
cicp_callback_allocated(const cicpos_callback_registration_t *cb)
{   return NULL != cb;
}

typedef struct cicp_ipif_kmib_s 
{  
  uintptr_t         alloc_cookie;
  uintptr_t         alloc_cookie_rows;
  cicp_ipif_row_t   *ipif;
  ci_uint16         rows_max;
} cicp_ipif_kmib_t;



/*----------------------------------------------------------------------------
 * Path MTU MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/
typedef struct cicp_pmtu_row_s {
  ci_ip_addr_net_t  net_ip;
  oo_os_timestamp_t timestamp;
} cicp_pmtu_row_t;

/*! emulating an "allocated" field in a pmtu row: set it to "unallocated" */
ci_inline void
cicp_pmtu_row_free(cicp_pmtu_row_t *row)
{
 row->net_ip = INADDR_ANY;
}

/*! emulating an "allocated" field in a pmtu row: read whether allocated */
ci_inline int /* bool */
cicp_pmtu_row_allocated(const cicp_pmtu_row_t *row)
{
   return row->net_ip != INADDR_ANY;
}

typedef struct cicp_pmtu_kmib_s {
  uintptr_t alloc_cookie;
  uintptr_t alloc_cookie_rows;
  cicp_pmtu_row_t *entries;
  ci_uint16 used_rows_max;
  ci_uint16 rows_max;
} cicp_pmtu_kmib_t;


/*----------------------------------------------------------------------------
 * Parse state
 *---------------------------------------------------------------------------*/

typedef struct
{
  /* "imported" bitmaps */
  cicp_handle_t *control_plane;
  
  ci_uint32 *imported_route;
  ci_uint32 *imported_ipif;
  ci_uint32 *imported_llap;
  ci_uint32 *imported_pmtu;
 
  oo_os_timestamp_t start_timestamp;

  int /* bool */  nosort;

  uintptr_t alloc_cookie;
  uintptr_t alloc_cookie_route;
  uintptr_t alloc_cookie_ipif;
  uintptr_t alloc_cookie_llap;
  uintptr_t alloc_cookie_pmtu;
} cicpos_parse_state_t;

typedef void ci_post_handling_fn_t(cicpos_parse_state_t *);


/*----------------------------------------------------------------------------
 * Protocols
 *---------------------------------------------------------------------------*/

typedef struct {
  ci_dllink     dllink;
  ci_ifid_t     ifindex;
  ci_ether_arp  arp;
} cicppl_rx_fifo_item_t;


#endif /* __CI_DRIVER_EFAB_CPLANE_TYPES_H__ */

/*! \cidoxg_end */
