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


#include <ci/internal/cplane_types.h>
#include <ci/internal/cplane_ops2.h>
#include <ci/driver/internal.h>  /* for ci_contig_shmbuf_* */
#include <onload/common.h>


#include <ci/driver/platform/linux_cplane_sync.h> /* O/S synchronization */


typedef struct cicp_mac_kmib_s cicp_mac_kmib_t; /* fwd ref for cplane_prot.h */
#include <onload/cplane_prot.h> /* ARP, ICMPv6 etc. protocol */
 
#include <ci/tools/spinlock.h> /* for ci_irqlock_t */
#include <ci/driver/efab/open.h> /* for cicp_ns_mmap_info_t */


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
  ci_uint32 last_poll_bgn;     /*|< last time poller was started          */
  ci_uint32 last_poll_end;     /*!< last time poller ended                */
  ci_uint32 pkt_last_recv;     /*!< time of last ARP pkt recv by char drv */
} cicp_stat_t;


#define cicp_stat_get_sys_ticks() (jiffies)


#define CICP_STAT_SET_SYS_TICKS(_cplane, fldname)		\
    (_cplane)->stat.fldname = cicp_stat_get_sys_ticks()


/* ARP module statistics access macros */
#define CICP_STAT_INC_DROPPED_IP(_cplane)     (++(_cplane)->stat.dropped_ip)
#define CICP_STAT_INC_TBL_FULL(_cplane)       (++(_cplane)->stat.tbl_full)
#define CICP_STAT_INC_TBL_CLASHES(_cplane)    (++(_cplane)->stat.tbl_clashes)
#define CICP_STAT_INC_UNSUPPORTED(_cplane)    (++(_cplane)->stat.unsupported)
#define CICP_STAT_INC_PKT_REJECT(_cplane)     (++(_cplane)->stat.pkt_reject)
#define CICP_STAT_INC_NL_MSG_REJECT(_cplane)  (++(_cplane)->stat.nl_msg_reject)
#define CICP_STAT_INC_RETRANS(_cplane)        (++(_cplane)->stat.retrans)
#define CICP_STAT_INC_TIMEOUTS(_cplane)       (++(_cplane)->stat.timeouts)
#define CICP_STAT_INC_REQ_SENT(_cplane)       (++(_cplane)->stat.req_sent)
#define CICP_STAT_INC_REQ_RECV(_cplane)       (++(_cplane)->stat.req_recv)
#define CICP_STAT_INC_REPL_RECV(_cplane)      (++(_cplane)->stat.repl_recv)
#define CICP_STAT_INC_REINFORCEMENTS(_cplane) (++(_cplane)->stat.reinforcements)
#define CICP_STAT_INC_FIFO_OVERFLOW(_cplane)  (++(_cplane)->stat.fifo_overflow)
#define CICP_STAT_INC_DL_C2N_TX_ERR(_cplane)  (++(_cplane)->stat.dl_c2n_tx_err)
#define CICP_STAT_INC_OTHER_ERRORS(_cplane)   (++(_cplane)->stat.other_errors)

#define CICP_STAT_SET_LAST_POLL_BGN(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, last_poll_bgn)
#define CICP_STAT_SET_LAST_POLL_END(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, last_poll_end)
#define CICP_STAT_SET_PKT_LAST_RECV(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, pkt_last_recv)



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

/* row index type: cicp_mac_rowid_t; */

typedef struct
{   cicpos_mac_row_t sync;    /*< O/S synchronization info */
    cicppl_mac_row_t prot;    /*< fields for ARP/ICMPv6/.. protocol support */
} cicp_mac_kernrow_t;


struct cicp_mac_kmib_s
{   ci_verlock_t       version;      /*< incremented whenever table changed */
    ci_uint32          sync_claimed; /*< synchronizer instance active */
    cicpos_mac_mib_t   sync;         /*< fields for O/S synch support */
    cicppl_mac_mib_t   prot;         /*< fields for protocol support */
    /* ci_mac_stat_t      stat; */      /*< Address resolution statistics */
    cicp_mac_kernrow_t entry[1];     /*< no. of rows varies with allocation */
} /* cicp_mac_kmib_t */;




/* constant-preserving macro for determining size of kernel MAC MIB */ 
#define CICP_MAC_KMIB_SIZE(_kmact, _n) \
        (sizeof(*_kmact)+((_n)-1)*sizeof((_kmact)->entry[0]))

/*! emulate sizeof() for a kernel mac mib - using entries of user mac mib */
ci_inline size_t
cicp_mac_kmib_size(const cicp_mac_mib_t *mact, const cicp_mac_kmib_t *kmact)
{   return CICP_MAC_KMIB_SIZE(kmact, cicp_mac_mib_rows(mact));
}


/*----------------------------------------------------------------------------
 * kernel routing MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

/*! Much of the information in the routing table is a subset of the information
 *  in the user-visible fwd table.  This MIB is therefore implemented over two
 *  tables - one defined by cicp_fwd_row_t and the one defined here.
 */
typedef struct cicp_route_kmib_s cicp_route_kmib_t;

/* row index type: cicp_route_rowid_t; */
/* #define CICP_ROUTE_ROWID_BAD ... */

typedef struct {
    cicpos_route_row_t sync;  /*< synchronization support information */
} cicp_route_kernrow_t;

/* Note: free status implied by free status of the same row in fwd table */

/*! emulating an "allocated" field in a route row: set it to "unallocated" */
ci_inline void
cicp_route_row_free(cicp_route_kernrow_t *krow, cicp_fwd_row_t *row)
{   (void)krow;
    cicp_fwd_row_free(row);
}

/*! emulating an "allocated" field in a route row: read whether allocated */
ci_inline int /* bool */
cicp_route_row_allocated(const cicp_route_kernrow_t *krow,
			 const cicp_fwd_row_t *row)
{   (void)krow;
    return cicp_fwd_row_allocated(row);
}


struct cicp_route_kmib_s
{
  cicp_route_kernrow_t *entry;
  /*< allocated entries marked in_use in the user-mode forwarding info
   * table, ordered in terms of in_use then source prefix len -
   * completely resorted on write 
   */

  ci_uint16 rows_max;
} /* cicp_route_kmib_t */;



/*----------------------------------------------------------------------------
 * kernel access point MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

typedef struct cicp_llap_kmib_s cicp_llap_kmib_t;

/* row index type: cicp_llap_rowid_t; */
/* #define CICP_LLAP_ROWID_BAD ... */
/* #define CICP_LLAP_NAME_MAX  ... */

typedef struct  { 
    /* ci_uint32 metric; */     /*< a relaying cost associated with this i/f */
    ci_ifid_t ifindex;          /*< key: O/S index of this layer 2 interface */
    ci_mtu_t mtu;		/*< IP Maximum Transmit Unit for this i/f */
    ci_uint8 /* bool */ up;     /*< if true, this interface is up */
    char name[CICP_LLAP_NAME_MAX+1]; /*< interface name e.g. eth0 */
    /* the following fields are only valid in level5 interfaces */
    ci_hwport_id_t hwport;      /*< hardware port & NIC of interface */
    ci_int16 bond_rowid;        /*< bond table row id */
    ci_int16 vlan_rowid;        /*< VLAN master LLAP rowid */

    ci_mac_addr_t mac;		/*< MAC address of access point */ 
    cicp_encap_t encapsulation; /*< encapsulation used on this i/f */
    cicpos_llap_row_t sync;     /*< O/S synchronization info */
} cicp_llap_row_t;


/*! Retrieve source information relevant to a given access point
 *  - system call implementation: see user header for documentation
extern int 
cicp_llap_retrieve(ci_netif *netif, ci_ifid_t ifindex, ci_mtu_t *out_mtu,
		   ci_hwport_id_t *out_hwport, ci_mac_addr_t *out_mac)
 */

    
/*! emulating an "allocated" field in a llap row: set it to "unallocated" */
ci_inline void
cicp_llap_row_free(cicp_llap_row_t *row)
{    row->mtu = 0;
}

/*! emulating an "allocated" field in a llap row: set it to "unallocated" */
ci_inline int /* bool */
cicp_llap_row_allocated(const cicp_llap_row_t *row)
{   return (row->mtu > 0);
}

/*! emulating an "hasnic" field in a llap row: read whether our NIC */
ci_inline int /* bool */
cicp_llap_row_hasnic(const cicp_ul_mibs_t* user, const cicp_llap_row_t *row)
{
  return row->hwport != CI_HWPORT_ID_BAD;
}

/*! emulating an "up" field in a llap row: read whether interface is up */
ci_inline int /* bool */
cicp_llap_row_isup(const cicp_llap_row_t *row)
{    return row->up;
}

/*! emulating an "up" field in a llap row: set it to up (true) or down */
ci_inline void
cicp_llap_row_set_updown(cicp_llap_row_t *row, int /* bool */ updown)
{    row->up = (ci_uint8)updown;
}

struct cicp_llap_kmib_s
{   
  ci_verlock_t     version;      /*< incremented whenever table changed */
  cicp_llap_row_t* llap;
  ci_uint16        rows_max;
} /* cicp_llap_kmib_t */;


/*----------------------------------------------------------------------------
 * kernel IP interface MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

typedef struct cicp_ipif_kmib_s cicp_ipif_kmib_t;

/* row index type: cicp_ipif_rowid_t */
/* #define CICP_IPIF_ROWID_BAD ... */

typedef struct
{   ci_ip_addr_net_t bcast_ip;  /*< broadcast IP address, 0 if not set */
    ci_ip_addr_net_t net_ip;    /*< network own address */
    ci_ip_addrset_t  net_ipset; /*< network IP address set specification */
    ci_ifid_t        ifindex;   /*< O/S index of link layer interface */
    ci_int16         bond_rowid; /*< Bond table rowid if onloadable bond */
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


/*! Type of callback function when ipif table is updated
 *
 * \param onloadable_port non-zero if port for this address is accessible from 
 *                        this stack
 * \param net_ip          network own address 
 * \param net_ipset       network IP address set specification (e.g. netmask)
 * \param net_bcast       network broadcast address
 * \param arg             registration parameter
 *
 * Functions of this type are called back after registration when the IP
 * interfaces table has a row added or deleted.
 *
 * When added \c net_ip and \c net_ipset identify the IP address that is
 * being added, and when deleted they identify the one being deleted.
 *

 */
typedef void
cicpos_ipif_event_fn_t(ci_ip_addr_net_t net_ip, ci_ip_addrset_t  net_ipset,
		       ci_ip_addr_net_t net_bcast, ci_ifid_t ifindex, 
                       void *arg);

typedef struct
{   cicpos_ipif_event_fn_t *add_fn;
    cicpos_ipif_event_fn_t *delete_fn;
    void                   *arg;
    int id; /* used to track if the add has been called */
} cicpos_ipif_callback_registration_t;

ci_inline int /* bool */
cicp_ipif_callback_allocated(const cicpos_ipif_callback_registration_t *row)
{   return NULL != row->add_fn;
}

ci_inline void
cicp_ipif_callback_free(cicpos_ipif_callback_registration_t *row)
{   row->add_fn = NULL;
    row->delete_fn = NULL;
    row->arg = NULL;
}

typedef ci_uint8 cicpos_ipif_callback_handle_t;

typedef struct
{   cicpos_ipif_callback_registration_t reg[1]; /*< callback registrations */
} cicpos_ipif_callbacks_t;

typedef struct
{   cicpos_ipif_callbacks_t callback;
} cicpos_ipif_mib_t;

struct cicp_ipif_kmib_s 
{  
  ci_verlock_t      version;      /*< incremented whenever table changed */
  cicpos_ipif_mib_t sync;         /*< fields for O/S synch support */
  cicp_ipif_row_t   *ipif;
  ci_uint16         rows_max;
} /* cicp_ipif_kmib_t */;



/*----------------------------------------------------------------------------
 * kernel hardware port MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <onload/cplane.h>
*/

typedef struct cicp_hwport_kmib_s cicp_hwport_kmib_t;

typedef struct
{   ci_mtu_t max_mtu;           /*< hardware administered MTU on this port */
} cicp_hwport_row_t;


/*! emulating an "allocated" field in a hwport row: set it to "unallocated" */
ci_inline void
cicp_hwport_row_free(cicp_hwport_row_t *row)
{   row->max_mtu = 0;
}

/*! emulating an "allocated" field in a hwport row: read whether allocated */
ci_inline int /* bool */
cicp_hwport_row_allocated(const cicp_hwport_row_t *row)
{   return (row->max_mtu > 0);
}


typedef struct 
{   ci_mtu_t          mtu; /* what's this for?? */
    cicp_hwport_row_t port;
} cicp_hwdev_row_t;


struct cicp_hwport_kmib_s
{   cicp_hwdev_row_t nic[CI_HWPORT_ID_MAX + 1];
} /* cicp_hwport_kmib_t */;



/*----------------------------------------------------------------------------
 * Control Plane kernel-visible information 
 *---------------------------------------------------------------------------*/


typedef ci_contig_shmbuf_t cicp_mib_shared_t;


/*! Type for kernel driver data required for access through a netif */
struct cicp_mibs_kern_s
{   cicp_ul_mibs_t      user;		  /*< user-visible shared MIB info */
    cicp_mib_shared_t   mac_shared;       /*< shared area holding mac_utable */
    cicp_mib_shared_t   fwdinfo_shared;   /*< shared area for fwdinfo_utable */
    cicp_mib_shared_t   bondinfo_shared;  /*< shared area for bondinfo_utable */
    ci_irqlock_t        lock;             /*< shared by all kernel MIBs */
    cicp_mac_kmib_t    *mac_table;        /*< kernel-visible part of mac MIB */
    cicp_route_kmib_t  *route_table;      /*< kernel-visible part of fwdinfo */
    cicp_ipif_kmib_t   *ipif_table;       /*< IP interfaces MIB cache */
    cicp_llap_kmib_t   *llap_table;       /*< Link Access Point MIB cache */
    cicp_hwport_kmib_t *hwport_table;     /*< Hardware port MIB */
    cicp_stat_t         stat;             /*< control Plane Statistics */
} /* cicp_mibs_kern_t */;

/* typedef struct cicp_mibs_kern_s cicp_handle_t; */


#endif /* __CI_DRIVER_EFAB_CPLANE_TYPES_H__ */

/*! \cidoxg_end */
