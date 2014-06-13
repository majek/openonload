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
** \author  cgg
**  \brief  Control Plane type definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_types */

#ifndef __CI_INTERNAL_CPLANE_TYPES_H__
#define __CI_INTERNAL_CPLANE_TYPES_H__

/*----------------------------------------------------------------------------
 * Headers
 *---------------------------------------------------------------------------*/

#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>


/*----------------------------------------------------------------------------
 * Configuration
 *---------------------------------------------------------------------------*/

#ifdef __ci_driver__

typedef struct cicp_mibs_kern_s cicp_handle_t;
#define CICP_MIBS(handle_kernel) (handle_kernel)
#define CICP_DRIVER_HANDLE(netif) 0

#else

typedef struct ci_netif_s cicp_handle_t;
#define CICP_MIBS(handle_netif) ((handle_netif)->cplane.cp_mibs)
#define CICP_DRIVER_HANDLE(netif) (ci_netif_get_driver_handle(netif))

#endif /* __ci_driver__ */


/*----------------------------------------------------------------------------
 * Reference types
 *---------------------------------------------------------------------------*/


/* O/S dependent types */






/*! type for a Unix ID for an IP Interface (ifindex) */
typedef ci_int16 _cicpos_ifid_t;

#define _CICPOS_IFID_PRINTF_FORMAT "%02d"

#define _CICPOS_IFID_BAD ((_cicpos_ifid_t)(-1))



/* non-O/S dependent types */

/*! Possible return codes between cicp_user_retrieve and cicp_user_defer
    if these codes have their least significant bit set it may be worth
    re-trying the operation
 */
typedef enum
{  retrrc_success = 0,/* call was successful */
   retrrc_nomac   = 1,/* no mac found, deferred retrieval of MAC info needed */
   retrrc_noroute = 2,/* route not found */
   retrrc_alienroute = 3, /* route found but is not via our interfaces */
   retrrc_localroute = 4, /* destination is local address of the host */ 
} cicpos_retrieve_rc_t;


#define CICPOS_RETRRC(rc, reqs)    ((rc) | (reqs))
#define CICPOS_RETRRC_RC(retrrc)   ((retrrc) & 0x00FF)
#define CICPOS_RETRRC_REQS(retrrc) ((retrrc) & 0xFF00)

#define CICPOS_RETRRC_RCSTR(rc) \
        ((rc) == retrrc_success? "success":                                \
         (rc) == retrrc_nomac? "MAC currently unknown":                    \
         (rc) == retrrc_noroute? "no route known to IP address":           \
         (rc) == retrrc_alienroute? "non-EtherFabric route":               \
         (rc) == retrrc_localroute? "loopback route":                      \
         "<unknown forwarding return code>")


/* sub-second unspecified epoch timer value with max value of at least 20min */
typedef ci_uint32 ci_subsec_time_t;


/*! an Ip network prefix length */
typedef ci_uint8 cicp_prefixlen_t;
#define CICP_PREFIXLEN_BAD ((cicp_prefixlen_t)0xffu)

/* Note on XXXXXXX_BAD macros:
 *    these are usually named in upper case after the type (less its final _t)
 *    they are chosen to provide a good "uninitialized" value for the type.
 *    Where possible (i.e. not always) they are "impossible" values
 */

/*! type for a network-represented IP address ("bigendian" - a.b.c.d a=lsb) */
typedef ci_uint32 ci_ip_addr_t;

/*! type for a network-represented IP address mask ("host endian" - on a.b.c.d
 *  0xff000000 masks 'a')
 */
typedef ci_uint32 ci_ip_mask_t;

/*! Convert a ci_ip_mask_t into ci_ip_addr_t byte ordering */
#define CI_IP_ADDR_OF_MASK(ref_ip, ref_mask)   \
        (*(ref_ip) = CI_BSWAP_BE32(*ref_mask)) 

#define CI_IP_ADDR_BAD ((ci_ip_addr_t)0)
/* warning: really there are no bad values available! use this with care */

/* The following macros are used to help enable an easy transition to IPv6
   in the future - they all work on references to IP addresses instead of
   assuming that the addresses will fit into a single word.
   Note that the compiler will generally optimize out the sequences
   these macros tend to generate, such as "*(&ip1) = *(&ip2)" to "ip1 = ip2".
*/

/*! Copy one address to another */
#define CI_IP_ADDR_SET(ref_ipto, ref_ipfrom) \
        *(ref_ipto) = *(ref_ipfrom)

/*! Return TRUE if addresses are equal */
#define CI_IP_ADDR_EQ(ref_ip1, ref_ip2) \
        (*(ref_ip1) == *(ref_ip2))

/*! Generate a 32-bit hash from the IP address */
#define CI_IP_ADDR_HASH32(ref_ip) \
        (*(ref_ip))

/*! Test if address is an IP broadcast address */
#define CI_IP_ADDR_IS_BROADCAST(ref_ip) \
        (*(ref_ip) == 0xffffffffu)

/*! Test if address is an empty IP broadcast */
#define CI_IP_ADDR_IS_EMPTY(ref_ip) \
        (*(ref_ip) == 0u)

/*! Test if address is an empty IP broadcast */
#define CI_IP_ADDR_SET_EMPTY(ref_ip) \
        *(ref_ip) = 0u

/*! Test if address is an IP multicast address */
#define CI_IP_ADDR_IS_MULTICAST(ref_ip) \
        CI_IP_IS_MULTICAST(*(ref_ip))

/*! Test if address is an IP local loopback address */
#define CI_IP_ADDR_IS_LOOPBACK(ref_ip) \
        CI_IP_IS_LOOPBACK(*(ref_ip))

/*! type for a network represented IP address */
typedef ci_uint32 ci_ip_addr_net_t; /* intended to be stored big endian */
#define CI_IP_IPADDR_NET_BAD ((ci_ip_addr_net_t)0)
/* warning: not always bad! use with care */

/*! type used to identify "special" IP addresses */
typedef union {
    struct {
        unsigned is_broadcast:1, /* is an IPIF broadcast address */
	         is_ownaddr:1,   /* is an IPIF home address */
		 is_netaddr:1;   /* is an IPIF subetwork address */
    } bits;
    ci_uint32 bitsvalue; /* zero when none of the bits are set */
} ci_ip_addr_kind_t;

#define CI_IP_ADDR_KIND_VALUE_BAD (-1)



/*! type used when specifying a set of addresses from an IP address */
typedef cicp_prefixlen_t ci_ip_addrset_t;

#define CI_IP_ADDRSET_PRINTF_FORMAT "%u"
#define CI_IP_ADDRSET_PRINTF_ARGS(x) x

#define CI_IP_ADDRSET_BAD CICP_PREFIXLEN_BAD
#define CI_IP_ADDRSET_UNIVERSAL 32

/*! set ci_ip_addr_t to the mask implied by the ci_ip_addrset_t */
#define CI_IP_SET_MASK(ref_ipmask_he, addrset) \
        (*(ref_ipmask_he) = ci_ip_prefix2mask(addrset))

/*! TRUE if address set of ipmask1 is wholely included in those of ipmask2 */
#define CI_IP_MASK_INCLUDES(ref_ipmask1, ref_ipmask2) \
        ((*(ref_ipmask1) & *(ref_ipmask2)) == *(ref_ipmask1))

/*! TRUE if address set of addrset1 is wholely included in those of addrset2 */
#define CI_IP_ADDRSET_INCLUDES(addrset1, addrset2) \
        ((addrset1) <= (addrset2))

/*! TRUE if i1 and ip2 share the same network as defined by addrset */
#define CI_IP_ADDR_SAME_NETWORK(ip1_be, ip2_be, addrset) \
        (!((*(ip1_be) ^ *(ip2_be)) &                     \
	   CI_BSWAP_BE32(ci_ip_prefix2mask(addrset))))

/*! Set an IP address to the ipset subnet part of another IP address */
#define CI_IP_ADDR_SET_SUBNET(ref_subnetaddr, ref_ipaddr_he, addrset) \
        *(ref_subnetaddr) = ((*(ref_ipaddr_he) &                      \
	                     CI_BSWAP_BE32(ci_ip_prefix2mask(addrset))))

/*! Set an IP address to the "all ones" broadcast address of a net/addrset */
#define CI_IP_ADDR_SET_BCAST(ref_bcastaddr, ref_ipnet_he, addrset)  \
        *(ref_bcastaddr) = ((*(ref_ipnet_he) |                      \
	                     ~CI_BSWAP_BE32(ci_ip_prefix2mask(addrset))))


/*! type for a locally represented MAC address */
typedef ci_uint8 ci_mac_addr_t[6];

/*! Copy one address to another */
#define CI_MAC_ADDR_SET(ref_macto, ref_macfrom) \
        memcpy(ref_macto, ref_macfrom, sizeof(ci_mac_addr_t))

/*! Copy one address to another */
#define CI_MAC_ADDR_SET_EMPTY(ref_mac) \
        memset(ref_mac, 0, sizeof(ci_mac_addr_t))

/*! Copy one address to another */
#define CI_MAC_ADDR_EQ(ref_mac1, ref_mac2) \
        (0 == memcmp(ref_mac1, ref_mac2, sizeof(ci_mac_addr_t)))

/*! Test for all zero bytes */
#define CI_MAC_ADDR_IS_EMPTY(mac) \
        (((char *)mac)[0]==0 && ((char *)mac)[1]==0 && ((char *)mac)[2]==0 && \
	 ((char *)mac)[3]==0 && ((char *)mac)[4]==0 && ((char *)mac)[5]==0)

/*! Test for standard MAC broadcast address */
#define CI_MAC_ADDR_IS_BROADCAST(mac) \
        (((unsigned char *)mac)[0]==0xff && ((unsigned char *)mac)[1]==0xff &&\
         ((unsigned char *)mac)[2]==0xff && ((unsigned char *)mac)[3]==0xff &&\
	 ((unsigned char *)mac)[4]==0xff && ((unsigned char *)mac)[5]==0xff)

/*! type for an O/S ID for a Link Layer Access Point Interface */
typedef _cicpos_ifid_t ci_ifid_t;

#define CI_IFID_BAD _CICPOS_IFID_BAD
#define CI_IFID_ALL ((ci_ifid_t)(-2))

#define CI_IFID_PRINTF_FORMAT _CICPOS_IFID_PRINTF_FORMAT
#define CI_IFID_PRINTF_ARGS(arg) arg 

/*! type for a Maximum Transmission Unit */
typedef ci_uint16 ci_mtu_t;

#define CI_MTU_BAD (0)


/*----------------------------------------------------------------------------
 * Reference: Etherfabric Port IDs
 *---------------------------------------------------------------------------*/

/*! type for a local ID for a hardware port on a NIC */
typedef ci_uint8 ci_hwport_id_t;

#define CI_HWPORT_ID_MAX        (CI_CFG_MAX_REGISTER_INTERFACES - 1)

#define CI_HWPORT_ID(oo_nic_i)  (oo_nic_i)

#define CI_HWPORT_ID_BAD        ((ci_hwport_id_t) -1)

/*----------------------------------------------------------------------------
 * Reference: encapsulation specifications
 *---------------------------------------------------------------------------*/

/*! flags for types of encapsulation supported by the NIC */
enum {
  CICP_LLAP_TYPE_NONE   = 0,
  CICP_LLAP_TYPE_VLAN   = 1,
  CICP_LLAP_TYPE_BOND   = 2, 
  CICP_LLAP_TYPE_SFC    = 4,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER4 = 8,
  CICP_LLAP_TYPE_USES_HASH = 0x10,
  /* Distinguishes onloadable from not onloadable when hwport ==
   * CI_HWPORT_ID_BAD */
  CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT = 0x20
};
/* enum is always int, so no typedef for enum */
typedef ci_uint8 cicp_llap_type_t;

typedef struct {
  cicp_llap_type_t type;
  ci_uint16 vlan_id;
} cicp_encap_t;


#define CICP_ENCAP_NAME_FMT "%s%s%s%s%s%s"
#define CICP_ENCAP_NAME_MAX_LEN 28

#define cicp_encap_name(encap)                                  \
  (encap & CICP_LLAP_TYPE_SFC ? "SFC " : ""),                   \
    (encap & CICP_LLAP_TYPE_VLAN ? "VLAN " : ""),               \
    (encap & CICP_LLAP_TYPE_BOND ? "BOND " : ""),               \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER4 ? "L4 " : ""),     \
    (encap & CICP_LLAP_TYPE_USES_HASH ? "HASH " : ""),          \
    (encap & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT ? "COB " : "")


/*----------------------------------------------------------------------------
 * Version count locking
 *---------------------------------------------------------------------------*/

typedef struct
{   ci_verlock_value_t row_version;
    ci_int32           row_index;
} cicp_mib_verinfo_t;


/*----------------------------------------------------------------------------
 * MAC Address resolution MIB
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <ci/internal/cplane_ops.h>
*/

typedef ci_int32 cicp_mac_rowid_t;

#define CICP_MAC_ROWID_BAD (-1)

typedef struct
{   ci_verlock_t  version;   /*< incremented whenever this row is changed */
    ci_ip_addr_t  ip_addr;   /*< the entry's ip address */
    ci_mac_addr_t mac_addr;  /*< the ip address's MAC address */
    ci_uint16     rc;        /*< permanent return code associated with entry */
    ci_ifid_t     ifindex;   /*< access point on which the MAC addr is valid */
    ci_uint16     use_enter; /*< hash chain use count + enter kernel flag */
    ci_uint8      need_update; /*< ARP entry should be updated (STALE).
                                   This field is changed without
                                   version change */
#define CICP_MAC_ROW_NEED_UPDATE_SOON  1
#define CICP_MAC_ROW_NEED_UPDATE_STALE 2
} cicp_mac_row_t;


struct cicp_mac_mib_s
{   
  ci_uint32 rows_ln2;             /*< power of two, NB: can only increase */
  cicp_mac_row_t mostly_valid_row;  /*< special row -- mostly valid */
  /* This must be last in the structure, as we allocate extra trailing
   * space for the correct number of rows 
   */
  cicp_mac_row_t ipmac[1];
} /* cicp_mac_mib_t */;


/* Index of special row [mostly_valid_row] that does not contain an IP->MAC
 * mapping.  Its version is bumped whenever the forwarding or bond tables
 * are updated.
 */
#define CICP_MAC_MIB_ROW_MOSTLY_VALID  -1


typedef struct cicp_mac_mib_s cicp_mac_mib_t;


/* The MAC MIB is a table indexed by IP address.
   
   This is achieved by performing an initial hash dependent on the ARP table
   size and IP address and then rehashing dependent on the previous hash and
   the IP address.  The number of rehashes is limited.  Because entries can be
   deleted a lookup must incorporate at least this number of accesses before
   concluding that an IP address is not present.
   
   \todo: Implement:
   If the rehash limit is reached while locating a row for a new entry a table
   twice as large will be allocated and each existing entry will be hashed
   into the new table.
   
   Thus the limit defines both the maximum amount of work done while accessing
   the table and the rate at which the table will grow.
*/

/*! Type used to represent the continued validity of an address resolution */
typedef cicp_mib_verinfo_t cicp_mac_verinfo_t;

/*! Type required for user-mode operating system synchronization
 */
typedef struct cicpos_mac_row_sync_s cicpos_mac_row_sync_t;


/*----------------------------------------------------------------------------
 * per-route forwarding information table (user-visible)
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <ci/internal/cplane_ops.h>
*/

typedef struct cicp_fwdinfo_s cicp_fwdinfo_t;
typedef struct cicp_bondinfo_s cicp_bondinfo_t;

typedef ci_int32 cicp_fwd_rowid_t;

#define CICP_FWD_ROWID_BAD (-1)

typedef struct {
    unsigned is_ownaddr:1;    /* first hop supposed to be IPIF home address */
    unsigned tracking_llap:1; /* change IFID to correspond to first hop */
} ci_scope_t;

#define ci_scope_set_global(ref_scope) \
do {   (ref_scope)->is_ownaddr = 0;    \
    (ref_scope)->tracking_llap = 0;    \
} while(0)
#define ci_scope_set_host(ref_scope)   \
do {   (ref_scope)->is_ownaddr = 1;    \
    (ref_scope)->tracking_llap = 1;    \
} while(0)
#define ci_scope_set(ref_scope1, ref_scope2) \
   do { *(ref_scope1) = *(ref_scope2); } while(0)
#define ci_scope_eq(ref_scope1, ref_scope2)                         \
   ((ref_scope1)->is_ownaddr == (ref_scope2)->is_ownaddr        &&  \
    (ref_scope1)->tracking_llap == (ref_scope2)->tracking_llap)     \

typedef ci_uint8 cicp_metric_t;
typedef ci_uint8 cicp_ip_tos_t;

typedef struct
{   ci_ip_addr_t     destnet_ip;   /*< destination route base ip address */
    ci_ip_addr_t     first_hop;    /*< gateway, invalid if 0.0.0.0 */
    ci_ip_addr_t     pref_source;  /*< a source IP addr of dest_ifindex  */
    ci_ip_addr_t     net_ip;       /*< k* network ip address of output i/f */
    ci_ip_addr_t     net_bcast;    /*< k* broadcast IP address of output i/f */
    ci_ip_addrset_t  net_ipset;    /*< k* network IP addr set of output i/f */
    /* k* = used as cache of IPIF table for _addr_kind, not route _retrieve */
    ci_ip_addrset_t  destnet_ipset;/*< destination route address set spec. */
    ci_mac_addr_t    pref_src_mac; /*< MAC addr of pref_source */
    ci_ifid_t        dest_ifindex; /*< ifindex of output LL access point */
    cicp_encap_t     encap;        /*< NIC encapsulation used on this i/f */
    ci_mtu_t         mtu;          /*< the Maximum Transmit Unit on this i/f */
    cicp_ip_tos_t    tos;          /*< type of service */
    cicp_metric_t    metric;       /*< route metric; cost of route */
    ci_scope_t       scope;        /*< validity of destination information */
    /* The following fields and "encap" are only set if an EtherFabric i/f */
    ci_hwport_id_t   hwport;       /*< number of port & NIC */
    ci_int16         bond_rowid;   /*< rowid in bond table */
    ci_uint32        flags;
#define CICP_FLAG_ROUTE_MTU 0x1
} cicp_fwd_row_t;


struct cicp_fwdinfo_s
{  
  /*! Protects this table and the bond table. */
  ci_verlock_t   version;
  /*! Mapping from hwport to ifindex of the "base" llap.  A base llap is
   * either the hardware interface or a bond master if the hwport is
   * enslaved.
   */
  ci_ifid_t      hwport_to_base_ifindex[CI_CFG_MAX_REGISTER_INTERFACES];
  ci_uint16      rows_max;

  /* This must be last in the structure, as we allocate extra trailing
   * space for the correct number of rows 
   */
  cicp_fwd_row_t path[1];
} /* cicp_fwdinfo_t */;


/* The entries in path[] are ordered in terms of "allocated" then destnet_set
 * (longest first). The table will be completely re-sorted on updates to
 * destnet_set, destnet_ip, or "allocated" (i.e. insertion or deletion).
 */

/*----------------------------------------------------------------------------
 * oo_timesync state (user-visible)
 *---------------------------------------------------------------------------*/

struct oo_timesync {
  struct oo_timespec clock;         /* a recent value from system clock */
  ci_uint64 clock_made;             /* time (frc) clock was stored */
  ci_uint64 smoothed_ticks;         /* frc ticks during smoothed_ns time */
  ci_uint64 smoothed_ns;            /* ns to count smoothed_ticks */
  ci_uint64 update_jiffies;         /* time in jiffies of next update */
  ci_uint32 generation_count;       /* to synchronise with local copy */
};

/*----------------------------------------------------------------------------
 * bonding information table (user-visible)
 *---------------------------------------------------------------------------*/

#define CICP_BOND_ROW_TYPE_FREE 0
#define CICP_BOND_ROW_TYPE_MASTER 1
#define CICP_BOND_ROW_TYPE_SLAVE 2

#define CICP_BOND_ROW_NEXT_BAD -1

#define CICP_BOND_ROW_FLAG_MARK   1
#define CICP_BOND_ROW_FLAG_ACTIVE 2

/* XOR mode is currently unsupported due to difficulty getting link
 * status for XOR bonds - see Bug21239 
 */
#define CICP_BOND_MODE_ACTIVE_BACKUP 1
#define CICP_BOND_MODE_BALANCE_XOR   2
#define CICP_BOND_MODE_802_3AD       4

/* These should mirror BOND_XMIT_POLICY_* values in linux/if_bonding.h */
#define CICP_BOND_XMIT_POLICY_NONE   -1
#define CICP_BOND_XMIT_POLICY_LAYER2  0 
#define CICP_BOND_XMIT_POLICY_LAYER34 1
#define CICP_BOND_XMIT_POLICY_LAYER23 2

typedef struct {
  ci_int16 next;
  ci_ifid_t ifid;
  ci_uint8 type;
  union{ 
    struct {
      ci_hwport_id_t hwport;
      ci_int16 master;
      ci_uint8 flags;
    } slave;
    struct {
      ci_hwport_id_t active_hwport;
      ci_int8 n_slaves;
      ci_int8 n_active_slaves;
      ci_int8 mode;
      ci_int8 hash_policy;
      ci_int8 fatal;
    } master;
  };
} cicp_bond_row_t;


struct cicp_bondinfo_s
{   
  /* uses verlock from forwarding table */
  ci_uint16 rows_max;
  /* This must be last in the structure, as we allocate extra trailing
   * space for the correct number of rows 
   */
  cicp_bond_row_t bond[1];
} /* cicp_bondinfo_t */;


/*----------------------------------------------------------------------------
 * Information required for optionally available syncrhonization API
 *---------------------------------------------------------------------------*/

/*! types to use to to hold an indexes to the MIBs */

typedef ci_int16 cicp_llap_rowid_t;
#define CICP_LLAP_ROWID_BAD (-1)
#define CICP_LLAP_NAME_MAX 16

typedef ci_int16 cicp_ipif_rowid_t;
#define CICP_IPIF_ROWID_BAD (-1)

typedef cicp_fwd_rowid_t cicp_route_rowid_t;
#define CICP_ROUTE_ROWID_BAD CICP_FWD_ROWID_BAD


/*----------------------------------------------------------------------------
 * Control Plane information - entire user representation
 *---------------------------------------------------------------------------*/


/* The details of these data structures are not public - please do not
   refer to their content directly - use/define functions in
   <ci/internal/cplane_ops.h>
*/


/*! Type used to represent the continued validity of user information */
typedef cicp_mac_verinfo_t cicp_user_verinfo_t;

/*! Type for user-visible data required for access through in a netif */
typedef struct
{   cicp_mac_mib_t     *mac_utable;	  /*< user-visible part of MAC MIB */
    size_t              mac_mmap_len;     /*< size of table pages in bytes */
    cicp_fwdinfo_t     *fwdinfo_utable;   /*< user-visible fwdinfo table */
    size_t              fwdinfo_mmap_len; /*< size of table pages in bytes */
    cicp_bondinfo_t    *bondinfo_utable;  /*< user-visible bondinfo table */
    size_t              bondinfo_mmap_len;/*< size of table pages in bytes */
    struct oo_timesync *oo_timesync;    /*< user-visible timesync state */
} cicp_ul_mibs_t;

/*! Non-opaque structure for user-visible information */
typedef struct
{   cicp_ul_mibs_t      user;		  /*< user-visible shared MIB info */
} cicp_mibs_user_t;


/*! Opaque structure for kernel-visible information */
typedef struct cicp_mibs_kern_s cicp_mibs_kern_t;


/*! Type of per-netif data held about the control plane */
typedef struct
{
#ifdef __ci_driver__
    cicp_mibs_kern_t       *cp_mibs;  /* read-write access */
#else
    const cicp_mibs_user_t *cp_mibs;  /* read-only access */
    /* Driver code gets the benefit of a single global instance of the
       tables, but this user-mode code needs its own instance */
    cicp_mibs_user_t        user_mibs;
#endif
} cicp_ni_t;



/*! Type of data required for allocation in shared netif_state */ 
typedef struct {
  /* alignment helps ensure type has the same size in 32 & 64 bit contexts */
  ci_uint32 mac_mmap_len;
  ci_uint32 fwdinfo_mmap_len;
  ci_uint32 bondinfo_mmap_len;
} cicp_ns_mmap_info_t;


#endif /* __CI_INTERNAL_CPLANE_TYPES_H__ */

/*! \cidoxg_end */
