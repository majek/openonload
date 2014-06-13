/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
**  \brief  Control Plane O/S protocol support definitions
**   \date  2005/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane_prot */

#ifndef __CI_DRIVER_EFAB_CPLANE_PROT_H__
#define __CI_DRIVER_EFAB_CPLANE_PROT_H__

#include <ci/compat.h>
#include <ci/internal/cplane_types.h>
#include <ci/net/arp.h>


/*! This file provides definitions are specific to given address resolution
 *  scenario.  For example two versions of this header may be used to deal
 *  with explicit ARP protocols and with "raw" socket ARP use.
 *
 *  In the (distant?) future ICMPv6 support may be added here.
 *
 *  The prefix cicppl is used for definitions in this header:
 *       ci - our main prefix
 *       cp - control plane
 *       pl - protocols
 */

/*----------------------------------------------------------------------------
 * Configuration
 *---------------------------------------------------------------------------*/

#define CICPPL_PKTBUF_COUNT 128 /*< number of deferred MAC-requiring packets */



/*----------------------------------------------------------------------------
 * O/S-specific Address Resolution MIB Data types
 *---------------------------------------------------------------------------*/

/* The details of these data structures are not public - please do not
   refer to their content directly - use the functions defined in
   <onload/cplane.h>
*/


typedef struct {
    ci_ip_addr_t ip;
    ci_uint16 id;
    ci_uint16 tx_seq_next;
    ci_uint8 rx_type;
    ci_uint8 rx_code;
    ci_uint16 rx_seq;
    ci_uint8 rx_valid;
} cicppl_client_t;


/*----------------------------------------------------------------------------
 * O/S-specific Operations
 *---------------------------------------------------------------------------*/

/*! Initialize any driver-global O/S specific protocol control plane state */
extern int /* rc */
cicpplos_ctor(cicp_mibs_kern_t *control_plane);

/*! Finalize any driver-global O/S specific protocol control plane state */
extern void
cicpplos_dtor(cicp_mibs_kern_t *control_plane);

/*! Request IP resolution and queue the ip packet that triggered it
 *  See the definition of cicppl_pktbuf_pend_send 
 */
extern int /*rc*/
cicpplos_pktbuf_defer_send(const cicp_handle_t *control_plane, 
			   ci_ip_addr_t ip, int buf_pktid, ci_ifid_t ifindex);

/*----------------------------------------------------------------------------
 * Pooled packet buffer support Operations
 *---------------------------------------------------------------------------*/

typedef struct cicp_bufpool_s cicp_bufpool_t;

/*! Check that a packet buffer ID is valid */
ci_inline int /* bool */
cicppl_pktbuf_is_valid_id(int id)
{   return (id >= 0 && id < CICPPL_PKTBUF_COUNT);
}

/*! Return address of the packet referred to by a packet buffer ID  */
extern ci_ip_pkt_fmt *
cicppl_pktbuf_pkt(cicp_bufpool_t *pool, int id);

/*! Return EtherFabric visible address of a packet buffer ID
 *  This function is implemented only in a specific configuration  
 */
extern ci_uintptr_t
_cicppl_pktbuf_addr(cicp_bufpool_t *pool, int id);

#define cicppl_pktbuf_addr(pool, id) ((ef_addr)_cicppl_pktbuf_addr(pool, id))

/*! Return ID of a new packet buffer */
extern int
cicppl_pktbuf_alloc(cicp_bufpool_t *pool);

/*! Free a packet buffer referred to by its ID */
extern void
cicppl_pktbuf_free(cicp_bufpool_t *pool, int id);

/*!
 * Very restricted copying of an IP packet in to a packet buffer. 
 *
 * \param netif             owner of the source packet
 * \param netif_ip_pktid    Netif packet ID of the source packet
 * \param dst               destination packet from ARP table poll
 *
 * \retval 0                Success
 * \retval -EFAULT          Failed to convert efab address to kernel
 *                          virtual address
 *
 * \attention It's assumed that the segments after the first contain
 *            data from the pinned pages.
 *
 * Only data and its length is copied. No metadata are copied.
 *
 * This operation assumes that \c dst is from contiguous vm_alloc()'ed memory
 */
extern int
cicppl_ip_pkt_flatten_copy(ci_netif *ni, 
                           oo_pkt_p src_pktid, 
                           ci_ip_pkt_fmt *dst);

struct efrm_vi; /* defined in ci/driver/efab/vi_resource_manager.h -
                       which we don't want to include here*/

/*! Initialize memory to hold deferred packets awaiting MAC resolution */
extern int
cicppl_pktbuf_ctor(cicp_bufpool_t **out_pool, struct efrm_vi* evq_rs);

/*! Free any memory used to hold deferred packets awaiting MAC resolution */
extern void
cicppl_pktbuf_dtor(cicp_bufpool_t **ref_pool);

/* Packet pool locking: for the time being misuse the global control plane
   lock to lock access to the buffer pool */

#define CICP_BUFPOOL_LOCK(_pool, _code)	\
    CICP_LOCK(&CI_GLOBAL_CPLANE, _code)
    
#define CICP_BUFPOOL_CHECK_LOCKED(_pool) \
    CICP_CHECK_LOCKED(&CI_GLOBAL_CPLANE)





/*----------------------------------------------------------------------------
 * Address Resolution MIB Data Types
 *---------------------------------------------------------------------------*/


/*! Protocol-support module-specific per-entry information */
typedef struct
{   /*! e.g. a field that is valid when an ARP request has been sent and we are
     *  waiting for the reply. If arp_pending.arp_pktid == -1, then the
     *  no ARP packet is pending i.e. structure is unsused.
     */
    /* e.g. ci_arp_pending_t arp_pending; */
} cicppl_mac_row_t;


/*! Protocol-support module-specific per-table information */
typedef struct  
{   ci_uint32 flags;
    /*! queued data in driverlink, is used to batch queue packets in
     *  driverlink and then sending a single notification for the whole
     *  batch */
} cicppl_mac_mib_t;


/*----------------------------------------------------------------------------
 * Address Resolution MIB Operations
 *---------------------------------------------------------------------------*/


/*! Initialize protocol-specific section of Address Resolution MIB */
extern int /* rc */
cicppl_mac_kmib_ctor(cicppl_mac_mib_t *macprot);


/*! Initialize kernel resolution protocol state in a MAC MIB row */
extern void
cicppl_mac_kmib_row_ctor(cicppl_mac_row_t *prot_entry);


/*! Terminate kernel resolution protocol state of a MAC MIB entry
 *
 *  NB: control-plane lock is held while this function is being called
 */
extern void
cicppl_mac_kmib_row_dtor(cicppl_mac_row_t *prot_entry);


/*! Terminate kernel protocol-specific section of Address Resolution MIB */
extern void
cicppl_mac_kmib_dtor(cicppl_mac_mib_t *macprot);


/*! Handles an ARP packet from the net driver */
extern void 
cicppl_handle_arp_pkt(cicp_handle_t *control_plane,
		      ci_ether_hdr *ethhdr, ci_ether_arp *arp,
		      ci_ifid_t ifindex, int is_slave);


/*! Request IP resolution and queue the ip packet that triggered it
 *
 *  \param netif           a the network interface representation
 *  \param out_os_rc       an O/S error code - non-zero iff send known failed
 *  \param ref_ip          (location of) IP address of destination
 *  \param pkt_id          the ID of a packet buffer of data to be transmitted

 *  \return                TRUE iff the packet was accepted
 *
 *  The ownership of the packet remains with the caller if this function
 *  returns FALSE.
 */
extern int /*bool*/
cicppl_mac_defer_send(ci_netif *netif, int *out_os_rc,
		      ci_ip_addr_t ip, oo_pkt_p ip_pktid, ci_ifid_t ifindex);


/*----------------------------------------------------------------------------
 * Ping ICMP liveness control operations
 *---------------------------------------------------------------------------*/


/*! Handle an incomming ICMP packet
 *
 * \param control_plane   control plane handle (use CICP_HANDLE(netif))
 * \param ip_pkt          an IP packet containing an ICMP message
 * \param ip_len          number of bytes in the IP packet
 *
 * \returns               0 iff successful, negative return code otherwise
 */
extern int /* rc */
cicppl_handle_icmp(cicp_handle_t *control_plane,
		   const ci_ip4_hdr*, size_t ip_len);

/*----------------------------------------------------------------------------
 * Initialization and termination
 *---------------------------------------------------------------------------*/

/*! Initialize protocol-specific code */
extern int /* rc */
cicppl_ctor(cicp_handle_t *control_plane);

/*! Finalize protocol-specific code */
extern void
cicppl_dtor(cicp_handle_t *control_plane);





#endif /* __CI_DRIVER_EFAB_CPLANE_PROT_H__ */

/*! \cidoxg_end */

