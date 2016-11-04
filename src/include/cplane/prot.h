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
**  \brief  Control Plane O/S protocol support definitions
**   \date  2005/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane_prot */

#ifndef __CI_DRIVER_EFAB_CPLANE_PROT_H__
#define __CI_DRIVER_EFAB_CPLANE_PROT_H__

#ifndef __ci_driver__
#error "this header is driver-only"
#endif

#include <cplane/shared_types.h>
#include <cplane/prot_types.h>
#include <ci/compat.h>
#include <ci/net/arp.h>


#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility push(default)
#endif

/*----------------------------------------------------------------------------
 * O/S-specific Operations
 *---------------------------------------------------------------------------*/

/*! Request IP resolution and queue the ip packet that triggered it
 *  See the definition of cicppl_pktbuf_pend_send 
 */
extern int /*rc*/
cicpplos_pktbuf_defer_send(const cicp_handle_t *control_plane, 
			   ci_ip_addr_t ip, int buf_pktid, ci_ifid_t ifindex);

/*----------------------------------------------------------------------------
 * Pooled packet buffer support Operations
 *---------------------------------------------------------------------------*/

/*! Check that a packet buffer ID is valid */
ci_inline int /* bool */
cicppl_pktbuf_is_valid_id(cicp_bufpool_t *pool, int id)
{   return (id >= 0 && id < CPLANE_PROT_PKTBUF_COUNT);
}

/*! Return address of the packet referred to by a packet buffer ID  */
extern struct cicp_bufpool_pkt *
cicppl_pktbuf_pkt(cicp_bufpool_t *pool, int id);

/*! Return ID of a new packet buffer */
extern int
cicppl_pktbuf_alloc(cicp_bufpool_t *pool);

/*! Free a packet buffer referred to by its ID */
extern void
cicppl_pktbuf_free(cicp_bufpool_t *pool, int id);

extern cicp_bufpool_t *cicppl_pktpool;

/* Packet pool locking: for the time being misuse the global control plane
   lock to lock access to the buffer pool */

#define CICP_BUFPOOL_LOCK(_pool, _code)	\
    CICP_LOCK(&CI_GLOBAL_CPLANE, _code)
    
#define CICP_BUFPOOL_CHECK_LOCKED(_pool) \
    CICP_CHECK_LOCKED(&CI_GLOBAL_CPLANE)





/*----------------------------------------------------------------------------
 * Address Resolution MIB Operations
 *---------------------------------------------------------------------------*/

/*! Handles an ARP packet from the net driver */
extern void 
cicppl_handle_arp_pkt(cicp_handle_t *control_plane,
		      ci_ether_hdr *ethhdr, ci_ether_arp *arp,
		      ci_ifid_t ifindex, int is_slave);


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


#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility pop
#endif

#endif /* __CI_DRIVER_EFAB_CPLANE_PROT_H__ */

/*! \cidoxg_end */

