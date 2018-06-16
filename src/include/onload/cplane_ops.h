/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

/* Cplane related functions which are part of Onload */
#ifndef __ONLOAD_CPLANE_OPS_H__
#define __ONLOAD_CPLANE_OPS_H__

#include <cplane/cplane.h>
#include <ci/internal/ip.h>

#ifndef __KERNEL__
#include <onload/unix_intf.h>
#endif

#ifdef __KERNEL__

#define CICP_HANDLE(netif) (&CI_GLOBAL_CPLANE)

#else

#define CICP_HANDLE(netif) ((netif)->cplane)

#endif

/*----------------------------------------------------------------------------
 * System call interface
 *---------------------------------------------------------------------------*/

#ifdef __ci_driver__

#define CICP_SYSCALL extern
#define CICP_SYSBODY(_body) ;

#else /* not part of the driver - generate system calls */

#define CICP_SYSCALL ci_inline
#define CICP_SYSBODY(_body) { _body }

#endif /* __ci_driver__ */


/*! Defer transmission of packet until forwarding information re-established
 *
 * \param netif           a the network interface representation
 * \param retrieve_rc     the fault identified by \c cicp_fwd_retrieve
 * \param ref_os_rc       a corresponding O/S error code - later updated
 * \param pkt_id          the ID of a packet buffer of data to be transmitted
 *
 * This function is normally called if the return code from
 * \c cicp_fwd_retrieve indicates that deferred transmission is necessary
 * (e.g. following the retrieval of forwarding information).
 *
 * Some values of \c retrieve_rc are allowed to refer to an O/S return
 * code. When they do the O/S error code involved is passed in \c os_rc.
 *
 * If there was a reason for entry into the kernel indicated in \c retrieve_rc
 * this call will, as a side-effect, service that request.
 *
 * The destination address for the packet is embedded in the packet itself.
 *
 * \return                TRUE iff the packet was accepted/used 
 *
 * The return value does not indicate that the packet buffer will or will not
 * be transmitted - it defines whose responsibility it is to free/transmit the
 * packet.  If it is non-zero the packet continues to be the caller's
 * responsibility.
 *
 * If it is transmitted its transmission is likely to precede visible
 * availability of valid forwarding information in \c cicp_fwd_retrieve, but
 * this is not guaranteed.
 *
 */
CICP_SYSCALL int /* bool */
cicp_user_defer_send(ci_netif *netif, cicpos_retrieve_rc_t retrieve_rc,
		     ci_uerr_t *ref_os_rc, oo_pkt_p pkt_id,
                     ci_ifid_t ifindex, ci_uint32 next_hop)
CICP_SYSBODY(
    cp_user_defer_send_t op;

    op.retrieve_rc = retrieve_rc;
    op.os_rc       = *ref_os_rc;
    op.pkt         = pkt_id;
    op.ifindex     = ifindex;
    op.next_hop    = next_hop;

    oo_resource_op(ci_netif_get_driver_handle(netif),
                   OO_IOC_CP_USER_DEFER_SEND, &op);
    
    *ref_os_rc = op.os_rc;

    return op.rc;
)

#undef CICP_SYSBODY
#undef CICP_SYSCALL

#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility push(default)
#endif

/*!
 * Establish forwarding information.
 *
 * \param ni       The Onload stack
 * \param ipcache  The cached forwarding state
 * \param sock_cp  Per-socket inputs to the lookup
 *
 * Return value is in [ipcache->status], which will either be a value from
 * [cicpos_retrieve_rc_t], or -ve, in which case it is an error code.  The
 * -ve errors relate to the mac lookup, so imply that the route can be
 * accelerated.
 *
 *    retrrc_success: Can accelerate, and all forwarding info was valid
 *                    just before return.
 *
 *      retrrc_nomac: Can accelerate route, but do not currently have
 *                    destination MAC.  Per-route info other than the
 *                    outgoing interface is valid.
 *
 *    retrrc_noroute: No route to destination.
 *
 * retrrc_alienroute: Can't be accelerated.
 */
extern void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp) CI_HF;


/*! Update forwarding and mac info of [ipcache] from [from_ipcache].
 *
 * NB. This function does not take a complete copy of [from_ipcache].  It
 * only takes the fields that are updated by control plane lookup.  These
 * include:
 *
 * - mac_integrity
 * - freshness (invalidated)
 * - ip_saddr_be32
 * - status
 * - pmtus (invalidated)
 * - mtu
 * - ifindex
 * - intf_i
 * - hwport
 * - ether_offset
 * - mac addresses + vlan header
 */
extern void
cicp_ip_cache_update_from(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                          const ci_ip_cached_hdrs* from_ipcache);



ci_inline void
cicp_ipcache_vlan_set(ci_ip_cached_hdrs*  ipcache)
{
  if( ipcache->encap.type & CICP_LLAP_TYPE_VLAN ) {
    ci_uint16* vlan_tag = (ci_uint16*) ipcache->ether_header + 6;
    vlan_tag[0] = CI_ETHERTYPE_8021Q;
    vlan_tag[1] = CI_BSWAP_BE16(ipcache->encap.vlan_id);
    ipcache->ether_offset = 0;
  }
  else {
    ipcache->ether_offset = ETH_VLAN_HLEN;
  }
}

extern int
cicp_llap_ipif_check_onloaded(struct oo_cplane_handle* cp,
                              cicp_llap_row_t* llap, cicp_ipif_row_t* ipif,
                              void* data);
/*! Checks if the given ip address is both local and etherfabric.
 *  Returns 1 if it is, 0 if it isn't.
 *  If the address isn't found, it returns 0
 */
ci_inline int
cicp_user_addr_is_local_efab(ci_netif* ni, ci_ip_addr_t ip)
{ 
  return oo_cp_find_llap_by_ip(ni->cplane, ip,
                               cicp_llap_ipif_check_onloaded, ni);
}

extern int
cicp_ipif_check_ok(struct oo_cplane_handle* cp,
                   cicp_ipif_row_t* ipif, void* data);
ci_inline int /* bool */
cicp_user_is_local_addr(struct oo_cplane_handle *cplane,
			ci_ip_addr_t ip)
{
  return oo_cp_find_ipif_by_ip(cplane, ip, cicp_ipif_check_ok, NULL);
}

ci_inline int ci_hwport_check_onload(ci_hwport_id_t hwport,
                                     const cicp_encap_t *encap)
{
  return (hwport != CI_HWPORT_ID_BAD);
}


/*----------------------------------------------------------------------------
 * Control Plane initialization/termination 
 *---------------------------------------------------------------------------*/


#ifdef __ci_driver__

static inline struct cicppl_instance* cicppl_by_netif(ci_netif *netif)
{
  return &netif->cplane->cppl;
}

/*!
 * Very restricted copying of an IP packet in to a packet buffer. 
 *
 * \param netif             owner of the source packet
 * \param netif_ip_pktid    Netif packet ID of the source packet
 * \param dst               destination packet from ARP table pool
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
cicppl_ip_pkt_flatten_copy(ci_netif *ni, oo_pkt_p src_pktid,
                           struct cicp_bufpool_pkt* dst);

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


/*! Send IP packet via RAW socket.  Computes TCP/UDP checksum if possible */
extern int cicp_raw_ip_send(struct cicppl_instance* cppl,
                            const ci_ip4_hdr* ip, int len, ci_ifid_t ifindex,
                            ci_ip_addr_t next_hop);

#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility pop
#endif

#endif

#endif /* __ONLOAD_CPLANE_OPS_H__ */
