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
**  \brief  Control Plane operation definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_ops */

#ifndef __CI_INTERNAL_CPLANE_OPS_H__
#define __CI_INTERNAL_CPLANE_OPS_H__

#include <ci/internal/ip.h>          /* for ci_netif */
#include <ci/internal/cplane_types.h>/* types for user-available information */
#include <ci/internal/cplane_ops2.h>

#ifdef __ci_driver__
#include <onload/cplane_types.h>
#else
#include <onload/ul.h>
#endif

/*----------------------------------------------------------------------------
 * System call interface
 *---------------------------------------------------------------------------*/

#ifdef __ci_driver__

#define CICP_SYSCALL extern
#define CICP_SYSBODY(_body) ;
#define CICP_EXTENDED_INTERFACE 1

#else /* not part of the driver - generate system calls */

#define CICP_SYSCALL ci_inline
#define CICP_SYSBODY(_body) { _body }
#define CICP_EXTENDED_INTERFACE CI_CFG_CONTROL_PLANE_USER_SYNC

#endif /* __ci_driver__ */


#if CICP_EXTENDED_INTERFACE

#define CICP_OPTSYSCALL CICP_SYSCALL
#define CICP_OPTSYSBODY CICP_SYSBODY

#else

#define CICP_OPTSYSCALL extern
#define CICP_OPTSYSBODY(_body) ; /* won't be implemented */

#endif /* CICP_EXTENDED_INTERFACE */



#ifdef __cplusplus
extern "C" {
#endif


/*----------------------------------------------------------------------------
 * Hardware port MIB
 *---------------------------------------------------------------------------*/

/* Synchronization functions optionally made visible to the user */
    
/*! Register the ports associated with a new NIC
 *
 * \param cplane_handle   control plane handle (use CICP_HANDLE(netif))
 * \param hwport          number of NIC (starting from zero)
 * \param max_mtu         hardware limit on MTUs supported on this NIC
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_hwport_update(cicp_handle_t *cplane_netif,
                     ci_hwport_id_t hwport, ci_mtu_t max_mtu)
CICP_OPTSYSBODY(
    cp_hwport_update_t op;

    op.hwport = hwport;
    op.max_mtu = max_mtu;

    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_HWPORT_UPDATE, &op);
)
    

/*----------------------------------------------------------------------------
 * link layer access point interface MIB
 *---------------------------------------------------------------------------*/



CICP_SYSCALL int /* rc */
cicp_llap_find(const cicp_handle_t *cplane_netif, ci_ifid_t *out_ifindex,
	       ci_hwport_id_t port, const ci_uint16 vlan_id)
CICP_SYSBODY(
    cp_llap_find_t op;
    int rc;

    op.hwport = port;
    op.vlan_id = vlan_id;
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_LLAP_FIND, &op);

    if (rc == 0)
	*out_ifindex = op.ifindex_out;
    else
        *out_ifindex = CI_IFID_BAD;

    return rc;
)


/*!
 * Retrieve source information relevant to a given access point
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex         the link layer access point identifier
 * \param out_mtu         a place to store the access point's MTU
 * \param out_hwport      a place for the hardware port ID
 * \param out_mac         a place for the source MAC address
 * \param out_base_ifindex underlying interface if vlan
 * \param out_bond_rowid  the corresponding row in bond table
 *
 * \return                0 iff the call succeeded, error code otherwise
 *
 * None of the return values out_* are updated when a non-zero return is made.
 * If a zero return code is provided only non-NULL out_* values are updated.
 *
 * Note that both the NIC number and hardware port number can be found from the
 * hardware port ID.
 */
CICP_SYSCALL int /* rc */
cicp_llap_retrieve(const cicp_handle_t *cplane_netif, ci_ifid_t ifindex,
		   ci_mtu_t *out_mtu, ci_hwport_id_t *out_hwport,
		   ci_mac_addr_t *out_mac, cicp_encap_t *out_encap,
                   ci_ifid_t *out_base_ifindex, ci_int16* out_bond_rowid)
CICP_SYSBODY(
    cp_llap_retrieve_t op;
    int rc;

    op.ifindex = ifindex;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_LLAP_RETRIEVE, &op);
    
    if (rc == 0)
    {
	if (NULL != out_hwport)
            *out_hwport = op.hwport;
	if (NULL != out_mtu)
            *out_mtu = op.mtu;
	if (NULL != out_mac)
            memcpy(out_mac, op.mac, sizeof(*out_mac));
	if (NULL != out_encap)
            *out_encap = op.encap;
	if (NULL != out_base_ifindex)
            *out_base_ifindex = op.base_ifindex;
        if (NULL != out_bond_rowid)
            *out_bond_rowid = op.bond_rowid;
    }
    return rc;
)

/* Synchronization functions optionally made visible to the user */

/*! Import data into the link layer access point cache
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param out_rowid       a place to write the index of llap MIB row updated
 * \param ifindex         O/S index of this layer 2 interface
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param up              if true, this interface is up 
 * \param name            name of interface
 * \param ref_mac     	  MAC address of access point
 *
 * \return                FALSE iff no change was made
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /* rc */
cicp_llap_import(cicp_handle_t *cplane_netif,
		 cicp_llap_rowid_t *out_rowid,
		 ci_ifid_t ifindex,
		 ci_mtu_t mtu,
		 ci_uint8 /* bool */ up,
		 char *name,
		 ci_mac_addr_t *ref_mac)
CICP_OPTSYSBODY(
    cp_llap_import_t op;
    int rc;

    op.ifindex = ifindex;
    op.max_mtu = mtu;
    op.up = up;
    CI_MAC_ADDR_SET(op.mac, ref_mac);

    strncpy(op.name, name,
	    sizeof(op.name)-1);
    op.name[sizeof(op.name)-1] = '\0';
    
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_LLAP_IMPORT, &op);
    
    if (rc == 0)
        *out_rowid = op.rowid_out;
    
    return rc;
)


/*! Delete the link layer access point row with the given interface ID
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex         the O/S network access point to find in \c llapt
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_llap_delete(cicp_handle_t *cplane_netif, ci_ifid_t ifindex)
CICP_OPTSYSBODY((void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                                     OO_IOC_CP_LLAP_DELETE, &ifindex);
)

	

	
/*!
 * Retrieve link layer access point table information
 *
 * \param cplane_netif       the control plane handle, e.g. CICP_HANDLE(netif)
 * \param rowid              the index of the table row to be read
 * \param out_table_version  a place to put the LLAP table version
 * \param out_ifindex        a place for LLAP identifier
 * \param out_up             a place for whether the interface is up
 * \param out_encap          a place for whether the interface's encapsulation
 *
 * \return                0 iff the call succeeded, error code otherwise
 *
 * None of the return values out_* are updated when a non-zero return is made.
 * If a zero return code is provided only non-NULL out_* values are updated.
 *
 * The return code -EINVAL is returned if the given row number is invalid.
 *
 * This function, alongside cicp_retrieve can be used to determine the
 * content of the LLAP table.  Successive rows (starting at 0) are read until
 * an EINVAL return code is provided.  Rows with other return codes are
 * possible and indicate that the data for that row number is not valid.
 *
 * The table version number is returned.  Consistant data can be ensured by
 * re-reading if the version number is found to vary during the read.
 */
CICP_OPTSYSCALL int /* rc */
cicpos_llap_readrow(const cicp_handle_t *cplane_netif,
	            cicp_llap_rowid_t rowid,
	            ci_verlock_value_t *out_table_version,
	            ci_ifid_t *out_ifindex,
	            ci_uint8 /* bool */ *out_up,
	            cicp_encap_t *out_encap)
CICP_OPTSYSBODY(
    cp_llap_readrow_t op;
    int rc;

    op.rowinfo_index = rowid;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_LLAP_READROW, &op);
    
    if (rc == 0)
    {
	if (NULL != out_table_version)
            *out_table_version = op.table_version;
	if (NULL != out_encap)
            *out_encap = op.encap;
	if (NULL != out_ifindex)
            *out_ifindex = op.ifindex;
	if (NULL != out_up)
            *out_up = op.up;
    }
    return rc;
)


/*----------------------------------------------------------------------------
 * IP interface MIB
 *---------------------------------------------------------------------------*/


/*! return whether a supplied IP address is a special IP interface address
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ip              the IP address to check
 * \param out_addr_kind   a place to store the kind of IP address found
 *
 * This function returns a value in \c out_addr_kind that represents any
 * special status of the IP address provided.  Its value will be non-zero if
 * the address is a network address, a broadcast address or the home address on
 * any of the subnetworks associated with one of the machine's IP interface.
 */
CICP_SYSCALL int /* rc */
cicp_ipif_addr_kind(const cicp_handle_t *cplane_netif, ci_ip_addr_net_t ip,
		    ci_ip_addr_kind_t* out_addr_kind)
CICP_SYSBODY(
    cp_ipif_addr_kind_t op;
    int rc;

    op.ip_be32 = ip;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_IPIF_ADDR_KIND, &op);
    
    if (rc == 0)
        *out_addr_kind = op.addr_kind;
    
    return rc;
)


/* Synchronization functions optionally made visible to the user */


/*! Import data into the IP interface cache
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param out_rowid       a place to write the index of llap MIB row updated
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 * \param net_bcast       set of addresses around the base address
 *
 * \return                zero or an error code 
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /* rc */
cicpos_ipif_import(cicp_handle_t     *cplane_netif, 
		   cicp_ipif_rowid_t *out_rowid,
		   ci_ifid_t          ifindex,
		   ci_ip_addr_net_t   net_ip,
		   ci_ip_addrset_t    net_ipset,
		   ci_ip_addr_net_t   net_bcast,
		   ci_uint8           scope)
CICP_OPTSYSBODY(
    cp_ipif_import_t op;
    int rc;

    op.ifindex = ifindex;
    op.net_ip = net_ip;
    op.net_ipset = net_ipset;
    op.net_bcast = net_bcast;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_IPIF_IMPORT, &op);
    
    if (rc == 0)
        *out_rowid = op.rowid;
    return rc;
)



/*! Delete the IP interface row with the given set of subnet addresses
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_ipif_delete(cicp_handle_t   *cplane_netif, 
		   ci_ifid_t        ifindex,
		   ci_ip_addr_net_t net_ip,
		   ci_ip_addrset_t  net_ipset)
CICP_OPTSYSBODY(
    cp_ipif_delete_t op;

    op.ifindex = ifindex;
    op.net_ip = net_ip;
    op.net_ipset = net_ipset;

    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_IPIF_DELETE, &op);
)
	


/*!
 * Retrieve IP interfaces table information
 *
 * \param cplane_netif       the control plane handle, e.g. CICP_HANDLE(netif)
 * \param rowid              the index of the table row to be read
 * \param out_table_version  a place to put the LLAP table version
 * \param out_ifindex        a place for LLAP identifier
 * \param out_net_ip         a place for this machine's address on the subnet 
 * \param out_net_ipset      a place for the subnet's address range
 * \param out_net_bcast      a place for the subnet's broadcast address
 *
 * \return                0 iff the call succeeded, error code otherwise
 *
 * None of the return values out_* are updated when a non-zero return is made.
 * If a zero return code is provided only non-NULL out_* values are updated.
 *
 * The return code -EINVAL is returned if the given row number is invalid.
 *
 * This function can be used to determine the content of the IPIF table.
 * Successive rows (starting at 0) are read until an EINVAL return code is
 * provided.  Rows with other return codes are possible and indicate that the
 * data for that row number is not valid.
 *
 * The table version number is returned.  Consistant data can be ensured by
 * re-reading if the version number is found to vary during the read.
 */
CICP_OPTSYSCALL int /* rc */
cicpos_ipif_readrow(const cicp_handle_t *cplane_netif,
	            cicp_llap_rowid_t rowid,
	            ci_verlock_value_t *out_table_version,
	            ci_ifid_t *out_ifindex,
		    ci_ip_addr_t *out_net_ip,
		    ci_ip_addrset_t *out_net_ipset,
		    ci_ip_addr_t *out_net_bcast)
CICP_OPTSYSBODY(
    cp_ipif_readrow_t op;
    int rc;

    op.rowinfo_index = rowid;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_IPIF_READROW, &op);
    
    if (rc == 0)
    {
	if (NULL != out_table_version)
            *out_table_version = op.table_version;
	if (NULL != out_ifindex)
            *out_ifindex = op.ifindex;
	if (NULL != out_net_ip)
            *out_net_ip = op.net_ip;
	if (NULL != out_net_ipset)
            *out_net_ipset = op.net_ipset;
	if (NULL != out_net_bcast)
            *out_net_bcast = op.net_bcast;
    }
    return rc;
)



CICP_SYSCALL int
cicp_ipif_pktinfo_query(const cicp_handle_t *cplane_netif,
                        ci_netif            *netif,
                        oo_pkt_p             pktid,
                        ci_ifid_t            ifindex,
                        ci_ip_addr_t        *out_spec_addr)
CICP_SYSBODY(
    cp_ipif_pktinfo_query_t op;
    int rc;

    op.pktid = pktid;
    op.ifindex = ifindex;
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_IPIF_PKTINFO_QUERY, &op);

    *out_spec_addr = op.out_spec_addr;
    return rc;
)

/*!
 * Retrieve IP interfaces table information
 *
 * \param cplane_netif       the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex            OS ifindex to find
 * \param out_addr           local address of the interface
 *
 * \return                0 iff the call succeeded, error code otherwise
 *
 */
CICP_OPTSYSCALL int /* rc */
cicp_ipif_by_ifindex(const cicp_handle_t *cplane_netif,
	            ci_ifid_t ifindex, ci_ip_addr_t *out_addr)
CICP_OPTSYSBODY(
    cp_ipif_by_ifindex_t op;
    int rc;

    op.ifindex = ifindex;
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
			OO_IOC_CP_IPIF_BY_IFINDEX, &op);
    *out_addr = op.out_addr;
    return rc;
)



	
/*----------------------------------------------------------------------------
 * routing MIB
 *---------------------------------------------------------------------------*/

	
/* Synchronization functions optionally made visible to the user */

/*!
 * Ammend a currently existing route to a given set of IP addresses
 *
 * \param cplane_netif    control plane handle. e.g. CICP_HANDLE(netif)
 * \param dest_ip         the route set base IP address 
 * \param dest_set        the set of addresses based on \c dest_ip
 * \param next_hop_ip     the forwarding address to use on a match
 * \param ifindex         the link access point of the forwarding address
 * \param pref_source     the IP source address to use when transmitting 
 * \param hwport_id       the port on which the link access point is located
 *
 * \return                0 on success, error code otherwise
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /* rc */
cicp_route_import(cicp_handle_t      *cplane_netif,
		  cicp_route_rowid_t *out_rowid,
		  ci_ip_addr_t        dest_ip,
		  ci_ip_addrset_t     dest_ipset,
		  ci_ip_addr_t        next_hop_ip,
		  ci_ip_tos_t         tos,
		  cicp_metric_t       metric,
		  ci_ip_addr_t        pref_source,
		  ci_ifid_t           ifindex,
		  ci_mtu_t            mtu)
CICP_OPTSYSBODY(
    cp_route_import_t op;
    int rc;

    op.dest_ip = dest_ip;
    op.dest_ipset = dest_ipset;
    op.next_hop_ip = next_hop_ip;
    op.pref_source = pref_source;
    op.tos = tos;
    op.metric = metric;
    op.ifindex = ifindex;
    op.mtu = mtu;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_ROUTE_IMPORT, &op);
    
    if (rc == 0)
        *out_rowid = op.rowid;
    return rc;
)



/*! Remove a route 
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param dest_ip         the route set base IP address
 * \param dest_set        the set of addresses based on \c dest_ip
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_route_delete(cicp_handle_t     *cplane_netif, 
		    ci_ip_addr_t       dest_ip,
		    ci_ip_addrset_t    dest_ipset,
                    ci_ifid_t          dest_ifindex)
CICP_OPTSYSBODY(
    cp_route_delete_t op;

    op.dest_ip = dest_ip;
    op.dest_ipset = dest_ipset;

    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_ROUTE_DELETE, &op);
)


	

/*----------------------------------------------------------------------------
 * address resolution MIB
 *---------------------------------------------------------------------------*/



#ifdef NDEBUG
  #define CICP_MAC_MIB_ROW_VALID(cplane_netif,idx) do {} while(0)
#else
  #define CICP_MAC_MIB_ROW_VALID(cplane_netif,row) \
    do { \
      ci_assert_ge(ci_to_int((int)row), 0); \
      ci_assert_lt(ci_to_int((int)row), \
                   (int)cicp_mac_mib_rows(CICP_MIBS(cplane_netif)-> \
					  user.mac_utable))); \
    } while(0)
#endif



/*! Validate that an address resolution table entry is still current
 *
 * \param mact            the address resolution table
 * \param handle          the integrity handle
 *
 * \return                0 iff the entry is no longer valid
 */
ci_inline int /* bool */
cicp_mac_is_valid(const cicp_mac_mib_t *mact, 
                  const cicp_mac_verinfo_t *handle)
{
  ci_assert_ge(handle->row_index, CICP_MAC_MIB_ROW_MOSTLY_VALID);
  ci_assert_lt(handle->row_index, cicp_mac_mib_rows(mact));

  return mact->ipmac[handle->row_index].version == handle->row_version;
}


ci_inline void
cicp_mac_set_mostly_valid(const cicp_mac_mib_t *mact,
                          cicp_mac_verinfo_t *handle)
{
  handle->row_index = CICP_MAC_MIB_ROW_MOSTLY_VALID;
  handle->row_version = mact->ipmac[CICP_MAC_MIB_ROW_MOSTLY_VALID].version;
}


/*! Return a pointer to the MAC address of the MAC table entry identified
 *  by its row handle.
 *
 * \param mact            the address resolution table
 * \param handle          the integrity handle (not checked!)
 *
 * \return                A pointer to the MAC address
 *
 * You should check the validity of the provided handle after copying the
 * MAC address address returned and discard it if the pointer is invalid
 *
 * Note: this function is intended to be used only via the macro
 * \c cicp_mac_handle_mac_addr() below.
 */
ci_inline const ci_mac_addr_t *
_cicp_mac_handle_mac_addr(const cicp_mac_mib_t *mact,
                          const cicp_mac_verinfo_t *handle)
{   return (const ci_mac_addr_t *)mact->ipmac[handle->row_index].mac_addr;
}


#define cicp_mac_handle_mac_addr(cicp_handle, ver_handle) \
        _cicp_mac_handle_mac_addr(&CICP_MIBS(cicp_handle)->user.mac_utable), \
                                  ver_handle)



/*!
 * Locate a MAC address associated with the given IP address
 *
 * \param mact            the address resolution table
 * \param ifindex         the interface the IP and MAC address are relevant to
 * \param ip              the IP address being looked up
 * \param out_mac         a place to store the MAC address located
 * \param out_handle      a place to store the row and version of the entry
 *
 * \returnval             -EAGAIN if entry was locked or altered during access
 * \returnval             -EDESTADDRREQ if no MAC address was found
 * \returnval             0 if a MAC address for the IP address was found
 * \returnval             other values signal a permanent error with the lookup
 *
 * There may be more than one MAC address associated in the Address Resolution
 * MIB with the given IP address (e.g. at seperate link layer access points).
 * The MAC returned is simply "the first" such MAC address.
 *
 * If 0 is returned a MAC address is provided that was once associated with
 * the IP address.  The \c out_handle can be used to determine the subsequent
 * validity of the relationship between the IP and MAC addresses.
 */
extern int /* rc */
cicp_mac_get(const cicp_mac_mib_t *mact, ci_ifid_t ifindex,
             const ci_ip_addr_t ip, ci_mac_addr_t *out_mac,
	     cicp_mac_verinfo_t *out_handle);


/*!
 * Confirm that an address resolution table entry is known correct
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ver             ARP entry to update
 * \param confirm         confirm or send an ARP request?
 *
 * Update STALE entry in ARP table.  If we do not know if the entry is
 * really valid, tell OS to re-validate it via ARP request.
 * If we know the entry is valid (UDP MSG_CONFIRM or TCP ACK received),
 * jusr tell OS the entry is OK.
 */
CICP_SYSCALL void
cicp_mac_update(ci_netif *netif, cicp_mac_verinfo_t *ver, 
                ci_ip_addr_t ip, const ci_mac_addr_t *mac, 
                int confirm)
CICP_SYSBODY(
    cp_mac_update_t op;

    op.ver = *ver;
    op.ip = ip;
    ci_assert(sizeof(op.mac) >= sizeof(*mac));
    memcpy(&op.mac, mac, sizeof(op.mac));
    op.confirm = confirm;

    (void)oo_resource_op(CICP_DRIVER_HANDLE(netif),
                         OO_IOC_CP_MAC_UPDATE, &op);
)


/* Synchronization functions */
    

/* Find an allocated MAC entry holding the given IP address
 *
 * \param mact            the address resolution table
 * \param ip              the IP address being looked for
 * \param out_ver         the version of the MAC table entry used
 *
 * \return                \c CICP_MAC_ROWID_BAD iff not found, index otherwise
 *
 * This function returns the index of the MAC entry which will either be
 * \c CICP_MAC_ROWID_BAD or will be a value guaranteed to be within the bounds
 * of the address resolution table.
 *
 * The version number of the entry at that index is returned.  This is the
 * version of the data just prior to the establishment that the entry was
 * correct.  If the entry's version number is subsequently found to be
 * different the index is no longer valid.
 *
 * The version number returned never indicates that the MAC entry is currently
 * being updated because this check is implicit in the
 * \c cicp_mac_row_allocated check.
 *
 * Note that the version number will be overwritten even if
 * \c CICP_MAC_ROWID_BAD is returned - such values should be ignored.
 *
 * No locking of the MAC table is used
 */
extern cicp_mac_rowid_t
cicpos_mac_find_ip(const cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		   ci_ip_addr_t ip, ci_verlock_value_t *out_ver);



/* synchronization functions optionally made visible to the user */


/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *
 * \param cplane_netif    control plane handle (use CICP_HANDLE(netif))
 * \param out_rowid       the row number & version used for the mapping
 * \param ifindex         the LLAP interface handle
 * \param nexthop_ip      an IP address on a the LLAP interface
 * \param mac             the MAC address for the IP address
 *
 * \return                0 or error code if control plane uninitialized
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /*rc*/
cicp_mac_set(cicp_handle_t *cplane_netif,
	     cicp_mib_verinfo_t *out_rowinfo,
             ci_ifid_t ifindex,
             ci_ip_addr_net_t nexthop_ip,
             const ci_mac_addr_t *mac)
CICP_OPTSYSBODY(
    cp_mac_set_t op;
    int rc;

    CI_USER_PTR_SET(op.os_sync_ptr, NULL);
    /* NULL == sync from protocol */
    op.ifindex = ifindex;
    op.ip_be32 = nexthop_ip;
    ci_assert(sizeof(op.mac) >= sizeof(*mac));
    memcpy(&op.mac, mac, sizeof(op.mac));
    
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_MAC_SET, &op);
    if (rc == 0)
	*out_rowinfo = op.rowinfo;

    return rc;
)


    

/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *
 * \param control_plane   control plane handle
 * \param out_rowid       the row number & version used for the mapping
 * \param ifindex         the LLAP interface handle
 * \param nexthop_ip      an IP address on a the LLAP interface
 * \param mac             the MAC address for the IP address
 * \param os              (optional) O/S synchronization information
 *
 * \return                0 or error code if control plane uninitialized
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /*rc*/
cicpos_mac_set(cicp_handle_t *cplane_netif,
	       cicp_mib_verinfo_t *out_rowinfo,
	       ci_ifid_t ifindex,
	       ci_ip_addr_net_t nexthop_ip,
	       const ci_mac_addr_t *mac,
	       const cicpos_mac_row_sync_t *os)
CICP_OPTSYSBODY(
    cp_mac_set_t op;
    int rc;

    CI_USER_PTR_SET(op.os_sync_ptr, os);
    op.ifindex = ifindex;
    op.ip_be32 = nexthop_ip;
    ci_assert(sizeof(op.mac) >= sizeof(*mac));
    memcpy(&op.mac, mac, sizeof(op.mac));
    
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_MAC_SET, &op);
    if (rc == 0)
	*out_rowinfo = op.rowinfo;

    return rc;
)



    
/*! Claim the "synchronizer" role with respect to the MAC table
 *
 * \param cplane_netif    control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL int /* bool */
cicpos_mact_open(cicp_handle_t *cplane_netif)
CICP_OPTSYSBODY(
    if (oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                            OO_IOC_CP_MAC_OPEN, NULL) == 0)
        return 1/*true*/;
    else
        return 0/*false*/;
)


/*! Release the "synchronizer" role with respect to the MAC table
 *
 * \param cplane_netif   control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_mact_close(cicp_handle_t *cplane_netif)
CICP_OPTSYSBODY(
    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_MAC_CLOSE, NULL);
)


/*! Indicate that the numbered row has been seen during synchronization
 *
 * \param cplane_netif    control plane handle (use CICP_HANDLE(netif))
 * \param rowinfo         the number & version of the row in the MAC table seen
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_mac_row_seen(cicp_handle_t *cplane_netif, cicp_mib_verinfo_t *rowinfo)
CICP_OPTSYSBODY(
    cicp_mib_verinfo_t op;

    op.row_index = rowinfo->row_index;
    op.row_version = rowinfo->row_version;
    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_MAC_SEEN, &op);
)


/*!
 * Delete all address resolution entries other than those in the provided set
 *
 * \param cplane_netif   control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
CICP_OPTSYSCALL void
cicpos_mac_purge_unseen(cicp_handle_t *cplane_netif)
CICP_OPTSYSBODY(
    (void)oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                         OO_IOC_CP_MAC_PURGE_UNSEEN, NULL);
)





    
/*----------------------------------------------------------------------------
 * Control Plane user-visible information 
 *---------------------------------------------------------------------------*/



/*!
 * validate that cached forwarding information is still correct
 *
 * \param user            the user-visible control plane information handle
 * \param handle          the integrity handle
 *
 * \return                0 iff the entry is no longer valid
 *
 * The information validated as "correct" includes all the data returned by
 * the /c cicp_fwd_retrieve function below.
 *
 * The correctness of the implementation of this function depends on the
 * explicit invalidation of the IP-MAC mapping for a nexthop IP address
 * whenever any of the information that should be returned by
 * /c cicp_fwd_retrieve is altered including
 *
 *     - change in first hop MAC address
 *     - change in source IP address associated with source interface
 *     - change in status of source interface (e.g. up/down)
 *     - change in encapsulation used on source interface
 *
 * It must also be invalidated whenever any change to the routing table that
 * might result in the selection of a different nexthop IP address is made
 *
 * This function can be used in the validation of the best   
 * source IP address as well as the next hop address.
 *
 * Note the user argument is not a control plane handle - it is the value
 * that is returned by "CICP_MIBS(CICP_HANDLE(netif))->user".  The reason for
 * this is to allow the user to cache this value and thus avoid an indirection.
 */
ci_inline int /* bool */
cicp_user_is_valid(const cicp_ul_mibs_t *user, 
                   const cicp_user_verinfo_t *handle)
{   return cicp_mac_is_valid(user->mac_utable, handle);
}



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


/*! Check the ip cache is currently valid
 */
ci_inline int /* bool */
cicp_ip_cache_is_valid(cicp_handle_t *cicp_handle,  ci_ip_cached_hdrs *ipcache)
{
    return cicp_user_is_valid(&CICP_MIBS(cicp_handle)->user,
			      &ipcache->mac_integrity);
}


/*! Update MAC entry if necessary */
ci_inline void
cicp_ip_cache_mac_update(ci_netif* ni, ci_ip_cached_hdrs *ipcache,
                         int/*bool*/ confirm)
{
    if( (ipcache->flags & CI_IP_CACHE_NEED_UPDATE_STALE) ||
        (confirm && (ipcache->flags & CI_IP_CACHE_NEED_UPDATE_SOON))) {
        ipcache->flags &= ~(CI_IP_CACHE_NEED_UPDATE_STALE |
                            CI_IP_CACHE_NEED_UPDATE_SOON);
        cicp_mac_update(ni, &ipcache->mac_integrity, ipcache->nexthop,
                        ci_ip_cache_ether_dhost(ipcache), confirm);
    }
}

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
                     ci_ifid_t ifindex)
CICP_SYSBODY(
    cp_user_defer_send_t op;

    op.retrieve_rc = retrieve_rc;
    op.os_rc       = *ref_os_rc;
    op.pkt         = pkt_id;
    op.ifindex     = ifindex;

    oo_resource_op(CICP_DRIVER_HANDLE(netif),
                   OO_IOC_CP_USER_DEFER_SEND, &op);
    
    *ref_os_rc = op.os_rc;

    return op.rc;
)


/*! Return the access point an incomming packet probably arrived on
 *
 * \param netif           the network interface handle
 * \param pkt_id          the ID of an incomming packet
 * \param out_ifindex     the ID of the receiving link layer access point ID 
 *
 * \return                0 iff relevant IP subnet found
 *
 * This function uses the destination MAC address stored in the given packet
 * and any relevant protocol details (such as its encapsulation and
 * encapsulation parameter) to determine the probably access point that
 * received the packet.
 *
 * Typically this information is used in order to find a destination access
 * point for traffic that should return along precisely the route that
 * incomming data arrived on.
 *
 */
CICP_SYSCALL int /* rc */
cicp_user_pkt_dest_ifid(ci_netif *netif, int pkt_id, ci_ifid_t *out_ifindex)
CICP_SYSBODY(
    cp_user_pkt_dest_ifid_t op;
    int rc;

    op.pkt = pkt_id;

    rc = oo_resource_op(CICP_DRIVER_HANDLE(netif),
                        OO_IOC_CP_USER_PKT_DEST_IFID, &op);
    
    if (rc == 0)
      *out_ifindex = op.ifindex;
    return rc;
)


/*! Lookup details of a local (home) IP address.
 *
 * \param cplane_netif    the control plane handle, e.g. CICP_HANDLE(netif)
 * \param ref_ip_be32     location of the IP home IP address to check
 * \param out_hwport      hardware port of the home LLAP interface 
 * \param out_ifindex     home LLAP interface ID
 * \param out_mac         MAC address of the home LLAP interface ID
 * \param out_mtu         MTU of the LLAP
 * \param out_encap       Encapsulation of the LLAP
 *
 * returns
 *   0 if \c *ref_ip_be32 is a local IP address
 *   -ENODATA if *ref_ip_be32 is not a local IP address
 *   -EINVAL if the corresponding LLAP could not be found
 *
 * NB. If duplicate IP addresses are present in the IPIF table, we return
 * info about the first one found.
 *
 * out_hwport, out_ifindex, out_mac, out_mtu and out_encap may be NULL.
 */
CICP_SYSCALL int /* rc */
cicp_user_find_home(cicp_handle_t *cplane_netif,
		    const ci_ip_addr_t *ref_ip_be32,
                    ci_hwport_id_t *out_hwport, 
                    ci_ifid_t *out_ifindex, ci_mac_addr_t *out_mac,
                    ci_mtu_t *out_mtu, cicp_encap_t *out_encap)
CICP_SYSBODY(
    cp_src_addr_checks_t op;
    int rc;

    CI_IP_ADDR_SET(&op.ip_be32, ref_ip_be32);
    rc = oo_resource_op(CICP_DRIVER_HANDLE(cplane_netif),
                        OO_IOC_CP_SRC_ADDR_CHECKS, &op);
    
    if (rc == 0) {
      if (out_hwport != NULL)
          *out_hwport = op.hwport;
      if (out_ifindex != NULL)
          *out_ifindex = op.ifindex;
      if (out_mac != NULL)
	  CI_MAC_ADDR_SET(out_mac, op.mac);
      if (out_mtu != NULL)
          *out_mtu = op.mtu;
      if (out_encap != NULL)
          *out_encap = op.encap;
    }
    return rc;
)


/*! Checks if the given ip address is both local and etherfabric.
 *  Returns 1 if it is, 0 if it isn't.
 *  If the address isn't found, it returns 0
 */
ci_inline int
cicp_user_addr_is_local_efab(cicp_handle_t *cplane_netif,
			     const ci_ip_addr_t *ref_ip_be32)
{ 
  /* Sadly we need to initialize these because gcc 4 is dumb and bitches if we
   * don't (which is bad, since we compile with -Werror)
   */
  ci_hwport_id_t hwport = 0;
  if (CI_UNLIKELY(cicp_user_find_home(cplane_netif, ref_ip_be32,
				      &hwport,
				      /*ifindex*/NULL, /*mac*/NULL,
                                      /*mtu*/NULL, /*encap*/NULL)))
    return 0;
  else
    return hwport != CI_HWPORT_ID_BAD;
}

#if CI_CFG_TEAMING

/*!
 * Gets the bond rowid, hash in use (if needed for current bond mode),
 * and vlock value at time the information is retrieved 
 */

extern int 
cicp_user_bond_get_info(cicp_handle_t* cplane, const cicp_fwd_row_t* fwd_row,
                        ci_ifid_t ifindex, ci_int16* row_id, ci_int8* hash,
                        ci_verlock_value_t* vlock);


ci_inline int cicp_user_bond_check_fwd_vlock(cicp_handle_t* control_plane,
                                             ci_verlock_value_t vlock)
{
  const cicp_ul_mibs_t* user = &CICP_MIBS(control_plane)->user;
  const cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;

  if( vlock != fwdt->version ) 
    return 1;

  return 0;
}

#endif


/*----------------------------------------------------------------------------
 * Internal functions - used only between parts of the control plane
 *---------------------------------------------------------------------------*/

/* The details of these functions are not public - please do not
   refer to them directly - use/define documented public functions in
   <ci/internal/cplane_ops.h>
*/

extern cicp_mac_rowid_t
_cicp_mac_find_ipaloc(cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		      ci_ip_addr_t ip);

extern cicp_mac_rowid_t
_cicp_mac_find_ipunaloc(cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		        ci_ip_addr_t ip);

extern cicp_fwd_rowid_t 
_cicpos_route_find(const cicp_fwdinfo_t   *routet,
		   ci_ip_addr_t            dest_ip,
                   ci_ip_addrset_t         dest_set,
                   ci_ifid_t               dest_ifindex);

extern cicp_fwd_row_t *
_cicpos_fwd_find_free(cicp_fwdinfo_t *fwdt);


 

/*----------------------------------------------------------------------------
 * Control Plane initialization/termination 
 *---------------------------------------------------------------------------*/


/*! Return the number of bytes mapped for the control plane in the shared
 *  memory area.
 */
extern size_t 
cicp_mapped_bytes(const cicp_ns_mmap_info_t *shared);


/*! Create control plane per-netif information from shared information
 *
 */
extern void 
cicp_ni_build(cicp_ni_t *control, const cicp_ns_mmap_info_t *shared,
	      void *mem);


/*----------------------------------------------------------------------------
 * Timesync state
 *---------------------------------------------------------------------------*/

extern unsigned oo_timesync_cpu_khz;

extern void oo_timesync_wait_for_cpu_khz_to_stabilize(void);

ci_inline struct oo_timesync* oo_timesync_state(cicp_handle_t* cplane)
{
  const cicp_ul_mibs_t *umibs = &CICP_MIBS(cplane)->user;
  return umibs->oo_timesync;
}

#ifdef __KERNEL__
extern void oo_timesync_update(cicp_handle_t* control_plane);
#endif


/*----------------------------------------------------------------------------
 * Temporary calls to support legacy control plane
 *---------------------------------------------------------------------------*/


ci_inline int /* bool */
cicp_user_is_local_addr(cicp_handle_t *cplane_netif,
			const ci_uint32 *ref_ip_be32)
{
  ci_hwport_id_t hwport;
  return cicp_user_find_home(cplane_netif, ref_ip_be32, &hwport,
                             /*ifindex*/NULL, /*mac*/NULL, /*mtu*/NULL,
                             /*encap*/NULL) == 0;
}


#ifdef __cplusplus
}
#endif



#endif /* __CI_INTERNAL_CPLANE_OPS_H__ */

/*! \cidoxg_end */
