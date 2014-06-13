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
**  \brief  Control Plane kernel definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_cplane */

/*! The definitions in this header are an amalgamation of definitions for 
 *  the following purposes:
 *
 *  (cicp_*) Functions for calling from the protocol stack including
 *      - implementation of user-mode system calls
 *      - functions used only from within the kernel
 *
 *  (cicpos_*) Functions used internally to synchronize with the O/S
 *
 *  For completeness the other (cicp_*) functions (those accessible from both
 *  the user-mode and the kernel that do not require implementation through
 *  system calls) are also described in comments.
 */

#ifndef __CI_DRIVER_EFAB_CPLANE_H__
#define __CI_DRIVER_EFAB_CPLANE_H__


#include <ci/internal/cplane_ops.h>
#include <onload/cplane_types.h>

#include <ci/efhw/efhw_types.h>


/*----------------------------------------------------------------------------
 * Reference types
 *---------------------------------------------------------------------------*/

/* O/S dependent type support functions */


#ifndef __ci_driver__
#error cplane.h must be included from a driver source
#endif

#ifdef linux


/*#include <linux/jiffies.h>*/

ci_inline ci_subsec_time_t ci_subsec_time_now(void)
{   return jiffies; /* typical units and resolution 10ms */
}

#ifndef HZ
#warning Jiffies #define 'HZ' not available
#endif

#define CI_SUBSEC_TIME_HZ HZ

#endif /* linux */



#if defined(__unix__) && defined(__ci_driver__)
typedef struct
{
  /* "imported" bitmaps */
  cicp_handle_t *control_plane;
  
  ci_uint32 *imported_route;
  ci_uint32 *imported_ipif;
  ci_uint32 *imported_llap;
 
  int /* bool */  nosort;
} cicpos_parse_state_t;

typedef void ci_post_handling_fn_t(cicpos_parse_state_t *);

extern cicpos_parse_state_t *
cicpos_parse_state_alloc(cicp_handle_t *control_plane);

extern void cicpos_parse_state_free(cicpos_parse_state_t *session);

extern void cicpos_parse_init(cicpos_parse_state_t *session,
			      cicp_handle_t *control_plane);

extern void cicpos_route_post_poll(cicpos_parse_state_t *session);

extern void cicpos_llap_post_poll(cicpos_parse_state_t *session);

extern void cicpos_ipif_post_poll(cicpos_parse_state_t *session);

#endif


 /*----------------------------------------------------------------------------
 * routing MIB
 *---------------------------------------------------------------------------*/




/* Synchronization functions */


/*! Initialize kernel synchronization state in a route MIB row
 *
 * \param syn_row         the routing table entry O/S synchronization info
 */
extern void
cicpos_route_kmib_row_ctor(cicpos_route_row_t *syn_row);


/*! Update the O/S-specific route information
 *
 * \param syn_row         the routing table entry O/S synchronization info
 *
 * \return                FALSE iff no update was made
 *
 */
extern int /* bool */
cicpos_route_kmib_row_update(cicpos_route_row_t *syn_oldrow,
			     const cicpos_route_row_t *syn_newrow);



/*!
 * Ammend an existing route or set a new route to a given set of IP addresses
 *
 * \param control_plane   control plane handle
 * \param dest_ip         the route set base IP address 
 * \param dest_set        the set of addresses based on \c dest_ip
 * \param scope           any special interpretation of next_hop_ip
 * \param next_hop_ip     the forwarding address to use on a match
 * \param ifindex         the link access point of the forwarding address
 * \param pref_source     IP address (of an ifindex ipif) to use as source
 * \param hwport_id       the port on which the link access point is located
 * \param ref_sync        O/S-specific synchronization information
 * \param nosort          Do not sort route table after addition
 *
 * \return                0 on success, error code otherwise
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.
 *
 * The \c pref_source is used to select among the (many?) IP interfaces that
 * may be supported by the LLAP identified by \c ifindex.  If it is the
 * address 0.0.0.0 it will be replaced by the home address of any (e.g the
 * "first") IP interface that is active on the LLAP.  It is an error to
 * specify another IP address that does not correspond to the \c ifindex.
 *
 * Note: in principle more than one IP interface might be supported on the
 *       a single LLAP with the same home IP address but with different
 *       IP address sets (masks) - but since it is the home IP address that
 *       we need this creates no ambiguity
 *
 * If \c nosort parameter is set, user should sort route table himself
 * after all additions are done.
 *
 * \c out_rowid should be used only if zero is returned.
 *
 * The row written to for the assignment is returned only if \c out_rowid is
 * not NULL.
 */
extern int /* rc */
cicpos_route_import(cicp_handle_t      *control_plane,
		    cicp_route_rowid_t *out_rowid,
		    ci_ip_addr_t        dest_ip,
		    ci_ip_addrset_t     dest_ipset,
		    ci_scope_t          scope,
		    ci_ip_addr_t        next_hop_ip,
		    ci_ip_tos_t         tos,
		    cicp_metric_t       metric,
		    ci_ip_addr_t        pref_source,
		    ci_ifid_t           ifindex,
		    ci_mtu_t            mtu,
		    cicpos_route_row_t *ref_sync,
		    int /* bool */      nosort);


/*!
 * Ammend a currently existing route to a given set of IP addresses
 *
 * \param control_plane   control plane handle
 * \param dest_ip         the route set base IP address 
 * \param dest_set        the set of addresses based on \c dest_ip
 * \param next_hop_ip     the forwarding address to use on a match
 * \param ifindex         the link access point of the forwarding address
 * \param pref_source     the IP source address to use when transmitting 
 * \param hwport_id       the port on which the link access point is located
 *
 * \return                0 on success, error code otherwise
 *
 * This function calls \c cicpos_route_import with a NULL synchronization
 * argument, see above
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int
cicp_route_import(cicp_handle_t      *control_plane,
		  cicp_route_rowid_t *out_rowid,
		  ci_ip_addr_t        dest_ip,
		  ci_ip_addrset_t     dest_ipset,
		  ci_ip_addr_t        next_hop_ip,
		  ci_ip_tos_t         tos,
		  cicp_metric_t       metric,
		  ci_ip_addr_t        pref_source,
		  ci_ifid_t           ifindex)
 */



/*! Remove a route 
 *
 * \param control_plane   control plane handle
 * \param dest_ip         the route set base IP address
 * \param dest_set        the set of addresses based on \c dest_ip
 *
 * \return                CICP_IPIF_ROUTE_BAD iff route not found, else row
 *
 * This function locates the row in the routing table that describes the
 * route identified by the given destination IP address and address set and
 * (if found) deletes it from the table
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int
cicpos_route_delete(cicp_handle_t     *control_plane, 
		    ci_ip_addr_t       dest_ip,
		    ci_ip_addrset_t    dest_ipset);
 */




/*!
 * Delete all entries other than those in the provided set and reorder
 *
 * \param routet          the route table
 * \param kroutet         the kernel route table
 * \param keep_set	  set of rows to keep
 * \param changes_made    FALSE iff no changes have been made
 *
 * This function deletes all the rows of the route table that are not in
 * the set \c keep_set.  If there have been any additions or deletions it then
 * re-orders the table as necessary to provide optimal longest-prefix-first
 * matching.
 * 
 * Typically every route that has been found in the O/S MIB will be entered
 * into the set and this function will be called at the end of the update.
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 */
extern void
cicpos_route_purge(cicp_fwdinfo_t    *routet,
		   cicp_route_kmib_t *kroutet,
		   ci_bitset_ref_t    keep_set,
		   int /*bool*/       changes_made);



/*----------------------------------------------------------------------------
 * address resolution MIB
 *---------------------------------------------------------------------------*/


/*! Validate that an address resolution table entry is still current
 *  - inline call defined in the user-mode library: ci/internal/cplane_ops.h 
ci_inline int
cicp_mac_is_valid(const cicp_mac_mib_t *mact, 
                  const cicp_mac_verinfo_t *handle)
 */


/*! Request that a (MAC) address resolution be found for an IP address
 *  - system call defined in the user-mode library: ci/internal/cplane_ops.h 
extern int
cicp_mac_request(ci_netif *netif,
                 ci_ifid_t ifindex,
                 ci_ip_addr_net_t nexthop_ip)
 */



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
 * If the \c os argument is NULL it is assumed that the information is being
 * set by local protocols, otherwise it is assume to be being set from
 * the O/S copy of the table
 *
 * \c out_rowid should be used only if zero is returned.
 *
 * The row written to for the assignment is returned only if \c out_rowid is
 * not NULL.
 *
 * The table is written to using a write lock.  The update causes the version
 * number of the IP-MAC mapping to be updated if its details change.
 *
extern int // rc
cicpos_mac_set(cicp_handle_t *control_plane,
	       cicp_mib_verinfo_t *out_rowinfo,
	       ci_ifid_t ifindex,
	       ci_ip_addr_net_t nexthop_ip,
	       const ci_mac_addr_t *mac,
	       const cicpos_mac_row_sync_t *os);
*/


/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *
 * \param control_plane   control plane handle (use CICP_HANDLE(netif))
 * \param out_rowid       the row number & version used for the mapping
 * \param ifindex         the LLAP interface handle
 * \param nexthop_ip      an IP address on a the LLAP interface
 * \param mac             the MAC address for the IP address
 *
 * \return                0 or error code if control plane uninitialized
 *
 * calls cicpos_mac_set with os == NULL, see above
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern void
cicp_mac_set(cicp_handle_t *control_plane,
	     cicp_mib_verinfo_t *out_rowinfo,
	     ci_ifid_t ifindex,
	     ci_ip_addr_net_t nexthop_ip,
	     const ci_mac_addr_t *mac)
 */



/*! Set a permanent return code to be returned for an IP address
 *
 * \param control_plane   control plane handle
 * \param ifindex         the LLAP interface handle
 * \param nexthop_ip      an IP address on a the LLAP interface
 * \param os_rc           a permanent return code to set for this mapping
 *
 * \return                0 or negative error code if os_rc is invalid
 *
 * The return code will be given by future calls of \c cicp_mac_get until
 * (possibly) overridden by synchronization information from the O/S
 *
 * The table is written to using a write lock.  The update causes the version
 * number of the IP-MAC mapping to be updated if the return code changes.
 */
extern int /*rc*/
cicp_mac_set_rc(cicp_handle_t *control_plane,
                ci_ifid_t ifindex,
                ci_ip_addr_net_t nexthop_ip,
		ci_uerr_t os_rc);
    

/* Synchronization functions */



/*! Initialize kernel synchronization state in a MAC MIB */
extern int /* rc */
cicpos_mac_kmib_ctor(cicpos_mac_mib_t *sync);



/*! Initialize kernel synchronization state in a MAC MIB row */
extern void
cicpos_mac_kmib_row_ctor(cicpos_mac_row_t *syn_row,
			 const cicpos_mac_row_sync_t *os);


/*! Claim the "synchronizer" role with respect to the MAC table
 *
 * \param control_plane   control plane handle
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int
cicpos_mact_open(cicp_handle_t *control_plane);
 */
    
/*! Release the "synchronizer" role with respect to the MAC table
 *
 * \param control_plane   control plane handle
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern void
cicpos_mact_close(cicp_handle_t *control_plane);
 */

/*! Indicate that the numbered row has been seen during synchronization
 *
 * \param control_plane   control plane handle
 * \param rowinfo         the number & version of the row in the MAC table seen
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern void
cicpos_mac_row_seen(cicp_handle_t *control_plane, cicp_mib_verinfo_t *rowinfo);
 */


/*!
 * Delete all address resolution entries other than those in the provided set
 *
 * \param control_plane   control plane handle
 *
 * This function deletes all the rows of the address resolution table that are
 * not in the set \c keep_set.  
 * 
 * Typically every route that has been found in the O/S MIB will be entered
 * into the keep set as well as those that have been marked as confirmed and
 * this function will be called at the end of the update.
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern void
cicpos_mac_purge_unseen(cicp_handle_t *control_plane);
 */




/*! Indicate that the original content of this mapping could be altered
 *
 * \param control_plane   control plane handle
 * \param syn_row         kernel MAC MIB row sync information to be updated
 * \param row             user MAC MIB row inc. permanent return code location
 * \param os              (optional) O/S synchronization information
 * \param mac             The new MAC address being proposed for the row
 * \param alteration      TRUE iff a new MAC address is provided
 * \param out_ignore_clash TRUE iff should not complain about strange MAC addr
 *
 * \return                TRUE iff the update should go ahead
 *
 * The update being considered is from the host operating system if
 * \c os is not \c NULL (and from a local protocol otherwise)
 *
 * This function decides whether an update to the table should be made
 * (it may be that the existing content is considered more or less
 * authoritative than the information represented in \c os)
 *
 * If this function returns TRUE the syn_row will have been updated with
 * details from \c os and \c row->rc may have been updated.  These updates
 * will not take place otherwise
 */
extern int /* bool */
cicpos_mac_kmib_row_update(cicp_handle_t *control_plane,
			   cicpos_mac_row_t *syn_row, cicp_mac_row_t *row,
			   const cicpos_mac_row_sync_t *os,
			   const ci_mac_addr_t *mac,
			   int /* bool */ alteration,
			   int /* bool */ *out_ignore_clash);



/*! Destroy kernel synchronization state in a MAC MIB */
extern void
cicpos_mac_kmib_dtor(cicpos_mac_mib_t *sync);




/*! Confirm that an address resolution table entry is known correct
 *
 * \param mact_sync       the synchronization state of the table
 * \param sync            the synchronization state of the entry
 * \param rowinfo         the row index & version of the row being confirmed
 *
 * This call requests that the IP and MAC addresses referred to in the given
 * version of the address resolution table should be confirmed.  That is, that
 * they should be prevented from timing out in the operating system's copy
 * of the table.
 */
extern void
cicpos_mac_row_confirm(cicpos_mac_mib_t *mact_sync, cicpos_mac_row_t *sync,
		       cicp_mib_verinfo_t *rowinfo);



/* Find an allocated MAC entry holding the given IP address
 * - in user header - see for documentation
 *
extern cicp_mac_rowid_t
cicpos_mac_find_ip(const cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		   ci_ip_addr_t ip, ci_verlock_value_t *out_ver);
 */


/*! Mark all existing IP-MAC mappings as invalid to force their users to
 *  
 * \param mact            the user-visible address resolution table
 *
 * This invalidataion will force the users of the given IP addresses to
 * re-evaluate their addressing information
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 */
extern void
_cicpos_mac_invalidate_all(cicp_mac_mib_t *mact);



/*----------------------------------------------------------------------------
 * Bonding MIB
 *---------------------------------------------------------------------------*/

#if CI_CFG_TEAMING

extern int /* rc */
cicp_llap_set_bond(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                   ci_ifid_t master_ifindex, cicp_encap_t *encap);

extern int cicp_bond_find_rowid(cicp_handle_t *control_plane, 
                                ci_ifid_t ifindex);

extern int cicp_bond_set_active(cicp_handle_t *control_plane, 
                                int master_rowid, ci_ifid_t master_ifindex,
                                int slave_rowid, ci_ifid_t slave_ifindex,
                                int is_active);

extern int cicp_bond_get_n_active_slaves(cicp_handle_t *control_plane,
                                         int rowid, ci_ifid_t ifindex);

extern int 
cicp_bond_check_active_slave_hwport(cicp_handle_t *control_plane,
                                    int rowid, ci_ifid_t ifindex,
                                    ci_hwport_id_t curr_hwport,
                                    ci_hwport_id_t *hwport);

extern int cicp_bond_mark_row(cicp_handle_t *control_plane, int rowid, 
                              ci_ifid_t ifindex);

extern void
cicp_bond_prune_unmarked_in_bond(cicp_handle_t *control_plane,
                                 ci_ifid_t master_ifindex);

extern int cicp_bond_set_hash_policy(cicp_handle_t *control_plane,
                                     int rowid, int mode,
                                     ci_ifid_t master_ifindex,
                                     int hash_policy);

extern int cicp_bond_check_slave_owner(cicp_handle_t *control_plane,
                                       int rowid, ci_ifid_t ifindex,
                                       ci_ifid_t master_ifindex);
extern int 
cicp_bond_add_slave(cicp_handle_t *control_plane, 
                    ci_ifid_t master_ifindex, ci_ifid_t ifindex);

extern int 
cicp_bond_remove_slave(cicp_handle_t *control_plane,
                       ci_ifid_t master_ifindex, ci_ifid_t ifindex);

extern int 
cicp_bond_remove_master(cicp_handle_t *control_plane, ci_ifid_t ifindex);

extern int cicp_bond_update_hwport(cicp_handle_t *control_plane, 
                                   int rowid, ci_ifid_t ifindex,
                                   ci_hwport_id_t hwport);

extern int cicp_bond_update_mode(cicp_handle_t *control_plane,
                                 int rowid, ci_ifid_t ifindex, int mode);

extern int cicp_bond_get_mode(cicp_handle_t *control_plane, 
                              int rowid, ci_ifid_t ifindex,
                              int *mode);

extern int
cicp_bond_get_master_ifindex(cicp_handle_t *control_plane,
                             ci_ifid_t slave_ifindex,
                             ci_ifid_t *master_ifindex);

extern void cicp_bondinfo_dump(const cicp_handle_t *control_plane);

#endif

/* Caller must take control plane lock before calling this */
extern int cicp_get_active_hwport_mask(cicp_handle_t *control_plane,
                                       ci_ifid_t ifindex, 
                                       unsigned *hwport_mask);


/*----------------------------------------------------------------------------
 * access point MIB
 *---------------------------------------------------------------------------*/


/*! find whether the supplied access point is currently up
 *
 * \param control_plane   control plane handle
 * \param ifindex         the O/S network access point to find in \c llapt
 * \param out_up          a place for whether the interface is up
 *
 * \return                0 iff the ifindex was be found, error code otherwise
 *
 * The interface is up if it is activated by a management interface - i.e.
 * if it is currently being made available.  It has no explicit relationship
 * with (for example) connectivity at the PHY layer. 
 *
 * The table is read using a lock.  
 *
 * If the return code is non-zero the value returned in \c out_up represents
 * false.
 */
extern int /* rc */
cicp_llap_is_up(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
		int /* bool */ *out_up);


 /*! return the MTU associated with the given link layer access point
 *
 * \param control_plane   control plane handle
 * \param ifindex         the O/S network access point to find in \c llapt
 * \param out_mtu         a place to store the MTU
 *
 * \return                0 iff the ifindex was be found, error code otherwise
 *
 * If the return code is non-zero the value returned in \c out_up represents
 * false.
 *
 * The table is read using a lock.
 */
extern int /* rc */
cicp_llap_get_mtu(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
	          ci_mtu_t *out_mtu);

/* NB: also need to call cicp_fwdinfo_set_encapsulation when you use this */
    
/*! get the encapsulation specification for a given access point
 *
 *  \param control_plane   control plane handle
 *  \param ifindex         the O/S network access point to find in \c llapt
 *  \param mac             a place for the encapsulation specification 
 *
 *  \return                0 iff successful, error code otherwise
 *
 *  If the return code is non-zero \c mac is not updated.
 *
 *  The table is read using a lock.
 */
extern int /* rc */
cicp_llap_get_encapsulation(const cicp_handle_t *control_plane,
			    ci_ifid_t ifindex, cicp_encap_t *mac);
    
/*! Return the nic and port number associated with a particular ifindex
 *
 *  If no match is found, CI_HWPORT_ID_BAD is returned.
 *
 *  This function requires the tables to be locked and performs this locking
 *  itself.
 *
 *  The table is read using a lock.
 */
extern ci_hwport_id_t
cicp_llap_get_hwport(const cicp_handle_t *control_plane, ci_ifid_t ifindex);


/*! find the name used by the O/S for a given link layer access point
 *
 *  This function is intended for debugging output/use only.
 *
 *  Always returns a string.  However, unless the table is locked, the string
 *  may no longer be the one associated with the given access point by the time
 *  its address is used.
 *
 *  This function requires the tables to be locked but does not itself lock
 *  them.
 */
extern const char *
_cicp_llap_get_name(const cicp_handle_t *control_plane, ci_ifid_t ifindex);


/*! find the MAC address associated with a given link layer access point
 *
 *  \param control_plane   control plane handle
 *  \param ifindex         the O/S network access point to find in \c llapt
 *  \param out_mac         a place for the LLAP's mac address 
 *
 *  This function differs from cicp_llap_retrieve in that it does not lock
 *  the whole control plane.
 *
 *  This function requires the LLAP table to be locked and locks it itself.
 */
extern int /* rc */
cicppl_llap_get_mac(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
	            ci_mac_addr_t *out_mac);


/*! Find ifindex and source MAC of VLAN interface using master interface
 * and VLAN id.
 *
 *  \param control_plane   control plane handle
 *  \param inout_ifindex   the O/S network access point to find in \c llapt
 *  \param vlan_id         VLAN id
 *  \param out_mac         a place for the LLAP's mac address 
 *
 * This is VLAN-aware version of cicppl_llap_get_mac().  It also returns
 * ifindex of the vlan'ed interface in inout_ifindex parameter.
 *
 *  This function requires the LLAP table to be locked and locks it itself.
 */
extern int /* rc */
cicppl_llap_get_vlan(const cicp_handle_t *control_plane,
                     ci_ifid_t *inout_ifindex, ci_uint16 vlan_id,
                     ci_mac_addr_t *out_mac);


/*! Link the VLAN interface LLAP to the master LLAP in the control plane
 */
extern int /* rc */
cicp_llap_set_vlan(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                   ci_ifid_t master_ifindex);


/*! Prevent an LLAP with CI_HWPORT_ID_BAD from being considered
 *  onloadable.  This is the default state, so only currently
 *  necessary for bonded interfaces which set
 *  CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT.
 */
extern int 
cicp_llap_cant_onload_bad_hwport(cicp_handle_t *control_plane,
                                 ci_ifid_t ifindex);


/* synchronization functions */

extern void
cicpos_llap_kmib_row_ctor(cicpos_llap_row_t *row);


/*! Tell the control plane what "hwport" is associated with a link layer
 * access point.
 *
 * \param control_plane   control plane handle
 * \param ifindex         O/S index of this layer 2 interface
 * \param hwport          hardware port of interface
 * \param ref_encap       encapsulation used on this i/f
 *
 * \return                0 on success, error code otherwise
 *
 * This function is called when creating a new link layer access point that
 * is supported by a NIC.  It registers the fact that the given \c ifindex
 * is associated with the driver.  Also called with hwport=CI_HWPORT_ID_BAD
 * to disassociate the LLAP from the driver.
 *
 * This function only creates an link layer access point if one does
 * not already exist with the given \c ifindex.  If one already exists
 * the hwport and encap are updated to the supplied values.
 *
 * If a new link layer access point is created it is created with an invalid
 * mtu size, with no name and with an invalid MAC address.  It is not "up".
 *
 * This function locks the tables that it updates.
 */
extern int /* rc */
cicp_llap_set_hwport(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                     ci_hwport_id_t hwport, cicp_encap_t *ref_encap);


/*! Update the control plane's "hwport" associated with a link layer
 * access point.
 *
 * \param control_plane   control plane handle
 * \param ifindex         O/S index of this layer 2 interface
 * \param hwport          hardware port of interface
 * \param bond_rowid      row ID into bonding table.
 *                       
 *
 * \return                0 on success, error code otherwise
 *
 * This function is called when the hwport associated with a link
 * layer access point that is supported by a NIC changes. E.g. when a
 * teaming interface changes its active slave.  It also updates the
 * active_hwport in the bonding table
 *
 * This function locks the tables that it updates.
 */
extern int /* rc */
cicp_llap_update_active_hwport(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                               ci_hwport_id_t hwport, int bond_rowid,
                               int fatal);


/*! Import data into the link layer access point cache
 *
 * \param control_plane   control plane handle
 * \param out_rowid       a place to write the index of llap MIB row updated
 * \param ifindex         O/S index of this layer 2 interface
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param up              if true, this interface is up 
 * \param name            name of interface
 * \param ref_mac     	  MAC address of access point
 * \param ref_sync        O/S synchronization info
 *
 * \return                FALSE iff no change was made
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.
 *
 * \c out_rowid should be used only if zero is returned.
 *
 * The row written to for the assignment is returned only if \c out_rowid is
 * not NULL.
 *
 * This function requires the tables to be locked and locks them itself.
 */
extern int /* rc */
cicpos_llap_import(cicp_handle_t *control_plane,
		   cicp_llap_rowid_t *out_rowid,
		   ci_ifid_t ifindex,
		   ci_mtu_t mtu,
		   ci_uint8 /* bool */ up,
		   char *name,
		   ci_mac_addr_t *ref_mac,
		   cicpos_llap_row_t *ref_sync);


/*! Delete the link layer access point row with the given interface ID
 *
 * \param control_plane   control plane handle
 * \param ifindex         the O/S network access point to find in \c llapt
 *
 * \return                0 iff an entry was located and deleted
 *
 * This function requires the tables to be locked and locks them itself.
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int 
cicpos_llap_delete(cicp_handle_t *control_plane, ci_ifid_t ifindex);
 */





/*!
 * Dump the contents of the link layer access point table to the system log
 *
 * \param control_plane   control plane handle
 *
 * This function requires the table to be locked and locks it itself.
 */
extern void
cicp_llap_cilog(cicp_handle_t *control_plane);



/*----------------------------------------------------------------------------
 * IP interface MIB
 *---------------------------------------------------------------------------*/


/*! Return whether a supplied IP address is a special IP interface address
 *  in the user-mode library: ci/internal/cplane_ops.h
extern void
cicp_ipif_addr_kind(ci_netif *netif, ci_ip_addr_net_t ip,
		    ci_ip_addr_kind_t* out_addr_kind)
 */
    
    
/*!
 * Dump the contents of the IP interfaces table to the system log
 *
 * \param control_plane   control plane handle
 *
 * This function requires the table to be locked and locks it itself.
 */
extern void
cicp_ipif_cilog(cicp_handle_t *control_plane);


/*!
 * Copy the network and broadcast addresses of efab IP i/fs to an array
 *
 * \param control_plane   control plane handle
 * \param addr_array      IP address array to place addresses in
 *
 * \returns               The number of IP interfaces written
 *
 * The array must have 2 * CICP_IPIF_MIB_ROWS_MAX entries.
 *
 * Local addresses are written to the array at (addr_array+0) and broadcast
 * addresses are written to the array at (addr_array+CICP_IPIF_MIB_ROWS_MAX).
 *
 * This function requires the table to be locked and locks it itself.
 */
extern int
cicp_ipif_dump_efab(const cicp_handle_t *control_plane,
		    ci_ip_addr_t *addr_array);



/* synchronization functions */




/*! Import data into the IP interface cache
 *
 * \param control_plane   control plane handle
 * \param out_rowid       a place to write the index of llap MIB row updated
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 * \param net_bcast       set of addresses around the base address
 *
 * \return                zero or an error code 
 *
 * This function is typically called in response to information found in the
 * O/S copy of the IP interfaces MIB.
 *
 * \c out_rowid should be used only if zero is returned.
 *
 * The row written to for the assignment is returned only if \c out_rowid is
 * not NULL.
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int
cicpos_ipif_import(cicp_handle_t     *control_plane, 
		   cicp_ipif_rowid_t *out_rowid,
		   ci_ifid_t          ifindex,
		   ci_ip_addr_net_t   net_ip,
		   ci_ip_addrset_t    net_ipset,
		   ci_ip_addr_net_t   net_bcast);
 */



/*! Delete the IP interface row with the given set of subnet addresses
 *
 * \param control_plane   control plane handle
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 * \return                0 iff an IP interface was found and deleted
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern int 
cicpos_ipif_delete(cicp_handle_t   *control_plane, 
		   ci_ifid_t        ifindex,
		   ci_ip_addr_net_t net_ip,
		   ci_ip_addrset_t  net_ipset);
 */


/*!
 * Delete all IP interface entries other than those in the provided set
 *
 * \param control_plane   control plane handle
 * \param keep_set	  set of rows to keep
 *
 * This function deletes all the rows of the IP interfaces table that are
 * not in the set \c keep_set.  
 * 
 * Typically every IP interface that has been found in the O/S MIB will be
 * entered into the keep set and this function will be called at the end of the
 * update.
 *
 * UNUSED?
 *
 * This function requires the table to be locked but does not itself lock it.
 */
extern void
cicpos_ipif_purge(cicp_handle_t *control_plane, ci_bitset_ref_t keep_set);


/*!
 * Update the IP interface entry and callbacks when there's a state
 * (onloadable<->not_onloadable) change in the underlying bonded interface
 */
extern void
cicpos_ipif_bond_change(cicp_handle_t *control_plane, ci_ifid_t ifindex);

/*!
 * Query control plane to get an IP addr for the specified ifindex
 */
extern int
cicpos_ipif_get_ifindex_ipaddr(cicp_handle_t *control_plane, ci_ifid_t ifindex, 
                               ci_ip_addr_net_t *addr_out);

/*! Register a callback for when ipif table is updated
 *
 * \param control_plane   control plane handle
 * \param add_fn          function to be called when an ipif is added
 * \param delete_fn       function to be called when an ipif is removed
 * \returns               0 if the registration failed, handle otherwise
 *
 * The control plane handle can normally be provided via the macro
 * CICP_HANDLE(netif) -- where the netif is unused in the kernel
 *
 * If there are enough registration resources, this function registers the
 * given callback information and passes back a handle to it which can be
 * used with \c cicpos_ipif_deregister_callback.
 *
 * The two functions are called in the kernel's environment in response to
 * updates from the synchronization code.
 */
extern cicpos_ipif_callback_handle_t
cicpos_ipif_callback_register(cicp_handle_t          *control_plane,
			      cicpos_ipif_event_fn_t *add_fn,
                              cicpos_ipif_event_fn_t *delete_fn,
                              void                   *arg);

/*! Remove callback registration 
 *
 * \param control_plane   control plane handle
 * \param handle          a callback handle allocated by  ..callback_register
 * \returns               0 if the registration failed, handle otherwise
 *
 * If non-zero the callback \c handle provided will be deregistered, following
 * which no invocation of the registered callback functions will take place.
 *
 * Calling this function will increase the number of resource available for
 * \c cicpos_ipif_callback_register.
 */
extern void
cicpos_ipif_callback_deregister(cicp_handle_t                *control_plane,
			        cicpos_ipif_callback_handle_t handle);



/* protocol functions */


/*!
 * \param control_plane   control plane handle
 *
 * Check if the ip address given is a broadcast or network address.
 * Restricts the search to only the ip interfaces associated with the
 * given ifindex. 
 *
 * This function takes the CICP lock.
 */
extern int
cicp_ipif_net_or_brd_addr(const cicp_handle_t *control_plane,
			  ci_ifid_t ifindex, ci_ip_addr_t *ref_ip);





/*----------------------------------------------------------------------------
 * hardware port MIB
 *---------------------------------------------------------------------------*/


/*! indicate that a new NIC has been detected
 *
 * \param hwportt         the hardware port table
 * \param nic             the local ID of the NIC that has been detected
 *
 * This function must create representations of the ports on the new NIC and
 * must initialize the L5 stack equipment necessary for their correct
 * operation.
 *
 * This function requires the table to be locked and locks it itself.
 */
extern void
cicp_hwport_add_nic(cicp_handle_t *control_plane, ci_hwport_id_t);


/*! indicate that an old NIC is no longer detected
 *
 * \param hwportt         the hardware port table
 * \param nic             the local ID of the NIC that has been lost
 *
 * This function must prevent further use of the ports on the old NIC and
 * must initiate the collection of resources devoted to them.
 *
 * This function requires the table to be locked and locks it itself.
 */
extern void
cicp_hwport_remove_nic(cicp_handle_t *control_plane, ci_hwport_id_t);


/* Synchronization functions */

/*! Register the ports associated with a new NIC
 *
 * \param control_plane   control plane handle (use CICP_HANDLE(netif))
 * \param nic_id          number of NIC (starting from zero)
 * \param max_mtu         hardware limit on MTUs supported on this NIC
 *
 * NB: user-optional function - declaration is in user-mode header
 *
extern void
cicpos_hwport_update(cicp_handle_t *control_plane, 
                     ci_hwport_id_t, ci_mtu_t max_mtu);
 */


/*! DO WE NEED THIS ? */
extern void
cicpos_hwport_purge(cicp_handle_t *control_plane);


/*----------------------------------------------------------------------------
 * Control Plane kernel-visible information 
 *---------------------------------------------------------------------------*/

/*! Initialize and allocate driver-global control plane state
 *  \param control_plane   allocated data structure to initialize
 *  \param max_macs        size of mac table
 *  \param max_layer2_interfaces size of layer2 interface tables
 *  \param max_routes      size of route, ipif etc. tables
 *  \returns               0 on success, negative error code otherwise
 */
extern int /* rc */
cicp_ctor(cicp_mibs_kern_t *control_plane, unsigned max_macs, 
          unsigned max_layer2_interfaces, unsigned max_routes);

/*! Finalize and free driver-global control plane state 
 *  \param control_plane   allocated data structure to tidy up
 */
extern void
cicp_dtor(cicp_mibs_kern_t *control_plane);

/*! Indicate that new (NIC) hardware is now available for use 
 *  \param control_plane   control plane to advertise new NIC to
 */
extern void
cicp_hw_registered(cicp_handle_t *control_plane);


ci_inline void
cicp_lock_ctor(cicp_handle_t *control_plane)
{   ci_irqlock_ctor(&control_plane->lock);
}


ci_inline void
cicp_lock_dtor(cicp_handle_t *control_plane)
{   ci_irqlock_dtor(&control_plane->lock);
}

/* We use #define for cicp_lock() and cicp_unlock() rather than ci_inline
   so that the Windows static code analyser "prefast" can see its underlying
   function - and then apply additional checks to the code that performs
   the locking and unlocking

   Currently one consequence of this is that you can not take the address of
   these functions or use their value without applying arguments.

   The signatures should be:
     cicp_lock(cicp_handle_t *cplane, ci_irqlock_state_t *ref_irq_state)
   and
     cicp_unlock(cicp_handle_t *cplane, ci_irqlock_state_t *ref_irq_state)
*/

#ifndef ci_irqlock_lock_dbg
#define ci_irqlock_lock_dbg(lock, irq, file, line) \
        ci_irqlock_lock(lock, irq)
#endif

#ifndef ci_irqlock_unlock_dbg
#define ci_irqlock_unlock_dbg(lock, irq, file, line) \
        ci_irqlock_unlock(lock, irq)
#endif


#define cicp_lock_dbg(cplane, ref_irq, _file, _line) \
        ci_irqlock_lock_dbg(&(cplane)->lock, ref_irq, _file, _line)

#define cicp_lock(cplane, ref_irq) \
        cicp_lock_dbg(cplane, ref_irq, __FILE__, __LINE__)


#define cicp_unlock_dbg(cplane, ref_irq, _file, _line) \
        ci_irqlock_unlock_dbg(&(cplane)->lock, ref_irq, _file, _line)

#define cicp_unlock(cplane, ref_irq) \
        cicp_unlock_dbg(cplane, ref_irq, __FILE__, __LINE__)


#define CICP_LOCK_BEGIN_DBG(_cplane, _file, _line)			    \
        {   ci_irqlock_state_t _lock_state;                                 \
            cicp_handle_t *_control_plane = _cplane;                        \
            cicp_lock_dbg(_cplane, &_lock_state, _file, _line);             \
            {

#define CICP_LOCK_END_DBG(_file, _line)	   		                    \
            }                                                               \
            cicp_unlock_dbg(_control_plane, &_lock_state, _file, _line);    \
        }

#define CICP_LOCK_BEGIN(_cplane)					\
        CICP_LOCK_BEGIN_DBG(_cplane, __FILE__, __LINE__)

#define CICP_LOCK_END							\
        CICP_LOCK_END_DBG(__FILE__, __LINE__)


#define CICP_LOCK_DBG(_cplane, _code, _file, _line)			\
        CICP_LOCK_BEGIN_DBG(_cplane, _file, _line)	                \
            _code;                                                      \
        CICP_LOCK_END_DBG(_file, _line)
        
#define CICP_LOCK(_cplane, _code)					\
        CICP_LOCK_DBG(_cplane, _code, __FILE__, __LINE__)

#ifdef NDEBUG
#define CICP_CHECK_LOCKED(_cplane) do {} while(0)
#else
#define CICP_CHECK_LOCKED(_cplane) \
    ci_irqlock_check_locked(&(_cplane)->lock)
#endif




/*----------------------------------------------------------------------------
 * overall control plane
 *---------------------------------------------------------------------------*/




/* Protocol support functions */

/*! Defer transmission of packet until forwarding information re-established
 *  - system call defined in the user-mode library: ci/internal/cplane_ops.h 
extern int 
cicp_user_defer_send(ci_netif *netif, cicpos_retrieve_rc_t retrieve_rc,
		     ci_uerr_t *ref_os_rc, int netif_pkt_id)
 */


/*! Return the access point an incomming packet probably arrived on
 *  - system call defined in the user-mode library: ci/internal/cplane_ops.h 
extern int 
cicp_user_pkt_dest_ifid(ci_netif *netif, int pkt_id, ci_ifid_t *out_ifindex)
 */
    
/* Synchronization functions */
    
/*! Initialize any driver-global synchronization control plane state
 */
extern int /* rc */
cicpos_ctor(cicp_mibs_kern_t *control_plane);

/*! Indicate that new (NIC) hardware is now available for use
 *
 *  This function may repreent a convenient time at which resources for
 *  e.g. onward transmission of packets held pending ARP replies can be
 *  allocated
 */
extern void
cicpos_hw_registered(cicp_handle_t *control_plane);

/*! Finalize any driver-global synchronization control plane state
 */
extern void
cicpos_dtor(cicp_mibs_kern_t *control_plane);


/* Initial netif creation */

/*! Inherit per-netif control plane handle from a common kernel source */
ci_inline void
cicp_ni_sethandle(cicp_ni_t *ni_cplane, cicp_handle_t *control_plane)
{   ni_cplane->cp_mibs = control_plane;
}


#ifdef __KERNEL__
/* These functions are used in tcp_helper_resource - which is only compiled
   when we are in the kernel (not when we are a user-mode driver)
*/

/*! Initialize per-netif shared state memory map from global driver state */
extern size_t 
cicp_ns_map(cicp_ns_mmap_info_t *ni_shared, cicp_handle_t *control_plane);


/*! Map tables from global driver into per-netif handle */
extern int /* rc */
cicp_mmap(cicp_handle_t *control_plane, unsigned long *ref_bytes,
	  void *opaque, int *ref_map_num, unsigned long *ref_offset);


/*! Check whether control plane resources account for the page at the
 *  given offset
 *
 * \param netif_cplane    the network interface control plane data
 * \param opaque          data passed through to mapping function
 * \param ref_offset	  offset in cplane area of data to search
 * \param out_page_frameno the page in which the offset was found
 *
 * \return                true iff the offset was within control plane data
 *
 * This function provide a handler for "no page" error in shared memory buffers
 *
 * If the offset was not found within the control plane data areas the
 * location at \c ref_offset is decremented by the size of the control plane
 * data area for subsequent use outside this function.
 */
extern int /* bool */
cicp_nopage_found(cicp_ni_t *netif_cplane, void *opaque,
		  unsigned long *ref_offset,
		  unsigned int *out_page_frameno);


/*! Raw socket constructor */
extern  int cicp_raw_sock_ctor(struct socket **raw_sock);

/*! Raw socket destructor */
extern void cicp_raw_sock_dtor(struct socket *raw_sock);

/*! Send buffer via provided raw socket without trying to do any
 *  layer 4 checksum 
 */
extern int cicp_raw_sock_send(struct socket *raw_sock, ci_ip_addr_t ip_be32, 
                              const char *buf, unsigned int size);

/*! Send IP packet via RAW socket.  Computes TCP/UDP checksum if possible */
extern int cicp_raw_ip_send(ci_ip4_hdr* ip);

extern struct socket *cicp_bond_raw_sock;

/*! If ARP entry is STALE, force ARP request or confirm existing entry */
extern void cicpos_arp_stale_update(ci_ip_addr_t dst, ci_ifid_t ifindex,
                                    int confirm);

#endif /* __KERNEL__ */


#endif /* __CI_DRIVER_EFAB_CPLANE_H__ */
/*! \cidoxg_end */
