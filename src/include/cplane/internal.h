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

/* Cplane internal types, macros and functions */
#ifndef __CPLANE_INTERNAL_H__
#define __CPLANE_INTERNAL_H__

#include <cplane/debug.h>
#include <cplane/shared_ops.h>
#include <cplane/prot.h>
#include <cplane/internal_types.h>
#include <cplane/exported.h>
#include <cplane/ioctl.h>


/*----------------------------------------------------------------------------
 * OS lock and alloc
 *---------------------------------------------------------------------------*/
extern oo_os_lock_t oo_os_lock_alloc(void);
extern void oo_os_lock_free(oo_os_lock_t lock);

#ifdef NDEBUG
#define CICP_CHECK_LOCKED(_cplane) do {} while(0)
#else
extern int oo_os_lock_is_locked(oo_os_lock_t lock);
#define CICP_CHECK_LOCKED(_cplane)                      \
  do {                                                  \
    if( !oo_os_lock_is_locked((_cplane)->lock) )        \
      ci_fail(("cplane is not locked at %s:%d %s()",    \
              __FILE__, __LINE__, __func__));           \
  } while(0)
#endif

extern void* oo_os_alloc(int size, uintptr_t* cookie);
extern void oo_os_free(void* mem, uintptr_t cookie);

extern void oo_os_rand(ci_uint8* data, unsigned len);

/*----------------------------------------------------------------------------
 * O/S-specific Protocol Operations
 *---------------------------------------------------------------------------*/

/*! Initialize any driver-global O/S specific protocol control plane state */
extern int /* rc */
cicpplos_ctor(cicp_mibs_kern_t *control_plane);

/*! Finalize any driver-global O/S specific protocol control plane state */
extern void
cicpplos_dtor(cicp_mibs_kern_t *control_plane);

/* Queur incoming ARP packet - OS-specific part */
extern void
cicpplos_queue_arp(cicp_handle_t *control_plane, ci_ether_arp *arp,
                   ci_ifid_t ifindex, cicppl_rx_fifo_item_t *item_ptr);

/*! Work item routine that get scheduled in the work queue and reads ARP
    headers from the fifo and updates the arp table. */
extern void
cicppl_handle_arp_data(void);

extern void
cicppl_rx_fifo_push(cicppl_rx_fifo_item_t *item_ptr);


/*----------------------------------------------------------------------------
 * Pooled packet buffer support Operations
 *---------------------------------------------------------------------------*/

/*! Initialize memory to hold deferred packets awaiting MAC resolution */
extern int
cicppl_pktbuf_ctor(cicp_bufpool_t **out_pool);

/*! Free any memory used to hold deferred packets awaiting MAC resolution */
extern void
cicppl_pktbuf_dtor(cicp_bufpool_t **ref_pool);


/*----------------------------------------------------------------------------
 * Address Resolution MIB Operations
 *---------------------------------------------------------------------------*/

/*! Indicate that the numbered row has been seen during synchronization
 *
 * \param cplane_netif    control plane handle (use CICP_HANDLE(netif))
 * \param rowinfo         the number & version of the row in the MAC table seen
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_mac_row_seen(cicp_handle_t *cplane_netif, cicp_mac_verinfo_t *rowinfo);


/*!
 * Delete all address resolution entries other than those in the provided set
 *
 * \param cplane_netif   control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_mac_purge_unseen(cicp_handle_t *cplane_netif);



/*----------------------------------------------------------------------------
 * IP interface MIB
 *---------------------------------------------------------------------------*/

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
 */
extern int /* rc */
cicpos_ipif_import(cicp_handle_t     *cplane_netif, 
		   cicp_rowid_t      *out_rowid,
		   ci_ifid_t          ifindex,
		   ci_ip_addr_net_t   net_ip,
		   ci_ip_addrset_t    net_ipset,
		   ci_ip_addr_net_t   net_bcast,
		   ci_uint8           scope);


/*! Delete the IP interface row with the given set of subnet addresses
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_ipif_delete(cicp_handle_t   *cplane_netif, 
		   ci_ifid_t        ifindex,
		   ci_ip_addr_net_t net_ip,
		   ci_ip_addrset_t  net_ipset);

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


/*----------------------------------------------------------------------------
 * routing MIB
 *---------------------------------------------------------------------------*/

/*! Remove a route 
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param dest_ip         the route set base IP address
 * \param dest_set        the set of addresses based on \c dest_ip
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_route_delete(cicp_handle_t     *cplane_netif, 
		    ci_ip_addr_t       dest_ip,
		    ci_ip_addrset_t    dest_ipset,
                    ci_ifid_t          dest_ifindex);


/*----------------------------------------------------------------------------
 * address resolution MIB
 *---------------------------------------------------------------------------*/

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
 */
extern int /*rc*/
cicpos_mac_set(cicp_handle_t *cplane_netif,
	       cicp_mac_verinfo_t *out_rowinfo,
	       ci_ifid_t ifindex,
	       ci_ip_addr_net_t nexthop_ip,
	       const ci_mac_addr_t *mac,
	       const cicpos_mac_row_sync_t *os);

/*! Initialize kernel synchronization state in a MAC MIB */
extern int /* rc */
cicpos_mac_kmib_ctor(cicpos_mac_mib_t *sync);



/*! Initialize kernel synchronization state in a MAC MIB row */
extern void
cicpos_mac_kmib_row_ctor(cicpos_mac_row_t *syn_row,
			 const cicpos_mac_row_sync_t *os);


/*! Claim the "synchronizer" role with respect to the MAC table
 *
 * \param cplane_netif    control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
extern int /* bool */
cicpos_mact_open(cicp_handle_t *cplane_netif);


/*! Release the "synchronizer" role with respect to the MAC table
 *
 * \param cplane_netif   control plane handle (use CICP_HANDLE(netif))
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_mact_close(cicp_handle_t *cplane_netif);


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


/*----------------------------------------------------------------------------
 * Parse state
 *---------------------------------------------------------------------------*/

extern cicpos_parse_state_t *
cicpos_parse_state_alloc(cicp_handle_t *control_plane);

extern void cicpos_parse_state_free(cicpos_parse_state_t *session);

extern void cicpos_parse_init(cicpos_parse_state_t *session,
			      cicp_handle_t *control_plane);

extern void cicpos_route_post_poll(cicpos_parse_state_t *session);

extern void cicpos_llap_post_poll(cicpos_parse_state_t *session);

extern void cicpos_ipif_post_poll(cicpos_parse_state_t *session);



/*----------------------------------------------------------------------------
 * routing MIB
 *---------------------------------------------------------------------------*/

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
 * If \c flags & CICP_FLAG_ROUTE_MTU, than mtu is trusted and should be set
 * without any checks; untrusted mtu is used only if it is smaller than
 * currently-known mtu.
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
		    cicp_rowid_t       *out_rowid,
		    ci_ip_addr_t        dest_ip,
		    ci_ip_addrset_t     dest_ipset,
		    cicp_route_type_t   type,
		    ci_ip_addr_t        next_hop_ip,
		    ci_ip_tos_t         tos,
		    cicp_metric_t       metric,
		    ci_ip_addr_t        pref_source,
		    ci_ifid_t           ifindex,
		    ci_mtu_t            mtu,
		    int /* bool */      nosort);


/*----------------------------------------------------------------------------
 * access point MIB
 *---------------------------------------------------------------------------*/

/*! emulating an "allocated" field in a llap row: set it to "unallocated" */
ci_inline void
cicp_llap_row_free(cicp_llap_row_t *row)
{    row->mtu = 0;
}
ci_inline int
cicp_llap_row_is_free(const cicp_llap_row_t *row)
{
  return row->mtu == 0;
}

/*! emulating an "hasnic" field in a llap row: read whether our NIC */
ci_inline int /* bool */
cicp_llap_row_hasnic(const cicp_llap_row_t *row)
{
  return row->hwport != CI_HWPORT_ID_BAD;
}

/*! emulating an "up" field in a llap row: set it to up (true) or down */
ci_inline void
cicp_llap_row_set_updown(cicp_llap_row_t *row, int /* bool */ updown)
{    row->up = (ci_uint8)updown;
}


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
		   cicp_rowid_t *out_rowid,
		   ci_ifid_t ifindex,
		   ci_mtu_t mtu,
		   ci_uint8 /* bool */ up,
		   cicp_llap_type_t type,
		   const char *name,
		   ci_mac_addr_t *ref_mac);


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
                               ci_hwport_id_t hwport, cicp_rowid_t bond_rowid,
                               int fatal);

/* Synchronization functions optionally made visible to the user */

/*! Delete the link layer access point row with the given interface ID
 *
 * \param cplane_netif    control plane handle, e.g. CICP_HANDLE(netif)
 * \param ifindex         the O/S network access point to find in \c llapt
 *
 *  - (user-optional function) see driver header for documentation
 */
extern void
cicpos_llap_delete(cicp_handle_t *cplane_netif, ci_ifid_t ifindex);


/*----------------------------------------------------------------------------
 * PMTU MIB
 *---------------------------------------------------------------------------*/

extern int /* bool */
cicpos_pmtu_check(cicp_handle_t *control_plane, ci_ip_addr_net_t net_ip,
                  ci_ifid_t ifindex, ci_mtu_t pmtu);


/*----------------------------------------------------------------------------
 * Bonding MIB
 *---------------------------------------------------------------------------*/

#if CPLANE_TEAMING

extern int cicp_bond_find_rowid(cicp_handle_t *control_plane, 
                                ci_ifid_t ifindex);

extern int cicp_bond_set_active(cicp_handle_t *control_plane, 
                                cicp_rowid_t master_rowid,
                                ci_ifid_t master_ifindex,
                                cicp_rowid_t slave_rowid,
                                ci_ifid_t slave_ifindex,
                                int is_active);

extern int cicp_bond_get_n_active_slaves(cicp_handle_t *control_plane,
                                         cicp_rowid_t rowid,
                                         ci_ifid_t ifindex);

extern int 
cicp_bond_check_active_slave_hwport(cicp_handle_t *control_plane,
                                    cicp_rowid_t rowid,
                                    ci_ifid_t ifindex,
                                    ci_hwport_id_t curr_hwport,
                                    ci_hwport_id_t *hwport);

extern int cicp_bond_mark_row(cicp_handle_t *control_plane,
                              cicp_rowid_t rowid, 
                              ci_ifid_t ifindex);

extern void
cicp_bond_prune_unmarked_in_bond(cicp_handle_t *control_plane,
                                 ci_ifid_t master_ifindex);

extern int cicp_bond_set_hash_policy(cicp_handle_t *control_plane,
                                     cicp_rowid_t rowid, int mode,
                                     ci_ifid_t master_ifindex,
                                     int hash_policy);

extern int cicp_bond_check_slave_owner(cicp_handle_t *control_plane,
                                       cicp_rowid_t rowid,
                                       ci_ifid_t ifindex,
                                       ci_ifid_t master_ifindex);
extern int 
cicp_bond_add_slave(cicp_handle_t *control_plane, 
                    ci_ifid_t master_ifindex, ci_ifid_t ifindex);

extern int 
cicp_bond_remove_slave(cicp_handle_t *control_plane,
                       ci_ifid_t master_ifindex, ci_ifid_t ifindex);

extern int 
cicp_bond_remove_master(cicp_handle_t *control_plane, ci_ifid_t ifindex);

extern int cicp_bond_update_mode(cicp_handle_t *control_plane,
                                 cicp_rowid_t rowid,
                                 ci_ifid_t ifindex, int mode);

extern int cicp_bond_get_mode(cicp_handle_t *control_plane, 
                              cicp_rowid_t rowid, ci_ifid_t ifindex,
                              int *mode);

extern int
cicp_bond_get_master_ifindex(cicp_handle_t *control_plane,
                             ci_ifid_t slave_ifindex,
                             ci_ifid_t *master_ifindex);

#endif /* CPLANE_TEAMING */

/*----------------------------------------------------------------------------
 * statistics
 *---------------------------------------------------------------------------*/

extern oo_os_timestamp_t oo_os_timestamp(void);

#define cicp_stat_get_sys_ticks() oo_os_timestamp()


#define CICP_STAT_SET_SYS_TICKS(_cplane, fldname)		\
    (_cplane)->stat->fldname = cicp_stat_get_sys_ticks()


/* ARP module statistics access macros */
#define CICP_STAT_INC_DROPPED_IP(_cplane)     (++(_cplane)->stat->dropped_ip)
#define CICP_STAT_INC_TBL_FULL(_cplane)       (++(_cplane)->stat->tbl_full)
#define CICP_STAT_INC_TBL_CLASHES(_cplane)    (++(_cplane)->stat->tbl_clashes)
#define CICP_STAT_INC_UNSUPPORTED(_cplane)    (++(_cplane)->stat->unsupported)
#define CICP_STAT_INC_PKT_REJECT(_cplane)     (++(_cplane)->stat->pkt_reject)
#define CICP_STAT_INC_NL_MSG_REJECT(_cplane)  (++(_cplane)->stat->nl_msg_reject)
#define CICP_STAT_INC_RETRANS(_cplane)        (++(_cplane)->stat->retrans)
#define CICP_STAT_INC_TIMEOUTS(_cplane)       (++(_cplane)->stat->timeouts)
#define CICP_STAT_INC_REQ_SENT(_cplane)       (++(_cplane)->stat->req_sent)
#define CICP_STAT_INC_REQ_RECV(_cplane)       (++(_cplane)->stat->req_recv)
#define CICP_STAT_INC_REPL_RECV(_cplane)      (++(_cplane)->stat->repl_recv)
#define CICP_STAT_INC_REINFORCEMENTS(_cplane) (++(_cplane)->stat->reinforcements)
#define CICP_STAT_INC_FIFO_OVERFLOW(_cplane)  (++(_cplane)->stat->fifo_overflow)
#define CICP_STAT_INC_DL_C2N_TX_ERR(_cplane)  (++(_cplane)->stat->dl_c2n_tx_err)
#define CICP_STAT_INC_OTHER_ERRORS(_cplane)   (++(_cplane)->stat->other_errors)

#define CICP_STAT_SET_LAST_POLL_BGN(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, last_poll_bgn)
#define CICP_STAT_SET_LAST_POLL_END(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, last_poll_end)
#define CICP_STAT_SET_PKT_LAST_RECV(_cplane)  \
        CICP_STAT_SET_SYS_TICKS(_cplane, pkt_last_recv)


/*----------------------------------------------------------------------------
 * Control Plane kernel-visible information 
 *---------------------------------------------------------------------------*/

/*! Initialize and allocate driver-global control plane state
 *  \param control_plane   allocated data structure to initialize
 *  \param max_macs        size of mac table
 *  \param max_layer2_interfaces size of layer2 interface tables
 *  \param max_local_addrs size of ipif table
 *  \param max_routes      size of route table
 *  \returns               0 on success, negative error code otherwise
 */
extern int /* rc */
cicp_ctor(cicp_mibs_kern_t *control_plane, unsigned max_macs, 
          unsigned max_layer2_interfaces, unsigned max_local_addrs,
          unsigned max_routes);

/*! Finalize and free driver-global control plane state 
 *  \param control_plane   allocated data structure to tidy up
 */
extern void
cicp_dtor(cicp_mibs_kern_t *control_plane);

/*! Initialize any driver-global synchronization control plane state
 */
extern int /* rc */
cicpos_ctor(cicp_mibs_kern_t *control_plane);

/*! Finalize any driver-global synchronization control plane state
 */
extern void
cicpos_dtor(cicp_mibs_kern_t *control_plane);

/*! Send buffer via provided raw socket without trying to do any
 *  layer 4 checksum 
 */
extern int cicp_raw_sock_send_bindtodev(int ifindex, char *ifname, 
                                        ci_ip_addr_t ip_be32,
                                        const void* buf, unsigned int size);

/*! If ARP entry is STALE, force ARP request or confirm existing entry */
extern void cicpos_arp_stale_update(ci_ip_addr_t dst, ci_ifid_t ifindex,
                                    int confirm);


/*----------------------------------------------------------------------------
 * UL mmap support
 *---------------------------------------------------------------------------*/

/*! Initialize per-netif shared state memory map from global driver state */
extern void
cicp_ns_map(cicp_ns_mmap_info_t *ni_shared, cicp_handle_t *control_plane);

/*! Map tables from global driver into per-netif handle */
extern int /* rc */
cicp_mmap(cicp_handle_t *control_plane, unsigned long *ref_bytes,
	  void *opaque, int *ref_map_num, unsigned long *ref_offset);

/*! Check whether control plane resources account for the page at the
 *  given offset
 *
 * \param netif_cplane    the network interface control plane data
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
cicp_nopage_found(cicp_handle_t *cplane,
		  unsigned long ref_offset,
		  unsigned int *out_page_frameno);



enum cp_version_type {
  CP_VERSION_LIB,
  CP_VERSION_API,
};
extern const char *
cicp_binary_version(enum cp_version_type type);

#endif /* __CPLANE_INTERNAL_H__ */
