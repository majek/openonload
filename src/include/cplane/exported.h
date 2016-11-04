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

/* Cplane kernel module: exported functions. */
#ifndef __CPLANE_EXPORTED_H__
#define __CPLANE_EXPORTED_H__

#include <cplane/driver_types.h>
#include <ci/net/ipv4.h>

#include <cplane/shared_ops.h>


#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility push(default)
#endif


extern cicp_handle_t onload_cplane_handle;
#define CI_GLOBAL_CPLANE   onload_cplane_handle


/*----------------------------------------------------------------------------
 * Licensing
 *---------------------------------------------------------------------------*/
extern int
cicp_licensing_get_challenge(ci_hwport_id_t hwport, char *challenge_buf,
                             size_t challenge_len);

extern int /* bool */
cicp_licensing_has_state_been_set(ci_hwport_id_t hwport);

struct efhw_device_type;

extern void
cicp_licensing_validate_signature(ci_hwport_id_t hwport,
                                  const ci_uint8* signature,
                                  ci_uint64 app_id,
                                  ci_uint32 expiry_date,
                                  ci_uint32 expiry_units,
                                  ci_uint8* base_macaddr,
                                  ci_uint8* vadaptor_macaddr,
                                  ci_uint64 license_state,
                                  struct efhw_device_type *devtype);

/*----------------------------------------------------------------------------
 * PMTU MIB
 *---------------------------------------------------------------------------*/

extern void
cicpos_pmtu_add(cicp_handle_t *control_plane, ci_ip_addr_net_t net_ip);

/*----------------------------------------------------------------------------
 * Bonding MIB
 *---------------------------------------------------------------------------*/

#if CPLANE_TEAMING

extern int /* rc */
cicp_llap_set_bond(cicp_handle_t *control_plane, ci_ifid_t ifindex);

extern void ci_bonding_set_timer_period(int period, int occurences);

#endif /* CPLANE_TEAMING */

/* Caller must NOT take control plane lock before calling this */
extern int cicp_get_active_hwport_mask(cicp_handle_t *control_plane,
                                       ci_ifid_t ifindex, 
                                       unsigned *hwport_mask);

/*----------------------------------------------------------------------------
 * access point MIB
 *---------------------------------------------------------------------------*/

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

/*! Link the VLAN interface LLAP to the master LLAP in the control plane
 */
extern int /* rc */
cicp_llap_set_vlan(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                   ci_ifid_t master_ifindex, ci_uint16 vlan_id);

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

/*! Import data into the link layer access point cache
 *
 * \param control_plane   control plane handle
 * \param ifindex         O/S index of this layer 2 interface
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param type            llap type (SFC, bond, vlan, etc)
 * \param name            name of interface
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
cicp_llap_import(cicp_handle_t *control_plane, 
		   ci_ifid_t ifindex,
		   ci_mtu_t mtu,
		   cicp_llap_type_t type,
		   const char *name);


/*----------------------------------------------------------------------------
 * IP interface MIB
 *---------------------------------------------------------------------------*/

/* Find the specific destination address of the packet */
extern int cicp_ipif_find_spec_addr(const cicp_handle_t *cplane_netif,
                                    ci_ifid_t ifindex,
                                    ci_ip_addr_t dst_ip_be32,
                                    ci_ip_addr_t src_ip_be32,
                                    ci_ip_addr_t *out_spec_addr);

/* Find the number of ipif routes */
extern unsigned cicp_get_max_local_addr(cicp_handle_t *control_plane);

/*----------------------------------------------------------------------------
 * Callbacks
 *---------------------------------------------------------------------------*/

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
 * used with \c cicpos_callback_deregister.
 *
 * The two functions are called in the kernel's environment in response to
 * updates from the synchronization code.
 */
extern int
cicpos_callback_register(cicp_handle_t            *control_plane,
                         cicpos_ipif_event_fn_t   *add_fn,
                         cicpos_ipif_event_fn_t   *delete_fn,
                         cicpos_llap_event_fn_t   *llap_fn,
                         cicpos_hwport_event_fn_t *hwport_fn,
                         void                     *arg);

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
 * \c cicpos_callback_register.
 */
extern void
cicpos_callback_deregister(cicp_handle_t           *control_plane);


/*----------------------------------------------------------------------------
 * Cplane lock
 *---------------------------------------------------------------------------*/

extern void oo_os_lock_lock(oo_os_lock_t lock);
extern void oo_os_lock_unlock(oo_os_lock_t lock);
#define cicp_lock(cplane) oo_os_lock_lock((cplane)->lock)
#define cicp_unlock(cplane) oo_os_lock_unlock((cplane)->lock)


#define CICP_LOCK_BEGIN(_cplane)                        \
        do {                                            \
            cicp_handle_t *_control_plane = _cplane;    \
            cicp_lock(_cplane);                         \
            {

#define CICP_LOCK_END                                   \
            }                                           \
            cicp_unlock(_control_plane);                \
        } while(0);


#define CICP_LOCK(_cplane, _code)   \
        CICP_LOCK_BEGIN(_cplane)    \
            _code;                  \
        CICP_LOCK_END


/*----------------------------------------------------------------------------
 * netif support
 *---------------------------------------------------------------------------*/


/*! Send IP packet via RAW socket.  Computes TCP/UDP checksum if possible */
extern int cicp_raw_ip_send(const ci_ip4_hdr* ip, int len, ci_ifid_t ifindex);

/*! Force full table sync. */
extern void
cicpos_sync_tables(cicp_handle_t *control_plane);

#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility pop
#endif

#endif /* __CPLANE_EXPORTED_H__ */
