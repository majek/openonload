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
**  \brief  Control Plane operation definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_ops */

#ifndef __CI_INTERNAL_CPLANE_OPS2_H__
#define __CI_INTERNAL_CPLANE_OPS2_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cplane/shared_types.h>
#include <cplane/verlock.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/debug.h>
#include <ci/tools/byteorder.h>
#include <cplane/ioctl_ops.h>
#include <ci/net/ipv4.h>


/* UL/kernel code uses following primitives for locking.
 * Kernel: get cplane lock, assert that verlock does not indicate "under
 * update".
 * UL: use verlock.  The MIBS can not be written from user-lavel, because
 * the MIBs are mmapped with read-only flags.
 */
#ifdef __KERNEL__
#define CICP_READ_LOCK(handle, verlock) \
  CICP_LOCK_BEGIN(handle)
#define CICP_READ_UNLOCK(handle, verlock) \
    ci_assert(!ci_verlock_updating(&verlock)); \
  CICP_LOCK_END
#else
#define CICP_READ_LOCK(handle, verlock) \
  CI_VERLOCK_READ_BEGIN(verlock)
#define CICP_READ_UNLOCK(handle, verlock) \
  CI_VERLOCK_READ_END(verlock)
#endif



#if CPLANE_TEAMING

#define CICP_HASH_STATE_FLAGS_IS_IP      0x1
#define CICP_HASH_STATE_FLAGS_IS_TCP_UDP 0x2
#define CICP_HASH_STATE_FLAGS_IS_FRAG    0x4

struct cicp_hash_state {
  int flags;
  ci_mac_addr_t src_mac;
  ci_mac_addr_t dst_mac;
  ci_ip_addr_t src_addr_be32;
  ci_ip_addr_t dst_addr_be32;
  ci_uint16 src_port_be16;
  ci_uint16 dst_port_be16;
};

ci_inline void cicp_layer2_hash(const cicp_bond_row_t *row,
                                struct cicp_hash_state *hs,
                                int *out_hash)
{
  *out_hash = (hs->src_mac[5] ^ hs->dst_mac[5]) % row->master.n_active_slaves;
}


ci_inline void cicp_layer23_hash(const cicp_bond_row_t *row,
                                 struct cicp_hash_state *hs,
                                 int *out_hash)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    *out_hash = 
      ((CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff) ^ 
       (hs->src_mac[5] ^ hs->dst_mac[5])) % row->master.n_active_slaves;
  }
  else
    cicp_layer2_hash(row, hs, out_hash);
}


ci_inline void cicp_layer34_hash(const cicp_bond_row_t *row,
                                 struct cicp_hash_state *hs,
                                 int *out_hash)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    if( !(hs->flags & CICP_HASH_STATE_FLAGS_IS_FRAG) &&
        (hs->flags & CICP_HASH_STATE_FLAGS_IS_TCP_UDP) ) {
      *out_hash = 
        (CI_BSWAP_BE16(hs->src_port_be16 ^ hs->dst_port_be16) ^
         (CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff))
        % row->master.n_active_slaves;
    } else
      *out_hash = (CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff)
        % row->master.n_active_slaves;
  }
  else
    cicp_layer2_hash(row, hs, out_hash);
}

extern ci_hwport_id_t
ci_hwport_bond_get(cicp_handle_t* cplane, const cicp_encap_t *encap, 
                   ci_int16 bond_rowid, struct cicp_hash_state *hs);

#endif


ci_inline int ci_hwport_check_onload(ci_hwport_id_t hwport,
                                     const cicp_encap_t *encap)
{
  return ((hwport != CI_HWPORT_ID_BAD) ||
          (encap->type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT));
}

ci_inline void
cicp_mac_row_free(cicp_mac_row_t *row)
{   ci_verlock_write_start(&row->version);
}


ci_inline void
cicp_mac_row_allocate(cicp_mac_row_t *row)
{   ci_verlock_write_stop(&row->version);
}


ci_inline int /* bool */
cicp_mac_row_enter_requested(const cicp_mac_row_t *row)
{   return 0 != (row->use_enter & 0x8000);
}


ci_inline void
cicp_mac_row_enter_request(cicp_mac_row_t *row, int /* bool */see_me)
{   if (see_me)
        row->use_enter |= 0x8000;
    else
        row->use_enter &= 0x7FFF;
}


ci_inline ci_uint16
cicp_mac_row_usecount(const cicp_mac_row_t *row)
{   return row->use_enter & 0x7FFF;
}


ci_inline void
cicp_mac_row_usecount_inc(cicp_mac_row_t *row)
{   if ((row->use_enter & 0x7FFF) != 0x7FFF)
        row->use_enter++;
}


ci_inline void
cicp_mac_row_usecount_dec(cicp_mac_row_t *row)
{   row->use_enter--; /* must not be called when count is zero */
}


/*! the following should not be used unless a write lock has been
 *  obtained and no rows are being updated.
 */
ci_inline int /* bool */
cicp_mac_row_allocated(const cicp_mac_row_t *row)
{   return !ci_verlock_updating(&row->version);
}


ci_inline int
cicp_mac_mib_rows(const cicp_mac_mib_t *mact)
{   return (1 << mact->rows_ln2);
}


/* constant-preserving macro for determining size of kernel MAC MIB */ 
#define CICP_MAC_MIB_SIZE(_mact, _n) \
        (sizeof(*(_mact))+((_n)-1)*sizeof((_mact)->ipmac[0]))

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
             const ci_ip_addr_t ip, ci_uint8 *out_mac,
	     cicp_mac_verinfo_t *out_handle);




ci_inline int /* bool */
cicp_fwd_row_hasnic(const cicp_ul_mibs_t* user, const cicp_fwd_row_t *row)
{
  ci_assert(CICP_ROWID_IS_VALID(row->llap_rowid));
  return user->llapinfo_utable->llap[row->llap_rowid].hwport != CI_HWPORT_ID_BAD;
}

ci_inline ci_mtu_t
cicp_fwd_row_mtu(const cicp_ul_mibs_t* user, const cicp_fwd_row_t *row)
{
  ci_assert(CICP_ROWID_IS_VALID(row->llap_rowid));
  return row->mtu == 0 ?
    user->llapinfo_utable->llap[row->llap_rowid].mtu : row->mtu;
}

ci_inline void
cicp_fwd_row_free(cicp_fwd_row_t *row)
{   row->destnet_ipset = CI_IP_ADDRSET_BAD;
}


ci_inline int /* bool */
cicp_fwd_row_allocated(const cicp_fwd_row_t *row)
{   return (row->destnet_ipset != CI_IP_ADDRSET_BAD);
}


ci_inline ci_ifid_t
cicp_fwd_hwport_to_base_ifindex(const cicp_ul_mibs_t* user,
                                ci_hwport_id_t hwport)
{
  return user->llapinfo_utable->hwport_to_base_ifindex[hwport];
}

/*! Locate an entry in the routing table that incorporates the destination
 *
 *  It is assumed that this table is short and that it is, by and large,
 *  cheaper to search its content linearly than to maintain per-netmask
 *  structure and to search that.
 *
 *  The routing decision is made solely on the destination IP address.
 *  Currently TOS, routing metric, source IP address, etc. are not used.
 *
 *  The table is kept sorted with smaller destination IP address sets
 *  held in earlier entries and more widely applicable ones held in later
 *  ones.  Same netmask entries are ordered by the route metric.
 *  Thus the first match will always be the correct one.
 */
ci_inline const cicp_fwd_row_t *
_cicp_fwd_find_ip(const cicp_fwdinfo_t *fwdt, ci_ip_addr_t ip_dest,
                  ci_ifid_t dest_ifindex)
{
  const cicp_fwd_row_t *row    = &fwdt->path[0];
  const cicp_fwd_row_t *maxrow = row + fwdt->rows_max;
    
  while (row < maxrow && cicp_fwd_row_allocated(row) &&
         (!CI_IP_ADDR_SAME_NETWORK(&ip_dest,
                                  &row->destnet_ip, row->destnet_ipset) ||
         (dest_ifindex != CI_IFID_BAD && dest_ifindex != row->dest_ifindex)))
    row++;

  return row < maxrow && cicp_fwd_row_allocated(row)?
    (cicp_fwd_row_t *)row: (cicp_fwd_row_t *)NULL;
}




ci_inline void
cicp_bond_row_free(cicp_bond_row_t *row)
{
  row->type = CICP_BOND_ROW_TYPE_FREE;
}


ci_inline int /* bool */
cicp_bond_row_allocated(const cicp_bond_row_t *row)
{
  return (row->type != CICP_BOND_ROW_TYPE_FREE);
}


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



/*! emulating an "allocated" field in a llap row: set it to "unallocated" */
ci_inline int /* bool */
cicp_llap_row_allocated(const cicp_llap_row_t *row)
{   return (row->mtu > 0);
}

/*! read whether interface is up */
ci_inline int /* bool */
cicp_llap_row_isup(const cicp_llap_row_t *row)
{    return row->up;
}

/*! find the LLAP MIB row with the given ifindex - caller should care about
 * verlock */
ci_inline cicp_llap_row_t *
cicp_llap_find_ifid(const cicp_llapinfo_t *llapt, ci_ifid_t ifindex)
{   const cicp_llap_row_t *row;
    const cicp_llap_row_t *end_row = llapt->llap + llapt->rows_max;

    for (row = &llapt->llap[0]; row < end_row; ++row)
        if (cicp_llap_row_allocated(row) && row->ifindex == ifindex)
            return (cicp_llap_row_t *)row;

    return NULL;
}

extern int /* rc */
cicp_llap_retrieve(cicp_handle_t *control_plane, ci_ifid_t ifindex,
		   ci_mtu_t *out_mtu, ci_hwport_id_t *out_hwport,
		   ci_mac_addr_t *out_mac, cicp_encap_t *out_encap,
                   ci_ifid_t *out_base_ifindex, ci_int16* out_bond_rowid);

extern int /* rc */
cicp_llap_find(cicp_handle_t *control_plane, ci_ifid_t *out_ifindex,
	       ci_hwport_id_t port, const ci_uint16 vlan_id);




/*! Checks if the given ip address is both local and etherfabric.
 *  Returns 1 if it is, 0 if it isn't.
 *  If the address isn't found, it returns 0
 */
ci_inline int
cicp_user_addr_is_local_efab(cicp_handle_t *cplane,
			     const ci_ip_addr_t *ref_ip_be32)
{ 
  /* Sadly we need to initialize these because gcc 4 is dumb and bitches if we
   * don't (which is bad, since we compile with -Werror)
   */
  ci_hwport_id_t hwport = 0;
  if (CI_UNLIKELY(cicp_user_find_home(cplane, ref_ip_be32,
				      &hwport,
				      /*ifindex*/NULL, /*mac*/NULL,
                                      /*mtu*/NULL, /*encap*/NULL)))
    return 0;
  else
    return hwport != CI_HWPORT_ID_BAD;
}

ci_inline int /* bool */
cicp_user_is_local_addr(cicp_handle_t *cplane,
			const ci_uint32 *ref_ip_be32)
{
  ci_hwport_id_t hwport;
  return cicp_user_find_home(cplane, ref_ip_be32, &hwport,
                             /*ifindex*/NULL, /*mac*/NULL, /*mtu*/NULL,
                             /*encap*/NULL) == 0;
}

#ifdef __cplusplus
}
#endif

#endif  /* __CI_INTERNAL_CPLANE_OPS2_H__ */
