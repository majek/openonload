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
**  \brief  Control Plane kernel code
**   \date  2005/07/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is available both in the kernel and from the
 *  user-mode libraries.
 *
 *  This code could be split among a number of different files but is divided
 *  instead into the following sections:
 *
 *      ACM  - Functions on Abstract Cacheable MIBs
 *             (which hide use of CM and support protocols)
 *      CM   - Functions on Cacheable MIBs
 *             (which hide use of SYN)
 *      SYN  - Functions on local MIB caches required for O/S synchronization
 *
 *  These divisions are documented in L5-CGG/1-SD 'IP "Control Plane" Design
 *  Notes'
 *
 *  Within each section code supporting each of the following Management
 *  Information Bases (MIBs) potentially occur.
 *
 *  User and kernel visible information
 *
 *      cicp_mac_kmib_t    - IP address resolution table
 *
 *      cicp_fwdinfo_t     - cache of kernel forwarding information table
 *
 *  The information is related as follows:
 *
 *   * the IP address resolution table provides link layer addresses usable at
 *     a given link layer access point that identify IP entities directly
 *     connected to IP interfaces the access point supports
 *
 *   * the cache of forwarding information remembers a complete set of the
 *     data that needs to be known when transmitting to a destination
 *     IP address - including the first hop and its link layer access point
 *     for example
 *
 */




/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/





#include <ci/internal/cplane_ops.h>
#include <ci/internal/cplane_handle.h>

#ifdef __KERNEL__
# include <onload/cplane.h>
#endif



#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif



#ifdef __KERNEL__
# define CICP_LOCK_BEGIN_IF(cplane, is_locked)          \
  do {                                                  \
    ci_irqlock_state_t lock_flags;                      \
    if( ! (is_locked) )                                 \
      ci_irqlock_lock(&(cplane)->lock, &lock_flags);    \
    do {
# define CICP_LOCK_END_IF(cplane, is_locked)            \
    } while( 0 );                                       \
    if( ! (is_locked) )                                 \
      ci_irqlock_unlock(&(cplane)->lock, &lock_flags);  \
  } while( 0 )
# define ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt)    \
  ci_assert(!ci_verlock_updating(&(fwdt)->version))
#else
# define CICP_LOCK_BEGIN(_cplane)        do{
# define CICP_LOCK_END                   }while(0)
# define CICP_LOCK_BEGIN_IF(cp, locked)  do{
# define CICP_LOCK_END_IF(cp, locked)    }while(0)
# define ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt)  do{}while(0)
#endif


/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#ifdef IGNORE
#undef IGNORE
#endif

#ifdef DO
#undef DO
#endif

#define DO(_x) _x
#define IGNORE(_x)


#define DEBUG_FORCE

/* #define DEBUGMEM          DO */
/* #define DEBUGMACHASH      DO */
/* #define DEBUGFWDINFO      DO */
/* #define DEBUGCONFIRM      DO */
/* #define DEBUGLOGEVENTS    DO */
/* #define DEBUGMIBROUTELOG  DO */  /* show content of route MIB */
/* #define DEBUGMIBFWDLOG    DO */  /* show content of forwarding info MIB */

/* switch off debugging in non-debug builds */
#if defined(NDEBUG) && !defined(DEBUG_FORCE)
#undef DEBUGMEM
#undef DEBUGMACHASH
#undef DEBUGFWDINFO
#undef DEBUGCONFIRM
#undef DEBUGLOGEVENTS
#undef DEBUGMIBROUTELOG
#undef DEBUGMIBFWDLOG
#endif

#ifndef DEBUGMEM
#define DEBUGMEM          IGNORE
#endif
#ifndef DEBUGMACHASH
#define DEBUGMACHASH      IGNORE
#endif
#ifndef DEBUGFWDINFO
#define DEBUGFWDINFO      IGNORE
#endif
#ifndef DEBUGCONFIRM
#define DEBUGCONFIRM      IGNORE
#endif
#ifndef DEBUGLOGEVENTS
#define DEBUGLOGEVENTS    IGNORE
#endif
#ifndef DEBUGMIBROUTELOG
#define DEBUGMIBROUTELOG  IGNORE
#endif
#ifndef DEBUGMIBFWDLOG
#define DEBUGMIBFWDLOG    IGNORE
#endif

#if 0 != (DEBUGMIBROUTELOG(1+)0)
#undef DEBUGMIBFWDLOG
#define DEBUGMIBFWDLOG DO
#endif

#define DPRINTF ci_log

#define CODEID "cplane(ul)"




/*****************************************************************************
 *****************************************************************************
 *                                                                           *
 *          ACM - Abstract Cacheable MIBs                                    *
 *          =============================                                    *
 *                                                                           *
 *****************************************************************************
 *****************************************************************************/





/*****************************************************************************
 *                                                                           *
 *          Address Resolution MIB					     *
 *          ======================					     *
 *                                                                           *
 *****************************************************************************/




/*! This number defines the number of hash table entries that will be
 *  searched to find a match.  A maximum of CICP_MAC_HASHMAX entries
 *  will be searched.  Note that this number of entries may have to be
 *  searched whether a match is found or not because
 *  former intermediate collisions may have been deleted from the table.
 *
 *  Note that with a perfect hash/rehash the chances of clashing when the table
 *  is "2^-o" percent occupied is 2^-o.  The probability of clashing n times is
 *  2^(-no). If we want to keep this probability low, say lower than 2^-p, we
 *  need to ensure that 2^(-no) <= 2^-p,
 *                     =>   -no <= -p,
 *                     =>     o > p/n
 *
 *  The occupancy of the table depends on its size and the number of used
 *  entries, u:   2^-o = u/2^s
 *                2^(s-o) = u
 *                o = s - ln2(u)
 *
 *  If o > p/n then ideally the size, 2^s, will be such that
 *         s - ln2(u) > p/CICP_MAC_HASHMAX
 *  =>     s - p/CICP_MAC_HASHMAX > ln2(u)
 *  =>     u < 2^(s - p/CICP_MAC_HASHMAX)
 *
 *  In principle we can work out p/CICP_MAC_HASHMAX once (e.g. for a
 *  one-in-a million failure p=20 with a maximum of 8 rehashes this would be
 *  20/8 = 2.5 which we would round up to the next integer 3). We would
 *  re-evaluate this condition on each addition to the table, doubling the size
 *  of the table (increasing s by one) every time it is found to be false.
 *
 *  Actually, now that we employ reference counts in the entries, it is less
 *  important that this number be small - since a search will now be stopped
 *  by an unused entry.
 */
#define CICP_MAC_HASHMAX 500
/*  A value of 20 allows a 1K entry table to grow to 2^9 = 512 entries
 *  maintaining a failure probability of 2^-20
 */




/*! Generate a rows_ln2-bit hash of an IP address
 *
 *  This function tries to ensure that, roughly speaking, there is as much
 *  dependence of the hash value on all parts of the IP address as possible
 *  whatever the size of the hash.
 *
 *  Note that it is very likely that all of the addresses submitted to this
 *  function belong to the same one or two subnets (since all addresses are
 *  next hops), so it is much more important to make use of variability in the
 *  bottom bits than in the top ones.
 */
ci_inline cicp_mac_rowid_t
cicp_mac_hash(int rows_ln2, ci_uint32 ip_hash32, ci_ifid_t ifindex)
{   ci_uint32 hash = ip_hash32 ^ (ip_hash32 >> 16) ^ ifindex;
    hash = hash ^ (hash >> 8);
    /* This hash value has contributions from all four bytes in the bottom
       byte, and both 16-bit values in the bottom 16-bits
    */
    DEBUGMACHASH(DPRINTF(CODEID": %02d %08X #%x",
			 ifindex, ip_hash32, hash & ((1<<rows_ln2) - 1));)
    return hash & ((1<<rows_ln2) - 1);
}




#ifndef ci_rot_r
ci_inline int ci_rot_r(ci_uint32 i, int n)
{   /* I bet the processor has a more efficient way of doing a 32-bit right
       rotate!
    */
    n = n & 0x1f;
    return (i >> n) | (i << (32-n));
}
#endif





ci_inline cicp_mac_rowid_t
cicp_mac_rehash(int rows_ln2, ci_uint32 ip_hash32, ci_ifid_t ifindex,
		int iteration)
{   /* We hope we get a result on the first hash and that this function
       won't be called so often as the initial hash.
       There is probably more variability in the lower order bits of
       the IP address so it might be best to ensure they get used in
       the rehash.
       This function rotates lower order bits into place depending on
       the iteration.
       We add the iteration number in so that if we continue to clash
       with other hashes after the 32nd iteration subsequent rehashes we
       will not simply repeat - the cost is some loss of dependence on
       the original address in the bottom bits.
    */
    return cicp_mac_hash(rows_ln2,
			 ci_rot_r(ip_hash32, iteration) + iteration,
			 ifindex);
}




/* Find an allocated MAC entry holding the given IP address
 * - see header for documentation
 */
extern cicp_mac_rowid_t
cicpos_mac_find_ip(const cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		   ci_ip_addr_t ip, ci_verlock_value_t *out_ver)
{   int rows_ln2 = mact->rows_ln2;
    ci_uint32 ip_hash32 = CI_IP_ADDR_HASH32(&ip);
    /* above preferably with high-order subnet-constant address bits */
    cicp_mac_rowid_t rowid = cicp_mac_hash(rows_ln2, ip_hash32, ifindex);
    const cicp_mac_row_t *ipmac = &mact->ipmac[0];
    const cicp_mac_row_t *row = &ipmac[rowid];
    int iteration = 0;

    *out_ver = ci_verlock_get(&row->version);
    /* record initial version - before we use it */

    /* Single initial test to optimize hoped-for best case */
    if (cicp_mac_row_allocated(row = &ipmac[rowid]) &&
	row->ifindex == ifindex &&
	CI_IP_ADDR_EQ(&row->ip_addr, &ip))
	return rowid;
    else if (cicp_mac_row_usecount(row) <= 0)
	/* nothing hashes through here - that was the only row it could be */
	return CICP_MAC_ROWID_BAD;  
    else
    {	int /*bool*/ found;
	do {
	    DEBUGMACHASH(DPRINTF(CODEID": retry");)
	    rowid = cicp_mac_rehash(rows_ln2, ip_hash32, ifindex, ++iteration);
	    row = &ipmac[rowid];
            *out_ver = ci_verlock_get(&row->version);
	    found = cicp_mac_row_allocated(row) &&
                    row->ifindex == ifindex &&
		    CI_IP_ADDR_EQ(&row->ip_addr, &ip);
	} while (!found && cicp_mac_row_usecount(row)> 0 &&
		 iteration < CICP_MAC_HASHMAX);
	/* we rehash no more than CICP_MAC_HASHMAX number of times but only
	   until we find a row with a zero use count (i.e. one on no hash
	   chains
	*/

        return found? rowid: CICP_MAC_ROWID_BAD;
    }
}
	   
    







#ifdef __ci_driver__

/* Find and delete an allocated MAC entry that holds the given IP address
 *
 * \param mact            the address resolution table
 * \param ip              the IP address being looked for
 *
 * \return                \c CICP_MAC_ROWID_BAD iff not found, index otherwise
 *
 * This function should only be used when it is known that an address table
 * entry holding the given MAC and IP address is known to exist.
 *
 * This function decrements the hash chain use-count of all of the entries
 * which are hashed/rehashed to.
 *
 * No locking of the MAC table is used in this function, but locking is
 * required in order to ensure that none of the entries are written to
 * during the seach (which would make them look allocated)
 */
extern cicp_mac_rowid_t
_cicp_mac_find_ipaloc(cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		      ci_ip_addr_t ip)
{   int rows_ln2 = mact->rows_ln2;
    ci_uint32 ip_hash32 = CI_IP_ADDR_HASH32(&ip);
    /* above preferably with high-order subnet-constant address bits */
    cicp_mac_row_t *ipmac = &mact->ipmac[0];
    cicp_mac_rowid_t rowid = cicp_mac_hash(rows_ln2, ip_hash32, ifindex);
    cicp_mac_row_t *row = &ipmac[rowid];
    int iteration = 0;

    cicp_mac_row_usecount_dec(row); /* no longer on this hash chain */
	
    /* Single initial test to optimize hoped-for best case */
    if (cicp_mac_row_allocated(row) &&
	row->ifindex == ifindex && CI_IP_ADDR_EQ(&row->ip_addr, &ip))
        return rowid;
    else
    {	int /*bool*/ found;
	do {
	    rowid = cicp_mac_rehash(rows_ln2, ip_hash32, ifindex, iteration);
	    row = &ipmac[rowid];
	    cicp_mac_row_usecount_dec(row); /* no longer on this hash chain */
	    found = cicp_mac_row_allocated(row) &&
                    row->ifindex == ifindex &&
		    CI_IP_ADDR_EQ(&row->ip_addr, &ip);
	} while (!found && ++iteration < CICP_MAC_HASHMAX);

        return found? rowid: CICP_MAC_ROWID_BAD;;
    }
}
	   
    






/* Find an unallocated MAC entry to hold the given IP address
 *
 * \param mact            the address resolution table
 * \param ip              the IP address being looked for
 *
 * \return                \c CICP_MAC_ROWID_BAD iff not found, index otherwise
 *
 * This function returns the index of the MAC table entry which will either be
 * \c CICP_MAC_ROWID_BAD or will be a value guaranteed to be within the bounds
 * of the address resolution table.
 *
 * If a free entry is found this function increments the hash chain use-count
 * of all of the entries which are hashed/rehashed to.
 *
 * Note that this function executes only CICP_MAC_HASHMAX inspections
 * of the table.  This will limit the number of corresponding inspections
 * needed to locate the entry once it has been positioned.  Unfortunately
 * it also increases the chances that no free entry will be found in a
 * heavily occupied table.
 *
 * No locking of the MAC table is used in this function, but locking is
 * required in order to ensure that none of the entries are written to
 * during the seach (which would make them look allocated)
 */
extern cicp_mac_rowid_t
_cicp_mac_find_ipunaloc(cicp_mac_mib_t *mact, ci_ifid_t ifindex,
		        ci_ip_addr_t ip)
{   int rows_ln2 = mact->rows_ln2;
    ci_uint32 ip_hash32 = CI_IP_ADDR_HASH32(&ip);
    /* above preferably with high-order subnet-constant address bits */
    cicp_mac_row_t *ipmac = &mact->ipmac[0];
    cicp_mac_rowid_t rowid = cicp_mac_hash(rows_ln2, ip_hash32, ifindex);
    cicp_mac_row_t *row = &ipmac[rowid];
    int iteration = 0;

    cicp_mac_row_usecount_inc(row); /* now on another hash chain */
    
    /* Single initial test to optimize hoped-for best case */
    if (!cicp_mac_row_allocated(row))
	return rowid;
    else
    {	int /*bool*/ found;
	do {
	    rowid = cicp_mac_rehash(rows_ln2, ip_hash32, ifindex, iteration);
	    row = &ipmac[rowid];
	    cicp_mac_row_usecount_inc(row); /* now on another hash chain */
	    found = !cicp_mac_row_allocated(row);
	} while (!found && ++iteration < CICP_MAC_HASHMAX);

	if (found)
	    return rowid;
	else
	{   /* we'd better undo all the hash chain increments we've added! */
	    (void)_cicp_mac_find_ipaloc(mact, ifindex, ip);
	    return CICP_MAC_ROWID_BAD;
	}	    
    }
}

#endif
    




extern int /* rc */
cicp_mac_get(const cicp_mac_mib_t *mact, ci_ifid_t ifindex,
             const ci_ip_addr_t ip, ci_mac_addr_t *out_mac,
	     cicp_mac_verinfo_t *out_handle)
{   cicp_mac_rowid_t rowid;
    int rc;

    ci_assert(NULL != mact);
    ci_assert(NULL != out_mac);
    ci_assert(NULL != out_handle);

    rowid = cicpos_mac_find_ip(mact, ifindex, ip, &out_handle->row_version);
    if (CICP_MAC_ROWID_BAD != rowid)
    {   /* even if the data is invalid this rowid will be in the table */
	const cicp_mac_row_t *row = &mact->ipmac[rowid];
        ci_assert(row);
	out_handle->row_index = rowid;
	CI_MAC_ADDR_SET(out_mac, row->mac_addr);
        rc = row->rc;
        if(CI_LIKELY( ! ci_verlock_updating(&out_handle->row_version) &&
                      ci_verlock_unchanged(&row->version,
                                           out_handle->row_version) ))
          return rc;
        else
          return -EAGAIN;
    } else
	return -EDESTADDRREQ;
}







/*****************************************************************************
 *                                                                           *
 *          hwport access						     *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/

#if CI_CFG_TEAMING

extern ci_hwport_id_t ci_hwport_bond_get(cicp_handle_t* cplane,
                                         int cplane_locked,
                                         const cicp_encap_t *encap, 
                                         ci_int16 bond_rowid,
                                         struct cicp_hash_state *hs)
{
  const cicp_ul_mibs_t *user = &CICP_MIBS(cplane)->user;
  int hash = -1;
  ci_hwport_id_t rc;
  cicp_bond_row_t *bond_row;
  const cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;
  ci_verlock_value_t vlock;

  ci_assert(bond_rowid >= 0 || bond_rowid == CICP_BOND_ROW_NEXT_BAD);
  ci_assert(bond_rowid < user->bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN_IF(cplane, cplane_locked);
  ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt);
 again:
  vlock = fwdt->version;
  ci_rmb();  /* Read lock before fields. */

  if(CI_UNLIKELY( ci_verlock_updating(&vlock) ))
    goto again;

  if( bond_rowid == CICP_BOND_ROW_NEXT_BAD )
    rc = CI_HWPORT_ID_BAD;
  else {
    bond_row = &user->bondinfo_utable->bond[bond_rowid];

    if( bond_row->type != CICP_BOND_ROW_TYPE_MASTER )
      return CI_HWPORT_ID_BAD;

    switch( bond_row->master.mode ) {
    case CICP_BOND_MODE_ACTIVE_BACKUP:
      rc = bond_row->master.active_hwport;
      break;
    case CICP_BOND_MODE_802_3AD:
      if( bond_row->master.n_slaves && bond_row->master.n_active_slaves ) {
        switch( bond_row->master.hash_policy ) {
        case CICP_BOND_XMIT_POLICY_LAYER2:
          cicp_layer2_hash(bond_row, hs, &hash);
          break;
        case CICP_BOND_XMIT_POLICY_LAYER23:
          cicp_layer23_hash(bond_row, hs, &hash);
          break;
        case CICP_BOND_XMIT_POLICY_LAYER34:
          cicp_layer34_hash(bond_row, hs, &hash);
          break;
        default:
          ci_assert(0);
        }
        ci_assert(hash >= 0);
        if( hash >= bond_row->master.n_active_slaves ) 
          rc = CI_HWPORT_ID_BAD;
        else {
          rc = CI_HWPORT_ID_BAD;
          while( bond_row->next != CICP_BOND_ROW_NEXT_BAD ) {
            bond_row = &user->bondinfo_utable->bond[bond_row->next];
            if( bond_row->type != CICP_BOND_ROW_TYPE_SLAVE )
              return CI_HWPORT_ID_BAD;
            if( bond_row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ) {
              --hash;
              if( hash < 0 ) {
                rc = bond_row->slave.hwport;
                break;
              }
            }
          }
        }
      }
      else 
        rc = CI_HWPORT_ID_BAD;
      break;
    default:
      rc = CI_HWPORT_ID_BAD;
    }
  }

  ci_rmb();
  if(CI_UNLIKELY( fwdt->version != vlock ))
    goto again;
  CICP_LOCK_END_IF(cplane, cplane_locked);

  return rc;
}

/* Returns 0 if it is a master interface (and fills hwports list).
 * Returns -1 if it is not a bond master interface. */
extern int ci_bond_get_hwport_list(cicp_handle_t* cplane, ci_ifid_t ifindex,
                                   ci_int8 hwports[])
{
  ci_verlock_value_t *vlock = NULL;
  const cicp_ul_mibs_t *user = &CICP_MIBS(cplane)->user;
  const cicp_bondinfo_t *bondt = user->bondinfo_utable;
  const cicp_bond_row_t *bond_row = &bondt->bond[0];
  const cicp_bond_row_t *max_bond_row = bond_row + bondt->rows_max;
  const cicp_fwdinfo_t *fwdt = user->fwdinfo_utable;

  CICP_LOCK_BEGIN_IF(cplane, vlock == NULL);
  ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt);
 again:
  if( vlock != NULL ) {
    *vlock = fwdt->version; /* Yes, bondt uses fwdt->version :-) */
    ci_rmb();  /* Read lock before fields. */
    if(CI_UNLIKELY( ci_verlock_updating(vlock) ))
      goto again;
  }

  while( bond_row < max_bond_row) {
    if( cicp_bond_row_allocated(bond_row) && bond_row->ifid == ifindex ) {
      ci_int16 slave_rowid;
      if( bond_row->type != CICP_BOND_ROW_TYPE_MASTER)
        return -ENODEV;
      for( slave_rowid = bond_row->next;
           slave_rowid != CICP_BOND_ROW_NEXT_BAD;
           slave_rowid = bondt->bond[slave_rowid].next ) {
        hwports[bondt->bond[slave_rowid].slave.hwport] = 1;
      }
      break;
    }
    ++bond_row;
  }
  if( bond_row == max_bond_row )
    return -ENODEV;

  if( vlock != NULL ) {
    ci_rmb();
    if( CI_UNLIKELY(fwdt->version != *vlock) )
      goto again;
  }
  CICP_LOCK_END_IF(cplane, vlock == NULL);

  return 0;
}

#endif


/*****************************************************************************
 *                                                                           *
 *          Cache of Forwarding Information				     *
 *          ===============================				     *
 *                                                                           *
 *****************************************************************************/







#if 0 != DEBUGMIBFWDLOG(1+)0


static int /* rc */
fwd_get_row(const cicp_handle_t *control_plane,
	    cicp_fwd_row_t *route_mem, cicp_fwd_rowid_t rowid,
	    ci_verlock_t *out_version)
{   const cicp_ul_mibs_t *user = &CICP_MIBS(control_plane)->user;
    const cicp_fwdinfo_t *fwdt = NULL;
    const cicp_fwd_row_t *row;
    int result;

    if (NULL != user)
        fwdt = user->fwdinfo_utable;

    if (NULL == fwdt)
	result = -ENODEV; /* where are the tables?? - device not open? */

    else if (rowid >= fwdt->rows_max || rowid < 0)
	result = -EINVAL;
    else
    {   CI_VERLOCK_READ_BEGIN(fwdt->version)
	    /* we want to re-do all of the following if the forwarding table
	       gets updated during the operation of this code
	    */

	    row = &fwdt->path[rowid];
	    if (cicp_fwd_row_allocated(row))
	    {   memcpy(route_mem, row, sizeof(*route_mem));
		result = 0;
	    } else
		result = -ENODEV;

	    *out_version = fwdt->version;
	    
	CI_VERLOCK_READ_END(fwdt->version)
    }	
    return result;
}







typedef void *fwd_row_fn_t(cicp_fwd_rowid_t n, const cicp_fwd_row_t *route,
		           void *arg);



static void *
fwd_for_row(const cicp_handle_t *control_plane, fwd_row_fn_t *rowdo, void *arg)
{  
  void *found = NULL;
  cicp_fwd_rowid_t i = 0;
  cicp_fwd_row_t route;
  ci_verlock_t fwdver;
  int rc;
  const cicp_ul_mibs_t *user = &CICP_MIBS(control_plane)->user;
  const cicp_fwdinfo_t *fwdt = NULL;
  if( user != NULL )
    fwdt = user->fwdinfo_utable;
  if( fwdt == NULL )
    return NULL;
  while( i < fwdt->rows_max && found == NULL ) {
    rc = fwd_get_row(control_plane, &route, i, &fwdver);
    if( rc == 0 )
      found = (*rowdo)(i, &route, arg);
    ++i;
  }
  return found;
}
	








static void *fwd_row_print(cicp_fwd_rowid_t n, const cicp_fwd_row_t *row,
		           void *arg)
{
    cicp_ul_mibs_t *user = (cicp_ul_mibs_t *)arg;

    if (cicp_fwd_row_allocated(row)) {   
        if (cicp_fwd_row_hasnic(user, row))
            ci_log("%02d: "CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT
                   " -> " CI_IP_PRINTF_FORMAT
	           " llap "CI_IFID_PRINTF_FORMAT" port "
	           "%1d encap %s",
	           n, CI_IP_PRINTF_ARGS(&row->destnet_ip),
	           CI_IP_ADDRSET_PRINTF_ARGS((unsigned)row->destnet_ipset),
	           CI_IP_PRINTF_ARGS(&row->first_hop), row->dest_ifindex,
		   row->hwport, cicp_encap_name(row->encap.id));
	else
            ci_log("%02d: "CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT
                   " -> " CI_IP_PRINTF_FORMAT
	           " llap "CI_IFID_PRINTF_FORMAT" port X",
	           n, CI_IP_PRINTF_ARGS(&row->destnet_ip),
	           CI_IP_ADDRSET_PRINTF_ARGS((unsigned)row->destnet_ipset),
	           CI_IP_PRINTF_ARGS(&row->first_hop), row->dest_ifindex);

	ci_log("    dst "CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT
               " bcast " CI_IP_PRINTF_FORMAT
	       " mtu %d"
	       " tos %d metric %d",
	       CI_IP_PRINTF_ARGS(&row->net_ip),
               CI_IP_ADDRSET_PRINTF_ARGS((unsigned)row->net_ipset),
	       CI_IP_PRINTF_ARGS(&row->net_bcast), row->mtu,
	       row->tos, row->metric);
	ci_log("    src ip "CI_IP_PRINTF_FORMAT " mac "CI_MAC_PRINTF_FORMAT,
               CI_IP_PRINTF_ARGS(&row->pref_source),
	       CI_MAC_PRINTF_ARGS(&row->pref_src_mac));
    }
    return NULL;
}






static void
cicp_fwd_log(const cicp_handle_t *control_plane)
{   ci_log(CODEID": Cache of Forwarding information:");
    fwd_for_row(control_plane, &fwd_row_print, &control_plane->user);
}


#else

#define cicp_fwd_log(cplane)

#endif /* DEBUGMIBFWDLOG */






#if 0 != DEBUGMIBROUTELOG(1+)0

static void *route_row_print(cicp_fwd_rowid_t n, const cicp_fwd_row_t *row,
		            void *arg)
{   (void)arg; /* unused */
    
    /* <ip dest>/<bits> <ip next> <tos> <metric> <ip source> <ifid> */
    
    if (CI_IP_ADDR_IS_EMPTY(&row->first_hop))
	ci_log("%02d: "CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT" -> "
	       "llap"
	       " \tllap "CI_IFID_PRINTF_FORMAT" metric %d tos %d src "
	       CI_IP_PRINTF_FORMAT,
	       n, CI_IP_PRINTF_ARGS(&row->destnet_ip),
	       CI_IP_ADDRSET_PRINTF_ARGS((unsigned)row->destnet_ipset),
               row->dest_ifindex, row->metric, row->tos, 
	       CI_IP_PRINTF_ARGS(&row->pref_source) );
    else
	ci_log("%02d: "CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT" -> "
	       CI_IP_PRINTF_FORMAT
	       " \tllap "CI_IFID_PRINTF_FORMAT" metric %d tos %d src "
	       CI_IP_PRINTF_FORMAT,
	       n, CI_IP_PRINTF_ARGS(&row->destnet_ip),
	       CI_IP_ADDRSET_PRINTF_ARGS((unsigned)row->destnet_ipset),
	       CI_IP_PRINTF_ARGS(&row->first_hop),
               row->dest_ifindex, row->metric, row->tos, 
	       CI_IP_PRINTF_ARGS(&row->pref_source) );
    return NULL;
}






static void
cicp_route_log(const cicp_handle_t *control_plane)
{   ci_log(CODEID": Route Table:");
    fwd_for_row(control_plane, &route_row_print, /*unused arg*/NULL);
}


#else

#define cicp_route_log(cplane)

#endif /* DEBUGMIBROUTELOG */





/*!
 * This function reads all of its information about the Link level access
 * points from the forwarding information table - which has one entry for
 * every route.  This means that no account can be made of access points that
 * do not have a route to them.
 *
 * Note that, although this function, identifies whether the address has
 * any of the special types it does not indicate which IP interface or
 * link level access point is involved.  In principle different IP interfaces
 * may be responsible for each of the bits that get set in the IP address
 * "kind".
 */
static void
cicp_fwdinfo_addr_kind(const cicp_fwdinfo_t *fwdt, ci_ip_addr_net_t ip,
		       ci_ip_addr_kind_t *out_addr_kind)
{
  const cicp_fwd_row_t *row    = &fwdt->path[0];
  const cicp_fwd_row_t *maxrow = row + fwdt->rows_max;
  ci_ip_addr_t net_addr;

  out_addr_kind->bitsvalue = 0;  /* clear all bits to zero */

  while( row < maxrow && cicp_fwd_row_allocated(row) ) {
    CI_IP_ADDR_SET_SUBNET(&net_addr, &row->net_ip, row->net_ipset);

    if (CI_IP_ADDR_EQ(&ip, &net_addr))
      out_addr_kind->bits.is_netaddr = 1;

    if (CI_IP_ADDR_EQ(&ip, &row->net_ip))
      out_addr_kind->bits.is_ownaddr = 1;

    if (CI_IP_ADDR_EQ(&ip, &row->net_bcast))
      out_addr_kind->bits.is_broadcast = 1;

    row++;
  }
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
 *  ones.  Thus the first match will always be the correct one.
 */
extern const cicp_fwd_row_t *
_cicp_fwd_find_ip(const cicp_fwdinfo_t *fwdt, ci_ip_addr_t ip_dest)
{
  const cicp_fwd_row_t *row    = &fwdt->path[0];
  const cicp_fwd_row_t *maxrow = row + fwdt->rows_max;
    
  while (row < maxrow && cicp_fwd_row_allocated(row) &&
         !CI_IP_ADDR_SAME_NETWORK(&ip_dest,
                                  &row->destnet_ip, row->destnet_ipset))
    row++;

  return row < maxrow && cicp_fwd_row_allocated(row)?
    (cicp_fwd_row_t *)row: (cicp_fwd_row_t *)NULL;
}








/*! Locate a forwarding information row that is not allocated
 *
 * Note that this function does not "allocate" the sought entry
 */
extern cicp_fwd_row_t *
_cicpos_fwd_find_free(cicp_fwdinfo_t *fwdt)
{
  cicp_fwd_row_t *row = &fwdt->path[0];
  cicp_fwd_row_t *maxrow = row + fwdt->rows_max;

  while (row < maxrow && cicp_fwd_row_allocated(row))
    row++;

  return row < maxrow? row: NULL;
}






/*!
 * Locate routing information for a set of IP addresses
 *
 * \param routet          the routing table
 * \param dest_ip         the route set base IP address
 * \param dest_set        the set of addresses based on \c dest_ip
 *
 * \return                CICP_IPIF_ROUTE_BAD iff route not found, else row
 *
 * This function locates the row in the routing table that describes the
 * route identified by the given destination IP address and address set.
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 */
extern cicp_fwd_rowid_t 
_cicpos_route_find(const cicp_fwdinfo_t   *routet,
		   ci_ip_addr_t            dest_ip,
                   ci_ip_addrset_t         dest_set)
{   const cicp_fwd_row_t *minrow = &routet->path[0];
    const cicp_fwd_row_t *maxrow = minrow + routet->rows_max;
    const cicp_fwd_row_t *row = minrow;

    /* N.B. assumes that all allocated entries are at the front of
       the table */
    while (row < maxrow && cicp_fwd_row_allocated(row) &&
	   !(CI_IP_ADDR_EQ(&row->destnet_ip, &dest_ip) &&
	     dest_set == row->destnet_ipset)
	  )
	row++;

    return row < maxrow && cicp_fwd_row_allocated(row)?
	   (ci_uint32)(row-minrow): CICP_FWD_ROWID_BAD;
}




ci_inline int cicp_blacklist_match(const ci_int8 *blacklist_to_intf_i,
                                   int max_index, ci_ifid_t ifindex)
{
  int i;
  ci_assert_le(max_index, CI_CFG_MAX_BLACKLIST_INTERFACES);
  for( i = 0; i < max_index; ++i)
    if( blacklist_to_intf_i[i] == ifindex )
      return 1;
  return 0;
}


ci_inline int cicp_all_slaves_in_stack(const cicp_ul_mibs_t *user,
                                       ci_netif *ni, ci_int16 bond_rowid)
{
  /* Check all slaves are in this stack.
   *
   * NB. Caller must check the forwarding table lock.
   */
  cicp_bond_row_t* bond_row;
  ci_hwport_id_t hwport;

  ci_assert(bond_rowid >= 0 && bond_rowid < user->bondinfo_utable->rows_max);
  bond_row = &user->bondinfo_utable->bond[bond_rowid];

  while( bond_row->next != CICP_BOND_ROW_NEXT_BAD ) {
    ci_assert(bond_row->next < user->bondinfo_utable->rows_max);
    bond_row = &user->bondinfo_utable->bond[bond_row->next];
    if( bond_row->type != CICP_BOND_ROW_TYPE_SLAVE )
      return 0;
    hwport = bond_row->slave.hwport;
    if( (unsigned) hwport >= CI_CFG_MAX_REGISTER_INTERFACES ||
        __ci_hwport_to_intf_i(ni, hwport) < 0 )
      return 0;
  }

  return 1;
}


ci_inline int
ci_ip_cache_is_onloadable(ci_netif* ni, ci_ip_cached_hdrs* ipcache)
{
  /* Return true if [ipcache->hwport] can be accelerated by [ni], and also
   * sets [ipcache->intf_i] in that case.
   *
   * [ipcache->hwport] must have a legal value here.
   */
  ci_hwport_id_t hwport = ipcache->hwport;
  ci_assert(hwport == CI_HWPORT_ID_BAD ||
            (unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES);
  return (unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES &&
    (ipcache->intf_i = __ci_hwport_to_intf_i(ni, hwport)) >= 0;
}


#if CI_CFG_TEAMING
static int
cicp_user_bond_hash_get_hwport(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                               const cicp_fwd_row_t* fwd_row,
                               ci_uint16 src_port_be16,
                               cicp_encap_t encap, int bond_rowid)
{
  /* For an active-active bond that uses hashing, choose the appropriate
   * interface to send out of.
   */
  struct cicp_hash_state hs;

  if( bond_rowid < 0 ) {
    /* TODO: would be more efficient if caller had obtained [bond_rowid]
     * from cicp_llap_retrieve().
     */
    ci_int16 rowid;
    ci_int8 hash;
    if( cicp_user_bond_get_info(CICP_HANDLE(ni), fwd_row, ipcache->ifindex,
                                &rowid, &hash, NULL) < 0 )
      return 1;  /* not onloadable */
    bond_rowid = rowid;
  }

  if( src_port_be16 != 0 || ipcache->dport_be16 != 0)
    hs.flags = CICP_HASH_STATE_FLAGS_IS_TCP_UDP | 
      CICP_HASH_STATE_FLAGS_IS_IP;
  else
    hs.flags = CICP_HASH_STATE_FLAGS_IS_IP;
  CI_MAC_ADDR_SET(&hs.dst_mac, ci_ip_cache_ether_dhost(ipcache));
  CI_MAC_ADDR_SET(&hs.src_mac, ci_ip_cache_ether_shost(ipcache));
  hs.src_addr_be32 = ipcache->ip_saddr_be32;
  hs.dst_addr_be32 = ipcache->ip.ip_daddr_be32;
  hs.src_port_be16 = src_port_be16;
  hs.dst_port_be16 = ipcache->dport_be16;
  ipcache->hwport = ci_hwport_bond_get(CICP_HANDLE(ni), 1, &encap,
                                       bond_rowid, &hs);
  return ! ci_ip_cache_is_onloadable(ni, ipcache);
}
#endif


ci_inline int
cicp_mcast_use_gw_mac(const cicp_fwd_row_t* row,
                      const struct oo_sock_cplane* sock_cp)
{
  /* If:
   * - route table says (via explicit route) that this mcast addr should be
   *   delivered via a gateway
   *
   *   If:
   *   - have set IP_MULTICAST_IF to the same dev (as route table)
   *   Or:
   *   - have NOT set IP_MULTICAST_IF
   *   - and socket laddr is not bound
   *   - and socket is not connected
   *   Then:
   *   => use GATEWAY mac.
   *
   * Else:
   * => use MCAST mac.
   */
  if( row != NULL && row->first_hop != 0 && row->destnet_ipset != 0 ) {
    if( sock_cp->ip_multicast_if == CI_IFID_BAD ) {
      return (sock_cp->sock_cp_flags &
              (OO_SCP_LADDR_BOUND | OO_SCP_CONNECTED)) == 0;
    }
    else {
      return sock_cp->ip_multicast_if == row->dest_ifindex;
    }
  }
  return 0;
}


ci_inline void
ci_ip_cache_init_mcast_mac(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                           unsigned daddr_be32)
{
  ci_uint8* dhost = ci_ip_cache_ether_dhost(ipcache);
  dhost[0] = 1;
  dhost[1] = 0;
  dhost[2] = 0x5e;
  dhost[3] = (daddr_be32 >> 8) & 0x7f;
  dhost[4] = (daddr_be32 >> 16) & 0xff;
  dhost[5] = (daddr_be32 >> 24) & 0xff;
  cicp_mac_set_mostly_valid(CICP_MIBS(CICP_HANDLE(ni))->user.mac_utable,
                            &ipcache->mac_integrity);
  ipcache->nexthop = 0;
}


void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp)
{
  const cicp_ul_mibs_t* user = &CICP_MIBS(CICP_HANDLE(ni))->user;
  cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;
  const cicp_fwd_row_t* row;
  ci_verlock_value_t version;
  cicp_mac_verinfo_t mac_info;
  ci_ip_addr_kind_t kind;
  ci_mac_addr_t mac_storage;
  void* source_mac;
  ci_int16 bond_rowid;
  int osrc;

  CI_DEBUG(ipcache->status = -1);

  if(CI_UNLIKELY( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) &&
                  (sock_cp->sock_cp_flags & OO_SCP_NO_MULTICAST) ))
    goto alienroute_no_verlock;

  CICP_LOCK_BEGIN(CICP_HANDLE(ni));
  ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt);
 again:
  version = fwdt->version;
  ci_rmb();

  /* We need to do a route table lookup even when hwport is selected by
   * IP_MULTICAST_IF, due to the baroque rules for selecting the MAC addr.
   *
   * ?? TODO: Are there scenarious with SO_BINDTODEVICE where a route table
   * lookup can be avoided?  Probably there are.
   */
  row = _cicp_fwd_find_ip(fwdt, ipcache->ip.ip_daddr_be32);

  if( sock_cp->so_bindtodevice != CI_IFID_BAD ) {
    ipcache->ifindex = sock_cp->so_bindtodevice;
    goto handle_bound_dev;
  }
  else if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) &&
           sock_cp->ip_multicast_if != CI_IFID_BAD ) {
    /* TODO: Optimisation: Remember non-mac info associated with the
     * ifindex selected by IP_MULTICAST_IF or SO_BINDTODEVICE when
     * destination changes.  Requires that we remember the fwd table
     * version.
     */
    ipcache->ifindex = sock_cp->ip_multicast_if;
  handle_bound_dev:
    bond_rowid = -1;
    source_mac = &mac_storage;
    osrc = cicp_llap_retrieve(CICP_HANDLE(ni), ipcache->ifindex, &ipcache->mtu,
                              &ipcache->hwport, source_mac, &ipcache->encap,
                              NULL/*base_ifindex*/, &bond_rowid);
    if( osrc != 0 || ! ci_ip_cache_is_onloadable(ni, ipcache)
#if CI_CFG_TEAMING
        || ( (ipcache->encap.type & CICP_LLAP_TYPE_BOND) && 
             ! cicp_all_slaves_in_stack(user, ni, bond_rowid) )
#endif
        )
      goto alienroute;
    /* Select source IP: Bound local IP, else local IP given with
     * IP_MULTICAST_IF, else arbitrary IP on this interface.
     *
     * NB. We're handling SO_BINDTODEVICE as well as IP_MULTICAST_IF here.
     */
    if( sock_cp->ip_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_laddr_be32;
    else if( sock_cp->ip_multicast_if != CI_IFID_BAD &&
             sock_cp->ip_multicast_if_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_multicast_if_laddr_be32;
    /* TODO: Could this syscall either by bundling in cicp_llap_retrieve(),
     * or by having a u/l llap table that includes this.
     */
    else if( cicp_ipif_by_ifindex(CICP_HANDLE(ni), ipcache->ifindex,
                                  &ipcache->ip_saddr_be32) != 0 )
      goto alienroute;  /* really this is "no source addr" */
  }
  else {
    if(CI_UNLIKELY( row == NULL ))
      goto noroute;
    ipcache->mtu = row->mtu;
    ci_assert(ipcache->mtu);
    if( ipcache->ip.ip_daddr_be32 == row->net_ip ) {
      ipcache->status = retrrc_localroute;
      ipcache->encap.type = CICP_LLAP_TYPE_SFC;
      ipcache->ether_offset = 4;
      ipcache->intf_i = OO_INTF_I_LOOPBACK;
      goto check_verlock_and_out;
    }
    ipcache->hwport = row->hwport;
    if( ! ci_ip_cache_is_onloadable(ni, ipcache)
#if CI_CFG_TEAMING
        || ( (row->encap.type & CICP_LLAP_TYPE_BOND) && 
             ! cicp_all_slaves_in_stack(user, ni, row->bond_rowid) )
#endif
        )
      goto alienroute;
    ipcache->ifindex = row->dest_ifindex;
    if( sock_cp->ip_laddr_be32 != 0 )
      ipcache->ip_saddr_be32 = sock_cp->ip_laddr_be32;
    else
      ipcache->ip_saddr_be32 = row->pref_source;
    ipcache->encap = row->encap;
    source_mac = &row->pref_src_mac;
    bond_rowid = row->bond_rowid;
  }

  /* Layout the Ethernet header, and set the source mac. */
  if( ipcache->encap.type & CICP_LLAP_TYPE_VLAN ) {
    ci_uint16* vlan_tag = (ci_uint16*) ipcache->ether_header + 6;
    vlan_tag[0] = CI_ETHERTYPE_8021Q;
    vlan_tag[1] = CI_BSWAP_BE16(ipcache->encap.vlan_id);
    ipcache->ether_offset = 0;
  }
  else {
    ipcache->ether_offset = ETH_VLAN_HLEN;
  }
  memcpy(ci_ip_cache_ether_shost(ipcache), source_mac, ETH_ALEN);

  /* Find the next hop, initialise the destination mac and select TTL. */
  if( CI_IP_IS_MULTICAST(ipcache->ip.ip_daddr_be32) ) {
    ipcache->ip.ip_ttl = sock_cp->ip_mcast_ttl;
    if( ! cicp_mcast_use_gw_mac(row, sock_cp) ) {
      ci_ip_cache_init_mcast_mac(ni, ipcache, ipcache->ip.ip_daddr_be32);
#if CI_CFG_TEAMING
      if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH )
        if( cicp_user_bond_hash_get_hwport(ni, ipcache, row, 
                                           sock_cp->lport_be16,
                                           ipcache->encap, bond_rowid) != 0 )
          goto alienroute;
#endif
      ipcache->status = retrrc_success;
      goto check_verlock_and_out;
    }
    ipcache->nexthop = row->first_hop;
  }
  else {
    ipcache->ip.ip_ttl = sock_cp->ip_ttl;
    if( row != NULL && row->first_hop != 0 ) {
      ipcache->nexthop = row->first_hop;
    }
    else {
      ipcache->nexthop = ipcache->ip.ip_daddr_be32;
    }
  }
  /* ?? TODO: The next line is expensive because we iterate over the whole
   * route table (again).  I'm sure we can make this much cheaper in the
   * common case.
   */
  cicp_fwdinfo_addr_kind(fwdt, ipcache->nexthop, &kind);
  if( kind.bitsvalue != 0 )
    goto alienroute;

  /* Find the MAC address of the first hop destination.
   *
   * TODO: This requires two rmb()s, and can I think be significantly
   * improved upon.  One approach could be to add a new verlock that is
   * bumped both when updating the fwd+bond tables, and also when updating
   * any mac entry.  Thus a single pair of verlock checks would suffice for
   * this entire function.
   */
  osrc = cicp_mac_get(user->mac_utable, ipcache->ifindex, ipcache->nexthop,
                      ci_ip_cache_ether_dhost(ipcache), &mac_info);

  if( osrc == 0 ) {
#if CI_CFG_TEAMING
    if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH )
      if( cicp_user_bond_hash_get_hwport(ni, ipcache, row, sock_cp->lport_be16,
                                         ipcache->encap, bond_rowid) != 0 )
        goto alienroute;
#endif
    ipcache->mac_integrity = mac_info;
    ipcache->status = retrrc_success;
    if( user->mac_utable->ipmac[mac_info.row_index].need_update ) {
      ipcache->flags |= CI_IP_CACHE_NEED_UPDATE_SOON;
      if( user->mac_utable->ipmac[mac_info.row_index].need_update ==
          CICP_MAC_ROW_NEED_UPDATE_STALE )
        ipcache->flags |= CI_IP_CACHE_NEED_UPDATE_STALE;
    }
    goto check_verlock_and_out;
  }
  else if( osrc == -EDESTADDRREQ ) {
    /* TODO out_hwport is wrong if bonding encap */
    ipcache->mac_integrity.row_version = CI_VERLOCK_BAD;
    ipcache->status = retrrc_nomac;
    goto check_verlock_and_out;
  }
  else if( osrc == -EAGAIN ) {
    goto again;
  }
  else {
    /* TODO out_hwport is wrong if bonding encap */
    /* At time of writing, osrc is taken from a ci_uint16, which is
     * assigned to with either 0 or a -ve constant int.  Ugly.
     */
    ipcache->status = (ci_int16) osrc;
    if( ipcache->status == -EHOSTUNREACH ) {
      /* Treat this the same as nomac.  Arguably it would be better to
       * handle this exception when writing the table rather than when
       * reading it, but modifying the write code scares the willies out of
       * me.
       */
      ipcache->mac_integrity.row_version = CI_VERLOCK_BAD;
      ipcache->status = retrrc_nomac;
      goto check_verlock_and_out;
    }
    goto not_onloadable;
  }

 check_verlock_and_out:
  ci_rmb();
  if(CI_UNLIKELY( ci_verlock_updating(&version) || fwdt->version != version ))
    goto again;
  CICP_LOCK_END;
 out:
  ci_assert(ipcache->status != -1);
  return;

 not_onloadable:
  ipcache->hwport = CI_HWPORT_ID_BAD;
  ipcache->intf_i = -1;
  cicp_mac_set_mostly_valid(CICP_MIBS(CICP_HANDLE(ni))->user.mac_utable,
                            &ipcache->mac_integrity);
  goto check_verlock_and_out;

 alienroute:
  ipcache->status = retrrc_alienroute;
  goto not_onloadable;

 noroute:
  ipcache->status = retrrc_noroute;
  goto not_onloadable;

 alienroute_no_verlock:
  ipcache->hwport = CI_HWPORT_ID_BAD;
  ipcache->intf_i = -1;
  cicp_mac_set_mostly_valid(CICP_MIBS(CICP_HANDLE(ni))->user.mac_utable,
                            &ipcache->mac_integrity);
  ipcache->status = retrrc_alienroute;
  goto out;
}


void
cicp_ip_cache_update_from(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                          const ci_ip_cached_hdrs* from_ipcache)
{
  /* We can't check the inputs that come from oo_sock_cplane, but this at
   * least gives us a little checking...
   */
  ci_assert_equal(ipcache->ip.ip_daddr_be32, from_ipcache->ip.ip_daddr_be32);
  ci_assert_equal(ipcache->dport_be16, from_ipcache->dport_be16);

  ipcache->mac_integrity = from_ipcache->mac_integrity;
  ipcache->ip_saddr_be32 = from_ipcache->ip_saddr_be32;
  ipcache->ip.ip_ttl = from_ipcache->ip.ip_ttl;
  ipcache->status = from_ipcache->status;
  ipcache->flags = from_ipcache->flags;
  /* ipcache->pmtus = something; */
  ipcache->mtu = from_ipcache->mtu;
  ipcache->ifindex = from_ipcache->ifindex;
  ipcache->encap = from_ipcache->encap;
  ipcache->intf_i = from_ipcache->intf_i;
  ipcache->hwport = from_ipcache->hwport;
  ipcache->ether_offset = from_ipcache->ether_offset;
  memcpy(ipcache->ether_header, from_ipcache->ether_header,
         sizeof(ipcache->ether_header));
}


#if CI_CFG_TEAMING

int cicp_user_bond_get_info(cicp_handle_t* control_plane, 
                            const cicp_fwd_row_t* fwd_row,
                            ci_ifid_t ifindex,
                            ci_int16* rowid, ci_int8* hash, 
                            ci_verlock_value_t* vlock)
{
  const cicp_ul_mibs_t* user = &CICP_MIBS(control_plane)->user;
  const cicp_fwdinfo_t* fwdt = user->fwdinfo_utable;
  const cicp_bondinfo_t* bondt = user->bondinfo_utable;
  const cicp_bond_row_t *bond_row;
  const cicp_fwd_row_t *max_fwd_row = &fwdt->path[0] + fwdt->rows_max;

  /* ?? [vlock == NULL] here is a temp hack.  Quite soon I expect all
   * callers of this to already have the lock.
   */
  CICP_LOCK_BEGIN_IF(control_plane, vlock == NULL);
  ASSERT_VERLOCK_NOT_UPDATING_IN_KERNEL(fwdt);
 again:
  if( vlock != NULL ) {
    *vlock = fwdt->version;
    ci_rmb();  /* Read lock before fields. */
    if(CI_UNLIKELY( ci_verlock_updating(vlock) ))
      goto again;
  }

  if( fwd_row != NULL ) {
    /* Try fwd_row we were passed in */
    if( cicp_fwd_row_allocated(fwd_row) && 
        fwd_row->dest_ifindex == ifindex &&
        fwd_row->bond_rowid != CICP_BOND_ROW_NEXT_BAD ) {
      bond_row = &bondt->bond[fwd_row->bond_rowid];
      if( cicp_bond_row_allocated(bond_row) &&
          bond_row->type == CICP_BOND_ROW_TYPE_MASTER ) {
        *rowid = bond_row - &bondt->bond[0];
        *hash = bond_row->master.hash_policy;
      } 
      else {
        /* clobber fwd_row so we return error */
        fwd_row = max_fwd_row;
      }
    }
    else {
      /* Wrong row passed in (e.g. route table conflicts with
       * SO_BINDTODEVICE) 
       */
      goto search_fwd_table;
    }
  }
  else {
    /* No route configured, so search fwd table for matching ifindex */
  search_fwd_table:
    fwd_row = &fwdt->path[0];
    while( fwd_row < max_fwd_row ) {
      if( cicp_fwd_row_allocated(fwd_row) && 
          fwd_row->dest_ifindex == ifindex &&
          fwd_row->bond_rowid != CICP_BOND_ROW_NEXT_BAD ) {
        ci_assert(fwd_row->bond_rowid >= 0 && 
                  fwd_row->bond_rowid < bondt->rows_max);
        bond_row = &bondt->bond[fwd_row->bond_rowid];
        if( cicp_bond_row_allocated(bond_row) &&
            bond_row->type == CICP_BOND_ROW_TYPE_MASTER ) {
          *rowid = bond_row - &bondt->bond[0];
          *hash = bond_row->master.hash_policy;
          break;
        }
      }
      ++fwd_row;
    }
  }

  if( vlock != NULL ) {
    ci_rmb();
    if( CI_UNLIKELY(fwdt->version != *vlock) )
      goto again;
  }
  CICP_LOCK_END_IF(control_plane, vlock == NULL);

  if( fwd_row == max_fwd_row ) {
    *rowid = -1;
    *hash = CICP_BOND_XMIT_POLICY_NONE;
    return -ENODEV;
  }
  
  return 0;
}

#endif



/*****************************************************************************
 *                                                                           *
 *          Whole Control Plane						     *
 *          ===================						     *
 *                                                                           *
 *****************************************************************************/








extern size_t 
cicp_mapped_bytes(const cicp_ns_mmap_info_t *shared)
{   
  return shared->fwdinfo_mmap_len + 
    shared->mac_mmap_len + 
    shared->bondinfo_mmap_len;
}







/* 
   e.g. cicp_ni_build(&ni->cplane, &ni->state->control_mmap,
                      (ulong) ni->state + (ulong) ns->netif_mmap_bytes);
*/


/*! Initialization of kernel-visible per-netif control plane */
extern void 
cicp_ni_build(cicp_ni_t *control, const cicp_ns_mmap_info_t *shared, void *mem)
{   cicp_ul_mibs_t *umibs;

#if !defined(__ci_driver__)
    /* in the kernel we have an instance of the kernel available */
    control->cp_mibs = &control->user_mibs; /* "const" pointer */
    umibs = &control->user_mibs.user;       /* no "const" accessing this */
#else
    umibs = &control->cp_mibs->user;
#endif
    
    /* kernel-user shared data areas */
    umibs->fwdinfo_mmap_len = shared->fwdinfo_mmap_len;
    umibs->mac_mmap_len     = shared->mac_mmap_len;
    umibs->bondinfo_mmap_len = shared->bondinfo_mmap_len;

    umibs->fwdinfo_utable   = (cicp_fwdinfo_t *)((ci_uint8 *)mem + 0);
    umibs->mac_utable       = (cicp_mac_mib_t *)((ci_uint8 *)mem + 
                                                 umibs->fwdinfo_mmap_len);
    umibs->bondinfo_utable  = (cicp_bondinfo_t *)((ci_uint8 *)mem + 
                                                  umibs->fwdinfo_mmap_len + 
                                                  umibs->mac_mmap_len);
    umibs->oo_timesync      = (struct oo_timesync *)
      (&(umibs->bondinfo_utable->bond[umibs->bondinfo_utable->rows_max]));
    DEBUGMEM(DPRINTF(CODEID": MAC MIB at %p[%d] FWD info table at %p[%d]"
                     "BOND table at %p[%d] TIMESYNC at %p\n",
		     umibs->mac_utable, (int) umibs->mac_mmap_len,
		     umibs->fwdinfo_utable, (int) umibs->fwdinfo_mmap_len,
                     umibs->bondinfo_utable, (int) umibs->bondinfo_mmap_len,
                     umibs->oo_timesync);)
}
