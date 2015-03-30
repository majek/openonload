/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
**   \date  2005/07/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is relevant only to the kernel - it is not visible
 *  from the user-mode libraries.
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
 *  Kernel visible information
 *
 *      cicp_route_kmib_t  - IP routing table
 *
 *      cicp_llap_kmib_t   - Link Layer Access Point interface table 
 *
 *      cicp_ipif_kmib_t   - IP interface table
 *
 *      cicp_hwport_kmib_t - Hardware port table
 *
 *  The information is related as follows:
 *
 *   * each L5 NIC support a number of ports - a hardware port is identified
 *     with the number of its NIC and the port on it
 *
 *   * link layer acccess points are allowed to occur many:one with respect to
 *     hardware ports - each link layer access point may, for example, use a
 *     different encapsulation over the same port
 *     The issue of channel bonding whereby a number of ports are combined to
 *     provide the abstraction of a single link layer access point is not
 *     supported in this code - although host O/S features may provide it
 *     externally
 *
 *   * IP interfaces occur many:one with link layer access points - each link
 *     layer access point may, for example, be associated with a number of
 *     home addresses on directly connected subnetworks
 *
 *   * routing tables provide information that allows the determination of a
 *     preferred first hop IP address and link layer access point that can
 *     be used to transmit an IP packet to a given IP destination.
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



#include <onload/debug.h>
#include <onload/cplane.h>
#include <onload/cplane_prot.h>
#include <onload/oof_interface.h>
#include <ci/internal/cplane_handle.h>

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif




/*****************************************************************************
 *                                                                           *
 *          Configuration                                                    *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/






#define CICP_HWPORT_MAX_MTU_DEFAULT 1460 /*< @TODO: PROBABLY NOT! - FIX ME */




#ifndef __ci_driver__
#error This file should not be compiled as part of a user-level library
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

#define DO(_x...) _x
#define IGNORE(_x...)

/* To turn on compile time debugging uncomment one or more of these defines */

#define FORCEDEBUG /* include debugging even in NDEBUG builds */


/* #define DEBUGMIBMAC       DO */  /* ARP table access */
/* #define DEBUGMIBMACSET    DO */  /* XXXX_mac_set() common cases */
/* #define DEBUGMIBLLAPLOG   DO */  /* show content of LLAP MIB */
/* #define DEBUGLOGEVENTS    DO */  /* event message generation */


/* switching off debugging if NDEBUG - no debug output in released code */
#if defined(NDEBUG) && !defined(FORCEDEBUG)
#undef DEBUGMIBMAC
#undef DEBUGMIBMACSET
#undef DEBUGMIBLLAPLOG
#undef DEBUGLOGEVENTS
#endif


#ifndef DEBUGINIT
#define DEBUGINIT       IGNORE
#endif
#ifndef DEBUGMIBMAC
#define DEBUGMIBMAC     IGNORE
#endif
#ifndef DEBUGMIBMACSET
#define DEBUGMIBMACSET  IGNORE
#endif
#ifndef OO_DEBUG_ARP
#define OO_DEBUG_ARP    IGNORE
#endif
#ifndef DEBUGMIBLLAPLOG
#define DEBUGMIBLLAPLOG IGNORE
#endif
#ifndef DEBUGLOGEVENTS
#define DEBUGLOGEVENTS  IGNORE
#endif

#define DPRINTF ci_log

#define CODEID "cplane"








/*****************************************************************************
 *                                                                           *
 *          Events						             *
 *          ======						             *
 *                                                                           *
 *****************************************************************************/







#define LOGEVENT_CP_MAC_DUPLICATE(ifindex, ip, mac_new, mac_old) \
{   (void)ifindex; (void)ip; (void)mac_new; (void)mac_old;     }

#define LOGEVENT_CP_ROUTE_NOSRC(ifindex, dest_ip, dest_ipset, next_hop) \
{   (void)ifindex; (void)dest_ip; (void)dest_ipset; (void)next_hop;    }





#if 0 != DEBUGLOGEVENTS(1+)0

#define CI_IP_ADDR_INIT(ip_ref, a,b,c,d) *ip_ref = CI_IP_ADDR(a,b,c,d)

#define CI_MAC_ADDR_INIT(mac_ref, a,b,c,d,e,f) \
{   ((unsigned char *)(mac_ref))[0] = a;       \
    ((unsigned char *)(mac_ref))[1] = b;       \
    ((unsigned char *)(mac_ref))[2] = c;       \
    ((unsigned char *)(mac_ref))[3] = d;       \
    ((unsigned char *)(mac_ref))[4] = e;       \
    ((unsigned char *)(mac_ref))[5] = f;       \
}

static void
eventlog_test(void)
{   static int done = 0;
    if (!done)
    {   /* example values to log */
	ci_ifid_t ifindex = 42;
	ci_ip_addr_t ip1, ip2;
	ci_mac_addr_t mac1, mac2;
	ci_ip_addrset_t setsize = 24;

	CI_IP_ADDR_INIT(&ip1, 10,20,129,42);
	CI_IP_ADDR_INIT(&ip2, 10,20,129,254);
	CI_MAC_ADDR_INIT(&mac1, 0x10,0x20,0x30,0x40,0x50,0x60);
	CI_MAC_ADDR_INIT(&mac2, 0x01,0x02,0x03,0x04,0x05,0x06);

	ci_log("%s: testing event generation in %s", __FUNCTION__, __FILE__);
#ifdef LOGEVENT_CP_TEST
	LOGEVENT_CP_TEST(ifindex, &ip1, &mac1, &mac2);
#endif
	LOGEVENT_CP_MAC_DUPLICATE(ifindex, &ip1, &mac1, &mac2);
	LOGEVENT_CP_ROUTE_NOSRC(ifindex, &ip1, setsize, &ip2);

	done = 1; /* just test things once */
    }
}

#else

#define eventlog_test()

#endif







/*****************************************************************************
 *                                                                           *
 *          Shared Memory						     *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/




/* use contiguous shared memory buffers as shared memory storage */



static void *cicp_shared_alloc(size_t bytes, 
			       size_t *out_mmap_len,
			       cicp_mib_shared_t *out_shared_handle,
			       int *out_rc)
{   int rc;

    OO_DEBUG_MEMSIZE(DPRINTF(CODEID ": requesting %u bytes of shared memory into %p",
		     (unsigned)bytes, out_shared_handle););
    
    rc = ci_contig_shmbuf_alloc(out_shared_handle, bytes);

    if (rc >= 0)
    {   *out_mmap_len = ci_contig_shmbuf_size(out_shared_handle);

	OO_DEBUG_MEMSIZE(DPRINTF(CODEID ": allocated %u for %u bytes of shared memory",
		         (unsigned)*out_mmap_len, (unsigned)bytes););
	    
	/* generate kernel pointer to memory area */
	return ci_contig_shmbuf_ptr(out_shared_handle);
    } else
    {   *out_rc = -rc;
	return NULL;
    }
}





ci_inline void cicp_shared_free(cicp_mib_shared_t *ref_shared_handle)
{   ci_contig_shmbuf_free(ref_shared_handle);
}







/*****************************************************************************
 *****************************************************************************
 *                                                                           *
 *          ACM - Abstract Cacheable MIBs                                    *
 *          =============================                                    *
 *                                                                           *
 *****************************************************************************
 *****************************************************************************/










/* forward references to caching functions */
#if CI_CFG_TEAMING
static void
cicp_fwdinfo_llap_set_encapsulation(cicp_mibs_kern_t *control_plane,
			            ci_ifid_t ifindex,
			            const cicp_encap_t *encap);
#endif


static void
cicp_fwdinfo_hwport_add_nic(cicp_mibs_kern_t *control_plane,
		            ci_hwport_id_t, ci_mtu_t max_mtu);


static void
cicp_fwdinfo_hwport_remove_nic(cicp_mibs_kern_t *control_plane,
			       ci_hwport_id_t);



/* forward references to debugging functions */

static void
cicp_llap_log(const cicp_handle_t *control_plane);

#if CI_CFG_TEAMING
static int 
cicp_llap_update_all_bond_rowid(cicp_handle_t *control_plane, 
                                ci_ifid_t ifindex, ci_int16 new_rowid,
                                int llapt_locked);
static int 
cicp_llap_update_all_hash_state(cicp_handle_t *control_plane,
                                ci_int16 bond_rowid,
                                ci_int8 hash_policy);
#endif

static void
cicp_fwdinfo_something_changed(cicp_mibs_kern_t *control_plane);


/*****************************************************************************
 *                                                                           *
 *          Link Layer Access Point MIB					     *
 *          ===========================					     *
 *                                                                           *
 *****************************************************************************/







static int /* rc */
cicp_llap_kmib_ctor(cicp_llap_kmib_t **out_llapt, int rows_max)
{
  cicp_llap_kmib_t *llapt;
  int i;

  OO_DEBUG_ARP(DPRINTF(CODEID ": constructing kernel Link-layer "
                       "Access Point table"););
    
  *out_llapt  = (cicp_llap_kmib_t *)ci_vmalloc(sizeof(cicp_llap_kmib_t));
  llapt = *out_llapt;

  if( llapt == NULL )
    return -ENOMEM;

  llapt->llap = ci_vmalloc(rows_max * sizeof(cicp_llap_row_t));
  if( llapt->llap == NULL) {
    ci_vfree(llapt);
    *out_llapt = NULL;
    return -ENOMEM;
  }

  llapt->rows_max = rows_max;

  for( i = 0; i < llapt->rows_max; i++ ) {
    cicp_llap_row_t *row = &llapt->llap[i];
    memset(row, 0, sizeof(*row));
    row->hwport = CI_HWPORT_ID_BAD;
    row->bond_rowid = CICP_BOND_ROW_NEXT_BAD;
    row->vlan_rowid = CICP_BOND_ROW_NEXT_BAD;
    cicp_llap_row_free(row);
    cicpos_llap_kmib_row_ctor(&row->sync);
  }
	
  llapt->version = CI_VERLOCK_INIT_VALID;
    
  return 0;
}








ci_inline void
cicp_llap_kmib_dtor(cicp_llap_kmib_t **ref_llapt)
{
  OO_DEBUG_ARP(DPRINTF(CODEID ": kernel Link-layer Access Point table "
                       "destructor called"););
  
  if (NULL != *ref_llapt) {
    ci_vfree((*ref_llapt)->llap);
    ci_vfree(*ref_llapt);
    *ref_llapt = NULL;
  }
}





/*! find the first unallocated LLAP MIB row */
ci_inline cicp_llap_row_t *cicp_llap_find_free(const cicp_llap_kmib_t *llapt)
{   const cicp_llap_row_t *row = &llapt->llap[0];
    const cicp_llap_row_t *end_row = row + llapt->rows_max;
    
    while (row < end_row && cicp_llap_row_allocated(row))
	row++;

    return row < end_row? (cicp_llap_row_t *)row: (cicp_llap_row_t *)NULL;
}






/*! find the LLAP MIB row with the given ifindex */
ci_inline cicp_llap_row_t *
cicp_llap_find_ifid(const cicp_llap_kmib_t *llapt, ci_ifid_t ifindex)
{   const cicp_llap_row_t *row;
    const cicp_llap_row_t *end_row = llapt->llap + llapt->rows_max;

    for (row = &llapt->llap[0]; row < end_row; ++row)
        if (cicp_llap_row_allocated(row) && row->ifindex == ifindex)
            return (cicp_llap_row_t *)row;

    return NULL;
}






/*! find the LLAP MIB row with the given ifindex which must be up and
 *  associated with a NIC
 */
ci_inline cicp_llap_row_t *
cicp_llap_find_upnicifid(const cicp_handle_t *control_plane, 
                         const cicp_llap_kmib_t *llapt, ci_ifid_t ifindex)
{   const cicp_llap_row_t *row = &llapt->llap[0];
    const cicp_llap_row_t *end_row = row + llapt->rows_max;
    
    while (row < end_row &&
	    !(cicp_llap_row_allocated(row) &&
	      cicp_llap_row_isup(row) &&
	      cicp_llap_row_hasnic(&control_plane->user, row) &&
	      row->ifindex == ifindex))
	row++;

    return row < end_row? (cicp_llap_row_t *)row: (cicp_llap_row_t *)NULL;
}






/*! Retrieve source information relevant to a given access point
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicp_llap_retrieve(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
		   ci_mtu_t *out_mtu, ci_hwport_id_t *out_hwport,
		   ci_mac_addr_t *out_mac, cicp_encap_t *out_encap,
                   ci_ifid_t *out_base_ifindex, ci_int16* out_bond_rowid)
{   int rc;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_row_t *vlan_master;
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;

    CI_VERLOCK_READ_BEGIN(llapt->version)
    
	cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (NULL != row)
	{   if (NULL != out_mtu)
	        *out_mtu = row->mtu;
            if (NULL != out_hwport) {
                *out_hwport = row->hwport;
             /*foobar */
                ci_assert(*out_hwport == CI_HWPORT_ID_BAD || 
                          *out_hwport <= CI_HWPORT_ID_MAX);
            }
            if (NULL != out_mac)
	        CI_MAC_ADDR_SET(out_mac, &row->mac);
	    if (NULL != out_encap)
                *out_encap = row->encapsulation;
            if (NULL != out_base_ifindex) {
                if ((row->encapsulation.type & CICP_LLAP_TYPE_VLAN) &&
                    (unsigned) row->vlan_rowid < llapt->rows_max) {
                  vlan_master = llapt->llap + row->vlan_rowid;
                  *out_base_ifindex = vlan_master->ifindex;
                }
                else {
                  *out_base_ifindex = ifindex;
                }
            }
            if (NULL != out_bond_rowid)
                *out_bond_rowid = row->bond_rowid;
	    rc = 0;
	} else
	    rc = -ENODEV; /* device not found */
	
    CI_VERLOCK_READ_END(llapt->version)

    if (0 != rc)
        cicp_llap_log(control_plane);

    return rc;
}






/*! Retrieve source MAC relevant to a given link layer access point
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicppl_llap_get_mac(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
	            ci_mac_addr_t *out_mac)
{   int rc;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;
    
    CI_VERLOCK_READ_BEGIN(llapt->version)

        cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (NULL != row)
	{   CI_MAC_ADDR_SET(out_mac, &row->mac);
	    rc = 0;
	} else
	    rc = -ENODEV; /* device not found */
	
    CI_VERLOCK_READ_END(llapt->version)
	
    return rc;
}






/*! find the hardware port ID used by a given access point
 *  - see driver header for documentation
 */
extern ci_hwport_id_t
cicp_llap_get_hwport(const cicp_handle_t *control_plane, ci_ifid_t ifindex)
{   
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  ci_hwport_id_t rc = CI_HWPORT_ID_BAD;
  const cicp_llap_kmib_t *llapt;
		       
  ci_assert(NULL != mibs);
  ci_assert(NULL != mibs->llap_table);
    
  llapt = mibs->llap_table;

  CI_VERLOCK_READ_BEGIN(llapt->version)
    cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

    if( CI_LIKELY(NULL != row) ) {
      rc = row->hwport;
      ci_assert(rc == CI_HWPORT_ID_BAD || rc <= CI_HWPORT_ID_MAX);
    }

  CI_VERLOCK_READ_END(llapt->version)

  return rc;
}







/*! find the name used by the O/S for a given access point
 *  - see driver header for documentation
 */
extern const char *
_cicp_llap_get_name(const cicp_handle_t *control_plane, ci_ifid_t ifindex)
{   const char *name = "<!>";
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;
    
    if (NULL != llapt)
    {   cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (CI_LIKELY(NULL != row))
	    name = &row->name[0]; /* warning - may be updated */
	else
	    name = "<?>";
    }
    return name;
}






/*! find whether the supplied access point is currently up
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_llap_is_up(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
		int /* bool */ *out_up)
{   int rc;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;
    
    CI_VERLOCK_READ_BEGIN(llapt->version)
    
	cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (NULL != row)
	{   *out_up = cicp_llap_row_isup(row);
	    rc = 0;
	} else
	    rc = -ENODEV; /* device not found */
	
    CI_VERLOCK_READ_END(llapt->version)

    return rc;
}





 /*! find a specific entry and return a copy of it, for internal use
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_llap_get_mtu(const cicp_handle_t *control_plane, ci_ifid_t ifindex,
                  ci_mtu_t *out_mtu)
{   int rc;
    const cicp_mibs_kern_t *mibs = control_plane;
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;

    CI_VERLOCK_READ_BEGIN(llapt->version)
    
	cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (NULL != row)
	{   *out_mtu = row->mtu;
	    rc = 0;
	} else
	    rc = -ENODEV; /* device not found */
	
    CI_VERLOCK_READ_END(llapt->version)

    return rc;
}


    


/*! get the encapsulation specification for a given access point
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_llap_get_encapsulation(const cicp_handle_t *control_plane,
			    ci_ifid_t ifindex, cicp_encap_t *encap)
{   int rc;
    const cicp_llap_kmib_t *llapt ;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != control_plane->llap_table);

    llapt = control_plane->llap_table;
    
    CI_VERLOCK_READ_BEGIN(llapt->version)
    
	cicp_llap_row_t *row = cicp_llap_find_ifid(llapt, ifindex);

	if (NULL != row)
	{   memcpy(encap, &row->encapsulation, sizeof(*encap));
	    rc = 0;
	} else
	    rc = -ENODEV; /* device not found */
	
    CI_VERLOCK_READ_END(llapt->version)

    return rc;
}








/*! find the first LLAP MIB row with the given ifindex which must be up and
 *  associated with a NIC
 *
 *  Note: we require a hardware port, and VLAN ID to determine an llap
 *        uniquely
 */
static ci_ifid_t
cicp_llap_hwport_to_ifindex(const cicp_handle_t *control_plane, 
                            const cicp_llap_kmib_t *llapt, 
                            ci_hwport_id_t hwport,
                            const ci_uint16 vlan_id)
{
  const cicp_llap_row_t *row = &llapt->llap[0];
  const cicp_llap_row_t *end_row = row + llapt->rows_max;
#if CI_CFG_TEAMING
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
#endif

  if( hwport == CI_HWPORT_ID_BAD )
    return (ci_ifid_t)-1;

  while( row < end_row ) {
    if( cicp_llap_row_allocated(row) &&
        cicp_llap_row_isup(row) &&
        row->hwport == hwport ) {
#if CI_CFG_TEAMING
      /* For a VLAN over a bond there are three rows of interest: (i)
       * VLAN LLAP; (ii) bond master LLAP; (iii) bond slave LLAP.  We
       * try to find the bond slave LLAP with the matching hwport and
       * navigate up to the correct VLAN LLAP.  We ignore the bond
       * master LLAP as it has ambiguous hwport and the (unambiguous)
       * slave will be tested.
       */
      cicp_bond_row_t *bond_row = NULL;
      if( row->bond_rowid != CICP_BOND_ROW_NEXT_BAD )
        bond_row = &mibs->user.bondinfo_utable->bond[row->bond_rowid];
      
      if( bond_row != NULL && bond_row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
        bond_row = &mibs->user.bondinfo_utable->bond[bond_row->slave.master];
        if( vlan_id == 0 ) {
          /* Return ifindex of the bond master */
          return bond_row->ifid;
        }
        else {
          const cicp_llap_row_t *master_row = 
            cicp_llap_find_ifid(llapt, bond_row->ifid);
          const cicp_llap_row_t *vlan_row;
          ci_uint16 master_rowid;
          ci_assert(master_row);
          master_rowid = master_row - &llapt->llap[0];
          /* search for VLAN interface with right VLAN ID and where the
           * VLAN master and bond master are common (i.e. slave's
           * master LLAP rowid is same as VLAN's LLAP vlan_rowid)
           */
          for( vlan_row = &llapt->llap[0]; vlan_row < end_row; ++vlan_row ) {
            if( cicp_llap_row_allocated(vlan_row) && 
                vlan_row->encapsulation.type & CICP_LLAP_TYPE_VLAN &&
                vlan_row->encapsulation.vlan_id == vlan_id &&
                vlan_row->vlan_rowid == master_rowid ) 
              return vlan_row->ifindex;
          }
          OO_DEBUG_BONDING
            (ci_log("%s: didn't find VLAN interface for %d on BOND master %d",
                    __FUNCTION__, vlan_id, bond_row->ifid));
          return (ci_ifid_t)-1;
        }
      }
      else 
#endif
        if( row->encapsulation.vlan_id == vlan_id ) {
          ci_assert_impl((row->encapsulation.type & CICP_LLAP_TYPE_VLAN) == 0,
                         row->encapsulation.vlan_id == 0);
          return row->ifindex;
        }
      
    }
    ++row;
  }

  return (ci_ifid_t)-1;
}



/*! Find ifindex and source MAC of VLAN interface using master interface
 * and VLAN id.
 */
extern int /* rc */
cicppl_llap_get_vlan(const cicp_handle_t *control_plane,
                     ci_ifid_t *inout_ifindex, ci_uint16 vlan_id,
                     ci_mac_addr_t *out_mac)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  const cicp_llap_kmib_t *llapt;
  const cicp_llap_row_t *vlan_row;
  cicp_llap_row_t *master_row;
  ci_uint16 master_rowid;
  int rc = -ENODEV;

  ci_assert(NULL != mibs);
  ci_assert(NULL != mibs->llap_table);
    
  llapt = mibs->llap_table;
    
  CI_VERLOCK_READ_BEGIN(llapt->version);

  master_row = cicp_llap_find_ifid(llapt, *inout_ifindex);

  if( master_row != NULL ) {
    const cicp_llap_row_t *end_row = &llapt->llap[0] + llapt->rows_max;
    master_rowid = master_row - &llapt->llap[0];
    for( vlan_row = &llapt->llap[0]; vlan_row < end_row; ++vlan_row ) {
      if( cicp_llap_row_allocated(vlan_row) && 
          vlan_row->encapsulation.type & CICP_LLAP_TYPE_VLAN &&
          vlan_row->encapsulation.vlan_id == vlan_id &&
          vlan_row->vlan_rowid == master_rowid ) {
        CI_MAC_ADDR_SET(out_mac, &vlan_row->mac);
        *inout_ifindex = vlan_row->ifindex;
        rc = 0;
        break;
      }
    }
  }

  CI_VERLOCK_READ_END(llapt->version);
	
  return rc;
}




/*! Find first ifindex based on the given hwport supporting a given
 *  vlan_id
 */ 
extern int /* rc */
cicp_llap_find(const cicp_handle_t *control_plane, ci_ifid_t *out_ifindex,
	       ci_hwport_id_t hwport, const ci_uint16 vlan_id)
{   int rc = -ENODEV;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_kmib_t *llapt;
    ci_ifid_t ifindex;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;
    
    CI_VERLOCK_READ_BEGIN(llapt->version);
	
    ifindex = cicp_llap_hwport_to_ifindex(control_plane, llapt, hwport, vlan_id);
    
    if( ifindex != (ci_ifid_t)-1 ) {
      *out_ifindex = ifindex;
      rc = 0;
    }
    
    CI_VERLOCK_READ_END(llapt->version);
	
    return rc;
}





extern void
cicp_llap_cilog(cicp_handle_t *control_plane)
{   int i;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_llap_kmib_t *llapt;
    const cicp_llap_row_t *rowp;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;
    rowp = &llapt->llap[0];  
    ci_log("Link Layer Access Point Table:");
  
    CICP_LOCK_BEGIN(control_plane);  /* better to use a read lock really */

    for( i = 0; i < llapt->rows_max; ++i, ++rowp )
      ci_log("%3d: %s "CI_MAC_PRINTF_FORMAT" mtu %u name \"%s\"",
             rowp->ifindex, rowp->up ? " UP " : "DOWN",
             CI_MAC_PRINTF_ARGS(&rowp->mac), rowp->mtu, rowp->name);

    CICP_LOCK_END;
}


    



/*****************************************************************************
 *                                                                           *
 *          Bonding MIB							     *
 *          ===========							     *
 *                                                                           *
 *****************************************************************************/


static int 
cicp_check_ipif_callback(const cicp_mibs_kern_t *mibs, ci_ifid_t ifindex);
static void
cicp_ipif_announce_if(cicp_handle_t *control_plane, 
                      ci_ifid_t ifindex, int add);

#if CI_CFG_TEAMING

/*! find the first unallocated BOND MIB row */
ci_inline cicp_bond_row_t *cicp_bond_find_free(const cicp_mibs_kern_t *mibs)
{
  cicp_bond_row_t *end_row = &mibs->user.bondinfo_utable->bond[0];
  cicp_bond_row_t *row = end_row + (mibs->user.bondinfo_utable->rows_max - 1);

  while( row >= end_row && cicp_bond_row_allocated(row) )
    row--;
  
  return row >= end_row ? row : NULL;
}


static cicp_bond_row_t *cicp_bond_find(const cicp_mibs_kern_t *mibs, 
                                       ci_ifid_t ifindex)
{
  cicp_bond_row_t *row = &mibs->user.bondinfo_utable->bond[0];
  cicp_bond_row_t *end_row = row + mibs->user.bondinfo_utable->rows_max;
  
  while( row < end_row ) {
    if( cicp_bond_row_allocated(row) && 
        row->ifid == ifindex )
      return row;
    row++;
  }
  
  return NULL;
}


static int cicp_bond_find_rowid_locked(const cicp_mibs_kern_t *mibs, 
                                       ci_ifid_t ifindex)
{
  int rc;
  cicp_bond_row_t *row;

  row = cicp_bond_find(mibs, ifindex);
  rc = (row == NULL ? -1 : row - &mibs->user.bondinfo_utable->bond[0]);
 
  return rc;
}


extern int cicp_bond_find_rowid(cicp_handle_t *control_plane, 
                                ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs;
  int rc;

  CICP_LOCK_BEGIN(control_plane);

  mibs = CICP_MIBS(control_plane);  
  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);

  rc = cicp_bond_find_rowid_locked(mibs, ifindex);

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);
  
  CICP_LOCK_END;

  return rc;
}


static int cicp_bond_check_row(const cicp_mibs_kern_t *mibs, 
                               cicp_bond_row_t **row, int *rowid, 
                               ci_ifid_t ifindex, int type)
{
  if( (*row)->type != type || (*row)->ifid != ifindex ) {
    OO_DEBUG_BONDING(ci_log("%s: inconsistent bond table row %d", 
                            __FUNCTION__, *rowid));
    *rowid = cicp_bond_find_rowid_locked(mibs, ifindex);
    if( *rowid == -1 ) {
      OO_DEBUG_BONDING(ci_log("%s: no row matching ifindex %d",
                              __FUNCTION__, ifindex));
      return -EAGAIN;
    }
    *row = &mibs->user.bondinfo_utable->bond[*rowid];
  }
  return 0;
}


extern int cicp_bond_set_active(cicp_handle_t *control_plane, 
                                int master_rowid, ci_ifid_t master_ifindex,
                                int slave_rowid, ci_ifid_t slave_ifindex,
                                int is_active)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  cicp_bond_row_t *master_row;
  cicp_fwdinfo_t *fwdinfot = mibs->user.fwdinfo_utable;
  int was_active, rc;

  ci_assert(master_rowid >= 0 && slave_rowid >= 0);
  ci_assert(master_rowid < mibs->user.bondinfo_utable->rows_max && 
            slave_rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);

  row = &mibs->user.bondinfo_utable->bond[slave_rowid];
  if( (rc = cicp_bond_check_row(mibs, &row, &slave_rowid, slave_ifindex, 
                                CICP_BOND_ROW_TYPE_SLAVE)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);
    was_active = row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE;
    
    if( (!was_active) != (!is_active) ) {
      ci_verlock_write_start(&fwdinfot->version);
      
      master_row = &mibs->user.bondinfo_utable->bond[master_rowid];
      if( (rc = cicp_bond_check_row(mibs, &master_row, 
                                    &master_rowid, master_ifindex, 
                                    CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
        ci_assert(master_row->type == CICP_BOND_ROW_TYPE_MASTER);
        if( is_active ) {
          row->slave.flags |= CICP_BOND_ROW_FLAG_ACTIVE;
          ++master_row->master.n_active_slaves;
        }
        else {
          row->slave.flags &= ~CICP_BOND_ROW_FLAG_ACTIVE;
          --master_row->master.n_active_slaves;
        }
      }

      ci_verlock_write_stop(&fwdinfot->version);

      if( rc == 0 ) {
        cicp_fwdinfo_something_changed(control_plane);

        oof_mcast_update_filters(efab_tcp_driver.filter_manager,
                                 master_ifindex);
      }
    }
  }

  CICP_LOCK_END;
  
  return rc;
}


extern int cicp_bond_get_n_active_slaves(cicp_handle_t *control_plane,
                                         int rowid, ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  int rc;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);
  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);

  row = &mibs->user.bondinfo_utable->bond[rowid];
  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_MASTER);
    rc = row->master.n_active_slaves;
  }

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);
  CICP_LOCK_END;

  return rc;
}


extern int cicp_bond_check_slave_owner(cicp_handle_t *control_plane,
                                       int rowid, ci_ifid_t ifindex,
                                       ci_ifid_t master_ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row, *master;
  int rc;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);
  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);

  row = &mibs->user.bondinfo_utable->bond[rowid];
  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_SLAVE)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);
    ci_assert(row->slave.master >= 0);
    ci_assert(row->slave.master < mibs->user.bondinfo_utable->rows_max);
    master = &mibs->user.bondinfo_utable->bond[row->slave.master];
    if( master->ifid == master_ifindex )
      rc = 0;
    else
      rc = master->ifid;
  }

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);
  CICP_LOCK_END;

  return rc;
}


extern int cicp_bond_set_hash_policy(cicp_handle_t *control_plane,
                                     int rowid, int mode, ci_ifid_t ifindex,
                                     int hash_policy)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_fwdinfo_t *fwdinfot = mibs->user.fwdinfo_utable;
  cicp_bond_row_t *master;
  int rc = 0;

  CICP_LOCK_BEGIN(control_plane);
  
  master = &mibs->user.bondinfo_utable->bond[rowid];
  if( (rc = cicp_bond_check_row(mibs, &master, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    ci_assert(master->type == CICP_BOND_ROW_TYPE_MASTER);
    
    if( master->master.hash_policy != hash_policy ) {
      if( rc == 0 ) {
        ci_verlock_write_start(&fwdinfot->version);
        rc = 1;
      }
      master->master.hash_policy = hash_policy;
      cicp_llap_update_all_hash_state(control_plane, rowid, hash_policy);
    }
  }

  if( rc == 1 ) {
    ci_verlock_write_stop(&fwdinfot->version);
    cicp_fwdinfo_something_changed(control_plane);
  }

  CICP_LOCK_END;

  return rc;
}


extern int 
cicp_bond_check_active_slave_hwport(cicp_handle_t *control_plane,
                                    int rowid, ci_ifid_t ifindex,
                                    ci_hwport_id_t curr_hwport,
                                    ci_hwport_id_t *hwport)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  ci_hwport_id_t active_hwport = CI_HWPORT_ID_BAD;
  int rc = 0;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);
  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);

  row = &mibs->user.bondinfo_utable->bond[rowid];
  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_MASTER);
    
    while( row->next != CICP_BOND_ROW_NEXT_BAD ) {
      row = &mibs->user.bondinfo_utable->bond[row->next];
      ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);
      
      if( row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ) {
        if( curr_hwport != CI_HWPORT_ID_BAD && 
            row->slave.hwport == curr_hwport ) {
          active_hwport = curr_hwport;
          break;
        }
        else if ( active_hwport == CI_HWPORT_ID_BAD )
          active_hwport = row->slave.hwport;
      }
    }
  }

  *hwport = active_hwport;

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);
  CICP_LOCK_END;

  return rc;
}


extern int cicp_bond_mark_row(cicp_handle_t *control_plane, int rowid, 
                              ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  cicp_fwdinfo_t *fwdinfot = mibs->user.fwdinfo_utable;
  int rc = 0;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);

  row = &mibs->user.bondinfo_utable->bond[rowid];

  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_SLAVE)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);
    ci_verlock_write_start(&fwdinfot->version);
    row->slave.flags |= CICP_BOND_ROW_FLAG_MARK;
    ci_verlock_write_stop(&fwdinfot->version);
  }

  CICP_LOCK_END;

  return rc;
}


static void 
cicp_bond_remove_slave_row(cicp_handle_t *control_plane,
                           cicp_bond_row_t *master, cicp_bond_row_t *slave)
{
  cicp_llap_row_t *llap_row;

  --master->master.n_slaves;
  if( slave->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ) 
    --master->master.n_active_slaves;

  cicp_llap_update_all_bond_rowid(control_plane, slave->ifid, 
                                  CICP_BOND_ROW_NEXT_BAD, 0);

  llap_row = cicp_llap_find_ifid(CICP_MIBS(control_plane)->llap_table, 
                                 slave->ifid);
  if( llap_row )
    llap_row->encapsulation.type |= CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;

  /* TODO really need to first check if there are any other
   * users of this hwport still in unacceleratable bonds
   */
  if( slave->slave.hwport != CI_HWPORT_ID_BAD )
    oof_hwport_un_available(slave->slave.hwport, 1);

  slave->type = CICP_BOND_ROW_TYPE_FREE;
}


extern void
cicp_bond_prune_unmarked_in_bond(cicp_handle_t *control_plane,
                                 ci_ifid_t master_ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_fwdinfo_t *fwdinfot = mibs->user.fwdinfo_utable;
  cicp_bond_row_t *master;
  cicp_bond_row_t *row;
  cicp_bond_row_t *prev_row;
  int change = 0;

  CICP_LOCK_BEGIN(control_plane);
  
  master = cicp_bond_find(mibs, master_ifindex);

  if( master == NULL ) {
    OO_DEBUG_BONDING(ci_log("No row found for bond master %d", 
                            master_ifindex));
    goto out;
  }

  ci_assert(master != NULL);
  ci_assert(master->type == CICP_BOND_ROW_TYPE_MASTER);

  prev_row = row = master;
  while( row->next != CICP_BOND_ROW_NEXT_BAD ) {
    ci_assert(row->next < mibs->user.bondinfo_utable->rows_max);
    row = &mibs->user.bondinfo_utable->bond[row->next];
    ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);

    if( !(row->slave.flags & CICP_BOND_ROW_FLAG_MARK) ) {
      OO_DEBUG_BONDING(ci_log("Pruning slave %d", row->ifid));

      if( !change ) {
        ci_verlock_write_start(&fwdinfot->version);
        change = 1;
      }

      prev_row->next = row->next;
      cicp_bond_remove_slave_row(control_plane, master, row);
      cicp_bondinfo_dump(control_plane);
    } else {
      row->slave.flags &=~ CICP_BOND_ROW_FLAG_MARK;
      prev_row = row;
    }
  }

 out:
  if( change ) {
    ci_verlock_write_stop(&fwdinfot->version);

    cicp_fwdinfo_something_changed(control_plane);
    oof_mcast_update_filters(efab_tcp_driver.filter_manager, 
                             master_ifindex);
  }

  CICP_LOCK_END;
}


extern int
cicp_bond_get_master_ifindex(cicp_handle_t *control_plane,
                             ci_ifid_t slave_ifindex,
                             ci_ifid_t *master_ifindex)
{
  const cicp_mibs_kern_t *mibs;
  cicp_bond_row_t *row;
  int rc;

  mibs = CICP_MIBS(control_plane);  
  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);

  row = cicp_bond_find(mibs, slave_ifindex);

  if( row != NULL && row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
    ci_assert(row->slave.master >= 0);
    ci_assert(row->slave.master < mibs->user.bondinfo_utable->rows_max);
    row = &mibs->user.bondinfo_utable->bond[row->slave.master];
    ci_assert(row->type == CICP_BOND_ROW_TYPE_MASTER);
    *master_ifindex = row->ifid;
    rc = 0;
  } else
    rc = -1;

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);

  return rc;
}


static int 
cicp_bond_add_master(const cicp_mibs_kern_t *mibs, cicp_llap_row_t *row,
                     ci_ifid_t ifindex)
{
  cicp_bond_row_t *bond;
  int rc = 0;

  /* fwdinfot write lock should already be held as well */

  bond = cicp_bond_find_free(mibs);
  if( bond == NULL )
    rc = -ENOMEM;
  else {
    bond->type = CICP_BOND_ROW_TYPE_MASTER;
    bond->next = CICP_BOND_ROW_NEXT_BAD;
    bond->ifid = ifindex;
    bond->master.n_slaves = 0;
    bond->master.n_active_slaves = 0;
    bond->master.mode = -1;
    bond->master.active_hwport = CI_HWPORT_ID_BAD;
    bond->master.fatal = 0;
    bond->master.hash_policy = CICP_BOND_XMIT_POLICY_NONE;
    row->bond_rowid = (bond - &mibs->user.bondinfo_utable->bond[0]);
  }

  cicp_bondinfo_dump(mibs);

  return rc;
}


extern int 
cicp_bond_remove_master(cicp_handle_t *control_plane, ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *master, *tmp_row;
  cicp_fwdinfo_t *fwdinfot;
  int rc = 0, next_rowid;

  fwdinfot = mibs->user.fwdinfo_utable;

  CICP_LOCK_BEGIN(control_plane);

  master = cicp_bond_find(mibs, ifindex);
  if( master == NULL ) {
    OO_DEBUG_BONDING(ci_log("No row found for bond master %d", ifindex));
    rc = -ENODEV;
  }
  else {
    ci_verlock_write_start(&fwdinfot->version);

    cicp_llap_update_all_bond_rowid(control_plane, ifindex, 
                                    CICP_BOND_ROW_NEXT_BAD, 0);

    next_rowid = master->next;
    while ( next_rowid != CICP_BOND_ROW_NEXT_BAD ) {
      tmp_row = &mibs->user.bondinfo_utable->bond[next_rowid];
      ci_assert(tmp_row->type == CICP_BOND_ROW_TYPE_SLAVE);

      next_rowid = tmp_row->next;

      cicp_bond_remove_slave_row(control_plane, master, tmp_row);

      OO_DEBUG_BONDING(ci_log("Removing master %d purged slave %d (row %d)",
                              ifindex, tmp_row->ifid, 
                              (int)(tmp_row - 
                                    &mibs->user.bondinfo_utable->bond[0])));
    }
    ci_assert(master->master.n_slaves == 0);
    ci_assert(master->master.n_active_slaves == 0);
    master->type = CICP_BOND_ROW_TYPE_FREE;
    OO_DEBUG_BONDING(ci_log("Removed master %d (row %d)", ifindex, 
                            (int)(master - 
                                  &mibs->user.bondinfo_utable->bond[0])));

    ci_verlock_write_stop(&fwdinfot->version);
    
    cicp_fwdinfo_something_changed(control_plane);
  }

  cicp_bondinfo_dump(control_plane);

  CICP_LOCK_END;

  return rc;
}


extern int 
cicp_bond_add_slave(cicp_handle_t *control_plane, 
                    ci_ifid_t master_ifindex, ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *master, *row;
  cicp_llap_row_t *master_llap, *row_llap;
  cicp_fwdinfo_t *fwdinfot;
  int rc;

  fwdinfot = mibs->user.fwdinfo_utable;

  CICP_LOCK_BEGIN(control_plane);

  row = cicp_bond_find_free(mibs);
  if( row == NULL )
    rc = -ENOMEM;
  else {
    master = cicp_bond_find(mibs, master_ifindex);
    
    if( master == NULL ) {
      OO_DEBUG_BONDING(ci_log("No row found for bond master %d slave %d",
                              master_ifindex, ifindex));
      rc = -ENODEV;
    } else {
      ci_verlock_write_start(&fwdinfot->version);

      ci_assert(master->type == CICP_BOND_ROW_TYPE_MASTER);
      
      row_llap = cicp_llap_find_ifid(mibs->llap_table, ifindex);
      if( row_llap == NULL ) {
        OO_DEBUG_BONDING(ci_log("%s: No LLAP found for slave %d",
                                __FUNCTION__, ifindex));
        rc = -ENODEV;
      } 
      else {
        row->type = CICP_BOND_ROW_TYPE_SLAVE;
        row->next = master->next;
        row->ifid = ifindex;
        row->slave.master = (master - &mibs->user.bondinfo_utable->bond[0]);
        row->slave.hwport = row_llap->hwport;
        ci_assert(row->slave.hwport == CI_HWPORT_ID_BAD || 
                  row->slave.hwport <= CI_HWPORT_ID_MAX);
        row->slave.flags = 0;

        row_llap->bond_rowid = (row - &mibs->user.bondinfo_utable->bond[0]);

        master->next = (row - &mibs->user.bondinfo_utable->bond[0]);
        rc = master->next;
        master->master.n_slaves++;

        master_llap = cicp_llap_find_ifid(mibs->llap_table, master_ifindex);
        if( master_llap != NULL && 
            !(master_llap->encapsulation.type & 
              CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT) && 
            row->slave.hwport != CI_HWPORT_ID_BAD )
          oof_hwport_un_available(row->slave.hwport, 0);
      }

      ci_verlock_write_stop(&fwdinfot->version);
    }
  }

  if( rc >= 0 )
    cicp_fwdinfo_something_changed(control_plane);

  cicp_bondinfo_dump(control_plane);

  CICP_LOCK_END;

  return rc;
}


extern int 
cicp_bond_remove_slave(cicp_handle_t *control_plane,
                       ci_ifid_t master_ifindex, ci_ifid_t ifindex)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *master, *row, *tmp_row;
  cicp_fwdinfo_t *fwdinfot;
  int rc, rowid;

  fwdinfot = mibs->user.fwdinfo_utable;

  CICP_LOCK_BEGIN(control_plane);

  row = cicp_bond_find(mibs, ifindex);
  if( row == NULL ) {
    OO_DEBUG_BONDING(ci_log("No row found for bond slave %d", ifindex));
    rc = -ENODEV;
  }
  else {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_SLAVE);
    master = cicp_bond_find(mibs, master_ifindex);
    
    if( master == NULL ) {
      OO_DEBUG_BONDING(ci_log("No row found for bond master %d slave %d",
                              master_ifindex, ifindex));
      rc = -ENODEV;
    } else {
      int found = 0;

      ci_verlock_write_start(&fwdinfot->version);

      ci_assert(master->type == CICP_BOND_ROW_TYPE_MASTER);
      
      rowid = (row - &mibs->user.bondinfo_utable->bond[0]);

      tmp_row = master;
      while ( tmp_row->next != CICP_BOND_ROW_NEXT_BAD ) {
        if( tmp_row->next == rowid ) {
          tmp_row->next = row->next;
          found = 1;
          break;
        }
        tmp_row = &mibs->user.bondinfo_utable->bond[tmp_row->next];
      }

      if( found ) {
        cicp_bond_remove_slave_row(control_plane, master, tmp_row);
        rc = 0;
        OO_DEBUG_BONDING(ci_log("Slave %d removed from master %d",
                                ifindex, master_ifindex));
      } else {
        OO_DEBUG_BONDING(ci_log("Slave %d not found in master %d's list",
                                ifindex, master_ifindex));
        rc = -EINVAL;
      }
      ci_verlock_write_stop(&fwdinfot->version);
    }
  }

  if( rc == 0 ) {
    cicp_fwdinfo_something_changed(control_plane);
    oof_mcast_update_filters(efab_tcp_driver.filter_manager, 
                             master_ifindex);
  }
  cicp_bondinfo_dump(control_plane);

  CICP_LOCK_END;

  return rc;
  
}


extern int /* rc */
cicp_llap_set_bond(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                   ci_ifid_t master_ifindex, cicp_encap_t *encap)
{
  cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  int rc = 0, ipif_status_before, ipif_status_after;
  cicp_llap_kmib_t *llapt;
  cicp_llap_row_t *row;
  cicp_bond_row_t *bond;

  ci_assert(mibs != NULL);
  ci_assert(mibs->llap_table != NULL);
  ci_assert(encap->type & CICP_LLAP_TYPE_BOND);
   
  CICP_LOCK_BEGIN(control_plane);

  llapt = mibs->llap_table;
   
  row = cicp_llap_find_ifid(llapt, ifindex);

  if( row != NULL ) {
    ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

    ci_verlock_write_start(&llapt->version);

    encap->type |= CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
    memcpy(&row->encapsulation, encap, sizeof(row->encapsulation));

    bond = cicp_bond_find(mibs, master_ifindex);
    if( bond == NULL )
      rc = cicp_bond_add_master(mibs, row, master_ifindex);
    else {
      row->bond_rowid = (bond - &mibs->user.bondinfo_utable->bond[0]);
      ci_assert(bond->type == CICP_BOND_ROW_TYPE_MASTER);
      /* This is useful to sync-up any VLAN-over-bond interfaces that
       * have been brought up after the bonding interface and set their
       * hwport appropriately */ 
      row->hwport = bond->master.active_hwport;
    }

    ci_verlock_write_stop(&llapt->version);

    /* Check to see if this change should cause an ipif callback */
    ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
    if( ipif_status_before != ipif_status_after )
      cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);

    /* update the forwarding cache correspondingly */
    cicp_fwdinfo_llap_set_encapsulation(control_plane, ifindex,
                                        encap);
  } else
    rc = -ENODEV; /* device not found */
	
  CICP_LOCK_END;

  cicp_bondinfo_dump(control_plane);

  return rc;
}


extern int cicp_bond_update_mode(cicp_handle_t *control_plane, 
                                 int rowid, ci_ifid_t ifindex, int mode)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  cicp_fwdinfo_t *fwdinfot = mibs->user.fwdinfo_utable;
  int rc = 0, change = 0;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);
  CICP_LOCK_BEGIN(control_plane);

  row = &mibs->user.bondinfo_utable->bond[rowid];

  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_MASTER);
    if( row->master.mode != mode ) {
      ci_verlock_write_start(&fwdinfot->version);
      row->master.mode = mode;
      ci_verlock_write_stop(&fwdinfot->version);
      change = 1;
    }
  }

  if( change == 1 )
    cicp_fwdinfo_something_changed(control_plane);
  
  cicp_bondinfo_dump(control_plane);

  CICP_LOCK_END;

  return rc;
}


extern int cicp_bond_get_mode(cicp_handle_t *control_plane, int rowid,
                              ci_ifid_t ifindex, int *mode)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_bond_row_t *row;
  int rc = 0;

  ci_assert(rowid >= 0);
  ci_assert(rowid < mibs->user.bondinfo_utable->rows_max);

  CICP_LOCK_BEGIN(control_plane);

  CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);
  row = &mibs->user.bondinfo_utable->bond[rowid];

  if( (rc = cicp_bond_check_row(mibs, &row, &rowid, ifindex, 
                                CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    ci_assert(row->type == CICP_BOND_ROW_TYPE_MASTER);
    *mode = row->master.mode;
  }

  CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);

  CICP_LOCK_END;

  return rc;
}

#endif


/* NB caller is responsible for taking and releasing the control plane lock */

extern int cicp_get_active_hwport_mask(cicp_handle_t *control_plane,
                                       ci_ifid_t ifindex, 
                                       unsigned *hwport_mask)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *llap_row;
  int rc = 0;

  CICP_CHECK_LOCKED(control_plane);

  if( ifindex == CI_IFID_ALL ) {
    *hwport_mask = (unsigned)-1;
    return 0;
  }

  *hwport_mask = 0;

  CI_VERLOCK_READ_BEGIN(mibs->llap_table->version);

  llap_row = cicp_llap_find_ifid(mibs->llap_table, ifindex);
  if( llap_row == NULL ) {
    rc = -ENODEV;
  } 
#if CI_CFG_TEAMING
  else if( !(llap_row->encapsulation.type & CICP_LLAP_TYPE_BOND) ) {
    if( llap_row->hwport != CI_HWPORT_ID_BAD )
      *hwport_mask = (1 << llap_row->hwport);
  } 
  else if( llap_row->bond_rowid != CICP_BOND_ROW_NEXT_BAD ) {
    cicp_bond_row_t *bond_row;
    CI_VERLOCK_READ_BEGIN(mibs->user.fwdinfo_utable->version);
    bond_row = &mibs->user.bondinfo_utable->bond[llap_row->bond_rowid];
    ci_assert_equal(bond_row->type, CICP_BOND_ROW_TYPE_MASTER);

    while ( bond_row->next != CICP_BOND_ROW_NEXT_BAD ) {
      bond_row = &mibs->user.bondinfo_utable->bond[bond_row->next];
      ci_assert(bond_row->type == CICP_BOND_ROW_TYPE_SLAVE);
      if( (bond_row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE) &&
          (bond_row->slave.hwport != CI_HWPORT_ID_BAD) )
        *hwport_mask |= (1 << bond_row->slave.hwport);
    }
    CI_VERLOCK_READ_END(mibs->user.fwdinfo_utable->version);
  }
#else
  else {
    if( llap_row->hwport != CI_HWPORT_ID_BAD )
      *hwport_mask = (1 << llap_row->hwport);
  }
#endif

  CI_VERLOCK_READ_END(mibs->llap_table->version);

  return rc;
}



/*****************************************************************************
 *                                                                           *
 *          IP interface MIB						     *
 *          ================						     *
 *                                                                           *
 *****************************************************************************/











ci_inline cicp_ipif_row_t *
cicp_ipif_iterator_start(cicp_ipif_kmib_t *ipift)
{
    return &ipift->ipif[-1];
}







/*! ipif table iterator, iterates all entries of a given ifindex
 *  the first time it must be called with cicp_ipif_iterator_start() */
ci_inline cicp_ipif_row_t *
cicp_ipif_iterator(cicp_ipif_kmib_t *ipift,
		   cicp_ipif_row_t *row, ci_ifid_t ifindex)
{   cicp_ipif_row_t *row_end = &ipift->ipif[ipift->rows_max];
    while (++row < row_end && cicp_ipif_row_allocated(row))
        if (row->ifindex == ifindex)
          return row;
    return NULL;
}

/* Same as cicp_ipif_iterator, but do not check ifindex. */
ci_inline cicp_ipif_row_t *
cicp_ipif_iterator_all(cicp_ipif_kmib_t *ipift, cicp_ipif_row_t *row)
{   cicp_ipif_row_t *row_end = &ipift->ipif[ipift->rows_max];
    while (++row < row_end && cicp_ipif_row_allocated(row))
        return row;
    return NULL;
}






static int /* rc */
cicp_ipif_kmib_ctor(cicp_ipif_kmib_t **out_ipift, int rows_max)
{
  int i;
  cicp_ipif_kmib_t *ipift;

  OO_DEBUG_FWD(DPRINTF(CODEID ": constructing kernel IP Interface table"););
    
  *out_ipift = (cicp_ipif_kmib_t *)ci_vmalloc(sizeof(cicp_ipif_kmib_t));
  ipift = *out_ipift;

  if( ipift == NULL )
    return -ENOMEM;

  ipift->ipif = ci_vmalloc(rows_max * sizeof(cicp_ipif_row_t));
  if( ipift->ipif == NULL ) {
    ci_vfree(ipift);
    *out_ipift = NULL;
    return -ENOMEM;
  }

  ipift->rows_max = rows_max;

  for( i = 0; i < ipift->rows_max; i++ ) {
    cicp_ipif_row_t *row = &ipift->ipif[i];
    memset(row, 0, sizeof(*row));
    cicp_ipif_row_free(row);
  }
	
  ipift->version = CI_VERLOCK_INIT_VALID;

  for( i = 0; i < 1; ++i )
    cicp_ipif_callback_free(&ipift->sync.callback.reg[i]);
	
  return 0;
}






ci_inline void
cicp_ipif_kmib_dtor(cicp_ipif_kmib_t **ref_ipift)
{
  OO_DEBUG_ARP(DPRINTF(CODEID ": kernel IP Interface table "
                       "destructor called"););
  
  if( NULL != *ref_ipift ) {
    ci_vfree((*ref_ipift)->ipif);
    ci_vfree(*ref_ipift);
    *ref_ipift = NULL;
  }
}





/*! return whether a supplied IP address is a special IP interface address
 *  - system call implementation: see user header for documentation
 */
ci_inline int /* rc */
cicp_ipif_addr_get_kind(const cicp_ipif_kmib_t *ipift, ci_ip_addr_net_t ip,
		        ci_ip_addr_kind_t* out_addr_kind)
{   const cicp_ipif_row_t *row;
    const cicp_ipif_row_t *maxrow;
    
    out_addr_kind->bitsvalue = 0;
    
    row = &ipift->ipif[0];
    maxrow = row + ipift->rows_max;

    while (row < maxrow && cicp_ipif_row_allocated(row))
    {
	ci_ip_addr_t net_addr;

	CI_IP_ADDR_SET_SUBNET(&net_addr, &row->net_ip, row->net_ipset);
	/* if (CI_IP_ADDR_IN_SUBNET(&ip, &row->net_ip, row->net_ipset))
	       subnet_found = TRUE;  */

	if (CI_IP_ADDR_EQ(&ip, &net_addr))
	    out_addr_kind->bits.is_netaddr = 1;

	if (CI_IP_ADDR_EQ(&ip, &row->net_ip))
	    out_addr_kind->bits.is_ownaddr = 1;

	if (CI_IP_ADDR_EQ(&ip, &row->bcast_ip))
	    out_addr_kind->bits.is_broadcast = 1;

	row++;
    }
    

    return /* rc */ 0;
}






/*! return whether a supplied IP address is a special IP interface address
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicp_ipif_addr_kind(const cicp_handle_t *control_plane, ci_ip_addr_net_t ip,
		    ci_ip_addr_kind_t* out_addr_kind)
{   int rc;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_ipif_kmib_t *ipift;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->ipif_table);
    
    ipift = mibs->ipif_table;
	    
    CI_VERLOCK_READ_BEGIN(ipift->version)
    
        rc = cicp_ipif_addr_get_kind(ipift, ip, out_addr_kind);
    
    CI_VERLOCK_READ_END(ipift->version)
	
    return rc;
}






/*! Find the IP interface row offering the IP address over a given access point
 */
static const cicp_ipif_row_t *
cicp_ipif_find_ip(const cicp_ipif_kmib_t *ipift, 
		  ci_ifid_t ifindex,
		  const ci_ip_addr_net_t *ref_local_ip)
{   const cicp_ipif_row_t *minrow       = &ipift->ipif[0];
    const cicp_ipif_row_t *maxrow       = minrow + ipift->rows_max;
    const cicp_ipif_row_t *row          = minrow;
    const cicp_ipif_row_t *home_row     = NULL;
    const cicp_ipif_row_t *tightest_row = NULL;
    ci_ip_addrset_t tightest_match      = CI_IP_ADDRSET_UNIVERSAL;

    /* There may be many matching IP interfaces: find out which
           (a) actually have a home address matching the IP address, or
	   (b) has the smallest size that includes it
    */
    while (row < maxrow && cicp_ipif_row_allocated(row))
    {   if ((ifindex == CI_IFID_BAD || ifindex == row->ifindex) &&
             CI_IP_ADDR_SAME_NETWORK(ref_local_ip, &row->net_ip,
				    row->net_ipset))
        {   if (CI_IP_ADDR_EQ(&row->net_ip, ref_local_ip))
	        home_row = row;
	    if (CI_IP_ADDRSET_INCLUDES(row->net_ipset, tightest_match))
	    {   tightest_match = row->net_ipset;
		tightest_row = row;
	    }
	}
        IGNORE(else DPRINTF("%d: %08X not in %08X/%d - mask %08X nxor %08X",
		row-minrow, local_ip, row->net_ip, row->net_ipset,
		CI_BSWAP_BE32(ci_ip_prefix2mask(row->net_ipset)),
		       (local_ip ^ row->net_ip));)
	row++;
    }

    return NULL != home_row? home_row: tightest_row;
}






/*! Find the IP interface row by ifindex
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicp_ipif_by_ifindex(const cicp_handle_t *control_plane, 
		     ci_ifid_t ifindex, ci_ip_addr_t *out_addr)
{   int rc = -ENODEV;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_ipif_kmib_t *ipift;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);

    ipift = mibs->ipif_table;

    CI_VERLOCK_READ_BEGIN(ipift->version)

	const cicp_ipif_row_t *minrow       = &ipift->ipif[0];
	const cicp_ipif_row_t *maxrow       = minrow + ipift->rows_max;
	const cicp_ipif_row_t *row          = minrow;

        while (row < maxrow && cicp_ipif_row_allocated(row))
        {   if (ifindex == row->ifindex)
            {   *out_addr = row->net_ip;
                rc = 0;
                break;
            }
            row++;
        }

    CI_VERLOCK_READ_END(ipift->version)

    return rc;
}







static const cicp_ipif_row_t *
_cicp_ipif_choose_if(cicp_ipif_kmib_t *ipift,
		     ci_ifid_t ifindex,
                     ci_ip_addr_t dst_ip_be32,
                     ci_ip_addr_t src_ip_be32)
{
  cicp_ipif_row_t *row = cicp_ipif_iterator_start(ipift);

  while((row = cicp_ipif_iterator(ipift, row, ifindex))) {
    int dst = (dst_ip_be32 ^ row->net_ip)
              & CI_BSWAP_BE32(ci_ip_prefix2mask(row->net_ipset));
    int src = (src_ip_be32 ^ row->net_ip)
              & CI_BSWAP_BE32(ci_ip_prefix2mask(row->net_ipset));
    if (dst == 0 && src == 0)
      return row; /* we found a good match, return it */
  }

  /* we didn't find a good match, return anything with a matching ifindex */
  return cicp_ipif_iterator(ipift, cicp_ipif_iterator_start(ipift), ifindex);
}






/*! Find first ifindex based on the given nic and port supporting a given
 *  encapsulation
 */ 
extern int
cicp_ipif_pktinfo_query(const cicp_handle_t *control_plane, 
                        ci_netif            *netif,
                        oo_pkt_p             pktid,
                        ci_ifid_t            ifindex,
                        ci_ip_addr_t        *out_spec_addr)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  ci_ip_pkt_fmt *pkt = PKT(netif, pktid);
  const cicp_ipif_row_t *row;
  cicp_ipif_kmib_t *ipift; 

  ci_assert(NULL != netif);
  ci_assert(NULL != mibs->ipif_table);

  ipift = mibs->ipif_table;

  /* usualy the specific address is the address in the packet */
  *out_spec_addr = oo_ip_hdr(pkt)->ip_daddr_be32;

  /* select an IP appropriate interface */
  row = _cicp_ipif_choose_if(ipift, ifindex,
                             oo_ip_hdr(pkt)->ip_daddr_be32,
                             oo_ip_hdr(pkt)->ip_saddr_be32);

  if (row == NULL) {
    /* what do we do when we don't have an IP interface? an interface could be
     * removed while a packet is travelling up the stack, I imagine that the
     * best thing would be to drop the packet, we return an error to mark this
     * case so that the caller can drop the packet
     */
    return -EINVAL;

  } else
  {
    ci_ip_addr_t ipif_ip_subnet;

    CI_IP_ADDR_SET_SUBNET(&ipif_ip_subnet, &row->net_ip, row->net_ipset);
     /* check if it is a broadcast address, here I am assuming that the network
     * address is treated as a broadcast address, if it is, then set the 
     * specific address to the address of the interface
     */
    if (CI_IP_ADDR_EQ(&oo_ip_hdr(pkt)->ip_daddr_be32, &row->bcast_ip) ||
	CI_IP_ADDR_EQ(&oo_ip_hdr(pkt)->ip_daddr_be32, &ipif_ip_subnet) ||
	CI_IP_ADDR_IS_MULTICAST(&oo_ip_hdr(pkt)->ip_daddr_be32))
    {
      CI_IP_ADDR_SET(out_spec_addr, &row->net_ip);
    }

    return 0;
  }
}





static int /* bool */
_cicp_ipif_net_or_brd_addr(cicp_ipif_kmib_t *ipift,
		           ci_ifid_t ifindex, ci_ip_addr_t *ref_ip_be32)
{
  cicp_ipif_row_t *row = cicp_ipif_iterator_start(ipift);

  while((row = cicp_ipif_iterator(ipift, row, ifindex)))
  {   ci_ip_addr_t ipif_ip_subnet;
      CI_IP_ADDR_SET_SUBNET(&ipif_ip_subnet, &row->net_ip, row->net_ipset);
      if (CI_IP_ADDR_EQ(ref_ip_be32, &row->bcast_ip) ||
	  CI_IP_ADDR_EQ(ref_ip_be32, &ipif_ip_subnet))
      return TRUE;
  }
  return FALSE;
}






extern int
cicp_ipif_net_or_brd_addr(const cicp_handle_t *control_plane, 
		          ci_ifid_t ifindex, ci_ip_addr_t *ref_ip_be32)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_ipif_kmib_t *ipift; 
    int rc;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);

    ipift = mibs->ipif_table;
    
    CI_VERLOCK_READ_BEGIN(ipift->version)
	
	rc = _cicp_ipif_net_or_brd_addr(ipift, ifindex, ref_ip_be32);
    
    CI_VERLOCK_READ_END(ipift->version)
	
    return rc;
}






/*!
 * Dump the contents of the IP interfaces table to the system log
 *
 * \param control_plane   control plane handle
 *
 * This function requires the table to be locked and locks it itself.
 */
extern void
cicp_ipif_cilog(cicp_handle_t *control_plane)
{
    int i;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_ipif_kmib_t *ipift;
    const cicp_ipif_row_t *rowp;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->ipif_table);
    
    ipift = mibs->ipif_table;
    rowp = &ipift->ipif[0];
    
    ci_log("IP Interfaces Table:");

    CICP_LOCK_BEGIN(control_plane);  /* better to use a read lock really */

	for( i = 0; i < ipift->rows_max; ++i, ++rowp ) 
	    ci_log("%3d: "CI_IP_PRINTF_FORMAT"/%d bcast "
		   CI_IP_PRINTF_FORMAT" llap "CI_IFID_PRINTF_FORMAT,
		   i, CI_IP_PRINTF_ARGS(&rowp->net_ip),
		   rowp->net_ipset,
		   CI_IP_PRINTF_ARGS(&rowp->bcast_ip),
		   rowp->ifindex);

    CICP_LOCK_END;
}






/*!
 * Copy the network and broadcast addresses of efab IP i/f table to array
 *
 * \param control_plane   control plane handle
 * \param addr_array      IP address array to place addresses in
 *
 * \returns               The number of IP interfaces written
 *
 *  - see driver header for documentation
 *
 * This function requires the table to be locked and locks it itself.
 */
extern int
cicp_ipif_dump_efab(const cicp_handle_t *control_plane,
		    ci_ip_addr_t *addr_array)
{   int count = 0;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_ipif_kmib_t *ipift;
    const cicp_llap_kmib_t *llapt;
    const cicp_ipif_row_t *row;
    const cicp_ipif_row_t *maxrow;
    const cicp_llap_row_t *row_llap;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->ipif_table);
    ci_assert(NULL != mibs->llap_table);
    
    ipift = mibs->ipif_table;
    llapt = mibs->llap_table;
    
    row = &ipift->ipif[0];
    maxrow = row + ipift->rows_max;

    CI_VERLOCK_READ_BEGIN(ipift->version)

      while (row < maxrow && cicp_ipif_row_allocated(row)) {
	row_llap = cicp_llap_find_ifid(llapt, row->ifindex);
	if (CI_LIKELY(row_llap != 0)) {
	  ci_assert_equal(row->ifindex, row_llap->ifindex);
	  if (row_llap->hwport != CI_HWPORT_ID_BAD) {
	      CI_IP_ADDR_SET(&addr_array[count], &row->net_ip);
	      CI_IP_ADDR_SET(&addr_array[ipift->rows_max + count],
			     &row->bcast_ip);
	      count++;
	  }
	}
	row++;
      }

    CI_VERLOCK_READ_END(ipift->version)

    return count;
}








/*****************************************************************************
 *                                                                           *
 *          Routing MIB							     *
 *          ===========							     *
 *                                                                           *
 *****************************************************************************/







ci_inline int /* rc */
cicp_route_kmib_ctor(cicp_route_kmib_t **out_routet, int rows_max)
{
  int i;
  cicp_route_kmib_t *routet;
  
  OO_DEBUG_FWD(DPRINTF(CODEID ": constructing kernel Routing table"););
    
  *out_routet = (cicp_route_kmib_t *)ci_vmalloc(sizeof(cicp_route_kmib_t));
  routet = *out_routet;
  
  if( routet == NULL )
    return -ENOMEM;

  routet->entry = ci_vmalloc(rows_max * sizeof(cicp_route_kernrow_t));
  if( routet->entry == NULL ) {
    ci_vfree(routet);
    *out_routet = NULL;
    return -ENOMEM;
  }

  routet->rows_max = rows_max;

  for( i = 0; i < routet->rows_max; ++i ) {
    cicp_route_kernrow_t *row = &routet->entry[i];
    cicpos_route_kmib_row_ctor(&row->sync);
  }
  return 0;
}





ci_inline void
cicp_route_kmib_dtor(cicp_route_kmib_t **ref_routet)
{   
  OO_DEBUG_FWD(DPRINTF(CODEID ": kernel Route table destructor called"););
  
  if( NULL != *ref_routet ) {
    ci_vfree((*ref_routet)->entry);
    ci_vfree(*ref_routet);
    *ref_routet = NULL;
  }
}












/*****************************************************************************
 *                                                                           *
 *          Address Resolution MIB					     *
 *          ======================					     *
 *                                                                           *
 *****************************************************************************/






/*< Initialize kernel synchronization state in the MAC MIB */
static int /* rc */
cicp_mac_kmib_ctor(cicp_mac_kmib_t **out_mact, int mac_rows_ln2)
{   int rc = 0;
    int rows = 1 << mac_rows_ln2;
    cicp_mac_kmib_t *mact;
    
    OO_DEBUG_ARP(DPRINTF(CODEID ": constructing kernel Address Resolution "
			"table"););

    mact = (cicp_mac_kmib_t *)ci_vmalloc(CICP_MAC_KMIB_SIZE(mact, rows));
    
    if (NULL == mact)
	rc = -ENOMEM;
    else
    {   int rc_prot = cicppl_mac_kmib_ctor(&mact->prot);
	int rc_sync = cicpos_mac_kmib_ctor(&mact->sync);

	OO_DEBUG_MEMSIZE(DPRINTF(CODEID ": %u bytes of kernel memory for "
			 "the kernel address resolution table",
		         (unsigned)CICP_MAC_KMIB_SIZE(mact, rows)););

	mact->sync_claimed = FALSE;
	    
	if (rc_prot != 0 || rc_sync != 0)
	{   if (rc_prot != 0)
	        rc = rc_prot;
	    else
	        rc = rc_sync;
	    ci_vfree(mact);
        } else
	{   /* ensure that resolution protocol and O/S sync fields are set */
	    int i;
	    
	    for (i=0; i < rows; i++)
	    {   cicp_mac_kernrow_t *row = &(mact->entry[i]);
		cicpos_mac_kmib_row_ctor(&row->sync, NULL);
		cicppl_mac_kmib_row_ctor(&row->prot);
	    }
	    *out_mact = mact;
	}
    }
    return rc;
}






static void
cicp_mac_kmib_dtor(cicp_mibs_kern_t *control_plane,
		   cicp_mac_kmib_t **ref_mact, cicp_mac_mib_t *umact)
{   cicp_mac_kmib_t *mact = *ref_mact;
    
    OO_DEBUG_ARP(DPRINTF(CODEID ": kernel Address Resolution table "
		        "destructor called"););
    
    if (NULL != mact)
    {   /* ensure all pending protocol activity has ceased */
	CICP_LOCK(control_plane,
            unsigned int i;
	    for (i=0; i< cicp_mac_mib_rows(umact); i++)
	    {   cicp_mac_row_t  *urow = &umact->ipmac[i];
                cicp_mac_kernrow_t *row  = &mact->entry[i];
                
		if (cicp_mac_row_allocated(urow))
		    cicppl_mac_kmib_row_dtor(&row->prot);
	    }
	)

	/* terminate protocol-specific state */
	cicppl_mac_kmib_dtor(&mact->prot);
	/* terminate O/S-synchronization-specific state */
	cicpos_mac_kmib_dtor(&mact->sync);

	ci_vfree(mact);
	*ref_mact = NULL;
    }
}





static int /* rc */ 
cicp_mac_mib_ctor(cicp_mibs_kern_t *mibs, int mac_rows_ln2)
{   cicp_mac_mib_t *mact;
    int rc = 0;
    int rows = 1 << mac_rows_ln2;
    cicp_ul_mibs_t *umibs = &mibs->user;

    OO_DEBUG_ARP(DPRINTF(CODEID ": constructing user Address Resolution "
			"table"););

    ci_assert(NULL != mibs);
    
    umibs->mac_utable =
	(cicp_mac_mib_t *)cicp_shared_alloc(CICP_MAC_MIB_SIZE(
						umibs->mac_utable,
					        rows),
					    &umibs->mac_mmap_len,
					    &mibs->mac_shared,
					    &rc);

    if (CI_LIKELY(NULL != umibs->mac_utable))
    {	/* Initialize the address resolution table.			 */
	/* NB: Interrupts (for char driver) must be disconnected here.	 */
	int i;

	mact = umibs->mac_utable;
	mact->rows_ln2 = mac_rows_ln2;

        /* Mark all entries as free and set seq_num to a valid number. */
	for (i=CICP_MAC_MIB_ROW_MOSTLY_VALID; i < rows; i++)
	{   cicp_mac_row_t *row = &mact->ipmac[i];

	    row->version = CI_VERLOCK_INIT_VALID;
	    /* set ip and mac addresses to all 0xEE; for debugging */
	    memset(&row->mac_addr, 0xEE, sizeof(row->mac_addr));
	    memset(&row->ip_addr, 0xEE, sizeof(row->ip_addr));
	    cicp_mac_row_free(row); /* NB: alters version to invalid */
	    row->rc = 0;
	    row->use_enter = 0; /* set use-count to zero */
	}
        mact->ipmac[CICP_MAC_MIB_ROW_MOSTLY_VALID].version =
          CI_VERLOCK_INIT_VALID;
    } else {
      rc = -ENOMEM;
    }

    return rc;
}





ci_inline void 
cicp_mac_mib_dtor(cicp_mibs_kern_t *mibs)
{   cicp_mac_mib_t *mact;
    cicp_ul_mibs_t *umibs = &mibs->user;
  
    OO_DEBUG_ARP(DPRINTF(CODEID ": user Address Resolution table destructor "
			"called"););

    ci_assert(mibs != NULL);
    mact = umibs->mac_utable;

    if (NULL != mact)
    {   cicp_shared_free(&mibs->mac_shared);
	umibs->mac_utable = NULL; /* shared resource gone now */
    }
}






/*****************************************************************************
 *                                                                           *
 *          EtherFabric Hardware Port MIB				     *
 *          =============================				     *
 *                                                                           *
 *****************************************************************************/







static int /* rc */
cicp_hwport_kmib_ctor(cicp_hwport_kmib_t **out_hwportt)
{   cicp_hwport_kmib_t *hwportt;

    OO_DEBUG_ARP(DPRINTF(CODEID ": constructing kernel Hardware Port "
			   "table"););
    
    *out_hwportt = (cicp_hwport_kmib_t *)
		   ci_vmalloc(sizeof(cicp_hwport_kmib_t));
    hwportt = *out_hwportt;

    if (NULL != hwportt)
    {	int hwport;
	
	OO_DEBUG_MEMSIZE(DPRINTF(CODEID ": %u bytes of kernel memory for "
			 "hardware port table",
		         (unsigned)sizeof(cicp_hwport_kmib_t)););
	    
	for (hwport=0; hwport < CI_HWPORT_ID_MAX; hwport++)
	{
	    cicp_hwport_row_t *row = &hwportt->nic[hwport];
	    memset(&hwportt->nic[hwport], 0, sizeof(hwportt->nic[hwport]));
	    cicp_hwport_row_free(row);
	}
	return 0;
    } else
	return ENOMEM;
}





ci_inline void
cicp_hwport_kmib_dtor(cicp_hwport_kmib_t **ref_hwportt)
{   OO_DEBUG_ARP(DPRINTF(CODEID ": kernel IP Interface table "
			 "destructor called"););

    if (NULL != *ref_hwportt)
    {   ci_vfree(*ref_hwportt);
	*ref_hwportt = NULL;
    }
}






    
/*! indicate that a new NIC has been detected
 *  - see driver header for documentation
 */
extern void
cicp_hwport_add_nic(cicp_handle_t *control_plane, ci_hwport_id_t hwport)
{
    const cicp_mibs_kern_t *mibs;
    ci_mtu_t max_mtu = CICP_HWPORT_MAX_MTU_DEFAULT;
    cicp_hwport_kmib_t *hwportt;

    ci_assert(NULL != control_plane);

    mibs = CICP_MIBS(control_plane);
    ci_assert(NULL != mibs);

    hwportt = mibs->hwport_table;
    ci_assert(NULL != hwportt);

    ci_assert_le(hwport, CI_HWPORT_ID_MAX);

    CICP_LOCK_BEGIN(control_plane)
	
	hwportt->nic[hwport].max_mtu = max_mtu;

        /* update the forwarding cache correspondingly */
        cicp_fwdinfo_hwport_add_nic(control_plane, hwport, max_mtu);
	
    CICP_LOCK_END

    /* allow syncrhonization to start as soon as the first port is added */
    cicpos_running = 1;
}





/*! indicate that an old NIC is no longer detected
 *  - see driver header for documentation
 */
extern void
cicp_hwport_remove_nic(cicp_handle_t *control_plane, ci_hwport_id_t hwport)
{   const cicp_mibs_kern_t *mibs;
    cicp_hwport_kmib_t *hwportt;

    ci_assert((unsigned) hwport <= CI_HWPORT_ID_MAX);
    ci_assert(control_plane != NULL);

    mibs = CICP_MIBS(control_plane);
    if( mibs == NULL )
      return;
    if( mibs->hwport_table == NULL )
      return;

    hwportt = mibs->hwport_table;

    CICP_LOCK_BEGIN(control_plane);
    
    cicp_hwport_row_free(&hwportt->nic[hwport]);
    
    /* update the forwarding cache correspondingly */
    cicp_fwdinfo_hwport_remove_nic(control_plane, hwport);
    
    CICP_LOCK_END;

    /* Get the available hwport state back to what it should in case
     * this hwport re-appears later 
     */
    ci_assert(hwport != CI_HWPORT_ID_BAD);
    oof_hwport_un_available(hwport, 1);
}


/*****************************************************************************
 *          PMTU MIB                                                *
 *****************************************************************************/

int cicp_pmtu_kmib_ctor(cicp_pmtu_kmib_t **p_pmtu_table, int rows_max)
{
  cicp_pmtu_kmib_t *pmtu_table = kmalloc(sizeof(*pmtu_table), GFP_KERNEL);
  if( pmtu_table == NULL )
    return -ENOMEM;
  pmtu_table->entries = vmalloc(rows_max * sizeof(cicp_pmtu_row_t));
  if( pmtu_table->entries == NULL ) {
    kfree(pmtu_table);
    return -ENOMEM;
  }

  memset(pmtu_table->entries, 0, rows_max * sizeof(cicp_pmtu_row_t));
  pmtu_table->rows_max = rows_max;
  pmtu_table->used_rows_max = 0;
  *p_pmtu_table = pmtu_table;
  return 0;
}
void
cicp_pmtu_kmib_dtor(cicp_mibs_kern_t *cp, cicp_pmtu_kmib_t **p_pmtu_table)
{
  cicp_pmtu_kmib_t *pmtu_table = *p_pmtu_table;
  vfree(pmtu_table->entries);
  kfree(pmtu_table);
  *p_pmtu_table = NULL;
}


/*****************************************************************************
 *          oo_timesync state                                                *
 *****************************************************************************/

#ifdef __KERNEL__
/* Onload module parameter:  jiffies between synchronisation times */
extern int timesync_period;


/* Maintains an estimate of cpu frequency.  WARNING!!! You need to use
 * oo_timesync_wait_for_cpu_khz_to_stabilize() before reading this.
 * Note that this can take a long time to stabilize (order of ms).
 * Note that it is probably not a good idea to block on it too early
 * e.g. at module initialisation.
 */
unsigned oo_timesync_cpu_khz;


struct work_struct stabilize_cpu_khz_wi;

/* Internal, do not use!  Use
 *  oo_timesync_wait_for_cpu_khz_to_stabilize() instead.  Signal sent
 *  when equal to 2. */
static int signal_cpu_khz_stabilized = 0;
static struct timer_list timer_node;


DECLARE_COMPLETION(cpu_khz_stabilized_completion);


/* Look at comments above oo_timesync_cpu_khz */
void oo_timesync_wait_for_cpu_khz_to_stabilize(void)
{
  wait_for_completion(&cpu_khz_stabilized_completion);
}


#if BITS_PER_LONG != 64
/* The following division functions are a simplied version of the
 * algorithm found in
 * http://www.hackersdelight.org/HDcode/newCode/divDouble.c.txt */

/* Divide 64 bits dividend and 32 bits divisor and return 32 bits
 * quotient */
static ci_uint32 div_64dd_32ds_32qt(ci_uint64 dividend, ci_uint32 divisor)
{
  ci_uint32 low, high, quotient = 0, c = 32;
  ci_uint64 d = (ci_uint64)divisor << 31;

  low = dividend & 0xffffffff;
  high = dividend >> 32;

  while( dividend > 0xffffffff ) {
    quotient <<= 1;
    if( dividend >= d ) {
      dividend -= d;
      quotient |= 1;
    }
    d >>= 1;
    c--;
  }
  quotient <<= c;
  if( ! dividend )
    return quotient;
  low = dividend;
  return quotient | (low / divisor);
}


/* Divide 64 bits dividend and 32 bits divisor and return 64 bits
 * quotient */
static ci_uint64 div_64dd_32ds_64qt(ci_uint64 dividend, ci_uint32 divisor)
{
  ci_uint32 low, high, high1;

  low = dividend & 0xffffffff;
  high = dividend >> 32;

  if( ! high )
    return low / divisor;

  high1 = high % divisor;
  high /= divisor;
  low = div_64dd_32ds_32qt((ci_uint64)high1 << 32 | low, divisor);

  return (ci_uint64)high << 32 | low;
}
#endif


/* Divide 64 bits dividend and 64 bits divisor and return 64 bits
 * quotient */
static ci_uint64 div_64dd_64ds_64qt(ci_uint64 dividend, ci_uint64 divisor)
{
#if BITS_PER_LONG == 64
  return dividend / divisor;
#else
  ci_uint32 high;
  ci_uint64 quotient;
  int n;

  high = divisor >> 32;
  if( ! high )
    return div_64dd_32ds_64qt(dividend, divisor);

  n = 1 + fls(high);
  quotient = div_64dd_32ds_64qt(dividend >> n, divisor >> n);

  if( quotient != 0 )
    quotient--;
  if( (dividend - quotient * divisor) >= divisor )
    quotient++;
  return quotient;
#endif
}


static void oo_timesync_stabilize_cpu_khz(struct oo_timesync* oo_ts)
{
  static int cpu_khz_warned = 0;

  /* Want at least two data points in oo_ts (oo_timesync_update called
   * twice) before computing cpu_khz */
  if( signal_cpu_khz_stabilized == 0 ) {
    ++signal_cpu_khz_stabilized;
    return;
  }

  /* Current oo_timesync implementation guarantees smoothed_ns <
   * 16*(10**10).  uint64 will give us at least 10**18.  If
   * smoothed_ticks is in same order as smoothed_ns, then we can
   * multiply by 10**6 without dange of overflow.  This is better than
   * dividing first as that can introduce large errors when
   * smoothed_ticks is in the same order as smoothed_ns.  Note: we
   * cannot use doubles in kernel. */
  oo_timesync_cpu_khz = div_64dd_64ds_64qt((ci_uint64)oo_ts->smoothed_ticks *
                                           1000000, oo_ts->smoothed_ns);

  /* Warn if the oo_timesync_cpu_khz computation over or under flowed. */
  if( oo_timesync_cpu_khz < 400000 || oo_timesync_cpu_khz > 10000000 )
    if( ! cpu_khz_warned ) {
      cpu_khz_warned = 1;
      ci_log("WARNING: cpu_khz computed to be %d which may not be correct\n",
             oo_timesync_cpu_khz);
    }

  if( signal_cpu_khz_stabilized == 1 ) {
    complete_all(&cpu_khz_stabilized_completion);
    ++signal_cpu_khz_stabilized;
  }
}


static void stabilize_cpu_khz_wi_fn_cont(unsigned long unused)
{
  oo_timesync_update(&CI_GLOBAL_CPLANE);
  /* If oo_timesync_update called too soon.  Start timer again. */
  if( signal_cpu_khz_stabilized != 2 )
    mod_timer(&timer_node, jiffies + HZ / 2);
}


static void stabilize_cpu_khz_wi_fn(struct work_struct* unused)
{
  /* Need two data points sufficiently (0.5 sec) far apart. */
  oo_timesync_update(&CI_GLOBAL_CPLANE);
  init_timer(&timer_node);
  timer_node.expires = jiffies + HZ / 2;
  timer_node.data = 0;
  timer_node.function = &stabilize_cpu_khz_wi_fn_cont;
  add_timer(&timer_node);
}


static int oo_timesync_ctor(cicp_mibs_kern_t *mibs)
{
  cicp_ul_mibs_t *umibs = &mibs->user;
  struct oo_timesync *oo_ts;
  ci_uint64 now_frc;
  struct timespec now;

  if( umibs->bondinfo_utable != NULL ) {
    /* This shares the same mapping as the bond table for space efficiency */
    oo_ts = (struct oo_timesync*)
      (&(umibs->bondinfo_utable->bond[umibs->bondinfo_utable->rows_max]));

    ci_frc64(&now_frc);
    getnstimeofday(&now);

    oo_ts->clock.tv_sec = now.tv_sec;
    oo_ts->clock.tv_nsec = now.tv_nsec;
    oo_ts->clock_made = now_frc;
    
    /* Set to zero to prevent smoothing when first set */
    oo_ts->smoothed_ticks = 0;
    oo_ts->smoothed_ns = 0;
    oo_ts->generation_count = 0;
    oo_ts->update_jiffies = jiffies - 1;

    umibs->oo_timesync = oo_ts;

    INIT_WORK(&stabilize_cpu_khz_wi, stabilize_cpu_khz_wi_fn);
    queue_work(CI_GLOBAL_WORKQUEUE, &stabilize_cpu_khz_wi);
    return 0;
  } 
  else
    return -ENOMEM;
}


static void oo_timesync_dtor(cicp_mibs_kern_t *mibs)
{
  mibs->user.oo_timesync = NULL;
}

#define TIMESYNC_SMOOTH_SAMPLES 16
#define TIMESYNC_SMOOTH_SAMPLES_MASK 0xf
static ci_uint64 timesync_smooth_tick_samples[TIMESYNC_SMOOTH_SAMPLES];
static ci_uint64 timesync_smooth_ns_samples[TIMESYNC_SMOOTH_SAMPLES];
static int timesync_smooth_i = 0;

void oo_timesync_update(cicp_handle_t* control_plane)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  const cicp_ul_mibs_t *umibs = &mibs->user;
  struct oo_timesync *oo_ts = umibs->oo_timesync;
  ci_uint64 frc, ticks, ns;
  struct timespec ts;
  int reset = 0;

  if( time_after(jiffies, (unsigned long)oo_ts->update_jiffies) ) {
    CICP_LOCK_BEGIN(control_plane);
    /* Re-check incase it was updated while we waited for the lock */
    if( time_after(jiffies, (unsigned long)oo_ts->update_jiffies) ) {
      ci_frc64(&frc);
      getnstimeofday(&ts);

      /* FRC ticks since last update */
      ticks = frc - oo_ts->clock_made;

      /* Nanoseconds since last update */
      if( ts.tv_sec == oo_ts->clock.tv_sec && 
          ts.tv_nsec > oo_ts->clock.tv_nsec ) {
        ns = ts.tv_nsec - oo_ts->clock.tv_nsec;
      }
      else if( ts.tv_sec > oo_ts->clock.tv_sec ) {
        ci_assert(oo_ts->clock.tv_nsec <= 1000000000);
        ns = ts.tv_nsec + (1000000000 - oo_ts->clock.tv_nsec) + 
          (ts.tv_sec - oo_ts->clock.tv_sec - 1) * 1000000000llu;
      } 
      else {
        /* Time has gone backwards. Work around this by not taking a
         * sample, but updating state about time clock made so that
         * next time we update we'll (hopefully) get a better estimate
         */
        LOG_U(ci_log("%s: time has jumped backwards, ignoring sample",
                     __FUNCTION__));
        ++oo_ts->generation_count;
        ci_wmb();
        goto store_time_made;
      }

      /* scale down ns and ticks to avoid overflow */
      while( ns > 10000000000llu ) {
        ns = ns >> 1;
        ticks = ticks >> 1;

        /* We've seen a big gap, which means the old values are
         * probably not much use, so reset the smoothing state
         */
        reset = 1;
      }

      ++oo_ts->generation_count;
      ci_wmb();
      
      if( reset ) {
        oo_ts->smoothed_ticks = 0;
        oo_ts->smoothed_ns = 0;
        for( timesync_smooth_i = 0; 
             timesync_smooth_i < TIMESYNC_SMOOTH_SAMPLES;
             ++timesync_smooth_i ) {
          timesync_smooth_tick_samples[timesync_smooth_i] = 0;
          timesync_smooth_ns_samples[timesync_smooth_i] = 0;
        }
        timesync_smooth_i = 0;
      }
      
      oo_ts->smoothed_ticks += ticks;
      oo_ts->smoothed_ticks -=
        timesync_smooth_tick_samples[timesync_smooth_i];
      timesync_smooth_tick_samples[timesync_smooth_i] = ticks;
      oo_ts->smoothed_ns += ns;
      oo_ts->smoothed_ns -= timesync_smooth_ns_samples[timesync_smooth_i];
      timesync_smooth_ns_samples[timesync_smooth_i] = ns;
      timesync_smooth_i = 
        (timesync_smooth_i + 1) & TIMESYNC_SMOOTH_SAMPLES_MASK;

    store_time_made:
      oo_ts->clock.tv_sec = ts.tv_sec;
      oo_ts->clock.tv_nsec = ts.tv_nsec;
      oo_ts->clock_made = frc;

      oo_ts->update_jiffies = jiffies + msecs_to_jiffies(timesync_period);

      ci_wmb();

      /* Avoid zero for generation count as that is special value for
       * "not yet initialized"
       */
      if( oo_ts->generation_count + 1 == 0 )
        oo_ts->generation_count = 2;
      else
        ++oo_ts->generation_count;
    }
    CICP_LOCK_END;

    oo_timesync_stabilize_cpu_khz(oo_ts);
  }
}
#endif

/*****************************************************************************
 *                                                                           *
 *          Cache of Bonding Information				     *
 *          ============================				     *
 *                                                                           *
 *****************************************************************************/


static int cicp_bondinfo_ctor(cicp_mibs_kern_t *mibs, int rows_max)
{
  cicp_ul_mibs_t *umibs = &mibs->user;
  int rc = 0;
  int i;

  OO_DEBUG_FWD(DPRINTF(CODEID ": constructing user bonding table"););

  ci_assert(NULL != mibs);

  /* Allocate enough for the oo_timesync state as well */
  umibs->bondinfo_utable = (cicp_bondinfo_t *)cicp_shared_alloc
    (sizeof(*umibs->bondinfo_utable) + 
     sizeof(cicp_bond_row_t) * (rows_max - 1) +
     sizeof(*umibs->oo_timesync),
     &umibs->bondinfo_mmap_len, &mibs->bondinfo_shared, &rc);

  mibs->user.bondinfo_utable->rows_max = rows_max;

  if( umibs->bondinfo_utable != NULL ) {
    for( i = 0; i < mibs->user.bondinfo_utable->rows_max; i++ ) {
      cicp_bond_row_t *row = &umibs->bondinfo_utable->bond[i];
      cicp_bond_row_free(row);
    }
  }
  else
    rc = -ENOMEM;

  OO_DEBUG_FWD(DPRINTF(CODEID ": cicp_bondinfo_ctor: DONE (rc %d)", rc););

  return rc;
}


static void cicp_bondinfo_dtor(cicp_mibs_kern_t *mibs)
{
  OO_DEBUG_FWD(DPRINTF(CODEID ": user bond info destructor called"););

  if( mibs->user.bondinfo_utable != NULL ) {
    cicp_shared_free(&mibs->bondinfo_shared);
    mibs->user.bondinfo_utable = NULL;
  }
}

#if CI_CFG_TEAMING
void cicp_bondinfo_dump(const cicp_handle_t *control_plane)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  int i;

  if( mibs->user.bondinfo_utable != NULL ) {
    for( i = 0; i < mibs->user.bondinfo_utable->rows_max; i++ ) {
      cicp_bond_row_t *row = &mibs->user.bondinfo_utable->bond[i];
      if( row->type == CICP_BOND_ROW_TYPE_FREE )
        ;/*OO_DEBUG_BONDING(ci_log("Bond row %d: FREE", i));*/
      else if( row->type == CICP_BOND_ROW_TYPE_MASTER )
        OO_DEBUG_BONDING(ci_log("Bond row %d: MST if %d, next %d, "
                                "mode %d, hash %d, slaves %d, "
                                "actv_slaves %d, actv_hwport %d",
                                i, row->ifid, row->next, 
                                row->master.mode, row->master.hash_policy,
                                row->master.n_slaves,
                                row->master.n_active_slaves,
                                row->master.active_hwport));
      else if( row->type == CICP_BOND_ROW_TYPE_SLAVE )
        OO_DEBUG_BONDING(ci_log("Bond row %d: SLV if %d, next %d, "
                                "hwport %d, flags %d (%s)",
                                i, row->ifid, row->next, row->slave.hwport,
                                row->slave.flags,
                                row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ?
                                "Active" : "Inactive"));
      else
        OO_DEBUG_BONDING(ci_log("Bond row %d: BAD type %d", i, row->type));

    }
  }
}
#endif

/*****************************************************************************
 *                                                                           *
 *          Cache of Forwarding Information				     *
 *          ===============================				     *
 *                                                                           *
 *****************************************************************************/








/* forward reference */
static cicp_llap_rowid_t
cicpos_llap_find(const cicp_llap_kmib_t *llapt, ci_ifid_t ifindex);





    
static int /* rc */ 
cicp_fwdinfo_ctor(cicp_mibs_kern_t *mibs, int rows_max)
{
  cicp_fwdinfo_t *fwdinfot;
  cicp_ul_mibs_t *umibs = &mibs->user;
  int i, rc;
    
  OO_DEBUG_FWD(DPRINTF(CODEID ": constructing user Forwarding "
                       "Information table"););
    
  ci_assert(NULL != mibs);
    
  /* allocate enough space for the correct number of rows */
  umibs->fwdinfo_utable = (cicp_fwdinfo_t *)cicp_shared_alloc
    (sizeof(*umibs->fwdinfo_utable) + (rows_max-1) * sizeof(cicp_fwd_row_t),
     &umibs->fwdinfo_mmap_len, &mibs->fwdinfo_shared, &rc);

  if( umibs->fwdinfo_utable == NULL )
    return -ENOMEM;

  /* Initialize the forwarding information table. */
  fwdinfot = umibs->fwdinfo_utable;
  fwdinfot->version = CI_VERLOCK_INIT_VALID;
  fwdinfot->rows_max = rows_max;

  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    fwdinfot->hwport_to_base_ifindex[i] = CI_IFID_BAD;

  /* mark all entries as free and set seq_num to a valid number */
  for( i = 0; i < fwdinfot->rows_max; ++i ) {
    cicp_fwd_row_t *row = &fwdinfot->path[i];
    /* set info to all 0xEE; for debugging */
    memset(row, 0xEE, sizeof(*row));
    cicp_fwd_row_free(row);
  }
  return 0;
}








ci_inline void 
cicp_fwdinfo_dtor(cicp_mibs_kern_t *mibs)
{   cicp_fwdinfo_t *fwdinfot;
    cicp_ul_mibs_t *umibs = &mibs->user;

    OO_DEBUG_FWD(DPRINTF(CODEID ": user Forwarding Info destructor "
			 "called"););
    fwdinfot = umibs->fwdinfo_utable;

    if (NULL != fwdinfot)
    {	cicp_shared_free(&mibs->fwdinfo_shared);
	umibs->fwdinfo_utable = NULL; /* shared resource gone now */
    }
}





/*! Test memory area to see if it is all set to a given value */
ci_inline int memeq(const void *mem, char val, size_t len)
{   const char *ptr = mem;
    const char *end = ptr+len;
    
    while (ptr < end && *ptr == val)
	ptr++;
    
    return ptr >= end;
}






/*! Re-cache forwarding information based on route information
 *
 * \param llapt           the link layer access point table
 * \param ipift           the IP interface table
 * \param row             the row of the forwarding table to be updated
 * \param ref_read_lock   the read lock for the row
 * \param changed         whether the read lock has already been opened
 *
 * \return                FALSE iff no alteration to the fwd table made
 *
 *  This function assumes that the following fields are correct
 *      dest_ifindex  -- unless scope.tracking_llap is set
 *      destnet_ip
 *      destnet_ipset
 *      first_hop     -- empty if unset
 *      pref_source
 *  and uses them to determine the other fields
 *
 *  This function opens the read lock for writing only if necessary - and
 *  thus ensures that, if no change has occurred, that this action does not
 *  cause unnecessary re-evaluation elsewhere.
 *
 *  Note that if an alteration is made by this function the caller must
 *  ensure that the read lock is closed for writing when the update is
 *  complete.
 *
 *  This function requires the tables to be locked but does not itself lock
 *  them.
 */
static int /* bool */
cicpos_fwd_route_cache(const cicp_llap_kmib_t *llapt,
		       const cicp_ipif_kmib_t *ipift,
		       cicp_fwd_row_t *row,
		       ci_verlock_t *ref_read_lock,
		       int /* bool */ changed)
{
    const cicp_ipif_row_t *ipif_row;
    const cicp_llap_row_t *llap =
	cicp_llap_find_ifid(llapt, row->dest_ifindex);

    /* Fill in mtu, hwport, encap and preferred source mac from ifindex */
    if (NULL != llap)
    {   /* the destination ifindex is in the LLAP table - use details there */ 
	if (((~row->flags & CICP_FLAG_ROUTE_MTU) && row->mtu != llap->mtu) || 
            row->hwport != llap->hwport ||
            row->bond_rowid != llap->bond_rowid || 
	    0 != memcmp(&row->encap, &llap->encapsulation,
			sizeof(row->encap)) ||
	    !CI_MAC_ADDR_EQ(&row->pref_src_mac, &llap->mac))
	{   if (!changed)
	    {   ci_verlock_write_start(ref_read_lock);
		changed = TRUE;
	    }
	    if (~row->flags & CICP_FLAG_ROUTE_MTU)
		row->mtu = llap->mtu;
	    row->hwport = llap->hwport;
	    ci_assert(row->hwport == CI_HWPORT_ID_BAD || row->mtu > 0);
            row->bond_rowid = llap->bond_rowid;
	    memcpy(&row->encap, &llap->encapsulation, sizeof(row->encap));
	    CI_MAC_ADDR_SET(&row->pref_src_mac, &llap->mac);
	}
    } else
    { 	/* the destination ifindex is not in the LLAP table - use defaults */ 
	if ((~row->flags & CICP_FLAG_ROUTE_MTU) ||
            row->hwport != CI_HWPORT_ID_BAD ||
            row->bond_rowid != CICP_BOND_ROW_NEXT_BAD ||
	    memeq(&row->encap, 0, sizeof(row->encap)) ||
	    memeq(&row->pref_src_mac, 0, sizeof(row->pref_src_mac)))
	{   if (!changed)
	    {   ci_verlock_write_start(ref_read_lock);
		changed = TRUE;
	    }
            /* fixme: this should be used in loopback only; loopback has
             * mtu=16436 on linux.  We should get it via netlink instead of
             * hardcode... */
	    if (~row->flags & CICP_FLAG_ROUTE_MTU)
		row->mtu = (16 * 1024) + 20 + 20 + 12;
	    row->hwport = CI_HWPORT_ID_BAD;
            row->bond_rowid = CICP_BOND_ROW_NEXT_BAD;
	    memset(&row->encap, 0, sizeof(row->encap));
	    memset(&row->pref_src_mac, 0, sizeof(row->pref_src_mac));
	}
    }

    /* Fill in subnet details from IP interface first hop uses (which will be
       the destination if the first_hop field is not set)
       This information will be used by the user as a partial cache of the
       entries in the IPIF table.
    */
    ipif_row = cicp_ipif_find_ip(ipift, row->dest_ifindex,
				 CI_IP_ADDR_IS_EMPTY(&row->first_hop)?
				 &row->destnet_ip: &row->first_hop);

    if (NULL != ipif_row)
    {   /* the destination subnet is in the ipif table - use details there */ 
        if (row->net_ipset != ipif_row->net_ipset ||
	    !CI_IP_ADDR_EQ(&row->net_ip, &ipif_row->net_ip) ||
	    !CI_IP_ADDR_EQ(&row->net_bcast, &ipif_row->bcast_ip))
	{   if (!changed)
	    {   ci_verlock_write_start(ref_read_lock);
		changed = TRUE;
	    }
	    row->net_ipset = ipif_row->net_ipset;
	    CI_IP_ADDR_SET(&row->net_ip, &ipif_row->net_ip);
	    CI_IP_ADDR_SET(&row->net_bcast, &ipif_row->bcast_ip);
	}
    }
    else
    {	/* the destination subnet is not in the ipif table - use defaults */ 
	if (row->net_ipset != CI_IP_ADDRSET_BAD ||
	    memeq(&row->net_ip, 0, sizeof(row->net_ip)) ||
	    memeq(&row->net_bcast, 0, sizeof(row->net_bcast)))
	{   if (!changed)
	    {   ci_assert(NULL != ref_read_lock);
		ci_verlock_write_start(ref_read_lock);
		changed = TRUE;
	    }
            row->net_ipset = CI_IP_ADDRSET_BAD;
	    memset(&row->net_ip, 0, sizeof(row->net_ip));
	    memset(&row->net_bcast, 0, sizeof(row->net_bcast));
	}
    }

    eventlog_test();/* note: cicp lock is out at this point */

    return changed;
}






/*! Re-calculate the cached information for every forward info entry
 *
 * \param fwdinfot        the forwarding informaton table
 * \param llapt           the link layer access point table
 * \param ipift           the IP interface table
 * \param only_tracking   update only routes with a tracking scope
 * \param changed         whether the read lock has already been opened
 *
 * \return                FALSE iff no alteration to the fwd table made
 *
 *  This function opens the read lock for writing only if necessary - and
 *  thus ensures that, if no change has occurred, that this action does not
 *  cause unnecessary re-evaluation elsewhere.
 *
 *  Note that if an alteration is made by this function the caller must
 *  ensure that the read lock is closed for writing when the update is
 *  complete.
 */
ci_inline int /* bool */
cicpos_fwd_recache(cicp_fwdinfo_t *fwdinfot,
                   const cicp_llap_kmib_t *llapt,
		   const cicp_ipif_kmib_t *ipift, 
		   int /* bool */changed)
{   cicp_fwd_row_t *row;
    cicp_fwd_rowid_t rowid;

    for (rowid = 0;
	 rowid < fwdinfot->rows_max &&
           cicp_fwd_row_allocated(row = &fwdinfot->path[rowid]);
	 rowid++)
    {   ci_assert(NULL != row);
	if (cicpos_fwd_route_cache(llapt, ipift, row,
				   &fwdinfot->version, changed))
	    changed = TRUE;
    }
    
    return changed;
}


static void
cicp_fwdinfo_update_hwport_to_base_ifindex(cicp_mibs_kern_t *control_plane)
{
  /* Update mapping from hwport to ifindex of the "base" interface.  For
   * interfaces that are bond slaves, the base interface is the bond
   * master.  Otherwise it is just the hardware interface.
   */
  cicp_mibs_kern_t* mibs = control_plane;
  cicp_fwdinfo_t* fwdinfot = mibs->user.fwdinfo_utable;
  const cicp_llap_kmib_t* llapt = mibs->llap_table;
  const cicp_bondinfo_t* bondt = mibs->user.bondinfo_utable;
  const cicp_llap_row_t* row = &llapt->llap[0];
  const cicp_llap_row_t* end_row = row + llapt->rows_max;
  const cicp_bond_row_t* slave;
  ci_hwport_id_t hwport;
  unsigned hwports = 0u;
  ci_ifid_t ifindex;

  for( ; row < end_row; ++row )
    if( cicp_llap_row_allocated(row) && row->up &&
        (row->encapsulation.type & CICP_LLAP_TYPE_SFC) ) {
      /* This LLAP is an SF hardware interface and is up.
       *
       * NB. An up SFC interface can have a bad hwport transiently while it
       * is going down.
       */
      hwport = row->hwport;
      if( (unsigned) hwport < CI_CFG_MAX_REGISTER_INTERFACES ) {
        if( (unsigned) row->bond_rowid < bondt->rows_max ) {
          /* Regular hardware interface, enslaved in bond.  We want the
           * ifindex of the bond.
           */
          slave = &bondt->bond[row->bond_rowid];
          if( (unsigned) slave->slave.master < bondt->rows_max )
            ifindex = bondt->bond[slave->slave.master].ifid;
          else
            /* Don't expect this, but belt and braces... */
            ifindex = CI_IFID_BAD;
        }
        else {
          /* Regular hardware interface, not enslaved. */
          ifindex = row->ifindex;
        }
        if( fwdinfot->hwport_to_base_ifindex[hwport] != ifindex )
          fwdinfot->hwport_to_base_ifindex[hwport] = ifindex;
        hwports |= (1u << hwport);
      }
    }
      
  for( hwport = 0; hwport < CI_CFG_MAX_REGISTER_INTERFACES; ++hwport )
    if( !(hwports & (1u << hwport)) &&
        fwdinfot->hwport_to_base_ifindex[hwport] != CI_IFID_BAD )
      fwdinfot->hwport_to_base_ifindex[hwport] = CI_IFID_BAD;
}


#if CI_CFG_TEAMING
ci_inline int cicpos_bond_refresh_hwport(cicp_mibs_kern_t *mibs, int locked)
{
  cicp_fwdinfo_t *fwdinfot;
  cicp_bond_row_t *bond_row;
  const cicp_llap_row_t *llap_row;
  ci_hwport_id_t hwport;
  int i;

  fwdinfot = mibs->user.fwdinfo_utable;

  for( i = 0; i < mibs->user.bondinfo_utable->rows_max; i++ ) {
    bond_row = &mibs->user.bondinfo_utable->bond[i];
    if( bond_row->type == CICP_BOND_ROW_TYPE_SLAVE ) {
      llap_row = cicp_llap_find_ifid(mibs->llap_table, bond_row->ifid);
      ci_assert_equal(llap_row->bond_rowid, i);
      if( llap_row != NULL ) {
        hwport = llap_row->hwport;
      }
      else {
        OO_DEBUG_BONDING(ci_log("Couldn't find LLAP for slave %d", 
                                bond_row->ifid));
        hwport = CI_HWPORT_ID_BAD;
      }
      if( bond_row->slave.hwport != hwport ) {
        if( ! locked ) {
          ci_verlock_write_start(&fwdinfot->version);
          locked = 1;
        }
        bond_row->slave.hwport = hwport;
      }
    }
  }

  return locked;
}
#endif


/*! This is a very non-specific function that can safely be called to
 *  re-evaluate the whole forwarding table - in case some change has
 *  made a diffference to the way information is retrieved.
 *
 *  Efficiency could, in general, be improved by analysing the change
 *  in more detail and considering only possible alterations for update.
 *
 */
static void
cicp_fwdinfo_something_changed(cicp_mibs_kern_t *control_plane)
{   cicp_mibs_kern_t *mibs = control_plane;
    cicp_fwdinfo_t *fwdinfot;
    const cicp_llap_kmib_t *llapt;
    const cicp_ipif_kmib_t *ipift;
    cicp_mac_mib_t *mact;
    int changed = 0;

    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->user.fwdinfo_utable);
    ci_assert(NULL != mibs->user.mac_utable);
    ci_assert(NULL != mibs->llap_table);
    ci_assert(NULL != mibs->ipif_table);

    fwdinfot = mibs->user.fwdinfo_utable;
    mact = mibs->user.mac_utable;
    llapt = mibs->llap_table;
    ipift = mibs->ipif_table;

    changed = cicpos_fwd_recache(fwdinfot, llapt, ipift, /*changed*/FALSE);
#if CI_CFG_TEAMING
    changed = cicpos_bond_refresh_hwport(mibs, changed);
#endif
    cicp_fwdinfo_update_hwport_to_base_ifindex(control_plane);
    if (changed)
        ci_verlock_write_stop(&fwdinfot->version);

    /* sledgehammer - rather than working out which MAC addresses might
     * need prodding, prod them all.
     *
     * Why do we call this even when nothing has changed?  Because there
     * may have been changes to the bonding table that are not detected
     * here.
     */
    _cicpos_mac_invalidate_all(mact);
}
    



#if CI_CFG_TEAMING
static void
cicp_fwdinfo_llap_set_encapsulation(cicp_mibs_kern_t *control_plane,
			            ci_ifid_t ifindex,
			            const cicp_encap_t *encap)
{   (void)ifindex; /* currently unused */
    (void)encap;   /* currently unused */
    cicp_fwdinfo_something_changed(control_plane);
    /* IS THIS RIGHT? */
}
#endif


static void
cicp_fwdinfo_hwport_add_nic(cicp_mibs_kern_t *control_plane,
		            ci_hwport_id_t hwport, ci_mtu_t max_mtu)
{   (void)hwport;     /* currently unused */
    (void)max_mtu; /* currently unused */
    cicp_fwdinfo_something_changed(control_plane);
    /* IS THIS RIGHT? */
}




static void
cicp_fwdinfo_hwport_remove_nic(cicp_mibs_kern_t *control_plane,
			       ci_hwport_id_t hwport)
{   (void)hwport; /* currently unused */
    cicp_fwdinfo_something_changed(control_plane);
}










/*****************************************************************************
 *                                                                           *
 *          Whole Control Plane						     *
 *          ===================						     *
 *                                                                           *
 *****************************************************************************/







#ifdef __KERNEL__
/* These functions are used in tcp_helper_resource - which is only compiled
   when we are in the kernel (not when we are a user-mode driver)
*/


extern size_t 
cicp_ns_map(cicp_ns_mmap_info_t *ni_shared, cicp_mibs_kern_t *driver_handle)
{   cicp_ul_mibs_t *umibs;

    ci_assert(NULL != ni_shared);
    ci_assert(NULL != driver_handle);
    
    umibs = &driver_handle->user;
    
    /* Initialise info for tables */
    ni_shared->mac_mmap_len     = umibs->mac_mmap_len;
    ni_shared->fwdinfo_mmap_len = umibs->fwdinfo_mmap_len;
    ni_shared->bondinfo_mmap_len = umibs->bondinfo_mmap_len;

    return umibs->mac_mmap_len + 
      umibs->fwdinfo_mmap_len + 
      umibs->bondinfo_mmap_len;
}





/*! Map tables from global driver into per-netif handle */
extern int /* rc */
cicp_mmap(cicp_handle_t *control_plane, unsigned long *ref_bytes,
	  void *opaque, int *ref_map_num, unsigned long *ref_offset)
{   int rc = 0;  
    cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);

    ci_assert(NULL != mibs);
    
    /* map forwarding information table */
    OO_DEBUG_SHM(DPRINTF(CODEID": mmap user FWD info at offset 0x%lx",
                     *ref_offset););
    rc = ci_contig_shmbuf_mmap(&mibs->fwdinfo_shared, /* offset */0,
                               ref_bytes, opaque, ref_map_num, ref_offset);
    /* increments map_num, increments offset by bytes, ignores opaque */
    
    if (rc >= 0)
    {   /* map MAC MIB table */
      OO_DEBUG_SHM(DPRINTF(CODEID": mmap user MAC MIB at offset 0x%lx",
                       *ref_offset););
      rc = ci_contig_shmbuf_mmap(&mibs->mac_shared, /* offset */0,
                                 ref_bytes, opaque, ref_map_num, ref_offset);
    }

    if (rc >= 0) {
      OO_DEBUG_SHM(DPRINTF(CODEID": mmap user bond info at offset 0x%lx",
                           *ref_offset););
      rc = ci_contig_shmbuf_mmap(&mibs->bondinfo_shared, /* offset */0,
                                 ref_bytes, opaque, ref_map_num, ref_offset);
 
    }
    return rc;
}




# ifdef CI_HAVE_OS_NOPAGE
/*! Check whether control plane resources account for the page at the
 *  given offset
 *  - see driver header for documentation
 */
extern int /* bool */
cicp_nopage_found(cicp_ni_t *netif_cplane, void *opaque,
		  unsigned long *ref_offset,
		  unsigned int *out_page_frameno)
{   ci_contig_shmbuf_t *ref_shm;
    unsigned int pages_size;
    cicp_mibs_kern_t *mibs;

    ci_assert(NULL != netif_cplane);
    ci_assert(NULL != netif_cplane->cp_mibs);
    ci_assert(NULL != ref_offset);
    ci_assert(NULL != out_page_frameno);
    
    (void)opaque; /* unused */
    
    mibs = netif_cplane->cp_mibs;
    
    OO_DEBUG_SHM(DPRINTF(CODEID": check nopage mmap at offset 0x%lx",
		     *ref_offset););
	
    ref_shm = &mibs->fwdinfo_shared;
    pages_size = ci_contig_shmbuf_size(ref_shm);
    if (*ref_offset < pages_size)
    {   *out_page_frameno = ci_contig_shmbuf_nopage(ref_shm, *ref_offset);
	return 1 /* true */;
    } else
        *ref_offset -= pages_size;

    ref_shm = &mibs->mac_shared;
    pages_size = ci_contig_shmbuf_size(ref_shm);
    if (*ref_offset < pages_size)
    {   *out_page_frameno = ci_contig_shmbuf_nopage(ref_shm, *ref_offset);
	return 1 /* true */;
    } else
        *ref_offset -= pages_size;

    ref_shm = &mibs->bondinfo_shared;
    pages_size = ci_contig_shmbuf_size(ref_shm);
    if (*ref_offset < pages_size)
    {   *out_page_frameno = ci_contig_shmbuf_nopage(ref_shm, *ref_offset);
	return 1 /* true */;
    } else
        *ref_offset -= pages_size;

    return 0 /* false */;
}
# endif	/*CI_HAVE_OS_NOPAGE*/



#endif /* __KERNEL__ */





/*! Create and initialize control-plane data structures */
extern int /* rc */
cicp_ctor(cicp_mibs_kern_t *cp, unsigned max_macs, 
          unsigned max_layer2_interfaces, unsigned max_routes)
{
  int mac_rows_ln2 = ci_log2_ge(max_macs, 5);
  int rc = 0;
  const char *where = "";
  
  OO_DEBUG_VERB(DPRINTF(CODEID": Constructing control plane at %p", cp););
  ci_assert(NULL != cp);
  
  /* initialise the cplane stats */
  memset(&cp->stat, 0, sizeof(cp->stat));
    
  /* create control plane lock */
  cicp_lock_ctor(cp);
   
  /* Construct user-visible state in Control Plane */
    
  {   /* Initialize everything to give citp_dtor() something to go on */
	
    int rc_umac     = cicp_mac_mib_ctor(cp, mac_rows_ln2);
    int rc_ufwdinfo = cicp_fwdinfo_ctor(cp, max_routes);
    int rc_ubondinfo = cicp_bondinfo_ctor(cp, max_layer2_interfaces);
    int rc_timesync = oo_timesync_ctor(cp);
    int rc_mac      = cicp_mac_kmib_ctor(&cp->mac_table, mac_rows_ln2);
    int rc_route    = cicp_route_kmib_ctor(&cp->route_table, max_routes);
    int rc_ipif     = cicp_ipif_kmib_ctor(&cp->ipif_table, max_routes);
    int rc_llap     = cicp_llap_kmib_ctor(&cp->llap_table, 
                                          max_layer2_interfaces);
    int rc_hwport   = cicp_hwport_kmib_ctor(&cp->hwport_table);
    int rc_pmtu     = cicp_pmtu_kmib_ctor(&cp->pmtu_table, max_routes);
    int rc_sync     = cicpos_ctor(cp);
    int rc_prot     = cicppl_ctor(cp);

    if (0 != rc_umac) {
      rc = rc_umac;
      where = "user-mode MAC MIB";
    } else if (0 != rc_ufwdinfo) {
      rc = rc_ufwdinfo;
      where = "user-mode forwarding table";
    } else if (0 != rc_ubondinfo) {
      rc = rc_ubondinfo;
      where = "user-mode bonding table";
    } else if (0 != rc_timesync) {
      rc = rc_timesync;
      where = "oo timesync state";
    } else if (0 != rc_mac) {
      rc = rc_mac;
      where = "kernel-mode MAC MIB";
    } else if (0 != rc_route) {
      rc = rc_route;
      where = "kernel-mode Route MIB";
    } else if (0 != rc_ipif) {
      rc = rc_ipif;
      where = "kernel-mode IP Interface MIB";
    } else if (0 != rc_llap) {
      rc = rc_llap;
      where = "kernel-mode Link Access Point MIB";
    } else if (0 != rc_hwport) {
      rc = rc_hwport;
      where = "kernel-mode Hardware Port MIB";
    } else if (0 != rc_pmtu) {
      rc = rc_pmtu;
      where = "kernel-mode PMTU MIB";
    } else if (0 != rc_sync) {
      rc = rc_sync;
      where = "O/S Synchronization module";
    } else if (0 != rc_prot) {
      rc = rc_prot;
      where = "O/S Protocol module";
    }
  }

  if( 0 != rc ) {
    ci_log(CODEID ": ERROR - initializing %s, rc %d", where, rc);
    /* warning: found the lock with bad magic here(!?) */
    cicp_dtor(cp);
  }

  ci_assert_le(rc, 0);
  return rc;
}




/*! Indicate that new (NIC) hardware is now available for use */
extern void
cicp_hw_registered(cicp_handle_t *control_plane)
{   /* forward indication to O/S synchronization code */
    cicpos_hw_registered(control_plane);
}
	






/*! Destroy control-plane data structures */
extern void
cicp_dtor(cicp_mibs_kern_t *cp)
{   OO_DEBUG_VERB(DPRINTF(CODEID": destroying control plane at %p", cp););
	
    /* wind down any O/S synchronization state */
    cicpos_dtor(cp);
	
    /* wind down any O/S protocol state */
    cicppl_dtor(cp);
	
    /* destroy kernel-mode information */
    cicp_pmtu_kmib_dtor(cp, &cp->pmtu_table);
    cicp_mac_kmib_dtor(cp, &cp->mac_table, cp->user.mac_utable);
    cicp_route_kmib_dtor(&cp->route_table);
    cicp_ipif_kmib_dtor(&cp->ipif_table);
    cicp_llap_kmib_dtor(&cp->llap_table);
    cicp_hwport_kmib_dtor(&cp->hwport_table);

    /* destroy user-mode information */
    cicp_mac_mib_dtor(cp); /* NB: table used in dtor of kmib */
    cicp_fwdinfo_dtor(cp);
    oo_timesync_dtor(cp);
    cicp_bondinfo_dtor(cp);

    /* no more locking from now on */
    cicp_lock_dtor(cp);

    /* ensure the timer is gone */
    signal_cpu_khz_stabilized = 2;
    flush_workqueue(CI_GLOBAL_WORKQUEUE);
    del_timer(&timer_node);
    flush_workqueue(CI_GLOBAL_WORKQUEUE);
}











/*****************************************************************************
 *****************************************************************************
 *									     *
 *          CM - Cacheable MIBs						     *
 *          ===================						     *
 *									     *
 *****************************************************************************
 *****************************************************************************/




/*****************************************************************************
 *                                                                           *
 *          Address Resolution MIB					     *
 *          ======================					     *
 *                                                                           *
 *****************************************************************************/













/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *  - see driver header for documentation
 */
extern int /* rc */
cicpos_mac_set(cicp_handle_t *control_plane, 
	       cicp_mib_verinfo_t *out_rowinfo,
               ci_ifid_t ifindex,
               ci_ip_addr_net_t nexthop_ip,
               const ci_mac_addr_t *mac,
	       const cicpos_mac_row_sync_t *os)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    
    if (NULL != out_rowinfo)
    {   /* default value taken if no update takes place */
	out_rowinfo->row_index = 0;
	out_rowinfo->row_version = CI_VERLOCK_BAD;
    }

    if (NULL == control_plane)
    {   ci_log(CODEID": ignored attempt to set IP-MAC mapping "
	       "before allocation");
        return EINVAL;
    } else if (NULL == mibs->mac_table ||
             NULL == mibs->user.mac_utable ||
	     NULL == mibs->llap_table)
    {   ci_log(CODEID": ignored attempt to set IP-MAC mapping "
	       "before initialization");
	return ENOMEM;
    } else
    {
	DEBUGMIBMAC(
	    typedef enum {
		do_nothing, do_update, do_set, do_reject, do_fail
	    } debug_cases_t;
	    debug_cases_t what = do_nothing;
	    int kept = /*false*/0;
	    int row_rc = 0;
	)
	cicp_mac_mib_t *mact = mibs->user.mac_utable;
	cicp_mac_kmib_t *kmact = mibs->mac_table;
	cicp_llap_kmib_t *llapt = mibs->llap_table;
	cicp_mac_rowid_t rowid = CICP_MAC_ROWID_BAD;
	ci_mac_addr_t *mac_clash = NULL; /* warning when set */

	CICP_LOCK_BEGIN(control_plane)

            cicp_llap_row_t *llap = cicp_llap_find_upnicifid(control_plane, 
                                                             llapt, ifindex);
	    ci_verlock_value_t version; /* ignored */
	    cicp_mac_row_t *row = NULL;

	    if (NULL != llap) /* the ifindex LLAP is up and has a NIC */
	    {
		rowid = cicpos_mac_find_ip(mact, ifindex, nexthop_ip,
					   &version);
		if (CICP_MAC_ROWID_BAD != rowid)
		{   /* update an existing entry */
		    cicp_mac_kernrow_t *krow = &kmact->entry[rowid];
		    int /* bool */ new_mac;
		    int /* bool */ ignore_clash;
		    int orig_row_rc;

		    row = &mact->ipmac[rowid];
		    orig_row_rc = row->rc; /* this is updated below */
		    new_mac = !CI_MAC_ADDR_EQ(&row->mac_addr, mac);

		    if (cicpos_mac_kmib_row_update(control_plane,
						   &krow->sync, row, os, mac,
						   new_mac, &ignore_clash))
		    {   /* entry with same IP and ifindex needs updating */
			DEBUGMIBMAC(what=do_update; row_rc=row->rc; kept=1;);
			CI_VERLOCK_WRITE_BEGIN(row->version)
			    /* MAC addresses only valid if orig_row_rc is 0 */
			    if (0 == orig_row_rc && 0 == row->rc &&
				!ignore_clash)
			    {   mac_clash = (ci_mac_addr_t *)
				    ci_atomic_alloc(sizeof(ci_mac_addr_t));
				if (NULL != mac_clash)
				{   CI_MAC_ADDR_SET(mac_clash,
						    &row->mac_addr);
				}
			    }
			    CI_MAC_ADDR_SET(&row->mac_addr, mac);
			CI_VERLOCK_WRITE_END(row->version)
		    }
		    DEBUGMIBMAC(else what = do_reject;)
		    
		} else
		{   /* make a new entry for the IP address */
		    rowid = _cicp_mac_find_ipunaloc(mact, ifindex, nexthop_ip);
		    if (CICP_MAC_ROWID_BAD != rowid)
		    {   /* fill in a new entry */
			cicp_mac_kernrow_t *krow = &kmact->entry[rowid];
		        int /* bool */ ignore_clash;
			int /*bool*/ keep;
			/* now we have a mac table entry should we keep it? */

			DEBUGMIBMAC(what = do_set;);
			row = &mact->ipmac[rowid];
			/* unallocated state means read is already locked */
			row->ifindex = ifindex;
			if (os != NULL && os->state & CICPOS_IPMAC_STALE)
			    row->need_update = CICP_MAC_ROW_NEED_UPDATE_STALE;
			else
			    row->need_update = 0;
			CI_MAC_ADDR_SET(&row->mac_addr, mac);
			CI_IP_ADDR_SET(&row->ip_addr, &nexthop_ip);
			cicpos_mac_kmib_row_ctor(&krow->sync, os);
			keep = cicpos_mac_kmib_row_update(control_plane,
							  &krow->sync,
							  row, os, mac,
							  /*newcontent*/TRUE,
							  &ignore_clash);
			DEBUGMIBMAC(row_rc = row->rc; kept=keep;);
			cicp_mac_row_allocate(row);

			if (!keep)
			{    /* NB: the brief state during which this entry was
				    allocated might be seen by the user but
				    (because of the write lock) it will never 
				    be seen by this function
			     */
			    ci_assert_equal(rowid,
					    _cicp_mac_find_ipaloc(mact,
								  ifindex,
								  nexthop_ip));
			    /* we should find the same hash for
			       the same IP addr */

			    cicp_mac_row_free(row);
			    DEBUGMIBMAC(what = do_reject;);
			}
		    }
		    DEBUGMIBMAC(else what = do_fail;)
		    /* else
		       We couldn't get a new entry to put this information in 
		       so we don't record it
		    */
		}
	    }

	    if (NULL != out_rowinfo && NULL != row)
	    {   out_rowinfo->row_index = rowid;
		out_rowinfo->row_version = row->version;
	    }

	CICP_LOCK_END


	DO(
	    if (NULL != mac_clash)
	    {   if (os == NULL? CI_MAC_ADDR_IS_EMPTY(mac):
		                CI_MAC_ADDR_IS_EMPTY(mac_clash))
		{   ci_log(CODEID": O/S %s MAC address for "
			   CI_IP_PRINTF_FORMAT " sync:",
			   os == NULL? "protocol setting empty":
				       "set empty duplicate",
			   CI_IP_PRINTF_ARGS(&nexthop_ip));
		    if (NULL != os)
			ci_hex_dump(ci_log_fn, os, sizeof(*os), 0);
		} else
		if (CI_MAC_ADDR_IS_EMPTY(mac))
		    ci_log(CODEID": %s is setting an empty MAC address",
			   os == NULL? "protocol": "O/S");
	    }
	)

	if (NULL != mac_clash)
	{   /* Prefast: the windows static code analysis tool does not like the
	                specific use of "CI_MAC_PRINTF_ARGS(mac_clash)" here.
			(it thinks that it will be indexed as if an integer
			 array) - it may simply be wrong.
	    */
	    DO(ci_log(CODEID": duplicate claim of IP address "
			 CI_IP_PRINTF_FORMAT" by "CI_MAC_PRINTF_FORMAT" and "
			 CI_MAC_PRINTF_FORMAT" on LLAP "CI_IFID_PRINTF_FORMAT
		         " from %s",
			 CI_IP_PRINTF_ARGS(&nexthop_ip),
			 CI_MAC_PRINTF_ARGS(mac),
			 CI_MAC_PRINTF_ARGS(mac_clash),
			 ifindex,
		         os == NULL? "network": "O/S"
		      ));
	    LOGEVENT_CP_MAC_DUPLICATE(ifindex, &nexthop_ip, mac, mac_clash);
			      
	    if (mac != (const ci_mac_addr_t *)mac_clash)
		ci_free(mac_clash);
	}

	DEBUGMIBMAC(
	    switch (what)
	    {   case do_nothing:
		    DEBUGMIBMACSET(
			DPRINTF(CODEID": mac set ifid "
			        CI_IFID_PRINTF_FORMAT" "CI_IP_PRINTF_FORMAT
				" to "CI_MAC_PRINTF_FORMAT
				" by %s ignored (not ours)",
			        ifindex, CI_IP_PRINTF_ARGS(&nexthop_ip),
			        CI_MAC_PRINTF_ARGS(mac), 
			        os == NULL? "protocol": "O/S");
		    );
		    break;
		case do_reject:
		    DEBUGMIBMACSET(
			DPRINTF(CODEID": mac set [%x] ifid "
			        CI_IFID_PRINTF_FORMAT" "CI_IP_PRINTF_FORMAT
				" to "CI_MAC_PRINTF_FORMAT
 			        " by %s update unnecessary - still v%u",
			        rowid, ifindex, CI_IP_PRINTF_ARGS(&nexthop_ip),
			        CI_MAC_PRINTF_ARGS(mac), 
			        os == NULL? "protocol": "O/S",
		                NULL==out_rowinfo? 0:
				                   out_rowinfo->row_version);
		    );
		    break;
		case do_update:
		case do_set:
		    DPRINTF(CODEID": mac %s [%x] ifid "CI_IFID_PRINTF_FORMAT" "
			    CI_IP_PRINTF_FORMAT" to "CI_MAC_PRINTF_FORMAT
			    " rc %d by %s%s",
			    what==do_update? "update": "set",
			    rowid, ifindex, CI_IP_PRINTF_ARGS(&nexthop_ip),
			    CI_MAC_PRINTF_ARGS(mac), row_rc,
			    os == NULL? "protocol": "O/S",
			    kept? "": " (ignored)");
		    break;
		case do_fail:
		    ci_log(CODEID": no free MAC table entries");
		    break;
	    }
	)
    }

    return 0;
}





/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *  (with no O/S sychronizaton information)
 *  - see driver header for documentation
 */
extern int /*rc*/ 
cicp_mac_set(cicp_handle_t *control_plane, 
	     cicp_mib_verinfo_t *out_rowinfo,
	     ci_ifid_t ifindex,
	     ci_ip_addr_net_t nexthop_ip,
	     const ci_mac_addr_t *mac)
{   return cicpos_mac_set(control_plane, out_rowinfo, ifindex, nexthop_ip,
			  mac, NULL);
}





    
/*! Enter a new IP-MAC address mapping into the Address Resolution MIB
 *  - see driver header for documentation
 */
extern int /*rc*/ 
cicp_mac_set_rc(cicp_handle_t *control_plane, 
                ci_ifid_t ifindex, ci_ip_addr_net_t nexthop_ip,
		ci_uerr_t os_rc)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_mac_mib_t *mact;
    
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->user.mac_utable);

    mact = mibs->user.mac_utable;

    if (os_rc != (ci_uint16)os_rc)
	return -EINVAL;
    else
    {	CICP_LOCK_BEGIN(control_plane)
	    ci_verlock_value_t version; /* ignored */
	    cicp_mac_rowid_t rowid = cicpos_mac_find_ip(mact, ifindex,
							nexthop_ip, &version);

	    if (CICP_MAC_ROWID_BAD != rowid)
	    {   cicp_mac_row_t *row = &mact->ipmac[rowid];

		if (row->rc != os_rc)
		{   CI_VERLOCK_WRITE_BEGIN(row->version)
			row->rc = (ci_uint16)os_rc;
		    CI_VERLOCK_WRITE_END(row->version)
		}
	    }

	    /* TODO: give the synchronization code a chance to update itself
		     depending on the return code set
	    */
	CICP_LOCK_END
	return 0;
    }
}







/*! Defer transmission of packet until forwarding information is re-established
 *  - system call implementation: see user header for documentation
 */
extern int /* bool */
cicp_user_defer_send(ci_netif *netif, cicpos_retrieve_rc_t retrieve_rc,
		     ci_uerr_t *ref_os_rc, oo_pkt_p pkt_id,
                     ci_ifid_t ifindex)
{
  /* TODO: Perform any service request implied by retrieve_rc:
   *    
   * Split cicp_user_service to return kernel requests and then to
   * call cicpos_mac_reconfirm on the result
   *
   * Use the first half of this function prior to this call and pass
   * the kernel requests and the version handle in to
   * cicp_user_defer_send then call cicpos_mac_reconfirm here
   */

  switch (CICPOS_RETRRC_RC(retrieve_rc)) {
  case retrrc_success:
    return FALSE;
	      
  case retrrc_nomac:
    /* The ARP table didn't have an appropriate entry readily
     * available. We must queue the packet until the ARP protocol
     * either resolves the address or it times out.
     */
    IGNORE(ci_log(CODEID": defer this send, pending ARP"););
    return cicppl_mac_defer_send(netif, ref_os_rc,
                                 oo_tx_ip_hdr(PKT(netif,pkt_id))->ip_daddr_be32,
                                 pkt_id, ifindex);

  case retrrc_noroute:
    CI_IPV4_STATS_INC_OUT_NO_ROUTES(netif);
    *ref_os_rc = -ENETUNREACH;
    return FALSE;

  case retrrc_alienroute:
    /* if the route isn't going out of a L5 i/f, then don't send it */
    CITP_STATS_NETIF_INC(netif, tx_discard_alien_route);
    *ref_os_rc = -ENETUNREACH;
    return FALSE;

  default:
    ci_log(CODEID ": unknown code returned by cicp_user_retrieve(), "
           "retrieve_rc=0x%x", retrieve_rc);
    *ref_os_rc = -EHOSTUNREACH;
    return FALSE;
  }
}








/*! Update STALE entry in ARP table.
 *  Do and ARP request or just confirm the entry.
 *  - see user-mode header for documentation
 *  Called to service a SYSCALL
 */
extern void
cicp_mac_update(ci_netif *ni, cicp_mac_verinfo_t *ver, ci_ip_addr_t ip,
                const ci_mac_addr_t *mac, int confirm)
{
  cicp_mac_mib_t *mact;
  cicp_mac_row_t *row;
  ci_ip_addr_t dst = 0;
  ci_ifid_t ifindex = 0;
  int send_arp = 0;

  mact = CICP_MIBS(CICP_HANDLE(ni))->user.mac_utable;
  if( ver->row_index >= cicp_mac_mib_rows(mact) )
    return;
  row = &mact->ipmac[ver->row_index];
  CICP_LOCK_BEGIN(CICP_HANDLE(ni));
  if( CI_MAC_ADDR_EQ(&row->mac_addr, mac) && row->ip_addr == ip && 
      row->need_update ) {
    /* do not update row version: this socket have already removed
     * CI_IP_CACHE_NEED_UPDATE flag from its ipcache, and there is no need
     * to update the arp entry.
     * TODO: if multiple sockets are using this ARP, version update will
     * safe a few syscalls.  Do we need it? */
    row->need_update = 0;
    send_arp = 1;
    dst = row->ip_addr;
    ifindex = row->ifindex;
  }
  CICP_LOCK_END

  if( send_arp ) {
    DEBUGMIBMAC(DPRINTF("%s: send ARP to %s", __func__, ip_addr_str(dst)));
    cicpos_arp_stale_update(dst, ifindex, confirm);
  }
}







/*! Return the access point an incomming packet probably arrived on
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicp_user_pkt_dest_ifid(ci_netif *netif, int pkt_id, ci_ifid_t *out_ifindex)
{
    return -EOPNOTSUPP; /* TODO: not implemented yet */
}
















/*****************************************************************************
 *****************************************************************************
 *									     *
 *          SYN - Cacheable MIB Synchronization				     *
 *          ===================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/





/* This section will have common code used by all syncrhonization modules
 * currently all the code is in just the Linux module, but it will be moved
 * back here if and when it is found to be common
 */






/*****************************************************************************
 *                                                                           *
 *          Cache of Forwarding Information				     *
 *          ===============================				     *
 *                                                                           *
 *****************************************************************************/



















/*! Mirror update to link layer access point table in forwarding table
 *
 * \param control_plane   control plane handle
 * \param ifindex         O/S index of this layer 2 interface
 * \param up              if true, this interface is up 
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param hwport          (if relevant) hardware port & NIC of interface
 * \param ref_oldmac   	  previous MAC address of access point
 * \param ref_newmac   	  new MAC address of access point
 * \param ref_encap       encapsulation used on this i/f
 *
 * \return                error code, 0 iff successful
 *
 * The \c ref_oldmac parameter is NULL if there was no previous value
 * The \c ref_newmac parameter is NULL if there is no new value (deleted)
 *
 * Several implementation options can be considered:
 *
 *  - Check ifindex against forwarding destination ifindexes for changes to the
 *    destination mtu, hwport and (up) availability, encapsulation;
 *    +
 *    Check old mac against forwarding table source mac address and change if
 *    necessary
 *
 *  - Re-evaluate affecting routing entries from scratch
 *
 *  - Re-evaluation all routing table entries
 *
 */
ci_inline int /* rc */
cicpos_fwdinfo_llap_import(cicp_handle_t *control_plane, 
			   ci_ifid_t ifindex,
			   ci_uint8 /* bool */ up,
			   ci_mtu_t mtu,
			   ci_mac_addr_t *ref_oldmac,
			   ci_mac_addr_t *ref_newmac)
{
    (void)ifindex;     /* currently unused */
    (void)up;          /* currently unused */
    (void)mtu;         /* currently unused */
    (void)ref_oldmac;  /* currently unused */
    (void)ref_newmac;  /* currently unused */
    cicp_fwdinfo_something_changed(control_plane);
    return 0;
}









/*! Mirror update to IP interface table in forwarding table
 *
 * \param control_plane     control plane handle
 * \param ref_old_bcast_ip  original subnet broadcast address on IP interface
 * \param ref_new_bcast_ip  updated broadcast home address on IP interface
 *
 * \return                error code, 0 iff successful
 *
 * The \c ref_old_net_ip field is NULL if there was no previous value
 * The \c ref_new_net_ip field is NULL if there was no new value (delete)
 * 
 * A change in the broadcast address can mean that existing destinations have a
 * different address type - becomming, or ceasing to be, broadcast addresses.
 *
 * Several implementation options can be considered:
 *
 *  - Check old IP interface broadcast addresses against \c old_net_ip and 
 *    change them to the new one if necessary.
 *
 *  - Re-evaluate affecting routing entries from scratch
 *
 *  - Re-evaluation all routing table entries
 */
ci_inline int /* rc */
cicpos_fwdinfo_ipif_import(cicp_handle_t *control_plane, 
			   ci_ip_addr_net_t *ref_old_net_bcast,
			   ci_ip_addr_net_t *ref_new_net_bcast)
{   (void)ref_old_net_bcast;  /* currently unused */
    (void)ref_new_net_bcast;  /* currently unused */
    cicp_fwdinfo_something_changed(control_plane);
    return 0;
}





/*! Mirror update to hardware port table in forwarding table 
 *
 * Several implementation options can be considered:
 *
 *  - Check old forwarding hardware ports to see if they are via the given
 *    nic and readjust their MTU in the light of the NICs new maximum.
 *
 *  - Re-evaluate affecting routing entries from scratch
 *
 *  - Re-evaluation all routing table entries
 */
ci_inline void
cicpos_fwdinfo_hwport_update(cicp_handle_t *control_plane, 
                             ci_hwport_id_t hwport,
			     ci_mtu_t max_mtu)
{   cicp_fwdinfo_something_changed(control_plane);
}






/*! Mirror update to route table in forwarding table 
 *
 * If ref_next_hop_ip or ref_pref_source are NULL the "import" is really
 * a deletion of the route
 * 
 * Several implementation options can be considered:
 *
 *  - Update all MAC adddreses which had MAC addresses corresponding to
 *    the next hop address for the old or new route's destination 
 *
 *  - Re-evaluate all MAC addresses mentioned in the old routing table and
 *    in the new
 *
 *  - Re-evaluation all MAC table entries
 */
ci_inline int /* rc */
cicpos_fwdinfo_route_import(cicp_handle_t *control_plane,
			    ci_ip_addrset_t dest_ipset,
			    ci_ip_addr_t dest_ip,
			    ci_ip_addr_t *ref_next_hop_ip,
			    ci_ip_addr_t *ref_pref_source)
{   /* The route table is the forwarding table - the forwarding table is
       up-to-date already - so we don't need to recached it
       
       but we do have to do something about the users who ought to notice
       the effect of the altered route on their destination.
       
       We could try to see which MAC addresses might have been affected by
       looking at those that might have been interested in the old route and
       those that will be interested in the new route - but rather than that
       we use a sledgehammer - simply invalidating all MAC addresses!!
    */
    cicp_mibs_kern_t *mibs = control_plane;
    cicp_mac_mib_t *mact = mibs->user.mac_utable;
    (void)ref_next_hop_ip; /* unused */
    (void)ref_pref_source; /* unused */

    _cicpos_mac_invalidate_all(mact);
    return 0;
}



    






/*****************************************************************************
 *                                                                           *
 *          Address Resolution MIB					     *
 *          ======================					     *
 *                                                                           *
 *****************************************************************************/













/*! Claim the "synchronizer" role with respect to the MAC table
 *  - see driver header for documentation
 */
extern int /* bool */ cicpos_mact_open(cicp_handle_t *control_plane)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_mac_kmib_t *kmact;
    int /* bool */ success;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->mac_table);

    kmact = mibs->mac_table;

    CICP_LOCK_BEGIN(control_plane)
        if (kmact->sync_claimed)
	    success = FALSE;
	else
	{   kmact->sync_claimed = 1;
	    success = TRUE;
	}
    CICP_LOCK_END

    return success;
}





/*! Release the "synchronizer" role with respect to the MAC table
 *  - see driver header for documentation
 */
extern void cicpos_mact_close(cicp_handle_t *control_plane)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_mac_kmib_t *kmact;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->mac_table);

    kmact = mibs->mac_table;
    kmact->sync_claimed = FALSE;
}






/*! Indicate that the numbered row has been seen during synchronization
 *  - see driver header for documentation
 */
extern void
cicpos_mac_row_seen(cicp_handle_t *control_plane,cicp_mib_verinfo_t *rowinfo)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_mac_mib_t *mact;
    cicp_mac_kmib_t *kmact;
    unsigned rowid;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->mac_table);
    ci_assert(NULL != mibs->user.mac_utable);
    ci_assert(NULL != rowinfo);

    mact = mibs->user.mac_utable;
    kmact = mibs->mac_table;
    rowid = rowinfo->row_index;

    if (rowid < (unsigned) cicp_mac_mib_rows(mact))
    {   CICP_LOCK_BEGIN(control_plane)

	    cicp_mac_row_t *row = &mact->ipmac[rowid];

	    /* mark it as read, only if we're talking about the
	       current version */
	    if (row->version == rowinfo->row_version)
		cicpos_mac_row_synced(&kmact->entry[rowid].sync);

	CICP_LOCK_END
	IGNORE(ci_log(CODEID": MAC [%x] v%u seen",
		      rowinfo->row_index, rowinfo->row_version);)
    } else
	ci_log(CODEID": seen version information row %u incorrect",
	       rowinfo->row_index);
}








/*! Delete all address resolution entries other than those in the provided set
 *  - see driver header for documentation
 */
extern void
cicpos_mac_purge_unseen(cicp_handle_t *control_plane)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_mac_mib_t *mact;
    cicp_mac_kmib_t *kmact;
    cicp_mac_rowid_t rowid;
    DEBUGMIBMAC(int purgecount = 0; ci_ip_addr_t lastip = 0;)
    
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->mac_table);
    ci_assert(NULL != mibs->user.mac_utable);

    mact = mibs->user.mac_utable;
    kmact = mibs->mac_table;

    CICP_LOCK_BEGIN(control_plane)
    
	for (rowid = 0; rowid < (int) cicp_mac_mib_rows(mact); rowid++)
	{   cicp_mac_kernrow_t *krow = &kmact->entry[rowid];
	    cicp_mac_row_t *row = &mact->ipmac[rowid];
	    
	    if (cicp_mac_row_allocated(row) &&
		!cicpos_mac_row_recent(&krow->sync))
	    {   cicp_mac_rowid_t hashedrowid;

		/* The following function decrements usecounts on the rehash
		   path to the given IP-MAC entry, if the entry were not
		   allocated it would decrement a usecount that it should not!
		*/
		hashedrowid = _cicp_mac_find_ipaloc(mact, row->ifindex,
						    row->ip_addr);

		ci_assert_equal(rowid, hashedrowid);
                /* we should find ourselves! */

		if (CICP_MAC_ROWID_BAD != hashedrowid)
		{   DEBUGMIBMAC(CI_IP_ADDR_SET(&lastip, &row->ip_addr););
		    cicp_mac_row_free(row);
		    /* w.r.t. the read lock this is the same as starting
		       to write..
		    */
		    DEBUGMIBMAC(purgecount++;)
		}
	    }
	}
    
    CICP_LOCK_END

    DEBUGMIBMAC(
	if (purgecount > 0)
        {   DPRINTF(CODEID": purged %d MAC table entries, last for "
		    CI_IP_PRINTF_FORMAT,
		    purgecount, CI_IP_PRINTF_ARGS(&lastip));
	}
    )
}





/*! Mark all existing IP-MAC mappings as invalid 
 *  - see driver header for documentation
 */
extern void
_cicpos_mac_invalidate_all(cicp_mac_mib_t *mact)
{   cicp_mac_rowid_t rowid;

    for (rowid = CICP_MAC_MIB_ROW_MOSTLY_VALID;
         rowid < (int) cicp_mac_mib_rows(mact); rowid++)
    {   cicp_mac_row_t *row = &mact->ipmac[rowid];

	if (cicp_mac_row_allocated(row))
	    ci_verlock_invalidate(&row->version);
    }
}















/*****************************************************************************
 *                                                                           *
 *          Routing MIB							     *
 *          ===========							     *
 *                                                                           *
 *****************************************************************************/














/*! Sort tables according to preifx length
 *
 *  This sort is undertaken in place with a bubble sort(!), heap sort would
 *  be much more appropriate for a larger routing table.
 *
 *  The table must first be compressed (with all entries at the beginning
 *  of the table) before calling this function.
 *
 *  Note this function opens a write version lock only if a new change is
 *  necessary.  That way updates that do nothing will not result in the
 *  existing table becomming out of date.
 */
static int /* bool */ 
cicp_route_sort(cicp_fwdinfo_t *routet,
		cicp_route_kmib_t *kroutet,
		int /* bool */ changed)
{   cicp_fwd_row_t *row;
    cicp_fwd_rowid_t rowid;
    
    for (rowid = 0;
	 rowid < kroutet->rows_max-1 &&
           cicp_fwd_row_allocated(row = &routet->path[rowid]);
	 rowid++)
    {   cicp_route_rowid_t bestid = rowid;
	cicp_fwd_row_t *best = row;
	cicp_route_rowid_t otherid;
	cicp_fwd_row_t *other;
	
	for (otherid = rowid+1;
	     otherid < kroutet->rows_max &&
               cicp_fwd_row_allocated(other = &routet->path[otherid]);
	     otherid++)
        {   ci_ip_mask_t othermask;
	    ci_ip_mask_t bestmask;

	    /* compare this with the best */
	    CI_IP_SET_MASK(&othermask, other->destnet_ipset);
	    CI_IP_SET_MASK(&bestmask,  best->destnet_ipset);

	    /* routes which are most specific (i.e. possibly included by
	       other routes) must come first in the table */
	    if (!CI_IP_ADDR_EQ(&bestmask, &othermask) &&
		CI_IP_MASK_INCLUDES(&bestmask, &othermask))
	    {   /* assume masks are proper subsets */
		ci_assert(!CI_IP_MASK_INCLUDES(&othermask, &bestmask));
		
		bestid = otherid;
		best = other;
	    }
	}
	if (bestid != rowid)
	{   /* swap these two rows over */
	    cicp_route_kernrow_t ktmprow;
	    cicp_fwd_row_t       tmprow;

	    if (!changed)
	    {   ci_verlock_write_start(&routet->version);
		changed = TRUE;
	    }
	    
	    /* could do this more efficiently with a memswap(m1,m2,sz) fn */
	    memcpy(&tmprow, &routet->path[rowid], sizeof(tmprow));
	    memcpy(&ktmprow, &kroutet->entry[rowid], sizeof(ktmprow));

	    memcpy(&routet->path[rowid], &routet->path[bestid],
		   sizeof(tmprow));
	    memcpy(&kroutet->entry[rowid], &kroutet->entry[bestid],
		   sizeof(ktmprow));
	    
	    memcpy(&routet->path[bestid], &tmprow, sizeof(tmprow));
	    memcpy(&kroutet->entry[bestid], &ktmprow, sizeof(ktmprow));
	}
    }

    return changed;
}









/*! Adjust route entries that track other route entries
 *
 * \param routet          the routing table
 * \param ipift           the IP interface table
 * \param ref_read_lock   the read lock for the route table
 * \param changed         whether the read lock has already been opened
 *
 * \return                FALSE iff no alteration to the route table made
 *
 *  This function adjusts the \c dest_ifindex field if
 *  scope.tracking_llap is set
 *
 *  This function opens the read lock for writing only if necessary - and
 *  thus ensures that, if no change has occurred, that this action does not
 *  cause unnecessary re-evaluation elsewhere.
 *
 *  Note that if an alteration is made by this function the caller must
 *  ensure that the read lock is closed for writing when the update is
 *  complete.
 *
 *  This function requires the tables to be locked but does not itself lock
 *  them.
 */
static int /* bool */
cicpos_route_retrack(cicp_fwdinfo_t *routet,
		     const cicp_ipif_kmib_t *ipift,
		     ci_verlock_t *ref_read_lock,
		     int /* bool */ changed)
{   cicp_fwd_row_t *row;
    cicp_fwd_rowid_t rowid;

    for (rowid = 0;
	 rowid < routet->rows_max &&
           cicp_fwd_row_allocated(row = &routet->path[rowid]);
	 rowid++)
    {   ci_assert(NULL != row);
	if (row->scope.tracking_llap)
	{   /* we want to work out the LLAP from the gateway (which is expected
		to be a local address in the IPIF table)
	     */
	     if (!CI_IP_ADDR_IS_EMPTY(&row->first_hop))
	     {   /* find an IP interface that matches the first hop then find
		    its ifindex */
		 ci_ifid_t orig_ifindex = row->dest_ifindex;
		 const cicp_ipif_row_t *ipif_row =
		     cicp_ipif_find_ip(ipift, CI_IFID_BAD/*(any)*/,
				       &row->destnet_ip);
		 if (NULL != ipif_row)
		     row->dest_ifindex = ipif_row->ifindex;
		 else
		 {   /* this first hop is no longer available, refer to O/S */
		     row->dest_ifindex = CI_IFID_BAD;
		 }

		 if (orig_ifindex != row->dest_ifindex && !changed)
		 {   ci_verlock_write_start(ref_read_lock);
		     changed = TRUE;
		 }
	     } 
	     /* else - we have asked for tracking but there is no (i.e. a zero)
		first hop (gateway) address - assume current interface is OK
	     */
	}
    }
    
    return changed;
}








/*!
 * Record a new route (that does not currently exist)
 *
 * \param routet          the route table
 * \param kroutet         the kernel route table
 * \param out_rowid       a location where the mac MIB row number is written
 * \param dest_ip         the route set base IP address 
 * \param dest_set        the set of addresses based on \c dest_ip
 * \param next_hop_ip     the forwarding address to use on a match
 * \param tos             the type of service the route supports
 * \param metric          the cost of taking the route
 * \param pref_source     the IP source address to use when transmitting 
 * \param ifindex         the link access point of the forwarding address
 *
 * \return                0 on success, error code otherwise
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 */
ci_inline int /* rc */
cicpos_route_add(cicp_handle_t      *control_plane,
		 cicp_fwdinfo_t     *routet,
		 cicp_route_kmib_t  *kroutet,
		 cicp_route_rowid_t *out_rowid,
		 ci_ip_addr_t        dest_ip,
		 ci_ip_addrset_t     dest_set,
		 ci_ip_tos_t         tos,
		 cicp_metric_t       metric,
		 ci_scope_t          scope,
		 ci_ip_addr_t        next_hop_ip,
		 ci_ip_addr_t        pref_source,
		 ci_ifid_t           ifindex,
		 ci_mtu_t            mtu,
                 int /* bool */      nosort)
{   cicp_fwd_row_t *newrow;
    int rc;
    
    ci_assert(NULL != routet);
    ci_assert(CI_IP_ADDRSET_BAD != dest_set);
    /* otherwise the new route will appear to be bad */
    
    newrow = _cicpos_fwd_find_free(routet);
    if (NULL != newrow)
    {   cicp_route_rowid_t rowid = (ci_uint32)(newrow - &routet->path[0]);
	cicp_route_kernrow_t *knewrow = &kroutet->entry[rowid];

	*out_rowid = rowid;
	
	CI_VERLOCK_WRITE_BEGIN(routet->version)
	    
	    /* fill in other fwdinfo entries for the route */
	    CI_IP_ADDR_SET_SUBNET(&newrow->destnet_ip, &dest_ip, dest_set);
	    newrow->destnet_ipset = dest_set; /* sets the entry to allocated */
	    CI_IP_ADDR_SET(&newrow->first_hop, &next_hop_ip);
	    newrow->scope = scope;
	    newrow->tos = tos;
	    newrow->metric = metric;
	    CI_IP_ADDR_SET(&newrow->pref_source, &pref_source);
	    newrow->dest_ifindex = ifindex;
	    if (mtu != 0) {
		newrow->mtu = mtu;
		newrow->flags |= CICP_FLAG_ROUTE_MTU;
	    }

	    cicpos_route_kmib_row_ctor(&knewrow->sync);
	    /*block:*/
            {	const cicp_llap_kmib_t *llapt = control_plane->llap_table;
		const cicp_ipif_kmib_t *ipift = control_plane->ipif_table;
		(void)cicpos_fwd_route_cache(llapt, ipift, newrow,
					     &routet->version,
					     /*changed*/TRUE);
		/* do any necesary retracking */
		(void)cicpos_route_retrack(routet, ipift, &routet->version,
					   /*changed*/TRUE);
            }

	    /* sort this new entry in to position */
            if (!nosort)
                (void)cicp_route_sort(routet, kroutet, /*changed*/TRUE);
	    
	CI_VERLOCK_WRITE_END(routet->version)
	    
	rc = 0;
    } else
    {   OO_DEBUG_FWD(DPRINTF(CODEID": no free route table entries"););
	rc = -ENOMEM;
    }
	
    return rc;
}






/*!
 * Ammend a currently existing route to a given set of IP addresses
 *
 * \param routet          the route table
 * \param kroutet         the kernel route table
 * \param rowid           the row of the table that is to be updated
 * \param dest_ip         the route set base IP address 
 * \param dest_set        the set of addresses based on \c dest_ip
 * \param next_hop_ip     the forwarding address to use on a match
 * \param tos             the type of service the route supports
 * \param metric          the cost of taking the route
 * \param ifindex         the link access point of the forwarding address
 * \param pref_source     the IP source address to use when transmitting 
 * \param hwport_id       the port on which the link access point is located
 * \param ref_sync        O/S-specific synchronization information
 *
 * \return                FALSE iff no change was made to the entry
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * Note: none of these updates can change the order of the fields in
 *       the table - so resorting is not necessary.
 */
ci_inline int /* bool */
cicpos_route_update(cicp_handle_t      *control_plane,
		    cicp_fwdinfo_t     *routet,
		    cicp_route_kmib_t  *kroutet,
		    cicp_route_rowid_t  rowid,
		    ci_scope_t          scope,
                    ci_ip_addr_t        next_hop_ip,
		    ci_ip_tos_t         tos,
		    cicp_metric_t       metric,
                    ci_ip_addr_t        pref_source,
                    ci_ifid_t           ifindex,
		    ci_mtu_t            mtu,
                    ci_uint32           flags,
		    cicpos_route_row_t *ref_sync)
{   cicp_fwd_row_t *row;
    cicp_route_kernrow_t *krow;
    int /* bool */ changed = FALSE;
    
    ci_assert(NULL != routet);
    ci_assert(NULL != kroutet);

    row = &routet->path[rowid];
    krow = &kroutet->entry[rowid];

    if (!CI_IP_ADDR_EQ(&row->first_hop, &next_hop_ip))
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	CI_IP_ADDR_SET(&row->first_hop, &next_hop_ip);
    }
    if (!CI_IP_ADDR_EQ(&row->pref_source, &pref_source))
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	CI_IP_ADDR_SET(&row->pref_source, &pref_source);
    }
    if (row->dest_ifindex != ifindex)
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	row->dest_ifindex = ifindex;
    }

    if ((mtu != 0) == !(row->flags & CICP_FLAG_ROUTE_MTU))
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	row->flags ^= CICP_FLAG_ROUTE_MTU;
	if (mtu != 0)
	    row->mtu = mtu;
    }
    /* Fixme: we should use mtu != row->mtu, but in this case UDP PMTU
     * discovery does not work for linux < 3.6.  Route cache has incorrect
     * entries with large mtu on such old kernels. */
    else if ( (row->flags & CICP_FLAG_ROUTE_MTU) && mtu != row->mtu &&
              (mtu < row->mtu || (flags & CICP_FLAG_ROUTE_MTU)) )
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	row->mtu = mtu;
    }


    if (!ci_scope_eq(&row->scope, &scope))
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	ci_scope_set(&row->scope, &scope);
    }
    if (row->tos != tos)
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	row->tos = tos;
    }
    if (row->metric != metric)
    {   if (!changed)
	{   ci_verlock_write_start(&routet->version);
	    changed = TRUE;
	}
	row->metric = metric;
    }

    /* any change here makes no difference to user-visible information */
    (void)cicpos_route_kmib_row_update(&krow->sync, ref_sync);

    if (changed)
    {
        const cicp_llap_kmib_t *llapt = control_plane->llap_table;
	const cicp_ipif_kmib_t *ipift = control_plane->ipif_table;
	(void)cicpos_fwd_route_cache(llapt, ipift, row,
				     &routet->version, changed);
	/* do any necesary retracking */
	(void)cicpos_route_retrack(routet, ipift, &routet->version, changed);
        ci_verlock_write_stop(&routet->version);
    }
    return changed;
}







/*! Ammend an existing or add a new route
 *  - see driver header for documentation
 *
 * Note: none of these updates can change the order of the fields in
 *       the table - so re-sorting is not necessary.
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
		    ci_uint32           flags,
		    cicpos_route_row_t *ref_sync,
                    int /* bool */      nosort)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_fwdinfo_t *routet;
    cicp_route_kmib_t *kroutet;
    cicp_ipif_kmib_t *ipift;
    cicp_route_rowid_t rowid = CICP_ROUTE_ROWID_BAD;
    int rc = 0;
    int changed = FALSE;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->route_table);
    ci_assert(NULL != mibs->user.fwdinfo_utable);
    ci_assert(NULL != mibs->ipif_table);
    
    routet = mibs->user.fwdinfo_utable;
    kroutet = mibs->route_table;
    ipift = mibs->ipif_table;

    CICP_LOCK_BEGIN(control_plane)
	
        /* check the preferred source, if it is zero then we generate one */
        if (CI_IP_ADDR_IS_EMPTY(&pref_source))
        {   cicp_ipif_row_t *ipif_row = cicp_ipif_iterator_start(ipift);
	    int ifindex_matched = 0;
	    ci_uint8 scope = 255;
	    int network_matched = 0;

	    /* Try to find acceptable source address.
	     * - get address on this interface;
	     * - and, if possible, from the same network;
	     * - if no address on this interface, get a global scope
	     *   address (i.e. avoid loopback one).
	     */
	    while ((ipif_row = cicp_ipif_iterator_all(ipift, ipif_row)))
	    {   int same_net;
		if (ifindex_matched && ipif_row->ifindex != ifindex)
		    continue;
		same_net = CI_IP_ADDR_SAME_NETWORK(&next_hop_ip,
		                                   &ipif_row->net_ip,
		                                   ipif_row->net_ipset);
		if (network_matched && !same_net)
		    continue;
		if (ipif_row->scope > scope)
		    continue;

		CI_IP_ADDR_SET(&pref_source, &ipif_row->net_ip);
		scope = ipif_row->scope;
		ifindex_matched = (ipif_row->ifindex == ifindex);
		network_matched = same_net;
		if (ifindex_matched && network_matched && scope == 0)
		    break;
	    }
        }

        if (CI_LIKELY(!CI_IP_ADDR_IS_EMPTY(&pref_source))) {
	    rowid = _cicpos_route_find(routet, dest_ip, dest_ipset, ifindex);
            if (CICP_ROUTE_ROWID_BAD == rowid) {
                rc = cicpos_route_add(control_plane,
				      routet, kroutet, &rowid, dest_ip,
                                      dest_ipset, tos, metric, scope,
				      next_hop_ip, pref_source, ifindex, mtu,
                                      nosort);
                changed = TRUE;
            } else
                changed = cicpos_route_update(control_plane,
					      routet, kroutet, rowid,
                                              scope, next_hop_ip, tos, metric, 
                                              pref_source, ifindex, mtu,
                                              flags, ref_sync);
            if (changed)
	      cicpos_fwdinfo_route_import(control_plane, dest_ipset, dest_ip,
	                                  &next_hop_ip, &pref_source);

        } else {
          rc = -EINVAL; 
	}
	
    CICP_LOCK_END

    if (CI_UNLIKELY(CI_IP_ADDR_IS_EMPTY(&pref_source))) {
        OO_DEBUG_FWD(ci_log(CODEID": ignored route " CI_IP_PRINTF_FORMAT"/"
                            CI_IP_ADDRSET_PRINTF_FORMAT" -> "CI_IP_PRINTF_FORMAT
                            ": couldn't find a src addr on LLAP "
                            CI_IFID_PRINTF_FORMAT,
                            CI_IP_PRINTF_ARGS(&dest_ip),
                            CI_IP_ADDRSET_PRINTF_ARGS(dest_ipset),
                            CI_IP_PRINTF_ARGS(&next_hop_ip), ifindex));
                   
        LOGEVENT_CP_ROUTE_NOSRC(ifindex, &dest_ip, dest_ipset, &next_hop_ip);
    }

    if (NULL != out_rowid)
	*out_rowid = rowid;

    OO_DEBUG_FWD(
        if (0 != rc)
            DPRINTF(CODEID": failed to add new route, rc=%d "
		    "ifindex "CI_IFID_PRINTF_FORMAT" "
		    CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT" -> "
		    CI_IP_PRINTF_FORMAT,
		    rc, ifindex, CI_IP_PRINTF_ARGS(&dest_ip),
		    CI_IP_ADDRSET_PRINTF_ARGS(dest_ipset),
		    CI_IP_PRINTF_ARGS(&next_hop_ip));
	else if (CICP_ROUTE_ROWID_BAD == rowid)
            DPRINTF(CODEID": fwd set ifid "CI_IFID_PRINTF_FORMAT" "
		    CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT" -> "
		    CI_IP_PRINTF_FORMAT,
		    ifindex, CI_IP_PRINTF_ARGS(&dest_ip),
		    CI_IP_ADDRSET_PRINTF_ARGS(dest_ipset),
		    CI_IP_PRINTF_ARGS(&next_hop_ip));
	else if (changed)
	    DPRINTF(CODEID": fwd update [%d] ifid "CI_IFID_PRINTF_FORMAT" "
		    CI_IP_PRINTF_FORMAT"/"CI_IP_ADDRSET_PRINTF_FORMAT" -> "
		    CI_IP_PRINTF_FORMAT,
		    rowid, ifindex, CI_IP_PRINTF_ARGS(&dest_ip),
		    CI_IP_ADDRSET_PRINTF_ARGS(dest_ipset),
		    CI_IP_PRINTF_ARGS(&next_hop_ip));
    );
    
    return rc;
}







/*! Record a new route (that does not currently exist) without O/S sync info
 * 
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_route_import(cicp_handle_t      *control_plane, 
		  cicp_route_rowid_t *out_rowid,
		  ci_ip_addr_t        dest_ip,
		  ci_ip_addrset_t     dest_ipset,
		  ci_ip_addr_t        next_hop_ip,
		  ci_ip_tos_t         tos,
		  cicp_metric_t       metric,
		  ci_ip_addr_t        pref_source,
		  ci_ifid_t           ifindex,
		  ci_mtu_t            mtu)
{   ci_scope_t scope;
    ci_scope_set_global(&scope); /* we don't allow non-sync code to set this */
    return cicpos_route_import(control_plane, out_rowid, dest_ip, dest_ipset,
			       scope, next_hop_ip, tos, metric, pref_source,
			       ifindex, mtu,
			       mtu == 0 ? 0 : CICP_FLAG_ROUTE_MTU,
			       /*sync*/ NULL, /*nosort*/CI_FALSE);
}









/*! compress used entries to beginning of table */
static int /* bool */
cicpos_route_compress(cicp_fwdinfo_t    *routet,
		      cicp_route_kmib_t *kroutet,
		      int /*bool*/       changed)
{   cicp_route_rowid_t   rowid;
    cicp_route_kernrow_t *kfreerow = &kroutet->entry[0];
    cicp_fwd_row_t       *freerow  = &routet->path[0];
    
    for (rowid = 0; rowid < kroutet->rows_max; rowid++)
    {   cicp_route_kernrow_t *krow = &kroutet->entry[rowid];
	cicp_fwd_row_t       *row = &routet->path[rowid];
    	
    	if (cicp_fwd_row_allocated(row))
	{   if (!changed) /* in case deleted before the purge */
	    {   ci_verlock_write_start(&routet->version);
		changed = TRUE;
	    }
	    if (row != freerow)
	    {   memcpy(freerow, row, sizeof(*freerow));
	        memcpy(kfreerow, krow, sizeof(*kfreerow));
	        cicp_fwd_row_free(row);
	    }
	    freerow++;
	    kfreerow++;
	}
    }

    return changed;
}







/*! Remove a route 
 *  - see driver header for documentation
 *
 * Note: none of these updates can change the order of the fields in
 *       the table - so resorting is not necessary.
 */
extern void
cicpos_route_delete(cicp_handle_t     *control_plane, 
		    ci_ip_addr_t       dest_ip,
		    ci_ip_addrset_t    dest_ipset,
                    ci_ifid_t          dest_ifindex)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_fwdinfo_t *routet;
    cicp_route_kmib_t *kroutet;
    cicp_route_rowid_t rowid;
			  
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->route_table);
    ci_assert(NULL != mibs->user.fwdinfo_utable);

    routet = mibs->user.fwdinfo_utable;
    kroutet = mibs->route_table;
    
    CICP_LOCK_BEGIN(control_plane)
	
	CI_IP_ADDR_SET_SUBNET(&dest_ip, &dest_ip, dest_ipset);
	rowid = _cicpos_route_find(routet, dest_ip, dest_ipset,
                                   dest_ifindex);
	if (CICP_ROUTE_ROWID_BAD != rowid)
	{   CI_VERLOCK_WRITE(routet->version,
			     cicp_fwd_row_free(&routet->path[rowid]);
			    (void)cicpos_route_compress(routet, kroutet,
							 /*changed*/ TRUE);
		             )
	    cicpos_fwdinfo_route_import(control_plane, dest_ipset,
                                        dest_ip, /* next hop */NULL,
                                        /* pref_source */NULL);
	} else
          OO_DEBUG_FWD(ci_log("%s: route not found", __FUNCTION__));
		
    CICP_LOCK_END

    return;
}








/*----------------------------------------------------------------------------
 * PMTU MIB
 *---------------------------------------------------------------------------*/


static void
cicpos_pmtu_remove_locked(cicp_handle_t *control_plane,
                          ci_ip_addr_net_t net_ip)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_pmtu_kmib_t *pmtu_table = mibs->pmtu_table;
  int i;

  for( i = 0; i < pmtu_table->used_rows_max; i++ )
    if( pmtu_table->entries[i].net_ip == net_ip )
      cicp_pmtu_row_free(&pmtu_table->entries[i]);
}

void
cicpos_pmtu_remove(cicp_handle_t *control_plane, ci_ip_addr_net_t net_ip)
{
  CICP_LOCK_BEGIN(control_plane)
    cicpos_pmtu_remove_locked(control_plane, net_ip);
  CICP_LOCK_END
}

void
cicpos_pmtu_add(cicp_handle_t *control_plane, ci_ip_addr_net_t net_ip)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_pmtu_kmib_t *pmtu_table = mibs->pmtu_table;
  int i, free = -1;

  CICP_LOCK_BEGIN(control_plane)

    for( i = 0; i < pmtu_table->rows_max; i++ ) {
      if( pmtu_table->entries[i].net_ip == net_ip )
        goto unlock;
      if( free == -1 && !cicp_pmtu_row_allocated(&pmtu_table->entries[i]) )
        free = i;
    }

    if( free != -1 ) {
      pmtu_table->entries[free].net_ip= net_ip;
      pmtu_table->entries[free].timestamp = jiffies;
      if( free >= pmtu_table->used_rows_max )
        pmtu_table->used_rows_max = free + 1;
    }
    else {
      OO_DEBUG_FWD(DPRINTF(CODEID": no space in pmtu table: %d rows, "
                           "can't add "CI_IP_PRINTF_FORMAT,
                           pmtu_table->rows_max,
                           CI_IP_PRINTF_ARGS(&net_ip)));
    }

unlock:
    ;
  CICP_LOCK_END
}


int
cicpos_pmtu_check(cicp_handle_t *control_plane, ci_ip_addr_net_t net_ip,
                  ci_ifid_t ifindex, ci_mtu_t pmtu)
{
  int rc = -1;
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_pmtu_kmib_t *pmtu_table = mibs->pmtu_table;
  cicp_llap_row_t *llap_row;

  CICP_LOCK_BEGIN(control_plane)
    llap_row = cicp_llap_find_ifid(mibs->llap_table, ifindex);
    if( pmtu != 0 && llap_row != NULL && pmtu < llap_row->mtu ) {
      int i;
      for( i = 0; i < pmtu_table->used_rows_max; i++ )
        if( pmtu_table->entries[i].net_ip == net_ip ) {
          rc = i;
          break;
        }
      if( i == pmtu_table->rows_max )
        rc = -1;
    }
  CICP_LOCK_END

  return rc;
}



/*****************************************************************************
 *                                                                           *
 *          IP Interface MIB						     *
 *          ================						     *
 *                                                                           *
 *****************************************************************************/










/*! Register a callback for when ipif table is updated
 *  - see driver header for documentation
 */
extern cicpos_ipif_callback_handle_t
cicpos_ipif_callback_register(cicp_handle_t          *control_plane,
			      cicpos_ipif_event_fn_t *add_fn,
                              cicpos_ipif_event_fn_t *delete_fn,
                              void                   *arg)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicpos_ipif_callback_handle_t handle = 0;
			  
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);

    CICP_LOCK_BEGIN(control_plane)
        int id = 0;
        cicp_ipif_kmib_t *ipift = mibs->ipif_table;
	cicpos_ipif_callback_registration_t *reg =
	                                     &ipift->sync.callback.reg[id];
	if (!cicp_ipif_callback_allocated(reg))
	{   reg->add_fn = add_fn;
	    reg->delete_fn = delete_fn;
	    reg->arg = arg;
            reg->id = id;
	    handle = 1;
	}
    
    CICP_LOCK_END

    return handle;
}


/*! Remove callback registration 
 *  - see driver header for documentation
 */
extern void
cicpos_ipif_callback_deregister(cicp_handle_t *control_plane,
			        cicpos_ipif_callback_handle_t handle)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    			  
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);

    if (0 != handle && handle <= 1)
    {   cicp_ipif_kmib_t *ipift = mibs->ipif_table;

	CICP_LOCK_BEGIN(control_plane)

	    cicpos_ipif_callback_registration_t *reg =
		&ipift->sync.callback.reg[handle-1];

	    cicp_ipif_callback_free(reg);

	CICP_LOCK_END
    }
}


static void
cicpos_ipif_callback_add(cicp_handle_t *control_plane,
			 const cicp_ipif_kmib_t *ipift, ci_ifid_t ifindex,
			 ci_ip_addr_net_t net_ip, ci_ip_addrset_t net_ipset,
                         ci_ip_addr_net_t net_bcast)
{
  const cicpos_ipif_callback_registration_t *reg =
    &ipift->sync.callback.reg[0];

  if (cicp_ipif_callback_allocated(reg) && NULL != reg->add_fn)
    (*reg->add_fn)(net_ip, net_ipset, net_bcast, ifindex, reg->arg);

  cicp_llap_log(control_plane);
}


static void
cicpos_ipif_callback_delete(cicp_handle_t *control_plane,
			    const cicp_ipif_kmib_t *ipift, ci_ifid_t ifindex,
			    ci_ip_addr_net_t net_ip,
			    ci_ip_addrset_t  net_ipset,
			    ci_ip_addr_net_t net_bcast)
{
  const cicpos_ipif_callback_registration_t *reg =
    &ipift->sync.callback.reg[0];

  if( cicp_ipif_callback_allocated(reg) && NULL != reg->delete_fn )
    (*reg->delete_fn)(net_ip, net_ipset, net_bcast, ifindex, reg->arg);

  cicp_llap_log(control_plane);
}







    


/*!
 * Retrieve link layer access point table information
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicpos_ipif_readrow(const cicp_handle_t *control_plane,
	            cicp_llap_rowid_t rowid,
	            ci_verlock_value_t *out_table_version,
	            ci_ifid_t *out_ifindex,
		    ci_ip_addr_t *out_net_ip,
		    ci_ip_addrset_t *out_net_ipset,
		    ci_ip_addr_t *out_net_bcast)
		    
{   int rc;
    const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    const cicp_ipif_kmib_t *ipift;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->ipif_table);
    
    ipift = mibs->ipif_table;

    if (rowid < ipift->rows_max)
    {   const cicp_ipif_row_t *row = &ipift->ipif[rowid];

	if (cicp_ipif_row_allocated(row))
	{   if (NULL != out_table_version)
	        *out_table_version = ipift->version;
	    if (NULL != out_ifindex)
	        *out_ifindex = row->ifindex;
	    if (NULL != out_net_ip)
	        CI_IP_ADDR_SET(out_net_ip, &row->net_ip);
	    if (NULL != out_net_ipset)
	        *out_net_ipset = row->net_ipset;
	    if (NULL != out_net_bcast)
	        CI_IP_ADDR_SET(out_net_bcast, &row->bcast_ip);
	    rc = 0;
	} else
	    rc = -ENODEV;
    } else
        rc = -EINVAL;

    return rc;
}






/*! Locate an entry in the IP interface table for the destination IP subnet
 *
 *  It is assumed that this table is short and that it is, by and large,
 *  cheaper to search its content linearly.
 */
ci_inline cicp_ipif_row_t *
cicp_ipif_find_subnet(const cicp_ipif_kmib_t *ipift, 
		      ci_ifid_t ifindex,
		      ci_ip_addr_net_t net_ip,
		      ci_ip_addrset_t  net_ipset)
{   const cicp_ipif_row_t *row    = &ipift->ipif[0];
    const cicp_ipif_row_t *maxrow = row + ipift->rows_max;
    
    while (row < maxrow && cicp_ipif_row_allocated(row) &&
	   !(ifindex == row->ifindex &&
	     CI_IP_ADDR_EQ(&net_ip, &row->net_ip) &&
	     net_ipset == row->net_ipset))
	row++;

    return row < maxrow && cicp_ipif_row_allocated(row)?
	   (cicp_ipif_row_t *)row: (cicp_ipif_row_t *)NULL;
}







/*! Locate an entry in the IP interface table for home IP address
 *
 *  It is assumed that this table is short and that it is, by and large,
 *  cheaper to search its content linearly.
 */
static cicp_ipif_row_t *
cicp_ipif_find_home(const cicp_ipif_kmib_t *ipift, ci_ip_addr_net_t net_ip)
{   const cicp_ipif_row_t *row    = &ipift->ipif[0];
    const cicp_ipif_row_t *maxrow = row + ipift->rows_max;
    
    while (row < maxrow && cicp_ipif_row_allocated(row) &&
	   !CI_IP_ADDR_EQ(&net_ip, &row->net_ip))
	row++;

    return row < maxrow && cicp_ipif_row_allocated(row)?
	   (cicp_ipif_row_t *)row: (cicp_ipif_row_t *)NULL;
}







extern int
cicp_user_find_home(cicp_handle_t *control_plane,
		    const ci_ip_addr_t *ref_ip_be32,
                    ci_hwport_id_t *out_hwport, 
                    ci_ifid_t *out_ifindex, ci_mac_addr_t *out_mac,
                    ci_mtu_t *out_mtu, cicp_encap_t *out_encap)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    ci_hwport_id_t hwport = CI_HWPORT_ID_BAD;
    cicp_llap_kmib_t *llapt; 
    cicp_ipif_kmib_t *ipift; 
    int rc;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->llap_table);
    ci_assert(NULL != mibs->ipif_table);

    llapt = mibs->llap_table;
    ipift = mibs->ipif_table;
    
    CICP_LOCK_BEGIN(control_plane)

        const cicp_ipif_row_t *row = cicp_ipif_find_home(ipift, *ref_ip_be32);
        /* warning - in theory there could be more than one row with this
	             home address - we take only the first here
	*/
        rc = -ENODATA;
        if (NULL != row)
        {   cicp_llap_row_t *lrow = cicp_llap_find_ifid(llapt, row->ifindex);
	    
	    if (CI_UNLIKELY(lrow == NULL))
		rc = -EINVAL;
	    else
	    {   
                hwport = lrow->hwport;
                ci_assert(hwport == CI_HWPORT_ID_BAD ||
                          hwport <= CI_HWPORT_ID_MAX);
		if (NULL != out_hwport)
                    *out_hwport = hwport;
		if (NULL != out_ifindex)
		     *out_ifindex = row->ifindex;
		if (NULL != out_mac)
		    CI_MAC_ADDR_SET(out_mac, &lrow->mac);
                if (NULL != out_mtu)
                    *out_mtu = lrow->mtu;
                if (NULL != out_encap)
                    memcpy(out_encap, &lrow->encapsulation, sizeof(*out_encap));
		rc = 0;
	    }
	}	    

    CICP_LOCK_END
	
    OO_DEBUG_FWD(
	DPRINTF(CODEID": find home "CI_IP_PRINTF_FORMAT
		" rc %d (%s) hwport=%d",
		CI_IP_PRINTF_ARGS(ref_ip_be32), -rc,
		rc==0? "OK":
		rc==-ENODATA? "ENODATA":
		rc==-EINVAL? "EINVAL": "unknown",
		(int) hwport);
    );

    return rc;
}





/*! Locate a forwarding information row that is not allocated
 *
 * Note that this function does not "allocate" the sought entry
 */
ci_inline cicp_ipif_row_t *
cicpos_ipif_find_free(cicp_ipif_kmib_t *ipift)
{   cicp_ipif_row_t *row = &ipift->ipif[0];
    cicp_ipif_row_t *maxrow = row + ipift->rows_max;

    while (row < maxrow && cicp_ipif_row_allocated(row))
	row++;

    return row < maxrow? row: NULL;
}






/*! Find the IP interface row with the given set of subnet addresses
 *
 * \param llapt           the IP interface table
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 * \return                CICP_IPIF_ROWID_BAD iff ifindex not found, else row
 *
 * This function requires the table to be locked but does not itself lock it.
 */
ci_inline cicp_ipif_rowid_t
cicpos_ipif_find(const cicp_ipif_kmib_t *ipift,
		 ci_ifid_t ifindex,
		 ci_ip_addr_net_t net_ip,
                 ci_ip_addrset_t  net_ipset)
{   cicp_ipif_row_t *row;
    
    ci_assert(NULL != ipift);

    row = cicp_ipif_find_subnet(ipift, ifindex, net_ip, net_ipset);

    return NULL == row?  CICP_IPIF_ROWID_BAD:
		         (ci_uint32)(row - &ipift->ipif[0]);
}






/*! Create a new IP interface (that does not currently exist)
 *
 * \param llapt           the IP interface table
 * \param out_rowid       a place to write the index of ipif MIB row updated
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 * \return                0 iff addition successful
 *
 * This function is typically called in response to information found in the
 * O/S copy of the IP interfaces MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: also need to call cicpos_fwdinfo_ipif_import when this returns TRUE 
 */
ci_inline int /* rc */
cicpos_ipif_add(cicp_ipif_kmib_t  *ipift,
		cicp_ipif_rowid_t *out_rowid,
		ci_ifid_t          ifindex,
		ci_ip_addr_net_t   net_ip,
		ci_ip_addrset_t    net_ipset,
		ci_ip_addr_net_t   bcast_ip,
		ci_uint8           scope)
{   cicp_ipif_row_t *newrow;
    int rc;
    
    ci_assert(NULL != ipift);
    ci_assert(net_ipset != CI_IP_ADDRSET_BAD);
    /* otherwise the new row will not become allocated */
    
    newrow = cicpos_ipif_find_free(ipift);

    if (NULL != newrow)
    {
	CI_VERLOCK_WRITE_BEGIN(ipift->version)
	    /* not really a lock - reversion when # rows changes */
	    newrow->ifindex = ifindex;
	    CI_IP_ADDR_SET(&newrow->net_ip, &net_ip);
	    CI_IP_ADDR_SET(&newrow->bcast_ip, &bcast_ip);
	    newrow->net_ipset = net_ipset;
            newrow->bond_rowid = CICP_BOND_ROW_NEXT_BAD;
            newrow->scope = scope;
	    OO_DEBUG_FWD(DPRINTF(CODEID": ipif "CI_IFID_PRINTF_FORMAT" set "
				 CI_IP_PRINTF_FORMAT"/"
                                 CI_IP_ADDRSET_PRINTF_FORMAT" "
				 CI_IP_PRINTF_FORMAT,
				 newrow->ifindex,
				 CI_IP_PRINTF_ARGS(&newrow->net_ip),
				 CI_IP_ADDRSET_PRINTF_ARGS(newrow->net_ipset),
				 CI_IP_PRINTF_ARGS(&newrow->bcast_ip)););
	    *out_rowid = (ci_uint32)(newrow - &ipift->ipif[0]);
	    rc = 0;
	CI_VERLOCK_WRITE_END(ipift->version)
    } else
    {   OO_DEBUG_FWD(DPRINTF(CODEID": no free IP interface table entries"););
	rc = -ENOMEM;
    }

    return rc;
}





/*! Ammend a currently existing IP interface with a given broadcast addres
 *
 * \param llapt           the IP interface table
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 * \return                FALSE iff no change was made
 *
 * This function is typically called in response to information found in the
 * O/S copy of the IP interfaces MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: also need to call cicpos_fwdinfo_ipif_import when you call this
 */
ci_inline int /* bool */
cicpos_ipif_update(cicp_ipif_kmib_t *ipift, 
                   cicp_ipif_rowid_t rowid,
                   ci_ip_addr_net_t  bcast_ip,
                   ci_uint8          scope)
{   int /* bool */ change = FALSE;
    cicp_ipif_row_t *newrow = &ipift->ipif[rowid];
    
    ci_assert(NULL != ipift);
    
    if (!CI_IP_ADDR_EQ(&newrow->bcast_ip, &bcast_ip))
    {   change = TRUE;
	CI_IP_ADDR_SET(&newrow->bcast_ip, &bcast_ip);
    }
    if (newrow->scope != scope)
    {   change = TRUE;
        newrow->scope = scope;
    }

    return change;
}






/*! compress used entries to beginning of table */
static void
cicpos_ipif_compress(cicp_ipif_kmib_t *ipift)
{
    cicp_ipif_rowid_t rowid;
    cicp_ipif_row_t *freerow = &ipift->ipif[0];
    int /*bool*/ changed = FALSE;
    
    for (rowid = 0; rowid < ipift->rows_max; rowid++)
    {   cicp_ipif_row_t *row = &ipift->ipif[rowid];
    	if (cicp_ipif_row_allocated(row))
	{   if (row != freerow)
	    {   if (!changed)
		{   ci_verlock_write_start(&ipift->version);
		    changed = TRUE;
		}
		memcpy(freerow, row, sizeof(*freerow));
	        cicp_ipif_row_free(row);
	    }
	    freerow++;
	}
    }

    if (changed)
	ci_verlock_write_stop(&ipift->version);
}





/*! Delete the IP interface row with the given set of subnet addresses
 *
 * \param control_plane   control plane handle
 * \param ifindex         the O/S link layer access point the subnet is on
 * \param net_ip          base IP address of subnetwork
 * \param net_ipset       set of addresses around the base address
 *
 */
extern void
cicpos_ipif_delete(cicp_handle_t *control_plane, 
		   ci_ifid_t ifindex,
		   ci_ip_addr_net_t net_ip,
		   ci_ip_addrset_t  net_ipset)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_ipif_kmib_t *ipift;
    ci_ip_addr_net_t net_bcast;
    cicp_ipif_rowid_t rowid;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);
    ci_assert(NULL != mibs->llap_table);
    ci_assert(NULL != mibs->user.fwdinfo_utable);

    ipift = mibs->ipif_table;

    CICP_LOCK_BEGIN(control_plane);
	
    rowid = cicpos_ipif_find(ipift, ifindex, net_ip, net_ipset);

    if( CICP_IPIF_ROWID_BAD != rowid ) {
      cicp_ipif_row_t *row = &ipift->ipif[rowid];
      CI_IP_ADDR_SET(&net_bcast, &row->bcast_ip);
      cicp_ipif_row_free(row);
      if( ! cicp_ipif_find_home(ipift, net_ip) ) {
        cicpos_ipif_callback_delete(control_plane, ipift, ifindex,
                                    net_ip, net_ipset, net_bcast);
      }
      cicpos_ipif_compress(ipift);
      cicpos_fwdinfo_ipif_import(control_plane, &net_bcast, NULL);
    } 
    else {
      OO_DEBUG_FWD(ci_log("%s: ipif not found", __FUNCTION__));
    }
	
    CICP_LOCK_END;
	
    return;
}



static int 
cicp_check_ipif_callback(const cicp_mibs_kern_t *mibs, ci_ifid_t ifindex)
{
  cicp_llap_row_t *lrow;

  lrow = cicp_llap_find_ifid(mibs->llap_table, ifindex);

  if( lrow != NULL ) {
    ci_hwport_id_t port = lrow->hwport;
    ci_assert(port == CI_HWPORT_ID_BAD || port <= CI_HWPORT_ID_MAX);
    if( (port != CI_HWPORT_ID_BAD) || 
        (lrow->encapsulation.type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT) ) {
      return 1;
    }
  }
  return 0;
}



/*! Import data into the IP interface cache
 *  - see driver header for documentation
 */
extern int /* rc */
cicpos_ipif_import(cicp_handle_t     *control_plane, 
		   cicp_ipif_rowid_t *out_rowid,
		   ci_ifid_t          ifindex,
		   ci_ip_addr_net_t   net_ip,
		   ci_ip_addrset_t    net_ipset,
		   ci_ip_addr_net_t   net_bcast,
		   ci_uint8           scope)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_ipif_kmib_t *ipift;
  cicp_ipif_rowid_t rowid;
  int rc = 0;
			  
  ci_assert(NULL != control_plane);
  ci_assert(NULL != mibs->ipif_table);
  ci_assert(NULL != mibs->user.fwdinfo_utable);

  ipift = mibs->ipif_table;

  CICP_LOCK_BEGIN(control_plane);

  rowid = cicpos_ipif_find(ipift, ifindex, net_ip, net_ipset);

  if( CICP_IPIF_ROWID_BAD == rowid ) {
    rc = cicpos_ipif_add(ipift, &rowid,
                         ifindex, net_ip, net_ipset, net_bcast, scope);
    if( rc == 0 ) {
      rc = cicpos_fwdinfo_ipif_import(control_plane, NULL, &net_ip);
      if( rc == 0 &&
          cicp_check_ipif_callback(control_plane, ifindex) ) {
        cicpos_ipif_callback_add(control_plane, ipift, ifindex,
                                 net_ip, net_ipset, net_bcast);
      }
    }
  } else {
    ci_ip_addr_t old_net_bcast;
    CI_IP_ADDR_SET(&old_net_bcast, &ipift->ipif[rowid].bcast_ip);
    
    if( cicpos_ipif_update(ipift, rowid, net_bcast, scope) ) { 
      rc = cicpos_fwdinfo_ipif_import(control_plane, &old_net_bcast,
                                      &net_bcast);
    }
  }
	
  CICP_LOCK_END;
    
  if( rc == 0 && NULL != out_rowid )
    *out_rowid = rowid;
  
  OO_DEBUG_FWD(if (0 != rc)
                 DPRINTF(CODEID": failed to %s IP interface, rc=%d",
                         CICP_IPIF_ROWID_BAD == rowid? "add": "update", rc););
  return rc;
}


/* Announce (or deannounce) all addresses assigned to this ifindex.
 * Should be called under lock. */
static void
cicp_ipif_announce_if(cicp_handle_t *control_plane,
                      ci_ifid_t ifindex, int add)
{
  cicp_ipif_kmib_t *ipift = CICP_MIBS(control_plane)->ipif_table;
  cicp_ipif_rowid_t rowid;

  for( rowid = 0;
       rowid < ipift->rows_max &&
       cicp_ipif_row_allocated(&ipift->ipif[rowid]);
       rowid++) {
    const cicp_ipif_row_t *row = &ipift->ipif[rowid];
    if( ifindex == row->ifindex ) {
      if( add ) {
        cicpos_ipif_callback_add(control_plane, ipift, ifindex,
                                 row->net_ip, row->net_ipset,
                                 row->bcast_ip);
      }
      else {
        cicpos_ipif_callback_delete(control_plane, ipift, ifindex,
                                   row->net_ip, row->net_ipset,
                                   row->bcast_ip);
      }
    }
  }
}



/*! Delete all IP interface entries other than those in the provided set
 *  - see driver header for documentation
 */
extern void
cicpos_ipif_purge(cicp_handle_t *control_plane, ci_bitset_ref_t keep_set)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_ipif_kmib_t *ipift;
    cicp_ipif_rowid_t rowid;
			  
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->ipif_table);

    ipift = mibs->ipif_table;

    ci_assert(NULL != ipift);
    
    CICP_LOCK_BEGIN(control_plane);

    for( rowid = 0; rowid < ipift->rows_max; rowid++ ) {
      if( !ci_bitset_in(keep_set, rowid) ) {
        cicp_ipif_row_t   *row;

        row = &ipift->ipif[rowid];
        
        cicpos_ipif_callback_delete(control_plane, ipift, row->ifindex,
                                    row->net_ip, row->net_ipset, 
                                    row->bcast_ip);
        cicp_ipif_row_free(row);
      }
    }
    
    /* compress used entries to beginning of table */
    cicpos_ipif_compress(ipift);

    CICP_LOCK_END;
}


extern int
cicpos_ipif_get_ifindex_ipaddr(cicp_handle_t *control_plane, ci_ifid_t ifindex, 
                               ci_ip_addr_net_t *addr_out)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_ipif_kmib_t *ipift;
  cicp_ipif_row_t *row;

  ipift = mibs->ipif_table;

  CICP_LOCK_BEGIN(control_plane);

  /* we didn't find a good match, return anything with a matching ifindex */
  row = cicp_ipif_iterator(ipift, cicp_ipif_iterator_start(ipift), ifindex);

  if( row != NULL )
    *addr_out = row->net_ip;

  CICP_LOCK_END;

  return row != NULL ? 0 : -1;
}


#if CI_CFG_TEAMING
static int 
cicp_llap_check_vlan_ifindex(const cicp_llap_kmib_t *llapt,
                             const cicp_llap_row_t *lrow, ci_ifid_t ifindex)
{
  if( lrow->encapsulation.type & CICP_LLAP_TYPE_VLAN) {
    const cicp_llap_row_t *vlan_row;

    ci_assert(lrow->vlan_rowid >= 0);
    ci_assert(lrow->vlan_rowid < llapt->rows_max);
    
    vlan_row = &llapt->llap[lrow->vlan_rowid];

    if( vlan_row->ifindex == ifindex )
      return 1;
  }
  return 0;
}
#endif


struct ipif_callback {
  int type;
  ci_ifid_t ifindex;
  ci_ip_addr_net_t net_ip;
  ci_ip_addrset_t net_ipset;
  ci_ip_addr_net_t net_bcast;
  ci_dllink list_link;
};

extern void
cicpos_ipif_bond_change(cicp_handle_t *control_plane, ci_ifid_t ifindex)
{
#if CI_CFG_TEAMING
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_ipif_kmib_t *ipift;
  const cicp_llap_kmib_t *llapt;
  cicp_ipif_row_t *irow;
  const cicp_llap_row_t *lrow;
  const cicp_llap_row_t *end_lrow;

  ci_assert(NULL != control_plane);
  ci_assert(NULL != mibs->ipif_table);
  ci_assert(NULL != mibs->llap_table);
  ci_assert(NULL != mibs->user.fwdinfo_utable);
  
  ipift = mibs->ipif_table;
  llapt = mibs->llap_table;

  CICP_LOCK_BEGIN(control_plane);

  lrow = &llapt->llap[0];
  end_lrow = llapt->llap + llapt->rows_max;

  while( lrow < end_lrow ) {
    if( cicp_llap_row_allocated(lrow) && 
        (lrow->ifindex == ifindex ||
         cicp_llap_check_vlan_ifindex(llapt, lrow, ifindex)) ) {
      ci_hwport_id_t hwport = lrow->hwport;
      int onloadable = (hwport != CI_HWPORT_ID_BAD) || 
        (lrow->encapsulation.type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT);
      irow = cicp_ipif_iterator_start(ipift);
      while( (irow = cicp_ipif_iterator(ipift, irow, lrow->ifindex)) != NULL ) {
        if( onloadable ) {
          cicpos_ipif_callback_add(control_plane, ipift, 
                                   lrow->ifindex, irow->net_ip,
                                   irow->net_ipset, irow->bcast_ip);
          irow->bond_rowid = lrow->bond_rowid;
        } 
        else {
          cicpos_ipif_callback_delete(control_plane, ipift, 
                                      lrow->ifindex, irow->net_ip,
                                      irow->net_ipset, irow->bcast_ip);
          irow->bond_rowid = CICP_BOND_ROW_NEXT_BAD;
        }
      }
    }
    ++lrow;
  }

  CICP_LOCK_END;
#endif
}







/*****************************************************************************
 *                                                                           *
 *          Link Layer Access Point MIB					     *
 *          ===========================					     *
 *                                                                           *
 *****************************************************************************/








/*!
 * Retrieve link layer access point table information
 *  - system call implementation: see user header for documentation
 */
extern int /* rc */
cicpos_llap_readrow(const cicp_handle_t *control_plane, 
	            cicp_llap_rowid_t rowid,
	            ci_verlock_value_t *out_table_version,
	            ci_ifid_t *out_ifindex,
	            ci_uint8 /* bool */ *out_up,
	            cicp_encap_t *out_encap)
{   int rc;
    const cicp_mibs_kern_t *mibs = control_plane;
    const cicp_llap_kmib_t *llapt;
		       
    ci_assert(NULL != mibs);
    ci_assert(NULL != mibs->llap_table);
    
    llapt = mibs->llap_table;

    if (rowid < llapt->rows_max)
    {   const cicp_llap_row_t *row = &llapt->llap[rowid];

	if (cicp_llap_row_allocated(row))
	{   if (NULL != out_table_version)
	        *out_table_version = llapt->version;
	    if (NULL != out_ifindex)
	        *out_ifindex = row->ifindex;
	    if (NULL != out_up)
	        *out_up = row->up;
	    if (NULL != out_encap)
		memcpy(out_encap, &row->encapsulation, sizeof(*out_encap));
	    rc = 0;
	} else
	    rc = -ENODEV;
    } else
        rc = -EINVAL;

    return rc;
}





#if 0 != DEBUGMIBLLAPLOG(1+)0
static void
cicp_llap_log(const cicp_handle_t *control_plane)
{   int rowid = 0;
    int rc;
    ci_verlock_value_t tablever;
    ci_ifid_t ifindex = 0;       /* initialize to shut up gcc 4 */
    ci_uint8 up = 0;             /* initialize to shut up gcc 4 */
    cicp_encap_t encap = {0, CICP_LLAP_TYPE_NONE};
    const int silly_rowid = 10000;

    
    {   ci_log("Link Layer Access Point Table:");
	while ((rc = cicpos_llap_readrow(control_plane,
					 (cicp_llap_rowid_t)rowid, &tablever,
					 &ifindex, &up, &encap)) != -EINVAL &&
	       rowid < silly_rowid)
	{   if (0 == rc)
	    {   ci_mtu_t mtu;
		ci_hwport_id_t hwport;
		ci_mac_addr_t mac;

		rc = cicp_llap_retrieve(control_plane, ifindex, &mtu,
					&hwport, &mac, NULL/*encap*/,
                                        NULL/*base_ifindex*/, NULL);
		if (rc != 0)
		    ci_log("llap %d retrieve failed: %src %d",
			   ifindex, 
			   rc<0?"": "ioctl ", rc<0? -rc: rc);
		else
		{   if (hwport == CI_HWPORT_ID_BAD)
		        ci_log("%02d: llap "CI_IFID_PRINTF_FORMAT
			       " %s port X",
			       rowid, ifindex, up?" UP ":"DOWN");
		    else
		    {   ci_log("%02d: llap "CI_IFID_PRINTF_FORMAT" %s port "
			       "%d mac "CI_MAC_PRINTF_FORMAT" mtu %d "
				"encap "CICP_ENCAP_NAME_FMT,
			       rowid, ifindex, up?" UP ":"DOWN",
			       hwport, CI_MAC_PRINTF_ARGS(&mac),
			       mtu, cicp_encap_name(encap.id));
		    }
		}
	    }

	    rowid++;
	}
	if (rowid >= silly_rowid)
	    ci_log(CODEID": failed to read LLAP row - last (row %d) "
		   "returned rc %d", rowid, -rc);
    }    
}
#else
static void
cicp_llap_log(const cicp_handle_t *control_plane)
{   (void)control_plane;
}
#endif






/*! find the link layer access point row with the given interface ID
 *
 * \param llapt           the link layer access point table
 * \param ifindex         the O/S network access point to find in \c llapt
 *
 * \return                CICP_LLAP_ROWID_BAD iff ifindex not found, else row
 *
 * This function requires the table to be locked but does not itself lock it.
 */
static cicp_llap_rowid_t
cicpos_llap_find(const cicp_llap_kmib_t *llapt, ci_ifid_t ifindex)
{   cicp_llap_row_t *row;
    
    ci_assert(NULL != llapt);
    row = cicp_llap_find_ifid(llapt, ifindex);
    
    return NULL == row?  CICP_LLAP_ROWID_BAD:
		         (ci_uint32)(row - &llapt->llap[0]);
}






/*! Add a new link layer access point (that does not exist)
 *
 * \param llapt           the link layer access point table
 * \param out_rowid       a place to write the index of llap MIB row updated
 * \param ifindex         O/S index of this layer 2 interface
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param up              if true, this interface is up 
 * \param name            name of interface
 * \param hwport          (if relevant) hardware port & NIC of interface
 * \param ref_mac     	  MAC address of access point
 * \param ref_encap       encapsulation used on this i/f
 * \param ref_sync        O/S synchronization info
 *
 * \return                0 on success, error code otherwise
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: also need to call cicpos_fwdinfo_llap_import when you use this
 */
static int /* rc */
cicpos_llap_add(cicp_llap_kmib_t *llapt, 
                cicp_llap_rowid_t *out_rowid,
		ci_ifid_t ifindex,
                ci_mtu_t mtu,
                ci_uint8 /* bool */ up,
                char *name,
                ci_hwport_id_t hwport,
                ci_mac_addr_t *ref_mac,
		cicp_encap_t *ref_encap,
		cicpos_llap_row_t *ref_sync)
{   cicp_llap_row_t *newrow;
    int rc;
    
    ci_assert(NULL != llapt);
    ci_assert(mtu != 0); /* otherwise the new row will not become allocated */
    ci_assert(ref_encap);
    
    newrow = cicp_llap_find_free(llapt);

    if (NULL != newrow)
    {
	CI_VERLOCK_WRITE_BEGIN(llapt->version)
	    /* not really a lock - reversion when # rows changes */
	    newrow->ifindex = ifindex;
	    newrow->mtu = mtu;
	    newrow->up = up;
	    memcpy(newrow->name, name, CICP_LLAP_NAME_MAX+1);
	    newrow->hwport = hwport;
            ci_assert(hwport == CI_HWPORT_ID_BAD || 
                      hwport <= CI_HWPORT_ID_MAX);
	    ci_assert(newrow->hwport == CI_HWPORT_ID_BAD || newrow->mtu > 0);
            newrow->bond_rowid = CICP_BOND_ROW_NEXT_BAD;
            newrow->vlan_rowid = CICP_BOND_ROW_NEXT_BAD;
	    CI_MAC_ADDR_SET(&newrow->mac, ref_mac);
	    memcpy(&newrow->encapsulation, ref_encap,
		   sizeof(newrow->encapsulation));
	    if (NULL == ref_sync)
		memset(&newrow->sync, 0, sizeof(newrow->sync));
	    else
		memcpy(&newrow->sync, ref_sync, sizeof(newrow->sync));

	    *out_rowid = (ci_uint32)(newrow - &llapt->llap[0]);
	    rc = 0;
	CI_VERLOCK_WRITE_END(llapt->version)
          
        OO_DEBUG_ARP(DPRINTF(CODEID": llap "CI_IFID_PRINTF_FORMAT" set "
                             "%s %c "CI_MAC_PRINTF_FORMAT" %d "
                             CICP_ENCAP_NAME_FMT,
                             ifindex,
                             (up) ? "UP" : "DOWN",
                             (hwport == CI_HWPORT_ID_BAD) ? 'X' : 
                             hwport + '0',
                             CI_MAC_PRINTF_ARGS(ref_mac),
                             mtu, cicp_encap_name(ref_encap->type)));
    } else
    {   OO_DEBUG_ARP(DPRINTF(CODEID": no free link layer access point "
			     "table entries"););
	rc = -ENOMEM;
    }

    return rc;
}


/*! compress used entries to beginning of table */
static void
cicpos_llap_compress(cicp_llap_kmib_t *llapt)
{
  cicp_llap_rowid_t rowid;
  cicp_llap_row_t *freerow = &llapt->llap[0];
  int /* bool */changed = FALSE;

  for( rowid = 0; rowid < llapt->rows_max; rowid++ ) {
    cicp_llap_row_t *row = &llapt->llap[rowid];
    if( cicp_llap_row_allocated(row) ) {
      if( row != freerow ) {
        if( !changed ) {
          ci_verlock_write_start(&llapt->version);
          changed = TRUE;
        }
        /* not really a lock - reversion when # rows changes */
        memcpy(freerow, row, sizeof(*freerow));
        cicp_llap_row_free(row);

        {
          cicp_llap_row_t *tmp_row = &llapt->llap[0];
          int old_rowid = (int)(row - tmp_row);
          int new_rowid = (int)(freerow - tmp_row);
          while( tmp_row < llapt->llap + llapt->rows_max ) {
            if( tmp_row->vlan_rowid == old_rowid )
              tmp_row->vlan_rowid = new_rowid;
            ++tmp_row;
          }
        }
      }
      ++freerow;
    }
  }

  if( changed )
    ci_verlock_write_stop(&llapt->version);
}


extern int /* rc */
cicp_llap_set_vlan(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                   ci_ifid_t master_ifindex)
{
  cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_kmib_t *llapt;
  cicp_llap_row_t *row, *master_row;
  int rc = 0, ipif_status_before, ipif_status_after;

  ci_assert(mibs->llap_table != NULL);

  CICP_LOCK_BEGIN(control_plane);

  llapt = mibs->llap_table;
   
  ci_verlock_write_start(&llapt->version);

  row = cicp_llap_find_ifid(llapt, ifindex);
  master_row = cicp_llap_find_ifid(llapt, master_ifindex);
  if( row != NULL && master_row != NULL ) {
    ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

    row->vlan_rowid = master_row - &llapt->llap[0];
    /* This property is inherited from the parent LLAP */ 
    if( master_row->encapsulation.type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT )
      row->encapsulation.type |= CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
    else
      row->encapsulation.type &=~ CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;

    /* Check to see if this change should cause an ipif callback */
    ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
    if( ipif_status_before != ipif_status_after )
      cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);
  } else
    rc = -ENODEV; /* device not found */

  ci_verlock_write_stop(&llapt->version);

  CICP_LOCK_END;

  return rc;
}


#if CI_CFG_TEAMING

static int 
cicp_llap_update_all_bond_rowid(cicp_handle_t *control_plane, 
                                ci_ifid_t ifindex,
                                ci_int16 new_rowid, 
                                int llapt_locked)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *row;
  const cicp_llap_row_t *end_row;
  int rc = 0;

  ci_assert(control_plane != NULL);
  ci_assert(mibs->llap_table != NULL);

  CICP_CHECK_LOCKED(control_plane);
  if( !llapt_locked) 
    ci_verlock_write_start(&mibs->llap_table->version);

  end_row = mibs->llap_table->llap + mibs->llap_table->rows_max;
  for( row = &mibs->llap_table->llap[0]; row < end_row; ++row ) {
    if( cicp_llap_row_allocated(row) ) {
      if( ifindex == row->ifindex )
        row->bond_rowid = new_rowid;
      else if( row->encapsulation.type & CICP_LLAP_TYPE_VLAN ) {
        cicp_llap_row_t *vlan_row = &mibs->llap_table->llap[row->vlan_rowid];
        ci_assert(row->vlan_rowid != CICP_BOND_ROW_NEXT_BAD);
        if( vlan_row->ifindex == ifindex )
          row->bond_rowid = new_rowid;
      }
    }
  }

  if( !llapt_locked )
    ci_verlock_write_stop(&mibs->llap_table->version);

  /* Not necessary: all callers do this on return:
   * cicp_fwdinfo_something_changed(control_plane);
   */

  return rc;
}



static int 
cicp_llap_update_all_hwport(cicp_handle_t *control_plane, 
                            ci_ifid_t ifindex, ci_hwport_id_t new_hwport, 
                            int llapt_locked)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *row;
  const cicp_llap_row_t *end_row;
  int rc = 0, ipif_status_before, ipif_status_after;

  ci_assert(control_plane != NULL);
  ci_assert(mibs->llap_table != NULL);

  CICP_CHECK_LOCKED(control_plane);

  ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

  if( !llapt_locked) 
    ci_verlock_write_start(&mibs->llap_table->version);

  end_row = mibs->llap_table->llap + mibs->llap_table->rows_max;
  for( row = &mibs->llap_table->llap[0]; row < end_row; ++row ) {
    if( cicp_llap_row_allocated(row) ) {
      if( (row->encapsulation.type & CICP_LLAP_TYPE_BOND) && 
          ifindex == row->ifindex )
        row->hwport = new_hwport;
      else if( row->encapsulation.type & CICP_LLAP_TYPE_VLAN ) {
        cicp_llap_row_t *vlan_row = &mibs->llap_table->llap[row->vlan_rowid];
        ci_assert(row->vlan_rowid != CICP_BOND_ROW_NEXT_BAD);
        if( vlan_row->ifindex == ifindex )
          row->hwport = new_hwport;
      }
    }
  }

  if( !llapt_locked )
    ci_verlock_write_stop(&mibs->llap_table->version);

  /* Check to see if this change should cause an ipif callback */
  ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
  if( ipif_status_before != ipif_status_after )
    cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);

  /* Not necessary: all callers do this on return:
   * cicp_fwdinfo_something_changed(control_plane);
   */

  return rc;
}



static int 
cicp_llap_update_all_hash_state(cicp_handle_t *control_plane,
                                ci_int16 bond_rowid,
                                ci_int8 hash_policy)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *row;
  const cicp_llap_row_t *end_row;

  ci_assert(control_plane != NULL);
  ci_assert(mibs->llap_table != NULL);

  CICP_CHECK_LOCKED(control_plane);

  end_row = mibs->llap_table->llap + mibs->llap_table->rows_max;
  for( row = &mibs->llap_table->llap[0]; row < end_row; ++row ) {
    if( cicp_llap_row_allocated(row) ) {
      if( (row->encapsulation.type & CICP_LLAP_TYPE_BOND) && 
          (row->bond_rowid == bond_rowid) ) {
        if( hash_policy == CICP_BOND_XMIT_POLICY_NONE )
          row->encapsulation.type &=~ CICP_LLAP_TYPE_USES_HASH;
        else
          row->encapsulation.type |= CICP_LLAP_TYPE_USES_HASH;
        if( hash_policy == CICP_BOND_XMIT_POLICY_LAYER34 )
          row->encapsulation.type |= CICP_LLAP_TYPE_XMIT_HASH_LAYER4;
        else
          row->encapsulation.type &=~ CICP_LLAP_TYPE_XMIT_HASH_LAYER4;
      }
    }
  }

  /* Not necessary: all callers do this on return:
   * cicp_fwdinfo_something_changed(control_plane);
   */

  return 0;
}



extern int cicp_llap_update_can_onload_bad_hwport(cicp_handle_t *control_plane,
                                                  ci_ifid_t ifindex,
                                                  int can_onload)
{
  cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *row;
  const cicp_llap_row_t *end_row;
  int rc = 0, ipif_status_before, ipif_status_after;

  ci_assert(mibs != NULL);
  ci_assert(mibs->llap_table != NULL);

  CICP_CHECK_LOCKED(control_plane);

  end_row = mibs->llap_table->llap + mibs->llap_table->rows_max;
  for( row = &mibs->llap_table->llap[0]; row < end_row; ++row ) {
    if( cicp_llap_row_allocated(row) ) {
      ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

      if( ifindex == row->ifindex ) {
        cicp_bond_row_t *bond_row;
        if( can_onload )
          row->encapsulation.type |= CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
        else 
          row->encapsulation.type &=~ CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
        bond_row = cicp_bond_find(mibs, ifindex);
        if( bond_row != NULL ) {
          ci_assert(bond_row->type & CICP_BOND_ROW_TYPE_MASTER);
          while( bond_row->next != CICP_BOND_ROW_NEXT_BAD ) {
            bond_row = &mibs->user.bondinfo_utable->bond[bond_row->next];
            ci_assert(bond_row->type & CICP_BOND_ROW_TYPE_SLAVE);
            if( bond_row->slave.hwport != CI_HWPORT_ID_BAD )
              oof_hwport_un_available(bond_row->slave.hwport, can_onload);
          }
        }
      }
      else if( row->encapsulation.type & CICP_LLAP_TYPE_VLAN ) {
        cicp_llap_row_t *vlan_row = &mibs->llap_table->llap[row->vlan_rowid];
        ci_assert(row->vlan_rowid != CICP_BOND_ROW_NEXT_BAD);
        if( vlan_row->ifindex == ifindex ) {
          if( can_onload )
            row->encapsulation.type |= CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
          else
            row->encapsulation.type &=~ CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT;
        }
      }

      /* Check to see if this change should cause an ipif callback */
      ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
      if( ipif_status_before != ipif_status_after )
        cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);
    }
  }

  return rc;
}

#endif


extern int 
cicp_llap_update_active_hwport(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                               ci_hwport_id_t hwport, int bond_rowid, 
                               int fatal)
{
  int rc = 0;
#if CI_CFG_TEAMING
  int change = 0;
  const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
  cicp_llap_row_t *row;
  cicp_bond_row_t *bond_row;

  ci_assert(control_plane != NULL);
  ci_assert(mibs->llap_table != NULL);

  CICP_LOCK_BEGIN(control_plane);

  row = cicp_llap_find_ifid(mibs->llap_table, ifindex);
  bond_row = &mibs->user.bondinfo_utable->bond[bond_rowid];

  if( row == NULL )
    rc = -ENODEV;
  else if( (rc = cicp_bond_check_row(mibs, &bond_row, &bond_rowid, ifindex, 
                                     CICP_BOND_ROW_TYPE_MASTER)) == 0 ) {
    if( bond_row->master.active_hwport != hwport ) {
      ci_verlock_write_start(&mibs->user.fwdinfo_utable->version);
      bond_row->master.active_hwport = hwport;
      ci_verlock_write_stop(&mibs->user.fwdinfo_utable->version);
      change = 1;
    }
    if( row->hwport != hwport || 
        row->bond_rowid != bond_rowid || 
        fatal != bond_row->master.fatal ) {
      ci_verlock_write_start(&mibs->llap_table->version);
      if( row->hwport != hwport )
        cicp_llap_update_all_hwport(control_plane, ifindex, hwport, 1);
      if( row->bond_rowid != bond_rowid )
        cicp_llap_update_all_bond_rowid(control_plane, ifindex, bond_rowid, 1);
      if( fatal != bond_row->master.fatal ) {
        cicp_llap_update_can_onload_bad_hwport(&CI_GLOBAL_CPLANE, ifindex, 
                                               !fatal);
        bond_row->master.fatal = fatal;
      }
      ci_verlock_write_stop(&mibs->llap_table->version);
      change = 1;
    }
    if( change )
      cicp_fwdinfo_something_changed(control_plane);
  }
  
  CICP_LOCK_END;
#endif
  return rc;
}



/*! Declare a new link layer access point (if it does not exist) with NIC
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_llap_set_hwport(cicp_handle_t *control_plane, ci_ifid_t ifindex,
                     ci_hwport_id_t hwport, cicp_encap_t *ref_encap)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    int rc = 0, ipif_status_before, ipif_status_after;

    if (NULL == control_plane)
        rc = EINVAL;
    else if (NULL == mibs->llap_table)
        rc = ENOMEM;
    else
    {	cicp_llap_kmib_t *llapt;
	cicp_llap_row_t *row;
	ci_mac_addr_t default_mac;
	cicpos_llap_row_t default_sync;
	
        memset(&default_mac,  0, sizeof(default_mac));
	memset(&default_sync, 0, sizeof(default_sync));

	llapt = mibs->llap_table;

	CICP_LOCK_BEGIN(control_plane);

        row = cicp_llap_find_ifid(llapt, ifindex);

        ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

        if( row == NULL ) {
          cicp_llap_rowid_t rowid;

          rc = cicpos_llap_add(llapt, &rowid, ifindex,
                               CICP_HWPORT_MAX_MTU_DEFAULT,
                               /* up */ FALSE, /* name */"", hwport,
                               &default_mac, ref_encap, &default_sync);
        } 
        else {
          ci_assert(row->hwport == CI_HWPORT_ID_BAD || 
                    row->hwport <= CI_HWPORT_ID_MAX);

          CI_VERLOCK_WRITE_BEGIN(llapt->version);

          if( row->hwport != hwport )
            row->hwport = hwport;

          if( ref_encap != NULL )
            memcpy(&row->encapsulation, ref_encap, sizeof(row->encapsulation));

          CI_VERLOCK_WRITE_END(llapt->version);
        }

        /* Check to see if this change should cause an ipif callback */
        ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
        if( ipif_status_before != ipif_status_after )
          cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);

	CICP_LOCK_END;
    }
    
    OO_DEBUG_ARP(
	if (0 != rc)
	    DPRINTF(CODEID": declaring access point failed rc=%d", rc);
    );
    return rc;
}





/*! Ammend a currently existing access point to a given set of IP addresses
 *
 * \param llapt           the link layer access point table
 * \param ifindex         O/S index of this layer 2 interface
 * \param mtu             Maximum Transmit Unit set for this i/f
 * \param up              if true, this interface is up 
 * \param ref_mac     	  MAC address of access point
 * \param ref_sync        O/S synchronization info
 *
 * \return                FALSE iff no change was made
 *
 * This function is typically called in response to information found in the
 * O/S copy of the routing MIB.  
 *
 * This function requires the tables to be locked but does not itself lock
 * them.
 *
 * NB: also need to call cicpos_fwdinfo_llap_import when this returns TRUE
 * NB2: hwport and encap can't be updated via cicpos_llap_update, use
 * remove/add instead.
 */
static int /* bool */
cicpos_llap_update(cicp_llap_kmib_t *llapt, 
                   cicp_llap_rowid_t rowid,
                   ci_mtu_t mtu,
                   ci_uint8 /* bool */ up,
                   char *name,
                   ci_mac_addr_t *ref_mac,
		   cicpos_llap_row_t *ref_sync)
{   int /* bool */ change = FALSE;
    cicp_llap_row_t *newrow = &llapt->llap[rowid];
    
    ci_assert(NULL != llapt);
    
    /* RFC 1191: A host MUST never reduce its estimate of the Path MTU
     * below 68 octets.
     * Linux uses 68 in inetdev_valid_mtu(). */
    if (mtu < 68)
    {   up = FALSE;
        mtu = 68;
    }

    if (newrow->mtu != mtu)
    {   change = TRUE;
	newrow->mtu = mtu;
	ci_assert(newrow->hwport == CI_HWPORT_ID_BAD || mtu > 0);
    }
    if (newrow->up != up)
    {   change = TRUE;
	newrow->up = up;
    }
    if (strncmp(newrow->name, name, CICP_LLAP_NAME_MAX+1) != 0)
    {   change = TRUE;
	memcpy(newrow->name, name, CICP_LLAP_NAME_MAX+1);
    }
    if (!CI_MAC_ADDR_EQ(&newrow->mac, ref_mac))
    {   change = TRUE;
	  CI_MAC_ADDR_SET(&newrow->mac, ref_mac);
    }
    if (ref_sync != NULL &&
	0 != memcmp(&newrow->sync, ref_sync, sizeof(newrow->sync)))
    {   change = TRUE;
	memcpy(&newrow->sync, ref_sync, sizeof(newrow->sync));
    }
    return change;
}






/*! Import data into the link layer access point cache
 *  - see driver header for documentation
 */
extern int /* rc */
cicpos_llap_import(cicp_handle_t *control_plane, 
		   cicp_llap_rowid_t *out_rowid,
		   ci_ifid_t ifindex,
		   ci_mtu_t mtu,
		   ci_uint8 /* bool */ up,
		   cicp_llap_type_t type,
		   char *name,
		   ci_mac_addr_t *ref_mac,
		   cicpos_llap_row_t *ref_sync)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_llap_kmib_t *llapt;
    cicp_llap_rowid_t rowid;
    int rc = 0, ipif_status_before, ipif_status_after;
    ci_mac_addr_t empty_mac;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->llap_table);

    if( ref_mac == NULL ) {
      CI_MAC_ADDR_SET_EMPTY(&empty_mac);
      ref_mac = &empty_mac;
    }

    llapt = mibs->llap_table;

    CICP_LOCK_BEGIN(control_plane)
    
        rowid = cicpos_llap_find(llapt, ifindex);

        ipif_status_before = cicp_check_ipif_callback(mibs, ifindex);

	if( CICP_LLAP_ROWID_BAD == rowid ) {
          cicp_encap_t encap;
          if( type == CICP_LLAP_TYPE_LOOP )
            encap.type = CICP_LLAP_TYPE_LOOP;
          else
            encap.type = CICP_LLAP_TYPE_NONE;
          encap.vlan_id = 0;
          rc = cicpos_llap_add(llapt, &rowid, ifindex, mtu, up, name, 
                               CI_HWPORT_ID_BAD, ref_mac, &encap, ref_sync);
          OO_DEBUG_ARP(if (0 != rc)
                         DPRINTF(CODEID": adding access point failed rc=%d",
                                 rc););
          if( 0 == rc )
            cicpos_fwdinfo_llap_import(control_plane, ifindex, up, mtu,
                                       /*old mac*/NULL, ref_mac);
	} else
	{   ci_mac_addr_t old_mac;

	    memcpy(&old_mac, &llapt->llap[rowid].mac, sizeof(old_mac));
	    if (cicpos_llap_update(llapt, rowid, mtu, up, name, 
				   ref_mac, ref_sync))
		cicpos_fwdinfo_llap_import(control_plane, ifindex, up, mtu,
					   &old_mac, ref_mac);
	}

        /* Check to see if this change should cause an ipif callback */
        ipif_status_after = cicp_check_ipif_callback(mibs, ifindex);
        if( ipif_status_before != ipif_status_after )
          cicp_ipif_announce_if(control_plane, ifindex, ipif_status_after);

    CICP_LOCK_END

    if (NULL != out_rowid && rowid != CICP_LLAP_ROWID_BAD)
	*out_rowid = rowid;

    return rc;
}







/*! Import data into the link layer access point cache
 *  - see driver header for documentation
 */
extern int /* rc */
cicp_llap_import(cicp_handle_t *control_plane, 
		 cicp_llap_rowid_t *out_rowid,
		 ci_ifid_t ifindex,
		 ci_mtu_t mtu,
		 ci_uint8 /* bool */ up,
		 char *name,
		 ci_mac_addr_t *ref_mac)
{   return cicpos_llap_import(control_plane, out_rowid, ifindex, mtu, up,
                              CICP_LLAP_TYPE_NONE,
			      name, ref_mac, /*sync*/NULL);
}









/*! Delete the link layer access point row with the given interface ID
 *  - see driver header for documentation
 */
extern void
cicpos_llap_delete(cicp_handle_t *control_plane, ci_ifid_t ifindex)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_llap_kmib_t *llapt;
    cicp_llap_rowid_t rowid;
			  
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->llap_table);

    llapt = mibs->llap_table;
    rowid = cicpos_llap_find(llapt, ifindex);

    CICP_LOCK_BEGIN(control_plane)
	
	if (CICP_LLAP_ROWID_BAD != rowid)
	{
	    /* not really a lock - reversion when # rows changes */
	    cicp_llap_row_free(&llapt->llap[rowid]);
	    cicpos_llap_compress(llapt);
	    cicpos_fwdinfo_llap_import(control_plane, ifindex,
				       /*up*/FALSE, /*mtu*/0,
				       NULL, NULL);
	} else
            OO_DEBUG_FWD(ci_log("%s: LLAP not found", __FUNCTION__));

    CICP_LOCK_END
	
    return;
}









    


    




/*****************************************************************************
 *                                                                           *
 *          NIC Hardware Port MIB					     *
 *          =====================					     *
 *                                                                           *
 *****************************************************************************/








extern void
cicpos_hwport_update(cicp_handle_t *control_plane, 
                     ci_hwport_id_t hwport, ci_mtu_t max_mtu)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_hwport_kmib_t *hwportt;
    
    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->hwport_table);

    hwportt = mibs->hwport_table;
    
    CICP_LOCK_BEGIN(control_plane)
	
	hwportt->nic[hwport].max_mtu = max_mtu;

        /* update the forwarding cache correspondingly */
        cicpos_fwdinfo_hwport_update(control_plane, hwport, max_mtu);
	
    CICP_LOCK_END
	
}






extern void
cicpos_hwport_purge(cicp_handle_t *control_plane)
{   const cicp_mibs_kern_t *mibs = CICP_MIBS(control_plane);
    cicp_hwport_kmib_t *hwportt;

    ci_assert(NULL != control_plane);
    ci_assert(NULL != mibs->hwport_table);

    hwportt = mibs->hwport_table;

    /* TODO: not implemented yet */
    (void)hwportt;
}




/*****************************************************************************
 *                                                                           *
 *          Common Unix (Linux/Solaris) Synchronization Code		     *
 *          ================================================		     *
 *                                                                           *
 *****************************************************************************/

extern cicpos_parse_state_t *
cicpos_parse_state_alloc(cicp_handle_t *control_plane)
{
  cicpos_parse_state_t *session =
    (cicpos_parse_state_t *)kmalloc(sizeof(cicpos_parse_state_t), GFP_ATOMIC);

  if( session == NULL )
    return NULL;

  session->imported_route = 
    kmalloc(CI_BITSET_SIZE(CICP_MIBS(control_plane)->route_table->rows_max),
            GFP_ATOMIC);
  if( session->imported_route == NULL ) 
    goto out1;

  session->imported_ipif = 
    kmalloc(CI_BITSET_SIZE(CICP_MIBS(control_plane)->ipif_table->rows_max), 
            GFP_ATOMIC);
  if( session->imported_ipif == NULL ) 
    goto out2;

  session->imported_llap = 
    kmalloc(CI_BITSET_SIZE(CICP_MIBS(control_plane)->llap_table->rows_max),
            GFP_ATOMIC);
  if( session->imported_llap == NULL ) 
    goto out3;

  session->imported_pmtu = 
    kmalloc(CI_BITSET_SIZE(CICP_MIBS(control_plane)->pmtu_table->rows_max),
            GFP_ATOMIC);
  if( session->imported_pmtu == NULL ) 
    goto out4;

  return session;

 out4:
  kfree(session->imported_pmtu);
 out3:
  kfree(session->imported_ipif);
 out2:
  kfree(session->imported_route);
 out1:
  kfree(session);
  return NULL;
}

extern void
cicpos_parse_state_free(cicpos_parse_state_t *session)
{
  kfree(session->imported_route);
  kfree(session->imported_ipif);
  kfree(session->imported_llap);
  kfree(session->imported_pmtu);
  kfree(session);
}

extern void
cicpos_parse_init(cicpos_parse_state_t *session, cicp_handle_t *control_plane)
{
    session->control_plane = control_plane;
    session->start_timestamp = jiffies;
    ci_bitset_clear(CI_BITSET_REF(session->imported_route),
		    CICP_MIBS(control_plane)->route_table->rows_max);
    ci_bitset_clear(CI_BITSET_REF(session->imported_ipif),
		    CICP_MIBS(control_plane)->ipif_table->rows_max);
    ci_bitset_clear(CI_BITSET_REF(session->imported_llap),
		    CICP_MIBS(control_plane)->llap_table->rows_max);
    ci_bitset_clear(CI_BITSET_REF(session->imported_pmtu),
		    CICP_MIBS(control_plane)->pmtu_table->rows_max);
    session->nosort = CI_FALSE;
    IGNORE(ci_log(CODEID": parse structure given %d entries for MAC table",
	          cicp_mac_mib_rows(mact));)
}

static void
cicpos_pmtu_post_poll(cicpos_parse_state_t *session)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(session->control_plane);
  int i;
  cicp_pmtu_kmib_t *pmtu_table = mibs->pmtu_table;
  for( i = 0; i < pmtu_table->rows_max; i++ ) {
    if( cicp_pmtu_row_allocated(&pmtu_table->entries[i]) &&
        !ci_bitset_in(CI_BITSET_REF(session->imported_pmtu), i) ) {
      if( pmtu_table->entries[i].timestamp - session->start_timestamp < 0 )
        cicp_pmtu_row_free(&pmtu_table->entries[i]);
      else {
        /* make sure we have turned around: make timestamp fresh */
        pmtu_table->entries[i].timestamp = session->start_timestamp;
      }
    }
  }
}

extern void 
cicpos_route_post_poll(cicpos_parse_state_t *session)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(session->control_plane);
  cicp_fwdinfo_t *routet = mibs->user.fwdinfo_utable;
  cicp_route_kmib_t *kroutet = mibs->route_table;
  cicp_route_rowid_t rowid;

  CICP_LOCK_BEGIN(session->control_plane);

  cicpos_pmtu_post_poll(session);

  if (!session->nosort) {
    /* May be, we added some routes with nosort and removed nosort
     * afterwards. In this case, we should sort all routes */
    goto sort;
  }

  for (rowid = 0; 
       rowid < kroutet->rows_max && 
       cicp_fwd_row_allocated(&routet->path[rowid]); 
       rowid++) {
    if (!ci_bitset_in(CI_BITSET_REF(session->imported_route), rowid)) {
      cicp_fwd_row_free(&routet->path[rowid]);
    }
  }
  (void)cicpos_route_compress(routet, kroutet, /*changed*/TRUE);
sort:
  (void)cicp_route_sort(routet, kroutet, /*changed*/TRUE);
  CICP_LOCK_END;
}

extern void 
cicpos_llap_post_poll(cicpos_parse_state_t *session)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(session->control_plane);
  cicp_llap_kmib_t *llapt = mibs->llap_table;
  cicp_ipif_rowid_t rowid;

  if (!session->nosort)
    return;

  CICP_LOCK_BEGIN(session->control_plane);

  for( rowid = 0; 
       rowid < llapt->rows_max && 
       cicp_llap_row_allocated(&llapt->llap[rowid]); 
       rowid++ ) {
    if( !ci_bitset_in(CI_BITSET_REF(session->imported_llap), rowid) ) 
      cicp_llap_row_free(&llapt->llap[rowid]);
  }
  (void)cicpos_llap_compress(llapt);

  CICP_LOCK_END;
}


extern void 
cicpos_ipif_post_poll(cicpos_parse_state_t *session)
{
  const cicp_mibs_kern_t *mibs = CICP_MIBS(session->control_plane);
  cicp_ipif_kmib_t *ipift = mibs->ipif_table;
  cicp_ipif_rowid_t rowid;

  if (!session->nosort)
    return;

  CICP_LOCK_BEGIN(session->control_plane);

  for (rowid = 0; 
       rowid < ipift->rows_max && 
       cicp_ipif_row_allocated(&ipift->ipif[rowid]); 
       rowid++) {
    if (!ci_bitset_in(CI_BITSET_REF(session->imported_ipif), rowid)) {
      cicp_ipif_row_free(&ipift->ipif[rowid]);
    }
  }
  (void)cicpos_ipif_compress(ipift);

   CICP_LOCK_END;
}






