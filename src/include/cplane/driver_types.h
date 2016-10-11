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

/* Cplane types used outside of the cplane driver itself */
#ifndef __CPLANE_DRIVER_TYPES_H__
#define __CPLANE_DRIVER_TYPES_H__

#include <cplane/contig_shmbuf.h>
#include <cplane/shared_types.h>

/*----------------------------------------------------------------------------
 * OS lock for control plane
 *---------------------------------------------------------------------------*/
typedef void* oo_os_lock_t;


/*----------------------------------------------------------------------------
 * Control Plane kernel-visible information 
 *---------------------------------------------------------------------------*/

typedef ci_contig_shmbuf_t cicp_mib_shared_t;

/*! Type for kernel driver data required for access through a netif */
struct cicp_mibs_kern_s
{   cicp_ul_mibs_t      user;		  /*< user-visible shared MIB info */
    cicp_mib_shared_t   mac_shared;       /*< shared area holding mac_utable */
    cicp_mib_shared_t   fwdinfo_shared;   /*< shared area for fwdinfo_utable */
    cicp_mib_shared_t   llapinfo_shared;  /*< shared area for llapinfo_utable */
    cicp_mib_shared_t   bondinfo_shared;  /*< shared area for bondinfo_utable */
    oo_os_lock_t        lock;             /*< shared by all kernel MIBs */
    struct cicp_mac_kmib_s    *mac_table;        /*< kernel-visible part of mac MIB */
    struct cicp_ipif_kmib_s   *ipif_table;       /*< IP interfaces MIB cache */
    struct cicp_pmtu_kmib_s   *pmtu_table;       /*< PMTU cache */
    struct cicp_stat_s        *stat;             /*< control Plane Statistics */
    

    struct ci_team_control *team;         /*< object providing team support */

    struct cicpos_callback_registration_s  *callbacks;
                        /*< callbacks to be called when something changed */
} /* cicp_mibs_kern_t */;

/* typedef struct cicp_mibs_kern_s cicp_handle_t; */


/*! Type of callback function when ipif table is updated
 *
 * \param onloadable_port non-zero if port for this address is accessible from 
 *                        this stack
 * \param net_ip          network own address 
 * \param net_ipset       network IP address set specification (e.g. netmask)
 * \param net_bcast       network broadcast address
 * \param arg             registration parameter
 *
 * Functions of this type are called back after registration when the IP
 * interfaces table has a row added or deleted.
 *
 * When added \c net_ip and \c net_ipset identify the IP address that is
 * being added, and when deleted they identify the one being deleted.
 *

 */
typedef void
cicpos_ipif_event_fn_t(ci_ip_addr_net_t net_ip, ci_ip_addrset_t  net_ipset,
		       ci_ip_addr_net_t net_bcast, ci_ifid_t ifindex, 
                       void *arg);

typedef void
cicpos_llap_event_fn_t(ci_ifid_t ifindex, void *arg);
typedef void
cicpos_hwport_event_fn_t(ci_hwport_id_t hwport, int available, void *arg);

#endif /* __CPLANE_DRIVER_TYPES_H__ */
