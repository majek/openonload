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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane Linux specific kernel code
**   \date  2005/07/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is relevant only to the kernel - it is not visible
 *  from the user-mode libraries.  This code is Linux specific.
 *
 *  This code could be split among a number of different files but is divided
 *  instead into the following sections:
 *
 *      PROT - Functions to support a Linux interface for protocol support
 *      PROC - Functions on the /proc filing system
 *      SYN  - Functions on local MIB caches required for O/S synchronization
 *
 *  (you can search for these key words in the text to find the sections)
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
 */




/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/


#include "onload_internal.h"
#include <onload/nic.h>
#include <onload/debug.h>
#include <net/arp.h>
#include <linux/inetdevice.h>
/* Compat just for RHEL4 clock_t_to_jiffies() */
#include <linux/times.h>
#include "../linux_resource/kernel_compat.h"
#include <onload/tcp_driver.h> /* for CI_GLOBAL_WORKQUEUE */
#include <onload/cplane_ops.h>
#include <onload/cplane_prot.h>
#include <onload/linux_onload_internal.h>



#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

/* Buffer size for netlink messages.  Largest tables are neighbour and
 * route cache, and it will be nice to fit these tables into the buffer. */
#define NL_BUFSIZE 16384



/*****************************************************************************
 *                                                                           *
 *          Configuration                                                    *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/




#define CICPOS_USE_NETLINK 1



/* /proc */

#define CICPOS_PROCFS 1

#define CICPOS_PROCFS_FILE_HWPORT  "mib-hwport"
#define CICPOS_PROCFS_FILE_LLAP    "mib-llap"
#define CICPOS_PROCFS_FILE_MAC     "mib-mac"
#define CICPOS_PROCFS_FILE_IPIF    "mib-ipif"
#define CICPOS_PROCFS_FILE_FWDINFO "mib-fwd"
#define CICPOS_PROCFS_FILE_BONDINFO "mib-bond"
#define CICPOS_PROCFS_FILE_PMTU    "mib-pmtu"
#define CICPOS_PROCFS_FILE_BLACK_WHITE_LIST "intf-black-white-list"



/* synchronization */

/*!
 *  Time (in jiffies) between netlink updates polling. IP-MAC table (ARP)
 *  garbage collection runs at half the rate (every second) and a complete
 *  tables dumps is triggered on every twentieth iteration (every 10 seconds).
 *  A fast mode also exists immediatelly after driver load but before a
 *  complete tables dump is received where the timer is run at 10 times the
 *  speed (50ms).
 */
#define CICPOS_SCAN_INTERVAL (HZ/2)


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


/* #define DEBUGNETLINK   DO */
/* #define DEBUGINJECT    DO */

#ifdef NDEBUG
#undef DEBUGNETLINK
#undef DEBUGINJECT
#endif


#ifndef DEBUGNETLINK
#define DEBUGNETLINK   IGNORE
#endif
#ifndef DEBUGINJECT
#define DEBUGINJECT    IGNORE
#endif

#define DPRINTF ci_log
#define CICP_LOG LOG_ARP

#define CODEID "cplane sync"




/*****************************************************************************
 *                                                                           *
 *          Deferred packet transmission                                     *
 *          ============================                                     *
 *                                                                           *
 *****************************************************************************/


static inline struct cicppl_instance* cicppl_by_netif(ci_netif *netif)
{
  return &netif->cplane->cppl;
}


/**
 * Allocates an ARP module ip buffer and copies the IP pkt passed by the
 * application into the ARP module buffer. If the packet is segmented, it
 * flattens it because the segments don't make sense outside of the context
 * of the application that owns them.
 *
 * NB: the ARP table MUST NOT be locked
 */
static int 
cicppl_ip_pkt_handover(ci_netif *netif, oo_pkt_p src_pktid)
{
  struct cicp_bufpool_pkt* dst_pkt;
  int dst_pktid;
  int rc;
  struct cicppl_instance* cppl = cicppl_by_netif(netif);

  ci_assert(netif);
  ASSERT_VALID_PKT(netif, PKT_CHK(netif, src_pktid));

  /* allocate a packet to hold a copy of the ip packet passed to us */
  spin_lock_bh(&cppl->lock);
  dst_pktid = cicppl_pktbuf_alloc(cppl->pktpool);
  spin_unlock_bh(&cppl->lock);
  if(dst_pktid < 0) {
    return -ENOBUFS;
  }
  ci_assert(cicppl_pktbuf_is_valid_id(cppl->pktpool, dst_pktid));

  /* copy packet from the netif to arp table */
  dst_pkt = cicppl_pktbuf_pkt(cppl->pktpool, dst_pktid);
  rc = cicppl_ip_pkt_flatten_copy(netif, src_pktid, dst_pkt);
  if (rc < 0) {
    spin_lock_bh(&cppl->lock);
    cicppl_pktbuf_free(cppl->pktpool, dst_pktid);
    spin_unlock_bh(&cppl->lock);
    return rc;
  }

  return dst_pktid;
}


#ifndef NDEBUG
static void
cicppl_mac_defer_send_failed(ci_ip4_hdr *iph, ci_ip_addr_t dst, int err)
{
  ci_log(CODEID": IP "CI_IP_PRINTF_FORMAT"->"CI_IP_PRINTF_FORMAT
         " %s pkt handover failed, rc %d",
         CI_IP_PRINTF_ARGS(&iph->ip_saddr_be32),
         CI_IP_PRINTF_ARGS(&dst),\
         iph->ip_protocol == IPPROTO_TCP ? "TCP" : "UDP",
         err);
}
#endif

/**
 * Queue ARP packet request and the ip packet that triggered it.
 * Note1: arptbl lock MUST NOT be locked!
 * Note2: netif  lock MUST     be locked!
 */
extern int /* bool */
cicppl_mac_defer_send(ci_netif *netif, int *ref_os_rc,
		      ci_ip_addr_t ip, oo_pkt_p ip_pktid, ci_ifid_t ifindex)
{ int pendable_pktid;
  
  OO_DEBUG_ARP(ci_log(CODEID": ni %p (ID:%d) ip "CI_IP_PRINTF_FORMAT
                      " pkt ID %d ifindex %d",
                      netif, NI_ID(netif), CI_IP_PRINTF_ARGS(&ip), 
                      OO_PP_FMT(ip_pktid), ifindex));

  ci_assert(ci_netif_is_locked(netif));
  ASSERT_VALID_PKT(netif, PKT_CHK(netif, ip_pktid));

  /* if weren't given a packet there is nothing we can do */
  if (OO_PP_IS_NULL(ip_pktid))
  {   *ref_os_rc = -EINVAL;
      return FALSE;
  } else {
  
    /* copy IP pkt before locking table because copy of segments can block */
    pendable_pktid = cicppl_ip_pkt_handover(netif, ip_pktid);
    if (pendable_pktid < 0) {
      LOG_U(
        static ci_uint32 last_dst = 0;
        ci_ip4_hdr *iph = oo_tx_ip_hdr(PKT(netif, ip_pktid));
        if( last_dst != ip ) {
          cicppl_mac_defer_send_failed(iph, ip, pendable_pktid);
          last_dst = ip;
        }
        else {
          CI_LOG_LIMITED(cicppl_mac_defer_send_failed(iph, ip,
                                                      pendable_pktid));
        }
        );
      *ref_os_rc = pendable_pktid;
      return FALSE;
    } else
    {
      struct cicppl_instance *cppl = cicppl_by_netif(netif);
      (void) cppl;
      
      /* from this point onwards, pendable_pktid is an ARP buffer ID */
      ci_assert(cicppl_pktbuf_is_valid_id(cppl->pktpool, pendable_pktid));

      /* now we have a cicp_bufpool_t buffer ID we can call this: */
      *ref_os_rc = cicpplos_pktbuf_defer_send(netif->cplane, ip,
					      pendable_pktid, ifindex);

      return (*ref_os_rc == 0);
    }
  }
}



