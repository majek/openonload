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
#include <onload/cplane.h>
#include <onload/debug.h>
#include <ci/internal/cplane_handle.h>
#include <net/arp.h>
#include <linux/inetdevice.h>
/* Compat just for RHEL4 clock_t_to_jiffies() */
#include <linux/times.h>



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




#define CICPOS_USE_NETLINK 1



/* /proc */

#define CICPOS_PROCFS 1

#define CICPOS_PROCFS_FILE_HWPORT  "mib-hwport"
#define CICPOS_PROCFS_FILE_LLAP    "mib-llap"
#define CICPOS_PROCFS_FILE_MAC     "mib-mac"
#define CICPOS_PROCFS_FILE_IPIF    "mib-ipif"
#define CICPOS_PROCFS_FILE_FWDINFO "mib-fwd"
#define CICPOS_PROCFS_FILE_BONDINFO "mib-bond"



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
 *          Kernel versioning                                                *
 *          =================						     *
 *                                                                           *
 *****************************************************************************/

#ifndef NDA_RTA
# define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef IFLA_RTA
# define IFLA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif

#ifndef IFA_RTA
# define IFA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif





/*****************************************************************************
 *****************************************************************************
 *									     *
 *          PROT - Raw Socket Synchronization				     *
 *          =================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/








static struct socket *cicp_raw_sock;
struct socket *cicp_bond_raw_sock;





/*! create the raw socket */
int cicp_raw_sock_ctor(struct socket **raw_sock)
{
  int rc = sock_create(PF_INET, SOCK_RAW, IPPROTO_RAW, raw_sock);
  if (CI_UNLIKELY(rc < 0)) {
    ci_log("%s: failed to create the raw socket, rc=%d", __FUNCTION__, rc);
    return rc;
  }
  
  if (CI_UNLIKELY((*raw_sock)->sk == 0)) {
    ci_log("ERROR:%s: cicp_raw_sock->sk is zero!", __FUNCTION__);
    sock_release(*raw_sock);
    return -EINVAL;
  }
  
  (*raw_sock)->sk->sk_allocation = GFP_ATOMIC;
  return 0;
}





/*! destroy the raw socket */
void cicp_raw_sock_dtor(struct socket *raw_sock)
{
  sock_release(raw_sock);
}





int cicp_raw_sock_send(struct socket *raw_sock, ci_ip_addr_t ip_be32, 
                       const char *buf, unsigned int size)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  struct sockaddr_in addr;
  int rc;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = ip_be32;

  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = MSG_DONTWAIT;

  iov.iov_base=(void *)buf;
  iov.iov_len=size;

  oldfs = get_fs(); 
  set_fs(KERNEL_DS);
  rc = sock_sendmsg(raw_sock, &msg, size);
  set_fs(oldfs);

  return rc;
}





/*****************************************************************************
 *                                                                           *
 *          Deferred packet transmission                                     *
 *          ============================                                     *
 *                                                                           *
 *****************************************************************************/





static cicp_bufpool_t *cicppl_pktpool = NULL;





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
  ci_ip_pkt_fmt *dst_pkt;
  int dst_pktid;
  int rc;

  ci_assert(netif);
  ASSERT_VALID_PKT(netif, PKT_CHK(netif, src_pktid));

  /* allocate a packet to hold a copy of the ip packet passed to us */
  CICP_BUFPOOL_LOCK(cicppl_pktpool,
	            dst_pktid = cicppl_pktbuf_alloc(cicppl_pktpool));
  if(dst_pktid < 0) {
    return -ENOBUFS;
  }
  ci_assert(cicppl_pktbuf_is_valid_id(dst_pktid));

  /* copy packet from the netif to arp table */
  dst_pkt = cicppl_pktbuf_pkt(cicppl_pktpool, dst_pktid);
  rc = cicppl_ip_pkt_flatten_copy(netif, src_pktid, dst_pkt);
  if (rc < 0) {
    CICP_BUFPOOL_LOCK(cicppl_pktpool,
        	      cicppl_pktbuf_free(cicppl_pktpool, dst_pktid));
    return rc;
  }

  return dst_pktid;
}


int
cicp_raw_ip_send(ci_ip4_hdr* ip)
{
  int ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  void* ip_data = (char*) ip + CI_IP4_IHL(ip);
  ci_tcp_hdr* tcp;
  ci_udp_hdr* udp;

  switch( ip->ip_protocol ) {
  case IPPROTO_TCP:
    ci_assert_equal(ip->ip_frag_off_be16, CI_IP4_FRAG_DONT);
    tcp = ip_data;
    tcp->tcp_check_be16 = ci_tcp_checksum(ip, tcp, CI_TCP_PAYLOAD(tcp));
    break;
  case IPPROTO_UDP:
  {
    ci_iovec iov;
    /* In case of fragmented UDP packet we have already calculated checksum */
    if( ip->ip_frag_off_be16 & ~CI_IP4_FRAG_DONT )
      break;
    udp = ip_data;
    iov.iov_base = CI_UDP_PAYLOAD(udp);
    iov.iov_len = CI_BSWAP_BE16(ip->ip_tot_len_be16) - CI_IP4_IHL(ip) -
        sizeof(ci_udp_hdr);
    udp->udp_check_be16 = ci_udp_checksum(ip, udp, &iov, 1);
    break;
  }
  }
  return cicp_raw_sock_send(cicp_raw_sock, ip->ip_daddr_be32, 
                            (char *)ip, ip_len);
}


struct cicp_raw_sock_work_parcel {
  ci_workitem_t wqi;
  int pktid;
  const cicp_handle_t *control_plane;
};


static void
cicppl_arp_pkt_tx_queue(void *context)
{
  struct cicp_raw_sock_work_parcel *wp = context;
  ci_ip_pkt_fmt *pkt;
  ci_ip4_hdr* ip;
  int rc;

  /* Now that we use raw sockets, we don't support sending an ARP requests
   * if the IP packet that caused the transaction isn't given */
  if (wp->pktid < 0) return;
  
  ci_assert(cicppl_pktbuf_is_valid_id(wp->pktid));

  pkt = cicppl_pktbuf_pkt(cicppl_pktpool, wp->pktid);
  if (CI_UNLIKELY(pkt == 0)) {
    ci_log("%s: BAD packet %d", __FUNCTION__, wp->pktid);
    return;
  }
  ip = oo_tx_ip_hdr(pkt);

  ci_assert_equal(pkt->n_buffers, 1);
  ci_assert_gt(pkt->buf_len, ETH_HLEN);

  OO_DEBUG_ARP(ci_log("%s: id=%d, mac=" CI_MAC_PRINTF_FORMAT,
                  __FUNCTION__, wp->pktid,
                  CI_MAC_PRINTF_ARGS(oo_ether_dhost(pkt))));

  rc = cicp_raw_ip_send(ip);
  OO_DEBUG_ARP(ci_log("%s: send packet to "CI_IP_PRINTF_FORMAT" via raw "
                      "socket, rc=%d", __FUNCTION__,
                      CI_IP_PRINTF_ARGS(&ip->ip_daddr_be32), rc));
  if (CI_UNLIKELY(rc < 0)) {
    /* NB: we have not got a writeable pointer to the control plane -
           so we shouldn't really increment the statistics in it.
	   We will anyway though.
    */
    CICP_STAT_INC_DROPPED_IP((cicp_handle_t *)wp->control_plane);
    OO_DEBUG_ARP(ci_log("%s: failed to queue packet, rc=%d", __FUNCTION__, rc));
  }

  /* release the ARP module buffer */
  CICP_BUFPOOL_LOCK(cicppl_pktpool,
	            cicppl_pktbuf_free(cicppl_pktpool, wp->pktid));

  /* free the work parcel */
  ci_free(wp);
}


/*! Request IP resolution and queue the ip packet that triggered it
 *  See protocol header for the definition of this function
 *
 *  The supplied buffer ID must be one managed by a cicp_bufpool_t.
 *
 *  The control plane must not be locked when calling this function.
 */
extern int /*rc*/
cicpplos_pktbuf_defer_send(const cicp_handle_t *control_plane,
			   ci_ip_addr_t ip, int pendable_pktid)
/* schedule a workqueue task to send IP packet using the raw socket */
{
  struct cicp_raw_sock_work_parcel *wp = ci_atomic_alloc(sizeof(*wp));
  
  if (CI_LIKELY(wp != NULL)) {
    wp->pktid = pendable_pktid;
    wp->control_plane = control_plane;
    ci_workitem_init(&wp->wqi, cicppl_arp_pkt_tx_queue, wp);
    ci_verify(ci_workqueue_add(&CI_GLOBAL_WORKQUEUE, &wp->wqi) == 0);
    return 0;
  } else {
    return -ENOMEM;
  } 
}



/**
 * Queue ARP packet request and the ip packet that triggered it.
 * Note1: arptbl lock MUST NOT be locked!
 * Note2: netif  lock MUST     be locked!
 */
extern int /* bool */
cicppl_mac_defer_send(ci_netif *netif, int *ref_os_rc,
		      ci_ip_addr_t ip, oo_pkt_p ip_pktid)
{ int pendable_pktid;
  
  OO_DEBUG_ARP(ci_log(CODEID": ni %p (ID:%d) ip "CI_IP_PRINTF_FORMAT" pkt ID %d",
                      netif, NI_ID(netif), CI_IP_PRINTF_ARGS(&ip), 
                      OO_PP_FMT(ip_pktid)));

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
          ci_ip4_hdr *iph = oo_tx_ip_hdr(PKT(netif, ip_pktid));
          ci_log(CODEID": IP "CI_IP_PRINTF_FORMAT"->"CI_IP_PRINTF_FORMAT
                   " %s pkt handover failed, rc %d",
                   CI_IP_PRINTF_ARGS(&iph->ip_saddr_be32),
                   CI_IP_PRINTF_ARGS(&ip),
	           iph->ip_protocol == IPPROTO_TCP ? "TCP" : "UDP",
                   pendable_pktid);
        );
      *ref_os_rc = pendable_pktid;
      return FALSE;
    } else
    {
      cicp_handle_t *control_plane = CICP_HANDLE(netif);
      
      /* from this point onwards, pendable_pktid is an ARP buffer ID */
      ci_assert(cicppl_pktbuf_is_valid_id(pendable_pktid));

      /* now we have a cicp_bufpool_t buffer ID we can call this: */
      *ref_os_rc = cicpplos_pktbuf_defer_send(control_plane, ip,
					      pendable_pktid);

      return (*ref_os_rc == 0);
    }
  }
}







/*****************************************************************************
 *                                                                           *
 *          O/S-specific Synchronization Overall Operation                   *
 *          ==============================================                   *
 *                                                                           *
 *****************************************************************************/






/*! Initialize any driver-global O/S specific protocol control plane state */
extern int /* rc */
cicpplos_ctor(cicp_mibs_kern_t *control_plane)
{  
  int rc;
    
  /* construct ARP table buffers (event queue unused in Linux) */
  rc = cicppl_pktbuf_ctor(&cicppl_pktpool, /*evq*/NULL);
  if (CI_UNLIKELY(rc < 0)) {
    ci_log(CODEID": ERROR - couldn't construct ARP table buffers, rc=%d",
           -rc);
    return rc;
  } 

  /* construct raw socket */
  if (CI_UNLIKELY((rc = cicp_raw_sock_ctor(&cicp_raw_sock)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct raw socket module, rc=%d",
           -rc);
    cicppl_pktbuf_dtor(&cicppl_pktpool);
    return rc;
  } 
  
  /* construct raw socket */
  if (CI_UNLIKELY((rc = cicp_raw_sock_ctor(&cicp_bond_raw_sock)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct raw socket module, rc=%d",
           -rc);
    cicp_raw_sock_dtor(cicp_raw_sock);
    cicppl_pktbuf_dtor(&cicppl_pktpool);
    return rc;
  } 

  return 0;
}



void cicpos_arp_stale_update(ci_ip_addr_t dst, ci_ifid_t ifindex, int confirm)
{
  struct net_device *dev;
  struct neighbour *neigh;

  dev = dev_get_by_index(&init_net, ifindex);

  if( dev == NULL )
    return;
  neigh = neigh_lookup(&arp_tbl, &dst, dev);
  if( neigh == NULL ) {
    dev_put(dev);
    return;
  }
  /*ci_log("%s: ifindex %d ip "CI_IP_PRINTF_FORMAT" mac "
         CI_MAC_PRINTF_FORMAT" confirm %d state %x "
         "jiffies-neigh->confirmed=%ld reachable_time=%d/%d",
         __func__, ifindex, CI_IP_PRINTF_ARGS(&dst),
         CI_MAC_PRINTF_ARGS(neigh->ha), confirm, neigh->nud_state,
         jiffies - neigh->confirmed,
         arp_tbl.parms.reachable_time, neigh->parms->reachable_time);*/
  if( confirm) {
    if( neigh->nud_state == NUD_STALE)
      neigh_update(neigh, NULL, NUD_REACHABLE, NEIGH_UPDATE_F_ADMIN);
    else
      neigh_confirm(neigh);
  }
  else if (!confirm && neigh->nud_state == NUD_STALE ) {
    arp_send(ARPOP_REQUEST, ETH_P_ARP, dst, dev,
             inet_select_addr(dev, dst, RT_SCOPE_LINK),
             neigh->ha, dev->dev_addr, NULL);
    neigh_update(neigh, NULL, NUD_DELAY, NEIGH_UPDATE_F_ADMIN);
  }
  neigh_release(neigh);
  dev_put(dev);
}



/*! Finalize any driver-global O/S specific protocol control plane state */
extern void
cicpplos_dtor(cicp_mibs_kern_t *control_plane)
{   
  cicp_raw_sock_dtor(cicp_bond_raw_sock);
  cicp_raw_sock_dtor(cicp_raw_sock);
  cicppl_pktbuf_dtor(&cicppl_pktpool);
}







/*****************************************************************************
 *****************************************************************************
 *									     *
 *          PROC - /proc Filing System Support				     *
 *          ===================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/







/* PROCFS read functions
   =====================

   [This is based on a quote from
       http://kernelnewbies.org/documents/kdoc/procfs-guide/userland.html
    which I have made less ambiguous]

   The read function is a call back function that allows userland processes to
   read data from the kernel. The read function should have the following
   format:

       int read_func(char *buffer, char **out_mybuffer, off_t file_offset,
                     int buffer_size, int *ref_file_eof, void* data);

   The read function should write its information into the buffer. For proper
   use, the function should start writing from byte file_offset in the notional
   file that is being read and should write at most buffer_size bytes, but
   because most read functions are quite simple and only return a small amount
   of information, these two parameters are often ignored (this breaks pagers
   like more and less, but cat still works).

   If the file_offset and buffer_size parameters are properly used, eof should
   be used to signal that the end of the file has been reached by writing 1 to
   the memory location ref_file_eof points to once the last buffer of data has
   been provided.  (Otherwise only a single buffer should be generated by
   always setting *file_eof to 1.)

   The parameter out_mybuffer points to buffer on entry and represents the
   location where read data is expected to be found.  In principal file data
   can be written not to buffer but to an alternative (e.g. a static) and
   out_mybuffer can be updated to point at this buffer.
   
   The data parameter is set by create_proc_read_entry(..., data) and can be
   used to distinguish which of several such entries this call is being used to
   service (so that we can use a single call back function for several files).
   [the mechanism passing this to the read functions does not always seem to
   work]

   The read_func function must return the number of bytes written into the
   buffer.

   Arguments
   =========
   1. The buffer where the data is to be inserted, if 
      you decide to use it.
   2. A pointer to a pointer to characters. This is 
      useful if you don't want to use the buffer 
      allocated by the kernel.
   3. The current position in the file. 
   4. The size of the buffer in the first argument.  
   5. create_proc_read_entry() argument
*/





#if CICPOS_PROCFS





#define procfs_control_plane(caller_info) (&CI_GLOBAL_CPLANE)





/**
 * Returns a textual description of the value of
 * rtm_scope field of struct rtmsg.
 */
static const char*
ci_route_scope_str(int scope) {
  switch(scope) {
    case RT_SCOPE_UNIVERSE: return "univ";
    case RT_SCOPE_SITE:     return "site";
    case RT_SCOPE_LINK:     return "link";
    case RT_SCOPE_HOST:     return "host";
    case RT_SCOPE_NOWHERE:  return "nwhr";
    default:                return "<other>";
  }
}


extern int 
cicp_stat_read_proc(char *buf, char **start, off_t offset, int count,
		    int *eof, void *caller_info)
{   int len=0;
    cicp_stat_t *statp = &(procfs_control_plane(caller_info)->stat);
    ci_assert(statp);

    (void)start;       /* unused */
    (void)caller_info; /* unused */

    if (offset != 0)
	buf[0]='\0';
    else
    {
#define CICP_READ_PROC_PRINT_CTR(counter) \
  len += snprintf(buf+len, count-len, "%14s = %u\n", #counter, statp->counter)
#define CICP_READ_PROC_PRINT_TIME(timer) \
  len += snprintf(buf+len, count-len, "%17s = %u\n", #timer, statp->timer)
	/* using snprintf instead of sprintf will fix bug1584 */

	/* Dump the counters */
	CICP_READ_PROC_PRINT_CTR(dropped_ip);
	CICP_READ_PROC_PRINT_CTR(tbl_full);
	CICP_READ_PROC_PRINT_CTR(tbl_clashes);
	CICP_READ_PROC_PRINT_CTR(unsupported);
	CICP_READ_PROC_PRINT_CTR(pkt_reject);
	CICP_READ_PROC_PRINT_CTR(nl_msg_reject);
	CICP_READ_PROC_PRINT_CTR(retrans);
	CICP_READ_PROC_PRINT_CTR(timeouts);
	CICP_READ_PROC_PRINT_CTR(req_sent);
	CICP_READ_PROC_PRINT_CTR(req_recv);
	CICP_READ_PROC_PRINT_CTR(repl_recv);
	CICP_READ_PROC_PRINT_CTR(reinforcements);
	CICP_READ_PROC_PRINT_CTR(fifo_overflow);
	CICP_READ_PROC_PRINT_CTR(dl_c2n_tx_err);
	CICP_READ_PROC_PRINT_CTR(other_errors);
	CICP_READ_PROC_PRINT_TIME(last_poll_bgn);
	CICP_READ_PROC_PRINT_TIME(last_poll_end);
	CICP_READ_PROC_PRINT_TIME(pkt_last_recv);
	len += snprintf(buf+len, count-len, "%17s = %lu (%dHz)\n",
			"Time Now", jiffies, HZ);
    }    
    return strlen(buf);
}





static int
cicpos_hwport_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                   void *caller_info)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);
    const cicp_hwport_kmib_t *hwportt = control_plane->hwport_table;
    int len = 0;

    (void)start;       /* unused */
    (void)caller_info; /* unused */

    if (offset != 0)
	buf[0]='\0';
    else
    {
	if (NULL == hwportt)
	    len += snprintf(buf+len, bufsz-len,
			    "hardware port table unallocated\n");
	else
	{   int n = 0;
	    int nicid;

	    for (nicid = 0; nicid <= CI_HWPORT_ID_MAX; nicid++)
	    {   const cicp_hwdev_row_t *port_row = &hwportt->nic[nicid];
		const cicp_hwport_row_t *row = &port_row->port;

		if (cicp_hwport_row_allocated(row) && len < bufsz)
		{   CICP_LOCK_BEGIN(control_plane)
			/* better to use a read lock really */
			len += snprintf(buf+len, bufsz-len,
					"nic %02d: max mtu %d\n",
					nicid, row->max_mtu);
			CICP_LOCK_END
			n++;
		}
	    }

	    if (len < bufsz)
		len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n",
                                n, CI_HWPORT_ID_MAX+1);
	}
    }
    *eof = TRUE;
    buf[bufsz-2]='\n'; /* end neatly even if we overran */
    buf[bufsz-1]='\0';
    return strlen(buf);
}





static int
cicpos_llap_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                 void *caller_info)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);

    const cicp_llap_kmib_t *llapt = control_plane->llap_table;
    int len = 0;
	
    (void)start;       /* unused */
    (void)caller_info; /* unused */

    if (offset != 0)
	buf[0]='\0';
    else
    {
	if (NULL == llapt)
	    len += snprintf(buf+len, bufsz-len,
			    "link layer access point table unallocated\n");
	else
	{   cicp_llap_rowid_t llap_index;
	    int n = 0;

	    for (llap_index = 0;
		 llap_index < llapt->rows_max;
		 llap_index++)
	    {   const cicp_llap_row_t *row = &llapt->llap[llap_index];

		if (cicp_llap_row_allocated(row) && len < bufsz)
		{   CICP_LOCK_BEGIN(control_plane)
			/* better to use a read lock really */

			len += snprintf(buf+len, bufsz-len,
					"%02d: llap %02d %4s %4s port ",
					llap_index, row->ifindex, row->name,
					row->up? "UP ": "DOWN");
                        if (cicp_llap_row_hasnic(&control_plane->user, row))
			{   len += 
                            snprintf(buf+len, bufsz-len, "%1d ", row->hwport);
			    len += snprintf(buf+len, bufsz-len,
					    "mac "CI_MAC_PRINTF_FORMAT
					    " mtu %d",
					    CI_MAC_PRINTF_ARGS(&row->mac),
					    row->mtu);
			} else
			{   len += snprintf(buf+len, bufsz-len,
					    "X ");
			}
			if (row->encapsulation.type & CICP_LLAP_TYPE_VLAN) {
			    len += snprintf(buf+len, bufsz-len, " VLAN %d",
					    row->encapsulation.vlan_id);
			}
			if (row->encapsulation.type & CICP_LLAP_TYPE_BOND) {
			    len += snprintf(buf+len, bufsz-len, " BOND HW%d ROW%d",
					    row->hwport, row->bond_rowid);
			}
			if (row->encapsulation.type & 
			    CICP_LLAP_TYPE_USES_HASH) {
			    len += snprintf(buf+len, bufsz-len, " HASH");
			    if (row->encapsulation.type & 
				CICP_LLAP_TYPE_XMIT_HASH_LAYER4) {
				len += snprintf(buf+len, bufsz-len, "-L4");
			    }
			}

			len += snprintf(buf+len, bufsz-len, "\n");

		    CICP_LOCK_END
		    n++;
		}
	    }

	    if (len < bufsz)
		len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n",
                                n, llapt->rows_max);
	}
    }
    *eof = TRUE;
    buf[bufsz-2]='\n'; /* end neatly even if we overran */
    buf[bufsz-1]='\0';
    return strlen(buf);
}


/*
 * Attention: MAC_STR_LENGTH should be more than total length
 *            returned by snprintfs.
 */
static int
cicpos_mac_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                void *caller_info)
{
    cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);
    const cicp_mac_mib_t *umact = control_plane->user.mac_utable;
    const cicp_mac_kmib_t *kmact = control_plane->mac_table;

    /*const cicp_mac_kmib_t *kmact = control_plane->mac_table;*/

    int len = 0;
    int entries;
    int str_end;
    int n = 0;
    off_t offset_orig = offset;

    cicp_mac_rowid_t mac_index = 0;

    (void)caller_info; /* unused */

    memset(buf, ' ', bufsz);

#ifdef MAC_STR_LENGTH
#undef MAC_STR_LENGTH
#endif
#define MAC_STR_LENGTH    160

#ifdef MAC_STR_LAST_POS
#undef MAC_STR_LAST_POS
#endif
#define MAC_STR_LAST_POS  (MAC_STR_LENGTH - 1)

    entries = bufsz / MAC_STR_LENGTH;

    if (entries == 0)
    {
        /* Provided bufsz is insufficient to retrieve whole mac entry */
    }
    else if (NULL == umact)
    {
        if (offset_orig == 0)
            len += snprintf(buf+len, bufsz-len,
                            "user address resolution table unallocated\n");
        *eof = TRUE;
    }
    else
    {
        for (mac_index = 0;
             mac_index < cicp_mac_mib_rows(umact);
             mac_index++)
        {
            const cicp_mac_row_t *row = &umact->ipmac[mac_index];
            const cicp_mac_kernrow_t *krow = &kmact->entry[mac_index];
            const cicpos_mac_row_t *sync = &krow->sync;

            if (cicp_mac_row_allocated(row) && len < bufsz)
            {
                if (offset >= MAC_STR_LENGTH)
                {
                    offset -= MAC_STR_LENGTH;
                    continue;
                }

                CICP_LOCK_BEGIN(control_plane)
		    /* better to use a read lock really */

                    str_end = len + MAC_STR_LAST_POS;
                    /* user-visible args */
                    len += snprintf(buf+len, bufsz-len,
                                    "#%04x: llap %02d %4s"
                                    " ip "CI_IP_PRINTF_FORMAT
                                    " mac "CI_MAC_PRINTF_FORMAT
                                    " on %3d%s%s",
                                     mac_index, row->ifindex,
				    _cicp_llap_get_name(control_plane,
							row->ifindex),
                                     CI_IP_PRINTF_ARGS(&row->ip_addr),
                                     CI_MAC_PRINTF_ARGS(&row->mac_addr),
                                     cicp_mac_row_usecount(row),
                                     cicp_mac_row_enter_requested(row)?
                                     " !service!": "",
                row->need_update == CICP_MAC_ROW_NEED_UPDATE_STALE ?
                " STALE" :
                row->need_update == CICP_MAC_ROW_NEED_UPDATE_SOON ?
                " almost-STALE" : "");
                    /* O/S synch args */
                    len += snprintf(buf+len, bufsz-len,
                                    " [u %08x up %08x ref %d "
                                    "%s%s%s%s%s%s%s%s%s%02X "
                                    "%03d %s%s%s]",
                                    sync->os.used, sync->os.updated,
                                    sync->os.refcnt,
                                    0 == sync->os.state? "NONE ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_INCOMPLETE)?
                                          "INCOMPLETE ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_REACHABLE)?
                                          "REACHABLE ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_STALE)?
                                          "STALE ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_DELAY)?
                                          "DELAY ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_PROBE)?
                                          "PROBE ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_FAILED)?
                                          "FAILED ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_NOARP)?
                                          "NOARP ":"",
                                    0 != (sync->os.state &
                                          CICPOS_IPMAC_PERMANENT)?
                                          "PERMANENT ":"",
                                    sync->os.flags, sync->os.family,
                                    0 != sync->source_sync? "S": "s",
                                    0 != sync->source_prot? "P": "p",
                                    0 != sync->recent_sync? "R": "r");
                    len += snprintf(buf+len, bufsz-len, " v%d rc %d",
                                    row->version, -row->rc);
                    *(buf + len) = ' ';
                    len = str_end;
                    *(buf + len) = '\n';
                    len++;

                CICP_LOCK_END

                n++;
                entries--;
                if (entries == 0)
                    break;
            }
        }

        if ((n == 0) && (offset_orig == 0) && (umact != NULL))
            len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n", 
                            n, cicp_mac_mib_rows(umact));

        *start = (char *)((ci_ptr_arith_t)len);
    }

    if (mac_index == cicp_mac_mib_rows(umact))
        *eof = TRUE;

    return len;

#undef MAC_STR_LENGTH
#undef MAC_STR_LAST_POS
}





static int
cicpos_ipif_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                 void *caller_info)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);
    const cicp_ipif_kmib_t *ipift = control_plane->ipif_table;
    int len = 0;
	
    (void)start;       /* unused */
    (void)caller_info; /* unused */
    
    if (offset != 0)
	buf[0]='\0';
    else
    {
	if (NULL == ipift)
	    len += snprintf(buf+len, bufsz-len,
			    "IP interface table unallocated\n");
	else
	{   cicp_ipif_rowid_t ipif_index;
	    int n = 0;

	    for (ipif_index = 0;
		 ipif_index < ipift->rows_max;
		 ipif_index++)
	    {   const cicp_ipif_row_t *row = &ipift->ipif[ipif_index];

		if (cicp_ipif_row_allocated(row) && len < bufsz)
		{   CICP_LOCK_BEGIN(control_plane)
			/* better to use a read lock really */
			len += snprintf(buf+len, bufsz-len,
					"%02d: llap %02d %4s "
					CI_IP_PRINTF_FORMAT
					"/%d\t bcast "CI_IP_PRINTF_FORMAT
					" scope %s\n",

					ipif_index,
					row->ifindex,
					_cicp_llap_get_name(control_plane,
							    row->ifindex),
					CI_IP_PRINTF_ARGS(&row->net_ip),
					row->net_ipset,
					CI_IP_PRINTF_ARGS(&row->bcast_ip),
					ci_route_scope_str(row->scope));
		    CICP_LOCK_END
		    n++;
		}
	    }

	    if (len < bufsz)
		len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n",
                                n, ipift->rows_max);
	}
    }
    *eof = TRUE;
    buf[bufsz-2]='\n'; /* end neatly even if we overran */
    buf[bufsz-1]='\0';
    return strlen(buf);
}


static int 
cicpos_bond_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                 void *caller_info)
{
  cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);
  const cicp_bondinfo_t *bondt;
  int len = 0;
  int n = 0;
  int i;
  
  bondt = control_plane->user.bondinfo_utable;
  
  memset(buf, ' ', bufsz);

  if( offset != 0 )
    buf[0]='\0';
  else {
    if( bondt == NULL )
      len += snprintf(buf+len, bufsz-len, "bond table unallocated\n");
    else {
      for( i = 0; i < bondt->rows_max; i++ ) {
        const cicp_bond_row_t *row = &bondt->bond[i];
        if( cicp_bond_row_allocated(row) && len < bufsz) {
          CICP_LOCK_BEGIN(control_plane);

          if( row->type == CICP_BOND_ROW_TYPE_MASTER ) 
            len += snprintf(buf+len, bufsz-len, 
                            "Row %d: MST if %d, next %d, "
                            "mode %d, hash %d, slaves %d, actv_slaves %d, "
                            "actv_hwport %d\n",
                            i, row->ifid, row->next, 
                            row->master.mode, row->master.hash_policy,
                            row->master.n_slaves,
                            row->master.n_active_slaves,
                            row->master.active_hwport);
          else if( row->type == CICP_BOND_ROW_TYPE_SLAVE )
            len += snprintf(buf+len, bufsz-len,
                            "Row %d: SLV if %d, next %d, "
                            "hwport %d, flags %d (%s)\n",
                            i, row->ifid, row->next, row->slave.hwport,
                            row->slave.flags, 
                            row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ?
                            "Active" : "Inactive");
          else
            len += snprintf(buf+len, bufsz-len, "Bond row %d: BAD type %d\n", 
                            i, row->type);
          CICP_LOCK_END;

          ++n;
        }
      }
      if (len < bufsz)
        len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n", 
                        n, bondt->rows_max);
    }
  }

  *eof = TRUE;
  buf[bufsz-2]='\n'; /* end neatly even if we overran */
  buf[bufsz-1]='\0';
  return strlen(buf);
}



/*
 * FWD info retrieves series of blocks of an equal length.
 * Block consists of 3 strings. The strings in the block have the equal
 * length.
 * ATTENTION: The length of string returned by appropriate snprintf
 *            should not exceed FWD_STR_LENGTH.
 */
static int
cicpos_fwd_read(char *buf, char **start, off_t offset, int bufsz, int *eof,
                void *caller_info)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(caller_info);
    const cicp_fwdinfo_t *fwdt;
    int len = 0;
    int str_end = 0;
    int entries;
    int n = 0;
    off_t offset_orig = offset;
    cicp_fwd_rowid_t fwd_index = 0;

    (void)caller_info; /* unused */

    fwdt = control_plane->user.fwdinfo_utable;

    memset(buf, ' ', bufsz);

#ifdef FWD_TAB
#undef FWD_TAB
#endif
#define FWD_TAB          8

#ifdef FWD_STR_LENGTH
#undef FWD_STR_LENGTH
#endif
#define FWD_STR_LENGTH   80

#ifdef FWD_STR_LAST_POS
#undef FWD_STR_LAST_POS
#endif
#define FWD_STR_LAST_POS  (FWD_STR_LENGTH - 1)

#ifdef FWD_ENTRY_LENGTH
#undef FWD_ENTRY_LENGTH
#endif
#define FWD_ENTRY_LENGTH  (FWD_STR_LENGTH * 3)

    entries = bufsz / FWD_ENTRY_LENGTH;

    if (entries == 0)
    {
        /* Provided bufsz is insufficient to retrive whole fwd entry */
    }
    else if (NULL == fwdt)
    {
        if (offset_orig == 0)
        len += snprintf(buf+len, bufsz-len,
                        "user forwarding information unallocated\n");
        *eof = TRUE;
    }
    else
    {
        for (fwd_index = 0; fwd_index < fwdt->rows_max; fwd_index++)
        {
            const cicp_fwd_row_t *row = &fwdt->path[fwd_index];

            if (cicp_fwd_row_allocated(row) && len < bufsz)
            {
                if (offset >= FWD_ENTRY_LENGTH)
                {
                    offset -= FWD_ENTRY_LENGTH;
                    continue;
                }

                /* better to use a read lock really */
                CICP_LOCK_BEGIN(control_plane)
                    /* first string */
                    str_end = len + FWD_STR_LAST_POS;
                    len += snprintf(buf+len, bufsz-len,
                                    CI_IP_PRINTF_FORMAT"/%u -> "
                                    CI_IP_PRINTF_FORMAT
                                    " llap %d %4s port ",
                                    CI_IP_PRINTF_ARGS(&row->destnet_ip),
                                    row->destnet_ipset,
                                    CI_IP_PRINTF_ARGS(&row->first_hop),
                                    row->dest_ifindex,
                                    _cicp_llap_get_name(control_plane,
							row->dest_ifindex));
                    if (cicp_fwd_row_hasnic(&control_plane->user, row))
                        len += 
                          snprintf(buf+len, bufsz-len,
                                   "%1d encap " CICP_ENCAP_NAME_FMT,
                                   row->hwport,
                                   cicp_encap_name(row->encap.type));
                    else
                        len += snprintf(buf+len, bufsz-len,
                                        "X");
                    *(buf + len) = ' ';
                    len = str_end;
                    *(buf + len) = '\n';
                    len++;
                    /* second string */
                    str_end = len + FWD_STR_LAST_POS;
                    len += FWD_TAB;
                    len += snprintf(buf+len, bufsz-len,
                                    "dst "CI_IP_PRINTF_FORMAT
                                    "/%d bcast "
                                    CI_IP_PRINTF_FORMAT" mtu %d"
                                    " tos %d metric %d",
                                    CI_IP_PRINTF_ARGS(&row->net_ip),
                                    row->net_ipset,
                                    CI_IP_PRINTF_ARGS(&row->net_bcast),
                                    row->mtu,
                                    row->tos, row->metric);
                    *(buf + len) = ' ';
                    len = str_end;
                    *(buf + len) = '\n';
                    len++;
                    /* third string */
                    str_end = len + FWD_STR_LAST_POS;
                    len += FWD_TAB;
                    len += snprintf(buf+len, bufsz-len,
                                    "src ip "CI_IP_PRINTF_FORMAT
                                    " mac "CI_MAC_PRINTF_FORMAT,
                                    CI_IP_PRINTF_ARGS(&row->pref_source),
                                    CI_MAC_PRINTF_ARGS(&row->
                                                           pref_src_mac));
                    *(buf + len) = ' ';
                    len = str_end;
                    *(buf + len) = '\n';
                    len++;
                CICP_LOCK_END
                n++;
                entries--;
                if (entries == 0)
                    break;
            }
        }

	*start = (char *)((ci_ptr_arith_t)len);
    }

    if (fwd_index == fwdt->rows_max) {
        if( fwdt != NULL && len < bufsz )
          len += snprintf(buf+len, bufsz-len, "%d (of %d) allocated\n", 
                          n, fwdt->rows_max);
        *eof = TRUE;
    }

    return len;
#undef FWD_TAB
#undef FWD_STR_LENGTH
#undef FWD_STR_LAST_POS
#undef FWD_ENTRY_LENGTH
}


static void
cicpos_procfs_ctor(cicp_mibs_kern_t *control_plane)
{   void *caller_info = control_plane;
    /* warning: the mechanism passing this to the read functions does not
                always seem to work */
    
    ci_assert(NULL != control_plane);

    /* if this function is called a number of times - for a number of different
       control planes, we want only one of them to be associated with the file
       names below */
    if (control_plane == &CI_GLOBAL_CPLANE)
    {
	ci_assert(NULL != oo_proc_root);

	create_proc_read_entry(CICPOS_PROCFS_FILE_HWPORT, 0, oo_proc_root,
			       &cicpos_hwport_read, caller_info);
	create_proc_read_entry(CICPOS_PROCFS_FILE_LLAP, 0, oo_proc_root,
			       &cicpos_llap_read, caller_info);
	create_proc_read_entry(CICPOS_PROCFS_FILE_MAC, 0, oo_proc_root,
			       &cicpos_mac_read, caller_info);
	create_proc_read_entry(CICPOS_PROCFS_FILE_IPIF, 0, oo_proc_root,
			       &cicpos_ipif_read,  caller_info);
	create_proc_read_entry(CICPOS_PROCFS_FILE_FWDINFO, 0, oo_proc_root,
			       &cicpos_fwd_read,  caller_info);
	create_proc_read_entry(CICPOS_PROCFS_FILE_BONDINFO, 0, oo_proc_root,
			       &cicpos_bond_read,  caller_info);
    }
}





static void
cicpos_procfs_dtor(cicp_mibs_kern_t *control_plane)
{   if (NULL != oo_proc_root)
    {   remove_proc_entry(CICPOS_PROCFS_FILE_HWPORT, oo_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_LLAP, oo_proc_root);
	remove_proc_entry(CICPOS_PROCFS_FILE_MAC, oo_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_IPIF, oo_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_FWDINFO, oo_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_BONDINFO, oo_proc_root);
    }
}






#else


#define cicpos_procfs_ctor(control_plane)
#define cicpos_procfs_dtor(control_plane)


#endif /* CICPOS_PROCFS */








/*****************************************************************************
 *****************************************************************************
 *									     *
 *          SYN - Cacheable MIB Synchronization				     *
 *          ===================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/











#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#include <linux/if_addr.h>
#endif
#include <linux/if_arp.h>






/*****************************************************************************
 *                                                                           *
 *          LINUX Netlink socket messages				     *
 *          =============================			             *
 *                                                                           *
 *****************************************************************************/





#if CICPOS_USE_NETLINK

/*! Defines a pointer to a function that handle an rtnetlink message */
typedef int ci_rtnl_msg_handler_t(cicpos_parse_state_t *, struct nlmsghdr *);


/* forward references */
static int 
cicpos_handle_rtnl_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr);

static void
cicpos_dump_tables(cicp_handle_t *control_plane, int /*bool*/ mac_only);











static int ci_bind_netlink_socket(struct socket *sockp, __u32 nl_groups)
{
  struct sockaddr_nl addr;
  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = nl_groups;
  return (sockp)->ops->bind(sockp, (struct sockaddr*)&addr, sizeof(addr));
}






static int ci_add_netlink_memberships(struct socket *sockp)
{
  /* In kernel 2.6.13, the netlink groups represantation was changed from a
   * bitmask to a list of integers, this means that we can't just OR the groups
   * that we want to listen to and bind to that value. Instread, they introduced
   * netlink socket options to register your interest for a certain netlink
   * group broadcast.
   */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
  return ci_bind_netlink_socket
           (sockp, RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR);
#else
  mm_segment_t fs;
  int optval, rc;

  rc = ci_bind_netlink_socket(sockp, 0);
  if (rc < 0) return rc;

  /* the kernel expects netlink_setsockopt to be used only from userspace,
   * bypass the memory checks */
  fs = get_fs();
  set_fs (get_ds());

  /* register for route changes */
  optval = RTNLGRP_LINK;
  rc = (sockp)->ops->setsockopt(sockp, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                                (void*)&optval, sizeof(int));
  if (rc < 0) {
    ci_log("****** ERROR: netlink setsockopt(link) failed, rc=%d ******", rc);
    goto end;
  }

  /* register for route changes */
  optval = RTNLGRP_IPV4_ROUTE;
  rc = (sockp)->ops->setsockopt(sockp, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                                (void*)&optval, sizeof(int));
  if (rc < 0) {
    ci_log("****** ERROR: netlink setsockopt(route) failed, rc=%d ******", rc);
    goto end;
  }

  /* register for ip interface changes */
  optval = RTNLGRP_IPV4_IFADDR;
  rc = (sockp)->ops->setsockopt(sockp, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                                (void*)&optval, sizeof(int));
  if (rc < 0) {
    ci_log("****** ERROR: netlink setsockopt(ifaddr) failed, rc=%d ******", rc);
    goto end;
  }
 
end:
  set_fs(fs);
  return rc;
#endif
}






/** create and bind an rtnetlink socket */
static int create_netlink_socket(struct socket **sockp)
{
  return sock_create(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE, sockp);
}






/** create and bind an rtnetlink socket */
static int create_listening_netlink_socket(struct socket **sockp)
{
  int rc, step=0;
  
  rc = sock_create(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE, sockp);
  if (rc < 0) goto error;
  
  step++;
  rc = ci_add_netlink_memberships(*sockp);
  if (rc < 0) goto error;

  return 0;

error:
  ci_log("%s: couldn't create listening netlink socket, rc=%d, step=%d",
         __FUNCTION__, rc, step);
  sock_release(*sockp);
  *sockp=0;
  return rc;
}






/*! This function is NOT re-entrant!
 *  Request the contents of the IP-MAC mapping (ARP) table
 */
static int 
request_table(struct socket *sock, __u32 seq, int nlmsg_type)
{
  struct msghdr msg;
  struct iovec iov;
  static char buf[8192];
  struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;
  int ret;

  memset(buf, 0, sizeof(buf));
  nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  nlhdr->nlmsg_type = nlmsg_type; /* RTM_GET* */
  nlhdr->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  nlhdr->nlmsg_seq = seq;

  iov.iov_base = (void*)buf;
  iov.iov_len = nlhdr->nlmsg_len;
  msg.msg_name=NULL;
  msg.msg_namelen=0;
  msg.msg_controllen=0;
  msg.msg_flags=0;
  msg.msg_iov=&iov;
  msg.msg_iovlen=1;

  ret = sock_sendmsg(sock, &msg, nlhdr->nlmsg_len);
  
  if (ret < 0) {
    ci_log("%s():sock_sendmsg failed, err=%d", __FUNCTION__, ret);
    return ret;
    
  } else
  if(ret != nlhdr->nlmsg_len) {
    ci_log("%s():sock_sendmsg failed. Read %d bytes but expected %d.",
           __FUNCTION__, ret, nlhdr->nlmsg_len);
    return -ENODATA;
    
  } else
    return 0;
}






static ssize_t 
netlink_read(struct socket *sock, char *buf, size_t count,
             int blocking, int retry)
{   struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    int rc;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    iov.iov_base = buf;
    iov.iov_len = count;

    msg.msg_name=&nladdr;
    msg.msg_namelen=sizeof(nladdr);
    msg.msg_iov=&iov;
    msg.msg_iovlen=1;
    msg.msg_control=0;
    msg.msg_controllen=0;
    msg.msg_flags = blocking ? 0 : MSG_DONTWAIT;

    rc = sock_recvmsg(sock, &msg, count, msg.msg_flags);

    /* wait a bit for the reply */
    if (retry && rc == -EAGAIN) {
	DEBUGNETLINK(DPRINTF(CODEID": re-read netlink #1"));
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ/100);
	rc = sock_recvmsg(sock, &msg, count, msg.msg_flags);
	/* wait a little bit more for the reply */
	if (retry && rc == -EAGAIN) {
	    DEBUGNETLINK(DPRINTF(CODEID": re-read netlink #2"));
	    set_current_state(TASK_INTERRUPTIBLE);
	    schedule_timeout(HZ/10);
	    rc = sock_recvmsg(sock, &msg, count, msg.msg_flags);
	}
    }

    return rc;
}





static int 
read_nl_msg(struct socket *sock, char (*buf)[8192], int blocking, int retry)
{   int bytes;

    memset(buf, 0, sizeof(*buf));
    bytes = netlink_read(sock, (char *) buf, sizeof(*buf), blocking, retry);
    if (bytes < 0)
    {   DEBUGNETLINK(
	    if (bytes != -EAGAIN)
	        DPRINTF(CODEID": netlink read failed, rc %d", -bytes);
	)
        return bytes;
    } else
    if (bytes == 0) {
        DEBUGNETLINK(DPRINTF(CODEID": EOF, netlink socket closed"));
        return -EIO;
    } else
        return bytes;
}







/*! read a netlink neighbor packet from socket 'sock'
 */
static int 
read_rtnl_response(struct socket *sock, __u32 seq, ci_rtnl_msg_handler_t *hf,
                   cicpos_parse_state_t *session,
		   ci_post_handling_fn_t *post_handling_fn)
{
  int rc, bytes;
  static char buf[8192];
  struct nlmsghdr *nlhdr;

  do {

    /* read an rtnetlink packet in non-blocking mode with retries */
    rc = bytes = read_nl_msg(sock, &buf, 0, 1);
    if (rc < 0) 
      return rc;
    else
    {	nlhdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(nlhdr, bytes)) {

	  if (nlhdr->nlmsg_seq != seq) {
	    /* ignore unsolicited packets */
	    ci_log("%s: Unsolicited netlink msg, msg_seq=%d, expected_seq=%d",
		   __FUNCTION__, nlhdr->nlmsg_seq, seq);

	  } else if (nlhdr->nlmsg_type == NLMSG_DONE) {
	    /* NLMSG_DONE marks the end of a dump */
	    rc = 0;
	    goto done;

	  } else if (nlhdr->nlmsg_type == NLMSG_NOOP) {
	    /* ignore NOOP message */
	    DEBUGNETLINK(DPRINTF(CODEID": ignoring NOOP netlink packet"));

	  } else if (nlhdr->nlmsg_type == NLMSG_ERROR) {
	    ci_log(CODEID": netlink error packet received!");
            return -EIO;
	  } else {
	    /* call the handling function; ignore errors returned because
             * we should handle all the rest. */
	    if ((rc = (*hf)(session, nlhdr)) < 0) {
	      ci_log(CODEID": netlink message handling function failed, rc=%d",
		     rc);
	    }
	  }

	  /* go to the next netlink message */
	  nlhdr = NLMSG_NEXT(nlhdr, bytes);
	}
    }

  } while(1);

done:
  /* call the post handling function */
  if (NULL != post_handling_fn)
      (*post_handling_fn)(session);

  return rc;
}





/*! Warning: this function is NOT re-entrant
 */
ci_inline int
rtnl_poll(struct socket *sock, ci_rtnl_msg_handler_t *hf,
	  cicpos_parse_state_t *session)
{
  int rc, bytes;
  static char buf[8192];
  struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;

  /* read an rtnetlink packet in non-blocking mode without retries */
  rc = bytes = read_nl_msg(sock, &buf, 0, 0);
  if (rc < 0) {
    if (rc != -ERESTART && rc != -EAGAIN)
      ci_log(CODEID": failed to read netlink message during poll, rc=%d", -rc);
    return rc;
  }

  while (NLMSG_OK(nlhdr, bytes)) {
    if (nlhdr->nlmsg_type == NLMSG_DONE) {
      return 0;
    } else if (nlhdr->nlmsg_type == NLMSG_NOOP) {
      /* ignore NOOP message */
      DEBUGNETLINK(DPRINTF(CODEID": ignoring NOOP netlink packet in poll"));
    } else if (nlhdr->nlmsg_type == NLMSG_ERROR) {
      ci_log(CODEID": netlink error packet received in poll!");
      return -EIO;
    } else {
      /* call the handling function */
      if ((rc = (*hf)(session, nlhdr)) < 0)
        ci_log(CODEID": handling function failed after poll, rc=%d", -rc);
    }
    nlhdr = NLMSG_NEXT(nlhdr, bytes);
  } /*while*/

  return 0;
}



#endif /* CICPOS_USE_NETLINK */







/*****************************************************************************
 *                                                                           *
 *          LINUX Netlink worker					     *
 *          ====================			                     *
 *                                                                           *
 *****************************************************************************/






#if CICPOS_USE_NETLINK




/*! Typedef of data to be passed the arp table poll timer function */
typedef struct {
  cicp_handle_t *control_plane;
  /** Signals the timer to not re-insert itself into the timer queue */
  int stop;
} cicpos_timer_data_t;



/*! Data to be passed to the synchronization timer handler function */
static cicpos_timer_data_t cicpos_timer_data;
/*< @TODO: this should be allocated from the control plane sync data area so
           that this code can be used to service more than one control plane
	   if necessary
*/

/*! Control plane timer node */
static struct timer_list cicpos_timer_node;

/*! Netlink socket */
static struct socket *NL_SOCKET;


/* XXXXX FIXME: this should be removed, it is here because if we update the
 * llap table before we have the ifindex information then it is possible that
 * the table will mark some L5 entries as non-level5 */
int cicpos_running = 0;











/*! Warning: this function is NOT re-entrant
 */
static int
efab_netlink_poll_for_updates(cicp_handle_t *control_plane)
{   
  int rc;
  cicpos_parse_state_t *session = cicpos_parse_state_alloc(control_plane);

  if( NULL == session )
    rc = -ENOMEM;
  else {
    cicpos_parse_init(session, control_plane);

    do
      rc = rtnl_poll(NL_SOCKET, &cicpos_handle_rtnl_msg, session);
    while( rc == 0 );

    cicpos_parse_state_free(session);
  }
  return rc == -EAGAIN ? 0 : rc;
}




/*! control plane pollers */
static void 
cicpos_worker(void *context_cplane)
{
    static unsigned int count = 0;

    if (cicpos_running)
    {	cicp_handle_t *control_plane = (cicp_handle_t *)context_cplane;
        efab_netlink_poll_for_updates(control_plane);
	if (count % 2 == 0)
	    cicpos_dump_tables(control_plane, count%20);
	count++;
    }
}





/** Timer function that schedules the synchronization task */
static void 
cicpos_timer(unsigned long in_data)
{
  cicpos_timer_data_t *datap = (void *) in_data;

  if (! datap->stop) {
    static ci_workitem_t wi =
      CI_WORKITEM_INITIALISER(wi, (CI_WITEM_ROUTINE) &cicpos_worker, NULL);
    CI_WORKITEM_SET_CONTEXT(&wi, datap->control_plane);
    ci_workqueue_add(&CI_GLOBAL_WORKQUEUE, &wi);

    mod_timer(&cicpos_timer_node, jiffies + CICPOS_SCAN_INTERVAL);
  }
}






static int constructed = FALSE;




static int /* rc */
cicpos_sync_ctor(cicp_handle_t *control_plane)
{   int rc;

    if (constructed)
    {	ci_log(CODEID": duplicate synchronizer construction detected!");
	rc = 0;
    } else
    {	constructed = TRUE;
	
	DEBUGNETLINK(DPRINTF(CODEID ": constructing synchronizer"));

	/* create the netlink socket and bind it to listen
	 * for IP address and route updates */
	rc = create_listening_netlink_socket(&NL_SOCKET);
	if (CI_LIKELY(rc >= 0)) {

	    cicpos_timer_data.control_plane = control_plane;
	    /* init synchronizer timer function data */
	    cicpos_timer_data.stop = 0;

	    /* init synchronizer timer */
	    init_timer(&cicpos_timer_node);
	    cicpos_timer_node.expires = jiffies + CICPOS_SCAN_INTERVAL;
	    cicpos_timer_node.data = (unsigned long) &cicpos_timer_data;
	    cicpos_timer_node.function = &cicpos_timer;

	    /*
	     * Start the timer that schedules a regular kernel system MIB poll.
	     * Regularity is achieved by re-registering the timer at each
	     * trigger.
	     */
	    add_timer(&cicpos_timer_node);

	    DEBUGNETLINK(DPRINTF(CODEID": constructed"));
	    rc = 0;
	} else
	    ci_log(CODEID": can't create netlink socket, rc=%d.", rc);
    }    
    return rc;
}






static void 
cicpos_sync_dtor(cicp_handle_t *control_plane)
{
    DEBUGNETLINK(DPRINTF(CODEID": destroying synchronizer"));

    if (!constructed)
        ci_log(CODEID": duplicate synchronizer destruction detected!");
    else
    {
	/* Signal the synchronizer poll timer function not to re-insert itself
	 * into the timer queue. Otherwise, it is theoretically (in practise 
	 * it is improbable) possible for the timer to keep adding itself
	 * forever.
	 */
        cicpos_timer_data.stop = 1;

	/* delete the arp poll timer synchronously */
	DEBUGNETLINK(DPRINTF("Deleting synchronizer timer"));
	del_timer_sync(&cicpos_timer_node);

	/* flush the workqueue to make sure there are no pending ARP
	   work items */
	ci_verify(ci_workqueue_flush(&CI_GLOBAL_WORKQUEUE) == 0);

	/* destroy the persistent netlink socket */
	sock_release(NL_SOCKET);

	DEBUGNETLINK(DPRINTF(CODEID": synchronizer destroyed"));
    }
}




#else

#define cicpos_sync_ctor(control_plane) (0)
#define cicpos_sync_dtor(control_plane)

#endif /* CICPOS_USE_NETLINK */







/*****************************************************************************
 *                                                                           *
 *          Routing MIB							     *
 *          ===========							     *
 *                                                                           *
 *****************************************************************************/






/*! Initialize kernel synchronization state in a route MIB row */
extern void
cicpos_route_kmib_row_ctor(cicpos_route_row_t *sync_row)
{   ci_assert(NULL != sync_row);
    /* set to an initial value */
    memset(sync_row, 0, sizeof(*sync_row));
}




/*! Update synchronization information from new copy from O/S */
extern int
cicpos_route_kmib_row_update(cicpos_route_row_t *sync_row,
			     const cicpos_route_row_t *sync_newrow)
{   int /* bool */ changed;
    
    ci_assert(NULL != sync_row);

    if (NULL == sync_newrow)
    {   changed = FALSE;
        memset(sync_row, 0, sizeof(*sync_row));
    } else
    {   changed = (0 != memcmp(sync_row, sync_newrow, sizeof(*sync_row)));    
        memcpy(sync_row, sync_newrow, sizeof(*sync_row));
    }

    return changed;
}







#if CICPOS_USE_NETLINK


/*! Processes a route rtnetlink message.
 */
ci_noinline int 
cicpos_handle_route_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr)
{   int rc = 0;
    int rlen = RTM_PAYLOAD(nlhdr);
    struct rtmsg *rtmsg = (struct rtmsg *)NLMSG_DATA(nlhdr);

    struct rtattr  *attr;
    ci_ip_addr_t    dest_ip;
    ci_ip_addrset_t dest_ipset = CI_IP_ADDRSET_BAD;
    ci_ip_addr_t    next_hop_ip;
    ci_ip_addr_t    pref_source;
    ci_ifid_t       ifindex = CI_IFID_BAD;
    cicp_metric_t   metric = 1; /* default */
    ci_ip_tos_t     tos = 0;
    ci_mtu_t        mtu = 0;

    static int unsupported_print_once = 0;
    static int unsupported_metrics_print_once = 0;

    ci_assert(NULL != nlhdr);
    ci_assert(NULL != session);
    ci_assert_gt(rlen, 0);
    ci_assert(NULL != rtmsg);

    if (rtmsg->rtm_family != PF_INET)
    {   DEBUGNETLINK(DPRINTF(CODEID": ignoring non IP entry (fam=%x)",
	                     rtmsg->rtm_family));
	return 0;
    }

    /* Only look at the main table for now,
       ignore local & other tables */
    if (rtmsg->rtm_table != RT_TABLE_MAIN &&
        rtmsg->rtm_table != RT_TABLE_LOCAL)
	return 0;

    attr = (struct rtattr *)RTM_RTA(rtmsg);
    ci_assert(NULL != attr);

    memset(&dest_ip, 0, sizeof(dest_ip));
    memset(&pref_source, 0, sizeof(pref_source));
    memset(&next_hop_ip, 0, sizeof(next_hop_ip));

    while (RTA_OK(attr, rlen))
    {
        switch (attr->rta_type)
        {
	    case RTA_DST:
		dest_ip = *((ci_uint32 *)RTA_DATA(attr));

		/* ci_log("dst_ip=" CI_IP_PRINTF_FORMAT "/%d",
		       CI_IP_PRINTF_ARGS(&dest_ip),
		       rtmsg->rtm_dst_len); */
		break;


	    case RTA_OIF:
		ifindex = *((int *)RTA_DATA(attr));
		/* ci_log("oif=%d", ifindex); */
		break;

	    case RTA_GATEWAY:
		next_hop_ip = *((ci_uint32 *)RTA_DATA(attr));
		/* ci_log("gw=" CI_IP_PRINTF_FORMAT,
		        CI_IP_PRINTF_ARGS(&next_hop_ip));
		 */
		break;

	    case RTA_PRIORITY:
		break;

	    case RTA_PREFSRC:
		pref_source = *((ci_uint32 *)RTA_DATA(attr));
		/* ci_log("src=" CI_IP_PRINTF_FORMAT,
		          CI_IP_PRINTF_ARGS(&pref_source));
		*/
		break;

	    case RTA_METRICS: {
		struct rtattr *rta = RTA_DATA(attr);
		int len = RTA_PAYLOAD(attr);
		while (RTA_OK(rta, len)) {
		    switch( rta->rta_type ) {
			case RTAX_MTU:
			    mtu = *((ci_uint32 *)RTA_DATA(rta));
			    break;

#define RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(rtax) \
            case rtax:                                                  \
                if( ~unsupported_metrics_print_once & (1 << rtax) ) {   \
                    ci_log(CODEID": ignoring "#rtax);                   \
                    unsupported_metrics_print_once |= (1 << rtax);      \
                }                                                       \
                break
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_UNSPEC);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_LOCK);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_WINDOW);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_RTT);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_RTTVAR);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_SSTHRESH);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_CWND);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_ADVMSS);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_REORDERING);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_HOPLIMIT);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_INITCWND);
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_FEATURES);
#ifdef RTAX_RTO_MIN
			RTAX_UNSUPPORTED_METRICS_PRINT_ONCE(RTAX_RTO_MIN);
#endif
#undef RTAX_UNSUPPORTED_METRICS_PRINT_ONCE
		    }
		    rta = RTA_NEXT(rta, len);
		}
		break;
	}

#define RTA_UNSUPPORTED_PRINT_ONCE(rta) \
            case rta:                                           \
                if( ~unsupported_print_once & (1 << rta) ) {    \
                    ci_log(CODEID": ignoring "#rta);            \
                    unsupported_print_once |= (1 << rta);       \
                }                                               \
                break

            RTA_UNSUPPORTED_PRINT_ONCE(RTA_SRC);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_IIF);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_MULTIPATH);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_PROTOINFO);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_FLOW);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_CACHEINFO);
#undef RTA_UNSUPPORTED_PRINT_ONCE

	    default:
		DEBUGNETLINK(ci_log( CODEID": ignoring unknown rta_type %d",
			             attr->rta_type));
		break;
	}
	attr = RTA_NEXT(attr, rlen);
    }

    dest_ipset = rtmsg->rtm_dst_len;
    tos = rtmsg->rtm_tos;

    /* We only support RTN_UNICAST and 32 bit netmask
     * RTN_LOCAL entries. We assume that the 32 bit netmask
     * local routes will be route for the loopback addresses
     */
    if (CI_UNLIKELY(rtmsg->rtm_type != RTN_UNICAST &&
                    !(rtmsg->rtm_type == RTN_LOCAL &&
                      dest_ipset == 32)))
    {   /* don't complain for local table routes */
        if (rtmsg->rtm_table != RT_TABLE_LOCAL)
        {
            ci_log("%s: We only support unicast entries. "
	           "Ignoring route entry:",
	           __FUNCTION__);
	    ci_log("dst=" CI_IP_PRINTF_FORMAT "/%u"
	           " gw="  CI_IP_PRINTF_FORMAT
	           " src=" CI_IP_PRINTF_FORMAT
	           " tos=%u oif=%d",
	           CI_IP_PRINTF_ARGS(&dest_ip), dest_ipset,
	           CI_IP_PRINTF_ARGS(&next_hop_ip),
	           CI_IP_PRINTF_ARGS(&pref_source),
	           tos, ifindex);
        }
    } else
    {	int /* bool */ add =
	    (nlhdr->nlmsg_type == RTM_NEWROUTE);

	/* route table update */
	{   cicpos_route_row_t sync;
	    ci_scope_t         scope;

	    memset(&sync, 0, sizeof(sync)); /* for now */

	    if (rtmsg->rtm_scope == RT_SCOPE_HOST)
	    {   ci_scope_set_host(&scope);
	    } else
		ci_scope_set_global(&scope);

	    if (add)
	    {   cicp_route_rowid_t rowid;
		rc = cicpos_route_import(session->
					   control_plane,
					 &rowid,
					 dest_ip, dest_ipset,
					 scope, next_hop_ip,
					 tos, metric,
					 pref_source,
					 ifindex, mtu, &sync, 
                                         session->nosort);
		/* remember we've seen this route */
		if (0 == rc)
		{   ci_assert(CICP_ROUTE_ROWID_BAD != rowid);
		    ci_assert(rowid >= 0);
		    ci_bitset_add(
			CI_BITSET_REF(session->imported_route),
			rowid);
		}
                else {
                  DEBUGNETLINK
                    (ci_log(CODEID": cicpos_route_import failed, rc=%d ", rc));
                }
	    } else /* assume delete if not add */ {
		cicpos_route_delete(session->control_plane, 
                                    dest_ip, dest_ipset);
                if (session->nosort) {
                    session->nosort = CI_FALSE;
                    DEBUGNETLINK(ci_log("%s: delete route when dumping",
                                   __FUNCTION__));
                    /* \todo we should re-read the table in
                     * this case. */
                }
            }
	}
    }
    
    return rc;
}






ci_inline int /* rc */
cicpos_dump_routet(struct socket *sock, ci_uint32 seq,
		   cicpos_parse_state_t *session)
{   int rc;

    /* request the route table */
    if ((rc = request_table(sock, seq, RTM_GETROUTE)) < 0 ) 
	ci_log(CODEID": route table request "
	       "failed, rc %d", -rc);

    /* listen for reply */
    else if ((rc = read_rtnl_response(sock, seq,
				      &cicpos_handle_route_msg,
				      session,
				      &cicpos_route_post_poll))
	     < 0)
	ci_log(CODEID": failed to read route table from "
	       "rtnetlink, rc %d", -rc);

    return rc;
}






#endif /* CICPOS_USE_NETLINK */









/*****************************************************************************
 *                                                                           *
 *          Address Resolution MIB					     *
 *          ======================					     *
 *                                                                           *
 *****************************************************************************/





/*! Initialize kernel synchronization state in a MAC MIB row */
extern void
cicpos_mac_kmib_row_ctor(cicpos_mac_row_t *sync_row,
			 const cicpos_mac_row_sync_t *os)
{   ci_assert(NULL != sync_row);

    memset(sync_row, 0, sizeof(*sync_row));
    
    sync_row->mapping_set = 0; /* unset time */
    
    if (NULL == os)
        sync_row->source_prot = 1;  /* must be a new protocol entry */
    else 
    {   memcpy(&sync_row->os, os, sizeof(sync_row->os));
	sync_row->source_sync = 1;  /* must be a new o/s entry */
    }
}





/*! Initialize kernel synchronization state in a MAC MIB 
 *  - see driver header for documentation
 */
extern int /* rc */
cicpos_mac_kmib_ctor(cicpos_mac_mib_t *sync)
{   ci_assert(NULL != sync);
    return 0;
}






/*! Terminate kernel synchronization state of a MAC MIB */
extern void
cicpos_mac_kmib_dtor(cicpos_mac_mib_t *sync)
{   (void)sync; /* not actually used */
    /* flush the workqueue to make sure there are no pending ARP work items */
    ci_verify(ci_workqueue_flush(&CI_GLOBAL_WORKQUEUE) == 0);
}





/*! Indicate that the original content of this mapping could be altered
 *  - see driver header for documentation
 */
extern int /* bool */
cicpos_mac_kmib_row_update(cicp_handle_t *control_plane,
			   cicpos_mac_row_t *sync_row, cicp_mac_row_t *row,
			   const cicpos_mac_row_sync_t *os,
			   const ci_mac_addr_t *unused_mac,
			   int /* bool */ alteration,
			   int /* bool */ *out_ignore_clash)
{   int do_update = 0;

    ci_assert(NULL != sync_row);
    *out_ignore_clash = 0;

    if (sync_row->source_sync) /* had O/S info in it */
    {   if (CI_UNLIKELY(0 != (sync_row->os.state & CICPOS_IPMAC_PERMANENT))
	    ||
	    CI_UNLIKELY(0 != (sync_row->os.state & CICPOS_IPMAC_NOARP)))
        {
            *out_ignore_clash = 1;
            /* not a proper clash if we know it had a rubbish MAC address
	       anyway */
	}
    }
    if (NULL != os) /* has O/S info to come */
    {   if (CI_UNLIKELY(0 != (os->state & CICPOS_IPMAC_PERMANENT))
	    /* a permanent entry - can clash with existing entry */
	    ||
	    CI_UNLIKELY(0 != (os->state & CICPOS_IPMAC_NOARP))
	    /* not an ARP entry - can clash with existing entry */)
	{   *out_ignore_clash = 1;
	}
    }
	
    if (sync_row->source_sync) /* had O/S info in it */
    {   /* this entry already has valid information from the O/S */
	if (os == NULL) /* protocol update */
	{   if (CI_LIKELY(0 == (sync_row->os.state & CICPOS_IPMAC_PERMANENT))
	        /* not a permanent entry - don't update permanent entries */
		&&
		CI_LIKELY(0 == (sync_row->os.state & CICPOS_IPMAC_NOARP))
		/* not an ARP entry - don't update entries that don't store
		   proper ARP information */)
	    {   do_update = 1;
	    }
	} else
	{   /* previous O/S info, system update */
	    if (CI_LIKELY(0 == (os->state & CICPOS_IPMAC_INCOMPLETE))
		/* not an incomplete entry */
	        && CI_LIKELY(os->state != CICPOS_IPMAC_NONE))
		/* a none entry - linux sometimes gives us one these... */
	    {   do_update = 1;
	    }
	}
    } else /* never had O/S info */
    if (os == NULL) /* no previous O/S info, protocol update */
    {   /* accept the newer protocol update */
	do_update = 1;
    } else /* no previous O/S info, O/S update */
    {   /* overwrite last protocol information */
	ci_assert(sync_row->source_prot); /* info must have be from protocol */
	if (CI_LIKELY(0 == (os->state & CICPOS_IPMAC_INCOMPLETE))
	    /* not an incomplete entry */
	    && CI_LIKELY(os->state != CICPOS_IPMAC_NONE))
	    /* a none entry - linux sometimes gives us one these... */
	{   do_update = 1;
	}
    }

    if (do_update)
    {   int newly_valid = alteration;
	
	if (os != NULL)
	{   ci_uint16 orig_state = sync_row->os.state;
            memcpy(&sync_row->os, os, sizeof(sync_row->os));
	    sync_row->source_sync = 1;
	    /* Not really a permanent error: 
	    if (CI_UNLIKELY(0!=(sync_row->os.state & CICPOS_IPMAC_INCOMPLETE)))
	        row->rc = -ENOTCONN;
	    */
	    if (CI_UNLIKELY(0!=(sync_row->os.state & CICPOS_IPMAC_NOARP)))
	        row->rc = -EINVAL;
	    if (CI_UNLIKELY(0!=(sync_row->os.state & CICPOS_IPMAC_FAILED)))
	        row->rc = -EHOSTUNREACH;
	    else
		row->rc = 0;
	    
	    if (os->state & CICPOS_IPMAC_STALE) {
		if (row->need_update != CICP_MAC_ROW_NEED_UPDATE_STALE) {
		    row->need_update = CICP_MAC_ROW_NEED_UPDATE_STALE;
		    alteration = 1; *out_ignore_clash = 1;
		}
	    }
	    else if (os->state == CICPOS_IPMAC_REACHABLE &&
		     os->confirmed > arp_tbl.parms.reachable_time / 3 ) {
		/* reachable_time for an arp entry is in the range
		 * base/2 - 3base/2. We'd like to confirm it while it is
		 * still reachable, so base/3 is a good value here.
		 * It means we do a syscall every 10 seconds. */
		if (row->need_update != CICP_MAC_ROW_NEED_UPDATE_SOON) {
		    row->need_update = CICP_MAC_ROW_NEED_UPDATE_SOON;
		    alteration = 1; *out_ignore_clash = 1;
		}
	    }
	    else
		row->need_update = 0;

             if (0 != (sync_row->os.state & CICPOS_IPMAC_REACHABLE) &&
		 sync_row->os.state != orig_state)
		 newly_valid = 1; 
        } else
	{   sync_row->source_prot = 1;
	    sync_row->os.state = CICPOS_IPMAC_REACHABLE;
	    row->rc = 0;
	}

	if (newly_valid)
	{   sync_row->mapping_set = jiffies;
            /* record time when mapping last set/re-established */
	}
    }

    return do_update && alteration;
}





/*! Indicate that this entry has just been synchronized with the O/S
 *  - see driver header for documentation
 */
extern void cicpos_mac_row_synced(cicpos_mac_row_t *row)
{   row->recent_sync = 1;
}






/*! Check whether this row has been synced since this function was last
 *  called
 *  - see driver header for documentation
 *
 *  In effect this function determines whether an IP-MAC entry survives
 *  during a purge.
 */
extern int /* bool */ cicpos_mac_row_recent(cicpos_mac_row_t *sync)
{
    /* TODO: should we count the number of times we haven't
	     seen the entry during synch and wait until we haven't seen
	     it a number of times (in case we have missed a netlink message
	     that reported the MAC entry live)?
     */

    /* if entry has been inherited from O/S use sync->recent_sync */
    if( !sync->recent_sync )
        return 0;

    sync->recent_sync = 0;
    /* this bit was set when this entry was seen in the O/S table */
    return sync->source_sync;
}
    




#if CICPOS_USE_NETLINK



/* IP-MAC MIB information from the O/S to our local cache */


ci_noinline int /* rc */
cicpos_handle_mac_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr)
{   int rc = 0;
    int rlen = NLMSG_PAYLOAD(nlhdr, sizeof(struct ndmsg));
    struct ndmsg *ndmsg = (struct ndmsg *)NLMSG_DATA(nlhdr);

    /* standard fields */
    ci_ifid_t     ifindex = ndmsg->ndm_ifindex;
    /* includes info from nda_cacheinfo(rtnetlink.h) */
    cicpos_mac_row_sync_t os;
    /* L2  and L3 addresses */
    ci_mac_addr_t mac_addr;
    ci_ip_addr_t  ip_addr;
    int /*bool*/ mac_valid = FALSE;
    struct rtattr *attr = (struct rtattr *)NDA_RTA(ndmsg);

    ci_assert(NULL != nlhdr);
    ci_assert(NULL != session);
    ci_assert_gt(rlen, 0);
    ci_assert(NULL != ndmsg);

    /* we only support IPv4 */
    if (ndmsg->ndm_family != AF_INET)
    {   CICPOS_MAC_STAT_INC_NL_MSG_REJECT(session->control_plane);
	/*CICP_LOG(DPRINTF("%s: IPv4 only", __FUNCTION__));*/
	return 0;
    }

    ci_assert(NULL != attr);

    memset(&mac_addr, 0, sizeof(mac_addr));
    memset(&ip_addr, 0, sizeof(ip_addr));
    
    memset(&os, 0, sizeof(os));
    os.family  = ndmsg->ndm_family;
    os.state   = ndmsg->ndm_state;
    os.flags   = ndmsg->ndm_flags;

    while (RTA_OK(attr, rlen))
    {
	switch (attr->rta_type)
	{
	    case NDA_DST:
		CI_IP_ADDR_SET(&ip_addr, (const ci_ip_addr_t *)RTA_DATA(attr));
		break;

	    case NDA_LLADDR:
		CI_MAC_ADDR_SET(&mac_addr,
		                (const ci_mac_addr_t *)RTA_DATA(attr));
		mac_valid = TRUE;
		break;

	    case NDA_CACHEINFO:
	    {   struct nda_cacheinfo *cacheinfo =
		        (struct nda_cacheinfo *)RTA_DATA(attr);
                /* Kernel thought it a good idea to break the ABI in
                 * 2.6.26 by changing the units of ndm_confirmed */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
                os.confirmed = clock_t_to_jiffies(cacheinfo->ndm_confirmed);
#else
                os.confirmed = cacheinfo->ndm_confirmed;
#endif
		os.used      = cacheinfo->ndm_used;
		os.updated   = cacheinfo->ndm_updated;
		os.refcnt    = cacheinfo->ndm_refcnt;
		break;
	    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
	    case NDA_PROBES:
		/* in 2.6.12, the kernel gives out its count of
		   neighbour probes as additional information -- not
		   interesting, so just ignore it...
		 */
		break;
#endif
	    default:
		DEBUGNETLINK(ci_log(
                    "%s: ERROR: Unknown NDA_RTA type (%d)!",
                    __FUNCTION__, attr->rta_type));
                break;
	}
	attr = RTA_NEXT(attr, rlen);
    }

    if (rc != 0)
	return rc;

    if (CI_UNLIKELY(!mac_valid && (os.state & CICPOS_IPMAC_VALID)))
    {
	ci_log(CODEID": Linux volunteered no MAC address for "
	       CI_IP_PRINTF_FORMAT" in state 0x%02x",
	       CI_IP_PRINTF_ARGS(&ip_addr), os.state);
    } else
    {   cicp_mib_verinfo_t rowinfo;

	rowinfo.row_version = CI_VERLOCK_BAD;
	rowinfo.row_index = CICP_MAC_ROWID_BAD;

	cicpos_mac_set(session->control_plane, &rowinfo, ifindex, ip_addr,
	               (const ci_mac_addr_t *)&mac_addr, &os);

	if (CICP_MAC_ROWID_BAD != rowinfo.row_index)
	    cicpos_mac_row_seen(session->control_plane, &rowinfo);
    }

    return rc;
}








/* IP-MAC MIB information from the our local cache to the O/S */

static void 
cicpos_mac_post_poll(cicpos_parse_state_t *session)
{   cicpos_mac_purge_unseen(session->control_plane);
}






ci_inline int /* rc */
cicpos_dump_mact(struct socket *sock, ci_uint32 seq,
		 cicpos_parse_state_t *session)
{   int rc;

    if (cicpos_mact_open(session->control_plane))
    {   /* request the ARP table */
	if ((rc = request_table(sock, seq, RTM_GETNEIGH)) < 0) 
	    ci_log(CODEID": arp table request failed, rc %d", rc);

	/* listen for reply */
	else if ((rc = read_rtnl_response(sock, seq,
					  &cicpos_handle_mac_msg,
					  session,
					  &cicpos_mac_post_poll)) < 0)
	{   DEBUGNETLINK(DPRINTF(CODEID": reading of arp table from "
				 "rtnetlink failed, rc %d", -rc));
	}

	cicpos_mact_close(session->control_plane);
    } else
    {   DEBUGNETLINK(DPRINTF(CODEID": IP-MAC mappings already "
			     "being synchronized"););
	rc = -EALREADY;
    }

    return rc;
}







#endif /* CICPOS_USE_NETLINK */










/*****************************************************************************
 *                                                                           *
 *          Link Layer Access Point MIB					     *
 *          ===========================					     *
 *                                                                           *
 *****************************************************************************/






extern void
cicpos_llap_kmib_row_ctor(cicpos_llap_row_t *row)
{
    ci_assert(NULL != row);
}




#if CICPOS_USE_NETLINK


/*! Processes a link rtnetlink message.
 */
ci_noinline int 
cicpos_handle_llap_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr)
{   int rc = 0;
    int rlen = RTM_PAYLOAD(nlhdr);
    struct ifinfomsg *ifinfomsg = (struct ifinfomsg *)NLMSG_DATA(nlhdr);

    struct rtattr *attr;
    ci_uint8 /* bool */ add;
    ci_uint8 /* bool */ up;
    ci_mtu_t          mtu = 0;
    char              name[CICP_LLAP_NAME_MAX+1];
    ci_mac_addr_t     mac;	
    cicpos_llap_row_t sync;

    ci_assert(NULL != nlhdr);
    ci_assert(NULL != session);
    ci_assert_gt(rlen, 0);
    ci_assert(NULL != ifinfomsg);

    /* we are only interested in ethernet interfaces */
    if (ifinfomsg->ifi_type != ARPHRD_ETHER)
    {   /*ci_log("Only interested in ethernet interfaces");*/
	return 0;
    }

    attr = (struct rtattr *)IFLA_RTA(ifinfomsg);
    add = (nlhdr->nlmsg_type == RTM_NEWLINK);
    up = (0 != (ifinfomsg->ifi_flags & IFF_UP)); 
    
    memset(&name, 0, sizeof(name));
    memset(&mac, 0, sizeof(mac));
    memset(&sync, 0, sizeof(sync)); /* for now */


    ci_assert(add || (nlhdr->nlmsg_type == RTM_DELLINK));
    ci_assert(NULL != attr);

    while (RTA_OK(attr, rlen))
    {
	switch (attr->rta_type)
	{
	    case IFLA_UNSPEC:
		break;

	    case IFLA_ADDRESS:
		CI_MAC_ADDR_SET(&mac, RTA_DATA(attr));
		break;

	    case IFLA_IFNAME:
		memcpy(&name, RTA_DATA(attr), sizeof(name));
		break;

	    case IFLA_MTU:
		mtu = (ci_mtu_t) *((unsigned *)RTA_DATA(attr));
		break;

	    case IFLA_BROADCAST:
	    case IFLA_LINK:
	    case IFLA_QDISC:
	    case IFLA_STATS:
	    case IFLA_PRIORITY:
	    case IFLA_MASTER:
#ifdef IFLA_WIRELESS
	    case IFLA_WIRELESS:
#endif
		break;

	    default:
		DEBUGNETLINK(ci_log("%s: Ignoring rta_type %d",
		                    __FUNCTION__, attr->rta_type));
		break;
	}
	attr = RTA_NEXT(attr, rlen);
    }


    if (add)
    {   cicp_llap_rowid_t rowid;

	rc = cicpos_llap_import(session->control_plane, &rowid,
	                        ifinfomsg->ifi_index,
	                        mtu, up, &name[0], &mac, &sync);
	    
	/* remember we've seen this LLAP */
	if (0 == rc)
	{   ci_assert(CICP_LLAP_ROWID_BAD != rowid);
	    ci_assert(rowid >= 0);
	    ci_bitset_add(CI_BITSET_REF(session->imported_llap), rowid);
	}
    }
    else {
	cicpos_llap_delete(session->control_plane, ifinfomsg->ifi_index);
	if (session->nosort) {
	    session->nosort = CI_FALSE;
	    DEBUGNETLINK(ci_log("%s: delete LLAP entry when dumping",
	           __FUNCTION__));
	    /* \todo we should re-read the table in
	     * this case. */
	}
    }

    return rc;
}






ci_inline int /* rc */
cicpos_dump_llapt(struct socket *sock, ci_uint32 seq,
		  cicpos_parse_state_t *session)
{   int rc;

    /* request the LLAP table */
    if ((rc = request_table(sock, seq, RTM_GETLINK)) < 0 )
	ci_log(CODEID": route table request "
	       "failed, rc %d", -rc);

    /* listen for reply */
    else if ((rc = read_rtnl_response(sock, seq,
				      &cicpos_handle_llap_msg,
				      session,
				      &cicpos_llap_post_poll))
	     < 0)
	ci_log(CODEID": failed to read links table from "
	       "rtnetlink, rc %d", -rc);

    return rc;
}





#endif /* CICPOS_USE_NETLINK */








/*****************************************************************************
 *                                                                           *
 *          IP Interface table					             *
 *          ==================						     *
 *                                                                           *
 *****************************************************************************/







#if CICPOS_USE_NETLINK


ci_noinline int 
cicpos_handle_ipif_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr)
{   int rc = 0;

    int rlen = NLMSG_PAYLOAD(nlhdr, sizeof(struct ifaddrmsg));
    struct ifaddrmsg *ifmsg = (struct ifaddrmsg *)NLMSG_DATA(nlhdr);
    
    struct rtattr *attr;
    int /* bool */ add;
    
    ci_ifid_t         ifindex;
    ci_ip_addr_net_t  net_ip;
    ci_ip_addrset_t   net_ipset;
    ci_ip_addr_net_t  net_bcast;
    char              name[IFNAMSIZ];
    
    ci_assert(NULL != nlhdr);
    ci_assert(NULL != session);
    ci_assert_gt(rlen, 0);
    ci_assert(NULL != ifmsg);

    if (ifmsg->ifa_family != AF_INET)
    {   DEBUGNETLINK(DPRINTF("%s: ignoring non IP entry", __FUNCTION__));
	return 0;
    }

    attr = (struct rtattr *)IFA_RTA(ifmsg);
    ifindex = ifmsg->ifa_index;
    net_ipset = ifmsg->ifa_prefixlen;

    memset(&net_ip, 0, sizeof(net_ip));
    memset(&net_bcast, 0, sizeof(net_bcast));
    memset(&name, 0, sizeof(name));
    
    ci_assert(NULL != attr);

    while (RTA_OK(attr, rlen))
    {   switch (attr->rta_type)
	{   case IFA_ADDRESS:
		/* From linux-3.6.32/include/linux/if_addr.h:
		 * IFA_ADDRESS is prefix address, rather than local
		 * interface address.  It makes no difference for normally
		 * configured broadcast interfaces, but for point-to-point
		 * IFA_ADDRESS is DESTINATION address, local address is
		 * supplied in IFA_LOCAL attribute.
		 */
		//CI_IP_ADDR_SET(&net_ip, (ci_uint32 *) RTA_DATA(attr));
		break;

	    case IFA_LOCAL:
		CI_IP_ADDR_SET(&net_ip, (ci_uint32 *) RTA_DATA(attr));
		break;

	    case IFA_LABEL:
		memset(name, 0, sizeof(name));
		memcpy(name, RTA_DATA(attr),
		       CI_MIN(IFNAMSIZ, sizeof(name)));
		break;

	    case IFA_BROADCAST:
		CI_IP_ADDR_SET(&net_bcast,(ci_uint32 *)RTA_DATA(attr));
		break;

	    case IFA_ANYCAST:
		ci_log("Ignoring IFA_ANYCAST");
		break;

	    case IFA_CACHEINFO:
		ci_log("Ignoring IFA_CACHEINFO");
		break;

	    default:
		DEBUGNETLINK(ci_log("%s: Ignoring rta_type %d",
				    __FUNCTION__, attr->rta_type));
		break;
	}
	attr = RTA_NEXT(attr, rlen);
    }

    add = (nlhdr->nlmsg_type == RTM_NEWADDR);
    ci_assert(add || nlhdr->nlmsg_type == RTM_DELADDR);

    /* IP interface update */
    if (add)
    {   cicp_ipif_rowid_t rowid;
        rc = cicpos_ipif_import(session->control_plane, &rowid,
                                ifindex, net_ip, net_ipset, net_bcast,
                                ifmsg->ifa_scope);

	if (0 == rc)
	{   ci_assert(CICP_IPIF_ROWID_BAD != rowid);
	    ci_assert(rowid >= 0);
	    ci_bitset_add(CI_BITSET_REF(session->imported_ipif), rowid);
	}
        else
            ci_log("%s: cicpos_ipif_import failed, rc=%d", __FUNCTION__, rc);
    } else {
	cicpos_ipif_delete(session->control_plane, ifindex, net_ip, net_ipset);
        if (session->nosort) {
            session->nosort = CI_FALSE;
            DEBUGNETLINK(ci_log("%s: delete interface when dumping",
                   __FUNCTION__));
            /* \todo we should re-read the table in
             * this case. */
        }
    }

    return rc;
}





ci_inline int /* rc */
cicpos_dump_ipift(struct socket *sock, ci_uint32 seq,
		  cicpos_parse_state_t *session)
{   int rc;

    /* request the list of ip interfaces */
    if ((rc = request_table(sock, seq, RTM_GETADDR)) < 0 ) 
	ci_log(CODEID": ip interface list request "
	       "failed, rc %d", -rc);
	
    /* listen for reply */
    else if ((rc = read_rtnl_response(sock, seq,
				      &cicpos_handle_ipif_msg,
				      session,
				      &cicpos_ipif_post_poll)) < 0)
    ci_log(CODEID": reading of IP i/f list from rtnetlink "
	   "failed, rc %d",  -rc);

    return rc;
}







#endif /* CICPOS_USE_NETLINK */








/*****************************************************************************
 *                                                                           *
 *          Overall operation						     *
 *          =================						     *
 *                                                                           *
 *****************************************************************************/








#if CICPOS_USE_NETLINK


/**
 * Called whenever the rtnetlink listener receives a message. It's job
 * is to delegate the work to the right function.
 */
static int 
cicpos_handle_rtnl_msg(cicpos_parse_state_t *session, struct nlmsghdr *nlhdr)
{
    switch (nlhdr->nlmsg_type)
    {
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	    /* check that this is a message holding an ARP entry */
	    if (CI_UNLIKELY(nlhdr->nlmsg_type != RTM_NEWNEIGH))
	    {   CICPOS_MAC_STAT_INC_NL_MSG_REJECT(session->control_plane);
		CICP_LOG(DPRINTF("%s: nlmsg_type isn't RTM_NEWNEIGH, "
		                 "nlmsg_type=%d",
		                 __FUNCTION__, nlhdr->nlmsg_type));
	    } else
		return cicpos_handle_mac_msg(session, nlhdr);

	case RTM_NEWADDR:
	case RTM_DELADDR:
	    ci_assert(NULL != session->imported_ipif);
	    return cicpos_handle_ipif_msg(session, nlhdr);

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	    ci_assert(NULL != session->imported_route);
	    return cicpos_handle_route_msg(session, nlhdr);

	case RTM_NEWLINK:
	case RTM_DELLINK:
	    ci_assert(NULL != session->imported_llap);
	    return cicpos_handle_llap_msg(session, nlhdr);

	default:
	    ci_log(CODEID": unhandled netlink message type (%d) - "
		   "ignoring message",
		   nlhdr->nlmsg_type);
	    return -EINVAL;
    }
}




/** Note: this function ISN'T re-entrant
 *  If mac_only is set then only do an IP-MAC mapping update
 */
static void
cicpos_dump_tables(cicp_handle_t *control_plane, int /*bool*/ mac_only)
{   int rc;
    cicpos_parse_state_t *session;
    struct socket *sock = NULL;
    static __u32 seq = 1;

    session = cicpos_parse_state_alloc(control_plane);

    if (NULL == session)
    {   DEBUGNETLINK(DPRINTF(CODEID": (system table request "
			     "failed, out of memory)"));
	return;
    }

    cicpos_parse_init(session, control_plane);
    CICPOS_MAC_STAT_SET_POLLER_LAST_START(control_plane);

    /* setup socket */
    if ((rc = create_netlink_socket(&sock)) < 0 )
    {   ci_log(CODEID": failed to create netlink socket rc %d", rc);
	kfree(session);
	return;
    }
        
    cicpos_dump_mact(sock, seq, session);

    /* We do address resolution updates more often than than route/llap
       etc. updates. */
    if (!mac_only) 
    {   seq++;
        session->nosort = CI_TRUE;
	/* Ignore rc: if we failed to parse one table, it is not
         * the end of the world. */
	cicpos_dump_ipift(sock, seq, session);
	seq++;
	cicpos_dump_routet(sock, seq, session);
	seq++;
	cicpos_dump_llapt(sock, seq, session);
    }
    sock_release(sock);

    CICPOS_MAC_STAT_SET_POLLER_LAST_END(control_plane);

    cicpos_parse_state_free(session);
}






#endif /* CICPOS_USE_NETLINK */






/*! Initialize any driver-global synchronization control plane state */
extern int /* rc */
cicpos_ctor(cicp_mibs_kern_t *control_plane)
{   cicpos_procfs_ctor(control_plane);
    return cicpos_sync_ctor(control_plane);
}




/*! Indicate that  new (NIC) hardware is now available for use */
extern void
cicpos_hw_registered(cicp_handle_t *control_plane)
{   /* we don't really need to do anything at this time on Linux */
    return;
}




/*! Finalize any driver-global synchronization control plane state */
extern void
cicpos_dtor(cicp_mibs_kern_t *control_plane)
{   cicpos_procfs_dtor(control_plane);
    cicpos_sync_dtor(control_plane);
}








