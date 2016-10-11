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


#include "linux_cplane_internal.h"
#include <net/arp.h>
#include <linux/inetdevice.h>
/* Compat just for RHEL4 clock_t_to_jiffies() */
#include <linux/times.h>
#include <linux/random.h>
#include "driver/linux_affinity/kernel_compat.h" /* for PDE_DATA */
#include <net/sock.h>
#include <ci/tools/utils.h>
#include <ci/tools/iovec.h>
#include <ci/tools/ipcsum.h>
#include <onload/version.h> /* For ONLOAD_VERSION */


MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("Proprietary");
MODULE_VERSION(ONLOAD_VERSION);


/* Following set of three options define the control plane table sizes */

unsigned max_layer2_interfaces = 50;
module_param(max_layer2_interfaces, int, S_IRUGO);
MODULE_PARM_DESC(max_layer2_interfaces,
                 "Maximum number of LLAP interfaces (inc. bonds, vlans, etc)"
                 "in Onload's control plane tables");
unsigned max_local_addrs = 256;
module_param(max_local_addrs, int, S_IRUGO);
MODULE_PARM_DESC(max_local_addrs,
                 "Maximum number of rows in Onload's ipif table");
unsigned max_routes = 256;
module_param(max_routes, int, S_IRUGO);
MODULE_PARM_DESC(max_routes,
                 "Maximum number of rows in Onload's route table");
unsigned max_neighs = 1024;
module_param(max_neighs, int, S_IRUGO);
MODULE_PARM_DESC(max_neighs,
                 "Maximum number of rows in Onload's ARP/neighbour table."
                 "This is rounded up internally to a power of two");


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

#define CICPOS_PROCFS_FILE_LLAP    "mib-llap"
#define CICPOS_PROCFS_FILE_MAC     "mib-mac"
#define CICPOS_PROCFS_FILE_IPIF    "mib-ipif"
#define CICPOS_PROCFS_FILE_FWDINFO "mib-fwd"
#define CICPOS_PROCFS_FILE_BONDINFO "mib-bond"
#define CICPOS_PROCFS_FILE_PMTU    "mib-pmtu"



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

#define CODEID "cplane sync"

unsigned cplane_debug_bits = __CP_DEBUG_DEFAULT__;
module_param(cplane_debug_bits, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_debug_bits, "Cplane driver log level");



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
static struct socket *cicp_bindtodev_raw_sock;





/*! create the raw socket */
static int cicp_raw_sock_ctor(struct socket **raw_sock)
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
static void cicp_raw_sock_dtor(struct socket *raw_sock)
{
  sock_release(raw_sock);
}





static int
cicp_raw_sock_send(struct socket *raw_sock, ci_ip_addr_t ip_be32, 
                   const void* buf, unsigned int size)
{
  struct msghdr msg;
  struct kvec iov;
  struct sockaddr_in addr;
  int rc;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = ip_be32;

  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = MSG_DONTWAIT;

  iov.iov_base = (void*) buf;
  iov.iov_len  = size;

  rc = kernel_sendmsg(raw_sock, &msg, &iov, 1, size);

  return rc;
}



int cicp_raw_sock_send_bindtodev(int ifindex, char *ifname, 
                                 ci_ip_addr_t ip_be32,
                                 const void* buf, unsigned int size)
{
  static int last_ifindex = -1;
  struct net_device *dev = NULL;
  mm_segment_t oldfs;
  int rc;

  if( ifindex != last_ifindex ) {
    if( ifname == NULL ) {
      dev = dev_get_by_index(&init_net, ifindex);
      if( dev != NULL ) 
        ifname = dev->name;
      else {
        CP_DBG_ARP(ci_log("%s: bad net device index %d", __FUNCTION__,
                          ifindex));
        return -EINVAL;
      }
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    rc = sock_setsockopt(cicp_bindtodev_raw_sock, SOL_SOCKET, SO_BINDTODEVICE, 
                         ifname, strlen(ifname));
    set_fs(oldfs);

    if( dev != NULL )
      dev_put(dev);

    if( rc != 0 ) {
      CP_DBG_ARP(ci_log("%s: failed to BINDTODEVICE %d", __FUNCTION__, rc));
      return rc;
    }

    last_ifindex = ifindex;
  }

  return cicp_raw_sock_send(cicp_bindtodev_raw_sock, ip_be32, buf, size);
}



/*****************************************************************************
 *                                                                           *
 *          Deferred packet transmission                                     *
 *          ============================                                     *
 *                                                                           *
 *****************************************************************************/





cicp_bufpool_t *cicppl_pktpool = NULL;






int cicp_raw_ip_send(const ci_ip4_hdr* ip, int len, ci_ifid_t ifindex)
{
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

  if( ifindex != CI_IFID_BAD )
    return cicp_raw_sock_send_bindtodev(ifindex, NULL, ip->ip_daddr_be32, 
                                        ip, len);
  else 
    return cicp_raw_sock_send(cicp_raw_sock, ip->ip_daddr_be32, ip, len);
}


struct cicp_raw_sock_work_parcel {
  struct work_struct wqi;
  int pktid;
  const cicp_handle_t *control_plane;
  ci_ifid_t ifindex;
};


static void
cicppl_arp_pkt_tx_queue(struct work_struct *data)
{
  struct cicp_raw_sock_work_parcel *wp =
            container_of(data, struct cicp_raw_sock_work_parcel, wqi);
  struct cicp_bufpool_pkt* pkt;
  ci_ip4_hdr* ip;
  int rc;

  /* Now that we use raw sockets, we don't support sending an ARP requests
   * if the IP packet that caused the transaction isn't given */
  if (wp->pktid < 0) goto out;
  
  ci_assert(cicppl_pktbuf_is_valid_id(cicppl_pktpool, wp->pktid));

  pkt = cicppl_pktbuf_pkt(cicppl_pktpool, wp->pktid);
  if (CI_UNLIKELY(pkt == 0)) {
    ci_log("%s: BAD packet %d", __FUNCTION__, wp->pktid);
    goto out;
  }
  ip = (void*) (pkt + 1);

  rc = cicp_raw_ip_send(ip, pkt->len, wp->ifindex);
  CP_DBG_ARP(ci_log("%s: send packet to "CI_IP_PRINTF_FORMAT" via raw "
                    "socket, rc=%d", __FUNCTION__,
                    CI_IP_PRINTF_ARGS(&ip->ip_daddr_be32), rc));
  if (CI_UNLIKELY(rc < 0)) {
    /* NB: we have not got a writeable pointer to the control plane -
           so we shouldn't really increment the statistics in it.
	   We will anyway though.
    */
    CICP_STAT_INC_DROPPED_IP((cicp_handle_t *)wp->control_plane);
    CP_DBG_ARP(ci_log("%s: failed to queue packet, rc=%d", __FUNCTION__, rc));
  }

  /* release the ARP module buffer */
  CICP_BUFPOOL_LOCK(cicppl_pktpool,
	            cicppl_pktbuf_free(cicppl_pktpool, wp->pktid));
 out:
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
                           ci_ip_addr_t ip, int pendable_pktid, 
                           ci_ifid_t ifindex)
/* schedule a workqueue task to send IP packet using the raw socket */
{
  struct cicp_raw_sock_work_parcel *wp = ci_atomic_alloc(sizeof(*wp));
  
  if (CI_LIKELY(wp != NULL)) {
    wp->pktid = pendable_pktid;
    wp->control_plane = control_plane;
    wp->ifindex = ifindex;
    INIT_WORK(&wp->wqi, cicppl_arp_pkt_tx_queue);
    ci_verify(schedule_work(&wp->wqi) != 0);
    return 0;
  } else {
    return -ENOMEM;
  } 
}


static void 
cicpplos_handle_arp_data(struct work_struct *data)
{
  cicppl_handle_arp_data();
}

void
cicpplos_queue_arp(cicp_handle_t *control_plane, ci_ether_arp *arp,
                   ci_ifid_t ifindex, cicppl_rx_fifo_item_t *item_ptr)
{
  static struct work_struct wi;
  static int initialized = 0;
  if( !initialized ) {
    INIT_WORK(&wi, cicpplos_handle_arp_data);
    /*CI_WORKITEM_SET_CONTEXT(&wi, (void *)control_plane);*/
    initialized = 1;
  }

  /* populate the work item */
  item_ptr->ifindex = ifindex;
  memcpy(&item_ptr->arp, arp, sizeof(ci_ether_arp));

  /* add the work item to the rx fifo */
  cicppl_rx_fifo_push(item_ptr);

  /* schedule a job to consume the ARP packet at a better time */
  schedule_work(&wi);
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
  rc = cicppl_pktbuf_ctor(&cicppl_pktpool);
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
  if (CI_UNLIKELY((rc = cicp_raw_sock_ctor(&cicp_bindtodev_raw_sock)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct raw socket module, rc=%d",
           -rc);
    cicp_raw_sock_dtor(cicp_raw_sock);
    cicppl_pktbuf_dtor(&cicppl_pktpool);
    return rc;
  } 

  return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
/* We can not use dst_confirm() because we have no dst
 * and we do not want to use expensive neigh_update(). */
#define neigh_confirm(neigh) \
  do {                              \
    (neigh)->confirmed = jiffies;   \
  } while(0)
#endif

void cicpos_arp_stale_update(ci_ip_addr_t dst, ci_ifid_t ifindex, int confirm)
{
  struct net_device *dev;
  struct neighbour *neigh;

  dev = dev_get_by_index(&init_net, ifindex);

  if( dev == NULL )
    return;
  neigh = neigh_lookup(&arp_tbl, &dst, dev);
  /*ci_log("%s: ifindex %d ip "CI_IP_PRINTF_FORMAT" mac "
         CI_MAC_PRINTF_FORMAT" confirm %d state %x "
         "jiffies-neigh->confirmed=%ld reachable_time=%d/%d",
         __func__, ifindex, CI_IP_PRINTF_ARGS(&dst),
         CI_MAC_PRINTF_ARGS(neigh->ha), confirm, neigh->nud_state,
         jiffies - neigh->confirmed,
         arp_tbl.parms.reachable_time, neigh->parms->reachable_time);*/
  if( neigh != NULL && confirm) {
    if( neigh->nud_state == NUD_STALE)
      neigh_update(neigh, NULL, NUD_REACHABLE, NEIGH_UPDATE_F_ADMIN);
    else
      neigh_confirm(neigh);
    CICPOS_MAC_STAT_INC_REINFORCEMENTS(&CI_GLOBAL_CPLANE);
  }
  else {
    if( neigh == NULL )
      neigh = neigh_create(&arp_tbl, &dst, dev);
    neigh_event_send(neigh, NULL);
  }
  neigh_release(neigh);
  dev_put(dev);
}




/*! Finalize any driver-global O/S specific protocol control plane state */
extern void
cicpplos_dtor(cicp_mibs_kern_t *control_plane)
{   
  cicp_raw_sock_dtor(cicp_bindtodev_raw_sock);
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


static int 
cicp_stat_read_proc(struct seq_file *seq, void *s)
{
    cicp_stat_t *statp = procfs_control_plane(seq->private)->stat;
    ci_assert(statp);


#define CICP_READ_PROC_PRINT_CTR(counter) \
  seq_printf(seq, "%14s = %u\n", #counter, statp->counter)
#define CICP_READ_PROC_PRINT_TIME(timer) \
  seq_printf(seq, "%17s = %lu\n", #timer, statp->timer)
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
	seq_printf(seq, "%17s = %lu (%dHz)\n", "Time Now", jiffies, HZ);
    return 0;
}
static int cicp_stat_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, cicp_stat_read_proc, PDE_DATA(inode));
}
static const struct file_operations cicp_stat_fops = {
    .owner   = THIS_MODULE,
    .open    = cicp_stat_open_proc,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static int 
cicp_version_read_proc(struct seq_file *seq, void *s)
{
  /* Fixme: we probably want a call into the binary part here. */
  seq_printf(seq, "source:\t%s\n", ONLOAD_VERSION);
  seq_printf(seq, "API:\t%s\n", cicp_binary_version(CP_VERSION_API));
  seq_printf(seq, "library:%s\n", cicp_binary_version(CP_VERSION_LIB));
  return 0;
}
static int cicp_version_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, cicp_version_read_proc, 0);
}
static const struct file_operations cicp_version_fops = {
    .owner   = THIS_MODULE,
    .open    = cicp_version_open_proc,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};



static int
cicpos_llap_read(struct seq_file *seq, void *s)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);

    const cicp_llapinfo_t *llapt = control_plane->user.llapinfo_utable;

	if (NULL == llapt)
	    seq_printf(seq, "link layer access point table unallocated\n");
	else
	{   cicp_rowid_t llap_index;
	    int n = 0;

	    for (llap_index = 0;
		 llap_index < llapt->rows_max;
		 llap_index++)
	    {   const cicp_llap_row_t *row = &llapt->llap[llap_index];

		if (cicp_llap_row_allocated(row))
		{   CICP_LOCK_BEGIN(control_plane)
			/* better to use a read lock really */

			seq_printf(seq, "%02d: llap %02d %8s %4s mtu %d "
				   "ip "CI_IP_PRINTF_FORMAT"\tport ",
				   llap_index, row->ifindex, row->name,
				   row->up? "UP ": "DOWN", row->mtu,
				   CI_IP_PRINTF_ARGS(&row->ip_addr));
                        if (cicp_llap_row_hasnic(row))
			{
                            seq_printf(seq, "%1d ", row->hwport);
			    seq_printf(seq, "mac "CI_MAC_PRINTF_FORMAT,
				       CI_MAC_PRINTF_ARGS(&row->mac));
			} else
			{   seq_printf(seq, "X ");
			}
			if (row->encap.type & CICP_LLAP_TYPE_LOOP) {
			    seq_printf(seq, " LOOP");
			}
			if (row->encap.type & CICP_LLAP_TYPE_VLAN) {
			    seq_printf(seq, " VLAN %d",
				       row->encap.vlan_id);
			}
			if (row->encap.type & CICP_LLAP_TYPE_BOND) {
			    seq_printf(seq, " BOND HW%d ROW%d",
				       row->hwport, row->bond_rowid);
			}
			if (row->encap.type & 
			    CICP_LLAP_TYPE_USES_HASH) {
			    seq_printf(seq, " HASH");
			    if (row->encap.type & 
				CICP_LLAP_TYPE_XMIT_HASH_LAYER4) {
				seq_printf(seq, "-L4");
			    }
			}
			seq_printf(seq, "\n");

		    CICP_LOCK_END
		    n++;
		}
	    }

	    seq_printf(seq, "%d (of %d) allocated\n", n, llapt->rows_max);
	}
    return 0;
}
static int cicpos_llap_open(struct inode *inode, struct file *file)
{
    return single_open(file, cicpos_llap_read, PDE_DATA(inode));
}
static const struct file_operations cicpos_llap_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_llap_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


static void *cicpos_mac_read_start(struct seq_file *seq, loff_t *pos)
{
    cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
    const cicp_mac_mib_t *umact = control_plane->user.mac_utable;
    if (umact == NULL)
      return NULL;
    return (*pos <= cicp_mac_mib_rows(umact)) ? pos : NULL;
}
static void *cicpos_mac_read_next(struct seq_file *seq, void *v, loff_t *pos)
{
    (*pos)++;
    return cicpos_mac_read_start(seq, pos);
}
static void cicpos_mac_read_stop(struct seq_file *seq, void *s)
{
}
static int
cicpos_mac_read(struct seq_file *seq, void *s)
{
    cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
    const cicp_mac_mib_t *umact = control_plane->user.mac_utable;
    const cicp_mac_kmib_t *kmact = control_plane->mac_table;
    cicp_mac_rowid_t mac_index = *(loff_t *)s;

    if (NULL == umact)
    {
        seq_printf(seq, "user address resolution table unallocated\n");
    }
    else if (mac_index == cicp_mac_mib_rows(umact))
    {
        int n = 0;
        for (mac_index = 0; mac_index < cicp_mac_mib_rows(umact);
             mac_index++)
            if (cicp_mac_row_allocated(&umact->ipmac[mac_index]))
                n++;
        seq_printf(seq, "%d (of %d) allocated\n",
                   n, cicp_mac_mib_rows(umact));
    }
    else if (cicp_mac_row_allocated(&umact->ipmac[mac_index]))
    {
        const cicp_mac_row_t *row = &umact->ipmac[mac_index];
        const cicp_mac_kernrow_t *krow = &kmact->entry[mac_index];
        const cicpos_mac_row_t *sync = &krow->sync;

        CICP_LOCK_BEGIN(control_plane)
        /* better to use a read lock really */

        /* user-visible args */
        seq_printf(seq, "#%04x: llap %02d %8s ip "CI_IP_PRINTF_FORMAT
                   " mac "CI_MAC_PRINTF_FORMAT" on %3d%s%s",
                   mac_index, row->ifindex,
                   _cicp_llap_get_name(control_plane, row->ifindex),
                   CI_IP_PRINTF_ARGS(&row->ip_addr),
                   CI_MAC_PRINTF_ARGS(&row->mac_addr),
                   cicp_mac_row_usecount(row),
                   cicp_mac_row_enter_requested(row) ? " !service!": "",
                   row->need_update == CICP_MAC_ROW_NEED_UPDATE_STALE ?
                        " STALE" :
                        row->need_update == CICP_MAC_ROW_NEED_UPDATE_SOON ?
                        " almost-STALE" : "");
        /* O/S synch args */
        seq_printf(seq, " [u %08x up %08x ref %d %s%s%s%s%s%s%s%s%s%02X "
                   "%03d %s%s%s]",
                   sync->os.used, sync->os.updated, sync->os.refcnt,
                   0 == sync->os.state? "NONE ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_INCOMPLETE)?
                            "INCOMPLETE ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_REACHABLE)?
                            "REACHABLE ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_STALE) ? "STALE ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_DELAY) ? "DELAY ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_PROBE) ? "PROBE ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_FAILED) ?
                            "FAILED ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_NOARP)?  "NOARP ":"",
                   0 != (sync->os.state & CICPOS_IPMAC_PERMANENT)?
                            "PERMANENT ":"",
                   sync->os.flags, sync->os.family,
                   0 != sync->source_sync? "S": "s",
                   0 != sync->source_prot? "P": "p",
                   0 != sync->recent_sync? "R": "r");
        seq_printf(seq, " v%d rc %d\n", row->version, (ci_int16)row->rc);

        CICP_LOCK_END
    }

    return 0;
}
static struct seq_operations cicpos_mac_seq_ops = {
    .start = cicpos_mac_read_start,
    .next  = cicpos_mac_read_next,
    .stop  = cicpos_mac_read_stop,
    .show  = cicpos_mac_read,
};
static int cicpos_mac_open(struct inode *inode, struct file *file)
{
    int rc;
    rc = seq_open(file, &cicpos_mac_seq_ops);
    if (rc == 0)
        ((struct seq_file *)file->private_data)->private = PDE_DATA(inode);
    return rc;
}
static const struct file_operations cicpos_mac_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_mac_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release,
};





static int
cicpos_ipif_read(struct seq_file *seq, void *s)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
    const cicp_ipif_kmib_t *ipift = control_plane->ipif_table;
    
	if (NULL == ipift)
	    seq_printf(seq, "IP interface table unallocated\n");
	else
	{   cicp_rowid_t ipif_index;
	    int n = 0;

	    for (ipif_index = 0;
		 ipif_index < ipift->rows_max;
		 ipif_index++)
	    {   const cicp_ipif_row_t *row = &ipift->ipif[ipif_index];

		if (cicp_ipif_row_allocated(row))
		{   CICP_LOCK_BEGIN(control_plane)
			/* better to use a read lock really */
			seq_printf(seq, "%02d: llap %02d %4s "
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

	    seq_printf(seq, "%d (of %d) allocated\n", n, ipift->rows_max);
	}
    return 0;
}
static int cicpos_ipif_open(struct inode *inode, struct file *file)
{
    return single_open(file, cicpos_ipif_read, PDE_DATA(inode));
}
static const struct file_operations cicpos_ipif_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_ipif_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


static int 
cicpos_bond_read(struct seq_file *seq, void *s)
{
  cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
  const cicp_bondinfo_t *bondt;
  int n = 0;
  int i;
  
  bondt = control_plane->user.bondinfo_utable;
  

    if( bondt == NULL )
      seq_printf(seq, "bond table unallocated\n");
    else {
      for( i = 0; i < bondt->rows_max; i++ ) {
        const cicp_bond_row_t *row = &bondt->bond[i];
        if( cicp_bond_row_allocated(row) ) {
          CICP_LOCK_BEGIN(control_plane);

          if( row->type == CICP_BOND_ROW_TYPE_MASTER ) 
            seq_printf(seq, "Row %d: MST if %d, next %d, "
                            "mode %d, hash %d, slaves %d, actv_slaves %d, "
                            "actv_hwport %d\n",
                            i, row->ifid, row->next, 
                            row->master.mode, row->master.hash_policy,
                            row->master.n_slaves,
                            row->master.n_active_slaves,
                            row->master.active_hwport);
          else if( row->type == CICP_BOND_ROW_TYPE_SLAVE )
            seq_printf(seq, "Row %d: SLV if %d, next %d, "
                            "hwport %d, flags %d (%s)\n",
                            i, row->ifid, row->next, row->slave.hwport,
                            row->slave.flags, 
                            row->slave.flags & CICP_BOND_ROW_FLAG_ACTIVE ?
                            "Active" : "Inactive");
          else
            seq_printf(seq, "Bond row %d: BAD type %d\n", 
                            i, row->type);
          CICP_LOCK_END;

          ++n;
        }
      }
      seq_printf(seq, "%d (of %d) allocated\n", n, bondt->rows_max);
    }

  return 0;
}
static int cicpos_bond_open(struct inode *inode, struct file *file)
{
    return single_open(file, cicpos_bond_read, PDE_DATA(inode));
}
static const struct file_operations cicpos_bond_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_bond_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};



static void *cicpos_fwd_read_start(struct seq_file *seq, loff_t *pos)
{
    cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
    const cicp_fwdinfo_t *fwdt = control_plane->user.fwdinfo_utable;
    if (fwdt == NULL)
      return NULL;
    return (*pos <= fwdt->rows_max) ? pos : NULL;
}
static void *cicpos_fwd_read_next(struct seq_file *seq, void *v, loff_t *pos)
{
    (*pos)++;
    return cicpos_fwd_read_start(seq, pos);
}
static void cicpos_fwd_read_stop(struct seq_file *seq, void *s)
{
}
/*
 * FWD info retrieves series of blocks.  Block consists of 2 strings.
 */
static int
cicpos_fwd_read(struct seq_file *seq, void *s)
{   cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
    const cicp_fwdinfo_t *fwdt = control_plane->user.fwdinfo_utable;
    cicp_rowid_t fwd_index = *(loff_t *)s;

    if (NULL == fwdt)
    {
        seq_printf(seq, "user forwarding information unallocated\n");
    }
    else if (fwd_index == fwdt->rows_max) {
      int n = 0;
      for (fwd_index = 0; fwd_index < fwdt->rows_max; fwd_index++)
          if (cicp_fwd_row_allocated(&fwdt->path[fwd_index]))
              n++;
      seq_printf(seq, "%d (of %d) allocated\n", n, fwdt->rows_max);
    }
    else if (cicp_fwd_row_allocated(&fwdt->path[fwd_index]))
    {
        const cicp_fwd_row_t *row = &fwdt->path[fwd_index];
        /* better to use a read lock really */
        CICP_LOCK_BEGIN(control_plane)
        /* first string */
        seq_printf(seq, CI_IP_PRINTF_FORMAT"/%u -> "CI_IP_PRINTF_FORMAT
                   " llap %d %4s (id=%d)",
                   CI_IP_PRINTF_ARGS(&row->destnet_ip),
                   row->destnet_ipset,
                   CI_IP_PRINTF_ARGS(&row->first_hop),
                   row->dest_ifindex,
                   _cicp_llap_get_name(control_plane, row->dest_ifindex),
                   row->llap_rowid);
        seq_printf(seq, "\n");
        /* second string */
        seq_printf(seq, "\tmtu %d tos %d metric %d type %s",
                   row->mtu, row->tos, row->metric,
                   row->type == CICP_ROUTE_NORMAL ? "NORMAL" :
                   row->type == CICP_ROUTE_LOCAL ? "LOCAL" : "ALIEN");
        seq_printf(seq, "\tsrc ip "CI_IP_PRINTF_FORMAT"\n",
                   CI_IP_PRINTF_ARGS(&row->pref_source));
        CICP_LOCK_END
    }

    return 0;
}
static struct seq_operations cicpos_fwd_seq_ops = {
    .start = cicpos_fwd_read_start,
    .next  = cicpos_fwd_read_next,
    .stop  = cicpos_fwd_read_stop,
    .show  = cicpos_fwd_read,
};
static int cicpos_fwd_open(struct inode *inode, struct file *file)
{
    int rc;
    rc = seq_open(file, &cicpos_fwd_seq_ops);
    if (rc == 0)
        ((struct seq_file *)file->private_data)->private = PDE_DATA(inode);
    return rc;
}
static const struct file_operations cicpos_fwd_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_fwd_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release,
};


static int 
cicpos_pmtu_read(struct seq_file *seq, void *s)
{
  cicp_mibs_kern_t *control_plane = procfs_control_plane(seq->private);
  cicp_pmtu_kmib_t *pmtu_table = control_plane->pmtu_table;
  int i, n = 0;

  for( i = 0; i < pmtu_table->used_rows_max; i++ ) {
    cicp_pmtu_row_t *row = &pmtu_table->entries[i];
    CICP_LOCK_BEGIN(control_plane)
    if( cicp_pmtu_row_allocated(row) ) {
      seq_printf(seq, "%d: "CI_IP_PRINTF_FORMAT" timestamp=0x%lx\n",
                 i, CI_IP_PRINTF_ARGS(&row->net_ip), row->timestamp);
      n++;
    }
    CICP_LOCK_END;
  }

  seq_printf(seq, "%d (of %d) allocated, with maximum %d\n",
             n, pmtu_table->rows_max, pmtu_table->used_rows_max);
  return 0;
}
static int cicpos_pmtu_open(struct inode *inode, struct file *file)
{
    return single_open(file, cicpos_pmtu_read, PDE_DATA(inode));
}
static const struct file_operations cicpos_pmtu_fops = {
    .owner   = THIS_MODULE,
    .open    = cicpos_pmtu_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


static void
cicpos_procfs_ctor(cicp_mibs_kern_t *control_plane,
                   struct proc_dir_entry *cp_proc_root)
{   void *caller_info = control_plane;
    /* warning: the mechanism passing this to the read functions does not
                always seem to work */
    
    ci_assert(NULL != control_plane);

    /* if this function is called a number of times - for a number of different
       control planes, we want only one of them to be associated with the file
       names below */
    if (control_plane == &CI_GLOBAL_CPLANE)
    {
	ci_assert(NULL != cp_proc_root);

        proc_create_data("stats", 0, cp_proc_root,
                         &cicp_stat_fops, caller_info);
        proc_create_data("version", 0, cp_proc_root,
                         &cicp_version_fops, caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_LLAP, 0, cp_proc_root,
			 &cicpos_llap_fops, caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_MAC, 0, cp_proc_root,
			 &cicpos_mac_fops, caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_IPIF, 0, cp_proc_root,
			 &cicpos_ipif_fops,  caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_FWDINFO, 0, cp_proc_root,
			 &cicpos_fwd_fops,  caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_BONDINFO, 0, cp_proc_root,
			 &cicpos_bond_fops,  caller_info);
	proc_create_data(CICPOS_PROCFS_FILE_PMTU, 0, cp_proc_root,
			 &cicpos_pmtu_fops,  caller_info);
    }
}





static void
cicpos_procfs_dtor(cicp_mibs_kern_t *control_plane,
                   struct proc_dir_entry *cp_proc_root)
{   if (NULL != cp_proc_root)
    {
        remove_proc_entry(CICPOS_PROCFS_FILE_LLAP, cp_proc_root);
	remove_proc_entry(CICPOS_PROCFS_FILE_MAC, cp_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_IPIF, cp_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_FWDINFO, cp_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_BONDINFO, cp_proc_root);
        remove_proc_entry(CICPOS_PROCFS_FILE_PMTU, cp_proc_root);
        remove_proc_entry("stats", cp_proc_root);
        remove_proc_entry("version", cp_proc_root);
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
cicpos_dump_tables(cicp_handle_t *control_plane, int /*bool*/ mac_only,
                   char *buf);

typedef struct {
  struct socket *sock;
  __u32 seq;
} cicp_nlsock_t;









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






/*! Request the contents of the IP-MAC mapping (ARP) table, route table,
 *  link or address table
 */
static int 
request_table(cicp_nlsock_t *nlsock, int nlmsg_type, int rtm_flags,
              char* buf)
{
  struct msghdr msg;
  struct kvec iov;
  struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;
  struct rtmsg *rtm = (void *)(nlhdr+1);
  int ret;

  memset(buf, 0, NL_BUFSIZE);
  if( nlmsg_type == RTM_GETROUTE )
    nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  else
    nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
  nlhdr->nlmsg_type = nlmsg_type; /* RTM_GET* */
  nlhdr->nlmsg_flags = NLM_F_ROOT | NLM_F_REQUEST;
  nlhdr->nlmsg_seq = ++nlsock->seq;
  rtm->rtm_family = AF_INET;
  rtm->rtm_flags = rtm_flags;

  iov.iov_base = (void*)buf;
  iov.iov_len = nlhdr->nlmsg_len;
  msg.msg_name=NULL;
  msg.msg_namelen=0;
  msg.msg_controllen=0;
  msg.msg_flags=0;

  ret = kernel_sendmsg(nlsock->sock, &msg, &iov, 1, nlhdr->nlmsg_len);
  
  if (ret < 0) {
    ci_log("%s():kernel_sendmsg failed, err=%d", __FUNCTION__, ret);
    return ret;
    
  } else
  if(ret != nlhdr->nlmsg_len) {
    ci_log("%s():kernel_sendmsg failed. Read %d bytes but expected %d.",
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
    struct kvec iov;
    int rc;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    iov.iov_base = buf;
    iov.iov_len = count;

    msg.msg_name=&nladdr;
    msg.msg_namelen=sizeof(nladdr);
    msg.msg_control=0;
    msg.msg_controllen=0;
    msg.msg_flags = blocking ? 0 : MSG_DONTWAIT;

    rc = kernel_recvmsg(sock, &msg, &iov, 1, count, msg.msg_flags);

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
read_nl_msg(struct socket *sock, char *buf, int blocking,
            int retry)
{   int bytes;

    memset(buf, 0, NL_BUFSIZE);
    bytes = netlink_read(sock, (char *) buf, NL_BUFSIZE, blocking, retry);
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
read_rtnl_response(cicp_nlsock_t *nlsock, ci_rtnl_msg_handler_t *hf,
                   cicpos_parse_state_t *session,
		   ci_post_handling_fn_t *post_handling_fn,
                   char* buf)
{
  int rc, bytes;
  struct nlmsghdr *nlhdr;

  do {

    /* read an rtnetlink packet in non-blocking mode with retries */
    rc = bytes = read_nl_msg(nlsock->sock, buf, 0, 1);
    if (rc < 0) 
      return rc;
    else
    {	nlhdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(nlhdr, bytes)) {

	  if (nlhdr->nlmsg_seq != nlsock->seq) {
	    /* ignore unsolicited packets */
	    ci_log("%s: Unsolicited netlink msg, msg_seq=%d, expected_seq=%d",
		   __FUNCTION__, nlhdr->nlmsg_seq, nlsock->seq);

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
	  cicpos_parse_state_t *session, char* buf)
{
  int rc, bytes;
  struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;

  /* read an rtnetlink packet in non-blocking mode without retries */
  rc = bytes = read_nl_msg(sock, buf, 0, 0);
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
static struct delayed_work cicpos_update_work;

/*! Netlink socket */
static struct socket *NL_SOCKET;









/*! Warning: this function is NOT re-entrant
 */
static int
efab_netlink_poll_for_updates(cicp_handle_t *control_plane, char* buf)
{   
  int rc;
  cicpos_parse_state_t *session = cicpos_parse_state_alloc(control_plane);

  if( NULL == session )
    rc = -ENOMEM;
  else {
    cicpos_parse_init(session, control_plane);

    do
      rc = rtnl_poll(NL_SOCKET, &cicpos_handle_rtnl_msg, session, buf);
    while( rc == 0 );

    cicpos_parse_state_free(session);
  }
  return rc == -EAGAIN ? 0 : rc;
}




/*! control plane pollers */
static void 
cicpos_worker(struct work_struct *data)
{
    static unsigned int count = 0;
    static char buf[NL_BUFSIZE];
    cicp_handle_t *control_plane = &CI_GLOBAL_CPLANE;

    if( cicpos_timer_data.stop )
	return;

    if (count % 2 == 0)
        cicpos_dump_tables(control_plane, count%20, buf);
    efab_netlink_poll_for_updates(control_plane, buf);
    count++;

    schedule_delayed_work(&cicpos_update_work, CICPOS_SCAN_INTERVAL);
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

	    /*
	     * Start the timer that schedules a regular kernel system MIB poll.
	     * Regularity is achieved by re-registering the timer at each
	     * trigger.
	     */
	    INIT_DELAYED_WORK(&cicpos_update_work, cicpos_worker);
	    schedule_delayed_work(&cicpos_update_work, CICPOS_SCAN_INTERVAL);

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

	/* Stop MIB updates */
	cancel_delayed_work_sync(&cicpos_update_work);

	/* destroy the persistent netlink socket */
	sock_release(NL_SOCKET);

	DEBUGNETLINK(DPRINTF(CODEID": synchronizer destroyed"));
    }
}




#else

#define cicpos_sync_ctor(control_plane) (0)
#define cicpos_sync_dtor(control_plane)

#endif /* CICPOS_USE_NETLINK */





#if CICPOS_USE_NETLINK

#ifndef LOOPBACK_IFINDEX
/* Needed for <=3.2; not needed for >=3.10(rhel7) and >=3.16. */
#define LOOPBACK_IFINDEX 1
#endif

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
    int             ignore = 0;

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

    /* Only look at the main and local tables for now,
       ignore other tables */
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
                metric = *((ci_uint32 *)RTA_DATA(attr));
		break;

	    case RTA_SRC:
		ci_assert(rtmsg->rtm_flags & RTM_F_CLONED);
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

            case RTA_CACHEINFO: {
                /* Silently ignore: we are not interested */
                break;
            }

            case RTA_IIF: {
                /* Route with input interface:
                 * not interested in such route. */
                ignore = 1;
                break;
            }

#define RTA_UNSUPPORTED_PRINT_ONCE(rta) \
            case rta:                                           \
                if( ~unsupported_print_once & (1 << rta) ) {    \
                    ci_log(CODEID": ignoring "#rta);            \
                    unsupported_print_once |= (1 << rta);       \
                }                                               \
                break

            RTA_UNSUPPORTED_PRINT_ONCE(RTA_MULTIPATH);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_PROTOINFO);
            RTA_UNSUPPORTED_PRINT_ONCE(RTA_FLOW);
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

    if (ignore ||
        (rtmsg->rtm_type != RTN_UNICAST && (rtmsg->rtm_flags & RTM_F_CLONED))
        ) {
      /* silently ignore non-unicast cache routes: we need route cache for
       * pmtu only */
    }
    else
    {   /* route table update */
	cicp_route_type_t type = CICP_ROUTE_NORMAL;

        /* RTN_LOCAL route should be also RT_SCOPE_HOST,
         * but let's be sure. */
	if (rtmsg->rtm_scope == RT_SCOPE_HOST || rtmsg->rtm_type == RTN_LOCAL ) {
	    type = CICP_ROUTE_LOCAL;
	    ifindex = LOOPBACK_IFINDEX;
	}
        else if( rtmsg->rtm_type != RTN_UNICAST )
          type = CICP_ROUTE_ALIEN;

        if( (rtmsg->rtm_flags & RTM_F_CLONED) ) {
            int rowid = -1;
            ci_assert_equal(dest_ipset, 32);
            ci_assert_equal(nlhdr->nlmsg_type, RTM_NEWROUTE);
            /* We need route cache for PMTU only */
            if( mtu != 0 && rtmsg->rtm_type == RTN_UNICAST ) {
                rowid = cicpos_pmtu_check(session->control_plane,
                                          dest_ip, ifindex, mtu);
            }
            if( rowid != -1 )
              ci_bitset_add(CI_BITSET_REF(session->imported_pmtu), rowid);
            else
              ignore = 1;
        }

	if (nlhdr->nlmsg_type == RTM_NEWROUTE && !ignore)
	{   cicp_rowid_t rowid;

	    rc = cicpos_route_import(session-> control_plane, &rowid,
				     dest_ip, dest_ipset, type,
				     next_hop_ip, tos, metric,
				     pref_source, ifindex, mtu,
                                     session->nosort);
	    /* remember we've seen this route */
	    if (0 == rc)
	    {   ci_assert(CICP_ROWID_BAD != rowid);
		ci_assert(rowid >= 0);
		ci_bitset_add(CI_BITSET_REF(session->imported_route),
			      rowid);
	    }
            else {
                DEBUGNETLINK
                    (ci_log(CODEID": cicpos_route_import failed, rc=%d ", rc));
            }

	}
	if( nlhdr->nlmsg_type == RTM_DELROUTE ) {
	    cicpos_route_delete(session->control_plane, dest_ip,
                                dest_ipset, ifindex);
            if (session->nosort) {
                session->nosort = CI_FALSE;
                DEBUGNETLINK(ci_log("%s: delete route when dumping",
                                    __FUNCTION__));
                /* \todo we should re-read the table in this case. */
            }
	}
    }
    
    return rc;
}






/* You MUST call cicpos_dump_route_cache() with the same session
 * after successfull call to this function, to get
 * cicpos_route_post_poll() called. */
ci_inline int /* rc */
cicpos_dump_routet(cicp_nlsock_t *nlsock,
		   cicpos_parse_state_t *session, char *buf)
{   int rc;

    /* request the route table */
    if ((rc = request_table(nlsock, RTM_GETROUTE, 0, buf)) < 0 ) 
	ci_log(CODEID": route table request "
	       "failed, rc %d", -rc);

    /* listen for reply */
    else if ((rc = read_rtnl_response(nlsock,
				      &cicpos_handle_route_msg,
				      session,
				      NULL,
                                      buf))
	     < 0)
	ci_log(CODEID": failed to read route table from "
	       "rtnetlink, rc %d", -rc);

    return rc;
}

/* This function should not be necessary, because cicpos_dump_pmtu_cache()
 * dumps all interesting routes.  But Linux route cache is a mess, we
 * get incorrect mtu values when asking for a route to the given address. */
ci_inline int /* rc */
cicpos_dump_route_cache(cicp_nlsock_t *nlsock,
			cicpos_parse_state_t *session, char *buf)
{   int rc;

    /* request the route table */
    if ((rc = request_table(nlsock, RTM_GETROUTE, RTM_F_CLONED, buf)) < 0 ) 
	ci_log(CODEID": route cache table request "
	       "failed, rc %d", -rc);

    /* listen for reply */
    else if ((rc = read_rtnl_response(nlsock,
				      &cicpos_handle_route_msg,
				      session,
				      NULL,
                                      buf))
	     < 0)
	ci_log(CODEID": failed to read route cache table from "
	       "rtnetlink, rc %d", -rc);

    return rc;
}



ci_inline void
cicpos_dump_pmtu_row(cicp_nlsock_t *nlsock, int rowid,
		     cicpos_parse_state_t *session, char *buf)
{
  int rc;
  struct msghdr msg;
  struct kvec iov;
  ci_ip_addr_net_t net_ip = CICP_MIBS(session->control_plane)->
                                pmtu_table->entries[rowid].net_ip;
  struct nlmsghdr *nlhdr = (struct nlmsghdr *) buf;
  struct rtmsg *rtm = (void *)(nlhdr+1);
  struct rtattr *rta;

  if( net_ip == INADDR_ANY )
    return;

  memset(buf, 0, NL_BUFSIZE);
  nlhdr->nlmsg_type = RTM_GETROUTE;
  nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  nlhdr->nlmsg_flags = NLM_F_REQUEST;
  nlhdr->nlmsg_seq = ++nlsock->seq;
  rtm->rtm_family = AF_INET;
  rtm->rtm_flags = RTM_F_CLONED;
  rta = (void *)(rtm+1);
  rta->rta_type = RTA_DST;
  rta->rta_len = RTA_LENGTH(4);
  memcpy(RTA_DATA(rta), &net_ip, 4);
  rtm->rtm_dst_len = 32;
  nlhdr->nlmsg_len = NLMSG_ALIGN(nlhdr->nlmsg_len) + RTA_LENGTH(4);

  iov.iov_base = (void*)buf;
  iov.iov_len = nlhdr->nlmsg_len;
  msg.msg_name=NULL;
  msg.msg_namelen=0;
  msg.msg_controllen=0;
  msg.msg_flags=0;

  rc = kernel_sendmsg(nlsock->sock, &msg, &iov, 1, nlhdr->nlmsg_len);
  if( rc < 0 )
    return;

  rc = read_rtnl_response(nlsock, &cicpos_handle_route_msg,
                          session, NULL, buf);
}

ci_inline void
cicpos_dump_pmtu_cache(cicp_nlsock_t *nlsock,
			cicpos_parse_state_t *session, char *buf)
{
  cicp_pmtu_kmib_t *pmtu_table =
                CICP_MIBS(session->control_plane)->pmtu_table;
  int i;
  for( i = 0; i < pmtu_table->used_rows_max; i++)
    if( cicp_pmtu_row_allocated(&pmtu_table->entries[i]) ) {
      cicpos_dump_pmtu_row(nlsock, i, session, buf);
    }
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
    flush_scheduled_work();
}





/*! Indicate that the original content of this mapping could be altered
 *  - see driver header for documentation
 */
extern int /* bool */
cicpos_mac_kmib_row_update(cicp_handle_t *control_plane,
			   cicpos_mac_row_t *sync_row, cicp_mac_row_t *row,
			   const cicpos_mac_row_sync_t *os,
			   const ci_mac_addr_t *mac,
			   int /* bool */ alteration,
			   int /* bool */ *out_ignore_clash)
{
    int newly_valid = alteration;

    ci_assert(NULL != sync_row);
    *out_ignore_clash = 0;


    /* We do not accept:
     * - OS update with incomplete or none status:
     *   we are not interested
     * - Protocol update for a valid OS entry:
     *   we already have a valid OS entry, no need in unnecessary hacks.
     * - Protocol update for protocol entry:
     *   someone is playing nasty games unless we are adding new row
     */
    if (os != NULL &&
        (os->state == CICPOS_IPMAC_INCOMPLETE ||
         os->state == CICPOS_IPMAC_NONE))
        return 0;
    if (sync_row->source_sync && sync_row->os.state != CICPOS_IPMAC_FAILED &&
        os == NULL)
        return 0;
    if (os == NULL && !sync_row->source_sync && alteration &&
        !CI_MAC_ADDR_EQ(&row->mac_addr, mac))
        return 0;

    /* We ignore clash when it is internal OS behaviour */
    if (os != NULL && sync_row->source_sync)
        *out_ignore_clash = 1;

    {
	/* keep indentation for hg annotate */
	if (os != NULL)
	{   ci_uint16 orig_state = sync_row->os.state;
            memcpy(&sync_row->os, os, sizeof(sync_row->os));
	    sync_row->source_sync = 1;
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
    return alteration;
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
	/*CP_DBG_ARP(DPRINTF("%s: IPv4 only", __FUNCTION__));*/
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
    {   cicp_mac_verinfo_t rowinfo;

	rowinfo.row_version = CI_VERLOCK_BAD;
	rowinfo.row_index = CICP_ROWID_BAD;

	cicpos_mac_set(session->control_plane, &rowinfo, ifindex, ip_addr,
	               (const ci_mac_addr_t *)&mac_addr, &os);

	if (CICP_ROWID_BAD != rowinfo.row_index)
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
cicpos_dump_mact(cicp_nlsock_t *nlsock,
		 cicpos_parse_state_t *session, char *buf)
{   int rc;

    if (cicpos_mact_open(session->control_plane))
    {   /* request the ARP table */
	if ((rc = request_table(nlsock, RTM_GETNEIGH, 0, buf)) < 0) 
	    ci_log(CODEID": arp table request failed, rc %d", rc);

	/* listen for reply */
	else if ((rc = read_rtnl_response(nlsock,
					  &cicpos_handle_mac_msg,
					  session,
					  &cicpos_mac_post_poll,
                                          buf)) < 0)
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
    char              name[CPLANE_LLAP_NAME_MAX+1];
    ci_mac_addr_t     mac;	

    ci_assert(NULL != nlhdr);
    ci_assert(NULL != session);
    ci_assert_gt(rlen, 0);
    ci_assert(NULL != ifinfomsg);

    /* we are only interested in ethernet interfaces */
    if (ifinfomsg->ifi_type != ARPHRD_ETHER &&
        ifinfomsg->ifi_type != ARPHRD_LOOPBACK)
    {   /*ci_log("Only interested in ethernet interfaces");*/
	return 0;
    }

    attr = (struct rtattr *)IFLA_RTA(ifinfomsg);
    add = (nlhdr->nlmsg_type == RTM_NEWLINK);
    up = (0 != (ifinfomsg->ifi_flags & IFF_UP)); 
    
    memset(&name, 0, sizeof(name));
    memset(&mac, 0, sizeof(mac));


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
                /* On linux>=3.14 (and possibly earlier) loopback interface
                 * has no mtu; let's set a safe default. */
                if( mtu == 0 )
                    mtu = (ci_mtu_t) (-1);
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
    {   cicp_rowid_t rowid;

	rc = cicpos_llap_import(session->control_plane, &rowid,
	                        ifinfomsg->ifi_index,
	                        mtu, up,
                                ifinfomsg->ifi_type == ARPHRD_LOOPBACK ?
                                  CICP_LLAP_TYPE_LOOP : CICP_LLAP_TYPE_NONE,
                                &name[0], &mac);
	    
	/* remember we've seen this LLAP */
	if (0 == rc)
	{   ci_assert(CICP_ROWID_BAD != rowid);
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
cicpos_dump_llapt(cicp_nlsock_t *nlsock,
		  cicpos_parse_state_t *session, char *buf)
{   int rc;

    /* request the LLAP table */
    if ((rc = request_table(nlsock, RTM_GETLINK, 0, buf)) < 0 )
	ci_log(CODEID": route table request "
	       "failed, rc %d", -rc);

    /* listen for reply */
    else if ((rc = read_rtnl_response(nlsock,
				      &cicpos_handle_llap_msg,
				      session,
				      &cicpos_llap_post_poll,
                                      buf))
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
		/* From linux-3.1.3/net/ipv6/addrconf.c: This define
		 * is only used for IPv6 and this warning tends to spam
		 * the dmesg for certain users so silently ignoring
		 * it.
		 */
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
    {   cicp_rowid_t rowid;
        rc = cicpos_ipif_import(session->control_plane, &rowid,
                                ifindex, net_ip, net_ipset, net_bcast,
                                ifmsg->ifa_scope);

	if (0 == rc)
	{   ci_assert(CICP_ROWID_BAD != rowid);
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
cicpos_dump_ipift(cicp_nlsock_t *nlsock,
		  cicpos_parse_state_t *session, char *buf)
{   int rc;

    /* request the list of ip interfaces */
    if ((rc = request_table(nlsock, RTM_GETADDR, 0, buf)) < 0 ) 
	ci_log(CODEID": ip interface list request "
	       "failed, rc %d", -rc);
	
    /* listen for reply */
    else if ((rc = read_rtnl_response(nlsock,
				      &cicpos_handle_ipif_msg,
				      session,
				      &cicpos_ipif_post_poll,
                                      buf)) < 0)
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
		CP_DBG_ARP(DPRINTF("%s: nlmsg_type isn't RTM_NEWNEIGH, "
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
cicpos_dump_tables(cicp_handle_t *control_plane, int /*bool*/ mac_only,
                   char *buf)
{   int rc;
    cicpos_parse_state_t *session;
    cicp_nlsock_t nlsock = {
        .sock = NULL,
        .seq = 1
    };

    session = cicpos_parse_state_alloc(control_plane);

    if (NULL == session)
    {   DEBUGNETLINK(DPRINTF(CODEID": (system table request "
			     "failed, out of memory)"));
	return;
    }

    cicpos_parse_init(session, control_plane);
    CICPOS_MAC_STAT_SET_POLLER_LAST_START(control_plane);

    /* setup socket */
    if ((rc = create_netlink_socket(&nlsock.sock)) < 0 )
    {   ci_log(CODEID": failed to create netlink socket rc %d", rc);
	kfree(session);
	return;
    }
    CICP_STAT_SET_LAST_POLL_BGN(control_plane);
        
    /* We do address resolution updates more often than than route/llap
       etc. updates. */
    if (!mac_only) 
    {   session->nosort = CI_TRUE;
	/* Ignore rc: if we failed to parse one table, it is not
         * the end of the world. */
	cicpos_dump_ipift(&nlsock, session, buf);
	cicpos_dump_llapt(&nlsock, session, buf);
	cicpos_dump_routet(&nlsock, session, buf);
    }

    /* pmtu overwrites some route entries - do it next */
    cicpos_dump_pmtu_cache(&nlsock, session, buf);
    cicpos_dump_route_cache(&nlsock, session, buf);
    cicpos_route_post_poll(session);

    /* MAC table is the largest one, and if we fail to read the full
     * answer we spoil all the next tables.  So, read it the last. */
    cicpos_dump_mact(&nlsock, session, buf);

    CICP_STAT_SET_LAST_POLL_END(control_plane);
    sock_release(nlsock.sock);

    CICPOS_MAC_STAT_SET_POLLER_LAST_END(control_plane);

    cicpos_parse_state_free(session);
}






#endif /* CICPOS_USE_NETLINK */




static struct proc_dir_entry *cp_proc_root = NULL;


/*! Initialize any driver-global synchronization control plane state */
extern int /* rc */
cicpos_ctor(cicp_mibs_kern_t *control_plane)
{
    ci_assert_equal(cp_proc_root, NULL);
    cp_proc_root = proc_mkdir("driver/onload_cplane", NULL);
    if( cp_proc_root == NULL )
        return -ENOMEM;
    cicpos_procfs_ctor(control_plane, cp_proc_root);
    return cicpos_sync_ctor(control_plane);
}




/*! Finalize any driver-global synchronization control plane state */
extern void
cicpos_dtor(cicp_mibs_kern_t *control_plane)
{
    if( cp_proc_root == NULL )
        return;
    cicpos_procfs_dtor(control_plane, cp_proc_root);
    remove_proc_entry("driver/onload_cplane", NULL);
    cicpos_sync_dtor(control_plane);
}




extern void
cicpos_sync_tables(cicp_handle_t *control_plane)
{
    char *buf;
    /* This function is called in process context, but wants to use a kernel
     * buffer for a socket call, so we need to set use of kernel address
     * space.
     */
    mm_segment_t fs = get_fs();
    set_fs(get_ds());

    buf = ci_alloc(NL_BUFSIZE);

    if( buf ) {
        /* sync all tables */
        cicpos_dump_tables(control_plane, 0, buf);
        ci_free(buf);
    }

    set_fs(fs);
}


oo_os_timestamp_t oo_os_timestamp(void)
{
  return jiffies;
}



/* Cplane lock: we do not run in hard-interrupt context, so
 * we lock bottom-halvs only.  Cplane is used from various callbacks
 * (including NAPI callbacks) which can be bottom-halvs. */
struct oo_os_lock {
  spinlock_t lock;
#ifndef NDEBUG
  /* is_locked field is protected by the lock above, and should be changed
   * when the lock is held. */
  int        is_locked;
#endif
};

oo_os_lock_t oo_os_lock_alloc(void)
{
  struct oo_os_lock* l;
  l = kmalloc(sizeof(*l), GFP_KERNEL);
  if( l == NULL )
    return NULL;
  spin_lock_init(&l->lock);
#ifndef NDEBUG
  l->is_locked = 0;
#endif
  return l;
}
void oo_os_lock_free(oo_os_lock_t lock)
{
  kfree(lock);
}
void oo_os_lock_lock(oo_os_lock_t lock)
{
  struct oo_os_lock* l = lock;
  ci_assert(!in_irq());
  spin_lock_bh(&l->lock);
#ifndef NDEBUG
  l->is_locked = 1;
#endif
}
void oo_os_lock_unlock(oo_os_lock_t lock)
{
  struct oo_os_lock* l = lock;
#ifndef NDEBUG
  ci_assert(!in_irq());
  ci_assert(l->is_locked);
  l->is_locked = 0;
#endif
  spin_unlock_bh(&l->lock);
}
#ifndef NDEBUG
int oo_os_lock_is_locked(oo_os_lock_t lock)
{
  struct oo_os_lock* l = lock;
  return l->is_locked;
}
#endif


int ci_contig_shmbuf_alloc(ci_contig_shmbuf_t* kus, unsigned bytes) {
  ci_assert(bytes > 0);
  kus->bytes = CI_ROUND_UP(bytes, CI_PAGE_SIZE);
  ci_assert(! ci_in_atomic());
  kus->p = vmalloc(kus->bytes);
  return kus->p ? 0 : -ENOMEM;
}

void ci_contig_shmbuf_free(ci_contig_shmbuf_t* kus) {
  ci_assert(! ci_in_atomic());
  ci_assert(kus);  ci_assert(kus->p);
  vfree(kus->p);
  CI_DEBUG_ZERO(kus);
}


#define OO_OS_ALLOC_COOKIE_KMALLOC 1
#define OO_OS_ALLOC_COOKIE_VMALLOC 2
void* oo_os_alloc(int size, uintptr_t* cookie)
{
  ci_assert(!in_atomic());
  if( size < PAGE_SIZE ) {
    *cookie = OO_OS_ALLOC_COOKIE_KMALLOC;
    return kmalloc(size, GFP_KERNEL);
  }
  *cookie = OO_OS_ALLOC_COOKIE_VMALLOC;
  return vmalloc(size);
}
void oo_os_free(void* mem, uintptr_t cookie)
{
  if( cookie == OO_OS_ALLOC_COOKIE_KMALLOC )
    kfree(mem);
  else {
    ci_assert_equal(cookie, OO_OS_ALLOC_COOKIE_VMALLOC);
    vfree(mem);
  }
}


void oo_os_rand(ci_uint8* data, unsigned count)
{
  get_random_bytes(data, count);
}


/* Map any virtual address in the kernel address space to the physical page
** frame number.
*/
unsigned ci_va_to_pfn(void *addr)
{
  struct page *page = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
  ci_check(!in_atomic());

  page = vmalloc_to_page(addr);
#else
  unsigned long address = (unsigned long)addr;
  pgd_t *pgd;
  pmd_t *pmd;
  pte_t *ptep, pte;

  ci_check(!in_atomic());

  pgd = pgd_offset_k(address);
  if (pgd_none(*pgd) || pgd_bad(*pgd))
    return -1;

  pmd = pmd_offset(pgd, address);
  if (pmd_none(*pmd) || pmd_bad(*pmd))
    return -1;

  ptep = pte_offset_map(pmd, address);
  if (!ptep)
    return -1;

  pte = *ptep;
  if (pte_present(pte))
    page = pte_page(pte);	
  pte_unmap(ptep);
#endif

  return page ? page_to_pfn(page) : -1;
}
EXPORT_SYMBOL(ci_va_to_pfn);



#include "cplane_api_version.h"
static int __init cplane_module_init(void)
{
  int rc;

  ci_set_log_prefix("[onload_cplane] ");
  ci_log("Control Plane for Onload " ONLOAD_VERSION);
  ci_log("Control Plane API " CPLANE_API_VERSION);
  ci_log("Control Plane library %s", cicp_binary_version(CP_VERSION_LIB));
  ci_log("%s", ONLOAD_COPYRIGHT);

  if( strcmp(CPLANE_API_VERSION, cicp_binary_version(CP_VERSION_API)) != 0 ) {
    ci_log("Binary API version mismatch: %s vs %s",
           CPLANE_API_VERSION, cicp_binary_version(CP_VERSION_API));
    return -EPERM;
  }


  /* Allocate resources & construct the control plane  */
  if ((rc = cicp_ctor(&onload_cplane_handle, max_neighs, 
                      max_layer2_interfaces, max_local_addrs,
                      max_routes)) < 0)
    goto fail_cicp;

  rc = ci_bonding_init();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_bonding_init failed (%d)", __FUNCTION__, rc);
    goto fail_bonding;
  }

  rc = ci_teaming_init(&CI_GLOBAL_CPLANE);
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_teaming_init failed (%d)", __FUNCTION__, rc);
    goto failed_teaming;
  }

  rc = cicp_chrdev_ctor(THIS_MODULE->name);
  if( rc < 0 ) {
    ci_log("%s: ERROR: cicp_chrdev_ctor failed (%d)", __FUNCTION__, rc);
    goto failed_chrdev;
  }


  return 0;
failed_chrdev:
  ci_teaming_fini(&onload_cplane_handle);
failed_teaming:
  ci_bonding_fini();
fail_bonding:
  cicp_dtor(&onload_cplane_handle);
fail_cicp:
  return rc;
}
module_init(cplane_module_init);

static void cplane_module_exit(void)
{
  cicp_chrdev_dtor(THIS_MODULE->name);
  ci_teaming_fini(&onload_cplane_handle);
  ci_bonding_fini();
  cicp_dtor(&onload_cplane_handle);

}
module_exit(cplane_module_exit);



/* DRIVERLINK */
/* Used from driver/linux_onload/driverlink_ip.c */
EXPORT_SYMBOL(ci_bonding_set_timer_period);
EXPORT_SYMBOL(cicp_llap_get_encapsulation);
EXPORT_SYMBOL(cicp_llap_retrieve);
EXPORT_SYMBOL(cicp_llap_set_bond);
EXPORT_SYMBOL(cicp_llap_set_hwport);
EXPORT_SYMBOL(cicp_llap_set_vlan);
EXPORT_SYMBOL(cicp_llap_import);
EXPORT_SYMBOL(cicppl_handle_arp_pkt);
EXPORT_SYMBOL(cicp_licensing_has_state_been_set);
EXPORT_SYMBOL(cicp_licensing_get_challenge);
EXPORT_SYMBOL(cicp_licensing_validate_signature);

/* MMAP */
/* Used from lib/efthrm/tcp_helper_resource.c */
EXPORT_SYMBOL(ci_contig_shmbuf_alloc);
EXPORT_SYMBOL(ci_contig_shmbuf_free);
EXPORT_SYMBOL(cicpos_sync_tables);

/* FILTERS */
/* Used from lib/efthrm/oof_onload.c */
EXPORT_SYMBOL(cicp_get_active_hwport_mask);
EXPORT_SYMBOL(cicpos_callback_deregister);
EXPORT_SYMBOL(cicpos_callback_register);
EXPORT_SYMBOL(cicp_get_max_local_addr);
EXPORT_SYMBOL(cicppl_llap_get_mac);
EXPORT_SYMBOL(onload_cplane_handle);
/* Used from lib/efthrm/driverlink_filter.c */
EXPORT_SYMBOL(cicp_llap_get_hwport);
EXPORT_SYMBOL(cicppl_handle_icmp);

/* PROTOCOLS */
/* Used from lib/efthrm/ip_protocols.c */
EXPORT_SYMBOL(cicpos_pmtu_add);

/* TCP/IP: via wrappers */
/* Used from driver/linux_onload/linux_cplane_netif.c */
EXPORT_SYMBOL(cicpplos_pktbuf_defer_send);
EXPORT_SYMBOL(cicppl_pktbuf_alloc);
EXPORT_SYMBOL(cicppl_pktbuf_free);
EXPORT_SYMBOL(cicppl_pktbuf_pkt);
EXPORT_SYMBOL(cicppl_pktpool);

/* TCP/IP: have syscall */
/* Used from lib/transport/ip/cplane_ops.c */
EXPORT_SYMBOL(cicpos_mac_find_ip);
EXPORT_SYMBOL(cicp_mac_get);
EXPORT_SYMBOL(ci_hwport_bond_get);
/* Used from lib/transport/ip/tcp_tx.c */
EXPORT_SYMBOL(cicp_raw_ip_send);
/* Used from lib/transport/ip/udp_sockopts.c */
EXPORT_SYMBOL(cicp_user_find_home);
/* Used from lib/transport/ip/cplane_ops.c */
EXPORT_SYMBOL(oo_os_lock_lock);
EXPORT_SYMBOL(oo_os_lock_unlock);
/* Used from lib/transport/ip/ via cicp_ip_cache_mac_update() */
EXPORT_SYMBOL(cicp_mac_update);
/* Used from lib/transport/ip/ip_cmsg.c */
EXPORT_SYMBOL(cicp_llap_find);
