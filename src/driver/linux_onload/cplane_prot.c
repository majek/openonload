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
**  \brief  Control Plane resolution protocol kernel code
**   \date  2005/07/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is relevant only to the kernel - it is not visible
 *  from the user-mode libraries.
 *
 *  This code is specific to the handling address resolution protocols in
 *  the control plane.
 */


/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/


#include "onload_internal.h"
#include "onload/cplane_prot.h"
#include "onload/cplane_ops.h"
#include "onload/debug.h"
#include <ci/net/arp.h>


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



#define CODEID "cplane prot"


#define CICPOSPL_MAC_TXBUF_PAGEMAX (4)  /* max page parts in jumbo pkt */

/* IP header + 8 bytes is smallest possible ICMP error payload */
#define CI_ICMP_MIN_PAYLOAD ( 60 + 8 )




/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DO(_x) _x
#define IGNORE(_x)


/* #define FORCEDEBUG */ /* include debugging even in NDEBUG builds */

#define DPRINTF ci_log


/* ARP module statistics access macros */
#define CICP_STAT_INC_DROPPED_IP(_cpl)     (++(_cpl)->stat.dropped_ip)


/*****************************************************************************
 *****************************************************************************
 *									     *
 *          PROT - Raw Socket Synchronization				     *
 *          =================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/






/*! create the raw socket */
static int cicp_raw_sock_ctor(struct socket **raw_sock)
{
  int on = 1;
  mm_segment_t oldfs;
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

  /* We've already done all the routing decisions.  Set SO_DONTROUTE */
  oldfs = get_fs();
  set_fs(KERNEL_DS);
  rc = sock_setsockopt(*raw_sock, SOL_SOCKET, SO_DONTROUTE, (void*)&on, sizeof(on));
  set_fs(oldfs);
  if( rc != 0 ) {
    /* If user does not use any complex policy routing, things will work
     * for them. */
    ci_log("ERROR: %s failed to set SO_DONTROUTE", __func__);
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



static int
cicp_raw_sock_send_bindtodev(struct oo_cplane_handle* cp,
                             int ifindex, ci_ip_addr_t ip_be32,
                             const void* buf, unsigned int size)
{
  struct cicppl_instance* cppl = &cp->cppl;
  struct net_device* dev = NULL;
  mm_segment_t oldfs;
  int rc;
  char* ifname;
  const struct cred *orig_creds = NULL;

  if( ifindex != cppl->bindtodevice_ifindex ) {
    dev = dev_get_by_index(cppl->cp->cp_netns, ifindex);
    if( dev != NULL ) 
      ifname = dev->name;
    else {
      OO_DEBUG_ARP(ci_log("%s: bad net device index %d", __FUNCTION__,
                          ifindex));
      return -EINVAL;
    }

    orig_creds = oo_cplane_empower_cap_net_raw(cp->cp_netns);
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    rc = sock_setsockopt(cppl->bindtodev_raw_sock, SOL_SOCKET, SO_BINDTODEVICE, 
                         ifname, strlen(ifname));
    set_fs(oldfs);
    oo_cplane_drop_cap_net_raw(orig_creds);

    if( dev != NULL )
      dev_put(dev);

    if( rc != 0 ) {
      OO_DEBUG_ARP(ci_log("%s: failed to BINDTODEVICE %d", __FUNCTION__, rc));
      return rc;
    }

    cppl->bindtodevice_ifindex = ifindex;
  }

  return cicp_raw_sock_send(cppl->bindtodev_raw_sock, ip_be32, buf, size);
}



/*****************************************************************************
 *                                                                           *
 *          Deferred packet transmission                                     *
 *          ============================                                     *
 *                                                                           *
 *****************************************************************************/




int cicp_raw_ip_send(struct oo_cplane_handle* cp,
                     const ci_ip4_hdr* ip, int len, ci_ifid_t ifindex,
                     ci_ip_addr_t next_hop)
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

  ci_assert(next_hop);
  ci_assert_ge(ifindex, 1);

  return cicp_raw_sock_send_bindtodev(cp, ifindex, next_hop, ip, len);
}


struct cicp_raw_sock_work_parcel {
  struct work_struct wqi;
  int pktid;
  struct oo_cplane_handle* cp;
  ci_ifid_t ifindex;
  ci_ip_addr_t ip;
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
  
  ci_assert(cicppl_pktbuf_is_valid_id(wp->cp->cppl.pktpool, wp->pktid));

  pkt = cicppl_pktbuf_pkt(wp->cp->cppl.pktpool, wp->pktid);
  if (CI_UNLIKELY(pkt == 0)) {
    ci_log("%s: BAD packet %d", __FUNCTION__, wp->pktid);
    goto out;
  }
  ip = (void*) (pkt + 1);

  rc = cicp_raw_ip_send(wp->cp, ip, pkt->len, wp->ifindex, wp->ip);
  OO_DEBUG_ARP(ci_log("%s: send packet to "CI_IP_PRINTF_FORMAT" via raw "
                    "socket, rc=%d", __FUNCTION__,
                    CI_IP_PRINTF_ARGS(&wp->ip), rc));
  if (CI_UNLIKELY(rc < 0)) {
    /* NB: we have not got a writeable pointer to the control plane -
           so we shouldn't really increment the statistics in it.
	   We will anyway though.
    */
    CICP_STAT_INC_DROPPED_IP(&wp->cp->cppl);
    OO_DEBUG_ARP(ci_log("%s: failed to queue packet, rc=%d", __FUNCTION__, rc));
  }

  /* release the ARP module buffer */
  spin_lock_bh(&wp->cp->cppl.lock);
  cicppl_pktbuf_free(wp->cp->cppl.pktpool, wp->pktid);
  spin_unlock_bh(&wp->cp->cppl.lock);
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
cicpplos_pktbuf_defer_send(struct oo_cplane_handle* cp,
                           ci_ip_addr_t ip, int pendable_pktid, 
                           ci_ifid_t ifindex)
/* schedule a workqueue task to send IP packet using the raw socket */
{
  struct cicp_raw_sock_work_parcel *wp = ci_atomic_alloc(sizeof(*wp));
  
  if (CI_LIKELY(wp != NULL)) {
    wp->pktid = pendable_pktid;
    wp->cp = cp;
    wp->ifindex = ifindex;
    wp->ip = ip;
    INIT_WORK(&wp->wqi, cicppl_arp_pkt_tx_queue);
    if( !in_atomic() )
      cicppl_arp_pkt_tx_queue(&wp->wqi);
    else
      ci_verify(schedule_work(&wp->wqi) != 0);
    return 0;
  } else {
    return -ENOMEM;
  } 
}



/*****************************************************************************
 *                                                                           *
 *          Packet Buffer Pool                                               *
 *          ==================	  				             *
 *                                                                           *
 *****************************************************************************/





#include <ci/tools/istack.h>


#define CICPPL_PKTBUF_SIZE                                      \
  (sizeof(struct cicp_bufpool_pkt) + CI_MAX_ETH_FRAME_LEN)


#define cicp_bufset_ptr(ref_bufset, id) \
        ((char *)(*(ref_bufset)) + (CICPPL_PKTBUF_SIZE * (id)))




/** Free buffer pool for deferred network packets awaiting MAC resolution */
typedef struct {
    unsigned  istack_size;
    unsigned  istack_ptr;
    ci_int16  istack_base[CPLANE_PROT_PKTBUF_COUNT];
} cicp_pktbuf_istack_t; /* conforming to "istack" definition */


struct cicp_bufpool_s
{  cicp_pktbuf_istack_t freebufs;
   char* bufmem;
} /* cicp_bufpool_t */;


struct cicp_bufpool_pkt *
cicppl_pktbuf_pkt(cicp_bufpool_t *pool, int id) 
{
  if( cicppl_pktbuf_is_valid_id(pool, id) )
    return (void*) (pool->bufmem + id * CICPPL_PKTBUF_SIZE);
  else
    return NULL;
}


/*  This function requires the control plane to be locked but does not
 *  lock it itself.
 */
extern int /* packet ID or negative if none available */
cicppl_pktbuf_alloc(cicp_bufpool_t *pool) 
{   int id = -1;
    
    if (pool != NULL && !ci_istack_empty(&pool->freebufs))
    {   id = ci_istack_pop(&pool->freebufs);
	ci_assert(cicppl_pktbuf_is_valid_id(pool, id));
    }

    return id;
}


void cicppl_pktbuf_free(cicp_bufpool_t *pool, int id)
{
  ci_assert(!ci_istack_full(&pool->freebufs));
  ci_istack_push(&pool->freebufs, (ci_int16) id);
}


static int cicppl_pktbuf_ctor(cicp_bufpool_t** out_pool)
{
  struct cicp_bufpool_pkt *pkt;
  cicp_bufpool_t* pool;
  int i;

  *out_pool = NULL;
  if( (pool = kmalloc(sizeof(*pool), GFP_KERNEL)) == NULL ) {
    ci_log(CODEID": ERROR - failed to allocate memory for buffer pool");
    return -ENOMEM;
  }
  pool->bufmem = vmalloc(CPLANE_PROT_PKTBUF_COUNT * CICPPL_PKTBUF_SIZE);
  if( pool->bufmem == NULL ) {
    ci_log(CODEID": ERROR - failed to allocate %ldKB of memory for "
           "%d packets awaiting MAC resolution",
           (long)(CICPPL_PKTBUF_SIZE*CPLANE_PROT_PKTBUF_COUNT/1024),
           CPLANE_PROT_PKTBUF_COUNT);
    kfree(pool);
    return -ENOMEM;
  }
  ci_istack_init(&pool->freebufs, CPLANE_PROT_PKTBUF_COUNT);
  for( i = 0; i < CPLANE_PROT_PKTBUF_COUNT; ++i ) {
    pkt = cicppl_pktbuf_pkt(pool, i);
    pkt->id = i;
    cicppl_pktbuf_free(pool, i);
  }
  *out_pool = pool;
  return 0;
}


static void cicppl_pktbuf_dtor(cicp_bufpool_t **ref_pool)
{
  cicp_bufpool_t* pool = *ref_pool;
  if( pool != NULL ) {
    vfree(pool->bufmem);
    kfree(pool);
    *ref_pool = NULL;
  }
}


/*****************************************************************************
 *                                                                           *
 *          O/S-specific Synchronization Overall Operation                   *
 *          ==============================================                   *
 *                                                                           *
 *****************************************************************************/






/*! Initialize any driver-global O/S specific protocol control plane state */
int /* rc */
cicpplos_ctor(struct cicppl_instance* cppl)
{  
  int rc;
    
  /* construct ARP table buffers (event queue unused in Linux) */
  rc = cicppl_pktbuf_ctor(&cppl->pktpool);
  if (CI_UNLIKELY(rc < 0)) {
    ci_log(CODEID": ERROR - couldn't construct ARP table buffers, rc=%d",
           -rc);
    return rc;
  } 

  /* cicp_raw_sock_ctor() calls sock_create(), which uses
   * current->nsproxy->net_ns.  We expect that we are called in the right
   * namespace. */
  ci_assert_equal(current->nsproxy->net_ns, cppl->cp->cp_netns);

  /* construct raw socket */
  if (CI_UNLIKELY((rc = cicp_raw_sock_ctor(&cppl->bindtodev_raw_sock)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct raw socket module, rc=%d",
           -rc);
    cicppl_pktbuf_dtor(&cppl->pktpool);
    return rc;
  } 
  cppl->bindtodevice_ifindex = 0; /* invalid ifindex */

  spin_lock_init(&cppl->lock);
  cppl->stat.dropped_ip = 0;

  return 0;
}


/*! Finalize any driver-global O/S specific protocol control plane state */
void
cicpplos_dtor(struct cicppl_instance *cppl)
{
  if( cppl->bindtodev_raw_sock != NULL )
    cicp_raw_sock_dtor(cppl->bindtodev_raw_sock);
  cicppl_pktbuf_dtor(&cppl->pktpool);
}


