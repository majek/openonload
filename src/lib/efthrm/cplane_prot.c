/*
** Copyright 2005-2014  Solarflare Communications Inc.
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


#include <onload/debug.h>
#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>
#include <onload/cplane_prot.h>
#include <onload/cplane.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/tools/dllist.h>
#include <ci/tools.h>
#include <ci/net/arp.h>
#include <onload/tcp_driver.h>


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
    ci_int16  istack_base[CICPPL_PKTBUF_COUNT];
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
    
    CICP_BUFPOOL_CHECK_LOCKED(pool);

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




int cicppl_pktbuf_ctor(cicp_bufpool_t** out_pool)
{
  struct cicp_bufpool_pkt *pkt;
  cicp_bufpool_t* pool;
  int i;

  *out_pool = NULL;
  if( (pool = (cicp_bufpool_t *) ci_alloc(sizeof(*pool))) == NULL ) {
    ci_log(CODEID": ERROR - failed to allocate memory for buffer pool");
    return -ENOMEM;
  }
  pool->bufmem = ci_vmalloc(CICPPL_PKTBUF_COUNT * CICPPL_PKTBUF_SIZE);
  if( pool->bufmem == NULL ) {
    ci_log(CODEID": ERROR - failed to allocate %ldKB of memory for "
           "%d packets awaiting MAC resolution",
           (long)(CICPPL_PKTBUF_SIZE*CICPPL_PKTBUF_COUNT/1024),
           CICPPL_PKTBUF_COUNT);
    ci_free(pool);
    return -ENOMEM;
  }
  ci_istack_init(&pool->freebufs, CICPPL_PKTBUF_COUNT);
  for( i = 0; i < CICPPL_PKTBUF_COUNT; ++i ) {
    pkt = cicppl_pktbuf_pkt(pool, i);
    pkt->id = i;
    cicppl_pktbuf_free(pool, i);
  }
  *out_pool = pool;
  return 0;
}


void cicppl_pktbuf_dtor(cicp_bufpool_t **ref_pool)
{
  cicp_bufpool_t* pool = *ref_pool;
  if( pool != NULL ) {
    ci_vfree(pool->bufmem);
    ci_free(pool);
    *ref_pool = NULL;
  }
}



static int pkt_chain_copy(ci_netif* ni, ci_ip_pkt_fmt* src_head,
                          struct cicp_bufpool_pkt* dst)
{
  ci_ip_pkt_fmt* src_pkt = src_head;
  int n, n_seg, bytes_copied, seg_i;
  char* dst_ptr = (void*) (dst + 1);
  const char* src_ptr;

  ci_assert_equal(oo_ether_type_get(src_head), CI_ETHERTYPE_IP);
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(src_head)), sizeof(ci_ip4_hdr));
  n_seg = CI_MIN(src_head->n_buffers, CI_IP_PKT_SEGMENTS_MAX);

  bytes_copied = 0;
  seg_i = 0;
  /* Start copying from the IP header. */
  n = src_pkt->buf_len - oo_ether_hdr_size(src_pkt);
  src_ptr = PKT_START(src_pkt) + oo_ether_hdr_size(src_pkt);

  while( 1 ) {
    if( bytes_copied + n > CI_MAX_ETH_FRAME_LEN )
      /* Protect against corrupted packet. */
      break;
    memcpy(dst_ptr, src_ptr, n);
    dst_ptr += n;
    bytes_copied += n;
    ++seg_i;
    if( OO_PP_IS_NULL(src_pkt->frag_next) || seg_i == n_seg )
      break;
    src_pkt = PKT_CHK(ni, src_pkt->frag_next);
    n = src_pkt->buf_len;
    src_ptr = PKT_START(src_pkt);
  }

  dst->len = bytes_copied;
  return bytes_copied;
}


/**
 * Very restricted copying of an IP packet in to a packet buffer. 
 *
 * \param netif             owner of the source packet
 * \param netif_ip_pktid    Netif packet ID of the source packet
 * \param dst               destination packet from ARP table poll
 *
 * \retval 0                Success
 * \retval -EFAULT          Failed to convert efab address to kernel
 *                          virtual address
 *
 * \attention It's assumed that the segments after the first contain
 *            data from the pinned pages.
 *
 * Only data and its length is copied. No metadata are copied.
 *
 * This operation assumes that \c dst is from contiguous vm_alloc()'ed memory
 */
int cicppl_ip_pkt_flatten_copy(ci_netif* ni, oo_pkt_p src_pktid,
                               struct cicp_bufpool_pkt* dst)
{
  ci_ip_pkt_fmt *pkt = PKT(ni, src_pktid);  

#ifndef NDEBUG
  ci_assert(ni);
  ci_assert(pkt);
  ASSERT_VALID_PKT(ni, pkt);
#endif
  ci_assert_gt(pkt->refcount, 0);

  if( oo_tcpdump_check(ni, pkt, OO_INTF_I_SEND_VIA_OS) ) {
    pkt->intf_i = OO_INTF_I_SEND_VIA_OS;
    memset(oo_ether_dhost(pkt), 0, 2 * ETH_ALEN);
    oo_tcpdump_dump_pkt(ni, pkt);
  }

  return pkt_chain_copy(ni, pkt, dst);
}








/*****************************************************************************
 *                                                                           *
 *          ICMP Server							     *
 *          ===========							     *
 *                                                                           *
 *****************************************************************************/





	

ci_inline int /* rc */
cicppl_handle_ping(cicp_handle_t *control_plane,
		   ci_icmp_hdr *icmp_hdr, size_t icmp_len,
		   ci_ip_addr_t from_ip)
{   return -EINVAL;
}







/*! Finalize driver-global ICMP server protocol control plane state */
ci_inline void
cicppl_icmpd_dtor(cicp_mibs_kern_t *control_plane)
{   return;
}








/*****************************************************************************
 *                                                                           *
 *          (Kernel) ICMP Handler                                            *
 *          =====================					     *
 *                                                                           *
 *****************************************************************************/







extern int /* rc */
cicppl_handle_icmp(cicp_handle_t *control_plane,
		   const ci_ip4_hdr* ip_pkt, size_t hw_len)
{   int rc = -EINVAL;
    size_t icmp_len = CI_BSWAP_BE16(ip_pkt->ip_tot_len_be16) -
			(CI_IP4_IHL(ip_pkt)+sizeof(ci_icmp_msg));
    /* decode icmp reply */
    ci_icmp_hdr *icmp_hdr = (void *)((char*)ip_pkt +
				     CI_IP4_IHL(ip_pkt));
    ci_uint8 icmp_type = icmp_hdr->type;
    ci_ip_addr_t to_ip = ip_pkt->ip_daddr_be32;
    ci_ip_addr_t from_ip = ip_pkt->ip_saddr_be32;
    ci_ip_addr_kind_t addrtype;

    /* Caller guarantees that there is ci_icmp_hdr in the packet, not
     * ci_icmp_msg + echo data.  
     * Non-first fragments can't come here, but we are not interested in
     * fragmented packets at all. */
    if( icmp_len <= 0 || (ip_pkt->ip_frag_off_be16 & CI_IP4_FRAG_MORE) != 0 )
      return rc;

    rc = cicp_ipif_addr_kind(control_plane, to_ip, &addrtype);

    if (addrtype.bits.is_ownaddr || addrtype.bits.is_broadcast) {
	if (icmp_type == CI_ICMP_ECHO)
	    rc = cicppl_handle_ping(control_plane, icmp_hdr, icmp_len,
				    from_ip);

	OO_DEBUG_IPP(
	    if (rc != 0)
		DPRINTF(CODEID": ICMP OP %02X from "CI_IP_PRINTF_FORMAT
			" failed rc %d",
			icmp_type,
			CI_IP_PRINTF_ARGS(&from_ip), -rc);
	);
    } else
    {   OO_DEBUG_IPP(
	    DPRINTF(CODEID": ICMP OP %02X from "CI_IP_PRINTF_FORMAT
		    " to "CI_IP_PRINTF_FORMAT" is not for us",
		    icmp_type, CI_IP_PRINTF_ARGS(&from_ip),
		    CI_IP_PRINTF_ARGS(&to_ip));
	);
    }

    return rc;
}




/*****************************************************************************
 *                                                                           *
 *          Processing of ARP incoming packets                               *
 *          =====================================			     *
 *                                                                           *
 *****************************************************************************/




#define CICPPL_RX_FIFO_POOL_SIZE 48

typedef struct {
  ci_dllink     dllink;
  ci_ifid_t     ifindex;
  ci_ether_arp  arp;
} cicppl_rx_fifo_item_t;



typedef struct {
  ci_irqlock_t lock;   /*!< lock that protects the whole struct */
  ci_dllist free_list; /*!< list of free items */
  ci_dllist fifo_list; /*!< list of items ready to be processed */
  /*! memory pool - pool of items used and free */
  cicppl_rx_fifo_item_t pool[CICPPL_RX_FIFO_POOL_SIZE];
} cicppl_rx_fifo_t;



/*! FIFO between driverlink and ARP processor */
static cicppl_rx_fifo_t static_fifo;



ci_inline int cicppl_rx_fifo_is_valid_id(int id)
{
  return (id >= 0 && id < CICPPL_RX_FIFO_POOL_SIZE);
}



ci_inline void 
cicppl_rx_fifo_ctor(cicppl_rx_fifo_t *fifo)
{
  int i;
  ci_irqlock_ctor(&fifo->lock);
  ci_dllist_init(&fifo->free_list);
  ci_dllist_init(&fifo->fifo_list);
  for (i=0; i < CICPPL_RX_FIFO_POOL_SIZE; i++)
    ci_dllist_push(&fifo->free_list, &fifo->pool[i].dllink);
}



ci_inline void 
cicppl_rx_fifo_dtor(cicppl_rx_fifo_t *fifo)
{
  /* flush the workqueue to make sure there are no pending ARP work items */
  flush_workqueue(CI_GLOBAL_WORKQUEUE);
  ci_irqlock_dtor(&fifo->lock);
}



ci_inline cicppl_rx_fifo_item_t *
cicppl_rx_fifo_get_from_free_list(cicppl_rx_fifo_t *fifo)
{
  ci_dllink *item_ptr;
  ci_irqlock_state_t lock_state;

  ci_irqlock_lock(&fifo->lock, &lock_state);
  item_ptr = ci_dllist_try_pop(&fifo->free_list);
  ci_irqlock_unlock(&fifo->lock, &lock_state);

  return CI_CONTAINER(cicppl_rx_fifo_item_t, dllink, item_ptr);
}


ci_inline void
cicppl_rx_fifo_add_to_free_list(cicppl_rx_fifo_t *fifo,
                                cicppl_rx_fifo_item_t *item_ptr)
{
  ci_irqlock_state_t lock_state;
  ci_irqlock_lock(&fifo->lock, &lock_state);
  ci_dllist_push(&fifo->free_list, &item_ptr->dllink);
  ci_irqlock_unlock(&fifo->lock, &lock_state);
}


ci_inline void
cicppl_rx_fifo_push(cicppl_rx_fifo_t *fifo,
                    cicppl_rx_fifo_item_t *item_ptr)
{
  ci_irqlock_state_t lock_state;
  ci_irqlock_lock(&fifo->lock, &lock_state);
  ci_dllist_push(&fifo->fifo_list, &item_ptr->dllink);
  ci_irqlock_unlock(&fifo->lock, &lock_state);
}


ci_inline cicppl_rx_fifo_item_t *
cicppl_rx_fifo_pop(cicppl_rx_fifo_t *fifo)
{
  ci_irqlock_state_t lock_state;
  cicppl_rx_fifo_item_t *item_ptr = NULL;

  ci_irqlock_lock(&fifo->lock, &lock_state);

  if ( ! ci_dllist_is_empty(&fifo->fifo_list) ) {
    item_ptr = CI_CONTAINER(cicppl_rx_fifo_item_t, dllink,
                            ci_dllist_pop_tail(&fifo->fifo_list));
  }
  ci_irqlock_unlock(&fifo->lock, &lock_state);

  return item_ptr;
}



/*****************************************************************************
 *                                                                           *
 *          RX ARP packet handling                                           *
 *          ======================	  				     *
 *                                                                           *
 *****************************************************************************/








static int /*rc*/
cicppl_arp_check_src(cicp_handle_t *control_plane,
		     ci_ip_addr_t src_ip, ci_ifid_t ifindex)
{   /* if it local broadcast or multicast then it is not valid */
    if (CI_IP_ADDR_IS_EMPTY(&src_ip) ||
	CI_IP_ADDR_IS_BROADCAST(&src_ip) ||
	CI_IP_ADDR_IS_MULTICAST(&src_ip))

        return -EINVAL;
    else
        /* if it is a net-directed broadcast then it is not valid */
        return cicp_ipif_net_or_brd_addr(control_plane, ifindex, &src_ip);
} 
  


static int /*rc*/
cicppl_arp_check_mac(ci_uint8 *mac)
{
  /* if it an empty MAC address it is not valid */
  if (CI_MAC_ADDR_IS_EMPTY((ci_mac_addr_t *)mac))
  { 
    return -EINVAL;
  }
    
  return 0;
} 
  


static int /*rc*/
cicppl_arp_pkt_update(cicp_handle_t *control_plane,
		      ci_ether_arp *arp, ci_ifid_t ifindex)
{
  ci_assert(arp);

  /* check that it the correct H/W type */
  if (arp->hdr.arp_hw_type_be16 != CI_ARP_HW_ETHER) {
    CICP_STAT_INC_UNSUPPORTED(control_plane);
    OO_DEBUG_ARP(DPRINTF("%s: I can only handle ethernet ARP, hw_type=%d",
		      __FUNCTION__, CI_BSWAP_BE16(arp->hdr.arp_hw_type_be16)));
    return -EINVAL;
  }
  else
   /* check that it the correct protocol type */
  if (arp->hdr.arp_prot_type_be16 != CI_ARP_PROT_IP) {
    CICP_STAT_INC_UNSUPPORTED(control_plane);
    OO_DEBUG_ARP(DPRINTF("%s: I can only handle ethernet ARP, prot_type=%d",
		      __FUNCTION__,
		      CI_BSWAP_BE16(arp->hdr.arp_prot_type_be16)));
    return -EINVAL;
  }
  else
  /* check that it is an ARP request or reply */
  if (arp->hdr.arp_op_be16 != CI_ARP_REQUEST
      && arp->hdr.arp_op_be16 != CI_ARP_REPLY)
  {
    CICP_STAT_INC_UNSUPPORTED(control_plane);
    OO_DEBUG_ARP(DPRINTF("%s: I can only handle ARP REQ or REPL, arp_op=%d",
		      __FUNCTION__, CI_BSWAP_BE16(arp->hdr.arp_op_be16)));
    return -EINVAL;
  }
  else
  /* check source IP address of packet for validity */
  if (cicppl_arp_check_src(control_plane,
			   *(ci_ip_addr_t*) CI_ETHER_ARP_SRC_IP_PTR(arp),
			   ifindex)) {
    CICP_STAT_INC_PKT_REJECT(control_plane);
    OO_DEBUG_ARP(DPRINTF(CODEID": Dropping ARP pkt due to it having "
		      "a bad src IP addr."));
    return -EINVAL;
  }
  else
  /* check MAC address of packet for validity */
  if (0 != cicppl_arp_check_mac(CI_ETHER_ARP_SRC_MAC_PTR(arp))) {
    CICP_STAT_INC_PKT_REJECT(control_plane);
    OO_DEBUG_ARP(DPRINTF(CODEID": Dropping ARP pkt for "
		      CI_IP_PRINTF_FORMAT" due to "
                      "it having a zero MAC addr.",
		      CI_IP_PRINTF_ARGS(CI_ETHER_ARP_SRC_IP_PTR(arp))));
    return -EINVAL;
  }
  else
  {   /* update counters */
      if (arp->hdr.arp_op_be16 == CI_ARP_REQUEST)
	CICP_STAT_INC_REQ_RECV(control_plane);
      else
	CICP_STAT_INC_REPL_RECV(control_plane);

      /* update the table */
      cicp_mac_set(control_plane, /*out_rowid*/ NULL,
		   (ci_ifid_t)ifindex, *CI_ETHER_ARP_SRC_IP_PTR(arp),
		   (const ci_mac_addr_t *)(CI_ETHER_ARP_SRC_MAC_PTR(arp)));

      return 0;
  }
}



/*! Work item routine that get scheduled in the work queue and reads ARP
    headers from the fifo and updates the arp table. */
static void 
cicppl_handle_arp_data(struct work_struct *data)
{
  cicppl_rx_fifo_item_t *item_ptr;
  cicp_handle_t *control_plane = &CI_GLOBAL_CPLANE;
  
  /* is there anything to do? */
  while (NULL != (item_ptr = cicppl_rx_fifo_pop(&static_fifo))) {
    OO_DEBUG_VERB(DPRINTF(CODEID": "CI_ARP_PRINTF_FORMAT " llap "
	              CI_IFID_PRINTF_FORMAT,
                      CI_ARP_PRINTF_ARGS(&item_ptr->arp), item_ptr->ifindex));

    /* update ARP table */
    CICP_STAT_SET_PKT_LAST_RECV(control_plane);

    cicppl_arp_pkt_update(control_plane, &item_ptr->arp,
			  item_ptr->ifindex);
    
    
    /* release ARP data buffer */
    cicppl_rx_fifo_add_to_free_list(&static_fifo, item_ptr);
  }
}




/*! Check that the dest address of the ARP and ethernet headers match the
 *  MAC address of the layer 2 interface. Only applies for ARP replies.
 */
static int
cicppl_chk_arp_dest_addr(cicp_handle_t *control_plane,
			 ci_mac_addr_t *ether_mac, ci_ether_arp *arp,
			 ci_mac_addr_t *ourmac, ci_ifid_t ifindex)
{
    ci_mac_addr_t *arp_tgt_mac;

    ci_assert(arp->hdr.arp_op_be16 == CI_ARP_REPLY);

    arp_tgt_mac = (ci_mac_addr_t *)CI_ETHER_ARP_TGT_MAC_PTR(arp);

    /* check that the dest fields match */
    if (!CI_MAC_ADDR_EQ(ether_mac, arp_tgt_mac))
    {   OO_DEBUG_ARP(DPRINTF(CODEID": ethenet hdr dest("CI_MAC_PRINTF_FORMAT") "
			  "doesn't match ARP hdr dest("
			  CI_MAC_PRINTF_FORMAT")",
			  CI_MAC_PRINTF_ARGS(ether_mac),
			  CI_MAC_PRINTF_ARGS(arp_tgt_mac)));
	return -EINVAL;
    } else

    /* check that the dest field matches our MAC address */
    if (!CI_MAC_ADDR_EQ(ether_mac, ourmac) &&
	!CI_MAC_ADDR_IS_BROADCAST(ether_mac))
    {   OO_DEBUG_ARP(DPRINTF(CODEID": our MAC addr("CI_MAC_PRINTF_FORMAT
			  " llap "CI_IFID_PRINTF_FORMAT") "
			  "doesn't match the ARP dest("
			  CI_MAC_PRINTF_FORMAT")",
			  CI_MAC_PRINTF_ARGS(ourmac), ifindex,
			  CI_MAC_PRINTF_ARGS(ether_mac)));
	return -EINVAL;
    } else

        return 0;
}


static void
cicppl_queue_arp(cicp_handle_t *control_plane, ci_ether_arp *arp,
                 ci_ifid_t ifindex)
{
  cicppl_rx_fifo_item_t *item_ptr =
      cicppl_rx_fifo_get_from_free_list(&static_fifo);
  static struct work_struct wi;
  static int initialized = 0;
  if( !initialized ) {
    INIT_WORK(&wi, cicppl_handle_arp_data);
    /*CI_WORKITEM_SET_CONTEXT(&wi, (void *)control_plane);*/
    initialized = 1;
  }

  if (NULL != item_ptr) {
    /* populate the work item */
    item_ptr->ifindex = ifindex;
    memcpy(&item_ptr->arp, arp, sizeof(ci_ether_arp));

    /* add the work item to the rx fifo */
    cicppl_rx_fifo_push(&static_fifo, item_ptr);

    /* schedule a job to consume the ARP packet at a better time */
    queue_work(CI_GLOBAL_WORKQUEUE, &wi);
  } else {
    CICP_STAT_INC_FIFO_OVERFLOW(control_plane);
    OO_DEBUG_ARP(DPRINTF(CODEID": dropped received ARP packet - "
		         "work queue full?"));
  }
}



/*! Queue the packet and schedule a task to consume it */
extern void
cicppl_handle_arp_pkt(cicp_handle_t *control_plane,
		      ci_ether_hdr *ethhdr, ci_ether_arp *arp,
		      ci_ifid_t ifindex, int is_slave)
{
  ci_mac_addr_t ourmac;
  int rc = 0;

#if CI_CFG_TEAMING
  /* If it's a bond slave, find the master ifindex */
  if( is_slave ) {
    rc = cicp_bond_get_master_ifindex(control_plane, ifindex, &ifindex);
    if( rc != 0 ) {
      OO_DEBUG_ARP(DPRINTF(CODEID": couldn't find master from slave ifindex "
                           CI_IFID_PRINTF_FORMAT,
                           ifindex));
      return;
    }
  }
#endif

  /* In VLAN case, find proper ifindex and our mac */
  if (ethhdr->ether_type == CI_ETHERTYPE_8021Q) {
    rc = cicppl_llap_get_vlan(control_plane, &ifindex,
                              *((ci_uint16 *)(ethhdr + 1) + 1) & 0xe000,
                              &ourmac);
  }
  else if (arp->hdr.arp_op_be16 == CI_ARP_REPLY) {
    /* In case of ARP reply, just find our mac */
    rc = cicppl_llap_get_mac(control_plane, ifindex, &ourmac);
  }

  if (CI_UNLIKELY(rc < 0)) 
  {
    OO_DEBUG_ARP(DPRINTF(CODEID": couldn't find an llap with ifindex "
                         CI_IFID_PRINTF_FORMAT,
                         ifindex));
    return;
  }

  /* the ethernet dest field (of an ARP reply) must match our MAC addr
   * and it must match the dest field of the ARP header, bug 4036 */
  if (arp->hdr.arp_op_be16 == CI_ARP_REPLY &&
      CI_UNLIKELY(cicppl_chk_arp_dest_addr(control_plane, &ethhdr->ether_dhost,
					   arp, &ourmac, ifindex))) {
    CICP_STAT_INC_PKT_REJECT(control_plane);
    OO_DEBUG_ARP(DPRINTF(CODEID": ARP reply not for our MAC address (for "
		      CI_MAC_PRINTF_FORMAT")",
		      CI_MAC_PRINTF_ARGS(&ethhdr->ether_dhost)));
    return;
  }

  cicppl_queue_arp(control_plane, arp, ifindex);
}




/*! Initialize protocol-specific section of Address Resolution MIB */
extern int /* rc */
cicppl_mac_kmib_ctor(cicppl_mac_mib_t *macprot)
{
  /* install the ARP packet processor */
  cicppl_rx_fifo_ctor(&static_fifo);
  return 0;
}

    


/*! Initialize kernel resolution protocol state in a MAC MIB row */
extern void
cicppl_mac_kmib_row_ctor(cicppl_mac_row_t *prot_entry)
{   return;
}




/*! Terminate kernel resolution protocol state of a MAC MIB entry
 *
 *  NB: control-plane lock is held while this function is being called
 */
extern void
cicppl_mac_kmib_row_dtor(cicppl_mac_row_t *prot_entry)
{   return;
}





/*! Terminate kernel protocol-specific section of Address Resolution MIB */
extern void
cicppl_mac_kmib_dtor(cicppl_mac_mib_t *macprot)
{
    cicppl_rx_fifo_dtor(&static_fifo);
}





/*! Initialize protocol-specific code - for CICP_CP_OPTION_RAWARP,
 *  CICP_CP_OPTION_OSARP and CICP_CP_OPTION_OWNARP
 */
extern int /* rc */
cicppl_ctor(cicp_handle_t *control_plane)
{   return cicpplos_ctor(control_plane); /* pass to O/S specific code */
}




/*! Finalize protocol-specific code */
extern void
cicppl_dtor(cicp_handle_t *control_plane)
{   cicpplos_dtor(control_plane);  /* pass to O/S specific code */
}







