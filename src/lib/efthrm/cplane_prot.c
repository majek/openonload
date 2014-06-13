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
#include <ci/driver/efab/workqueue.h>


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


typedef char *cicp_bufset_t;

#define cicp_bufset_ptr(ref_bufset, unused_rs, id) \
        ((char *)(*(ref_bufset)) + (CICPPL_PKTBUF_SIZE * (id)))
/* can't provide cicp_buffset_addr() without using IO bufsets */
#define cicp_bufset_alloc(out_bufset, unused_rs, ev_rs,                \
			  phys_addr, count, size)		       \
        (  *out_bufset = ci_vmalloc((count) * (size)),                 \
           *out_bufset==NULL? -ENOMEM: 0                               \
	)
#define cicp_bufset_free(pool) (ci_vfree((pool)->bufmem), 0)




/** Free buffer pool for deferred network packets awaiting MAC resolution */
typedef struct {
    unsigned  istack_size;
    unsigned  istack_ptr;
    ci_int16  istack_base[CICPPL_PKTBUF_COUNT];
} cicp_pktbuf_istack_t; /* conforming to "istack" definition */


struct cicp_bufpool_s
{  cicp_pktbuf_istack_t freebufs;
   cicp_bufset_t bufmem;
} /* cicp_bufpool_t */;



#define CICPPL_PKTBUF_SIZE (PKT_START_OFF() + CI_MAX_ETH_FRAME_LEN)


extern ci_ip_pkt_fmt *
cicppl_pktbuf_pkt(cicp_bufpool_t *pool, int id) 
{   if (CI_LIKELY(cicppl_pktbuf_is_valid_id(id)))
       return (ci_ip_pkt_fmt *)cicp_bufset_ptr(&pool->bufmem, NULL, id);
    else
       return (ci_ip_pkt_fmt *)NULL;
}



#ifdef cicp_bufset_addr
extern ci_uintptr_t
_cicppl_pktbuf_addr(cicp_bufpool_t *pool, int id) 
{   if (CI_LIKELY(cicppl_pktbuf_is_valid_id(id)))
       return (ci_uintptr_t)cicp_bufset_addr(&pool->bufmem, id);
    else
       return 0;
}
#endif



ci_inline int
cicppl_pktbuf_has_buf(cicp_bufpool_t *pool)
{   return !ci_istack_empty(&pool->freebufs);
}







/*  This function requires the control plane to be locked but does not
 *  lock it itself.
 */
extern int /* packet ID or negative if none available */
cicppl_pktbuf_alloc(cicp_bufpool_t *pool) 
{   int id = -1;
    
    CICP_BUFPOOL_CHECK_LOCKED(pool);

    if (pool != NULL && cicppl_pktbuf_has_buf(pool))
    {   ci_ip_pkt_fmt *pkt;

	id = ci_istack_pop(&pool->freebufs);

	ci_assert(cicppl_pktbuf_is_valid_id(id));
	pkt = cicppl_pktbuf_pkt(pool, id);
	ci_assert(pkt);

	ci_assert_equal(pkt->refcount, 0);
	pkt->refcount = 1;

	/* Packets in pending pool must be prepared for flat transmission */
	ci_assert_equal(pkt->n_buffers, 1);
    }

    return id;
}




extern void
cicppl_pktbuf_free(cicp_bufpool_t *pool, int id)
{
  ci_ip_pkt_fmt *arp_pkt = cicppl_pktbuf_pkt(pool, id);
  
  CICP_BUFPOOL_CHECK_LOCKED(pool);

  ci_assert_gt(arp_pkt->refcount, 0);
  if( (--arp_pkt->refcount) == 0 ) {
    /* Packets in pending pool always consist of 1 segment */
    ci_assert_equal(arp_pkt->n_buffers, 1);

    ci_assert(!ci_istack_full(&pool->freebufs));
    ci_istack_push(&pool->freebufs, (ci_uint16)id);
  }
}




static void
cicppl_pktbuf_init(cicp_bufpool_t *pool)
{   ci_ip_pkt_fmt *pkt;
    int i;

    ci_istack_init(&pool->freebufs, CICPPL_PKTBUF_COUNT);

    for (i = 0; i < CICPPL_PKTBUF_COUNT; i++)
    {   pkt = cicppl_pktbuf_pkt(pool, i);

        OO_PKT_PP_INIT(pkt, i);
	pkt->refcount = 0;

	/* Prepare templates for flat pending packets - 1 segment and fixed 
	 * length.
	 * 'iov_base' is not used, since virtual memory addresses of the data
	 * are required (instead of addresses understood by hardware).
	 */
        pkt->n_buffers = 1;

	ci_istack_push(&pool->freebufs, (ci_uint16)i);
    }
}










/** Initialize memory to hold deferred packets awaiting MAC resolution */
extern int
cicppl_pktbuf_ctor(cicp_bufpool_t **out_pool, struct efrm_vi *evq_rs)
{   int rc;
    /* allocate this memory from non-pageable memory so that it can be
       accessed when the application is swapped out */
    cicp_bufpool_t *pool = (cicp_bufpool_t *)
			   ci_vmalloc(sizeof(cicp_bufpool_t));
    
    if (NULL == pool)
    {   ci_log(CODEID": ERROR - failed to allocate memory for buffer pool");
	rc = -ENOMEM;
    } else
    {   rc = cicp_bufset_alloc(&pool->bufmem, NULL,
			       evq_rs, CI_FALSE, CICPPL_PKTBUF_COUNT, 
			       CICPPL_PKTBUF_SIZE);

	if (CI_UNLIKELY(0 != rc))
	{   ci_log(CODEID": ERROR - failed to allocate %ldKB of memory for "
			    "%d packets awaiting MAC resolution - rc %d",
		   (long)(CICPPL_PKTBUF_SIZE*CICPPL_PKTBUF_COUNT/1024),
		   CICPPL_PKTBUF_COUNT, -rc);
	    ci_vfree(pool);
	    pool = NULL;
	} else
	{   OO_DEBUG_ARP(DPRINTF(CODEID": allocated %ldKB of memory for "
			      "%d packets awaiting MAC resolution",
			      (long)(CICPPL_PKTBUF_SIZE*
				     CICPPL_PKTBUF_COUNT/1024),
			      CICPPL_PKTBUF_COUNT));

	    /* initialise the deferred packet freebuffer pool */
	    cicppl_pktbuf_init(pool);
	    rc = 0;
	}
    }
    
    *out_pool = pool;
    return rc;
}





/** Free any memory used to hold deferred packets awaiting MAC resolution */
extern void
cicppl_pktbuf_dtor(cicp_bufpool_t **ref_pool)
{   if (NULL != *ref_pool)
    {   cicp_bufset_free(*ref_pool);
        ci_vfree(*ref_pool);
	*ref_pool = NULL;
    }
}



static int pkt_chain_copy(ci_netif* ni, ci_ip_pkt_fmt* src_head,
                          ci_ip_pkt_fmt* dst)
{
  ci_ip_pkt_fmt* src_pkt = src_head;
  int n, n_seg, bytes_copied, seg_i;
  char* dst_ptr = PKT_START(dst);

  ci_assert_equal(oo_ether_type_get(src_head), CI_ETHERTYPE_IP);
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(src_head)), sizeof(ci_ip4_hdr));
  n_seg = CI_MIN(src_head->n_buffers, CI_IP_PKT_SEGMENTS_MAX);
  bytes_copied = 0;
  seg_i = 0;

  while( 1 ) {
    n = src_pkt->buf_len;

    /* Protect against corrupted packet. */
    if( bytes_copied + n > CI_MAX_ETH_FRAME_LEN )
      break;

    memcpy(dst_ptr, PKT_START(src_pkt), n);
    dst_ptr += n;
    bytes_copied += n;
    ++seg_i;

    if( OO_PP_IS_NULL(src_pkt->frag_next) || seg_i == n_seg )
      break;

    src_pkt = PKT_CHK(ni, src_pkt->frag_next);
  }

  dst->buf_len = dst->tx_pkt_len = bytes_copied;
  dst->n_buffers = 1;
  ci_assert_equal(oo_ether_type_get(dst), CI_ETHERTYPE_IP);
  ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(dst)), sizeof(ci_ip4_hdr));

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
extern int
cicppl_ip_pkt_flatten_copy(ci_netif* ni, oo_pkt_p src_pktid, ci_ip_pkt_fmt*dst)
{
  ci_ip_pkt_fmt *pkt = PKT(ni, src_pktid);  

  oo_pkt_layout_set(dst, pkt->pkt_layout);
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
 *          Protocol Transmission - Transmission Channel                     *
 *          ============================================                     *
 *                                                                           *
 *****************************************************************************/






#ifdef CICPPL_USE_TRANSMITTER


#include <etherfabric/vi.h>   /* for ef_vi */



typedef struct
{   efhw_nic_t    *handle;              /*< handle for this NIC */
    ef_eventq_state evq_state;
    ef_vi          evq;			/*< queue of events comming from NIC */
    struct efrm_vi* evq_rs;              /*< Resource of [evq] */
    ef_vi          interface;		/*< "virtual interface" to the NIC */
    struct efrm_vi* interface_rs;      /*< Resource of [interface] */
    ef_vi_state *  vi_state;            /*< state needed for a VI */
} cicp_transmitter_nic_t;


struct cicp_transmitter_s
{   const cicp_mac_mib_t *mact;         /*< IP-MAC resolution table */
    struct efrm_vi *evq_rs;              /*< resource representing all NICs */
    ci_uint32 evq_mmap_bytes;           /*< memory mapped bytes for event q */
    cicp_transmitter_nic_t nic[CI_CFG_MAX_REGISTER_INTERFACES];
} /*cicp_transmitter_t*/; 




ci_inline int /* rc */
cicp_nic_open(cicp_transmitter_t *txer, ef_driver_handle *ref_nic, int nicno)
{   ef_driver_handle nic = ci_driver.nic[nicno];
    int rc = 0;

    if (NULL == nic)
    {   rc = -ENODEV;
	*ref_nic = NULL;
	OO_DEBUG_ARP(DPRINTF(CODEID": (NIC %d) not present - rc %d",
			  nicno, rc););
    } else
    if (NULL == nic->efhw_func || 0 == EFHW_KVA(nic))
    {   rc = -ENXIO;
	*ref_nic = NULL;
	OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) hardware uninitialized - "
                	  "deferring initialization",
	                  nicno););
    } else
    if (NULL == txer->evq_rs)
    {
	{   struct efrm_vi *evq_rs; /* resource for event queue to use */
            ci_uint32 evq_mmap_bytes;
	    
            /* safe to open an event queue resource on this NIC */

            /* ?? FIXME: This is broken as we need an efrm_client, and a VI
             * per NIC.  At time of writing, this code is not used, hence
             * not fixed.
             */
            rc = efrm_vi_resource_alloc(fixme_efrm_client, NULL, 0, 256, 0, 0,
                                        0, 0,&evq_rs,
                                        NULL, &evq_mmap_bytes, NULL, NULL);
	    if (0 == rc)
	    {   txer->evq_rs = evq_rs;
		txer->evq_mmap_bytes = evq_mmap_bytes;
	        *ref_nic = nic;
	    } else
	    {   *ref_nic = NULL; /* try again next time */
		OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) can't open event queue "
		                  "resource - rc %d",
		                  nicno, -rc););
	    }
	}
    } else
	/* already opened? */
	*ref_nic = nic;
    
    /*in user mode: rc = ef_onload_driver_open(ref_nic);*/
    IGNORE(DPRINTF(CODEID": open NIC %d - rc %d", nicno, rc););
    return rc;
}


ci_inline int
cicp_vi_alloc(ef_vi* ep, efhw_nic_t* nic, cicp_transmitter_nic_t* nicinfo)
{
  ci_uint32 nic_index = nic->index;
  int rc;
  char vi_data[VI_MAPPINGS_SIZE]; /* buffer for ef_vi_init() */

  ci_assert(ep);
  ci_assert(nicinfo);
  CI_ASSERT_DRIVER_VALID();

  /* using arbitrary transmit and received ID's for queues */
  /*   mnemonic: deferred from: (De)fF, defferred to: (De)f2   */
  rc = efab_vi_resource_alloc(nicinfo->evq_rs, 0, 0,
                              FALCON_DMA_Q_DEFAULT_TX_SIZE,
                              FALCON_DMA_Q_DEFAULT_RX_SIZE,
                              0xf2, 0xfF, &nicinfo->interface_rs,
                              NULL, NULL, NULL, NULL);
  
  if( rc != 0 ) {
    IGNORE(DPRINTF("%s: efab_vi_resource_alloc VI rc %d",
		   __FUNCTION__, rc));
    ci_assert(nicinfo->interface_rs == NULL);
    return rc;
  } else {

    efrm_vi_resource_mappings(nicinfo->interface_rs, vi_data);
    ef_vi_init(ep, vi_data, nicinfo->vi_state, NULL, /*flags*/0);
    ef_vi_state_init(ep);

    return 0;
  }
}


/*! if necessary, initialize NIC-specific area in transmitter, and return it */
static cicp_transmitter_nic_t *
cicp_transmitter_nic(cicp_transmitter_t *txer, int nicno)
{   cicp_transmitter_nic_t *nicinfo = &txer->nic[nicno];
    int /*bool*/ ok = FALSE;
    ef_driver_handle nic;

    /* see if we are up yet - try to open the default NIC */
    if (0 == cicp_nic_open(txer, &nic, CI_DEFAULT_NIC))
    {   nic = nicinfo->handle;

	ok = (NULL != nic);
	if (!ok) /* perhaps this NIC was late - try again */
	{   int rc = 0;

	    IGNORE(DPRINTF(CODEID" init NIC %d eventq", nicno););
	    nic = ci_driver.nic[nicno];
	    
	    if (NULL == nic)
		rc = -ENODEV; /* this NIC is not known yet */
	    
            /* ensure we have this NIC's version of the event queue set up */
	    if (rc == 0)
		rc = ef_eventq_initialize_for_one_nic(txer->evq_rs,
						      txer->evq_mmap_bytes,
						      &nicinfo->evq, nicno,
						      &nicinfo->evq_state);
	    if (0 != rc)
	    {   OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d%s) can't initialize "
				  "event queue - rc %d",
				  nicno, NULL==nic?" - absent":"", -rc););
	    } else
	    {
		size_t state_size = EF_VI_STATE_BYTES;

		/* get the event q resource for this NIC */
		nicinfo->evq_rs = txer->evq_rs;

		nicinfo->vi_state = (ef_vi_state *)ci_vmalloc(state_size);

		if (NULL == nicinfo->vi_state)
		{   rc = -ENOMEM;
		    OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) failed to allocate"
                                      " virtual interface state - rc %d",
				      nicno, rc););
		} else
		{   /* make a virtual interface from event queue */
		    ef_vi     *ref_vi    = &nicinfo->interface;

		    rc = cicp_vi_alloc(ref_vi, nic, nicinfo);
		    /* TODO: do we have to use flag EF_VI_RX_SCATTER for
		             transmitting jumbo frames? */
		    if (0 != rc)
		    {   OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) failed to "
					  "allocate deferred transmit "
					  "virtual interface - rc %d",
					  nicno, rc););
		    } else
		    {   IGNORE(ci_log(CODEID": (NIC %d) initialized",  nicno);)
			ok = TRUE;
		    }

		    if (0 == rc)
			/* setting this means we won't try to initialize
			   again */
	                nicinfo->handle = nic;
		    else
		    {   ci_free(nicinfo->vi_state);
			nicinfo->vi_state = NULL;
		    }
		}
	    } 
	}
    }

    return ok? nicinfo: NULL;
}
    





/* Allocate the resources necessary for subsequent transmission on given NIC */
ci_inline int /* rc */
cicp_transmitter_nic_ctor(cicp_transmitter_t *txer, int nicno)
{   /* Actually, we can't allocate any resources really - each port needs
       a virtual interface, each virtual interface needs an event queue,
       each interface event queue needs our event queue resource,  our event
       queue resource should not be initialized until we know a PCI bus scan
       has taken place - and that sometimes hasn't happened yet.
       So we do most of our initialization work in the call-on-demand function
       cicp_transmitter_nic (above)
    */
    cicp_transmitter_nic_t *nicinfo = &txer->nic[nicno];
    int rc = 0; /* succeed by default */
    nicinfo->handle    = NULL;
    /* leave event queue uninitialized until we have a event queue resource */
    /* leave virutal interface uninitialized until we have an event queue */
    /* leave ports uninitialized until we have a virtual interface */
    return rc;
}





/*! Handle an event returning from a previous transmission
 *
 *  The control plane lock is used as the lock for this datastructure
 *  - the control plane is expected to be locked
 */
ci_inline void
handle_ev_tx(ef_vi *interface, ef_event event)
{   ef_request_id dma_ids[EF_VI_TRANSMIT_BATCH];
    int i, idcount;

    /* if this TX event is OK it should carry a DMA identifier that was
       set to be the ID of the buffer used for the transmission */
    idcount = ef_vi_transmit_unbundle(interface, &event, dma_ids);
    for( i = 0; i < idcount; ++i )
    {   if (cicppl_pktbuf_is_valid_id(dma_ids[i]))
        {   /*! @TODO: which is the correct control plane to use?? if there
	               were more than one?
	    */
	    cicp_handle_t *control_plane = &CI_GLOBAL_CPLANE;
	    cicp_bufpool_t *pool = cicppl_transmitter_pool(control_plane);
	    ci_ip_pkt_fmt *pkt = cicppl_pktbuf_pkt(pool, dma_ids[i]);
	    /* free space in DMA transmit queue */
            cicppl_pktbuf_free(pool, dma_ids[i]);
        } else
        {   /* NB: messsage is logged whilst locked */
	    OO_DEBUG_ERR(DPRINTF(CODEID": deferred transmission of illegal "
			      "buffer number #%d", dma_ids[i]););
	}
    }
}






/*! Read and deal with returning events from previous transmissions 
 *
 *  The control plane lock is used as the lock for this datastructure
 *  - the control plane is expected to be locked
 */
ci_inline void
cicp_transmitter_doevents(cicp_transmitter_t *txer)
{   int nicno;
    
    for (nicno=0; nicno < CI_CFG_MAX_REGISTER_INTERFACES; nicno++)
	/* read events only from NICs that are initialized */
	if (NULL != txer->nic[nicno].handle)
	{   int eventcount = 0;

	    do
	    {   ef_event event_in[EF_VI_EVENT_POLL_MIN_EVS];
		eventcount = ef_eventq_poll(&txer->nic[nicno].evq, &event_in,
                                      sizeof(event_in) / sizeof(event_in[0]));

            fixme: need to cope with eventcount > 1;
		if (eventcount > 0)
		{   OO_DEBUG_CPTX(DPRINTF(CODEID": (NIC %d) event "EF_EVENT_FMT,
				    nicno, EF_EVENT_PRI_ARG(event_in)););

		    if (EF_EVENT_TYPE_TX == EF_EVENT_TYPE(event_in))
			/* we expect only transmit events on this DMA queue */
			handle_ev_tx(&txer->nic[nicno].interface, event_in);
		    else
                    {   /* messsage is logged whilst locked - remove later? */
			OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) unexpected "
			                  "non-transmit event type in "
					  EF_EVENT_FMT,
					  nicno, EF_EVENT_PRI_ARG(event_in)););
		    }
		}
	    } while (eventcount > 0);
	}
}









/*! Transmit the identified IP packet using the provided transmitter resources
 *  to the given next hop IP address via the NIC/port provided (from the
 *  link layer access point identified by \c ifindex)
 *
 *  This function will take ownership of the packet (e.g. to return it to
 *  the pool) whether or not transmission is successful
 *
 *  This function requires the control plane to be locked but does not itself
 *  lock it.
 */
extern int /* rc */
cicp_transmitter_tx(cicp_transmitter_t *txer, ci_hwport_id_t hwport,
		    cicp_bufpool_t *pool, int pktbuf_id,
		    const ci_mac_addr_t *ref_source_mac,
		    const ci_mac_addr_t *ref_nexthop_mac)
{   int rc;
    cicp_transmitter_nic_t *nicinfo =
	cicp_transmitter_nic(txer, ci_hwport_get_nic(hwport));

    if (nicinfo == NULL)
	rc = -ENODEV;
    else
    {	ci_ip_pkt_fmt *pkt = cicppl_pktbuf_pkt(pool, pktbuf_id);
	/* address of buffer visible on the NIC */
	int port = ci_hwport_get_portno(hwport);
	ef_iovec iov[CICPOSPL_MAC_TXBUF_PAGEMAX];
	int seg_space, left;
	int offset = 0;
	int vec_idx = 0;

        cicp_transmitter_doevents(txer);  /* consume incomming events */
 
        ci_assert( ! (pkt->flags & CI_PKT_FLAG_TX_PENDING));

        /* fill in packet details */
	pkt->netif.tx.port_i = ci_hwport_get_portno(hwport);
	pkt->netif.tx.nic_i = ci_hwport_get_nic(hwport);
        ci_assert_ge(pkt->netif.tx.port_i, 0);
	
        /* fill in the MAC-layer header */
	CI_MAC_ADDR_SET(&pkt->ether_shost, ref_source_mac);
	CI_MAC_ADDR_SET(&pkt->ether_dhost, ref_nexthop_mac);
	
	/* the packet should be flattened */
	ci_assert_equal(pkt->n_buffers, 1);

	/* We need to deal with buffers that traverse page boundaries
	   because each DMA request must contain no addresses from more
	   than one page
	 */

	iov[0].iov_base = cicppl_pktbuf_addr(pool, pktbuf_id) +
			  CI_MEMBER_OFFSET(ci_ip_pkt_fmt, ether_dhost);
        left = pkt->buf_len;
	seg_space = (ci_uint32)(CI_PTR_ALIGN_NEEDED(iov[0].iov_base,
						    CI_PAGE_SIZE));

	while (left > 0 && vec_idx < CICPOSPL_MAC_TXBUF_PAGEMAX) {
	    int n = CI_MIN(left, seg_space);

	    iov[vec_idx].iov_base = iov[0].iov_base + offset;
	    iov[vec_idx].iov_len = n;

	    /* we know the packet is flattened */
	    seg_space = CI_PAGE_SIZE;

	    offset += n;
	    left   -= n;
	    vec_idx++;
	}

	ci_assert_equal(left, 0);

	if (vec_idx > 0) {
            rc = ef_vi_transmitv(&nicinfo->interface, port,
                                 iov, vec_idx, pktbuf_id); 
	    /* This buffer is now in use by the hardware, it will become
	       available for use again once an event signalling the end
	       of the DMA is received - by handle_ev_tx() - e.g. called
	       above in cicp_transmitter_doevents().
	    */
	    if (0 != rc)
	    {   /* messsage is logged whilst locked - remove later? */
		OO_DEBUG_ERR(DPRINTF(CODEID
                                     ": (NIC %d) tx %d bytes [in %d segs] "
                                     "to port %d failed rc %d",
                                     ci_hwport_get_nic(hwport),
                                     pkt->buf_len, vec_idx,
                                     ci_hwport_get_portno(hwport), rc););
	    } else
	    {   OO_DEBUG_CPTX(DPRINTF(CODEID": (NIC %d) tx %d bytes "
                                      "[in %d segs] on port %d to "
                                      CI_MAC_PRINTF_FORMAT,
                                      ci_hwport_get_nic(hwport),
                                      pkt->buf_len, vec_idx,
                                      ci_hwport_get_portno(hwport),
                                      CI_MAC_PRINTF_ARGS(ref_nexthop_mac)););
		LOG_AT(ci_analyse_pkt(pkt->ether_dhost, pkt->buf_len));
		LOG_DT(ci_hex_dump(ci_log_fn, pkt->ether_dhost,
				   pkt->buf_len, 0));
		OO_DEBUG_CPTX(
		    /* DPRINTF(CODEID": sent to TX DMAQ %d",
			       ref_port->p_ep->ep_dma_tx_q.dmaq); */
		    )
		/* unfortunately we don't have access to an option that
		   would allow us to determine whether we should be
		   capturing these packets (for debug) here */
	    }
	} else
	{   OO_DEBUG_ERR(DPRINTF(CODEID": (NIC %d) tx %d bytes "
                                 "on port %d: divided into %d bits",
                                 ci_hwport_get_nic(hwport),
                                 pkt->buf_len,
                                 ci_hwport_get_portno(hwport),
                                 vec_idx););
	    /* rc is zero, force packet to be returned */
	    cicppl_pktbuf_free(pool, pktbuf_id);
	    rc = 0;
	}
    }
    if (0 != rc)
	/* pool is locked under the control plane lock */
        cicppl_pktbuf_free(pool, pktbuf_id); /* drop it if not transmitted */
    
    return rc;
}







/*! Obtain a packet buffer from the pool - consuming transmit events if
 *  necessary in order to free additional resources
 *
 *  This function requires the control plane to be locked and locks it
 *  itself.  (The control plane should not be locked when calling this.)
 */
extern int /* packet ID or negative if none available */
cicp_transmitter_pktbuf_alloc(cicp_transmitter_t *txer, cicp_bufpool_t *pool) 
{   int pktid = -1;
    
    CICP_BUFPOOL_LOCK(pool, pktid = cicppl_pktbuf_alloc(pool));

    if (pktid < 0)
    {   OO_DEBUG_CPTX(DPRINTF(CODEID": processing DMA events to free "
			"up packet buffers"););
	CICP_BUFPOOL_LOCK(pool, 
	    cicp_transmitter_doevents(txer);
	    /* consume events - with any luck returning buffers */
	    pktid = cicppl_pktbuf_alloc(pool);
	);
    }

    return pktid;
}






/*! Allocate the resources necessary for subsequent transmission */
static int /* rc */
cicp_transmitter_alloc(cicp_transmitter_t **ref_txer,
		       cicp_handle_t *control_plane)
{   /* @TODO: we allocate this data structure from dispatch mode in Windows
              so we want this memory to be from the nonpaged pool.
	      Unfortunately we don't have an O/S independent way to
	      ask for this - windows has ci_alloc_nonpaged() but the
	      other operating systems do not
    */
    cicp_transmitter_t *txer = CI_ALLOC_OBJ(cicp_transmitter_t);
    int overall_rc;

    if (txer == NULL)
	overall_rc = -ENOMEM;
    else
    {	int nicno;
	int rc;
	ef_driver_handle nic;
        const cicp_mac_mib_t *mact = control_plane->user.mac_utable;

	overall_rc = 0;
	txer->mact = mact;
	txer->evq_rs = NULL;      /* resource repr'ing event Q on all NICs */
	txer->evq_mmap_bytes = 0; /* memory mapped bytes for our event Q */

	for (nicno=0; nicno < CI_CFG_MAX_REGISTER_INTERFACES; nicno++)
	{   rc = cicp_transmitter_nic_ctor(txer, nicno);

	    if (0 != rc && 0 == overall_rc)
		overall_rc = rc;
	}

	/* Assumption: if the default NIC is present all the NIC's we're
		       interested in are present
	*/
	rc = cicp_nic_open(txer, &nic, CI_DEFAULT_NIC);

	/* We ignore this return code - 
	   unfortunately the hardware registers for the NIC have not always
	   been set up when this function is called - so it is likely that
	   this initialization will be deferred until first transmission
	   when cicp_transmitter_nic() will be called again
	*/
    }
    
    *ref_txer = txer;
    return overall_rc;
}




/*! Free the resources contained in the transmitter provided */
static void
cicp_transmitter_free(cicp_transmitter_t **ref_txer)
{   cicp_transmitter_t *txer = *ref_txer;

    if (NULL != txer)
    {	int nicno;

        for (nicno=0; nicno < CI_CFG_MAX_REGISTER_INTERFACES; nicno++)
	{   cicp_transmitter_nic_t *nicinfo = &txer->nic[nicno];
	    ef_driver_handle nic = nicinfo->handle;

	    if (0 != nic)
	    {   ef_driver_handle *ref_nic   = &nicinfo->handle;

		if (NULL != nicinfo->interface_rs)
		    efab_vi_resource_release(nicinfo->interface_rs);
		if (NULL != nicinfo->vi_state)
		    ci_free(nicinfo->vi_state);
		/*ef_driver_close(nic); - in user mode*/
		*ref_nic = 0;
		/* no action needed to close the event queue */
	    }
	}
	if (NULL != txer->evq_rs)
	    efab_vi_resource_release(txer->evq_rs);

	ci_free(txer);
	*ref_txer = (cicp_transmitter_t *)NULL;
    }
}







#endif /* CICPPL_USE_TRANSMITTER */













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
  ci_verify(ci_workqueue_flush(&CI_GLOBAL_WORKQUEUE) == 0);
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



/*! schedule efab_handle_arp_data() to run at process context(i.e. non-irq) */
#define cicppl_schedule_arp_data_handler(wi)                                 \
  do {                                                                       \
    int rc;                                                                  \
    ci_assert_equal(CI_WORKITEM_GET_ROUTINE(wi),                             \
                     (CI_WITEM_ROUTINE) &cicppl_handle_arp_data);            \
    ci_assert_nequal(CI_WORKITEM_GET_CONTEXT(wi) /*control_plane*/, NULL);   \
    rc = ci_workqueue_add(&CI_GLOBAL_WORKQUEUE, (wi));                       \
    if (CI_UNLIKELY( (rc != 0) && (rc != -EALREADY) ))                       \
      OO_DEBUG_ARP(DPRINTF(CODEID": Can't queue ARP data handler, rc %d",       \
		        -rc));             		                     \
  } while(0)




/*! Work item routine that get scheduled in the work queue and reads ARP
    headers from the fifo and updates the arp table. */
static void 
cicppl_handle_arp_data(void *context)
{
  cicppl_rx_fifo_item_t *item_ptr;
  cicp_handle_t *control_plane = (cicp_handle_t *)context;
  
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
  static ci_workitem_t wi =
      CI_WORKITEM_INITIALISER(wi,
                              (CI_WITEM_ROUTINE) &cicppl_handle_arp_data,
                              NULL);
  CI_WORKITEM_SET_CONTEXT(&wi, (void *)control_plane);

  if (NULL != item_ptr) {
    /* populate the work item */
    item_ptr->ifindex = ifindex;
    memcpy(&item_ptr->arp, arp, sizeof(ci_ether_arp));

    /* add the work item to the rx fifo */
    cicppl_rx_fifo_push(&static_fifo, item_ptr);

    /* schedule a job to consume the ARP packet at a better time */
    cicppl_schedule_arp_data_handler(&wi);
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







