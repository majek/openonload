/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#include <ci/internal/transport_config_opt.h>
#include <ci/tools/dllist.h>
#include <ci/tools.h>
#include <ci/net/arp.h>
#include <onload/tcp_driver.h>
#include <onload/cplane_ops.h>


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



#define CODEID "cplane onload"




/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DO(_x) _x
#define IGNORE(_x)



static int pkt_chain_copy(ci_netif* ni, ci_ip_pkt_fmt* src_head,
                          struct cicp_bufpool_pkt* dst)
{
  ci_ip_pkt_fmt* src_pkt = src_head;
  int n, n_seg, bytes_copied, seg_i;
  char* dst_ptr = (void*) (dst + 1);
  const char* src_ptr;

#ifndef NDEBUG
  if( oo_tx_ether_type_get(src_pkt) == CI_ETHERTYPE_IP )
    ci_assert_equal(CI_IP4_IHL((ci_ip4_hdr*)oo_tx_outer_l3_hdr(src_head)),
                    sizeof(ci_ip4_hdr));
#endif

  n_seg = CI_MIN(src_head->n_buffers, CI_IP_PKT_SEGMENTS_MAX);

  bytes_copied = 0;
  seg_i = 0;
  /* Start copying from the IP header. */
  src_ptr = oo_tx_outer_l3_hdr(src_pkt);
  n = src_pkt->buf_len - (src_ptr - (const char*) oo_ether_hdr(src_pkt));

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
    ci_frc64(&(pkt->tstamp_frc));
    memset(oo_ether_dhost(pkt), 0, 2 * ETH_ALEN);
    oo_tcpdump_dump_pkt(ni, pkt);
  }

  return pkt_chain_copy(ni, pkt, dst);
}




/*! Defer transmission of packet until forwarding information is re-established
 *  - system call implementation: see user header for documentation
 */
extern int /* bool */
cicp_user_defer_send(ci_netif *netif, cicpos_retrieve_rc_t retrieve_rc,
		     ci_uerr_t *ref_os_rc, oo_pkt_p pkt_id,
                     ci_ifid_t ifindex, ci_addr_t next_hop)
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
                                 next_hop, pkt_id, ifindex);

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


