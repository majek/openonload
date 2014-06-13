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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Raw packet transmit.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "netif_tx.h"
#include <ci/tools/pktdump.h>


static void __ci_netif_dmaq_shove(ci_netif* ni, int intf_i)
{
  oo_pktq* dmaq = &ni->state->nic[intf_i].dmaq;
  ef_vi* vi = &ni->nic_hw[intf_i].vi;
  ci_ip_pkt_fmt* pkt;
  int rc;

  ci_assert(oo_pktq_not_empty(dmaq));

  do {
    pkt = PKT_CHK(ni, dmaq->head);
    ci_assert(pkt->flags & CI_PKT_FLAG_TX_PENDING);
    ci_assert_equal(intf_i, pkt->intf_i);
    {
      ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];
      ci_netif_pkt_to_iovec(ni, pkt, iov, sizeof(iov) / sizeof(iov[0]));
      rc = ef_vi_transmitv_init(vi, iov, pkt->n_buffers, OO_PKT_ID(pkt));
      if( rc >= 0 ) {
        __oo_pktq_next(ni, dmaq, pkt, netif.tx.dmaq_next);
        CI_DEBUG(pkt->netif.tx.dmaq_next = OO_PP_NULL);
      }
      else {
        /* Descriptor ring is full. */
#if CI_CFG_STATS_NETIF
        if( (ci_uint32) dmaq->num > ni->state->stats.tx_dma_max )
          ni->state->stats.tx_dma_max = dmaq->num;
#endif
        break;
      }
    }
  }
  while( oo_pktq_not_empty(dmaq) );

  ef_vi_transmit_push(vi);
  CITP_STATS_NETIF_INC(ni, tx_dma_doorbells);
}


void ci_netif_dmaq_shove1(ci_netif* ni, int intf_i)
{
  ef_vi* vi = &ni->nic_hw[intf_i].vi;
  if( ef_vi_transmit_space(vi) >= (ef_vi_transmit_capacity(vi) >> 1) )
    __ci_netif_dmaq_shove(ni, intf_i);
}


void ci_netif_dmaq_shove2(ci_netif* ni, int intf_i)
{
  ef_vi* vi = &ni->nic_hw[intf_i].vi;
  if( ef_vi_transmit_space(vi) > CI_IP_PKT_SEGMENTS_MAX )
    __ci_netif_dmaq_shove(ni, intf_i);
}


void ci_netif_send(ci_netif* netif, ci_ip_pkt_fmt* pkt)
{
  int intf_i;
  oo_pktq* dmaq;
  ef_vi* vi;
  ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];

  ci_assert(netif);
  ci_assert(pkt);
  ci_assert(pkt->intf_i >= 0);
  ci_assert(pkt->intf_i < CI_CFG_MAX_INTERFACES);

  __ci_netif_dmaq_insert_prep_pkt(netif, pkt);

  LOG_NT(log("%s: id=%d nseg=%d 0:["EF_ADDR_FMT":%d] dhost="
             CI_MAC_PRINTF_FORMAT, __FUNCTION__, OO_PKT_FMT(pkt),
             pkt->n_buffers, pkt->base_addr[pkt->intf_i], pkt->buf_len,
             CI_MAC_PRINTF_ARGS(oo_ether_dhost(pkt))));

  ci_check( ! ci_eth_addr_is_zero((ci_uint8 *)oo_ether_dhost(pkt)));

  /*
   * Packets can be now be n fragments long. If the packet at the head of the
   * DMA overflow queue has multiple fragments we might succeed to add
   * this packet to the PT endpoint if we unconditional attempt to do this
   * (causing an out of order send). Therefore we have to check whether the
   * DMA overflow queue is empty before proceding
   */
  intf_i = pkt->intf_i;

  dmaq = ci_netif_dmaq(netif, intf_i);
  vi = &netif->nic_hw[intf_i].vi;

  /* Check that the VI we're given matches the pkt's intf_i */
  ci_assert_equal(vi, &netif->nic_hw[pkt->intf_i].vi);

  if( oo_pktq_is_empty(dmaq) &&
      (ci_netif_pkt_to_iovec(netif, pkt, iov,
                             sizeof(iov) / sizeof(iov[0])), 1) && 
      ef_vi_transmitv(vi, iov, pkt->n_buffers, OO_PKT_ID(pkt)) == 0 ) {
    CITP_STATS_NETIF_INC(netif, tx_dma_doorbells);
    LOG_AT(ci_analyse_pkt(oo_ether_hdr(pkt), pkt->buf_len));
    LOG_DT(ci_hex_dump(ci_log_fn, oo_ether_hdr(pkt), pkt->buf_len, 0));
  }
  else {
    LOG_NT(log("%s: ENQ id=%d", __FUNCTION__, OO_PKT_FMT(pkt)));
    __ci_netif_dmaq_put(netif, dmaq, pkt);
  }

  /* Poll every now and then to ensure we keep up with completions.  If we
   * don't do this then we can ignore completions for so long that we start
   * putting stuff on the overflow queue when we don't really need to.
   */
  if( netif->state->send_may_poll ) {
    ci_netif_state_nic_t* nsn = &netif->state->nic[intf_i];
    if( nsn->tx_dmaq_insert_seq - nsn->tx_dmaq_insert_seq_last_poll >
        NI_OPTS(netif).send_poll_thresh ) {
      nsn->tx_dmaq_insert_seq_last_poll = nsn->tx_dmaq_insert_seq;
      if( ci_netif_intf_has_event(netif, intf_i) ) {
        /* The poll call may get us back here, so we need to ensure that we
         * doesn't recurse back into another poll.
         */
        netif->state->send_may_poll = 0;
        ci_netif_poll_n(netif, NI_OPTS(netif).send_poll_max_events);
        netif->state->send_may_poll = 1;
      }
    }
  }
}

/*! \cidoxg_end */
