/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

#ifndef __NETIF_TX_H__
#define __NETIF_TX_H__


/**********************************************************************
 * Sending packet helper
 */

ci_inline void ci_netif_pkt_tx_assert_len(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                          unsigned n)
{
#ifndef NDEBUG
  ci_ip_pkt_fmt* first = pkt;
  int i, t = 0;
  for( i = 0; ; ) {
    t += pkt->buf_len;
    ci_assert_le(t, first->pay_len);
    if( ++i == n )
      break;
    pkt = PKT_CHK(ni, pkt->frag_next);
  }
  ci_assert_equal(t, first->pay_len);
#endif
}


ci_inline void ci_netif_pkt_to_iovec(ci_netif* ni, ci_ip_pkt_fmt* pkt, 
                                     ef_iovec* iov, unsigned iovlen)
{
  int i, intf_i = pkt->intf_i;
  unsigned n = pkt->n_buffers;

  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_ge(iovlen, n);

#if CI_CFG_NETIF_HARDEN
  if( n > iovlen )
    n = iovlen;
#endif

  ci_netif_pkt_tx_assert_len(ni, pkt, n);

  for( i = 0; ; ) {
    iov[i].iov_base = pkt->dma_addr[intf_i] + pkt->pkt_start_off;
    iov[i].iov_len = pkt->buf_len;
    if( ++i == n )
      return;
    pkt = PKT_CHK(ni, pkt->frag_next);
  }
}


#if CI_CFG_PIO
ci_inline void ci_netif_pkt_to_pio(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                   ci_int32 offset)
{
  int i = 0, intf_i = pkt->intf_i;
  unsigned n = pkt->n_buffers;

  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  ci_assert_ge(2048 /* PIO region size */, pkt->pay_len);

  while( 1 ) {
    ef_pio_memcpy(&ni->nic_hw[intf_i].vi, PKT_START(pkt), offset, pkt->buf_len);
    if( ++i == n )
      return;
    offset += pkt->buf_len;
    pkt = PKT_CHK(ni, pkt->frag_next);
  } 
}
#endif


/**********************************************************************
 * DMA queues.
 */

/* Moves packets from the overflow queue to the hardware ring iff the
 * hardware queue has lots of space.
 */
extern void ci_netif_dmaq_shove1(ci_netif*, int intf_i);

/* Moves packets from the overflow queue to the hardware ring if the
 * hardware queue has at least space for one packet.
 */
extern void ci_netif_dmaq_shove2(ci_netif*, int intf_i);


#define ci_netif_dmaq(ni, nic_i)  (&(ni)->state->nic[nic_i].dmaq)


#define ci_netif_dmaq_is_empty(ni, nic_i)               \
        oo_pktq_is_empty(ci_netif_dmaq((ni), (nic_i)))

#define ci_netif_dmaq_not_empty(ni, nic_i)               \
        oo_pktq_not_empty(ci_netif_dmaq((ni), (nic_i)))


#define __ci_netif_dmaq_put(ni, q, pkt)                         \
  do {                                                          \
    __oo_pktq_put((ni), (q), (pkt), netif.tx.dmaq_next);        \
    /* ?? pkt->usage += CI_CFG_BUFFER_TRACE_DMAQIN; */          \
  } while(0)


ci_inline void ci_netif_dmaq_and_vi_for_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                            oo_pktq** dmaq, ef_vi** vi) {
  *dmaq = &ni->state->nic[pkt->intf_i].dmaq;
  *vi = &ni->nic_hw[pkt->intf_i].vi;
}


#define __ci_netif_dmaq_insert_prep_pkt(ni, pkt)                        \
  do {                                                                  \
    ci_assert( ! ((pkt)->flags & CI_PKT_FLAG_TX_PENDING) );             \
    (pkt)->flags |= CI_PKT_FLAG_TX_PENDING;                             \
    ci_netif_pkt_hold((ni), (pkt));                                     \
    ++(ni)->state->nic[(pkt)->intf_i].tx_dmaq_insert_seq;               \
    (ni)->state->nic[(pkt)->intf_i].tx_bytes_added+=TX_PKT_LEN(pkt);    \
    if( oo_tcpdump_check(ni, pkt, (pkt)->intf_i) )                      \
      oo_tcpdump_dump_pkt(ni, pkt);                                     \
  } while(0)


#define __ci_netif_dmaq_insert_prep_pkt_warm_undo(ni, pkt)              \
  do {                                                                  \
    (pkt)->flags &=~ CI_PKT_FLAG_TX_PENDING;                            \
    --(ni)->state->nic[(pkt)->intf_i].tx_dmaq_insert_seq;               \
    (ni)->state->nic[(pkt)->intf_i].tx_bytes_added-=TX_PKT_LEN(pkt);    \
    ci_netif_pkt_release(ni, pkt);                                      \
  } while(0)


#endif  /* __NETIF_TX_H__ */
