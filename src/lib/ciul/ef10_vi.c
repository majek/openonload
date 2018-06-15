/*
** Copyright 2005-2018  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*
 * \author  djr, stg
 *  \brief  ef10-specific VI
 *   \date  2006/11/30
 */

#include "ef_vi_internal.h"
#include <etherfabric/pio.h>
#include "logging.h"
#include "memcpy_to_io.h"


#define EFVI_EF10_DMA_TX_FRAG		1


/* TX descriptor for both physical and virtual packet transfers */
typedef ci_qword_t ef_vi_ef10_dma_tx_buf_desc;
typedef ci_qword_t ef_vi_ef10_dma_tx_phys_desc;


/* RX descriptor for physical addressed transfers */
typedef ci_qword_t ef_vi_ef10_dma_rx_phys_desc;


/* RX descriptor for virtual packet transfers */
typedef ci_qword_t ef_vi_ef10_dma_rx_buf_desc;


ef_vi_inline void
ef10_dma_tx_calc_ip_buf(ef_addr buf_vaddr, unsigned bytes, int port, 
                        int frag, ef_vi_ef10_dma_tx_buf_desc *desc)
{
  DWCHCK(ESF_DZ_TX_USR_4KBPS_BYTE_OFFSET_LBN,
         ESF_DZ_TX_USR_4KBPS_BYTE_OFFSET_WIDTH);

  RANGECHCK(EF10_BUF_VADDR_2_ID_OFFSET(buf_vaddr),
            ESF_DZ_TX_USR_BUF_ID_OFFSET_WIDTH);
  RANGECHCK(EF10_BUF_VADDR_2_ORDER(buf_vaddr),
            ESF_DZ_TX_USR_BUF_PAGE_SIZE_WIDTH);
  RANGECHCK(bytes, ESF_DZ_TX_USR_BYTE_CNT_WIDTH);

  EF_VI_BUG_ON(desc == NULL);

  /* The ESF_DZ_USR_BUF_ID is actually split between the buffer index
   * and an offset.  This split varies with different pages sizes.
   * Currently we are passed the whole field.
   */
  CI_POPULATE_QWORD_4(*desc,
                      ESF_DZ_TX_USR_BUF_ID_OFFSET,
                      EF10_BUF_VADDR_2_ID_OFFSET(buf_vaddr),
                      ESF_DZ_TX_USR_BUF_PAGE_SIZE,
                      EF10_BUF_VADDR_2_ORDER(buf_vaddr),
                      ESF_DZ_TX_USR_BYTE_CNT, bytes,
                      ESF_DZ_TX_USR_CONT, frag);
}


/*! Setup an physical address based descriptor for an IPMODE transfer */
ef_vi_inline void
ef10_dma_tx_calc_ip_phys(uint64_t src_dma_addr, unsigned bytes, 
                         int port, int frag,
                         ef_vi_ef10_dma_tx_phys_desc *desc)
{
  DWCHCK(__DW2(ESF_DZ_TX_KER_CONT_LBN), ESF_DZ_TX_KER_CONT_WIDTH);
  DWCHCK(__DW2(ESF_DZ_TX_KER_BYTE_CNT_LBN), ESF_DZ_TX_KER_BYTE_CNT_WIDTH);

  LWCHK(ESF_DZ_TX_KER_BUF_ADDR_LBN, ESF_DZ_TX_KER_BUF_ADDR_WIDTH);

  RANGECHCK(frag,   ESF_DZ_TX_KER_CONT_WIDTH);
  RANGECHCK(bytes,  ESF_DZ_TX_KER_BYTE_CNT_WIDTH);

  CI_POPULATE_QWORD_3(*desc,
                      ESF_DZ_TX_KER_CONT, frag,
                      ESF_DZ_TX_KER_BYTE_CNT, bytes,
                      ESF_DZ_TX_KER_BUF_ADDR, src_dma_addr);
}


/*! Setup a physical address based descriptor with a specified length */
ef_vi_inline void
ef10_dma_rx_calc_ip_phys(uint64_t dest_pa,
			 ef_vi_ef10_dma_rx_phys_desc* desc, int bytes)
{

  DWCHCK(__DW2(ESF_DZ_RX_KER_BYTE_CNT_LBN), ESF_DZ_RX_KER_BYTE_CNT_WIDTH);
  LWCHK(ESF_DZ_RX_KER_BUF_ADDR_LBN, ESF_DZ_RX_KER_BUF_ADDR_WIDTH);
  RANGECHCK(bytes,  ESF_DZ_RX_KER_BYTE_CNT_LBN);

  CI_POPULATE_QWORD_2(*desc,
                      ESF_DZ_RX_KER_BUF_ADDR, dest_pa,
                      ESF_DZ_RX_KER_BYTE_CNT, bytes);
}


ef_vi_inline void
ef10_dma_rx_calc_ip_buf(ef_addr buf_vaddr, ef_vi_ef10_dma_rx_buf_desc* desc,
                        int rx_bytes)
{
  DWCHCK(ESF_DZ_RX_USR_4KBPS_BYTE_OFFSET_LBN, 
         ESF_DZ_RX_USR_4KBPS_BYTE_OFFSET_WIDTH);
  RANGECHCK(EF10_BUF_VADDR_2_ID_OFFSET(buf_vaddr),
            ESF_DZ_RX_USR_BUF_ID_OFFSET_WIDTH);
  RANGECHCK(EF10_BUF_VADDR_2_ORDER(buf_vaddr),
            ESF_DZ_RX_USR_BUF_PAGE_SIZE_WIDTH);
  RANGECHCK(rx_bytes, ESF_DZ_RX_USR_BYTE_CNT_WIDTH);

  /* The ESF_DZ_USR_BUF_ID is actually split between the buffer index
   * and an offset.  This split varies with different pages sizes.
   * Currently we are passed the whole field.
   */
  CI_POPULATE_QWORD_3(*desc,
                      ESF_DZ_RX_USR_BUF_ID_OFFSET,
                      EF10_BUF_VADDR_2_ID_OFFSET(buf_vaddr),
                      ESF_DZ_RX_USR_BUF_PAGE_SIZE,
                      EF10_BUF_VADDR_2_ORDER(buf_vaddr),
                      ESF_DZ_RX_USR_BYTE_CNT, rx_bytes);
}


static int ef10_ef_vi_transmitv_init(ef_vi* vi, const ef_iovec* iov,
				     int iov_len, ef_request_id dma_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_ef10_dma_tx_buf_desc* dp;
  unsigned len, dma_len, di;
  unsigned added_save = qs->added;
  ef_addr dma_addr;

  EF_VI_BUG_ON((iov_len <= 0));
  EF_VI_BUG_ON(iov == NULL);
  EF_VI_BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
  EF_VI_BUG_ON(dma_id == 0xffffffff);

  dma_addr = iov->iov_base;
  len = iov->iov_len;

  while( 1 ) {
    if( qs->added - qs->removed >= q->mask ) {
      qs->added = added_save;
      return -EAGAIN;
    }

    di = qs->added++ & q->mask;
    dp = (ef_vi_ef10_dma_tx_buf_desc*) q->descriptors + di;

    if (vi->vi_flags & EF_VI_TX_PHYS_ADDR ) {
      ef10_dma_tx_calc_ip_phys(
                               dma_addr, len, /*port*/ 0,
                               (iov_len == 1) ? 0 : EFVI_EF10_DMA_TX_FRAG,
                               dp);
    }
    else {
      dma_len = (~dma_addr & 0xfff) + 1;
      if (dma_len > len)
        dma_len = len;
      ef10_dma_tx_calc_ip_buf(
                              dma_addr, dma_len, /*port*/ 0,
                              (iov_len == 1 && dma_len == len) ?
                              0 : EFVI_EF10_DMA_TX_FRAG, dp);
      dma_addr += dma_len;
      len -= dma_len;
      if (len > 0)
        continue;
    }

    if (--iov_len == 0)
      break;
    iov++;
    dma_addr = iov->iov_base;
    len = iov->iov_len;
  }

  EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
  q->ids[di] = dma_id;
  return 0;
}


static void ef_vi_transmit_push_desc(ef_vi* vi, ef_vi_ef10_dma_tx_phys_desc *dp)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  uint32_t *dbell = (void*) (vi->io + ER_DZ_TX_DESC_UPD_REG);

#if !defined(__KERNEL__) && (defined(__x86_64__) || defined(__i386__))
  ci_oword_t d;
  d.u32[0] = dp->u32[0];
  d.u32[1] = dp->u32[1];
  d.u32[2] = cpu_to_le32(qs->added & q->mask);
  __asm__ __volatile__("movups %1, %%xmm0\n\t"
                       "movaps %%xmm0, %0"
                       : "=m" (*(volatile uint64_t*)(dbell))
                       : "m" (d)
                       : "xmm0", "memory");
#elif !defined(__KERNEL__) && defined(__powerpc64__) &&  __GNUC__ >= 4
  ci_oword_t d;
  d.u32[0] = dp->u32[0];
  d.u32[1] = dp->u32[1];
  d.u32[2] = cpu_to_le32(qs->added & q->mask);
  /* TODO: This sync is needed for the DMA path, but is redundant on PIO
   * paths due to the wmb_wc() which is also a sync.  We should optimise
   * that case...
   */
  __asm__ __volatile__("sync\n\t"
                       "lxvw4x %%vs32, 0, %2\n\t"
                       "stxvw4x %%vs32, 0, %1"
                       : "=m" (*(volatile uint64_t*)dbell)
                       : "r" (dbell), "r" (&d)
                       : "vs32", "memory");
#else
  noswap_writel(dp->u32[0],   dbell + 0);
  noswap_writel(dp->u32[1],   dbell + 1);
  writel(qs->added & q->mask, dbell + 2);
#endif
  mmiowb();
}


static void ef_vi_transmit_push_doorbell(ef_vi* vi)
{
  uint32_t* doorbell = (void*) (vi->io + ER_DZ_TX_DESC_UPD_REG);
  writel(vi->ep_state->txq.added & vi->vi_txq.mask, doorbell + 2);
  mmiowb();
}


ef_vi_inline int
ef10_tx_descriptor_can_push(const ci_qword_t* dp)
{
  const uint64_t is_opt = (uint64_t) 1u << ESF_DZ_TX_DESC_IS_OPT_LBN;
  const uint64_t is_cont = (uint64_t) 1u << ESF_DZ_TX_USR_CONT_LBN;
  const uint64_t is_pio = (uint64_t) 1u << ESF_DZ_TX_PIO_OPT_LBN;
  EF_VI_ASSERT( ESF_DZ_TX_DESC_IS_OPT_WIDTH == 1 );
  EF_VI_ASSERT( ESF_DZ_TX_USR_CONT_WIDTH == 1 );
  return ( ((dp->u64[0] & (is_opt | is_cont)) == 0) ||
           ((dp->u64[0] & (is_opt | is_pio)) == (is_opt | is_pio)) );
}


static void ef10_ef_vi_transmit_push(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_txq* q = &vi->vi_txq;
  unsigned di = qs->previous & q->mask;
  ef_vi_ef10_dma_tx_phys_desc *dp =
    (ef_vi_ef10_dma_tx_buf_desc*) q->descriptors + di;
  if( (qs->previous - qs->removed) < vi->tx_push_thresh &&
      ef10_tx_descriptor_can_push(dp) )
    ef_vi_transmit_push_desc(vi, dp);
  else
    ef_vi_transmit_push_doorbell(vi);
  EF_VI_BUG_ON(qs->previous == qs->added);
  qs->previous = qs->added;
}


static int ef10_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                               ef_request_id dma_id)
{
  ef_iovec iov = { base, len };
  int rc = ef10_ef_vi_transmitv_init(vi, &iov, 1, dma_id);
  if( rc == 0 ) {
    wmb();
    ef10_ef_vi_transmit_push(vi);
  }
  return rc;
}


static int ef10_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
                                ef_request_id dma_id)
{
  int rc = ef10_ef_vi_transmitv_init(vi, iov, iov_len, dma_id);
  if( rc == 0 ) {
    wmb();
    ef10_ef_vi_transmit_push(vi);
  }
  return rc;
}


ef_vi_inline void
ef10_pio_set_desc(ef_vi* vi, ef_vi_txq* q, ef_vi_txq_state* qs,
                  int offset, int len, ef_request_id dma_id)
{
  ef_vi_ef10_dma_tx_buf_desc* dp;
  unsigned di = qs->added & q->mask;

  dp = (ef_vi_ef10_dma_tx_buf_desc*) q->descriptors + di;
  CI_POPULATE_QWORD_4(*dp,
                      ESF_DZ_TX_PIO_TYPE, 1,
                      ESF_DZ_TX_PIO_OPT, 1,
                      ESF_DZ_TX_PIO_BYTE_CNT, len,
                      ESF_DZ_TX_PIO_BUF_ADDR, offset);
  q->ids[di] = dma_id;
}


static inline void ef10_pio_push(ef_vi* vi, ef_vi_txq_state* qs)
{
  /* Prior call to ef10_pio_set_desc does not increment queue position as
   * it is used for pio send path warming.  Increment here before push.
   */
  qs->added++;

  /* Ensure earlier writes via WC complete and the descriptor is written to
   * mem before the doorbell is sent.
   */
  wmb_wc();
  ef10_ef_vi_transmit_push(vi);
}


/* currently with pio only packets spanning over single contigous buffer
 * can be transmitted
 */
static int ef10_ef_vi_transmit_pio(ef_vi* vi, int offset, int len,
				   ef_request_id dma_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;

  EF_VI_ASSERT((dma_id & EF_REQUEST_ID_MASK) == dma_id);
  EF_VI_ASSERT(dma_id != 0xffffffff);
  EF_VI_ASSERT((unsigned) offset < vi->linked_pio->pio_len);
  EF_VI_ASSERT((unsigned) (offset + len) <= vi->linked_pio->pio_len);

  if(CI_UNLIKELY( (offset & 63) != 0 ))
    return -EINVAL;

  ef10_pio_set_desc(vi, q, qs, offset, len, dma_id);
  if( qs->added - qs->removed < q->mask ) {
    ef10_pio_push(vi, qs);
    return 0;
  } else {
    /* Undo effect of ef10_pio_set_desc */
    q->ids[qs->added & q->mask] = EF_REQUEST_ID_MASK;
    return -EAGAIN;
  }
}


static int ef10_ef_vi_transmit_copy_pio(ef_vi* vi, int offset,
					const void* src_buf, int len,
					ef_request_id dma_id)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_txq* q = &vi->vi_txq;
  ef_pio* pio = vi->linked_pio;

  EF_VI_ASSERT((dma_id & EF_REQUEST_ID_MASK) == dma_id);
  EF_VI_ASSERT(dma_id != 0xffffffff);
  EF_VI_ASSERT((unsigned) offset < pio->pio_len);
  EF_VI_ASSERT((unsigned) (offset + len) <= pio->pio_len);
  EF_VI_ASSERT(len >= 16);

  if(CI_UNLIKELY( (offset & 63) != 0 ))
    return -EINVAL;

  memcpy_to_pio(pio->pio_io + offset, src_buf, len);
  ef10_pio_set_desc(vi, q, qs, offset, len, dma_id);
  if( qs->added - qs->removed < q->mask ) {
    ef10_pio_push(vi, qs);
    return 0;
  } else {
    /* Undo effect of ef10_pio_set_desc */
    q->ids[qs->added & q->mask] = EF_REQUEST_ID_MASK;
    return -EAGAIN;
  }
}


static void ef10_ef_vi_transmit_pio_warm(ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_txq* q = &vi->vi_txq;
  unsigned save_removed = qs->removed;

  /* qs->removed is modified so ( qs->added - qs->removed < q->mask )
   * is false and packet is not sent.  Descriptor is written to
   * qs->added & q->mask.
   */
  qs->removed = qs->added - q->mask;
  ef10_ef_vi_transmit_pio(vi, 0, 0, 0);
  EF_VI_ASSERT(q->ids[qs->added & q->mask] == EF_REQUEST_ID_MASK);
  qs->removed = save_removed;
}


static void ef10_ef_vi_transmit_copy_pio_warm(ef_vi* vi, int pio_offset,
                                              const void* src_buf, int len)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_txq* q = &vi->vi_txq;
  unsigned save_removed = qs->removed;

  /* qs->removed is modified so ( qs->added - qs->removed < q->mask )
   * is false and packet is not sent.  Descriptor is written to
   * qs->added & q->mask.
   */
  qs->removed = qs->added - q->mask;
  ef10_ef_vi_transmit_copy_pio(vi, pio_offset, src_buf, len, 0);
  EF_VI_ASSERT(q->ids[qs->added & q->mask] == EF_REQUEST_ID_MASK);
  qs->removed = save_removed;
}


#ifndef __KERNEL__
#include <sys/uio.h>
/* Somewhat limited implementation of transmitv_.
 * Up to two iovecs can be given,
 * First iovec is 64byte aligned: both base and len.
 * Also as we are user only plain iovec is used.
 */
int ef10_ef_vi_transmitv_copy_pio(ef_vi* vi, int offset,
				  const struct iovec* iov, int iovcnt,
				  ef_request_id dma_id)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ef_vi_txq* q = &vi->vi_txq;
  ef_pio* pio = vi->linked_pio;

  EF_VI_ASSERT((dma_id & EF_REQUEST_ID_MASK) == dma_id);
  EF_VI_ASSERT(dma_id != 0xffffffff);
  EF_VI_ASSERT((unsigned) offset < pio->pio_len);
  EF_VI_ASSERT(iovcnt >= 1);
  EF_VI_ASSERT(iovcnt <= 2);
  EF_VI_ASSERT((unsigned) (offset + iov[0].iov_len) <= pio->pio_len);
  EF_VI_ASSERT(iovcnt < 2 ||
               (unsigned) (offset + iov[0].iov_len + iov[1].iov_len) <=
                          pio->pio_len);
  EF_VI_ASSERT(iov[0].iov_len != 0);
  EF_VI_ASSERT((iov[0].iov_len & 7) == 0 || iovcnt == 1);

  if(CI_UNLIKELY( (offset & 63) != 0 ))
    return -EINVAL;

  if( qs->added - qs->removed < q->mask ) {
    unsigned char* pio_dst = pio->pio_io + offset;
    int len = iov[0].iov_len;
    /* copy multiples of 8 - we make a lot of assumption on first iovec here */
    memcpy_to_pio_aligned(pio_dst, iov[0].iov_base, (iov[0].iov_len + 7) & ~7);

    if( iovcnt > 1 ) {
      memcpy_to_pio(pio_dst + len, iov[1].iov_base, iov[1].iov_len);
      len += iov[1].iov_len;
    }
    ef10_pio_set_desc(vi, q, qs, offset, len, dma_id);
    ef10_pio_push(vi, qs);
    return 0;
  } else {
    return -EAGAIN;
  }
}
#endif


/* ?? todo: rename and move to host_ef10_common.h (via firmwaresrc) */
#define ALT_OP_VFIFO_ID_LBN    48
#define ALT_OP_VFIFO_ID_WIDTH  5
#define ALT_OP_IS_SELECT_LBN   59
#define ALT_OP_IS_SELECT_WIDTH 1


static int ef10_ef_vi_transmit_alt_select(ef_vi* vi, unsigned alt_id)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ci_qword_t* dp;
  unsigned di;

  EF_VI_ASSERT( vi->vi_flags & EF_VI_TX_ALT );
  EF_VI_ASSERT( alt_id < vi->tx_alt_num );

  if( qs->added - qs->removed >= q->mask )
    return -EAGAIN;

  di = (qs->added)++ & q->mask;
  dp = (ci_qword_t*) q->descriptors + di;
  alt_id = vi->tx_alt_id2hw[alt_id];

  CI_POPULATE_QWORD_4(*dp,
                      ESF_DZ_TX_DESC_IS_OPT, 1,
                      ESF_DZ_TX_OPTION_TYPE, 2,
                      ALT_OP_IS_SELECT, 1,
                      ALT_OP_VFIFO_ID, alt_id);
  EF_VI_BUG_ON( q->ids[di] != EF_REQUEST_ID_MASK );

  return 0;
}


static int ef10_ef_vi_transmit_alt_select_normal(ef_vi* vi)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  ci_qword_t* dp;
  unsigned di;

  EF_VI_ASSERT( vi->vi_flags & EF_VI_TX_ALT );

  if( qs->added - qs->removed >= q->mask )
    return -EAGAIN;

  di = (qs->added)++ & q->mask;
  dp = (ci_qword_t*) q->descriptors + di;

  CI_POPULATE_QWORD_4(*dp,
                      ESF_DZ_TX_DESC_IS_OPT, 1,
                      ESF_DZ_TX_OPTION_TYPE, 2,
                      ALT_OP_IS_SELECT, 1,
                      ALT_OP_VFIFO_ID, 0x1f);
  EF_VI_BUG_ON( q->ids[di] != EF_REQUEST_ID_MASK );

  return 0;
}


static int ef10_ef_vi_transmit_alt_stop(ef_vi* vi, unsigned alt_id)
{
  uint32_t* doorbell = (uint32_t*) (vi->io + ER_DZ_TX_DESC_UPD_REG + 8);
  EF_VI_ASSERT( vi->vi_flags & EF_VI_TX_ALT );
  EF_VI_ASSERT( alt_id < vi->tx_alt_num );
  alt_id = vi->tx_alt_id2hw[alt_id];
  /* ?? todo: magic numbers */
  writel((1u << 11) | (3u << 8) | (4u << 5) | alt_id, doorbell);
  mmiowb();
  return 0;
}


static int ef10_ef_vi_transmit_alt_discard(ef_vi* vi, unsigned alt_id)
{
  uint32_t* doorbell = (uint32_t*) (vi->io + ER_DZ_TX_DESC_UPD_REG + 8);
  EF_VI_ASSERT( vi->vi_flags & EF_VI_TX_ALT );
  EF_VI_ASSERT( alt_id < vi->tx_alt_num );
  alt_id = vi->tx_alt_id2hw[alt_id];
  /* ?? todo: magic numbers */
  writel((1u << 11) | (3u << 8) | alt_id, doorbell);
  mmiowb();
  return 0;
}


static int ef10_ef_vi_transmit_alt_go(ef_vi* vi, unsigned alt_id)
{
  uint32_t* doorbell = (uint32_t*) (vi->io + ER_DZ_TX_DESC_UPD_REG + 8);
  EF_VI_ASSERT( vi->vi_flags & EF_VI_TX_ALT );
  EF_VI_ASSERT( alt_id < vi->tx_alt_num );
  alt_id = vi->tx_alt_id2hw[alt_id];
  /* ?? todo: magic numbers */
  writel((1u << 11) | (2u << 8) | alt_id, doorbell);
  mmiowb();
  return 0;
}


static int ef10_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                   ef_request_id dma_id)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned di;

  if( ef_vi_receive_space(vi) ) {
    di = qs->added++ & q->mask;
    EF_VI_BUG_ON(q->ids[di] !=  EF_REQUEST_ID_MASK);
    q->ids[di] = dma_id;

    if( vi->vi_flags & EF_VI_RX_PHYS_ADDR ) {
      ef_vi_ef10_dma_rx_phys_desc* dp;
      dp =(ef_vi_ef10_dma_rx_phys_desc*)q->descriptors + di;
      ef10_dma_rx_calc_ip_phys(addr, dp, vi->rx_buffer_len);
    }
    else {
      ef_vi_ef10_dma_rx_buf_desc* dp;
      dp = (ef_vi_ef10_dma_rx_buf_desc*)q->descriptors + di;
      ef10_dma_rx_calc_ip_buf(addr, dp, vi->rx_buffer_len);
    }
    return 0;
  }
  return -EAGAIN;
}


static int ef10_ef_vi_receive_init_ps(ef_vi* vi, ef_addr addr,
				      ef_request_id dma_id)
{
  if( (addr & (vi->vi_ps_buf_size - 1)) != 0 )
    return -EINVAL;
  return ef10_ef_vi_receive_init(vi, addr | EF_VI_PS_DMA_START_OFFSET, 0);
}


static void ef10_ef_vi_receive_push(ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  /* Descriptors can only be posted in batches of 8. */
  uint32_t posted = qs->added & ~7;
  if(likely( posted != qs->posted )) {
    writel(posted & vi->vi_rxq.mask, vi->io + ER_DZ_RX_DESC_UPD_REG);
    qs->posted = posted;
    mmiowb();
  }
}


static void ef10_vi_initialise_ops(ef_vi* vi)
{
  vi->ops.transmit               = ef10_ef_vi_transmit;
  vi->ops.transmitv              = ef10_ef_vi_transmitv;
  vi->ops.transmitv_init         = ef10_ef_vi_transmitv_init;
  vi->ops.transmit_push          = ef10_ef_vi_transmit_push;
  vi->ops.transmit_pio           = ef10_ef_vi_transmit_pio;
  vi->ops.transmit_copy_pio      = ef10_ef_vi_transmit_copy_pio;
  vi->ops.transmit_pio_warm      = ef10_ef_vi_transmit_pio_warm;
  vi->ops.transmit_copy_pio_warm = ef10_ef_vi_transmit_copy_pio_warm;
  vi->ops.transmit_alt_select    = ef10_ef_vi_transmit_alt_select;
  vi->ops.transmit_alt_select_default = ef10_ef_vi_transmit_alt_select_normal;
  vi->ops.transmit_alt_stop      = ef10_ef_vi_transmit_alt_stop;
  vi->ops.transmit_alt_go        = ef10_ef_vi_transmit_alt_go;
  vi->ops.transmit_alt_discard   = ef10_ef_vi_transmit_alt_discard;
  if( vi->vi_flags & EF_VI_RX_PACKED_STREAM ) {
    vi->ops.receive_init   = ef10_ef_vi_receive_init_ps;
  } else {
    vi->ops.receive_init   = ef10_ef_vi_receive_init;
  }
  vi->ops.receive_push           = ef10_ef_vi_receive_push;
  vi->ops.eventq_poll            = ef10_ef_eventq_poll;
  vi->ops.eventq_prime           = ef10_ef_eventq_prime;
  vi->ops.eventq_timer_prime     = ef10_ef_eventq_timer_prime;
  vi->ops.eventq_timer_run       = ef10_ef_eventq_timer_run;
  vi->ops.eventq_timer_clear     = ef10_ef_eventq_timer_clear;
  vi->ops.eventq_timer_zero      = ef10_ef_eventq_timer_zero;
}


void ef10_vi_init(ef_vi* vi)
{
  /* XXX: bug31845: need to push a descriptor to enable checksum
   * offload to be similar to seina.  According to comment3 on
   * bug30838 and bug29981, the TX collector has to be flushed
   * on TXQ init.  Pushing the descriptor will achieve this.
   * Still documenting this in case in future we stop pusing the
   * enable checksum offload at startup. */

  /* This is set to match Falcon arch.  In future we should provide a
   * way for applications to override.
   */
  vi->rx_buffer_len = 2048 - 256;

  /* Set default rx_discard_mask for ef10 */
  vi->rx_discard_mask =
    CI_BSWAPC_LE64(1LL << ESF_DZ_RX_ECC_ERR_LBN
                   | 1LL << ESF_DZ_RX_TCPUDP_CKSUM_ERR_LBN
                   | 1LL << ESF_DZ_RX_IPCKSUM_ERR_LBN
                   | 1LL << ESF_DZ_RX_ECRC_ERR_LBN);

  ef10_vi_initialise_ops(vi);
}

/*! \cidoxg_end */
