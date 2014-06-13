/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
#include "logging.h"


#define EFVI_EF10_DMA_TX_FRAG		1


/* TX descriptor for both physical and virtual packet transfers */
typedef ci_qword_t ef_vi_ef10_dma_tx_buf_desc;
typedef ef_vi_ef10_dma_tx_buf_desc ef_vi_ef10_dma_tx_phys_desc;


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


static void ef_vi_transmit_push_desc(ef_vi* vi)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	unsigned di = qs->previous & q->mask;
	ef_vi_ef10_dma_tx_phys_desc *dp =
		(ef_vi_ef10_dma_tx_buf_desc*) q->descriptors + di;
	uint32_t *dbell = (void*) (vi->io + ER_DZ_TX_DESC_UPD_REG);

#if !defined(__KERNEL__) && (defined(__x86_64__) || defined(__i386__))
	ci_oword_t d;
	d.u32[0] = cpu_to_le32(dp->u32[0]);
	d.u32[1] = cpu_to_le32(dp->u32[1]);
	d.u32[2] = qs->added & q->mask;
	__asm__("movups %1, %%xmm0\n\t"
		"movaps %%xmm0, %0"
		: "=m" (*(volatile uint64_t*)(dbell))
		: "m" (d)
		: "xmm0");
#else
	writel(cpu_to_le32(dp->u32[0]), (void *)(dbell));
	writel(cpu_to_le32(dp->u32[1]), (void *)(dbell + 1));
	wmb();
	writel((qs->added & q->mask), dbell + 2);
#endif
	mmiowb();
}


static void ef_vi_transmit_push_doorbell(ef_vi* vi)
{
	uint32_t* doorbell = (void*) (vi->io + ER_DZ_TX_DESC_UPD_REG);
	wmb();
	writel(vi->ep_state->txq.added & vi->vi_txq.mask, doorbell + 2);
	mmiowb();
}


static void ef10_ef_vi_transmit_push(ef_vi* vi)
{
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	if( (qs->previous - qs->removed) < vi->tx_push_thresh )
		ef_vi_transmit_push_desc(vi);
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
	if( rc == 0 )
		ef10_ef_vi_transmit_push(vi);
	return rc;
}


static int ef10_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
				  ef_request_id dma_id)
{
	int rc = ef10_ef_vi_transmitv_init(vi, iov, iov_len, dma_id);
	if( rc == 0 )
		ef10_ef_vi_transmit_push(vi);
	return rc;
}


/* currently with pio only packets spanning over single contigous buffer
 * can be transmitted
 */
static int ef10_ef_vi_transmit_pio(ef_vi* vi, ef_addr offset, int len,
				   ef_request_id dma_id)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	ef_vi_ef10_dma_tx_buf_desc* dp;
	unsigned di;

#if defined(__powerpc64__)
	return -EOPNOTSUPP;
#endif

	EF_VI_BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
	EF_VI_BUG_ON(dma_id == 0xffffffff);
	EF_VI_BUG_ON(offset > 0x7ff);
	EF_VI_BUG_ON(len > 0xfff);

	if( qs->added - qs->removed >= q->mask )
		return -EAGAIN;

	di = qs->added++ & q->mask;
	dp = (ef_vi_ef10_dma_tx_buf_desc*) q->descriptors + di;

	CI_POPULATE_QWORD_4(*dp,
		ESF_DZ_TX_PIO_TYPE, 1,
		ESF_DZ_TX_PIO_OPT, 1,
		ESF_DZ_TX_PIO_BYTE_CNT, len,
		ESF_DZ_TX_PIO_BUF_ADDR, offset);

	q->ids[di] = dma_id;

	ef10_ef_vi_transmit_push(vi);
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


static void ef10_ef_vi_receive_push(ef_vi* vi)
{
	/* Descriptors can only be posted in batches of 8 */
	ef_vi_rxq_state* qs = &vi->ep_state->rxq;
	if( qs->added - qs->prev_added < 8 )
		return;
	wmb();
	writel(((qs->added - ((qs->added - qs->prev_added) & 7)) &
		vi->vi_rxq.mask), vi->io + ER_DZ_RX_DESC_UPD_REG);
	qs->prev_added = qs->added - ((qs->added - qs->prev_added) & 7);
	mmiowb();
}


static void ef10_vi_initialise_ops(ef_vi* vi)
{
	vi->ops.transmit               = ef10_ef_vi_transmit;
	vi->ops.transmitv              = ef10_ef_vi_transmitv;
	vi->ops.transmitv_init         = ef10_ef_vi_transmitv_init;
	vi->ops.transmit_push          = ef10_ef_vi_transmit_push;
	vi->ops.transmit_pio           = ef10_ef_vi_transmit_pio;
	vi->ops.receive_init           = ef10_ef_vi_receive_init;
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

	ef10_vi_initialise_ops(vi);
}

/*! \cidoxg_end */
