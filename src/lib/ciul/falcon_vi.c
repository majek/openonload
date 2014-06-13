/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
 *  \brief  Falcon-specific VI
 *   \date  2006/11/30
 */

#include "ef_vi_internal.h"
#include "logging.h"

#define EFVI_FALCON_DMA_TX_FRAG		1


static void falcon_vi_initialise_ops(ef_vi* vi);


/* TX descriptor for both physical and virtual packet transfers */
typedef ci_qword_t ef_vi_falcon_dma_tx_buf_desc;
typedef ef_vi_falcon_dma_tx_buf_desc ef_vi_falcon_dma_tx_phys_desc;


/* RX descriptor for physical addressed transfers */
typedef ci_qword_t ef_vi_falcon_dma_rx_phys_desc;

/* RX descriptor for virtual packet transfers */
typedef ci_dword_t ef_vi_falcon_dma_rx_buf_desc;

/* Buffer table index */
typedef uint32_t		ef_vi_buffer_addr_t;

ef_vi_inline int64_t dma_addr_to_u46(int64_t src_dma_addr)
{
	return (src_dma_addr & __EFVI_MASK(46, int64_t));
}

/*! Setup a physical address based descriptor with a specified length */
ef_vi_inline void
__falcon_dma_rx_calc_ip_phys(ef_vi_dma_addr_t dest_pa, 
			     ef_vi_falcon_dma_rx_phys_desc *desc,
			     int bytes)
{
	int region = 0; 		/* TODO fixme */
	int64_t dest    = dma_addr_to_u46(dest_pa); /* lower 46 bits */

	DWCHCK(__DW2(RX_KER_BUF_SIZE_LBN),  RX_KER_BUF_SIZE_WIDTH);
	DWCHCK(__DW2(RX_KER_BUF_REGION_LBN),RX_KER_BUF_REGION_WIDTH);

	LWCHK(RX_KER_BUF_ADR_LBN, RX_KER_BUF_ADR_WIDTH);

	RANGECHCK(bytes,  RX_KER_BUF_SIZE_WIDTH);
	RANGECHCK(region, RX_KER_BUF_REGION_WIDTH);

	CI_POPULATE_QWORD_3(*desc,
			    RX_KER_BUF_SIZE, bytes,
			    RX_KER_BUF_REGION, region,
			    RX_KER_BUF_ADR, dest);

	LOGV(ef_log("vi: dma_rx_calc_ip_phys(): bytes=%d region=%d dest=%llx->%llx "
		    "desc="CI_QWORD_FMT,
		    bytes, region,
		    (long long)dest_pa, (long long)dest,
		    CI_QWORD_VAL(*desc)));
}

/*! Setup a virtual buffer descriptor for an IPMODE transfer */
ef_vi_inline void
__falcon_dma_tx_calc_ip_buf(unsigned buf_id, unsigned buf_ofs, unsigned bytes,
			    int port, int frag, 
			    ef_vi_falcon_dma_tx_buf_desc *desc)
{
	DWCHCK(__DW2(TX_USR_PORT_LBN), TX_USR_PORT_WIDTH);
	DWCHCK(__DW2(TX_USR_CONT_LBN), TX_USR_CONT_WIDTH);
	DWCHCK(__DW2(TX_USR_BYTE_CNT_LBN), TX_USR_BYTE_CNT_WIDTH);
	LWCHK(RX_KER_BUF_ADR_LBN, RX_KER_BUF_ADR_WIDTH);
	DWCHCK(TX_USR_BYTE_OFS_LBN, TX_USR_BYTE_OFS_WIDTH);

	RANGECHCK(bytes,   TX_USR_BYTE_CNT_WIDTH);
	RANGECHCK(port,    TX_USR_PORT_WIDTH);
	RANGECHCK(frag,    TX_USR_CONT_WIDTH);
	RANGECHCK(buf_id,  TX_USR_BUF_ID_WIDTH);
	RANGECHCK(buf_ofs, TX_USR_BYTE_OFS_WIDTH);

	CI_POPULATE_QWORD_5(*desc,
			    TX_USR_PORT, port,
			    TX_USR_CONT, frag,
			    TX_USR_BYTE_CNT, bytes,
			    TX_USR_BUF_ID, buf_id,
			    TX_USR_BYTE_OFS, buf_ofs);

	LOGV(ef_log("vi: dma_tx_calc_ip_buf: "CI_QWORD_FMT,
		    CI_QWORD_VAL(*desc)));
}

ef_vi_inline void
falcon_dma_tx_calc_ip_buf_4k(unsigned buf_vaddr, unsigned bytes,
			     int port, int frag, 
			     ef_vi_falcon_dma_tx_buf_desc *desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the
	** high bits, and an offset in the low bits. Assumptions
	** permate the code that these can be rolled into one 32bit
	** value, so this is currently preserved for Falcon. But we
	** should change to support 8K pages
	*/
	unsigned buf_id =  EFVI_FALCON_BUFFER_4K_PAGE(buf_vaddr);
	unsigned buf_ofs = EFVI_FALCON_BUFFER_4K_OFF(buf_vaddr);

	__falcon_dma_tx_calc_ip_buf( buf_id, buf_ofs, bytes, port, frag, desc);
}

ef_vi_inline void
falcon_dma_tx_calc_ip_buf(unsigned buf_vaddr, unsigned bytes, int port, 
			  int frag, ef_vi_falcon_dma_tx_buf_desc *desc)
{
	falcon_dma_tx_calc_ip_buf_4k(buf_vaddr, bytes, port, frag, desc);
}

/*! Setup a virtual buffer based descriptor */
ef_vi_inline void
__falcon_dma_rx_calc_ip_buf(unsigned buf_id, unsigned buf_ofs, 
			    ef_vi_falcon_dma_rx_buf_desc *desc)
{ 
	/* check alignment of buffer offset and pack */
	EF_VI_BUG_ON((buf_ofs & 0x1) != 0);

	buf_ofs >>= 1;

	DWCHCK(RX_USR_2BYTE_OFS_LBN, RX_USR_2BYTE_OFS_WIDTH);
	DWCHCK(RX_USR_BUF_ID_LBN, RX_USR_BUF_ID_WIDTH);

	RANGECHCK(buf_ofs, RX_USR_2BYTE_OFS_WIDTH);
	RANGECHCK(buf_id,  RX_USR_BUF_ID_WIDTH);

	CI_POPULATE_DWORD_2(*desc,
			    RX_USR_2BYTE_OFS, buf_ofs,
			    RX_USR_BUF_ID, buf_id);

	LOGV(ef_log("vi: dma_rx_calc_ip_buf: "CI_DWORD_FMT,
		    CI_DWORD_VAL(*desc)));
}

ef_vi_inline void
falcon_dma_rx_calc_ip_buf_4k(unsigned buf_vaddr, 
			     ef_vi_falcon_dma_rx_buf_desc *desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the
	** high bits, and an offset in the low bits. Assumptions
	** permeate the code that these can be rolled into one 32bit
	** value, so this is currently preserved for Falcon. But we
	** should change to support 8K pages
	*/
	unsigned buf_id =  EFVI_FALCON_BUFFER_4K_PAGE(buf_vaddr);
	unsigned buf_ofs = EFVI_FALCON_BUFFER_4K_OFF(buf_vaddr);

	__falcon_dma_rx_calc_ip_buf(buf_id, buf_ofs, desc);
}

ef_vi_inline void
falcon_dma_rx_calc_ip_buf(unsigned buf_vaddr, 
			  ef_vi_falcon_dma_rx_buf_desc *desc)
{ 
	falcon_dma_rx_calc_ip_buf_4k(buf_vaddr, desc);
}


ef_vi_inline ef_vi_dma_addr_t ef_physaddr(ef_addr efaddr)
{
	return (ef_vi_dma_addr_t) efaddr;
}


/*! Convert between an ef_addr and a buffer table index
**  Assert that this was not a physical address
*/
ef_vi_inline ef_vi_buffer_addr_t ef_bufaddr(ef_addr efaddr)
{
	EF_VI_BUG_ON(efaddr >= ((uint64_t)1 << 32));

	return (ef_vi_buffer_addr_t) efaddr;
}

/*! Setup an physical address based descriptor for an IPMODE transfer */
ef_vi_inline void
falcon_dma_tx_calc_ip_phys(ef_vi_dma_addr_t	src_dma_addr, unsigned bytes, 
			   int			port, int frag,
			   ef_vi_falcon_dma_tx_phys_desc *desc)
{
	int64_t src = dma_addr_to_u46(src_dma_addr);
	int region = 0; /* FIXME */

	DWCHCK(__DW2(TX_KER_PORT_LBN),      TX_KER_PORT_WIDTH);
	DWCHCK(__DW2(TX_KER_CONT_LBN),      TX_KER_CONT_WIDTH);
	DWCHCK(__DW2(TX_KER_BYTE_CNT_LBN),  TX_KER_BYTE_CNT_WIDTH);
	DWCHCK(__DW2(TX_KER_BUF_REGION_LBN),TX_KER_BUF_REGION_WIDTH);

	LWCHK(TX_KER_BUF_ADR_LBN, TX_KER_BUF_ADR_WIDTH);

	RANGECHCK(port,   TX_KER_PORT_WIDTH);
	RANGECHCK(frag,   TX_KER_CONT_WIDTH);
	RANGECHCK(bytes,  TX_KER_BYTE_CNT_WIDTH);
	RANGECHCK(region, TX_KER_BUF_REGION_WIDTH);

	CI_POPULATE_QWORD_5(*desc,
			    TX_KER_PORT, port,
			    TX_KER_CONT, frag,
			    TX_KER_BYTE_CNT, bytes,
			    TX_KER_BUF_REGION, region,
			    TX_KER_BUF_ADR, src);

	LOGV(ef_log("vi: dma_tx_calc_ip_phys: "CI_QWORD_FMT,
		    CI_QWORD_VAL(*desc)));
}


void falcon_vi_init(ef_vi* vi, void* vvis)
{
	struct vi_mappings *vm = (struct vi_mappings*)vvis;
	uint32_t* ids;

	EF_VI_BUG_ON(vm->signature != VI_MAPPING_SIGNATURE);
	EF_VI_BUG_ON(vm->nic_type.arch != EF_VI_ARCH_FALCON);

	vi->rx_prefix_len = vm->rx_prefix_len;

	/* ?? FIXME: We need to query the driver to find this value, since
	 * ultimately it is set by the sfc net driver.
	 */
	vi->rx_buffer_len = 2048 - 256;

	/* Initialise masks to zero, so that ef_vi_state_init() will
	** not do any harm when we don't have DMA queues. */
	vi->vi_rxq.mask = vi->vi_txq.mask = 0;

	/* Initialise doorbell addresses to a distinctive small value
	** which will cause a segfault, to trap doorbell pushes to VIs
	** without DMA queues. */
	vi->vi_rxq.doorbell = vi->vi_txq.doorbell = (ef_vi_ioaddr_t)0xdb;

	ids = (uint32_t*) (vi->ep_state + 1);

	if( vm->tx_queue_capacity ) {
		vi->vi_txq.mask = vm->tx_queue_capacity - 1;
		vi->vi_txq.doorbell = vm->tx_bell + 12;
		vi->vi_txq.descriptors = vm->tx_dma_falcon;
		vi->vi_txq.ids = ids;
		ids += vi->vi_txq.mask + 1;
		/* Check that the id fifo fits in the space allocated. */
		EF_VI_BUG_ON((char*) (vi->vi_txq.ids + vm->tx_queue_capacity) >
			     (char*) vi->ep_state
			     + ef_vi_calc_state_bytes(vm->rx_queue_capacity,
						      vm->tx_queue_capacity));
	}
	if( vm->rx_queue_capacity ) {
		vi->vi_rxq.mask = vm->rx_queue_capacity - 1;
		vi->vi_rxq.doorbell = vm->rx_bell + 12;
		vi->vi_rxq.descriptors = vm->rx_dma_falcon;
		vi->vi_rxq.ids = ids;
		/* Check that the id fifo fits in the space allocated. */
		EF_VI_BUG_ON((char*) (vi->vi_rxq.ids + vm->rx_queue_capacity) >
			     (char*) vi->ep_state
			     + ef_vi_calc_state_bytes(vm->rx_queue_capacity,
						      vm->tx_queue_capacity));
	}

	falcon_vi_initialise_ops(vi);
}


static int falcon_ef_vi_transmitv_init(ef_vi* vi, const ef_iovec* iov,
				       int iov_len, ef_request_id dma_id)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	ef_vi_falcon_dma_tx_buf_desc* dp;
	unsigned len, dma_len, di;
	unsigned added_save = qs->added;
	ef_addr dma_addr;
	unsigned last_len = 0;

	EF_VI_BUG_ON(iov_len <= 0);
	EF_VI_BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
	EF_VI_BUG_ON(dma_id == 0xffffffff);

	dma_addr = iov->iov_base;
	len = iov->iov_len;

	if( vi->vi_flags & EF_VI_ISCSI_TX_DDIG ) {
		/* Last 4 bytes of placeholder for digest must be
		 * removed for h/w */
		EF_VI_BUG_ON(len <= 4);
		last_len = iov[iov_len - 1].iov_len;
		if( last_len <= 4 ) {
			EF_VI_BUG_ON(iov_len <= 1);
			--iov_len;
			last_len = iov[iov_len - 1].iov_len - (4 - last_len);
		}
		else {
			last_len = iov[iov_len - 1].iov_len - 4;
		}
		if( iov_len == 1 )
			len = last_len;
	}

	while( 1 ) {
		if( qs->added - qs->removed >= q->mask ) {
			qs->added = added_save;
			return -EAGAIN;
		}

		dma_len = (~((unsigned) dma_addr) & 0xfff) + 1;
		if( dma_len > len )  dma_len = len;

		di = qs->added++ & q->mask;
		dp = (ef_vi_falcon_dma_tx_buf_desc*) q->descriptors + di;
		if( vi->vi_flags & EF_VI_TX_PHYS_ADDR )
			falcon_dma_tx_calc_ip_phys
				(ef_physaddr(dma_addr), dma_len, /*port*/ 0,
				 (iov_len == 1 && dma_len == len) ? 0 :
				 EFVI_FALCON_DMA_TX_FRAG, dp);
		else
			falcon_dma_tx_calc_ip_buf
				(ef_bufaddr(dma_addr), dma_len, /*port*/ 0,
				 (iov_len == 1 && dma_len == len) ? 0 :
				 EFVI_FALCON_DMA_TX_FRAG, dp);

		dma_addr += dma_len;
		len -= dma_len;

		if( len == 0 ) {
			if( --iov_len == 0 )  break;
			++iov;
			dma_addr = iov->iov_base;
			len = iov->iov_len;
			if( (vi->vi_flags & EF_VI_ISCSI_TX_DDIG) &&
			    (iov_len == 1) )
				len = last_len;
		}
	}

	EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
	q->ids[di] = dma_id;
	return 0;
}


static void ef_vi_transmit_push_desc(ef_vi* vi)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	unsigned di = qs->removed & q->mask;
	ef_vi_falcon_dma_tx_buf_desc* dp = 
		(ef_vi_falcon_dma_tx_buf_desc*) q->descriptors + di;
	ci_oword_t d;

#if  !defined(__KERNEL__) && defined(__powerpc64__) &&  __GNUC__ >= 4
	d.u32[0] = dp->u32[0];
	d.u32[1] = dp->u32[1];
	__nosync_writel((1) << __DW3(FRF_AZ_TX_DESC_PUSH_CMD_LBN), &d.u32[2]);
	__nosync_writel((qs->added & q->mask) << __DW4(FRF_AZ_TX_DESC_WPTR_LBN), &d.u32[3]);
#else
	d.u32[0] = cpu_to_le32(dp->u32[0]);
	d.u32[1] = cpu_to_le32(dp->u32[1]);
	d.u32[2] = ((1) << __DW3(FRF_AZ_TX_DESC_PUSH_CMD_LBN));
	d.u32[3] = ((qs->added & q->mask) << __DW4(FRF_AZ_TX_DESC_WPTR_LBN));
#endif

	LOGV(ef_log("vi: vi_tx_push: "CI_OWORD_FMT,
              CI_OWORD_VAL(d)));

#if !defined(__KERNEL__) && (defined(__x86_64__) || defined(__i386__))
	/* This beats the individual writes (below) because the whole thing
	 * gets emitted as a single TLP.
	 */
	__asm__("movups %1, %%xmm0\n\t"
		"movaps %%xmm0, %0"
		: "=m" (*(volatile uint64_t*)((char*)vi->vi_txq.doorbell - 12))
		: "m" (d)
		: "xmm0");
#elif  !defined(__KERNEL__) && defined(__powerpc64__) &&  __GNUC__ >= 4
	__asm__ __volatile__ 
		("lxvw4x %%vs32, 0, %2\n\t"
		 "stxvw4x %%vs32, 0, %1"
		 : "=m" (*(volatile uint64_t*)((char*)vi->vi_txq.doorbell - 12))
                 : "r" ((char*)vi->vi_txq.doorbell - 12), 
		    "r" (&d)
		 : "vs32");
		
#else
	/* byte swapping was already performed, bytes were filled in correct
	 * order */
	writel(d.u32[0], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 12);
	writel(d.u32[1], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 8);
	writel(d.u32[2], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 4);
	wmb();
	writel(d.u32[3], vi->vi_txq.doorbell);
#endif
	mmiowb();
}


static void ef_vi_transmit_push_doorbell(ef_vi* vi)
{
	LOGV(ef_log("vi: vi_tx_push_dbell: "));

	writel((vi->ep_state->txq.added & vi->vi_txq.mask) <<
	       __DW4(FRF_AZ_TX_DESC_WPTR_LBN),
	       vi->vi_txq.doorbell);
	mmiowb();
}


static void falcon_ef_vi_transmit_push(ef_vi* vi)
{
	ef_vi_txq_state* qs = &vi->ep_state->txq;
        /* If added is one bigger than removed, then we have exactly
         * one descriptor to push and the queue was otherwise empty,
         * so we can use TX push 
         */
	if( (qs->removed+1 == qs->added) &&
	    ! (vi->vi_flags & EF_VI_TX_PUSH_DISABLE) )
		ef_vi_transmit_push_desc(vi);
	else
		ef_vi_transmit_push_doorbell(vi);
	EF_VI_BUG_ON(qs->previous == qs->added);
	EF_VI_DEBUG(qs->previous = qs->added);
}


static int falcon_ef_vi_transmit_pio(ef_vi* vi, ef_addr offset, int len,
                                     ef_request_id dma_id)
{
	LOGVV(ef_log("%s: falcon does not support PIO", __FUNCTION__));
	return -EINVAL;
}


static int falcon_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
				     ef_request_id dma_id)
{
	ef_vi_rxq* q = &vi->vi_rxq;
	ef_vi_rxq_state* qs = &vi->ep_state->rxq;
	unsigned di;

	if( ef_vi_receive_space(vi) ) {
		di = qs->added++ & q->mask;
		EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
		q->ids[di] = dma_id;

		if( ! (vi->vi_flags & EF_VI_RX_PHYS_ADDR) ) {
			ef_vi_falcon_dma_rx_buf_desc* dp;
			dp = (ef_vi_falcon_dma_rx_buf_desc*) 
				q->descriptors + di;
			falcon_dma_rx_calc_ip_buf(ef_bufaddr(addr), dp);
		}
		else {
			ef_vi_falcon_dma_rx_phys_desc* dp;
			dp = (ef_vi_falcon_dma_rx_phys_desc*) 
				q->descriptors + di;
                        /* NB. Length of zero here means 16384 bytes.  Not
                         * used when in scatter mode.  So in phys/contig
                         * mode user must supply buffer a bit larger than
                         * MAC MTU.
                         */
			__falcon_dma_rx_calc_ip_phys(addr, dp, 0);
		}

		return 0;
	}

	return -EAGAIN;
}


static void falcon_ef_vi_receive_push(ef_vi* vi)
{
	LOGV(ef_log("vi: vi_rx_push: "));

	writel ((vi->ep_state->rxq.added & vi->vi_rxq.mask) <<
		__DW4(FRF_AZ_RX_DESC_WPTR_LBN),
		vi->vi_rxq.doorbell);
	mmiowb();
}


static int falcon_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
				 ef_request_id dma_id)
{
	ef_iovec iov = { base, len };
	int rc = falcon_ef_vi_transmitv_init(vi, &iov, 1, dma_id);
	if( rc == 0 )  falcon_ef_vi_transmit_push(vi);
	return rc;
}


static int falcon_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
				  ef_request_id dma_id)
{
	int rc = falcon_ef_vi_transmitv_init(vi, iov, iov_len, dma_id);
	if( rc == 0 )  falcon_ef_vi_transmit_push(vi);
	return rc;
}


static void falcon_vi_initialise_ops(ef_vi* vi)
{
	vi->ops.transmit               = falcon_ef_vi_transmit;
	vi->ops.transmitv              = falcon_ef_vi_transmitv;
	vi->ops.transmitv_init         = falcon_ef_vi_transmitv_init;
	vi->ops.transmit_push          = falcon_ef_vi_transmit_push;
        vi->ops.transmit_pio           = falcon_ef_vi_transmit_pio;
	vi->ops.receive_init           = falcon_ef_vi_receive_init;
	vi->ops.receive_push           = falcon_ef_vi_receive_push;
	vi->ops.eventq_poll            = falcon_ef_eventq_poll;
	vi->ops.eventq_prime           = falcon_ef_eventq_prime;
	vi->ops.eventq_timer_prime     = falcon_ef_eventq_timer_prime;
	vi->ops.eventq_timer_run       = falcon_ef_eventq_timer_run;
	vi->ops.eventq_timer_clear     = falcon_ef_eventq_timer_clear;
	vi->ops.eventq_timer_zero      = falcon_ef_eventq_timer_zero;
}


/*! \cidoxg_end */
