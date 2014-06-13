/*
** Copyright 2005-2012  Solarflare Communications Inc.
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


/* TX descriptor for both physical and virtual packet transfers */
typedef union {
	uint32_t	dword[2];
} ef_vi_falcon_dma_tx_buf_desc;
typedef ef_vi_falcon_dma_tx_buf_desc ef_vi_falcon_dma_tx_phys_desc;


/* RX descriptor for physical addressed transfers */
typedef union {
	uint32_t	dword[2];
} ef_vi_falcon_dma_rx_phys_desc;


/* RX descriptor for virtual packet transfers */
typedef struct {
	uint32_t	dword[1];
} ef_vi_falcon_dma_rx_buf_desc;

/* Buffer table index */
typedef uint32_t		ef_vi_buffer_addr_t;

ef_vi_inline int64_t dma_addr_to_u46(int64_t src_dma_addr)
{
	return (src_dma_addr & __FALCON_MASK(46, int64_t));
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

	desc->dword[1] = ((bytes << __DW2(RX_KER_BUF_SIZE_LBN)) |
			  (region << __DW2(RX_KER_BUF_REGION_LBN)) |
			  (HIGH(dest,
				RX_KER_BUF_ADR_LBN, 
				RX_KER_BUF_ADR_WIDTH)));

	desc->dword[0] = LOW(dest, 
			     RX_KER_BUF_ADR_LBN, 
			     RX_KER_BUF_ADR_WIDTH);
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

	desc->dword[1] = ((port   <<  __DW2(TX_USR_PORT_LBN))      | 
			  (frag   <<  __DW2(TX_USR_CONT_LBN))      | 
			  (bytes  <<  __DW2(TX_USR_BYTE_CNT_LBN))  |
			  (HIGH(buf_id, 
				TX_USR_BUF_ID_LBN,
				TX_USR_BUF_ID_WIDTH)));

	desc->dword[0] =  ((LOW(buf_id,
				TX_USR_BUF_ID_LBN,
				(TX_USR_BUF_ID_WIDTH))) |
			   (buf_ofs << TX_USR_BYTE_OFS_LBN));
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
	BUG_ON((buf_ofs & 0x1) != 0);

	buf_ofs >>= 1;

	DWCHCK(RX_USR_2BYTE_OFS_LBN, RX_USR_2BYTE_OFS_WIDTH);
	DWCHCK(RX_USR_BUF_ID_LBN, RX_USR_BUF_ID_WIDTH);

	RANGECHCK(buf_ofs, RX_USR_2BYTE_OFS_WIDTH);
	RANGECHCK(buf_id,  RX_USR_BUF_ID_WIDTH);

	desc->dword[0] = ((buf_ofs << RX_USR_2BYTE_OFS_LBN) | 
			  (buf_id  << RX_USR_BUF_ID_LBN));
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
	BUG_ON(efaddr >= ((uint64_t)1 << 32));

	return (ef_vi_buffer_addr_t) efaddr;
}


/*! Setup an physical address based descriptor for an IPMODE transfer */
ef_vi_inline void
falcon_dma_tx_calc_ip_phys(ef_vi_dma_addr_t src_dma_addr, unsigned bytes, 
			   int port, int frag,
			   ef_vi_falcon_dma_tx_phys_desc *desc)
{

	int region = 0; /* FIXME */
	int64_t src    = dma_addr_to_u46(src_dma_addr); /* lower 46 bits */

	DWCHCK(__DW2(TX_KER_PORT_LBN),      TX_KER_PORT_WIDTH);
	DWCHCK(__DW2(TX_KER_CONT_LBN),      TX_KER_CONT_WIDTH);
	DWCHCK(__DW2(TX_KER_BYTE_CNT_LBN),  TX_KER_BYTE_CNT_WIDTH);
	DWCHCK(__DW2(TX_KER_BUF_REGION_LBN),TX_KER_BUF_REGION_WIDTH);

	LWCHK(TX_KER_BUF_ADR_LBN, TX_KER_BUF_ADR_WIDTH);

	RANGECHCK(port,   TX_KER_PORT_WIDTH);
	RANGECHCK(frag,   TX_KER_CONT_WIDTH);
	RANGECHCK(bytes,  TX_KER_BYTE_CNT_WIDTH);
	RANGECHCK(region, TX_KER_BUF_REGION_WIDTH);

	desc->dword[1] = ((port   <<  __DW2(TX_KER_PORT_LBN))      | 
			  (frag   <<  __DW2(TX_KER_CONT_LBN))      | 
			  (bytes  <<  __DW2(TX_KER_BYTE_CNT_LBN))  | 
			  (region << __DW2(TX_KER_BUF_REGION_LBN)) |
			  (HIGH(src,
				TX_KER_BUF_ADR_LBN, 
				TX_KER_BUF_ADR_WIDTH)));

	EF_VI_BUILD_ASSERT(TX_KER_BUF_ADR_LBN == 0);
	desc->dword[0] = (uint32_t) src_dma_addr;
}


void falcon_vi_init(ef_vi* vi, void* vvis)
{
	struct vi_mappings *vm = (struct vi_mappings*)vvis;
	uint16_t* ids;

	BUG_ON(vm->signature != VI_MAPPING_SIGNATURE);
	BUG_ON(vm->nic_type.arch != EF_VI_ARCH_FALCON);

	/* Initialise masks to zero, so that ef_vi_state_init() will
	** not do any harm when we don't have DMA queues. */
	vi->vi_rxq.mask = vi->vi_txq.mask = 0;

	/* Initialise doorbell addresses to a distinctive small value
	** which will cause a segfault, to trap doorbell pushes to VIs
	** without DMA queues. */
	vi->vi_rxq.doorbell = vi->vi_txq.doorbell = (ef_vi_ioaddr_t)0xdb;

	ids = (uint16_t*) (vi->ep_state + 1);

	if( vm->tx_queue_capacity ) {
		vi->vi_txq.mask = vm->tx_queue_capacity - 1;
		vi->vi_txq.doorbell = vm->tx_bell + 12;
		vi->vi_txq.descriptors = vm->tx_dma_falcon;
		vi->vi_txq.ids = ids;
		ids += vi->vi_txq.mask + 1;
		/* Check that the id fifo fits in the space allocated. */
		BUG_ON((char*) (vi->vi_txq.ids + vm->tx_queue_capacity) >
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
		BUG_ON((char*) (vi->vi_rxq.ids + vm->rx_queue_capacity) >
                       (char*) vi->ep_state
                       + ef_vi_calc_state_bytes(vm->rx_queue_capacity,
                                                vm->tx_queue_capacity));
	}
}


int ef_vi_transmitv_init(ef_vi* vi, const ef_iovec* iov, int iov_len,
			 ef_request_id dma_id)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	ef_vi_falcon_dma_tx_buf_desc* dp;
	unsigned len, dma_len, di;
	unsigned added_save = qs->added;
	ef_addr dma_addr;
	unsigned last_len = 0;

	BUG_ON(iov_len <= 0);
	BUG_ON((dma_id & EF_REQUEST_ID_MASK) != dma_id);
	BUG_ON(dma_id == 0xffff);

	dma_addr = iov->iov_base;
	len = iov->iov_len;

	if( vi->vi_flags & EF_VI_ISCSI_TX_DDIG ) {
		/* Last 4 bytes of placeholder for digest must be
		 * removed for h/w */
		BUG_ON(len <= 4);
		last_len = iov[iov_len - 1].iov_len;
		if( last_len <= 4 ) {
			BUG_ON(iov_len <= 1);
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

	q->ids[di] = (uint16_t) dma_id;
	return 0;
}


union u128 {
	uint64_t u64[2];
	uint32_t u32[4];
};


static void ef_vi_transmit_push_desc(ef_vi* vi)
{
	ef_vi_txq* q = &vi->vi_txq;
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	unsigned di = qs->previous & q->mask;
	ef_vi_falcon_dma_tx_buf_desc* dp = 
		(ef_vi_falcon_dma_tx_buf_desc*) q->descriptors + di;
	union u128 d;

	d.u32[0] = dp->dword[0];
	d.u32[1] = dp->dword[1];
	d.u32[2] = (1) << __DW3(FRF_AZ_TX_DESC_PUSH_CMD_LBN);
	d.u32[3] = (qs->added & q->mask) << __DW4(FRF_AZ_TX_DESC_WPTR_LBN);

#if !defined(__KERNEL__) && (defined(__x86_64__) || defined(__i386__))
	/* This beats the individual writes (below) because the whole thing
	 * gets emitted as a single TLP.
	 */
	asm("movups %1, %%xmm0\n\t"
	    "movaps %%xmm0, %0"
	    : "=m" (*(volatile uint64_t*)((char*)vi->vi_txq.doorbell - 12))
	    : "m" (d)
	    : "xmm0");
#else
	writel(d.u32[0], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 12);
	writel(d.u32[1], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 8);
	writel(d.u32[2], ((ef_vi_ioaddr_t)vi->vi_txq.doorbell) - 4);
	wmb();
	writel(d.u32[3], vi->vi_txq.doorbell);
#endif
}


static void ef_vi_transmit_push_doorbell(ef_vi* vi)
{
	wmb();
	writel((vi->ep_state->txq.added & vi->vi_txq.mask) <<
	       __DW4(FRF_AZ_TX_DESC_WPTR_LBN),
	       vi->vi_txq.doorbell);
}


void ef_vi_transmit_push(ef_vi* vi)
{
	ef_vi_txq_state* qs = &vi->ep_state->txq;
	if( qs->removed == qs->previous &&
	    ! (vi->vi_flags & EF_VI_TX_PUSH_DISABLE) )
		ef_vi_transmit_push_desc(vi);
	else
		ef_vi_transmit_push_doorbell(vi);
	qs->previous = qs->added;
}

int ef_vi_receive_init(ef_vi* vi, ef_addr addr, ef_request_id dma_id)
{
	ef_vi_rxq* q = &vi->vi_rxq;
	ef_vi_rxq_state* qs = &vi->ep_state->rxq;
	unsigned di;

	if( ef_vi_receive_space(vi) ) {
		di = qs->added++ & q->mask;
		BUG_ON(q->ids[di] != 0xffff);
		q->ids[di] = (uint16_t) dma_id;

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


int ef_vi_receive_post(ef_vi* vi, ef_addr addr, ef_request_id dma_id)
{
  int rc = ef_vi_receive_init(vi, addr, dma_id);
  if( rc == 0 )  ef_vi_receive_push(vi);
  return rc;
}


void ef_vi_receive_push(ef_vi* vi)
{
	wmb();
	writel ((vi->ep_state->rxq.added & vi->vi_rxq.mask) <<
		__DW4(FRF_AZ_RX_DESC_WPTR_LBN),
		vi->vi_rxq.doorbell);
}


int ef_vi_receive_prefix_len(ef_vi* vi)
{
	/* The sfc net driver is currently configured to deliver a prefix
	 * that includes the RSS hash.
	 *
	 * TODO: Get this prefix length from the driver.
	 */
	return 16;
}

/*! \cidoxg_end */
