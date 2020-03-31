/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
  /**************************************************************************\
*//*! \file
   ** <L5_PRIVATE L5_HEADER >
   ** \author  slp
   **  \brief  EtherFabric NIC - EFXXXX (aka Falcon) specific definitions
   **     $Id$
   **   \date  2004/08
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_driver_efab_hardware  */

#ifndef __CI_DRIVER_EFAB_HARDWARE_FALCON_UL_H__
#define __CI_DRIVER_EFAB_HARDWARE_FALCON_UL_H__

#ifdef __KERNEL__
#error "This file is UL-only!"
#endif

#include <ci/efhw/checks.h>

/* fixme kostik: proper place should be selected */
#include "bitfield.h"

/*----------------------------------------------------------------------------
 * Falcon bug workarounds
 *---------------------------------------------------------------------------*/
#define TX_CFG2_REG		0xa80
#define TX_CSR_ONE_TAG_ONLY	21	/* disable multiple outstanding PCI
					   transactions */
#define TX_UIPD_SFT_EVT_LBN	48	/* bit in TX desc to generate SW ev */
#define TX_UIPD_SFT_EVT_WIDTH	1
#define HW_INIT_REG		0xC0	/* see bug 3544 */
#define FALCON_RX_DMA_HOLD_LBN	36	/* See tests/nic/falcon and bug 5286 */
#define FALCON_RX_DMA_HOLD_WIDTH 1


/* Based address of user VI pages 1024 - 4095 */
#define VI_PAGE123K_OFST (FR_AB_TIMER_COMMAND_REGP123_OFST - FR_AA_TIMER_COMMAND_REG_KER_OFST)

/*! Returns offset of I/O page for given VI instance. */
static inline unsigned falcon_vi_page_offset(unsigned instance)
{
        EFHW_ASSERT(instance < FALCON_DMAQ_NUM_SANITY
                    || instance < FALCON_EVQ_TBL_NUM_SANITY);

	if (instance < 1024)
		return instance * EFHW_8K;
	else
		return (VI_PAGE123K_OFST - 1024 * EFHW_8K) + instance * EFHW_8K;
}

static inline uint64_t ci_dma_addr_to_u46(uint64_t src_dma_addr)
{
	return (src_dma_addr & __FALCON_MASK(46, uint64_t));
}


/*----------------------------------------------------------------------------
 *
 * Events 
 *
 *---------------------------------------------------------------------------*/

/*---- Receive IP user events ----*/
#define __1__				((uint64_t)1)
#define FALCON_GLB_EV_G_PHY0		(__1__ << G_PHY0_INTR_LBN)
#define FALCON_GLB_EV_G_PHY1		(__1__ << G_PHY1_INTR_LBN)
#define FALCON_GLB_EV_XG_PHY		(__1__ << XG_PHY_INTR_LBN)
#define FALCON_GLB_EV_XFP_PHY		(__1__ << XFP_PHY_INTR_LBN)
#define FALCON_GLB_EV_RX_LOCKUP		(__1__ << 11)	/* TODO: replace
							   with define */

/* Accessors for event fields */
#define FALCON_EVENT_GLB_G_PHY0(evp) ((evp)->u64 & FALCON_GLB_EV_G_PHY0)
#define FALCON_EVENT_GLB_G_PHY1(evp) ((evp)->u64 & FALCON_GLB_EV_G_PHY1)
#define FALCON_EVENT_GLB_XG_PHY(evp) ((evp)->u64 & FALCON_GLB_EV_XG_PHY)
#define FALCON_EVENT_GLB_XFP_PHY(evp) ((evp)->u64 & FALCON_GLB_EV_XFP_PHY)
#define FALCON_EVENT_GLB_RX_LOCKUP(evp) ((evp)->u64 & FALCON_GLB_EV_RX_LOCKUP)

#ifdef USE_OLD_HWDEFS
#define FALCON_EVENT_DMA_Q_ID_MASK \
           (__FALCON_OPEN_MASK(RX_EV_Q_LABEL_WIDTH) \
            << RX_EV_Q_LABEL_LBN)

#define FALCON_EVENT_DMA_BYTES_MASK \
           (__FALCON_OPEN_MASK(RX_EV_BYTE_CNT_WIDTH) \
            << RX_EV_BYTE_CNT_LBN)

#define FALCON_EVENT_TX_PTR_MASK \
           (__FALCON_OPEN_MASK(TX_EV_DESC_PTR_WIDTH) \
            << TX_EV_DESC_PTR_LBN)

#define FALCON_EVENT_RX_PTR_MASK \
           (__FALCON_OPEN_MASK(RX_EV_DESC_PTR_WIDTH) \
            << RX_EV_DESC_PTR_LBN)

#define FALCON_EVENT_TX_COMP_MASK \
           (__FALCON_OPEN_MASK(TX_EV_COMP_WIDTH) \
            << TX_EV_COMP_LBN)

#define FALCON_EVENT_TX_ERROR \
           (__FALCON_OPEN_MASK(TX_EV_PKT_ERR_WIDTH) \
            << TX_EV_PKT_ERR_LBN)
#else
#define FALCON_EVENT_DMA_Q_ID_MASK \
           (__FALCON_OPEN_MASK(FSF_AZ_RX_EV_Q_LABEL_WIDTH) \
            << FSF_AZ_RX_EV_Q_LABEL_LBN)

#define FALCON_EVENT_DMA_BYTES_MASK \
           (__FALCON_OPEN_MASK(FSF_AZ_RX_EV_BYTE_CNT_WIDTH) \
            << FSF_AZ_RX_EV_BYTE_CNT_LBN)

#define FALCON_EVENT_TX_PTR_MASK \
           (__FALCON_OPEN_MASK(FSF_AZ_TX_EV_DESC_PTR_WIDTH) \
            << FSF_AZ_TX_EV_DESC_PTR_LBN)

#define FALCON_EVENT_RX_PTR_MASK \
           (__FALCON_OPEN_MASK(FSF_AZ_RX_EV_DESC_PTR_WIDTH) \
            << FSF_AZ_RX_EV_DESC_PTR_LBN)

#define FALCON_EVENT_TX_COMP_MASK \
           (__FALCON_OPEN_MASK(FSF_AZ_TX_EV_COMP_WIDTH) \
            << FSF_AZ_TX_EV_COMP_LBN)

#define FALCON_EVENT_TX_ERROR \
           (__FALCON_OPEN_MASK(FSF_AZ_TX_EV_PKT_ERR_WIDTH) \
            << FSF_AZ_TX_EV_PKT_ERR_LBN)
#endif

#define FALCON_EVENT_CODE_RX_IP   ((uint64_t)RX_IP_EV_DECODE \
				                      << EV_CODE_LBN)
#define FALCON_EVENT_CODE_TX_IP   ((uint64_t)TX_IP_EV_DECODE \
                                                      << EV_CODE_LBN)
#define FALCON_EVENT_CODE_TIMER   ((uint64_t)TIMER_EV_DECODE \
                                                      << EV_CODE_LBN)
#define FALCON_EVENT_CODE_GLOBAL  ((uint64_t)GLOBAL_EV_DECODE \
                                                     << EV_CODE_LBN)

#define FALCON_EVENT_DMA_RX_OKAY_B  ((uint64_t)1 << RX_EV_PKT_OK_LBN)
#define FALCON_EVENT_DMA_RX_CONT_B  ((uint64_t)1 << RX_JUMBO_CONT_LBN)
#define FALCON_EVENT_DMA_RX_SOP_B  ((uint64_t)1  << RX_SOP_LBN)
#define FALCON_EVENT_DMA_TX_OKAY_B  ((uint64_t)1 << TX_EV_COMP_LBN)
#define FALCON_EVENT_DMA_TX_RIGHTS ((uint64_t)1 << TX_EV_BUF_OWNER_ID_ERR_LBN)


#define FALCON_EVENT_RX_PKT_TYPE(evp) \
  (((evp)->u64 >> RX_EV_PKT_TYPE_LBN) & __FALCON_OPEN_MASK(RX_EV_PKT_TYPE_WIDTH))
#define FALCON_EVENT_RX_SNAP(evp) \
  ((FALCON_EVENT_RX_PKT_TYPE(evp) == RX_EV_PKT_TYPE_LLC_DECODE) | \
   (FALCON_EVENT_RX_PKT_TYPE(evp) == RX_EV_PKT_TYPE_VLAN_LLC_DECODE))

#define FALCON_EVENT_DMA_RX_PTR(evp) \
       (((evp)->u64 & FALCON_EVENT_RX_PTR_MASK) >> RX_EV_DESC_PTR_LBN)
#define FALCON_EVENT_DMA_TX_OKAY(evp) \
       (((evp)->u64 & FALCON_EVENT_DMA_TX_OKAY_B) != 0)
#define FALCON_EVENT_DMA_TX_RIGHTS_FAIL(evp)                            \
        ((FALCON_EVENT_CODE((evp)) == FALCON_EVENT_CODE_TX_IP) &&       \
        (((evp)->u64 & FALCON_EVENT_DMA_TX_RIGHTS)))


/*----------------------------------------------------------------------------
 *
 * Buffers and the buffer table -- this section is depreciated 
 *
 *---------------------------------------------------------------------------*/

#define FALCON_BUFFER_TBL_RESERVED	   (128)


/* TX descriptor for both physical and virtual packet transfers */
typedef ci_qword_t falcon_dma_tx_buf_desc;

/* RX descriptor for virtual packet transfers */
typedef ci_dword_t falcon_dma_rx_buf_desc;

/*----------------------------------------------------------------------------
 *
 * TX DMA Descriptor operations for the Queue Engine
 *
 *---------------------------------------------------------------------------*/

#ifndef CI_DMA_TX_DEBUG_REG_ACCESS
#define CI_DMA_TX_DEBUG_REG_ACCESS(x) x
#endif


/*! Setup a virtual buffer descriptor for an IPMODE transfer */
static inline void
__falcon_dma_tx_calc_ip_buf(unsigned buf_id,
			    unsigned buf_ofs,
			    uint bytes,
			    int port, int frag, falcon_dma_tx_buf_desc * desc)
{

	CI_DMA_TX_DEBUG_REG_ACCESS(ci_log("ul: dma_tx_calc_ip_buf: %x:%x %d:%d:%d",
                                    buf_id, buf_ofs, bytes, port, frag));

	__DW2CHCK(TX_USR_PORT);
	__DW2CHCK(TX_USR_CONT);
	__DW2CHCK(TX_USR_BYTE_CNT);
	__LWCHK(RX_KER_BUF_ADR);
	__DWCHCK(TX_USR_BYTE_OFS);

	__RANGECHCK(bytes, TX_USR_BYTE_CNT_WIDTH);
	__RANGECHCK(port, TX_USR_PORT_WIDTH);
	__RANGECHCK(frag, TX_USR_CONT_WIDTH);
	__RANGECHCK(buf_id, TX_USR_BUF_ID_WIDTH);
	__RANGECHCK(buf_ofs, TX_USR_BYTE_OFS_WIDTH);

	ci_assert(desc);

	CI_POPULATE_QWORD_5(*desc,
			    TX_USR_PORT, port,
			    TX_USR_CONT, frag,
			    TX_USR_BYTE_CNT, bytes,
			    TX_USR_BUF_ID, buf_id,
			    TX_USR_BYTE_OFS, buf_ofs);

	CI_DMA_TX_DEBUG_REG_ACCESS(ci_log("ul dma_tx_calc_ip_buf: "CI_QWORD_FMT,
                                    CI_QWORD_VAL(*desc)));
}

static inline void
falcon_dma_tx_calc_ip_buf_4k(unsigned buf_vaddr,
			     uint bytes,
			     int port, int frag, falcon_dma_tx_buf_desc * desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the high
	 ** bits, and an offset in the low bits. Assumptions permate the code
	 ** that these can be rolled into one 32bit value, so this is
	 ** currently preserved for Falcon. But we should change to support 8K pages
	 */
	unsigned buf_id = FALCON_BUFFER_4K_PAGE(buf_vaddr);
	unsigned buf_ofs = FALCON_BUFFER_4K_OFF(buf_vaddr);

	__falcon_dma_tx_calc_ip_buf(buf_id, buf_ofs, bytes, port, frag, desc);
}

static inline void
falcon_dma_tx_calc_ip_buf_8k(unsigned buf_vaddr,
			     uint bytes,
			     int port, int frag, falcon_dma_tx_buf_desc * desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the high
	 * bits, and an offset in the low bits. Assumptions permate the code
	 * that these can be rolled into one 32bit value, so this is
	 * currently preserved for Falcon. But we should change to support
	 * 8K pages
	 */
	unsigned buf_id = FALCON_BUFFER_8K_PAGE(buf_vaddr);
	unsigned buf_ofs = FALCON_BUFFER_8K_OFF(buf_vaddr);

	__falcon_dma_tx_calc_ip_buf(buf_id, buf_ofs, bytes, port, frag, desc);
}

static inline void
falcon_dma_tx_calc_ip_buf(unsigned buf_vaddr,
			  uint bytes,
			  int port, int frag, falcon_dma_tx_buf_desc * desc)
{
	falcon_dma_tx_calc_ip_buf_4k(buf_vaddr, bytes, port, frag, desc);
}

/*! Setup an physical address based descriptor for an IPMODE transfer */
static inline void
falcon_dma_tx_calc_ip_phys(dma_addr_t src_dma_addr,
			   uint bytes,
			   int port, int frag, falcon_dma_tx_buf_desc * desc)
{

	int region = 0;		/* Only support region 0 */
	ci_uint64 src = ci_dma_addr_to_u46(src_dma_addr);	/* lower 46 bits */

	__DW2CHCK(TX_KER_PORT);
	__DW2CHCK(TX_KER_CONT);
	__DW2CHCK(TX_KER_BYTE_CNT);
	__DW2CHCK(TX_KER_BUF_REGION);

	__LWCHK(TX_KER_BUF_ADR);

	__RANGECHCK(port, TX_KER_PORT_WIDTH);
	__RANGECHCK(frag, TX_KER_CONT_WIDTH);
	__RANGECHCK(bytes, TX_KER_BYTE_CNT_WIDTH);
	__RANGECHCK(region, TX_KER_BUF_REGION_WIDTH);

	ci_assert(desc);

	CI_POPULATE_QWORD_5(*desc,
			    TX_KER_PORT, port,
			    TX_KER_CONT, frag,
			    TX_KER_BYTE_CNT, bytes,
			    TX_KER_BUF_REGION, region,
			    TX_KER_BUF_ADR, src);

	CI_DMA_TX_DEBUG_REG_ACCESS(ci_log("ul: dma_tx_calc_ip_phys: "CI_QWORD_FMT,
                                    CI_QWORD_VAL(*desc)));

}


/*----------------------------------------------------------------------------
 *
 * RX DMA Descriptor operations for the Queue Engine
 *
 *---------------------------------------------------------------------------*/

#ifndef CI_DMA_RX_DEBUG_REG_ACCESS
#define CI_DMA_RX_DEBUG_REG_ACCESS(x) x
#endif


/*! Setup a virtual buffer based descriptor */
static inline void
__falcon_dma_rx_calc_ip_buf(unsigned buf_id, unsigned buf_ofs,
			    falcon_dma_rx_buf_desc * desc)
{
	CI_DMA_RX_DEBUG_REG_ACCESS(ci_log("ul: dma_rx_calc_ip_buf: %x:%x",
                                    buf_id, buf_ofs));

	/* check alignment of buffer offset and pack */
	ci_assert((buf_ofs & 0x1) == 0);
	buf_ofs >>= 1;

	__DWCHCK(RX_USR_2BYTE_OFS);
	__DWCHCK(RX_USR_BUF_ID);

	__RANGECHCK(buf_ofs, RX_USR_2BYTE_OFS_WIDTH);
	__RANGECHCK(buf_id, RX_USR_BUF_ID_WIDTH);

	ci_assert(desc);

	CI_POPULATE_DWORD_2(*desc,
			   RX_USR_2BYTE_OFS, buf_ofs,
			   RX_USR_BUF_ID, buf_id);

	CI_DMA_RX_DEBUG_REG_ACCESS(ci_log("ul: dma_rx_calc_ip_buf: "CI_DWORD_FMT,
                                    CI_DWORD_VAL(*desc)));
}

static inline void
falcon_dma_rx_calc_ip_buf_4k(unsigned buf_vaddr, falcon_dma_rx_buf_desc * desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the high
	 * bits, and an offset in the low bits. Assumptions permate the code
	 * that these can be rolled into one 32bit value, so this is
	 * currently preserved for Falcon. But we should change to support
	 * 8K pages
	 */
	unsigned buf_id = FALCON_BUFFER_4K_PAGE(buf_vaddr);
	unsigned buf_ofs = FALCON_BUFFER_4K_OFF(buf_vaddr);

	__falcon_dma_rx_calc_ip_buf(buf_id, buf_ofs, desc);
}

static inline void
falcon_dma_rx_calc_ip_buf_8k(unsigned buf_vaddr, falcon_dma_rx_buf_desc * desc)
{
	/* TODO FIXME [buf_vaddr] consists of the buffer index in the high
	 * bits, and an offset in the low bits. Assumptions permate the code
	 * that these can be rolled into one 32bit value, so this is
	 * currently preserved for Falcon. But we should change to support
	 * 8K pages
	 */
	unsigned buf_id = FALCON_BUFFER_8K_PAGE(buf_vaddr);
	unsigned buf_ofs = FALCON_BUFFER_8K_OFF(buf_vaddr);

	__falcon_dma_rx_calc_ip_buf(buf_id, buf_ofs, desc);
}

static inline void
falcon_dma_rx_calc_ip_buf(unsigned buf_vaddr, falcon_dma_rx_buf_desc * desc)
{
	falcon_dma_rx_calc_ip_buf_4k(buf_vaddr, desc);
}


#endif /* __CI_DRIVER_EFAB_HARDWARE_FALCON_UL_H__ */
