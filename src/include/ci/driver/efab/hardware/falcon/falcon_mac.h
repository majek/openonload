/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC - EFXXXX (aka Falcon) MAC register
 * definitions.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
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
#ifdef USE_OLD_HWDEFS

/*********---- 1G/10G Ethernet MAC Wrapper Registers C Header ----*********/
#define MD_TXD_REG_KER_OFST 0xC00 /* PHY management transmit data register */
#define MD_TXD_REG_OFST 0xC00 /* PHY management transmit data register */
  #define MD_TXD_LBN 0
  #define MD_TXD_WIDTH 16
#define MD_RXD_REG_KER_OFST 0xC10 /* PHY management receive data register */
#define MD_RXD_REG_OFST 0xC10 /* PHY management receive data register */
  #define MD_RXD_LBN 0
  #define MD_RXD_WIDTH 16
#define MD_CS_REG_KER_OFST 0xC20 /* PHY management configuration &
				    status register */
#define MD_CS_REG_OFST 0xC20 /* PHY management configuration &
				status register */
  #define MD_PT_LBN 7
  #define MD_PT_WIDTH 3
  #define MD_PL_LBN 6
  #define MD_PL_WIDTH 1
  #define MD_INT_CLR_LBN 5
  #define MD_INT_CLR_WIDTH 1
  #define MD_GC_LBN 4
  #define MD_GC_WIDTH 1
  #define MD_PRSP_LBN 3
  #define MD_PRSP_WIDTH 1
  #define MD_RIC_LBN 2
  #define MD_RIC_WIDTH 1
  #define MD_RDC_LBN 1
  #define MD_RDC_WIDTH 1
  #define MD_WRC_LBN 0
  #define MD_WRC_WIDTH 1
#define MD_PHY_ADR_REG_KER_OFST 0xC30 /* PHY management PHY address register */
#define MD_PHY_ADR_REG_OFST 0xC30 /* PHY management PHY address register */
  #define MD_PHY_ADR_LBN 0
  #define MD_PHY_ADR_WIDTH 16
#define MD_ID_REG_KER_OFST 0xC40 /* PHY management ID register */
#define MD_ID_REG_OFST 0xC40 /* PHY management ID register */
  #define MD_PRT_ADR_LBN 11
  #define MD_PRT_ADR_WIDTH 5
  #define MD_DEV_ADR_LBN 6
  #define MD_DEV_ADR_WIDTH 5
#define MD_STAT_REG_KER_OFST 0xC50 /* PHY management status & mask register */
#define MD_STAT_REG_OFST 0xC50 /* PHY management status & mask register */
  #define MD_PINT_LBN 4
  #define MD_PINT_WIDTH 1
  #define MD_DONE_LBN 3
  #define MD_DONE_WIDTH 1
  #define MD_BSERR_LBN 2
  #define MD_BSERR_WIDTH 1
  #define MD_LNFL_LBN 1
  #define MD_LNFL_WIDTH 1
  #define MD_BSY_LBN 0
  #define MD_BSY_WIDTH 1
#define MAC0_STAT_DMA_REG_KER_OFST 0xC60 /* Port 0 MAC statistical counter
					    DMA register */
#define MAC0_STAT_DMA_REG_OFST 0xC60 /* Port 0 MAC statistical counter
					DMA register */
  #define MAC0_STAT_DMA_CMD_LBN 48
  #define MAC0_STAT_DMA_CMD_WIDTH 1
  #define MAC0_STAT_DMA_ADR_LBN 0
  #define MAC0_STAT_DMA_ADR_WIDTH 48
#define MAC1_STAT_DMA_REG_KER_OFST 0xC70 /* Port 1 MAC statistical counter
					    DMA register */
#define MAC1_STAT_DMA_REG_OFST 0xC70 /* Port 1 MAC statistical counter
					DMA register */
  #define MAC1_STAT_DMA_CMD_LBN 48
  #define MAC1_STAT_DMA_CMD_WIDTH 1
  #define MAC1_STAT_DMA_ADR_LBN 0
  #define MAC1_STAT_DMA_ADR_WIDTH 48
#define MAC0_CTRL_REG_KER_OFST 0xC80 /* Port 0 MAC control register */
#define MAC0_CTRL_REG_OFST 0xC80 /* Port 0 MAC control register */
  #define MAC0_XOFF_VAL_LBN 16
  #define MAC0_XOFF_VAL_WIDTH 16
  #define MAC0_BCAD_ACPT_LBN 4
  #define MAC0_BCAD_ACPT_WIDTH 1
  #define MAC0_UC_PROM_LBN 3
  #define MAC0_UC_PROM_WIDTH 1
  #define MAC0_LINK_STATUS_LBN 2
  #define MAC0_LINK_STATUS_WIDTH 1
  #define MAC0_SPEED_LBN 0
  #define MAC0_SPEED_WIDTH 2
#define MAC1_CTRL_REG_KER_OFST 0xC90 /* Port 1 MAC control register */
#define MAC1_CTRL_REG_OFST 0xC90 /* Port 1 MAC control register */
  #define MAC1_XOFF_VAL_LBN 16
  #define MAC1_XOFF_VAL_WIDTH 16
  #define MAC1_BCAD_ACPT_LBN 4
  #define MAC1_BCAD_ACPT_WIDTH 1
  #define MAC1_UC_PROM_LBN 3
  #define MAC1_UC_PROM_WIDTH 1
  #define MAC1_LINK_STATUS_LBN 2
  #define MAC1_LINK_STATUS_WIDTH 1
  #define MAC1_SPEED_LBN 0
  #define MAC1_SPEED_WIDTH 2
#define MAC_MC_HASH_REG0_KER_OFST 0xCA0 /* Multicast address hash table */
#define MAC_MC_HASH_REG0_OFST 0xCA0 /* Multicast address hash table */
  #define MAC_MCAST_HASH0_LBN 0
  #define MAC_MCAST_HASH0_WIDTH 128
#define MAC_MC_HASH_REG1_KER_OFST 0xCB0 /* Multicast address hash table */
#define MAC_MC_HASH_REG1_OFST 0xCB0 /* Multicast address hash table */
  #define MAC_MCAST_HASH1_LBN 0
  #define MAC_MCAST_HASH1_WIDTH 128
/*************---- 1G MAC Port 0 Registers C Header ----*************/
#define GM_P0_BASE 0xE00
#define GM_P1_BASE 0x1000
#define GM_CFG1_REG_KER_OFST 0x00 /* GMAC configuration register 1 */
#define GM_CFG1_REG_OFST 0x00 /* GMAC configuration register 1 */
  #define GM_SW_RST_LBN 31
  #define GM_SW_RST_WIDTH 1
  #define GM_SIM_RST_LBN 30
  #define GM_SIM_RST_WIDTH 1
  #define GM_RST_RX_MAC_CTL_LBN 19
  #define GM_RST_RX_MAC_CTL_WIDTH 1
  #define GM_RST_TX_MAC_CTL_LBN 18
  #define GM_RST_TX_MAC_CTL_WIDTH 1
  #define GM_RST_RX_FUNC_LBN 17
  #define GM_RST_RX_FUNC_WIDTH 1
  #define GM_RST_TX_FUNC_LBN 16
  #define GM_RST_TX_FUNC_WIDTH 1
  #define GM_LOOP_LBN 8
  #define GM_LOOP_WIDTH 1
  #define GM_RX_FC_EN_LBN 5
  #define GM_RX_FC_EN_WIDTH 1
  #define GM_TX_FC_EN_LBN 4
  #define GM_TX_FC_EN_WIDTH 1
  #define GM_SYNC_RXEN_LBN 3
  #define GM_SYNC_RXEN_WIDTH 1
  #define GM_RX_EN_LBN 2
  #define GM_RX_EN_WIDTH 1
  #define GM_SYNC_TXEN_LBN 1
  #define GM_SYNC_TXEN_WIDTH 1
  #define GM_TX_EN_LBN 0
  #define GM_TX_EN_WIDTH 1
#define GM_CFG2_REG_KER_OFST 0x10 /* GMAC configuration register 2 */
#define GM_CFG2_REG_OFST 0x10 /* GMAC configuration register 2 */
  #define GM_PAMBL_LEN_LBN 12
  #define GM_PAMBL_LEN_WIDTH 4
  #define GM_IF_MODE_LBN 8
  #define GM_IF_MODE_WIDTH 2
  #define GM_HUGE_FRM_EN_LBN 5
  #define GM_HUGE_FRM_EN_WIDTH 1
  #define GM_LEN_CHK_LBN 4
  #define GM_LEN_CHK_WIDTH 1
  #define GM_PAD_CRC_EN_LBN 2
  #define GM_PAD_CRC_EN_WIDTH 1
  #define GM_CRC_EN_LBN 1
  #define GM_CRC_EN_WIDTH 1
  #define GM_FD_LBN 0
  #define GM_FD_WIDTH 1
#define GM_IPG_REG_KER_OFST 0x20 /* GMAC IPG register */
#define GM_IPG_REG_OFST 0x20 /* GMAC IPG register */
  #define GM_NONB2B_IPG1_LBN 24
  #define GM_NONB2B_IPG1_WIDTH 7
  #define GM_NONB2B_IPG2_LBN 16
  #define GM_NONB2B_IPG2_WIDTH 7
  #define GM_MIN_IPG_ENF_LBN 8
  #define GM_MIN_IPG_ENF_WIDTH 8
  #define GM_B2B_IPG_LBN 0
  #define GM_B2B_IPG_WIDTH 7
#define GM_HD_REG_KER_OFST 0x30 /* GMAC half duplex register */
#define GM_HD_REG_OFST 0x30 /* GMAC half duplex register */
  #define GM_ALT_BOFF_VAL_LBN 20
  #define GM_ALT_BOFF_VAL_WIDTH 4
  #define GM_ALT_BOFF_EN_LBN 19
  #define GM_ALT_BOFF_EN_WIDTH 1
  #define GM_BP_NO_BOFF_LBN 18
  #define GM_BP_NO_BOFF_WIDTH 1
  #define GM_DIS_BOFF_LBN 17
  #define GM_DIS_BOFF_WIDTH 1
  #define GM_EXDEF_TX_EN_LBN 16
  #define GM_EXDEF_TX_EN_WIDTH 1
  #define GM_RTRY_LIMIT_LBN 12
  #define GM_RTRY_LIMIT_WIDTH 4
  #define GM_COL_WIN_LBN 0
  #define GM_COL_WIN_WIDTH 10
#define GM_MAX_FLEN_REG_KER_OFST 0x40 /* GMAC maximum frame length register */
#define GM_MAX_FLEN_REG_OFST 0x40 /* GMAC maximum frame length register */
  #define GM_MAX_FLEN_LBN 0
  #define GM_MAX_FLEN_WIDTH 16
#define GM_TEST_REG_KER_OFST 0x70 /* GMAC test register */
#define GM_TEST_REG_OFST 0x70 /* GMAC test register */
  #define GM_MAX_BOFF_LBN 3
  #define GM_MAX_BOFF_WIDTH 1
  #define GM_REG_TX_FLOW_EN_LBN 2
  #define GM_REG_TX_FLOW_EN_WIDTH 1
  #define GM_TEST_PAUSE_LBN 1
  #define GM_TEST_PAUSE_WIDTH 1
  #define GM_SHORT_SLOT_LBN 0
  #define GM_SHORT_SLOT_WIDTH 1
#define GM_ADR1_REG_KER_OFST 0x100 /* GMAC station address register 1 */
#define GM_ADR1_REG_OFST 0x100 /* GMAC station address register 1 */
  #define GM_ADR1_LBN 0
  #define GM_ADR1_WIDTH 32
#define GM_ADR2_REG_KER_OFST 0x110 /* GMAC station address register 2 */
#define GM_ADR2_REG_OFST 0x110 /* GMAC station address register 2 */
  #define GM_ADR2_LBN 16
  #define GM_ADR2_WIDTH 16
#define GMF_CFG0_REG_KER_OFST 0x120 /* GMAC FIFO configuration register 0 */
#define GMF_CFG0_REG_OFST 0x120 /* GMAC FIFO configuration register 0 */
  #define GMF_FTFENRPLY_LBN 20
  #define GMF_FTFENRPLY_WIDTH 1
  #define GMF_STFENRPLY_LBN 19
  #define GMF_STFENRPLY_WIDTH 1
  #define GMF_FRFENRPLY_LBN 18
  #define GMF_FRFENRPLY_WIDTH 1
  #define GMF_SRFENRPLY_LBN 17
  #define GMF_SRFENRPLY_WIDTH 1
  #define GMF_WTMENRPLY_LBN 16
  #define GMF_WTMENRPLY_WIDTH 1
  #define GMF_FTFENREQ_LBN 12
  #define GMF_FTFENREQ_WIDTH 1
  #define GMF_STFENREQ_LBN 11
  #define GMF_STFENREQ_WIDTH 1
  #define GMF_FRFENREQ_LBN 10
  #define GMF_FRFENREQ_WIDTH 1
  #define GMF_SRFENREQ_LBN 9
  #define GMF_SRFENREQ_WIDTH 1
  #define GMF_WTMENREQ_LBN 8
  #define GMF_WTMENREQ_WIDTH 1
  #define GMF_HSTRSTFT_LBN 4
  #define GMF_HSTRSTFT_WIDTH 1
  #define GMF_HSTRSTST_LBN 3
  #define GMF_HSTRSTST_WIDTH 1
  #define GMF_HSTRSTFR_LBN 2
  #define GMF_HSTRSTFR_WIDTH 1
  #define GMF_HSTRSTSR_LBN 1
  #define GMF_HSTRSTSR_WIDTH 1
  #define GMF_HSTRSTWT_LBN 0
  #define GMF_HSTRSTWT_WIDTH 1
#define GMF_CFG1_REG_KER_OFST 0x130 /* GMAC FIFO configuration register 1 */
#define GMF_CFG1_REG_OFST 0x130 /* GMAC FIFO configuration register 1 */
  #define GMF_CFGFRTH_LBN 16
  #define GMF_CFGFRTH_WIDTH 5
  #define GMF_CFGXOFFRTX_LBN 0
  #define GMF_CFGXOFFRTX_WIDTH 16
#define GMF_CFG2_REG_KER_OFST 0x140 /* GMAC FIFO configuration register 2 */
#define GMF_CFG2_REG_OFST 0x140 /* GMAC FIFO configuration register 2 */
  #define GMF_CFGHWM_LBN 16
  #define GMF_CFGHWM_WIDTH 6
  #define GMF_CFGLWM_LBN 0
  #define GMF_CFGLWM_WIDTH 6
#define GMF_CFG3_REG_KER_OFST 0x150 /* GMAC FIFO configuration register 3 */
#define GMF_CFG3_REG_OFST 0x150 /* GMAC FIFO configuration register 3 */
  #define GMF_CFGHWMFT_LBN 16
  #define GMF_CFGHWMFT_WIDTH 6
  #define GMF_CFGFTTH_LBN 0
  #define GMF_CFGFTTH_WIDTH 6
#define GMF_CFG4_REG_KER_OFST 0x160 /* GMAC FIFO configuration register 4 */
#define GMF_CFG4_REG_OFST 0x160 /* GMAC FIFO configuration register 4 */
  #define GMF_HSTFLTRFRM_LBN 0
  #define GMF_HSTFLTRFRM_WIDTH 18
#define GMF_CFG5_REG_KER_OFST 0x170 /* GMAC FIFO configuration register 5 */
#define GMF_CFG5_REG_OFST 0x170 /* GMAC FIFO configuration register 5 */
  #define GMF_CFGHDPLX_LBN 22
  #define GMF_CFGHDPLX_WIDTH 1
  #define GMF_SRFULL_LBN 21
  #define GMF_SRFULL_WIDTH 1
  #define GMF_HSTSRFULLCLR_LBN 20
  #define GMF_HSTSRFULLCLR_WIDTH 1
  #define GMF_CFGBYTMODE_LBN 19
  #define GMF_CFGBYTMODE_WIDTH 1
  #define GMF_HSTDRPLT64_LBN 18
  #define GMF_HSTDRPLT64_WIDTH 1
  #define GMF_HSTFLTRFRMDC_LBN 0
  #define GMF_HSTFLTRFRMDC_WIDTH 18
/*************---- 10G MAC Registers C Header ----*************/
#define XM_ADR_LO_REG_KER_P0_OFST 0x1200 /* XGMAC address register low -
					    port 0 */
#define XM_ADR_LO_REG_P0_OFST 0x1200 /* XGMAC address register low -
					port 0 */
  #define XM_ADR_LO_LBN 0
  #define XM_ADR_LO_WIDTH 32
#define XM_ADR_HI_REG_KER_P0_OFST 0x1210 /* XGMAC address register high -
					    port 0 */
#define XM_ADR_HI_REG_P0_OFST 0x1210 /* XGMAC address register high -
					port 0 */
  #define XM_ADR_HI_LBN 0
  #define XM_ADR_HI_WIDTH 16
#define XM_GLB_CFG_REG_KER_P0_OFST 0x1220 /* XGMAC global configuration -
					     port 0 */
#define XM_GLB_CFG_REG_P0_OFST 0x1220 /* XGMAC global configuration -
					 port 0 */
  #define XM_LINE_LB_DEEP_RSVD_LBN 28
  #define XM_LINE_LB_DEEP_RSVD_WIDTH 1
  #define XM_RMTFLT_GEN_LBN 17
  #define XM_RMTFLT_GEN_WIDTH 1
  #define XM_DEBUG_MODE_LBN 16
  #define XM_DEBUG_MODE_WIDTH 1
  #define XM_RX_STAT_EN_LBN 11
  #define XM_RX_STAT_EN_WIDTH 1
  #define XM_TX_STAT_EN_LBN 10
  #define XM_TX_STAT_EN_WIDTH 1
  #define XM_CUT_THRU_MODE_LBN 7
  #define XM_CUT_THRU_MODE_WIDTH 1
  #define XM_RX_JUMBO_MODE_LBN 6
  #define XM_RX_JUMBO_MODE_WIDTH 1
  #define XM_WAN_MODE_LBN 5
  #define XM_WAN_MODE_WIDTH 1
  #define XM_AUTOCLR_MODE_LBN 4
  #define XM_AUTOCLR_MODE_WIDTH 1
  #define XM_INTCLR_MODE_LBN 3
  #define XM_INTCLR_MODE_WIDTH 1
  #define XM_CORE_RST_LBN 0
  #define XM_CORE_RST_WIDTH 1
#define XM_TX_CFG_REG_KER_P0_OFST 0x1230 /* XGMAC transmit configuration -
					    port 0 */
#define XM_TX_CFG_REG_P0_OFST 0x1230 /* XGMAC transmit configuration -
					port 0 */
  #define XM_TX_PROG_LBN 24
  #define XM_TX_PROG_WIDTH 1
  #define XM_IPG_LBN 16
  #define XM_IPG_WIDTH 4
  #define XM_FCNTL_LBN 10
  #define XM_FCNTL_WIDTH 1
  #define XM_TXCRC_LBN 8
  #define XM_TXCRC_WIDTH 1
  #define XM_EDRC_LBN 6
  #define XM_EDRC_WIDTH 1
  #define XM_AUTO_PAD_LBN 5
  #define XM_AUTO_PAD_WIDTH 1
  #define XM_TX_PRMBL_LBN 2
  #define XM_TX_PRMBL_WIDTH 1
  #define XM_TXEN_LBN 1
  #define XM_TXEN_WIDTH 1
  #define XM_TX_RST_LBN 0
  #define XM_TX_RST_WIDTH 1
#define XM_RX_CFG_REG_KER_P0_OFST 0x1240 /* XGMAC receive configuration -
					    port 0 */
#define XM_RX_CFG_REG_P0_OFST 0x1240 /* XGMAC receive configuration -
					port 0 */
  #define XM_PASS_LENERR_LBN 26
  #define XM_PASS_LENERR_WIDTH 1
  #define XM_PASS_CRC_ERR_LBN 25
  #define XM_PASS_CRC_ERR_WIDTH 1
  #define XM_PASS_PRMBLE_ERR_LBN 24
  #define XM_PASS_PRMBLE_ERR_WIDTH 1
  #define XM_REJ_UCAST_LBN 18
  #define XM_REJ_UCAST_WIDTH 1
  #define XM_BSC_EN_LBN 17
  #define XM_BSC_EN_WIDTH 1
  #define XM_ACPT_ALL_MCAST_LBN 11
  #define XM_ACPT_ALL_MCAST_WIDTH 1
  #define XM_PASS_SAP_LBN 10
  #define XM_PASS_SAP_WIDTH 1
  #define XM_ACPT_ALL_UCAST_LBN 9
  #define XM_ACPT_ALL_UCAST_WIDTH 1
  #define XM_AUTO_DEPAD_LBN 8
  #define XM_AUTO_DEPAD_WIDTH 1
  #define XM_RXCRC_LBN 3
  #define XM_RXCRC_WIDTH 1
  #define XM_RX_PRMBL_LBN 2
  #define XM_RX_PRMBL_WIDTH 1
  #define XM_RXEN_LBN 1
  #define XM_RXEN_WIDTH 1
  #define XM_RX_RST_LBN 0
  #define XM_RX_RST_WIDTH 1
#define XM_FC_REG_KER_P0_OFST 0x1270 /* XGMAC flow control register -
					port 0 */
#define XM_FC_REG_P0_OFST 0x1270 /* XGMAC flow control register -
				    port 0 */
  #define XM_PAUSE_TIME_LBN 16
  #define XM_PAUSE_TIME_WIDTH 16
  #define XM_RX_MAC_STAT_LBN 11
  #define XM_RX_MAC_STAT_WIDTH 1
  #define XM_TX_MAC_STAT_LBN 10
  #define XM_TX_MAC_STAT_WIDTH 1
  #define XM_MCNTL_PASS_LBN 8
  #define XM_MCNTL_PASS_WIDTH 2
  #define XM_REJ_CNTL_UCAST_LBN 6
  #define XM_REJ_CNTL_UCAST_WIDTH 1
  #define XM_REJ_CNTL_MCAST_LBN 5
  #define XM_REJ_CNTL_MCAST_WIDTH 1
  #define XM_AUTO_XMIT_ZPAUSE_LBN 4
  #define XM_AUTO_XMIT_ZPAUSE_WIDTH 1
  #define XM_AUTO_XMIT_PAUSE_LBN 3
  #define XM_AUTO_XMIT_PAUSE_WIDTH 1
  #define XM_ZPAUSE_LBN 2
  #define XM_ZPAUSE_WIDTH 1
  #define XM_XMIT_PAUSE_LBN 1
  #define XM_XMIT_PAUSE_WIDTH 1
  #define XM_DIS_FCNTL_LBN 0
  #define XM_DIS_FCNTL_WIDTH 1
#define XM_PAUSE_TIME_REG_KER_P0_OFST 0x1290 /* XGMAC pause time register -
						port 0 */
#define XM_PAUSE_TIME_REG_P0_OFST 0x1290 /* XGMAC pause time register -
					    port 0 */
  #define XM_TX_PAUSE_CNT_LBN 16
  #define XM_TX_PAUSE_CNT_WIDTH 16
  #define XM_RX_PAUSE_CNT_LBN 0
  #define XM_RX_PAUSE_CNT_WIDTH 16
#define XM_TX_PARAM_REG_KER_P0_OFST 0x12D0 /* XGMAC transmit parameter
					      register - port 0 */
#define XM_TX_PARAM_REG_P0_OFST 0x12D0 /* XGMAC transmit parameter register -
					  port 0 */
  #define XM_TX_JUMBO_MODE_LBN 31
  #define XM_TX_JUMBO_MODE_WIDTH 1
  #define XM_MAX_TX_FRM_SIZE_LBN 16
  #define XM_MAX_TX_FRM_SIZE_WIDTH 14
  #define XM_PAD_CHAR_LBN 0
  #define XM_PAD_CHAR_WIDTH 8
#define XM_RX_PARAM_REG_KER_P0_OFST 0x12E0 /* XGMAC receive parameter
					      register - port 0 */
#define XM_RX_PARAM_REG_P0_OFST 0x12E0 /* XGMAC receive parameter register -
					  port 0 */
  #define XM_MAX_RX_FRM_SIZE_LBN 0
  #define XM_MAX_RX_FRM_SIZE_WIDTH 14
#define XX_PWR_RST_REG_KER_P0_OFST 0x1300 /* XGXS/XAUI powerdown/reset
					     register */
#define XX_PWR_RST_REG_P0_OFST 0x1300 /* XGXS/XAUI powerdown/reset register */
  #define XX_PWRDND_SIG_LBN 31
  #define XX_PWRDND_SIG_WIDTH 1
  #define XX_PWRDNC_SIG_LBN 30
  #define XX_PWRDNC_SIG_WIDTH 1
  #define XX_PWRDNB_SIG_LBN 29
  #define XX_PWRDNB_SIG_WIDTH 1
  #define XX_PWRDNA_SIG_LBN 28
  #define XX_PWRDNA_SIG_WIDTH 1
  #define XX_SIM_MODE_LBN 27
  #define XX_SIM_MODE_WIDTH 1
  #define XX_RSTPLLCD_SIG_LBN 25
  #define XX_RSTPLLCD_SIG_WIDTH 1
  #define XX_RSTPLLAB_SIG_LBN 24
  #define XX_RSTPLLAB_SIG_WIDTH 1
  #define XX_RESETD_SIG_LBN 23
  #define XX_RESETD_SIG_WIDTH 1
  #define XX_RESETC_SIG_LBN 22
  #define XX_RESETC_SIG_WIDTH 1
  #define XX_RESETB_SIG_LBN 21
  #define XX_RESETB_SIG_WIDTH 1
  #define XX_RESETA_SIG_LBN 20
  #define XX_RESETA_SIG_WIDTH 1
  #define XX_RSTXGXSTX_SIG_LBN 18
  #define XX_RSTXGXSTX_SIG_WIDTH 1
  #define XX_RSTXGXSRX_SIG_LBN 17
  #define XX_RSTXGXSRX_SIG_WIDTH 1
  #define XX_SD_RST_ACT_LBN 16
  #define XX_SD_RST_ACT_WIDTH 1
  #define XX_PWRDND_EN_LBN 15
  #define XX_PWRDND_EN_WIDTH 1
  #define XX_PWRDNC_EN_LBN 14
  #define XX_PWRDNC_EN_WIDTH 1
  #define XX_PWRDNB_EN_LBN 13
  #define XX_PWRDNB_EN_WIDTH 1
  #define XX_PWRDNA_EN_LBN 12
  #define XX_PWRDNA_EN_WIDTH 1
  #define XX_RSTPLLCD_EN_LBN 9
  #define XX_RSTPLLCD_EN_WIDTH 1
  #define XX_RSTPLLAB_EN_LBN 8
  #define XX_RSTPLLAB_EN_WIDTH 1
  #define XX_RESETD_EN_LBN 7
  #define XX_RESETD_EN_WIDTH 1
  #define XX_RESETC_EN_LBN 6
  #define XX_RESETC_EN_WIDTH 1
  #define XX_RESETB_EN_LBN 5
  #define XX_RESETB_EN_WIDTH 1
  #define XX_RESETA_EN_LBN 4
  #define XX_RESETA_EN_WIDTH 1
  #define XX_RSTXGXSTX_EN_LBN 2
  #define XX_RSTXGXSTX_EN_WIDTH 1
  #define XX_RSTXGXSRX_EN_LBN 1
  #define XX_RSTXGXSRX_EN_WIDTH 1
  #define XX_RST_XX_EN_LBN 0
  #define XX_RST_XX_EN_WIDTH 1
#define XX_SD_CTL_REG_KER_P0_OFST 0x1310 /* XGXS/XAUI powerdown/reset control
					    register */
#define XX_SD_CTL_REG_P0_OFST 0x1310 /* XGXS/XAUI powerdown/reset control
					register */
  #define XX_TERMADJ1_LBN 17
  #define XX_TERMADJ1_WIDTH 1
  #define XX_TERMADJ0_LBN 16
  #define XX_TERMADJ0_WIDTH 1
  #define XX_HIDRVD_LBN 15
  #define XX_HIDRVD_WIDTH 1
  #define XX_LODRVD_LBN 14
  #define XX_LODRVD_WIDTH 1
  #define XX_HIDRVC_LBN 13
  #define XX_HIDRVC_WIDTH 1
  #define XX_LODRVC_LBN 12
  #define XX_LODRVC_WIDTH 1
  #define XX_HIDRVB_LBN 11
  #define XX_HIDRVB_WIDTH 1
  #define XX_LODRVB_LBN 10
  #define XX_LODRVB_WIDTH 1
  #define XX_HIDRVA_LBN 9
  #define XX_HIDRVA_WIDTH 1
  #define XX_LODRVA_LBN 8
  #define XX_LODRVA_WIDTH 1
  #define XX_LPBKD_LBN 3
  #define XX_LPBKD_WIDTH 1
  #define XX_LPBKC_LBN 2
  #define XX_LPBKC_WIDTH 1
  #define XX_LPBKB_LBN 1
  #define XX_LPBKB_WIDTH 1
  #define XX_LPBKA_LBN 0
  #define XX_LPBKA_WIDTH 1
#define XX_TXDRV_CTL_REG_KER_P0_OFST 0x1320 /* XAUI SerDes transmit drive
					       control register */
#define XX_TXDRV_CTL_REG_P0_OFST 0x1320 /* XAUI SerDes transmit drive
					   control register */
  #define XX_DEQD_LBN 28
  #define XX_DEQD_WIDTH 4
  #define XX_DEQC_LBN 24
  #define XX_DEQC_WIDTH 4
  #define XX_DEQB_LBN 20
  #define XX_DEQB_WIDTH 4
  #define XX_DEQA_LBN 16
  #define XX_DEQA_WIDTH 4
  #define XX_DTXD_LBN 12
  #define XX_DTXD_WIDTH 4
  #define XX_DTXC_LBN 8
  #define XX_DTXC_WIDTH 4
  #define XX_DTXB_LBN 4
  #define XX_DTXB_WIDTH 4
  #define XX_DTXA_LBN 0
  #define XX_DTXA_WIDTH 4
#define XX_PRBS_CTL_REG_KER_P0_OFST 0x1330 /* XAUI PRBS control register */
#define XX_PRBS_CTL_REG_P0_OFST 0x1330 /* XAUI PRBS control register */
  #define XX_CH3_RX_PRBS_SEL_LBN 30
  #define XX_CH3_RX_PRBS_SEL_WIDTH 2
  #define XX_CH3_RX_PRBS_INV_LBN 29
  #define XX_CH3_RX_PRBS_INV_WIDTH 1
  #define XX_CH3_RX_PRBS_CHKEN_LBN 28
  #define XX_CH3_RX_PRBS_CHKEN_WIDTH 1
  #define XX_CH2_RX_PRBS_SEL_LBN 26
  #define XX_CH2_RX_PRBS_SEL_WIDTH 2
  #define XX_CH2_RX_PRBS_INV_LBN 25
  #define XX_CH2_RX_PRBS_INV_WIDTH 1
  #define XX_CH2_RX_PRBS_CHKEN_LBN 24
  #define XX_CH2_RX_PRBS_CHKEN_WIDTH 1
  #define XX_CH1_RX_PRBS_SEL_LBN 22
  #define XX_CH1_RX_PRBS_SEL_WIDTH 2
  #define XX_CH1_RX_PRBS_INV_LBN 21
  #define XX_CH1_RX_PRBS_INV_WIDTH 1
  #define XX_CH1_RX_PRBS_CHKEN_LBN 20
  #define XX_CH1_RX_PRBS_CHKEN_WIDTH 1
  #define XX_CH0_RX_PRBS_SEL_LBN 18
  #define XX_CH0_RX_PRBS_SEL_WIDTH 2
  #define XX_CH0_RX_PRBS_INV_LBN 17
  #define XX_CH0_RX_PRBS_INV_WIDTH 1
  #define XX_CH0_RX_PRBS_CHKEN_LBN 16
  #define XX_CH0_RX_PRBS_CHKEN_WIDTH 1
  #define XX_CH3_TX_PRBS_SEL_LBN 14
  #define XX_CH3_TX_PRBS_SEL_WIDTH 2
  #define XX_CH3_TX_PRBS_INV_LBN 13
  #define XX_CH3_TX_PRBS_INV_WIDTH 1
  #define XX_CH3_TX_PRBS_CHKEN_LBN 12
  #define XX_CH3_TX_PRBS_CHKEN_WIDTH 1
  #define XX_CH2_TX_PRBS_SEL_LBN 10
  #define XX_CH2_TX_PRBS_SEL_WIDTH 2
  #define XX_CH2_TX_PRBS_INV_LBN 9
  #define XX_CH2_TX_PRBS_INV_WIDTH 1
  #define XX_CH2_TX_PRBS_CHKEN_LBN 8
  #define XX_CH2_TX_PRBS_CHKEN_WIDTH 1
  #define XX_CH1_TX_PRBS_SEL_LBN 6
  #define XX_CH1_TX_PRBS_SEL_WIDTH 2
  #define XX_CH1_TX_PRBS_INV_LBN 5
  #define XX_CH1_TX_PRBS_INV_WIDTH 1
  #define XX_CH1_TX_PRBS_CHKEN_LBN 4
  #define XX_CH1_TX_PRBS_CHKEN_WIDTH 1
  #define XX_CH0_TX_PRBS_SEL_LBN 2
  #define XX_CH0_TX_PRBS_SEL_WIDTH 2
  #define XX_CH0_TX_PRBS_INV_LBN 1
  #define XX_CH0_TX_PRBS_INV_WIDTH 1
  #define XX_CH0_TX_PRBS_CHKEN_LBN 0
  #define XX_CH0_TX_PRBS_CHKEN_WIDTH 1
#define XX_PRBS_CHK_REG_KER_P0_OFST 0x1340 /* XAUI PRBS checker control
					      register */
#define XX_PRBS_CHK_REG_P0_OFST 0x1340 /* XAUI PRBS checker control
					  register */
  #define XX_REV_LB_EN_LBN 16
  #define XX_REV_LB_EN_WIDTH 1
  #define XX_CH3_DEG_DET_LBN 15
  #define XX_CH3_DEG_DET_WIDTH 1
  #define XX_CH3_LFSR_LOCK_IND_LBN 14
  #define XX_CH3_LFSR_LOCK_IND_WIDTH 1
  #define XX_CH3_PRBS_FRUN_LBN 13
  #define XX_CH3_PRBS_FRUN_WIDTH 1
  #define XX_CH3_ERR_CHK_LBN 12
  #define XX_CH3_ERR_CHK_WIDTH 1
  #define XX_CH2_DEG_DET_LBN 11
  #define XX_CH2_DEG_DET_WIDTH 1
  #define XX_CH2_LFSR_LOCK_IND_LBN 10
  #define XX_CH2_LFSR_LOCK_IND_WIDTH 1
  #define XX_CH2_PRBS_FRUN_LBN 9
  #define XX_CH2_PRBS_FRUN_WIDTH 1
  #define XX_CH2_ERR_CHK_LBN 8
  #define XX_CH2_ERR_CHK_WIDTH 1
  #define XX_CH1_DEG_DET_LBN 7
  #define XX_CH1_DEG_DET_WIDTH 1
  #define XX_CH1_LFSR_LOCK_IND_LBN 6
  #define XX_CH1_LFSR_LOCK_IND_WIDTH 1
  #define XX_CH1_PRBS_FRUN_LBN 5
  #define XX_CH1_PRBS_FRUN_WIDTH 1
  #define XX_CH1_ERR_CHK_LBN 4
  #define XX_CH1_ERR_CHK_WIDTH 1
  #define XX_CH0_DEG_DET_LBN 3
  #define XX_CH0_DEG_DET_WIDTH 1
  #define XX_CH0_LFSR_LOCK_IND_LBN 2
  #define XX_CH0_LFSR_LOCK_IND_WIDTH 1
  #define XX_CH0_PRBS_FRUN_LBN 1
  #define XX_CH0_PRBS_FRUN_WIDTH 1
  #define XX_CH0_ERR_CHK_LBN 0
  #define XX_CH0_ERR_CHK_WIDTH 1
#define XX_PRBS_ERR_REG_KER_P0_OFST 0x1350 /* XAUI PRBS checker error
					      count register */
#define XX_PRBS_ERR_REG_P0_OFST 0x1350 /* XAUI PRBS checker error count
					  register */
  #define XX_CH3_PRBS_ERR_CNT_LBN 24
  #define XX_CH3_PRBS_ERR_CNT_WIDTH 8
  #define XX_CH2_PRBS_ERR_CNT_LBN 16
  #define XX_CH2_PRBS_ERR_CNT_WIDTH 8
  #define XX_CH1_PRBS_ERR_CNT_LBN 8
  #define XX_CH1_PRBS_ERR_CNT_WIDTH 8
  #define XX_CH0_PRBS_ERR_CNT_LBN 0
  #define XX_CH0_PRBS_ERR_CNT_WIDTH 8
#define XX_CORE_STAT_REG_KER_P0_OFST 0x1360 /* XAUI XGXS core status
					       register */
#define XX_CORE_STAT_REG_P0_OFST 0x1360 /* XAUI XGXS core status register */
  #define XX_FORCE_SIG3_LBN 31
  #define XX_FORCE_SIG3_WIDTH 1
  #define XX_FORCE_SIG3_VAL_LBN 30
  #define XX_FORCE_SIG3_VAL_WIDTH 1
  #define XX_FORCE_SIG2_LBN 29
  #define XX_FORCE_SIG2_WIDTH 1
  #define XX_FORCE_SIG2_VAL_LBN 28
  #define XX_FORCE_SIG2_VAL_WIDTH 1
  #define XX_FORCE_SIG1_LBN 27
  #define XX_FORCE_SIG1_WIDTH 1
  #define XX_FORCE_SIG1_VAL_LBN 26
  #define XX_FORCE_SIG1_VAL_WIDTH 1
  #define XX_FORCE_SIG0_LBN 25
  #define XX_FORCE_SIG0_WIDTH 1
  #define XX_FORCE_SIG0_VAL_LBN 24
  #define XX_FORCE_SIG0_VAL_WIDTH 1
  #define XX_XGXS_LB_EN_LBN 23
  #define XX_XGXS_LB_EN_WIDTH 1
  #define XX_XGMII_LB_EN_LBN 22
  #define XX_XGMII_LB_EN_WIDTH 1
  #define XX_MATCH_FAULT_LBN 21
  #define XX_MATCH_FAULT_WIDTH 1
  #define XX_ALIGN_DONE_LBN 20
  #define XX_ALIGN_DONE_WIDTH 1
  #define XX_SYNC_STAT3_LBN 19
  #define XX_SYNC_STAT3_WIDTH 1
  #define XX_SYNC_STAT2_LBN 18
  #define XX_SYNC_STAT2_WIDTH 1
  #define XX_SYNC_STAT1_LBN 17
  #define XX_SYNC_STAT1_WIDTH 1
  #define XX_SYNC_STAT0_LBN 16
  #define XX_SYNC_STAT0_WIDTH 1
  #define XX_COMMA_DET_CH3_LBN 15
  #define XX_COMMA_DET_CH3_WIDTH 1
  #define XX_COMMA_DET_CH2_LBN 14
  #define XX_COMMA_DET_CH2_WIDTH 1
  #define XX_COMMA_DET_CH1_LBN 13
  #define XX_COMMA_DET_CH1_WIDTH 1
  #define XX_COMMA_DET_CH0_LBN 12
  #define XX_COMMA_DET_CH0_WIDTH 1
  #define XX_CGRP_ALIGN_CH3_LBN 11
  #define XX_CGRP_ALIGN_CH3_WIDTH 1
  #define XX_CGRP_ALIGN_CH2_LBN 10
  #define XX_CGRP_ALIGN_CH2_WIDTH 1
  #define XX_CGRP_ALIGN_CH1_LBN 9
  #define XX_CGRP_ALIGN_CH1_WIDTH 1
  #define XX_CGRP_ALIGN_CH0_LBN 8
  #define XX_CGRP_ALIGN_CH0_WIDTH 1
  #define XX_CHAR_ERR_CH3_LBN 7
  #define XX_CHAR_ERR_CH3_WIDTH 1
  #define XX_CHAR_ERR_CH2_LBN 6
  #define XX_CHAR_ERR_CH2_WIDTH 1
  #define XX_CHAR_ERR_CH1_LBN 5
  #define XX_CHAR_ERR_CH1_WIDTH 1
  #define XX_CHAR_ERR_CH0_LBN 4
  #define XX_CHAR_ERR_CH0_WIDTH 1
  #define XX_DISPERR_CH3_LBN 3
  #define XX_DISPERR_CH3_WIDTH 1
  #define XX_DISPERR_CH2_LBN 2
  #define XX_DISPERR_CH2_WIDTH 1
  #define XX_DISPERR_CH1_LBN 1
  #define XX_DISPERR_CH1_WIDTH 1
  #define XX_DISPERR_CH0_LBN 0
  #define XX_DISPERR_CH0_WIDTH 1
#endif
