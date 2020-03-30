/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __FALCON_STATS_H__
#define __FALCON_STATS_H__

/*
 * This file is a digest of defs/decls used by the eftest stats counter
 * routines, and will require uopdate if any of the originals are modified
 */

/**************************************************************************
 *
 * - efx_types.h
 *
 **************************************************************************
 *
 */

/* Specified attribute (i.e. LBN ow WIDTH) of the specified field */
#define EFX_VAL(_field, _attribute)					\
	_field ## _ ## _attribute

/**************************************************************************
 *
 * Falcon MAC stats - falcon_hwdefs.h
 *
 **************************************************************************
 *
 */

#define GRxGoodOct_offset 0x0
#define GRxGoodOct_WIDTH 48
#define GRxBadOct_offset 0x8
#define GRxBadOct_WIDTH 48
#define GRxMissPkt_offset 0x10
#define GRxMissPkt_WIDTH 32
#define GRxFalseCRS_offset 0x14
#define GRxFalseCRS_WIDTH 32
#define GRxPausePkt_offset 0x18
#define GRxPausePkt_WIDTH 32
#define GRxBadPkt_offset 0x1C
#define GRxBadPkt_WIDTH 32
#define GRxUcastPkt_offset 0x20
#define GRxUcastPkt_WIDTH 32
#define GRxMcastPkt_offset 0x24
#define GRxMcastPkt_WIDTH 32
#define GRxBcastPkt_offset 0x28
#define GRxBcastPkt_WIDTH 32
#define GRxGoodLt64Pkt_offset 0x2C
#define GRxGoodLt64Pkt_WIDTH 32
#define GRxBadLt64Pkt_offset 0x30
#define GRxBadLt64Pkt_WIDTH 32
#define GRx64Pkt_offset 0x34
#define GRx64Pkt_WIDTH 32
#define GRx65to127Pkt_offset 0x38
#define GRx65to127Pkt_WIDTH 32
#define GRx128to255Pkt_offset 0x3C
#define GRx128to255Pkt_WIDTH 32
#define GRx256to511Pkt_offset 0x40
#define GRx256to511Pkt_WIDTH 32
#define GRx512to1023Pkt_offset 0x44
#define GRx512to1023Pkt_WIDTH 32
#define GRx1024to15xxPkt_offset 0x48
#define GRx1024to15xxPkt_WIDTH 32
#define GRx15xxtoJumboPkt_offset 0x4C
#define GRx15xxtoJumboPkt_WIDTH 32
#define GRxGtJumboPkt_offset 0x50
#define GRxGtJumboPkt_WIDTH 32
#define GRxFcsErr64to15xxPkt_offset 0x54
#define GRxFcsErr64to15xxPkt_WIDTH 32
#define GRxFcsErr15xxtoJumboPkt_offset 0x58
#define GRxFcsErr15xxtoJumboPkt_WIDTH 32
#define GRxFcsErrGtJumboPkt_offset 0x5C
#define GRxFcsErrGtJumboPkt_WIDTH 32
#define GTxGoodBadOct_offset 0x80
#define GTxGoodBadOct_WIDTH 48
#define GTxGoodOct_offset 0x88
#define GTxGoodOct_WIDTH 48
#define GTxSglColPkt_offset 0x90
#define GTxSglColPkt_WIDTH 32
#define GTxMultColPkt_offset 0x94
#define GTxMultColPkt_WIDTH 32
#define GTxExColPkt_offset 0x98
#define GTxExColPkt_WIDTH 32
#define GTxDefPkt_offset 0x9C
#define GTxDefPkt_WIDTH 32
#define GTxLateCol_offset 0xA0
#define GTxLateCol_WIDTH 32
#define GTxExDefPkt_offset 0xA4
#define GTxExDefPkt_WIDTH 32
#define GTxPausePkt_offset 0xA8
#define GTxPausePkt_WIDTH 32
#define GTxBadPkt_offset 0xAC
#define GTxBadPkt_WIDTH 32
#define GTxUcastPkt_offset 0xB0
#define GTxUcastPkt_WIDTH 32
#define GTxMcastPkt_offset 0xB4
#define GTxMcastPkt_WIDTH 32
#define GTxBcastPkt_offset 0xB8
#define GTxBcastPkt_WIDTH 32
#define GTxLt64Pkt_offset 0xBC
#define GTxLt64Pkt_WIDTH 32
#define GTx64Pkt_offset 0xC0
#define GTx64Pkt_WIDTH 32
#define GTx65to127Pkt_offset 0xC4
#define GTx65to127Pkt_WIDTH 32
#define GTx128to255Pkt_offset 0xC8
#define GTx128to255Pkt_WIDTH 32
#define GTx256to511Pkt_offset 0xCC
#define GTx256to511Pkt_WIDTH 32
#define GTx512to1023Pkt_offset 0xD0
#define GTx512to1023Pkt_WIDTH 32
#define GTx1024to15xxPkt_offset 0xD4
#define GTx1024to15xxPkt_WIDTH 32
#define GTx15xxtoJumboPkt_offset 0xD8
#define GTx15xxtoJumboPkt_WIDTH 32
#define GTxGtJumboPkt_offset 0xDC
#define GTxGtJumboPkt_WIDTH 32
#define GTxNonTcpUdpPkt_offset 0xE0
#define GTxNonTcpUdpPkt_WIDTH 16
#define GTxMacSrcErrPkt_offset 0xE4
#define GTxMacSrcErrPkt_WIDTH 16
#define GTxIpSrcErrPkt_offset 0xE8
#define GTxIpSrcErrPkt_WIDTH 16
#define GDmaDone_offset 0xEC
#define GDmaDone_WIDTH 32

#define XgRxOctets_offset 0x0
#define XgRxOctets_WIDTH 48
#define XgRxOctetsOK_offset 0x8
#define XgRxOctetsOK_WIDTH 48
#define XgRxPkts_offset 0x10
#define XgRxPkts_WIDTH 32
#define XgRxPktsOK_offset 0x14
#define XgRxPktsOK_WIDTH 32
#define XgRxBroadcastPkts_offset 0x18
#define XgRxBroadcastPkts_WIDTH 32
#define XgRxMulticastPkts_offset 0x1C
#define XgRxMulticastPkts_WIDTH 32
#define XgRxUnicastPkts_offset 0x20
#define XgRxUnicastPkts_WIDTH 32
#define XgRxUndersizePkts_offset 0x24
#define XgRxUndersizePkts_WIDTH 32
#define XgRxOversizePkts_offset 0x28
#define XgRxOversizePkts_WIDTH 32
#define XgRxJabberPkts_offset 0x2C
#define XgRxJabberPkts_WIDTH 32
#define XgRxUndersizeFCSerrorPkts_offset 0x30
#define XgRxUndersizeFCSerrorPkts_WIDTH 32
#define XgRxDropEvents_offset 0x34
#define XgRxDropEvents_WIDTH 32
#define XgRxFCSerrorPkts_offset 0x38
#define XgRxFCSerrorPkts_WIDTH 32
#define XgRxAlignError_offset 0x3C
#define XgRxAlignError_WIDTH 32
#define XgRxSymbolError_offset 0x40
#define XgRxSymbolError_WIDTH 32
#define XgRxInternalMACError_offset 0x44
#define XgRxInternalMACError_WIDTH 32
#define XgRxControlPkts_offset 0x48
#define XgRxControlPkts_WIDTH 32
#define XgRxPausePkts_offset 0x4C
#define XgRxPausePkts_WIDTH 32
#define XgRxPkts64Octets_offset 0x50
#define XgRxPkts64Octets_WIDTH 32
#define XgRxPkts65to127Octets_offset 0x54
#define XgRxPkts65to127Octets_WIDTH 32
#define XgRxPkts128to255Octets_offset 0x58
#define XgRxPkts128to255Octets_WIDTH 32
#define XgRxPkts256to511Octets_offset 0x5C
#define XgRxPkts256to511Octets_WIDTH 32
#define XgRxPkts512to1023Octets_offset 0x60
#define XgRxPkts512to1023Octets_WIDTH 32
#define XgRxPkts1024to15xxOctets_offset 0x64
#define XgRxPkts1024to15xxOctets_WIDTH 32
#define XgRxPkts15xxtoMaxOctets_offset 0x68
#define XgRxPkts15xxtoMaxOctets_WIDTH 32
#define XgRxLengthError_offset 0x6C
#define XgRxLengthError_WIDTH 32
#define XgTxPkts_offset 0x80
#define XgTxPkts_WIDTH 32
#define XgTxOctets_offset 0x88
#define XgTxOctets_WIDTH 48
#define XgTxMulticastPkts_offset 0x90
#define XgTxMulticastPkts_WIDTH 32
#define XgTxBroadcastPkts_offset 0x94
#define XgTxBroadcastPkts_WIDTH 32
#define XgTxUnicastPkts_offset 0x98
#define XgTxUnicastPkts_WIDTH 32
#define XgTxControlPkts_offset 0x9C
#define XgTxControlPkts_WIDTH 32
#define XgTxPausePkts_offset 0xA0
#define XgTxPausePkts_WIDTH 32
#define XgTxPkts64Octets_offset 0xA4
#define XgTxPkts64Octets_WIDTH 32
#define XgTxPkts65to127Octets_offset 0xA8
#define XgTxPkts65to127Octets_WIDTH 32
#define XgTxPkts128to255Octets_offset 0xAC
#define XgTxPkts128to255Octets_WIDTH 32
#define XgTxPkts256to511Octets_offset 0xB0
#define XgTxPkts256to511Octets_WIDTH 32
#define XgTxPkts512to1023Octets_offset 0xB4
#define XgTxPkts512to1023Octets_WIDTH 32
#define XgTxPkts1024to15xxOctets_offset 0xB8
#define XgTxPkts1024to15xxOctets_WIDTH 32
#define XgTxPkts1519toMaxOctets_offset 0xBC
#define XgTxPkts1519toMaxOctets_WIDTH 32
#define XgTxUndersizePkts_offset 0xC0
#define XgTxUndersizePkts_WIDTH 32
#define XgTxOversizePkts_offset 0xC4
#define XgTxOversizePkts_WIDTH 32
#define XgTxNonTcpUdpPkt_offset 0xC8
#define XgTxNonTcpUdpPkt_WIDTH 16
#define XgTxMacSrcErrPkt_offset 0xCC
#define XgTxMacSrcErrPkt_WIDTH 16
#define XgTxIpSrcErrPkt_offset 0xD0
#define XgTxIpSrcErrPkt_WIDTH 16
#define XgDmaDone_offset 0xD4
#define XgDmaDone_WIDTH 32

#define FALCON_STATS_NOT_DONE 0x00000000
#define FALCON_STATS_DONE 0xffffffff

#define FALCON_STAT_OFFSET(falcon_stat) EFX_VAL ( falcon_stat, offset )
#define FALCON_STAT_WIDTH(falcon_stat) EFX_VAL ( falcon_stat, WIDTH )

#define FALCON_MAC_STATS_SIZE 0x100

/**************************************************************************
 *
 * Efx extended statistics - net_driver.h
 *
 * Not all statistics are provided by all supported MACs.  The purpose
 * is this structure is to contain the raw statistics provided by each
 * MAC.
 *
 ***************************************************************************/
struct efx_mac_stats {
	uint64_t tx_bytes;
	uint64_t tx_good_bytes;
	uint64_t tx_bad_bytes;
	unsigned long tx_packets;
	unsigned long tx_bad;
	unsigned long tx_pause;
	unsigned long tx_control;
	unsigned long tx_unicast;
	unsigned long tx_multicast;
	unsigned long tx_broadcast;
	unsigned long tx_lt64;
	unsigned long tx_64;
	unsigned long tx_65_to_127;
	unsigned long tx_128_to_255;
	unsigned long tx_256_to_511;
	unsigned long tx_512_to_1023;
	unsigned long tx_1024_to_15xx;
	unsigned long tx_15xx_to_jumbo;
	unsigned long tx_gtjumbo;
	unsigned long tx_collision;
	unsigned long tx_single_collision;
	unsigned long tx_multiple_collision;
	unsigned long tx_excessive_collision;
	unsigned long tx_deferred;
	unsigned long tx_late_collision;
	unsigned long tx_excessive_deferred;
	unsigned long tx_non_tcpudp;
	unsigned long tx_mac_src_error;
	unsigned long tx_ip_src_error;
	uint64_t rx_bytes;
	uint64_t rx_good_bytes;
	uint64_t rx_bad_bytes;
	unsigned long rx_packets;
	unsigned long rx_good;
	unsigned long rx_bad;
	unsigned long rx_pause;
	unsigned long rx_control;
	unsigned long rx_unicast;
	unsigned long rx_multicast;
	unsigned long rx_broadcast;
	unsigned long rx_lt64;
	unsigned long rx_64;
	unsigned long rx_65_to_127;
	unsigned long rx_128_to_255;
	unsigned long rx_256_to_511;
	unsigned long rx_512_to_1023;
	unsigned long rx_1024_to_15xx;
	unsigned long rx_15xx_to_jumbo;
	unsigned long rx_gtjumbo;
	unsigned long rx_bad_lt64;
	unsigned long rx_bad_64_to_15xx;
	unsigned long rx_bad_15xx_to_jumbo;
	unsigned long rx_bad_gtjumbo;
	unsigned long rx_overflow;
	unsigned long rx_missed;
	unsigned long rx_false_carrier;
	unsigned long rx_symbol_error;
	unsigned long rx_align_error;
	unsigned long rx_length_error;
	unsigned long rx_internal_error;
	/* GMAC compatability. TODO Can these be removed? */
	unsigned long rx_good_lt64;
	unsigned long rx_bad_64_to_jumbo;
	unsigned long rx_good_gtjumbo;
};

/**************************************************************************
 *
 * MAC stats register - efx_regs.h
 *
 ***************************************************************************/
#define MAC_STAT_DMA_REG 0xc60
#define MAC_STAT_DMA_CMD_LBN 48
#define MAC_STAT_DMA_CMD_WIDTH 1
#define MAC_STAT_DMA_REGION_LBN 46
#define MAC_STAT_DMA_REGION_WIDTH 2
#define MAC_STAT_DMA_ADR_LBN 0
#define MAC_STAT_DMA_ADR_WIDTH 46

/*
 * **************************************************************************
 * - falcon_core.h
 */

#define ALTERA_BUILD_REG_OFST 0x300	// Altera build register

#endif /* __FALCON_STATS_H__ */
