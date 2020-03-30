/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC - EFXXXX (aka Falcon) 1G MAC
 * statistics register definitions.
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

/*************---- 1G MAC Statistical Counters C Header ----*************/
#define GRxGoodOct_offset 0x0
    #define GRxGoodOct_width 48
#define GRxBadOct_offset 0x8
    #define GRxBadOct_width 48
#define GRxMissPkt_offset 0x10
    #define GRxMissPkt_width 32
#define GRxFalseCRS_offset 0x14
    #define GRxFalseCRS_width 32
#define GRxPausePkt_offset 0x18
    #define GRxPausePkt_width 32
#define GRxBadPkt_offset 0x1C
    #define GRxBadPkt_width 32
#define GRxUcastPkt_offset 0x20
    #define GRxUcastPkt_width 32
#define GRxMcastPkt_offset 0x24
    #define GRxMcastPkt_width 32
#define GRxBcastPkt_offset 0x28
    #define GRxBcastPkt_width 32
#define GRxGoodLt64Pkt_offset 0x2C
    #define GRxGoodLt64Pkt_width 32
#define GRxBadLt64Pkt_offset 0x30
    #define GRxBadLt64Pkt_width 32
#define GRx64Pkt_offset 0x34
    #define GRx64Pkt_width 32
#define GRx65to127Pkt_offset 0x38
    #define GRx65to127Pkt_width 32
#define GRx128to255Pkt_offset 0x3C
    #define GRx128to255Pkt_width 32
#define GRx256to511Pkt_offset 0x40
    #define GRx256to511Pkt_width 32
#define GRx512to1023Pkt_offset 0x44
    #define GRx512to1023Pkt_width 32
#define GRx1024to15xxPkt_offset 0x48
    #define GRx1024to15xxPkt_width 32
#define GRxFcsErr64to15xxPkt_offset 0x4C
    #define GRxFcsErr64to15xxPkt_width 32
#define GRx15xxtoJumboPkt_offset 0x50
    #define GRx15xxtoJumboPkt_width 32
#define GRxFcsErr15xxtoJumboPkt_offset 0x54
    #define GRxFcsErr15xxtoJumboPkt_width 32
#define GRxGtJumboPkt_offset 0x58
    #define GRxGtJumboPkt_width 32
#define GRxFcsErrGtJumboPkt_offset 0x5C
    #define GRxFcsErrGtJumboPkt_width 32
#define GTxGoodBadOct_offset 0x80
    #define GTxGoodBadOct_width 48
#define GTxBoodOct_offset 0x88
    #define GTxBoodOct_width 48
#define GTxSglColPkt_offset 0x90
    #define GTxSglColPkt_width 32
#define GTxMultColPkt_offset 0x94
    #define GTxMultColPkt_width 32
#define GTxExColPkt_offset 0x98
    #define GTxExColPkt_width 32
#define GTxDefPkt_offset 0x9C
    #define GTxDefPkt_width 32
#define GTxLateCol_offset 0xA0
    #define GTxLateCol_width 32
#define GTxExDefPkt_offset 0xA4
    #define GTxExDefPkt_width 32
#define GTxPausePkt_offset 0xA8
    #define GTxPausePkt_width 32
#define GTxBadPkt_offset 0xAC
    #define GTxBadPkt_width 32
#define GTxUcastPkt_offset 0xB0
    #define GTxUcastPkt_width 32
#define GTxMcastPkt_offset 0xB4
    #define GTxMcastPkt_width 32
#define GTxBcastPkt_offset 0xB8
    #define GTxBcastPkt_width 32
#define GTxLt64Pkt_offset 0xBC
    #define GTxLt64Pkt_width 32
#define GTx64Pkt_offset 0xC0
    #define GTx64Pkt_width 32
#define GTx65to127Pkt_offset 0xC4
    #define GTx65to127Pkt_width 32
#define GTx128to255Pkt_offset 0xC8
    #define GTx128to255Pkt_width 32
#define GTx256to511Pkt_offset 0xCC
    #define GTx256to511Pkt_width 32
#define GTx512to1023Pkt_offset 0xD0
    #define GTx512to1023Pkt_width 32
#define GTx1024to15xxPkt_offset 0xD4
    #define GTx1024to15xxPkt_width 32
#define GTx15xxtoJumboPkt_offset 0xD8
    #define GTx15xxtoJumboPkt_width 32
#define GTxGtJumboPkt_offset 0xDC
    #define GTxGtJumboPkt_width 32
#define GDmaDone_offset 0xE0
    #define GDmaDone_width 32
/*************---- 10G MAC Statistical Counters C Header ----*************/
#define XgRxOctets_offset 0x0
    #define XgRxOctets_width 48
#define XgRxOctetsOK_offset 0x8
    #define XgRxOctetsOK_width 48
#define XgRxPkts_offset 0x10
    #define XgRxPkts_width 32
#define XgRxPktsOK_offset 0x14
    #define XgRxPktsOK_width 32
#define XgRxBroadcastPkts_offset 0x18
    #define XgRxBroadcastPkts_width 32
#define XgRxMulticastPkts_offset 0x1C
    #define XgRxMulticastPkts_width 32
#define XgRxUnicastPkts_offset 0x20
    #define XgRxUnicastPkts_width 32
#define XgRxUndersizePkts_offset 0x24
    #define XgRxUndersizePkts_width 32
#define XgRxOversizePkts_offset 0x28
    #define XgRxOversizePkts_width 32
#define XgRxJabberPkts_offset 0x2C
    #define XgRxJabberPkts_width 32
#define XgRxUndersizeFCSerrorPkts_offset 0x30
    #define XgRxUndersizeFCSerrorPkts_width 32
#define XgRxDropEvents_offset 0x34
    #define XgRxDropEvents_width 32
#define XgRxFCSerrorPkts_offset 0x38
    #define XgRxFCSerrorPkts_width 32
#define XgRxAlignError_offset 0x3C
    #define XgRxAlignError_width 32
#define XgRxLengthError_offset 0x40
    #define XgRxLengthError_width 32
#define XgRxSymbolError_offset 0x44
    #define XgRxSymbolError_width 32
#define XgRxInternalMACError_offset 0x48
    #define XgRxInternalMACError_width 32
#define XgRxPkts64Octets_offset 0x4C
    #define XgRxPkts64Octets_width 32
#define XgRxPkts65to127Octets_offset 0x50
    #define XgRxPkts65to127Octets_width 32
#define XgRxPkts128to255Octets_offset 0x54
    #define XgRxPkts128to255Octets_width 32
#define XgRxPkts256to511Octets_offset 0x58
    #define XgRxPkts256to511Octets_width 32
#define XgRxPkts512to1023Octets_offset 0x5C
    #define XgRxPkts512to1023Octets_width 32
#define XgRxPkts1024to1518Octets_offset 0x60
    #define XgRxPkts1024to1518Octets_width 32
#define XgRxPkts1519toMaxOctets_offset 0x64
    #define XgRxPkts1519toMaxOctets_width 32
#define XgRxControlPkts_offset 0x68
    #define XgRxControlPkts_width 32
#define XgRxPausePkts_offset 0x6C
    #define XgRxPausePkts_width 32
#define XgTxPkts_offset 0x80
    #define XgTxPkts_width 32
#define XgTxOctets_offset 0x88
    #define XgTxOctets_width 48
#define XgTxMulticastPkts_offset 0x90
    #define XgTxMulticastPkts_width 32
#define XgTxBroadcastPkts_offset 0x94
    #define XgTxBroadcastPkts_width 32
#define XgTxUnicastPkts_offset 0x98
    #define XgTxUnicastPkts_width 32
#define XgTxControlPkts_offset 0x9C
    #define XgTxControlPkts_width 32
#define XgTxPausePkts_offset 0xA0
    #define XgTxPausePkts_width 32
#define XgTxPkts64Octets_offset 0xA4
    #define XgTxPkts64Octets_width 32
#define XgTxPkts65to127Octets_offset 0xA8
    #define XgTxPkts65to127Octets_width 32
#define XgTxPkts128to255Octets_offset 0xAC
    #define XgTxPkts128to255Octets_width 32
#define XgTxPkts256to511Octets_offset 0xB0
    #define XgTxPkts256to511Octets_width 32
#define XgTxPkts512to1023Octets_offset 0xB4
    #define XgTxPkts512to1023Octets_width 32
#define XgTxPkts1024to1518Octets_offset 0xB8
    #define XgTxPkts1024to1518Octets_width 32
#define XgTxPkts1519toMaxOctets_offset 0xBC
    #define XgTxPkts1519toMaxOctets_width 32
#define XgTxOversizePkts_offset 0xC0
    #define XgTxOversizePkts_width 32
#define XgDmaDone_offset 0xC4
    #define XgDmaDone_width 32
