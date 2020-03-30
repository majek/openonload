/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC - EFXXXX (aka Falcon) 10G MAC
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

/*************---- 10G MAC Statistical Counters C Header ----*************/
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
#define xGTxNonTcpUdpPkt_offset 0xC8
    #define xGTxNonTcpUdpPkt_WIDTH 16
#define xGTxMacSrcErrPkt_offset 0xCC
    #define xGTxMacSrcErrPkt_WIDTH 16
#define xGTxIpSrcErrPkt_offset 0xD0
    #define xGTxIpSrcErrPkt_WIDTH 16
#define XgDmaDone_offset 0xD4
    #define XgDmaDone_WIDTH 32
