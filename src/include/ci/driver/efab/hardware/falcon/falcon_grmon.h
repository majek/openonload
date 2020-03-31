/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC - EFXXXX (aka Falcon) 1G MAC
 * counters.
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
