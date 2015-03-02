/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

#ifndef __ONLOAD_MMAP_H__
#define __ONLOAD_MMAP_H__

/*********************************************************************
***************************** Memory maps ****************************
*********************************************************************/

/* Mmap areas:
 * - CI_NETIF_MMAP_ID_STATE     netif shared state; ep buffers
 * - CI_NETIF_MMAP_ID_CPLANE    control plane shared state, read-only
 * - CI_NETIF_MMAP_ID_IO        VI resource: IO bar.
 * - CI_NETIF_MMAP_ID_IOBUFS    VI resource: queues
 *   + if CI_CFG_PKTS_AS_HUGE_PAGES=1, mmap pkt_shm_id array
 * - CI_NETIF_MMAP_ID_PIO       VI resource: PIO IO BAR
 * - CI_NETIF_MMAP_ID_OFE_RO    OFE read-only part of engine
 * - CI_NETIF_MMAP_ID_OFE_RW    OFE read-write part of engine
 * - CI_NETIF_MMAP_ID_PKTS + packet set id
 *   packet sets
 *
 * Offset for each area is CI_NETIF_MMAP_ID_* << CI_NETIF_MMAP_ID_SHIFT
 * In Linux, area size may be larger than 1<<CI_NETIF_MMAP_ID_SHIFT,
 * so they "virtally overlap".  In reality, each area gets its own nopage
 * handler.
 */
#define CI_NETIF_MMAP_ID_STATE    0
#define CI_NETIF_MMAP_ID_CPLANE   1
#define CI_NETIF_MMAP_ID_IO       2
#define CI_NETIF_MMAP_ID_IOBUFS   3
#if CI_CFG_PIO
#define CI_NETIF_MMAP_ID_PIO      4
#endif
#ifdef ONLOAD_OFE
#define CI_NETIF_MMAP_ID_OFE_RO   5
#define CI_NETIF_MMAP_ID_OFE_RW   6
#endif
#define CI_NETIF_MMAP_ID_PKTS     7
#define CI_NETIF_MMAP_ID_PKTSET(id) (CI_NETIF_MMAP_ID_PKTS+(id))

/* Mmap start should be aligned by page, so
 * CI_NETIF_MMAP_ID_SHIFT >= CI_PAGE_SHIFT.
 * Let's take the minimal value.
 * I hope it is good for Solaris as well.
 */
#define CI_NETIF_MMAP_ID_SHIFT  CI_PAGE_SHIFT

#endif
