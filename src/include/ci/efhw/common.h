/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides API of the efhw library which may be used both from
 * the kernel and from the user-space code.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
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

#ifndef __CI_EFHW_COMMON_H__
#define __CI_EFHW_COMMON_H__

#include <ci/efhw/common_sysdep.h>

enum efhw_arch {
	EFHW_ARCH_FALCON,
	EFHW_ARCH_EF10,
};

typedef uint32_t efhw_buffer_addr_t;
#define EFHW_BUFFER_ADDR_FMT	"[ba:%"PRIx32"]"

/* Below event structure is in NIC bytes order. When using either field for
 * something other then check against 0xffff one should convert the event
 * into CPU byte order.  Normally this is done in the HW-specific macros */

/*! Comment? */
typedef union {
	uint64_t u64;
	struct {
		uint32_t a;
		uint32_t b;
	} opaque;
} efhw_event_t;

/* Flags for TX/RX queues */
#define EFHW_VI_JUMBO_EN           0x01    /*! scatter RX over multiple desc */
#define EFHW_VI_ISCSI_RX_HDIG_EN   0x02    /*! iscsi rx header digest */
#define EFHW_VI_ISCSI_TX_HDIG_EN   0x04    /*! iscsi tx header digest */
#define EFHW_VI_ISCSI_RX_DDIG_EN   0x08    /*! iscsi rx data digest */
#define EFHW_VI_ISCSI_TX_DDIG_EN   0x10    /*! iscsi tx data digest */
#define EFHW_VI_TX_PHYS_ADDR_EN    0x20    /*! TX physical address mode */
#define EFHW_VI_RX_PHYS_ADDR_EN    0x40    /*! RX physical address mode */
#define EFHW_VI_RM_WITH_INTERRUPT  0x80    /*! VI with an interrupt */
#define EFHW_VI_TX_IP_CSUM_DIS     0x100   /*! enable ip checksum generation */
#define EFHW_VI_TX_TCPUDP_CSUM_DIS 0x200   /*! enable tcp/udp checksum
					       generation */
#define EFHW_VI_TX_TCPUDP_ONLY     0x400   /*! drop non-tcp/udp packets */
/* from here on, Siena only: */
#define EFHW_VI_TX_IP_FILTER_EN    0x800   /*! TX IP filtering */
#define EFHW_VI_TX_ETH_FILTER_EN   0x1000  /*! TX MAC filtering */
#define EFHW_VI_TX_Q_MASK_WIDTH_0  0x2000  /*! TX filter q_mask_width bit 0 */
#define EFHW_VI_TX_Q_MASK_WIDTH_1  0x4000  /*! TX filter q_mask_width bit 1 */
#define EFHW_VI_RX_HDR_SPLIT       0x8000  /*! RX header split */

/* Flags for hw features */
#define EFHW_VI_NIC_BUG35388_WORKAROUND 0x01  /*! workaround for bug35388 */

/* Types of hardware filter */
/* Each of these values implicitly selects scatter filters on B0 - or in
   EFHW_IP_FILTER_TYPE_NOSCAT_B0_MASK if a non-scatter filter is required */
#define EFHW_IP_FILTER_TYPE_UDP_WILDCARD  (0)	/* dest host only */
#define EFHW_IP_FILTER_TYPE_UDP_FULL      (1)	/* dest host and port */
#define EFHW_IP_FILTER_TYPE_TCP_WILDCARD  (2)	/* dest based filter */
#define EFHW_IP_FILTER_TYPE_TCP_FULL      (3)	/* src  filter */
/* Same again, but with RSS (for B0 only) */
#define EFHW_IP_FILTER_TYPE_UDP_WILDCARD_RSS_B0  (4)
#define EFHW_IP_FILTER_TYPE_UDP_FULL_RSS_B0      (5)
#define EFHW_IP_FILTER_TYPE_TCP_WILDCARD_RSS_B0  (6)
#define EFHW_IP_FILTER_TYPE_TCP_FULL_RSS_B0      (7)

#define EFHW_IP_FILTER_TYPE_FULL_MASK      (0x1) /* Mask for full / wildcard */
#define EFHW_IP_FILTER_TYPE_TCP_MASK       (0x2) /* Mask for TCP type */
#define EFHW_IP_FILTER_TYPE_RSS_B0_MASK    (0x4) /* Mask for B0 RSS enable */
#define EFHW_IP_FILTER_TYPE_NOSCAT_B0_MASK (0x8) /* Mask for B0 SCATTER dsbl */

#define EFHW_IP_FILTER_TYPE_MASK	(0xffff) /* Mask of types above */

#define EFHW_IP_FILTER_BROADCAST	(0x10000) /* driverlink filter
						     support */

/* Similar for RX MAC filters -- Siena only */
#define EFHW_MAC_FILTER_TYPE_WILDCARD	      (0)
#define EFHW_MAC_FILTER_TYPE_FULL	      (1)
#define EFHW_MAC_FILTER_TYPE_IPOVER_WILDCARD  (2)
#define EFHW_MAC_FILTER_TYPE_IPOVER_FULL      (3)
/* Same again, but with RSS */
#define EFHW_MAC_FILTER_TYPE_WILDCARD_RSS        (4)
#define EFHW_MAC_FILTER_TYPE_FULL_RSS            (5)
#define EFHW_MAC_FILTER_TYPE_IPOVER_WILDCARD_RSS (6)
#define EFHW_MAC_FILTER_TYPE_IPOVER_FULL_RSS     (7)

#define EFHW_MAC_FILTER_TYPE_FULL_MASK     (0x1) /* Mask for full / wildcard */
#define EFHW_MAC_FILTER_TYPE_IPOVER_MASK   (0x2) /* Mask for IP override flg */
#define EFHW_MAC_FILTER_TYPE_RSS_MASK      (0x4) /* Mask for RSS enable */
#define EFHW_MAC_FILTER_TYPE_NOSCAT_MASK   (0x8) /* Mask for SCATTER dsbl */

#define EFHW_MAC_FILTER_TYPE_MASK	(0xffff) /* Mask of types above */


/* NIC's page size information */

#define EFHW_1K		0x00000400u
#define EFHW_2K		0x00000800u
#define EFHW_4K		0x00001000u
#define EFHW_8K		0x00002000u
#define EFHW_16K	0x00004000u
#define EFHW_32K	0x00008000u
#define EFHW_64K	0x00010000u
#define EFHW_128K	0x00020000u
#define EFHW_256K	0x00040000u
#define EFHW_512K	0x00080000u
#define EFHW_1M		0x00100000u
#define EFHW_2M		0x00200000u
#define EFHW_4M		0x00400000u
#define EFHW_8M		0x00800000u
#define EFHW_16M	0x01000000u
#define EFHW_32M	0x02000000u
#define EFHW_48M	0x03000000u
#define EFHW_64M	0x04000000u
#define EFHW_128M	0x08000000u
#define EFHW_256M	0x10000000u
#define EFHW_512M	0x20000000u
#define EFHW_1G 	0x40000000u
#define EFHW_2G		0x80000000u
#define EFHW_4G		0x100000000ULL
#define EFHW_8G		0x200000000ULL

/* --- DMA --- */
#define EFHW_DMA_ADDRMASK		(0xffffffffffffffffULL)

#define EFHW_IP_FILTER_NUM		8192

#define EFHW_NIC_PAGE_SIZE  EFHW_4K
#define EFHW_NIC_PAGE_SHIFT 12

#define EFHW_NIC_PAGE_MASK (~(EFHW_NIC_PAGE_SIZE-1))

#endif /* __CI_EFHW_COMMON_H__ */
