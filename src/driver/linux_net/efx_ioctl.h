/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2006-2010: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Initially developed by Michael Brown <mbrown@fensystems.co.uk>
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
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

#ifndef EFX_IOCTL_H
#define EFX_IOCTL_H

#if defined(__KERNEL__)
#include <linux/if.h>
#include <linux/types.h>
#else
#include <net/if.h>
#ifndef _LINUX_IF_H
#define _LINUX_IF_H /* prevent <linux/if.h> from conflicting with <net/if.h> */
#endif
#include "efx_linux_types.h"
#endif
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

/* Efx private ioctl number */
/* We do not use the first 3 private ioctls because some utilities expect
 * them to be the old MDIO ioctls. */
#define SIOCEFX (SIOCDEVPRIVATE + 3)

/*
 * Efx private ioctls
 */

/* For talking MCDI to siena ************************************************/
#define EFX_MCDI_REQUEST 0xef0c
struct efx_mcdi_request {
	__u32 payload[63];
	__u8 cmd;
	__u8 len; /* In and out */
	__u8 rc;
};

/* Reset selected components, like ETHTOOL_RESET ****************************/
#define EFX_RESET_FLAGS 0xef0d
struct efx_reset_flags {
	__u32 flags;
};
#ifndef ETH_RESET_SHARED_SHIFT
	enum ethtool_reset_flags {
		/* These flags represent components dedicated to the interface
		 * the command is addressed to.  Shift any flag left by
		 * ETH_RESET_SHARED_SHIFT to reset a shared component of the
		 * same type.
		 */
	  	ETH_RESET_MGMT		= 1 << 0,	/* Management processor */
		ETH_RESET_IRQ		= 1 << 1,	/* Interrupt requester */
		ETH_RESET_DMA		= 1 << 2,	/* DMA engine */
		ETH_RESET_FILTER	= 1 << 3,	/* Filtering/flow direction */
		ETH_RESET_OFFLOAD	= 1 << 4,	/* Protocol offload */
		ETH_RESET_MAC		= 1 << 5,	/* Media access controller */
		ETH_RESET_PHY		= 1 << 6,	/* Transceiver/PHY */
		ETH_RESET_RAM		= 1 << 7,	/* RAM shared between
							 * multiple components */

		ETH_RESET_DEDICATED	= 0x0000ffff,	/* All components dedicated to
							 * this interface */
		ETH_RESET_ALL		= 0xffffffff,	/* All components used by this
							 * interface, even if shared */
	};
	#define ETH_RESET_SHARED_SHIFT	16
#endif
#ifndef ETHTOOL_RESET
	#define ETHTOOL_RESET           0x00000034
#endif

/* Get RX flow hashing capabilities, like ETHTOOL_GRX{RINGS,FH} *************/
#define EFX_RXNFC 0xef0e
#ifndef ETHTOOL_GRXFH
	#define ETHTOOL_GRXFH		0x00000029
#endif
#ifndef ETHTOOL_GRXRINGS
	#define ETHTOOL_GRXRINGS	0x0000002d
#endif
#ifndef ETHTOOL_GRXCLSRULE
	struct ethtool_tcpip4_spec {
		__be32	ip4src;
		__be32	ip4dst;
		__be16	psrc;
		__be16	pdst;
		__u8    tos;
	};
	#define RX_CLS_FLOW_DISC	0xffffffffffffffffULL
	#define ETHTOOL_GRXCLSRLCNT	0x0000002e
	#define ETHTOOL_GRXCLSRULE	0x0000002f
	#define ETHTOOL_GRXCLSRLALL	0x00000030
	#define ETHTOOL_SRXCLSRLDEL     0x00000031
	#define ETHTOOL_SRXCLSRLINS	0x00000032
#endif
#ifndef EFX_HAVE_EFX_ETHTOOL_RXNFC
	union efx_ethtool_flow_union {
		struct ethtool_tcpip4_spec		tcp_ip4_spec;
		struct ethtool_tcpip4_spec		udp_ip4_spec;
		struct ethtool_tcpip4_spec		sctp_ip4_spec;
		struct ethhdr				ether_spec;
		/* unneeded members omitted... */
		__u8					hdata[60];
	};
	struct efx_ethtool_flow_ext {
		__be16	vlan_etype;
		__be16	vlan_tci;
		__be32	data[2];
	};
	struct efx_ethtool_rx_flow_spec {
		__u32		flow_type;
		union efx_ethtool_flow_union h_u;
		struct efx_ethtool_flow_ext h_ext;
		union efx_ethtool_flow_union m_u;
		struct efx_ethtool_flow_ext m_ext;
		__u64		ring_cookie;
		__u32		location;
	};
	struct efx_ethtool_rxnfc {
		__u32				cmd;
		__u32				flow_type;
		__u64				data;
		struct efx_ethtool_rx_flow_spec	fs;
		__u32				rule_cnt;
		__u32				rule_locs[0];
	};
	#define EFX_HAVE_EFX_ETHTOOL_RXNFC yes
#endif
#ifndef RX_CLS_LOC_SPECIAL
	#define RX_CLS_LOC_SPECIAL	0x80000000
	#define RX_CLS_LOC_ANY		0xffffffff
	#define RX_CLS_LOC_FIRST	0xfffffffe
	#define RX_CLS_LOC_LAST		0xfffffffd
#endif

/* Get/set RX flow hash indirection table, like ETHTOOL_{G,S}RXFHINDIR} *****/
#define EFX_RXFHINDIR 0xef10
#ifndef ETHTOOL_GRXFHINDIR
	struct ethtool_rxfh_indir {
		__u32	cmd;
		/* On entry, this is the array size of the user buffer.  On
		 * return from ETHTOOL_GRXFHINDIR, this is the array size of
		 * the hardware indirection table. */
		__u32	size;
		__u32	ring_index[0];	/* ring/queue index for each hash value */
	};
	#define ETHTOOL_GRXFHINDIR	0x00000038
	#define ETHTOOL_SRXFHINDIR	0x00000039
#endif
struct efx_rxfh_indir {
	struct ethtool_rxfh_indir head;
	__u32 table[128];
};

/* PTP support for NIC time disciplining ************************************/

struct efx_timespec {
	__s64	tv_sec;
	__s32	tv_nsec;
};

#if !defined(EFX_HAVE_NET_TSTAMP)

/* Initialise timestamping, like SIOCHWTSTAMP *******************************/
#define EFX_TS_INIT 0xef12

enum {
	HWTSTAMP_TX_OFF,
	HWTSTAMP_TX_ON,
};

enum {
	HWTSTAMP_FILTER_NONE,
	HWTSTAMP_FILTER_ALL,
	HWTSTAMP_FILTER_SOME,
	HWTSTAMP_FILTER_PTP_V1_L4_EVENT,
	HWTSTAMP_FILTER_PTP_V1_L4_SYNC,
	HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_L4_EVENT,
	HWTSTAMP_FILTER_PTP_V2_L4_SYNC,
	HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_L2_EVENT,
	HWTSTAMP_FILTER_PTP_V2_L2_SYNC,
	HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_EVENT,
	HWTSTAMP_FILTER_PTP_V2_SYNC,
	HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
};

struct hwtstamp_config {
	__u32 flags;
	__u32 tx_type;
	__u32 rx_filter;
};

/* Read any transmit or receive timestamps since the last call **************/
#define EFX_TS_READ 0xef13

struct efx_ts_read {
	__u32 tx_valid;
	struct efx_timespec tx_ts;	
	struct efx_timespec tx_ts_hw;	
	__u32 rx_valid;
	struct efx_timespec rx_ts;
	struct efx_timespec rx_ts_hw;
	__u8 uuid [6];
	__u8 seqid [2];
};
#endif

/* Set the NIC time clock offset ********************************************/
#define EFX_TS_SETTIME 0xef14
struct efx_ts_settime {
	struct efx_timespec ts;	/* In and out */
	__u32 iswrite;		/* 1 == write, 0 == read (only) */
};

/* Adjust the NIC time frequency ********************************************/
#define EFX_TS_ADJTIME 0xef15
struct efx_ts_adjtime {
	__s64 adjustment;	/* Parts per billion, In and out */
	__u32 iswrite;		/* 1 == write, 0 == read (only) */
};

/* Get the NIC-system time skew *********************************************/
#define EFX_TS_SYNC 0xef16
struct efx_ts_sync {
	struct efx_timespec ts;
};

/* Next available cmd number is 0xef17 */

/* Efx private ioctl command structures *************************************/

union efx_ioctl_data {
	struct efx_mcdi_request mcdi_request;
	struct efx_reset_flags reset_flags;
	struct efx_ethtool_rxnfc rxnfc;
	struct efx_rxfh_indir rxfh_indir;
#if !defined(EFX_HAVE_NET_TSTAMP)
	struct hwtstamp_config ts_init;
	struct efx_ts_read ts_read;
#endif
	struct efx_ts_settime ts_settime;
	struct efx_ts_adjtime ts_adjtime;
	struct efx_ts_sync ts_sync;
};

#ifdef EFX_NOT_UPSTREAM
struct efx_ioctl {
	char if_name[IFNAMSIZ];
	/* Command to run */
	__u16 cmd;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));
#endif

struct efx_sock_ioctl {
	/* Command to run */
	__u16 cmd;
	__u16 reserved;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));

#ifdef __KERNEL__
extern int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
			     union efx_ioctl_data __user *data);
#ifdef EFX_NOT_UPSTREAM
extern int efx_control_init(void);
extern void efx_control_fini(void);
#endif
#endif

#endif /* EFX_IOCTL_H */
