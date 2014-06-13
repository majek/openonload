/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

#ifndef AOE_IOCTL_H
#define AOE_IOCTL_H

#include <linux/types.h>

#define SIOCAOE (SIOCDEVPRIVATE + 3)

/*
 * AOE private ioctls
 */

/* Deprecated IOCTL __AOE_BIND */
#define __AOE_BIND 0xa0e1

/* Parameters for __AOE_BIND */
struct __aoe_bind_ioctl {
	__u32 ifindex;
	__u32 conn_port;
	__u32 board;
};

#define AOE_LINK_MODE 0xa0e2

/* Parameters for AOE_LINK_MODE */
#define LINK_SEPERATE 0
#define LINK_COMBINED 1
struct aoe_link_mode {
	__u32 mode;
};

#define AOE_DMA_OP 0xa0e3

/* Parameters for AOE_DMA_OP */
enum aoe_dma_op {
	AOE_DMA_OP_ADD = 1,
	AOE_DMA_OP_DEL = 2,
	AOE_DMA_OP_READ = 3,
	AOE_DMA_OP_ENABLE = 4,
};

struct aoe_add_dma {
	__u64 aoe_addr;
	__u32 aoe_len;
	__u32 flags;
	__u32 dma_id;
};

struct aoe_del_dma {
	__u32 dma_id;
};

struct aoe_dma_ts {
	__u64 tv_sec;
	__u32 tv_nsec;
};

struct aoe_dma_times {
	struct aoe_dma_ts raw;
	struct aoe_dma_ts sys;
};

struct aoe_read_dma {
	__u32 dma_id;
	void *buff;
	__u32 read_len;
	struct aoe_dma_times gen_time;
};

struct aoe_enable_dma {
	__u32 dma_id;
	__u32 enable;
	__u32 interval_ms;
	__u16 op_data_offset;
	__u16 op_data;
	__u32 flags;
};

union aoe_dma_data {
	struct aoe_add_dma add;
	struct aoe_del_dma del;
	struct aoe_read_dma read;
	struct aoe_enable_dma enable;
};

struct aoe_dma_req {
	enum aoe_dma_op op_code;
	union aoe_dma_data data;
};

#define AOE_MTU_OP 0xa0e4

#define AOE_MTU_GET 0
#define AOE_MTU_SET 1

struct aoe_mtu_req {
	__u32 req;
	__u32 mtu;
};

#define AOE_BIND 0xa0e5
/* Parameters for AOE_BIND */
#define AOE_BIND_ONCE_PER_DEVICE 0x1
struct aoe_bind_ioctl {
	__u32 ifindex;
	__u32 flags;
	__u32 conn_port;
	__u32 board;
};

#define AOE_NUM_BOARDS 0xa0e6
struct aoe_num_boards_ioctl {
	__u32 num_boards;
};

#define AOE_NUM_PORTS 0xa0e7
struct aoe_num_ports_ioctl {
	__u32 board_id;
	__u32 num_ports;
};

#define AOE_GET_IFINDEX 0xa0e8
struct aoe_get_ifindex_ioctl {
	__u32 board_id;
	__u32 port_id;
	__u32 ifindex;
};

#define AOE_GET_PORT_ID 0xa0e9
struct aoe_get_portid_ioctl {
	__u32 ifindex;
	__u32 board_id;
	__u32 port_id;
};

/* AOE private ioctl command structures *************************************/

union aoe_ioctl_data {
	struct __aoe_bind_ioctl __bind;
	struct aoe_bind_ioctl bind;
	struct aoe_link_mode link_mode;
	struct aoe_dma_req dma;
	struct aoe_mtu_req mtu;
	struct aoe_num_boards_ioctl num_boards;
	struct aoe_num_ports_ioctl num_ports;
	struct aoe_get_ifindex_ioctl get_ifindex;
	struct aoe_get_portid_ioctl get_portid;
};

struct aoe_ioctl {
	/* Command to run */
	__u16 cmd;
	/* Parameters */
	union aoe_ioctl_data u;
} __attribute__ ((packed));

#endif /* AOE_IOCTL_H */
