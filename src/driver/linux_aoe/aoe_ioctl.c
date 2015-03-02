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

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"

static int aoe_bind_fd_to_port(struct aoe_map_entry *entry,
			       struct aoe_bind_ioctl *ioctl)
{
	int ifindex = ioctl->ifindex;
	int conn_port;
	int board;
	int ret;

	if ((ret = aoe_fd_port_bind(entry, ifindex, ioctl->flags, &board, &conn_port)))
		return ret;

	ioctl->board = board;
	ioctl->conn_port = conn_port;

	return 0;
}

static int __aoe_bind_fd_to_port(struct aoe_map_entry *entry,
				 struct __aoe_bind_ioctl *ioctl)
{
	int ifindex = ioctl->ifindex;
	int conn_port;
	int board;
	int ret;

	if ((ret = aoe_fd_port_bind(entry, ifindex, 0, &board, &conn_port)))
		return ret;

	ioctl->board = board;
	ioctl->conn_port = conn_port;

	return 0;
}

static int aoe_change_link_mode(struct aoe_map_entry *entry,
				struct aoe_link_mode *mode)
{
	struct aoe_device *dev = entry->aoe_dev;

	return aoe_mcdi_link_status_split(dev, mode->mode);
}

static int aoe_ioctl_bind_fd_to_port(struct aoe_map_entry *entry,
				     struct aoe_ioctl *ioctl)
{
	if (entry->state != OPENED)
                return -EINVAL;

	return aoe_bind_fd_to_port(entry, &ioctl->u.bind);
}

static int __aoe_ioctl_bind_fd_to_port(struct aoe_map_entry *entry,
				       struct aoe_ioctl *ioctl)
{
	if (entry->state != OPENED)
                return -EINVAL;

	return __aoe_bind_fd_to_port(entry, &ioctl->u.__bind);
}

static int aoe_ioctl_change_link_mode(struct aoe_map_entry *entry,
				      struct aoe_ioctl *ioctl)
{
	if (entry->state < INITIALISED)
                return -EINVAL;

	return aoe_change_link_mode(entry, &ioctl->u.link_mode);
}

static int aoe_handle_dma_op(struct aoe_map_entry *entry,
			     struct aoe_dma_req *req)
{
	/* Copy the data here */
	int ret = 0;

	switch (req->op_code) {
	case AOE_DMA_OP_ADD:
		ret = aoe_setup_stats_entry(entry, &req->data.add);
		break;

	case AOE_DMA_OP_DEL:
		ret = aoe_remove_stats_entry(entry, &req->data.del);
		break;

	case AOE_DMA_OP_READ:
		ret = aoe_copy_stats_entry(entry, &req->data.read);
		break;

	case AOE_DMA_OP_ENABLE:
		ret = aoe_enable_stats_entry(entry, &req->data.enable);
		break;

	default:
		return -EINVAL;
	}

	return ret;
}

static int aoe_ioctl_dma_op(struct aoe_map_entry *entry,
			    struct aoe_ioctl *ioctl)
{
	if (entry->state < INITIALISED)
                return -EINVAL;

	return aoe_handle_dma_op(entry, &ioctl->u.dma);
}

int aoe_handle_mtu_op(struct aoe_map_entry *entry, struct aoe_mtu_req *op)
{
	return aoe_mcdi_set_mtu(entry->port, op->mtu);
}

static int aoe_ioctl_mtu_op(struct aoe_map_entry *entry,
			    struct aoe_ioctl *ioctl)
{
	if (entry->state < INITIALISED)
                return -EINVAL;

	return aoe_handle_mtu_op(entry, &ioctl->u.mtu);
}

static int aoe_ioctl_num_boards(struct aoe_map_entry *entry,
				struct aoe_ioctl *ioctl)
{
	struct aoe_num_boards_ioctl *op = &ioctl->u.num_boards;

	if (entry->state < OPENED)
                return -EINVAL;

	op->num_boards = aoe_get_num_boards();

	return 0;
}

static int aoe_ioctl_num_ports(struct aoe_map_entry *entry,
			       struct aoe_ioctl *ioctl)
{
	struct aoe_num_ports_ioctl *op = &ioctl->u.num_ports;

	if (entry->state < OPENED)
                return -EINVAL;

	return aoe_get_num_ports(op->board_id, &op->num_ports);
}

static int aoe_ioctl_get_ifindex(struct aoe_map_entry *entry,
				 struct aoe_ioctl *ioctl)
{
	struct aoe_get_ifindex_ioctl *op = &ioctl->u.get_ifindex;

	if (entry->state < OPENED)
                return -EINVAL;

	return aoe_get_ifindex(op->board_id, op->port_id, &op->ifindex);
}

static int aoe_ioctl_get_portid(struct aoe_map_entry *entry,
				struct aoe_ioctl *ioctl)
{
	struct aoe_get_portid_ioctl *op = &ioctl->u.get_portid;

	if (entry->state < OPENED)
                return -EINVAL;

	return aoe_get_portid(op->ifindex, &op->board_id, &op->port_id);
}

long aoe_control_ioctl(struct aoe_map_entry *entry, u16 aoe_cmd,
		       struct aoe_ioctl __user *user_data)
{
	struct aoe_ioctl data;
	int (*op)(struct aoe_map_entry *, struct aoe_ioctl *);
	ssize_t size;
	int ret;

	switch (aoe_cmd) {
	case __AOE_BIND:
		op = __aoe_ioctl_bind_fd_to_port;
		size = sizeof(data.u.__bind);
		break;

	case AOE_BIND:
		op = aoe_ioctl_bind_fd_to_port;
		size = sizeof(data.u.bind);
		break;

	case AOE_LINK_MODE:
		op = aoe_ioctl_change_link_mode;
		size = sizeof(data.u.link_mode);
		break;

	case AOE_DMA_OP:
		op = aoe_ioctl_dma_op;
		size = sizeof(data.u.dma);
		break;

	case AOE_MTU_OP:
		op = aoe_ioctl_mtu_op;
		size = sizeof(data.u.mtu);
		break;

	case AOE_NUM_BOARDS:
		op = aoe_ioctl_num_boards;
		size = sizeof(data.u.num_boards);
		break;

	case AOE_NUM_PORTS:
		op = aoe_ioctl_num_ports;
		size = sizeof(data.u.num_ports);
		break;

	case AOE_GET_IFINDEX:
		op = aoe_ioctl_get_ifindex;
		size = sizeof(data.u.get_ifindex);
		break;

	case AOE_GET_PORT_ID:
		op = aoe_ioctl_get_portid;
		size = sizeof(data.u.get_portid);
		break;

	default:
		return -EINVAL;
	}

	if (copy_from_user(&data.u, &user_data->u, size))
		return -EFAULT;

	ret = op(entry, &data);
	if (ret)
		return ret;

	if (copy_to_user(&user_data->u, &data.u, size))
		return -EFAULT;

	return 0;
}
