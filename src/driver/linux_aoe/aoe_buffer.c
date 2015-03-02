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

void aoe_reset_buffers(struct aoe_map_entry *entry)
{
	entry->response.read_offset = 0;
	entry->response.write_offset = 0;
	entry->response.cmd_len = 0;

	entry->request.read_offset = 0;
	entry->request.write_offset = 0;
	entry->request.cmd_len = 0;
}

void aoe_close_entry(struct aoe_map_entry *entry)
{
	/* First stop any future data comming in */
	if (!entry)
		return;

	if (entry->request.data) {
		kfree(entry->request.data);
		entry->request.data = NULL;
		DPRINTK("Request buffer closed\n");
	}

	if (entry->response.data) {
		kfree(entry->response.data);
		entry->response.data = NULL;
		DPRINTK("Response buffer closed\n");
	}
}

#define DEFAULT_SIZE	(4 * PAGE_SIZE)

int aoe_alloc_entry(struct aoe_map_entry *entry, unsigned int size)
{
	unsigned int buffer_size = DEFAULT_SIZE;

	if (!entry)
		goto out;

	entry->request.size = buffer_size;
	entry->request.data = kzalloc(entry->request.size, GFP_KERNEL);
	if (!entry->request.data)
		goto out;

	entry->response.size = buffer_size;
	entry->response.data = kzalloc(entry->response.size, GFP_KERNEL);
	if (!entry->response.data)
		goto out1;

	aoe_reset_buffers(entry);

	return 0;
out1:
	kfree(entry->request.data);
out:
	return -ENOMEM;
}

int aoe_copy_to_req_buff(struct aoe_map_entry *entry,
			 const char __user *data,
			 unsigned int len)
{
	struct aoe_user_buffer *buffer = &entry->request;

	if (buffer->write_offset + len > buffer->size)
		return -ENOSPC;

	if (copy_from_user(buffer->data + buffer->write_offset,
			   data,
			   len)) {
		DPRINTK("copy_from_user failed\n");
		return -EIO;
	}

	buffer->write_offset += len;
	DPRINTK("Copied TO REQ this time %d, so far %d\n", len, buffer->write_offset);
	return 0;
}

int aoe_copy_from_req_buff(struct aoe_map_entry *entry, void *data, unsigned int len)
{
	struct aoe_user_buffer *buffer = &entry->request;

	memcpy(data,
	       buffer->data + buffer->read_offset,
	       len);

	buffer->read_offset += len;

	return 0;
}

int aoe_copy_to_resp_buff(struct aoe_map_entry *entry, void *data, unsigned int len)
{
	struct aoe_user_buffer *buffer = &entry->response;

	memcpy(buffer->data + buffer->write_offset,
	       data,
	       len);

	buffer->write_offset += len;

	return 0;
}

int aoe_reserve_resp_buff(struct aoe_map_entry *entry, unsigned int len)
{
	struct aoe_user_buffer *buffer = &entry->response;

	if ((buffer->write_offset + len) > buffer->size)
		return -EINVAL;

	buffer->write_offset += len;
	return 0;
}

int aoe_skip_req_buff(struct aoe_map_entry *entry, unsigned int len)
{
	struct aoe_user_buffer *buffer = &entry->request;

	if ((buffer->read_offset + len) > buffer->size)
		return -EINVAL;

	buffer->read_offset += len;
	return 0;
}

int aoe_copy_from_resp_buff(struct aoe_map_entry *entry,
			    char __user *data,
			    unsigned int len,
			    unsigned int *remaining)
{
	struct aoe_user_buffer *buffer = &entry->response;
	*remaining = 0;

	if (len + buffer->read_offset > buffer->size)
		return -EIO;

	if (len + buffer->read_offset > buffer->write_offset)
		len = buffer->write_offset - buffer->read_offset;

	if (copy_to_user(data,
			 buffer->data + buffer->read_offset,
			 len)) {
		DPRINTK("copy to user failed\n");
		return -EIO;
	}

	buffer->read_offset += len;
	DPRINTK("Copied FROM RESP this time %d, so far %d, remaining %d\n",
		len,
		buffer->read_offset,
		buffer->write_offset - buffer->read_offset);

	*remaining = buffer->write_offset - buffer->read_offset;

	return len;
}
