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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"

#define AOE_MIN(x, y)   (x < y ? x : y)

enum aoe_cmd_progress {
	AOE_CMD_REQ_DATA,
	AOE_CMD_CONTINUE,
	AOE_CMD_HANDLED,
	AOE_CMD_INVALID,
};

extern struct aoe_parent_dev *aoe_parent_p;

void aoe_entry_inc(struct aoe_map_entry *entry)
{
	entry->pending++;
}

int aoe_entry_dec(struct aoe_map_entry *entry)
{
	if (!(--entry->pending) && entry->remove) {
		mutex_lock(&entry->close_lock);
		aoe_async_close(entry);
		mutex_unlock(&entry->close_lock);
		return -1;
	}
	return 0;
}

static int aoe_file_open(struct inode *inode_p, struct file *file_p)
{
	int ret;
	struct aoe_map_entry *entry;

	entry = aoe_find_free();
	if (!entry)
		return -ENOSPC;
	
	ret = aoe_alloc_entry(entry, PAGE_SIZE);
	if (ret)
		return ret;

	file_p->private_data = entry;

	return 0;
}

void aoe_async_close(struct aoe_map_entry *entry)
{
	switch (entry->state) {
		case CLOSED:
			return;
		case CLOSING:
		case OPENED:
		case INITIALISED:
		case LENGTH_RECVD:
		case COMMAND_RECVD:
		case DATA_NEEDED:
		case DATA_PENDING:
		case DATA_PENDING_DONE:
		case DATA_PENDING_FAILED:
			break;
		case SENDING:
			entry->remove = true;
			return;
	}

	if (entry->aoe_dev) {
		aoe_remove_stats_entries(entry);
		/* If this is the last entry and reference to the
 		 * device then delete it, cleanup will have been
 		 * done by the driverlink unregistration
 		 */

		aoe_dev_dec_and_unlink_ref(entry->aoe_dev,
					   &entry->dev_list,
					   fd_ref);
	}

	aoe_release_entry(entry);
}

/* Release now does a delayed clenup depending on the state
 * of the file data when the request comes in.
 * If nothing is being handled then close down
 * If it is then tag for a delayed cleanup which will be
 * called by the completion handler from the
 * mcdi thread context.
 */
static int aoe_file_release(struct inode *inode_p, struct file *file_p)
{
	struct aoe_map_entry *entry;

	entry = (struct aoe_map_entry*)file_p->private_data;

	if (!entry)
		return -ENODEV;


	mutex_lock(&entry->close_lock);	

	aoe_async_close(entry);
	file_p->private_data = NULL;

	mutex_unlock(&entry->close_lock);

	return 0;
}

static int check_stream_header(struct aoe_map_entry *entry)
{
	struct aoe_user_buffer *buffer = &entry->request;
	unsigned int header_len = sizeof(struct amm_header);

	if (buffer->write_offset < header_len) {
		entry->state = OPENED;
		return -EAGAIN;
	}
	entry->state = LENGTH_RECVD;
	buffer->cmd_len = header_len;
	DPRINTK("HEADER len is %d, total size now %d\n", header_len, buffer->cmd_len);
	return 0;
}

/* put version check in here */
static int check_cmd_header(struct aoe_map_entry *entry)
{
	unsigned int op_size;
	struct amm_stream_control *request;
	struct amm_header *header;
	struct aoe_user_buffer *buffer = &entry->request;

	request = (struct amm_stream_control*)buffer->data;
	header = &request->header;
	op_size = be32_to_cpu(header->op_len_be);

	if ((buffer->cmd_len + op_size) > buffer->write_offset)
		return -EAGAIN;

	entry->state = COMMAND_RECVD;
	buffer->cmd_len += op_size;
	DPRINTK("OP len is %d, total size now %d\n", op_size, buffer->cmd_len);
	return 0;
}

static enum aoe_cmd_progress check_cmd_data(struct aoe_map_entry *entry)
{
	unsigned int bytes;
	unsigned int required_bytes;
	struct amm_stream_control *request;
	struct aoe_user_buffer *buffer = &entry->request;

	request = (struct amm_stream_control*)buffer->data;

	switch (request->header.op) {
	case AMM_OP_READ_REQUEST:
		bytes = be32_to_cpu(request->read_req.data_len_be);
		required_bytes = buffer->cmd_len;
		entry->response_size = sizeof(request->header) +
				       sizeof(request->read_resp) +
				       bytes;

		DPRINTK("Read Data len is %d\n", bytes);
		break;
	case AMM_OP_WRITE_REQUEST:
		bytes = be32_to_cpu(request->write_req.data_len_be);
		required_bytes = buffer->cmd_len + bytes;
		entry->response_size = sizeof(request->header) +
				       sizeof(request->write_resp);

		DPRINTK("Write Data len is %d\n", bytes);
		break;
	case AMM_OP_READMAPCOUNT_REQUEST:
		required_bytes = buffer->cmd_len;
		entry->response_size = sizeof(request->header) +
				       sizeof(request->read_map_count_resp);
		DPRINTK("Readmap count request\n");
		break;
	case AMM_OP_READMAP_REQUEST:
		required_bytes = buffer->cmd_len;
		entry->response_size = sizeof(request->header) +
				       sizeof(request->read_map_resp);
		DPRINTK("Readmap request\n");
		break;
	default:
		return AOE_CMD_INVALID;
	}

	if ((required_bytes) > buffer->write_offset) {
		DPRINTK("More data needed, %d/%d\n",
			required_bytes,
			buffer->write_offset);
		return AOE_CMD_REQ_DATA;
	}

	return AOE_CMD_CONTINUE;
}

static int aoe_handle_cmd(struct aoe_map_entry *entry)
{
	int ret;
	struct aoe_user_buffer *buffer = &entry->request;
	struct amm_stream_control *request = 
		(struct amm_stream_control*)buffer->data;

	/* at this point we know that we have enough data fully
 	 * process a command
 	 */

	switch (request->header.op) {
	case AMM_OP_READ_REQUEST:
		{
			uint64_t addr = be64_to_cpu(request->read_req.address_be);
			uint32_t len = be32_to_cpu(request->read_req.data_len_be);
			ret = aoe_verify_map_range_lock(entry, addr, len);
		}
		break;
	case AMM_OP_WRITE_REQUEST:
		{
			uint64_t addr = be64_to_cpu(request->write_req.address_be);
			uint32_t len = be32_to_cpu(request->write_req.data_len_be);
			ret = aoe_verify_map_range_lock(entry, addr, len);
		}
		break;
	case AMM_OP_READMAPCOUNT_REQUEST:
		ret = aoe_fetch_map_count(entry);
		break;
	case AMM_OP_READMAP_REQUEST:
		{
			uint32_t index = be32_to_cpu(request->read_map_req.index_be);
			ret = aoe_fetch_map_instance(entry, index);
		}
		break;
	default:
		ret = -EOPNOTSUPP;
	}

	return ret;
}

/* should maybe split this into a proper state machine
 * might not be worth it though */

static ssize_t aoe_file_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	int ret = -EIO;
	enum aoe_cmd_progress cmd_ret;
	struct aoe_map_entry *entry;
	entry = (struct aoe_map_entry*)file->private_data;

	if (!entry || !buf || !count) {
		printk(KERN_ERR "sfc_aoe: invalid write attempted\n");
		return -EBADF;
	}

	/* try and take the lock, if this does not work
 	 * then the release handler has it so exit 
 	 */
	if (!mutex_trylock(&entry->close_lock))
		return -EAGAIN;

	DPRINTK("state = %d\n", entry->state);

	if (entry->state <= OPENED) {
		mutex_unlock(&entry->close_lock);
		return -EINVAL;
	}

	/* copy what we can into the buffer at offset that we last used
 	 * this offset will be reset once a full set of completions comes in,
	 * need to check that we are in greater than SENDING  as if not we could
	 * have been interrupted on the read of the response and do not
	 * want to lose the request
	 */

	if (entry->state >= SENDING) {
		ret = -EIO;
		goto out;
	}

	if ((ret = aoe_copy_to_req_buff(entry, buf, count))) {
		goto fail;
	}
		

	/* This picks up where we were on last write
 	 * and if there is enough data falls though to send
 	 * or at each point returns so more data can come in
 	 */

	switch (entry->state) {
	case INITIALISED:
		if (check_stream_header(entry))
			goto fail;

		DPRINTK("Enough data for STREAM HEADER\n");
	case LENGTH_RECVD:
		if (check_cmd_header(entry))
			goto fail;

		DPRINTK("Enough data for CMD ok\n");
	case COMMAND_RECVD:
		cmd_ret = check_cmd_data(entry);
		switch (cmd_ret) {
		case AOE_CMD_REQ_DATA:
		case AOE_CMD_HANDLED:
			ret = count;
			goto out;
		case AOE_CMD_CONTINUE:
			if ((ret = aoe_handle_cmd(entry))) {
				DPRINTK("send failure %d\n", ret);
				goto fail;
			}
			ret = count;
			goto out;
		case AOE_CMD_INVALID:
		default:
			ret = -EINVAL;
			goto fail;
		}
		goto out;
	case DATA_NEEDED:
		DPRINTK("More data that was needed now in\n");
		if ((ret = entry->continueMessageSend(entry))) {
			DPRINTK("CONT Failure\n");
			goto fail;
		}
		goto out;
	case DATA_PENDING:
	case DATA_PENDING_FAILED:
	case CLOSED:
	case OPENED:
		ret = -EIO;
		goto fail;
	default:
		ret = -EINVAL;
		goto fail;
	}

	/* If we do then pass it on, we only deal with getting an op here
 	 * not how it should be split up by what ever transport is in use
 	 * - we use the more_data flag as flow control */

fail:
	entry->state = INITIALISED;
	aoe_reset_buffers(entry);
	aoe_release_map_lock(entry);
out:
	mutex_unlock(&entry->close_lock);
	return ret;
}

static ssize_t aoe_file_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	int ret = 0;
	struct aoe_map_entry *entry;
	ssize_t to_copy = -EAGAIN;
	entry = (struct aoe_map_entry*)file->private_data;

	if (!entry || !buf || !count) {
		printk(KERN_ERR "sfc_aoe: invalid read attempted\n");
		return -EBADF;
	}

	/* try and take the lock, if this does not work
	 * then the release handler has it so exit 
	 */
	if (!mutex_trylock(&entry->close_lock))
		return -EAGAIN;

	if (entry->state <= OPENED) {
		mutex_unlock(&entry->close_lock);
		return -EINVAL;
	}

	if (file->f_flags & O_NONBLOCK) {
		DPRINTK("Read attempted - NON-blocking\n");
		if (entry->state <= SENDING) {
			DPRINTK("No pending read !!!!\n");
			ret = -EAGAIN;
			goto out;
		}

	} else {
		DPRINTK("Read attempted - Blocking\n");

		while (!aoe_data_result_pending(entry)) {
			if (wait_event_interruptible(entry->read_queue,
						aoe_data_result_pending(entry))) {
				DPRINTK("INT for %d\n", entry->idx);
				ret = -EINTR;
				goto out;
			}
		}
	}

	/* Once the buffer is empty then can call back in with
 	 * continueMessageSend() to get the rest */
	switch (entry->state) {
	case DATA_PENDING:
		DPRINTK("Not handled yet, just return what there is\n");

	case DATA_PENDING_DONE:
		{
		unsigned int remain;
		DPRINTK("All responses back for %d\n", entry->idx);
		to_copy = AOE_MIN(count, entry->response_size);

		ret = aoe_copy_from_resp_buff(entry, buf, to_copy, &remain);

		/* we have had all the response back but not enough data
 		 * so return what there was, not our fault */
		if ((ret != to_copy) || !remain)
			goto reset;
		break;
		}
	case DATA_PENDING_FAILED:
		DPRINTK("Returing failure to user\n");
		ret = entry->mcdi_return_code;
		goto reset;
	case CLOSED:
		ret = -EIO;
		goto reset;
	default:
		DPRINTK("Should never be here\n");
	}

	mutex_unlock(&entry->close_lock);
	return ret;

reset:
	entry->state = INITIALISED;
	aoe_reset_buffers(entry);
out:
	mutex_unlock(&entry->close_lock);
	DPRINTK("ret=%d\n", ret);
	return ret;
}

static unsigned int aoe_file_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	struct aoe_map_entry *entry;
	unsigned int mask = 0;
	entry = (struct aoe_map_entry*)file->private_data;

	if (!mutex_trylock(&entry->close_lock))
		return -ENODEV;

	if (entry->state <= OPENED) {
		mask = -ENODEV;
		goto out;
	}

	poll_wait(file, &entry->poll_queue, wait);

	if (entry->state == INITIALISED) {
		mask |= (POLLOUT | POLLWRNORM);
		goto out;
	}

	if (aoe_data_ready(entry))
		mask |= (POLLIN | POLLRDNORM);

out:
	mutex_unlock(&entry->close_lock);

	return mask;
}

static long control_ioctl(struct file *file, unsigned int req, unsigned long arg)
{
	struct aoe_ioctl __user *user_data = (struct aoe_ioctl __user *)arg;
	u16 aoe_cmd;
	struct aoe_map_entry *entry = (struct aoe_map_entry*)file->private_data;
	long ret;

	if (req != SIOCAOE)
		return -ENOTTY;

	if (!entry)
		return -EBADF;

	if (copy_from_user(&aoe_cmd, &user_data->cmd, sizeof(aoe_cmd)))
		return -EFAULT;

	if (!mutex_trylock(&entry->close_lock))
		return -ENODEV;

	ret = aoe_control_ioctl(entry, aoe_cmd, user_data);
	mutex_unlock(&entry->close_lock);
	return ret;
}

#ifndef HAVE_UNLOCKED_IOCTL
static int control_legacy_ioctl(struct inode *ino, struct file *filp,
				unsigned int req, unsigned long arg)
{
	return (int) control_ioctl(filp, req, arg);
}
#endif

const struct file_operations aoe_file_ops = {
	.owner = THIS_MODULE,
	.open = aoe_file_open,
	.write = aoe_file_write,
	.read = aoe_file_read,
	.poll = aoe_file_poll,
	.release = aoe_file_release,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = control_ioctl,
#else
	.ioctl = control_legacy_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	.compat_ioctl = control_ioctl,
#endif
};
