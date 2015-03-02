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

#include <linux/netdevice.h>
#include <net_driver.h>
#include <mcdi.h>
#include <mcdi_pcol.h>
#include "mcdi_pcol_aoe.h"

#include "aoe.h"

/* Used by the transport to manage progress of buffer send/recv */
struct mcdi_chunking_data {
	unsigned int rx_exp;
	unsigned int rx_recved;
	unsigned int bytes_per_rx;
	unsigned int curr_idx;
	unsigned int bytes_this_msg;
	unsigned int total_data;
	unsigned int data_so_far;
	uint64_t curr_address;
};

#define set_resp_handler(_msg, _handler) (_msg->resp_handler = _handler)
#define set_cont_handler(_msg, _handler) (_msg->cont_handler = _handler)
#define set_encode_handler(_msg, _handler) (_msg->encode_handler = _handler)

#ifndef NDEBUG
void dump_header(struct amm_header *header)
{
	printk(KERN_ERR "op        : %d\n", header->op);
	printk(KERN_ERR "version   : %d\n", header->version);
	printk(KERN_ERR "result    : %d\n", header->result);
	printk(KERN_ERR "reserved  : %d\n", header->reserved);
	printk(KERN_ERR "op_len_be : %d\n", header->op_len_be);
	printk(KERN_ERR "op_len    : %d\n", be32_to_cpu(header->op_len_be));
}
#else
#define dump_header(x)
#endif


static struct aoe_proxy_msg * mcdi_alloc_message(struct aoe_map_entry *e)
{
#define REQUEST_SIZE    256
#define RESPONSE_SIZE   256

	struct aoe_proxy_msg *new_msg;
	int size_to_alloc = REQUEST_SIZE + RESPONSE_SIZE + sizeof(*new_msg);
	new_msg = kmalloc(size_to_alloc, GFP_KERNEL | GFP_ATOMIC);

	if (!new_msg) {
		return NULL;
	}

	new_msg->chunking_data = kmalloc(sizeof(struct mcdi_chunking_data), GFP_KERNEL);
	if (!new_msg->chunking_data) {
		kfree(new_msg);
		return NULL;
	}

	new_msg->request_data = (efx_dword_t *)(new_msg + 1);
	new_msg->response_data = (efx_dword_t *)((uint8_t *)new_msg->request_data +
                                                 REQUEST_SIZE);
	e->messages = new_msg;
	new_msg->parent = e;

	return new_msg;
}

static void free_aoe_msg(struct aoe_proxy_msg *msg)
{
	if (msg) {
		if (msg->parent) {
			msg->parent->messages = NULL;
			msg->parent = NULL;
		}

		if (msg->chunking_data)
			kfree(msg->chunking_data);

		kfree(msg);
	}
}

/* FC WRITE32 handling */

static int decode_fc_write_resp(struct amm_stream_control *req,
				struct amm_stream_control *resp,
				struct aoe_proxy_msg *msg)
{
	struct aoe_map_entry *entry = msg->parent;
	struct mcdi_chunking_data *progress = msg->chunking_data;
	struct amm_ctrl_write_resp *write_resp = &resp->write_resp;
	struct amm_ctrl_write_req *write_req = &req->write_req;

	struct amm_stream_control *in_req = req;

	/* Need to verify that the address back matches the 
 	 * Address that was asked for */

	if (!(progress->rx_recved++)) {
		if (aoe_reserve_resp_buff(entry, sizeof(resp->header) +
					  sizeof(*write_resp)))
			return -EINVAL;

		resp->header.op = AMM_OP_WRITE_RESPONSE;
		if ((!req) && !(&req->header))
			printk(KERN_ERR "Req now bad, was %p", in_req);

		resp->header.version = req->header.version;
		resp->header.result = AMM_RESULT_SUCCESS;

		if ((!req) || !(&req->header))
                        printk(KERN_ERR "Req now bad, was %p", in_req);

		resp->header.reserved = req->header.reserved;
		resp->header.op_len_be = cpu_to_be32(sizeof(*write_resp));

		write_resp->address_be = write_req->address_be;
		write_resp->data_len_be = write_req->data_len_be;
		write_resp->options_be = write_req->options_be;

		dump_header(&resp->header);

	}

	progress->data_so_far += progress->bytes_this_msg;
	progress->curr_address += progress->bytes_this_msg;

	return 0;
}

static void encode_fc_write(struct amm_stream_control *req,
			    struct aoe_proxy_msg *msg,
			    unsigned int data_len)
{
	efx_dword_t *cmd_ptr;
	struct mcdi_chunking_data *progress;
	struct aoe_map_entry *entry = msg->parent;
	unsigned int le_address_lo;
	unsigned int le_address_hi;
	unsigned int len_words = data_len / sizeof(unsigned int);

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	le_address_lo = cpu_to_le64(progress->curr_address);
	le_address_hi = cpu_to_le64(progress->curr_address) >> 32;

	msg->cmd = MC_CMD_FC;
	msg->req_len = MC_CMD_FC_IN_IO_REL_WRITE32_LEN(len_words);
	msg->resp_len = MC_CMD_FC_OUT_IO_REL_WRITE32_LEN;

	MCDI_SET_DWORD(msg->request_data, FC_IN_OP_HDR,
		       MC_CMD_FC_OP_IO_REL);
	cmd_ptr = (efx_dword_t *)MCDI_PTR(msg->request_data, FC_IN_IO_REL_HEADER);
	EFX_POPULATE_DWORD_2(*cmd_ptr,
			     MC_CMD_FC_IN_IO_REL_OP, MC_CMD_FC_IN_IO_REL_WRITE32,
			     MC_CMD_FC_IN_IO_REL_COMP_TYPE, MC_CMD_FC_COMP_TYPE_APP_ADDR_SPACE);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_WRITE32_ADDR_LO,
		       le_address_lo);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_WRITE32_ADDR_HI,
		       le_address_hi);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_WRITE32_BUFFER,
		       len_words);

	aoe_copy_from_req_buff(entry,
			       (uint8_t *)msg->request_data + MC_CMD_FC_IN_IO_REL_WRITE32_BUFFER_OFST,
			       data_len);

	progress->curr_idx++;
	progress->bytes_this_msg = data_len;
}

/* FC READ32 handling */
static int decode_fc_read_resp(struct amm_stream_control *req,
			       struct amm_stream_control *resp,
			       struct aoe_proxy_msg *msg)
{
	struct aoe_map_entry *entry = msg->parent;
	struct mcdi_chunking_data *progress = msg->chunking_data;
	struct amm_ctrl_read_resp *read_resp = &resp->read_resp;
	struct amm_ctrl_read_req *read_req = &req->read_req;

	if (!(progress->rx_recved++)) {
		if (aoe_reserve_resp_buff(entry, sizeof(resp->header) +
						 sizeof(*read_resp)))
			return -EINVAL;

		resp->header.op = AMM_OP_READ_RESPONSE;
		resp->header.version = req->header.version;
		resp->header.result = AMM_RESULT_SUCCESS;
		resp->header.reserved = req->header.reserved;
		resp->header.op_len_be = cpu_to_be32(sizeof(*read_resp));

		read_resp->address_be = read_req->address_be;
		read_resp->data_len_be = read_req->data_len_be;
		read_resp->options_be = read_req->options_be;

		dump_header(&resp->header);
	}

	DPRINTK("Decoding read response %d/%d\n", progress->rx_recved, progress->rx_exp);

	aoe_copy_to_resp_buff(entry, msg->response_data, msg->real_resp);

	progress->data_so_far += msg->real_resp;
	progress->curr_address += msg->real_resp;

	if (msg->real_resp != msg->resp_len) {
		printk(KERN_ERR "Message fragment not as long as expected %d/%d\n",
		       (int)msg->real_resp,
		       (int)msg->resp_len);
		return -EINVAL;
	}

	return 0;
}

//#define FAKE_READ

static void encode_fc_read(struct amm_stream_control *req,
			   struct aoe_proxy_msg *msg,
			   unsigned int data_len)
{
	efx_dword_t *cmd_ptr;
	unsigned int len_words = data_len / sizeof(unsigned int);
	unsigned int le_address_lo;
	unsigned int le_address_hi;
	struct mcdi_chunking_data *progress; 

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	le_address_lo = cpu_to_le64(progress->curr_address);
	le_address_hi = cpu_to_le64(progress->curr_address) >> 32;

	msg->cmd = MC_CMD_FC;
	msg->req_len = MC_CMD_FC_IN_IO_REL_READ32_LEN;
	msg->resp_len = data_len;

	MCDI_SET_DWORD(msg->request_data, FC_IN_OP_HDR,
		       MC_CMD_FC_OP_IO_REL);
	cmd_ptr = (efx_dword_t *)MCDI_PTR(msg->request_data, FC_IN_IO_REL_HEADER);
	EFX_POPULATE_DWORD_2(*cmd_ptr,
			     MC_CMD_FC_IN_IO_REL_OP, MC_CMD_FC_IN_IO_REL_READ32,
			     MC_CMD_FC_IN_IO_REL_COMP_TYPE, MC_CMD_FC_COMP_TYPE_APP_ADDR_SPACE);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_READ32_ADDR_LO,
		       le_address_lo);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_READ32_ADDR_HI,
		       le_address_hi);
	MCDI_SET_DWORD(msg->request_data, FC_IN_IO_REL_READ32_NUMWORDS,
		       len_words);

	progress->curr_idx++;
	progress->bytes_this_msg = data_len;
}

static int continue_fc_request(struct amm_stream_control *req,
			       struct aoe_proxy_msg *msg)
{
	unsigned int data_length;
	unsigned int data_remaining;
	struct mcdi_chunking_data *progress;
	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	data_remaining = progress->total_data - progress->data_so_far;

	if (data_remaining < progress->bytes_per_rx)
		data_length = data_remaining;
	else
		data_length = progress->bytes_per_rx;

	msg->encode_handler(req, msg, data_length);

	return 0;
}

static int decode_fc_mapc_resp(struct amm_stream_control *req,
			       struct amm_stream_control *resp,
			       struct aoe_proxy_msg *msg)
{
	int count;
	struct mcdi_chunking_data *progress;
	progress = (struct mcdi_chunking_data*)msg->chunking_data;
	count = MCDI_DWORD(msg->response_data, FC_OUT_READ_MAP_COUNT_NUM_MAPS);

	aoe_process_map_count_resp(msg->parent, count);

	progress->rx_recved = 1;
	return 0;
}

static void encode_fc_mapc_req(struct amm_stream_control *req,
			       struct aoe_proxy_msg *msg,
			       unsigned int data_len)
{
	msg->cmd = MC_CMD_FC;
	msg->req_len = MC_CMD_FC_IN_READ_MAP_LEN;
	msg->resp_len = MC_CMD_FC_OUT_READ_MAP_COUNT_LEN;
	MCDI_SET_DWORD(msg->request_data, FC_IN_OP_HDR,
		       MC_CMD_FC_OP_READ_MAP);
	MCDI_SET_DWORD(msg->request_data, FC_IN_READ_MAP_HEADER,
		       MC_CMD_FC_OP_READ_MAP_COUNT);
}

#define CONVERT_TO_CPU64(__data, __store, __offset) do { \
	uint32_t __temp_lo = MCDI_DWORD(msg->response_data, __offset ## _LO); \
	uint32_t __temp_hi = MCDI_DWORD(msg->response_data, __offset ## _HI); \
	__store = __temp_hi; \
	__store = __store << 32 | __temp_lo; \
	} while (0)

static int decode_fc_map_index_resp(struct amm_stream_control *req,
				    struct amm_stream_control *resp,
				    struct aoe_proxy_msg *msg)
{
	struct aoe_mmap_entry mmap_entry;
	struct mcdi_chunking_data *progress;
	progress = (struct mcdi_chunking_data*)msg->chunking_data;
	memset(&mmap_entry, 0x0, sizeof(mmap_entry));

	CONVERT_TO_CPU64(msg->response_data, mmap_entry.base_addr,
			FC_OUT_READ_MAP_INDEX_ADDRESS);
	CONVERT_TO_CPU64(msg->response_data, mmap_entry.length,
			FC_OUT_READ_MAP_INDEX_LEN);
	CONVERT_TO_CPU64(msg->response_data, mmap_entry.license_date,
			FC_OUT_READ_MAP_INDEX_LICENSE_DATE);
	mmap_entry.comp_info = MCDI_DWORD(msg->response_data,
					  FC_OUT_READ_MAP_INDEX_COMP_INFO);
	mmap_entry.index = MCDI_DWORD(msg->response_data,
				      FC_OUT_READ_MAP_INDEX_INDEX);
	mmap_entry.options = MCDI_DWORD(msg->response_data,
					FC_OUT_READ_MAP_INDEX_OPTIONS);
	strncpy(mmap_entry.name,
		MCDI_PTR(msg->response_data, FC_OUT_READ_MAP_INDEX_NAME),
		MAP_ENTRY_NAME_LEN);

	aoe_process_map_index_resp(msg->parent, &mmap_entry, true);

	progress->rx_recved = 1;
	return 0;
}

static void encode_fc_map_index_req(struct amm_stream_control *req,
				    struct aoe_proxy_msg *msg,
				    unsigned int data_len)
{
	struct amm_ctrl_read_map_req *read_req = &req->read_map_req;

	msg->cmd = MC_CMD_FC;
	msg->req_len = MC_CMD_FC_IN_READ_MAP_INDEX_LEN;
	msg->resp_len = MC_CMD_FC_OUT_READ_MAP_INDEX_LEN;
	MCDI_SET_DWORD(msg->request_data, FC_IN_OP_HDR,
		       MC_CMD_FC_OP_READ_MAP);
	MCDI_SET_DWORD(msg->request_data, FC_IN_READ_MAP_HEADER,
		       MC_CMD_FC_OP_READ_MAP_INDEX);
	MCDI_SET_DWORD(msg->request_data, FC_IN_MAP_INDEX,
		       be32_to_cpu(read_req->index_be));
}

static int process_fc_map_index_request(struct amm_stream_control *req,
					struct aoe_proxy_msg *msg)
{
	int size = MC_CMD_FC_OUT_READ_MAP_COUNT_LEN;
	struct mcdi_chunking_data *progress;

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	progress->rx_recved = 0;
	progress->curr_idx = 0;
	progress->total_data = size;
	progress->data_so_far = 0;
	progress->curr_address = 0;
	progress->rx_exp = 1;

	set_resp_handler(msg, decode_fc_map_index_resp);
	set_cont_handler(msg, NULL);
	set_encode_handler(msg, encode_fc_map_index_req);

	msg->encode_handler(req, msg, size);

	return progress->rx_exp = 1;
}

static int process_fc_mapc_request(struct amm_stream_control *req,
				   struct aoe_proxy_msg *msg)
{
	int size = 8;

	struct mcdi_chunking_data *progress;

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	progress->rx_recved = 0;
	progress->curr_idx = 0;
	progress->total_data = size;
	progress->data_so_far = 0;
	progress->curr_address = 0;
	progress->rx_exp = 1;

	set_resp_handler(msg, decode_fc_mapc_resp);
	set_cont_handler(msg, NULL);
	set_encode_handler(msg, encode_fc_mapc_req);

	msg->encode_handler(req, msg, size);

	return progress->rx_exp = 1;
}

static int process_fc_write_request(struct amm_stream_control *req,
				    struct aoe_proxy_msg *msg)
{
	struct aoe_map_entry *entry = msg->parent;
	struct amm_ctrl_write_req *write_req = &req->write_req;
	struct mcdi_chunking_data *progress;
	uint32_t total_len_bytes = be32_to_cpu(write_req->data_len_be);
	uint64_t base_address = be64_to_cpu(write_req->address_be);

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	progress->rx_exp = 1;

	progress->bytes_per_rx = MC_CMD_FC_IN_IO_REL_WRITE32_BUFFER_MAXNUM * 4;

	if (total_len_bytes > progress->bytes_per_rx) {
		progress->rx_exp = (total_len_bytes / progress->bytes_per_rx) + 1;
		progress->bytes_this_msg = progress->bytes_per_rx;
	} else
		progress->bytes_this_msg = total_len_bytes;

	aoe_skip_req_buff(entry,
			  sizeof(struct amm_header) + sizeof(*write_req));
				 

	progress->rx_recved = 0;
	progress->curr_idx = 0;
	progress->total_data = total_len_bytes;
	progress->data_so_far = 0;
	progress->curr_address = base_address;

	set_resp_handler(msg, decode_fc_write_resp);
	set_cont_handler(msg, continue_fc_request);
	set_encode_handler(msg, encode_fc_write);

	msg->encode_handler(req, msg, progress->bytes_this_msg);

	return progress->rx_exp;
}

static int process_fc_read_request(struct amm_stream_control *req,
				   struct aoe_proxy_msg *msg)
{
	struct amm_ctrl_read_req *read_req = &req->read_req;
	struct mcdi_chunking_data *progress;
	uint32_t total_len_bytes = be32_to_cpu(read_req->data_len_be);
	uint64_t base_address = be64_to_cpu(read_req->address_be);

	progress = (struct mcdi_chunking_data*)msg->chunking_data;

	progress->rx_exp = 1;

	progress->bytes_per_rx = MC_CMD_FC_OUT_IO_REL_READ32_BUFFER_MAXNUM * 4;

	if (total_len_bytes > progress->bytes_per_rx) {
		progress->rx_exp = (total_len_bytes / progress->bytes_per_rx) + 1;
		progress->bytes_this_msg = progress->bytes_per_rx;
	} else
		progress->bytes_this_msg = total_len_bytes;


	progress->rx_recved = 0;
	progress->total_data = total_len_bytes;
	progress->data_so_far = 0;
	progress->curr_address = base_address;

	set_resp_handler(msg, decode_fc_read_resp);
	set_cont_handler(msg, continue_fc_request);
	set_encode_handler(msg, encode_fc_read);

	msg->encode_handler(req, msg, progress->bytes_this_msg);

	return progress->rx_exp;
}

/* All the encode methods should return at least 1 
 * since there is always a response to a request
 */

static int mcdi_encode_request_msg(struct aoe_map_entry *entry,
				   struct aoe_proxy_msg *msg)
{
	/* Do the encoding for an MCDI proxy request */
	int ret = 0;
	struct amm_stream_control *req;
	req = (struct amm_stream_control*)entry->request.data;

	if (!req || !entry) {
		return -EINVAL;
	}

	switch (req->header.op) {
	case AMM_OP_READ_REQUEST:
		ret = process_fc_read_request(req, msg);
		break;
		
	case AMM_OP_WRITE_REQUEST:
		ret = process_fc_write_request(req, msg);
		break;

	case AMM_OP_READMAPCOUNT_REQUEST:
		ret = process_fc_mapc_request(req, msg);
		break;

	case AMM_OP_READMAP_REQUEST:
		ret = process_fc_map_index_request(req, msg);
		break;

	case AMM_OP_REGISTERNOTIFICATION_REQUEST:
	case AMM_OP_UNREGISTERNOTIFICATION_REQUEST:
	case AMM_OP_NOTIFICATION_IND:
	default:
		printk(KERN_ERR "Unable to handle this type %d\n", req->header.op);
		ret = -EINVAL;
		goto fail;

	}

	DPRINTK("Splitting message into %d\n", ret);

fail:
	return ret;
}

static int mcdi_decode_response_msg(struct aoe_map_entry *entry,
				    struct aoe_proxy_msg *msg)
{
	int ret = 0;
	enum entry_state new_state;
	struct amm_stream_control *resp;
	struct amm_stream_control *req;
	struct mcdi_chunking_data *progress = msg->chunking_data;

	resp = (struct amm_stream_control*)entry->response.data;
	req = (struct amm_stream_control*)entry->request.data;


	if (msg->status != AOE_SUCCESS) {
		new_state = DATA_PENDING_FAILED;
		ret = -EINVAL;
		goto finish;
	}

	if (msg->resp_handler(req, resp, msg)) {
		new_state = DATA_PENDING_FAILED;
		ret = -EINVAL;
		goto finish;
	}

	if (progress->rx_exp != progress->rx_recved) {
		if (msg->cont_handler && msg->cont_handler(resp, msg)) {
			new_state = DATA_NEEDED;
			printk(KERN_ERR "Not enough data to package request\n");
			goto finish;
		}
		else {
			/* send next part, do not release sema until complete */
			new_state = SENDING;
			aoe_qu_add_msg(msg);
			ret = (progress->rx_exp - progress->rx_recved);
			goto finish_ret;
		}
	
	} else {
		new_state = DATA_PENDING_DONE;
		ret = (progress->rx_exp - progress->rx_recved);
	}

finish:
	aoe_release_map_lock(entry);
finish_ret:
	entry->state = new_state;
	entry->mcdi_return_code = msg->mcdi_return_code;
	if (ret <= 0) {
		/* been closed mid transaction */
		if (aoe_entry_dec(entry)) {
			ret = -EINVAL;
			goto error;
		}
	}
//	printk(KERN_ERR "before lock\n");
//	mutex_lock(&entry->close_lock);
//	printk(KERN_ERR "lock taken\n");
//	entry->state = new_state;
//	mutex_unlock(&entry->close_lock);
//	printk(KERN_ERR "back from lock\n");
error:
	return ret;
}

static int mcdi_send_message(struct aoe_map_entry *entry)
{
	int ret;
	struct aoe_proxy_msg *msg;

	if (!entry)
		return -EINVAL;

	msg = mcdi_alloc_message(entry);
	if (!msg)
		return -ENOMEM;

	ret = mcdi_encode_request_msg(entry, msg);

	if (ret <= 0)
		goto error;

	/* Place on send queue */
	entry->state = SENDING;
	ret = aoe_qu_add_msg(msg);
	if (ret)
		goto error;

	return 0;
error:
	free_aoe_msg(msg);
	return ret;
}

/* entry is guarenteed to be valid here under normal operation */
static int mcdi_completion_handler(struct aoe_proxy_msg *msg)
{
	/* If there is nothing more to do for the entry then set
	 * state to DATA_PENDING and set the FD */
	struct aoe_map_entry *entry = msg->parent;

	if (!entry) {
		printk(KERN_ERR "entry failure\n");
		return -EINVAL;
	}

	if (0 >= mcdi_decode_response_msg(entry, msg))
		free_aoe_msg(msg);

	/* If a multi part message has been send and all
	 * the matching responses have been seen then it is
	 * ok to free the send buffer - THIS MAY BE RE-USED later
	 */

	if (entry->state >= DATA_PENDING) {
		wake_up(&entry->read_queue);
		DPRINTK("Wake up sent, state for %d is %d\n", entry->seqno, entry->state);
	} else {
		DPRINTK("Partial message complete, sending next chunk state=%d\n", entry->state);
	}
out:
	return 0;
}

/* No need to process the header in this case, just jump on
 * with packing up the data */
static int mcdi_continue_send_message(struct aoe_map_entry *entry)
{
	/* this just needs to call
 	 * continue_fc_read_request()
	 * continue_fc_write_request() 
	 * this will add anothe message onto the send
	 * queue and then the completion thread will keep
	 * processing this until it stops or
	 * DATA_PENDING_DONE is set */
	return 0;
}

void setup_mcdi_handlers(struct aoe_map_entry *entry)
{
	entry->completeMessageSend = mcdi_completion_handler;
	entry->startMessageSend = mcdi_send_message;
	entry->continueMessageSend = mcdi_continue_send_message;
}

int aoe_mcdi_mac_stats(struct aoe_device *dev,
		       dma_addr_t dma_addr,
		       unsigned int dma_len,
		       int enable, int clear,
		       int index, enum aoe_mac_type type)
{
	struct aoe_proxy_msg msg;
	efx_dword_t *cmd_ptr;
	int period = enable ? 1000 : 0;
	u32 addr_hi;
	u32 addr_lo;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_MAC_STATS_LEN);

	msg.request_data = inbuf;

	addr_lo = ((u64)dma_addr) >> 0;
	addr_hi = ((u64)dma_addr) >> 32;

	if (type == AOE_MAC_INT)
		index += MC_CMD_FC_IN_PORT_INT_OFST;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_MAC_STATS);
	MCDI_SET_DWORD(inbuf, AOE_IN_MAC_STATS_PORT, index);
	
	MCDI_SET_DWORD(inbuf, AOE_IN_MAC_STATS_DMA_ADDR_LO, addr_lo);
	MCDI_SET_DWORD(inbuf, AOE_IN_MAC_STATS_DMA_ADDR_HI, addr_hi);
	cmd_ptr = (efx_dword_t *)MCDI_PTR(inbuf, AOE_IN_MAC_STATS_CMD);
	EFX_POPULATE_DWORD_7(*cmd_ptr,
			MC_CMD_AOE_IN_MAC_STATS_DMA, !!enable,
			MC_CMD_AOE_IN_MAC_STATS_CLEAR, clear,
			MC_CMD_AOE_IN_MAC_STATS_PERIODIC_CHANGE, 1,
			MC_CMD_AOE_IN_MAC_STATS_PERIODIC_ENABLE, !!enable,
			MC_CMD_AOE_IN_MAC_STATS_PERIODIC_CLEAR, 0,
			MC_CMD_AOE_IN_MAC_STATS_PERIODIC_NOEVENT, 1,
			MC_CMD_AOE_IN_MAC_STATS_PERIOD_MS, period);
	MCDI_SET_DWORD(inbuf, AOE_IN_MAC_STATS_DMA_LEN, dma_len);

	msg.cmd = MC_CMD_AOE;
	msg.req_len = MC_CMD_AOE_IN_MAC_STATS_LEN;
	msg.resp_len = 0;

	msg.request_data = inbuf;
	msg.response_data = NULL;

	return aoe_dl_send_block_wait(dev, &msg);
}

unsigned int get_aoe_stats_len(void)
{
	return MC_CMD_MAC_NSTATS * sizeof(u64);
}

static inline void aoe_update_diff_stat(u64 *stat, u64 diff)
{
	if ((s64)(diff - *stat) > 0)
		*stat = diff;
}

#define STATS_GENERATION_INVALID ((__force __le64)(-1))

int aoe_mcdi_update_stats(__le64 *dma_stats, struct aoe_mac_stats *mac_stats)
{

#define MAC_STAT(M, D) \
	mac_stats->M = le64_to_cpu(dma_stats[MC_CMD_MAC_ ## D])

	__le64 generation_start, generation_end;

        generation_end = dma_stats[MC_CMD_MAC_GENERATION_END];
        if (generation_end == STATS_GENERATION_INVALID)
                return 0;
        rmb();

	MAC_STAT(tx_bytes, TX_BYTES);
	MAC_STAT(tx_bad_bytes, TX_BAD_BYTES);
	aoe_update_diff_stat(&mac_stats->tx_good_bytes,
			mac_stats->tx_bytes - mac_stats->tx_bad_bytes);
	MAC_STAT(tx_packets, TX_PKTS);
	MAC_STAT(tx_bad, TX_BAD_FCS_PKTS);
	MAC_STAT(tx_pause, TX_PAUSE_PKTS);
	MAC_STAT(tx_control, TX_CONTROL_PKTS);
	MAC_STAT(tx_unicast, TX_UNICAST_PKTS);
	MAC_STAT(tx_multicast, TX_MULTICAST_PKTS);
	MAC_STAT(tx_broadcast, TX_BROADCAST_PKTS);
	MAC_STAT(tx_lt64, TX_LT64_PKTS);
	MAC_STAT(tx_64, TX_64_PKTS);
	MAC_STAT(tx_65_to_127, TX_65_TO_127_PKTS);
	MAC_STAT(tx_128_to_255, TX_128_TO_255_PKTS);
	MAC_STAT(tx_256_to_511, TX_256_TO_511_PKTS);
	MAC_STAT(tx_512_to_1023, TX_512_TO_1023_PKTS);
	MAC_STAT(tx_1024_to_15xx, TX_1024_TO_15XX_PKTS);
	MAC_STAT(tx_15xx_to_jumbo, TX_15XX_TO_JUMBO_PKTS);
	MAC_STAT(tx_gtjumbo, TX_GTJUMBO_PKTS);
	mac_stats->tx_collision = 0;
	MAC_STAT(tx_single_collision, TX_SINGLE_COLLISION_PKTS);
	MAC_STAT(tx_multiple_collision, TX_MULTIPLE_COLLISION_PKTS);
	MAC_STAT(tx_excessive_collision, TX_EXCESSIVE_COLLISION_PKTS);
	MAC_STAT(tx_deferred, TX_DEFERRED_PKTS);
	MAC_STAT(tx_late_collision, TX_LATE_COLLISION_PKTS);
	mac_stats->tx_collision = (mac_stats->tx_single_collision +
			mac_stats->tx_multiple_collision +
			mac_stats->tx_excessive_collision +
			mac_stats->tx_late_collision);
	MAC_STAT(tx_excessive_deferred, TX_EXCESSIVE_DEFERRED_PKTS);
	MAC_STAT(tx_non_tcpudp, TX_NON_TCPUDP_PKTS);
	MAC_STAT(tx_mac_src_error, TX_MAC_SRC_ERR_PKTS);
	MAC_STAT(tx_ip_src_error, TX_IP_SRC_ERR_PKTS);
	MAC_STAT(rx_bytes, RX_BYTES);
	MAC_STAT(rx_bad_bytes, RX_BAD_BYTES);
	aoe_update_diff_stat(&mac_stats->rx_good_bytes,
			mac_stats->rx_bytes - mac_stats->rx_bad_bytes);
	MAC_STAT(rx_packets, RX_PKTS);
	MAC_STAT(rx_good, RX_GOOD_PKTS);
	MAC_STAT(rx_bad, RX_BAD_FCS_PKTS);
	MAC_STAT(rx_pause, RX_PAUSE_PKTS);
	MAC_STAT(rx_control, RX_CONTROL_PKTS);
	MAC_STAT(rx_unicast, RX_UNICAST_PKTS);
	MAC_STAT(rx_multicast, RX_MULTICAST_PKTS);
	MAC_STAT(rx_broadcast, RX_BROADCAST_PKTS);
	MAC_STAT(rx_lt64, RX_UNDERSIZE_PKTS);
	MAC_STAT(rx_64, RX_64_PKTS);
	MAC_STAT(rx_65_to_127, RX_65_TO_127_PKTS);
	MAC_STAT(rx_128_to_255, RX_128_TO_255_PKTS);
	MAC_STAT(rx_256_to_511, RX_256_TO_511_PKTS);
	MAC_STAT(rx_512_to_1023, RX_512_TO_1023_PKTS);
	MAC_STAT(rx_1024_to_15xx, RX_1024_TO_15XX_PKTS);
	MAC_STAT(rx_15xx_to_jumbo, RX_15XX_TO_JUMBO_PKTS);
	MAC_STAT(rx_gtjumbo, RX_GTJUMBO_PKTS);
	mac_stats->rx_bad_lt64 = 0;
	mac_stats->rx_bad_64_to_15xx = 0;
	mac_stats->rx_bad_15xx_to_jumbo = 0;
	MAC_STAT(rx_bad_gtjumbo, RX_JABBER_PKTS);
	MAC_STAT(rx_overflow, RX_OVERFLOW_PKTS);
	mac_stats->rx_missed = 0;
	MAC_STAT(rx_false_carrier, RX_FALSE_CARRIER_PKTS);
	MAC_STAT(rx_symbol_error, RX_SYMBOL_ERROR_PKTS);
	MAC_STAT(rx_align_error, RX_ALIGN_ERROR_PKTS);
	MAC_STAT(rx_length_error, RX_LENGTH_ERROR_PKTS);
	MAC_STAT(rx_internal_error, RX_INTERNAL_ERROR_PKTS);
	mac_stats->rx_good_lt64 = 0;

	rmb();
        generation_start = dma_stats[MC_CMD_MAC_GENERATION_START];
        if (generation_end != generation_start)
                return -EAGAIN;

	return 0;
}

static int aoe_mcdi_fc_info(struct aoe_device *dev, struct aoe_dev_info *info)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_GET_VERSION_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_GET_VERSION_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_GET_VERSION);

	msg.cmd = MC_CMD_FC;
        msg.req_len = MC_CMD_FC_IN_GET_VERSION_LEN;
        msg.resp_len = MC_CMD_FC_OUT_GET_VERSION_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	/* Fpga version can be obtained from here as well but it does
	 * not have the major.minor.build format and so is of less use
	 */
	info->fc_version[0] = MCDI_DWORD(msg.response_data,
					 FC_OUT_GET_VERSION_VERSION_LO);
	info->fc_version[1] = MCDI_DWORD(msg.response_data,
					 FC_OUT_GET_VERSION_VERSION_HI);

	return 0;
}

static int aoe_mcdi_aoe_info(struct aoe_device *dev, struct aoe_dev_info *info)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_INFO_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_AOE_OUT_INFO_LEN);
	uint32_t flags;

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_INFO);

	msg.cmd = MC_CMD_AOE;
	msg.req_len = MC_CMD_AOE_IN_INFO_LEN;
	msg.resp_len = MC_CMD_AOE_OUT_INFO_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	/* Fpga version can be obtained from here as well but it does
 	 * not have the major.minor.build format and so is of less use
 	 */
	info->cpld_version = MCDI_DWORD(msg.response_data,
					AOE_OUT_INFO_CPLD_VERSION);
	info->board_rev = MCDI_DWORD(msg.response_data,
				      AOE_OUT_INFO_BOARD_REVISION);
	flags = MCDI_DWORD(msg.response_data,
				      AOE_OUT_INFO_FLAGS);

	info->peg_power = ((flags & MC_CMD_AOE_OUT_INFO_PEG_POWER) != 0);
	info->cpld_good = ((flags & MC_CMD_AOE_OUT_INFO_CPLD_GOOD) != 0);
	info->fpga_good = ((flags & MC_CMD_AOE_OUT_INFO_FPGA_GOOD) != 0);
	info->fpga_power = ((flags & MC_CMD_AOE_OUT_INFO_FPGA_POWER) != 0);
	info->bad_sodimm = ((flags & MC_CMD_AOE_OUT_INFO_BAD_SODIMM) != 0);
	info->has_byteblaster =
			((flags & MC_CMD_AOE_OUT_INFO_HAS_BYTEBLASTER) != 0);
	flags = MCDI_DWORD(msg.response_data, AOE_OUT_INFO_FC_STATE);
	info->fc_running = flags ? true : false;
	info->boot_result = MCDI_DWORD(msg.response_data, AOE_OUT_INFO_FC_BOOT_RESULT);

	return 0;
}

#define COMP_FIELD(_buf, _field1, _field2) \
	EFX_EXTRACT_DWORD(*(efx_dword_t*)&((u8*)_buf)[MC_CMD_##_field1##_OFST], \
			  MC_CMD_##_field2##_LBN, \
			  MC_CMD_##_field2##_LBN + MC_CMD_##_field2##_WIDTH - 1)

#define BITFIELD_GET(_dword, _field) \
        EFX_EXTRACT_DWORD(*(efx_dword_t *)&_dword, \
			  MC_CMD_##_field##_LBN, \
			  MC_CMD_##_field##_LBN + MC_CMD_##_field##_WIDTH - 1)


static int aoe_mcdi_fpga_info(struct aoe_device *dev, struct aoe_dev_info *info)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_FPGA_BUILD_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_FPGA_BUILD_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_FPGA_BUILD);
	MCDI_SET_DWORD(inbuf, FC_IN_FPGA_BUILD_OP, MC_CMD_FC_IN_FPGA_BUILD_BUILD);

	msg.cmd = MC_CMD_FC;
	msg.req_len = MC_CMD_FC_IN_FPGA_BUILD_LEN;
	msg.resp_len = MC_CMD_FC_OUT_FPGA_BUILD_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	info->fpga_compid = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_COMPONENT_INFO,
				       FC_OUT_FPGA_BUILD_COMPONENT_ID);
	info->fpga_major = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_VERSION_HI,
					FC_OUT_FPGA_BUILD_DEPLOYMENT_VERSION_MAJOR);

	if (info->fpga_major == 0) {
		/* Old versioning scheme where version number was of the form A.B.C */
		info->fpga_major = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_COMPONENT_INFO,
				      FC_OUT_FPGA_BUILD_VERSION_MAJOR);
		info->fpga_minor = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_COMPONENT_INFO,
					FC_OUT_FPGA_BUILD_VERSION_MINOR);
		info->fpga_micro = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_COMPONENT_INFO,
					FC_OUT_FPGA_BUILD_BUILD_NUM);
		info->fpga_build = 0;
	} else {
		/* Current versioning scheme where version number is of the form A.B.C.D */
		info->fpga_minor = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_VERSION_HI,
					FC_OUT_FPGA_BUILD_DEPLOYMENT_VERSION_MINOR);
		info->fpga_micro = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_VERSION_LO,
					FC_OUT_FPGA_BUILD_DEPLOYMENT_VERSION_MICRO);
		info->fpga_build = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_VERSION_LO,
					FC_OUT_FPGA_BUILD_DEPLOYMENT_VERSION_BUILD);
	}
	info->fpga_type = COMP_FIELD(outbuf, FC_OUT_FPGA_BUILD_PARAMETERS,
				     FC_OUT_FPGA_BUILD_FPGA_TYPE);

	info->fpga_build_revision = COMP_FIELD(outbuf,
					       FC_OUT_FPGA_BUILD_IDENTIFIER,
					       FC_OUT_FPGA_BUILD_CHANGESET);
	info->fpga_build_type = COMP_FIELD(outbuf,
					   FC_OUT_FPGA_BUILD_IDENTIFIER,
					   FC_OUT_FPGA_BUILD_BUILD_FLAG);
	info->fpga_build_changeset[0] = MCDI_DWORD(outbuf,
						   FC_OUT_FPGA_BUILD_REVISION_LO);
	info->fpga_build_changeset[1] = COMP_FIELD(outbuf,
						   FC_OUT_FPGA_BUILD_REVISION_HI,
						   FC_OUT_FPGA_BUILD_REVISION_HIGH);
	return 0;
}

static int aoe_mcdi_fpga_services_info(struct aoe_device *dev, struct aoe_dev_info *info)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_FPGA_BUILD_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_FPGA_SERVICES_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_FPGA_BUILD);
	MCDI_SET_DWORD(inbuf, FC_IN_FPGA_BUILD_OP, MC_CMD_FC_IN_FPGA_BUILD_SERVICES);

	msg.cmd = MC_CMD_FC;
	msg.req_len = MC_CMD_FC_IN_FPGA_BUILD_LEN;
	msg.resp_len = MC_CMD_FC_OUT_FPGA_SERVICES_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	info->fpga_compid = COMP_FIELD(outbuf, FC_OUT_FPGA_SERVICES_COMPONENT_INFO,
				       FC_OUT_FPGA_SERVICES_COMPONENT_ID);
	info->fpga_minor = COMP_FIELD(outbuf, FC_OUT_FPGA_SERVICES_COMPONENT_INFO,
                                      FC_OUT_FPGA_SERVICES_VERSION_MINOR);
	info->fpga_build = COMP_FIELD(outbuf, FC_OUT_FPGA_SERVICES_COMPONENT_INFO,
                                      FC_OUT_FPGA_SERVICES_BUILD_NUM);
	info->fpga_major = COMP_FIELD(outbuf, FC_OUT_FPGA_SERVICES_COMPONENT_INFO,
				      FC_OUT_FPGA_SERVICES_VERSION_MAJOR);

	info->fpga_build_revision = COMP_FIELD(outbuf,
					       FC_OUT_FPGA_SERVICES_IDENTIFIER,
					       FC_OUT_FPGA_SERVICES_CHANGESET);
	info->fpga_build_type = COMP_FIELD(outbuf,
					   FC_OUT_FPGA_SERVICES_IDENTIFIER,
					   FC_OUT_FPGA_SERVICES_BUILD_FLAG);
	info->fpga_build_changeset[0] = MCDI_DWORD(outbuf,
						   FC_OUT_FPGA_SERVICES_REVISION_LO);
	info->fpga_build_changeset[1] = COMP_FIELD(outbuf,
						   FC_OUT_FPGA_SERVICES_REVISION_HI,
						   FC_OUT_FPGA_SERVICES_REVISION_HIGH);
	return 0;
}

static int aoe_mcdi_fpga_bsp_info(struct aoe_device *dev, struct aoe_dev_info *info)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_FPGA_BUILD_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_BSP_VERSION_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_FPGA_BUILD);
	MCDI_SET_DWORD(inbuf, FC_IN_FPGA_BUILD_OP, MC_CMD_FC_IN_FPGA_BUILD_BSP_VERSION);

	msg.cmd = MC_CMD_FC;
	msg.req_len = MC_CMD_FC_IN_FPGA_BUILD_LEN;
	msg.resp_len = MC_CMD_FC_OUT_BSP_VERSION_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	info->fpga_bsp_version = MCDI_DWORD(outbuf, FC_OUT_BSP_VERSION_SYSID);
	info->fpga_major = COMP_FIELD(outbuf, FC_OUT_BSP_VERSION_SYSID,
				FC_OUT_BSP_VERSION_VERSION_MAJOR);
	info->fpga_minor = COMP_FIELD(outbuf, FC_OUT_BSP_VERSION_SYSID,
				FC_OUT_BSP_VERSION_VERSION_MINOR);
	info->fpga_build = COMP_FIELD(outbuf, FC_OUT_BSP_VERSION_SYSID,
				FC_OUT_BSP_VERSION_BUILD_NUM);
	return 0;
}

int aoe_mcdi_fpga_version(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_fpga_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%2X:%d:%d.%d.%d.%d\n",
			info.fpga_type, info.fpga_compid,
                        info.fpga_major, info.fpga_minor, info.fpga_micro, info.fpga_build);
}

int aoe_mcdi_fpga_services_version(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_fpga_services_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d:%d.%d.%d\n",
			info.fpga_compid,
                        info.fpga_major, info.fpga_minor, info.fpga_build);
}

int aoe_mcdi_fpga_build_changeset(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_fpga_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%s:%d:%4x%8x\n",
			(info.fpga_build_type)? "Release":"Internal",
			info.fpga_build_revision,
			info.fpga_build_changeset[1],
			info.fpga_build_changeset[0]);
}

int aoe_mcdi_fpga_services_changeset(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_fpga_services_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%s:%d:%4x%8x\n",
			(info.fpga_build_type)? "Release":"Internal",
			info.fpga_build_revision,
			info.fpga_build_changeset[1],
			info.fpga_build_changeset[0]);
}

int aoe_mcdi_fpga_bsp_version(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_fpga_bsp_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d:%d.%d.%d\n",
			info.fpga_bsp_version, info.fpga_major, info.fpga_minor, info.fpga_build);
}

int aoe_mcdi_cpld_version(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.cpld_version);
}

int aoe_mcdi_board_revision(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	switch (info.board_rev) {
	case MC_CMD_AOE_OUT_INFO_R1_0:
		return snprintf(buf, PAGE_SIZE, "R1.0\n");
	case MC_CMD_AOE_OUT_INFO_R1_1:
		return snprintf(buf, PAGE_SIZE, "R1.1\n");
	case MC_CMD_AOE_OUT_INFO_R1_2:
		return snprintf(buf, PAGE_SIZE, "R1.2\n");
	default:
		return snprintf(buf, PAGE_SIZE, "Unknown\n");
	}
}

int aoe_mcdi_fc_version(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	uint16_t *version;
	ret = aoe_mcdi_fc_info(dev, &info);
	if (ret)
		return ret;

	version = (uint16_t*)info.fc_version;
	return snprintf(buf, PAGE_SIZE, "%d.%d.%d.%.4d\n",
			le16_to_cpu(version[0]),
			le16_to_cpu(version[1]),
			le16_to_cpu(version[2]),
			le16_to_cpu(version[3]));
}

int aoe_mcdi_link_status_split(struct aoe_device *dev, uint32_t mode)
{
	struct aoe_proxy_msg msg;
	int ret;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_LINK_STATE_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_LINK_STATE);
	MCDI_SET_DWORD(inbuf, AOE_IN_LINK_STATE_MODE, mode);

	msg.cmd = MC_CMD_AOE;
	msg.req_len = MC_CMD_AOE_IN_LINK_STATE_LEN;
	msg.resp_len = 0;

	msg.request_data = inbuf;
	msg.response_data = NULL;

	if ((ret = aoe_dl_send_block_wait(dev, &msg)))
		return ret;

	return 0;
}

/* MACRO defining a per-device message */
#define fpga_event(_dev, fmt, args...) \
  printk(KERN_INFO "sfc_aoe: FPGA%d: " fmt "\n",  _dev->board, ##args);

/* sfc net driver style MACRO defining a per-port message */
#define port_event(port, fmt, args...) \
  printk(KERN_INFO "sfc_aoe: " fmt " ifindex=%d\n",  ##args, port->ifindex);

int aoe_mcdi_set_siena_override(struct aoe_device *dev, bool override)
{
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_SIENA_STATS_LEN);

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_SIENA_STATS);
	MCDI_SET_DWORD(inbuf, AOE_IN_SIENA_STATS_MODE, override == true ? 
		       MC_CMD_AOE_IN_SIENA_STATS_STATS_AOE :
		       MC_CMD_AOE_IN_SIENA_STATS_STATS_SIENA);

	msg.cmd = MC_CMD_AOE;
	msg.req_len = MC_CMD_AOE_IN_SIENA_STATS_LEN;
	msg.resp_len = 0;

	msg.request_data = inbuf;
	msg.response_data = NULL;

	return aoe_dl_send_block_wait(dev, &msg);
}

static const char* aoe_fc_err(int rc)
{
        switch (rc) {
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_NO_ERROR:
                return "No Error";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_ADDRESS:
                return "Bad address set in CPLD";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_MAGIC:
                return "Bad header";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_TEXT:
                return "Bad text section details";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_CHECKSUM:
                return "Bad checksum";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_BSP:
                return "Bad BSP";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_APP_EXECUTE:
                return "FC application loaded and execution attempted";
        case MC_CMD_AOE_OUT_INFO_FC_BOOT_NO_BOOTROM:
                return "No Bootrom in FPGA image";
        default:
                return "Unknown error";
        }
}

void aoe_mcdi_ddr_ecc_status(struct aoe_device *dev,
			     struct aoe_ddr_ecc_work_params_s *params)
{
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_DDR_ECC_STATUS_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_AOE_OUT_DDR_ECC_STATUS_LEN);
	int ret = 0;
	uint32_t status;
	uint8_t bank_id = params->bank_id;

	msg.request_data = inbuf;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_DDR_ECC_STATUS);
	MCDI_SET_DWORD(inbuf, AOE_IN_DDR_ECC_STATUS_BANK, bank_id);

	msg.cmd = MC_CMD_AOE;
	msg.req_len = MC_CMD_AOE_IN_DDR_ECC_STATUS_LEN;
	msg.resp_len = MC_CMD_AOE_OUT_DDR_ECC_STATUS_LEN;

	msg.request_data = inbuf;
	msg.response_data = outbuf;

	ret = aoe_dl_send_block_wait(dev, &msg);
	if (ret)
		printk(KERN_ERR "sfc_aoe: read DDR ECC status failed %d\n", ret);

	if (COMP_FIELD(outbuf, AOE_OUT_DDR_ECC_STATUS_FLAGS, AOE_OUT_DDR_ECC_STATUS_VALID)) {

		status = MCDI_DWORD(outbuf, AOE_OUT_DDR_ECC_STATUS_STATUS);

		if (BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_SBE))
			fpga_event(dev, "DDR Slot#%d(%s) Single-bit error_count = %d",
			       bank_id, dimm_bank_name[bank_id],
			       BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_SBE_COUNT));
		if (BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_DBE))
			fpga_event(dev, "DDR Slot#%d(%s) Double-bit error_count = %d",
			       bank_id, dimm_bank_name[bank_id],
			       BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_DBE_COUNT));
		if (BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_CORDROP))
			fpga_event(dev, "DDR Slot#%d(%s) Cordrop error_count = %d",
			       bank_id, dimm_bank_name[bank_id],
			       BITFIELD_GET(status, AOE_OUT_DDR_ECC_STATUS_CORDROP_COUNT));
	}
}

static void aoe_ddr_ecc_status_event(struct aoe_port_info *nic_port, uint8_t bank_id)
{
	struct aoe_device *dev = nic_port->aoe_parent;
	struct aoe_ddr_ecc_work_params_s *work_params =
		&(dev->aoe_event_work.work_params.ddr_ecc_work_params);

	work_params->bank_id = bank_id;

	dev->aoe_event_work.work_type = AOE_WORK_DDR_ECC;
	queue_work(dev->event_workwq, &dev->aoe_event_work.event_work);
	fpga_event(dev,
		   "DDR ECC status update on bank#%d(%s)",
		   bank_id, dimm_bank_name[bank_id])
}

static const char* ptp_event_code_string(int32_t data)
{
      switch(data)
      {
        case FCDI_EVENT_PTP_OPERATIONAL:
          return "PTP operational.\n";
        case FCDI_EVENT_PTP_SETUP_FAILED:
          return "PTP setup failed.\n";
        case FCDI_EVENT_PTP_UNDEFINED:
          return "PTP not present.\n";
        default:
          return "PTP status unknown; value passed up from FC does not match known codes.\n";
      }
}

bool aoe_handle_mcdi_event(struct aoe_port_info *nic_port, void *p_event)
{
  efx_qword_t *event = p_event;
  int32_t code = MCDI_EVENT_FIELD(*event, CODE);
  int32_t aoe_code;
  struct aoe_device *dev = nic_port->aoe_parent;

  if (MCDI_EVENT_CODE_AOE != code)
    return false;

  /* We do not have any per-port AOE events at the moment.
   * So ignore any events on ports other than port0 as duplicates
   */
  if (AOE_PHYS_PORT(nic_port) != 0)
    return true;

  aoe_code = MCDI_EVENT_FIELD(*event, AOE_ERR_TYPE);

  switch(aoe_code) {
  case MCDI_EVENT_AOE_NO_LOAD:
    fpga_event(dev, "AOE image failed to load");
    if (waitqueue_active(&dev->event_queue)) {
      dev->state = FPGA_ON;
      wake_up(&dev->event_queue);
    }
    break;
  case MCDI_EVENT_AOE_FC_ASSERT:
    fpga_event(dev, "AOE FC triggered Assert");
    break;
  case MCDI_EVENT_AOE_FC_WATCHDOG:
    fpga_event(dev, "AOE FC watchdog timeout");
    break;
  case MCDI_EVENT_AOE_FC_NO_START:
                fpga_event(dev, "AOE FC failed to start - Error %d (%s)",
                           (unsigned int)MCDI_EVENT_FIELD(*event, AOE_ERR_DATA),
                           aoe_fc_err((unsigned int)MCDI_EVENT_FIELD(*event, AOE_ERR_DATA)));
                break;
  case MCDI_EVENT_AOE_FAULT:
    fpga_event(dev, "AOE General fault");
    break;
  case MCDI_EVENT_AOE_LOAD:
    fpga_event(dev, "AOE FPGA Image loaded");

    if (waitqueue_active(&dev->event_queue)) {
      dev->state = FPGA_LOADED;
      wake_up(&dev->event_queue);
    }
    /* Apply configuration after a reload */
    dev->aoe_event_work.work_type = AOE_WORK_RELOAD;
    dev->aoe_event_work.work_params.reload_work_params.null_param = NULL;
    queue_work(dev->event_workwq, &dev->aoe_event_work.event_work);
    break;
  case MCDI_EVENT_AOE_BYTEBLASTER:
    fpga_event(dev, "AOE byteblaster %s",
                           (MCDI_EVENT_FIELD(*event, AOE_ERR_DATA))? "connected" : "disconnected");
                break;
  case MCDI_EVENT_AOE_DDR_ECC_STATUS:
    aoe_ddr_ecc_status_event(nic_port,
           MCDI_EVENT_FIELD(*event, AOE_ERR_DATA));
                break;
  case MCDI_EVENT_AOE_PTP_STATUS:
    {
      int32_t data = (MCDI_EVENT_FIELD(*event, AOE_ERR_DATA));
      fpga_event(dev, "%s", ptp_event_code_string(data));
                break;
    }

  default:
   printk(KERN_INFO "sfc_aoe: Unhandled event type=%d\n",
           aoe_code);
    return false;
  }

  return true;
}

int aoe_mcdi_fpga_reload(struct aoe_device *dev, int partition)
{
	int status;
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_LOAD_LEN);

	msg.request_data = inbuf;
	msg.cmd = MC_CMD_AOE;
	msg.response_data = NULL;
	msg.resp_len = 0;
	msg.req_len = MC_CMD_AOE_IN_LOAD_LEN;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_LOAD);
	MCDI_SET_DWORD(inbuf, AOE_IN_LOAD_IMAGE, partition);

	printk(KERN_INFO "sfc_aoe: Attempting load of %s image\n",
               partition ? "Backup" : "Main");

	dev->state = FPGA_RESET;

	if ((status = aoe_dl_send_block_wait(dev, &msg)) != 0)
		dev->state = FPGA_ON;

	return status;
}

int aoe_mcdi_timed_read(struct aoe_device *dev,
			struct aoe_dma_area *dma,
			uint16_t op_data,
			uint16_t op_data_offset,
			uint32_t interval,
			bool set)
{
	struct aoe_proxy_msg msg;
	int ret;
	/* These are the max sizes */
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_TIMED_READ_SET_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_TIMED_READ_GET_LEN);

	msg.request_data = inbuf;
	msg.response_data = outbuf;
	msg.req_len = MC_CMD_FC_IN_TIMED_READ_LEN;
	msg.cmd = MC_CMD_FC;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_TIMED_READ);
	MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_OP,
		       set ? MC_CMD_FC_IN_TIMED_READ_SET :
			MC_CMD_FC_IN_TIMED_READ_GET);

	if (set) {
		uint32_t low_addr = (uint32_t)(dma->aoe_addr);
		uint32_t high_addr = (uint32_t)(dma->aoe_addr >> 32);
		efx_dword_t *cmd_ptr;
		int32_t indirect = dma->flags ? 0 : 1;
		uint64_t dh;

		cmd_ptr = (efx_dword_t *)MCDI_PTR(msg.request_data,
						  FC_IN_TIMED_READ_SET_FLAGS);
		EFX_POPULATE_DWORD_2(*cmd_ptr,
				     MC_CMD_FC_IN_TIMED_READ_SET_INDIRECT, indirect,
				     MC_CMD_FC_IN_TIMED_READ_SET_PREREAD,
					op_data_offset ? MC_CMD_FC_IN_TIMED_READ_SET_READWRITE :
					MC_CMD_FC_IN_TIMED_READ_SET_NONE);

		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_HOST_HANDLE,
			       dma->id);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_AOE_ADDRESS_LO,
			       low_addr);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_AOE_ADDRESS_HI,
			       high_addr);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_OFFSET,
			       op_data_offset);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_DATA,
			       op_data);

		dh = (uint64_t)dma->dma_handle;
		low_addr = (uint32_t)dh;
		high_addr = (uint32_t)(dh >> 32);

		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_HOST_DMA_ADDRESS_LO,
			       low_addr);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_HOST_DMA_ADDRESS_HI,
			       high_addr);

		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_AOE_LENGTH,
			       dma->aoe_len);
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_HOST_LENGTH,
			       dma->len / 2);

		
		MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_PERIOD,
			       interval);

		msg.resp_len = MC_CMD_FC_OUT_TIMED_READ_SET_LEN;
		msg.req_len = MC_CMD_FC_IN_TIMED_READ_SET_LEN;
		
	} else {
		msg.resp_len = MC_CMD_FC_OUT_TIMED_READ_GET_LEN;
		msg.req_len = MC_CMD_FC_IN_TIMED_READ_GET_LEN;
		/* Not really bothered about the get as far as I can tell at the moment */
	}

	ret = aoe_dl_send_block_wait(dev, &msg);

	if (ret)
		printk(KERN_ERR "sfc_aoe: async stats setup failed %d\n", ret);

	return ret;
}

int aoe_mcdi_clear_timed_read(struct aoe_device *dev,
			      struct aoe_dma_area *area)
{
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_TIMED_READ_CLEAR_LEN);

	msg.request_data = inbuf;
	msg.response_data = NULL;
	msg.req_len = MC_CMD_FC_IN_TIMED_READ_CLEAR_LEN;
	msg.resp_len = 0;
	msg.cmd = MC_CMD_FC;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_TIMED_READ);
	MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_OP,
		       MC_CMD_FC_IN_TIMED_READ_CLEAR);
	MCDI_SET_DWORD(inbuf, FC_IN_TIMED_READ_SET_HOST_HANDLE,
		       area->id);

	aoe_dl_send_block_wait(dev, &msg);

	return 0;
}

int aoe_mcdi_set_mtu(struct aoe_port_info *port, uint32_t aoe_mtu)
{
	int ret;
	struct aoe_proxy_msg msg;
	struct aoe_device *dev;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_SET_MTU_OFFSET_LEN);

	dev = port->aoe_parent;

	msg.request_data = inbuf;
	msg.response_data = NULL;
	msg.req_len = MC_CMD_AOE_IN_SET_MTU_OFFSET_LEN;
	msg.resp_len = 0;
	msg.cmd = MC_CMD_AOE;

	MCDI_SET_DWORD(inbuf, AOE_IN_OP_HDR, MC_CMD_AOE_OP_SET_MTU_OFFSET);
	MCDI_SET_DWORD(inbuf, AOE_IN_SET_MTU_OFFSET_PORT, AOE_PHYS_PORT(port));
	MCDI_SET_DWORD(inbuf, AOE_IN_SET_MTU_OFFSET_OFFSET, aoe_mtu);

	ret = aoe_dl_send_block_wait(dev, &msg);

	if (ret)
		printk(KERN_ERR "sfc_aoe: AOE port mtu change on port %d failed %d\n",
                       AOE_PHYS_PORT(port), ret);
        else
          port->mtu = aoe_mtu;

	return ret;
}

static int aoe_mcdi_get_link_params(struct aoe_port_info *port)
{
	int ret;
	struct aoe_device *dev;
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_OP_UHLINK_PHY_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_UHLINK_PHY_LEN);
	uint32_t cmd_header;

	dev = port->aoe_parent;

	msg.request_data = inbuf;
	msg.response_data = outbuf;
	msg.req_len = MC_CMD_FC_OP_UHLINK_PHY_LEN;
	msg.resp_len = MC_CMD_FC_OUT_UHLINK_PHY_LEN;
	msg.cmd = MC_CMD_FC;

	cmd_header = (MC_CMD_FC_OP_UHLINK_PHY << MC_CMD_FC_IN_UHLINK_OP_LBN) |
		     (MC_CMD_FC_IN_PORT_EXT_OFST << MC_CMD_FC_IN_UHLINK_PORT_TYPE_LBN) |
		     (AOE_PHYS_PORT(port) << MC_CMD_FC_IN_UHLINK_PORT_IDX_LBN) |
		     (MC_CMD_FC_OP_UHLINK_CMD_FORMAT_PORT_OVERRIDE << MC_CMD_FC_IN_UHLINK_CMD_FORMAT_LBN);

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_UHLINK);
	MCDI_SET_DWORD(inbuf, FC_IN_UHLINK_HEADER, cmd_header);

	ret = aoe_dl_send_block_wait(dev, &msg);

	if (ret) {
		printk(KERN_ERR "sfc_aoe: AOE read transceiver settings on port %d failed %d\n",
                       AOE_PHYS_PORT(port), ret);
		goto failed;
	}

	port->params.valid = (*(uint32_t*)MCDI_PTR(outbuf, FC_OUT_UHLINK_PHY_SFP_PRESENT)) & 0x01;
	port->params.vod = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_TX_SETTINGS_0,
				      FC_OUT_UHLINK_PHY_TRC_TX_VOD);
	port->params.preemp_1posttap = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_TX_SETTINGS_0,
				      FC_OUT_UHLINK_PHY_TRC_TX_PREEMP_1STPOSTTAP);
	port->params.preemp_pretap = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_TX_SETTINGS_1,
				      FC_OUT_UHLINK_PHY_TRC_TX_PREEMP_PRETAP);
	port->params.preemp_2posttap = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_TX_SETTINGS_1,
				      FC_OUT_UHLINK_PHY_TRC_TX_PREEMP_2NDPOSTTAP);
	port->params.dc_gain = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_RX_SETTINGS,
					  FC_OUT_UHLINK_PHY_TRC_RX_DC_GAIN);
	port->params.eq = COMP_FIELD(outbuf, FC_OUT_UHLINK_PHY_TRC_RX_SETTINGS,
					  FC_OUT_UHLINK_PHY_TRC_RX_EQ_CONTROL);
failed:
	return ret;


}

int aoe_mcdi_get_time(struct aoe_device *dev, struct aoe_remote_clock *rem)
{
	int ret;
	struct aoe_proxy_msg msg;
	uint64_t hi_seconds;
	uint64_t lo_seconds;
	uint32_t nseconds;
	uint32_t range;
	uint32_t scale;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_CLOCK_GET_TIME_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_CLOCK_GET_TIME_LEN);

	msg.request_data = inbuf;
	msg.response_data = outbuf;
	msg.req_len = MC_CMD_FC_IN_CLOCK_GET_TIME_LEN;
	msg.resp_len = MC_CMD_FC_OUT_CLOCK_GET_TIME_LEN;
	msg.cmd = MC_CMD_FC;

	MCDI_SET_DWORD(inbuf, FC_IN_OP_HDR, MC_CMD_FC_OP_CLOCK);
	MCDI_SET_DWORD(inbuf, FC_IN_CLOCK_OP, MC_CMD_FC_IN_CLOCK_GET_TIME);
	MCDI_SET_DWORD(inbuf, FC_IN_CLOCK_ID, MC_CMD_FC_IN_CLOCK_STATS);

	ret = aoe_dl_send_block_wait(dev, &msg);

	if (ret) {
		printk(KERN_ERR "sfc_aoe: unable to get clock value %d\n", ret);
		return ret;
	}

	hi_seconds = *(uint32_t*)MCDI_PTR(outbuf,
					  FC_OUT_CLOCK_GET_TIME_SECONDS_HI);
	lo_seconds = *(uint32_t*)MCDI_PTR(outbuf,
					  FC_OUT_CLOCK_GET_TIME_SECONDS_LO);
	nseconds = *(uint32_t*)MCDI_PTR(outbuf,
				        FC_OUT_CLOCK_GET_TIME_NANOSECONDS);
	range = *(uint32_t*)MCDI_PTR(outbuf,
				     FC_OUT_CLOCK_GET_TIME_RANGE);
	scale = *(uint32_t*)MCDI_PTR(outbuf,
				     FC_OUT_CLOCK_GET_TIME_PRECISION);

	set_normalized_timespec(&rem->clock, hi_seconds << 32 | lo_seconds,
				nseconds);

	hi_seconds = ((1LL << range) - 1);
	hi_seconds = do_div(hi_seconds, range);
	nseconds = ((1LL << range) - 1) - (hi_seconds * scale);

	set_normalized_timespec(&rem->limit, hi_seconds, nseconds);

	return ret;
}

static int aoe_mcdi_query_ddr_bank_page(struct aoe_dimm_info *info,
					int page_id)
{
	struct aoe_proxy_msg msg;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_DDR_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_AOE_OUT_DDR_LENMAX);
	struct aoe_device *dev = info->parent;
	int ret = 0;
	int spd_len;

	msg.request_data = inbuf;
	msg.response_data = outbuf;
	msg.req_len = MC_CMD_AOE_IN_DDR_LEN;
	msg.resp_len = MC_CMD_AOE_OUT_DDR_LENMAX;
	msg.cmd = MC_CMD_AOE;

	MCDI_SET_DWORD(inbuf, AOE_IN_CMD, MC_CMD_AOE_OP_DDR);
	MCDI_SET_DWORD(inbuf, AOE_IN_DDR_BANK, info->id);
	MCDI_SET_DWORD(inbuf, AOE_IN_DDR_SPD_PAGE_ID, page_id);

	ret = aoe_dl_send_block_wait(dev, &msg);
	if (ret) {
		printk(KERN_ERR "sfc_aoe: unable to get DDR "
				"information for bank %u\n", info->id);
		goto fail;
	}

	if (page_id == 0) {
		info->present = COMP_FIELD(outbuf, AOE_OUT_DDR_FLAGS,
					   AOE_OUT_DDR_PRESENT);
		info->powered = COMP_FIELD(outbuf, AOE_OUT_DDR_FLAGS,
					   AOE_OUT_DDR_POWERED);
		info->operational = COMP_FIELD(outbuf, AOE_OUT_DDR_FLAGS,
					   AOE_OUT_DDR_OPERATIONAL);
		info->size = *((uint32_t *)(MCDI_PTR(outbuf, AOE_OUT_DDR_CAPACITY)));
		info->type = *((uint32_t *)(MCDI_PTR(outbuf, AOE_OUT_DDR_TYPE)));
		info->voltage = *((uint32_t *)(MCDI_PTR(outbuf, AOE_OUT_DDR_VOLTAGE)));
	}
	spd_len = msg.real_resp - MC_CMD_AOE_OUT_DDR_SPD_OFST;
	if (spd_len > 0)
		memcpy(&(info->spd[page_id*DIMM_SPD_PAGE_LEN]),
		       MCDI_PTR(outbuf, AOE_OUT_DDR_SPD),
		       spd_len);

fail:
	return ret;
}

static int aoe_mcdi_query_ddr_bank(struct aoe_dimm_info *info)
{
	int ret = 0;
	int page_id;
	int num_pages = DIMM_SPD_LEN/DIMM_SPD_PAGE_LEN;

	if (!info)
		return -EINVAL;

	memset(&info->spd, 0x0, DIMM_SPD_LEN);
	for (page_id = 0; page_id < num_pages; page_id++)
	{
		ret = aoe_mcdi_query_ddr_bank_page(info, page_id);
		if (ret)
			return ret;
	}
	return ret;
}

int aoe_mcdi_ddr_size(struct aoe_dimm_info *dimm, char *buf)
{
        int ret;

        ret = aoe_mcdi_query_ddr_bank(dimm);
        if (ret)
                return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", dimm->size);
}

int aoe_mcdi_ddr_type(struct aoe_dimm_info *dimm, char *buf)
{
        int ret;
        ret = aoe_mcdi_query_ddr_bank(dimm);
        if (ret)
                return ret;

	switch (dimm->type)
	{
        case 0:
		return snprintf(buf, PAGE_SIZE, "Reserved\n");
	case 11:
		return snprintf(buf, PAGE_SIZE, "DDR3 SDRAM\n");
	default:
		return snprintf(buf, PAGE_SIZE, "0x%x\n", dimm->type);
	}
}

int aoe_mcdi_ddr_voltage(struct aoe_dimm_info *dimm, char *buf)
{
        int ret;

        ret = aoe_mcdi_query_ddr_bank(dimm);
        if (ret)
                return ret;

	return snprintf(buf, PAGE_SIZE, "%dmV\n", dimm->voltage);
}

int aoe_mcdi_ddr_status(struct aoe_dimm_info *dimm, char *buf)
{
        int ret;

        ret = aoe_mcdi_query_ddr_bank(dimm);
        if (ret)
                return ret;

	if (dimm->present)
		if (dimm->powered)
			if (dimm->operational)
				return snprintf(buf, PAGE_SIZE,	"Calibrated\n");
			else
				return snprintf(buf, PAGE_SIZE, "Not calibrated\n");
		else
			return snprintf(buf, PAGE_SIZE, "Not powered\n");
	else
		return snprintf(buf, PAGE_SIZE, "Not present\n");
}

int aoe_mcdi_ddr_partnum(struct aoe_dimm_info *dimm, char *buf)
{
	int ret;

	ret = aoe_mcdi_query_ddr_bank(dimm);
	if (ret)
		return ret;

	strncpy(buf, &(dimm->spd[DIMM_SPD_PARTNO_LBN]), DIMM_SPD_PARTNO_WIDTH);
	buf[DIMM_SPD_PARTNO_WIDTH] = 0;

	return strlen(buf);
}

int aoe_mcdi_ddr_spd(struct aoe_dimm_info *dimm, char *buf)
{
	int ret;

	ret = aoe_mcdi_query_ddr_bank(dimm);
	if (ret)
		return ret;

	memcpy(buf, dimm->spd, DIMM_SPD_LEN);
	return (DIMM_SPD_LEN);
}

int aoe_mcdi_info_peg_power(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.peg_power);
}

int aoe_mcdi_info_cpld_good(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.cpld_good);
}

int aoe_mcdi_info_fpga_good(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.fpga_good);
}

int aoe_mcdi_info_fpga_power(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.fpga_power);
}

int aoe_mcdi_info_bad_sodimm(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.bad_sodimm);
}

int aoe_mcdi_info_has_byteblaster(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.has_byteblaster);
}

int aoe_mcdi_info_fc_running(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	return snprintf(buf, PAGE_SIZE, "%d\n", info.fc_running);
}

int aoe_mcdi_info_boot_result(struct aoe_device *dev, char *buf)
{
	struct aoe_dev_info info;
	int ret;
	const char *reason;
	ret = aoe_mcdi_aoe_info(dev, &info);
	if (ret)
		return ret;

	switch (info.boot_result)
	{
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_NO_ERROR:
		reason = "Booting";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_ADDRESS:
		reason = "Bad flash boot address";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_MAGIC:
		reason = "Bad magic";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_TEXT:
		reason = "Image address out of range";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_CHECKSUM:
		reason = "Bad checksum";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_FAIL_BAD_BSP:
		reason = "Incorrect BSP";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_APP_EXECUTE:
		reason = "OK";
		break;
	case MC_CMD_AOE_OUT_INFO_FC_BOOT_NO_BOOTROM:
		reason = "No bootrom or ByteBlaster connected";
		break;
	default:
		reason = "?";
		break;
	}

	return snprintf(buf, PAGE_SIZE, "%d, %s\n", info.boot_result, reason);
}

int aoe_mcdi_port_vod(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->vod);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_preemp_1stposttap(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->preemp_1posttap);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_preemp_pretap(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->preemp_pretap);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_preemp_2ndposttap(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->preemp_2posttap);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_dc_gain(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->dc_gain);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_rx_eq(struct aoe_port_info *port, char *buf)
{
	struct aoe_link_params *params = NULL;
	int ret;

	ret = aoe_mcdi_get_link_params(port);
	if (ret)
		return ret;

	params = &(port->params);

	if (params->valid) {
		return snprintf(buf, PAGE_SIZE, "%d\n", params->eq);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "No-SFP-module\n");
	}
}

int aoe_mcdi_port_mac_addr(struct aoe_port_info *port, char *buf)
{
	if (port->mac_address) {
		return snprintf(buf, PAGE_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X\n",	port->mac_address[0],
											port->mac_address[1],
											port->mac_address[2],
											port->mac_address[3],
											port->mac_address[4],
											port->mac_address[5]);
	}
	else {
		return snprintf(buf, PAGE_SIZE, "%s\n", "No MAC address data.");
	}
}

void aoe_mcdi_set_funcs(struct aoe_device *dev)
{
	dev->fpga_version = aoe_mcdi_fpga_version;
	dev->board_rev = aoe_mcdi_board_revision;
	dev->fc_version = aoe_mcdi_fc_version;
	dev->cpld_version = aoe_mcdi_cpld_version;
	dev->fpga_build_changeset = aoe_mcdi_fpga_build_changeset;
	dev->fpga_services_version = aoe_mcdi_fpga_services_version;
	dev->fpga_services_changeset = aoe_mcdi_fpga_services_changeset;
	dev->fpga_bsp_version = aoe_mcdi_fpga_bsp_version;
	dev->peg_power = aoe_mcdi_info_peg_power;
	dev->cpld_good = aoe_mcdi_info_cpld_good;
	dev->fpga_good = aoe_mcdi_info_fpga_good;
	dev->fpga_power = aoe_mcdi_info_fpga_power;
	dev->bad_sodimm = aoe_mcdi_info_bad_sodimm;
	dev->has_byteblaster = aoe_mcdi_info_has_byteblaster;
	dev->fc_running = aoe_mcdi_info_fc_running;
	dev->boot_result = aoe_mcdi_info_boot_result;
}

void aoe_mcdi_set_ddr_funcs(struct aoe_dimm_info *dimm)
{
	dimm->ddr_size = aoe_mcdi_ddr_size;
	dimm->ddr_type = aoe_mcdi_ddr_type;
	dimm->ddr_voltage = aoe_mcdi_ddr_voltage;
	dimm->ddr_status = aoe_mcdi_ddr_status;
	dimm->ddr_partnum = aoe_mcdi_ddr_partnum;
	dimm->ddr_spd = aoe_mcdi_ddr_spd;
}

void aoe_mcdi_set_port_funcs(struct aoe_port_info *port)
{
	port->vod = aoe_mcdi_port_vod;
	port->preemp_1stposttap = aoe_mcdi_port_preemp_1stposttap;
	port->preemp_pretap = aoe_mcdi_port_preemp_pretap;
	port->preemp_2ndposttap = aoe_mcdi_port_preemp_2ndposttap;
	port->dc_gain = aoe_mcdi_port_dc_gain;
	port->rx_eq = aoe_mcdi_port_rx_eq;
	port->mac_addr = aoe_mcdi_port_mac_addr;
}

