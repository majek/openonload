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
#include <linux/slab.h>

#define LOCK_LIMIT	1
#define LOOP_LIMIT	10

static inline struct aoe_mmap_entry * aoe_search_dev_maps(struct aoe_map_entry *entry,
							  int32_t index)
{
	struct aoe_mmap_entry *curr_mmap;
	struct aoe_device *aoe_instance = entry->aoe_dev;

	list_for_each_entry(curr_mmap, &aoe_instance->fpga_map->map_list, list) {
		if (curr_mmap->index == index) {
			goto out;
		}
	}

	return NULL;
out:
	return curr_mmap;
}

static int aoe_add_map_to_dev(struct aoe_map_entry *entry,
			      struct aoe_mmap_entry *mmap)
{
	int err = 0;
	struct aoe_device *aoe_instance = entry->aoe_dev;
	struct aoe_mmap_entry *new_mmap;
	struct aoe_mmap_entry *curr_mmap;

	mutex_lock(&aoe_instance->fpga_map->map_lock);

	/* only add if this is not already there */
	curr_mmap = aoe_search_dev_maps(entry, mmap->index);

	/* If already there then do not add */
	if (curr_mmap)
		goto out;

	new_mmap = kzalloc(sizeof(*new_mmap), GFP_ATOMIC);
	if (!new_mmap) {
		err = -ENOMEM;
		goto out;
	}

	memcpy(new_mmap, mmap, sizeof(*mmap));

	INIT_LIST_HEAD(&new_mmap->list);	
	list_add(&new_mmap->list, &aoe_instance->fpga_map->map_list);
	aoe_sysfs_add_map(aoe_instance, new_mmap);

	sema_init(&new_mmap->write_lock, 1);

out:
	mutex_unlock(&aoe_instance->fpga_map->map_lock);
	return err;
}

static void aoe_del_map_from_dev(struct aoe_device *aoe_instance,
				 struct aoe_mmap_entry *mmap)
{
	mutex_lock(&aoe_instance->fpga_map->map_lock);
	aoe_sysfs_del_map(aoe_instance, mmap);
	list_del(&mmap->list);
	kfree(mmap);
	mutex_unlock(&aoe_instance->fpga_map->map_lock);
}

int aoe_process_map_count_resp(struct aoe_map_entry *entry,
			       int count)
{
	struct amm_stream_control *req;
	struct amm_stream_control *resp;
	struct amm_ctrl_read_map_count_resp *mapc_resp;
	struct aoe_mmap_data *mmap = entry->aoe_dev->fpga_map;

	req = (struct amm_stream_control*)entry->request.data;
	resp = (struct amm_stream_control*)entry->response.data;
	mapc_resp =
		(struct amm_ctrl_read_map_count_resp*)&resp->read_map_count_resp;

	aoe_reserve_resp_buff(entry, sizeof(resp->header) + sizeof(*mapc_resp));

	resp->header.op = AMM_OP_READMAPCOUNT_RESPONSE;
	resp->header.version = req->header.version;
	resp->header.result = AMM_RESULT_SUCCESS;
	resp->header.reserved = req->header.reserved;
	resp->header.op_len_be = cpu_to_be32(sizeof(*mapc_resp));

	mapc_resp->count_be = cpu_to_be32(count);

	entry->state = DATA_PENDING_DONE;

	
	mmap->num_entries = count;

	return 0;
}

int aoe_process_map_index_resp(struct aoe_map_entry *entry,
			       struct aoe_mmap_entry *mmap_entry,
			       bool cache)
{
	struct amm_stream_control *req;
	struct amm_stream_control *resp;
	struct amm_ctrl_read_map_resp *mapindex_resp;

	req = (struct amm_stream_control*)entry->request.data;
	resp = (struct amm_stream_control*)entry->response.data;
	mapindex_resp =
		(struct amm_ctrl_read_map_resp*)&resp->read_map_resp;

	aoe_reserve_resp_buff(entry, sizeof(resp->header) + sizeof(*mapindex_resp));

	resp->header.op = AMM_OP_READMAP_RESPONSE;
	resp->header.version = req->header.version;
	resp->header.result = AMM_RESULT_SUCCESS;
	resp->header.reserved = req->header.reserved;
	resp->header.op_len_be = cpu_to_be32(sizeof(*mapindex_resp));

	mapindex_resp->index_be = cpu_to_be32(mmap_entry->index);
	mapindex_resp->options_be = cpu_to_be32(mmap_entry->options);
	mapindex_resp->address_be = cpu_to_be64(mmap_entry->base_addr);
	mapindex_resp->length_be = cpu_to_be64(mmap_entry->length);
	mapindex_resp->license_date_be = cpu_to_be64(mmap_entry->license_date);
	mapindex_resp->component_id_be = cpu_to_be32(mmap_entry->comp_info);
	mapindex_resp->reserved_be = cpu_to_be64(0ll);
	strncpy(mapindex_resp->app_name, mmap_entry->name, AMM_COM_NAME_LEN);

	entry->state = DATA_PENDING_DONE;

	if (cache)
		aoe_add_map_to_dev(entry, mmap_entry);

	return 0;
}

/* The descision on which direction takes priority is on the base address
 * of the read.
 */
static inline int address_in_map(uint64_t address,
				 uint32_t len,
				 struct aoe_mmap_entry *mmap)
{
	uint64_t top = mmap->base_addr + mmap->length;
	uint64_t bot = mmap->base_addr;
	uint64_t bot_u = address;
	uint64_t top_u = address + len;

	/* Return 0 if in */
	if (bot <= bot_u && top >= top_u) {
		return 0;
	}

	/* Return 1 if above */
	if (top >= top_u) {
		return 1;
	}

	/* Return -1 if below */
	if (bot > address) {
		return -1;
	}

	return -1;
}

static struct aoe_mmap_entry * aoe_search_maps(struct aoe_map_entry *entry,
	 				       uint64_t addr,
					       uint32_t len)
{
	struct aoe_mmap_data *fpga_data = entry->aoe_dev->fpga_map;
	struct aoe_mmap_entry *mmap = NULL;
	struct aoe_mmap_entry *ret = NULL;
	int dir;

	mutex_lock(&fpga_data->map_lock);

	/* Is the address we have been passed inside one of the entries */
	list_for_each_entry(mmap, &fpga_data->map_list, list) {
		dir = address_in_map(addr, len, mmap);

		if (!dir) {
			ret = mmap;
			goto out;
		}
	}

out:
	mutex_unlock(&fpga_data->map_lock);
	return ret;
}

int aoe_verify_map_range_lock(struct aoe_map_entry *entry,
			      uint64_t addr,
			      uint32_t len)
{
	int ret;
	struct aoe_mmap_entry *mmap = aoe_search_maps(entry, addr, len);

	if (!mmap)
		return -EFAULT;

	if (down_interruptible(&mmap->write_lock)) {
        	DPRINTK("sema interrupted\n");
		return -EINTR;
    }

	entry->write_map = mmap;
        mmap->entry = entry;

	ret = entry->startMessageSend(entry);
	if (ret) {
		entry->write_map = NULL;
		mmap->entry = NULL;
		up(&mmap->write_lock);
		return ret;
	}

	return ret;
}

void aoe_release_map_lock(struct aoe_map_entry *entry)
{
	struct aoe_mmap_entry *mmap = entry->write_map;

	if (mmap) {
		entry->write_map = NULL;
		mmap->entry = NULL;
		up(&mmap->write_lock);
	}
}

/* Have we already done a query on the map count?
 * if not then go and get the data from the FC,
 * otherwise return the cached value
 */
int aoe_fetch_map_count(struct aoe_map_entry *entry)
{
	return entry->startMessageSend(entry);
}

int aoe_fetch_map_instance(struct aoe_map_entry *entry, int32_t index)
{
	return entry->startMessageSend(entry);
}

int aoe_setup_mmaps(struct aoe_device *to_add)
{
	struct aoe_mmap_data *new_map;

	if (!to_add->fpga_map) {
		new_map = kzalloc(sizeof(*new_map), GFP_KERNEL);
		new_map->num_entries = 0;
		INIT_LIST_HEAD(&new_map->map_list);
		mutex_init(&new_map->map_lock);
		new_map->ref = 0;
		to_add->fpga_map = new_map;
	}

	to_add->fpga_map->ref++;

	return 0;
}

void aoe_flush_mmaps(struct aoe_device *dev)
{
	struct aoe_mmap_entry *safe;
	struct aoe_mmap_entry *mmap;

	list_for_each_entry_safe(mmap, safe, &dev->fpga_map->map_list, list) {
		if (mmap) {
			aoe_del_map_from_dev(dev, mmap);
		}
	}
}

void aoe_destroy_mmaps(struct aoe_device *dev)
{
	if (--dev->fpga_map->ref)
		return;

	aoe_flush_mmaps(dev);

	mutex_destroy(&dev->fpga_map->map_lock);

	kfree(dev->fpga_map);
}
