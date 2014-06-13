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
#include <linux/time.h>

#define AOE_SMALL_POOL_MAX	64
#define AOE_MED_POOL_MAX	512
#define AOE_LARGE_POOL_MAX	2048

#define AOE_STATS_GEN_START	0xffffeeee
#define AOE_STATS_GEN_END	0xaaaabbbb

struct aoe_stats_oob_data
{
	uint64_t clock_start;
	uint64_t clock_end;
	uint64_t gen_start;
	uint64_t gen_end;
};

static int next_block_id = 0;

static int aoe_stats_run_mode_disable(struct aoe_map_entry *entry,
				      struct aoe_dma_area *area,
				      bool force);

/* Search the allowed block number and re-use if key matches,
 * if we get to a free block there was no match so use that
 */
static int aoe_generate_dma_block(struct aoe_device *dev,
				  uint32_t aoe_addr,
				  uint32_t base_len,
				  struct aoe_dma_area **block)
{
	int ret = -ENOMEM;
	struct aoe_dma_area *curr_block;

	*block = NULL;

	mutex_lock(&dev->dma_lock);

	/* Look at the blocks that are already set up */

	list_for_each_entry(curr_block, &dev->dma_blocks, next) {
		if ((curr_block->aoe_addr == aoe_addr) &&
		    (curr_block->aoe_len == base_len)) {
			curr_block->ref ++;
			*block = curr_block;
			ret = 1;
			goto out;
		} else
			continue;
	}

	/* If there is a block that has been free'd then
	 * take this rather than make new one
	 */

	if (dev->dma_block_count >= MAX_DMA_AREAS)
		goto out;

	if (!list_empty(&dev->free_dma_blocks)) {
		curr_block = list_first_entry(&dev->free_dma_blocks, struct aoe_dma_area, next);
		list_move(&curr_block->next, &dev->dma_blocks);
	} else {

		/* if here then we allocate a new one if we
	 	 * are not at the limit we have set
	 	 */

		curr_block = kzalloc(sizeof(*curr_block), GFP_KERNEL);
		INIT_LIST_HEAD(&curr_block->next);
		list_add(&curr_block->next, &dev->dma_blocks);
	}

	curr_block->ref ++;
	curr_block->id = next_block_id++;
	curr_block->running = 0;
	*block = curr_block;
	dev->dma_block_count ++;
	ret = 0;

out:
	mutex_unlock(&dev->dma_lock);
	return ret;
}

static int aoe_search_id_dma_block(struct aoe_device *dev,
				   uint32_t id,
				   struct aoe_dma_area **block)
{
	int ret = -ENOMEM;
	struct aoe_dma_area *curr_block;

	*block = NULL;

	list_for_each_entry(curr_block, &dev->dma_blocks, next) {
		if (curr_block->id == id) {
			*block = curr_block;
			return 0;
		}
	}

	return ret;
}

static inline void __aoe_release_dma(struct aoe_device *aoe_dev,
				     struct aoe_dma_area *area)
{
	if (area->source) {
		dma_pool_free(area->source, area->h_addr,
			      area->dma_handle);

	} else {
		dma_free_coherent(&aoe_dev->pci_dev->dev,
				  area->len,
				   area->h_addr,
				   area->dma_handle);
	}
}

static void __aoe_free_dma_area(struct aoe_device *aoe_dev,
				struct aoe_dma_area *area)
{
	mutex_lock(&aoe_dev->dma_lock);

	if (!area->ref)
		goto out;

	if (!(--area->ref)) {

		if (area->running) {
			aoe_mcdi_clear_timed_read(aoe_dev, area);
		}

		if (area->stats_buff) {
			kfree(area->stats_buff);
			area->stats_buff = NULL;
		}

		__aoe_release_dma(aoe_dev, area);
		list_move(&area->next, &aoe_dev->free_dma_blocks);

		if (!--aoe_dev->dma_block_count) {
			/* If this is the last block that was used
			 * free them all
			 */
			struct list_head *c_area, *temp;
			struct aoe_dma_area *del_block;

			list_for_each_safe(c_area, temp, &aoe_dev->free_dma_blocks) {
				del_block = container_of(c_area, struct aoe_dma_area, next);
				list_del(&del_block->next);
				kfree(del_block);
			}
		}
	}
out:
	mutex_unlock(&aoe_dev->dma_lock);
}

/* Need to add a key to this, which is a combination of the params that make
 * up the request?
 */
static struct aoe_dma_area * aoe_alloc_dma_area(struct aoe_map_entry *entry,
						uint64_t aoe_addr,
						uint32_t base_len,
						uint32_t flags)
{
	struct aoe_dma_area *new_dma = NULL;
	struct dma_pool *alloc_from = NULL;
	struct aoe_user_dma *new_user = NULL;
	struct aoe_device *aoe_dev = entry->aoe_dev;
	struct aoe_stats_oob_data *header;
	int match;
	uint32_t len = base_len + sizeof(struct aoe_stats_oob_data);
	uint8_t *stats_buff = NULL;
	uint32_t stats_buff_len = base_len;

	/* Length of the data depends on the type of block */
	if (flags) {
		len *= 2;
		stats_buff_len *= 2;
	}

	match = aoe_generate_dma_block(aoe_dev, aoe_addr, base_len, &new_dma);

	if (!new_dma)
		return NULL;

	/* Once we have a descpritor that can be used
	 * we need to set up the mapping
	 * This depends on the size requested,
	 * from the pools if they accomodate or directly if not
	 */

	if (!match) {
		if (len < AOE_SMALL_POOL_MAX)
			alloc_from = aoe_dev->small_pool;
		else if (len < AOE_MED_POOL_MAX)
			alloc_from = aoe_dev->med_pool;
		else if (len < AOE_LARGE_POOL_MAX)
			alloc_from = aoe_dev->large_pool;

		if (!alloc_from) {
			new_dma->h_addr = dma_alloc_coherent(&aoe_dev->pci_dev->dev,
							     len,
							     &new_dma->dma_handle,
							     GFP_ATOMIC);
		} else {
			new_dma->h_addr = dma_pool_alloc(alloc_from, GFP_ATOMIC,
							 &new_dma->dma_handle);
		}

		if (!new_dma->h_addr)
			return NULL;

		/* scribble on gen data areas */
		header = (struct aoe_stats_oob_data*)(new_dma->h_addr + base_len);
		header->gen_start = AOE_STATS_GEN_START;
		header->gen_end = AOE_STATS_GEN_END;
		if (flags) {
			header = (struct aoe_stats_oob_data*)(new_dma->h_addr +
							      len -
							      sizeof(struct aoe_stats_oob_data));
			header->gen_start = AOE_STATS_GEN_START;
			header->gen_end = AOE_STATS_GEN_END;
		}

		if (stats_buff == NULL) {
			stats_buff = kzalloc(stats_buff_len, GFP_KERNEL);
			if (!stats_buff)
				goto error;
		}

		new_dma->source = alloc_from;
		new_dma->len = len;
		new_dma->aoe_addr = aoe_addr;
		new_dma->flags = flags;
		new_dma->aoe_len = base_len;
		new_dma->stats_buff = stats_buff;
	}

	/* if all this was ok then do the linking step */
	new_user = kzalloc(sizeof(*new_user), GFP_ATOMIC);
	if (!new_user)
		goto error;

	new_user->info = new_dma;

	INIT_LIST_HEAD(&new_user->list);
	list_add(&new_user->list, &entry->dma_list);

	return new_dma;

error:
	__aoe_free_dma_area(aoe_dev, new_dma);

	return NULL;
}

static void aoe_free_dma_area(struct aoe_device *aoe_dev,
			      struct aoe_user_dma *dma_h)
{
	list_del(&dma_h->list);
	__aoe_free_dma_area(aoe_dev, dma_h->info);
	kfree(dma_h);
}

int aoe_setup_stats_entry(struct aoe_map_entry *entry, struct aoe_add_dma *req)
{
	struct aoe_dma_area *new_dma = NULL;

	/* 1. Need to determine if there is already a dma region we can use,
	 * if so just return it.
	 */

	new_dma = aoe_alloc_dma_area(entry, req->aoe_addr, req->aoe_len, req->flags);
	if (!new_dma)
		return -ENOMEM;

	req->dma_id = new_dma->id;

	return 0;
}

int aoe_remove_stats_entry(struct aoe_map_entry *entry, struct aoe_del_dma *req)
{
	struct aoe_user_dma *user_dma;
	struct aoe_user_dma *tmp;
	struct aoe_device *dev = entry->aoe_dev;

	list_for_each_entry_safe(user_dma, tmp, &entry->dma_list, list) {
		if (user_dma->info->id == req->dma_id) {
			aoe_free_dma_area(dev, user_dma);
			return 0;
		}
	}

	return -EINVAL;
}

int aoe_remove_stats_entries(struct aoe_map_entry *entry)
{
	struct aoe_user_dma *user_dma;
	struct aoe_user_dma *tmp;

	list_for_each_entry_safe(user_dma, tmp, &entry->dma_list, list) {
		aoe_free_dma_area(entry->aoe_dev, user_dma);
	}

	return 0;
}

/* Disable but do not free, free left up to the owning entry */
int aoe_disable_stats_entries(struct aoe_map_entry *entry)
{
	struct aoe_user_dma *user_dma;
	struct aoe_user_dma *tmp;

	list_for_each_entry_safe(user_dma, tmp, &entry->dma_list, list) {
		aoe_stats_run_mode_disable(entry, user_dma->info, true);
	}

	return 0;
}

int aoe_copy_stats_entry(struct aoe_map_entry *entry, struct aoe_read_dma *req)
{
	struct aoe_device *aoe_dev = entry->aoe_dev;
	struct aoe_dma_area *area = NULL;
	struct aoe_stats_oob_data *oob;
	ssize_t len;
	ssize_t aoe_len;
	uint32_t retry;
	uint32_t loop;
	uint32_t h_offset;
	uint32_t b_offset;
	uint32_t u_offset;
	struct timespec this_stat[2];
	struct timespec *valid_stat;
	struct timespec delta;
	struct timespec sys_time;
	uint32_t loop_max = 1;
	int ret = -EAGAIN;
	uint64_t gen_start = 0;
	uint64_t dma_gen_start;
	uint32_t copy_len;
	uint64_t dma_gen_end;

	aoe_search_id_dma_block(aoe_dev, req->dma_id, &area);

	if (!area)
		return -EINVAL;

	aoe_len = area->aoe_len; /* stats data len unit */

	copy_len = area->flags ? (aoe_len*2) : aoe_len;

	if (copy_len > req->read_len)
		return -EINVAL;

	if (!area)
		return -EINVAL;

	len = aoe_len + sizeof(struct aoe_stats_oob_data); /* Included oob data */
	if (area->flags)
		loop_max = 2;

	/* Check that the start and end times of the data block are the same
	 * If they are not then wait until they are, should not take long
	 */

	 for (loop = 0; loop < loop_max; loop++) {

		u_offset = (aoe_len * loop);
		h_offset = (len * (loop + 1)) - (sizeof(struct aoe_stats_oob_data));
		b_offset = (len * loop);

		oob = (struct aoe_stats_oob_data*)((uint8_t*)area->h_addr + h_offset);

		ret = -EAGAIN;
		/* Wait for a maximum of 1second for an atomic stats block to be available */
		for (retry = 0; retry < 10000; ++retry) {
			rmb();
			dma_gen_start = oob->gen_start;
			dma_gen_end = oob->gen_end;
			if (dma_gen_start == dma_gen_end) {
				gen_start = dma_gen_start;
				
				/* Copy stats block into local buffer */
				memcpy(area->stats_buff + u_offset, area->h_addr + b_offset, aoe_len);

				/* If a new update to the stats_block has started already,
 				 * try reading the updated block */
				dma_gen_start = oob->gen_start;
				dma_gen_end = oob->gen_end;
				if (gen_start != dma_gen_start || gen_start != dma_gen_end)
					goto again;

				this_stat[loop] =
					ns_to_timespec(oob->clock_start * NSEC_PER_USEC);
				ret = 0;
				break;
			}
again:
			udelay(100);
		}
		if (ret) {
			if (ret == -EAGAIN) {
				if ((dma_gen_start == AOE_STATS_GEN_START) ||
				    (dma_gen_end == AOE_STATS_GEN_END)) {
					/* First update hasn't been initiated yet; just return buffer as it is */
					continue;
				}
			}
			return ret;
		}
	}

	/* Copy local stats buffer to user space */
	if (copy_to_user(req->buff,
			 &(area->stats_buff[0]),
			 req->read_len))
		return -EFAULT;
	
	/* Now work out how much FC time has passed since the last update, or first,
 	 * This delta can then be used to compute an estimate of the system time
 	 * when the stat was generated
 	 */

	/* Pick the most recent update, could be A or B */

	valid_stat = &this_stat[0];

	if (loop_max == 2) {
		if ((timespec_compare(&this_stat[0], &this_stat[1]) < 0))
			valid_stat = &this_stat[1];
	}

	/* Deal with wrapping */
	delta = timespec_sub(*valid_stat, area->last_fc_time.clock);
	if (delta.tv_sec < 0) {
		delta = timespec_add(*valid_stat,
				     timespec_sub(area->last_fc_time.limit,
						  area->last_fc_time.clock));
	}
	sys_time = timespec_add(area->last_sys_time, delta);

	req->gen_time.raw.tv_sec = valid_stat->tv_sec;
	req->gen_time.raw.tv_nsec = valid_stat->tv_nsec;
	req->gen_time.sys.tv_sec = sys_time.tv_sec;
	req->gen_time.sys.tv_nsec = sys_time.tv_nsec;

	area->last_fc_time.clock = *valid_stat;
	/* Reset last system time to reduce error and remove wrapping issues */
	getnstimeofday(&area->last_sys_time);

	return 0;
}

static int aoe_stats_run_mode_enable(struct aoe_map_entry *entry,
				     struct aoe_dma_area *area,
				     struct aoe_enable_dma *req)
{
	int ret = 0;
	struct aoe_device *aoe_dev = entry->aoe_dev;


	if (!area)
		return -EINVAL;

	mutex_lock(&aoe_dev->dma_lock);
	if (!area->running) {
		/* Query the time and then enable the timer.
		 * this removes a potential race where the
		 * timer could fire before we know the base time
		 */

		getnstimeofday(&area->last_sys_time);

		ret = aoe_mcdi_get_time(aoe_dev,
				&area->last_fc_time);
		if (ret)
			goto done;

		ret = aoe_mcdi_timed_read(aoe_dev, area,
				req->op_data,
				req->op_data_offset,
				req->interval_ms,
				true);
		if (ret)
			goto done;

		area->running++;
	}
	area->running++;
done:
	mutex_unlock(&aoe_dev->dma_lock);
	return ret;
}

static int aoe_stats_run_mode_disable(struct aoe_map_entry *entry,
				      struct aoe_dma_area *area,
				      bool force)
{
	struct aoe_device *aoe_dev = entry->aoe_dev;

	mutex_lock(&aoe_dev->dma_lock);
	if ((!--area->running) || force)
		aoe_mcdi_clear_timed_read(entry->aoe_dev, area);

	if (force)
		area->running = 0;

	mutex_unlock(&aoe_dev->dma_lock);
	return 0;
}

int aoe_enable_stats_entry(struct aoe_map_entry *entry,
			   struct aoe_enable_dma *req)
{
	struct aoe_dma_area *area;
	struct aoe_device *aoe_dev = entry->aoe_dev;

	aoe_search_id_dma_block(aoe_dev, req->dma_id, &area);

	if (!area)
		return -EINVAL;

	if (req->enable)
		return aoe_stats_run_mode_enable(entry, area, req);
	else
		return aoe_stats_run_mode_disable(entry, area, false);
}

#define AOE_POOL_NAME_LEN 20
static int __aoe_create_pool(struct aoe_device *dev,
			     struct dma_pool **pool,
			     unsigned int size)
{
	struct dma_pool *new_pool;
	char name[AOE_POOL_NAME_LEN];

	snprintf(name, AOE_POOL_NAME_LEN, "aoe_pool_%u", size);

	new_pool = dma_pool_create(name,
				   &dev->pci_dev->dev,
				   size, 64, 0);

	if (!new_pool)
		return -ENOMEM;

	*pool = new_pool;

	return 0;
}

int aoe_stats_device_setup(struct aoe_device *aoe_dev)
{
	/* Create three polls to allocate stats from
	 * small (0 - <64 bytes), medium (64 - <512), large (512 - <2048)
	 * Larger than 2048 will get it's own Page and be allocated on
	 * demand.
	 */

	int ret;

	if ((ret = __aoe_create_pool(aoe_dev, &aoe_dev->small_pool,
				     AOE_SMALL_POOL_MAX)))
		goto error_small;
	if ((ret = __aoe_create_pool(aoe_dev, &aoe_dev->med_pool,
				     AOE_MED_POOL_MAX)))
		goto error_med;
	if ((ret = __aoe_create_pool(aoe_dev, &aoe_dev->large_pool,
				     AOE_LARGE_POOL_MAX)))
		goto error_large;

	return 0;

error_large:
	dma_pool_destroy(aoe_dev->med_pool);
error_med:
	dma_pool_destroy(aoe_dev->small_pool);
error_small:
	return -ENOMEM;
}

void aoe_stats_device_destroy(struct aoe_device *aoe_dev)
{
	dma_pool_destroy(aoe_dev->med_pool);
	dma_pool_destroy(aoe_dev->small_pool);
	dma_pool_destroy(aoe_dev->large_pool);
}
