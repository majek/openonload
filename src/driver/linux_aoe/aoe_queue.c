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
#include <linux/kthread.h>
#include <linux/list.h>

#define QUEUE_SIZE      MAP_SIZE

struct aoe_send_queue_elem {
	struct list_head list;
	struct aoe_proxy_msg *msg;
	int idx;
};

struct aoe_send_queue {
	int queue_len;				/* Current length of queue */
	struct list_head free_list;		/* Free list of elems */
	struct list_head used_list;		/* Used list of elems */
	struct mutex tail_lock;			/* lock for head of list */
	struct efx_nic *efx;			/* Interface to use for sends */
	struct task_struct *task;		/* pointer to send task */
	wait_queue_head_t pending;		/* handles periods of inactivity */
	int (*mcdi_rpc) (void *cmd);		/* call into the sfc driver */
	struct aoe_send_queue_elem *elements;	/* pointer to allocated elements */
	bool shutdown;
};

void aoe_qu_flush(struct aoe_send_queue *queue)
{
	struct aoe_send_queue_elem *tail_elem;

	while (queue->queue_len) {
		tail_elem = list_first_entry(&queue->used_list,
					     struct aoe_send_queue_elem,
					     list);

		queue->queue_len --;

		if (!tail_elem ||
                    !tail_elem->msg)
			continue;

		tail_elem->msg->status = AOE_FAILED;
	
		tail_elem->msg->parent->completeMessageSend(tail_elem->msg);

		list_del(&tail_elem->list);	

	}
}

/* Queue needs to be thought about more, simple but at least
 * look at it, maybe a counting semaphore is the way
 * forward here
 */
static int aoe_qu_bottom_thread(void *data)
{
	struct aoe_send_queue *queue = (struct aoe_send_queue*)data;
	struct aoe_send_queue_elem *tail_elem;
	struct aoe_proxy_msg *msg;
	struct aoe_map_entry *entry;
	struct aoe_device *aoe_dev;

	while (!kthread_should_stop()) {
#ifndef NDEBUG
		int tmp_len;
#endif

		if (!queue->queue_len) {
			if (!wait_event_timeout(queue->pending,
						queue->queue_len,
						msecs_to_jiffies(100)))
				continue; /* timeout so carry on */
		}

		/* try and remove this later */
		if (!(mutex_trylock(&queue->tail_lock)))
			continue;

		tail_elem = list_first_entry(&queue->used_list,
					     struct aoe_send_queue_elem,
					     list);
		list_del(&tail_elem->list);
		queue->queue_len--;
#ifndef NDEBUG
		tmp_len = queue->queue_len;
#endif
		mutex_unlock(&queue->tail_lock);

		if (!tail_elem ||
		    !tail_elem->msg ||
		    !tail_elem->msg->parent)
			continue;

		msg = tail_elem->msg;
		entry = msg->parent;

		DPRINTK("New msg, queue now %d at %d\n", tmp_len, tail_elem->idx);

		aoe_dev = entry->aoe_dev;

		if (aoe_dev && !(msg->mcdi_return_code = aoe_dl_send_block_wait(aoe_dev, msg))) {
			DPRINTK("send complete - calling completion\n");
			msg->status = AOE_SUCCESS;
		} else {
			printk(KERN_ERR "sfc_aoe: MCDI send failure (%d)\n", msg->mcdi_return_code);
			msg->status = AOE_FAILED;
		}

		entry->completeMessageSend(msg);

		/* now add back onto the free queue */
		list_add_tail(&tail_elem->list, &queue->free_list);

	}

	return 0;
}

int aoe_qu_add_msg(struct aoe_proxy_msg *msg)
{
	/* Try and take an element of the top of the
 	 * free list and add to the used list,
 	 * this may block */

	struct aoe_map_entry *entry = msg->parent;
	struct aoe_device *dev = entry->aoe_dev;
	struct aoe_send_queue *queue = dev->queue;
	struct aoe_send_queue_elem *elem;

	if (!queue || !queue->task)
		return -ENOSYS;

	aoe_entry_inc(entry);

	/* If we did not get the lock check that
 	 * thread has not gone
 	 */
again:
	if (!(mutex_trylock(&queue->tail_lock))) {
		if (queue->shutdown)
			return -ENODEV;
		else
			goto again;
	}


	if (queue->queue_len == QUEUE_SIZE)
		goto fail;

	/* this list could be empty but the mutex protects us here */
	elem = list_first_entry(&queue->free_list,
				struct aoe_send_queue_elem,
				list);

	if (!elem)
		goto fail;

	list_move_tail(&elem->list, &queue->used_list);
	queue->queue_len++;
	elem->msg = msg;

	mutex_unlock(&queue->tail_lock);

	/* wake up the send thread if not already pending */
	wake_up(&queue->pending);

	DPRINTK("added %d\n", elem->idx);

	return 0;
fail:
	mutex_unlock(&queue->tail_lock);
	printk(KERN_ERR "Failure to add to send queue %d\n", queue->queue_len);
	aoe_entry_dec(entry);
	return -ENOSPC;
}

/* kernel thread that will 
 * 1. pull off the bottom of the queue
 * 2. Initiate a blocking rpc over driverlink/mcdi
 * 3. Place the response on the recv queue
 *
 * This will allow sends to be non overlapping
 * but also allow more than one client to have and
 * outstanding message that needs picking up
 * As well as allowing the calling thread
 * context to block after placing a message on the 
 * top of the queue or return straight away.
 *
 * It will also allow a level of interleaving in 
 * future
 */

int aoe_qu_setup(struct aoe_device *dev, int queue_elems)
{
	int idx;
	struct task_struct *send_thread;
	struct aoe_send_queue_elem *new_queue;
	struct aoe_send_queue_elem *elem;
	struct aoe_send_queue *send_queue;
	int queue_size = sizeof(struct aoe_send_queue_elem) * QUEUE_SIZE;
	int ret;

	/* Pre allocated the queue to match the number of fd's
	 * This may become a multiple in future */

	send_queue = kzalloc(sizeof(struct aoe_send_queue), GFP_KERNEL);
	if (!send_queue) {
		printk(KERN_ERR "Could not allocate QUEUE_struct\n");
		return -ENOMEM;
	}

	new_queue = kzalloc(queue_size, GFP_KERNEL);
	if (!new_queue) {
		printk(KERN_ERR "Could not allocate QUEUE\n");
		ret = -ENOMEM;
		goto out_struct;
	}

	mutex_init(&send_queue->tail_lock);
	INIT_LIST_HEAD(&send_queue->free_list);
	INIT_LIST_HEAD(&send_queue->used_list);
	init_waitqueue_head(&send_queue->pending);

	send_queue->elements = new_queue;
	send_queue->queue_len = 0;

	/* Need to pre-link the elements of the queue onto the freelist */
	for (idx = 0, elem = new_queue; idx < QUEUE_SIZE; idx++, elem++) {
		INIT_LIST_HEAD(&elem->list);
		list_add(&elem->list, &send_queue->free_list);
		elem->idx = idx;
	}

	send_thread = kthread_run(aoe_qu_bottom_thread,
				  (void*)send_queue, "aoe_send");

	if (!send_thread) {
		ret = -ENOMEM;
		goto out;
	}

	/* Start the completion work queue as well */

	send_queue->task = send_thread;
	dev->queue = send_queue;

	return 0;

out:
	kfree(new_queue);
out_struct:
	kfree(send_queue);
	return ret;
}

void aoe_qu_destroy(struct aoe_device *dev)
{
	struct aoe_send_queue *send_queue = dev->queue;
	struct task_struct *send_thread;

	if (!send_queue->task)
		return;

	send_queue->shutdown = true;
	send_thread = send_queue->task;
	send_queue->task = NULL;

	mutex_lock(&send_queue->tail_lock);

	/* Need to stop the completion work queue is well */
	kthread_stop(send_thread);

	/* Once no more msgs are being added the ones that
 	 * are need to be completed */
	aoe_qu_flush(send_queue);
	
	kfree(send_queue->elements);
	send_queue->elements = NULL;

	mutex_destroy(&send_queue->tail_lock);
	kfree(send_queue);
	dev->queue = NULL;
}
