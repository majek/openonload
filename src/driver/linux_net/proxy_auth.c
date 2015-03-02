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
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "net_driver.h"
#include "nic.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mcdi_proxy.h"

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_IS_POWER_OF_2)
#include <linux/log2.h>
#endif

#ifdef EFX_USE_MCDI_PROXY_AUTH

#include "proxy_auth.h"

#define OP_MASK_SIZE MC_CMD_PROXY_CONFIGURE_IN_ALLOWED_MCDI_MASK_LEN
#define OP_MAX (OP_MASK_SIZE * 8)

/* The timeout on the userspace app is set shorter than the MCDI timeout.
 * This should avoid timeouts in the proxy client in the event of app timeouts.
 */
#define APP_TIMEOUT   (MCDI_RPC_TIMEOUT / 2)

/* This structure is shared with the MC. We check the offset of each field
 * with BUILD_BUG_ON. */
struct proxy_mc_state {
	u32 handle;
	u16 pf;
	u16 vf;
	u16 rid;
	u16 status;
	u32 granted_privileges;
} __attribute__ (( packed ));

enum proxy_request_state {
	PROXY_REQ_IDLE,
	PROXY_REQ_INCOMING,
	PROXY_REQ_OUTSTANDING,
	PROXY_REQ_COMPLETED,
	PROXY_REQ_RESPONDING,
};

/**
 * struct proxy_req_state - per request state
 * @state:              request state, from #proxy_request_state
 * @deadline:           request deadline in jiffies
 * @list:               list structure
 * @result:             proxying result
 * @granted_privileges: if result is authorized, granted privilege mask
 * @complete_cb:        callback to call once response has been sent to MC
 * @cb_context:         context to accompany callback
 */
struct proxy_req_state {
	atomic_t state;
	unsigned long deadline;
	struct list_head list;
	int result;
	u32 granted_privileges;
	void (*complete_cb)(int, void *);
	void *cb_context;
};

enum proxy_auth_state {
	PROXY_AUTH_ADMIN_STARTING = 0,
	PROXY_AUTH_ADMIN_READY,
	PROXY_AUTH_ADMIN_STOPPING,
	PROXY_AUTH_ADMIN_RESTARTING,
};

/**
 * struct proxy_admin_state - overall proxying state
 * @efx:                NIC context.
 * @state:              Current auth admin state - are we accepting requests?
 * @req_state:          Per-request state array.
 * @session_tag:        Per-session tag, to allow distinguishing responses after
 *                      a userspace restart.
 * @default_result:     Proxy authorization result if userspace is dead.
 * @op_mask:            Bit mask of MCDI operations to proxy.
 * @handled_privileges: Privilege mask handled by the proxying mechanism.
 * @request_func:       Function to call to handle requests.
 * @stopped_func:       Function to call when proxying is stopped externally.
 * @request_size:       Maximum MCDI request size.
 * @response_size:      Maximum MCDI response size.
 * @block_count:        Total number of functions being proxied.
 * @request_buffer:     Device mapped buffer for MCDI requests.
 * @response_buffer:    Device mapped buffer for MCDI responses.
 * @status_buffer:      Device mapped buffer for MC proxy state storage.
 * @workqueue:          Workqueue for executing.
 * @request_work:       Work item for handling incoming requests.
 * @completed_work:     Work item for sending responses.
 * @detach_work:        Work item for handling MCDI detach.
 * @timeout_dwork:      Delayed work item for handling timeouts.
 * @incoming:           List of incoming items to be passed to userspace.
 * @outstanding:        List of outstanding items pending reply from userspace.
 * @completed:          List of completed items pending response to MC.
 * @incoming_lock:      Lock for incoming list.
 * @outstanding_lock:   Lock for outstanding list.
 * @completed_lock:     Lock for completed list.
 */
struct proxy_admin_state {
	struct efx_nic *efx;

	enum proxy_auth_state state;
	struct proxy_req_state *req_state;
	u16 session_tag;

	u32 default_result;
	u32 op_mask[DIV_ROUND_UP(OP_MASK_SIZE, sizeof(u32))];
	u32 handled_privileges;

	efx_proxy_auth_send_request *request_func;
	efx_proxy_auth_stopped *stopped_func;

	size_t request_size;
	size_t response_size;
	unsigned int block_count;
	struct efx_buffer request_buffer;
	struct efx_buffer response_buffer;
	struct efx_buffer status_buffer;

	struct workqueue_struct *workqueue;
	struct work_struct request_work;
	struct work_struct completed_work;
	struct work_struct detach_work;
	struct delayed_work timeout_dwork;

	struct list_head incoming;
	struct list_head outstanding;
	struct list_head completed;
	spinlock_t incoming_lock;
	spinlock_t outstanding_lock;
	spinlock_t completed_lock;
};

/* Allow forcing of authorization via module parameters. If proxy_force_enable
 * is set then no requests will be sent to userspace. The result of the
 * authorization request will be proxy_force_allow - authorized if true.
 */
static bool proxy_force_enable;
module_param(proxy_force_enable, bool, 0644);
MODULE_PARM_DESC(proxy_force_enable,
		"Enable forcing of proxy authorization to value in proxy_force_allow");

static bool proxy_force_allow;
module_param(proxy_force_allow, bool, 0644);
MODULE_PARM_DESC(proxy_force_allow,
		"Authorization result for proxy_force_enable");


static u16 proxy_auth_session_tag;


static void efx_proxy_request_work(struct work_struct *);
static void efx_proxy_completed_work(struct work_struct *);
static void efx_proxy_detach_work(struct work_struct *work);
static void efx_proxy_timeout_work(struct work_struct *);

static int efx_proxy_auth_fill_op_mask(struct proxy_admin_state *pa,
		unsigned int *op_list, unsigned int op_count)
{
	int i;

	if (!op_list)
		return -EINVAL;

	while (op_count--) {
		unsigned int op = *op_list++;

		if (op > OP_MAX)
			return -EINVAL;
		pa->op_mask[op/32] |= 1 << (op & 31);
	}

	for (i = 0; i < ARRAY_SIZE(pa->op_mask); i++)
		cpu_to_le32s(pa->op_mask + i);

	return 0;
}

static bool efx_proxy_auth_mc_check_admin(struct efx_nic *efx)
{
	u32 privilege_mask;
	int rc;

	rc = efx_mcdi_get_privilege_mask(efx, &privilege_mask);
	if (rc == 0 && (privilege_mask & MC_CMD_PRIVILEGE_MASK_IN_GRP_ADMIN))
		return true;

	return false;
}

static int efx_proxy_auth_mc_config(struct proxy_admin_state *pa)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PROXY_CONFIGURE_IN_LEN);
	int rc;

	BUILD_BUG_ON(MC_CMD_PROXY_CONFIGURE_IN_LEN <
		     MC_CMD_PRIVILEGE_MODIFY_IN_LEN);

	/* Configure proxying for the required operations. */
	MCDI_SET_DWORD(inbuf, PROXY_CONFIGURE_IN_FLAGS, 1);
	MCDI_SET_QWORD(inbuf, PROXY_CONFIGURE_IN_REQUEST_BUFF_ADDR,
			pa->request_buffer.dma_addr);
	MCDI_SET_QWORD(inbuf, PROXY_CONFIGURE_IN_REPLY_BUFF_ADDR,
			pa->response_buffer.dma_addr);
	MCDI_SET_QWORD(inbuf, PROXY_CONFIGURE_IN_STATUS_BUFF_ADDR,
			pa->status_buffer.dma_addr);
	MCDI_SET_DWORD(inbuf, PROXY_CONFIGURE_IN_REQUEST_BLOCK_SIZE,
			pa->request_size);
	MCDI_SET_DWORD(inbuf, PROXY_CONFIGURE_IN_REPLY_BLOCK_SIZE,
			pa->response_size);
	MCDI_SET_DWORD(inbuf, PROXY_CONFIGURE_IN_STATUS_BLOCK_SIZE,
			MC_PROXY_STATUS_BUFFER_LEN);
	MCDI_SET_DWORD(inbuf, PROXY_CONFIGURE_IN_NUM_BLOCKS, pa->block_count);

	memcpy(MCDI_PTR(inbuf, PROXY_CONFIGURE_IN_ALLOWED_MCDI_MASK),
			pa->op_mask, sizeof(pa->op_mask));

	rc = efx_mcdi_rpc(pa->efx, MC_CMD_PROXY_CONFIGURE,
			inbuf, sizeof(inbuf), NULL, 0, NULL);

	if (rc != 0)
		return rc;

	/* Remove privileges from non-admin functions that are to be handled by
	 * the proxying mechanism.
	 */
	if (!pa->handled_privileges)
		return rc;

	memset(inbuf, 0, MC_CMD_PRIVILEGE_MODIFY_IN_LEN);

	MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_FN_GROUP,
			MC_CMD_PRIVILEGE_MODIFY_IN_ALL);
	MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_ADD_MASK, 0);
	MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_REMOVE_MASK,
			pa->handled_privileges);

	rc = efx_mcdi_rpc(pa->efx, MC_CMD_PRIVILEGE_MODIFY,
			inbuf, MC_CMD_PRIVILEGE_MODIFY_IN_LEN, NULL, 0, NULL);

	if (rc) {
		/* Unable to set privileges - undo proxy configuration. */
		memset(inbuf, 0, MC_CMD_PROXY_CONFIGURE_IN_LEN);
		efx_mcdi_rpc(pa->efx, MC_CMD_PROXY_CONFIGURE,
				inbuf, sizeof(inbuf), NULL, 0, NULL);
	}

	return rc;
}

static void efx_proxy_auth_free(struct efx_nic *efx,
		struct proxy_admin_state *pa)
{
	if (!pa || !efx)
		return;

	if (pa->workqueue)
		destroy_workqueue(pa->workqueue);

	efx_nic_free_buffer(efx, &pa->request_buffer);
	efx_nic_free_buffer(efx, &pa->response_buffer);
	efx_nic_free_buffer(efx, &pa->status_buffer);

	kfree(pa->req_state);
	kfree(pa);
	efx->proxy_admin_state = NULL;
}


/**
 * efx_proxy_auth_configure_list() - set up proxy authorization for multiple ops
 * @efx:                NIC context.
 * @request_size:       Size to allow for each MCDI request.
 * @response_size:      Size to allow for each MCDI response.
 * @op_list:            Pointer to list of MCDI operations to be proxied.
 * @op_count:           Number of entries in op_list.
 * @handled_privileges: Privileges handled by the MCDI proxy.
 * @default_result:     Default result if userspace doesn't respond.
 * @request_func:       Function to call to handle requests.
 * @stopped_func:       Function to call when proxying is stopped externally.
 *
 * Configure the proxy MCDI authorization mechanism for multiple MCDI
 * operations. The request_size and response_size should be appropriate for the
 * operations being proxied.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_configure_list(struct efx_nic *efx,
		size_t request_size, size_t response_size,
		unsigned int *op_list, unsigned int op_count,
		u32 handled_privileges, u32 default_result,
		efx_proxy_auth_send_request *request_func,
		efx_proxy_auth_stopped *stopped_func)
{
	struct proxy_admin_state *pa;
	int block_count;
	int rc;

	if (!is_power_of_2(request_size) || !is_power_of_2(response_size))
		return -EINVAL;

	if (default_result > MC_CMD_PROXY_COMPLETE_IN_TIMEDOUT)
		return -EINVAL;

	if (!request_func)
		return -EINVAL;

	if (efx->proxy_admin_state)
		return -EBUSY;

	/* We're potentially going to allocate a contiguous block of memory
	 * that's substantially larger than a 4k page. Before we do that we
	 * check our permissions to see if we have any chance of successfully
	 * configuring this.
	 */
	if (!efx_proxy_auth_mc_check_admin(efx))
		return -EPERM;

	/* We need a block for every function, both PF and VF. There is
	 * currently no way to determine this at runtime, since it can be
	 * reconfigure quite arbitrarily. However, the index in to the various
	 * buffers is only 8 bits, so we have an upper bound of 256 entries.
	 */
	block_count = 256;

	pa = kzalloc(sizeof(*pa), GFP_KERNEL);
	if (!pa)
		return -ENOMEM;

	/* Process op list. */
	rc = efx_proxy_auth_fill_op_mask(pa, op_list, op_count);
	if (rc)
		goto fail_config;

	/* Allocate per-request storage. */
	pa->req_state = kcalloc(block_count,
			sizeof *(pa->req_state), GFP_KERNEL);
	if (!pa->req_state) {
		rc = -ENOMEM;
		goto fail_config;
	}

	/* Allocate three contiguous buffers for receiving requests, returning
	 * responses and bookkeeping.
	 */
	rc = efx_nic_alloc_buffer(efx, &pa->request_buffer,
			request_size * block_count, GFP_KERNEL);
	if (rc)
		goto fail_config;

	rc = efx_nic_alloc_buffer(efx, &pa->response_buffer,
			response_size * block_count, GFP_KERNEL);
	if (rc)
		goto fail_config;

	BUILD_BUG_ON(sizeof(struct proxy_mc_state) !=
			MC_PROXY_STATUS_BUFFER_LEN);
	rc = efx_nic_alloc_buffer(efx, &pa->status_buffer,
			MC_PROXY_STATUS_BUFFER_LEN * block_count,
			GFP_KERNEL);
	if (rc)
		goto fail_config;


	/* Create work queue and items for:
	 *  - submitting new requests to userspace;
	 *  - handling timeouts
	 */
	pa->workqueue = create_singlethread_workqueue("efx-proxy");
	INIT_WORK(&pa->request_work, efx_proxy_request_work);
	INIT_WORK(&pa->completed_work, efx_proxy_completed_work);
	INIT_WORK(&pa->detach_work, efx_proxy_detach_work);
	INIT_DELAYED_WORK(&pa->timeout_dwork, efx_proxy_timeout_work);

	/* Create lists for:
	 *  - queueing incoming requests;
	 *  - holding requests that have been passed to userspace
	 *  - holding responses to be passed back to the MC
	 */
	INIT_LIST_HEAD(&pa->incoming);
	INIT_LIST_HEAD(&pa->outstanding);
	INIT_LIST_HEAD(&pa->completed);

	spin_lock_init(&pa->outstanding_lock);
	spin_lock_init(&pa->incoming_lock);
	spin_lock_init(&pa->completed_lock);

	pa->efx = efx;
	pa->request_func = request_func;
	pa->stopped_func = stopped_func;
	pa->request_size = request_size;
	pa->response_size = response_size;
	pa->block_count = block_count;
	pa->default_result = default_result;
	pa->session_tag = proxy_auth_session_tag++;
	pa->handled_privileges = handled_privileges;

	rc = efx_proxy_auth_mc_config(pa);
	if (rc)
		goto fail_config;

	efx->proxy_admin_state = pa;

	write_lock_bh(&efx->proxy_admin_lock);
	pa->state = PROXY_AUTH_ADMIN_READY;
	write_unlock_bh(&efx->proxy_admin_lock);

	netif_dbg(efx, drv, efx->net_dev, "%s: configured proxy auth\n",
			__func__);

	return 0;

fail_config:
	netif_err(efx, drv, efx->net_dev, "%s: failed %d\n", __func__, rc);
	efx_proxy_auth_free(efx, pa);

	return rc;
}

/**
 * efx_proxy_auth_configure_one() - set up proxy authorization for one op
 * @efx:                NIC context.
 * @request_size:       Size to allow for each MCDI request.
 * @response_size:      Size to allow for each MCDI response.
 * @op:                 MCDI operation to be proxied.
 * @handled_privileges: Privileges handled by the MCDI proxy.
 * @default_result:     Default result if userspace doesn't respond.
 * @request_func:       Function to call to handle requests.
 * @stopped_func:       Function to call when proxying is stopped externally.
 *
 * Configure the proxy MCDI authorization mechanism for a single MCDI
 * operation. The request_size and response_size should be appropriate for the
 * operation being proxied.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_configure_one(struct efx_nic *efx,
		size_t request_size, size_t response_size, unsigned int op,
		u32 handled_privileges, u32 default_result,
		efx_proxy_auth_send_request *request_func,
		efx_proxy_auth_stopped *stopped_func)
{
	if (op > OP_MAX)
		return -EINVAL;

	return efx_proxy_auth_configure_list(efx, request_size, response_size,
			&op, 1, handled_privileges, default_result,
			request_func, stopped_func);
}

/**
 * efx_proxy_auth_stop() - stop proxy authorization
 * @efx:       NIC context.
 * @unloading: true if driver is unloading; false if requested by userspace.
 *
 * This stops proxy MCDI authorization as configured by
 * efx_proxy_auth_configure_one() or efx_proxy_auth_configure_list(). All
 * outstanding requests will be completed with -EPIPE. Further requests will
 * be ignored.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_stop(struct efx_nic *efx, bool unloading)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PROXY_CONFIGURE_IN_LEN);
	struct proxy_admin_state *pa;
	int rc = 0;

	if (!efx)
		return -EINVAL;

	if (in_interrupt()) {
		/* If we're in interrupt context defer the stop. We do this
		 * in the shared workqueue, since one of things we need to do
		 * is destroy our workqueue.
		 */
		netif_dbg(efx, drv, efx->net_dev, "%s: deferring stop\n",
				__func__);
		schedule_work(&efx->proxy_admin_stop_work);
		return -EAGAIN;
	}

	/* Claim the mutex; we need a lock that allows us to schedule, since
	 * we're going to do things with workqueues. */
	mutex_lock(&efx->proxy_admin_mutex);

	/* Ignore any further requests or responses coming in. */
	write_lock_bh(&efx->proxy_admin_lock);
	pa = efx->proxy_admin_state;
	if (!pa)
		rc = -EINVAL;
	else
		pa->state = PROXY_AUTH_ADMIN_STOPPING;
	write_unlock_bh(&efx->proxy_admin_lock);
	if (rc) {
		mutex_unlock(&efx->proxy_admin_mutex);
		return rc;
	}

	if (pa->workqueue) {
		/* Finish off anything that we've already started. */
		cancel_delayed_work(&pa->timeout_dwork);
		destroy_workqueue(pa->workqueue);
		pa->workqueue = NULL;
	}

	/* Tell userspace we've gone away. */
	if (unloading && pa->stopped_func)
		pa->stopped_func(efx);

	/* Restore permissions that we've been proxying. */
	if (pa->handled_privileges) {
		MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_FN_GROUP,
				MC_CMD_PRIVILEGE_MODIFY_IN_ALL);
		MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_ADD_MASK,
				pa->handled_privileges);
		MCDI_SET_DWORD(inbuf, PRIVILEGE_MODIFY_IN_REMOVE_MASK, 0);
		rc = efx_mcdi_rpc(efx, MC_CMD_PRIVILEGE_MODIFY,
				inbuf, MC_CMD_PRIVILEGE_MODIFY_IN_LEN,
				NULL, 0, NULL);
		if (rc)
			netif_err(efx, drv, efx->net_dev,
					"%s: failed to restore privileges %d\n",
					__func__, rc);
	}

	/* Turn off proxying in MC - marks outstanding requests as declined. */
	memset(inbuf, 0, MC_CMD_PROXY_CONFIGURE_IN_LEN);
	rc = efx_mcdi_rpc(efx, MC_CMD_PROXY_CONFIGURE, inbuf, sizeof(inbuf),
			NULL, 0, NULL);

	if (rc) {
		/* TODO: what should we really do here? */
		netif_err(efx, drv, efx->net_dev,
				"%s: failed to stop proxying %d\n",
				__func__, rc);
	}

	efx_proxy_auth_free(efx, pa);
	mutex_unlock(&efx->proxy_admin_mutex);

	return rc;
}

/**
 * efx_proxy_auth_detached() - proxy authorization has stopped
 * @efx:       NIC context.
 *
 * Called when the MC has stopped performing proxy authorization without us
 * asking. This is normally the result of an MC reset, BIST, etc. Outstanding
 * requests are no longer valid, since the MC will now ignore any responses.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_detached(struct efx_nic *efx)
{
	struct proxy_admin_state *pa;

	write_lock_bh(&efx->proxy_admin_lock);
	pa = efx->proxy_admin_state;
	if (!pa || (pa->state != PROXY_AUTH_ADMIN_READY)) {
		write_unlock_bh(&efx->proxy_admin_lock);
		return -EINVAL;
	}
	pa->state = PROXY_AUTH_ADMIN_RESTARTING;

	/* Moving out of the READY state means we'll no longer:
	 *  - accept new requests in handle_request
	 *  - accept responses in handle_response
	 *  - queue additional work on our workqueue
	 */

	/* We do the rest of the detach in a work item. This means that we'll
	 * have finished processing other work items by then, and the workqueue
	 * should then be empty.
	 */
	queue_work(pa->workqueue, &pa->request_work);
	write_unlock_bh(&efx->proxy_admin_lock);

	return 0;
}

static void efx_proxy_detach_work(struct work_struct *data)
{
	struct proxy_admin_state *pa;
	int index;

	pa = container_of(data, struct proxy_admin_state, detach_work);

	/* Flush the lists for the various work items. */
	spin_lock_bh(&pa->incoming_lock);
	INIT_LIST_HEAD(&pa->incoming);
	spin_unlock_bh(&pa->incoming_lock);

	spin_lock_bh(&pa->outstanding_lock);
	INIT_LIST_HEAD(&pa->outstanding);
	spin_unlock_bh(&pa->outstanding_lock);

	spin_lock_bh(&pa->completed_lock);
	INIT_LIST_HEAD(&pa->completed);
	spin_unlock_bh(&pa->completed_lock);

	/* Re-initialise per-request state and MC shared state. */
	for (index = 0; index < pa->block_count; index++) {
		int req_state = atomic_read(&pa->req_state[index].state);
		if (req_state != PROXY_REQ_IDLE)
			netif_warn(pa->efx, drv, pa->efx->net_dev,
					"%s: dropped req index %d, state %d\n",
					__func__, index, req_state);

		atomic_set(&pa->req_state[index].state, PROXY_REQ_IDLE);
		INIT_LIST_HEAD(&pa->req_state[index].list);
	}
	memset(pa->status_buffer.addr, 0,
			sizeof(struct proxy_mc_state) * pa->block_count);

	/* Don't free resources - we expect to be re-attached in the near
	 * future, at which point we'll want those resources still.
	 */
}

/**
 * efx_proxy_auth_attach() - proxy authorization is available again
 * @efx:       NIC context.
 *
 * Called when the MC is available for proxy authorization again having
 * previously detached. Unless we've been told to stop since detaching we will
 * re-configure proxying as before.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_attach(struct efx_nic *efx)
{
	struct proxy_admin_state *pa;
	int rc;

	mutex_lock(&efx->proxy_admin_mutex);

	write_lock_bh(&efx->proxy_admin_lock);
	pa = efx->proxy_admin_state;
	if (!pa || (pa->state != PROXY_AUTH_ADMIN_RESTARTING)) {
		/* Either proxying isn't in use or
		 * we've been stopped since detaching. */
		write_unlock_bh(&efx->proxy_admin_lock);
		mutex_unlock(&efx->proxy_admin_mutex);
		return -EINVAL;
	}
	write_unlock_bh(&efx->proxy_admin_lock);

	/* The last item on the workqueue after detaching will have been
	 * detach_work. So by ensuring the workqueue is empty we ensure the
	 * detach has actually completed before re-attaching.
	 */
	flush_workqueue(pa->workqueue);

	netif_dbg(efx, drv, efx->net_dev,
			"%s: re-attaching proxying\n", __func__);

	/* Any responses from user space from before we restarted are invalid,
	 * so we update our session tag.
	 */
	pa->session_tag = proxy_auth_session_tag++;

	rc = efx_proxy_auth_mc_config(pa);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
				"%s: failed to re-configure proxying %d\n",
				__func__, rc);

		if (pa->stopped_func)
			pa->stopped_func(efx);
		efx_proxy_auth_free(efx, pa);
	} else {
		pa->state = PROXY_AUTH_ADMIN_READY;
	}

	mutex_unlock(&efx->proxy_admin_mutex);

	return rc;
}

/**
 * efx_proxy_auth_handle_request() - handle a proxy request from the MC
 * @efx:   NIC context.
 * @index: Request index from MC.
 *
 * Handle an incoming proxy authorization request from the MC. If there is
 * already an outstanding request for this @index the request will fail.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_handle_request(struct efx_nic *efx, u32 index)
{
	struct proxy_admin_state *pa = efx->proxy_admin_state;
	struct proxy_req_state *req;
	int rc = 0;

	netif_dbg(efx, drv, efx->net_dev, "%s: rx request on index %d\n",
			__func__, index);

	/* Take state lock for read. Prevent state changes until after
	 * request has been accepted.
	 */
	read_lock_bh(&efx->proxy_admin_lock);
	if (!pa || pa->state != PROXY_AUTH_ADMIN_READY) {
		rc = -EBUSY;
		goto out_request;
	}

	if (index >= pa->block_count) {
		rc = -EINVAL;
		goto out_request;
	}
	req = &pa->req_state[index];

	if (atomic_cmpxchg(&req->state, PROXY_REQ_IDLE,
				PROXY_REQ_INCOMING) != PROXY_REQ_IDLE) {
		netif_err(efx, drv, efx->net_dev, "%s: invalid req state %d\n",
				__func__, atomic_read(&req->state));
		rc = -EBUSY;
		goto out_request;
	}

	spin_lock_bh(&pa->incoming_lock);
	list_add_tail(&req->list, &pa->incoming);
	spin_unlock_bh(&pa->incoming_lock);

	req->deadline = jiffies + APP_TIMEOUT;

	queue_work(pa->workqueue, &pa->request_work);
	queue_delayed_work(pa->workqueue, &pa->timeout_dwork,
			APP_TIMEOUT + 1);

out_request:
	read_unlock_bh(&efx->proxy_admin_lock);
	return rc;
}

/* Send a response, if we haven't already. */
static int efx_proxy_auth_send_response(struct proxy_admin_state *pa, u32 index,
		struct proxy_req_state *req)
{
	int rc;

	/* Check we haven't already sent a response. */
	if (atomic_cmpxchg(&req->state, PROXY_REQ_COMPLETED,
				PROXY_REQ_RESPONDING) != PROXY_REQ_COMPLETED) {
		netif_dbg(pa->efx, drv, pa->efx->net_dev,
				"%s: response already sent for index %d, %d\n",
				__func__, index, atomic_read(&req->state));
		rc = -EALREADY;
	} else {
		MCDI_DECLARE_BUF(inbuf, MC_CMD_PROXY_COMPLETE_IN_LEN);
		struct proxy_mc_state *mc_state;
		u32 handle;

		if (req->result > MC_CMD_PROXY_COMPLETE_IN_TIMEDOUT)
			req->result = MC_CMD_PROXY_COMPLETE_IN_DECLINED;

		mc_state = pa->status_buffer.addr;
		mc_state += index;
		handle = mc_state->handle;

		netif_dbg(pa->efx, drv, pa->efx->net_dev,
				"%s: sending %d for handle %d on index %d\n",
				__func__, req->result, handle, index);

		MCDI_SET_DWORD(inbuf, PROXY_COMPLETE_IN_BLOCK_INDEX, index);
		MCDI_SET_DWORD(inbuf, PROXY_COMPLETE_IN_STATUS, req->result);
		MCDI_SET_DWORD(inbuf, PROXY_COMPLETE_IN_HANDLE, handle);

		BUILD_BUG_ON(offsetof(struct proxy_mc_state, status) !=
				MC_PROXY_STATUS_BUFFER_STATUS_OFST);
		mc_state->status = req->result;
		if (req->result == MC_CMD_PROXY_COMPLETE_IN_AUTHORIZED)
			mc_state->granted_privileges = req->granted_privileges;

		rc = efx_mcdi_rpc(pa->efx, MC_CMD_PROXY_COMPLETE,
				inbuf, sizeof(inbuf),
				NULL, 0, NULL);

		if (rc)
			netif_warn(pa->efx, drv, pa->efx->net_dev,
					"%s: MC complete returned %d\n",
					__func__, rc);
	}

	atomic_set(&req->state, PROXY_REQ_IDLE);

	return rc;
}

/**
 * efx_proxy_auth_handle_response() - handle replies from user space
 * @pa:                 Proxy admin state context.
 * @uhandle:            Handle as passed to .request_func().
 * @result:             Result of authorization.
 * @granted_privileges: Elevated privileges for case where proxy is authorized
 * @response_buffer:    If the requested operation has been carried out on
 *                      behalf of the requesting function this buffer will
 *                      contain the MCDI response.
 * @response_size:      Size of @response_buffer.
 * @complete_cb:        Callback upon completion. Called iff return is zero.
 * @cb_context:         Callback context.
 *
 * Return: zero on success, error code on failure.
 */
int efx_proxy_auth_handle_response(struct proxy_admin_state *pa,
		u64 uhandle, u32 result, u32 granted_privileges,
		void *response_buffer, size_t response_size,
		void (*complete_cb)(int, void*), void *cb_context)
{
	struct proxy_mc_state *mc_state;
	struct proxy_req_state *req;
	u32 handle;
	u32 index;
	int rc;

	/* Take state lock for read. Prevent state changes until after
	 * request has been accepted.
	 */
	read_lock_bh(&pa->efx->proxy_admin_lock);
	if (!pa || pa->state != PROXY_AUTH_ADMIN_READY) {
		rc = -ESHUTDOWN;
		goto out_response;
	}

	/* Check response is from current userspace session. */
	if ((uhandle & 0xffff) != pa->session_tag) {
		rc = -EINVAL;
		goto out_response;
	}

	/* Split user handle into index and handle. */
	index = (uhandle >> 16) & 0xffff;
	handle = (uhandle >> 32) & 0xffffffff;

	if (index >= pa->block_count) {
		rc = -EINVAL;
		goto out_response;
	}

	mc_state = pa->status_buffer.addr;
	mc_state += index;

	/* Check handle is the one we're expecting. */
	if (mc_state->handle != handle) {
		rc = -EINVAL;
		goto out_response;
	}

	/* Now copy response buffer if applicable. */
	if (response_buffer && (response_size < pa->response_size)) {
		char *result_dest = pa->response_buffer.addr;

		result_dest += pa->response_size * index;
		memcpy(result_dest, response_buffer, response_size);
	} else if (result == MC_CMD_PROXY_COMPLETE_IN_COMPLETE) {
		/* Completed but no response - invalid. */
		netif_warn(pa->efx, drv, pa->efx->net_dev,
				"%s: completed without response for handle %d on index %d\n",
				__func__, handle, index);
		result = MC_CMD_PROXY_COMPLETE_IN_DECLINED;
	}

	req = &pa->req_state[index];
	req->result = result;
	req->granted_privileges = granted_privileges;

	req->complete_cb = complete_cb;
	req->cb_context = cb_context;

	spin_lock_bh(&pa->outstanding_lock);
	list_del_init(&req->list);
	spin_unlock_bh(&pa->outstanding_lock);

	atomic_set(&req->state, PROXY_REQ_COMPLETED);

	spin_lock_bh(&pa->completed_lock);
	list_add_tail(&req->list, &pa->completed);
	spin_unlock_bh(&pa->completed_lock);

	queue_work(pa->workqueue, &pa->completed_work);
	rc = 0;

out_response:
	read_unlock_bh(&pa->efx->proxy_admin_lock);
	return rc;
}

static struct proxy_req_state *efx_proxy_get_outstanding(
		struct proxy_admin_state *pa)
{
	struct proxy_req_state *req;

	spin_lock_bh(&pa->outstanding_lock);
	req = list_first_entry_or_null(&pa->outstanding,
			struct proxy_req_state, list);
	spin_unlock_bh(&pa->outstanding_lock);

	return req;
}

static struct proxy_req_state *efx_proxy_pop_incoming(
		struct proxy_admin_state *pa)
{
	struct proxy_req_state *req;

	spin_lock_bh(&pa->incoming_lock);
	req = list_first_entry_or_null(&pa->incoming,
			struct proxy_req_state, list);
	if (req)
		list_del_init(&req->list);
	spin_unlock_bh(&pa->incoming_lock);

	return req;
}

static void efx_proxy_request_work(struct work_struct *data)
{
	struct proxy_mc_state *mc_state;
	struct proxy_admin_state *pa;
	struct proxy_req_state *req;
	char *request_buff;

	pa = container_of(data, struct proxy_admin_state, request_work);

	while ((req = efx_proxy_pop_incoming(pa))) {
		u64 uhandle;
		u32 index = req - pa->req_state;
		int rc;
		bool immed_send = false;
		u32 immed_result;
		u16 pf, vf, rid;
		u32 handle;

		WARN_ON(index >= pa->block_count);
		if (index >= pa->block_count) {
			/* Invalid entry: throw it away. */
			continue;
		}

		if (atomic_cmpxchg(&req->state, PROXY_REQ_INCOMING,
				PROXY_REQ_OUTSTANDING) != PROXY_REQ_INCOMING) {
			netif_err(pa->efx, drv, pa->efx->net_dev,
					"%s: invalid state %d on index %d\n",
					__func__, atomic_read(&req->state),
					index);
			continue;
		}

		netif_dbg(pa->efx, drv, pa->efx->net_dev,
				"%s: handling index %d\n", __func__, index);

		mc_state = pa->status_buffer.addr;
		mc_state += index;

		BUILD_BUG_ON(offsetof(struct proxy_mc_state, handle) !=
				MC_PROXY_STATUS_BUFFER_HANDLE_OFST);
		BUILD_BUG_ON(offsetof(struct proxy_mc_state, pf) !=
				MC_PROXY_STATUS_BUFFER_PF_OFST);
		BUILD_BUG_ON(offsetof(struct proxy_mc_state, vf) !=
				MC_PROXY_STATUS_BUFFER_VF_OFST);
		BUILD_BUG_ON(offsetof(struct proxy_mc_state, rid) !=
				MC_PROXY_STATUS_BUFFER_RID_OFST);

		pf = mc_state->pf;
		vf = mc_state->vf;
		rid = mc_state->rid;
		handle = mc_state->handle;

		if (vf == MC_CMD_PROXY_CMD_IN_VF_NULL)
			netif_dbg(pa->efx, drv, pa->efx->net_dev,
					"%s: handling req %d on PF %u, PCI %02x.%x\n",
					__func__, handle, pf,
					(rid >> 3) & 0x1f, rid & 7);
		else
			netif_dbg(pa->efx, drv, pa->efx->net_dev,
					"%s: handling req %d on VF %u:%u, PCI %02x.%x\n",
					__func__, handle, pf, vf,
					(rid >> 3) & 0x1f, rid & 7);

		request_buff = pa->request_buffer.addr;
		request_buff += pa->request_size * index;

		/* Combine the instance, index and handle to an
		 * opaque 64 bit value. */
		uhandle = pa->session_tag |
			  (index & 0x0000ffff) << 16 |
			  (u64)handle << 32;

		if (!proxy_force_enable) {
			spin_lock_bh(&pa->outstanding_lock);
			list_add_tail(&req->list, &pa->outstanding);
			spin_unlock_bh(&pa->outstanding_lock);

			rc = pa->request_func(pa->efx, uhandle,
					pf, vf, rid,
					request_buff, pa->request_size);

			if (rc) {
				immed_send = true;
				immed_result = pa->default_result;
				spin_lock_bh(&pa->outstanding_lock);
				list_del_init(&req->list);
				spin_unlock_bh(&pa->outstanding_lock);
			}
		} else {
			immed_send = true;
			immed_result = proxy_force_allow ?
					MC_CMD_PROXY_COMPLETE_IN_AUTHORIZED :
					MC_CMD_PROXY_COMPLETE_IN_DECLINED;
		}

		if (immed_send) {
			read_lock_bh(&pa->efx->proxy_admin_lock);
			/* If we're no longer in the ready state leave this
			 * in the outstanding state to be picked up by
			 * fail_outstanding.
			 */
			if (pa->state == PROXY_AUTH_ADMIN_READY) {
				req->result = immed_result;
				atomic_set(&req->state, PROXY_REQ_COMPLETED);

				spin_lock_bh(&pa->completed_lock);
				list_add_tail(&req->list, &pa->completed);
				spin_unlock_bh(&pa->completed_lock);

				queue_work(pa->workqueue, &pa->completed_work);
			}
			read_unlock_bh(&pa->efx->proxy_admin_lock);
		}
	}
}

static struct proxy_req_state *efx_proxy_pop_completed(
		struct proxy_admin_state *pa)
{
	struct proxy_req_state *req;

	spin_lock_bh(&pa->completed_lock);
	req = list_first_entry_or_null(&pa->completed,
			struct proxy_req_state, list);
	if (req)
		list_del_init(&req->list);
	spin_unlock_bh(&pa->completed_lock);

	return req;
}

static void efx_proxy_completed_work(struct work_struct *data)
{
	struct proxy_admin_state *pa;
	struct proxy_req_state *req;

	pa = container_of(data, struct proxy_admin_state, completed_work);

	while ((req = efx_proxy_pop_completed(pa))) {
		u32 index = req - pa->req_state;
		struct proxy_mc_state *mc_state;
		void (*cb)(int, void*) = req->complete_cb;
		void *context = req->cb_context;
		int rc;

		netif_dbg(pa->efx, drv, pa->efx->net_dev,
				"%s: completing index %u\n", __func__, index);

		WARN_ON(index > pa->block_count);
		if (index > pa->block_count) {
			rc = -EINVAL;
		} else {
			mc_state = pa->status_buffer.addr;
			mc_state += index;

			rc = efx_proxy_auth_send_response(pa, index, req);
		}

		if (cb)
			cb(rc, context);
	}

	/* Now check for outstanding requests and cancel the timeout if
	 * there are none. */
	spin_lock_bh(&pa->outstanding_lock);
	if (list_empty(&pa->outstanding))
		cancel_delayed_work(&pa->timeout_dwork);
	spin_unlock_bh(&pa->outstanding_lock);
}

/* Fail outstanding requests that have expired at #deadline.
 * This returns the deadline for the next list entry to expire.
 */
static unsigned long efx_proxy_auth_fail_outstanding(
		struct proxy_admin_state *pa, unsigned long now)
{
	struct proxy_req_state *req, *prev;
	struct proxy_mc_state *mc_state;
	unsigned long deadline = 0;
	u32 index;

	/* Check list of outstanding responses.
	 * Replies may still come in for entries in the list, so the list
	 * may change - hence we get the first entry every time.
	 */
	prev = NULL;
	while ((req = efx_proxy_get_outstanding(pa))) {
		if (time_before(now, req->deadline)) {
			deadline = req->deadline;
			break;
		}

		/* Check for loops. */
		if (req == prev) {
			netif_err(pa->efx, drv, pa->efx->net_dev,
					"%s: loop detected\n", __func__);
			break;
		}
		prev = req;

		spin_lock_bh(&pa->outstanding_lock);
		list_del_init(&req->list);
		WARN_ON(!list_empty(&pa->outstanding));
		spin_unlock_bh(&pa->outstanding_lock);

		index = req - pa->req_state;
		WARN_ON(index > pa->block_count);
		if (index > pa->block_count)
			continue;

		req->result = pa->default_result;
		mc_state = pa->status_buffer.addr;
		mc_state += index;

		atomic_set(&req->state, PROXY_REQ_COMPLETED);
		efx_proxy_auth_send_response(pa, index, req);
	}

	return deadline;
}

static void efx_proxy_timeout_work(struct work_struct *data)
{
	struct proxy_admin_state *pa;
	unsigned long next_deadline;
	unsigned long next_delay;
	unsigned long now;

#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_WORK_API_WRAPPERS)
	pa = container_of(data, struct proxy_admin_state, timeout_dwork.work);
#else
	pa = container_of(data, struct proxy_admin_state, timeout_dwork);
#endif

	next_deadline = efx_proxy_auth_fail_outstanding(pa, jiffies);

	if (list_empty(&pa->outstanding))
		return;

	now = jiffies;
	if (time_after_eq(now, next_deadline))
		next_delay = 1;
	else
		next_delay = next_deadline - now + 1;

	read_lock_bh(&pa->efx->proxy_admin_lock);
	if (pa->state == PROXY_AUTH_ADMIN_READY) {
		netif_dbg(pa->efx, drv, pa->efx->net_dev,
				"%s: re-queueing in %lu\n",
				__func__, next_delay);
		queue_delayed_work(pa->workqueue, &pa->timeout_dwork,
				next_delay);
	}
	read_unlock_bh(&pa->efx->proxy_admin_lock);
}

void efx_proxy_auth_stop_work(struct work_struct *data)
{
	struct efx_nic *efx;

	efx = container_of(data, struct efx_nic, proxy_admin_stop_work);
	efx_proxy_auth_stop(efx, true);
}

#endif /* EFX_USE_MCDI_PROXY_AUTH */

