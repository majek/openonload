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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains event handling for VI resource.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
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

#include <ci/efrm/nic_table.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/eventq.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/buffer_table.h>
#include "efrm_internal.h"


static DEFINE_MUTEX(register_evq_cb_mutex);


static inline efhw_event_t *
efrm_eventq_base(struct efrm_vi *virs)
{
	return (efhw_event_t *) efhw_iopages_ptr(&virs->q[EFHW_EVQ].pages);
}


void efrm_eventq_request_wakeup(struct efrm_vi *virs, unsigned current_ptr)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	int next_i;
	next_i = current_ptr & (virs->q[EFHW_EVQ].capacity - 1);
	efhw_nic_wakeup_request(nic, virs->io_page, next_i);
}
EXPORT_SYMBOL(efrm_eventq_request_wakeup);


void efrm_eventq_reset(struct efrm_vi *virs)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_nic *efrm_nic = container_of(nic, struct efrm_nic,
						 efhw_nic);
	int instance = virs->rs.rs_instance;
	int wakeup_evq;

	EFRM_ASSERT(virs->q[EFHW_EVQ].capacity != 0);

	/* FIXME: Protect against concurrent resets. */

	efhw_nic_event_queue_disable(nic, instance,
				  (virs->flags & EFHW_VI_RX_TIMESTAMPS) != 0);

	wakeup_evq = virs->net_drv_wakeup_channel >= 0?
		virs->net_drv_wakeup_channel:
		efrm_nic->rss_channel_count == 0?
		0:
		instance % efrm_nic->rss_channel_count;
	memset(efrm_eventq_base(virs), EFHW_CLEAR_EVENT_VALUE,
	       efrm_vi_rm_evq_bytes(virs, -1));
	virs->out_flags = 0;
	/* NB. We do not enable DOS protection because of bug12916. */
	efhw_nic_event_queue_enable(nic, instance, virs->q[EFHW_EVQ].capacity,
			efrm_bt_allocation_base(&virs->q[EFHW_EVQ].bt_alloc),
			virs->q[EFHW_EVQ].dma_addrs, 
			1 << virs->q[EFHW_EVQ].page_order,
				    /* make siena look like falcon for now */
				    instance < 64, 
				    0, wakeup_evq,
				    (virs->flags &
				     (EFHW_VI_RX_TIMESTAMPS |
				      EFHW_VI_TX_TIMESTAMPS)) != 0,
				    (virs->flags &
				     EFHW_VI_NO_CUT_THROUGH) == 0,
				    &virs->rx_ts_correction,
				    &virs->out_flags);
}
EXPORT_SYMBOL(efrm_eventq_reset);

int
efrm_eventq_register_callback(struct efrm_vi *virs,
			      efrm_evq_callback_fn handler, void *arg)
{
	struct efrm_nic_per_vi *cb_info;
	int instance;
	int bit;
	int rc = 0;

	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
	EFRM_ASSERT(virs->q[EFHW_EVQ].capacity != 0);
	EFRM_ASSERT(handler != NULL);

	mutex_lock(&register_evq_cb_mutex);
	if (virs->evq_callback_fn != NULL) {
		rc = -EBUSY;
		goto unlock_and_out;
	}

	virs->evq_callback_arg = arg;
	wmb();
	virs->evq_callback_fn = handler;

	instance = virs->rs.rs_instance;
	cb_info = &efrm_nic(virs->rs.rs_client->nic)->vis[instance];
	cb_info->vi = virs;
	bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
			       &cb_info->state);
	EFRM_ASSERT(bit == 0);
unlock_and_out:
	mutex_unlock(&register_evq_cb_mutex);
	return rc;
}
EXPORT_SYMBOL(efrm_eventq_register_callback);

void efrm_eventq_kill_callback(struct efrm_vi *virs)
{
	struct efrm_nic_per_vi *cb_info;
	int32_t evq_state;
	int instance;
	int bit;

	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
	EFRM_ASSERT(virs->q[EFHW_EVQ].capacity != 0);
	EFRM_ASSERT(virs->rs.rs_client != NULL);

	mutex_lock(&register_evq_cb_mutex);

	instance = virs->rs.rs_instance;
	cb_info = &efrm_nic(virs->rs.rs_client->nic)->vis[instance];
	cb_info->vi = NULL;

	/* Disable the callback. */
	bit = test_and_clear_bit(VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
				 &cb_info->state);
	EFRM_ASSERT(bit);	/* do not call me twice! */

	/* If the vi had been primed, unset it. */
	test_and_clear_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING,
			   &cb_info->state);

	/* Spin until the callback is complete. */
	do {
		rmb();

		udelay(1);
		evq_state = cb_info->state;
	} while ((evq_state & VI_RESOURCE_EVQ_STATE(BUSY)));

	virs->evq_callback_fn = NULL;
	mutex_unlock(&register_evq_cb_mutex);
}
EXPORT_SYMBOL(efrm_eventq_kill_callback);

static void
efrm_eventq_do_callback(struct efhw_nic *nic, unsigned instance,
			bool is_timeout)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	efrm_evq_callback_fn handler;
	void *arg;
	struct efrm_nic_per_vi *cb_info;
	int32_t evq_state;
	int32_t new_evq_state;
	struct efrm_vi *virs;
	int bit;

	EFRM_ASSERT(efrm_vi_manager);

	cb_info = &rnic->vis[instance];

	/* Set the BUSY bit and clear WAKEUP_PENDING.  Do this
	 * before waking up the sleeper to avoid races. */
	while (1) {
		evq_state = cb_info->state;
		new_evq_state = evq_state;

		if ((evq_state & VI_RESOURCE_EVQ_STATE(BUSY)) != 0) {
			EFRM_ERR("%s:%d: evq_state[%d] corrupted!",
				 __FUNCTION__, __LINE__, instance);
			return;
		}

		if (!is_timeout)
			new_evq_state &= ~VI_RESOURCE_EVQ_STATE(WAKEUP_PENDING);

		if (evq_state & VI_RESOURCE_EVQ_STATE(CALLBACK_REGISTERED)) {
			new_evq_state |= VI_RESOURCE_EVQ_STATE(BUSY);
			virs = cb_info->vi;
			if (cmpxchg(&cb_info->state, evq_state,
				    new_evq_state) == evq_state)
				break;
		} else {
			/* Just update the state if necessary. */
			if (new_evq_state == evq_state ||
			    cmpxchg(&cb_info->state, evq_state,
				    new_evq_state) == evq_state)
				return;
		}
	}

	if (virs) {
		handler = virs->evq_callback_fn;
		rmb();
		arg = virs->evq_callback_arg;
		EFRM_ASSERT(handler != NULL);
		handler(arg, is_timeout, nic);
	}

	/* Clear the BUSY bit. */
	bit =
	    test_and_clear_bit(VI_RESOURCE_EVQ_STATE_BUSY,
			       &cb_info->state);
	if (!bit) {
		EFRM_ERR("%s:%d: evq_state corrupted!",
			 __FUNCTION__, __LINE__);
	}
}

void efrm_handle_wakeup_event(struct efhw_nic *nic, unsigned instance)
{
	efrm_eventq_do_callback(nic, instance, false);
}

void efrm_handle_timeout_event(struct efhw_nic *nic, unsigned instance)
{
	efrm_eventq_do_callback(nic, instance, true);
}

void efrm_handle_sram_event(struct efhw_nic *nic)
{
	if (nic->buf_commit_outstanding > 0)
		nic->buf_commit_outstanding--;
}


int efrm_vi_irq_moderate(struct efrm_vi *vi, int usec)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	if (vi->allocation.vf)
		return efrm_vf_vi_qmoderate(vi, usec);
#endif
	return -EINVAL;
}
EXPORT_SYMBOL(efrm_vi_irq_moderate);


int efrm_vi_irq_affinity(struct efrm_vi *vi, int cpu_core_id)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	if (vi->allocation.vf)
		return efrm_vf_vi_set_cpu_affinity(vi, cpu_core_id);
#endif
	return -EINVAL;
}
EXPORT_SYMBOL(efrm_vi_irq_affinity);
