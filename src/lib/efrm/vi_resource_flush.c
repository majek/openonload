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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains DMA queue flushing of VI resources.
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
#include <ci/efhw/falcon.h>
#include <ci/efrm/private.h>
#include <ci/efrm/sysdep.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include "efrm_internal.h"
#include "efrm_vi.h"


static const int flush_fifo_hwm = 8 /* TODO should be a HW specific const */ ;


static inline struct efrm_nic_vi *nvi_from_virs(struct efrm_vi *virs)
{
	return &efrm_nic_from_rs(&virs->rs)->nvi;
}


static void
efrm_vi_resource_rx_flush_done(struct efrm_vi *virs, bool *completed)
{
	struct efrm_nic_vi *nvi = nvi_from_virs(virs);

	/* We should only get a flush event if there is a flush
	 * outstanding, but we give up after 1 sec so a delayed
	 * completion could come here. */
	if (virs->rx_flush_outstanding) {
		virs->rx_flush_outstanding = 0;
		virs->q[EFHW_RXQ].flushing = 0;

		list_del(&virs->q[EFHW_RXQ].flush_link);
		--nvi->rx_flush_outstanding_count;
		
		if (virs->q[EFHW_TXQ].flushing == 0) {
			list_add_tail(&virs->q[EFHW_RXQ].flush_link,
				      &nvi->close_pending);
			*completed = 1;
		}
	} else
		EFRM_WARN("%s: unexpected flush completion on rx queue %d",
			  __FUNCTION__, virs->rs.rs_instance);
}

static void
efrm_vi_resource_tx_flush_done(struct efrm_vi *virs, bool *completed)
{
	/* We should only get a flush event if there is a flush
	 * outstanding, but we give up after 1 sec so a delayed
	 * completion could come here. */
	if (virs->q[EFHW_TXQ].flushing) {
		virs->q[EFHW_TXQ].flushing = 0;

		list_del(&virs->q[EFHW_TXQ].flush_link);

		if (virs->q[EFHW_RXQ].flushing == 0) {
			list_add_tail(&virs->q[EFHW_RXQ].flush_link,
				      &nvi_from_virs(virs)->close_pending);
			*completed = 1;
		}
	} else 
		EFRM_WARN("%s: unexpected flush completion on tx queue %d",
			  __FUNCTION__, virs->rs.rs_instance);	
}

static void
efrm_vi_resource_issue_rx_flush(struct efrm_vi *virs, bool *completed)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_rs(&virs->rs);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	int instance;

	instance = virs->rs.rs_instance;

	virs->q[EFHW_RXQ].flush_jiffies = jiffies;

	list_add_tail(&virs->q[EFHW_RXQ].flush_link,
		      &nvi->rx_flush_outstanding_list);
	virs->rx_flush_outstanding = virs->q[EFHW_RXQ].flushing;
	++(nvi->rx_flush_outstanding_count);
	
	if (atomic_read(&nvi->flush_timer_running) == 0) {
		atomic_set(&nvi->flush_timer_running, 1);
		mod_timer(&nvi->flush_timer, jiffies + HZ);
	}

	EFRM_TRACE("%s: rx queue %d flush requested for nic %d",
		   __FUNCTION__, instance, efrm_nic->efhw_nic.index);
	efhw_nic_flush_rx_dma_channel(&efrm_nic->efhw_nic, instance);
}

static void
efrm_vi_resource_issue_tx_flush(struct efrm_vi *virs, bool *completed)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_rs(&virs->rs);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	int instance;
	int rc;

	instance = virs->rs.rs_instance;

	virs->q[EFHW_TXQ].flush_jiffies = jiffies;

	list_add_tail(&virs->q[EFHW_TXQ].flush_link,
		      &efrm_nic->nvi.tx_flush_outstanding_list);

	if (atomic_read(&nvi->flush_timer_running) == 0) {
		atomic_set(&nvi->flush_timer_running, 1);
		mod_timer(&nvi->flush_timer, jiffies + HZ);
	}

	EFRM_TRACE("%s: tx queue %d flush requested for nic %d",
		   __FUNCTION__, instance, efrm_nic->efhw_nic.index);
	rc = efhw_nic_flush_tx_dma_channel(&efrm_nic->efhw_nic, instance);
	if (rc == -EAGAIN)
		efrm_vi_resource_tx_flush_done(virs, completed);
}

static void efrm_vi_resource_process_flushes(struct efrm_nic *efrm_nic,
					     bool *completed)
{
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	struct efrm_vi *virs;

	while (nvi->rx_flush_outstanding_count < flush_fifo_hwm &&
	       !list_empty(&nvi->rx_flush_waiting_list)) {
		virs =
		    list_entry(list_pop(&nvi->rx_flush_waiting_list),
			       struct efrm_vi, q[EFHW_RXQ].flush_link);
		efrm_vi_resource_issue_rx_flush(virs, completed);
	}
}


static DECLARE_WAIT_QUEUE_HEAD(flush_wq);

static bool efrm_vi_rm_flushes_pending(struct efrm_nic *efrm_nic)
{
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	return (nvi->rx_flush_outstanding_count != 0 ||
		!list_empty(&nvi->tx_flush_outstanding_list));
}

static bool efrm_vi_rm_flushes_pending_nic(struct efhw_nic *nic)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	struct list_head *pos, *temp;
	struct efhw_nic *flush_nic;
	struct efrm_vi *virs;

	if (!efrm_vi_rm_flushes_pending(efrm_nic))
		return false;

	list_for_each_safe(pos, temp,
			   &nvi->rx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_RXQ].flush_link);
		flush_nic = virs->rs.rs_client->nic;
		if (flush_nic->index == nic->index)
			return true;
	}
	list_for_each_safe(pos, temp,
			   &nvi->rx_flush_waiting_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_RXQ].flush_link);
		flush_nic = virs->rs.rs_client->nic;
		if (flush_nic->index == nic->index)
			return true;
	}
	list_for_each_safe(pos, temp,
			   &nvi->tx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_TXQ].flush_link);
		flush_nic = virs->rs.rs_client->nic;
		if (flush_nic->index == nic->index)
			return true;
	}
	return false;
}

static void efrm_vi_rm_may_complete_flushes(struct efrm_nic *efrm_nic)
{
	if (!efrm_vi_rm_flushes_pending(efrm_nic))
		atomic_set(&efrm_nic->nvi.flush_timer_running, 0);
	/* If there's any chance of a completion meaning
	 * efrm_vi_rm_flushes_pending_nic() could return true for any
	 * NIC then wake any waiters rather than go to the trouble of
	 * being more accurate */
	wake_up(&flush_wq);
}

void efrm_vi_flush_timer_fn(unsigned long l)
{
	struct efrm_nic_vi *nvi = (void *)l;
	if( atomic_read(&nvi->flush_timer_running) == 0 )
		return;
	queue_work(efrm_vi_manager->workqueue, &nvi->flush_work_item);
	mod_timer(&nvi->flush_timer, jiffies + HZ);
}

void efrm_vi_check_flushes(struct work_struct *data)
{
	struct efrm_nic_vi *nvi;
	struct efrm_nic *efrm_nic;
	struct list_head *pos, *temp;
	struct efrm_vi *virs;
	bool completed;
	bool found = false;

	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_vi_manager->rm);

	EFRM_TRACE("%s: %p", __FUNCTION__, efrm_vi_manager);

	nvi = container_of(data, struct efrm_nic_vi, flush_work_item);
	efrm_nic = container_of(nvi, struct efrm_nic, nvi);

	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);

	if (!efrm_vi_rm_flushes_pending(efrm_nic))
		goto out;

	list_for_each_safe(pos, temp, &nvi->rx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_RXQ].flush_link);
		if( time_after(jiffies, virs->q[EFHW_RXQ].flush_jiffies) ) {
			/* Please don't whitelist this log output. If
			 * it's appearing, that means this workaround
			 * for bug18474/bug20608 is needed, and we'd
			 * like to know about it.
			 */
			EFRM_WARN("%s: rx flush outstanding after 1 second\n",
				  __FUNCTION__);
			efrm_vi_resource_rx_flush_done(virs, &completed);
			found = true;
		}
		else 
			break;
	}
	list_for_each_safe(pos, temp, &nvi->tx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_TXQ].flush_link);
		if( time_after(jiffies, virs->q[EFHW_TXQ].flush_jiffies) ) {
			/* Please don't whitelist this log output. If
			 * it's appearing, that means this workaround
			 * for bug18474/bug20608 is needed, and we'd
			 * like to know about it.
			 */
			EFRM_WARN("%s: tx flush outstanding after 1 second\n",
				  __FUNCTION__);
			efrm_vi_resource_tx_flush_done(virs, &completed);
			found = true;
		}
		else 
			break;
	}

	efrm_vi_resource_process_flushes(efrm_nic, &completed);
	efrm_vi_rm_may_complete_flushes(efrm_nic);
	if (found)
		queue_work(efrm_vi_manager->workqueue, &nvi->work_item);

 out:
	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);
}


void efrm_vi_wait_nic_complete_flushes(struct efhw_nic *nic)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);
#ifndef NDEBUG
	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);
	/* flushes pending implies flush timer running */
	EFRM_ASSERT(!efrm_vi_rm_flushes_pending_nic(nic) || 
		    atomic_read(&efrm_nic->nvi.flush_timer_running));
	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);
#endif
	wait_event(flush_wq, !efrm_vi_rm_flushes_pending_nic(nic));

	/* Make use of the workqueue synchronisation guarantee, by enqueuing onto
	 * then flushing the work queue */
	queue_work(efrm_vi_manager->workqueue, &efrm_nic->nvi.work_item);
	flush_workqueue(efrm_vi_manager->workqueue);
}
EXPORT_SYMBOL(efrm_vi_wait_nic_complete_flushes);


void
efrm_vi_register_flush_callback(struct efrm_vi *virs,
				void (*handler)(void *), void *arg)
{
	if (handler == NULL) {
		virs->flush_callback_fn = handler;
		wmb();
		virs->flush_callback_arg = arg;
	} else {
		virs->flush_callback_arg = arg;
		wmb();
		virs->flush_callback_fn = handler;
	}
}
EXPORT_SYMBOL(efrm_vi_register_flush_callback);

void efrm_pt_flush(struct efrm_vi *virs)
{
	struct efrm_nic_vi *nvi = nvi_from_virs(virs);
	bool completed = false;

	EFRM_ASSERT(virs->q[EFHW_RXQ].flushing == 0);
	EFRM_ASSERT(virs->rx_flush_outstanding == 0);
	EFRM_ASSERT(virs->q[EFHW_TXQ].flushing == 0);

	EFRM_TRACE("%s: " EFRM_RESOURCE_FMT " EVQ=%d TXQ=%d RXQ=%d",
		   __FUNCTION__, EFRM_RESOURCE_PRI_ARG(&virs->rs),
		   virs->q[EFHW_EVQ].capacity,
		   virs->q[EFHW_TXQ].capacity,
		   virs->q[EFHW_RXQ].capacity);

	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);

	if (virs->q[EFHW_RXQ].capacity != 0)
		virs->q[EFHW_RXQ].flushing = 1;

	if (virs->q[EFHW_TXQ].capacity != 0)
		virs->q[EFHW_TXQ].flushing = 1;

	/* Clean up immediately if there are no flushes. */
	if (virs->q[EFHW_RXQ].flushing == 0 &&
	    virs->q[EFHW_TXQ].flushing == 0) {
		list_add_tail(&virs->q[EFHW_RXQ].flush_link,
			      &nvi->close_pending);
		completed = true;
	}

	/* Issue the RX flush if possible or queue it for later. */
	if (virs->q[EFHW_RXQ].flushing) {
		if (nvi->rx_flush_outstanding_count >=
		    flush_fifo_hwm) {
			list_add_tail(&virs->q[EFHW_RXQ].flush_link,
				      &nvi->rx_flush_waiting_list);
		} else {
			efrm_vi_resource_issue_rx_flush(virs, &completed);
		}
	}

	/* Issue the TX flush.  There's no limit to the number of
	 * outstanding TX flushes. */
	if (virs->q[EFHW_TXQ].flushing)
		efrm_vi_resource_issue_tx_flush(virs, &completed);

	virs->flush_time = get_jiffies_64();

	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);

	if (completed)
		queue_work(efrm_vi_manager->workqueue, &nvi->work_item);
}
EXPORT_SYMBOL(efrm_pt_flush);

static void
efrm_handle_rx_dmaq_flushed(struct efhw_nic *nic, int instance,
			    bool *completed, int failed)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	struct list_head *pos, *temp;
	struct efrm_vi *virs;
	int rc;

	list_for_each_safe(pos, temp, &nvi->rx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_RXQ].flush_link);

		if (instance == virs->rs.rs_instance) {
			if (failed) {
				rc = efhw_nic_flush_rx_dma_channel(nic,
								   instance);
				EFRM_ASSERT(rc == 0);
				(void) rc;  /* kill compiler warning */
				*completed = false;
			} else {
				efrm_vi_resource_rx_flush_done(virs, completed);
				efrm_vi_resource_process_flushes(efrm_nic,
								 completed);
				efrm_vi_rm_may_complete_flushes(efrm_nic);
			}
			return;
		}
	}
	EFRM_TRACE("%s: Unhandled rx flush event, nic %d, instance %d",
		   __FUNCTION__, nic->index, instance);
}

static void
efrm_handle_tx_dmaq_flushed(struct efhw_nic *nic, int instance,
			    bool *completed)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	struct list_head *pos, *temp;
	struct efrm_vi *virs;

	list_for_each_safe(pos, temp, &nvi->tx_flush_outstanding_list) {
		virs = container_of(pos, struct efrm_vi,
				    q[EFHW_TXQ].flush_link);

		if (instance == virs->rs.rs_instance) {
			efrm_vi_resource_tx_flush_done(virs, completed);
			efrm_vi_rm_may_complete_flushes(efrm_nic);
			return;
		}
	}
	EFRM_TRACE("%s: Unhandled tx flush event, nic %d, instance %d",
		   __FUNCTION__, nic->index, instance);
}

void
efrm_handle_dmaq_flushed(struct efhw_nic *flush_nic, unsigned instance,
			 int rx_flush, int failed)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(flush_nic);
	struct efrm_nic_vi *nvi = &efrm_nic->nvi;
	bool completed = false;

	EFRM_TRACE("%s: nic_i=%d  instance=%d  rx_flush=%d failed=%d",
		   __FUNCTION__, flush_nic->index, instance, rx_flush,
		   failed);

	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);

	if (rx_flush)
		efrm_handle_rx_dmaq_flushed(flush_nic, instance, &completed,
					    failed);
	else
		efrm_handle_tx_dmaq_flushed(flush_nic, instance, &completed);

	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);

	if (completed)
		queue_work(efrm_vi_manager->workqueue, &nvi->work_item);
}

static void
efrm_vi_rm_reinit_dmaqs(struct efrm_vi *virs)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;

	if (virs->q[EFHW_TXQ].capacity != 0)
		efrm_vi_rm_init_dmaq(virs, EFHW_TXQ, nic);
	if (virs->q[EFHW_RXQ].capacity)
		efrm_vi_rm_init_dmaq(virs, EFHW_RXQ, nic);
}

/* free any PT endpoints whose flush has now complete */
void efrm_vi_rm_delayed_free(struct work_struct *data)
{
	struct efrm_nic_vi *nvi;
	struct list_head close_pending;
	struct efrm_vi *virs;

	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_vi_manager->rm);

	nvi = container_of(data, struct efrm_nic_vi, work_item);
	spin_lock_bh(&efrm_vi_manager->rm.rm_lock);
	list_replace_init(&nvi->close_pending, &close_pending);
	spin_unlock_bh(&efrm_vi_manager->rm.rm_lock);

	EFRM_TRACE("%s: %p", __FUNCTION__, efrm_vi_manager);
	while (!list_empty(&close_pending)) {
		virs =
		    list_entry(list_pop(&close_pending), struct efrm_vi,
			       q[EFHW_RXQ].flush_link);
		EFRM_TRACE("%s: flushed VI instance=%d", __FUNCTION__,
			   virs->rs.rs_instance);

		if (~virs->flags & EFRM_VI_RELEASED)
			efrm_vi_rm_reinit_dmaqs(virs);
		if (virs->flush_callback_fn != NULL)
			virs->flush_callback_fn(virs->flush_callback_arg);
		if (virs->flags & EFRM_VI_RELEASED)
			efrm_vi_rm_free_flushed_resource(virs);
	}
}

void efrm_vi_rm_salvage_flushed_vis(struct efhw_nic *nic)
{
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);
	efrm_vi_rm_delayed_free(&efrm_nic->nvi.work_item);
}

void efrm_vi_resource_free(struct efrm_vi *virs)
{
	efrm_vi_register_flush_callback(virs, NULL, NULL);
	virs->flags |= EFRM_VI_RELEASED;
	efrm_pt_flush(virs);
}


void efrm_vi_resource_release(struct efrm_vi *virs)
{
	if (__efrm_resource_release(&virs->rs))
		efrm_vi_resource_free(virs);
}
EXPORT_SYMBOL(efrm_vi_resource_release);

void efrm_vi_resource_release_callback(struct efrm_vi *virs)
{
	EFRM_ASSERT(virs->flush_callback_fn);
	if (__efrm_resource_release(&virs->rs)) {
		virs->flags |= EFRM_VI_RELEASED;
		efrm_pt_flush(virs);
	}
}
EXPORT_SYMBOL(efrm_vi_resource_release_callback);

/*
 * vi: sw=8:ai:aw
 */
