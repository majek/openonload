/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides an allocator for Virtual Interfaces (VIs).
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/buddy.h>
#include <ci/efrm/debug.h>
#include <ci/efhw/common.h>
#include "efrm_internal.h"


#define ALLOCATOR_INITIALISED  (1u << 31)


int efrm_vi_allocator_ctor(struct efrm_nic *efrm_nic,
			   const struct vi_resource_dimensions *dims)
{
	struct efrm_vi_allocator *va;
	int i, rc, va_n = 0;
	unsigned timer_min, timer_lim;
	unsigned int_min, int_lim;

	if (efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF10) {
		int_min = timer_min = dims->vi_min; 
		int_lim = timer_lim = dims->vi_lim;
	}
	else if (efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_FALCON) {
		unsigned dmaq_min, dmaq_lim;
		
		dmaq_min = max(dims->rxq_min, dims->txq_min);
		dmaq_lim = min(dims->rxq_lim, dims->txq_lim);
		timer_min = max(dmaq_min, dims->evq_timer_min);
		timer_lim = min(dmaq_lim, dims->evq_timer_lim);
		int_min = max(dmaq_min, dims->evq_int_min);
		int_lim = min(dmaq_lim, dims->evq_int_lim);
		int_lim = max(int_lim, int_min);
	} else {
		rc = -EINVAL;
		EFRM_ERR("%s: unknown efhw device architecture %u",
			 __FUNCTION__, efrm_nic->efhw_nic.devtype.arch);
		goto fail;
	}

	for (i = 0; i < EFRM_NIC_N_VI_ALLOCATORS; ++i)
		efrm_nic->vi_allocators[i].props = 0;

	if (timer_lim > timer_min) {
		va = &efrm_nic->vi_allocators[va_n++];
		rc = efrm_buddy_range_ctor(&va->instances,
					   timer_min, timer_lim);
		if (rc < 0) {
			EFRM_ERR("%s: efrm_buddy_range_ctor(tmr, %d, %d) "
				 "failed (%d)",
				 __FUNCTION__, timer_min, timer_lim, rc);
			goto fail;
		}
		va->props |= vi_with_timer | ALLOCATOR_INITIALISED;
		if (int_min == timer_min && int_lim > int_min) {
			/* One allocator for timers and interrupts. */
			EFRM_ASSERT(int_lim == timer_lim);
			va->props |= vi_with_interrupt;
		}
	}

	if (int_lim > int_min && int_min != timer_min) {
		va = &efrm_nic->vi_allocators[va_n++];
		rc = efrm_buddy_range_ctor(&va->instances, int_min, int_lim);
		if (rc < 0) {
			EFRM_ERR("%s: efrm_buddy_range_ctor(int, %d, %d) "
				 "failed (%d)",
				 __FUNCTION__, int_min, int_lim, rc);
			goto fail;
			return rc;
		}
		va->props |= vi_with_interrupt | ALLOCATOR_INITIALISED;
	}

	return 0;

fail:
	efrm_vi_allocator_dtor(efrm_nic);
	return rc;
}


void efrm_vi_allocator_dtor(struct efrm_nic *efrm_nic)
{
	int i;
	for (i = 0; i < EFRM_NIC_N_VI_ALLOCATORS; ++i)
		if (efrm_nic->vi_allocators[i].props != 0) {
			efrm_nic->vi_allocators[i].props = 0;
			efrm_buddy_dtor(&efrm_nic->vi_allocators[i].instances);
		}
}


struct alloc_vi_constraints {
	struct efrm_nic *efrm_nic;
	int channel;
	int min_vis_in_set;
	int has_rss_context;
};


static bool accept_vi_constraints(int low, unsigned order, void* arg)
{
	struct alloc_vi_constraints *avc = arg;
	int high = low + avc->min_vis_in_set;
	int ok = 1;
	if (avc->efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_FALCON) {
		/* We want a VI whose wakeup events will go to the
		 * specified channel.  The channel used for wakeup events
		 * is (vi_instance & falcon_wakeup_mask).
		 */
		if( avc->channel >= 0 )
			ok &= ((low & avc->efrm_nic->falcon_wakeup_mask)
			       == avc->channel);
	}
	if ((avc->min_vis_in_set > 1) && (!avc->has_rss_context)) {
		/* We need to ensure that if an RSS-enabled filter is
		 * pointed at this VI-set then the queue selected will be
		 * within the default set.  The queue selected by RSS will be 
		 * in the range (low | (rss_channel_count - 1)).
		 */
		ok &= ((low | (avc->efrm_nic->rss_channel_count - 1)) < high);
	}
	return ok;
}


static int buddy_alloc_vi(struct efrm_nic *efrm_nic,
			  struct efrm_buddy_allocator *b, int order,
			  int channel, int min_vis_in_set, int has_rss_context)
{
	struct alloc_vi_constraints avc;
	avc.efrm_nic = efrm_nic;
	avc.channel = channel;
	avc.min_vis_in_set = min_vis_in_set;
	avc.has_rss_context = has_rss_context;
	return efrm_buddy_alloc_special(b, order, accept_vi_constraints, &avc);
}


int  efrm_vi_allocator_alloc_set(struct efrm_nic *efrm_nic, unsigned vi_props,
				 int min_vis_in_set, int has_rss_context,
				 int channel,
				 struct efrm_vi_allocation *set_out)
{
	struct efrm_vi_allocator *va;
	int i, rc;

	if (min_vis_in_set < 1)
		return -EINVAL;

	/* Ensure we only match an initialised allocator. */
	vi_props |= ALLOCATOR_INITIALISED;

	for (i = 0; i < EFRM_NIC_N_VI_ALLOCATORS; ++i) {
		va = &efrm_nic->vi_allocators[i];
		if ((vi_props & va->props) == vi_props)
			break;
	}
	if (i == EFRM_NIC_N_VI_ALLOCATORS) {
		EFRM_ERR("%s: no VIs with vi_props=%x", __FUNCTION__,vi_props);
		return -EINVAL;
	}
        set_out->vf = NULL;
	set_out->allocator_id = i;
	set_out->order = fls(min_vis_in_set - 1);
	spin_lock_bh(&efrm_nic->lock);
	set_out->instance = buddy_alloc_vi(efrm_nic, &va->instances,
					   set_out->order, channel,
					   min_vis_in_set, has_rss_context);
	spin_unlock_bh(&efrm_nic->lock);
	rc = (set_out->instance >= 0) ? 0 : -EBUSY;
	return rc;
}


void efrm_vi_allocator_free_set(struct efrm_nic *efrm_nic,
				struct efrm_vi_allocation *set)
{
	EFRM_ASSERT(set->instance >= 0);
	EFRM_ASSERT(set->allocator_id >= 0);
	EFRM_ASSERT(set->allocator_id < EFRM_NIC_N_VI_ALLOCATORS);

	spin_lock_bh(&efrm_nic->lock);
	efrm_buddy_free(&efrm_nic->vi_allocators[set->allocator_id].instances,
			set->instance, set->order);
	spin_unlock_bh(&efrm_nic->lock);
}
