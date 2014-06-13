/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
 * This file contains abstraction of the buffer table on the NIC.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
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

/*
** Might be worth keeping a bitmap of which entries are clear.  Then we
** wouldn't need to clear them all again when we free an allocation.
*/

#include <ci/efrm/debug.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/nic_table.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/buddy.h>

/*! Comment? */
struct efrm_buffer_table {
	spinlock_t lock;
	unsigned low;
	unsigned high;
	struct efrm_buddy_allocator buddy;
};

/* Efab buffer state. */
static struct efrm_buffer_table efrm_buffers;

int efrm_buffer_table_ctor(unsigned low, unsigned high)
{
	int rc;

	EFRM_NOTICE("%s: low=%u high=%u", __FUNCTION__, low, high);

	if (high > 0 && low < high) {
		rc = efrm_buddy_range_ctor(&efrm_buffers.buddy, low, high);
		if (rc < 0) {
			EFRM_ERR("%s: efrm_buddy_range_ctor(%d, %d) failed (%d)",
				 __FUNCTION__, low, high, rc);
			return rc;
		}
	}
	else
		low = high = 0;
	efrm_buffers.low = low;
	efrm_buffers.high = high;
	spin_lock_init(&efrm_buffers.lock);
	return 0;
}

void efrm_buffer_table_dtor(void)
{
	/* ?? debug check that all allocations have been freed? */

	spin_lock_destroy(&efrm_buffers.lock);
	if (efrm_buffers.low != efrm_buffers.high)
		efrm_buddy_dtor(&efrm_buffers.buddy);

	EFRM_TRACE("%s: done", __FUNCTION__);
}

/**********************************************************************/

int
efrm_buffer_table_alloc(unsigned order,
			struct efhw_buffer_table_allocation *a)
{
	irq_flags_t lock_flags;
	int rc;

	EFRM_ASSERT(&efrm_buffers.buddy);
	EFRM_ASSERT(a);
	if (efrm_buffers.low == efrm_buffers.high)
		return -ENOMEM;

	/* Round up to multiple of two, as the buffer clear logic works in
	 * pairs when not in "full" mode. */
	order = max_t(unsigned, order, 1);

	spin_lock_irqsave(&efrm_buffers.lock, lock_flags);
	rc = efrm_buddy_alloc(&efrm_buffers.buddy, order);
	spin_unlock_irqrestore(&efrm_buffers.lock, lock_flags);

	if (rc < 0) {
                EFRM_ERR_LIMITED("%s: failed (n=%ld) rc %d",
                        __FUNCTION__, 1ul << order, rc);
		return rc;
	}

	EFRM_TRACE("efrm_buffer_table_alloc: base=%d n=%ld",
		   rc, 1ul << order);
	a->order = order;
	a->base = (unsigned)rc;
	return 0;
}

void efrm_buffer_table_free(struct efhw_buffer_table_allocation *a)
{
	irq_flags_t lock_flags;
	struct efhw_nic *nic;
	int nic_i;

	if (efrm_buffers.low == efrm_buffers.high)
		return;

	EFRM_ASSERT(&efrm_buffers.buddy);
	EFRM_ASSERT(a);
	EFRM_ASSERT(a->base != -1);
	EFRM_ASSERT((unsigned long)a->base + (1ul << a->order) <=
		    efrm_buddy_size(&efrm_buffers.buddy));

	EFRM_TRACE("efrm_buffer_table_free: base=%d n=%ld",
		   a->base, (1ul << a->order));

	efrm_driver_lock(lock_flags);
	EFRM_FOR_EACH_NIC(nic_i, nic)
	    efhw_nic_buffer_table_clear(nic, a->base, 1ul << a->order);
	efrm_driver_unlock(lock_flags);

	spin_lock_irqsave(&efrm_buffers.lock, lock_flags);
	efrm_buddy_free(&efrm_buffers.buddy, a->base, a->order);
	spin_unlock_irqrestore(&efrm_buffers.lock, lock_flags);

	EFRM_DO_DEBUG(a->base = a->order = -1);
}

/**********************************************************************/

void
efrm_buffer_table_set(struct efhw_buffer_table_allocation *a,
		      struct efhw_nic *nic,
		      unsigned i, dma_addr_t dma_addr, int owner)
{
	EFRM_ASSERT(a);
	EFRM_ASSERT(i < (unsigned)1 << a->order);

	efhw_nic_buffer_table_set(nic, dma_addr, 0, owner, a->base + i);
}


int efrm_buffer_table_size(void)
{
	if (efrm_buffers.low == efrm_buffers.high)
		return 0;
	return efrm_buddy_size(&efrm_buffers.buddy);
}

void efrm_buffer_table_limits(int *low, int *high)
{
	*low = efrm_buffers.low;
	*high = efrm_buffers.high;
}

/**********************************************************************/

void efrm_buffer_table_commit(void)
{
	irq_flags_t lock_flags;
	struct efhw_nic *nic;
	int nic_i;

	efrm_driver_lock(lock_flags);
	EFRM_FOR_EACH_NIC(nic_i, nic)
	    efhw_nic_buffer_table_commit(nic);
	efrm_driver_unlock(lock_flags);
}
