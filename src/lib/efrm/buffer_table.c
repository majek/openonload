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

#include <ci/efrm/debug.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/nic_table.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/buddy.h>
#include <ci/efrm/efrm_nic.h>


struct efrm_buffer_table {
	/* Buffer table space is divided into two sets: Entries that can be
	 * allocated over all NICs, and entries that are allocated per-NIC.
	 *
	 * [all_nics_low, all_nics_high) defines the range of entries that
	 * can be allocated over all NICs.  Entries outside of this range
	 * are always per-nic.
	 *
	 * Within the all_nics range, the [all_nics_free] allocator
	 * remembers which entries are currently free.  Entries that are
	 * not free (within this range) are either allocated by someone, or
	 * have been reassigned to the per-nic set.
	 *
	 * Entries that are reassigned to the per-nic set are set in the
	 * per_nic_set bitmap.  The 0th bit in per_nic_set corresponds to
	 * the buffer table entry all_nics_low.
	 */
	spinlock_t lock;
	unsigned all_nics_low;
	unsigned all_nics_high;
	struct efrm_buddy_allocator all_nics_free;
	unsigned long *per_nic_set;
};


static struct efrm_buffer_table efrm_buffers;


int efrm_buffer_table_ctor(unsigned low, unsigned high)
{
	int n, rc;

	EFRM_NOTICE("%s: [%u,%u)", __FUNCTION__, low, high);

	spin_lock_init(&efrm_buffers.lock);

	if (high <= 0 || low > high) {
		efrm_buffers.all_nics_low = 0;
		efrm_buffers.all_nics_high = 0;
		return 0;
	}

	rc = efrm_buddy_range_ctor(&efrm_buffers.all_nics_free, low, high);
	if (rc < 0) {
		EFRM_ERR("%s: efrm_buddy_range_ctor(%d, %d) failed (%d)",
			 __FUNCTION__, low, high, rc);
		goto fail1;
	}

	n = DIV_ROUND_UP(high - low, sizeof(unsigned long) * 8);
	n *= sizeof(unsigned long);
	efrm_buffers.per_nic_set = kmalloc(n, GFP_KERNEL);
	if (efrm_buffers.per_nic_set == NULL) {
		EFRM_ERR("%s: kmalloc(%d) failed (low=%d high=%d)",
			 __FUNCTION__, n, low, high);
		goto fail2;
	}
	memset(efrm_buffers.per_nic_set, 0, n);
	efrm_buffers.all_nics_low = low;
	efrm_buffers.all_nics_high = high;
	return 0;

fail2:
	efrm_buddy_dtor(&efrm_buffers.all_nics_free);
fail1:
	spin_lock_destroy(&efrm_buffers.lock);
	return rc;
}


void efrm_buffer_table_dtor(void)
{
	if (efrm_buffers.all_nics_high != 0) {
		efrm_buddy_dtor(&efrm_buffers.all_nics_free);
		kfree(efrm_buffers.per_nic_set);
	}
	spin_lock_destroy(&efrm_buffers.lock);
	EFRM_TRACE("%s: done", __FUNCTION__);
}

/**********************************************************************/

int
efrm_buffer_table_alloc(unsigned order,
			struct efhw_buffer_table_allocation *a)
{
	int rc;

	if (efrm_buffers.all_nics_high == 0)
		return -ENOMEM;

	spin_lock_bh(&efrm_buffers.lock);
	rc = efrm_buddy_alloc(&efrm_buffers.all_nics_free, order);
	spin_unlock_bh(&efrm_buffers.lock);

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
	struct efhw_nic *nic;
	int nic_i;

	EFRM_ASSERT(efrm_buffers.all_nics_high != 0);
	EFRM_ASSERT(a != NULL);
	EFRM_ASSERT(a->base != -1);
	EFRM_ASSERT(a->base >= efrm_buffers.all_nics_low);
	EFRM_ASSERT(a->base + (1ul << a->order) <= efrm_buffers.all_nics_high);
	EFRM_ASSERT((unsigned long) a->base + (1ul << a->order) <=
		    efrm_buddy_size(&efrm_buffers.all_nics_free));

	EFRM_TRACE("efrm_buffer_table_free: base=%d n=%ld",
		   a->base, (1ul << a->order));

	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_FOR_EACH_NIC(nic_i, nic)
	    efhw_nic_buffer_table_clear(nic, a->base, 1ul << a->order);
	spin_unlock_bh(&efrm_nic_tablep->lock);

	spin_lock_bh(&efrm_buffers.lock);
	efrm_buddy_free(&efrm_buffers.all_nics_free, a->base, a->order);
	spin_unlock_bh(&efrm_buffers.lock);

	EFRM_DO_DEBUG(a->base = a->order = -1);
}

/**********************************************************************/

int efrm_nic_buffer_table_ctor(struct efrm_nic *efrm_nic,
			       int bt_min, int bt_lim)
{
	int rc, log, i;

	EFRM_NOTICE("%s: ifindex=%d [%d,%d) shared=[%d,%d)",
		    __FUNCTION__, efrm_nic->efhw_nic.ifindex, bt_min, bt_lim,
		    efrm_buffers.all_nics_low, efrm_buffers.all_nics_high);

	if (efrm_buffers.all_nics_high > 0 &&
	    (bt_min > efrm_buffers.all_nics_low ||
	     bt_lim < efrm_buffers.all_nics_high)) {
		EFRM_ERR("%s: ERROR: Buffer table [%d,%d) not compatible with "
			 "the shared pool [%d,%d)", __FUNCTION__, bt_min,
			 bt_lim, efrm_buffers.all_nics_low,
			 efrm_buffers.all_nics_high);
		EFRM_ERR("%s: HINT: See sfc_resource module parameter "
			 "'shared_buffer_table'", __FUNCTION__);
		return -E2BIG;
	}

	log = fls(bt_lim - 1);
	if ((rc = efrm_buddy_ctor(&efrm_nic->buf_tbl, log)) < 0) {
		EFRM_ERR("%s: efrm_buddy_ctor(%d) failed [%d,%d) rc=%d",
			 __FUNCTION__, log, bt_min, bt_lim, rc);
		return rc;
	}
	for (i = 0; i < (1 << log); ++i)
		(void) efrm_buddy_alloc(&efrm_nic->buf_tbl, 0);
	spin_lock_bh(&efrm_nic_tablep->lock);
	for (i = bt_min; i < bt_lim; ++i)
		if (i < efrm_buffers.all_nics_low ||
		    i >= efrm_buffers.all_nics_high ||
		    test_bit(i - efrm_buffers.all_nics_low,
			     efrm_buffers.per_nic_set))
			efrm_buddy_free(&efrm_nic->buf_tbl, i, 0);
	spin_unlock_bh(&efrm_nic_tablep->lock);
	return 0;
}


void efrm_nic_buffer_table_dtor(struct efrm_nic *efrm_nic)
{
	efrm_buddy_dtor(&efrm_nic->buf_tbl);
}


static void efrm_buffer_table_alloc_to_nics(unsigned order)
{
	/* Allocate some entries from the all-nics pool and transfer to the
	 * per-nic pools.
	 *
	 * Caller must hold [efrm_buffers.lock].
	 */
	struct efrm_nic *efrm_nic;
	struct efhw_nic *nic;
	int nic_i, addr, entry, i;

	if (efrm_buffers.all_nics_high == 0)
		return;

	/* Avoid fragmentation by only moving decent sized chunks.  (1<<9)
	 * is 512 which is enough for a 2Mb huge-page.
	 */
	order = max_t(int, order, 9);
	if ((addr = efrm_buddy_alloc(&efrm_buffers.all_nics_free, order)) < 0)
		return;

	spin_lock_bh(&efrm_nic_tablep->lock);
	for (i = 0; i < (1 << order); ++i) {
		entry = addr + i;
		__set_bit(entry - efrm_buffers.all_nics_low,
			  efrm_buffers.per_nic_set);
		EFRM_FOR_EACH_NIC(nic_i, nic) {
			efrm_nic = container_of(nic, struct efrm_nic, efhw_nic);
			efrm_buddy_free(&efrm_nic->buf_tbl, entry, 0);
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
}


int efrm_nic_buffer_table_alloc(struct efrm_nic *efrm_nic, unsigned order,
				struct efhw_buffer_table_allocation *a)
{
	int rc;

	spin_lock_bh(&efrm_buffers.lock);
	rc = efrm_buddy_alloc(&efrm_nic->buf_tbl, order);
	if (rc < 0) {
		efrm_buffer_table_alloc_to_nics(order);
		rc = efrm_buddy_alloc(&efrm_nic->buf_tbl, order);
	}
	spin_unlock_bh(&efrm_buffers.lock);
	if (rc < 0) {
                EFRM_ERR_LIMITED("%s: failed order=%d rc=%d",
				 __FUNCTION__, order, rc);
		return rc;
	}
	a->order = order;
	a->base = (unsigned)rc;
	return 0;
}


void efrm_nic_buffer_table_free(struct efrm_nic *efrm_nic,
				struct efhw_buffer_table_allocation *a)
{
	efhw_nic_buffer_table_clear(&efrm_nic->efhw_nic,
				    a->base, 1 << a->order);
	spin_lock_bh(&efrm_buffers.lock);
	efrm_buddy_free(&efrm_nic->buf_tbl, a->base, a->order);
	spin_unlock_bh(&efrm_buffers.lock);
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

void
efrm_buffer_table_set_n(struct efhw_buffer_table_allocation *a,
		        struct efhw_nic *nic, int n_pages,
		        unsigned i, dma_addr_t dma_addr, int owner)
{
	EFRM_ASSERT(a);
	EFRM_ASSERT(i < (unsigned)1 << a->order);

	efhw_nic_buffer_table_set_n(nic, a->base + i, dma_addr, 0,
				    n_pages, owner);
}

void efrm_buffer_table_limits(int *low, int *high)
{
	*low = efrm_buffers.all_nics_low;
	*high = efrm_buffers.all_nics_high;
}

/**********************************************************************/

void efrm_buffer_table_commit(struct efhw_nic *nic)
{
	efhw_nic_buffer_table_commit(nic);
}
