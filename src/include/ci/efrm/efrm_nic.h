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

#ifndef __EFRM_NIC_H__
#define __EFRM_NIC_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efrm/buddy.h>


struct efrm_nic_per_vi {
	unsigned long state;
	struct efrm_vi *vi;
};


/* Per-nic state for the VI resource manager. */
struct efrm_nic_vi {

	/* We keep VI resources which need flushing on these lists.  The VI
	 * is put on the outstanding list when the flush request is issued
	 * to the hardware and removed when the flush event arrives.  The
	 * hardware can only handle a limited number of RX flush requests at
	 * once, so VIs are placed in the waiting list until the flush can
	 * be issued.  Flushes can be requested by the client or internally
	 * by the VI resource manager.  In the former case, the reference
	 * count must be non-zero for the duration of the flush and in the
	 * later case, the reference count must be zero. */
	struct list_head rx_flush_waiting_list;
	struct list_head rx_flush_outstanding_list;
	struct list_head tx_flush_outstanding_list;
	int              rx_flush_outstanding_count;

	/* once the flush has happened we push the close into the work queue
	 * so its OK on Windows to free the resources (Bug 3469).  Resources
	 * on this list have zero reference count.
	 */
	struct list_head   close_pending;
	struct work_struct work_item;
	struct delayed_work flush_work_item;
};


struct efrm_vi_allocator {
	unsigned                    props;
	struct efrm_buddy_allocator instances;
};


/* Need two VI allocators on older silicon variants (Falcon B) -- one for
 * VIs with timers, and another for VIs with interrupts.
 */
#define EFRM_NIC_N_VI_ALLOCATORS  2

#define EFRM_MAX_STACK_ID 255

struct efrm_nic {
	struct efhw_nic efhw_nic;
	spinlock_t lock;
	struct list_head link;
	struct list_head clients;
	struct efrm_pd_owner_ids *owner_ids;
	struct efrm_nic_per_vi *vis;
	struct efrm_nic_vi      nvi;
	struct efrm_vi_allocator vi_allocators[EFRM_NIC_N_VI_ALLOCATORS];
	unsigned falcon_wakeup_mask;
	unsigned rss_channel_count;
	const struct efx_dl_device_info *dl_dev_info;
	unsigned stack_id_usage[(EFRM_MAX_STACK_ID + sizeof(unsigned) * 8)
				/ (sizeof(unsigned) * 8)];
};


#define efrm_nic(_efhw_nic)				\
  container_of(_efhw_nic, struct efrm_nic, efhw_nic)



#endif  /* __EFRM_NIC_H__ */
