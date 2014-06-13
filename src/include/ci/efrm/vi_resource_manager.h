/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
 * This file contains type definitions for VI resource.  These types
 * may be used outside of the SFC resource driver, but such use is not
 * recommended.
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

#ifndef __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__
#define __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__

#include <ci/efhw/common.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efrm/vi_allocation.h>


#define EFRM_VI_RM_DMA_QUEUE_COUNT 2

/* Sufficient for 32K x 8byte entry ring */
#define EFRM_VI_MAX_DMA_ADDR 64


struct efrm_pd;


/** Numbers of bits which can be set in the evq_state member of
 * vi_resource_evq_info. */
enum {
  /** This bit is set if a wakeup has been requested on the NIC. */
	VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING,
  /** This bit is set if the wakeup is valid for the sleeping
   * process. */
	VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
  /** This bit is set if a wakeup or timeout event is currently being
   * processed. */
	VI_RESOURCE_EVQ_STATE_BUSY,
};
#define VI_RESOURCE_EVQ_STATE(X) \
	(((int32_t)1) << (VI_RESOURCE_EVQ_STATE_##X))


/*! Global information for the VI resource manager. */
struct vi_resource_manager {
	struct efrm_resource_manager rm;
	struct workqueue_struct *workqueue;
};


struct efrm_vi_q {
	unsigned                             flags;
	int                                  capacity;
	int                                  bytes;
	int                                  page_order;
	struct efhw_iopages                  pages;
	struct efhw_buffer_table_allocation  buf_tbl_alloc;
	dma_addr_t                           dma_addrs[EFRM_VI_MAX_DMA_ADDR];
	/* The following fields are used for DMA queues only. */
	int                                  tag;
	unsigned long                        flush_jiffies;
	int                                  flushing;
	struct list_head                     flush_link;
	struct efrm_vi                      *evq_ref;
};


struct efrm_vi {
	/* Some macros make the assumption that the struct efrm_resource is
	 * the first member of a struct efrm_vi. */
	struct efrm_resource rs;
	atomic_t evq_refs;	/*!< Number of users of the event queue. */

	struct efrm_pd *pd;

	struct efrm_vi_allocation allocation;
	unsigned mem_mmap_bytes;

	/*! EFHW_VI_* flags or EFRM_VI_RELEASED */
	unsigned flags;
#define EFRM_VI_RELEASED 0x10000000

	int      rx_flush_outstanding;
	uint64_t flush_time;
	int      flush_count;
	void   (*flush_callback_fn)(void *);
	void    *flush_callback_arg;

	void (*evq_callback_fn) (void *arg, int is_timeout,
				 struct efhw_nic *nic);
	void *evq_callback_arg;
	struct efrm_vi_set *vi_set;
	struct efrm_vi_q q[EFHW_N_Q_TYPES];
};


#undef efrm_vi
#define efrm_vi(rs1)  container_of((rs1), struct efrm_vi, rs)


#endif /* __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__ */
