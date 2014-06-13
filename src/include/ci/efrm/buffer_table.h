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
 * This file provides private buffer table API.  This API is not designed
 * for use outside of SFC resource driver.
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

#ifndef __CI_EFRM_BUFFER_TABLE_H__
#define __CI_EFRM_BUFFER_TABLE_H__

#include <ci/efhw/efhw_types.h>


struct efrm_nic;
struct efhw_buffer_table_allocation;


/*--------------------------------------------------------------------
 *
 * NIC's buffer table.
 *
 *--------------------------------------------------------------------*/

/*! Managed interface. */

/*! construct a managed buffer table object, allocated over a region of
 *  the NICs buffer table space
 */
extern int efrm_buffer_table_ctor(unsigned low, unsigned high);
/*! destructor for above */
extern void efrm_buffer_table_dtor(void);

/*! allocate a contiguous region of buffer table space */
extern int efrm_buffer_table_alloc(unsigned order,
				   struct efhw_buffer_table_allocation *a);

/* Return the [min,max) buffer table entries that may be returned
 * by efrm_buffer_table_alloc() */
extern void efrm_buffer_table_limits(int *low, int *high);


/* Initialise per-nic buffer table allocator. */
extern int efrm_nic_buffer_table_ctor(struct efrm_nic *,
				      int bt_min, int bt_lim);

/* Destroy per-nic buffer table allocator. */
extern void efrm_nic_buffer_table_dtor(struct efrm_nic *);

/* Allocate buffer table entries for use with single NIC. */
extern int efrm_nic_buffer_table_alloc(struct efrm_nic *, unsigned order,
				       struct efhw_buffer_table_allocation *);

/* Free buffer table entries allocated with efrm_nic_buffer_table_alloc. */
extern void efrm_nic_buffer_table_free(struct efrm_nic *,
				       struct efhw_buffer_table_allocation *);


/*--------------------------------------------------------------------
 *
 * buffer table operations through the HW independent API
 *
 *--------------------------------------------------------------------*/

/*! free a previously allocated region of buffer table space */
extern void efrm_buffer_table_free(struct efhw_buffer_table_allocation *a);

extern void efrm_buffer_table_commit(struct efhw_nic*);

extern void efrm_buffer_table_set(struct efhw_buffer_table_allocation *,
				  struct efhw_nic *,
				  unsigned i, dma_addr_t dma_addr, int owner);
extern void efrm_buffer_table_set_n(struct efhw_buffer_table_allocation *a,
				    struct efhw_nic *nic, int n_pages,
				    unsigned i, dma_addr_t dma_addr, int owner);


#endif /* __CI_EFRM_BUFFER_TABLE_H__ */
