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
 * This file provides public API for iobufset resource.
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

#ifndef __CI_EFRM_IOBUFSET_H__
#define __CI_EFRM_IOBUFSET_H__

#include <ci/efrm/resource.h>
#include <ci/efhw/common.h>
#include <ci/efrm/debug.h>


struct efrm_pd;


/*! Iobufset resource structture.
 * Users should not access the structure fields directly, but use the API
 * below.
 * However, this structure should not be moved out of public headers,
 * because part of API (ex. efrm_iobufset_dma_addr function) is inline and
 * is used in the fast-path code.
 */
struct iobufset_resource {
	struct efrm_resource rs;
	struct pci_dev *pci_dev;
	struct efrm_pd *pd;
	struct iobufset_resource *linked;
	struct efhw_buffer_table_allocation buf_tbl_alloc;
	unsigned int n_bufs;
	struct efhw_iopage bufs[1];
	/*!< up to n_bufs can follow this, so this must be the last member */
};

#define iobufset_resource(rs1) \
	container_of((rs1), struct iobufset_resource, rs)

/*!
 * Allocate iobufset resource.
 *
 * \param vi        VI that "owns" these buffers. Grabs a reference
 *                  on success.
 * \param linked    Uses memory from an existing iobufset.  Grabs a
 *                  reference on success.
 * \param iobrs_out pointer to return the new filter resource
 *
 * \return          status code; if non-zero, frs_out is unchanged
 */
extern int
efrm_iobufset_resource_alloc(int n_pages, struct efrm_pd *pd,
			     struct iobufset_resource *linked,
			     struct iobufset_resource **iobrs_out);

extern void efrm_iobufset_resource_release(struct iobufset_resource *);

#endif /* __CI_EFRM_IOBUFSET_H__ */
