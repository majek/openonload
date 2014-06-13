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
 *
 * This file provides public API for vi_set resource.
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
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/pd.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"


#define efrm_vi_set(rs1)  container_of((rs1), struct efrm_vi_set, rs)


int efrm_vi_set_alloc(struct efrm_pd *pd, int min_n_vis,
		      unsigned vi_props, struct efrm_vi_set **vi_set_out)
{
	struct efrm_client *client;
	struct efrm_vi_set *vi_set;
	struct efrm_nic *efrm_nic;
	int rc;

	if (min_n_vis > 64) {
		EFRM_ERR("%s: ERROR: set size=%d too big (max=64)",
			 __FUNCTION__, min_n_vis);
		return -EINVAL;
	}

	if ((vi_set = kmalloc(sizeof(*vi_set), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	client = efrm_pd_to_resource(pd)->rs_client;
	efrm_nic = container_of(client->nic, struct efrm_nic, efhw_nic);
	rc = efrm_vi_allocator_alloc_set(efrm_nic, vi_props, min_n_vis,
					 -1, &vi_set->allocation);
	if (rc == 0) {
		efrm_resource_init(&vi_set->rs, EFRM_RESOURCE_VI_SET,
				   vi_set->allocation.instance);
		efrm_client_add_resource(client, &vi_set->rs);
		vi_set->pd = pd;
		efrm_resource_ref(efrm_pd_to_resource(pd));
		vi_set->free = (1 << (1 << vi_set->allocation.order)) - 1;
		*vi_set_out = vi_set;
	}
	return rc;
}
EXPORT_SYMBOL(efrm_vi_set_alloc);


void efrm_vi_set_release(struct efrm_vi_set *vi_set)
{
	if (__efrm_resource_release(&vi_set->rs))
		efrm_vi_set_free(vi_set);
}
EXPORT_SYMBOL(efrm_vi_set_release);


void efrm_vi_set_free(struct efrm_vi_set *vi_set)
{
	struct efrm_nic *efrm_nic;
	efrm_nic = container_of(vi_set->rs.rs_client->nic,
				struct efrm_nic, efhw_nic);
	efrm_vi_allocator_free_set(efrm_nic, &vi_set->allocation);
	efrm_pd_release(vi_set->pd);
	efrm_client_put(vi_set->rs.rs_client);
	EFRM_ASSERT(vi_set->free == (1 << (1 << vi_set->allocation.order)) - 1);
	kfree(vi_set);
}


int efrm_vi_set_num_vis(struct efrm_vi_set *vi_set)
{
	return 1 << vi_set->allocation.order;
}
EXPORT_SYMBOL(efrm_vi_set_num_vis);


int efrm_vi_set_get_base(struct efrm_vi_set *vi_set)
{
	return vi_set->allocation.instance;
}
EXPORT_SYMBOL(efrm_vi_set_get_base);


struct efrm_resource * efrm_vi_set_to_resource(struct efrm_vi_set *vi_set)
{
	return &vi_set->rs;
}
EXPORT_SYMBOL(efrm_vi_set_to_resource);


struct efrm_vi_set * efrm_vi_set_from_resource(struct efrm_resource *rs)
{
	return efrm_vi_set(rs);
}
EXPORT_SYMBOL(efrm_vi_set_from_resource);


static void efrm_vi_set_rm_dtor(struct efrm_resource_manager *rm)
{
}


int
efrm_create_vi_set_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_resource_manager *rm;
	int rc;

	rm = kmalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;
	memset(rm, 0, sizeof(*rm));

	rc = efrm_resource_manager_ctor(rm, efrm_vi_set_rm_dtor, "VI_SET",
					EFRM_RESOURCE_VI_SET);
	if (rc < 0)
		goto fail1;

	*rm_out = rm;
	return 0;

fail1:
	kfree(rm);
	return rc;
}
