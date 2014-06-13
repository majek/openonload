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
 * This file contains support for the global driver variables.
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
#include <ci/efrm/resource.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/pd.h>
#include "efrm_internal.h"


/* These routines are all methods on the architecturally singleton
   global variables: efrm_nic_table, efrm_rm_table.

   I hope we never find a driver model that does not allow global
   structure variables :) (but that would break almost every driver I've
   ever seen).
*/

/*! Exported driver state */
static struct efrm_nic_table efrm_nic_table;
struct efrm_nic_table *efrm_nic_tablep;
EXPORT_SYMBOL(efrm_nic_tablep);


/* Internal table with resource managers.
 * We'd like to not export it, but we are still using efrm_rm_table
 * in the char driver. So, it is declared in the private header with
 * a purpose. */
struct efrm_resource_manager *efrm_rm_table[EFRM_RESOURCE_NUM];
EXPORT_SYMBOL(efrm_rm_table);


/* List of registered nics. */
static LIST_HEAD(efrm_nics);


void efrm_driver_ctor(void)
{
	efrm_nic_tablep = &efrm_nic_table;
	spin_lock_init(&efrm_nic_tablep->lock);
	EFRM_TRACE("%s: driver created", __FUNCTION__);
}

void efrm_driver_stop(void)
{
	/* Take the nic table down so that users of EFRM_FOR_EACH_NIC()
	 * don't see any NICs */
	efrm_nic_table.down = 1;
	smp_wmb();
	while (efrm_nic_table_held())
		cpu_relax();
}


void efrm_driver_dtor(void)
{
	EFRM_ASSERT(efrm_nic_table_down());

	spin_lock_destroy(&efrm_nic_tablep->lock);
	memset(&efrm_nic_table, 0, sizeof(efrm_nic_table));
	memset(&efrm_rm_table, 0, sizeof(efrm_rm_table));
	EFRM_TRACE("%s: driver deleted", __FUNCTION__);
}


int efrm_nic_ctor(struct efrm_nic *efrm_nic, int ifindex,
		  const struct vi_resource_dimensions *res_dim)
{
	unsigned max_vis;
	int rc;

	if (efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_EF10) {
		max_vis = res_dim->vi_lim;
	}
	else if (efrm_nic->efhw_nic.devtype.arch == EFHW_ARCH_FALCON) {
		max_vis = max(res_dim->evq_int_lim, res_dim->evq_timer_lim);
		max_vis = min(max_vis, res_dim->txq_lim);
		max_vis = min(max_vis, res_dim->rxq_lim);
	}
	else {
		EFRM_ERR("%s: unknown efhw device architecture %u)",
			 __FUNCTION__, efrm_nic->efhw_nic.devtype.arch);
		rc = -EINVAL;
		goto fail1;
	}

	efrm_nic->vis = vmalloc(max_vis * sizeof(efrm_nic->vis[0]));
	if (efrm_nic->vis == NULL) {
		EFRM_ERR("%s: Out of memory (max_vis=%u)",
			 __FUNCTION__, max_vis);
		rc = -ENOMEM;
		goto fail1;
	}
	memset(efrm_nic->vis, 0, max_vis * sizeof(efrm_nic->vis[0]));

	rc = efrm_vi_allocator_ctor(efrm_nic, res_dim);
	if (rc < 0) {
		EFRM_ERR("%s: efrm_vi_allocator_ctor failed (%d)",
			 __FUNCTION__, rc);
		goto fail2;
	}

	/* We request ids based on 1, as we use a 0 owner_id within Onload to 
	 * show we're using physical addressing mode.  On ef10 0 is part of
	 * our available owner id space, so we will map owner id back to 0
	 * based before passing through MCDI.
	 */
	efrm_nic->owner_ids = efrm_pd_owner_ids_ctor(1, max_vis);
	if (efrm_nic->owner_ids == NULL) {
		EFRM_ERR("%s: Out of memory (max_vis=%u)",
			 __FUNCTION__, max_vis);
		rc = -ENOMEM;
		goto fail3;
	}

	spin_lock_init(&efrm_nic->lock);
	efrm_nic->efhw_nic.ifindex = ifindex;
	INIT_LIST_HEAD(&efrm_nic->clients);
	return 0;

fail3:
	efrm_vi_allocator_dtor(efrm_nic);
	
fail2:
	vfree(efrm_nic->vis);
fail1:
	return rc;
}


void efrm_nic_dtor(struct efrm_nic *efrm_nic)
{
	/* Things have gone very wrong if there are any driver clients */
	EFRM_ASSERT(list_empty(&efrm_nic->clients));

	efrm_pd_owner_ids_dtor(efrm_nic->owner_ids);
	efrm_vi_allocator_dtor(efrm_nic);
	vfree(efrm_nic->vis);

	/* Nobble some fields. */
	efrm_nic->vis = NULL;
	efrm_nic->efhw_nic.ifindex = -1;
}


int efrm_driver_register_nic(struct efrm_nic *rnic)
{
	struct efhw_nic *nic = &rnic->efhw_nic;
	int nic_index, rc = 0;

	spin_lock_bh(&efrm_nic_tablep->lock);

	if (efrm_nic_table_held()) {
		EFRM_ERR("%s: driver object is in use", __FUNCTION__);
		rc = -EBUSY;
		goto done;
	}

	/* Find a slot in the nic table. */
	for (nic_index = 0; nic_index < EFHW_MAX_NR_DEVS; ++nic_index)
		if (efrm_nic_tablep->nic[nic_index] == NULL)
			break;
	if (nic_index == EFHW_MAX_NR_DEVS) {
		EFRM_ERR("%s: filled up NIC table size %d", __FUNCTION__,
			 EFHW_MAX_NR_DEVS);
		rc = -E2BIG;
		goto done;
	}

	efrm_nic_tablep->nic[nic_index] = nic;
	nic->index = nic_index;
	list_add(&rnic->link, &efrm_nics);
	efrm_nic_vi_ctor(&rnic->nvi);
	spin_unlock_bh(&efrm_nic_tablep->lock);
	return 0;

done:
	spin_unlock_bh(&efrm_nic_tablep->lock);
	return rc;
}


void efrm_driver_unregister_nic(struct efrm_nic *rnic)
{
	struct efhw_nic *nic = &rnic->efhw_nic;
	int nic_index = nic->index;

	EFRM_ASSERT(nic_index >= 0);

	efrm_nic_vi_dtor(&rnic->nvi);

	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_ASSERT(efrm_nic_tablep->nic[nic_index] == nic);
	list_del(&rnic->link);
	nic->index = -1;
	efrm_nic_tablep->nic[nic_index] = NULL;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}

#ifdef __KERNEL__


int efrm_nic_post_reset(struct efhw_nic *nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	struct efrm_client *client;
	struct list_head *client_link;
	struct list_head reset_list;

	INIT_LIST_HEAD(&reset_list);

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(client_link, &rnic->clients) {
		client = container_of(client_link, struct efrm_client, link);
		/* can't call post_reset directly as we're holding a
		 * spin lock and it may block (on EF10).  So just take
		 * a reference and call post_reset below 
		 */
		if (client->callbacks->post_reset) {
			++client->ref_count;
			list_add(&client->reset_link, &reset_list);
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	while (!list_empty(&reset_list)) {
		client = list_entry(list_pop(&reset_list), struct efrm_client, 
				    reset_link);
		client->callbacks->post_reset(client, client->user_data);
		/* drop reference we took above */
		efrm_client_put(client);
	}

	return 0;
}


static void efrm_client_nullcb(struct efrm_client *client, void *user_data)
{
}


static struct efrm_client_callbacks efrm_null_callbacks = {
	efrm_client_nullcb
};

static void efrm_client_init_from_nic(struct efrm_nic *rnic,
				      struct efrm_client *client)
{
	client->nic = &rnic->efhw_nic;
	client->ref_count = 1;
	INIT_LIST_HEAD(&client->resources);
	list_add(&client->link, &rnic->clients);
}

int efrm_client_get(int ifindex, struct efrm_client_callbacks *callbacks,
		    void *user_data, struct efrm_client **client_out)
{
	struct efrm_nic *n, *rnic = NULL;
	struct list_head *link;
	struct efrm_client *client;

	if (callbacks == NULL)
		callbacks = &efrm_null_callbacks;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (client == NULL)
		return -ENOMEM;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each(link, &efrm_nics) {
		n = container_of(link, struct efrm_nic, link);
		if (n->efhw_nic.ifindex == ifindex || ifindex < 0) {
			rnic = n;
			break;
		}
	}
	if (rnic) {
		client->user_data = user_data;
		client->callbacks = callbacks;
		efrm_client_init_from_nic(rnic, client);
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	if (rnic == NULL) {
		kfree(client);
		return -ENODEV;
	}

	*client_out = client;
	return 0;
}
EXPORT_SYMBOL(efrm_client_get);


void efrm_client_put(struct efrm_client *client)
{
	EFRM_ASSERT(client->ref_count > 0);

	spin_lock_bh(&efrm_nic_tablep->lock);
	if (--client->ref_count > 0)
		client = NULL;
	else
		list_del(&client->link);
	spin_unlock_bh(&efrm_nic_tablep->lock);
	kfree(client);
}
EXPORT_SYMBOL(efrm_client_put);


void efrm_client_add_ref(struct efrm_client *client)
{
	EFRM_ASSERT(client->ref_count > 0);
	spin_lock_bh(&efrm_nic_tablep->lock);
	++client->ref_count;
	spin_unlock_bh(&efrm_nic_tablep->lock);
}
EXPORT_SYMBOL(efrm_client_add_ref);


struct efhw_nic *efrm_client_get_nic(struct efrm_client *client)
{
	return client->nic;
}
EXPORT_SYMBOL(efrm_client_get_nic);


int efrm_client_get_ifindex(struct efrm_client *client)
{
	return client->nic->ifindex;
}
EXPORT_SYMBOL(efrm_client_get_ifindex);

int efrm_nic_present(int ifindex)
{
	struct efrm_nic *nic;
	int rc = 0;

	spin_lock_bh(&efrm_nic_tablep->lock);
	list_for_each_entry(nic, &efrm_nics, link) {
		if (nic->efhw_nic.ifindex == ifindex) {
			rc = 1;
			break;
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);

	return rc;
}
EXPORT_SYMBOL(efrm_nic_present);


#endif  /* __KERNEL__ */
