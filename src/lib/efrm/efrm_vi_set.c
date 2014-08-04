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


/* These values are defined by hardware. */
#define RSS_KEY_LEN 40
#define RSS_TABLE_LEN 128


int efrm_rss_context_alloc(struct efrm_client *client,
			   struct efrm_vi_set *vi_set, int num_qs)
{
	int rc;
	int shared = 0;
	int index;
	uint8_t rx_hash_key[RSS_KEY_LEN];
	uint8_t rx_indir_table[RSS_TABLE_LEN];

	/* If the number of queues needed is a power of 2 we can simply use
	 * one of the shared contexts.
	 * If nic reports RX_RSS_LIMITED, shared rss contexts do not exist,
	 * so we must allocate an exclusive one.
	 */
	if ( !(num_qs & (num_qs - 1)) &&
		!(efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED) ) {
		/* Shared rss contexts are only valid up to 64 queues - we
		 * don't allow min_n_vis any bigger anyway, so this has already
		 * been checked.
		 */
		EFRM_ASSERT(num_qs <= 64);

		shared = 1;
	}

	rc = efhw_nic_rss_context_alloc(client->nic, num_qs, shared,
					&vi_set->rss_context);

	if (rc < 0 || shared)
		return rc;

	/* If we have an exclusive context we need to set up the key and
	 * indirection table.
	 *
	 * Just use a random key.
	 */
	get_random_bytes(rx_hash_key, RSS_KEY_LEN);
	rc = efhw_nic_rss_context_set_key(client->nic, vi_set->rss_context,
					  rx_hash_key);
	if (rc < 0)
		goto fail;

	/* Set up the indirection table to stripe evenly(ish) across vis. */
	for (index = 0; index < RSS_TABLE_LEN; index++)
		rx_indir_table[index] = index % num_qs;

	rc = efhw_nic_rss_context_set_table(client->nic, vi_set->rss_context,
					    rx_indir_table);
	if (rc <  0)
		goto fail;

	return rc;

fail:
	efhw_nic_rss_context_free(client->nic, vi_set->rss_context);
	return rc;
}


int efrm_vi_set_alloc(struct efrm_pd *pd, int n_vis, unsigned vi_props,
		      struct efrm_vi_set **vi_set_out)
{
	struct efrm_client *client;
	struct efrm_vi_set *vi_set;
	struct efrm_nic *efrm_nic;
	int i, rc;
	int rss_limited;

	if (n_vis > 64) {
		EFRM_ERR("%s: ERROR: set size=%d too big (max=64)",
			 __FUNCTION__, n_vis);
		return -EINVAL;
	}

	if ((vi_set = kmalloc(sizeof(*vi_set), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	client = efrm_pd_to_resource(pd)->rs_client;
	efrm_nic = container_of(client->nic, struct efrm_nic, efhw_nic);
	rss_limited =
		efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED;

	if (n_vis > 1 || rss_limited) {
		rc = efrm_rss_context_alloc(client, vi_set, n_vis);
		/* If we failed to allocate an RSS context fall back to
		* using the netdriver's default context.
		*
		* This can occur if the FW does not support allocating an
		* RSS context, or if it's out of contexts.
	 	*/
		if (rc != 0) {
			/* If RX_RSS_LIMITED is set, the netdriver will not
			 * have allocated a default context.
			 */
			if (rss_limited)
				return rc;

			if (rc != -EOPNOTSUPP)
				EFRM_ERR("%s: WARNING: Failed to allocate RSS "
					 "context of size %d (rc %d), falling "
					 "back to default context.",
					 __FUNCTION__, n_vis, rc);
			vi_set->rss_context = -1;
		}
	}
	else {
		/* Don't bother allocating a context of size 1, just use
		 * the netdriver's context.
		 */
		vi_set->rss_context = -1;
	}

	rc = efrm_vi_allocator_alloc_set(efrm_nic, vi_props, n_vis,
					 vi_set->rss_context != -1 ? 1 : 0,
					 -1, &vi_set->allocation);
	if (rc == 0) {
		efrm_resource_init(&vi_set->rs, EFRM_RESOURCE_VI_SET,
				   vi_set->allocation.instance);
		efrm_client_add_resource(client, &vi_set->rs);
		vi_set->pd = pd;
		efrm_resource_ref(efrm_pd_to_resource(pd));
		vi_set->free = 0;
		for (i = 0; i < n_vis; ++i )
			vi_set->free |= 1 << i;
		spin_lock_init(&vi_set->allocation_lock);
		vi_set->n_vis = n_vis;
		init_completion(&vi_set->allocation_completion);
		vi_set->n_vis_flushing = 0;
		vi_set->n_flushing_waiters = 0;
		*vi_set_out = vi_set;
	}
	else if (vi_set->rss_context != -1 ) {
		efhw_nic_rss_context_free(client->nic, vi_set->rss_context);
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
	int n_free;
	uint64_t free = vi_set->free;
	efrm_nic = container_of(vi_set->rs.rs_client->nic,
				struct efrm_nic, efhw_nic);

	if (vi_set->rss_context != -1)
		efhw_nic_rss_context_free(vi_set->rs.rs_client->nic,
					  vi_set->rss_context);
	efrm_vi_allocator_free_set(efrm_nic, &vi_set->allocation);
	efrm_pd_release(vi_set->pd);
	efrm_client_put(vi_set->rs.rs_client);

	for (n_free = 0; free; ++n_free)
		free &= free - 1;
	EFRM_ASSERT(n_free == vi_set->n_vis);
	kfree(vi_set);
}


int efrm_vi_set_num_vis(struct efrm_vi_set *vi_set)
{
	return vi_set->n_vis;
}
EXPORT_SYMBOL(efrm_vi_set_num_vis);


int efrm_vi_set_get_base(struct efrm_vi_set *vi_set)
{
	return vi_set->allocation.instance;
}
EXPORT_SYMBOL(efrm_vi_set_get_base);


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set)
{
	return vi_set->rss_context;
}
EXPORT_SYMBOL(efrm_vi_set_get_rss_context);


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


struct efrm_pd* efrm_vi_set_get_pd(struct efrm_vi_set *vi_set)
{
	return vi_set->pd;
}
EXPORT_SYMBOL(efrm_vi_set_get_pd);


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
