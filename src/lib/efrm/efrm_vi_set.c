/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/pd.h>
#include <ci/tools/log2.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"


#define efrm_vi_set(rs1)  container_of((rs1), struct efrm_vi_set, rs)


static int
efrm_rss_context_alloc_and_init(struct efrm_pd *pd,
				struct efrm_client *client,
				int num_qs,
				int rss_mode,
				unsigned *rss_context_out)
{
	int rc;
	int shared = 0;
	int index;
	/* Copied from efx_rss_fixed_key from linux_net/efx.c.
	 * FIXME: maintain consistency with net driver and tests. */
	static const uint8_t rx_hash_key_default[EFRM_RSS_KEY_LEN] = {
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	};
        const uint8_t* rx_hash_key = rx_hash_key_default;
	uint32_t rx_indir_table[EFRM_RSS_INDIRECTION_TABLE_LEN];
	if (num_qs > 1 && rss_mode != EFRM_RSS_MODE_DEFAULT &&
	    !(efrm_client_get_nic(client)->flags & NIC_FLAG_ADDITIONAL_RSS_MODES))
		return -EOPNOTSUPP;
	/* If the number of queues needed is a power of 2 we can simply use
	 * one of the shared contexts.
	 * If nic reports RX_RSS_LIMITED, shared rss contexts do not exist,
	 * so we must allocate an exclusive one.
	 * Alternative RSS hashes require individual RSS context.
	 */
	if (CI_IS_POW2(num_qs) &&
	    !(efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED) &&
	    rss_mode == EFRM_RSS_MODE_DEFAULT) {
		/* Shared rss contexts are only valid up to 64 queues - we
		 * don't allow min_n_vis any bigger anyway, so this has already
		 * been checked.
		 */
		EFRM_ASSERT(num_qs <= 64);

		shared = 1;
	}

	/* TODO: I've disabled use of shared RSS contexts because the
	 * firmware generates random hash keys by default.  This may give
	 * poor spreading, and won't be symmetric.  Once firmware has been
	 * fixed for a while we can re-enable shared contexts (or provide
	 * an option).
	 */
	shared = 0;

	/* Set up the indirection table to stripe evenly(ish) across VIs.
	 * FIXME: maintain consistency with net driver */
	for (index = 0; index < EFRM_RSS_INDIRECTION_TABLE_LEN; index++)
		rx_indir_table[index] = index % num_qs;

	/* If we have an exclusive context we need to set up the key and
	 * indirection table.
	 *
	 * We use fixed key, that:
	 * 1. has been tested and found to provide
	 * good spreading behaviour (random keys do not give such warranty).
	 *
	 * 2. matches net driver's rss key, meaning
	 * guarantees the same spreading regardless whether net driver's or private
	 * rss context is used (applies to 7000 series devices only).
	 * NOTE1: netdriver might be configured to use random key.
	 * NOTE2: shared keys currently are set with random keys by fw.
	 *
	 * The same key accross devices will ensure the identical spreading,
	 * which is important for maintaining proper opration after bond
	 * reconfiguration or fallover.
	 * Also Transparent proxy requires identical rss key on its devices.
	 */

	rc = efrm_rss_context_alloc(client, efrm_pd_get_vport_id(pd),
				    shared, rx_indir_table,
				    rx_hash_key, rss_mode, num_qs,
				    rss_context_out);
	return rc;
}


int efrm_vi_set_alloc(struct efrm_pd *pd, int n_vis, unsigned vi_props,
		      int rss_modes,
		      struct efrm_vi_set **vi_set_out)
{
	struct efrm_client *client;
	struct efrm_vi_set *vi_set;
	struct efrm_nic *efrm_nic;
	int i, j, rc;
	int rss_limited;
	EFRM_ASSERT(0 == (rss_modes &
		  ~(EFRM_RSS_MODE_DEFAULT|EFRM_RSS_MODE_SRC|EFRM_RSS_MODE_DST)));
	EFRM_ASSERT(rss_modes & (EFRM_RSS_MODE_DEFAULT|EFRM_RSS_MODE_SRC));
	/* mode default and src are exclusive */
	EFRM_ASSERT(~rss_modes & (EFRM_RSS_MODE_DEFAULT|EFRM_RSS_MODE_SRC));
	if (n_vis < 1 || n_vis > 64) {
		EFRM_ERR("%s: ERROR: set size=%d out of range (max=64)",
			 __FUNCTION__, n_vis);
		return -EINVAL;
	}

	if ((vi_set = kmalloc(sizeof(*vi_set), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	client = efrm_pd_to_resource(pd)->rs_client;
	efrm_nic = container_of(client->nic, struct efrm_nic, efhw_nic);
	rss_limited =
		efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED;

	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i)
		vi_set->rss_context[i] = -1;

	if (!(n_vis > 1 || rss_limited)) {
		/* Don't bother allocating a context of size 1, just use
		 * the netdriver's context.
		 */
		goto skip_context_alloc;
	}
	for (j = 0; rss_modes; j++) {
		/* least significant bit of rss_modes */
		int rss_mode = rss_modes ^ (rss_modes & (rss_modes -1));
		rss_modes &= ~rss_mode;
		rc = efrm_rss_context_alloc_and_init(pd, client, n_vis,
						     rss_mode,
						     &vi_set->rss_context[j]);
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
				goto fail1;

			if (rc != -EOPNOTSUPP)
				EFRM_ERR("%s: WARNING: Failed to allocate RSS "
					 "context of size %d (rc %d), falling "
					 "back to default context.",
					 __FUNCTION__, n_vis, rc);
		}
	}

 skip_context_alloc:
	rc = efrm_vi_allocator_alloc_set(efrm_nic, vi_props, n_vis,
					 vi_set->rss_context[0] != -1 ? 1 : 0,
					 -1, &vi_set->allocation);
	if (rc != 0)
		goto fail1;
	efrm_resource_init(&vi_set->rs, EFRM_RESOURCE_VI_SET,
			vi_set->allocation.instance);
	efrm_client_add_resource(client, &vi_set->rs);
	vi_set->pd = pd;
	efrm_resource_ref(efrm_pd_to_resource(pd));
	vi_set->free = 0;
	for (i = 0; i < n_vis; ++i )
		vi_set->free |= 1ULL << i;
	spin_lock_init(&vi_set->allocation_lock);
	vi_set->n_vis = n_vis;
	init_completion(&vi_set->allocation_completion);
	vi_set->n_vis_flushing = 0;
	vi_set->n_flushing_waiters = 0;
	*vi_set_out = vi_set;

	return 0;
 fail1:
	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i)
		if (vi_set->rss_context[i] != -1)
			efrm_rss_context_free(client, vi_set->rss_context[i]);

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
	int i;
	efrm_nic = container_of(vi_set->rs.rs_client->nic,
				struct efrm_nic, efhw_nic);

	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i)
		if (vi_set->rss_context[i] != -1)
			efrm_rss_context_free(vi_set->rs.rs_client,
					      vi_set->rss_context[i]);
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


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set, unsigned rss_id)
{
	EFRM_ASSERT(rss_id <= EFRM_RSS_MODE_ID_MAX);
	return vi_set->rss_context[rss_id];
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
