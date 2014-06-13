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

#ifndef __EFRM_INTERNAL_H__
#define __EFRM_INTERNAL_H__

#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>

#include <ci/efrm/vi_allocation.h>


struct efrm_resource;


struct efrm_client {
	void *user_data;
	/* Used to assemble list of clients in an efrm_nic */
	struct list_head link;
	/* Used to assemble list of clients needing post_reset callback */
	struct list_head reset_link;
	struct efrm_client_callbacks *callbacks;
	struct efhw_nic *nic;
	int ref_count;
	struct list_head resources;
};


/* Only for resources not associated with specific NIC. */
extern void efrm_resource_manager_add_resource(struct efrm_resource *);

extern void efrm_client_add_resource(struct efrm_client *,
				     struct efrm_resource *);

extern void efrm_nic_vi_ctor(struct efrm_nic_vi *);
extern void efrm_nic_vi_dtor(struct efrm_nic_vi *);


static inline void efrm_resource_init(struct efrm_resource *rs,
				      int type, int instance)
{
	EFRM_ASSERT(instance >= 0);
	EFRM_ASSERT(type >= 0 && type < EFRM_RESOURCE_NUM);
	rs->rs_ref_count = 1;
	rs->rs_type = type;
	rs->rs_instance = instance;
	rs->rs_client = NULL;
}

#ifdef __KERNEL__
extern int efrm_nic_post_reset(struct efhw_nic *nic);
#endif


static inline struct efrm_nic *efrm_nic_from_efhw_nic(struct efhw_nic *nic)
{
	return container_of(nic, struct efrm_nic, efhw_nic);
}


static inline struct efrm_nic *efrm_nic_from_client(struct efrm_client *client)
{
	return container_of(client->nic, struct efrm_nic, efhw_nic);
}


static inline struct efrm_nic *efrm_nic_from_rs(struct efrm_resource *rs)
{
	return efrm_nic_from_client(rs->rs_client);
}


extern int  efrm_vi_allocator_ctor(struct efrm_nic *,
				   const struct vi_resource_dimensions *);
extern void efrm_vi_allocator_dtor(struct efrm_nic *);

/* Allocate a set of VIs with given properties.  Returns 0 or negative
 * error code.  If more than one VI is requested, then a consecutive block
 * of VIs are allocated (if possible).
 */
extern int  efrm_vi_allocator_alloc_set(struct efrm_nic *, unsigned vi_props,
					int min_vis_in_set, int channel,
					struct efrm_vi_allocation *set_out);
extern void efrm_vi_allocator_free_set(struct efrm_nic *,
				       struct efrm_vi_allocation *);


#endif  /* __EFRM_INTERNAL_H__ */
