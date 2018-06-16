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

#ifndef __EFRM_CLIENT_H__
#define __EFRM_CLIENT_H__


struct efrm_client;


struct efrm_client_callbacks {
        /* Called after NIC is back up and MCDI is possible. */
	void (*post_reset)(struct efrm_client *, void *user_data);
        /* Called when a reset has been notified. */
	void (*reset_suspend)(struct efrm_client *, void *user_data);
};


struct efrm_client_attr {
	/* Bitmask of supported ring sizes indexed by efhw_q_type. */
	unsigned vi_ring_sizes[3];
	unsigned vi_ring_doorbell_off[3];
};


/* Selects an arbitrary interface. */
#define EFRM_IFINDEX_DEFAULT  -1


/* NB. Callbacks may be invoked even before this returns. */
extern int  efrm_client_get(int ifindex, struct efrm_client_callbacks *,
			    void *user_data, struct efrm_client **client_out);
extern void efrm_client_put(struct efrm_client *);
extern void efrm_client_add_ref(struct efrm_client *);

extern
const struct efrm_client_attr *efrm_client_get_attr(struct efrm_client *);
extern struct efhw_nic *efrm_client_get_nic(struct efrm_client *);
extern int efrm_client_get_ifindex(struct efrm_client *);

extern int efrm_nic_present(int ifindex);

extern void efrm_client_disable_post_reset(struct efrm_client*);



#endif  /* __EFRM_CLIENT_H__ */
