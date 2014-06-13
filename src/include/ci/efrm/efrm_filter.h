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
 * This file provides public API for adding packet filters.
 *
 * Copyright 2005-2012: Solarflare Communications Inc,
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

#ifndef __CI_EFRM_FILTER_H__
#define __CI_EFRM_FILTER_H__

struct efx_dl_device;
struct efx_filter_spec;
struct device;

enum efrm_filter_block_flags {
	EFRM_FILTER_BLOCK_UNICAST = 1,
	EFRM_FILTER_BLOCK_MULTICAST = 2,
	EFRM_FILTER_BLOCK_ALL = EFRM_FILTER_BLOCK_UNICAST |
				EFRM_FILTER_BLOCK_MULTICAST,
};


extern int  efrm_filter_insert(struct efrm_client *,
			       struct efx_filter_spec *spec,
			       bool replace_equal);
extern void efrm_filter_remove(struct efrm_client *, int filter_id);
extern void efrm_filter_redirect(struct efrm_client *,
				 int filter_id, int rxq_i);
extern int efrm_filter_block_kernel(struct efrm_client *client, int flags,
                                    bool block);

extern void efrm_filter_shutdown(void);
extern void efrm_filter_init(void);

extern void efrm_filter_install_proc_entries(void);
extern void efrm_filter_remove_proc_entries(void);

extern void efrm_init_resource_filter(struct device *dev, int ifindex);
extern void efrm_shutdown_resource_filter(struct device *dev);
extern int efrm_filter_rename( struct efhw_nic *nic,
                               struct net_device *net_dev );

#endif /* __CI_EFRM_FILTER_H__ */
