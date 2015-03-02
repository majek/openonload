/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_SRIOV_H
#define EFX_SRIOV_H

#include "net_driver.h"

#ifdef CONFIG_SFC_SRIOV

void efx_sriov_init_max_vfs(struct efx_nic *efx, unsigned int pf_index);

int efx_sriov_set_vf_mac(struct net_device *net_dev, int vf_i, u8 *mac);
int efx_sriov_set_vf_vlan(struct net_device *net_dev, int vf_i, u16 vlan,
			  u8 qos);
int efx_sriov_set_vf_spoofchk(struct net_device *net_dev, int vf_i,
			      bool spoofchk);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_sriov_get_vf_config(struct net_device *net_dev, int vf_i,
			    struct ifla_vf_info *ivi);
#endif
int efx_sriov_set_vf_link_state(struct net_device *net_dev, int vf_i,
				int link_state);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_NEED_GET_PHYS_PORT_ID)
int efx_sriov_get_phys_port_id(struct net_device *net_dev,
			       struct netdev_phys_item_id *ppid);
#endif

#endif /* CONFIG_SFC_SRIOV */

#endif /* EFX_SRIOV_H */
