/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#ifndef EF10_SRIOV_H
#define EF10_SRIOV_H

#include "net_driver.h"

/**
 * struct ef10_vf - PF's store of VF data
 * @efx: efx_nic struct for the current VF
 * @pci_dev: the pci_dev struct for the VF, retained while the VF is assigned
 * @vport_id: vport ID for the VF
 * @vport_assigned: record whether the vport is currently assigned to the VF
 * @mac: MAC address for the VF, zero when address is removed from the vport
 * @vlan: Default VLAN for the VF or #EFX_FILTER_VID_UNSPEC
 * @vlan_restrict: Restrict VLAN traffic VF is allowed to receive and send
 *	(if Tx MAC spoofing privilege is not granted). If restricted, VF
 *	driver should install filter with VLAN to get corresponding
 *	traffic. GRP_UNRESTRICTED_VLAN privilege controls if the filter
 *	installation is permitted.
#if defined(__VMKLNX__) && defined(EFX_USE_MCDI_PROXY_AUTH)
 * @rx_mode: Rx mode granted to the VF
 * @mac_mtu: MAC MTU set by the ESX for VF or 0
 * @pending_proxy_req: pending proxied auth request
 * @allowed_vlans: allowed VLANs
 * @active_vlans: VLANs requested by the VF driver
#endif
 */
struct ef10_vf {
	struct efx_nic *efx;
	struct pci_dev *pci_dev;
	unsigned int vport_id;
	unsigned int vport_assigned;
	u8 mac[ETH_ALEN];
	u16 vlan;
/* Default VF VLAN ID on creation */
#define EFX_VF_VID_DEFAULT	EFX_FILTER_VID_UNSPEC
	bool vlan_restrict;
};

#ifdef CONFIG_SFC_SRIOV
static inline struct ef10_vf *efx_ef10_vf_info(struct efx_nic *efx, int vf_i)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (!nic_data->vf || vf_i < 0 || vf_i >= efx->vf_count)
		return NULL;

	return nic_data->vf + vf_i;
}
#endif

int efx_ef10_sriov_init(struct efx_nic *efx);
void efx_ef10_sriov_fini(struct efx_nic *efx);
bool efx_ef10_sriov_wanted(struct efx_nic *efx);
int efx_ef10_sriov_configure(struct efx_nic *efx, int num_vfs);
void efx_ef10_sriov_flr(struct efx_nic *efx, unsigned int flr);

int efx_ef10_vswitching_probe_pf(struct efx_nic *efx);
int efx_ef10_vswitching_probe_vf(struct efx_nic *efx);
int efx_ef10_vswitching_restore_pf(struct efx_nic *efx);
int efx_ef10_vswitching_restore_vf(struct efx_nic *efx);
void efx_ef10_vswitching_remove_pf(struct efx_nic *efx);
void efx_ef10_vswitching_remove_vf(struct efx_nic *efx);
int efx_ef10_vadaptor_alloc(struct efx_nic *efx, unsigned int port_id);
int efx_ef10_vadaptor_query(struct efx_nic *efx, unsigned int port_id,
			    u32 *port_flags, u32 *vadaptor_flags,
			    unsigned int *vlan_tags);
int efx_ef10_vadaptor_free(struct efx_nic *efx, unsigned int port_id);

int efx_ef10_sriov_set_vf_mac(struct efx_nic *efx, int vf_i, u8 *mac);
int efx_ef10_sriov_set_vf_vlan(struct efx_nic *efx, int vf_i, u16 vlan,
			       u8 qos);
int efx_ef10_sriov_set_vf_spoofchk(struct efx_nic *efx, int vf, bool spoofchk);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_ef10_sriov_get_vf_config(struct efx_nic *efx, int vf_i,
				 struct ifla_vf_info *ivf);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_LINK_STATE)
int efx_ef10_sriov_set_vf_link_state(struct efx_nic *efx, int vf_i,
				     int link_state);
#endif
#endif

/* MCFW vswitch operations */
int efx_ef10_vswitch_alloc(struct efx_nic *efx, unsigned int port_id,
			   unsigned int vswitch_type);
int efx_ef10_vswitch_free(struct efx_nic *efx, unsigned int port_id);
int efx_ef10_vport_alloc(struct efx_nic *efx, unsigned int port_id_in,
			 unsigned int vport_type, u16 vlan, bool vlan_restrict,
			 unsigned int *port_id_out);
int efx_ef10_vport_free(struct efx_nic *efx, unsigned int port_id);
int efx_ef10_evb_port_assign(struct efx_nic *efx, unsigned int port_id,
			     unsigned int vf_fn);
int efx_ef10_vport_add_mac(struct efx_nic *efx, unsigned int port_id, u8 *mac);
int efx_ef10_vport_del_mac(struct efx_nic *efx, unsigned int port_id, u8 *mac);
int efx_ef10_vport_get_stats(struct efx_nic *efx, unsigned int vport_id,
			     u64 *stats, spinlock_t *lock);

#endif /* EF10_SRIOV_H */
