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
 * Copyright 2014 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/pci.h>
#include <linux/module.h>
#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "mcdi_pcol.h"
#include "sriov.h"
#include "ef10_sriov.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_GET_TOTALVFS) || defined(CONFIG_SFC_SRIOV)
/*
 * Force allocation of a vswitch.
 */
static bool enable_vswitch;
module_param(enable_vswitch, bool, 0444);
MODULE_PARM_DESC(enable_vswitch,
		 "Force allocation of a VEB vswitch on supported adapters");
#endif


#ifdef CONFIG_SFC_SRIOV
static void efx_ef10_sriov_free_vf_vports(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int i;

	if (!nic_data->vf)
		return;

	for (i = 0; i < efx->vf_count; i++) {
		struct ef10_vf *vf = nic_data->vf + i;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
		/* If VF is assigned, do not free the vport  */
		if (vf->pci_dev &&
		    vf->pci_dev->dev_flags & PCI_DEV_FLAGS_ASSIGNED)
			continue;
#endif

		if (vf->vport_assigned) {
			efx_ef10_evb_port_assign(efx, EVB_PORT_ID_NULL, i);
			vf->vport_assigned = 0;
		}

		if (!is_zero_ether_addr(vf->mac)) {
			efx_ef10_vport_del_mac(efx, vf->vport_id, vf->mac);
			eth_zero_addr(vf->mac);
		}

		if (vf->vport_id) {
			efx_ef10_vport_free(efx, vf->vport_id);
			vf->vport_id = 0;
		}

		vf->efx = NULL;
	}
}

static void efx_ef10_sriov_free_vf_vswitching(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	efx_ef10_sriov_free_vf_vports(efx);
	kfree(nic_data->vf);
	nic_data->vf = NULL;
}

static int efx_ef10_sriov_assign_vf_vport(struct efx_nic *efx,
					  unsigned int vf_i)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct ef10_vf *vf = nic_data->vf + vf_i;
	int rc;

	if (WARN_ON_ONCE(nic_data->vf == NULL))
		return -EOPNOTSUPP;

	rc = efx_ef10_vport_alloc(efx, EVB_PORT_ID_ASSIGNED,
				  MC_CMD_VPORT_ALLOC_IN_VPORT_TYPE_NORMAL,
				  vf->vlan, &vf->vport_id);
	if (rc)
		return rc;

	rc = efx_ef10_vport_add_mac(efx, vf->vport_id, vf->mac);
	if (rc) {
		eth_zero_addr(vf->mac);
		return rc;
	}

	rc = efx_ef10_evb_port_assign(efx, vf->vport_id, vf_i);
	if (rc)
		return rc;

	vf->vport_assigned = 1;
	return 0;
}

static int efx_ef10_sriov_alloc_vf_vswitching(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int i;
	int rc;

	nic_data->vf = kcalloc(efx->vf_count, sizeof(struct ef10_vf),
			       GFP_KERNEL);
	if (!nic_data->vf)
		return -ENOMEM;

	for (i = 0; i < efx->vf_count; i++) {
		random_ether_addr(nic_data->vf[i].mac);
		nic_data->vf[i].efx = NULL;
		nic_data->vf[i].vlan = EFX_EF10_NO_VLAN;

		rc = efx_ef10_sriov_assign_vf_vport(efx, i);
		if (rc)
			goto fail;
	}

	return 0;
fail:
	efx_ef10_sriov_free_vf_vports(efx);
	kfree(nic_data->vf);
	nic_data->vf = NULL;
	return rc;
}

static int efx_ef10_sriov_restore_vf_vswitching(struct efx_nic *efx)
{
	unsigned int i;
	int rc;

	for (i = 0; i < efx->vf_count; i++) {
		rc = efx_ef10_sriov_assign_vf_vport(efx, i);
		if (rc)
			goto fail;
	}

	return 0;
fail:
	efx_ef10_sriov_free_vf_vswitching(efx);
	return rc;
}
#endif

/* On top of the default firmware vswitch setup, create a VEB vswitch and
 * expansion vport for use by this function.
 */
int efx_ef10_vswitching_probe_pf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct net_device *net_dev = efx->net_dev;
	int rc;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SRIOV_GET_TOTALVFS)
	if (pci_sriov_get_totalvfs(efx->pci_dev) <= 0 && !enable_vswitch) {
#else
	if (efx->max_vfs <= 0 && !enable_vswitch) {
#endif
		/* vswitch not needed as we have no VFs */
		efx_ef10_vadaptor_alloc(efx, nic_data->vport_id);
		return 0;
	}

	rc = efx_ef10_vswitch_alloc(efx, EVB_PORT_ID_ASSIGNED,
				    MC_CMD_VSWITCH_ALLOC_IN_VSWITCH_TYPE_VEB);
	if (rc)
		goto fail1;

	rc = efx_ef10_vport_alloc(efx, EVB_PORT_ID_ASSIGNED,
				  MC_CMD_VPORT_ALLOC_IN_VPORT_TYPE_NORMAL,
				  EFX_EF10_NO_VLAN, &nic_data->vport_id);
	if (rc)
		goto fail2;
	efx->ef10_resources.vport_id = nic_data->vport_id;

	rc = efx_ef10_vport_add_mac(efx, nic_data->vport_id, net_dev->dev_addr);
	if (rc)
		goto fail3;
	ether_addr_copy(nic_data->vport_mac, net_dev->dev_addr);

	rc = efx_ef10_vadaptor_alloc(efx, nic_data->vport_id);
	if (rc)
		goto fail4;

	return 0;
fail4:
	efx_ef10_vport_del_mac(efx, nic_data->vport_id, nic_data->vport_mac);
	eth_zero_addr(nic_data->vport_mac);
fail3:
	efx_ef10_vport_free(efx, nic_data->vport_id);
	nic_data->vport_id = EVB_PORT_ID_ASSIGNED;
fail2:
	efx_ef10_vswitch_free(efx, EVB_PORT_ID_ASSIGNED);
fail1:
	return rc;
#else
	return 0;
#endif
}

int efx_ef10_vswitching_probe_vf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	return efx_ef10_vadaptor_alloc(efx, nic_data->vport_id);
#else
	return 0;
#endif
}

int efx_ef10_vswitching_restore_pf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int rc;

	if (!nic_data->must_probe_vswitching)
		return 0;

	rc = efx_ef10_vswitching_probe_pf(efx);
	if (rc)
		goto fail;

	rc = efx_ef10_sriov_restore_vf_vswitching(efx);
	if (rc)
		goto fail;

	nic_data->must_probe_vswitching = false;
fail:
	return rc;
#else
	return 0;
#endif
}

int efx_ef10_vswitching_restore_vf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int rc;

	if (!nic_data->must_probe_vswitching)
		return 0;

	rc = efx_ef10_vadaptor_free(efx, EVB_PORT_ID_ASSIGNED);
	if (rc)
		return rc;

	nic_data->must_probe_vswitching = false;
#endif
	return 0;
}

void efx_ef10_vswitching_remove_pf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	efx_ef10_sriov_free_vf_vswitching(efx);

	efx_ef10_vadaptor_free(efx, nic_data->vport_id);

	if (nic_data->vport_id == EVB_PORT_ID_ASSIGNED)
		return; /* No vswitch was ever created */

	if (!is_zero_ether_addr(nic_data->vport_mac)) {
		efx_ef10_vport_del_mac(efx, nic_data->vport_id,
				       efx->net_dev->dev_addr);
		eth_zero_addr(nic_data->vport_mac);
	}

	efx_ef10_vport_free(efx, nic_data->vport_id);
	nic_data->vport_id = EVB_PORT_ID_ASSIGNED;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	/* Only free the vswitch if no VFs are assigned */
	if (!pci_vfs_assigned(efx->pci_dev))
#endif
		efx_ef10_vswitch_free(efx, nic_data->vport_id);
#endif
}

void efx_ef10_vswitching_remove_vf(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	efx_ef10_vadaptor_free(efx, EVB_PORT_ID_ASSIGNED);
#endif
}


#ifdef CONFIG_SFC_SRIOV
static int efx_ef10_pci_sriov_enable(struct efx_nic *efx, int num_vfs)
{
	struct pci_dev *dev = efx->pci_dev;
	int rc;

	efx->vf_count = num_vfs;

	rc = efx_ef10_sriov_alloc_vf_vswitching(efx);
	if (rc)
		goto fail1;

	rc = pci_enable_sriov(dev, num_vfs);

	if (rc)
		goto fail2;

	return 0;

fail2:
	efx_ef10_sriov_free_vf_vswitching(efx);
fail1:
	efx->vf_count = 0;
	netif_err(efx, probe, efx->net_dev, "Failed to enable SRIOV VFs\n");
	return rc;
}

static int efx_ef10_pci_sriov_disable(struct efx_nic *efx, bool force)
{
	struct pci_dev *dev = efx->pci_dev;
	unsigned int vfs_assigned = 0;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	vfs_assigned = pci_vfs_assigned(dev);

	if (vfs_assigned && !force) {
		netif_info(efx, drv, efx->net_dev, "VFs are assigned to guests; "
			   "please detach them before disabling SR-IOV\n");
		return -EBUSY;
	}
#endif

	if (!vfs_assigned)
		pci_disable_sriov(dev);

	efx_ef10_sriov_free_vf_vswitching(efx);
	efx->vf_count = 0;
	return 0;
}
#endif

int efx_ef10_sriov_configure(struct efx_nic *efx, int num_vfs)
{
#ifdef CONFIG_SFC_SRIOV
	if (num_vfs == 0)
		return efx_ef10_pci_sriov_disable(efx, false);
	else
		return efx_ef10_pci_sriov_enable(efx, num_vfs);
#else
	return -EOPNOTSUPP;
#endif
}

#ifdef CONFIG_SFC_SRIOV
static int efx_ef10_sriov_vf_max(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_SRIOV_CFG_OUT_LEN);
	size_t outlen;
	int rc;
	int vf_max;

	BUILD_BUG_ON(MC_CMD_GET_SRIOV_CFG_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_SRIOV_CFG, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		vf_max = 0;
	else
		vf_max = MCDI_DWORD(outbuf, GET_SRIOV_CFG_OUT_VF_MAX);

	return vf_max;
}
#endif

int efx_ef10_sriov_init(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	int vf_max = efx_ef10_sriov_vf_max(efx);
	int vf_count;
	int rc;

	vf_count = min(vf_max, efx->max_vfs);

	if (vf_count > 0) {
		rc = efx->type->sriov_configure(efx, vf_count);
		if (rc)
			return rc;
	}

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

void efx_ef10_sriov_fini(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int i;
	int rc;

	if (!nic_data->vf) {
		/* Remove any un-assigned orphaned VFs */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
		if (pci_num_vf(efx->pci_dev) && !pci_vfs_assigned(efx->pci_dev))
#endif
			pci_disable_sriov(efx->pci_dev);
		return;
	}

	/* Remove any VFs in the host */
	for (i = 0; i < efx->vf_count; ++i) {
		struct efx_nic *vf_efx = nic_data->vf[i].efx;

		if (vf_efx) {
			efx_device_detach_sync(vf_efx);
			rtnl_lock();
			efx_net_stop(vf_efx->net_dev);
			rtnl_unlock();
			down_write(&vf_efx->filter_sem);
			vf_efx->type->filter_table_remove(vf_efx);
			up_write(&vf_efx->filter_sem);
			efx_ef10_vadaptor_free(vf_efx, EVB_PORT_ID_ASSIGNED);
			vf_efx->pci_dev->driver->remove(vf_efx->pci_dev);
		}
	}

	rc = efx_ef10_pci_sriov_disable(efx, true);
	if (rc)
		netif_dbg(efx, drv, efx->net_dev, "Disabling SRIOV was not successful rc=%d\n", rc);
	else
		netif_dbg(efx, drv, efx->net_dev, "SRIOV disabled\n");
#endif
}

#ifdef CONFIG_SFC_SRIOV

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_ef10_sriov_get_vf_config(struct efx_nic *efx, int vf_i,
				 struct ifla_vf_info *ivf)
{
#ifdef EFX_HAVE_VF_LINK_STATE
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LINK_STATE_MODE_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_LINK_STATE_MODE_OUT_LEN);
#endif
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct ef10_vf *vf;
#ifdef EFX_HAVE_VF_LINK_STATE
	size_t outlen;
	int rc;
#endif

	if (vf_i >= efx->vf_count)
		return -EINVAL;

	if (nic_data->vf == NULL)
		return -EOPNOTSUPP;

	vf = nic_data->vf + vf_i;

	ivf->vf = vf_i;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_INFO_MIN_TX_RATE)
	ivf->min_tx_rate = 0;
	ivf->max_tx_rate = 0;
#else
	ivf->tx_rate = 0;
#endif
	ether_addr_copy(ivf->mac, vf->mac);
	ivf->vlan = (vf->vlan == EFX_EF10_NO_VLAN) ? 0 : vf->vlan;
	ivf->qos = 0;

#ifdef EFX_HAVE_VF_LINK_STATE
	MCDI_POPULATE_DWORD_2(inbuf, LINK_STATE_MODE_IN_FUNCTION,
			      LINK_STATE_MODE_IN_FUNCTION_PF, nic_data->pf_index,
			      LINK_STATE_MODE_IN_FUNCTION_VF, vf_i);
	MCDI_SET_DWORD(inbuf, LINK_STATE_MODE_IN_NEW_MODE,
		       MC_CMD_LINK_STATE_MODE_IN_DO_NOT_CHANGE);
	rc = efx_mcdi_rpc(efx, MC_CMD_LINK_STATE_MODE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_LINK_STATE_MODE_OUT_LEN)
		return -EIO;
	ivf->linkstate = MCDI_DWORD(outbuf, LINK_STATE_MODE_OUT_OLD_MODE);
#endif

	return 0;
}
#endif

static int efx_ef10_vport_del_vf_mac(struct efx_nic *efx, unsigned int port_id,
				     u8 *mac)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_DEL_MAC_ADDRESS_IN_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, VPORT_DEL_MAC_ADDRESS_IN_VPORT_ID, port_id);
	ether_addr_copy(MCDI_PTR(inbuf, VPORT_DEL_MAC_ADDRESS_IN_MACADDR), mac);

	rc = efx_mcdi_rpc(efx, MC_CMD_VPORT_DEL_MAC_ADDRESS, inbuf,
				sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);

	return rc;
}

int efx_ef10_sriov_set_vf_mac(struct efx_nic *efx, int vf_i, u8 *mac)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct ef10_vf *vf;
	int rc;

	if (nic_data->vf == NULL)
		return -EOPNOTSUPP;

	if (vf_i >= efx->vf_count)
		return -EINVAL;
	vf = nic_data->vf + vf_i;

	if (vf->efx) {
		efx_device_detach_sync(vf->efx);
		efx_net_stop(vf->efx->net_dev);

		down_write(&vf->efx->filter_sem);
		vf->efx->type->filter_table_remove(vf->efx);

		rc = efx_ef10_vadaptor_free(vf->efx, EVB_PORT_ID_ASSIGNED);
		if (rc) {
			up_write(&vf->efx->filter_sem);
			return rc;
		}
	}

	rc = efx_ef10_evb_port_assign(efx, EVB_PORT_ID_NULL, vf_i);
	if (rc)
		return rc;

	if (!is_zero_ether_addr(vf->mac)) {
		rc = efx_ef10_vport_del_vf_mac(efx, vf->vport_id, vf->mac);
		if (rc)
			return rc;
	}

	if (!is_zero_ether_addr(mac)) {
		rc = efx_ef10_vport_add_mac(efx, vf->vport_id, mac);
		if (rc) {
			eth_zero_addr(vf->mac);
			goto fail;
		}
		if (vf->efx)
			ether_addr_copy(vf->efx->net_dev->dev_addr, mac);
	}
	ether_addr_copy(vf->mac, mac);

	rc = efx_ef10_evb_port_assign(efx, vf->vport_id, vf_i);
	if (rc)
		goto fail;

	if (vf->efx) {
		/* VF cannot use the vport_id that the PF created */
		rc = efx_ef10_vadaptor_alloc(vf->efx, EVB_PORT_ID_ASSIGNED);
		if (rc) {
			up_write(&vf->efx->filter_sem);
			return rc;
		}
		vf->efx->type->filter_table_probe(vf->efx);
		up_write(&vf->efx->filter_sem);
		efx_net_open(vf->efx->net_dev);
		netif_device_attach(vf->efx->net_dev);
	}

	return 0;

fail:
	memset(vf->mac, 0, ETH_ALEN);
	return rc;
}

int efx_ef10_sriov_set_vf_vlan(struct efx_nic *efx, int vf_i, u16 vlan,
			       u8 qos)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct ef10_vf *vf;
	u16 old_vlan, new_vlan;
	int rc = 0, rc2 = 0;

	if (vf_i >= efx->vf_count)
		return -EINVAL;
	if (qos != 0)
		return -EINVAL;

	vf = nic_data->vf + vf_i;

	new_vlan = (vlan == 0) ? EFX_EF10_NO_VLAN : vlan;
	if (new_vlan == vf->vlan)
		return 0;

	if (vf->efx) {
		efx_device_detach_sync(vf->efx);
		efx_net_stop(vf->efx->net_dev);

		down_write(&vf->efx->filter_sem);
		vf->efx->type->filter_table_remove(vf->efx);

		rc = efx_ef10_vadaptor_free(vf->efx, EVB_PORT_ID_ASSIGNED);
		if (rc)
			goto restore_filters;
	}

	if (vf->vport_assigned) {
		rc = efx_ef10_evb_port_assign(efx, EVB_PORT_ID_NULL, vf_i);
		if (rc) {
			netif_warn(efx, drv, efx->net_dev,
				   "Failed to change vlan on VF %d.\n", vf_i);
			netif_warn(efx, drv, efx->net_dev,
				   "This is likely because the VF is bound to a driver in a VM.\n");
			netif_warn(efx, drv, efx->net_dev,
				   "Please unload the driver in the VM.\n");
			goto restore_vadaptor;
		}
		vf->vport_assigned = 0;
	}

	if (!is_zero_ether_addr(vf->mac)) {
		rc = efx_ef10_vport_del_mac(efx, vf->vport_id, vf->mac);
		if (rc)
			goto restore_evb_port;
	}

	if (vf->vport_id) {
		rc = efx_ef10_vport_free(efx, vf->vport_id);
		if (rc)
			goto restore_mac;
		vf->vport_id = 0;
	}

	/* Do the actual vlan change */
	old_vlan = vf->vlan;
	vf->vlan = new_vlan;

	/* Restore everything in reverse order */
	rc = efx_ef10_vport_alloc(efx, EVB_PORT_ID_ASSIGNED,
			MC_CMD_VPORT_ALLOC_IN_VPORT_TYPE_NORMAL,
			vf->vlan, &vf->vport_id);
	if (rc)
		goto reset_nic;

restore_mac:
	if (!is_zero_ether_addr(vf->mac)) {
		rc2 = efx_ef10_vport_add_mac(efx, vf->vport_id, vf->mac);
		if (rc2) {
			eth_zero_addr(vf->mac);
			goto reset_nic;
		}
	}

restore_evb_port:
	rc2 = efx_ef10_evb_port_assign(efx, vf->vport_id, vf_i);
	if (rc2)
		goto reset_nic;
	else
		vf->vport_assigned = 1;

restore_vadaptor:
	if (vf->efx) {
		rc2 = efx_ef10_vadaptor_alloc(vf->efx, EVB_PORT_ID_ASSIGNED);
		if (rc2)
			goto reset_nic;
	}

restore_filters:
	if (vf->efx) {
		rc2 = vf->efx->type->filter_table_probe(vf->efx);
		if (rc2)
			goto reset_nic;

		rc2 = efx_net_open(vf->efx->net_dev);
		if (rc2)
			goto reset_nic;

		up_write(&vf->efx->filter_sem);

		netif_device_attach(vf->efx->net_dev);
	}

	return rc;

reset_nic:
	if (vf->efx) {
		up_write(&vf->efx->filter_sem);

		netif_err(efx, drv, efx->net_dev,
			  "Failed to restore the VF - scheduling reset.\n");

		efx_schedule_reset(vf->efx, RESET_TYPE_DATAPATH);
	} else {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to restore the VF and cannot reset the VF "
			  "- VF is not functional.\n");
		netif_err(efx, drv, efx->net_dev,
			  "Please reload the driver attached to the VF.\n");
	}

	return rc ? rc : rc2;
}

int efx_ef10_sriov_set_vf_spoofchk(struct efx_nic *efx, int vf_i,
				   bool spoofchk)
{
	return spoofchk ? -EOPNOTSUPP : 0;
}

#ifdef EFX_HAVE_VF_LINK_STATE
int efx_ef10_sriov_set_vf_link_state(struct efx_nic *efx, int vf_i,
				     int link_state)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LINK_STATE_MODE_IN_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	BUILD_BUG_ON(IFLA_VF_LINK_STATE_AUTO != MC_CMD_LINK_STATE_MODE_IN_LINK_STATE_AUTO);
	BUILD_BUG_ON(IFLA_VF_LINK_STATE_ENABLE != MC_CMD_LINK_STATE_MODE_IN_LINK_STATE_UP);
	BUILD_BUG_ON(IFLA_VF_LINK_STATE_DISABLE != MC_CMD_LINK_STATE_MODE_IN_LINK_STATE_DOWN);
	MCDI_POPULATE_DWORD_2(inbuf, LINK_STATE_MODE_IN_FUNCTION,
			      LINK_STATE_MODE_IN_FUNCTION_PF, nic_data->pf_index,
			      LINK_STATE_MODE_IN_FUNCTION_VF, vf_i);
	MCDI_SET_DWORD(inbuf, LINK_STATE_MODE_IN_NEW_MODE, link_state);
	return efx_mcdi_rpc(efx, MC_CMD_LINK_STATE_MODE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL); /* don't care what old mode was */
}
#endif /* EFX_HAVE_VF_LINK_STATE */

#else /* CONFIG_SFC_SRIOV */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
int efx_ef10_sriov_get_vf_config(struct efx_nic *efx, int vf_i,
				 struct ifla_vf_info *ivf)
{
	return -EOPNOTSUPP;
}
#endif

int efx_ef10_sriov_set_vf_mac(struct efx_nic *efx, int vf_i, u8 *mac)
{
	return -EOPNOTSUPP;
}

int efx_ef10_sriov_set_vf_vlan(struct efx_nic *efx, int vf_i, u16 vlan,
			       u8 qos)
{
	return -EOPNOTSUPP;
}

int efx_ef10_sriov_set_vf_spoofchk(struct efx_nic *efx, int vf_i,
				   bool spoofchk)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_SRC_SRIOV */

bool efx_ef10_sriov_wanted(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	return efx->max_vfs != 0 && efx_ef10_sriov_vf_max(efx) > 0;
#else
	return false;
#endif
}

void efx_ef10_sriov_flr(struct efx_nic *efx, unsigned vf_i) {}
