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
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2005-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Initially developed by Michael Brown <mbrown@fensystems.co.uk>
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
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
#define EFX_DRIVER_NAME "sfc_control"
#include "net_driver.h"
#include "efx.h"
#include "efx_ioctl.h"
#include "nic.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "aoe.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/fs.h>
#include <linux/compat.h>

/* Major device number */
static int major;
module_param(major, int, 0444);
MODULE_PARM_DESC(major, "char device major number to use");

static void efx_ioctl_mcdi_complete_reset(struct efx_nic *efx,
					  unsigned int cmd, int rc)
{
	/* efx_mcdi_rpc() will not schedule a reset if MC_CMD_REBOOT causes
	 * a reboot. But from the user's POV, they're triggering a reboot
	 * 'externally', and want both ports to recover. So schedule the
	 * reset here.
	 */
	if (cmd == MC_CMD_REBOOT && rc == -EIO) {
		netif_warn(efx, drv, efx->net_dev, "Expected MC rebooted\n");
		efx_schedule_reset(efx, RESET_TYPE_MC_FAILURE);
	}
}

static int efx_ioctl_do_mcdi_old(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_mcdi_request *req = &data->mcdi_request;
	size_t outlen;
	int rc;

	if (req->len > sizeof(req->payload)) {
		netif_err(efx, drv, efx->net_dev, "inlen is too long");
		return -EINVAL;
	}

	if (efx_nic_rev(efx) < EFX_REV_SIENA_A0) {
		netif_err(efx, drv, efx->net_dev,
			  "error: NIC has no MC for MCDI\n");
		return -ENOTSUPP;
	}

	rc = efx_mcdi_rpc_quiet(efx, req->cmd,
				(const efx_dword_t *)req->payload,
				req->len, (efx_dword_t *)req->payload,
				sizeof(req->payload), &outlen);
	efx_ioctl_mcdi_complete_reset(efx, req->cmd, rc);

	req->rc = -rc;
	req->len = (__u8)outlen;
	return 0;
}

static int efx_ioctl_do_mcdi(struct efx_nic *efx,
			     struct efx_mcdi_request2 __user *user_req)
{
	struct efx_mcdi_request2 req;
	size_t outlen_actual;
	efx_dword_t *buf;
	size_t buf_len;
	int rc;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	/* No input flags are defined yet */
	if (req.flags != 0)
		return -EINVAL;

	/* efx_mcdi_rpc() will check the length anyway, but this avoids
	 * trying to allocate an extreme amount of memory.
	 */
	if (req.inlen > MCDI_CTL_SDU_LEN_MAX_V2 ||
	    req.outlen > MCDI_CTL_SDU_LEN_MAX_V2)
		return -EINVAL;

	buf_len = ALIGN(max(req.inlen, req.outlen), 4);
	buf = kmalloc(buf_len, GFP_USER);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, &user_req->payload, req.inlen)) {
		rc = -EFAULT;
		goto out_free;
	}

	rc = efx_mcdi_rpc_quiet(efx, req.cmd, buf, req.inlen,
				buf, req.outlen, &outlen_actual);
	efx_ioctl_mcdi_complete_reset(efx, req.cmd, rc);

	if (rc) {
		if (outlen_actual) {
			/* Error was reported by the MC */
			req.flags |= EFX_MCDI_REQUEST_ERROR;
			req.host_errno = -rc;
			rc = 0;
		} else {
			/* Communication failure */
			goto out_free;
		}
	}
	req.outlen = outlen_actual;

	if (copy_to_user(user_req, &req, sizeof(req)) ||
	    copy_to_user(&user_req->payload, buf, outlen_actual))
		rc = -EFAULT;

out_free:
	kfree(buf);
	return rc;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RESET)

static int
efx_ioctl_reset_flags(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ethtool_reset(efx->net_dev, &data->reset_flags.flags);
}

#endif

#ifdef EFX_USE_KCOMPAT

#ifdef CONFIG_COMPAT
/* struct ethtool_rxnfc has extra padding on 64-bit architectures.
 * And we have to follow this stupidity in order to use the same
 * underlying implementation for both SIOCEFX and SIOCETHTOOL
 * operations.
 */
struct efx_compat_ethtool_rx_flow_spec {
	u32		flow_type;
	union efx_ethtool_flow_union h_u;
	struct efx_ethtool_flow_ext h_ext;
	union efx_ethtool_flow_union m_u;
	struct efx_ethtool_flow_ext m_ext;
	compat_u64	ring_cookie;
	u32		location;
};
struct efx_compat_ethtool_rxnfc {
	u32				cmd;
	u32				flow_type;
	compat_u64			data;
	struct efx_compat_ethtool_rx_flow_spec fs;
	u32				rule_cnt;
	u32				rule_locs[0];
};
#endif

static int efx_ioctl_rxnfc(struct efx_nic *efx, void __user *useraddr)
{
#ifdef CONFIG_COMPAT
	struct efx_compat_ethtool_rxnfc __user *compat_rxnfc = useraddr;
#endif
	struct efx_ethtool_rxnfc info;
	int ret;
	void *rule_buf = NULL;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		if (copy_from_user(&info, compat_rxnfc,
				   (void *)(&info.fs.m_ext + 1) -
				   (void *)&info) ||
		    copy_from_user(&info.fs.ring_cookie,
				   &compat_rxnfc->fs.ring_cookie,
				   (void *)(&info.fs.location + 1) -
				   (void *)&info.fs.ring_cookie) ||
		    copy_from_user(&info.rule_cnt, &compat_rxnfc->rule_cnt,
				   sizeof(info.rule_cnt)))
			return -EFAULT;
	} else
#endif
	if (copy_from_user(&info, useraddr, sizeof(info)))
		return -EFAULT;

	switch (info.cmd) {
	case ETHTOOL_GRXCLSRLALL:
		if (info.rule_cnt > 0) {
			/* No more than 1 MB of rule indices - way
			 * more than we could possibly have! */
			if (info.rule_cnt <= (1 << 18))
				rule_buf = kzalloc(info.rule_cnt * sizeof(u32),
						   GFP_USER);
			if (!rule_buf)
				return -ENOMEM;
		}
		/* fall through */
	case ETHTOOL_GRXFH:
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
		ret = efx_ethtool_get_rxnfc(efx->net_dev, &info, rule_buf);
		break;
	case ETHTOOL_SRXCLSRLINS:
	case ETHTOOL_SRXCLSRLDEL:
		ret = efx_ethtool_set_rxnfc(efx->net_dev, &info);
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ret < 0)
		goto err_out;

	ret = -EFAULT;
#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		if (copy_to_user(compat_rxnfc, &info,
				 (const void *)(&info.fs.m_ext + 1) -
				 (const void *)&info) ||
		    copy_to_user(&compat_rxnfc->fs.ring_cookie,
				 &info.fs.ring_cookie,
				 (const void *)(&info.fs.location + 1) -
				 (const void *)&info.fs.ring_cookie) ||
		    copy_to_user(&compat_rxnfc->rule_cnt, &info.rule_cnt,
				 sizeof(info.rule_cnt)))
			goto err_out;
	} else
#endif
	if (copy_to_user(useraddr, &info, sizeof(info)))
		goto err_out;

	if (rule_buf) {
#ifdef CONFIG_COMPAT
		if (is_compat_task())
			useraddr += offsetof(struct efx_compat_ethtool_rxnfc,
					     rule_locs);
		else
#endif
			useraddr += offsetof(struct efx_ethtool_rxnfc,
					     rule_locs);
		if (copy_to_user(useraddr, rule_buf,
				 info.rule_cnt * sizeof(u32)))
			goto err_out;
	}
	ret = 0;

err_out:
	kfree(rule_buf);

	return ret;
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)

static int
efx_ioctl_rxfh_indir(struct efx_nic *efx, union efx_ioctl_data *data)
{
	BUILD_BUG_ON(ARRAY_SIZE(data->rxfh_indir.table) !=
		     ARRAY_SIZE(efx->rx_indir_table));

	switch (data->rxfh_indir.head.cmd) {
	case ETHTOOL_GRXFHINDIR:
		return efx_ethtool_old_get_rxfh_indir(efx->net_dev,
						      &data->rxfh_indir.head);
	case ETHTOOL_SRXFHINDIR:
		return efx_ethtool_old_set_rxfh_indir(efx->net_dev,
						      &data->rxfh_indir.head);
	default:
		return -EOPNOTSUPP;
	}
}

#endif

#ifdef CONFIG_SFC_PTP

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
static int
efx_ioctl_ts_init(struct efx_nic *efx, union efx_ioctl_data *data)
{
	/* bug 33070: We use a bit in the flags field to indicate that
	 * the application wants to use PTPV2 enhanced UUID
	 * filtering. Old application code has this bit set to
	 * zero. Note that this has no effect if a V1 mode is
	 * specified.
	 */
	if (data->ts_init.rx_filter >= HWTSTAMP_FILTER_PTP_V2_L4_EVENT &&
	    !(data->ts_init.flags & EFX_TS_INIT_FLAGS_PTP_V2_ENHANCED)) {
		netif_err(efx, drv, efx->net_dev,
			  "PTPv2 now requires at least sfptpd 2.0.0.5\n");
		return -EINVAL;
	}

	data->ts_init.flags &= ~EFX_TS_INIT_FLAGS_PTP_V2_ENHANCED;
	return efx_ptp_ts_init(efx, &data->ts_init);
}

static int
efx_ioctl_ts_read(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_read(efx, &data->ts_read);
}

#endif

#ifdef EFX_NOT_UPSTREAM

static int
efx_ioctl_get_ts_config(struct efx_nic *efx, union efx_ioctl_data *data)
{
	mm_segment_t old_fs;
	struct ifreq ifr;
	int rc;

	ifr.ifr_data = &data->ts_init;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = efx_ptp_get_ts_config(efx, &ifr);
	set_fs(old_fs);
	return rc;
}

static int
efx_ioctl_ts_settime(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_settime(efx, &data->ts_settime);
}

static int
efx_ioctl_ts_adjtime(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_adjtime(efx, &data->ts_adjtime);
}

static int
efx_ioctl_ts_sync(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_sync(efx, &data->ts_sync);
}

static int
efx_ioctl_ts_set_sync_status(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_sync_status(efx, &data->ts_set_sync_status);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
static int
efx_ioctl_get_ts_info(struct efx_nic *efx, union efx_ioctl_data *data)
{
	memset(&data->ts_info, 0, sizeof(data->ts_info));
	data->ts_info.cmd = ETHTOOL_GET_TS_INFO;
	return efx_ethtool_get_ts_info(efx->net_dev, &data->ts_info);
}
#endif

static int
efx_ioctl_ts_set_vlan_filter(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_vlan_filter(efx, &data->ts_vlan_filter);
}

static int
efx_ioctl_ts_set_uuid_filter(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_uuid_filter(efx, &data->ts_uuid_filter);
}

static int
efx_ioctl_ts_set_domain_filter(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_ts_set_domain_filter(efx, &data->ts_domain_filter);
}
#endif

#endif

#ifdef CONFIG_SFC_PPS
static int
efx_ioctl_get_pps_event(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_pps_get_event(efx, &data->pps_event);
}

static int
efx_ioctl_hw_pps_enable(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ptp_hw_pps_enable(efx, &data->pps_enable);
}
#endif

#ifdef CONFIG_SFC_AOE
static int
efx_ioctl_update_cpld(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_aoe_update_cpld(efx, &data->cpld);
}

static int
efx_ioctl_update_license_old(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_aoe_update_keys(efx, &data->key_stats);
}

static int
efx_ioctl_reset_aoe(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_aoe_reset_aoe(efx, &data->aoe_reset);
}
#endif


static int
efx_ioctl_get_mod_eeprom(struct efx_nic *efx,
			 union efx_ioctl_data __user *useraddr)
{
	struct ethtool_eeprom eeprom;
	struct ethtool_modinfo modinfo;
	void __user *userbuf =
		((void __user *)&useraddr->eeprom.ee) + sizeof(eeprom);
	void __user *userbufptr = userbuf;
	u32 bytes_remaining;
	u32 total_len;
	u8 *data;
	int ret = 0;

	if (efx_ethtool_get_module_info(efx->net_dev, &modinfo))
		return -EINVAL;

	total_len = modinfo.eeprom_len;

	if (copy_from_user(&eeprom, &useraddr->eeprom.ee, sizeof(eeprom)))
		return -EFAULT;

	/* Check for wrap and zero */
	if (eeprom.offset + eeprom.len <= eeprom.offset)
		return -EINVAL;

	/* Check for exceeding total eeprom len */
	if (eeprom.offset + eeprom.len > total_len)
		return -EINVAL;

	data = kmalloc(PAGE_SIZE, GFP_USER);
	if (!data)
		return -ENOMEM;

	bytes_remaining = eeprom.len;
	while (bytes_remaining > 0) {
		eeprom.len = min(bytes_remaining, (u32)PAGE_SIZE);

		ret = efx_ethtool_get_module_eeprom(efx->net_dev, &eeprom, data);
		if (ret)
			break;
		if (copy_to_user(userbuf, data, eeprom.len)) {
			ret = -EFAULT;
			break;
		}
		userbuf += eeprom.len;
		eeprom.offset += eeprom.len;
		bytes_remaining -= eeprom.len;
	}

	eeprom.len = userbuf - userbufptr;
	eeprom.offset -= eeprom.len;
	if (copy_to_user(&useraddr->eeprom.ee, &eeprom, sizeof(eeprom)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int
efx_ioctl_get_mod_info(struct efx_nic *efx, union efx_ioctl_data *data)
{
	return efx_ethtool_get_module_info(efx->net_dev, &data->modinfo.info);
}

static int
efx_ioctl_get_device_ids(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_device_ids *ids = &data->device_ids;

	ids->vendor_id = efx->pci_dev->vendor;
	ids->device_id = efx->pci_dev->device;
	ids->subsys_vendor_id = efx->pci_dev->subsystem_vendor;
	ids->subsys_device_id = efx->pci_dev->subsystem_device;
	ids->phy_type = efx->phy_type;
	ids->port_num = efx_port_num(efx);
	/* ids->perm_addr isn't __aligned(2), so we can't use ether_addr_copy
	 * (and we can't change it because it's an ioctl argument)
	 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
	memcpy(ids->perm_addr, efx->net_dev->perm_addr, ETH_ALEN);
#else
	memcpy(ids->perm_addr, efx->perm_addr, ETH_ALEN);
#endif
	return 0;
}

static int
efx_ioctl_update_license(struct efx_nic *efx, union efx_ioctl_data *data)
{
	struct efx_update_license2 *stats = &data->key_stats2;
	int rc;

	if (efx_nic_rev(efx) >= EFX_REV_HUNT_A0) {
		rc = efx_ef10_update_keys(efx, stats);
		if (rc)
			return rc;
	} else {
		memset(stats, 0, sizeof(*stats));
	}

#ifdef CONFIG_SFC_AOE
	if (efx->aoe_data) {
		struct efx_update_license aoe_stats;

		rc = efx_aoe_update_keys(efx, &aoe_stats);
		if (rc)
			return rc;

		stats->valid_keys += aoe_stats.valid_keys;
		stats->invalid_keys += aoe_stats.invalid_keys;
		stats->blacklisted_keys += aoe_stats.blacklisted_keys;
	}
#endif

	return 0;
}

static int
efx_ioctl_licensed_app_state(struct efx_nic *efx, union efx_ioctl_data *data)
{
	int rc;

	if (efx_nic_rev(efx) < EFX_REV_HUNT_A0)
		return -EOPNOTSUPP;
	rc = efx_ef10_licensed_app_state(efx, &data->app_state);
	return rc;
}

/*****************************************************************************/

int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
		      union efx_ioctl_data __user *user_data)
{
	int (*op)(struct efx_nic *, union efx_ioctl_data *);
	union efx_ioctl_data data;
	size_t size;
	int rc;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case EFX_MCDI_REQUEST:
		size = sizeof(data.mcdi_request);
		op = efx_ioctl_do_mcdi_old;
		break;
	case EFX_MCDI_REQUEST2:
		/* This command has variable length */
		return efx_ioctl_do_mcdi(efx, &user_data->mcdi_request2);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RESET)
	case EFX_RESET_FLAGS:
		size = sizeof(data.reset_flags);
		op = efx_ioctl_reset_flags;
		break;
#endif
#ifdef EFX_USE_KCOMPAT
	case EFX_RXNFC:
		/* This command has variable length */
		return efx_ioctl_rxnfc(efx, &user_data->rxnfc);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
	case EFX_RXFHINDIR:
		size = sizeof(data.rxfh_indir);
		op = efx_ioctl_rxfh_indir;
		break;
#endif
#ifdef CONFIG_SFC_PTP
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	case EFX_TS_INIT:
		size = sizeof(data.ts_init);
		op = efx_ioctl_ts_init;
		break;
	case EFX_TS_READ:
		size = sizeof(data.ts_read);
		op = efx_ioctl_ts_read;
		break;
#endif
#if defined(EFX_NOT_UPSTREAM)
	case EFX_GET_TS_CONFIG:
		size = sizeof(data.ts_init);
		op = efx_ioctl_get_ts_config;
		break;
	case EFX_TS_SETTIME:
		size = sizeof(data.ts_settime);
		op = efx_ioctl_ts_settime;
		break;
	case EFX_TS_ADJTIME:
		size = sizeof(data.ts_adjtime);
		op = efx_ioctl_ts_adjtime;
		break;
	case EFX_TS_SYNC:
		size = sizeof(data.ts_sync);
		op = efx_ioctl_ts_sync;
		break;
	case EFX_TS_SET_SYNC_STATUS:
		size = sizeof(data.ts_set_sync_status);
		op = efx_ioctl_ts_set_sync_status;
		break;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
	case EFX_GET_TS_INFO:
		size = sizeof(data.ts_info);
		op = efx_ioctl_get_ts_info;
		break;
#endif
	case EFX_TS_SET_VLAN_FILTER:
		size = sizeof(data.ts_vlan_filter);
		op = efx_ioctl_ts_set_vlan_filter;
		break;
	case EFX_TS_SET_UUID_FILTER:
		size = sizeof(data.ts_uuid_filter);
		op = efx_ioctl_ts_set_uuid_filter;
		break;
	case EFX_TS_SET_DOMAIN_FILTER:
		size = sizeof(data.ts_domain_filter);
		op = efx_ioctl_ts_set_domain_filter;
		break;
#endif
#endif
#ifdef CONFIG_SFC_PPS
	case EFX_TS_GET_PPS:
		size = sizeof(data.pps_event);
		op = efx_ioctl_get_pps_event;
		break;
	case EFX_TS_ENABLE_HW_PPS:
		size = sizeof(data.pps_enable);
		op = efx_ioctl_hw_pps_enable;
		break;
#endif
#ifdef CONFIG_SFC_AOE
	case EFX_UPDATE_CPLD:
		size = sizeof(data.cpld);
		op = efx_ioctl_update_cpld;
		break;
	case EFX_LICENSE_UPDATE:
		size = sizeof(data.key_stats);
		op = efx_ioctl_update_license_old;
		break;
	case EFX_RESET_AOE:
		size = sizeof(data.aoe_reset);
		op = efx_ioctl_reset_aoe;
		break;
#endif
	case EFX_MODULEEEPROM:
		return efx_ioctl_get_mod_eeprom(efx, user_data);

	case EFX_GMODULEINFO:
		size = sizeof(data.modinfo);
		op = efx_ioctl_get_mod_info;
		break;
	case EFX_GET_DEVICE_IDS:
		size = sizeof(data.device_ids);
		op = efx_ioctl_get_device_ids;
		break;
	case EFX_LICENSE_UPDATE2:
		size = sizeof(data.key_stats2);
		op = efx_ioctl_update_license;
		break;
	case EFX_LICENSED_APP_STATE:
		size = sizeof(data.app_state);
		op = efx_ioctl_licensed_app_state;
		break;
	default:
		netif_err(efx, drv, efx->net_dev,
			  "unknown private ioctl cmd %x\n", cmd);
		return -EOPNOTSUPP;
	}

	if (copy_from_user(&data, user_data, size))
		return -EFAULT;
	rc = op(efx, &data);
	if (rc)
		return rc;
	if (copy_to_user(user_data, &data, size))
		return -EFAULT;
	return 0;
}

static long
control_ioctl(struct file *filp, unsigned int req, unsigned long arg)
{
	struct efx_nic *efx;
	char if_name[IFNAMSIZ];
	struct efx_ioctl __user *user_data = (struct efx_ioctl __user *)arg;
	u16 efx_cmd;
	int rc = 0;

	if (req != SIOCEFX && req != SIOCDEVPRIVATE)
		return -ENOTTY;

	if (copy_from_user(if_name, &user_data->if_name, sizeof(if_name)) ||
	    copy_from_user(&efx_cmd, &user_data->cmd, sizeof(efx_cmd)))
		return -EFAULT;

	/* Serialise ioctl access with efx_reset() by acquiring the rtnl_lock.
	 * This also maintains compatability with ioctls directly hung off
	 * the net_device */
	rtnl_lock();

	list_for_each_entry(efx, &efx_port_list, dl_node) {
		if (strncmp(efx->net_dev->name, if_name, sizeof(if_name)) != 0)
			continue;

		rc = efx_private_ioctl(efx, efx_cmd, &user_data->u);
		goto unlock;
	}

	/* Couldn't find the device */
	rc = -ENOSYS;

unlock:
	rtnl_unlock();
	return rc;
}

#ifndef HAVE_UNLOCKED_IOCTL
static int control_legacy_ioctl(struct inode *ino, struct file *filp,
				unsigned int req, unsigned long arg)
{
	return (int) control_ioctl(filp, req, arg);
}
#endif

static struct file_operations control_fops = {
	.owner = THIS_MODULE,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = control_ioctl,
#else
	.ioctl = control_legacy_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	.compat_ioctl = control_ioctl,
#endif
};

/*****************************************************************************/

int efx_control_init(void)
{
	int rc;

	if ((rc = register_chrdev(major, EFX_DRIVER_NAME, &control_fops))
	    < 0) {
		printk(KERN_ERR "Failed to register chrdev on %d (%d)\n", major, rc);
		return rc;
	}
	if (!major)
		major = rc;
	printk(KERN_INFO "Registered control device on %d\n", major);

	return 0;
}

void efx_control_fini(void)
{
	printk(KERN_INFO "Unregistering device %d from " EFX_DRIVER_NAME "\n", major);
	unregister_chrdev(major, EFX_DRIVER_NAME);
}
