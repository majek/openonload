/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
 * This file contains driverlink code which interacts with the sfc network
 * driver.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
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

#include "linux_resource_internal.h"
#include <driver/linux_net/driverlink_api.h>
#include "efrm_internal.h"
#include "kernel_compat.h"
#include <ci/efhw/falcon.h>

#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#  include <net/net_namespace.h>
#endif

/* The DL driver and associated calls */
static int efrm_dl_probe(struct efx_dl_device *efrm_dev,
			 const struct net_device *net_dev,
			 const struct efx_dl_device_info *dev_info,
			 const char *silicon_rev);

static void efrm_dl_remove(struct efx_dl_device *efrm_dev);

static void efrm_dl_reset_suspend(struct efx_dl_device *efrm_dev);

static void efrm_dl_reset_resume(struct efx_dl_device *efrm_dev, int ok);

static int efrm_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr);

static struct notifier_block efrm_netdev_notifier = {
	.notifier_call = efrm_netdev_event,
};

static void efrm_dl_event_falcon(struct efx_dl_device *efx_dev, void *p_event);

static struct efx_dl_driver efrm_dl_driver = {
	.name = "resource",
	.probe = efrm_dl_probe,
	.remove = efrm_dl_remove,
	.reset_suspend = efrm_dl_reset_suspend,
	.reset_resume = efrm_dl_reset_resume,
	.handle_event = efrm_dl_event_falcon,
};

static void
init_vi_resource_dimensions(struct vi_resource_dimensions *rd,
			    const struct efx_dl_falcon_resources *res,
			    struct efx_dl_siena_sriov *sriov_res)
{
	rd->evq_timer_min = res->evq_timer_min;
	rd->evq_timer_lim = res->evq_timer_lim;
	rd->evq_int_min = res->evq_int_min;
	rd->evq_int_lim = res->evq_int_lim;
	rd->rxq_min = res->rxq_min;
	rd->rxq_lim = res->rxq_lim;
	rd->txq_min = res->txq_min;
	rd->txq_lim = res->txq_lim;
	if (res->flags & EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT)
		rd->rss_channel_count = res->rss_channel_count;
	else
		rd->rss_channel_count = 1;
	if (sriov_res != NULL) {
		rd->vf_vi_base = sriov_res->vi_base;
		rd->vf_vi_scale = sriov_res->vi_scale;
		rd->vf_count = sriov_res->vf_count;
	}
	else
		rd->vf_count = rd->vf_vi_base = rd->vf_vi_scale = 0;
	EFRM_TRACE
	    ("Using evq_int(%d-%d) evq_timer(%d-%d) RXQ(%d-%d) TXQ(%d-%d)",
	     res->evq_int_min, res->evq_int_lim, res->evq_timer_min,
	     res->evq_timer_lim, res->rxq_min, res->rxq_lim, res->txq_min,
	     res->txq_lim);
}

static int
efrm_dl_probe(struct efx_dl_device *efrm_dev,
	      const struct net_device *net_dev,
	      const struct efx_dl_device_info *dev_info,
	      const char *silicon_rev)
{
	struct vi_resource_dimensions res_dim;
	struct efx_dl_falcon_resources *res;
	struct efx_dl_siena_sriov *sriov_res;
	struct linux_efhw_nic *lnic;
	struct pci_dev *dev;
	struct efhw_nic *nic;
	unsigned probe_flags = 0;
        unsigned timer_quantum_ns = 0;
	int non_irq_evq;
	int rc;

	efrm_dev->priv = NULL;

	efx_dl_search_device_info(dev_info, EFX_DL_FALCON_RESOURCES,
				  struct efx_dl_falcon_resources,
				  hdr, res);

	if (res == NULL) {
		EFRM_ERR("%s: Unable to find falcon driverlink resources",
			 __func__);
		return -EINVAL;
	}

	if (res->flags & EFX_DL_FALCON_DUAL_FUNC) {
		EFRM_ERR("%s: Falcon/A series is now unsupported",
			 __func__);
		return -EINVAL;
	}

	if (res->flags & EFX_DL_FALCON_ONLOAD_UNSUPPORTED)
		probe_flags |= NIC_FLAG_ONLOAD_UNSUPPORTED;

	if (res->flags & EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS) 
		timer_quantum_ns = res->timer_quantum_ns;

	efx_dl_search_device_info(dev_info, EFX_DL_SIENA_SRIOV,
				  struct efx_dl_siena_sriov,
				  hdr, sriov_res);

	dev = efrm_dev->pci_dev;
	init_vi_resource_dimensions(&res_dim, res, sriov_res);

	/* Use top-most EVQ for SRAM update events etc. */
	EFRM_ASSERT(res_dim.evq_timer_lim > res_dim.evq_timer_min);
	res_dim.evq_timer_lim--;
	non_irq_evq = res_dim.evq_timer_lim;

	rc = efrm_nic_add(dev, probe_flags, net_dev->dev_addr, &lnic,
			  res->biu_lock,
			  res->buffer_table_min, res->buffer_table_lim,
			  non_irq_evq, &res_dim, net_dev->ifindex,
                          timer_quantum_ns);
	if (rc != 0)
		return rc;

	nic = &lnic->efrm_nic.efhw_nic;
	nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
	efrm_dev->priv = nic;

	/* Keep a reference to the Driverlink context */
	lnic->dl_device = efrm_dev;

	return 0;
}

/* When we unregister ourselves on module removal, this function will be
 * called for all the devices we claimed */
static void efrm_dl_remove(struct efx_dl_device *efrm_dev)
{
	struct efhw_nic *nic = efrm_dev->priv;
	struct linux_efhw_nic *lnic = linux_efhw_nic(nic);
	EFRM_TRACE("%s called", __func__);
	if (efrm_dev->priv)
		efrm_nic_del(lnic);
	EFRM_TRACE("%s OK", __func__);
}

static void efrm_dl_reset_suspend(struct efx_dl_device *efrm_dev)
{
	struct efhw_nic *nic = efrm_dev->priv;

	EFRM_NOTICE("%s:", __func__);

	nic->resetting = 1;
}

static void efrm_dl_reset_resume(struct efx_dl_device *efrm_dev, int ok)
{
	struct efhw_nic *nic = efrm_dev->priv;

	EFRM_NOTICE("%s: ok=%d", __func__, ok);

        if( ok )
          nic->resetting = 0;
        
        efhw_nic_post_reset(nic);

	efrm_nic_post_reset(nic);
}

int efrm_driverlink_register(void)
{
	int rc;

	EFRM_TRACE("%s:", __func__);

	rc = efx_dl_register_driver(&efrm_dl_driver);
	if (rc)
		return rc;

	rc = register_netdevice_notifier(&efrm_netdev_notifier);
	if (rc) {
		efx_dl_unregister_driver(&efrm_dl_driver);
		return rc;
	}

	return 0;
}

void efrm_driverlink_unregister(void)
{
	EFRM_TRACE("%s:", __func__);

	unregister_netdevice_notifier(&efrm_netdev_notifier);
	efx_dl_unregister_driver(&efrm_dl_driver);
}


static int efrm_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *net_dev = ptr;
	struct efx_dl_device *dl_dev;
	struct efhw_nic *nic;

	if (event == NETDEV_CHANGEMTU) {
		dl_dev = efx_dl_dev_from_netdev(net_dev, &efrm_dl_driver);
		if (dl_dev) {
			nic = dl_dev->priv;
			EFRM_TRACE("%s: old=%d new=%d", __func__,
				   nic->mtu, net_dev->mtu + ETH_HLEN);
			nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
		}
	}

	return NOTIFY_DONE;
}


static void efrm_dl_event_falcon(struct efx_dl_device *efx_dev, void *p_event)
{
	struct efhw_nic *nic = efx_dev->priv;
	struct linux_efhw_nic *lnic = linux_efhw_nic(nic);
	efhw_event_t *ev = p_event;

	switch (FALCON_EVENT_CODE(ev)) {
	case FALCON_EVENT_CODE_CHAR:
		falcon_handle_char_event(nic, lnic->ev_handlers, ev);
		break;
	default:
		EFRM_WARN("%s: unknown event type=%x", __func__,
			  (unsigned)FALCON_EVENT_CODE(ev));
		break;
	}
}
