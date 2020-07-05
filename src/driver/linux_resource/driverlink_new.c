/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

#include <ci/driver/driverlink_api.h>

#include "efrm_internal.h"
#include "kernel_compat.h"

#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#  include <net/net_namespace.h>
#endif
#include <ci/efrm/efrm_filter.h>
#include <ci/efhw/nic.h>
#include <ci/tools/sysdep.h>
#include <ci/internal/transport_config_opt.h>

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

static int
efrm_dl_event(struct efx_dl_device *efx_dev, void *p_event, int budget);

static struct efx_dl_driver efrm_dl_driver = {
	.name = "resource",
	.priority = EFX_DL_EV_HIGH,
	.flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && \
                                        EFX_DRIVERLINK_API_VERSION_MINOR > 4)
		 | EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE
#endif
		 ,
	.probe = efrm_dl_probe,
	.remove = efrm_dl_remove,
	.reset_suspend = efrm_dl_reset_suspend,
	.reset_resume = efrm_dl_reset_resume,
	.handle_event = efrm_dl_event,
};


static void
init_vi_resource_dimensions(struct vi_resource_dimensions *rd,
			    const struct efx_dl_falcon_resources *falcon_res,
			    const struct efx_dl_siena_sriov *sriov_res,
			    const struct efx_dl_ef10_resources *ef10_res)
{
	if (ef10_res != NULL) {
		rd->vi_min = ef10_res->vi_min;
		rd->vi_lim = ef10_res->vi_lim;
		/* rss_channel_count is the number of rss channels the net
		 * driver is using.  The net driver also exposes
		 * rx_channel_count which is how many there are available in
		 * total to use.
		 */
		rd->rss_channel_count = ef10_res->rx_channel_count;
		rd->vi_base = ef10_res->vi_base;
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && \
					EFX_DRIVERLINK_API_VERSION_MINOR > 2)
		rd->vi_shift = ef10_res->vi_shift;
#else
		rd->vi_shift = 0;
#endif
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && \
					EFX_DRIVERLINK_API_VERSION_MINOR > 4)
		rd->mem_bar = ef10_res->mem_bar;
		rd->vi_stride = ef10_res->vi_stride;
#else
		rd->mem_bar = VI_RES_MEM_BAR_UNDEFINED;
		rd->vi_stride = ER_DZ_EVQ_RPTR_REG_STEP;
#endif
		/* assume all the register STEPS are identical */
		EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_EVQ_TMR_REG_STEP);
		EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_RX_DESC_UPD_REG_STEP);
		EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_TX_DESC_UPD_REG_STEP);

		EFRM_TRACE("Using VI range %d+(%d-%d)<<%d bar %d ws 0x%x", rd->vi_base,
			   rd->vi_min, rd->vi_lim, rd->vi_shift,
			   rd->mem_bar, rd->vi_stride);
#if EFX_DRIVERLINK_API_VERSION < 25
		rd->vport_id = ef10_res->vport_id;
#endif
	}
	else {
		rd->evq_timer_min = falcon_res->evq_timer_min;
		rd->evq_timer_lim = falcon_res->evq_timer_lim;
		rd->evq_int_min = falcon_res->evq_int_min;
		rd->evq_int_lim = falcon_res->evq_int_lim;
		rd->rxq_min = falcon_res->rxq_min;
		rd->rxq_lim = falcon_res->rxq_lim;
		rd->txq_min = falcon_res->txq_min;
		rd->txq_lim = falcon_res->txq_lim;
		rd->bt_min = falcon_res->buffer_table_min;
		rd->bt_lim = falcon_res->buffer_table_lim;

		/* Use top-most EVQ for SRAM update events etc. */
		EFRM_ASSERT(rd->evq_timer_lim > rd->evq_timer_min);
		rd->evq_timer_lim--;
		rd->non_irq_evq = rd->evq_timer_lim;

		/* See comment above for EF10 equivalent code */
		rd->rss_channel_count = falcon_res->rx_channel_count;
	}
	if (sriov_res != NULL) {
		rd->vf_vi_base = sriov_res->vi_base;
		rd->vf_vi_scale = sriov_res->vi_scale;
		rd->vf_count = sriov_res->vf_count;
	}
	else
		rd->vf_count = rd->vf_vi_base = rd->vf_vi_scale = 0;
}


static int
efrm_dl_probe(struct efx_dl_device *efrm_dev,
	      const struct net_device *net_dev,
	      const struct efx_dl_device_info *dev_info,
	      const char *silicon_rev)
{
	struct vi_resource_dimensions res_dim;
	struct efx_dl_falcon_resources *falcon_res = NULL;
	struct efx_dl_siena_sriov *sriov_res = NULL;
	struct efx_dl_ef10_resources *ef10_res = NULL;
	struct efx_dl_hash_insertion *hash = NULL;
	struct linux_efhw_nic *lnic;
	struct efhw_nic *nic;
	spinlock_t *biu_lock = NULL;
	unsigned probe_flags = 0;
        unsigned timer_quantum_ns = 0;
	unsigned hash_prefix = 0;
	unsigned rx_usr_buf_size = FALCON_RX_USR_BUF_SIZE;
	int rc;

	efrm_dev->priv = NULL;

	efx_dl_for_each_device_info_matching(dev_info, EFX_DL_FALCON_RESOURCES,
					     struct efx_dl_falcon_resources,
					     hdr, falcon_res) {
		if( falcon_res->rx_usr_buf_size > FALCON_RX_USR_BUF_SIZE ) {
			EFRM_ERR("%s: ERROR: Net driver rx_usr_buf_size %u"
				 " > %u", __func__,
				 falcon_res->rx_usr_buf_size,
				 FALCON_RX_USR_BUF_SIZE);
			return -1;
		}
	}

	efx_dl_search_device_info(dev_info, EFX_DL_EF10_RESOURCES,
				  struct efx_dl_ef10_resources,
				  hdr, ef10_res);
	if (ef10_res != NULL) {
		timer_quantum_ns = ef10_res->timer_quantum_ns;

		/* On EF10, the rx_prefix will get set by reading from
		 * the firmware in efhw_nic_init_hardware(), so leave
		 * hash_prefix as zero
		 */
	}
	else {
		/* Try looking for Falcon resource */
		efx_dl_search_device_info(dev_info, EFX_DL_FALCON_RESOURCES,
					  struct efx_dl_falcon_resources,
					  hdr, falcon_res);
		
		if (falcon_res == NULL) {
			EFRM_ERR("%s: Unable to find Falcon or EF10 "
				 "driverlink resources",  __func__);
			return -EINVAL;
		}

		biu_lock = falcon_res->biu_lock;

		if (falcon_res->flags & EFX_DL_FALCON_DUAL_FUNC) {
			EFRM_ERR("%s: Falcon/A series is now unsupported",
				 __func__);
			return -EINVAL;
		}

		rx_usr_buf_size = falcon_res->rx_usr_buf_size;

		if (falcon_res->flags & EFX_DL_FALCON_ONLOAD_UNSUPPORTED)
			probe_flags |= NIC_FLAG_ONLOAD_UNSUPPORTED;
		
		if (falcon_res->flags & EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS) 
			timer_quantum_ns = falcon_res->timer_quantum_ns;
		
		efx_dl_search_device_info(dev_info, EFX_DL_SIENA_SRIOV,
					  struct efx_dl_siena_sriov,
					  hdr, sriov_res);

		efx_dl_search_device_info(dev_info, EFX_DL_HASH_INSERTION,
					  struct efx_dl_hash_insertion,
					  hdr, hash);
		if (hash != NULL)
			hash_prefix = hash->data_offset;
	}

	init_vi_resource_dimensions(&res_dim, falcon_res, sriov_res, ef10_res);

	rc = efrm_nic_add(efrm_dev, probe_flags,
			  (/*no const*/ struct net_device *)net_dev,
			  &lnic, biu_lock, &res_dim,
                          timer_quantum_ns, hash_prefix, rx_usr_buf_size);
	if (rc != 0)
		return rc;

	/* Store pointer to net driver's driverlink device info.  It
	 * is guaranteed not to move, and we can use it to update our
	 * state in a reset_resume callback
	 */
	lnic->efrm_nic.dl_dev_info = dev_info;

	nic = &lnic->efrm_nic.efhw_nic;
	nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
	efrm_dev->priv = nic;

	return 0;
}

/* When we unregister ourselves on module removal, this function will be
 * called for all the devices we claimed. It will also be called on a single
 * device if that device is unplugged.
 */
static void efrm_dl_remove(struct efx_dl_device *efrm_dev)
{
	struct efhw_nic *nic = efrm_dev->priv;
	EFRM_TRACE("%s called", __func__);
	if (nic) {
		struct linux_efhw_nic *lnic = linux_efhw_nic(nic);

                /* flush all outstanding dma queues */
                efrm_nic_flush_all_queues(nic, 0);

		lnic->dl_device = NULL;
                lnic->efrm_nic.dl_dev_info = NULL;

		/* Wait for all in-flight driverlink calls to finish.  Since we
		 * have already cleared [lnic->dl_device], no new calls can
		 * start. */
		efhw_nic_flush_dl(nic);

		efrm_nic_unplug(nic, efrm_dev);

		/* Absent hardware is treated as a protracted reset. */
		efrm_nic_reset_suspend(nic);
		ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);
	}

}

static void efrm_dl_reset_suspend(struct efx_dl_device *efrm_dev)
{
	struct efhw_nic *nic = efrm_dev->priv;

	EFRM_NOTICE("%s:", __func__);

	efrm_nic_reset_suspend(nic);

	ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_RESET);
}

static void efrm_dl_reset_resume(struct efx_dl_device *efrm_dev, int ok)
{
	struct efhw_nic *nic = efrm_dev->priv;
	struct efrm_nic *efrm_nic = efrm_nic(nic);

	EFRM_NOTICE("%s: ok=%d", __func__, ok);

	/* Driverlink calls might have been disabled forcibly if, e.g., the NIC
	 * had been in BIST mode.  We know that they're safe now, so enable
	 * them. */
	efrm_driverlink_resume(efrm_nic);

	/* VI base may have changed on EF10 hardware */
	if (nic->devtype.arch == EFHW_ARCH_EF10) {
		struct efx_dl_ef10_resources *ef10_res = NULL;
		efx_dl_search_device_info(efrm_nic->dl_dev_info, 
					  EFX_DL_EF10_RESOURCES,
					  struct efx_dl_ef10_resources,
					  hdr, ef10_res);
		/* We shouldn't be able to get here if there wasn't an
		 * ef10_res structure as we know it's an EF10 NIC
		 */
		EFRM_ASSERT(ef10_res != NULL);
		if( nic->vi_base != ef10_res->vi_base ) {
			EFRM_TRACE("%s: vi_base changed from %d to %d\n",
				   __FUNCTION__, nic->vi_base, 
				   ef10_res->vi_base);
			nic->vi_base = ef10_res->vi_base;
		}
#if EFX_DRIVERLINK_API_VERSION < 25
		if( nic->vport_id != ef10_res->vport_id ) {
			EFRM_TRACE("%s: vport_id changed from %d to %d\n",
				   __FUNCTION__, nic->vport_id, 
				   ef10_res->vport_id);
			nic->vport_id = ef10_res->vport_id;
		}
#endif
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && \
					EFX_DRIVERLINK_API_VERSION_MINOR > 2)
		if( nic->vi_shift != ef10_res->vi_shift ) {
			EFRM_TRACE("%s: vi_shift changed from %d to %d\n",
				   __FUNCTION__, nic->vi_shift, 
				   ef10_res->vi_shift);
			nic->vi_shift = ef10_res->vi_shift;
		}
#endif
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && \
					EFX_DRIVERLINK_API_VERSION_MINOR > 4)
		if( nic->ctr_ap_bar != ef10_res->mem_bar ) {
			EFRM_TRACE("%s: mem_bar changed from %d to %d\n",
				   __FUNCTION__, nic->ctr_ap_bar,
				   ef10_res->mem_bar);
			nic->ctr_ap_bar = ef10_res->mem_bar;
		}
		if( nic->vi_stride != ef10_res->vi_stride ) {
			EFRM_TRACE("%s: vi_stride changed from %d to %d\n",
				   __FUNCTION__, nic->vi_stride,
				   ef10_res->vi_stride);
			nic->vi_stride = ef10_res->vi_stride;
		}
#endif
	}

	/* Remove record on que initialization from before a reset
	 * No hardware operation will be performed */
	efrm_nic_flush_all_queues(nic, 1);

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


/* In the ordinary course of things, when hardware is unplugged, the kernel
 * will tell the net driver, which will forward the news to us by calling our
 * removal hook, and this will prevent us from attempting any further
 * driverlink calls on that device. However, if we detect that hardware has
 * gone before receiving the notification, we would like just the same to
 * prevent further driverlink activity. These functions allow us to arrange
 * that. */

/* [failure_generation] is the value returned by efrm_driverlink_generation()
 * at some point before the detected failure that prompted this call. */
void efrm_driverlink_desist(struct efrm_nic* nic, unsigned failure_generation)
{
	EFRM_TRACE("%s:", __func__);

	spin_lock_bh(&nic->lock);
	if (failure_generation == nic->driverlink_generation)
		nic->rnic_flags |= EFRM_NIC_FLAG_DRIVERLINK_PROHIBITED;
	spin_unlock_bh(&nic->lock);
}

void efrm_driverlink_resume(struct efrm_nic* nic)
{
	EFRM_TRACE("%s:", __func__);

	spin_lock_bh(&nic->lock);
	++nic->driverlink_generation;
	nic->rnic_flags &= ~EFRM_NIC_FLAG_DRIVERLINK_PROHIBITED;
	spin_unlock_bh(&nic->lock);
}

unsigned efrm_driverlink_generation(struct efrm_nic* nic)
{
	return READ_ONCE(nic->driverlink_generation);
}


static int efrm_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
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
	if (event == NETDEV_CHANGENAME) {
		dl_dev = efx_dl_dev_from_netdev(net_dev, &efrm_dl_driver);
		if (dl_dev) {
			nic = dl_dev->priv;
			efrm_filter_rename(nic, net_dev);
			efrm_nic_rename(nic, net_dev);
		}
	}
#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
	if (event == NETDEV_CHANGE) {
		dl_dev = efx_dl_dev_from_netdev(net_dev, &efrm_dl_driver);
		if (dl_dev) {
			nic = dl_dev->priv;
			efrm_nic_xdp_change(nic);
		}
	}
#endif

	return NOTIFY_DONE;
}


static int
efrm_dl_event(struct efx_dl_device *efx_dev, void *p_event, int budget)
{
	struct efhw_nic *nic = efx_dev->priv;
	struct linux_efhw_nic *lnic = linux_efhw_nic(nic);
	efhw_event_t *ev = p_event;
	int rc;

	rc = efhw_nic_handle_event(nic, lnic->ev_handlers, ev, budget);
	return rc;
}
