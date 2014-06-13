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

/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005      Fen Systems Ltd.
 * Copyright 2005-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include "net_driver.h"
#include "efx.h"
#include "driverlink_api.h"
#include "driverlink.h"
#include "filter.h"
#include "nic.h"

/* Global lists are protected by rtnl_lock */

/* List of all registered drivers */
static LIST_HEAD(efx_driver_list);

/* List of all registered Efx ports. Protected by the rtnl_lock */
LIST_HEAD(efx_port_list);

/**
 * Driver link handle used internally to track devices
 * @efx_dev: driverlink device handle exported to consumers
 * @efx: efx_nic backing the driverlink device
 * @port_node: per-device list head
 * @driver_node: per-driver list head
 */
struct efx_dl_handle {
	struct efx_dl_device efx_dev;
	struct efx_nic *efx;
	struct list_head port_node;
	struct list_head driver_node;
};

static struct efx_dl_handle *efx_dl_handle(struct efx_dl_device *efx_dev)
{
	return container_of(efx_dev, struct efx_dl_handle, efx_dev);
}

/* Remove an Efx device, and call the driver's remove() callback if
 * present. The caller must hold rtnl_lock. */
static void efx_dl_del_device(struct efx_dl_device *efx_dev)
{
	struct efx_dl_handle *efx_handle = efx_dl_handle(efx_dev);
	struct efx_nic *efx = efx_handle->efx;

	netif_info(efx, drv, efx->net_dev,
		   "%s driverlink client unregistering\n",
		   efx_dev->driver->name);

	if (efx_dev->driver->remove)
		efx_dev->driver->remove(efx_dev);

	list_del(&efx_handle->driver_node);
	list_del(&efx_handle->port_node);

	kfree(efx_handle);
}

/* Attempt to probe the given device with the driver, creating a
 * new &struct efx_dl_device. If the probe routine returns an error,
 * then the &struct efx_dl_device is destroyed */
static void efx_dl_try_add_device(struct efx_nic *efx,
				  struct efx_dl_driver *driver)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_handle *ex_efx_handle;
	struct efx_dl_device *efx_dev;
	int rc;
	bool added = false;

	efx_handle = kzalloc(sizeof(*efx_handle), GFP_KERNEL);
	if (!efx_handle)
		goto fail;
	efx_dev = &efx_handle->efx_dev;
	efx_handle->efx = efx;
	efx_dev->driver = driver;
	efx_dev->pci_dev = efx->pci_dev;
	INIT_LIST_HEAD(&efx_handle->port_node);
	INIT_LIST_HEAD(&efx_handle->driver_node);

	rc = driver->probe(efx_dev, efx->net_dev, efx->dl_info, "");
	if (rc)
		goto fail;

	/* Rather than just add to the end of the list,
	 * find the point that is at the start of the desired priority level
	 * and insert there
	 */

	list_for_each_entry(ex_efx_handle, &efx->dl_device_list, port_node) {
		if (ex_efx_handle->efx_dev.driver->priority >=
			driver->priority) {
			list_add_tail(&efx_handle->port_node, &ex_efx_handle->port_node);
			added = true;
			break;
		}
	}

	if (!added)
		list_add_tail(&efx_handle->port_node, &efx->dl_device_list);

	list_add_tail(&efx_handle->driver_node, &driver->device_list);

	netif_info(efx, drv, efx->net_dev,
		   "%s driverlink client registered\n", driver->name);
	return;

fail:
	netif_info(efx, drv, efx->net_dev,
		   "%s driverlink client skipped\n", driver->name);

	kfree(efx_handle);
}

/* Unregister a driver from the driverlink layer, calling the
 * driver's remove() callback for every attached device */
void efx_dl_unregister_driver(struct efx_dl_driver *driver)
{
	struct efx_dl_handle *efx_handle, *efx_handle_n;

	printk(KERN_INFO "Efx driverlink unregistering %s driver\n",
		 driver->name);

	rtnl_lock();

	list_for_each_entry_safe(efx_handle, efx_handle_n,
				 &driver->device_list, driver_node)
		efx_dl_del_device(&efx_handle->efx_dev);

	list_del(&driver->node);

	rtnl_unlock();
}
EXPORT_SYMBOL(efx_dl_unregister_driver);

/* Register a new driver with the driverlink layer. The driver's
 * probe routine will be called for every attached nic. */
int efx_dl_register_driver(struct efx_dl_driver *driver)
{
	struct efx_nic *efx;

	if (!(driver->flags & EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE)) {
		pr_err("Efx driverlink: %s did not promise to check rx_usr_buf_size\n",
		       driver->name);
		return -EPERM;
	}

	printk(KERN_INFO "Efx driverlink registering %s driver\n",
		 driver->name);

	INIT_LIST_HEAD(&driver->node);
	INIT_LIST_HEAD(&driver->device_list);

	rtnl_lock();

	list_add_tail(&driver->node, &efx_driver_list);
	list_for_each_entry(efx, &efx_port_list, dl_node)
		efx_dl_try_add_device(efx, driver);

	rtnl_unlock();
	return 0;
}
EXPORT_SYMBOL(efx_dl_register_driver);

void efx_dl_unregister_nic(struct efx_nic *efx)
{
	struct efx_dl_handle *efx_handle, *efx_handle_n;

	ASSERT_RTNL();

	list_for_each_entry_safe_reverse(efx_handle, efx_handle_n,
					 &efx->dl_device_list,
					 port_node)
		efx_dl_del_device(&efx_handle->efx_dev);

	list_del(&efx->dl_node);
}

void efx_dl_register_nic(struct efx_nic *efx)
{
	struct efx_dl_driver *driver;

	ASSERT_RTNL();

	list_add_tail(&efx->dl_node, &efx_port_list);
	list_for_each_entry(driver, &efx_driver_list, node)
		efx_dl_try_add_device(efx, driver);
}

struct efx_dl_device *efx_dl_dev_from_netdev(const struct net_device *net_dev,
					     struct efx_dl_driver *driver)
{
	struct efx_dl_handle *efx_handle;
	struct efx_nic *efx;

	ASSERT_RTNL();

	if (!efx_dl_netdev_is_ours(net_dev))
		return NULL;

	efx = netdev_priv((struct net_device *)net_dev);
	list_for_each_entry(efx_handle, &efx->dl_device_list, port_node) {
		if (efx_handle->efx_dev.driver == driver)
			return &efx_handle->efx_dev;
	}

	return NULL;
}
EXPORT_SYMBOL(efx_dl_dev_from_netdev);

void efx_dl_schedule_reset(struct efx_dl_device *efx_dev)
{
	struct efx_dl_handle *efx_handle = efx_dl_handle(efx_dev);
	struct efx_nic *efx = efx_handle->efx;

	efx_schedule_reset(efx, RESET_TYPE_ALL);
}
EXPORT_SYMBOL(efx_dl_schedule_reset);

/* Suspend ready for reset, calling the reset_suspend() callback of every
 * registered driver */
void efx_dl_reset_suspend(struct efx_nic *efx)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	ASSERT_RTNL();

	list_for_each_entry_reverse(efx_handle,
				    &efx->dl_device_list,
				    port_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->reset_suspend)
			efx_dev->driver->reset_suspend(efx_dev);
	}
}

/* Resume after a reset, calling the resume() callback of every registered
 * driver */
void efx_dl_reset_resume(struct efx_nic *efx, int ok)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	ASSERT_RTNL();

	list_for_each_entry(efx_handle, &efx->dl_device_list,
			    port_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->reset_resume)
			efx_dev->driver->reset_resume(efx_dev, ok);
	}
}

bool efx_dl_handle_event(struct efx_nic *efx, void *event)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	list_for_each_entry(efx_handle, &efx->dl_device_list, port_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->handle_event &&
		    efx_dev->driver->handle_event(efx_dev, event))
			return true;
	}

	return false;
}

/* We additionally include priority in the filter ID so that we
 * can pass it back into efx_filter_remove_id_safe().
 */
#define EFX_FILTER_PRI_SHIFT	28
#define EFX_FILTER_ID_MASK	((1 << EFX_FILTER_PRI_SHIFT) - 1)

int efx_dl_filter_insert(struct efx_dl_device *efx_dev,
			 struct efx_filter_spec *spec,
			 bool replace_equal)
{
	s32 filter_id = efx_filter_insert_filter(efx_dl_handle(efx_dev)->efx,
						 spec, replace_equal);
	if (filter_id >= 0) {
		EFX_BUG_ON_PARANOID(filter_id & ~EFX_FILTER_ID_MASK);
		filter_id |= spec->priority << EFX_FILTER_PRI_SHIFT;
	}
	return filter_id;
}
EXPORT_SYMBOL(efx_dl_filter_insert);

void efx_dl_filter_remove(struct efx_dl_device *efx_dev, int filter_id)
{
	if (filter_id < 0)
		return;
	efx_filter_remove_id_safe(efx_dl_handle(efx_dev)->efx,
				  filter_id >> EFX_FILTER_PRI_SHIFT,
				  filter_id & EFX_FILTER_ID_MASK);
}
EXPORT_SYMBOL(efx_dl_filter_remove);

void efx_dl_filter_redirect(struct efx_dl_device *efx_dev,
			    int filter_id, int rxq_i)
{
	BUG_ON(filter_id < 0);
	efx_filter_redirect_id(efx_dl_handle(efx_dev)->efx,
			       filter_id & EFX_FILTER_ID_MASK, rxq_i);
}
EXPORT_SYMBOL(efx_dl_filter_redirect);

int efx_dl_mcdi_rpc(struct efx_dl_device *efx_dev, unsigned int cmd,
		    size_t inlen, size_t outlen, size_t *outlen_actual,
		    const u8 *inbuf, u8 *outbuf)
{
	/* FIXME: Buffer parameter types should be changed to __le32 *
	 * so we can reasonably assume they are properly padded even
	 * if the lengths are not multiples of 4.
	 */
	if (WARN_ON(inlen & 3 || outlen & 3))
		return -EINVAL;

	return efx_mcdi_rpc(efx_dl_handle(efx_dev)->efx, cmd,
			    (const efx_dword_t *)inbuf, inlen,
			    (efx_dword_t *)outbuf, outlen, outlen_actual);
}
EXPORT_SYMBOL(efx_dl_mcdi_rpc);
