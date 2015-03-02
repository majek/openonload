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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"
#include <linux/netdevice.h>
#include <net_driver.h>
#include <mcdi.h>
#include <driverlink_api.h>

static int aoe_dl_probe(struct efx_dl_device* dl_dev,
			const struct net_device* net_dev,
			const struct efx_dl_device_info* dev_info,
			const char* silicon_rev)
{
	struct efx_dl_aoe_resources *res;
	struct aoe_device *new_dev = NULL;

	efx_dl_search_device_info(dev_info, EFX_DL_AOE_RESOURCES,
				  struct efx_dl_aoe_resources,
				  hdr, res) {

		if (!res) {
			printk(KERN_INFO "No AOE extensions available\n");
			return -ENODEV;
		}

		new_dev = aoe_add_device(dl_dev, res, net_dev);
		if (!new_dev)
			return -ENOMEM;

	}

	return 0;
}

static void aoe_dl_remove(struct efx_dl_device* dl_dev)
{
	aoe_remove_device(dl_dev);
	dl_dev->priv = NULL;
}

static bool aoe_dl_handle_event(struct efx_dl_device *dl_dev, void *event)
{
	struct aoe_port_info *port = (struct aoe_port_info *)dl_dev->priv;

	if (!port)
		return false;

	return aoe_handle_mcdi_event(port, event);
}

static struct efx_dl_driver aoe_dl_driver = {
	.name = "aoe_dl",
	.priority = EFX_DL_EV_MED,
	.flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE,
	.probe = aoe_dl_probe,
	.remove = aoe_dl_remove,
	.handle_event = aoe_dl_handle_event,
};

int aoe_dl_send_block_wait(struct aoe_device *aoe_dev, struct aoe_proxy_msg *msg)
{
	int ret = 0;
	struct aoe_port_info *port;

	mutex_lock(&aoe_dev->dev_lock);

	port = list_first_entry(&aoe_dev->nic_ports, struct aoe_port_info, list);

	if (!port) {
		ret = -ENODEV;
		goto out;
	}

	ret = efx_dl_mcdi_rpc(port->dl_dev, msg->cmd, msg->req_len, msg->resp_len,
			      &msg->real_resp, (uint8_t*)msg->request_data, (uint8_t*)msg->response_data);

out:
	mutex_unlock(&aoe_dev->dev_lock);

	return ret;
}

int aoe_dl_register(void)
{
	int rc;

	rc = efx_dl_register_driver(&aoe_dl_driver);

	return rc;
}

void aoe_dl_unregister(void)
{
	efx_dl_unregister_driver(&aoe_dl_driver);
}
