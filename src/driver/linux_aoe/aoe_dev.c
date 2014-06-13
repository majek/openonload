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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"

#define AOE_MAX_DEVS		4	/* Two per card so two AOE boards */

static int max_fds = 32;
module_param(max_fds, int, 0444);
MODULE_PARM_DESC(max_fds,
		 "Set the maximum number of file descriptors"
		 "available to user space\n");

#define AOE_MIN(x, y)	(x < y ? x : y)

static struct aoe_device *aoe_dev_list[AOE_MAX_DEVS];
static struct aoe_map_entry *aoe_fds;
static struct mutex fd_list_lock;

enum aoe_cmd_progress {
	AOE_CMD_REQ_DATA,
	AOE_CMD_CONTINUE,
	AOE_CMD_HANDLED,
	AOE_CMD_INVALID,
};

extern struct aoe_parent_dev *aoe_parent_p;

struct aoe_map_entry *aoe_find_free(void)
{
	int idx;
	struct aoe_map_entry *new_entry = NULL;
	mutex_lock(&fd_list_lock);

	for (idx = 0; idx < max_fds; idx++) {
		if (aoe_fds[idx].state == CLOSED) {
			new_entry = &aoe_fds[idx];
			new_entry->state = OPENED;
			new_entry->remove = false;
			new_entry->aoe_dev = NULL;
			/* Reset buffers if there */
			aoe_close_entry(new_entry);
			break;
		}
	}

	mutex_unlock(&fd_list_lock);
	return new_entry;
}

void aoe_release_entry(struct aoe_map_entry *entry)
{
	if ((entry->aoe_dev) && (entry->aoe_dev->bind_unique_fd == entry)) {
		entry->aoe_dev->bind_unique_fd = NULL;
	}
	mutex_lock(&fd_list_lock);
	entry->state = CLOSED;
	aoe_release_map_lock(entry);
	mutex_unlock(&fd_list_lock);
}

int aoe_free_device(struct aoe_device *dev)
{
	if (list_empty(&dev->nic_ports) &&
	    list_empty(&dev->fd_list)) {
		aoe_destroy_mmaps(dev);
		aoe_dev_list[dev->board] = NULL;
		kfree(dev);
		return 0;
	}
	return -EAGAIN;
}

void aoe_setup_entry(struct aoe_map_entry *entry)
{
	entry->state = CLOSED;
	entry->file_p = NULL;
	entry->remove = false;
	setup_mcdi_handlers(entry);

	init_waitqueue_head(&entry->poll_queue);
	init_waitqueue_head(&entry->read_queue);

	mutex_init(&entry->close_lock);

	INIT_LIST_HEAD(&entry->dma_list);
	INIT_LIST_HEAD(&entry->dev_list);
}

int aoe_fd_port_bind(struct aoe_map_entry *entry,
 		     int ifindex, uint32_t flags,
		     int *board, int *conn_port)
{
	int idx;
	struct aoe_device *dev;
	struct aoe_port_info *port;

	/* Search through the instances of aoe devices for the one
	 * with the matching ifindex then
	 *      1. Bind the entry to the aoe_device
	 *      2. Return the conn_hw_port in the ioctl response
	 */

	for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
		dev = aoe_dev_list[idx];
		if (!dev || dev->closed) {
			continue;
		}

		list_for_each_entry(port, &dev->nic_ports, list) {

			if (port->ifindex != ifindex) {
				continue;
			}

			/* ifIndex matched */

			if (flags & AOE_BIND_ONCE_PER_DEVICE) {
				if (dev->bind_unique_fd != NULL) {
					printk(KERN_ERR "sfc_aoe: "
						"Failed to achieve unique bind on device; "
						"An Interface on this device is already bound\n");
					return -EEXIST;
				} else {
					dev->bind_unique_fd = entry;
				}
			}
			*conn_port = AOE_PHYS_PORT(port);
			*board = dev->board;
			entry->port = port;
			entry->aoe_dev = dev;
			entry->state = INITIALISED;
			aoe_dev_inc_and_link_ref(dev, &entry->dev_list,
						 &dev->fd_list, fd_ref);
			return 0;
		}
	}

	printk(KERN_INFO "sfc_aoe: Failed to bind on ifindex %d - "
               "not an AOE device or device not opened?\n",
               ifindex);
	return -ENODEV;
}

int aoe_get_num_boards(void)
{
	int idx;
	struct aoe_device *dev;
	int num_boards = 0;

        for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
                dev = aoe_dev_list[idx];
                if (!dev) {
                        break;
                }
		num_boards++;
	}
	return num_boards;
}

int aoe_get_num_ports(int board_id, int *num_ports)
{
	int idx;
	struct aoe_device *dev;
	int board_idx = 0;
	int port_id = 0;
	struct aoe_port_info *port;

        for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
                dev = aoe_dev_list[idx];
                if (!dev) {
                        break;
                }
		if (board_idx == board_id) {

			list_for_each_entry(port, &dev->nic_ports, list) {
				port_id++;
			}

			*num_ports = port_id;
			return 0;
		}

		board_idx++;
	}
	return -ENODEV;
}

int aoe_get_ifindex(int board_id, int port_id, int *ifindex)
{
	int idx;
	struct aoe_device *dev;
	int board_idx = 0;
	int port_idx = 0;
	struct aoe_port_info *port;

        for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
                dev = aoe_dev_list[idx];
                if (!dev) {
                        break;
                }
		if (board_idx == board_id) {

			list_for_each_entry(port, &dev->nic_ports, list) {
				if (port_idx == port_id) {
					*ifindex = port->ifindex;
					return 0;
				}
				port_idx++;
			}
			return -ENODEV;
		}
		board_idx++;
	}
	return -ENODEV;
}

int aoe_get_portid(int ifindex, int *board_id, int *port_id)
{
	int idx;
	struct aoe_device *dev;
	int board_idx = 0;
	int port_idx = 0;
	struct aoe_port_info *port;

        for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
                dev = aoe_dev_list[idx];
                if (!dev) {
                        break;
                }

		list_for_each_entry(port, &dev->nic_ports, list) {
			if (port->ifindex == ifindex) {
				*board_id = board_idx;
				*port_id = port_idx;
				return 0;
			}
			port_idx++;
		}
		board_idx++;
	}
	return -ENODEV;
}

static void aoe_update_port_config(struct aoe_port_info *port)
{
	aoe_mcdi_set_mtu(port, port->mtu);
}

/* FPGA restart event worker
 * Needs to handle close down of the FC
 *      Take down open FD's
 *      Remove memory map entries.
 * Reload of the FC
 *      Re-enable maps to be queried.
 *      Set state of FPGA such that the FD's can be created again.
 *
 */

static void aoe_prepare_for_reload(struct aoe_device *aoe_dev)
{
	struct aoe_map_entry *entry;
	struct aoe_map_entry *temp;

	list_for_each_entry_safe(entry, temp, &aoe_dev->fd_list, dev_list) {
		mutex_lock(&entry->close_lock);
		aoe_remove_stats_entries(entry);
		/* Mark as closed to the applications */
		aoe_async_close(entry);
		mutex_unlock(&entry->close_lock);
	}

	aoe_flush_mmaps(aoe_dev);
}

static void aoe_event_reload_worker(struct aoe_work_struct_s *aoe_work)
{
	struct aoe_device *dev =
		container_of(aoe_work, struct aoe_device, aoe_event_work);
	struct aoe_port_info *port;


	aoe_prepare_for_reload(dev);

	aoe_apply_static_config(dev);

	list_for_each_entry(port, &dev->nic_ports, list) {
		aoe_update_port_config(port);
	}
}

static void aoe_event_ddr_ecc_worker(struct aoe_work_struct_s *aoe_work)
{
	struct aoe_ddr_ecc_work_params_s *work_params =
		&(aoe_work->work_params.ddr_ecc_work_params);
	struct aoe_device *dev =
		container_of(aoe_work, struct aoe_device, aoe_event_work);

	aoe_mcdi_ddr_ecc_status(dev, work_params);
}

static void aoe_event_worker(struct work_struct *work)
{
	struct aoe_work_struct_s *aoe_event_work =
		container_of(work, struct aoe_work_struct_s, event_work);

	if (!aoe_event_work)
		return;

	switch (aoe_event_work->work_type) {
		case AOE_WORK_RELOAD:
			aoe_event_reload_worker(aoe_event_work);
			break;
		case AOE_WORK_DDR_ECC:
			aoe_event_ddr_ecc_worker(aoe_event_work);
			break;
		default:
			break;
	}
}

static void aoe_link_port(struct aoe_device *dev,
			  struct aoe_port_info *port,
			  const struct net_device* net_dev,
			  struct efx_dl_device *dl_dev)
{
	port->aoe_parent = dev;
	INIT_LIST_HEAD(&port->list);
	aoe_dev_inc_and_link_ref(dev, &port->list,
				 &dev->nic_ports, port_ref);
	port->dl_dev = dl_dev;
	port->ifindex = net_dev->ifindex;
	port->mtu = AOE_DEFAULT_MTU;
	port->update = aoe_update_port_config;

	if (net_dev->perm_addr) {
		memcpy(port->mac_address, net_dev->perm_addr, 6);
	}
	dl_dev->priv = port;

	if (aoe_port_sysfs_setup(dev, port)) {
		printk(KERN_ERR "sfc_aoe: Failed to set up PORT sysfs\n");
	}
}

struct aoe_device * aoe_add_device(struct efx_dl_device *dl_dev,
				   struct efx_dl_aoe_resources *res,
				   const struct net_device* net_dev)
{
	int idx;
	unsigned int int_macs;
	unsigned int ext_macs;
	struct aoe_device *aoe_instance = NULL;
	struct aoe_port_info *nic_port;
	struct aoe_device **stored_aoes = aoe_dev_list;

	if (!dl_dev || !res)
		goto out;

	for (idx = 0; idx < AOE_MAX_DEVS; idx++) {

		if (stored_aoes[idx] == NULL)
			break;

		if (stored_aoes[idx]->closed == true) {
			if (aoe_free_device(stored_aoes[idx])) {
				printk(KERN_ERR "sfc_aoe: Could not re-alloc instance\n");
				return NULL;
			}
			break;
		}

		/* Two potential paths here - but the second is very unlikely (maybe impossible)
		 * 1. function 1 gets registered first
		 *      Store this but do not set up the conn_path
		 *      Only when 0 is registered will the conn_path
		 *      be set up that will allow and MCDI commands to be done
		 * 2. function 0 gets registered first
		 *      Store this and do set up the connection path
		 *      Function 1 then comes in and this can just be set to
		 *      point to the device that is on the same slot
		 */

		if ((dl_dev->pci_dev->bus->number == 
			stored_aoes[idx]->pci_dev->bus->number) &&
			(PCI_SLOT(dl_dev->pci_dev->devfn) == 
			PCI_SLOT(stored_aoes[idx]->pci_dev->devfn))) {
			/* Have found a device that is in the same slot as the new one
			 * so re-use and add to the list of ports */
			aoe_instance = stored_aoes[idx];
			break;
		}
	}

	if (idx == AOE_MAX_DEVS)
		return NULL;

	nic_port = kzalloc(sizeof(*nic_port), GFP_ATOMIC);
	if (!nic_port) {
		printk(KERN_ERR "sfc_aoe: Unable to allocate memory for nic port\n");
		return NULL;
	}

	/* If there was a match then link only the port and create the int/ext
	 * MACs as well */
	if (aoe_instance) {
		aoe_link_port(aoe_instance, nic_port, net_dev, dl_dev);
		return aoe_instance;
	}

	aoe_instance = kzalloc(sizeof(*aoe_instance), GFP_ATOMIC);
	if (!aoe_instance) {
		printk(KERN_ERR "sfc_aoe: Unable to allocate memory\n");
		goto aoe_error;
	}

	/* take the first one as the pci device */
	aoe_instance->pci_dev = dl_dev->pci_dev;
	aoe_instance->board = idx;
	aoe_instance->closed = false;
	stored_aoes[idx] = aoe_instance;

	aoe_mcdi_set_funcs(aoe_instance);
	init_waitqueue_head(&aoe_instance->event_queue);
	INIT_WORK(&aoe_instance->aoe_event_work.event_work, aoe_event_worker);
	aoe_instance->event_workwq = create_singlethread_workqueue("sfc_aoe_ev");
	if (!aoe_instance->event_workwq) {
		printk(KERN_ERR "sfc_aoe: Event queue not created\n");
		goto queue_error;
	}

	ext_macs = res->external_macs;
	int_macs = res->internal_macs;

	INIT_LIST_HEAD(&aoe_instance->internal_mac_list);
	INIT_LIST_HEAD(&aoe_instance->external_mac_list);
	INIT_LIST_HEAD(&aoe_instance->nic_ports);
	INIT_LIST_HEAD(&aoe_instance->fd_list);
	INIT_LIST_HEAD(&aoe_instance->dimms);
	INIT_LIST_HEAD(&aoe_instance->dma_blocks);
	INIT_LIST_HEAD(&aoe_instance->free_dma_blocks);
	mutex_init(&aoe_instance->dev_lock);
	mutex_init(&aoe_instance->dma_lock);
	aoe_instance->bind_unique_fd = NULL;

	if (aoe_qu_setup(aoe_instance, 10)) {
		printk(KERN_ERR "sfc_aoe: Failed to set up comms thread\n");
		goto comms_error;
	}

	if (aoe_setup_mmaps(aoe_instance)) {
		printk(KERN_ERR "sfc_aoe: Failed to set up mmaps\n");
		goto map_error;
	}

	if (aoe_sysfs_setup(aoe_parent_p->aoe_dev, aoe_instance)) {
		printk(KERN_ERR "sfc_aoe: Failed to set up FPGA sysfs\n");
		goto sys_error;
	}

	aoe_link_port(aoe_instance, nic_port, net_dev, dl_dev);

	if (aoe_netdev_register(aoe_instance, int_macs, ext_macs)) {
		printk(KERN_ERR "sfc_aoe: Failed to set up register\n");
		goto net_error;
	}

	if (aoe_apply_static_config(aoe_instance)) {
		printk(KERN_ERR "sfc_aoe: Firmware not at required level\n");
		goto config_error;
	}

	if (aoe_stats_device_setup(aoe_instance)) {
		printk(KERN_ERR "sfc_aoe: Failed to setup DMA pools\n");
		goto stats_error;
	}

	return aoe_instance;

stats_error:
	aoe_remove_static_config(aoe_instance);
config_error:
	aoe_netdev_unregister(aoe_instance);
net_error:
	aoe_sysfs_delete(aoe_instance);
sys_error:
	aoe_destroy_mmaps(aoe_instance);
map_error:
	destroy_workqueue(aoe_instance->event_workwq);
comms_error:
	aoe_qu_destroy(aoe_instance);
queue_error:
	kfree(aoe_instance);
	stored_aoes[idx] = NULL;

aoe_error:
	kfree(nic_port);
out:
	return NULL;
}

static void aoe_device_clean(struct aoe_device *aoe_instance)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&aoe_instance->aoe_event_work.event_work);
#else
	flush_workqueue(aoe_instance->event_workwq);
#endif
	destroy_workqueue(aoe_instance->event_workwq);
	aoe_prepare_for_reload(aoe_instance);
	aoe_stats_device_destroy(aoe_instance);
	aoe_remove_static_config(aoe_instance);
	aoe_netdev_unregister(aoe_instance);
	aoe_sysfs_delete(aoe_instance);
}

void aoe_remove_device(struct efx_dl_device *dl_dev)
{
	/* Remove the device files */
	struct aoe_port_info *nic_port = dl_dev->priv;
	struct aoe_device *aoe_instance = nic_port->aoe_parent;

	/* The device will still be present but
	 * not usable for comms or visible to any new nodes
	 */

	if (!(aoe_dev_dec_ref(aoe_instance, port_ref))) {
		aoe_device_clean(aoe_instance);
		aoe_qu_destroy(aoe_instance);
	}

	mutex_lock(&aoe_instance->dev_lock);

	aoe_instance->closed = true;
	list_del(&nic_port->list);
	kfree(nic_port);

	mutex_unlock(&aoe_instance->dev_lock);
}

int aoe_device_setup(void)
{
	int idx;
	int retval;

	aoe_fds = kzalloc(sizeof(*aoe_fds) * max_fds, GFP_KERNEL);
	if (!aoe_fds) {
		printk(KERN_ERR "sfc_aoe: Memory allocation failure\n");
		retval = -ENOMEM;
		goto out1;
	}

	retval = aoe_dl_register();
	if (retval) {
		printk(KERN_ERR "sfc_aoe: No AOE Devices created\n");
		goto out2;
	}

	for (idx = 0; idx < max_fds; idx++) {
		aoe_setup_entry(&aoe_fds[idx]);
		aoe_fds[idx].idx = idx;
	}

	mutex_init(&fd_list_lock);

	return 0;

out2:
	kfree(aoe_fds);
out1:
	return retval;
}

void aoe_device_close(void)
{
	int idx;
	aoe_dl_unregister();

	for (idx = 0; idx < max_fds; idx++)
		aoe_close_entry(&aoe_fds[idx]);

	kfree(aoe_fds);

	for (idx = 0; idx < AOE_MAX_DEVS; idx++) {
		if (aoe_dev_list[idx])
			aoe_free_device(aoe_dev_list[idx]);
	}
}
