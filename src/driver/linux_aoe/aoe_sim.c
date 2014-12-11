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
#include <linux/netdevice.h>
#include <linux/ethtool.h>

static int num_boards = 1;
module_param(num_boards, int, 0444);
MODULE_PARM_DESC(num_boards,
		 "Set the maximum number of virtual boards that"
		 "will be added to the system\n");


static int aoe_file_open(struct inode *inode_p, struct file *file_p)
{
	struct aoe_map_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		printk(KERN_ERR "sfc_aoe_sim: Memory allocation failure\n");
		return -ENOMEM;
	}

	file_p->private_data = entry;
	init_waitqueue_head(&entry->poll_queue);
        init_waitqueue_head(&entry->read_queue);

        mutex_init(&entry->close_lock);

        INIT_LIST_HEAD(&entry->dma_list);
        INIT_LIST_HEAD(&entry->dev_list);

	return 0;
}

static int aoe_file_release(struct inode *inode_p, struct file *file_p)
{
	struct aoe_map_entry *entry = file_p->private_data;

	if (!entry)
                return -EBADF;

	if (entry->state >= INITIALISED)
		aoe_dev_dec_and_unlink_ref(entry->aoe_dev,
					   &entry->dev_list,
					   fd_ref);

	kfree(entry);

	file_p->private_data = NULL;

	return 0;
}

static ssize_t aoe_file_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	return -EBADF;
}

static ssize_t aoe_file_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	return -EBADF;
}

static unsigned int aoe_file_poll(struct file *file,
				  struct poll_table_struct *wait)
{
	return -EBADF;
}

/* Store the MTU but that is all
 */ 
static int aoe_ioctl_mtu_op(struct aoe_map_entry *entry,
			    struct aoe_ioctl *ioctl)
{
	struct aoe_mtu_req *req = &ioctl->u.mtu;
	uint32_t mtu = req->mtu;
	struct aoe_port_info *port = entry->port;

	if (!port)
		return -ENODEV;

	port->mtu = mtu;

	return 0;
}

/* Maintain a small list of id's and do some simple
 * handling of these since the HAL my call in
 */
static int aoe_ioctl_dma_op(struct aoe_map_entry *entry,
			    struct aoe_ioctl *ioctl)
{
	return 0;
}

/* Just return success */
static int aoe_ioctl_change_link_mode(struct aoe_map_entry *entry,
				      struct aoe_ioctl *ioctl)
{
	return 0;
}

/* Bind to one of the specified cards
 */
static int aoe_ioctl_bind_fd_to_port(struct aoe_map_entry *entry,
				     struct aoe_ioctl *ioctl)
{
	struct aoe_bind_ioctl *bind = &ioctl->u.bind;
	int ifindex = bind->ifindex;
	int conn_port;
	int board;

	if (aoe_fd_port_bind(entry, ifindex, 0, &board, &conn_port))
		return -ENODEV;

	bind->board = board;
	bind->conn_port = conn_port;

	return 0;
}

long aoe_control_ioctl(struct aoe_map_entry *entry, u16 aoe_cmd,
		struct aoe_ioctl __user *user_data)
{
	struct aoe_ioctl data;
	int (*op)(struct aoe_map_entry *, struct aoe_ioctl *);
	ssize_t size;
	int ret;

	switch (aoe_cmd) {
		case AOE_BIND:
			op = aoe_ioctl_bind_fd_to_port;
			size = sizeof(data.u.bind);
			break;

		case AOE_LINK_MODE:
			op = aoe_ioctl_change_link_mode;
			size = sizeof(data.u.link_mode);
			break;

		case AOE_DMA_OP:
			op = aoe_ioctl_dma_op;
			size = sizeof(data.u.dma);
			break;

		case AOE_MTU_OP:
			op = aoe_ioctl_mtu_op;
			size = sizeof(data.u.mtu);
			break;

		default:
			return -EINVAL;
	}

	if (copy_from_user(&data.u, &user_data->u, size))
		return -EFAULT;

	ret = op(entry, &data);
	if (ret)
		return ret;

	if (copy_to_user(&user_data->u, &data.u, size))
		return -EFAULT;

	return 0;
}

static long control_ioctl(struct file *file, unsigned int req, unsigned long arg)
{
	struct aoe_ioctl __user *user_data = (struct aoe_ioctl __user *)arg;
	struct aoe_map_entry *entry = file->private_data;
	u16 aoe_cmd;
	long ret;

	if (req != SIOCAOE)
		return -ENOTTY;

	if (copy_from_user(&aoe_cmd, &user_data->cmd, sizeof(aoe_cmd)))
		return -EFAULT;

	ret = aoe_control_ioctl(entry, aoe_cmd, user_data);
	return ret;
}

#ifndef HAVE_UNLOCKED_IOCTL
static int control_legacy_ioctl(struct inode *ino, struct file *filp,
				unsigned int req, unsigned long arg)
{
	return (int) control_ioctl(filp, req, arg);
}
#endif

const struct file_operations aoe_file_ops = {
	.owner = THIS_MODULE,
	.open = aoe_file_open,
	.write = aoe_file_write,
	.read = aoe_file_read,
	.poll = aoe_file_poll,
	.release = aoe_file_release,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = control_ioctl,
#else
	.ioctl = control_legacy_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	.compat_ioctl = control_ioctl,
#endif
};

/* Dummy functions for the fake ethernet devices
*/

static int aoe_net_open(struct net_device *net_dev)
{
	return 0;
}

static int aoe_net_stop(struct net_device *net_dev)
{
	return 0;
}

static void aoe_watchdog(struct net_device *net_dev)
{

}

static int aoe_change_mtu(struct net_device *net_dev, int new_mtu)
{
	return 0;
}

static int aoe_set_mac_address(struct net_device *net_dev, void *data)
{
	printk(KERN_ERR "trying to set mac\n");
	return 0;
}

static void aoe_set_rx_mode(struct net_device *net_dev)
{

}

void aoe_mcdi_ddr_ecc_status(struct aoe_device *dev,
			     struct aoe_ddr_ecc_work_params_s *params)
{

}

void aoe_stats_device_destroy(struct aoe_device *aoe_dev)
{

}

int aoe_remove_stats_entries(struct aoe_map_entry *entry)
{
	return 0;
}

netdev_tx_t aoe_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev)
{
	return NETDEV_TX_OK;
}

static int aoe_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
static int aoe_set_features(struct net_device *net_dev, netdev_features_t data)
{
	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
static const struct net_device_ops sim_netdev_ops = {
	.ndo_open               = aoe_net_open,
	.ndo_stop               = aoe_net_stop,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
	.ndo_get_stats64        = NULL,
#else
	.ndo_get_stats          = NULL,
#endif
	.ndo_tx_timeout         = aoe_watchdog,
	.ndo_start_xmit         = aoe_hard_start_xmit,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_do_ioctl           = aoe_ioctl,
	.ndo_change_mtu         = aoe_change_mtu,
	.ndo_set_mac_address    = aoe_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NDO_SET_MULTICAST_LIST)
	.ndo_set_rx_mode        = aoe_set_rx_mode,
#else
	.ndo_set_multicast_list = aoe_set_rx_mode,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_FEATURES)
	.ndo_set_features       = aoe_set_features,
#endif
};
#endif

/* Fake up the calls that would come the sfc driver
 * First we register some dummy ethernet interfcaces
 * for each of the ports. Then give this to
 * the aoe_add_device call as normal.
 */

static struct list_head fake_devs;
static struct efx_dl_device *sfc_devs;
static struct pci_dev *sfc_pci_devs;
static struct pci_bus *sfc_pci_bus;
static struct efx_dl_aoe_resources aoe_res = {
	.internal_macs = 0, /* won't be used but needed for aoe_add_device */
	.external_macs = 0, /*won't be used but needed for aoe_add_device */
};

#define SFC_IDX(_board,_port)	((_board * 2) + _port)
#define AOE_PPD	2

#define MAC_BOARD_IDX 4
#define MAC_PORT_IDX  5

int aoe_dl_register(void)
{
	int idx;
	int board_idx = 0;
	struct aoe_netdev *aoe_net;
	struct net_device *new_dev;
	struct pci_dev *this_dev;
	struct efx_dl_device *this_dl_dev;
	char mac[6] = {0x00,0x0F,0x53,0x00,0x00,0x00}; /* Base MAC address, SF OUI start */

	INIT_LIST_HEAD(&fake_devs);

	sfc_devs = kzalloc(sizeof(*sfc_devs) * num_boards * AOE_PPD, GFP_ATOMIC);
	if (!sfc_devs)
		return -ENOMEM;

	sfc_pci_devs = kzalloc(sizeof(*sfc_pci_devs) * num_boards * AOE_PPD, GFP_ATOMIC);
	if (!sfc_pci_devs)
		goto fail;

	sfc_pci_bus = kzalloc(sizeof(*sfc_pci_bus) * num_boards, GFP_ATOMIC);
	if (!sfc_pci_bus)
		goto fail;

	for (board_idx = 0; board_idx < num_boards; board_idx++) {
		sfc_pci_bus->number = board_idx;

		mac[MAC_BOARD_IDX] = board_idx;

		for (idx = 0; idx < AOE_PPD; idx++) {
			new_dev = alloc_etherdev_mq(sizeof(struct aoe_netdev), 1);
			if (!new_dev)
				goto fail;

			mac[MAC_PORT_IDX] = idx;

			dev_alloc_name(new_dev, "aoesim%d");
			aoe_net = netdev_priv(new_dev);
			aoe_net->netdev = new_dev;
			aoe_net->mac_type = AOE_MAC_SIM;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_OPS)
			new_dev->netdev_ops = &sim_netdev_ops;
#else
			new_dev->open = aoe_net_open;
			new_dev->stop = aoe_net_stop;
			new_dev->get_stats = aoe_net_stats;
			new_dev->tx_timeout = aoe_watchdog;
			new_dev->hard_start_xmit = aoe_hard_start_xmit;
			new_dev->do_ioctl = aoe_ioctl;
			new_dev->change_mtu = aoe_change_mtu;
			new_dev->set_mac_address = aoe_set_mac_address;
			new_dev->set_multicast_list = aoe_set_rx_mode;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
			new_dev->vlan_rx_register = NULL;
#endif
#ifdef AOE_USE_VLAN_RX_KILL_VID
			new_dev->vlan_rx_kill_vid = NULL;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
			new_dev->poll_controller = NULL;
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
			memcpy(new_dev->perm_addr, mac, ETH_ALEN);
#endif
#if !defined(EFX_USE_KCOMPAT) || !defined(SET_ETHTOOL_OPS)
                       net_dev->ethtool_ops = NULL;
#else
			SET_ETHTOOL_OPS(new_dev, NULL);
#endif

			if (register_netdev(new_dev)) {
				printk(KERN_ERR "Failed to register fake net device\n");
				goto fail;
			}

		        netif_carrier_off(new_dev);

			list_add(&aoe_net->list, &fake_devs);

			this_dl_dev = &sfc_devs[SFC_IDX(board_idx, idx)];
			this_dev = &sfc_pci_devs[SFC_IDX(board_idx, idx)];

			this_dev->devfn = PCI_DEVFN(board_idx, idx);
			this_dl_dev->pci_dev = this_dev;
			this_dl_dev->pci_dev->bus = &sfc_pci_bus[board_idx];

			aoe_add_device(this_dl_dev,
				       &aoe_res, new_dev);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
			memcpy(new_dev->dev_addr, new_dev->perm_addr, ETH_ALEN);
#else
			memcpy(new_dev->dev_addr, mac, ETH_ALEN);
#endif
		}
	}

	printk(KERN_ERR "sfc_aoe_sim: Sim driver loaded\n");

	return 0;

fail:
	aoe_dl_unregister();
	return -ENOMEM;
}

void aoe_dl_unregister(void)
{
	struct aoe_netdev *temp;
	struct aoe_netdev *aoe_net;

	list_for_each_entry_safe(aoe_net, temp, &fake_devs, list) {
		if (aoe_net) {
			unregister_netdev(aoe_net->netdev);
			free_netdev(aoe_net->netdev);
			list_del(&aoe_net->list);
		}
	}

	if (sfc_devs) {
		kfree(sfc_devs);
		sfc_devs = NULL;
	}

	if (sfc_pci_devs) {
		kfree(sfc_pci_devs);
		sfc_pci_devs = NULL;
	}

	if (sfc_pci_bus) {
		kfree(sfc_pci_bus);
		sfc_pci_bus = NULL;
	}
}

void aoe_mcdi_set_funcs(struct aoe_device *dev)
{
	/* leave as NULL */
}

void aoe_mcdi_set_ddr_funcs(struct aoe_dimm_info *dimm)
{
	/* leave as NULL */
}

void aoe_mcdi_set_port_funcs(struct aoe_port_info *port)
{
	/* leave as NULL */
}

/* Empty functions for linking */
int aoe_mcdi_fpga_reload(struct aoe_device *dev, int partition) { return 0; }
int aoe_setup_mmaps(struct aoe_device *to_add) { return 0; }
void aoe_destroy_mmaps(struct aoe_device *dev) { }
void aoe_remove_static_config(struct aoe_device *dev) { }
int aoe_qu_setup(struct aoe_device *dev, int queue_size) { return 0; }
void aoe_qu_destroy(struct aoe_device *dev) { }
void aoe_release_map_lock(struct aoe_map_entry *entry) { }
int aoe_mcdi_set_mtu(struct aoe_port_info *port, uint32_t aoe_mtu) { return 0; }
void aoe_netdev_unregister(struct aoe_device *dev) { }
void aoe_async_close(struct aoe_map_entry *entry) { }
int aoe_disable_stats_entries(struct aoe_map_entry *entry) { return 0; }
int aoe_netdev_register(struct aoe_device *dev,
			unsigned int int_macs,
			unsigned int ext_macs) { return 0; }
void setup_mcdi_handlers(struct aoe_map_entry *entry) { }
int aoe_apply_static_config(struct aoe_device *dev) { return 0; }
int aoe_stats_device_setup(struct aoe_device *aoe_dev) { return 0; }
void aoe_flush_mmaps(struct aoe_device *dev) { }
