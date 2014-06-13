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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2006-2010 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/pci.h>

#ifdef EFX_USE_KCOMPAT
# include "config.h"
# include "kernel_compat.h"
#endif

#include "driverlink_api.h"
#include "idle.h"
#include "efx.h"

/* High performance settings */
#define PCIE_MPL_HPERF 512 /* Max payload */
#define PCIE_MRR_HPERF 512 /* Max Read Request Size */
#define PARAM_DIS -1
#define PARAM_AUTO 0

/* Intel 5000 series specific register definitions */
#define PCI_5000_READ_MERGE_REG 0x48  /* 5000 chipset specific register */
#define PCI_5000_READ_MERGE_BIT 10    /* 5000 chipset specific field */

/*****************************************************************************/

/* Information about PCIe parameters being tweaked. */
struct efx_pcie_tweaks {
	/* Non-negative once we have found a parent bridge device */
	int bridge_vendor;
	int bridge_devid;

	/* Bridge requires disable read coalescing */
	int disable_bridge_read_coalesce;

	/* The bus which is being tuned. */
	struct pci_bus *bus;

	/* The slot on the bus which modified.  Since this is PCIe,
	 * we'd expect it to be zero, but you never know... */
	int slot;

	/* The maximum payload size supported by all devices seen so
	 * far as encoded in the device control register.  This is
	 * modified as devices are checked.  A value of -1 means that
	 * no change should be made. */
	int max_payload_size;

	/* The maximum read request size to be programmed into all
	 * functions on the device as encoded in the device control
	 * register.  A value of -1 means that no change should be
	 * made. */
	int max_read_request_size;
};


/*
 * PCIe maximum payload size
 *
 * If non-zero, tuning of the PCIe maximum payload size is enabled and
 * the maximum payload size is restricted to be no larger than this
 * parameter.  The same value is written to the root port and all
 * functions on the NIC and the value written is restricted to the
 * supported payload size of those components.  The value of this
 * parameter must be zero or a value listed in the PCIe specification.
 */
static int pcie_max_payload_size = PARAM_AUTO;

/*
 * PCIe maximum read size
 *
 * If non-zero, the PCIe maximum read request size on all functions of
 * every NIC are set to this value.  The value of this parameter must
 * be zero or listed in the PCIe specification.
 *
 */
static int pcie_max_read_request_size = PARAM_AUTO;

/*
 * Disable bridge read coalescing on Intel 5000 chipsets.
 *
 * Increasing the PCIe max payload size beyond 128 on an Intel 5000
 * chipset requires read coalescing to be disabled.
 */
static int disable_bridge_read_coalesce = PARAM_AUTO;

/*
 * Force the PCIe settings to be tweaked
 */
static unsigned int tweak_pcie = 0;

/*****************************************************************************/

static void efx_pcie_check_coalesce(struct efx_pcie_tweaks *tweaks)
{
	/* Check: http://pciids.sourceforge.net/ */
	tweaks->disable_bridge_read_coalesce =
		tweaks->disable_bridge_read_coalesce &&
		((tweaks->bridge_vendor == 0x8086)
		 && (tweaks->bridge_devid >= 0x25c0)
		 && (tweaks->bridge_devid <= 0x25FA));
}

static void efx_pcie_check_tweaks(struct pci_dev *dev,
				  struct efx_pcie_tweaks *tweaks)
{
	int pos;
	int rc;
	u16 dev_flags = -1;
	u16 dev_type;
	u32 dev_cap = -1;
	u32 dev_max_payload;

	/* This indicates that an error has already been
	 * encountered. */
	if (tweaks->max_payload_size == -1 &&
	    tweaks->max_read_request_size == -1)
		return;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (pos <= 0) {
		printk(KERN_INFO "Couldn't find PCIe capabilities of %s\n",
		       pci_name(dev));
		tweaks->max_read_request_size = -1;
		goto err_out;
	}

	/* Check the PCIe device/port type. */
	rc = pci_read_config_word(dev, pos + PCI_EXP_FLAGS, &dev_flags);
	if (rc) {
		printk(KERN_ERR "%s Error %d reading PCIe flags\n",
		       pci_name(dev), rc);
		goto err_out;
	}

	dev_type = (dev_flags & PCI_EXP_FLAGS_TYPE) >> 4;
	if (dev == tweaks->bus->self) {
		/* This is the root port (or a switch port).  For the
		 * moment, we don't handle switches.  The main reason
		 * is that updating registers on cards being managed
		 * by other drivers is a very dangerous thing to do
		 * rather than just a dangerous thing to do.  It's
		 * also a bit more awkward to find all the relevant
		 * devices.  PCIe switches are also uncommon enough
		 * that it's not worth the bother at the moment. */
		tweaks->bridge_vendor = dev->vendor;
		tweaks->bridge_devid = dev->device;
		if (dev_type != PCI_EXP_TYPE_ROOT_PORT) {
			printk(KERN_ERR
			       "PCIe port %s is not a root port (type %d)\n",
				pci_name(dev), dev_type);
			goto err_out;
		}
		efx_pcie_check_coalesce(tweaks);

	} else if (dev->bus == tweaks->bus &&
		   PCI_SLOT(dev->devfn) == tweaks->slot) {
		/* This is a function on the correct slot.  Slot is
		 * also know as device number and needs to be
		 * qualified by bus and function number to specify a
		 * particular function. */
		if (dev_type != PCI_EXP_TYPE_ENDPOINT &&
		    dev_type != PCI_EXP_TYPE_LEG_END) {
			printk(KERN_ERR
			       "%s PCIe device is not an endpoint (type %d)\n",
				pci_name(dev), dev_type);
			goto err_out;
		}

	} else {
		/* This is a function on a different slot.  This means
		 * there's something strange with the topology.  I
		 * thought PCIe was point-to-point. */
		printk(KERN_ERR "%s Can't tune performance of device\n",
			pci_name(dev));
		goto err_out;
	}

	/* Query the allowable maximum payload. */
	rc = pci_read_config_dword(dev, pos + PCI_EXP_DEVCAP, &dev_cap);
	if (rc) {
		printk(KERN_ERR "%s Error %d reading PCIe capabilities\n",
			pci_name(dev), rc);
		goto err_out;
	}

	/* The configured maximum payload size must be set to the same
	 * value for all devices and ports on the bus.  It mustn't
	 * exceed the maximum payload capability for any of the
	 * devices.  Here, we limit the payload size to the maximum
	 * supported by this device.  NB. The encodings used for the
	 * two fields are the same. */
	dev_max_payload = (dev_cap & PCI_EXP_DEVCAP_PAYLOAD) >> 0;
	if (tweaks->max_payload_size != -1 &&
	    tweaks->max_payload_size > dev_max_payload)
		tweaks->max_payload_size = dev_max_payload;

	return;

err_out:
	tweaks->max_payload_size = -1;
}


static void efx_pcie_perform_tweaks(struct pci_dev *dev,
				    const struct efx_pcie_tweaks *tweaks)
{
	int pos;
	int rc;
	int max_read_request_size = -1;
	int max_payload_size = -1;
	u16 dev_ctl_orig = -1;
	u16 dev_ctl = -1;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (pos <= 0) {
		printk(KERN_INFO "Couldn't find PCIe capabilities of %s\n",
			 pci_name(dev));
		goto err_out;
	}

	if (dev == tweaks->bus->self) {
		/* This is the root port.  Don't set the max read
		 * size.  Instead, disable read coalescing if
		 * required. */
		if (tweaks->disable_bridge_read_coalesce) {
			u16 read_merge, read_merge2;

			EFX_BUG_ON_PARANOID(tweaks->bridge_vendor !=
					    dev->vendor);
			EFX_BUG_ON_PARANOID(tweaks->bridge_devid !=
					    dev->device);
			pci_read_config_word(dev, PCI_5000_READ_MERGE_REG,
					     &read_merge);
			read_merge2 = read_merge;
			read_merge2 &= ~(1 << PCI_5000_READ_MERGE_BIT);
			printk(KERN_INFO "Changing PCIe read merging of %s "
				 "from 0x%x to 0x%x\n", pci_name(dev),
				 read_merge, read_merge2);
			pci_write_config_word(dev, PCI_5000_READ_MERGE_REG,
					      read_merge2);
		}

	} else if (dev->bus == tweaks->bus &&
		   PCI_SLOT(dev->devfn) == tweaks->slot) {
		/* This is a function on the correct slot.  Adjust the
		 * max read request.  Only adjust this on the device
		 * and not on the root port. */
		if (tweaks->max_read_request_size != -1) {
			printk(KERN_INFO "Setting PCIe max read request size"
				 " on %s to %d\n", pci_name(dev),
				 128 << tweaks->max_read_request_size);
			max_read_request_size = tweaks->max_read_request_size;
		}

	} else {
		/* This indicates a strange topology - we're not alone
		   on the bus. */
		if (tweaks->max_payload_size != -1)
			printk(KERN_ERR "%s Can't tune performance\n",
				pci_name(dev));
		goto err_out;
	}

	if (tweaks->max_payload_size != -1) {
		printk(KERN_INFO "Setting PCIe max payload size on %s to %d\n",
			 pci_name(dev), 128 << tweaks->max_payload_size);
		max_payload_size = tweaks->max_payload_size;
	}

	/* Update the configuration word as quickly as possible
	 * because there's no locking. */
	rc = pci_read_config_word(dev, pos + PCI_EXP_DEVCTL, &dev_ctl_orig);
	if (rc) {
		printk(KERN_ERR "%s Error %d reading PCIe control\n",
		       pci_name(dev), rc);
		goto err_out;
	}
	dev_ctl = dev_ctl_orig;

	if (max_payload_size != -1) {
		dev_ctl &= ~PCI_EXP_DEVCTL_PAYLOAD;
		dev_ctl |= tweaks->max_payload_size << 5;
	}

	if (max_read_request_size != -1) {
		dev_ctl &= ~PCI_EXP_DEVCTL_READRQ;
		dev_ctl |= max_read_request_size << 12;
	}

	if (dev_ctl != dev_ctl_orig) {
		rc = pci_write_config_word(dev, pos + PCI_EXP_DEVCTL, dev_ctl);
		if (rc) {
			printk(KERN_ERR "%s Error %d writing PCIe control\n",
				pci_name(dev), rc);
			goto err_out;
		}
	}

	return;

err_out:
	/* If something went wrong setting the payload size, the
	 * payload sizes on the bus will be inconsistent. */
	if (tweaks->max_payload_size != -1)
		printk(KERN_ERR "%s Performance tuning went wrong."
		       "  Expect badness.\n", pci_name(dev));
}


static void efx_pcie_tweak_performance(struct efx_dl_device *efx_dev,
				       const char *name)
{
	/* Traverse the PCI bus looking for registers to tweak. */
	struct efx_pcie_tweaks tweaks;
	struct pci_dev *root_dev;
	struct pci_dev *pci_dev;
	int mpl = ((pcie_max_payload_size != PARAM_AUTO) ?
		   pcie_max_payload_size : PCIE_MPL_HPERF);
	int mrr = ((pcie_max_read_request_size != PARAM_AUTO) ?
		   pcie_max_read_request_size : PCIE_MRR_HPERF);

	switch (mpl) {
	case PARAM_DIS:  tweaks.max_payload_size = -1; break;
	case 128:        tweaks.max_payload_size = 0;  break;
	case 256:        tweaks.max_payload_size = 1;  break;
	case 512:        tweaks.max_payload_size = 2;  break;
	case 1024:       tweaks.max_payload_size = 3;  break;
	case 2048:       tweaks.max_payload_size = 4;  break;
	case 4096:       tweaks.max_payload_size = 5;  break;
	default:
		printk(KERN_ERR "%s Invalid pcie_max_payload_size %d.\n",
			name, mpl);
		tweaks.max_payload_size = -1;
		break;
	}

	switch (mrr) {
	case PARAM_DIS: tweaks.max_read_request_size = -1; break;
	case 128:       tweaks.max_read_request_size = 0;  break;
	case 256:       tweaks.max_read_request_size = 1;  break;
	case 512:       tweaks.max_read_request_size = 2;  break;
	case 1024:      tweaks.max_read_request_size = 3;  break;
	case 2048:      tweaks.max_read_request_size = 4;  break;
	case 4096:      tweaks.max_read_request_size = 5;  break;
	default:
		printk(KERN_ERR "%s Invalid pcie_max_read_request_size %d.\n",
			name, mrr);
		tweaks.max_read_request_size = -1;
		break;
	}

	tweaks.disable_bridge_read_coalesce = (disable_bridge_read_coalesce
					       == PARAM_AUTO);

	tweaks.bridge_vendor = -1;
	tweaks.bridge_devid = -1;
	tweaks.bus = efx_dev->pci_dev->bus;
	tweaks.slot = PCI_SLOT(efx_dev->pci_dev->devfn);
	root_dev = tweaks.bus->self;
	if (!root_dev) {
		printk(KERN_ERR "%s PCI bus '%s' has no root port.\n",
			name, tweaks.bus->name);
		return;
	}

	if (tweaks.max_payload_size != -1 || tweaks.max_read_request_size != -1) {
		/* Check the values to be modified. */
		efx_pcie_check_tweaks(root_dev, &tweaks);
		pci_dev = NULL;
		while (1) {
			pci_dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID,
						 pci_dev);
			if (pci_dev == NULL)
				break;
			if (pci_dev->bus == tweaks.bus)
				efx_pcie_check_tweaks(pci_dev, &tweaks);
			/* No need to drop the reference to pci_dev
			 * here because it will be dropped by
			 * pci_get_device next time round the loop. */
		}
	}

	if (tweaks.max_payload_size != -1 || tweaks.max_read_request_size != -1) {
		/* Modify the values. */
		efx_pcie_perform_tweaks(root_dev, &tweaks);
		pci_dev = NULL;
		while (1) {
			pci_dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID,
						 pci_dev);
			if (pci_dev == NULL)
				break;
			if (pci_dev->bus == tweaks.bus)
				efx_pcie_perform_tweaks(pci_dev, &tweaks);
			/* No need to drop the reference to pci_dev
			 * here because it will be dropped by
			 * pci_get_device next time round the loop. */
		}
	}
#ifdef EFX_HAVE_PM_IDLE
	/* Enable the enhanced idle loop on Intel PCIe chipsets. */
	if (!xen_domain() &&
	    root_dev->vendor == 0x8086 &&
	    (efx_dev->pci_dev->device == PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0))
		efx_idle_enhance();
#endif
}


/*****************************************************************************/

static int efx_tweak_probe(struct efx_dl_device *efx_dev,
			   const struct net_device *net_dev,
			   const struct efx_dl_device_info *dev_info,
			   const char *silicon_rev)
{
	if ((efx_dev->pci_dev->device == PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0) ||
	    tweak_pcie)
		efx_pcie_tweak_performance(efx_dev, net_dev->name);

	return 0;
}

/*****************************************************************************/

static struct efx_dl_driver efx_tweak_driver = {
	.name = "sfc_tune",
	.priority = EFX_DL_EV_LOW,
	.probe = efx_tweak_probe,
};

static int __init efx_tweak_init_module(void)
{
#ifdef EFX_HAVE_PM_IDLE
	int rc;

	if ((rc = efx_idle_init()) != 0)
		return rc;
#endif

	return efx_dl_register_driver(&efx_tweak_driver);
}

static void __exit efx_tweak_exit_module(void)
{
	efx_dl_unregister_driver(&efx_tweak_driver);
#ifdef EFX_HAVE_PM_IDLE
	efx_idle_fini();
#endif
}

module_init(efx_tweak_init_module);
module_exit(efx_tweak_exit_module);

MODULE_AUTHOR("Solarflare Communications");
MODULE_DESCRIPTION("System tuning for high performance of SFC4000");
MODULE_LICENSE("GPL");

module_param(tweak_pcie, uint, 0644);
MODULE_PARM_DESC(tweak_pcie, "Force PCIe settings to be tuned");

module_param(pcie_max_payload_size, int, 0444);
MODULE_PARM_DESC(pcie_max_payload_size,
		 "PCIe maximum payload size or 0=>auto -1=>leave");

module_param(pcie_max_read_request_size, int, 0444);
MODULE_PARM_DESC(pcie_max_read_request_size,
		 "PCIe maximum read request size or 0=>auto -1=>leave");

module_param(disable_bridge_read_coalesce, int, 0444);
MODULE_PARM_DESC(disable_bridge_read_coalesce,
		 "Disable read coalescing on Intel 5000 chipset. 0=>auto -1=>leave");
