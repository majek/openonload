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
 * This file contains main driver entry points.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
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
#include "kernel_compat.h"
#include <ci/efrm/nic_table.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/falcon.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/driver_private.h>
#include <driver/linux_net/filter.h>
#include <ci/efrm/efrm_filter.h>

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");

static struct efhw_ev_handler ev_handler = {
	.wakeup_fn = efrm_handle_wakeup_event,
	.timeout_fn = efrm_handle_timeout_event,
	.dmaq_flushed_fn = efrm_handle_dmaq_flushed,
};

const int max_hardware_init_repeats = 10;

/*--------------------------------------------------------------------
 *
 * Module load time variables
 *
 *--------------------------------------------------------------------*/

#ifdef CONFIG_SFC_RESOURCE_VF
int claim_vf = 1;
module_param(claim_vf, int, S_IRUGO);
MODULE_PARM_DESC(claim_vf, "Set to 0 to prevent this driver from binding "
		 "to virtual functions");
#endif

/*--------------------------------------------------------------------
 *
 * Linux specific NIC initialisation
 *
 *--------------------------------------------------------------------*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
# define IRQ_PT_REGS_ARG   , struct pt_regs *regs __attribute__ ((unused))
#else
# define IRQ_PT_REGS_ARG
#endif

#ifndef IRQF_SHARED
# define IRQF_SHARED SA_SHIRQ
#endif

/* Allocate buffer table entries for a particular NIC.
 */
static int efrm_nic_buftbl_alloc(struct efrm_nic *efrm_nic)
{
	struct efhw_nic *nic = &efrm_nic->efhw_nic;
	int capacity;
	int page_order;
	int rc;

	/* Choose queue size. */
	for (capacity = 8192; capacity <= nic->q_sizes[EFHW_EVQ];
	     capacity <<= 1) {
		if (capacity > nic->q_sizes[EFHW_EVQ]) {
			EFRM_ERR
			    ("%s: Unable to choose EVQ size (supported=%x)",
			     __func__, nic->q_sizes[EFHW_EVQ]);
			return -E2BIG;
		} else if (capacity & nic->q_sizes[EFHW_EVQ])
			break;
	}

	nic->non_interrupting_evq.hw.capacity = capacity;
	nic->non_interrupting_evq.hw.buf_tbl_alloc.base = (unsigned)-1;

	/* allocate buffer table entries to map onto the iobuffer */
	page_order = get_order(capacity * sizeof(efhw_event_t));
	rc = efrm_nic_buffer_table_alloc(efrm_nic, page_order,
				 &nic->non_interrupting_evq.hw.buf_tbl_alloc);
	if (rc < 0) {
		EFRM_WARN
		    ("%s: failed (%d) to alloc %d buffer table entries",
		     __func__, rc, page_order);
		return rc;
	}

	return 0;
}

/* Free buffer table entries allocated for a particular NIC.
 */
static void efrm_nic_buftbl_free(struct efrm_nic *efrm_nic)
{
	struct efhw_nic *nic = &efrm_nic->efhw_nic;
	if (nic->non_interrupting_evq.hw.buf_tbl_alloc.base != (unsigned)-1)
		efrm_nic_buffer_table_free(efrm_nic,
				  &nic->non_interrupting_evq.hw.buf_tbl_alloc);
}

static int iomap_bar(struct linux_efhw_nic *lnic, size_t len)
{
	volatile char __iomem *ioaddr;

	ioaddr = ioremap_nocache(lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr, len);
	if (ioaddr == 0)
		return -ENOMEM;

	lnic->efrm_nic.efhw_nic.bar_ioaddr = ioaddr;
	return 0;
}

static int linux_efhw_nic_map_ctr_ap(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;

	rc = iomap_bar(lnic, nic->ctr_ap_bytes);

	/* Bug 5195: workaround for now. */
	if (rc != 0 && nic->ctr_ap_bytes > 16 * 1024 * 1024) {
		/* Try half the size for now. */
		nic->ctr_ap_bytes /= 2;
		EFRM_WARN("Bug 5195 WORKAROUND: retrying iomap of %d bytes",
			  nic->ctr_ap_bytes);
		rc = iomap_bar(lnic, nic->ctr_ap_bytes);
	}
	if (rc < 0) {
		EFRM_ERR("Failed (%d) to map bar (%d bytes)",
			 rc, nic->ctr_ap_bytes);
		return rc;
	}

	return rc;
}

static int
linux_efrm_nic_ctor(struct linux_efhw_nic *lnic, struct pci_dev *dev,
		    spinlock_t *reg_lock, unsigned nic_flags, int ifindex,
		    int bt_min, int bt_lim,
		    const struct vi_resource_dimensions *res_dim,
		    struct efhw_device_type dev_type)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;

	/* Initialise the adapter-structure. */
	efhw_nic_init(nic, nic_flags, NIC_OPT_DEFAULT, dev_type);
	lnic->efrm_nic.efhw_nic.pci_dev = dev;
	lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr =
		pci_resource_start(dev, nic->ctr_ap_bar);

	rc = linux_efhw_nic_map_ctr_ap(lnic);
	if (rc < 0)
		return rc;

	rc = efrm_nic_ctor(&lnic->efrm_nic, ifindex, bt_min, bt_lim, res_dim);
	if (rc < 0) {
		iounmap(nic->bar_ioaddr);
		return rc;
	}

	/* By default struct efhw_nic contains its own lock for protecting
	 * access to nic registers.  We override it with a pointer to the
	 * lock in the net driver.  This is needed when resource and net
	 * drivers share a single PCI function (falcon B series).
	 */
	nic->reg_lock = reg_lock;
	
	efrm_init_resource_filter(&dev->dev, ifindex);

	return 0;
}

static void linux_efrm_nic_dtor(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	volatile char __iomem *bar_ioaddr = nic->bar_ioaddr;

	efrm_nic_dtor(&lnic->efrm_nic);
	efhw_nic_dtor(nic);

	/* Unmap the bar. */
	EFRM_ASSERT(bar_ioaddr);
	iounmap(bar_ioaddr);
	nic->bar_ioaddr = 0;
	
	efrm_shutdown_resource_filter(&nic->pci_dev->dev);
}

static void efrm_dev_show(struct pci_dev *dev, int revision,
			  struct efhw_device_type dev_type, int ifindex,
			  int bt_min, int bt_lim,
			  const struct vi_resource_dimensions *res_dim)
{
	const char *dev_name = pci_name(dev) ? pci_name(dev) : "?";
	EFRM_NOTICE("%s pci_dev=%04x:%04x(%d) type=%d:%c%d ifindex=%d",
		    dev_name, (unsigned) dev->vendor, (unsigned) dev->device,
		    revision, dev_type.arch, dev_type.variant,
		    dev_type.revision, ifindex);
	EFRM_NOTICE("%s evq_timer=%d-%d buf_tbl=%d-%d rxq=%d-%d "
		    "txq=%d-%d rx_chans=%d", dev_name,
		    res_dim->evq_timer_min, res_dim->evq_timer_lim,
		    bt_min, bt_lim, res_dim->rxq_min, res_dim->rxq_lim,
		    res_dim->txq_min, res_dim->txq_lim,
		    res_dim->rss_channel_count);
}


/* A count of how many NICs this driver knows about. */
static int n_nics_probed;

/****************************************************************************
 *
 * efrm_nic_add: add the NIC to the resource driver
 *
 * NOTE: the flow of control through this routine is quite subtle
 * because of the number of operations that can fail. We therefore
 * take the apporaching of keeping the return code (rc) variable
 * accurate, and only do operations while it is non-negative. Tear down
 * is done at the end if rc is negative, depending on what has been set up
 * by that point.
 *
 * So basically just make sure that any code you add checks rc>=0 before
 * doing any work and you'll be fine.
 *
 ****************************************************************************/
int
efrm_nic_add(struct pci_dev *dev, unsigned flags, const uint8_t *mac_addr,
	     struct linux_efhw_nic **lnic_out, spinlock_t *reg_lock,
	     int bt_min, int bt_lim, int non_irq_evq,
	     const struct vi_resource_dimensions *res_dim, int ifindex,
             unsigned timer_quantum_ns)
{
	struct efhw_device_type dev_type;
	struct linux_efhw_nic *lnic = NULL;
	struct efrm_nic *efrm_nic = NULL;
	struct efhw_nic *nic = NULL;
	int count = 0, rc = 0, resources_init = 0;
	int constructed = 0;
	int registered_nic = 0;
	int buffers_allocated = 0;
	u8 class_revision;

	rc = pci_read_config_byte(dev, PCI_CLASS_REVISION, &class_revision);
	if (rc != 0) {
		EFRM_ERR("%s: pci_read_config_byte failed (%d)",
			 __func__, rc);
		return rc;
	}
	if (!efhw_device_type_init(&dev_type, dev->vendor, dev->device,
				   class_revision)) {
		EFRM_ERR("%s: efhw_device_type_init failed %04x:%04x(%d)",
			 __func__, (unsigned) dev->vendor,
			 (unsigned) dev->device, (int) class_revision);
		return -ENODEV;
	}

	efrm_dev_show(dev, class_revision, dev_type, ifindex,
		      bt_min, bt_lim, res_dim);

	if (n_nics_probed == 0) {
		rc = efrm_resources_init(res_dim);
		if (rc != 0)
			goto failed;
		resources_init = 1;
	} else {
#ifdef CONFIG_SFC_RESOURCE_VF
		unsigned vi_base, vi_scale, vf_count;

		/* VF check first, to set claim_vf properly */
		efrm_vf_manager_params(&vi_base, &vi_scale, &vf_count);
		if (res_dim->vf_vi_base != vi_base ||
		    res_dim->vf_vi_scale != vi_scale ||
		    res_dim->vf_count != vf_count) {
			EFRM_ERR("%s: ERROR: incompatible VF parameters: "
				 "vi_base %d vs %d, vi_scale %d vs %d, "
				 "vf_count %d vs %d", __func__,
				  res_dim->vf_vi_base, vi_base,
				  res_dim->vf_vi_scale, vi_scale,
				  res_dim->vf_count, vf_count);
			claim_vf = 0;
		}
#endif
	}

	/* Allocate memory for the new adapter-structure. */
	lnic = kmalloc(sizeof(*lnic), GFP_KERNEL);
	if (lnic == NULL) {
		EFRM_ERR("%s: ERROR: failed to allocate memory", __func__);
		rc = -ENOMEM;
		goto failed;
	}
	memset(lnic, 0, sizeof(*lnic));
	efrm_nic = &lnic->efrm_nic;
	nic = &efrm_nic->efhw_nic;

	lnic->ev_handlers = &ev_handler;

	/* OS specific hardware mappings */
	rc = linux_efrm_nic_ctor(lnic, dev, reg_lock, flags, ifindex,
				 bt_min, bt_lim, res_dim, dev_type);
	if (rc < 0) {
		EFRM_ERR("%s: ERROR: linux_efrm_nic_ctor failed (%d)",
			 __func__, rc);
		goto failed;
	}

	if( timer_quantum_ns )
		nic->timer_quantum_ns = timer_quantum_ns;

	constructed = 1;

	/* Tell the driver about the NIC - this needs to be done before the
	   resources managers get created below. Note we haven't initialised
	   the hardware yet, and I don't like doing this before the perhaps
	   unreliable hardware initialisation. However, there's quite a lot
	   of code to review if we wanted to hardware init before bringing
	   up the resource managers. */
	rc = efrm_driver_register_nic(efrm_nic);
	if (rc < 0) {
		EFRM_ERR("%s: ERROR: efrm_driver_register_nic failed (%d)",
			 __func__, rc);
		goto failed;
	}
	registered_nic = 1;

	rc = efrm_nic_buftbl_alloc(efrm_nic);
	if (rc != 0)
		goto failed;
	buffers_allocated = 1;

	/****************************************************/
	/* hardware bringup                                 */
	/****************************************************/
	/* Detecting hardware can be a slightly unreliable process;
	   we want to make sure that we maximise our chances, so we
	   loop a few times until all is good. */
	for (count = 0; count < max_hardware_init_repeats; count++) {
		rc = efhw_nic_init_hardware(nic, &ev_handler, mac_addr,
					    non_irq_evq);
		if (rc >= 0)
			break;

		/* pain */
		EFRM_TRACE("%s hardware init failed (%d, attempt %d of %d)",
			   pci_name(dev) ? pci_name(dev) : "?",
			   rc, count + 1, max_hardware_init_repeats);
	}
	if (rc < 0) {
		/* Again, PCI VFs may be available. */
		EFRM_ERR("%s: ERROR: hardware init failed rc=%d",
			 pci_name(dev) ? pci_name(dev) : "?", rc);
	}

	/* Tell NIC to spread wakeup events. */
	if (nic->devtype.arch == EFHW_ARCH_FALCON) {
		int n_int = 1;
		while ((n_int << 1) <= res_dim->rss_channel_count)
			n_int <<= 1;
		efrm_nic->falcon_wakeup_mask = n_int - 1;
		if (efrm_nic->falcon_wakeup_mask > 0)
			falcon_nic_wakeup_mask_set(nic,
					   efrm_nic->falcon_wakeup_mask);
	}
	efrm_nic->rss_channel_count = res_dim->rss_channel_count;

	EFRM_NOTICE("%s index=%d ifindex=%d",
		    pci_name(dev) ? pci_name(dev) : "?",
		    nic->index, nic->ifindex);

	*lnic_out = lnic;
	++n_nics_probed;
	return 0;

failed:
	if (buffers_allocated)
		efrm_nic_buftbl_free(efrm_nic);
	if (registered_nic)
		efrm_driver_unregister_nic(efrm_nic);
	if (constructed)
		linux_efrm_nic_dtor(lnic);
	kfree(lnic); /* safe in any case */
	if (resources_init)
		efrm_resources_fini();
	return rc;
}

/****************************************************************************
 *
 * efrm_nic_del: Remove the nic from the resource driver structures
 *
 ****************************************************************************/
void efrm_nic_del(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	EFRM_TRACE("%s:", __func__);
	EFRM_ASSERT(nic);

	efrm_vi_wait_nic_complete_flushes(nic);

	efrm_nic_buftbl_free(&lnic->efrm_nic);

	efrm_driver_unregister_nic(&lnic->efrm_nic);

	/* Close down hardware and free resources. */
	if (--n_nics_probed == 0)
		efrm_resources_fini();

	linux_efrm_nic_dtor(lnic);
	kfree(lnic);

	EFRM_TRACE("%s: done", __func__);
}


/****************************************************************************
 *
 * init_module: register as a PCI driver.
 *
 ****************************************************************************/
static int init_sfc_resource(void)
{
	int rc = 0;

	EFRM_TRACE("%s: RESOURCE driver starting", __func__);

	efrm_driver_ctor();
	efrm_filter_init();

	/* Register the driver so that our 'probe' function is called for
	 * each EtherFabric device in the system.
	 */
	rc = efrm_driverlink_register();
	if (rc == -ENODEV)
		EFRM_ERR("%s: no devices found", __func__);
	if (rc < 0)
		goto failed_driverlink;

	if (efrm_install_proc_entries() != 0) {
		/* Do not fail, but print a warning */
		EFRM_WARN("%s: WARNING: failed to install /proc entries",
			  __func__);
	}
	efrm_filter_install_proc_entries();
	
#ifdef CONFIG_SFC_RESOURCE_VF
	efrm_vf_driver_init();
#endif

	return 0;

failed_driverlink:
	efrm_driver_stop();
	efrm_filter_shutdown();
	efrm_driver_dtor();
	return rc;
}

/****************************************************************************
 *
 * cleanup_module: module-removal entry-point
 *
 ****************************************************************************/
static void cleanup_sfc_resource(void)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	efrm_vf_driver_fini();
#endif

	efrm_filter_shutdown();
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();

	efrm_driver_stop();

	efrm_driverlink_unregister();

	/* Clean up char-driver specific initialisation.
	   - driver dtor can use both work queue and buffer table entries */
	efrm_driver_dtor();

	EFRM_TRACE("%s: unloaded", __func__);
}

module_init(init_sfc_resource);
module_exit(cleanup_sfc_resource);
