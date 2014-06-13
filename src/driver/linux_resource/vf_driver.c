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
 *          PCI virtual function management
 *
 * This file contains PCI driver for VF.
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

#include <linux/init.h>
#include "linux_resource_internal.h"
#include <linux/stat.h>
#ifdef CONFIG_IOMMU_API
# include <linux/iommu.h>
# include <linux/acpi.h>
#endif

#include <ci/efrm/nic_table.h>
#include <ci/efhw/iopage.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/vf_resource_private.h>

#define EFX_USE_KCOMPAT
#include <driver/linux_net/efx.h> /* for various definitions */
#include "vfdi.h"
#include <driver/linux_net/regs.h> /* for FR_CZ_USR_EV */
#define EFX_IRQ_MOD_RESOLUTION 5
#include "kernel_compat.h"

#ifndef __devinitconst
# ifdef __devinitdata
#  define __devinitconst __devinitdata
# else
#  define __devinitconst
# endif
#endif


#ifdef CONFIG_PCI_IOV

struct vf_init_status {
	struct efhw_iopage req;
	struct efhw_iopage status;
	unsigned int req_seq;
	struct efrm_vf *vf;
};

extern int unsafe_sriov_without_iommu;
extern int claim_vf;
#if defined(CONFIG_IOMMU_API)
static int checked_vfs_bound;
static const char *sfc_resource_vfs_bound = "/dev/shm/sfc_resource_vfs_bound";
#endif

/****************************************************************************
 *
 * PCI IDs and init
 *
 ****************************************************************************/
static DEFINE_PCI_DEVICE_TABLE(efrm_pci_vf_table) = {
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1000 | 0x0803)},/* SFC9020 */
	{PCI_DEVICE(PCI_VENDOR_ID_SOLARFLARE, 0x1000 | 0x0813)},/* SFL9021 */
	{0}			/* end of list */
};
MODULE_DEVICE_TABLE(pci, efrm_pci_vf_table);


#ifdef CONFIG_IOMMU_API
static const char  __devinitconst iommu_err3[] = \
"Due to issues observed in testing on systems using the intel_iommu driver,\n"\
EFRM_PRINTK_PREFIX\
"rebinding to VFs (often due to a driver reload) has been prevented. Hence\n"\
EFRM_PRINTK_PREFIX\
"the extended buffer addressing feature (i.e. EF_PACKET_BUFFER_MODE=1)\n"\
EFRM_PRINTK_PREFIX\
"will not work until the system is rebooted. Onload will still be functional\n"\
EFRM_PRINTK_PREFIX\
"in all other ways";
#endif


/****************************************************************************
 *
 * Map BAR
 *
 ****************************************************************************/
static int __devinit vf_map_bar(struct efrm_vf *vf)
{
	int rc = -ENOTSUPP;
	uint64_t dma_mask;
	resource_size_t membase;
	void *ptr;

	/* TODO: How do we know that the mask is? */
	for (dma_mask = DMA_BIT_MASK(46); dma_mask > 0x7fffffffUL;
	     dma_mask >>= 1) {
		if (pci_dma_supported(vf->pci_dev, dma_mask) &&
		    ((rc = pci_set_dma_mask(vf->pci_dev, dma_mask)) == 0))
			break;
	}
	BUG_ON(rc);
	rc = pci_set_consistent_dma_mask(vf->pci_dev, dma_mask);
	BUG_ON(rc);

	if (!pci_resource_start(vf->pci_dev, 0))
		return -ENODEV;

	membase = pci_resource_start(vf->pci_dev, 0);
	rc = pci_request_region(vf->pci_dev, 0, "sfc_resource");
	if (rc) {
		EFRM_ERR("%s: failed reserving bar %d rc %d\n",
			 pci_name(vf->pci_dev), 0, rc);
		return rc;
	}

	ptr = ioremap_nocache(membase, pci_resource_len(vf->pci_dev, 0));
	if (!ptr) {
		EFRM_ERR("%s: failed mapping bar %d rc %d\n",
			 pci_name(vf->pci_dev), 0, rc);
		pci_release_region(vf->pci_dev, 0);
		return -ENOMEM;
	}
	vf->bar = ptr;
	EFRM_TRACE("%s: map BAR0 %p", pci_name(vf->pci_dev), vf->bar);

	return 0;
}

static void vf_unmap_bar(struct efrm_vf *vf)
{
	if (vf->bar) {
		iounmap(vf->bar);
		vf->bar = NULL;

		pci_release_region(vf->pci_dev, 0);
	}
}

/****************************************************************************
 *
 * Probe IRQ
 *
 * Tradeoff: enable all interrupts at once (possibly, unnecessary) or
 * enable/disbale them on every allocation.
 * Let's keep in the middle: enable once, but only when necessary.
 *
 ****************************************************************************/
int efrm_vf_interrupts_probe(struct efrm_vf *vf)
{
	struct pci_dev *pci_dev = vf->pci_dev;
	struct msix_entry *msix;
	int pos, rc;
	u16 control;

	msix = kmalloc(sizeof(*msix) * vf->vi_count, GFP_KERNEL);
	if (!msix)
		return -ENOMEM;

	/* Probe the number of interrupts support */
	pos = pci_find_capability(pci_dev, PCI_CAP_ID_MSIX);
	pci_read_config_word(pci_dev, pos + PCI_MSI_FLAGS, &control);
	vf->irq_count = min((u8)((control & PCI_MSIX_FLAGS_QSIZE) + 1),
				 vf->vi_count);
	if (vf->irq_count == 0) {
		rc = -ENOMEM;
		goto fail;
	}

	for (pos = 0; pos < vf->irq_count; pos++)
		msix[pos].entry = pos;
	rc = pci_enable_msix(pci_dev, msix, vf->irq_count);
	if (rc > 0) {
		vf->irq_count = rc;
		rc = pci_enable_msix(pci_dev, msix, rc);
	}
	if (rc != 0)
		goto fail;
	for (pos = 0; pos < vf->irq_count; pos++) {
		vf->vi[pos].irq = msix[pos].vector;
		vf->vi[pos].index = pos;
	}
	kfree(msix);

	EFRM_ASSERT(vf->vi_count);
	EFRM_NOTICE("%s: vi_count=%d irq_count=%d",
		    pci_name(vf->pci_dev), vf->vi_count, vf->irq_count);
	vf->vi_count = min(vf->vi_count, vf->irq_count);
	return 0;

fail:
	EFRM_ERR("%s: failed to probe interrupts rc %d",
		 pci_name(vf->pci_dev), rc);
	pci_disable_msix(pci_dev); /* just to be sure */
	kfree(msix);
	vf->irq_count = vf->vi_count = 0;
	return rc;
}


/*********************************************************************
 *
 * VFDI
 * We should move this to lib/efrm, since VFDI interface is OS-independent.
 * However, it is currently defined in driver/linux_net/vfdi.h, so no luck.
 *
 *********************************************************************/
static int __devinit vf_vfdi_req(struct vf_init_status *vf_ini)
{
	struct vfdi_req *req = vf_ini->req.kva;
	unsigned int op = req->op;
	unsigned data, type;
	efx_dword_t dword;
	unsigned long retry;

	BUG_ON(op == VFDI_OP_RESPONSE);
	req->rc = 0;
	mmiowb();	/* Order writes with MC reads */

	for (type = 0; type < 4; ++type) {
		data = (unsigned)((u64)vf_ini->req.dma_addr >> (type << 4));
		EFX_POPULATE_DWORD_3(dword,
				     VFDI_EV_SEQ, vf_ini->req_seq & 0xff,
				     VFDI_EV_TYPE, type,
				     VFDI_EV_DATA, data & 0xffff);
		writel(dword.u32[0], vf_ini->vf->bar + FR_CZ_USR_EV);
		wmb();
		vf_ini->req_seq++;
	}

	/* Wait up to 2s for the reply.
	 * We must use _uninterruptible() since we may be called when
	 * the process is killed. */
	for (retry = 1; retry < msecs_to_jiffies(2000); retry<<=1) {
		schedule_timeout_uninterruptible(retry);
		if (req->op == VFDI_OP_RESPONSE) {
			EFRM_TRACE("%s: op %d took %d ms rc %d",
				   pci_name(vf_ini->vf->pci_dev), op,
				   jiffies_to_msecs(retry) << 1, req->rc);
			return req->rc;
		}
	}

	EFRM_ERR("%s: Timed out op %d", pci_name(vf_ini->vf->pci_dev), op);
	return -ETIMEDOUT;
}

/* Read the status page in an atomic fashion */
static int __devinit vf_refresh_status(struct vf_init_status *vf_ini)
{
	struct vfdi_status *status = vf_ini->status.kva;
	struct efrm_vf *vf = vf_ini->vf;
	u32 generation_start, generation_end;
	unsigned int retry;

	if (status->version != 1 || status->length < sizeof(*status)) {
		EFRM_ERR("%s: Invalid status page",
			 pci_name(vf->pci_dev));
		return -EINVAL;
	}

	/* Keep reading the status page until the generation count stops
	 * changing */
	for (retry = 0; retry < 10000; ++retry) {
		generation_end = status->generation_end;
		rmb();

		/* From all the peers addresses, the only thing we need is
		 * the master address, which is assumed to be the first
		 * peer.
		 */
		memcpy(vf->mac_addr, status->peers->mac_addr, ETH_ALEN);
 
		vf->vi_scale = status->vi_scale;
		EFRM_ASSERT((1 << vf->vi_scale) <= EFRM_VF_MAX_VI_COUNT);
		vf->vi_count = 1 << vf->vi_scale;

		rmb();
		generation_start = status->generation_start;
		if (generation_start == generation_end)
			goto done;

		/* Spin for up to 10ms in total */
		if ((retry - 1) % 100 == 0)
			udelay(100);
	}

	return -ETIMEDOUT;

done:
	EFRM_NOTICE("%s: master MAC "MAC_ADDR_FMT, pci_name(vf->pci_dev),
		    MAC_ADDR_VAL(vf->mac_addr));
	return 0;
}

static void __devinit vf_fini_status(struct vf_init_status *vf_ini)
{
	struct vfdi_req *req = vf_ini->req.kva;
	req->op = VFDI_OP_CLEAR_STATUS_PAGE;
	vf_vfdi_req(vf_ini);
}

static int __devinit vf_init_status(struct vf_init_status *vf_ini)
{
	struct efrm_vf *vf = vf_ini->vf;
	struct vfdi_req *req = vf_ini->req.kva;
	int rc;

	req->op = VFDI_OP_SET_STATUS_PAGE;
	req->u.set_status_page.dma_addr = vf_ini->status.dma_addr;
	req->u.set_status_page.peer_page_count = 0;

	rc = vf_vfdi_req(vf_ini);
	if (rc != 0)
		goto fail1;

	/* For now sfc guarantees to DMA in a status page before it completes
	 * the vfdi request */
	rc = vf_refresh_status(vf_ini);
	if (rc)
		goto fail2;

	EFRM_TRACE("%s: vi_scale=%d vi_count=%d",
		   pci_name(vf->pci_dev), vf->vi_scale, vf->vi_count);
	return 0;

fail2:
	vf_fini_status(vf_ini);
fail1:
	EFRM_ERR("%s %s: failed rc=%d", pci_name(vf->pci_dev),
		__func__, rc);
	return rc;
}


/****************************************************************************
 *
 * Probe
 *
 ****************************************************************************/
#ifdef CONFIG_IOMMU_API
static const char  __devinitconst iommu_err1[] = \
"If you wish to use the 'onload extended packet buffer addressing'\n"\
EFRM_PRINTK_PREFIX\
"feature then please:\n"\
EFRM_PRINTK_PREFIX\
"  1) ensure that 'ACPI: DMAR' (Intel) or 'ACPI: IVRS' (AMD) is reported\n"\
EFRM_PRINTK_PREFIX\
"     during kernel boot. Otherwise please check your BIOS settings\n"\
EFRM_PRINTK_PREFIX\
"  2) ensure that 'iommu=on,pt' and 'amd_iommu=on' or 'intel_iommu=on' is\n"\
EFRM_PRINTK_PREFIX\
"     added to your kernel command line\n"\
EFRM_PRINTK_PREFIX\
"Alternatively to use extended packet buffer addressing feature without\n"\
EFRM_PRINTK_PREFIX\
"IOMMU protection set the sfc_resource kernel module option\n"\
EFRM_PRINTK_PREFIX\
"     'unsafe_sriov_without_iommu=1'";
#else
static const char  __devinitconst iommu_err2[] = \
"This kernel does not have IOMMU support. This is true for all real-time\n"\
EFRM_PRINTK_PREFIX\
"kernels and is otherwise a kernel compile time option.\n"\
EFRM_PRINTK_PREFIX\
"To use the 'onload extended packet buffer addressing' feature either:\n"\
EFRM_PRINTK_PREFIX\
"  1) change to a kernel with this feature\n"\
EFRM_PRINTK_PREFIX\
"  2) Set the sfc_resource kernel module option\n"\
EFRM_PRINTK_PREFIX\
"     'unsafe_sriov_without_iommu=1'";
#endif


#ifdef CONFIG_IOMMU_API
static inline int use_iommu(struct pci_dev *pci_dev) {
  return !unsafe_sriov_without_iommu && iommu_present(pci_dev->dev.bus);
}
#endif


static int __devinit vf_alloc_page(struct vf_init_status *vf_ini,
				   const char *type,
				   struct efhw_iopage *iommu_mapping)
{
	struct pci_dev *pci_dev = vf_ini->vf->pci_dev;
	int rc = 0;
#ifdef CONFIG_IOMMU_API
	struct efrm_vf *vf = vf_ini->vf;
	if (use_iommu(pci_dev)) {
		struct page *page = alloc_page(GFP_KERNEL);
		if (!page) {
			EFRM_ERR("%s %s: failed to allocate VFDI %s page",
				 pci_name(pci_dev), __func__, type);
			return -ENOMEM;
		}
		iommu_mapping->kva = page_address(page);
		iommu_mapping->dma_addr = efrm_vf_alloc_ioaddrs(vf, 1, NULL);
		rc = iommu_map(vf->iommu_domain, iommu_mapping->dma_addr,
			       page_to_phys(page), 0, vf->iommu_prot);
		if (rc) {
			EFRM_ERR("%s %s: failed IOMMU mapping VFDI %s page: %d",
				 pci_name(pci_dev), __func__, type, rc);
			__free_page(page);
			return rc;
		}
	} else
#endif
	{
		iommu_mapping->kva =
			pci_alloc_consistent(pci_dev, PAGE_SIZE,
					     &iommu_mapping->dma_addr);
		if (iommu_mapping->kva == NULL) {
			EFRM_ERR("%s %s: failed allocate VFDI %s page: %d",
				 pci_name(pci_dev), __func__, type, rc);
			return -ENOMEM;
		}
	}
	return 0;
}


static void __devinit vf_free_page(struct vf_init_status *vf_ini,
				   struct efhw_iopage *iommu_mapping)
{
	struct pci_dev *pci_dev = vf_ini->vf->pci_dev;
#ifdef CONFIG_IOMMU_API
	if (use_iommu(pci_dev)) {
		int rc;
		rc = iommu_unmap(vf_ini->vf->iommu_domain,
				 iommu_mapping->dma_addr, 0);
		EFRM_ASSERT(rc == 0);
		free_page((unsigned long)iommu_mapping->kva);
	} else
#endif
        {
	pci_free_consistent(pci_dev, PAGE_SIZE, iommu_mapping->kva,
			    iommu_mapping->dma_addr);
	}
}


#ifdef CONFIG_IOMMU_API
static int __devinit check_intel_iommu_bind_once(void)
{
# if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
	struct acpi_table_header *acpi_dmar;

	/* "intel_iommu_enabled" symbol not always available */
	if (ACPI_FAILURE(acpi_get_table("DMAR", 0, &acpi_dmar)))
		return 0;
# else
	/* Cannot detect if Intel IOMMU is in use; hence assume yes */
# endif

	/*
	 * SFC bug 27457: the intel-iommu driver is often seen to fault after
	 * the second time a VF is assigned to a freshly created IOMMU domain
	 * Also oopses have been seen within the IOMMU API calls on repeated
	 * reload. For safety do not rebind to VFs in this case
	 * Use file in /dev/shm as this is hopefully tmpfs backed (yuk)
	 */
	if (!checked_vfs_bound) {
		struct file *file;
		checked_vfs_bound = 1;
		file = filp_open(sfc_resource_vfs_bound, O_RDWR | O_CREAT |
				 O_EXCL, S_IRWXU);
		if (IS_ERR(file)) {
			claim_vf = 0;
			EFRM_WARN("%s", iommu_err3);	
			EFRM_WARN("At your own risk disable this safety check;"
				  " rm '%s'", sfc_resource_vfs_bound);
			return -ENODEV;
		} else {
			filp_close(file, NULL);
		}
	}
	return 0;
}
#endif


static int __devinit efrm_pci_vf_probe(struct pci_dev *pci_dev,
				       const struct pci_device_id *entry)
{
	int rc;
	struct efrm_vf *vf;
	struct vf_init_status vf_ini;

	/* Check if we really want to bind to this VF */
	if (!claim_vf)
		return -ENODEV;

#ifdef CONFIG_IOMMU_API
	if (!unsafe_sriov_without_iommu) {
		if (!iommu_present(pci_dev->dev.bus)) {
			EFRM_WARN_ONCE("Prevent use of VFs (e.g. %s) as IOMMU "
				       "not found", pci_name(pci_dev));
			EFRM_WARN_ONCE("%s", iommu_err1);
			return -ENODEV;
		}

		rc = check_intel_iommu_bind_once();
		if (rc != 0)
			return rc;

		/* SFC bug 29357: Need to prevent wrap-around */
		if (sizeof(vf->iova_base) < 8) {
			EFRM_WARN_ONCE("Prevent use of VFs (e.g. %s) as not a "
				       "64bit platform", pci_name(pci_dev));
			return -ENODEV;
		}
	}
#else
	if (!unsafe_sriov_without_iommu) {
		EFRM_WARN_ONCE("Prevent use of VFs (e.g. %s) as IOMMU APIs not "
			       "present in your kernel", pci_name(pci_dev));
		EFRM_WARN_ONCE("%s", iommu_err2);
		return -ENODEV;
	}
#endif
	if (unsafe_sriov_without_iommu) {
		EFRM_WARN_ONCE("Using VFs (e.g. %s) but without IOMMU "
			       "protection", pci_name(pci_dev));
	}

	vf = kzalloc(sizeof(*vf), GFP_KERNEL);
	if (vf == NULL) {
		EFRM_ERR("%s %s: failed to allocate memory",
			 pci_name(pci_dev), __func__);
		return -ENOMEM;
	}
	vf->pci_dev = pci_dev;
	vf->pci_dev_fn = pci_dev->devfn;

#ifdef CONFIG_IOMMU_API
	if (use_iommu(pci_dev)) {
		vf->iommu_domain = iommu_domain_alloc(pci_dev->dev.bus);
		if (!vf->iommu_domain) {
			EFRM_ERR("%s %s: failed to allocate IOMMU domain",
				 pci_name(pci_dev), __func__);
			rc = -ENOMEM;
			goto fail1;
		}

		vf->iommu_prot = IOMMU_READ | IOMMU_WRITE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
		if (iommu_domain_has_cap(vf->iommu_domain,
					 IOMMU_CAP_CACHE_COHERENCY))
			vf->iommu_prot |= IOMMU_CACHE;
#elif defined(RHEL_MAJOR) && defined(IOMMU_CACHE)
		/*
		 * Missing from the RHEL5 IOMMU API although present in .h
		 * Only the intel-iommu driver is sensitive to this flag
		 * Set IOMMU_CACHE to be most consistent across distros
		 */
		vf->iommu_prot |= IOMMU_CACHE;
#endif

		rc = iommu_attach_device(vf->iommu_domain, &pci_dev->dev);
		if (rc != 0) {
			EFRM_ERR("%s %s: failed to attach to IOMMU domain",
				 pci_name(pci_dev), __func__);
			goto fail2;
		}
	}
#endif

	rc = pci_enable_device(pci_dev);
	if (rc) {
		EFRM_ERR("%s %s: failed to enable PCI VF: %d",
			pci_name(pci_dev), __func__, rc);
		goto fail3;
	}

	pci_set_master(pci_dev);

	/* Map the BAR */
	rc = vf_map_bar(vf);
	if (rc != 0) {
		EFRM_ERR("%s %s: failed to map PCI BAR for VF: %d",
			pci_name(pci_dev), __func__, rc);
		goto fail4;
	}

	/* Allocate VFDI req and status pages. */
	vf_ini.vf = vf;
	vf_ini.req_seq = 0;

	EFRM_BUILD_ASSERT(sizeof(struct vfdi_req) <= PAGE_SIZE);
	rc = vf_alloc_page(&vf_ini, "req", &vf_ini.req);
	if (rc != 0)
		goto fail5;

	EFRM_BUILD_ASSERT(sizeof(struct vfdi_status) <= PAGE_SIZE);
	rc = vf_alloc_page(&vf_ini, "status", &vf_ini.status);
	if (rc != 0)
		goto fail6;

	/* Init status page */
	rc = vf_init_status(&vf_ini);
	if (rc != 0) {
		EFRM_ERR("%s %s: failed to init status page: %d",
			pci_name(pci_dev), __func__, rc);
		goto fail7;
	}

	vf_fini_status(&vf_ini);
	vf_free_page(&vf_ini, &vf_ini.status);
	vf_free_page(&vf_ini, &vf_ini.req);


	rc = efrm_vf_probed(vf);
	if (rc != 0) {
		EFRM_ERR("%s %s: failed to register VF: %d",
			pci_name(pci_dev), __func__, rc);
		goto fail5;
	}
	pci_set_drvdata(pci_dev, vf);

	return 0;

fail7:
	vf_free_page(&vf_ini, &vf_ini.status);
fail6:
	vf_free_page(&vf_ini, &vf_ini.req);
fail5:
	vf_unmap_bar(vf);
fail4:
	/* pci_clear_master is called from pci_disable_device */
	pci_disable_device(pci_dev);
fail3:
#ifdef CONFIG_IOMMU_API
	if (use_iommu(pci_dev))
		iommu_detach_device(vf->iommu_domain, &pci_dev->dev);
fail2:
	if (use_iommu(pci_dev))
		iommu_domain_free(vf->iommu_domain);
fail1:
#endif
	kfree(vf);
	return rc;
}

static void __devinit efrm_pci_vf_remove(struct pci_dev *pci_dev)
{
	struct efrm_vf *vf = pci_get_drvdata(pci_dev);
	int vi_count_saved = 0;

	if( vf->rs.rs_ref_count != 0 ) {
		int i;
		EFRM_ERR("Attempt to remove PCI VF %s while it is in use",
			 pci_name(vf->pci_dev));
		WARN_ON_ONCE(1);
		for (i = 0; i < vf->vi_count; i++) {
			struct efrm_vf_vi *vi = &vf->vi[i];
			if (vi->virs->evq_callback_fn != NULL)
				efrm_vf_eventq_callback_kill(vi->virs);
		}
		vi_count_saved = vf->vi_count;
		vf->vi_count = 0;
	}

	efrm_vf_removed(vf);
	if (vi_count_saved)
		vf->vi_count = vi_count_saved;

	pci_disable_msix(pci_dev);
	pci_set_drvdata(pci_dev, NULL);

	vf_unmap_bar(vf);
	/* pci_clear_master is called from pci_disable_device */
	pci_disable_device(pci_dev);

#ifdef CONFIG_IOMMU_API
	/*
	 * If not using kernel params "intel_iommu=on,strict" OR
	 * "amd_iommu=on,fullflush" this may lazily flush the IOTLB; but
	 * considering that the VF device has been disabled above this is safe
	 */
	if (use_iommu(pci_dev)) {
		iommu_detach_device(vf->iommu_domain, &pci_dev->dev);
		iommu_domain_free(vf->iommu_domain);
	}
#endif
	kfree(vf);
}


/*********************************************************************
 *
 * VI management:
 * Queue allocation
 *
 *********************************************************************/

void efrm_vf_vi_drop(struct efrm_vi *virs)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];

	EFRM_ASSERT(virs->allocation.instance >= vf->vi_base);
	EFRM_ASSERT(virs->allocation.instance < vf->vi_base + vf->vi_count);
	EFRM_ASSERT(vi->virs == virs);

	if (vi->virs->evq_callback_fn != NULL)
		efrm_vf_eventq_callback_kill(virs);

	vi->virs = NULL;
}

/*********************************************************************
 *
 * VI management: IRQ affinity
 *
 *********************************************************************/

irqreturn_t no_action(int cpl, void *dev_id
#if defined(EFX_HAVE_IRQ_HANDLER_REGS)
	, struct pt_regs *regs __attribute__ ((unused))
#endif
	)
{
        return IRQ_NONE;
}
static int efrm_vf_vi_set_cpu_affinity_via_proc(struct efrm_vi *virs, int cpu)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];
	char *content, filename[32];
	int content_len, rc = 0;
	struct file *file;
	mm_segment_t old_fs;
	loff_t offset = 0;
	ssize_t written;

	if (cpu < 0 || cpu >= num_online_cpus())
		return -EINVAL;

	/* Write the mask into a sufficient buffer. We need a byte
	 * for every 4 bits of mask, plus comma's, plus a NULL. */
	content_len = max(NR_CPUS, 8) / 2;
	content = kmalloc(content_len, GFP_KERNEL);
	if (!content)
		return -ENOMEM;
#ifdef EFX_HAVE_OLD_CPUMASK_SCNPRINTF
	{
		cpumask_t mask = cpumask_of_cpu(cpu);
		cpumask_scnprintf(content, content_len, mask);
	}
#else
	cpumask_scnprintf(content, content_len, cpumask_of(cpu));
#endif

	/* Open /proc/irq/XXX/smp_affinity */
	snprintf(filename, sizeof(filename), "/proc/irq/%d/smp_affinity",
		 vi->irq);
	file = filp_open(filename, O_RDWR, 0);
	if (IS_ERR(file)) {
		EFRM_TRACE("%s could not open %s: %ld; try request_irq(%d)",
			   pci_name(vf->pci_dev), filename, PTR_ERR(file),
			   vi->irq);
		rc = request_irq(vi->irq, no_action, IRQF_DISABLED,
				 vi->name, NULL);
		if (rc == 0)
			free_irq(vi->irq, NULL);
		file = filp_open(filename, O_RDWR, 0);
	}

	if (IS_ERR(file)) {
		EFRM_ERR("%s ERROR: could not open %s: error %ld",
			 pci_name(vf->pci_dev), filename, PTR_ERR(file));
		rc = -EIO;
		goto out1;
	}

	/* Write cpumask to file */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	written = file->f_op->write(file, (__force __user char *)content,
				    content_len, &offset);
	set_fs(old_fs);

	if (written != content_len) {
		EFRM_ERR("%s ERROR: unable to write affinity for interrupt %d",
			 pci_name(vf->pci_dev), vi->irq);
		rc = -EIO;
		goto out2;
	}

	EFRM_TRACE("%s: set interrupt %d affinity\n",
		   pci_name(vf->pci_dev), vi->irq);

out2:
	filp_close(file, NULL);
out1:
	kfree(content);
	return rc;
}


#if defined(CONFIG_KALLSYMS) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)

/* Fixme: export efrm_find_ksym and use it in onload module */
#include <linux/kallsyms.h>
struct efrm_ksym_name {
	const char *name;
	void *addr;
};
static int efrm_check_ksym(void *data, const char *name, struct module *mod,
			  unsigned long addr)
{
	struct efrm_ksym_name *t = data;
	if( strcmp(t->name, name) == 0 ) {
		t->addr = (void *)addr;
		return 1;
	}
	return 0;
}
static void *efrm_find_ksym(const char *name)
{
	struct efrm_ksym_name t;
        
	t.name = name;
	t.addr = NULL;
	kallsyms_on_each_symbol(efrm_check_ksym, &t);
	if (t.addr == NULL)
		EFRM_ERR("%s: Can't find symbol %s", __func__, t.name);
	return t.addr;
}

int efrm_vf_vi_set_cpu_affinity(struct efrm_vi *virs, int cpu)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];
	const struct cpumask *mask;
	static int (*irq_set_affinity)(unsigned int irq,
				       const struct cpumask *mask);

	if (irq_set_affinity == NULL)
		irq_set_affinity = efrm_find_ksym("irq_set_affinity");
	if (irq_set_affinity == NULL)
		return efrm_vf_vi_set_cpu_affinity_via_proc(virs, cpu);

	if (cpu < 0 || cpu >= num_online_cpus())
		return -EINVAL;
	mask = cpumask_of(cpu);
	if (!cpumask_intersects(mask, cpu_online_mask))
		return -EINVAL;
	return irq_set_affinity(vi->irq, mask);
}
#else
/* In reality, this is RHEL5 only.  SRIOV is not present in <2.6.30
 * in vanilla kernels, but 2.6.18 in RHEL5 has CONFIG_PCI_IOV.
 * CONFIG_KALLSYMS is on almost everywhere. */
#include <linux/kthread.h>
struct efrm_virs_affinity {
	struct efrm_vi *virs;
	int cpu;
	int rc;
	struct completion exit;
};
static int efrm_vf_vi_set_cpu_affinity_kthread(void *data)
{
	struct efrm_virs_affinity *aff = data;

	aff->rc = efrm_vf_vi_set_cpu_affinity_via_proc(aff->virs, aff->cpu);
	complete_and_exit(&aff->exit, aff->rc);
	return 0;
}
int efrm_vf_vi_set_cpu_affinity(struct efrm_vi *virs, int cpu)
{
	struct efrm_virs_affinity aff;
	struct task_struct *kt;

	aff.virs = virs;
	aff.cpu = cpu;
	init_completion(&aff.exit);
	kt = kthread_create(efrm_vf_vi_set_cpu_affinity_kthread, &aff,
			    __func__);
	if (kt == NULL)
		return -ENOMEM;
	wake_up_process(kt);
	wait_for_completion(&aff.exit);
	return aff.rc;
}
#endif


/*********************************************************************
 *
 * VI management: IRQ moderation and callback
 *
 *********************************************************************/

void efrm_vf_vi_qmoderate(struct efrm_vi *virs, int usec)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];
	unsigned int ticks, mode;
	efx_dword_t cmd;

	if (vi->irq_usec == usec)
		return;
	vi->irq_usec = usec;

	if (usec <= 0) {
		ticks = 0;
		mode = FFE_CZ_TIMER_MODE_DIS;
	} else if (usec < EFX_IRQ_MOD_RESOLUTION) {
		ticks = 0;
		mode = FFE_CZ_TIMER_MODE_INT_HLDOFF;
	} else {
		ticks = (usec / EFX_IRQ_MOD_RESOLUTION) - 1;
		mode = FFE_CZ_TIMER_MODE_INT_HLDOFF;
	}

	EFX_POPULATE_DWORD_2(cmd,
			     FRF_CZ_TC_TIMER_MODE, mode,
			     FRF_CZ_TC_TIMER_VAL, ticks);
	writel(cmd.u32[0],
	       vf->bar + FR_BZ_TIMER_COMMAND_P0 +
	       (vi->index << (PAGE_SHIFT + 1)));

	EFRM_TRACE("%s: VI %d/%d IRQ moderation %d", pci_name(vf->pci_dev),
		   vi->index, virs->allocation.instance, vi->irq_usec);
}


static void vf_vi_call_evq_callback(struct efrm_vf_vi *vi)
{
	struct efrm_vf *vf = vi_to_vf(vi);
	struct efrm_vi *virs = vi->virs;

	EFRM_ASSERT(virs);
	EFRM_ASSERT(virs->evq_callback_fn);

	/* Fixme: callback with is_timeout=true? */
	virs->evq_callback_fn(virs->evq_callback_arg, false,
			      efrm_nic_tablep->nic[vf->nic_index]);
}

static irqreturn_t vf_vi_interrupt(int irq, void *dev_id
#if defined(EFX_HAVE_IRQ_HANDLER_REGS)
	, struct pt_regs *regs __attribute__ ((unused))
#endif
	)
{
#ifdef EXF_HAVE_THREADED_IRQ
	vf_vi_call_evq_callback(dev_id);
#else
	struct efrm_vf_vi *vi = dev_id;
	queue_work(vi->threaded_irq.irq_wq, &vi->threaded_irq.irq_work);
#endif
	return IRQ_HANDLED;
}

#ifndef EXF_HAVE_THREADED_IRQ
static void ef_vi_irq_work(struct work_struct *data)
{
	struct efrm_vf_vi *vi = container_of(data, struct efrm_vf_vi,
					     threaded_irq.irq_work);
	vf_vi_call_evq_callback(vi);
}
#endif

/* When eventq callback was registered, enable interrupts */
int efrm_vf_eventq_callback_registered(struct efrm_vi *virs)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];
	int rc;

	EFRM_ASSERT(virs->allocation.instance >= vf->vi_base);
	EFRM_ASSERT(virs->allocation.instance < vf->vi_base + vf->vi_count);
	EFRM_ASSERT(vi->virs == virs);

	/* Enable interrupts */
#ifdef EXF_HAVE_THREADED_IRQ
	rc = request_threaded_irq(vi->irq, NULL, vf_vi_interrupt,
				  IRQF_SAMPLE_RANDOM, vi->name, vi);
#else
	INIT_WORK(&vi->threaded_irq.irq_work, ef_vi_irq_work);
	vi->threaded_irq.irq_wq = create_singlethread_workqueue(vi->name);
	rc = request_irq(vi->irq, vf_vi_interrupt,
			 IRQF_SAMPLE_RANDOM, vi->name, vi);
#endif
	if (rc) {
		EFRM_ERR("%s: failed to request IRQ %d for VI %d",
			 pci_name(vf->pci_dev), vi->irq, vi->index);
		virs->evq_callback_fn = NULL;
		return rc;
	}

	return 0;
}

/* Before really killing callback, disable interrupts */
void efrm_vf_eventq_callback_kill(struct efrm_vi *virs)
{
	struct efrm_vf *vf = virs->allocation.vf;
	struct efrm_vf_vi *vi = &vf->vi[virs->allocation.instance -
					vf->vi_base];

	EFRM_ASSERT(vf);
	EFRM_ASSERT(vi->virs == virs);
	if (virs->evq_callback_fn == NULL)
		return;

	free_irq(vi->irq, vi);
#ifndef EXF_HAVE_THREADED_IRQ
	destroy_workqueue(vi->threaded_irq.irq_wq);
#endif
	vi->virs->evq_callback_fn = NULL;
}

static struct pci_driver efrm_pci_vf_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= efrm_pci_vf_table,
	.probe		= efrm_pci_vf_probe,
	.remove		= efrm_pci_vf_remove,
};


void __devinit efrm_vf_driver_init(void)
{
	if (pci_register_driver(&efrm_pci_vf_driver) < 0) {
		EFRM_WARN("%s: failed to register PCI driver "
			  "for Virtual Functions", __func__);
	}
}

void efrm_vf_driver_fini(void)
{
	pci_unregister_driver(&efrm_pci_vf_driver);
}

#else /* CONFIG_PCI_IOV */

/* Fake implementation of VF-related functions */
void efrm_vf_eventq_callback_kill(struct efrm_vi *virs)
{
	EFRM_ASSERT(0);
}
int efrm_vf_eventq_callback_registered(struct efrm_vi *virs)
{
	EFRM_ASSERT(0);
	return -EINVAL;
}
void efrm_vf_vi_drop(struct efrm_vi *virs)
{
	EFRM_ASSERT(0);
}
int efrm_vf_interrupts_probe(struct efrm_vf *vf)
{
	EFRM_ASSERT(0);
	return -EINVAL;
}
void efrm_vf_vi_qmoderate(struct efrm_vi *virs, int usec)
{
	EFRM_ASSERT(0);
}
int efrm_vf_vi_set_cpu_affinity(struct efrm_vi *virs, int cpu)
{
	EFRM_ASSERT(0);
	return -EINVAL;
}
#endif /* CONFIG_PCI_IOV */
