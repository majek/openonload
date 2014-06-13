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
 *
 * This file provides private API for VF resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
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


#ifndef __CI_EFRM_VF_RESOURCE_INTERNAL_H__
#define __CI_EFRM_VF_RESOURCE_INTERNAL_H__

#ifdef CONFIG_SFC_RESOURCE_VF

#include <ci/efrm/vf_resource.h>
#include <ci/efrm/buddy.h>


#define EFRM_VF_MAX_VI_COUNT 64
#define EFRM_VF_NAME_LEN 32

#define MAC_ADDR_FMT							\
	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_VAL(_addr)						\
	(_addr)[0], (_addr)[1], (_addr)[2],				\
	(_addr)[3], (_addr)[4], (_addr)[5]

/* OS-dependent part should define this struct for real. */
struct pci_dev;

/* VF VI */
struct efrm_vf_vi_os;
struct efrm_vf_vi {
	/* Filled at VF PCI probe time: */
	int index;                      /* instance number of this VI */
	u32 irq;                        /* IRQ vector */
	struct tasklet_struct tasklet;  /* IRQ tasklet */

	/* Filled at allocation time: */
	char name[EFRM_VF_NAME_LEN];    /* human-readable name */
	struct efrm_vi *virs;   /* VI resource we are used with */

	/* VI-in-VF specific data: */
	u32 irq_usec;
	struct efrm_threaded_irq threaded_irq;
};

/* VF itself */
struct efrm_vf {
	struct efrm_resource rs;
	struct list_head link;
	int nic_index;

#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
	struct efrm_vf *linked;
#endif

	/* Number of this VF and VIs */
	int pci_dev_fn;
	int vi_base;
	u8 vi_count; /* Real number of VIs: rxq+txq+evq */

	struct pci_dev *pci_dev;

	/* state for IOMMU mappings */
	efhw_iommu_domain *iommu_domain;
	unsigned long *iova_basep;
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
	unsigned long iova_base;
#endif

	/* Data from the status page: */
	u8 vi_scale;
	u8 mac_addr[ETH_ALEN];

	u8 irq_count;

	struct efrm_vf_vi vi[EFRM_VF_MAX_VI_COUNT];

	struct efrm_buddy_allocator vi_instances;
};
#define efrm_vf(rs1)  container_of((rs1), struct efrm_vf, rs)
#define vi_to_vf(vi) container_of(vi, struct efrm_vf, vi[vi->index])

/* library functions called from driver */
extern int efrm_vf_probed(struct efrm_vf *vf);
extern void efrm_vf_removed(struct efrm_vf *vf);

/* driver OS-dependent functions called from library */
extern void efrm_vf_free_reset(struct efrm_vf *vf);
extern int efrm_vf_alloc_init(struct efrm_vf *vf, struct efrm_vf *linked,
                              int use_iommu);


#endif /* CONFIG_SFC_RESOURCE_VF */
#endif /* __CI_EFRM_VF_RESOURCE_INTERNAL_H__ */
