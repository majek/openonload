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
 * This file provides compatibility layer for various Linux kernel versions
 * (starting from 2.6.9 RHEL kernel).
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

#ifndef DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H
#define DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
# include <linux/io.h>
#else
# include <asm/io.h>
#endif
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
# include <linux/iommu.h>
#endif

/********* wait_for_completion_timeout() ********************/

/* RHEL_RELEASE_CODE from linux/version.h is only defined for 2.6.9-55EL
 * UTS_RELEASE is unfortunately unusable
 * Really only need this fix for <2.6.9-34EL
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)) && \
	!defined(RHEL_RELEASE_CODE)

static inline unsigned long fastcall
efrm_wait_for_completion_timeout(struct completion *x, unsigned long timeout)
{
	might_sleep();

	spin_lock_irq(&x->wait.lock);
	if (!x->done) {
		DECLARE_WAITQUEUE(wait, current);

		wait.flags |= WQ_FLAG_EXCLUSIVE;
		__add_wait_queue_tail(&x->wait, &wait);
		do {
			__set_current_state(TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&x->wait.lock);
			timeout = schedule_timeout(timeout);
			spin_lock_irq(&x->wait.lock);
			if (!timeout) {
				__remove_wait_queue(&x->wait, &wait);
				goto out;
			}
		} while (!x->done);
		__remove_wait_queue(&x->wait, &wait);
	}
	x->done--;
out:
	spin_unlock_irq(&x->wait.lock);
	return timeout;
}

#  ifdef wait_for_completion_timeout
#    undef wait_for_completion_timeout
#  endif
#  define wait_for_completion_timeout efrm_wait_for_completion_timeout

#endif

/********* io mapping ********************/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)

  #ifndef __iomem
  #define __iomem
  #endif

  static inline void efrm_iounmap(volatile void __iomem *addr)
  {
	  iounmap((void __iomem *)addr);
  }
  #define iounmap(arg) efrm_iounmap(arg)

#endif

/********* IOMMU mapping ********************/
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
#  if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34) || defined(RHEL_MAJOR)
  static inline int iommu_map(struct iommu_domain *domain,
			      unsigned long iova, phys_addr_t paddr,
			      int gfp_order, int prot) {
    return iommu_map_range(domain, iova, paddr, PAGE_SIZE << gfp_order, prot);
  }

  static inline int iommu_unmap(struct iommu_domain *domain,
				unsigned long iova, int gfp_order) {
    iommu_unmap_range(domain, iova, PAGE_SIZE << gfp_order);
    return 0;
  }
#  endif
#  ifndef IOMMU_CACHE
#    define IOMMU_CACHE 0
#  endif
#  if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#    define iommu_present(b) iommu_found()
#    define iommu_domain_alloc(b) iommu_domain_alloc()
#  endif
#endif

/********* Memory allocation *************/

#ifndef IN_KERNEL_COMPAT_C
#  ifndef __GFP_COMP
#    define __GFP_COMP 0
#  endif
#  ifndef __GFP_ZERO
#    define __GFP_ZERO 0
#  endif
#endif


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
static inline void efrm_pci_disable_msi(struct pci_dev *dev) {}
#undef pci_disable_msi
#define pci_disable_msi efrm_pci_disable_msi
#endif

#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */
