/*
** Copyright 2005-2019  Solarflare Communications Inc.
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
#include <driver/linux_affinity/kernel_compat.h>
#ifdef EFRM_HAVE_NSPROXY
#include <linux/nsproxy.h>
#endif


/********* IOMMU mapping ********************/
#ifdef CONFIG_SFC_RESOURCE_VF_IOMMU
/* iommu_map/iommu_unmap definition */
# ifdef EFRM_HAVE_IOMMU_MAP_OLD
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) && \
        LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0) && defined(HPAGE_SIZE)
	/* Yes, this is just crazy, but iommu_map does not
	 * correctly map 2M (huge|compound) pages on SLES11
	 * linux-3.0 Intel IOMMU.  See bug 31783. */
static inline int iommu_map_my(struct iommu_domain *domain,
			       unsigned long iova,
			       phys_addr_t paddr, size_t size, int prot)
{
	if (size <= HPAGE_SIZE / 2 )
		return iommu_map(domain, iova, paddr, get_order(size), prot);
	else {
		int rc = iommu_map(domain, iova, paddr,
				   HPAGE_SHIFT - PAGE_SHIFT - 1, prot);
		if (rc < 0)
			return rc;
		rc = iommu_map(domain, iova + HPAGE_SIZE / 2,
			       paddr + HPAGE_SIZE / 2,
			       HPAGE_SHIFT - PAGE_SHIFT - 1, prot);
		if (rc < 0)
			iommu_unmap(domain, iova, HPAGE_SHIFT - 1);
		return rc;
	}
}
static inline int iommu_unmap_my(struct iommu_domain *domain,
				 unsigned long iova, size_t size)
{
	int rc;
	if (size <= HPAGE_SIZE / 2 ) {
		rc = iommu_unmap(domain, iova, get_order(size));
		if (rc < 0)
			return rc;
		return size;
	} else {
		rc = iommu_unmap(domain, iova, HPAGE_SHIFT - PAGE_SHIFT - 1);
		if (rc < 0)
			return rc;
		rc = iommu_unmap(domain, iova + (1 << (HPAGE_SHIFT - 1)),
				 HPAGE_SHIFT - PAGE_SHIFT - 1);
		if (rc < 0)
			return rc;
		return size;
	}
}
#    define iommu_map iommu_map_my
#    define iommu_unmap iommu_unmap_my

#  else
   /* old API: get gfp_order, unmap returns 0 or -errno
    * new API: get size, unmap returns size */
static inline int iommu_map_my(struct iommu_domain *domain,
			       unsigned long iova,
			       phys_addr_t paddr, size_t size, int prot)
{
	return iommu_map(domain, iova, paddr, get_order(size), prot);
}
static inline int iommu_unmap_my(struct iommu_domain *domain,
				 unsigned long iova, size_t size)
{
	int rc = iommu_unmap(domain, iova, get_order(size));
	if (rc == 0)
		return size;
	return rc;
}
#    define iommu_map iommu_map_my
#    define iommu_unmap iommu_unmap_my

#  endif
# elif !defined(EFRM_HAVE_IOMMU_MAP)
  static inline int iommu_map(struct iommu_domain *domain,
			      unsigned long iova, phys_addr_t paddr,
			      int size, int prot) {
    return iommu_map_range(domain, iova, paddr, size, prot);
  }

  static inline int iommu_unmap(struct iommu_domain *domain,
				unsigned long iova, int size) {
    iommu_unmap_range(domain, iova, size);
    return size;
  }
# endif




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


/* VM_IO is used on mappings of PCI space to inform the kernel that the mapping
 * is not backed by host memory, and so to prevent it from doing anything that
 * it shouldn't.
 *
 * VM_DONTEXPAND prevents the MM from attempting to swap-out these
 * pages.  On very old kernels (2.4) this property belonged instead to
 * VM_RESERVED, but that also prevents core dumps, and we don't require it on
 * any of our supported kernels.  We continue to set it when setting VM_IO,
 * though, for consistency with other users in the kernel, even though its
 * effects are implied by VM_IO.  Similarly, on modern (>= 3.7) kernels in
 * which VM_RESERVED has been purged, we set VM_DONTDUMP if and only if we have
 * set VM_IO.
 */
#define EFRM_VM_BASE_FLAGS VM_DONTEXPAND
#ifdef VM_RESERVED
#define EFRM_VM_IO_FLAGS   (EFRM_VM_BASE_FLAGS | VM_IO | VM_RESERVED)
#else
#define EFRM_VM_IO_FLAGS   (EFRM_VM_BASE_FLAGS | VM_IO | VM_DONTDUMP)
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
# define f_vfsmnt f_path.mnt
#endif

#ifndef EFRM_HAVE_NETDEV_NOTIFIER_INFO
#define netdev_notifier_info_to_dev(info) (info)
#endif

#ifndef NOPAGE_SIGBUS
#  define NOPAGE_SIGBUS (NULL)
#endif

#ifndef FOLL_WRITE
#define FOLL_WRITE	0x01
#endif

#ifndef FOLL_FORCE
#define FOLL_FORCE	0x10
#endif

static inline long
get_user_pages_onload_compat(unsigned long start, unsigned long nr_pages,
			     unsigned int gup_flags, struct page **pages,
			     struct vm_area_struct **vmas)
{
  /* We support four get_user_pages() function prototypes here,
   * including an intermediate one that has one of the changes but not
   * the other, and we assume that intermediate case if the main three
   * are not defined:
   *
   * Pre-3.9: EFRM_GUP_RCINT_TASK_SEPARATE_FLAGS
   * int get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                    unsigned long start, int nr_pages, int write, int force,
   *                    struct page **pages, struct vm_area_struct **vmas);
   *
   * Pre-4.6.0: EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS
   * long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                     unsigned long start, unsigned long nr_pages,
   *                     int write, int force, struct page **pages,
   *                     struct vm_area_struct **vmas);
   *
   * 4.4.(>=168): EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS
   * long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                     unsigned long start, unsigned long nr_pages,
   *                     unsigned int gup_flags, struct page **pages,
   *                     struct vm_area_struct **vmas)
   *
   * Intermediate (up to 4.9.0): (would be EFRM_GUP_RCLONG_NOTASK_SEPARATEFLAGS)
   * long get_user_pages(unsigned long start, unsigned long nr_pages,
   *                     int write, int force, struct page **pages,
   *                     struct vm_area_struct **vmas);
   *
   * Post-4.9.0: EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS
   * long get_user_pages(unsigned long start, unsigned long nr_pages,
   *                     unsigned int gup_flags, struct page **pages,
   *                     struct vm_area_struct **vmas);
   */

#ifdef EFRM_GUP_RCINT_TASK_SEPARATEFLAGS
#define EFRM_GUP_NRPAGES_CAST (int)
#define EFRM_GUP_RC_CAST (long)
#else
#define EFRM_GUP_NRPAGES_CAST 
#define EFRM_GUP_RC_CAST 
#endif

  return EFRM_GUP_RC_CAST get_user_pages(
#if defined(EFRM_GUP_RCINT_TASK_SEPARATEFLAGS) ||    \
    defined(EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS) ||   \
    defined(EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS)
                                         current, current->mm,
#endif
                                         start, EFRM_GUP_NRPAGES_CAST nr_pages,
#if defined(EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS) || \
    defined(EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS)
                                         gup_flags,
#else
                                         gup_flags & FOLL_WRITE, 
                                         gup_flags & FOLL_FORCE,
#endif
                                         pages, vmas);
}
#define get_user_pages get_user_pages_onload_compat


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define VM_FAULT_ADDRESS(_vmf) (_vmf)->address
#else
#define VM_FAULT_ADDRESS(_vmf) (unsigned long)(_vmf)->virtual_address
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define dev_net(a) NULL
#define get_net(a) NULL
#define put_net(a)
#endif

#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */
