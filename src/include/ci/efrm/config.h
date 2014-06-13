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

#ifndef __CI_EFRM_CONFIG_H__
#define __CI_EFRM_CONFIG_H__

/********************************************************************
 *
 * CONFIG_SFC_RESOURCE_VF: it should be in Kconfig, but...
 *
 ********************************************************************/
#ifdef CONFIG_PCI_IOV
#if !defined(__powerpc__)
#define CONFIG_SFC_RESOURCE_VF
#ifdef CONFIG_IOMMU_API
#define CONFIG_SFC_RESOURCE_VF_IOMMU
#endif
#endif /* __powerpc__ */
#endif /* CONFIG_PCI_IOV */


#endif /* __CI_EFRM_CONFIG_H__ */
