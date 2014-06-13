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

#undef EFX_USE_IRQ_SET_AFFINITY_HINT
#undef EFX_HAVE_ROUND_JIFFIES_UP
#undef EFX_NEED_PCI_CLEAR_MASTER
#define EFX_NEED_PCI_CLEAR_MASTER
#undef EFX_HAVE_IOMMU_FOUND
#undef EFX_NEED_GETNSTIMEOFDAY
#define EFX_NEED_GETNSTIMEOFDAY
#undef EFX_NEED_NS_TO_TIMESPEC
#define EFX_NEED_NS_TO_TIMESPEC
#undef EFX_HAVE_XEN_START_INFO
#undef EFX_NEED_SET_NORMALIZED_TIMESPEC
#define EFX_NEED_SET_NORMALIZED_TIMESPEC
