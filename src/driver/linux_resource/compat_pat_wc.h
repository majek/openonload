/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
 * This file provides public API for protection domain resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#ifndef COMPAT_PAT_WC_H
#define COMPAT_PAT_WC_H

#include "kernel_compat.h"

/* Define CONFIG_FORCE_PIO_NON_CACHED to force
 * PIO mapping in non cached mode.
 */

#if (defined(__i386__) || defined(__x86_64__))
#if !defined(CONFIG_X86_PAT)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
#ifndef CONFIG_FORCE_PIO_NON_CACHED
#define HAS_COMPAT_PAT_WC
#endif
#endif
#endif
#endif

#ifdef HAS_COMPAT_PAT_WC

#include <asm/pgtable.h>

int compat_pat_wc_init(void);

void compat_pat_wc_shutdown(void);

int compat_pat_wc_is_initialized(void);

pgprot_t compat_pat_wc_pgprot_writecombine(pgprot_t _prot);

void __iomem *compat_pat_wc_ioremap_wc(unsigned long phys_addr, unsigned long size);

#endif

#endif
