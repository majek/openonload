/*
** Copyright 2005-2014  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
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

/*
 * \author  stg
 *  \brief  System dependent support for ef vi lib
 *   \date  2007/05/10
 */

/*! \cidoxg_include_ci_ul */
#ifndef __CI_CIUL_SYSDEP_LINUX_H__
#define __CI_CIUL_SYSDEP_LINUX_H__

#include <asm/io.h>
#include <linux/errno.h>
#include <linux/string.h>


typedef dma_addr_t ef_vi_dma_addr_t;


#define EF_VI_HF __attribute__((visibility("hidden")))
#define EF_VI_HV __attribute__((visibility("hidden")))

#if defined(__PPC__)
#if defined(__KERNEL__)
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define mmiowb() wmb()
#endif
#else
#define mmiowb() wmb()
#endif
#else
#if !defined(mmiowb)
#define mmiowb() ((void)0)
#endif
#endif


#ifndef __printf
# define __printf(fmt, arg)  __attribute__((format(printf, fmt, arg)))
#endif


#endif  /* __CI_CIUL_SYSDEP_LINUX_H__ */
