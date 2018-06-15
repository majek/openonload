/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
#include <linux/nodemask.h>


typedef dma_addr_t ef_vi_dma_addr_t;


#define EF_VI_HF __attribute__((visibility("hidden")))
#define EF_VI_HV __attribute__((visibility("hidden")))


#if defined(__i386__) || defined(__x86_64__)
# define wmb_wc()  __asm__ __volatile__("sfence": : :"memory")
#else
# define wmb_wc()  __asm__ __volatile__("sync" : : :"memory")
#endif


#ifndef __printf
# define __printf(fmt, arg)  __attribute__((format(printf, fmt, arg)))
#endif


/* We don't worry much about optimising these in kernel. */
#define unordered_writel(data, addr)  __raw_writel(cpu_to_le32(data), (addr))
#define noswap_writel(data, addr)     writel(le32_to_cpu(data), (addr))


static inline int sys_is_numa(void)
{
  return num_online_nodes() > 1;
}


#endif  /* __CI_CIUL_SYSDEP_LINUX_H__ */
