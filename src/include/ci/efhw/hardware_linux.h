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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides version-independent Linux kernel API for header files
 * with hardware-related definitions (in ci/driver/efab/hardware*).
 * Only kernels >=2.6.9 are supported.
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

#ifndef __CI_EFHW_HARDWARE_LINUX_H__
#define __CI_EFHW_HARDWARE_LINUX_H__

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <asm/byteorder.h>

#if defined(__LITTLE_ENDIAN)
# define EFHW_IS_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
# define EFHW_IS_BIG_ENDIAN
#else
# error Unknown endianness
#endif

#ifndef __iomem
#define __iomem
#endif

#ifndef mmiowb
	#if defined(__i386__) || defined(__x86_64__)
		#define mmiowb()
	#elif defined(__ia64__)
		#ifndef ia64_mfa
			#define ia64_mfa() asm volatile ("mf.a" ::: "memory")
		#endif
	#define mmiowb ia64_mfa
	#elif defined(__PPC32__)
		#define mmiowb
	#elif defined(__PPC64__)
/* On PPC mmwiob is defined as an inline function, not as a macro,
 * so the ifdef test fails, and thus we rely on kernel version.
 * The function definition cannot be backported to earlier kernels here,
 * because it uses a field in paca_struct that does not exist there either,
 * so we just use a plain write memory barrier and hope for the best
 */
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	#define mmiowb() __asm__ __volatile__ ("sync" ::: "memory")
	#endif
	#else
	#error "Need definition for mmiowb()"
	#endif
#endif

#ifndef readq
static inline uint64_t __readq(volatile void __iomem *addr)
{
	return *(volatile uint64_t *)addr;
}
static inline uint64_t readq(volatile void __iomem *addr)
{
	uint64_t x = __readq(addr);
	return le64_to_cpu(x);
}

#endif

#ifndef writeq
static inline void __writeq(uint64_t v, volatile void __iomem *addr)
{
	*(volatile uint64_t *)addr = v;
}
#define writeq(val, addr) __writeq(cpu_to_le64(val), (addr))
#endif

#endif /* __CI_EFHW_HARDWARE_LINUX_H__ */
