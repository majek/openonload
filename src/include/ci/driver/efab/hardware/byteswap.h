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

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2012: Solarflare Communications Inc,
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

/* The file is a partial copy-paste from sysdep_unix.h */

#ifndef __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__
#define __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__

#if defined(__i386__) || defined(__x86_64__)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__PPC__)
# define EF_VI_LITTLE_ENDIAN   0
#else
# error Unknown processor
#endif

#if EF_VI_LITTLE_ENDIAN
# define cpu_to_le32(v)   (v)
# define le32_to_cpu(v)   (v)
#else
# define cpu_to_le32(v)   (((v) >> 24)               |  \
	                   (((v) & 0x00ff0000) >> 8) |	\
			   (((v) & 0x0000ff00) << 8) |	\
			   ((v) << 24))
#define le32_to_cpu(v) (cpu_to_le32(v))
#endif

#if EF_VI_LITTLE_ENDIAN
# define cpu_to_le64(v)    (v)
# define le32_to_cpu(v)    (v)
#else
# define cpu_to_le64(v)     (((v) >> 56)                        |	\
	                     (((v) & 0x00ff000000000000ull) >> 40) |	\
	                     (((v) & 0x0000ff0000000000ull) >> 24) |	\
		             (((v) & 0x000000ff00000000ull) >> 8)  |	\
			     (((v) & 0x00000000ff000000ull) << 8)  |	\
			     (((v) & 0x0000000000ff0000ull) << 24) |	\
			     (((v) & 0x000000000000ff00ull) << 40) |	\
			     ((v) << 56))
# define le64_to_cpu(v) (cpu_to_le64(v))
#endif


#endif /* __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__ */
