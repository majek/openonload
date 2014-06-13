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

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_SYSDEP_H__
#define __CI_TOOLS_SYSDEP_H__

/* Make this header self-sufficient */
#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>


/**********************************************************************
 * Platform dependencies.
 */

#if defined(__KERNEL__)

# if defined(__ci_storport__)
#   error Storport and __KERNEL__ should not be mixed.
# else
#  include <ci/tools/platform/linux_kernel.h>
# endif

#elif defined(__ci_storport__)      // Order matters!! Keep this before __WIN32

#  include <ci/tools/platform/storport.h>

#else

# include <ci/tools/platform/unix.h>

#endif

/*! Linux sendfile() support enable/disable. */
# define CI_HAVE_SENDFILE            /* provide sendfile i/f */
# define CI_HAVE_OS_NOPAGE


typedef ci_int32 ci_uerr_t; /* range of OS user-mode return codes */
typedef ci_int32 ci_kerr_t; /* range of OS kernel-mode return codes */


/**********************************************************************
 * Compiler and processor dependencies.
 */

#if defined(__GNUC__)

#if defined(__i386__) || defined(__x86_64__)
# include <ci/tools/platform/gcc_x86.h>
#elif defined(__PPC__)
#  include <ci/tools/platform/gcc_ppc.h>
#elif defined(__ia64__)
#  include <ci/tools/platform/gcc_ia64.h>
#else
# error Unknown processor.
#endif

#elif defined(_MSC_VER)

#if defined(__i386__)
# include <ci/tools/platform/msvc_x86.h>
# elif defined(__x86_64__)
# include <ci/tools/platform/msvc_x86_64.h>
#else
# error Unknown processor.
#endif

#elif defined(__PGI)

# include <ci/tools/platform/pg_x86.h>

#elif defined(__INTEL_COMPILER)

/* Intel compilers v7 claim to be very gcc compatible. */
# include <ci/tools/platform/gcc_x86.h>

#else
# error Unknown compiler.
#endif


#endif  /* __CI_TOOLS_SYSDEP_H__ */

/*! \cidoxg_end */
