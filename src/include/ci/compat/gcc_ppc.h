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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_compat  */

#ifndef __CI_COMPAT_GCC_PPC_H__
#define __CI_COMPAT_GCC_PPC_H__

/* 
   Barriers to enforce ordering with respect to:
   normal memory use: ci_wmb, ci_rmb, ci_wmb
*/

/* 
	System wide macros 'mb,rmb,wmb' are supplied
	which are ppc 32/64 bit specific. See <asm/system.h>
*/

#define ci_mb()    __asm__ __volatile__ ("sync" : : : "memory")
#if defined(__powerpc64__)
#define ci_wmb()   __asm__ __volatile__ ("lwsync" : : : "memory")
#define ci_rmb()   ci_wmb()
#else
#define ci_wmb()   __asm__ __volatile__ ("eieio" : : : "memory")
#define ci_rmb()   ci_wmb()
#endif

#define ci_ul_iowb() ci_wmb()

/* Really these should be in  src/include/ci/driver/platform/... */
typedef unsigned long     	ci_phys_addr_t;
#define ci_phys_addr_fmt  "%lx"


#endif  /* __CI_COMPAT_GCC_PPC_H__ */

/*! \cidoxg_end */
