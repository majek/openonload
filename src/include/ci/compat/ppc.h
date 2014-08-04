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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_OPEN>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_compat */

#ifndef __CI_COMPAT_PPC_H__
#define __CI_COMPAT_PPC_H__


#define CI_MY_BYTE_ORDER   CI_BIG_ENDIAN

 
#define CI_WORD_SIZE     4
#define CI_PTR_SIZE      8

//
// Note: See #include <asm/page.h>
// Compiler doesn't seem to like the use of the OS defined macros,
// 'PAGE_SIZE' and 'PAGE_SHIFT' but it appears that for both the
// ppc 32/64, they are the same so we have hard coded the figures below
//

#define CI_PAGE_SHIFT    16
#define CI_PAGE_SIZE     (1 << CI_PAGE_SHIFT)
#define CI_PAGE_MASK     (~((ci_uintptr_t) CI_PAGE_SIZE - 1))

#define CI_CPU_HAS_IOSPACE 0 /* CPU has a separate IO space */

#endif  /* __CI_COMPAT_PPC_H__ */

/*! \cidoxg_end */
