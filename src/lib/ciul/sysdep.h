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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  System dependent support for ef vi lib
**   \date  2007/05/10
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __CI_CIUL_SYSDEP_H__
#define __CI_CIUL_SYSDEP_H__


#if defined(__i386__) || defined(__x86_64__)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__BYTE_ORDER)
# define EF_VI_LITTLE_ENDIAN   (__BYTE_ORDER == __LITTLE_ENDIAN)
#elif defined(__LITTLE_ENDIAN)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__BIG_ENDIAN)
# define EF_VI_LITTLE_ENDIAN   0
#else
# error "EF_VI_LITTLE_ENDIAN needs fixing"
#endif


#if defined(__unix__) && !defined(__KERNEL__)
# include "sysdep_unix.h"
#else
# include "sysdep_linux.h"
#endif

#include "bitfield.h"


#if defined(__x86_64__) || defined(__i386__)
# define EF_VI_CACHE_LINE_SIZE       64
# define EF_VI_WRITE_BUFFER_SIZE     64
#elif defined(__PPC__)
# define EF_VI_CACHE_LINE_SIZE       128
# define EF_VI_WRITE_BUFFER_SIZE     128  /* todo: check this */
#else
# error "Need to define EF_VI_CACHE_LINE_SIZE"
#endif


#endif  /* __CI_CIUL_SYSDEP_H__ */
