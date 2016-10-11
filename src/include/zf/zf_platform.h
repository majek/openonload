/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** \author  mj
**  \brief  ZF API
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_PLATFORM_H__
#define __ZF_PLATFORM_H__

/** \cond NODOC */

#ifdef __GNUC__
#define _GNU_SOURCE 1
#endif

/* Tell stdint.h to generate macros such as PRIx64 also in C++ */
#ifndef __STDC_FORMAT_MACROS
# define __STDC_FORMAT_MACROS
#endif
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
# include <sys/types.h>

#ifdef __GNUC__
# if __GNUC__ > 4 || (__GNUC__ >= 4 && __GNUC_MINOR__ >= 3)
#  define ZF_HOT __attribute__((hot,flatten))
#  define ZF_COLD __attribute__((cold))
# else
#  define ZF_HOT
#  define ZF_COLD
# endif
# define ZF_CONSTFUNC __attribute__((const))
# define ZF_LIKELY(t)    __builtin_expect((t), 1)
# define ZF_UNLIKELY(t)  __builtin_expect((t), 0)
# define ZF_UNREACHABLE __builtin_unreachable
#endif

#if defined(__x86_64__) || defined(__i386__)
# include <zf/sysdep/x86.h>
#elif defined(__PPC__)
# include <zf/sysdep/ppc.h>
#else
# error Unsupported platform.
#endif

#ifdef __cplusplus
#define LIBENTRY extern "C" __attribute__((visibility("default")))
#else
#define LIBENTRY extern
#endif

/** \endcond NODOC */

#endif /* __ZF_PLATFORM_H__ */
