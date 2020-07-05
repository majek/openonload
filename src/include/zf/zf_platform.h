/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect platform API
**
** This file contains platform-dependent code that is used by the other
** header files. It has no end-user API.
**
*//*! \cond NODOC
*//*
\**************************************************************************/

#ifndef __ZF_PLATFORM_H__
#define __ZF_PLATFORM_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif

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
# if __GNUC__ > 4 || (__GNUC__ >= 4 && __GNUC_MINOR__ >= 5)
#  define ZF_NOCLONE __attribute__((noclone))
# else
#  define ZF_NOCLONE
# endif
# define ZF_CONSTFUNC __attribute__((const))
# define ZF_LIKELY(t)    __builtin_expect((t), 1)
# define ZF_UNLIKELY(t)  __builtin_expect((t), 0)
# define ZF_UNREACHABLE __builtin_unreachable
# define ZF_NOINLINE __attribute__((noinline))
# define ZF_VISIBLE __attribute__((visibility("default")))
#endif

#if defined(__x86_64__) || defined(__i386__)
# include <zf/sysdep/x86.h>
#else
# error Unsupported platform.
#endif

#ifdef __cplusplus
#define ZF_LIBENTRY extern "C" __attribute__((visibility("default")))
#else
#define ZF_LIBENTRY extern
#endif

#ifdef __cplusplus
  #ifdef __GNUC__
    #if __GNUC__
      /* Flexible array is a GCC extension for C++ */
      #define ZF_FLEXIBLE_ARRAY_COUNT 0
    #endif
  #endif
#else
  #ifdef __STDC__VERSION__
    #if __STDC_VERSION__ >= 199901L
      /* C99 */
      #define ZF_FLEXIBLE_ARRAY_COUNT
    #else
      /* C<99 && C>=95 */
      #ifdef __GNUC__
        /* Work around GCC4.8 bug by using zero-length extension */
        #define ZF_FLEXIBLE_ARRAY_COUNT 0
      #endif
    #endif
  #else
    /* C<95 */
    #ifdef __GNUC__
      /* Work around GCC4.8 bug by using zero-length extension */
      #define ZF_FLEXIBLE_ARRAY_COUNT 0
    #endif
  #endif
#endif

#ifndef ZF_FLEXIBLE_ARRAY_COUNT
/* non-gnu C++, non-gnu C<99 */
#define ZF_FLEXIBLE_ARRAY_COUNT 1
#endif

#endif /* __ZF_PLATFORM_H__ */
/** @}
 * \endcond NODOC
 */
