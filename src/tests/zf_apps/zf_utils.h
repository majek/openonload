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
**  \brief  ZF logging facilities
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_APPS_UTILS_H__
#define __ZF_APPS_UTILS_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>


struct zf_stack;

/* Emit message to log unconditionally. */
extern void zf_log(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

/* Emit message to log depending on log level. */
extern void zf_err(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void zf_warn(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void zf_info(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void zf_trace(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

/* Emit message to log only in debug builds (and appropriate log level. */
#ifdef NDEBUG
# define zf_tracefp(st, ...)  do{ (void) (st); }while(0)
# define zf_trace_tcp(st, ...)  do{ (void) (st); }while(0)
# define zf_trace_tcp_full(st, ...)  do{ (void) (st); }while(0)
#else
extern void zf_tracefp(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void zf_trace_tcp(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
extern void zf_trace_tcp_full(struct zf_stack*, const char* fmt, ...)
  __attribute__((format(printf,2,3)));
#endif


#ifdef NDEBUG

#define zf_fail(x)
#define _zf_assert(exp, file, line)
#define _zf_assert2(e, x, y, file, line)

#define zf_assert(exp)
#define zf_assert_equal(exp1, exp2)
#define zf_assert_nequal(exp1, exp2)
#define zf_assert_le(exp1, exp2)
#define zf_assert_lt(exp1, exp2)
#define zf_assert_ge(exp1, exp2)
#define zf_assert_gt(exp1, exp2)
#define zf_assert_flags(val, flags)
#define zf_assert_nflags(val, flags)
#define zf_assert_impl(val, flags)

#else

#define zf_fail(x)                                                         \
  do{ zf_log(NULL, "FAIL at %s:%d", __FILE__, __LINE__);  abort(); }while(0)

#define _zf_assert(exp, file, line)                             \
  do {                                                          \
    if (__builtin_expect((!(exp)), 0))                          \
      zf_fail(("zf_assert(%s)\nfrom %s:%d", #exp,               \
               (file), (line)));                                \
  } while (0)

#define _zf_assert2(e, x, y, file, line)  do {      \
    if(__builtin_expect((!(e)), 0)) {               \
      zf_log(NULL, "zf_assert(%s)", #e);            \
      zf_log(NULL, "where [%s=%"PRIx64"]",          \
             #x, (uint64_t)(uintptr_t)(x));         \
      zf_log(NULL, "and [%s=%"PRIx64"]",            \
             #y, (uint64_t)(uintptr_t)(y));         \
      zf_log(NULL, "at %s:%d", __FILE__, __LINE__); \
      zf_fail(("from %s:%d", (file), (line)));      \
    }                                               \
  } while (0)

#define zf_assert(exp) \
        _zf_assert(exp, __FILE__, __LINE__)

#define zf_assert_equal(exp1, exp2) \
        _zf_assert2((exp1)==(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_nequal(exp1, exp2) \
        _zf_assert2((exp1)!=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_le(exp1, exp2) \
        _zf_assert2((exp1)<=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_lt(exp1, exp2) \
        _zf_assert2((exp1)<(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_ge(exp1, exp2) \
        _zf_assert2((exp1)>=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_gt(exp1, exp2) \
        _zf_assert2((exp1)>(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_flags(val, flags) \
        _zf_assert2(((val)&(flags))==(flags), val, flags, __FILE__, __LINE__)

#define zf_assert_nflags(val, flags) \
        _zf_assert2(((val)&(flags))==0, val, flags, __FILE__, __LINE__)

#define zf_assert_impl(exp1, exp2) \
        _zf_assert2(!(exp1) || (exp2), exp1, exp2, __FILE__, __LINE__)

#endif /*NDEBUG*/


#define ZF_TRY(x)                                                       \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: ZF_TRY(%s) failed\n", __func__, #x);  \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define ZF_TEST(x)                                                      \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: ZF_TEST(%s) failed\n", __func__, #x); \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#endif /* __ZF_APPS_UTILS_H__ */
