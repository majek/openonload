/*
** Copyright 2005-2019  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
** \author  djr, ctk; stg, refactoring
**  \brief  Assertion, logging, dumpers
**   \date  2006/12/05
**    \cop  (c) Level 5 Networks Limited.
**    \cop  (c) 2006, Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */
#include "ef_vi_internal.h"
#include <stdarg.h>


/* ****************************************************************************
 * OS Dependencies
 */

#if !defined(__KERNEL__)
# include <stdio.h>
# include <stdlib.h>
#  include <sys/uio.h>
#  include <sys/types.h>
#   include <ci/internal/syscall.h>
#  include <unistd.h>
#else
#  include <linux/slab.h>
#endif

# define EF_VI_HAVE_NPRINTF  1


/* ****************************************************************************
 * Locals
 */
static void __ef_log(const char* msg);

void (*ef_log_fn)(const char* msg) = __ef_log;
#define EF_LOG_LEVEL_UNINITIALISED -1
int    ef_log_level                = EF_LOG_LEVEL_UNINITIALISED;
int    ef_log_options		   = 0;

/* ****************************************************************************
 * Logging destinations
 */

static void __ef_log(const char* msg)
{
#if defined(__KERNEL__)
  printk("%s\n", msg);
#else /* !__KERNEL__ */
  struct iovec v[2];

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(msg);
  v[1].iov_base = (char*) "\n";
  v[1].iov_len = 1;

  my_syscall3(writev, STDERR_FILENO, (long)v, 2);
#endif
}

/* ****************************************************************************
 * Module API
 */

/* size of internal log buffer */ 
#define  EF_LOG_MAX_LINE        512
/* uses of ef_log must ensure that all trace messages are shorter than this */ 
#define  EF_LOG_MAX_MSG_LENGTH        (EF_LOG_MAX_LINE-50)

#define EF_LOG_PID		0x1
#define EF_LOG_TID		0x2


void ef_vlog(const char* fmt, va_list args)
{
  int n = 0;
  char line[EF_LOG_MAX_LINE];

  EF_VI_BUG_ON(fmt == NULL);

  if( ef_log_options ) {
#if defined(__unix__) && !defined(__KERNEL__)
    if( ef_log_options & EF_LOG_PID )
      n += sprintf(line + n, "%d ", (int) getpid());
    //??if( ef_log_options & EF_LOG_TID )
    //??  n += sprintf(line + n, "%d ", (int) gettid());
#endif
  }

#ifdef EF_VI_HAVE_NPRINTF
  vsnprintf(line + n,
	    EF_LOG_MAX_LINE - n, fmt, args);
#else
  {
    int len;
    len = ci_vsprintf(line + n, fmt, args);
    if (len+1 > EF_LOG_MAX_LINE - n) {
      (ef_log_fn)("ef_vlog: too long");
      EF_VI_BUG_ON(1);
    }
  }
#endif /* EF_VI_HAVE_NPRINTF */

  ef_log_fn(line);
}


void ef_log(const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ef_vlog(fmt, args);
  va_end(args);
}


#ifndef __KERNEL__
static void __attribute__((constructor)) ef_log_init(void)
{
  if( ef_log_level == EF_LOG_LEVEL_UNINITIALISED ) {
    const char* s = getenv("EF_VI_LOG_LEVEL");
    if( s != NULL )
      ef_log_level = atoi(s);
    else
      ef_log_level = 0; /* Critical */
  }
}
#endif

/*! \cidoxg_end */
