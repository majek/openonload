/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
#  include <sys/uio.h>
#  include <sys/types.h>
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
int    ef_log_level                = 1; /*Critical*/
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

  writev(STDERR_FILENO, v, 2);
#endif
}

/* ****************************************************************************
 * Helpers
 */

#if defined(__linux__) && defined(__KERNEL__)
/* This little helper-function returns the amount of stack space left before
 * encroaching the red-zone (once we get into here, the next IRQ will trigger a
 * kernel panic, so it is effectively unusable)
 */
inline size_t
ef_stack_space_left (void) {
#ifdef __x86_64__
  return 0x10000;  /* FIXME: how do I do this on x86-64?? */
#else
  unsigned long stack = (unsigned long) __builtin_frame_address(0);
  unsigned long stack_offs = stack & (THREAD_SIZE-1);
  return stack_offs - (THREAD_SIZE/8);
#endif
}
#endif

/* ****************************************************************************
 * Module API
 */

/* size of internal log buffer */ 
#define  EF_LOG_MAX_LINE        512
/* uses of ef_log must ensure that all trace messages are shorter than this */ 
#define  EF_LOG_MAX_MSG_LENGTH        (EF_LOG_MAX_LINE-50)

#define EF_LOG_PID		0x1
#define EF_LOG_TID		0x2

#ifdef __KERNEL__
#  define EF_BOMB()  BUG()
#else /* !__KERNEL__ */
#  define EF_BOMB()  do{ *(int*) 0 = 0; }while(0)
#endif


void ef_vlog(const char* fmt, va_list args)
{
  int n = 0;

#ifdef __KERNEL__
  /* On Linux kernel we need to be very careful with stack use.  Putting an
   * array of EF_LOG_MAX_LINE on stack can be bad, so:
   *  1 - use the stack if we determine there's enough space free
   *      (we use C99's clever dynamically sized automatic arrays for this)
   *  2 - if stack is too small, try to kalloc some memory.
   *  3 - If we can't even do that, use a static array.  This risks being
   *      overwritten by concurrent logs so we might lose log messages in
   *      low memory conditions.  Unfortunate, but preferable to kernel panics
   *      due to stack exhaustion.
   */
  char *heap_line = NULL;
  static char static_line [EF_LOG_MAX_LINE];
  char stack_line [ ef_stack_space_left() < (EF_LOG_MAX_LINE + 128)
                    ? 0
                    : EF_LOG_MAX_LINE ];
  char *line = stack_line;

  if (sizeof stack_line == 0) {
    /* Uh-oh - no space on stack.  Try to kalloc it */
    printk ("WARNING: Low stack space in %s - using kmalloc\n", __FUNCTION__);
    line = heap_line = kmalloc (EF_LOG_MAX_LINE, GFP_ATOMIC);
    if (!line) {
      /* Even that failed - fall back to static */
      printk ("WARNING: kmalloc failed in %s\n", __FUNCTION__);
      line = static_line;
    }
  }
#else /* !__KERNEL__ */
  char line[EF_LOG_MAX_LINE];
#endif /* __KERNEL__ */

  BUG_ON(fmt == NULL);

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
      EF_BOMB();
    }
  }
#endif /* EF_VI_HAVE_NPRINTF */

  ef_log_fn(line);

#ifdef __KERNEL__
  /* It's possible we did a kalloc above - if so we'd better free it
   * (Note: we're allowed to pass NULL to kfree)
   */
  kfree (heap_line);
#endif
}


void ef_log(const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ef_vlog(fmt, args);
  va_end(args);
}

/*! \cidoxg_end */
