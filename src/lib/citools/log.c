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
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <stdarg.h>


#ifndef  CI_LOG_PREFIX_DEFAULT 
# define CI_LOG_PREFIX_DEFAULT  "ci "
#endif

#ifndef  CI_LOG_LEVEL_DEFAULT 
# define CI_LOG_LEVEL_DEFAULT   1  /* critical */
#endif

#ifndef  CI_LOG_FN_DEFAULT
# define CI_LOG_FN_DEFAULT  ci_log_stderr
#endif

void (*ci_log_fn)(const char* msg) = CI_LOG_FN_DEFAULT;
int    ci_log_level                = CI_LOG_LEVEL_DEFAULT;
int    ci_log_options		   = 0;

const char* ci_log_prefix     = CI_LOG_PREFIX_DEFAULT;
static int ci_log_prefix_len = sizeof(CI_LOG_PREFIX_DEFAULT) - 1;

#if defined(__linux__) && defined(__KERNEL__)
/* This little helper-function returns the amount of stack space left before
 * encroaching the red-zone (once we get into here, the next IRQ will trigger a
 * kernel panic, so it is effectively unusable)
 */
static inline size_t
stack_space_left (void) {
#ifdef __x86_64__
  return 0x10000;  /* FIXME: how do I do this on x86-64?? */
#else
  ci_uintptr_t stack = (ci_uintptr_t) __builtin_frame_address(0);
  ci_uintptr_t stack_offs = stack & (THREAD_SIZE-1);
  return stack_offs - (THREAD_SIZE/8);
#endif
}
#endif


void ci_vlog(const char* fmt, va_list args)
{
  int n = 0;

#ifdef __KERNEL__
  /* On Linux kernel we need to be very careful with stack use.  Putting an
   * array of CI_LOG_MAX_LINE on stack can be bad, so:
   *  1 - use the stack if we determine there's enough space free
   *      (we use C99's clever dynamically sized automatic arrays for this)
   *  2 - if stack is too small, try to kalloc some memory.
   *  3 - If we can't even do that, use a static array.  This risks being
   *      overwritten by concurrent logs so we might lose log messages in
   *      low memory conditions.  Unfortunate, but preferable to kernel panics
   *      due to stack exhaustion.
   */
  char *heap_line = NULL;
  static char static_line [CI_LOG_MAX_LINE];
  char stack_line [ stack_space_left() < (CI_LOG_MAX_LINE + 128)
                    ? 0
                    : CI_LOG_MAX_LINE ];
  char *line = stack_line;

  if (sizeof stack_line == 0) {
    /* Uh-oh - no space on stack.  Try to kalloc it */
    printk ("WARNING: Low stack space in %s - using kmalloc\n", __FUNCTION__);
    line = heap_line = kmalloc (CI_LOG_MAX_LINE, GFP_ATOMIC);
    if (!line) {
      /* Even that failed - fall back to static */
      printk ("WARNING: kmalloc failed in %s\n", __FUNCTION__);
      line = static_line;
    }
  }
#else
  char line[CI_LOG_MAX_LINE];
#endif

  ci_assert(ci_log_prefix);
  ci_assert(fmt);

  if( ci_log_options ) {
#if defined(__linux__) && defined(__KERNEL__)
    if( ci_log_options & CI_LOG_CPU )
      n += ci_sprintf(line + n, "%d ", (int) smp_processor_id());
    if( ci_log_options & CI_LOG_PID )
      n += ci_sprintf(line + n, "%d ",
                      in_interrupt() ? 0 : (int) current->tgid);
    if( ci_log_options & CI_LOG_TID )
      n += ci_sprintf(line + n, "%d ",
                      in_interrupt() ? 0: (int) current->pid);
#elif defined(__FreeBSD__) && !defined(__KERNEL__)
    if( ci_log_options & CI_LOG_PID )
      n += ci_sprintf(line + n, "%d ", (int) getpid());
    if( ci_log_options & CI_LOG_TID )
      n += ci_sprintf(line + n, "%ld ", (long) pthread_self());
#elif defined(__unix__) && !defined(__KERNEL__)
    if( ci_log_options & CI_LOG_PID )
      n += ci_sprintf(line + n, "%d ", (int) getpid());
    if( ci_log_options & CI_LOG_TID )
      n += ci_sprintf(line + n, "%lx ", (long) pthread_self());
#endif
#ifdef CI_HAVE_FRC64
    if( ci_log_options & CI_LOG_TIME )
      n += ci_sprintf(line + n, "%010"CI_PRIu64" ",
		   (ci_uint64) (ci_frc64_get() & 0xffffffffffull));
#elif defined(CI_HAVE_FRC32)
    if( ci_log_options & CI_LOG_TIME )
      n += ci_sprintf(line + n, "%010u ", (unsigned) ci_frc32_get());
#endif
    if( ci_log_options & CI_LOG_DELTA ) {
      static ci_uint32 prev = 0;
      ci_uint32 now = ci_frc32_get();
      n += ci_sprintf(line + n, "%06u ", (unsigned) now - prev);
      prev = now;
    }
  }

  memcpy(line + n, ci_log_prefix, ci_log_prefix_len);
#ifdef CI_HAVE_NPRINTF
  vsnprintf(line + n + ci_log_prefix_len,
	    CI_LOG_MAX_LINE - ci_log_prefix_len - n, fmt, args);
#else
  {
    int len;
    len = ci_vsprintf(line + n + ci_log_prefix_len, fmt, args);
    if (len+1 > CI_LOG_MAX_LINE - ci_log_prefix_len - n) {
#if defined(__linux__) && !defined(__KERNEL__)
      printk(KERN_ERR "ci_vlog: too long %d : %50s", len, line);
#endif
      CI_BOMB();
    }
  }
#endif

  ci_log_fn(line);

#ifdef __KERNEL__
  /* It's possible we did a kalloc above - if so we'd better free it
   * (Note: we're allowed to pass NULL to kfree)
   */
  kfree (heap_line);
#endif
}


void ci_log(const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ci_vlog(fmt, args);
  va_end(args);
}

/* Wrapper to make ci_log conform to the signature of an oo_dump_log_fn_t. */
void ci_log_dump_fn(void* unused, const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ci_vlog(fmt, args);
  va_end(args);
}


void ci_set_log_prefix(const char* prefix)
{
  if( !prefix ) {
    ci_log_prefix = CI_LOG_PREFIX_DEFAULT;
    return;
  }

  ci_assert(strlen(prefix) < CI_LOG_MAX_LINE);

  ci_log_prefix = prefix;

  ci_log_prefix_len = strlen(ci_log_prefix);
}


/*! \cidoxg_end */
