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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Per-thread state
**   \date  2011/04/20
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_PER_THREAD_H__
#define __ONLOAD_UL_PER_THREAD_H__

#include <onload/signals.h>
#include <onload/ul/stackname.h>


struct oo_per_thread {
  int                        initialised;
  struct oo_sig_thread_state sig;
  struct oo_stackname_state  stackname;
  ci_uint64                  poll_nonblock_fast_frc;
  struct oo_timesync         timesync;
  unsigned                   spinstate; 
};


/* Initialise the per-thread module. */
extern int oo_per_thread_init(void);


#ifdef HAVE_CC__THREAD

extern __thread struct oo_per_thread* oo_per_thread_p CI_HV;
extern __thread struct oo_per_thread oo_per_thread CI_HV;

/* Initialise this thread's per-thread state. */
extern void oo_per_thread_init_thread(void);

/* Get pointer to per-thread state.  The per-thread state may not be
 * initialised, so only use for members that don't require explicit
 * initialisation (and when performance really matters).
 */
ci_inline struct oo_per_thread* __oo_per_thread_get(void)
{
  return &oo_per_thread;
}

ci_inline struct oo_per_thread* oo_per_thread_get(void)
{
  if(CI_UNLIKELY( !oo_per_thread.initialised ))
    oo_per_thread_init_thread();
  return &oo_per_thread;
}

#else 

extern pthread_key_t oo_per_thread_key CI_HV;

extern struct oo_per_thread* oo_per_thread_init_and_get(void);

ci_inline struct oo_per_thread* oo_per_thread_get(void)
{
  struct oo_per_thread* pt = pthread_getspecific(oo_per_thread_key);
  if(CI_LIKELY( pt != NULL && pt->initialized ))
    return pt;
  else
    return oo_per_thread_init_and_get();
}

ci_inline struct oo_per_thread* __oo_per_thread_get(void)
{
  return oo_per_thread_get();
}

#endif

#endif  /* __ONLOAD_UL_PER_THREAD_H__ */
