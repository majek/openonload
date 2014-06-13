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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Per-thread state
**   \date  2011/04/20
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/ul/per_thread.h>


#ifdef HAVE_CC__THREAD

#ifdef __powerpc__
__thread struct oo_per_thread oo_per_thread __attribute__((tls_model("local-dynamic")));
#else
__thread struct oo_per_thread oo_per_thread;
#endif

#else

pthread_key_t oo_per_thread_key = INVALID_PTHREAD_KEY_ID;

#endif

citp_init_thread_callback init_thread_callback;


int oo_per_thread_init(void)
{
#ifndef HAVE_CC__THREAD
  int rc = pthread_key_create(&oo_per_thread_key, ci_libc_free);
  if( rc != 0) {
    LOG_E(log("%s: ERROR: pthread_key_create failed (rc=%d errno=%d)",
              __FUNCTION__, rc, errno));
    return -1;
  }
#endif
  return 0;
}


#ifdef HAVE_CC__THREAD

void oo_per_thread_init_thread(void)
{
  if( init_thread_callback ) {
    init_thread_callback(&oo_per_thread);
    oo_per_thread.initialised = 1;
    oo_per_thread.in_vfork_child = 0;
  }
}

#else

struct oo_per_thread* oo_per_thread_init_and_get(void)
{
  struct oo_per_thread* pt = pthread_getspecific(oo_per_thread_key);
  if( pt == NULL ) {
    pt = ci_libc_malloc(sizeof(*oo_per_thread_p));
    CI_TEST(pt != NULL);
    pthread_setspecific(oo_per_thread_key, pt);
    memset(pt, 0, sizeof(*pt));
  }
  if( init_thread_callback ) {
    init_thread_callback(pt);
    pt->initialised = 1;
    pt->in_vfork_child = 0;
  }
  return pt;
}

#endif
