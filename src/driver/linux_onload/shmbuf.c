/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** \author  ok_sasha
**  \brief  shmbuf Linux support
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 
#include <onload/debug.h>
#include <onload/shmbuf.h>

int ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned bytes)
{
  unsigned i;

  ci_assert(b);
  
  b->n_pages = CI_ROUND_UP(bytes, CI_PAGE_SIZE) >> CI_PAGE_SHIFT;
  b->pages = ci_alloc(b->n_pages * sizeof(b->pages[0]));
  if( b->pages == 0 )  return -ENOMEM;

  for( i = 0; i < b->n_pages; ++i )  efhw_page_mark_invalid(&b->pages[i]);

  return 0;
}


void ci_shmbuf_free(ci_shmbuf_t* b)
{
  unsigned i;

  ci_assert(b);
  ci_assert(b->pages);

  for( i = 0; i < b->n_pages; ++i )
    if( efhw_page_is_valid(&b->pages[i]) )
      efhw_page_free(&b->pages[i]);

  ci_free(b->pages);
}


int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i,
			       ci_irqlock_t* lock)
{
  ci_assert(b);
  ci_assert(page_i < b->n_pages);

  if( ! efhw_page_is_valid(&b->pages[page_i]) ) {
    struct efhw_page p;
    if( efhw_page_alloc_zeroed(&p) == 0 ) {
      ci_irqlock_state_t lock_flags;
      ci_irqlock_lock(lock, &lock_flags);
      if( ! efhw_page_is_valid(&b->pages[page_i]) ) {
	b->pages[page_i] = p;
	efhw_page_mark_invalid(&p);
      }
      ci_irqlock_unlock(lock, &lock_flags);
      if( efhw_page_is_valid(&p) )  efhw_page_free(&p);
      return 0;
    }
    OO_DEBUG_VM(ci_log("%s: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  return 0;
}

/*! \cidoxg_end */
