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
** \author  ok_sasha
**  \brief  shmbuf Linux support
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver  */
 
#ifndef __CI_DRIVER_EFAB_SHMBUF_H__
#define __CI_DRIVER_EFAB_SHMBUF_H__

#include <ci/driver/internal.h>
#include <ci/efhw/iopage_types.h>

/*--------------------------------------------------------------------
 *
 * ci_shmbuf_t: A (potentially) large buffer that is page-wise contiguous
 * in the kernel address space.  It may be mapped to userlevel, where it is
 * contiguous.  On some platforms, pages may be allocated on demand.
 *
 * On Linux, pages are allocated on-demand.
 *
 *--------------------------------------------------------------------*/

typedef struct {
  struct efhw_page*	pages;
  unsigned		n_pages;
} ci_shmbuf_t;


extern int  ci_shmbuf_alloc(ci_shmbuf_t* b, unsigned bytes);
extern void ci_shmbuf_free(ci_shmbuf_t* b);

ci_inline unsigned ci_shmbuf_size(ci_shmbuf_t* b)
{ return b->n_pages << CI_PAGE_SHIFT; }

#define __ci_shmbuf_ptr(b, off)				\
  (efhw_page_ptr(&(b)->pages[(off) >> CI_PAGE_SHIFT])	\
   + ((off) & (CI_PAGE_SIZE - 1)))

#define __ci_shmbuf_page_ptr(b, page_i)		\
  efhw_page_ptr(&(b)->pages[(page_i)])

/* Returns true if accessing the shmbuf at the given offset (using
** efab_shmbuf_ptr above) is safe.
*/
ci_inline int ci_shmbuf_access_okay(ci_shmbuf_t* b, unsigned off,
				    unsigned size) {
  unsigned end_off = off + size - 1;
  /*
  ci_log("checking validity of %x", off >> CI_PAGE_SHIFT);
  ci_log("off %x size %x bufsize %x",
          off, size, (b->n_pages << CI_PAGE_SHIFT));
  ci_log("valid %d %d,",
	  efhw_page_is_valid(&b->pages[off >> CI_PAGE_SHIFT]),
	  efhw_page_is_valid(&b->pages[end_off >> CI_PAGE_SHIFT])); 
  ci_log("eptr %p %p",__ci_shmbuf_ptr(b, off) + size - 1, __ci_shmbuf_ptr(b, end_off));
  */  
  return 1
    /* The region lies within the shmbuf. */
    && off + size <= (b->n_pages << CI_PAGE_SHIFT)
    /* Pages have been allocated (assumes size <= CI_PAGE_SIZE). */
    && efhw_page_is_valid(&b->pages[off >> CI_PAGE_SHIFT])
    && efhw_page_is_valid(&b->pages[end_off >> CI_PAGE_SHIFT])
    /* The object is contiguous in kernel address space. */
    && __ci_shmbuf_ptr(b, off) + size - 1
    == __ci_shmbuf_ptr(b, end_off);
}

ci_inline char* ci_shmbuf_ptr(ci_shmbuf_t* b, unsigned off) {
  ci_assert(ci_shmbuf_access_okay(b, off, 1));
  return __ci_shmbuf_ptr(b, off);
}

ci_inline char* ci_shmbuf_page_ptr(ci_shmbuf_t* b, unsigned page_i) {
  ci_assert(page_i < b->n_pages);
  ci_assert(efhw_page_is_valid(&b->pages[page_i]));
  return __ci_shmbuf_page_ptr(b, page_i);
}

extern int ci_shmbuf_demand_page(ci_shmbuf_t* b, unsigned page_i,
				 ci_irqlock_t* lock);


ci_inline unsigned ci_shmbuf_nopage(ci_shmbuf_t* b, unsigned offset)
{
  ci_assert(CI_OFFSET(offset, CI_PAGE_SIZE) == 0);
  offset >>= CI_PAGE_SHIFT;
  ci_assert(offset < b->n_pages);
  if( efhw_page_is_valid(&b->pages[offset]) )
    return efhw_page_pfn(&b->pages[offset]);
  else 
    return (unsigned) -1;
}

ci_inline unsigned ci_shmbuf_demand_nopage(ci_shmbuf_t* b, unsigned offset,
					   ci_irqlock_t* lock)
{
  unsigned page_i = offset >> CI_PAGE_SHIFT;
  int rc = 0;
  ci_assert(CI_OFFSET(offset, CI_PAGE_SIZE) == 0);
  ci_assert(page_i < b->n_pages);
  if( ! efhw_page_is_valid(&b->pages[page_i]) )
    rc = ci_shmbuf_demand_page(b, page_i, lock);
  if( rc == 0 )  return efhw_page_pfn(&b->pages[page_i]);
  else           return (unsigned) -1;
}

ci_inline int ci_shmbuf_mmap(ci_shmbuf_t* b, unsigned offset,
			     unsigned long* bytes, void* opaque,
			     int* map_num, unsigned long* p_offset)
{
  unsigned n = ci_shmbuf_size(b) - offset;
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  ++*map_num;
  *p_offset += n;
  return 0;
}


#endif /* __CI_DRIVER_EFAB_SHMBUF_H__ */

/*! \cidoxg_end */
