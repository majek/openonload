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


#ifndef __ONLOAD_CONTIG_SHMBUF__
#define __ONLOAD_CONTIG_SHMBUF__

#include <ci/compat.h>
#include <ci/tools/debug.h>
#include <ci/tools/log.h>

extern unsigned ci_va_to_pfn(void* addr);

/*--------------------------------------------------------------------
 *
 * ci_contig_shmbuf_t: A (potentially) large buffer that is contiguous in
 * the driver address space, and may be mapped to userlevel.
 *
 *--------------------------------------------------------------------*/

typedef struct {
  char*		p;
  unsigned	bytes;
} ci_contig_shmbuf_t;

extern int ci_contig_shmbuf_alloc(ci_contig_shmbuf_t* kus, unsigned bytes);
extern void ci_contig_shmbuf_free(ci_contig_shmbuf_t* kus);

ci_inline caddr_t ci_contig_shmbuf_ptr(ci_contig_shmbuf_t* kus)
{ return kus->p; }

ci_inline size_t ci_contig_shmbuf_size(ci_contig_shmbuf_t* kus)
{ return kus->bytes; }

ci_inline int ci_contig_shmbuf_mmap(ci_contig_shmbuf_t* kus, unsigned offset,
				unsigned long* bytes, void* opaque,
				int* map_num, unsigned long* p_offset) {
  unsigned n = ci_contig_shmbuf_size(kus) - offset;
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  ++*map_num;
  *p_offset += n;
  return 0;
}

/*! map offset in contiguous shmbuf to physical page frame number */
ci_inline unsigned ci_contig_shmbuf_nopage(ci_contig_shmbuf_t* kus,
					   unsigned offset)
{
  ci_assert(CI_OFFSET(offset, CI_PAGE_SIZE) == 0);
  ci_assert(offset < kus->bytes);
  return ci_va_to_pfn(kus->p + offset);
}

#endif /* __ONLOAD_CONTIG_SHMBUF__ */
