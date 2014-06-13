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
** <L5_PRIVATE L5_HEADER>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 31/3/04
** Description: Resource initialisation code
** </L5_PRIVATE>
\**************************************************************************/

#include <etherfabric/base.h>
#include <etherfabric/iobufset.h>
#include "ef_vi_internal.h"


ef_vi_inline unsigned ef_log2_ge(unsigned long n, unsigned min_order) {
  unsigned order = min_order;
  while( (1ul << order) < n )  ++order;
  return order;
}


unsigned ef_iobufset_dimension(ef_iobufset* bufs, int size, int num,
                               int align)
{
  uint32_t log2_size, size_r, n_pages;

  EF_VI_BUG_ON(size <= 0);

  /* size of individual buffers is aligned */
  size = EF_VI_ROUND_UP(size, align);

  if( size < EF_VI_PAGE_SIZE ) {
    /* round up size to a power of 2 */
    log2_size = ef_log2_ge(size, 0);
    size_r  = 1 << log2_size; 
    n_pages = ((size_r * num) + EF_VI_PAGE_SIZE - 1) >> EF_VI_PAGE_SHIFT;
  }
  else {
    /* align up size to a EF_VI_PAGE_SIZE */
    size_r  = EF_VI_ALIGN_FWD(size, EF_VI_PAGE_SIZE);
    n_pages = (size_r / EF_VI_PAGE_SIZE) * num;
  }

  if( bufs ) {
    bufs->bufs_num = num;
    bufs->bufs_size = size_r;
  }

  return n_pages;
}


void ef_iobufset_init(ef_iobufset* bufs, ef_addr bufaddr,
                      void* ptr, int offset)
{
  EF_VI_BUG_ON(ptr == NULL);

#ifdef __KERNEL__
  bufs->bufs_ptr_off = offset;
#else
  bufs->bufs_ptr = (char*) ptr + offset;
#endif
  bufs->bufs_addr = bufaddr + offset;
  /* The rest were initialised in ef_iobufset_dimension(). */
}

/*! \cidoxg_end */
