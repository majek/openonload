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

#ifndef __CI_INTERNAL_PIO_BUDDY_H__
#define __CI_INTERNAL_PIO_BUDDY_H__


struct ci_pio_buddy_allocator;
struct ci_netif;


/*! Initialise a PIO buddy allocator. */
extern void ci_pio_buddy_ctor(ci_netif* ni, ci_pio_buddy_allocator* buddy);

/*! Destruct a PIO buddy allocator. */
extern void ci_pio_buddy_dtor(ci_netif* ni, ci_pio_buddy_allocator* buddy);

/*! Allocate a block from the PIO region.  Allocates a block of length
 * 1 << order and returns the offset into the PIO region of that block.
 * Returns less than 0 (errno) on failure.
 */
extern ci_int32 ci_pio_buddy_alloc(ci_netif* ni, ci_pio_buddy_allocator*,
                              ci_uint8 order);

/*! Free a block in the PIO region.  The provided offset should be an offset
 * into the region as returned from ci_pio_buddy_alloc.
 */
extern void ci_pio_buddy_free(ci_netif* ni, ci_pio_buddy_allocator*,
                              ci_int32 offset, ci_uint8 order);


#endif  /* __CI_INTERNAL_PIO_BUDDY_H__ */

