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
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_platform  */

#ifndef __CI_DRIVER_PLATFORM_UL_COMMON_H__
#define __CI_DRIVER_PLATFORM_UL_COMMON_H__


/*--------------------------------------------------------------------
 *
 * Hardware cosimulation varients of the user level driver
 *
 *--------------------------------------------------------------------*/

typedef void * ci_addr_spc_t;

#define CI_ADDR_SPC_INVALID     ((ci_addr_spc_t)(ci_uintptr_t) 1)
#define CI_ADDR_SPC_KERNEL      ((ci_addr_spc_t)(ci_uintptr_t) 2)
#define CI_ADDR_SPC_CURRENT     ((ci_addr_spc_t)(ci_uintptr_t) 3)

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


ci_inline int ci_contig_shmbuf_alloc(ci_contig_shmbuf_t* kus, unsigned bytes) {
  ci_assert(bytes > 0);
  kus->bytes = CI_ROUND_UP(bytes, CI_PAGE_SIZE);
  kus->p = ci_alloc(kus->bytes);
  return kus->p ? 0 : -ENOMEM;
}

ci_inline void ci_contig_shmbuf_free(ci_contig_shmbuf_t* kus) {
  ci_assert(kus);  ci_assert(kus->p);
  ci_free(kus->p);
  CI_DEBUG_ZERO(kus);
}

ci_inline caddr_t ci_contig_shmbuf_ptr(ci_contig_shmbuf_t* kus)
{ return kus->p; }

ci_inline size_t ci_contig_shmbuf_size(ci_contig_shmbuf_t* kus)
{ return kus->bytes; }


/*--------------------------------------------------------------------
 *
 * PCI configuration helpers
 *
 *--------------------------------------------------------------------*/

#define  PCI_BASE_ADDRESS_SPACE	0x01	/* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#ifndef PCI_BASE_ADDRESS_MEM_MASK /* may be defined in linux/pci_regs.h */
#define  PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#endif


/*--------------------------------------------------------------------
 *
 * udelay - stalls execution for up to 50us
 *
 *--------------------------------------------------------------------*/

/*! Stalls execution for up to 50us */
extern void ci_udelay(unsigned long usec);
extern int  ci_udelay_init(void);



#endif  /* __CI_DRIVER_PLATFORM_UL_COMMON_H__ */

/*! \cidoxg_end */
