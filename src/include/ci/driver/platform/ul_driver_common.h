/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
