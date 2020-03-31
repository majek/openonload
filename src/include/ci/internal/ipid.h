/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  IP ID allocation - values used in kernel & in UL
**   \date  2004/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal */

#ifndef __CI_INTERNAL_IPID_H__
#define __CI_INTERNAL_IPID_H__

/* In many cases, ipid=0 is a bad idea.  So, we avoid the first block */
# define CI_IPID_MIN 0x0400
# define CI_IPID_MAX 0xffff

/* MUST be a power of 2 */
#define CI_IPID_BLOCK_LENGTH 1024
/* must be the right number for shifts for CI_IPID_BLOCK_LENGTH */
#define CI_IPID_BLOCK_SHIFT  10

#define CI_IPID_BLOCK_MASK   (CI_IPID_BLOCK_LENGTH-1)
#define CI_IPID_BLOCK_COUNT                                             \
  (((CI_IPID_MAX+1)/CI_IPID_BLOCK_LENGTH) - (CI_IPID_MIN/CI_IPID_BLOCK_LENGTH))

#define CI_IPID_MIN_BLOCK_INDEX (CI_IPID_MIN / CI_IPID_BLOCK_LENGTH)
#define CI_IPID_MAX_BLOCK_INDEX                         \
  (CI_IPID_MIN_BLOCK_INDEX + CI_IPID_BLOCK_COUNT - 1)

/* **** control values used in the netif state struct. **** */

/* Minimum cycle time (in ticks) for the IP IDs - if we try to re-use
 * the first item in less than this time we will (try to) go get
 * some more IDs from the char driver
 */
#define CI_IPID_MIN_CYCLE_TIME       (5000)

/* "Maximum" cycle time (in ticks) for the IP IDs.  If the return to the
 * first item is longer than this period then we do not update the
 * low_use_start_time_ms field
 */
#define CI_IPID_MAX_CYCLE_TIME       (30000)

/* Release time (in ticks) for the IP IDs.  If the delta from 
 * low_use_start_time_ms to "now" is greater than this value we will
 * release one IPID range record (but always retain at least one record)
 */
#define CI_IPID_LOW_USE_TIME (5 * CI_IPID_MAX_CYCLE_TIME)


#endif

/*! \cidoxg_end */
