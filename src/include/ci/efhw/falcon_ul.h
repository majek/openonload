/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
  /**************************************************************************\
*//*! \file falcon_ul.h
   ** <L5_PRIVATE L5_HEADER >
   ** \author  kjm
   **  \brief  User-level driver interface.
   **   \date  2007/07/28
   **    \cop  (c) Solarflare Communications Inc.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_efhw  */

#ifndef __CI_EFHW_FALCON_UL_H__
#define __CI_EFHW_FALCON_UL_H__

#if defined(__KERNEL__)
#error "This header is UL-only"
#endif

#include <ci/efhw/efhw_types.h>
#include <ci/driver/efab/hardware/falcon_ul.h>

/*----------------------------------------------------------------------------
 *
 * DEBUG - User Level Driver Entry Points
 *
 *---------------------------------------------------------------------------*/

/* 
 * These functions are really defined in falcon.c, but they are exported in
 * userland only. 
 */

extern void falcon_nic_tx_cfg(struct efhw_nic *, int unlocked);

extern void falcon_ab_timer_tbl_set(struct efhw_nic *, unsigned evq,	/* timer id */
			     unsigned mode,	/* mode bits */
			     unsigned countdown /* counting value to set */ );

extern void siena_timer_tbl_set(struct efhw_nic *, int instance, int enable,
				int is_interrupting, int mode, int countdown);


#endif /* __CI_EFHW_FALCON_UL_H__ */
/*! \cidoxg_end */
