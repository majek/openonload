/*
** Copyright 2005-2015  Solarflare Communications Inc.
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

/* These are only used by user-level tools. */

/*!< Read strap pins to get MAC settings & init MAC plugin to match */
extern int falcon_nic_get_mac_config(struct efhw_nic *nic);

#endif /* __CI_EFHW_FALCON_UL_H__ */
/*! \cidoxg_end */
