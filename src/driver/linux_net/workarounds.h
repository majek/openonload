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

/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2006-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_WORKAROUNDS_H
#define EFX_WORKAROUNDS_H

/*
 * Hardware workarounds.
 * Bug numbers are from Solarflare's Bugzilla.
 */

#define EFX_WORKAROUND_FARCH(efx) (efx_nic_rev(efx) <= EFX_REV_SIENA_A0)
#ifdef CONFIG_SFC_FALCON
#define EFX_WORKAROUND_FALCON_A(efx) (efx_nic_rev(efx) <= EFX_REV_FALCON_A1)
#define EFX_WORKAROUND_FALCON_B(efx) (efx_nic_rev(efx) == EFX_REV_FALCON_B0)
#define EFX_WORKAROUND_FALCON_AB(efx) (efx_nic_rev(efx) <= EFX_REV_FALCON_B0)
#else
#define EFX_WORKAROUND_FALCON_A(efx) (0)
#define EFX_WORKAROUND_FALCON_B(efx) (0)
#define EFX_WORKAROUND_FALCON_AB(efx) (0)
#endif
#define EFX_WORKAROUND_SIENA(efx) (efx_nic_rev(efx) == EFX_REV_SIENA_A0)
#define EFX_WORKAROUND_EF10(efx) (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)

/* Selftests need to be retried */
#define EFX_WORKAROUND_8568 EFX_WORKAROUND_FARCH
/* Truncated IPv4 packets can confuse the TX packet parser */
#define EFX_WORKAROUND_15592 EFX_WORKAROUND_FALCON_AB
/* Legacy interrupt storm when interrupt fifo fills */
#define EFX_WORKAROUND_17213 EFX_WORKAROUND_SIENA

/* Unaligned read request >512 bytes after aligning may break TSORT */
#define EFX_WORKAROUND_5391 EFX_WORKAROUND_FALCON_A
/* RX events go missing */
#define EFX_WORKAROUND_5676 EFX_WORKAROUND_FALCON_A
/* RX_RESET on A1 */
#define EFX_WORKAROUND_6555 EFX_WORKAROUND_FALCON_A
/* Flushes may never complete */
#define EFX_WORKAROUND_7803 EFX_WORKAROUND_FALCON_AB
/* Leak overlength packets rather than free */
#define EFX_WORKAROUND_8071 EFX_WORKAROUND_FALCON_A

/* Lockup when writing event block registers at gen2/gen3 */
#define EFX_EF10_WORKAROUND_35388(efx)					\
	((struct efx_ef10_nic_data *)efx->nic_data)->workaround_35388
#define EFX_WORKAROUND_35388(efx)					\
	(efx_nic_rev(efx) == EFX_REV_HUNT_A0 && EFX_EF10_WORKAROUND_35388(efx))

#ifdef EFX_NOT_UPSTREAM
/* RX doorbell seems to go AWOL on Stratus machines during breaker tests */
#define EFX_WORKAROUND_59975(efx) 0
/* Driverlink probe can take >1 sec to perform license challenge */
#define EFX_WORKAROUND_62649 defined
#endif

/* Moderation timer access must go through MCDI */
#define EFX_EF10_WORKAROUND_61265(efx)					\
	((struct efx_ef10_nic_data *)efx->nic_data)->workaround_61265

#endif /* EFX_WORKAROUNDS_H */
