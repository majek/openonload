/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains API provided by efhw/falcon.c file.  This file is not
 * designed for use outside of the SFC resource driver.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __CI_EFHW_FALCON_H__
#define __CI_EFHW_FALCON_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efhw/common.h>

/*----------------------------------------------------------------------------
 *
 * Locks - unfortunately required
 *
 *---------------------------------------------------------------------------*/

#define FALCON_LOCK_DECL        irq_flags_t lock_state
#define FALCON_LOCK_LOCK(nic) \
	spin_lock_irqsave((nic)->reg_lock, lock_state)
#define FALCON_LOCK_UNLOCK(nic) \
	spin_unlock_irqrestore((nic)->reg_lock, lock_state)


extern struct efhw_func_ops falcon_char_functional_units;
extern void falcon_nic_wakeup_mask_set(struct efhw_nic *nic, unsigned mask);

/*! confirm buffer table updates - should be used for items where
   loss of data would be unacceptable. E.g for the buffers that back
   an event or DMA queue */
extern void falcon_nic_buffer_table_confirm(struct efhw_nic *nic);

#endif /* __CI_EFHW_FALCON_H__ */
