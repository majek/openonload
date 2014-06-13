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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains Linux-specific API internal for the resource driver.
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

#ifndef __LINUX_RESOURCE_INTERNAL__
#define __LINUX_RESOURCE_INTERNAL__

#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/driver_private.h>
#include <ci/driver/efab/hardware.h>
#include <driver/linux_net/driverlink_api.h>

extern int  efrm_driverlink_register(void);
extern void efrm_driverlink_unregister(void);

extern int
efrm_nic_add(struct efx_dl_device *dl_device, unsigned int opts,
	     const uint8_t *mac_addr,
	     struct linux_efhw_nic **lnic_out, spinlock_t *reg_lock,
	     const struct vi_resource_dimensions *, int ifindex,
	     unsigned timer_quantum_ns, unsigned rx_prefix_len,
	     unsigned rx_usr_buf_size);
extern void efrm_nic_del(struct linux_efhw_nic *);

extern int efrm_install_proc_entries(void);
extern void efrm_uninstall_proc_entries(void);

#ifdef CONFIG_SFC_RESOURCE_VF
extern void efrm_vf_driver_init(void);
extern void efrm_vf_driver_fini(void);
#endif

#endif  /* __LINUX_RESOURCE_INTERNAL__ */
