/*
** Copyright 2005-2013  Solarflare Communications Inc.
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

/****************************************************************************
 * Copyright 2012-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
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

#ifndef __EFAB_PD_H__
#define __EFAB_PD_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

enum ef_pd_flags {
	EF_PD_DEFAULT   = 0x0,
	EF_PD_VF        = 0x1,
	EF_PD_PHYS_MODE = 0x2,
};


typedef struct ef_pd {
	enum ef_pd_flags pd_flags;
	unsigned         pd_resource_id;
} ef_pd;


  /*! Allocate a protection domain. */
extern int ef_pd_alloc(ef_pd*, ef_driver_handle, int ifindex,
		       enum ef_pd_flags flags);

  /*! Unregister a memory region. */
extern int ef_pd_free(ef_pd*, ef_driver_handle);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PD_H__ */
