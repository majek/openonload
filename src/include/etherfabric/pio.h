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

#ifndef __EFAB_PIO_H__
#define __EFAB_PIO_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ef_pio {
	uint8_t*         pio_buffer;
	uint8_t*         pio_io;
	unsigned         pio_resource_id;
	unsigned         pio_len;
} ef_pio;


struct ef_pd;
struct ef_vi;

extern int ef_pio_alloc(ef_pio*, ef_driver_handle pio_dh, struct ef_pd*,
			unsigned len_hint, ef_driver_handle pd_dh);
extern int ef_pio_free(ef_pio*, ef_driver_handle dh);
extern int ef_pio_link_vi(ef_pio*, ef_driver_handle pio_dh, struct ef_vi*,
			  ef_driver_handle vi_dh);
extern int ef_pio_unlink_vi(ef_pio*, ef_driver_handle pio_dh, struct ef_vi*,
			    ef_driver_handle vi_dh);
extern int ef_pio_memcpy(ef_vi*, const void* base, int offset, int len);
extern int ef_vi_get_pio_size(ef_vi* vi);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PIO_H__ */
