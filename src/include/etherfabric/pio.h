/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
 * Copyright 2012-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
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

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Programmed Input/Output for EtherFabric Virtual Interface HAL.
** \date      2015/02/16
** \copyright Copyright &copy; 2015 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_PIO_H__
#define __EFAB_PIO_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif


/*! \brief A Programmed I/O region */
typedef struct ef_pio {
  /** The buffer for the Programmed I/O region */
  uint8_t*         pio_buffer;
  /** The I/O region of the virtual interface that is linked with the
  ** Programmed I/O region */
  uint8_t*         pio_io;
  /** The resource ID for the Programmed I/O region */
  unsigned         pio_resource_id;
  /** The length of the Programmed I/O region */
  unsigned         pio_len;
} ef_pio;


struct ef_pd;
struct ef_vi;

#ifdef __x86_64__
/*! \brief Allocate a Programmed I/O region
**
** \param pio      Memory to use for the allocated Programmed I/O region.
** \param pio_dh   The ef_driver_handle to associate with the Programmed
**                 I/O region.
** \param pd       The protection domain to associate with the Programmed
**                 I/O region.
** \param len_hint Hint for the requested length of the Programmed I/O
**                 region.
** \param pd_dh    The ef_driver_handle for the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Allocate a Programmed I/O region.
**
** This function is available only on 64-bit x86 processors.
*/
extern int ef_pio_alloc(ef_pio* pio, ef_driver_handle pio_dh, struct ef_pd* pd,
                        unsigned len_hint, ef_driver_handle pd_dh);
#endif


/*! \brief Get the size of the Programmed I/O region
**
** \param vi The virtual interface to query.
**
** \return The size of the Programmed I/O region.
**
** Get the size of the Programmed I/O region.
*/
extern int ef_vi_get_pio_size(ef_vi* vi);


/*! \brief Free a Programmed I/O region
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
**
** \return 0 on success, or a negative error code.
**
** Free a Programmed I/O region.
**
** The Programmed I/O region must not be linked when this function is
** called. See ef_pio_unlink_vi().
**
** To free up all resources, the associated driver handle must then be
** closed by calling ef_driver_close()).
*/
extern int ef_pio_free(ef_pio* pio, ef_driver_handle pio_dh);


/*! \brief Link a Programmed I/O region with a virtual interface
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
** \param vi     The virtual interface to link with the Programmed I/O
**               region.
** \param vi_dh  The ef_driver_handle for the virtual interface.
**
** \return 0 on success, or a negative error code.
**
** Link a Programmed I/O region with a virtual interface.
*/
extern int ef_pio_link_vi(ef_pio* pio, ef_driver_handle pio_dh,
                          struct ef_vi* vi, ef_driver_handle vi_dh);

/*! \brief Unlink a Programmed I/O region from a virtual interface
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
** \param vi     The virtual interface to unlink from the Programmed I/O
**               region.
** \param vi_dh  The ef_driver_handle for the virtual interface.
**
** \return 0 on success, or a negative error code.
**
** Unlink a Programmed I/O region from a virtual interface.
*/
extern int ef_pio_unlink_vi(ef_pio* pio, ef_driver_handle pio_dh,
                            struct ef_vi* vi, ef_driver_handle vi_dh);


/*! \brief Copy data from memory into a Programmed I/O region
**
** \param vi     The virtual interface for the Programmed I/O region.
** \param base   The base address of the memory to copy.
** \param offset The offset into the Programmed I/O region at which to copy
**               the data. This must be a multiple of 8, otherwise adjacent
**               sends might result in corrupt data.
** \param len    The number of bytes to copy.
**
** \return 0 on success, or a negative error code.
**
** Copy data from memory into a Programmed I/O region.
**
** This function copies the data via a local copy of the adapter's
** Programmed I/O buffer.
**
** The Programmed I/O region can hold multiple smaller packets, referenced
** by different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
extern int ef_pio_memcpy(ef_vi* vi, const void* base, int offset, int len);


#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PIO_H__ */
