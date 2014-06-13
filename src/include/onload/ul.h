/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

/*! \cidoxg_include_onload */

#ifndef __ONLOAD_UL_H__
#define __ONLOAD_UL_H__

#include <etherfabric/base.h>

#if !defined(__KERNEL__)
#  include <onload/unix_intf.h>
#endif

#include <onload/driveraccess.h>

/* Onload open functions:
 * oo_fd_open - function to be used in tests and tool. It just opens the
 *              onload device
 * oo_open - internal function, should not be used
 * ef_onload_driver_open - function to be used in the preloaded library.
 *                         It correctly handles open() replacement and
 *                         chroot.
 */

/*! Obtain a driver handle. */
extern int ef_onload_driver_open(ef_driver_handle* nic_out, int cloexec) CI_HF;

/*! Close a driver handle. */
ci_inline int
ef_onload_driver_close(ef_driver_handle nic)
{
  return oo_close(nic);
}

/*! Open and save a driver handle for later cloning. */
extern int ef_driver_save_fd(void) CI_HF;

#endif /* __ONLOAD_UL_H__ */
/*! \cidoxg_end */
