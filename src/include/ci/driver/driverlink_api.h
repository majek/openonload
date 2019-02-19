/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#ifndef __CI_DRIVER_DRIVERLINK_API__
#define __CI_DRIVER_DRIVERLINK_API__

#define EFX_DRIVERLINK_API_VERSION_MINOR 0

#include <driver/linux_net/driverlink_api.h>

/* Every time the major driverlink version is bumped, this check forces a build
 * failure, as it's necessary to audit the net driver change for compatibility
 * with driverlink clients.  */
#if EFX_DRIVERLINK_API_VERSION > 25
#error "Driverlink API has changed.  Audit client code for compatibility."
#endif

#endif  /* __CI_DRIVER_DRIVERLINK_API__ */
