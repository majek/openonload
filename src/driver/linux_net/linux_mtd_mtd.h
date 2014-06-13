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
 * Driver for Solarflare network controllers and boards
 * Copyright 2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Prior to Linux 3.2, <linux/mtd/mtd.h> would define a DEBUG
 * function-like macro, which we really don't want.  Save and
 * restore the defined-ness of DEBUG across this #include.
 */

#ifdef DEBUG
#define EFX_MTD_DEBUG
#undef DEBUG
#endif
#include <linux/mtd/mtd.h>
#undef DEBUG
#ifdef EFX_MTD_DEBUG
#define DEBUG
#endif
