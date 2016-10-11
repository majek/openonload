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

/* External API for UL users of libcplane. */
#ifndef __CPLANE_UL_H__
#define __CPLANE_UL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cplane/shared_types.h>

/* Get cplane handle.  Initializes such a handle if it does not exist for
 * this process. */
extern cicp_handle_t *cicp_get_handle(const char *api_version, int fd);

#ifdef __cplusplus
}
#endif

#endif /* __CPLANE_UL_H__ */
