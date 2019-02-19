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

/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

#ifndef __ONLOAD_CPLANE_AF_UNIX_H__
#define __ONLOAD_CPLANE_AF_UNIX_H__

#include <sys/un.h>

static void cp_init_af_unix_addr(struct sockaddr_un* addr,
                                 ci_uint32 server_pid)
{
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 2,
           "onload_cp_server.%d", server_pid);
}

#endif /* __ONLOAD_CPLANE_AF_UNIX_H__ */
