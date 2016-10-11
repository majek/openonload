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

#ifndef __CPLANE_UL_STSCALLS_H__
#define __CPLANE_UL_STSCALLS_H__

#include <unistd.h>
#include <sys/syscall.h>

/* We are linked with complicated libraries which overwrite open(),
 * close() and ioctl().  So we use syscall() if we need to call them.
 */

static inline int cp_sys_open(const char *path, int flags)
{
  return syscall(SYS_open, (unsigned long)path, flags);
}
static inline int cp_sys_ioctl(int fd, unsigned long cmd, void *arg)
{
  return syscall(SYS_ioctl, fd, cmd, (unsigned long)arg);
}
static inline int cp_sys_fcntl(int fd, unsigned long cmd, int arg)
{
  return syscall(SYS_fcntl, fd, cmd, arg);
}
static inline int cp_sys_close(int fd)
{
  return syscall(SYS_close, fd);
}


#endif /* __CPLANE_UL_STSCALLS_H__ */
