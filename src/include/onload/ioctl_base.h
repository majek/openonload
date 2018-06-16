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

#ifndef __ONLOAD_IOCTL_BASE_H__
#define __ONLOAD_IOCTL_BASE_H__

#include <linux/version.h>


/* Worth changing this base whenever you change an ioctl in an incompatible
** way, so we can catch the error more easily...
*/
# define OO_LINUX_IOC_BASE  90
# if OO_LINUX_IOC_BASE > 254
# error "OO_LINUX_IOC_BASE should be one byte"
# endif

# define OO_IOC_NONE(XXX)   _IO(OO_LINUX_IOC_BASE, OO_OP_##XXX)
# define OO_IOC_R(XXX, t)   _IOR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_W(XXX, t)   _IOW(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_RW(XXX, t)  _IOWR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)



#endif  /* __ONLOAD_IOCTL_BASE_H__ */
