/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

#ifndef __ONLOAD_DRIVERACCESS_H__
#define __ONLOAD_DRIVERACCESS_H__


#ifdef __KERNEL__

# error "No, don't."

#else

# include <sys/types.h>
# include <sys/stat.h>
# include <sys/ioctl.h>
# include <fcntl.h>
# include <stdarg.h>
# include <errno.h>
# include <unistd.h>
# include <ci/driver/efab/open.h>


typedef int oo_fd;


static inline int oo_fd_open(int* fd_out) {
  *fd_out = open("/dev/onload", O_RDWR);
  if( *fd_out < 0 )  return -errno;
  return 0;
}


static inline int oo_fd_close(int fd) {
  return close(fd) < 0 ? -errno : 0;
}


static inline int oo_ioctl(int fd, int rq, ...) {
  va_list vargs;
  int rc;
  va_start(vargs, rq);
  rc = ioctl(fd, rq, va_arg(vargs, unsigned long));
  va_end(vargs);
  return rc >= 0 ? rc : -errno;
}


extern int oo_version_check_ul(int fd);

/* Warning, this requires linking to transport lib */
static inline int oo_fd_open_versioned(int* fd_out) {
  int rc = oo_fd_open(fd_out);
  if( rc < 0 ) return rc;
  rc = oo_version_check_ul(*fd_out);
  if( rc < 0 )
    oo_fd_close(*fd_out);
  return rc;
}

#endif


#endif  /* __ONLOAD_DRIVERACCESS_H__ */
