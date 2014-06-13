/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */
 
#include <internal.h>


/*
** We can't just use the default log function, as it uses the standard I/O
** mechanisms, which we intercept, leading to recursive nastiness.
**
** Hence we jump straight into a syscall.
**
** An alternative would be to use ci_sys_writev() or something, but that
** wouldn't be available as early in the library initialisation.
*/

/**********************************************************************/
/**********************************************************************/

#include <ci/internal/syscall.h>


void citp_log_fn_ul(const char* msg)
{
  struct iovec v[2];

  if( citp.log_fd < 0 ) {
    citp.log_fd = oo_fcntl_dupfd_cloexec(STDERR_FILENO, 3);
    if( citp.log_fd < 0 )  return;
    if( citp_fdtable.table )
      citp_fdtable.table[citp.log_fd].fdip=fdi_to_fdip(&citp_the_reserved_fd);
  }

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(v[0].iov_base);
  v[1].iov_base = "\n";
  v[1].iov_len = strlen(v[1].iov_base);

  my_syscall3(writev, citp.log_fd, (long) v, 2); 
}


void citp_log_fn_drv(const char* msg)
{
  if( citp.log_fd < 0 ) {
    if( ef_onload_driver_open(&citp.log_fd, 1) )  return;
    if( citp_fdtable.table )
      citp_fdtable.table[citp.log_fd].fdip=fdi_to_fdip(&citp_the_reserved_fd);
    /* just to be sure: */
    ci_sys_fcntl(citp.log_fd, F_SETFD, FD_CLOEXEC);
  }

  my_syscall3(ioctl, citp.log_fd, OO_IOC_PRINTK, (long) msg);
}


void citp_log_change_fd(void)
{
  int newfd, prev;
  /* We need to change logging fd, probably because someone wants to do a
  ** dup2() onto it.
  **
  ** No need to set 'close-on-exec' (FD_CLOEXEC) again for the newfd as
  ** it will be copied by the dup().
  */
  CITP_FDTABLE_LOCK();
  prev = citp.log_fd;
  newfd = oo_fcntl_dupfd_cloexec(prev, 3);
  if( newfd >= 0 ) {
    __citp_fdtable_reserve(newfd, 1);
    citp.log_fd = newfd;
  }
  Log_S(log("%s: old=%d new=%d", __FUNCTION__, prev, newfd));
  __citp_fdtable_reserve(prev, 0);
  ci_sys_close(prev);
  CITP_FDTABLE_UNLOCK();
}



/*! \cidoxg_end */

