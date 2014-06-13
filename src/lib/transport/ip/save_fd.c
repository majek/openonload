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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author ok_sasha 
**  \brief Functions to save/restore onload fd
**   \date  2008/08
**    \cop  (c) Solarflare communications
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
 
#include <onload/ul.h>
#include <ci/internal/ip_log.h>


/*! Saved file descriptors for potential cloning with CI_CLONE_FD ioctl
 *  in the event that ci_open() fails.
 */
static ef_driver_handle saved_fd = (ef_driver_handle) -1;


int ef_onload_driver_open(ef_driver_handle* pfd, int cloexec)
{
  int rc;
  int flags = 0;
#ifdef O_CLOEXEC
  if( cloexec )
    flags = O_CLOEXEC;
#endif

  ci_assert(pfd);
  rc = oo_open(pfd, flags);
  if( rc == 0 ) {
#if defined(O_CLOEXEC)
    static int o_cloexec_fails = -1;
    if( cloexec && o_cloexec_fails < 0 ) {
      int arg;
      rc = ci_sys_fcntl(*(int *)pfd, F_GETFD, &arg);
      if( rc == 0 && (arg & FD_CLOEXEC) )
        o_cloexec_fails = 0;
      else
        o_cloexec_fails = 1;
    }
#else
    static const int o_cloexec_fails = 1;
#endif
    if( cloexec && o_cloexec_fails)
      CI_DEBUG_TRY(ci_sys_fcntl(*(int *)pfd, F_SETFD, FD_CLOEXEC));
    return 0;
  }

  if( saved_fd >= 0 ) {
    LOG_NV(ci_log("ef_driver_open: open failed, but cloning from saved fd"));
    rc = oo_clone_fd((ci_fd_t) saved_fd, (int*) pfd, cloexec);
  }

  return rc;
}


int ef_driver_save_fd(void)
{
  int rc = 0;
  ef_driver_handle fd;
  
  if( saved_fd == (ef_driver_handle) -1 ) {
    rc = ef_onload_driver_open(&fd, 0);
    if( rc == 0 ) {
      saved_fd = fd;
      LOG_NV(ci_log("ef_driver_save_fd: Saved fd %d for cloning", (int)fd));
    } else {
      LOG_NV(ci_log("ef_driver_save_fd: failed to open fd - rc=%d", rc));
    }
  }

  return rc;
}

/*! \cidoxg_end */
