/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
#include <onload/epoll.h>


/*! Names of the devices to open.
 */
const char* oo_device_name[] =
{
  "/dev/" EFAB_DEV_NAME,
  "/dev/" OO_EPOLL_DEV_NAME
};

static const int clone_ioctl[OO_MAX_DEV] =
{
  OO_IOC_CLONE_FD,
  OO_EPOLL_IOC_CLONE,
};

/*! Saved file descriptors for potential cloning with CI_CLONE_FD ioctl
 *  in the event that ci_open() fails.
 */
static int saved_fd[OO_MAX_DEV];
static int fd_is_saved[OO_MAX_DEV];

/*! Saved struct stat . st_rdev for our devices */
static unsigned long oo_st_rdev[OO_MAX_DEV];


/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int oo_open(ci_fd_t* out, enum oo_device_type dev_type, int flags) {
  ci_fd_t fp  = ci_sys_open(oo_device_name[dev_type], O_RDWR | flags);
  if( fp < 0 )  return -errno;
  *out = fp;
  return 0;
}

int ef_onload_driver_open(ef_driver_handle* pfd,
                          enum oo_device_type dev_type,
                          int do_cloexec)
{
  int rc;
  int flags = 0;
  int saved_errno = errno;

#ifdef O_CLOEXEC
  if( do_cloexec )
    flags = O_CLOEXEC;
#endif

  ci_assert(pfd);
  rc = oo_open(pfd, dev_type, flags);
  if( rc != 0 && fd_is_saved[dev_type] >= 0 ) {
    ci_clone_fd_t op;
    op.do_cloexec = do_cloexec;
    LOG_NV(ci_log("%s: open failed, but cloning from saved fd", __func__));
    rc = ci_sys_ioctl((ci_fd_t) saved_fd[dev_type],
                      clone_ioctl[dev_type], &op);
    if( rc < 0 )
      return rc;
    errno = saved_errno;
    *pfd = op.fd;
  }

  if( rc != 0 )
    return rc;
      
  if( do_cloexec ) {
#if defined(O_CLOEXEC)
    static int o_cloexec_fails = -1;
    if( o_cloexec_fails < 0 ) {
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
    if( o_cloexec_fails )
      CI_DEBUG_TRY(ci_sys_fcntl(*(int *)pfd, F_SETFD, FD_CLOEXEC));
  }

  return 0;
}


void ef_driver_save_fd(void)
{
  int rc = 0;
  ef_driver_handle fd;
  enum oo_device_type dev_type;

  for( dev_type = 0; dev_type < OO_MAX_DEV; dev_type++ ) {
    if( ! fd_is_saved[dev_type] ) {
      rc = ef_onload_driver_open(&fd, dev_type, 1);
      if( rc == 0 ) {
        saved_fd[dev_type] = fd;
        fd_is_saved[dev_type] = 1;
        LOG_NV(ci_log("%s: Saved fd %d %s for cloning",
                      __func__, (int)fd, oo_device_name[dev_type]));
        if( oo_st_rdev[dev_type] <= 0 ) {
          struct stat st;
          fstat(fd, &st);
          oo_st_rdev[dev_type] = st.st_rdev;
        }
      } else {
        ci_log("%s: failed to open %s - rc=%d",
               __func__, oo_device_name[dev_type], rc);
      }
    }
  }
}

unsigned long oo_get_st_rdev(enum oo_device_type dev_type)
{
  if( oo_st_rdev[dev_type] == 0 ) {
    struct stat st;
    if( stat(oo_device_name[dev_type], &st) == 0 )
      oo_st_rdev[dev_type] = st.st_rdev;
    else {
      LOG_NV(ci_log("%s: ERROR: stats(%s) failed errno=%d",
                    __func__, oo_device_name[dev_type], errno));
      oo_st_rdev[dev_type] = -1;
    }
  }
  return oo_st_rdev[dev_type];
}


dev_t oo_onloadfs_dev_t(void)
{
  static ci_uint32 onloadfs_dev_t = 0;

  if( onloadfs_dev_t == 0 ) {
    int fd;
    if( ef_onload_driver_open(&fd, OO_STACK_DEV, 1) != 0 ) {
      fprintf(stderr, "%s: Failed to open /dev/onload\n", __FUNCTION__);
      return 0;
    }
    if( ci_sys_ioctl(fd, OO_IOC_GET_ONLOADFS_DEV, &onloadfs_dev_t) != 0 ) {
      LOG_E(ci_log("%s: Failed to find onloadfs dev_t", __FUNCTION__));
    }
    ci_sys_close(fd);
  }
  return onloadfs_dev_t;
}


/*! \cidoxg_end */
