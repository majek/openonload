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

/**************************************************************************\
*//*! \file unix_intf.h
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Unix driver entry points.
**     $Id$
**   \date  2007/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_unix  */

#ifndef __ONLOAD_UNIX_INTF_H__
#define __ONLOAD_UNIX_INTF_H__

#if defined(__KERNEL__)
# error __KERNEL__ not allowed here.
#endif


#include <ci/compat.h>
#include <onload/syscall_unix.h>
#include <ci/driver/efab/open.h>
#include <onload/ioctl.h>
#include <onload/common.h>
#include <onload/mmap.h>


ci_inline int oo_fcntl_dupfd_cloexec(int fd, int arg)
{
  int rc;
#ifdef F_DUPFD_CLOEXEC
  static int f_dupfd_cloexec_fails = 0;

  if( !f_dupfd_cloexec_fails ) {
    rc = ci_sys_fcntl(fd, F_DUPFD_CLOEXEC, arg);
    if( rc >= 0 || errno != EINVAL )
      return rc;
    f_dupfd_cloexec_fails = 1;
  }
#endif
  rc = ci_sys_fcntl(fd, F_DUPFD, arg);
  if( rc < 0 )
    return rc;
  CI_DEBUG_TRY(ci_sys_fcntl(rc, F_SETFD, FD_CLOEXEC));
  return rc;
}

/*! \i_efab_unix */
/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int
oo_close(ci_fd_t fp)
{
  if( ci_sys_close(fp) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
oo_resource_alloc(ci_fd_t fp, ci_resource_onload_alloc_t* io)
{
  if( ci_sys_ioctl(fp, OO_IOC_RESOURCE_ONLOAD_ALLOC, io) < 0 )  return -errno;
  return 0;
}


/*! \i_efab_unix */
#define OO_MMAP_FLAG_DEFAULT  0
#define OO_MMAP_FLAG_READONLY 1
#define OO_MMAP_FLAG_FIXED    2
ci_inline int
oo_resource_mmap(ci_fd_t fp, ci_uint8 map_type, unsigned long map_id,
                 unsigned bytes, int flags, void** p_out)
{
  int mmap_prot = PROT_READ;
  int mmap_flags = MAP_SHARED;

  off_t offset = map_id << OO_MMAP_ID_SHIFT;
#ifdef OO_MMAP_HAVE_EXTENDED_MAP_TYPES
  offset |= ((off_t) map_type) << OO_MMAP_TYPE_SHIFT;
#else
  ci_assert_equal(map_type, OO_MMAP_TYPE_NETIF);
#endif

  if( ! (flags & OO_MMAP_FLAG_READONLY) )
    mmap_prot |= PROT_WRITE;
  if( flags & OO_MMAP_FLAG_FIXED )
    mmap_flags |= MAP_FIXED;
  *p_out = mmap((flags & OO_MMAP_FLAG_FIXED) ? *p_out : (void*) 0, bytes,
                mmap_prot, mmap_flags, fp, offset);
  return *p_out != MAP_FAILED ? 0 : -errno;
}


/*! \i_efab_unix */
ci_inline int
oo_resource_munmap(ci_fd_t fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}

ci_inline int
oo_resource_op(ci_fd_t fp, ci_uint32 cmd, void* io)
{
  int r;
  if( (r = ci_sys_ioctl(fp, cmd, io)) < 0 )  return -errno;
  return r;
}


/*! \i_efab_unix */
ci_inline int
oo_ipid_range_alloc(ci_fd_t fp, ci_int32* what)
{
  if( ci_sys_ioctl(fp, OO_IOC_IPID_RANGE_ALLOC, what) < 0) return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
oo_ipid_range_free(ci_fd_t fp, ci_int32 *what)
{
  if (ci_sys_ioctl(fp, OO_IOC_IPID_RANGE_FREE, what) < 0) return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
oo_ep_info(ci_fd_t fp, ci_ep_info_t* io)
{
  if( ci_sys_ioctl(fp, OO_IOC_EP_INFO, io) < 0 )  return -errno;
  return 0;
}

ci_inline int
oo_debug_op(ci_fd_t fp, ci_debug_onload_op_t *io)
{
  if (ci_sys_ioctl(fp, OO_IOC_DEBUG_OP, io) < 0) return -errno;
  return 0;
}

ci_inline int
oo_config_set (ci_fd_t fp, ci_cfg_ioctl_desc_t *desc)
{
  if (ci_sys_ioctl(fp, OO_IOC_CFG_SET, desc) < 0) return -errno;
  return 0;
}

ci_inline int
oo_config_unset (ci_fd_t fp, ci_cfg_ioctl_desc_t *desc)
{
  if (ci_sys_ioctl(fp, OO_IOC_CFG_UNSET, desc) < 0) return -errno;
  return 0;
}

ci_inline int
oo_config_get (ci_fd_t fp, ci_cfg_ioctl_desc_t *desc)
{
  if (ci_sys_ioctl(fp, OO_IOC_CFG_GET, desc) < 0) return -errno;
  return 0;
}

ci_inline int
oo_config_query (ci_fd_t fp, ci_cfg_ioctl_desc_t *desc)
{
  if (ci_sys_ioctl(fp, OO_IOC_CFG_QUERY, desc) < 0) return -errno;
  return 0;
}

#endif  /* _CI_DRIVER_UNIX_INTF_H_ */

/*! \cidoxg_end */

