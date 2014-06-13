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
ci_inline int oo_open(ci_fd_t* out, int flags) {
  ci_fd_t fp  = ci_sys_open(EFAB_DEV, O_RDWR | flags);
  if( fp < 0 )  return -errno;
  *out = fp;
  return 0;
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
ci_inline int
oo_resource_mmap(ci_fd_t fp, unsigned map_id, unsigned bytes, void** p_out)
{
  *p_out = mmap((void*) 0, bytes, PROT_READ | PROT_WRITE,
                MAP_SHARED, fp, map_id << CI_NETIF_MMAP_ID_SHIFT);
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

/*! \i_efab_unix */
ci_inline int
oo_clone_fd(ci_fd_t fp, int* fd_out, int cloexec)
{
  ci_clone_fd_t op;
  op.flags = cloexec;
  if( ci_sys_ioctl(fp, OO_IOC_CLONE_FD, &op) < 0 )  return -errno;
  *fd_out = op.fd;
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

