/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

ci_inline int
oo_resource_op(ci_fd_t fp, ci_uint32 cmd, void* io)
{
  int r;
  int saved_errno = errno;
  if( (r = ci_sys_ioctl(fp, cmd, io)) < 0 ) {
    r = -errno;
    errno = saved_errno;
  }
  return r;
}


/*! \i_efab_unix */
ci_inline int
oo_resource_alloc(ci_fd_t fp, ci_resource_onload_alloc_t* io)
{
  return oo_resource_op(fp, OO_IOC_RESOURCE_ONLOAD_ALLOC, io);
}


/*! \i_efab_unix */
#define OO_MMAP_FLAG_DEFAULT  0
#define OO_MMAP_FLAG_READONLY 1
#define OO_MMAP_FLAG_FIXED    2
#define OO_MMAP_FLAG_POPULATE 4
ci_inline int
oo_resource_mmap(ci_fd_t fp, ci_uint8 map_type, unsigned long map_id,
                 unsigned bytes, int flags, void** p_out)
{
  int mmap_prot = PROT_READ;
  int mmap_flags = MAP_SHARED;
  int saved_errno = errno;

#ifndef OO_MMAP_TYPE_DSHM
  ci_assert_equal(map_type, OO_MMAP_TYPE_NETIF);
#endif

  if( ! (flags & OO_MMAP_FLAG_READONLY) )
    mmap_prot |= PROT_WRITE;
  if( flags & OO_MMAP_FLAG_FIXED )
    mmap_flags |= MAP_FIXED;
  if( flags & OO_MMAP_FLAG_POPULATE )
    mmap_flags |= MAP_POPULATE;
  *p_out = mmap((flags & OO_MMAP_FLAG_FIXED) ? *p_out : (void*) 0, bytes,
                mmap_prot, mmap_flags, fp,
                OO_MMAP_MAKE_OFFSET(map_type, map_id));
  if( *p_out == MAP_FAILED ) {
    int rc = -errno;
    errno = saved_errno;
    return rc;
  }
  return 0;
}


/*! \i_efab_unix */
ci_inline int
oo_resource_munmap(ci_fd_t fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
oo_ipid_range_alloc(ci_fd_t fp, ci_int32* what)
{
  return oo_resource_op(fp, OO_IOC_IPID_RANGE_ALLOC, what);
}

/*! \i_efab_unix */
ci_inline int
oo_ipid_range_free(ci_fd_t fp, ci_int32 *what)
{
  return oo_resource_op(fp, OO_IOC_IPID_RANGE_FREE, what);
}

/*! \i_efab_unix */
ci_inline int
oo_ep_info(ci_fd_t fp, ci_ep_info_t* io)
{
  return oo_resource_op(fp, OO_IOC_EP_INFO, io);
}

ci_inline int
oo_vi_stats_query(ci_fd_t fp, int intf_i, void* data, int data_len,
                  int do_reset)
{
  ci_vi_stats_query_t io;
  io.intf_i = intf_i;
  CI_USER_PTR_SET(io.stats_data, data);
  io.data_len = data_len;
  io.do_reset = do_reset;

  return oo_resource_op(fp, OO_IOC_VI_STATS_QUERY, &io);
}

ci_inline int
oo_debug_op(ci_fd_t fp, ci_debug_onload_op_t *io)
{
  return oo_resource_op(fp, OO_IOC_DEBUG_OP, io);
}

#endif  /* _CI_DRIVER_UNIX_INTF_H_ */

/*! \cidoxg_end */

