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
*//*! \file unix_intf.h
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Unix driver entry points.
**     $Id$
**   \date  2002/08/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_unix  */

#ifndef _CI_DRIVER_UNIX_INTF_H_
#define _CI_DRIVER_UNIX_INTF_H_

#if defined(__KERNEL__)
# error __KERNEL__ not allowed here.
#endif


#include <ci/driver/efab/open.h>
#include <ci/driver/efab/operations.h>


#define EFAB_CHAR_DEV "/dev/sfc_char"


struct ci_resource_alloc_s;
struct ci_resource_op_s;


/*! \i_efab_unix */
/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int ci_open(ci_fd_t* out) {
  ci_fd_t fp  = open(EFAB_CHAR_DEV, O_RDWR);
  if( fp < 0 )  return -errno;
  *out = fp;
  return 0;
}

/*! \i_efab_unix */
/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int
ci_close(ci_fd_t fp)
{
  if( close(fp) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
ci_resource_alloc(ci_fd_t fp, struct ci_resource_alloc_s* io)
{
  if( ioctl(fp, CI_RESOURCE_ALLOC, io) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
ci_resource_mmap(ci_fd_t fp, unsigned res_id, unsigned map_id, unsigned bytes,
                 void** p_out)
{
  *p_out = mmap((void*) 0, bytes, PROT_READ | PROT_WRITE,
                MAP_SHARED, fp,
                EFAB_MMAP_OFFSET_MAKE(efch_make_resource_id(res_id), map_id));
  return *p_out != MAP_FAILED ? 0 : -errno;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_munmap(ci_fd_t fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_op(ci_fd_t fp, struct ci_resource_op_s* io)
{
  int r;
  if( (r = ioctl(fp, CI_RESOURCE_OP, io)) < 0 )  return -errno;
  return r;
}

ci_inline int 
ci_resource_op_blocking(ci_fd_t fp, struct ci_resource_op_s* io,
                        const ci_timeval_t* not_used,
                        ci_timeval_t* not_used_either)
{
  /* In Win32 ci_resource_op and ci_resource_op_blocking differ. Not here. */
  return ci_resource_op(fp, io);
}


#include <etherfabric/base.h>
/*! Close a driver handle. */
ci_inline int ef_driver_close(ef_driver_handle nic) {
  return ci_close(nic);
}

#endif  /* _CI_DRIVER_UNIX_INTF_H_ */

/*! \cidoxg_end */
