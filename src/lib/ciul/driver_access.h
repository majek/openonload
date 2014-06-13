/*
** Copyright 2005-2013  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __DRIVER_ACCESS_H__
#define __DRIVER_ACCESS_H__

#if defined(__KERNEL__)
# error __KERNEL__ not allowed here.
#endif

#include <ci/efch/op_types.h>
#include <ci/efrm/resource_id.h>

#include <sys/ioctl.h>
#include <sys/mman.h>


struct ci_resource_alloc_s;
struct ci_resource_op_s;


/*! \i_efab_unix */
ci_inline int
ci_resource_alloc(int fp, struct ci_resource_alloc_s* io)
{
  if( ioctl(fp, CI_RESOURCE_ALLOC, io) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
ci_resource_mmap(int fp, unsigned res_id, unsigned map_id, unsigned bytes,
                 void** p_out)
{
  *p_out = mmap((void*) 0, bytes, PROT_READ | PROT_WRITE,
                MAP_SHARED, fp,
                EFAB_MMAP_OFFSET_MAKE(efch_make_resource_id(res_id), map_id));
  return *p_out != MAP_FAILED ? 0 : -errno;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_munmap(int fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_op(int fp, struct ci_resource_op_s* io)
{
  int r;
  if( (r = ioctl(fp, CI_RESOURCE_OP, io)) < 0 )  return -errno;
  return r;
}


#endif  /* _CI_DRIVER_UNIX_INTF_H_ */
/*! \cidoxg_end */
