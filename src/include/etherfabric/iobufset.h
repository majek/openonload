/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

/*
 *  \brief  ef_iobufset
 *   \date  2008/03/10
 */

#ifndef __EFAB_IOBUFSET_H__
#define __EFAB_IOBUFSET_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \i_ef_bufs An [ef_iobufset] is a set of I/O buffers that are suitable
 *  for DMA.
 */
typedef struct ef_iobufset {
	unsigned                      bufs_resource_id;
	unsigned                      bufs_mmap_bytes;
#if defined(__KERNEL__)
	int                           bufs_ptr_off;
#else
	char*                         bufs_ptr;
#endif
	ef_addr                       bufs_addr;
	unsigned                      bufs_size; /* size rounded to pow2 */
	int                           bufs_num;
} ef_iobufset;


  /*! \i_ef_bufs  Allocate a set of I/O buffers.
  **
  **   \param vi The VI that these buffers will be used with
  **   \param size The size in bytes of each I/O buffer
  **   \param num The number of buffers required
  **   \param align The alignment requirement of the start of the buffer.
  **          This must be 1, 2, 4 or 8.
  **   \param offset The offset of the start of the I/O buffer
  */
extern int ef_iobufset_alloc(ef_iobufset*, ef_driver_handle,
			     ef_vi* vi, ef_driver_handle vi_dh,
			     int is_phys_addr_mode,
                             int size, int num, int align, int offset);

  /*! Map an iobufset into another VI. */
extern int ef_iobufset_remap(ef_iobufset* bs, ef_driver_handle bs_dh,
			     ef_vi* vi, ef_driver_handle vi_dh,
			     ef_driver_handle dh_for_this_op);

  /*! \i_ef_bufs  Free the set of buffers. */
extern int ef_iobufset_free(ef_iobufset*, ef_driver_handle);


  /*! \i_ef_bufs Returns the number of buffers in the set. */
ef_vi_inline int ef_iobufset_num(ef_iobufset* bs)
{ return bs->bufs_num; }


#ifndef __KERNEL__

ef_vi_inline char*
ef_iobufset_ptr(ef_iobufset* bs, unsigned i)
{
  return bs->bufs_ptr + (i * bs->bufs_size);
}


  /*! \i_ef_bufs [off] is an offset relative to the start of buffer [i]. */
ef_vi_inline char*
ef_iobufset_buf_off_ptr(ef_iobufset* bs, unsigned i, unsigned off)
{
  return bs->bufs_ptr + (i * bs->bufs_size) + off;
}

#endif /* __KERNEL__ */

  /*! \i_ef_bufs Returns the offset of buffer [i] within the set.  This is
  **             the offset of the prefix, rather than the payload.
  */
ef_vi_inline unsigned ef_iobufset_off(ef_iobufset* bs, unsigned i)
{ return i * bs->bufs_size; }

  /*! \i_ef_bufs Returns the [ef_addr] of the indicated buffer.
  **
  **  Compare with ef_iobufset_ref (which returns the kernel virtual address)
  */
ef_vi_inline ef_addr ef_iobufset_addr(ef_iobufset* bs, int i)
{ return bs->bufs_addr + (i * bs->bufs_size); }

ef_vi_inline unsigned ef_iobufset_buf_size(ef_iobufset* bs)
{ return bs->bufs_size; }

/*! Returns the number of pages needed to fit the given buffers in. */
extern unsigned ef_iobufset_dimension(ef_iobufset* bufs, int size, int num,
				      int align);

extern void ef_iobufset_init(ef_iobufset* bufs, ef_addr bufaddr,
			     void* ptr, int offset);

ef_vi_inline void ef_iobufset_offset_ptrs(ef_iobufset* bs, int offset)
{
#if defined(__KERNEL__)
  bs->bufs_ptr_off -= offset;
#else
  bs->bufs_ptr -= offset;
#endif
}

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_IOBUFSET_H__ */
