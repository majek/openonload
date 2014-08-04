/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * Copyright 2012-2012: Solarflare Communications Inc,
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

#ifndef __EFAB_MEMREG_H__
#define __EFAB_MEMREG_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ef_memreg {
	unsigned mr_resource_id;
	ef_addr* mr_dma_addrs;
	ef_addr* mr_dma_addrs_base;
} ef_memreg;


struct ef_pd;


  /*! Register memory for use with ef_vi.
   *
   *   \param mr          The ef_memreg object to initialise
   *   \param mr_dh       Driver handle for the ef_memreg
   *   \param pd          Protection domain to register memory in
   *   \param pd_dh       Driver handle for the protection domain
   *   \param p_mem       Start of memory region to be registered
   *   \param len_bytes   Length of memory region to be registered
   *
   * Use this function to register memory so that it can be used for DMA
   * buffers.  ef_memreg_dma_addr() can then be used to obtain DMA
   * addresses for buffers within the registered area.
   *
   * Registered memory is associated with a particular protection domain,
   * and the DMA addresses can be used only with VIs that are associated
   * with the same protection domain.  Memory can be registered with
   * multiple protection domains so that a single pool of buffers can be
   * used with multiple VIs.
   *
   * The start of the memory region (p_mem) must be aligned on a 4K
   * boundary.
   *
   * Memory that is registered is pinned, and therefore it cannot be
   * swapped out to disk.
   *
   * Note: If an application that has registered memory forks, then
   * copy-on-write semantics can cause new pages to be allocated which are
   * not registered.  This problem can be solved either by ensuring that
   * the registered memory regions are shared by parent and child (eg. by
   * using MAP_SHARED), or by using madvise(MADV_DONTFORK) to prevent the
   * registered memory from being accessible in the child.
   */
extern int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh,
			   struct ef_pd* pd, ef_driver_handle pd_dh,
			   void* p_mem, int len_bytes);

  /*! Unregister a memory region.  NB. The memory will only be unregistered
   * when the driver handle is also closed.
   */
extern int ef_memreg_free(ef_memreg*, ef_driver_handle);


  /*! Returns the DMA address corresponding to the given offset within
   * registered region.
   *
   * Note that DMA addresses are only contiguous within each 4K block of a
   * memory region.
   */
ef_vi_inline ef_addr ef_memreg_dma_addr(ef_memreg* mr, int offset)
{
	return mr->mr_dma_addrs[offset >> EF_VI_NIC_PAGE_SHIFT] |
		(offset & (EF_VI_NIC_PAGE_SIZE - 1));
}

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_MEMREG_H__ */
