/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
 * Copyright 2012-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
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

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Registering memory for EtherFabric Virtual Interface HAL.
** \date      2015/02/16
** \copyright Copyright &copy; 2015 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_MEMREG_H__
#define __EFAB_MEMREG_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Memory that has been registered for use with ef_vi */
typedef struct ef_memreg {
  /** Resource ID of the memory region */
  unsigned mr_resource_id;
  /** Addresses of DMA buffers within the reserved system memory */
  ef_addr* mr_dma_addrs;
  /** Base addresses of reserved system memory */
  ef_addr* mr_dma_addrs_base;
} ef_memreg;


struct ef_pd;


/*! \brief Register a memory region for use with ef_vi.
**
** \param mr        The ef_memreg object to initialize.
** \param mr_dh     Driver handle for the ef_memreg.
** \param pd        Protection domain in which to register memory.
** \param pd_dh     Driver handle for the protection domain.
** \param p_mem     Start of memory region to be registered. This must be
**                  page-aligned, and so be on a 4K boundary.
** \param len_bytes Length of memory region to be registered. This must be
**                  a multiple of the packet buffer size (currently 2048
**                  bytes).
**
** \return 0 on success, or a negative error code.
**
** Register memory for use with ef_vi.
**
** Before calling this function, the memory must be allocated. using malloc
** or similar.
**
** After calling this function, the memory is registered, and can be used
** for DMA buffers. ef_memreg_dma_addr() can then be used to obtain DMA
** addresses for buffers within the registered area.
**
** Registered memory is associated with a particular protection domain, and
** the DMA addresses can be used only with virtual interfaces that are
** associated with the same protection domain. Memory can be registered
** with multiple protection domains so that a single pool of buffers can be
** used with multiple virtual interfaces.
**
** Memory that is registered is pinned, and therefore it cannot be swapped
** out to disk.
**
** \note If an application that has registered memory forks, then
**       copy-on-write semantics can cause new pages to be allocated which
**       are not registered. This problem can be solved either by ensuring
**       that the registered memory regions are shared by parent and child
**       (e.g. by using MAP_SHARED), or by using madvise(MADV_DONTFORK) to
**       prevent the registered memory from being accessible in the child.
*/
extern int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh,
                           struct ef_pd* pd, ef_driver_handle pd_dh,
                           void* p_mem, size_t len_bytes);

/*! \brief Unregister a memory region
**
** \param mr    The ef_memreg object to unregister.
** \param mr_dh Driver handle for the ef_memreg.
**
** \return 0 on success, or a negative error code.
**
** Unregister a memory region.
**
** \note To free all the resources, the driver handle associated with the 
**       memory must also be closed by calling ef_driver_close().
*/
extern int ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh);


/*! \brief Return the DMA address for the given offset within a registered
**         memory region
**
** \param mr     The ef_memreg object to query.
** \param offset The offset within the ef_memreg object.
**
** \return The DMA address for the given offset within a registered memory
**         region.
**
** Return the DMA address for the given offset within a registered memory
** region.
**
** Note that DMA addresses are only contiguous within each 4K block of a
** memory region.
*/
ef_vi_inline ef_addr ef_memreg_dma_addr(ef_memreg* mr, size_t offset)
{
  return mr->mr_dma_addrs[offset >> EF_VI_NIC_PAGE_SHIFT] |
    (offset & (EF_VI_NIC_PAGE_SIZE - 1));
}

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_MEMREG_H__ */
