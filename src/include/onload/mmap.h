/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#ifndef __ONLOAD_MMAP_H__
#define __ONLOAD_MMAP_H__

/* For CI_CFG_* */
#include <ci/internal/transport_config_opt.h>
#include <onload/mmap_base.h>
#include <cplane/mmap.h>

/* OO_MMAP_TYPE_NETIF offsets has following IDs:
 * - CI_NETIF_MMAP_ID_STATE     netif shared state; ep buffers
 * - CI_NETIF_MMAP_ID_TIMESYNC  timesync shared state, read-only
 *                              (could be extended to other global shared
 *                              states)
 * - CI_NETIF_MMAP_ID_IO        VI resource: IO bar.
 * - CI_NETIF_MMAP_ID_IOBUFS    VI resource: queues
 *   + if CI_CFG_PKTS_AS_HUGE_PAGES=1, mmap pkt_shm_id array
 * - CI_NETIF_MMAP_ID_PIO       VI resource: PIO IO BAR
 * - CI_NETIF_MMAP_ID_OFE_RO    OFE read-only part of engine
 * - CI_NETIF_MMAP_ID_OFE_RW    OFE read-write part of engine
 * - CI_NETIF_MMAP_ID_CPLANE    Control plame MIBs mapping
 * - CI_NETIF_MMAP_ID_PKTS + packet set id
 *   packet sets
 */
#define CI_NETIF_MMAP_ID_STATE    0
#define CI_NETIF_MMAP_ID_TIMESYNC 1
#define CI_NETIF_MMAP_ID_IO       2
#define CI_NETIF_MMAP_ID_IOBUFS   3
#if CI_CFG_PIO
#define CI_NETIF_MMAP_ID_PIO      4
#endif
#ifdef ONLOAD_OFE
#define CI_NETIF_MMAP_ID_OFE_RO   5
#define CI_NETIF_MMAP_ID_OFE_RW   6
#endif
#define CI_NETIF_MMAP_ID_PKTS     7
#define CI_NETIF_MMAP_ID_PKTSET(id) (CI_NETIF_MMAP_ID_PKTS+(id))


/* OO_MMAP_TYPE_DSHM:
 * "Donation" shm mmap IDs encode buffer ID and class. */
#ifdef OO_MMAP_TYPE_DSHM
# define OO_MMAP_DSHM_BUFFER_ID_WIDTH 32
# define OO_MMAP_DSHM_SHM_CLASS_WIDTH 12
# define OO_MMAP_DSHM_BUFFER_ID(map_id) \
    ((map_id) & ((1ull << OO_MMAP_DSHM_BUFFER_ID_WIDTH) - 1))
# define OO_MMAP_DSHM_SHM_CLASS(map_id) \
    (((map_id) >> OO_MMAP_DSHM_BUFFER_ID_WIDTH) & \
     ((1ull << OO_MMAP_DSHM_SHM_CLASS_WIDTH) - 1))
# define OO_MMAP_DSHM_MAKE_ID(shm_class, buffer_id) \
    ((ci_uint64) (buffer_id) | \
     ((ci_uint64) (shm_class) << OO_MMAP_DSHM_BUFFER_ID_WIDTH))
#endif


static inline unsigned
OO_MMAP_OFFSET_TO_MAP_ID(off_t offset)
{
  return offset >> OO_MMAP_ID_SHIFT;
}

#define VMA_OFFSET(vma)  ((vma)->vm_pgoff << PAGE_SHIFT)

#endif
