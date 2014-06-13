/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2006/06/16
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <onload/debug.h>
#include <onload/cplane.h>
#include <ci/internal/cplane_handle.h>
#include <onload/tcp_helper.h>
#include <ci/efch/mmap.h>
#include <onload/mmap.h>



static int tcp_helper_rm_mmap_mem(tcp_helper_resource_t* trs,
                                  unsigned long* bytes,
                                  void* opaque, int* map_num,
                                  unsigned long* offset)
{
  int rc = 0;
  OO_DEBUG_SHM(ci_log("mmap mem %lx", *offset));
  OO_DEBUG_VM(ci_log("tcp_helper_rm_mmap_mem: %u "
                     "map_num=%d bytes=0x%lx offset=0x%lx",
                     trs->id, *map_num, *bytes, *offset));

  /* map contiguous shared state */
  rc = ci_contig_shmbuf_mmap(&trs->netif.state_buf, 0, bytes, opaque,
                             map_num, offset);
  if( rc < 0 )  goto out;

  OO_DEBUG_MEMSIZE(ci_log("%s: taken %d bytes for contig shmbuf leaving %lu",
                          __FUNCTION__,
                          (int) ci_contig_shmbuf_size(&trs->netif.state_buf),
                          *bytes));

#ifdef CI_HAVE_OS_NOPAGE
  rc = ci_shmbuf_mmap(&trs->netif.pages_buf, 0, bytes, opaque,
                           map_num, offset);
  if( rc < 0 )  goto out;
  OO_DEBUG_MEMSIZE(ci_log("after mapping page buf have %ld", *bytes));
#endif

  /* map the control plane shared data areas */
  rc = cicp_mmap(CICP_HANDLE(&trs->netif), bytes, opaque, map_num, offset);
  OO_DEBUG_MEMSIZE(ci_log("after mapping cplane sdata have %ld", *bytes));

 out:
  return rc;
}


static int tcp_helper_rm_mmap_io(tcp_helper_resource_t* trs,
                                 unsigned long* bytes,
                                 void* opaque, int* map_num,
                                 unsigned long* offset)
{
  int rc, intf_i;

  OO_DEBUG_SHM(ci_log("mmap io %lx", *offset));
  OO_DEBUG_VM(ci_log("tcp_helper_rm_mmap_io: %u "
                     "map_num=%d bytes=0x%lx offset=0x%lx",
                     trs->id, *map_num, *bytes, *offset));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].vi_rs, bytes, opaque,
                               map_num, offset, 0);
    if( rc < 0 )
      return rc;
  }

  return 0;
}


static int tcp_helper_rm_mmap_buf(tcp_helper_resource_t* trs,
                                  unsigned long* bytes,
                                  void* opaque, int* map_num,
                                  unsigned long* offset)
{
  int intf_i, rc;
  ci_netif* ni;

  ni = &trs->netif;
  OO_DEBUG_SHM(ci_log("mmap buf %lx %lx", *offset, *bytes));
  OO_DEBUG_VM(ci_log("tcp_helper_rm_mmap_buf: %u "
                     "map_num=%d bytes=0x%lx offset=0x%lx",
                     trs->id, *map_num, *bytes, *offset));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i ) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].vi_rs, bytes, opaque,
                               map_num, offset, 1);
    if( rc < 0 )  return rc;
  }
#ifdef OO_DO_HUGE_PAGES
  *bytes -= (((ni->pkt_sets_max * sizeof(trs->pkt_shm_id[0])) >> PAGE_SHIFT)
                                                        + 1) << PAGE_SHIFT;
#endif
  return 0;
}

static int tcp_helper_rm_mmap_pkts(tcp_helper_resource_t* trs,
                                   unsigned long* bytes,
                                   void* opaque, int map_id,
                                   unsigned long* offset)
{
  ci_netif* ni;
  ci_netif_state* ns;
  unsigned long n;

  ni = &trs->netif;
  ns = ni->state;
  ci_assert(ns);

  /* Reserve space for packet buffers */
#if !CI_CFG_MMAP_EACH_PKTSET
  n = CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET * ns->pkt_sets_max;
#else
  {
    int bufid = map_id - CI_NETIF_MMAP_ID_PKTS;
    if( bufid < 0 || bufid > ns->pkt_sets_max || ni->buf_pages[bufid] == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: %u BAD bufset_id=%d", __FUNCTION__,
                          trs->id, bufid));
      return -EINVAL;
    }
  }
  n = CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET;
#endif
  n = CI_MIN(n, *bytes);
  *bytes -= n;

  return 0;
}


#ifndef CI_HAVE_OS_NOPAGE

static int tcp_helper_rm_mmap_page(tcp_helper_resource_t* trs,
                                   unsigned long* bytes,
                                   void* opaque, int* map_num,
                                   unsigned long* offset, unsigned index)
{
  OO_DEBUG_SHM(ci_log("%s: offset=%lx index=%u", __FUNCTION__, *offset, index));

  if( index < trs->netif.k_shmbufs_n )
    return ci_shmbuf_mmap(trs->netif.k_shmbufs[index], 0, bytes,
                          opaque, map_num, offset);

  DEBUGERR(ci_log("%s: bad index=%d n=%u", __FUNCTION__, index,
                  trs->netif.k_shmbufs_n));
  return -EINVAL;
}


static int tcp_helper_rm_mmap_pktbuf(tcp_helper_resource_t* trs,
                                     unsigned long* bytes, void* opaque,
                                     int* map_num, unsigned long* offset,
                                     unsigned index)
{
  OO_DEBUG_SHM(ci_log("%s: offset=%lx index=%u", __FUNCTION__, *offset, index));

  if( index < trs->netif.pkt_sets_n ) {
    return efab_iobufset_resource_mmap(trs->netif.buf_pages[index], bytes,
                                       opaque, map_num, offset, index);
  }

  DEBUGERR(ci_log("%s: bad index=%d n=%u", __FUNCTION__, index,
                  trs->netif.pkt_sets_n));
  return -EINVAL;
}

#endif


int efab_tcp_helper_rm_mmap(tcp_helper_resource_t* trs, unsigned long* bytes,
                            void* opaque, int* map_num,
                            unsigned long* offset, int map_id)
{
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);
  ci_assert(*bytes > 0);

  OO_DEBUG_VM(ci_log("tcp_helper_rm_mmap: %u "
                     "map_num=%d bytes=0x%lx offset=0x%lx map_id=%x",
                     trs->id, *map_num, *bytes, *offset, map_id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      rc = tcp_helper_rm_mmap_mem(trs, bytes, opaque, map_num, offset);
      break;
    case CI_NETIF_MMAP_ID_IO:
      rc = tcp_helper_rm_mmap_io(trs, bytes, opaque, map_num, offset);
      break;
    case CI_NETIF_MMAP_ID_IOBUFS:
      rc = tcp_helper_rm_mmap_buf(trs, bytes, opaque, map_num, offset);
      break;
#if !CI_CFG_MMAP_EACH_PKTSET
    case CI_NETIF_MMAP_ID_PKTS:
      rc = tcp_helper_rm_mmap_pkts(trs, bytes, opaque, map_id, offset);
      break;
    default:
      rc = -EINVAL;
      break;
#else
    default:
      rc = tcp_helper_rm_mmap_pkts(trs, bytes, opaque, map_id, offset);
#endif
  }

  if( rc == 0 )  return 0;

  OO_DEBUG_VM(ci_log("%s: failed map_id=%x rc=%d", __FUNCTION__, map_id, rc));
  return rc;
}

/*! \cidoxg_end */
