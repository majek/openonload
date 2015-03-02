/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
#ifdef ONLOAD_OFE
#include "ofe/onload.h"
#endif



static int tcp_helper_rm_mmap_mem(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  void* opaque)
{
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  /* map contiguous shared state */
  rc = ci_contig_shmbuf_mmap(&trs->netif.state_buf, 0, &bytes, opaque,
                             &map_num, &offset);
  if( rc < 0 )  goto out;

  OO_DEBUG_MEMSIZE(ci_log("%s: taken %d bytes for contig shmbuf leaving %lu",
                          __FUNCTION__,
                          (int) ci_contig_shmbuf_size(&trs->netif.state_buf),
                          bytes));

#ifdef CI_HAVE_OS_NOPAGE
  rc = ci_shmbuf_mmap(&trs->netif.pages_buf, 0, &bytes, opaque,
                           &map_num, &offset);
  if( rc < 0 )  goto out;
  OO_DEBUG_MEMSIZE(ci_log("after mapping page buf have %ld", bytes));
#endif

  ci_assert_equal(bytes, 0);

 out:
  return rc;
}


static int tcp_helper_rm_mmap_cplane(tcp_helper_resource_t* trs,
                                     unsigned long bytes,
                                     void* opaque, int is_writable)
{
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  if( is_writable )
    return -EPERM;

  /* map the control plane shared data areas */
  rc = cicp_mmap(CICP_HANDLE(&trs->netif), &bytes, opaque,
                 &map_num, &offset);
  if( rc < 0 )  return rc;
  ci_assert_equal(bytes, 0);

  return rc;
}


static int tcp_helper_rm_mmap_io(tcp_helper_resource_t* trs,
                                 unsigned long bytes, void* opaque)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].vi_rs, &bytes, opaque,
                               &map_num, &offset, EFCH_VI_MMAP_IO);
    if( rc < 0 )
      return rc;
  }
  ci_assert_equal(bytes, 0);

  return 0;
}


#if CI_CFG_PIO
static int tcp_helper_rm_mmap_pio(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  void* opaque)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( trs->nic[intf_i].pio_io_mmap_bytes != 0 ) {
      rc = efab_vi_resource_mmap(trs->nic[intf_i].vi_rs, &bytes, opaque,
                                 &map_num, &offset, EFCH_VI_MMAP_PIO);
      if( rc < 0 )
        return rc;
    }
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif


static int tcp_helper_rm_mmap_buf(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  void* opaque)
{
  int intf_i, rc;
  ci_netif* ni;
  int map_num = 0;
  unsigned long offset = 0;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i ) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].vi_rs, &bytes, opaque,
                               &map_num, &offset, EFCH_VI_MMAP_MEM);
    if( rc < 0 )  return rc;
  }
#ifdef OO_DO_HUGE_PAGES
  ci_assert_ge(bytes, ni->pkt_sets_max * sizeof(trs->pkt_shm_id[0]));
  ci_assert_lt(bytes - PAGE_SIZE,
               ni->pkt_sets_max * sizeof(trs->pkt_shm_id[0]));
#else
  ci_assert_equal(bytes, 0);
#endif
  return 0;
}

/* fixme: this handler is linux-only */
static int tcp_helper_rm_mmap_pkts(tcp_helper_resource_t* trs,
                                   unsigned long bytes,
                                   void* opaque, int map_id)
{
  ci_netif* ni;
  ci_netif_state* ns;
  int bufid = map_id - CI_NETIF_MMAP_ID_PKTS;

  if( bytes != CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET )
    return -EINVAL;

  ni = &trs->netif;
  ns = ni->state;
  ci_assert(ns);

  /* Reserve space for packet buffers */
  if( bufid < 0 || bufid > ns->pkt_sets_max ||
      ni->buf_pages[bufid] == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD bufset_id=%d", __FUNCTION__,
                        trs->id, bufid));
    return -EINVAL;
  }

  return 0;
}

#ifdef ONLOAD_OFE
/* fixme: these handlers are linux-only */
static int tcp_helper_rm_mmap_ofe_ro(tcp_helper_resource_t* trs,
                                     unsigned long bytes,
                                     void* opaque, int is_writable)
{
  ci_netif* ni;

  ni = &trs->netif;
  if( ni->ofe == NULL )
    return -EINVAL;
  /* User may mmap all or ro-part only. */
  if( bytes > NI_OPTS(&trs->netif).ofe_size )
    return -EINVAL;
  if( is_writable )
    return -EPERM;
  return 0;
}
static int tcp_helper_rm_mmap_ofe_rw(tcp_helper_resource_t* trs,
                                     unsigned long bytes,
                                     void* opaque)
{
  ci_netif* ni;
  struct ofe_stats_usage stat;
  enum ofe_status orc;

  ni = &trs->netif;
  if( ni->ofe == NULL )
    return -EINVAL;

  orc = ofe_stats_rw_mem(ni->ofe, &stat);
  if( orc != OFE_OK )
    return -ofe_rc2errno(orc);
  if( bytes != stat.max )
    return -EINVAL;
  return 0;
}
#endif


int efab_tcp_helper_rm_mmap(tcp_helper_resource_t* trs, unsigned long bytes,
                            void* opaque, int map_id, int is_writable)
{
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);
  ci_assert(bytes > 0);

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx map_id=%x", __func__,
                     trs->id, bytes, map_id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      rc = tcp_helper_rm_mmap_mem(trs, bytes, opaque);
      break;
    case CI_NETIF_MMAP_ID_CPLANE:
      rc = tcp_helper_rm_mmap_cplane(trs, bytes, opaque, is_writable);
      break;
    case CI_NETIF_MMAP_ID_IO:
      rc = tcp_helper_rm_mmap_io(trs, bytes, opaque);
      break;
#if CI_CFG_PIO
    case CI_NETIF_MMAP_ID_PIO:
      rc = tcp_helper_rm_mmap_pio(trs, bytes, opaque);
      break;
#endif
    case CI_NETIF_MMAP_ID_IOBUFS:
      rc = tcp_helper_rm_mmap_buf(trs, bytes, opaque);
      break;
#ifdef ONLOAD_OFE
    case CI_NETIF_MMAP_ID_OFE_RO:
      rc = tcp_helper_rm_mmap_ofe_ro(trs, bytes, opaque, is_writable);
      break;
    case CI_NETIF_MMAP_ID_OFE_RW:
      rc = tcp_helper_rm_mmap_ofe_rw(trs, bytes, opaque);
      break;
#endif
    default:
      /* CI_NETIF_MMAP_ID_PKTS + set_id */
      rc = tcp_helper_rm_mmap_pkts(trs, bytes, opaque, map_id);
  }

  if( rc == 0 )  return 0;

  OO_DEBUG_VM(ci_log("%s: failed map_id=%x rc=%d", __FUNCTION__, map_id, rc));
  return rc;
}

/*! \cidoxg_end */
