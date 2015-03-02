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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Allocate a VI resource.
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <ci/efhw/common.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"
#include "efch_intf_ver.h"
#include <stdio.h>


/* ****************************************************************************
 * This set of functions provides the equivalent functionality of the
 * kernel vi resource manager.  They fully resolve the base addresses of
 * the Rx & Tx doorbell & DMA queue for both Falcon & EF1.
 */

static unsigned vi_flags_to_efab_flags(unsigned vi_flags)
{
  unsigned efab_flags = 0u;
  if( vi_flags & EF_VI_ISCSI_RX_HDIG     ) efab_flags |= EFHW_VI_ISCSI_RX_HDIG_EN;
  if( vi_flags & EF_VI_ISCSI_TX_HDIG     ) efab_flags |= EFHW_VI_ISCSI_TX_HDIG_EN;
  if( vi_flags & EF_VI_ISCSI_RX_DDIG     ) efab_flags |= EFHW_VI_ISCSI_RX_DDIG_EN;
  if( vi_flags & EF_VI_ISCSI_TX_DDIG     ) efab_flags |= EFHW_VI_ISCSI_TX_DDIG_EN;
  if( vi_flags & EF_VI_TX_PHYS_ADDR      ) efab_flags |= EFHW_VI_TX_PHYS_ADDR_EN;
  if( vi_flags & EF_VI_RX_PHYS_ADDR      ) efab_flags |= EFHW_VI_RX_PHYS_ADDR_EN;
  if( vi_flags & EF_VI_TX_IP_CSUM_DIS    ) efab_flags |= EFHW_VI_TX_IP_CSUM_DIS;
  if( vi_flags & EF_VI_TX_TCPUDP_CSUM_DIS) efab_flags |= EFHW_VI_TX_TCPUDP_CSUM_DIS;
  if( vi_flags & EF_VI_TX_TCPUDP_ONLY    ) efab_flags |= EFHW_VI_TX_TCPUDP_ONLY;
  if( vi_flags & EF_VI_TX_FILTER_IP      ) efab_flags |= EFHW_VI_TX_IP_FILTER_EN;
  if( vi_flags & EF_VI_TX_FILTER_MAC     ) efab_flags |= EFHW_VI_TX_ETH_FILTER_EN;
  if( vi_flags & EF_VI_TX_FILTER_MASK_1  ) efab_flags |= EFHW_VI_TX_Q_MASK_WIDTH_0;
  if( vi_flags & EF_VI_TX_FILTER_MASK_2  ) efab_flags |= EFHW_VI_TX_Q_MASK_WIDTH_1;
  if( vi_flags & EF_VI_RX_TIMESTAMPS     ) efab_flags |= EFHW_VI_RX_TIMESTAMPS;
  if( vi_flags & EF_VI_TX_TIMESTAMPS     ) efab_flags |= EFHW_VI_TX_TIMESTAMPS;
  if( vi_flags & EF_VI_RX_PACKED_STREAM  ) efab_flags |= (EFHW_VI_RX_PACKED_STREAM |
                                                          EFHW_VI_NO_CUT_THROUGH);
  return efab_flags;
}


/* Certain VI functionalities are only supported on certain NIC types.
 * This function validates that the requested functionality is present
 * on the selected NIC. */
static int check_nic_compatibility(unsigned vi_flags, unsigned ef_vi_arch)
{
  switch (ef_vi_arch) {
  case EFHW_ARCH_FALCON:
    if (vi_flags & EF_VI_TX_PUSH_ALWAYS) {
      LOGVV(ef_log("%s: ERROR: TX PUSH ALWAYS flag not supported"
                   " on FALCON architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    if (vi_flags & EF_VI_RX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: RX TIMESTAMPS flag not supported"
                   " on FALCON architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    if (vi_flags & EF_VI_TX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: TX TIMESTAMPS flag not supported"
                   " on FALCON architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    return 0;
    
  case EFHW_ARCH_EF10:
    return 0;
    
  default:
    return -EINVAL;
  }
}


static int get_ts_correction(ef_driver_handle vi_dh, int res_id,
			     int* rx_ts_correction)
{
  ci_resource_op_t op;
  int rc;
  op.op = CI_RSOP_VI_GET_RX_TS_CORRECTION;
  op.id = efch_make_resource_id(res_id);
  rc = ci_resource_op(vi_dh, &op);
  *rx_ts_correction = op.u.vi_rx_ts_correction.out_rx_ts_correction;
  return rc;
}


/****************************************************************************/

void ef_vi_set_intf_ver(char* intf_ver, size_t len)
{
  /* Bodge interface requested to match the one used in
   * openonload-201405-u1.  The interface has changed since then, but in
   * ways that are forward and backward compatible with
   * openonload-201405-u1.
   *
   * We check that the current interface is the one expected, because if
   * not then something has changed and compatibility may not have been
   * preserved.
   */
  strncpy(intf_ver, "1518b4f7ec6834a578c7a807736097ce", len);
  /* when built from repo */
  if( strcmp(EFCH_INTF_VER, "e12018c1ff2aff3d8ee46432b5669fcd") &&
      /* when built from distro */
      strcmp(EFCH_INTF_VER, "c4122121098b174cc48ef7e56c792b4a") ) {
    fprintf(stderr, "ef_vi: ERROR: char interface has changed\n");
    abort();
  }
}


int __ef_vi_alloc(ef_vi* vi, ef_driver_handle vi_dh,
		  efch_resource_id_t pd_or_vi_set_id,
		  ef_driver_handle pd_or_vi_set_dh,
		  int index_in_vi_set, int ifindex, int evq_capacity,
		  int rxq_capacity, int txq_capacity,
		  ef_vi* evq, ef_driver_handle evq_dh,
		  int vi_clustered, enum ef_vi_flags vi_flags)
{
  struct ef_vi_nic_type nic_type;
  ci_resource_alloc_t ra;
  char *mem_mmap_ptr_orig, *mem_mmap_ptr;
  char *io_mmap_ptr, *io_mmap_base;
  ef_vi_state* state;
  int rc;
  const char* s;
  uint32_t* ids;
  void* p;
  int q_label;

  EF_VI_BUG_ON((evq == NULL) != (evq_capacity != 0));
  EF_VI_BUG_ON(! evq_capacity && ! rxq_capacity && ! txq_capacity);

  /* Ensure ef_vi_free() only frees what we allocate. */
  io_mmap_ptr = NULL;
  io_mmap_base = NULL;
  mem_mmap_ptr = mem_mmap_ptr_orig = NULL;

  if( evq == NULL )
    q_label = 0;
  else if( (q_label = evq->vi_qs_n) == EF_VI_MAX_QS )
    return -EBUSY;

  if( ifindex < 0 && (s = getenv("EF_VI_IFINDEX")) )
    ifindex = atoi(s);
  if( evq_capacity == -1 )
    evq_capacity = (s = getenv("EF_VI_EVQ_SIZE")) ? atoi(s) : -1;
  if( txq_capacity == -1 )
    txq_capacity = (s = getenv("EF_VI_TXQ_SIZE")) ? atoi(s) : -1;
  if( rxq_capacity == -1 )
    rxq_capacity = (s = getenv("EF_VI_RXQ_SIZE")) ? atoi(s) : -1;
  if( evq_capacity == -1 && (vi_flags & EF_VI_RX_PACKED_STREAM) )
    /* At time of writing we're doing this at user-level as well as in
     * driver.  Utimately we want this default to be applied in the driver
     * so we don't have to know this magic number (which may change in
     * future).  For now we also apply it here so that the default will be
     * applied when running against a 201405-u1 driver.  This can be
     * removed once the driver ABI changes.
     */
    evq_capacity = 32768;

  /* Allocate resource and mmap. */
  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_VI;
  ra.u.vi_in.ifindex = ifindex;
  ra.u.vi_in.pd_or_vi_set_fd = pd_or_vi_set_dh;
  ra.u.vi_in.pd_or_vi_set_rs_id = pd_or_vi_set_id;
  ra.u.vi_in.vi_set_instance = index_in_vi_set;
  ra.u.vi_in.ps_buf_size_kb = (vi_flags & EF_VI_RX_PS_BUF_SIZE_64K) ? 64 : 1024;
  if( evq != NULL ) {
    ra.u.vi_in.evq_fd = evq_dh;
    ra.u.vi_in.evq_rs_id = efch_make_resource_id(evq->vi_resource_id);
  }
  else {
    ra.u.vi_in.evq_fd = -1;
    evq = vi;
  }
  ra.u.vi_in.evq_capacity = evq_capacity;
  ra.u.vi_in.txq_capacity = txq_capacity;
  ra.u.vi_in.rxq_capacity = rxq_capacity;
  ra.u.vi_in.tx_q_tag = q_label;
  ra.u.vi_in.rx_q_tag = q_label;
  ra.u.vi_in.flags = vi_flags_to_efab_flags(vi_flags);
  rc = ci_resource_alloc(vi_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc %d", __FUNCTION__, rc));
    goto fail1;
  }

  evq_capacity = ra.u.vi_out.evq_capacity;
  txq_capacity = ra.u.vi_out.txq_capacity;
  rxq_capacity = ra.u.vi_out.rxq_capacity;

  rc = -ENOMEM;
  state = malloc(ef_vi_calc_state_bytes(rxq_capacity, txq_capacity));
  if( state == NULL )
    goto fail1;

  if( ra.u.vi_out.io_mmap_bytes ) {
    rc = ci_resource_mmap(vi_dh, ra.out_id.index, EFCH_VI_MMAP_IO,
			  ra.u.vi_out.io_mmap_bytes, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (io) %d", __FUNCTION__, rc));
      goto fail2;
    }
    { /* On systems with large pages, multiple VI windows are mapped into
       * each system page.  Therefore the VI window may not appear at the
       * start of the I/O mapping.
       */
      int inst_in_iopage = 0;
      int vi_windows_per_page = CI_PAGE_SIZE / 8192;
      if( vi_windows_per_page > 1 )
        inst_in_iopage = ra.u.vi_out.instance & (vi_windows_per_page - 1);
      io_mmap_base = (char*) p;
      io_mmap_ptr = io_mmap_base + inst_in_iopage * 8192;
    }
  }

  if( ra.u.vi_out.mem_mmap_bytes ) {
    rc = ci_resource_mmap(vi_dh, ra.out_id.index, EFCH_VI_MMAP_MEM,
			  ra.u.vi_out.mem_mmap_bytes, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (mem) %d", __FUNCTION__, rc));
      goto fail3;
    }
    mem_mmap_ptr = mem_mmap_ptr_orig = (char*) p;
  }

  rc = ef_vi_arch_from_efhw_arch(ra.u.vi_out.nic_arch);
  EF_VI_BUG_ON(rc < 0);
  nic_type.arch = (unsigned char) rc;
  nic_type.variant = ra.u.vi_out.nic_variant;
  nic_type.revision = ra.u.vi_out.nic_revision;

  rc = check_nic_compatibility(vi_flags, nic_type.arch);
  if( rc != 0 )
    goto fail4;

  ids = (void*) (state + 1);

  ef_vi_init(vi, nic_type.arch, nic_type.variant, nic_type.revision,
	     vi_flags, state);
  ef_vi_init_out_flags(vi, (ra.u.vi_out.out_flags & EFHW_VI_CLOCK_SYNC_STATUS) ?
                       EF_VI_OUT_CLOCK_SYNC_STATUS : 0);
  ef_vi_init_io(vi, io_mmap_ptr);
  if( evq_capacity ) {
    ef_vi_init_evq(vi, evq_capacity, mem_mmap_ptr);
    mem_mmap_ptr += ((evq_capacity * sizeof(efhw_event_t) + CI_PAGE_SIZE - 1)
		     & CI_PAGE_MASK);
  }
  if( rxq_capacity ) {
    ef_vi_init_rxq(vi, rxq_capacity, mem_mmap_ptr, ids,
		   ra.u.vi_out.rx_prefix_len);
    mem_mmap_ptr += (ef_vi_rx_ring_bytes(vi) + CI_PAGE_SIZE-1) & CI_PAGE_MASK;
    ids += rxq_capacity;
    if( vi_flags & EF_VI_RX_TIMESTAMPS ) {
      int rx_ts_correction;
      rc = get_ts_correction(vi_dh, ra.out_id.index, &rx_ts_correction);
      if( rc < 0 )
        goto fail4;
      ef_vi_init_rx_timestamping(vi, rx_ts_correction);
    }
  }
  if( txq_capacity )
    ef_vi_init_txq(vi, txq_capacity, mem_mmap_ptr, ids);

  vi->vi_io_mmap_ptr = io_mmap_base;
  vi->vi_mem_mmap_ptr = mem_mmap_ptr_orig;
  vi->vi_io_mmap_bytes = ra.u.vi_out.io_mmap_bytes;
  vi->vi_mem_mmap_bytes = ra.u.vi_out.mem_mmap_bytes;
  vi->vi_resource_id = ra.out_id.index;
  if( ra.u.vi_out.out_flags & EFHW_VI_PS_BUF_SIZE_SET )
    vi->vi_ps_buf_size = ra.u.vi_out.ps_buf_size;
  else
    vi->vi_ps_buf_size = 1024 * 1024;
  BUG_ON(vi->vi_ps_buf_size != 64*1024 &&
         vi->vi_ps_buf_size != 1024*1024);
  vi->vi_clustered = vi_clustered;
  vi->vi_i = ra.u.vi_out.instance;
  ef_vi_init_state(vi);
  rc = ef_vi_add_queue(evq, vi);
  BUG_ON(rc != q_label);
  vi->vi_is_packed_stream = !! (vi_flags & EF_VI_RX_PACKED_STREAM);

  if( vi->vi_is_packed_stream )
    ef_vi_packed_stream_update_credit(vi);

  return q_label;

 fail4:
  if( mem_mmap_ptr != NULL )
    ci_resource_munmap(vi_dh, mem_mmap_ptr, ra.u.vi_out.mem_mmap_bytes);
 fail3:
  if( io_mmap_base != NULL )
    ci_resource_munmap(vi_dh, io_mmap_base, ra.u.vi_out.io_mmap_bytes);
 fail2:
  free(state);
 fail1:
  --evq->vi_qs_n;
  return rc;
}


int ef_vi_alloc_from_pd(ef_vi* vi, ef_driver_handle vi_dh,
			struct ef_pd* pd, ef_driver_handle pd_dh,
			int evq_capacity, int rxq_capacity, int txq_capacity,
			ef_vi* evq_opt, ef_driver_handle evq_dh,
			enum ef_vi_flags flags)
{
  efch_resource_id_t res_id = efch_make_resource_id(pd->pd_resource_id);
  int index_in_vi_set = 0;
  int vi_clustered = 0;

  if( pd->pd_flags & EF_PD_PHYS_MODE )
    flags |= EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR;
  else
    flags &= ~(EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR);

  if( pd->pd_cluster_sock != -1 ) {
    pd_dh = pd->pd_cluster_dh;
    res_id = efch_make_resource_id(
                                   pd->pd_cluster_viset_resource_id);
    index_in_vi_set = -1;
    vi_clustered = 1;
  }
  return __ef_vi_alloc(vi, vi_dh, res_id, pd_dh, index_in_vi_set,
                       -1/*ifindex*/, evq_capacity, rxq_capacity,
                       txq_capacity, evq_opt, evq_dh, vi_clustered,
                       flags);
			     
}


int ef_vi_alloc_from_set(ef_vi* vi, ef_driver_handle vi_dh,
			 ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
			 int index_in_vi_set, int evq_capacity,
			 int rxq_capacity, int txq_capacity,
			 ef_vi* evq_opt, ef_driver_handle evq_dh,
			 enum ef_vi_flags flags)
{
  if( vi_set->vis_pd->pd_flags & EF_PD_PHYS_MODE )
    flags |= EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR;
  else
    flags &= ~(EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR);
  return __ef_vi_alloc(vi, vi_dh,
                       efch_make_resource_id(vi_set->vis_res_id),
                       vi_set_dh, index_in_vi_set,
                       -1/*ifindex*/,
                       evq_capacity, rxq_capacity, txq_capacity,
                       evq_opt, evq_dh, 0, flags);
}


int ef_vi_free(ef_vi* ep, ef_driver_handle fd)
{
  int rc;

  if( ep->vi_io_mmap_ptr != NULL ) {
    rc = ci_resource_munmap(fd, ep->vi_io_mmap_ptr, ep->vi_io_mmap_bytes);
    if( rc < 0 ) {
      LOGV(ef_log("%s: ci_resource_munmap %d", __FUNCTION__, rc));
      return rc;
    }
  }

  if( ep->vi_mem_mmap_ptr != NULL ) {
    /* TODO: support variable sized DMAQ and evq */
    rc = ci_resource_munmap(fd, ep->vi_mem_mmap_ptr, ep->vi_mem_mmap_bytes);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_munmap iobuffer %d", __FUNCTION__, rc));
      return rc;
    }
  }

  free(ep->ep_state);

  EF_VI_DEBUG(memset(ep, 0, sizeof(*ep)));

  LOGVVV(ef_log("%s: DONE", __FUNCTION__));
  return 0;
}


unsigned ef_vi_mtu(ef_vi* vi, ef_driver_handle fd)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_VI_GET_MTU;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  rc = ci_resource_op(fd, &op);
  if( rc < 0 )
    LOGV(ef_log("%s: ci_resource_op %d", __FUNCTION__, rc));
  return op.u.vi_get_mtu.out_mtu;
}


int ef_vi_get_mac(ef_vi* vi, ef_driver_handle dh, void* mac_out)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_VI_GET_MAC;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  rc = ci_resource_op(dh, &op);
  if( rc < 0 )
    LOGV(ef_log("%s: ci_resource_op %d", __FUNCTION__, rc));
  memcpy(mac_out, op.u.vi_get_mac.out_mac, 6);
  return rc;
}


int ef_vi_flush(ef_vi* ep, ef_driver_handle fd)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PT_ENDPOINT_FLUSH;
  op.id = efch_make_resource_id(ep->vi_resource_id);
  rc = ci_resource_op(fd, &op);
  if( rc < 0 ) {
    LOGV(ef_log("ef_vi_flush: ci_resource_op %d", rc));
    return rc;
  }

  return 0;
}


int ef_vi_pace(ef_vi* ep, ef_driver_handle fd, int val)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PT_ENDPOINT_PACE;
  op.id = efch_make_resource_id(ep->vi_resource_id);
  op.u.pt.pace = val;
  rc = ci_resource_op(fd, &op);
  if( rc < 0 ) {
    LOGV(ef_log("ef_vi_pace: ci_resource_op %d", rc));
    return rc;
  }

  return 0;
}


int ef_vi_arch_from_efhw_arch(int efhw_arch)
{
  switch( efhw_arch ) {
  case EFHW_ARCH_FALCON:
    return EF_VI_ARCH_FALCON;
  case EFHW_ARCH_EF10:
    return EF_VI_ARCH_EF10;
  default:
    return -1;
  }
}

/*! \cidoxg_end */
