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


#include <ci/driver/efab/debug.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/pd.h>
#include <ci/driver/efab/efch.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/efab/efrm_mmap.h>
#include <ci/efch/op_types.h>
#include <driver/linux_resource/kernel_compat.h>
#include "char_internal.h"
#include "filter_list.h"


static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };


/*** Resource dumping ****************************************************/

static void
efch_vi_rm_dump_nic(struct efrm_vi* virs, const char *line_prefix)
{
  struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
  int queue_type;

  ci_log("%s  nic %d EVQ kva=0x%p  dma=0x"DMA_ADDR_T_FMT" capacity=%d",
         line_prefix, nic->index,
         efhw_iopages_ptr(&virs->q[EFHW_EVQ].pages),
         efhw_iopages_dma_addr(&virs->q[EFHW_EVQ].pages, 0),
         virs->q[EFHW_EVQ].capacity);

  for(queue_type=0; queue_type<EFRM_VI_RM_DMA_QUEUE_COUNT; queue_type++) {
    ci_log("%s  nic %d %s kva=0x%p dma=" DMA_ADDR_T_FMT,
           line_prefix, nic->index, q_names[queue_type],
           efhw_iopages_ptr(&virs->q[queue_type].pages),
           efhw_iopages_dma_addr(&virs->q[queue_type].pages, 0));
  }
}


static void efch_vi_rm_dump(struct efrm_resource* rs, ci_resource_table_t *rt,
                            const char *line_prefix) 
{
  struct efrm_vi* virs = efrm_vi(rs);

  ci_log("%sVI resource " EFRM_RESOURCE_FMT,
         line_prefix, EFRM_RESOURCE_PRI_ARG(&virs->rs));

  if (virs->q[EFHW_TXQ].evq_ref != NULL)
    ci_log("%s  txq_evq:" EFRM_RESOURCE_FMT, line_prefix,
           EFRM_RESOURCE_PRI_ARG(&virs->q[EFHW_TXQ].evq_ref->rs));
  if (virs->q[EFHW_RXQ].evq_ref != NULL)
    ci_log("%s  rxq_evq:" EFRM_RESOURCE_FMT, line_prefix,
           EFRM_RESOURCE_PRI_ARG(&virs->q[EFHW_RXQ].evq_ref->rs));

  ci_log("%s  mmap bytes: mem=%d", line_prefix, virs->mem_mmap_bytes);

  ci_log("%s  capacity: EVQ=%d TXQ=%d RXQ=%d", line_prefix,
         virs->q[EFHW_EVQ].capacity,
         virs->q[EFHW_TXQ].capacity,
         virs->q[EFHW_RXQ].capacity);

  ci_log("%s  tx_tag=0x%x  rx_tag=0x%x  flags=0x%x", line_prefix,
         virs->q[EFHW_TXQ].tag,
         virs->q[EFHW_RXQ].tag,
         (unsigned) virs->flags);

  ci_log("%s  flush: TX=%d RX=%d time=0x%"CI_PRIx64" count=%d",
         line_prefix, virs->q[EFHW_TXQ].flushing,
         virs->q[EFHW_TXQ].flushing, virs->flush_time, virs->flush_count);

  ci_log("%s  callback: fn=0x%p  arg=0x%p",
         line_prefix, virs->evq_callback_fn, virs->evq_callback_arg);

  ci_log("%s  buffer table: tx_base=0x%x tx_order=0x%x "
         "rx_base=0x%x rx_order=0x%x",
         line_prefix,
         virs->q[EFHW_TXQ].buf_tbl_alloc.base,
         virs->q[EFHW_TXQ].buf_tbl_alloc.order,
         virs->q[EFHW_RXQ].buf_tbl_alloc.base,
         virs->q[EFHW_RXQ].buf_tbl_alloc.order);

  efch_vi_rm_dump_nic(virs, line_prefix);
}


/*** Allocation ************************************************/

static int
vi_resource_alloc(struct efrm_vi_attr *attr,
                  struct efrm_client *client,
                  struct efrm_vi *evq_virs,
                  unsigned vi_flags,
                  int evq_capacity, int txq_capacity, int rxq_capacity,
                  int tx_q_tag, int rx_q_tag,
                  struct efrm_vi **virs_out)
{
	struct efrm_vi *virs;
	int rc;

	if (vi_flags & EFHW_VI_RM_WITH_INTERRUPT)
		efrm_vi_attr_set_with_interrupt(attr, 1);

	if ((rc = efrm_vi_alloc(client, attr, &virs)) < 0)
		goto fail_vi_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
				  tx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
				  rx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;

	if (evq_virs == NULL && evq_capacity < 0) {
		evq_capacity = (virs->q[EFHW_RXQ].capacity +
				virs->q[EFHW_TXQ].capacity);
		if (evq_capacity == 0)
			evq_capacity = -1;
	}

	if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
				  0, vi_flags, NULL)) < 0)
		goto fail_q_alloc;
	*virs_out = virs;
	return 0;


fail_q_alloc:
	efrm_vi_resource_release(virs);
fail_vi_alloc:
	return rc;
}


static int
efch_vi_rm_find(int fd, efch_resource_id_t rs_id, int rs_type,
                struct efrm_resource **rs_out)
{
  return (fd < 0) ? 1 : efch_lookup_rs(fd, rs_id, rs_type, rs_out);
}


static int
efch_vi_rm_alloc(ci_resource_alloc_t* alloc, ci_resource_table_t* rt,
                 efch_resource_t* rs, int intf_ver_id)
{
  const struct efch_vi_alloc_in *alloc_in;
  struct efch_vi_alloc_out *alloc_out;
  struct efrm_resource *vi_set = NULL;
  struct efrm_resource *evq = NULL;
  struct efrm_resource *pd = NULL;
  struct efrm_client *client;
  struct efrm_vi *virs = NULL;
  struct efrm_vi_attr attr;
  struct efhw_nic *nic;
  int rc;

  ci_assert(alloc != NULL);
  ci_assert(rt != NULL);
  ci_assert(rs != NULL);

  alloc_in = &alloc->u.vi_in;

  DEBUGRES(ci_log("%s: evq=%d txq=%d rxq=%d", __FUNCTION__,
                   alloc_in->evq_capacity,
                   alloc_in->txq_capacity,
                   alloc_in->rxq_capacity));

  efrm_vi_attr_init(&attr);

  /* Validate the request. */
  if( (rt->access & CI_CAP_PHYS) == 0 ) {
    if( (alloc_in->flags & (EFHW_VI_RX_PHYS_ADDR_EN |
                            EFHW_VI_TX_PHYS_ADDR_EN)) != 0 ) {
      DEBUGERR(ci_log("%s: Not permitted to create phys-addr resource",
                      __FUNCTION__));
      return -EPERM;
    }
  }

  if ((rc = efch_vi_rm_find(alloc_in->evq_fd, alloc_in->evq_rs_id,
                            EFRM_RESOURCE_VI, &evq)) < 0)
    goto fail1;
  if ((rc = efch_vi_rm_find(alloc_in->pd_or_vi_set_fd,
                            alloc_in->pd_or_vi_set_rs_id,
                            EFRM_RESOURCE_PD, &pd)) < 0)
    if ((rc = efch_vi_rm_find(alloc_in->pd_or_vi_set_fd,
                              alloc_in->pd_or_vi_set_rs_id,
                              EFRM_RESOURCE_VI_SET, &vi_set)) < 0)
      goto fail2;

  if( vi_set != NULL ) {
    client = NULL;
    efrm_vi_attr_set_instance(&attr, efrm_vi_set_from_resource(vi_set),
                              alloc_in->vi_set_instance);
  }
  else if( pd != NULL ) {
    client = NULL;
    efrm_vi_attr_set_pd(&attr, efrm_pd_from_resource(pd));
  }
  else {
    rc = efrm_client_get(alloc_in->ifindex, NULL, NULL, &client);
    if( rc != 0 ) {
      DEBUGERR(ci_log("%s: efrm_client_get(%d) failed (%d)",
                      __FUNCTION__, alloc_in->ifindex, rc));
      goto fail3;
    }
  }

  rc = vi_resource_alloc(&attr, client, evq ? efrm_vi(evq) : NULL,
                         alloc_in->flags,
                         alloc_in->evq_capacity,
                         alloc_in->txq_capacity, alloc_in->rxq_capacity,
                         alloc_in->tx_q_tag, alloc_in->rx_q_tag,
                         &virs);
  CI_DEBUG(alloc_in = NULL);
  if( client != NULL )
    efrm_client_put(client);
  if (evq != NULL) {
    efrm_resource_release(evq);
    evq = NULL;
  }
  if (vi_set != NULL) {
    efrm_resource_release(vi_set);
    vi_set = NULL;
  }
  if (pd != NULL) {
    efrm_resource_release(pd);
    pd = NULL;
  }
  if (rc != 0)
    goto fail3;

  efch_filter_list_init(&rs->vi.fl);

  /* Initialise the outputs. */
  alloc_out = &alloc->u.vi_out;
  CI_DEBUG(alloc = NULL);
  CI_DEBUG(alloc_in = NULL);
  alloc_out->instance = virs->rs.rs_instance;
  alloc_out->evq_capacity = virs->q[EFHW_EVQ].capacity;
  alloc_out->rxq_capacity = virs->q[EFHW_RXQ].capacity;
  alloc_out->txq_capacity = virs->q[EFHW_TXQ].capacity;
  nic = efrm_client_get_nic(virs->rs.rs_client);
  alloc_out->nic_arch = nic->devtype.arch;
  alloc_out->nic_variant = nic->devtype.variant;
  alloc_out->nic_revision = nic->devtype.revision;
  alloc_out->io_mmap_bytes = 4096;
  alloc_out->mem_mmap_bytes = virs->mem_mmap_bytes;

  rs->rs_base = &virs->rs;
  DEBUGRES(ci_log("%s: Allocated "EFRM_RESOURCE_FMT, __FUNCTION__,
                   EFRM_RESOURCE_PRI_ARG(&virs->rs)));
  DEBUGRES(efch_vi_rm_dump(&virs->rs, rt, ""));
  DEBUGRES(ci_log("%s: Returning rc %d", __FUNCTION__, rc));
  return 0;

 fail3:
  if (vi_set != NULL)
    efrm_resource_release(vi_set);
  if (pd != NULL)
    efrm_resource_release(pd);
 fail2:
  if (evq != NULL)
    efrm_resource_release(evq);
 fail1:
  return rc;
}


void efch_vi_rm_free(efch_resource_t *rs)
{
  efch_filter_list_free(rs->rs_base, &rs->vi.fl);
}


/*** Resource operations *************************************************/

static void
efrm_eventq_put(struct efrm_vi* virs, ci_resource_op_t* op)
{
  struct efhw_nic *nic;
  nic = efrm_client_get_nic(virs->rs.rs_client);

  DEBUGVERB(ci_log("efrm_eventq_put: nic "EFRM_RESOURCE_FMT" "
		   FALCON_EVENT_FMT,
		   EFRM_RESOURCE_PRI_ARG(&virs->rs),
                   FALCON_EVENT_PRI_ARG(op->u.evq_put.ev)));

  efhw_nic_sw_event(nic, op->u.evq_put.ev.opaque.a, virs->rs.rs_instance);
}


static int efab_vi_get_mtu(struct efrm_vi* virs, unsigned* mtu_out)
{
  struct efhw_nic* nic;
  nic = efrm_client_get_nic(virs->rs.rs_client);
  *mtu_out = nic->mtu;
  return 0;
}


static int efab_vi_get_mac(struct efrm_vi* virs, void* mac_out)
{
  struct efhw_nic* nic;
  nic = efrm_client_get_nic(virs->rs.rs_client);
  memcpy(mac_out, nic->mac_addr, 6);
  return 0;
}


static void efch_vi_flush_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}


static int
efch_vi_rm_rsops(efch_resource_t* rs, ci_resource_table_t* rt,
                 ci_resource_op_t* op, int* copy_out
                 CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t bc))
{
  struct efrm_vi *virs = efrm_vi(rs->rs_base);
  struct completion flush_completion;

  int rc;
  switch(op->op) {
    case CI_RSOP_EVENTQ_PUT:
      efrm_eventq_put(virs, op);
      rc = 0;
      break;

    case CI_RSOP_EVENTQ_WAIT:
      rc = efab_vi_rm_eventq_wait(virs, op->u.evq_wait.current_ptr,
                                  &op->u.evq_wait.timeout
                                  CI_BLOCKING_CTX_ARG(bc));
      *copy_out = 1;
      break;

    case CI_RSOP_VI_GET_MTU: {
      unsigned mtu;
      rc = efab_vi_get_mtu(virs, &mtu);
      op->u.vi_get_mtu.out_mtu = mtu;
      *copy_out = 1;
      break;
    }

    case CI_RSOP_VI_GET_MAC:
      rc = efab_vi_get_mac(virs, op->u.vi_get_mac.out_mac);
      *copy_out = 1;
      break;

    case CI_RSOP_PT_ENDPOINT_FLUSH:
      init_completion(&flush_completion);
      efrm_vi_register_flush_callback(virs, &efch_vi_flush_complete,
                                      &flush_completion);
      efrm_pt_flush(virs);
      while(wait_for_completion_timeout(&flush_completion, HZ) == 0)
        ci_log("%s: still waiting for flush to complete", __FUNCTION__);
      rc = 0;
      break;

    case CI_RSOP_PT_ENDPOINT_PACE:
      rc = efrm_pt_pace(virs, op->u.pt.pace);
      break;

    default:
      rc = efch_filter_list_op(rs->rs_base, &rs->vi.fl, op, copy_out, 0u);
      break;
  }
  return rc;
}


/*** Resource manager methods ********************************************/

static int efch_vi_rm_mmap(struct efrm_resource *rs, unsigned long *bytes,
                           void *opaque, int *map_num, unsigned long *offset,
                           int index)
{
  return efab_vi_resource_mmap(efrm_vi(rs), bytes, opaque,
                               map_num, offset, index);
}


#ifndef CI_HAVE_OS_NOPAGE
static unsigned
efab_vi_rm_nopage_not_supported(struct efrm_resource* rs,
                                void* opaque, unsigned long offset,
                                unsigned long map_size)
{
  ci_log("efab_nopage: on '%s' "EFRM_RESOURCE_FMT" offset=%lx"
	 " map_size=%lx", rs->rs_owner->rm_name,
	 EFRM_RESOURCE_PRI_ARG(rs), offset, map_size);
  return (unsigned) -1; /* bus fault */
}
#endif


static unsigned
efch_vi_rm_nopage(struct efrm_resource *rs, void *opaque,
                  unsigned long offset, unsigned long map_size)
{
  return efab_vi_resource_nopage(efrm_vi(rs), opaque, offset, map_size);
}


static int efch_vi_rm_mmap_bytes(struct efrm_resource* rs, int map_type)
{
  return efab_vi_resource_mmap_bytes(efrm_vi(rs), map_type);
}


efch_resource_ops efch_vi_ops = {
  efch_vi_rm_alloc,
  efch_vi_rm_free,
  efch_vi_rm_mmap,
#if defined(CI_HAVE_OS_NOPAGE)
  efch_vi_rm_nopage,
#else
  efch_vi_rm_nopage_not_supported,
#endif
  efch_vi_rm_dump,
  efch_vi_rm_rsops,
  efch_vi_rm_mmap_bytes,
};

