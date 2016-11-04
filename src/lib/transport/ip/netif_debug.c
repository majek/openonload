/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2005/02/08
** Description: Validation and debug ops for netifs.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"
#include "uk_intf_ver.h"
#include <onload/version.h>
#include <onload/sleep.h>


/**********************************************************************
 * Validation of state.
 */

#ifndef NDEBUG

static void ci_netif_state_assert_valid(ci_netif* ni,
					const char* file, int line)
{
  ci_netif_state* nis = ni->state;
  citp_waitable* w;
  ci_tcp_state* ts;
  int intf_i, n;
  ci_ni_dllist_link* lnk;
  ci_iptime_t last_time;
  oo_pkt_p pp, last_pp;
  oo_sp sockp;
  oo_p a;

  verify(nis);

  /* check DMAQ overflow queue if non-empty */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    oo_pktq* dmaq = &nis->nic[intf_i].dmaq;
    if( OO_PP_NOT_NULL(dmaq->head) ) {
      verify( IS_VALID_PKT_ID(ni, dmaq->head) );
      verify( IS_VALID_PKT_ID(ni, dmaq->tail) );
      verify( OO_PP_IS_NULL(PKT(ni, dmaq->tail)->netif.tx.dmaq_next) );
      n = 0;
      for( last_pp = pp = dmaq->head; OO_PP_NOT_NULL(pp); ) {
        ++n;
        last_pp = pp;
        pp = PKT(ni, pp)->netif.tx.dmaq_next;
      }
      verify(OO_PP_EQ(last_pp, dmaq->tail));
      verify(dmaq->num == n);
    }
    else
      verify(dmaq->num == 0);
  }

  verify(ni->filter_table->table_size_mask > 0u);

  /* Check timeout queue 
  **    - contains sockets in the correct (timewait or
  **      CI_TCP_STATE_TIMEOUT_ORPHAN) state, 
  **    - is ordered by t_last_sent (time to timeout state ), and that
  **    - the timer is pending if the queue is not empty.
  */
  for( n = 0; n < OO_TIMEOUT_Q_MAX; n++ ) {
    last_time = 0; /* fixme: 0 is a valid time */

    for( a = nis->timeout_q[n].l.next;
         ! OO_P_EQ(a, ci_ni_dllist_link_addr(ni,
                              &nis->timeout_q[n].l)); ) {
      ts = TCP_STATE_FROM_LINK((ci_ni_dllist_link*) CI_NETIF_PTR(ni, a));
      verify(IS_VALID_SOCK_P(ni, S_SP(ts)));
      if( n == OO_TIMEOUT_Q_TIMEWAIT )
        verify( (ts->s.b.state == CI_TCP_TIME_WAIT) );
      else
        verify( ci_tcp_is_timeout_orphan(ts) );
      if (!last_time) last_time = ts->t_last_sent;
      verify( TIME_LE(last_time, ts->t_last_sent) );
      last_time = ts->t_last_sent;
      verify(ci_ip_timer_pending(ni, &nis->timeout_tid));
      a = ts->timeout_q_link.next;
    }
  }

  { /* Check the allocated endpoint IDs. */
    unsigned id;
    verify(nis->n_ep_bufs <= NI_OPTS(ni).max_ep_bufs);
    for( id = 0; id < nis->n_ep_bufs; ++id ) {
      w = ID_TO_WAITABLE(ni, id);
      verify(w);
      verify(W_ID(w) == id);
    }
  }

  /* Check the stack of free endpoint state buffers. */
  for( sockp = nis->free_eps_head; OO_SP_NOT_NULL(sockp); ) {
    verify(IS_VALID_SOCK_P(ni, sockp));
    w = SP_TO_WAITABLE(ni, sockp);
    verify(w);
    verify(OO_SP_EQ(W_SP(w), sockp));
    verify(w->state == CI_TCP_STATE_FREE);
    sockp = w->wt_next;
  }

  for( lnk = ci_ni_dllist_start(ni, &ni->state->post_poll_list);
       lnk != ci_ni_dllist_end(ni, &ni->state->post_poll_list); ) {
    w = CI_CONTAINER(citp_waitable, post_poll_link, lnk);

    if( w == CI_CONTAINER(citp_waitable, post_poll_link, 
			  (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next)) ) {
      ci_log("**** POST POLL LOOP DETECTED ****" );
      ci_log(" ni:%p lnk:%p .next:%x ptr:%p", 
	     ni, lnk, OO_P_FMT(lnk->next), CI_NETIF_PTR(ni, lnk->next));

      ci_log(" list_start:%p _end:%p", 
	     ci_ni_dllist_start(ni, &ni->state->post_poll_list),
	     ci_ni_dllist_end(ni, &ni->state->post_poll_list));

      ci_log(" %d state=%#x", W_FMT(w), w->state);
      
      ci_log(" .wk_nd:%x post_poll_link.prev:%x .next:%x", 
	     (unsigned) w->wake_request, OO_P_FMT(w->post_poll_link.prev),
             OO_P_FMT(w->post_poll_link.next));
      ci_assert(0);
    }
    lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next);
  }

#if CI_CFG_FULL_IP_ID_HANDLING
  ci_ipid_assert_valid(ni, file, line);
#endif

  ci_ip_timer_state_assert_valid(ni, file, line);
}


void ci_netif_assert_valid(ci_netif* ni, const char* file, int line)
{
  verify(ni);
#ifndef __KERNEL__	/*??*/
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
#endif
  ci_netif_state_assert_valid(ni, file, line);
}


void ci_netif_verify_freepkts(ci_netif *ni, const char *file, int line)
{
  ci_ip_pkt_fmt *pkt;
  int c1, c2, i;

  for( c1 = 0, i = 0; i < ni->packets->sets_n; i++ ) {
    verify( OO_PP_NOT_NULL(ni->packets->set[i].free) ==
            (ni->packets->set[i].n_free > 0) );
    verify(ni->packets->set[i].n_free >= 0);
    c1 += ni->packets->set[i].n_free;

    if( ni->packets->set[i].n_free > 0 ) {
      c2 = 1;
      /* can't do PKT_CHK here as that asserts that refcount > 0 */
      pkt = PKT(ni, ni->packets->set[i].free);
      while( OO_PP_NOT_NULL(pkt->next) ) {
        verify(pkt->refcount == 0);
        verify(pkt->n_buffers == 1);
        verify((pkt->flags & ~ CI_PKT_FLAG_NONB_POOL) == 0);
        verify(OO_PP_IS_NULL(pkt->frag_next));

        pkt = PKT(ni, pkt->next);
        ++c2;
      }
      verify(c2 == ni->packets->set[i].n_free);
    }
  }
}

#endif  /* NDEBUG */


void __ci_assert_valid_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                           const char* file, int line)
{
  _ci_assert_gt(pkt->refcount, 0, file, line);
  _ci_assert_gt(pkt->n_buffers, 0, file, line);
  _ci_assert_le(pkt->n_buffers, CI_IP_PKT_SEGMENTS_MAX, file, line);

  /* For a packet of more than one buffer, the buffers should be
   * linked through frag_next
   */
  _ci_assert_impl((pkt->n_buffers > 1), OO_PP_NOT_NULL(pkt->frag_next),
                  file, line);
  /* For a packet of one buffer, frag_next should be NULL or (in case
   * of UDP datagram larger than IP packet) should point to next IP
   * packet
   */
  _ci_assert_impl((pkt->n_buffers == 1), 
                  OO_PP_IS_NULL(pkt->frag_next) || pkt->frag_next == pkt->next,
                  file, line);
  _ci_assert_impl(OO_PP_IS_NULL(pkt->frag_next), pkt->n_buffers == 1,
                  file, line);
}


void ci_assert_valid_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                         ci_boolean_t ni_locked,
                         const char* file, int line)
{
  _ci_assert(pkt, file, line);
  ASSERT_VALID_PKT_ID(ni, OO_PKT_P(pkt));
  _ci_assert_equal(pkt, __PKT(ni, OO_PKT_P(pkt)), file, line);

  if( ni_locked ) {
    _ci_assert(ci_netif_is_locked(ni), file, line);
    __ci_assert_valid_pkt(ni, pkt, file, line);
  }
}


/**********************************************************************
 * Dumping state.
 */

#if (!defined(__KERNEL__)) || defined(CI_CFG_BUILD_DUMP_CODE_IN_KERNEL)

void ci_netif_dump_sockets(ci_netif* ni)
{
  ci_netif_dump_sockets_to_logger(ni, ci_log_dump_fn, NULL);
}

void ci_netif_dump_sockets_to_logger(ci_netif* ni, oo_dump_log_fn_t logger,
                                     void *log_arg)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE ) {
      citp_waitable_dump_to_logger(ni, &wo->waitable, "", logger, log_arg);
      logger(log_arg,
             "------------------------------------------------------------");
    }
  }
}


void ci_netif_print_sockets(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE &&
        wo->waitable.state != CI_TCP_CLOSED &&
        CI_TCP_STATE_IS_SOCKET(wo->waitable.state) ) {
      citp_waitable_print(&wo->waitable);
    }
  }
}


static void ci_netif_dump_pkt_summary(ci_netif* ni, oo_dump_log_fn_t logger,
                                      void* log_arg)
{
  int intf_i, rx_ring = 0, tx_ring = 0, tx_oflow = 0, used, rx_queued, i;
  ci_netif_state* ns = ni->state;

  logger(log_arg, "  pkt_sets: pkt_size=%d set_size=%d max=%d alloc=%d",
         CI_CFG_PKT_BUF_SIZE, PKTS_PER_SET, ni->packets->sets_max,
         ni->packets->sets_n);

  for( i = 0; i < ni->packets->sets_n; i++ ) {
    logger(log_arg, "  pkt_set[%d]: free=%d%s", i, ni->packets->set[i].n_free,
           i == ni->packets->id ? " current" : "");
  }

  rx_ring = 0;
  tx_ring = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    rx_ring += ef_vi_receive_fill_level(ci_netif_rx_vi(ni, intf_i));
    tx_ring += ef_vi_transmit_fill_level(&ni->nic_hw[intf_i].vi);
    tx_oflow += ns->nic[intf_i].dmaq.num;
  }
  used = ni->packets->n_pkts_allocated - ni->packets->n_free - ns->n_async_pkts;
  rx_queued = ns->n_rx_pkts - rx_ring - ns->mem_pressure_pkt_pool_n;

  logger(log_arg, "  pkt_bufs: max=%d alloc=%d free=%d async=%d%s",
         ni->packets->sets_max * PKTS_PER_SET,
         ni->packets->n_pkts_allocated, ni->packets->n_free, ns->n_async_pkts,
         (ns->mem_pressure & OO_MEM_PRESSURE_CRITICAL) ? " CRITICAL":
         (ns->mem_pressure ? " LOW":""));
  logger(log_arg, "  pkt_bufs: rx=%d rx_ring=%d rx_queued=%d pressure_pool=%d",
         ns->n_rx_pkts, rx_ring, rx_queued, ns->mem_pressure_pkt_pool_n);
  logger(log_arg, "  pkt_bufs: tx=%d tx_ring=%d tx_oflow=%d",
         (used - ns->n_rx_pkts - ns->n_looppkts), tx_ring, tx_oflow);
  logger(log_arg, "  pkt_bufs: in_loopback=%d in_sock=%d", ns->n_looppkts,
         used - ns->n_rx_pkts - ns->n_looppkts - tx_ring - tx_oflow);
}


/* as displaying 16k buffers is not that helpful we try and 
   group output into common states */
#define MAX_NO_DIFF_ALLOCS  32

typedef struct {
  int flags;
  /* how many buffers in this state */
  int no_buffers;
} ci_buffer_alloc_info_t;


void ci_netif_pkt_dump_all(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  int i, j, n_zero_refs = 0;
  ci_buffer_alloc_info_t * alloc;

  log("%s: id=%d  "CI_DEBUG("uid=%d pid=%d"), __FUNCTION__, NI_ID(ni)
      CI_DEBUG_ARG((int) ns->uid) CI_DEBUG_ARG((int) ns->pid));

  ci_netif_dump_pkt_summary(ni, ci_log_dump_fn, NULL);

  alloc = CI_ALLOC_ARRAY(ci_buffer_alloc_info_t, MAX_NO_DIFF_ALLOCS);
  if( alloc == NULL ) {
    ci_log("%s: ERROR: could not allocate memory", __FUNCTION__);
    return;
  }
  CI_ZERO_ARRAY(alloc, MAX_NO_DIFF_ALLOCS);

  for( i = 0; i < ni->packets->n_pkts_allocated; i++ ) {
    ci_ip_pkt_fmt* pkt;
    oo_pkt_p pp;
    OO_PP_INIT(ni, pp, i);
    pkt = PKT(ni, pp);
    if( pkt->refcount == 0 ) {
      ++n_zero_refs;
      continue;
    }
    for( j = 0; j < MAX_NO_DIFF_ALLOCS; j++ )
      if( alloc[j].flags == pkt->flags ) {
        alloc[j].no_buffers++;
        break;
      }
      else if( alloc[j].no_buffers == 0 ) {
        alloc[j].flags = pkt->flags;
        alloc[j].no_buffers = 1;
        break;
      }
  }
  for( j = 0; j < MAX_NO_DIFF_ALLOCS; j++ )
    if( alloc[j].no_buffers )
      log("    %3d: 0x%x "CI_PKT_FLAGS_FMT, alloc[j].no_buffers,
          alloc[j].flags, __CI_PKT_FLAGS_PRI_ARG(alloc[j].flags));
  ci_free(alloc);

  log("   n_zero_refs=%d n_freepkts=%d estimated_free_nonb=%d", 
      n_zero_refs, ni->packets->id, n_zero_refs - ni->packets->id);

  {
    /* Can't do this race free, but what the heck.  (Actually we could, but
     * we'd have to grab the whole list).
     */
    int no_nonb=0, next;
    ci_ip_pkt_fmt* nonb_pkt;
    oo_pkt_p pp;

    next = ns->nonb_pkt_pool & 0xffffffff;
    while( next != 0xffffffff ) {
      OO_PP_INIT(ni, pp, next);
      nonb_pkt = PKT(ni, pp);
      no_nonb++;
      next = OO_PP_ID(nonb_pkt->next);
    }
    log("   free_nonb=%d nonb_pkt_pool=%"CI_PRIx64, no_nonb, ns->nonb_pkt_pool);
  }
}


static int citp_waitable_force_wake(ci_netif* ni, citp_waitable* sb)
{
  int rc = sb->wake_request != 0;
  log("%s: %d:%d ", __FUNCTION__, NI_ID(ni), W_FMT(sb));
  ci_bit_set(&sb->wake_request, CI_SB_FLAG_WAKE_RX_B);
  ci_bit_set(&sb->wake_request, CI_SB_FLAG_WAKE_TX_B);
  citp_waitable_wake_not_in_poll(ni, sb,CI_SB_FLAG_WAKE_RX|CI_SB_FLAG_WAKE_TX);
  return rc;
}


int ci_netif_force_wake(ci_netif* ni, int everyone)
{
  ci_netif_state* ns = ni->state;
  unsigned id;
  int rc = 0;

  /* ?? todo: could pass in mask to select states to wake */

  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable* w = ID_TO_WAITABLE(ni, id);

    if( w->state != CI_TCP_STATE_FREE ) {
      /* If !everyone, then just those that look like they're sleeping. */
      if( everyone || w->wake_request )
	rc += citp_waitable_force_wake(ni, w);
    }
  }

  return rc;
}


void ci_netif_pkt_dump(ci_netif* ni, ci_ip_pkt_fmt* pkt, int is_recv, int dump)
{
  if( pkt == NULL ) {
    ci_log("%s: ERROR: NULL", __FUNCTION__);
    return;
  }
  ci_log("%s: id=%d flags=%x "CI_PKT_FLAGS_FMT,
         __FUNCTION__, OO_PKT_FMT(pkt), pkt->flags, CI_PKT_FLAGS_PRI_ARG(pkt));

  switch( oo_ether_type_get(pkt) ) {
  case CI_ETHERTYPE_IP:
    switch( oo_ip_hdr(pkt)->ip_protocol ) {
    case IPPROTO_TCP:
      ci_tcp_pkt_dump(ni, pkt, is_recv, dump);
      break;
    default:
      log("%s: pkt=%d unsupported ip_protocol=%d",
	  __FUNCTION__, OO_PKT_FMT(pkt), (int) oo_ip_hdr(pkt)->ip_protocol);
      break;
    }
    break;
  default:
    log("%s: pkt=%d unsupported ethertype=%x", __FUNCTION__, OO_PKT_FMT(pkt),
	(unsigned) CI_BSWAP_BE16(oo_ether_type_get(pkt)));
    break;
  }
}


void ci_netif_pkt_list_dump(ci_netif* ni, oo_pkt_p head, int is_recv, int dump)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pkt_id;

  for( pkt_id = head; OO_PP_NOT_NULL(pkt_id); pkt_id = pkt->next ) {
    if( ! IS_VALID_PKT_ID(ni, pkt_id) ) {
      log("  invalid pkt_id=%d", OO_PP_FMT(pkt_id));
      break;
    }

    pkt = PKT(ni, pkt_id);
    ci_netif_pkt_dump(ni, pkt, is_recv, dump);
  }
}


void ci_netif_pkt_queue_dump(ci_netif* ni, ci_ip_pkt_queue* q,
			     int is_recv, int dump)
{
  log("%s: head=%d tail=%d n=%d", __FUNCTION__,
      OO_PP_FMT(q->head), OO_PP_FMT(q->tail), q->num);
  ci_netif_pkt_list_dump(ni, q->head, is_recv, dump);
}


void ci_netif_dump_dmaq(ci_netif* ni, int dump)
{
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
    log("%s: head=%d tail=%d num=%d", __FUNCTION__,
        OO_PP_FMT(nic->dmaq.head), OO_PP_FMT(nic->dmaq.tail), nic->dmaq.num);
    /* Following is bogus, as dmaq uses a different "next" field. */
    /*ci_netif_pkt_list_dump(ni, ni->state->nic[intf_i].dmaq.head, 0, dump);*/
  }
}


void ci_netif_dump_timeoutq(ci_netif* ni)
{
  ci_netif_state* nis = ni->state;
  ci_tcp_state * ts;
  oo_p a;
  int i;

  if( ci_ip_timer_pending(ni, &nis->timeout_tid) ) {
    int diff = nis->timeout_tid.time - ci_tcp_time_now(ni);
    log("timeout due in %umS",
          ci_ip_time_ticks2ms(ni, diff));
  }
  for( i = 0; i < OO_TIMEOUT_Q_MAX; i++ ) {
    if( i == OO_TIMEOUT_Q_TIMEWAIT )
      log("TIME-WAIT queue");
    else
      log("FIN-WAIT queue");
    for( a = nis->timeout_q[i].l.next;
         ! OO_P_EQ(a, ci_ni_dllist_link_addr(ni, &nis->timeout_q[i].l)); ) {
      ts = TCP_STATE_FROM_LINK((ci_ni_dllist_link*) CI_NETIF_PTR(ni, a));
      if( i == OO_TIMEOUT_Q_TIMEWAIT )
        log("   %d: t=0x%08x", S_FMT(ts), ts->t_last_sent);
      else
        log("   %d: t=0x%08x %s", S_FMT(ts), ts->t_last_sent, state_str(ts));
      a = ts->timeout_q_link.next;
    }
  }
}


void ci_netif_dump_reap_list(ci_netif* ni, int verbose)
{
  ci_ni_dllist_link* lnk;
  ci_sock_cmn* s;

  ci_log("%s: stack=%d", __FUNCTION__, NI_ID(ni));
  for( lnk = ci_ni_dllist_start(ni, &ni->state->reap_list);
       lnk != ci_ni_dllist_end(ni, &ni->state->reap_list);
       lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next) ) {
    s = CI_CONTAINER(ci_sock_cmn, reap_link, lnk);
    if( verbose )
      citp_waitable_dump(ni, &s->b, "");
    else
      ci_log("  "NS_FMT, NS_PRI_ARGS(ni, s));
  }
}


void ci_netif_dump_extra(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  char hp2i[CPLANE_MAX_REGISTER_INTERFACES * 10];
  char i2hp[CI_CFG_MAX_INTERFACES * 10];
  int i, off;

  for( i = 0, off = 0; i < CPLANE_MAX_REGISTER_INTERFACES; ++i )
    off += sprintf(hp2i+off, "%s%d", i?",":"", (int) ns->hwport_to_intf_i[i]);
  for( i = 0, off = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    off += sprintf(i2hp+off, "%s%d", i?",":"", (int) ns->intf_i_to_hwport[i]);

  log("%s: stack=%d", __FUNCTION__, NI_ID(ni));
  log("  in_poll=%d post_poll_list_empty=%d poll_did_wake=%d",
      ns->in_poll, ci_ni_dllist_is_empty(ni, &ns->post_poll_list),
      ns->poll_did_wake);
  log("  rx_defrag_head=%d rx_defrag_tail=%d",
      OO_PP_FMT(ns->rx_defrag_head), OO_PP_FMT(ns->rx_defrag_tail));
  log("  tx_may_alloc=%d can=%d nonb_pool=%d send_may_poll=%d is_spinner=%d,%d",
      ci_netif_pkt_tx_may_alloc(ni), ci_netif_pkt_tx_can_alloc_now(ni),
      ci_netif_pkt_nonb_pool_not_empty(ni), ns->send_may_poll,
      (int) ns->is_spinner, ns->n_spinners);
  log("  hwport_to_intf_i=%s intf_i_to_hwport=%s", hp2i, i2hp);
  log("  uk_intf_ver=%s", OO_UK_INTF_VER);
  log("  deferred count %d/%d", ns->defer_work_count, NI_OPTS(ni).defer_work_limit);
  log("  numa nodes: creation=%d load=%d",
      ns->creation_numa_node, ns->load_numa_node);
  log("  numa node masks: packet alloc=%x sock alloc=%x interrupt=%x",
      ns->packet_alloc_numa_nodes, ns->sock_alloc_numa_nodes,
      ns->interrupt_numa_nodes);
}


static void ci_netif_dump_vi(ci_netif* ni, int intf_i, oo_dump_log_fn_t logger,
                             void* log_arg)
{
  ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
  ef_vi* vi = &ni->nic_hw[intf_i].vi;

  if( intf_i < 0 || intf_i >= CI_CFG_MAX_INTERFACES ||
      ! efrm_nic_set_read(&ni->nic_set, intf_i) ) {
    logger(log_arg, "%s: stack=%d intf=%d ***BAD***",
           __FUNCTION__, NI_ID(ni), intf_i);
    return;
  }

  logger(log_arg, "%s: stack=%d intf=%d dev=%s hw=%d%c%d", __FUNCTION__,
         NI_ID(ni), intf_i, nic->pci_dev, (int) nic->vi_arch,
         nic->vi_variant, (int) nic->vi_revision);
  logger(log_arg, "  vi=%d pd_owner=%d channel=%d%s oo_vi_flags=%x",
         ef_vi_instance(vi), nic->pd_owner, (int) nic->vi_channel,
         ni->state->dump_intf[intf_i] ? " tcpdump" : "",
         nic->oo_vi_flags);
  logger(log_arg, "  evq: cap=%d current=%x is_32_evs=%d is_ev=%d",
         ef_eventq_capacity(vi), (unsigned) ef_eventq_current(vi),
         ef_eventq_has_many_events(vi, 32), ef_eventq_has_event(vi));
  logger(log_arg, "  rxq: cap=%d lim=%d spc=%d level=%d total_desc=%d",
         ef_vi_receive_capacity(vi), ni->state->rxq_limit,
         ci_netif_rx_vi_space(ni, vi), ef_vi_receive_fill_level(vi),
         vi->ep_state->rxq.removed);
  logger(log_arg, "  txq: cap=%d lim=%d spc=%d level=%d pkts=%d oflow_pkts=%d",
         ef_vi_transmit_capacity(vi), ef_vi_transmit_capacity(vi),
         ef_vi_transmit_space(vi), ef_vi_transmit_fill_level(vi),
         nic->tx_dmaq_insert_seq - nic->tx_dmaq_done_seq - nic->dmaq.num,
         nic->dmaq.num);
  logger(log_arg, "  txq: pio_buf_size=%d tot_pkts=%d bytes=%d",
#if CI_CFG_PIO
         nic->pio_io_len, 
#else
         0,
#endif
         nic->tx_dmaq_done_seq, nic->tx_bytes_added - nic->tx_bytes_removed);
  logger(log_arg, "  clk: %s%s",
         (nic->last_sync_flags & EF_VI_SYNC_FLAG_CLOCK_SET) ? "SET " : "",
         (nic->last_sync_flags & EF_VI_SYNC_FLAG_CLOCK_IN_SYNC) ? "SYNC" : "");
  if( nic->nic_error_flags )
    logger(log_arg, "  ERRORS: "CI_NETIF_NIC_ERRORS_FMT,
           CI_NETIF_NIC_ERRORS_PRI_ARG(nic->nic_error_flags));

#ifndef __KERNEL__
#if CI_CFG_SEPARATE_UDP_RXQ
  if( NI_OPTS(ni).separate_udp_rxq ) {
    vi = &ni->nic_hw[intf_i].udp_rxq_vi;
    logger(log_arg, "  vi=%d", ef_vi_instance(vi));
    logger(log_arg, "  evq: cap=%d current=%x is_32_evs=%d is_ev=%d",
           ef_eventq_capacity(vi), (unsigned) ef_eventq_current(vi),
           ef_eventq_has_many_events(vi, 32), ef_eventq_has_event(vi));
    logger(log_arg, "  rxq: cap=%d lim=%d spc=%d level=%d total_desc=%d",
           ef_vi_receive_capacity(vi), ni->state->rxq_limit,
           ci_netif_rx_vi_space(ni, vi), ef_vi_receive_fill_level(vi),
           vi->ep_state->rxq.removed);
  }
#endif
#endif
}

void ci_netif_dump(ci_netif* ni)
{
  ci_netif_dump_to_logger(ni, ci_log_dump_fn, NULL);
}

void ci_netif_dump_to_logger(ci_netif* ni, oo_dump_log_fn_t logger,
                             void* log_arg)
{
  ci_netif_state* ns = ni->state;
#ifdef __KERNEL__
  /* This is too large for the stack in the kernel */
  static ci_ip_timer_state its;
#else
  ci_ip_timer_state its;
#endif
  ci_uint64 tmp;
  long diff;
  int intf_i;

  logger(log_arg, "%s: stack=%d name=%s", __FUNCTION__, NI_ID(ni),
         ni->state->name);
  logger(log_arg, "  ver=%s uid=%d pid=%d ns_flags=%x %s %s", ONLOAD_VERSION
      , (int) ns->uid, (int) ns->pid
      , ns->flags
      , (ns->flags & CI_NETIF_FLAG_ONLOAD_UNSUPPORTED)
          ? "ONLOAD_UNSUPPORTED" : ""
#if CI_CFG_FD_CACHING
      , (ns->flags & CI_NETIF_FLAG_SOCKCACHE_FORKED)
          ? "SOCKCACHE_FORKED" : ""
#else
      , ""
#endif
      );

  tmp = ni->state->lock.lock;
  logger(log_arg, "  lock=%llx "CI_NETIF_LOCK_FMT"  nics=%x primed=%x",
         (unsigned long long)tmp,
         CI_NETIF_LOCK_PRI_ARG(tmp), ni->nic_set.nics, ns->evq_primed);
#ifdef __KERNEL__
  {
    /* This is useful mostly for orphaned stacks */
    tcp_helper_resource_t* trs = netif2tcp_helper_resource(ni);
    logger(log_arg, "  ref=%d trusted_lock=0x%x k_ref=0x%x "
           "n_ep_closing=%d",
           oo_atomic_read(&trs->ref_count),
           trs->trusted_lock, trs->k_ref_count, trs->n_ep_closing_refs);
  }
#endif

  logger(log_arg, "  sock_bufs: max=%u n_allocated=%u",
         NI_OPTS(ni).max_ep_bufs, ns->n_ep_bufs);
  /* aux buffers number is limited by tcp_synrecv_max*2 */
  logger(log_arg, "  aux_bufs: max=%u allocated=%u free=%u",
         NI_OPTS(ni).tcp_synrecv_max * 2, ni->state->n_aux_bufs,
         ns->n_free_aux_bufs);
  ci_netif_dump_pkt_summary(ni, logger, log_arg);


  its = *IPTIMER_STATE(ni);
  ci_ip_time_resync(&its);
  diff = its.ci_ip_time_real_ticks - ci_ip_time_now(ni);
  diff = ci_ip_time_ticks2ms(ni, diff);

  logger(log_arg, "  time: netif=%x poll=%x now=%x (diff=%ld.%03ldsec)%s",
         (unsigned) ci_ip_time_now(ni),
         (unsigned) IPTIMER_STATE(ni)->sched_ticks,
         (unsigned) its.ci_ip_time_real_ticks, diff / 1000, diff % 1000,
         diff > 5000 ? " !! STUCK !!":"");

  if( ns->error_flags )
    logger(log_arg, "  ERRORS: "CI_NETIF_ERRORS_FMT,
           CI_NETIF_ERRORS_PRI_ARG(ns->error_flags));
  if( ni->state->dump_write_i != ni->state->dump_read_i )
    logger(log_arg, "  tcpdump: %d/%d packets in queue",
           (ci_uint8)(ni->state->dump_write_i - ni->state->dump_read_i),
           CI_CFG_DUMPQUEUE_LEN);

#if CI_CFG_FD_CACHING
  logger(log_arg, "  active cache: hit=%d avail=%d cache=%s pending=%s",
         ns->stats.activecache_hit,
         *(ci_uint32*)CI_NETIF_PTR(ni, ns->active_cache.avail_stack), 
         ci_ni_dllist_is_empty(ni, &ns->active_cache.cache) ? "EMPTY":"yes",
         ci_ni_dllist_is_empty(ni, &ns->active_cache.pending) ? "EMPTY":"yes");

#endif

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_netif_dump_vi(ni, intf_i, logger, log_arg);
}
#endif /* __KERNEL__ */


int ci_netif_bad_hwport(ci_netif* ni, ci_hwport_id_t hwport)
{
  /* Called by ci_hwport_to_intf_i() when it detects a bad [hwport]. */
  static int once;
  if( ! once ) {
    once = 1;
    ci_log(FN_FMT "ERROR: bad hwport=%d", FN_PRI_ARGS(ni), (int) hwport);
    ci_backtrace();
  }
  return 0;  /* we *must* return a valid [intf_i] */
}

/*! \cidoxg_end */
