/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/*
 * \author  djr
 *  \brief  Routine to poll event queues.
 *   \date  2003/03/04
 */

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"

typedef ci_qword_t ef_vi_event;

#define EF_VI_EVENT_OFFSET(q, i)                                \
  (((q)->ep_state->evq.evq_ptr + (i) * sizeof(ef_vi_event)) &	\
   (q)->evq_mask)

#define EF_VI_EVENT_PTR(q, i)                                           \
  ((ef_vi_event*) ((q)->evq_base + EF_VI_EVENT_OFFSET((q), (i))))

/* Test for presence of event must ensure that both halves have changed
 * from the null.
 */
#define EF_VI_IS_EVENT(evp)                     \
  (!(CI_DWORD_IS_ALL_ONES((evp)->dword[0]) |    \
     CI_DWORD_IS_ALL_ONES((evp)->dword[1])))


#define INC_ERROR_STAT(vi, name)		\
  do {                                          \
    if ((vi)->vi_stats != NULL)                 \
      ++(vi)->vi_stats->name;                   \
  } while (0)


ef_vi_inline void falcon_rx_desc_consumed(ef_vi* vi, const ef_vi_event* ev,
					  ef_event** evs, int* evs_len,
					  int q_label, int desc_i)
{
  ef_event* ev_out = (*evs)++;
  ci_qword_t interesting_errors;
  --(*evs_len);
  ev_out->rx.q_id = q_label;
  ev_out->rx.rq_id = vi->vi_rxq.ids[desc_i];
  vi->vi_rxq.ids[desc_i] = EF_REQUEST_ID_MASK;  /* ?? killme */
  ++vi->ep_state->rxq.removed;
  if( QWORD_TEST_BIT(RX_SOP, *ev) )
    ev_out->rx.flags = EF_EVENT_FLAG_SOP;
  else
    ev_out->rx.flags = 0;
  if( QWORD_TEST_BIT(RX_JUMBO_CONT, *ev) )
    ev_out->rx.flags |= EF_EVENT_FLAG_CONT;

  interesting_errors.u64[0] = ev->u64[0] & vi->rx_discard_mask;

  /* Don't discard if packet ok or discard mask indicates
   * error type should not generate discard event.
   * Multicast mismatch always generates discard.
   */
  if(likely( QWORD_TEST_BIT(RX_EV_PKT_OK, *ev) )
    || ( ! interesting_errors.u64[0] )) {
  dont_discard:
    ev_out->rx.len = QWORD_GET_U(RX_EV_BYTE_CNT, *ev);
    ev_out->rx.type = EF_EVENT_TYPE_RX;
    if( QWORD_TEST_BIT(RX_iSCSI_PKT_OK, *ev) )
      ev_out->rx.flags |= EF_EVENT_FLAG_ISCSI_OK;
    if( QWORD_TEST_BIT(RX_EV_MCAST_PKT, *ev) ) {
      int match = QWORD_TEST_BIT(RX_EV_MCAST_HASH_MATCH,*ev);
      ev_out->rx.flags |= EF_EVENT_FLAG_MULTICAST;
      if(unlikely( ! match ))
        goto discard;
    }
  }
  else {
  discard:
    ev_out->rx_discard.len = QWORD_GET_U(RX_EV_BYTE_CNT, *ev);
    ev_out->rx_discard.type = EF_EVENT_TYPE_RX_DISCARD;
    /* Order matters here: more fundamental errors first. */
    if( QWORD_TEST_BIT(RX_EV_BUF_OWNER_ID_ERR, interesting_errors) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_RIGHTS;
    else if( QWORD_TEST_BIT(RX_EV_FRM_TRUNC, interesting_errors) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_TRUNC;
    else if( QWORD_TEST_BIT(RX_EV_ETH_CRC_ERR, interesting_errors) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_CRC_BAD;
    else if( QWORD_TEST_BIT(RX_EV_MCAST_PKT, *ev) &&
             ! QWORD_TEST_BIT(RX_EV_MCAST_HASH_MATCH,*ev) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_MCAST_MISMATCH;
    else if( QWORD_TEST_BIT(RX_EV_IP_HDR_CHKSUM_ERR, interesting_errors ) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_CSUM_BAD;
    else if( QWORD_TEST_BIT(RX_EV_TCP_UDP_CHKSUM_ERR, interesting_errors) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_CSUM_BAD;
    else if( QWORD_TEST_BIT(RX_EV_TOBE_DISC, interesting_errors) )
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_OTHER;
    else if( QWORD_TEST_BIT(RX_EV_IP_FRAG_ERR, *ev) )
      goto dont_discard;
    else
      ev_out->rx_discard.subtype =
        EF_EVENT_RX_DISCARD_OTHER;
  }
}


static void falcon_rx_no_desc_trunc(ef_event** evs, int* evs_len, int q_label)
{
  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->rx_no_desc_trunc.type = EF_EVENT_TYPE_RX_NO_DESC_TRUNC;
  ev_out->rx_no_desc_trunc.q_id = q_label;
}


static void falcon_rx_unexpected(ef_vi* vi, const ef_vi_event* ev,
				 ef_event** evs, int* evs_len,
				 int q_label, int desc_i)
{
  ef_event* ev_out;
  if (!((desc_i - 1 - vi->ep_state->rxq.removed) & vi->vi_rxq.mask)) {
    /* One ahead of expected: previous RX notification lost. */
    ev_out = (*evs)++;
    --(*evs_len);
    desc_i = (desc_i - 1) & vi->vi_rxq.mask;
    ev_out->rx_discard.type = EF_EVENT_TYPE_RX_DISCARD;
    ev_out->rx_discard.subtype = EF_EVENT_RX_DISCARD_EV_ERROR;
    ev_out->rx_discard.q_id = q_label;
    ev_out->rx_discard.rq_id = vi->vi_rxq.ids[desc_i];
    ev_out->rx_discard.len = 0;
    vi->vi_rxq.ids[desc_i] = EF_REQUEST_ID_MASK;/* ?? killme */
    ++vi->ep_state->rxq.removed;
    INC_ERROR_STAT(vi, rx_ev_lost);
    desc_i = (desc_i + 1) & vi->vi_rxq.mask;
    /* Handle the current event. */
    falcon_rx_desc_consumed(vi, ev, evs, evs_len, q_label, desc_i);
  } else {
    /* Misdirected? */
    INC_ERROR_STAT(vi, rx_ev_bad_desc_i);
  }
}


ef_vi_inline void falcon_rx_event(ef_vi* evq_vi, const ef_vi_event* ev,
				  ef_event** evs, int* evs_len)
{
  unsigned q_label = QWORD_GET_U(RX_EV_Q_LABEL, *ev);
  unsigned desc_i, q_mask;
  ef_vi *vi;

  vi = evq_vi->vi_qs[q_label];
  if (likely(vi != NULL)) {
    q_mask = vi->vi_rxq.mask;
    desc_i = q_mask & CI_QWORD_FIELD(*ev, RX_EV_DESC_PTR);
    if (likely(desc_i == (vi->ep_state->rxq.removed & q_mask)))
      falcon_rx_desc_consumed(vi, ev, evs, evs_len,
                              q_label, desc_i);
    else if (!((desc_i + 1 - vi->ep_state->rxq.removed) & q_mask))
      falcon_rx_no_desc_trunc(evs, evs_len, q_label);
    else
      falcon_rx_unexpected(vi, ev, evs, evs_len,
                           q_label, desc_i);
  } else {
    INC_ERROR_STAT(evq_vi, rx_ev_bad_q_label);
  }
}


ef_vi_inline void falcon_tx_event(ef_event* ev_out, const ef_vi_event* ev)
{
  /* Danger danger!  No matter what we ask for wrt batching, we
  ** will get a batched event every 16 descriptors, and we also
  ** get dma-queue-empty events.  i.e. Duplicates are expected.
  **
  ** In addition, if it's been requested in the descriptor, we
  ** get an event per descriptor.  (We don't currently request
  ** this).
  */
  ev_out->tx.q_id = QWORD_GET_U(TX_EV_Q_LABEL, *ev);
  ev_out->tx.desc_id = QWORD_GET_U(TX_EV_DESC_PTR, *ev) + 1;
  if(likely( QWORD_TEST_BIT(TX_EV_COMP, *ev) )) {
    ev_out->tx.type = EF_EVENT_TYPE_TX;
  }
  else {
    ev_out->tx_error.type = EF_EVENT_TYPE_TX_ERROR;
    if(likely( QWORD_TEST_BIT(TX_EV_BUF_OWNER_ID_ERR, *ev) ))
      ev_out->tx_error.subtype = EF_EVENT_TX_ERROR_RIGHTS;
    else if(likely( QWORD_TEST_BIT(TX_EV_WQ_FF_FULL, *ev) ))
      ev_out->tx_error.subtype = EF_EVENT_TX_ERROR_OFLOW;
    else if(likely( QWORD_TEST_BIT(TX_EV_PKT_TOO_BIG, *ev) ))
      ev_out->tx_error.subtype = EF_EVENT_TX_ERROR_2BIG;
    else if(likely( QWORD_TEST_BIT(TX_EV_PKT_ERR, *ev) ))
      ev_out->tx_error.subtype = EF_EVENT_TX_ERROR_BUS;
  }
}


static void falcon_drv_gen_event(ef_vi* evq_vi, const ef_vi_event* ev,
                                 ef_event** evs, int* evs_len)
{
  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->sw.type = EF_EVENT_TYPE_SW;
  ev_out->sw.data = CI_DWORD_VAL(*ev);
}


int falcon_ef_eventq_poll(ef_vi* evq, ef_event* evs, int evs_len)
{
  int evs_len_orig = evs_len;
  ef_vi_event *pev, ev;

  EF_VI_BUG_ON(evs == NULL);
  EF_VI_BUG_ON(evs_len < EF_VI_EVENT_POLL_MIN_EVS);

  if(unlikely( EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq,
                                   evq->ep_state->evq.evq_clear_stride - 1)) ))
    goto overflow;

 not_empty:
  /* Read the event out of the ring, then fiddle with copied version.
   * Reason is that the ring is likely to get pushed out of cache by
   * another event being delivered by hardware.
   */
  pev = EF_VI_EVENT_PTR(evq, 0);
  ev = *pev;
  if (!EF_VI_IS_EVENT(&ev))
    goto empty;

  do {
    CI_SET_QWORD(*EF_VI_EVENT_PTR(evq, evq->ep_state->evq.evq_clear_stride));
    evq->ep_state->evq.evq_ptr += sizeof(ef_vi_event);

    /* Ugly: Exploit the fact that event code lies in top bits
     * of event. */
    EF_VI_BUG_ON(EV_CODE_LBN < 32u);
    switch( CI_QWORD_FIELD(ev, EV_CODE) ) {
    case RX_IP_EV_DECODE:
      falcon_rx_event(evq, &ev, &evs, &evs_len);
      break;

    case TX_IP_EV_DECODE:
      falcon_tx_event(evs, &ev);
      --evs_len;
      ++evs;
      break;

    case DRV_GEN_EV_DECODE:
      falcon_drv_gen_event(evq, &ev, &evs, &evs_len);
      break;

    default:
      break;
    }

    if (evs_len == 0)
      break;

    pev = EF_VI_EVENT_PTR(evq, 0);
    ev = *pev;
  } while (EF_VI_IS_EVENT(&ev));

  return evs_len_orig - evs_len;


 empty:
  if (EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq, 1))) {
    smp_rmb();
    if (!EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq, 0))) {
      /* No event in current slot, but there is one in
       * the next slot.  Has NIC failed to write event
       * somehow?
       */
      evq->ep_state->evq.evq_ptr += sizeof(ef_vi_event);
      INC_ERROR_STAT(evq, evq_gap);
      goto not_empty;
    }
  }
  return 0;

 overflow:
  evs->generic.type = EF_EVENT_TYPE_OFLOW;
  return 1;
}


int ef_eventq_has_event(const ef_vi* vi)
{
  EF_VI_ASSERT(vi->evq_base);
  return EF_VI_IS_EVENT(EF_VI_EVENT_PTR(vi, 0));
}


int ef_eventq_has_many_events(const ef_vi* vi, int look_ahead)
{
  EF_VI_BUG_ON(look_ahead < 0);
  return EF_VI_IS_EVENT(EF_VI_EVENT_PTR(vi, look_ahead));
}


void falcon_ef_eventq_prime(ef_vi* vi)
{
  unsigned ring_i = (ef_eventq_current(vi) & vi->evq_mask) / 8;
  void* io = vi->io + (FR_BZ_EVQ_RPTR_REGP0_OFST & (EF_VI_PAGE_SIZE-1));
  EF_VI_ASSERT(vi->inited & EF_VI_INITED_IO);
  writel(ring_i << FRF_AZ_EVQ_RPTR_LBN, io);
  mmiowb();
}


/*! \cidoxg_end */
