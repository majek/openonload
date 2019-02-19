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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP metrics
**   \date  2018/06/07
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"


#if CI_CFG_TCP_METRICS


static inline int oo_metrics_export_enabled(ci_netif* ni)
{
  return ni->state->metrics_ring.export_enabled;
}


static int ci_tcp_metrics_record_put(ci_netif* ni, ci_tcp_state* ts,
                                     const struct oo_metrics_record* rec)
{
  struct oo_metrics_ring* mr = &ni->state->metrics_ring;
  ci_uint16 w_i = mr->metrics_write_i;
  ci_uint16 fill_level = w_i - mr->metrics_read_i;
  if( fill_level < CI_CFG_METRICS_RING_SIZE - 1 &&
      (ts->metrics.flags & TSM_F_EXPORT) ) {
    mr->entries[w_i % CI_CFG_METRICS_RING_SIZE] = *rec;
    ci_wmb();
    mr->metrics_write_i = w_i + 1;
    return 1;
  }
  else {
    ++(mr->drops);
    ts->metrics.flags &=~ TSM_F_EXPORT;
    return 0;
  }
}


void ci_tcp_metrics_init(ci_tcp_state* ts)
{
  ts->metrics.state = TSM_S_INITED;
  ts->metrics.flags = 0;
  ts->metrics.tx_time = 0;
  ts->metrics.rx_time = 0;
  ts->metrics.idle_time = 0;
  ts->metrics.app_time = 0;
  ts->metrics.retrans_adjust = 0;
}


static void ci_tcp_metrics_on_req(ci_netif* ni, ci_tcp_state* ts,
                                  oo_metrics_tstamp now)
{
  if( oo_metrics_export_enabled(ni) ) {
    struct oo_metrics_record rec;
    rec.type = MRT_TCP_REQ;
    rec.tcp_req.conn_id = ts->metrics.conn_id;
    rec.tcp_req.rx_bytes = ts->rcv_added - ts->stats.rx_isn;
    rec.tcp_req.tx_bytes = tcp_snd_nxt(ts) - ts->metrics.tx_isn;
    rec.tcp_req.app_time = ts->metrics.app_time;
    rec.tcp_req.tx_time = ts->metrics.tx_time;
    rec.tcp_req.idle_time = ts->metrics.idle_time;
    rec.tcp_req.rx_time = ts->metrics.rx_time;
    rec.tcp_req.retransmits =
      ts->stats.total_retrans - ts->metrics.retrans_adjust;
    ci_tcp_metrics_record_put(ni, ts, &rec);
  }
}


static void ci_tcp_metrics_open(ci_netif* ni, ci_tcp_state* ts,
                                int active_open, ci_uint64 frc_now,
                                oo_metrics_intvl open_time,
                                unsigned open_retries)
{
  if( oo_metrics_export_enabled(ni) ) {
    struct oo_metrics_record rec;
    ts->metrics.flags |= TSM_F_EXPORT;
    rec.type = MRT_TCP_OPEN;
    rec.tcp_open.open_frc = frc_now - oo_metrics_intvl2frc(ni, open_time);
    rec.tcp_open.conn_id = ts->metrics.conn_id;
    rec.tcp_open.ep_id = S_ID(ts);
    rec.tcp_open.lcl_ip = tcp_laddr_be32(ts);
    rec.tcp_open.rmt_ip = tcp_raddr_be32(ts);
    rec.tcp_open.lcl_port = tcp_lport_be16(ts);
    rec.tcp_open.rmt_port = tcp_rport_be16(ts);
    rec.tcp_open.open_time = open_time;
    rec.tcp_open.active_open = active_open;
    rec.tcp_open.open_retries = open_retries;
    ci_tcp_metrics_record_put(ni, ts, &rec);
  }
}


static void ci_tcp_metrics_on_close(ci_netif* ni, ci_tcp_state* ts,
                                    oo_metrics_tstamp now)
{
  switch( ts->metrics.state ) {
  case TSM_S_RX:
    ts->metrics.rx_time += ts->metrics.ts_last - ts->metrics.ts_enter;
    if( ts->metrics.flags & TSM_F_CLIENT )
      ci_tcp_metrics_on_req(ni, ts, now);
    break;
  case TSM_S_TX:
    ts->metrics.tx_time += ts->metrics.ts_last - ts->metrics.ts_enter;
    if( ! (ts->metrics.flags & TSM_F_CLIENT) )
      ci_tcp_metrics_on_req(ni, ts, now);
    break;
  }

  ts->metrics.state = TSM_S_DONE;
}


void ci_tcp_metrics_on_state(ci_netif* ni, ci_tcp_state* ts, int new_state)
{
  oo_metrics_tstamp now;
  ci_uint64 frc_now;

  if( ts->metrics.state == TSM_S_DONE )
    return;

  frc_now = ci_frc64_get();
  now = oo_metrics_frc2tstamp(ni, frc_now);

  switch( new_state ) {
  case CI_TCP_SYN_SENT:
    ts->metrics.ts_last = now;
    break;
  case CI_TCP_ESTABLISHED:
    ts->metrics.conn_id = ni->state->metrics.conn_id_gen++;
    ts->metrics.tx_isn = tcp_snd_nxt(ts);
    if( ts->s.b.state == CI_TCP_SYN_SENT ) {
      oo_metrics_intvl open_time = now - ts->metrics.ts_last;
      unsigned retries = ts->stats.total_retrans;
      ci_tcp_metrics_open(ni, ts, 1/*active*/, frc_now, open_time, retries);
      ts->metrics.ts_last = now;
      ts->metrics.retrans_adjust = retries;
    }
    break;

  case CI_TCP_CLOSING:
  case CI_TCP_TIME_WAIT:
    /* Clean -- we closed first. */
    ci_tcp_metrics_on_close(ni, ts, now);
    break;
  case CI_TCP_LAST_ACK:
    /* Clean -- peer closed first. */
    ci_tcp_metrics_on_close(ni, ts, now);
    break;
  case CI_TCP_CLOSED:
    /* Aborted -- don't record metrics of transaction in progress. */
    ts->metrics.flags |= TSM_F_ABORTED;
    ts->metrics.state = TSM_S_DONE;
    break;
  }
}


void ci_tcp_metrics_on_promote(ci_netif* ni, ci_tcp_state* ts,
                               const ci_tcp_state_synrecv* tsr)
{
  /* NB. ts->metrics.conn_id is set via ci_tcp_metrics_on_state(). */
  ci_uint64 frc_now = IPTIMER_STATE(ni)->frc;
  oo_metrics_tstamp now = oo_metrics_frc2tstamp(ni, frc_now);
  oo_metrics_intvl open_time = now - tsr->tstamp;
  unsigned retries = tsr->retries & CI_FLAG_TSR_RETRIES_MASK;
  ci_tcp_metrics_open(ni, ts, 0/*passive*/, frc_now, open_time, retries);
  ts->metrics.ts_last = now;
}


void ci_tcp_metrics_on_rx(ci_netif* ni, ci_tcp_state* ts)
{
  oo_metrics_tstamp now = oo_metrics_stack_now(ni);

  switch( ts->metrics.state ) {
  case TSM_S_INITED:
    ts->metrics.idle_time += now - ts->metrics.ts_last;
    ts->metrics.ts_enter = now;
    ts->metrics.state = TSM_S_RX;
    break;
  case TSM_S_RX:
    break;
  case TSM_S_TX:
    ts->metrics.tx_time += ts->metrics.ts_last - ts->metrics.ts_enter;
    if( ! (ts->metrics.flags & TSM_F_CLIENT) )
      ci_tcp_metrics_on_req(ni, ts, now);
    ts->metrics.idle_time += now - ts->metrics.ts_last;
    ts->metrics.ts_enter = now;
    ts->metrics.state = TSM_S_RX;
    break;
  }

  ts->metrics.ts_last = now;
}


void ci_tcp_metrics_on_tx(ci_netif* ni, ci_tcp_state* ts)
{
  /* Called from start of ci_tcp_tx_advance().  So tcp_enq_nxt has already
   * advanced somewhat, but tcp_snd_nxt has not.
   */
  oo_metrics_tstamp now = oo_metrics_now(ni);

  if( ts->s.b.state == CI_TCP_SYN_SENT )
    return;
  if( tcp_rcv_usr(ts) )
    ts->metrics.flags |= TSM_F_PIPELINED;

  switch( ts->metrics.state ) {
  case TSM_S_INITED:
    ts->metrics.flags |= TSM_F_CLIENT;
    ts->metrics.app_time += now - ts->metrics.ts_last;
    ts->metrics.ts_enter = now;
    ts->metrics.state = TSM_S_TX;
    break;
  case TSM_S_RX:
    ts->metrics.rx_time += ts->metrics.ts_last - ts->metrics.ts_enter;
    if( ts->metrics.flags & TSM_F_CLIENT )
      ci_tcp_metrics_on_req(ni, ts, now);
    ts->metrics.app_time += now - ts->metrics.ts_last;
    ts->metrics.ts_enter = now;
    ts->metrics.state = TSM_S_TX;
    break;
  case TSM_S_TX:
    break;
  }

  ts->metrics.ts_last = now;
}

#endif
