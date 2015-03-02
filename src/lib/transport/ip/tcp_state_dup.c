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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  duplicate a CLOSED TCP state
**   \date  2004/11/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"


#define LPF "TCP STATE DUP "

#define __COPY_FLD(tsd,tss,Fld) (tsd)->Fld=(tss)->Fld

/* Create a new tcp state in the context of [netif_out] and then
 * copy the important fields, to the newly created tcp state struct 
 *
 * Will only duplicate states in CLOSED state 
 *      i.e. with no filters, buffers....
 */
int ci_tcp_move_state(ci_netif* netif_in, ci_tcp_state* ts_in, 
                      ef_driver_handle fd, 
		      ci_netif* netif_out, ci_tcp_state** ts_out )
{
  ci_tcp_state* ts;
  int rc;

  ci_assert(netif_in);
  ci_assert(ts_in);
  ci_assert(netif_out);
  ci_assert(ts_out);

  ci_assert(ts_in->s.b.state == CI_TCP_CLOSED);

  /* Assumes nothing to do for:
   *  SACK
   *  Filters
   */

  /* Get a new tcp state struct */
  ts = ci_tcp_get_state_buf(netif_out);
  if( ts == NULL ) {
    LOG_E(ci_log("%s: [%d] out of socket buffers",
                 __FUNCTION__, NI_ID(netif_out)));
    return -ENOMEM;
  }

  ci_assert(IS_VALID_SOCK_P(netif_out, S_SP(ts)));
  ci_assert(ts->s.b.state == CI_TCP_CLOSED);

  /* ts.c.*
   * Common options/flags (state is already as we want it) */
  __COPY_FLD(ts, ts_in, tcpflags);

  /*  ts.st_opts.* - none  */
  /*  ts.udp_state.* - none */
  /*  ts.errq.* - none */

  /* tcp addressing (bind) */
  tcp_protocol(ts)   = tcp_protocol(ts_in);
  tcp_laddr_be32(ts) = tcp_laddr_be32(ts_in);
  tcp_lport_be16(ts) = tcp_lport_be16(ts_in);
  tcp_raddr_be32(ts) = tcp_raddr_be32(ts_in);
  tcp_rport_be16(ts) = tcp_rport_be16(ts_in);
  ts->s.domain = ts_in->s.domain;

  /* Fields that could have been set through a sockopt */
  ts->eff_mss = tcp_eff_mss(ts_in);
  ts->s.so = ts_in->s.so;
  /* We should copy all s_flags, including CI_SOCK_FLAG_BOUND */
  ts->s.s_flags = ts_in->s.s_flags;
  ts->s.s_aflags = ts_in->s.s_aflags;

  ts->s.pkt.ip.ip_tos = ts_in->s.pkt.ip.ip_tos;
  ts->s.pkt.ip.ip_ttl = ts_in->s.pkt.ip.ip_ttl;
  /* Linux specific (TCP), although should not hurt other OS's */
  ts->s.cmsg_flags = ts_in->s.cmsg_flags;

  ts->c.t_ka_time = ts_in->c.t_ka_time; /* TCP_KEEPIDLE */
  ts->c.t_ka_time_in_secs = ts_in->c.t_ka_time_in_secs;
  ts->c.t_ka_intvl = ts_in->c.t_ka_intvl; /* TCP_KEEPINTVL */
  ts->c.t_ka_intvl_in_secs = ts_in->c.t_ka_intvl_in_secs;
  ts->c.ka_probe_th = ts_in->c.ka_probe_th; /* TCP_KEEPCNT */


  /* OS socket */
  __COPY_FLD(ts, ts_in, s.ino);
  __COPY_FLD(ts, ts_in, s.uid);
  CI_DEBUG(__COPY_FLD(ts, ts_in, s.pid));

  rc = ci_tcp_helper_move_state(netif_in, fd, S_SP(ts_in), netif_out,S_SP(ts));
  *ts_out = ts;
  return rc;
}



/*! \cidoxg_end */
