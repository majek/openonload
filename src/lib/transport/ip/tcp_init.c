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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Initialisation and assert checks for TCP state.
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"

#define LPF "TCP "

/* Called where some initialisation is needed, but not a full
 * construction. */
#ifndef __ci_driver__
ci_fd_t ci_tcp_ep_ctor(citp_socket* ep, ci_netif* netif, int domain, int type)
{
  ci_tcp_state* ts;
  ci_fd_t fd;

  ci_assert(ep);
  ci_assert(netif);

  ci_netif_lock(netif);
  ts = ci_tcp_get_state_buf(netif);
  if( ts == NULL ) {
    ci_netif_unlock(netif);
    LOG_E(ci_log("%s: [%d] out of socket buffers", __FUNCTION__,NI_ID(netif)));
    return -ENOMEM;
  }

  /*
   * It's required to set protocol before ci_tcp_helper_sock_attach()
   * since it's used to determine TCP or UDP file operations should be
   * attached to the file descriptor in kernel.
   */
  ts->s.pkt.ip.ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(ci_ip4_hdr));
  ts->s.pkt.ip.ip_protocol = IPPROTO_TCP;

  fd = ci_tcp_helper_sock_attach(ci_netif_get_driver_handle(netif), S_SP(ts),
                                 domain, type);
  if( fd < 0 ) {
    LOG_E(ci_log("%s: ci_tcp_helper_sock_attach %d", __FUNCTION__, fd));
    ci_tcp_state_free(netif, ts);
  }
  else {
    ci_assert(~ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
    /* Apply default sockbuf sizes now we've updated them from the kernel
    ** defaults. */
    ts->s.so.sndbuf = NI_OPTS(netif).tcp_sndbuf_def;
    ts->s.so.rcvbuf = NI_OPTS(netif).tcp_rcvbuf_def;
    ep->netif = netif;
    ep->s = &ts->s;
    CHECK_TEP(ep);
  }

  ci_netif_unlock(netif);
  return fd;
}
#endif

/*! \cidoxg_end */
