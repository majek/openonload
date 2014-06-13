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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Misc stuff for UDP sockets.
**   \date  2005/02/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"
#include "udp_internal.h"
#include <onload/osfile.h>

#define VERB(x)


void ci_udp_state_free(ci_netif* ni, ci_udp_state* us)
{
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(us->s.b.state == CI_TCP_STATE_UDP);
  ci_assert(ci_ni_dllist_is_self_linked(ni, &us->s.b.post_poll_link));

  ci_sock_cmn_timestamp_q_drop(ni, &us->s);

  citp_waitable_obj_free(ni, &us->s.b);
}


void ci_udp_try_to_free_pkts(ci_netif* ni, ci_udp_state* us, int desperation)
{
  switch( desperation ) {
  case 0:
    ci_udp_recv_q_reap(ni, &us->recv_q);
    break;
  default:
    break;
  }
}

void ci_udp_perform_deferred_socket_work(ci_netif* ni, ci_udp_state* us)
{
  ci_assert(us->s.b.state == CI_TCP_STATE_UDP);

  ci_udp_sendmsg_send_async_q(ni, us);
}

/*! \cidoxg_end */
