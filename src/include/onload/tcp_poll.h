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

#ifndef __ONLOAD_TCP_POLL_H__
#define __ONLOAD_TCP_POLL_H__


/* Find events to return by poll() for a given TCP socket. 
 * These functions do not wait for events, but just report them. 
 *
 * ATTENTION! These functions should be kept is sync with
 * citp_tcp_select().  (Or better still, citp_tcp_select() should use
 * these).
 */

/* This function should be used for listening sockets only. */
ci_inline short
ci_tcp_poll_events_listen(ci_netif *ni, ci_tcp_socket_listen *tls)
{
  if( ci_tcp_acceptq_n(tls) || (tls->s.os_sock_status & OO_OS_STATUS_RX) )
    return  POLLIN | POLLRDNORM;
  return 0;
}

/* This function should not be used for listening sockets.
 * Once upon a time, this function simulated both Linux and Solaris.
 * Linux behaviour changed in 2.6.32, and this function was reworked.
 * See history for Solaris behaviour if you need it. */
ci_inline short
ci_tcp_poll_events_nolisten(ci_netif *ni, ci_tcp_state *ts)
{
  short revents = 0;

  ci_assert_nequal(ts->s.b.state, CI_TCP_LISTEN);

  /* Shutdown: */
  if( !(ts->s.b.state & CI_TCP_STATE_CAN_FIN) &&
      !(ts->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT) )
    revents |= POLLOUT; /* SHUT_WR && !NONBLOCK_CONNECT */
  if( (TCP_RX_DONE(ts) & CI_SHUT_RD) )
    revents |= POLLIN; /* SHUT_RD */
  if( !(ts->s.b.state & CI_TCP_STATE_CAN_FIN) && TCP_RX_DONE(ts) )
    revents |= POLLHUP; /* SHUT_RDWR */
  /* Errors */
  if( ts->s.so_error )
    revents |= POLLERR;

  /* synchronised: !CLOSED !SYN_SENT */
  if( ts->s.b.state & CI_TCP_STATE_SYNCHRONISED ) {
    /* normal send: */
    if( (ts->s.b.state & CI_TCP_STATE_CAN_FIN) && 
        ci_tcp_tx_advertise_space(ts) )
      revents |= POLLOUT | POLLWRNORM;

    /* urg */
    if( tcp_urg_data(ts) & CI_TCP_URG_IS_HERE )
      revents |= POLLPRI;

    /* normal recv or nothing to recv forever */
    if( (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ||
        ci_tcp_recv_not_blocked(ts) )
      revents |= POLLIN | POLLRDNORM;

  }
  else if( ts->s.b.state == CI_TCP_SYN_SENT )
    revents = 0;

  return revents;
}


ci_inline unsigned
ci_udp_poll_events(ci_netif* ni, ci_udp_state* us)
{
  unsigned events = 0;

  /* TX errno set by shutdown(SHUT_WR) must not set POLLERR. */
  if( us->s.so_error || UDP_RX_ERRNO(us) ||
      (UDP_TX_ERRNO(us) && ! UDP_IS_SHUT_WR(us)) )
    events |= POLLERR;

  if( UDP_IS_SHUT_RDWR(us) )
    events |= POLLHUP | POLLIN;

  if( UDP_RX_DONE(us) | ci_udp_recv_q_not_empty(us) )
    events |= POLLIN | POLLRDNORM;

  if( us->s.os_sock_status & OO_OS_STATUS_RX )
    events |= POLLIN | POLLRDNORM;

  if( ci_udp_tx_advertise_space(us) &&
      (us->s.os_sock_status & OO_OS_STATUS_TX) )
    events |= POLLOUT | POLLWRNORM | POLLWRBAND;

  return events;
}

#if CI_CFG_USERSPACE_PIPE
#include <onload/oo_pipe.h>

ci_inline unsigned
oo_pipe_poll_read_events(struct oo_pipe* p)
{
  unsigned events = 0;

  if( oo_pipe_data_len(p) )
    events |= POLLIN | POLLRDNORM;
  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
    events |= POLLHUP;

  return events;
}

ci_inline unsigned
oo_pipe_poll_write_events(struct oo_pipe* p)
{
  unsigned events = 0;

  if( oo_pipe_is_writable(p) )
    events |= POLLOUT | POLLWRNORM | POLLWRBAND;
  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) )
    events |= POLLERR;

  return events;
}
#endif


#endif  /* __ONLOAD_TCP_POLL_H__ */
