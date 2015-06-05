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

/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** * Redistributions of source code must retain the above copyright notice,
**   this list of conditions and the following disclaimer.
**
** * Redistributions in binary form must reproduce the above copyright
**   notice, this list of conditions and the following disclaimer in the
**   documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
** IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
** TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
** PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
** TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
** PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
** LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
** NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/* efdelegated_server
 *
 * Copyright 2009-2015 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2015/1/20
 *
 *
 * This is a sample application to demonstrate usage of the
 * onload_delegated_sends() API.  This API allows you to do sends via
 * ef_vi on an Onloaded TCP socket to get better latency.  The API
 * essentially boils down to first retriving the TCP header, adding
 * your own payload, sending via ef_vi layer, and finally telling the
 * API how many bytes you sent so it can update the internal TCP state
 * machinery.
 *
 * In this application, we compare the performance of an echo server
 * using normal sockets with using the delegated sends API.
 *
 * For normal sends, run apps like below:
 *
 * onload ./efdelegated_server 12345
 * onload ./efdelegated_client <srv-ip-addr> 12345
 *
 * For delegated sends, run apps like below:
 *
 * onload ./efdelegated_server -d 12345
 * onload ./efdelegated_client <srv-ip-addr> 12345
 */

#include <etherfabric/vi.h>
#include <etherfabric/pio.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <onload/extensions.h>
#include "utils.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <stdbool.h>


#define MTU                   1500
#define MAX_ETH_HEADERS       (14 + 4)
#define MAX_IP_TCP_HEADERS    (20 + 20 + 12)
#define MAX_PACKET            (MTU + MAX_ETH_HEADERS)
#define MAX_MESSAGE           (MTU - MAX_IP_TCP_HEADERS)


static unsigned  cfg_payload_len = 200;
static int       cfg_delegated;


struct state {
  int                          tcp_sock;
  int                          udp_sock;
  ef_pd                        pd;
  ef_pio                       pio;
  ef_driver_handle             dh;
  ef_vi                        vi;
  char                         pkt_buf[MAX_PACKET];
  char*                        msg_buf;
  int                          msg_len;
  int                          pio_pkt_len;
  bool                         pio_in_use;
  struct onload_delegated_send ods;
};


static int min(int x, int y)
{
  return x < y ? x : y;
}


static void evq_poll(struct state* s)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i;

  n_ev = ef_eventq_poll(&(s->vi), evs, sizeof(evs) / sizeof(evs[0]));
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      if( ef_vi_transmit_unbundle(&(s->vi), &evs[i], ids) )
        s->pio_in_use = false;
      break;
    default:
      fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
              EF_EVENT_PRI_ARG(evs[i]));
      TEST(0);
      break;
    }
}


static int sock_rx(int sock)
{
  char buf[1];
  int rc = recv(sock, buf, 1, MSG_DONTWAIT);
  if( rc >= 0 )
    return rc;
  else if( rc == -1 && errno == EAGAIN )
    return -1;
  else
    TEST(0);
}


static void normal_send(struct state* s)
{
  ssize_t rc = send(s->tcp_sock, s->msg_buf, s->msg_len, 0);
  TEST( rc == s->msg_len );
}


/**********************************************************************/
/* Below is the most interesting bit of code in the app */
/**********************************************************************/

/* Prepare to do a delegated send.  You want to try to call this out
 * of the critical path of sending or else you will not be getting
 * very much benefit from the API.
 *
 * In this app, we call this function right after having done the
 * previous send and while we wait for the next ping from the client.
 *
 * This function can be called speculatively.  If later on you decide
 * that you don't want to do a delegated send, you can call
 * onload_delegated_send_cancel().
 */
static void delegated_prepare(struct state* s)
{
  /* Prepare to do a delegated send: Get the current packet headers. */
  s->ods.headers = s->pkt_buf;
  s->ods.headers_len = MAX_ETH_HEADERS + MAX_IP_TCP_HEADERS;
  TRY( onload_delegated_send_prepare(s->tcp_sock, s->msg_len, 0, &(s->ods)) );

  /* We've probably put the headers in the wrong place, because we've
   * allowed enough space for worst-case headers (including VLAN tag and
   * TCP options).  Move the headers up so that the end of the headers
   * meets the start of the message.
   */
  s->ods.headers = s->msg_buf - s->ods.headers_len;
  memmove(s->ods.headers, s->pkt_buf, s->ods.headers_len);

  /* If we want to send more than MSS (maximum segment size), we will have
   * to segment the message into multiple packets.  We do not handle that
   * case in this app.
   */
  TEST( s->msg_len <= s->ods.mss );

  /* Figure out how much we are actually allowed to send. */
  int allowed_to_send = min(s->ods.send_wnd, s->ods.cong_wnd);
  allowed_to_send = min(allowed_to_send, s->ods.mss);

  if( s->msg_len <= allowed_to_send ) {
    s->pio_pkt_len = s->ods.headers_len + s->msg_len;
    onload_delegated_send_tcp_update(&(s->ods), s->msg_len, 1);
    TRY( ef_pio_memcpy(&(s->vi), s->ods.headers, 0, s->pio_pkt_len) );
  }
  else {
    /* We can't send at the moment, due to congestion window or receive
     * window being closed (or message larger than MSS).  Cancel the
     * delegated send and use normal send instead.
     */
    TRY(onload_delegated_send_cancel(s->tcp_sock));
    s->pio_pkt_len = 0;
  }
}


static void delegated_send(struct state* s)
{
  /* Fast path send: */
  TRY( ef_vi_transmit_pio(&(s->vi), 0, s->pio_pkt_len, 0) );
  s->pio_pkt_len = 0;
  s->pio_in_use = 1;

  /* Now tell Onload what we've sent.  It needs to know so that it can
   * update internal state (eg. sequence numbers) and take a copy of the
   * payload sent so that it can be retransmitted if needed.
   *
   * NB. This does not have to happen immediately after the delegated send
   * (and is not part of the critical path) but should be done soon after.
   */
  struct iovec iov;
  iov.iov_len  = s->msg_len;
  iov.iov_base = s->msg_buf;
  TRY( onload_delegated_send_complete(s->tcp_sock, &iov, 1, 0) );
}


static int rx_wait(struct state* s)
{
  int rc;
  do {
    evq_poll(s);
    if( ! s->pio_in_use && ! s->pio_pkt_len )
      /* Get ready for the next delegated send... */
      delegated_prepare(s);
  } while( (rc = sock_rx(s->udp_sock)) < 0 );
  return rc;
}


static void loop(struct state* s)
{
  while( 1 ) {
    if( rx_wait(s) == 0 )
      break;
    if( s->pio_pkt_len )
      delegated_send(s);
    else
      normal_send(s);
  }

  if( s->pio_pkt_len )
    TRY(onload_delegated_send_cancel(s->tcp_sock));
}


/**********************************************************************/
/* Below is just initialization cruft and not really interesting for
 * delegated sends API. */
/**********************************************************************/

static int parse_interface(const char* intf_name, int* ifindex_out)
{
  if( (*ifindex_out = if_nametoindex(intf_name)) == 0 )
    return -errno;
  return 0;
}


static int get_ifindex(int sock, int* ifindex_out)
{
  int rc = -1;
  struct ifaddrs *addrs, *iap;
  struct sockaddr_in sa;
  char sock_ip_addr[32];
  socklen_t len = sizeof(sa);
  TRY(getsockname(sock, (struct sockaddr*)&sa, &len));
  snprintf(sock_ip_addr, sizeof(sock_ip_addr), "%s", inet_ntoa(sa.sin_addr));

  getifaddrs(&addrs);
  for( iap = addrs; iap != NULL; iap = iap->ifa_next) {
    if( iap->ifa_addr &&
        iap->ifa_flags & IFF_UP &&
        iap->ifa_addr->sa_family == AF_INET ) {
      struct sockaddr_in* sa = (struct sockaddr_in*)iap->ifa_addr;
      char intf_ip_addr[32];
      inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), intf_ip_addr,
                sizeof(intf_ip_addr));
      if( ! strcmp(sock_ip_addr, intf_ip_addr) ) {
        TRY(parse_interface(iap->ifa_name, ifindex_out));
        rc = 0;
        goto done;
      }
    }
  }

 done:
  freeifaddrs(addrs);
  return rc;
}


static void ef_vi_init(struct state* s)
{
  enum ef_pd_flags pd_flags = EF_PD_DEFAULT;
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;
  int ifindex;

  s->pio_pkt_len = 0;
  s->pio_in_use = ! cfg_delegated;
  TRY(get_ifindex(s->tcp_sock, &ifindex));
  TRY(ef_driver_open(&s->dh));
  TRY(ef_pd_alloc(&s->pd, s->dh, ifindex, pd_flags));
  TRY(ef_vi_alloc_from_pd(&(s->vi), s->dh, &s->pd, s->dh, -1,0,-1, NULL, -1,
                          vi_flags));
  TRY(ef_pio_alloc(&s->pio, s->dh, &s->pd, -1, s->dh));
  TRY(ef_pio_link_vi(&s->pio, s->dh, &(s->vi), s->dh));
}


static int my_bind(int sock, int port)
{
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);
  return bind(sock, (struct sockaddr*)&sa, sizeof(sa));
}


static void init(struct state* s, int port)
{
  int lsock;
  int one = 1;

  s->msg_len = cfg_payload_len;
  s->msg_buf = s->pkt_buf + MAX_ETH_HEADERS + MAX_IP_TCP_HEADERS;

  TRY(s->udp_sock = socket(AF_INET, SOCK_DGRAM, 0));
  TRY(my_bind(s->udp_sock, port));

  TRY( lsock = socket(AF_INET, SOCK_STREAM, 0) );
  TRY( setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one)) );
  TRY( setsockopt(lsock, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one)) );
  TRY( my_bind(lsock, port) );
  TRY( listen(lsock, 1) );
  TRY( s->tcp_sock = accept(lsock, NULL, NULL) );
  TRY( close(lsock) );
  ef_vi_init(s);
}


static void usage_msg(FILE* f)
{
  fprintf(f, "\nusage:\n");
  fprintf(f, "  efdelegated_server [options] <port>\n");
  fprintf(f, "\noptions:\n");
  fprintf(f, "  -s <msg-size>      - set payload size\n");
  fprintf(f, "  -d                 - use delegated sends API to send\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


int main(int argc, char* argv[])
{
  int port;
  int c;

  while( (c = getopt(argc, argv, "hs:d")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
      break;
    case 's':
      cfg_payload_len = atoi(optarg);
      break;
    case 'd':
      cfg_delegated = 1;
      break;
    case '?':
      usage_err();
      break;
    default:
      TEST(0);
      break;
    }
  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage_err();

  port = atoi(argv[0]);

  if( cfg_delegated && ! onload_is_present() ) {
    fprintf(stderr, "ERROR: Must run with Onload to use delegated sends\n");
    exit(1);
  }

  struct state the_state;
  init(&the_state, port);
  loop(&the_state);
  return 0;
}

/*! \cidoxg_end */
