/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** Copyright 2005-2013  Solarflare Communications Inc.
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


/* efsink
 *
 * Receive streams of packets on a single interface.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/28
 */

#include "efvi_sfw.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>


#define LOGE(x)  do{ x; }while(0)
#define LOGW(x)  do{ x; }while(0)
#define LOGI(x)  do{}while(0)


struct thread {
  struct vi*  vi;
  int         n_rx_pkts;
  uint64_t    n_rx_bytes;
};


static int cfg_hexdump;


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i )
    printf("%02x%s", (unsigned) p[i], ((i&15)==15)?"\n":((i&1)==1)?" ":"");
  printf("\n\n");
}


static void handle_rx(struct thread* thread, struct vi* vi,
                      int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;

  LOGI(fprintf(stderr, "INFO: [%s] received pkt=%d len=%d\n",
               vi->interface, pkt_buf_i, len));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);

  /* Do something useful with packet contents here!  Packet payload starts
   * at RX_PKT_PTR(pkt_buf).
   */
  if( cfg_hexdump )
    hexdump(RX_PKT_PTR(pkt_buf), len);

  pkt_buf_release(pkt_buf);
  ++thread->n_rx_pkts;
  thread->n_rx_bytes += len;
}


static void handle_rx_discard(struct thread* thread, struct vi* vi,
                              int pkt_buf_i, int len, int discard_type)
{
  struct pkt_buf* pkt_buf;

  LOGE(fprintf(stderr, "ERROR: [%s] discard type=%d\n",
               vi->net_if->name, discard_type));

  if( /* accept_discard_pkts */ 1 ) {
    handle_rx(thread, vi, pkt_buf_i, len);
  }
  else {
    pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);
    pkt_buf_release(pkt_buf);
  }
}


static void complete_tx(struct thread* thread, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf;
  pkt_buf = pkt_buf_from_id(thread->vi, pkt_buf_i);
  pkt_buf_release(pkt_buf);
}


static void thread_main_loop(struct thread* thread)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[16];
  struct vi* vi;
  int i, j, n, n_ev;

  while( 1 ) {
    vi = thread->vi;

    n_ev = ef_eventq_poll(&vi->vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev <= 0 )
      continue;

    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        /* This code does not handle jumbos. */
        assert(EF_EVENT_RX_SOP(evs[i]) != 0);
        assert(EF_EVENT_RX_CONT(evs[i]) == 0);
        handle_rx(thread, vi, EF_EVENT_RX_RQ_ID(evs[i]),
                  EF_EVENT_RX_BYTES(evs[i]) - vi->rx_prefix_len);
        break;
      case EF_EVENT_TYPE_TX:
        n = ef_vi_transmit_unbundle(&vi->vi, &evs[i], ids);
        for( j = 0; j < n; ++j )
          complete_tx(thread, TX_RQ_ID_PB(ids[j]));
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(thread, vi, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                          EF_EVENT_RX_DISCARD_BYTES(evs[i])-vi->rx_prefix_len,
                          EF_EVENT_RX_DISCARD_TYPE(evs[i]));
        break;
      default:
        LOGE(fprintf(stderr, "ERROR: unexpected event type=%d\n",
                     (int) EF_EVENT_TYPE(evs[i])));
        break;
      }
    }
    vi_refill_rx_ring(vi);
  }
}

/**********************************************************************/

static void monitor(struct thread* thread)
{
  /* Print approx packet rate and bandwidth every second. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  int prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  printf("# pkt-rate  bandwidth(Mbps)\n");

  prev_pkts = thread->n_rx_pkts;
  prev_bytes = thread->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = thread->n_rx_pkts;
    now_bytes = thread->n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((int64_t) (now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    printf("%10d %16d\n", pkt_rate, mbps);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  struct thread* thread = arg;
  monitor(thread);
  return NULL;
}


static char* my_strtok(char** s, char delim)
{
  char* tok = *s;
  if( **s == '\0' )
    return NULL;
  while( **s != '\0' && **s != delim )
    ++(*s);
  if( **s != '\0' ) {
    **s = '\0';
    ++(*s);
  }
  return tok;
}


static int hostport_parse(struct sockaddr_in* sin, const char* s_in)
{
  struct addrinfo hints;
  struct addrinfo* ai;
  const char* host;
  const char* port;
  char *s, *p;
  int rc = -EINVAL;

  p = s = strdup(s_in);
  host = my_strtok(&p, ':');
  port = my_strtok(&p, '\0');
  if( port == NULL )
    goto out;

  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  rc = getaddrinfo(host, port, &hints, &ai);
  if( rc == 0 ) {
    TEST(ai->ai_addrlen == sizeof(*sin));
    memcpy(sin, ai->ai_addr, ai->ai_addrlen);
  }
  else {
    LOGE(fprintf(stderr, "ERROR: getaddrinfo(\"%s\", \"%s\") returned %d %s\n",
                 host, port, rc, gai_strerror(rc)));
    rc = -EINVAL;
  }
 out:
  free(s);
  return rc;
}


static int filter_parse(ef_filter_spec* fs, const char* s_in)
{
  struct sockaddr_in sin;
  const char* type;
  const char* hostport;
  char *s, *p;
  int rc = -EINVAL;
  int protocol;

  ef_filter_spec_init(fs, EF_FILTER_FLAG_NONE);

  p = s = strdup(s_in);
  if( (type = my_strtok(&p, ':')) == NULL )
    goto out;
  if( ! strcasecmp(type, "tcp") || ! strcasecmp(type, "udp") ) {
    protocol = strcasecmp(type, "tcp") ? IPPROTO_UDP : IPPROTO_TCP;
    if( (hostport = my_strtok(&p, '\0')) == NULL )
      goto out;
    if( (rc = hostport_parse(&sin, hostport)) != 0 )
      goto out;
    ef_filter_spec_set_ip4_local(fs, protocol, sin.sin_addr.s_addr,
                                 sin.sin_port);
  }
  else if( ! strcasecmp(type, "unicast") || ! strcasecmp(type, "ucast") ) {
    ef_filter_spec_set_unicast_all(fs);
    rc = 0;
  }
  else if( ! strcasecmp(type, "multicast") || ! strcasecmp(type, "mcast") ) {
    ef_filter_spec_set_multicast_all(fs);
    rc = 0;
  }

 out:
  free(s);
  return rc;
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsink <interface> <filter-spec>...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:<local-host-or-ip>:<local-port>\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* interface;
  pthread_t thread_id;
  struct thread* thread;
  struct net_if* net_if;
  struct vi* vi;
  int c;

  while( (c = getopt (argc, argv, "d")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc < 2 )
    usage();
  interface = argv[0];
  ++argv; --argc;

  net_if = net_if_alloc(0, interface, 0);
  vi = vi_alloc(0, net_if);
  printf("rxq_size=%d\n", ef_vi_receive_capacity(&vi->vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi->vi));

  thread = calloc(1, sizeof(*thread));
  thread->vi = vi;

  while( argc > 0 ) {
    ef_filter_spec filter_spec;
    if( filter_parse(&filter_spec, argv[0]) != 0 ) {
      LOGE(fprintf(stderr, "ERROR: Bad filter spec '%s'\n", argv[0]));
      exit(1);
    }
    TRY(ef_vi_filter_add(&vi->vi, vi->dh, &filter_spec, NULL));
    ++argv; --argc;
  }

  TEST(pthread_create(&thread_id, NULL, monitor_fn, thread) == 0);
  thread_main_loop(thread);

  return 0;
}
