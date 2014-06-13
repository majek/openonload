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

/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
static int cfg_timestamping;


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i )
    printf("%02x%s", (unsigned) p[i], ((i&15)==15)?"\n":((i&1)==1)?" ":"");
  printf("\n\n");
}


/* If (t1 >= t2) the sets result_out to t1 - t2 and returns 0 else
 * sets result_out to t2 - t1 and returns -1 */
static int ts_diff(const struct timespec* t1, const struct timespec* t2,
                   struct timespec* result_out)
{
  if( (t1->tv_sec > t2->tv_sec) ||
      ((t1->tv_sec == t2->tv_sec) && (t1->tv_nsec >= t2->tv_nsec)) ) {
    /* t1 >= t2 */
    result_out->tv_sec = t1->tv_sec - t2->tv_sec;
    if( t1->tv_nsec < t2->tv_nsec ) {
      result_out->tv_nsec = t1->tv_nsec + 1000000000L - t2->tv_nsec;
      --result_out->tv_sec;
    }
    else {
      result_out->tv_nsec = t1->tv_nsec - t2->tv_nsec;
    }
    return 0;
  }
  else {
    result_out->tv_sec = t2->tv_sec - t1->tv_sec;
    if( t2->tv_nsec < t1->tv_nsec ) {
      result_out->tv_nsec = t2->tv_nsec + 1000000000L - t1->tv_nsec;
      --result_out->tv_sec;
    }
    else {
      result_out->tv_nsec = t2->tv_nsec - t1->tv_nsec;
    }
    return -1;
  }
}


static void handle_rx(struct thread* thread, struct vi* vi,
                      int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;
  struct timespec hw_ts, sw_ts;
  struct timespec diff;
  void* dma;

  LOGI(fprintf(stderr, "INFO: [%s] received pkt=%d len=%d\n",
               vi->interface, pkt_buf_i, len));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);

  if( cfg_timestamping ) {
    TRY(clock_gettime(CLOCK_REALTIME, &sw_ts));
    dma = (char*) pkt_buf + RX_DMA_OFF;
    TRY(ef_vi_receive_get_timestamp(&vi->vi, dma, &hw_ts));
    printf("HW: %ld.%ld diff: ", hw_ts.tv_sec, hw_ts.tv_nsec);
    if( ts_diff(&sw_ts, &hw_ts, &diff) != 0 )
      printf("-");
    printf("%ld.%ld\n", diff.tv_sec, diff.tv_nsec);
  }

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
                  EF_EVENT_RX_BYTES(evs[i]) - vi->frame_off);
        break;
      case EF_EVENT_TYPE_TX:
        n = ef_vi_transmit_unbundle(&vi->vi, &evs[i], ids);
        for( j = 0; j < n; ++j )
          complete_tx(thread, TX_RQ_ID_PB(ids[j]));
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(thread, vi, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                          EF_EVENT_RX_DISCARD_BYTES(evs[i]) - vi->frame_off,
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


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsink <options> <interface> <filter-spec>...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:[vid=<vlan>,]<local-host>:<local-port>"
          "[,<remote-host>:<remote-port>]\n");
  fprintf(stderr, "  eth:[vid=<vlan>,]<local-mac>\n");
  fprintf(stderr, "  {unicast-all,multicast-all}:[vid=<vlan>]\n");
  fprintf(stderr, "  {unicast-mis,multicast-mis}:[vid=<vlan>]\n");
  fprintf(stderr, "  {sniff}:[promisc|no-promisc]\n");
  fprintf(stderr, "  {block-kernel|block-kernel-unicast|block-kernel-multicast}\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -d     hexdump received packet\n");
  fprintf(stderr, "  -t     Request hardware timestamping of packets\n");
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

  while( (c = getopt (argc, argv, "dt")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 't':
      cfg_timestamping = 1;
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

  if( (net_if = net_if_alloc(0, interface, 0)) == NULL ) {
    LOGE(fprintf(stderr, "ERROR: Bad interface '%s' or unable to allocate "
                 "resources\n", interface));
    exit(1);
  }
  vi = vi_alloc(0, net_if, cfg_timestamping ?
                EF_VI_RX_TIMESTAMPS :
                EF_VI_FLAGS_DEFAULT);

   thread = calloc(1, sizeof(*thread));
   thread->vi = vi;

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
