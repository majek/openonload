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


/* efforward
 *
 * Forward packets between two interfaces without modification.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/13
 */

#include "efvi_sfw.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <string.h>


#define LOGE(x)  do{ x; }while(0)
#define LOGW(x)  do{ x; }while(0)
#define LOGI(x)  do{}while(0)


struct thread {
  struct vi** vis;
  int         vis_n;
  struct vi** fwd_map;
  int         n_rx_pkts;
  uint64_t    n_rx_bytes;
};


static void handle_rx(struct thread* thread, struct vi* vi,
                      int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;
  struct vi* send_vi;
  int rc;

  LOGI(fprintf(stderr, "INFO: [%s] received pkt=%d len=%d\n",
               vi->interface, pkt_buf_i, len));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);

  send_vi = thread->fwd_map[vi->id];
  rc = vi_send(send_vi, pkt_buf, RX_PKT_OFF(vi), len);
  if( rc != 0 ) {
    assert(rc == -EAGAIN);
    /* TXQ is full.  A real app might consider implementing an overflow
     * queue in software.  We simply choose not to send.
     */
    LOGW(fprintf(stderr, "WARNING: [%s] dropped send\n",
                 send_vi->net_if->name));
  }
  pkt_buf_release(pkt_buf);
  ++thread->n_rx_pkts;
  thread->n_rx_bytes += len;
}


static void handle_rx_discard(struct thread* thread, struct vi* vi,
                              int pkt_buf_i, int discard_type)
{
  struct pkt_buf* pkt_buf;

  LOGE(fprintf(stderr, "ERROR: [%s] discard type=%d\n",
               vi->net_if->name, discard_type));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);
  pkt_buf_release(pkt_buf);
}


static void complete_tx(struct thread* thread, int vi_i, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf;
  assert(vi_i < thread->vis_n);
  pkt_buf = pkt_buf_from_id(thread->vis[vi_i], pkt_buf_i);
  pkt_buf_release(pkt_buf);
}


static void thread_main_loop(struct thread* thread)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[16];
  struct vi* vi;
  int i, j, n, n_ev, vi_i = 0;

  while( 1 ) {
    vi = thread->vis[vi_i];
    vi_i = (vi_i + 1) % thread->vis_n;

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
          complete_tx(thread, TX_RQ_ID_VI(ids[j]), TX_RQ_ID_PB(ids[j]));
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(thread, vi, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
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
    printf("%8d %10d\n", pkt_rate, mbps);
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
  fprintf(stderr, "  efforward <intf1> <intf2>\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  struct vi* vis[2];
  struct vi* fwd_map[2];
  struct thread* thread;
  struct net_if* net_if;
  int i, j;

  if( argc != 3 )
    usage();
  ++argv;
  --argc;

  thread = calloc(1, sizeof(*thread));
  thread->vis = vis;
  thread->vis_n = 2;
  thread->fwd_map = fwd_map;

  for( i = 0; i < thread->vis_n; ++i ) {
    if( (net_if = net_if_alloc(i, argv[i], 0)) == NULL ) {
      LOGE(fprintf(stderr, "ERROR: Bad interface '%s' or unable to allocate "
                   "resources\n", argv[i]));
      exit(1);
    }
    vis[i] = vi_alloc(i, net_if);
  }
  for( i = 0; i < thread->vis_n; ++i )
    for( j = 0; j < thread->vis_n; ++j )
      if( i != j )
        net_if_map_vi_pool(vis[i]->net_if, vis[j]);
  fwd_map[0] = vis[1];
  fwd_map[1] = vis[0];

  for( i = 0; i < thread->vis_n; ++i ) {
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    TRY(ef_filter_spec_set_unicast_all(&filter_spec));
    TRY(ef_vi_filter_add(&vis[i]->vi, vis[i]->dh, &filter_spec, NULL));
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    TRY(ef_filter_spec_set_multicast_all(&filter_spec));
    TRY(ef_vi_filter_add(&vis[i]->vi, vis[i]->dh, &filter_spec, NULL));
  }

  TEST(pthread_create(&thread_id, NULL, monitor_fn, thread) == 0);
  thread_main_loop(thread);

  return 0;
}
